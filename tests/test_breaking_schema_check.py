# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Regression tests for scripts/breaking_schema_check.py — the PR breaking-change gate.

These are the negative controls the gate must satisfy, pinned as tests so a future change to
the differ can't silently regress them:

1. Removing a declared property fails the gate and names the property.
2. Adding an existing property to `required` fails the gate.
3. Adding a new OPTIONAL property passes the gate (proves the gate isn't "any change fails",
   which would be trivially true and useless).

Also pinned: the allowlist's `reason` field is a real acknowledgement, not just a non-empty
string. This gate is ENFORCE (blocking) by design — "you may not break the contract silently"
— so a placeholder reason ("TODO", "see PR", a bare issue number) must NOT grant an opt-out,
and a real one must.

Each test builds a tiny throwaway git repo (not this repo) with one schema file, commits a
baseline, then commits one change on a branch, and runs the real CLI against it via
subprocess — exercising the exact code path a PR would hit, not just the internal comparator
function.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "breaking_schema_check.py"


def _git_local_env_vars() -> frozenset[str]:
    """The GIT_* variable names git itself considers repo-local (GIT_DIR,
    GIT_WORK_TREE, GIT_INDEX_FILE, ...) — as opposed to e.g. GIT_AUTHOR_NAME,
    which travels safely. Queried from git rather than hardcoded so this stays
    correct across git versions."""
    result = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        capture_output=True,
        text=True,
        check=True,
    )
    return frozenset(result.stdout.split())


def _sanitized_git_env() -> dict[str, str]:
    """A caller of this test module (a pre-push hook, a CI runner, a dev shell
    mid-rebase) may have GIT_DIR/GIT_WORK_TREE/etc. exported for ITS repo. If we
    forwarded that environment untouched, `git -C <throwaway-repo>` would still
    be redirected at the caller's repo — GIT_DIR overrides -C. Strip those names
    independent of whatever the pre-push hook does, so these tests are safe even
    invoked directly (pytest tests/, an IDE runner, a foreign CI job)."""
    local_vars = _git_local_env_vars()
    return {key: value for key, value in os.environ.items() if key not in local_vars}


def _load_gate_module():
    """scripts/ isn't a package (no __init__.py), so import the script directly by path
    rather than polluting sys.path — lets the placeholder-reason tests call
    reason_rejection() directly instead of only exercising it through the CLI."""
    spec = importlib.util.spec_from_file_location("breaking_schema_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses' string-annotation resolution (from __future__ import annotations) looks
    # the module up via sys.modules[cls.__module__] — register it before exec_module runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate_module()


def _stored_identity(finding, **updates):
    identity = {**finding.identity(), **updates}
    identity["fingerprint"] = gate._fingerprint_for_identity(
        finding.file,
        finding.rule,
        {key: value for key, value in identity.items() if key != "fingerprint"},
    )
    return identity


BASELINE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://schemas.traigent.ai/widgets/widget_request_schema.json",
    "type": "object",
    "title": "Widget Request",
    "properties": {
        "name": {"type": "string", "maxLength": 100},
        "color": {"type": "string"},
        "size": {"type": "integer", "minimum": 1},
    },
    "required": ["name"],
    "additionalProperties": False,
}


def _run_git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=True,
        env=_sanitized_git_env(),
    )
    return result.stdout


@pytest.fixture
def widget_repo(tmp_path: Path) -> Path:
    """A minimal git repo shaped like traigent_schema/schemas/, with a committed baseline
    widget_request_schema.json on `master` (HEAD)."""
    repo = tmp_path / "widget_repo"
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    schema_dir.mkdir(parents=True)
    (schema_dir / "widget_request_schema.json").write_text(
        json.dumps(BASELINE_SCHEMA, indent=2) + "\n", encoding="utf-8"
    )

    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Breaking Schema Check Tests")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "baseline widget_request_schema")
    return repo


def _commit_schema_change(
    repo: Path,
    branch: str,
    schema: dict,
    message: str,
    filename: str = "widget_request_schema.json",
) -> None:
    _run_git(repo, "checkout", "-q", "-b", branch)
    path = repo / "traigent_schema" / "schemas" / "widgets" / filename
    path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", message)
    _run_git(repo, "checkout", "-q", "master")


def _run_gate(repo: Path, base_ref: str, head_ref: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--check",
            "--repo-root",
            str(repo),
            "--base-ref",
            base_ref,
            "--head-ref",
            head_ref,
            # Point at a nonexistent allowlist so these tests can never be silently
            # neutralized by a stray/real scripts/breaking_schema_allowlist.json entry.
            "--allowlist",
            str(repo / "no-such-allowlist.json"),
        ],
        env=_sanitized_git_env(),
        capture_output=True,
        text=True,
    )


def _write_tar(archive_path: Path, members: list[tarfile.TarInfo]) -> None:
    with tarfile.open(archive_path, "w") as archive:
        for member in members:
            payload = io.BytesIO(b'{"type": "object"}\n') if member.isfile() else None
            archive.addfile(member, payload)


def _regular_tar_member(name: str) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.size = len(b'{"type": "object"}\n')
    return member


@pytest.mark.parametrize(
    "member",
    [
        _regular_tar_member("../escaped.json"),
        _regular_tar_member("/etc/passwd"),
        _regular_tar_member(r"C:\windows\escaped.json"),
        _regular_tar_member(r"\windows\escaped.json"),
        tarfile.TarInfo("safe-link"),
        tarfile.TarInfo("safe-hard-link"),
        tarfile.TarInfo("special-device"),
        tarfile.TarInfo("special-fifo"),
    ],
    ids=[
        "posix-traversal",
        "posix-absolute",
        "windows-drive-traversal",
        "windows-rooted-traversal",
        "symlink",
        "hardlink",
        "device",
        "fifo",
    ],
)
def test_tar_extraction_rejects_unsafe_members(
    tmp_path: Path, member: tarfile.TarInfo
) -> None:
    if member.name == "safe-link":
        member.type = tarfile.SYMTYPE
        member.linkname = "inside.json"
    elif member.name == "safe-hard-link":
        member.type = tarfile.LNKTYPE
        member.linkname = "inside.json"
    elif member.name == "special-device":
        member.type = tarfile.CHRTYPE
    elif member.name == "special-fifo":
        member.type = tarfile.FIFOTYPE

    archive_path = tmp_path / "unsafe.tar"
    destination = tmp_path / "destination"
    destination.mkdir()
    _write_tar(archive_path, [member])

    with (
        tarfile.open(archive_path) as archive,
        pytest.raises(ValueError, match="(escapes|unsafe)"),
    ):
        gate._extract_validated_tar_members(archive, destination)

    assert not (tmp_path / "escaped.json").exists()


def test_tar_extraction_materializes_a_valid_schema_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "valid.tar"
    destination = tmp_path / "destination"
    destination.mkdir()
    directory = tarfile.TarInfo("traigent_schema/schemas/widgets")
    directory.type = tarfile.DIRTYPE
    _write_tar(
        archive_path,
        [
            directory,
            _regular_tar_member("traigent_schema/schemas/widgets/widget_schema.json"),
        ],
    )

    with tarfile.open(archive_path) as archive:
        gate._extract_validated_tar_members(archive, destination)

    assert (
        destination / "traigent_schema/schemas/widgets/widget_schema.json"
    ).read_text(encoding="utf-8") == '{"type": "object"}\n'


def test_gate_rejects_a_historical_ref_with_file_at_schema_target(
    widget_repo: Path,
) -> None:
    """A historical ``schemas`` file must fail the CLI before an empty tree can pass."""
    _run_git(widget_repo, "checkout", "-q", "-b", "schemas-is-a-file")
    schema_target = widget_repo / "traigent_schema" / "schemas"
    shutil.rmtree(schema_target)
    schema_target.write_text("not a schema directory\n", encoding="utf-8")
    _run_git(widget_repo, "add", "-A")
    _run_git(widget_repo, "commit", "-q", "-m", "replace schemas directory with file")
    _run_git(widget_repo, "checkout", "-q", "master")

    result = _run_gate(widget_repo, "schemas-is-a-file", "master")

    assert result.returncode == 2, result.stdout
    assert "required tar directory is missing" in result.stderr


def test_removing_a_property_fails_and_names_it(widget_repo: Path) -> None:
    changed = dict(BASELINE_SCHEMA)
    baseline_properties: dict = BASELINE_SCHEMA["properties"]
    changed["properties"] = {
        k: v for k, v in baseline_properties.items() if k != "color"
    }
    _commit_schema_change(widget_repo, "remove-color", changed, "remove color property")

    result = _run_gate(widget_repo, "master", "remove-color")

    assert result.returncode == 1, result.stdout
    assert "property_removed" in result.stdout
    assert "'color' removed" in result.stdout


def test_adding_an_existing_property_to_required_fails(widget_repo: Path) -> None:
    changed = json.loads(json.dumps(BASELINE_SCHEMA))
    changed["required"] = ["name", "color"]
    _commit_schema_change(widget_repo, "require-color", changed, "make color required")

    result = _run_gate(widget_repo, "master", "require-color")

    assert result.returncode == 1, result.stdout
    assert "'color' added to required" in result.stdout


def test_adding_an_optional_property_passes(widget_repo: Path) -> None:
    changed = json.loads(json.dumps(BASELINE_SCHEMA))
    changed["properties"]["weight"] = {"type": "number"}
    _commit_schema_change(
        widget_repo, "add-weight", changed, "add optional weight property"
    )

    result = _run_gate(widget_repo, "master", "add-weight")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_response_role_mirrors_request_role(tmp_path: Path) -> None:
    """A *_response_schema.json is the mirror image of a *_request_schema.json: removing a
    field from `required` (walking back a guarantee) is BREAKING; adding one is not by
    itself.  A new member is separately BREAKING when the old response was closed, because
    an old strict consumer rejects a value that carries it."""
    repo = tmp_path / "resp_repo"
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    schema_dir.mkdir(parents=True)
    baseline = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://schemas.traigent.ai/widgets/widget_response_schema.json",
        "type": "object",
        "properties": {"id": {"type": "string"}, "color": {"type": "string"}},
        "required": ["id", "color"],
        "additionalProperties": False,
    }
    (schema_dir / "widget_response_schema.json").write_text(
        json.dumps(baseline, indent=2) + "\n", encoding="utf-8"
    )
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Breaking Schema Check Tests")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "baseline widget_response_schema")

    loosened = json.loads(json.dumps(baseline))
    loosened["required"] = ["id"]
    _commit_schema_change(
        repo,
        "loosen-required",
        loosened,
        "color no longer guaranteed",
        filename="widget_response_schema.json",
    )

    result = _run_gate(repo, "master", "loosen-required")
    assert result.returncode == 1, result.stdout
    assert "'color' removed from required" in result.stdout


def _response_schema_repo(tmp_path: Path, filename: str, baseline: dict) -> Path:
    repo = tmp_path / filename.removesuffix(".json")
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    schema_dir.mkdir(parents=True)
    (schema_dir / filename).write_text(
        json.dumps(baseline, indent=2) + "\n", encoding="utf-8"
    )
    _run_git(repo, "init", "-q")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Breaking Schema Check Tests")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", f"baseline {filename}")
    return repo


def _closed_response_schema(filename: str = "widget_response_schema.json") -> dict:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": f"https://schemas.traigent.ai/widgets/{filename}",
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": False,
    }


@pytest.mark.parametrize("make_required", [False, True], ids=["optional", "required"])
def test_closed_response_added_property_is_breaking(
    tmp_path: Path, make_required: bool
) -> None:
    """Both optional and required new response members can be emitted to an old strict
    consumer, so both must be classified as a response compatibility break."""
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["evidence_case"] = {"type": "object"}
    if make_required:
        changed["required"].append("evidence_case")
    _commit_schema_change(
        repo, "add-evidence-case", changed, "add response evidence case", filename
    )

    result = _run_gate(repo, "master", "add-evidence-case")

    assert result.returncode == 1, result.stdout
    assert "property_added, role=response" in result.stdout
    assert (
        "'evidence_case' added while the old schema's additionalProperties was closed"
        in result.stdout
    )


def test_open_response_added_property_is_not_breaking(tmp_path: Path) -> None:
    """An old open response contract already accepted unknown members, so a new optional
    member is not a strict-consumer compatibility break."""
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    baseline.pop("additionalProperties")
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["evidence_case"] = {"type": "object"}
    _commit_schema_change(
        repo, "add-evidence-case", changed, "add open response property", filename
    )

    result = _run_gate(repo, "master", "add-evidence-case")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def _open_schema(filename: str) -> dict:
    schema = _closed_response_schema(filename)
    schema.pop("additionalProperties")
    return schema


@pytest.mark.parametrize(
    ("added", "breaking"),
    [
        ({"type": "number"}, True),
        ({"enum": ["a"]}, True),
        ({"$ref": "#/definitions/x"}, True),
        ({"type": "number", "description": "d"}, True),
        ({}, False),
        (True, False),
        ({"description": "anything goes"}, False),
    ],
    ids=["type", "enum", "ref", "type-with-annotation", "empty", "true", "annotation-only"],
)
def test_open_request_added_property_breaking_only_when_constrained(
    tmp_path: Path, added: object, breaking: bool
) -> None:
    """On an open request object any value under the new key used to validate, so a
    constrained schema for it rejects a previously valid payload."""
    filename = "widget_request_schema.json"
    baseline = _open_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["temperature"] = added
    _commit_schema_change(repo, "add-prop", changed, "add request property", filename)

    result = _run_gate(repo, "master", "add-prop")

    if breaking:
        assert result.returncode == 1, result.stdout
        assert "property_added, role=request" in result.stdout
        assert "added with a constrained schema" in result.stdout
    else:
        assert result.returncode == 0, result.stdout
        assert "BREAKING (unacked):   0" in result.stdout


def test_nested_open_request_added_constrained_property_is_breaking(tmp_path: Path) -> None:
    filename = "widget_request_schema.json"
    baseline = _open_schema(filename)
    baseline["properties"]["options"] = {"type": "object", "properties": {}}
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["options"]["properties"]["temperature"] = {"type": "number"}
    _commit_schema_change(repo, "add-prop", changed, "add nested request property", filename)

    result = _run_gate(repo, "master", "add-prop")

    assert result.returncode == 1, result.stdout
    assert "/properties/options/properties/temperature" in result.stdout
    assert "property_added, role=request" in result.stdout


def _map_schema(filename: str, value_schema: dict) -> dict:
    schema = _open_schema(filename)
    schema["additionalProperties"] = value_schema
    return schema


def _gate_added(tmp_path: Path, baseline: dict, mutate, filename: str = "widget_request_schema.json"):
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    mutate(changed)
    _commit_schema_change(repo, "chg", changed, "change", filename)
    return _run_gate(repo, "master", "chg")


def test_constrained_map_request_added_different_property_is_breaking(tmp_path: Path) -> None:
    """Old extras had to be strings; a number-only property rejects {"temperature": "warm"}."""
    baseline = _map_schema("widget_request_schema.json", {"type": "string"})
    result = _gate_added(
        tmp_path, baseline, lambda c: c["properties"].update(temperature={"type": "number"})
    )
    assert result.returncode == 1, result.stdout
    assert "property_added, role=request" in result.stdout


def test_constrained_map_request_added_identical_property_is_still_breaking(
    tmp_path: Path,
) -> None:
    """No equality escape: identical-looking schemas are acknowledged via the allowlist."""
    baseline = _map_schema("widget_request_schema.json", {"type": "string"})
    result = _gate_added(
        tmp_path, baseline, lambda c: c["properties"].update(temperature={"type": "string"})
    )
    assert result.returncode == 1, result.stdout
    assert "property_added, role=request" in result.stdout


def test_pattern_governed_request_added_property_is_breaking(tmp_path: Path) -> None:
    baseline = _closed_response_schema("widget_request_schema.json")
    baseline["patternProperties"] = {"^temp": {"type": "string"}}
    result = _gate_added(
        tmp_path, baseline, lambda c: c["properties"].update(temperature={"type": "number"})
    )
    assert result.returncode == 1, result.stdout
    assert "property_added, role=request" in result.stdout


def test_pattern_governed_request_added_identical_property_is_still_breaking(
    tmp_path: Path,
) -> None:
    baseline = _closed_response_schema("widget_request_schema.json")
    baseline["patternProperties"] = {"^temp": {"type": "string"}}
    result = _gate_added(
        tmp_path, baseline, lambda c: c["properties"].update(temperature={"type": "string"})
    )
    assert result.returncode == 1, result.stdout


def test_pattern_over_declared_property_is_breaking(tmp_path: Path) -> None:
    """x is declared as a number; the new pattern must not be read as governed-equal."""
    baseline = _map_schema("widget_request_schema.json", {"type": "string"})
    baseline["properties"]["x"] = {"type": "number"}
    result = _gate_added(
        tmp_path, baseline, lambda c: c.update(patternProperties={"^x$": {"type": "string"}})
    )
    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=request" in result.stdout


def test_pattern_allof_of_several_governors_is_breaking(tmp_path: Path) -> None:
    baseline = _map_schema("widget_request_schema.json", {"type": "string"})
    baseline["patternProperties"] = {"^t": {"minLength": 2}}
    result = _gate_added(
        tmp_path,
        baseline,
        lambda c: c["properties"].update(
            temperature={"allOf": [{"type": "string"}, {"minLength": 2}]}
        ),
    )
    assert result.returncode == 1, result.stdout


def test_identical_ref_text_with_changed_definition_is_breaking(tmp_path: Path) -> None:
    filename = "widget_request_schema.json"
    baseline = _map_schema(filename, {"$ref": "#/definitions/v"})
    baseline["definitions"] = {"v": {"type": "string"}}

    def mutate(c: dict) -> None:
        c["definitions"]["v"] = {"type": "number"}
        c["properties"]["temperature"] = {"$ref": "#/definitions/v"}

    result = _gate_added(tmp_path, baseline, mutate)
    assert result.returncode == 1, result.stdout


def _closed_with_number_x(filename: str = "widget_request_schema.json") -> dict:
    schema = _closed_response_schema(filename)
    schema["properties"]["x"] = {"type": "number"}
    return schema


def test_closed_request_pattern_over_declared_property_is_breaking(tmp_path: Path) -> None:
    """{"x": 12} was valid; a string-only pattern matching the declared name rejects it."""
    result = _gate_added(
        tmp_path,
        _closed_with_number_x(),
        lambda c: c.update(patternProperties={"^x$": {"type": "string"}}),
    )
    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=request" in result.stdout


def test_closed_request_pattern_matching_no_declared_property_is_not_breaking(
    tmp_path: Path,
) -> None:
    result = _gate_added(
        tmp_path,
        _closed_with_number_x(),
        lambda c: c.update(patternProperties={"^y$": {"type": "string"}}),
    )
    assert result.returncode == 0, result.stdout


def test_nested_array_items_closed_pattern_over_declared_property_is_breaking(
    tmp_path: Path,
) -> None:
    filename = "widget_request_schema.json"
    baseline = _closed_response_schema(filename)
    baseline["properties"]["rows"] = {"type": "array", "items": _closed_with_number_x(filename)}
    for k in ("$schema", "$id"):
        baseline["properties"]["rows"]["items"].pop(k)
    result = _gate_added(
        tmp_path,
        baseline,
        lambda c: c["properties"]["rows"]["items"].update(
            patternProperties={"^x$": {"type": "string"}}
        ),
    )
    assert result.returncode == 1, result.stdout
    assert "/properties/rows/items/patternProperties/^x$" in result.stdout


def test_open_request_added_constrained_pattern_is_breaking(tmp_path: Path) -> None:
    baseline = _open_schema("widget_request_schema.json")
    result = _gate_added(
        tmp_path, baseline, lambda c: c.update(patternProperties={"^x-": {"type": "string"}})
    )
    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=request" in result.stdout


def test_open_request_added_unconstrained_pattern_is_not_breaking(tmp_path: Path) -> None:
    baseline = _open_schema("widget_request_schema.json")
    result = _gate_added(tmp_path, baseline, lambda c: c.update(patternProperties={"^x-": {}}))
    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_constrained_map_request_added_different_pattern_is_breaking(tmp_path: Path) -> None:
    baseline = _map_schema("widget_request_schema.json", {"type": "string"})
    result = _gate_added(
        tmp_path, baseline, lambda c: c.update(patternProperties={"^x-": {"type": "number"}})
    )
    assert result.returncode == 1, result.stdout


def test_closed_request_added_constrained_property_is_not_breaking(tmp_path: Path) -> None:
    filename = "widget_request_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["temperature"] = {"type": "number"}
    _commit_schema_change(repo, "add-prop", changed, "add closed request property", filename)

    result = _run_gate(repo, "master", "add-prop")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_open_bare_schema_added_constrained_property_is_conservatively_breaking(
    tmp_path: Path,
) -> None:
    filename = "widget_schema.json"
    baseline = _open_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["temperature"] = {"type": "number"}
    _commit_schema_change(repo, "add-prop", changed, "add bare property", filename)

    result = _run_gate(repo, "master", "add-prop")

    assert result.returncode == 1, result.stdout
    assert "property_added, role=conservative" in result.stdout


def test_bare_closed_schema_added_property_is_conservatively_breaking(
    tmp_path: Path,
) -> None:
    """A bare schema may be used as a response, so it must retain the strict-consumer
    protection rather than inheriting request-only permissiveness."""
    filename = "widget_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["evidence_case"] = {"type": "object"}
    _commit_schema_change(
        repo, "add-evidence-case", changed, "add bare schema property", filename
    )

    result = _run_gate(repo, "master", "add-evidence-case")

    assert result.returncode == 1, result.stdout
    assert "property_added, role=conservative" in result.stdout


def test_nested_closed_response_added_property_is_breaking(tmp_path: Path) -> None:
    """The rule applies at each nested object, not only the top-level response."""
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    baseline["properties"]["payload"] = {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": False,
    }
    baseline["required"].append("payload")
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["payload"]["properties"]["evidence_case"] = {"type": "object"}
    _commit_schema_change(
        repo, "add-evidence-case", changed, "add nested response property", filename
    )

    result = _run_gate(repo, "master", "add-evidence-case")

    assert result.returncode == 1, result.stdout
    assert "/properties/payload/properties/evidence_case" in result.stdout
    assert "property_added, role=response" in result.stdout


@pytest.mark.parametrize(
    "old_additional_properties",
    [False, {"type": "integer"}],
    ids=["closed", "constrained"],
)
def test_strict_response_added_pattern_property_is_breaking_for_matching_payload(
    tmp_path: Path, old_additional_properties: object
) -> None:
    """A matching member is rejected by the old strict response and accepted by the new
    pattern, which is the concrete consumer-compatibility break the gate reports."""
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    baseline["additionalProperties"] = old_additional_properties
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["patternProperties"] = {"^x-": {"type": "string"}}
    payload = {"id": "widget-1", "x-proof": "present"}
    assert list(Draft7Validator(baseline).iter_errors(payload))
    assert not list(Draft7Validator(changed).iter_errors(payload))
    _commit_schema_change(
        repo, "add-pattern", changed, "add strict response pattern property", filename
    )

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=response" in result.stdout
    assert "matching members accepted by the new response" in result.stdout


def test_closed_request_added_pattern_property_is_not_breaking(tmp_path: Path) -> None:
    filename = "widget_request_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["patternProperties"] = {"^x-": {"type": "string"}}
    _commit_schema_change(
        repo, "add-pattern", changed, "add strict request pattern property", filename
    )

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_open_response_added_pattern_property_is_not_breaking(tmp_path: Path) -> None:
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    baseline.pop("additionalProperties")
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["patternProperties"] = {"^x-": {"type": "string"}}
    _commit_schema_change(
        repo, "add-pattern", changed, "add open response pattern property", filename
    )

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_bare_closed_schema_added_pattern_property_is_conservatively_breaking(
    tmp_path: Path,
) -> None:
    filename = "widget_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["patternProperties"] = {"^x-": {"type": "string"}}
    _commit_schema_change(
        repo, "add-pattern", changed, "add bare pattern property", filename
    )

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=conservative" in result.stdout


def test_nested_closed_response_added_pattern_property_is_breaking(
    tmp_path: Path,
) -> None:
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    baseline["properties"]["payload"] = {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": False,
    }
    baseline["required"].append("payload")
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["payload"]["patternProperties"] = {"^x-": {"type": "string"}}
    _commit_schema_change(
        repo, "add-pattern", changed, "add nested response pattern property", filename
    )

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 1, result.stdout
    assert "/properties/payload/patternProperties/^x-" in result.stdout
    assert "patternProperties_added, role=response" in result.stdout


@pytest.mark.parametrize("combinator", ["allOf", "anyOf", "oneOf"])
@pytest.mark.parametrize(
    ("filename", "role"),
    [
        ("widget_request_schema.json", "request"),
        ("widget_response_schema.json", "response"),
        ("widget_schema.json", "conservative"),
    ],
)
@pytest.mark.parametrize("direction", ["added", "removed"])
def test_combinator_appearance_and_disappearance_follow_role_direction(
    tmp_path: Path, combinator: str, filename: str, role: str, direction: str
) -> None:
    """A combinator's appearance narrows the accepted set; disappearance broadens it.
    Request and response compatibility therefore point in opposite directions, while a
    bare/mixed schema conservatively blocks both."""
    baseline = _closed_response_schema(filename)
    branch = {"properties": {"id": {"minLength": 1}}}
    if direction == "removed":
        baseline[combinator] = [branch]
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    if direction == "added":
        changed[combinator] = [branch]
    else:
        changed.pop(combinator)
    _commit_schema_change(
        repo,
        f"{direction}-{combinator}",
        changed,
        f"{direction} {combinator}",
        filename,
    )

    result = _run_gate(repo, "master", f"{direction}-{combinator}")
    expected_breaking = (
        role == "conservative"
        or (role == "request" and direction == "added")
        or (role == "response" and direction == "removed")
    )

    assert result.returncode == int(expected_breaking), result.stdout
    assert f"{combinator}_{direction}, role={role}" in result.stdout


def test_empty_allof_appearance_is_not_a_contract_change(tmp_path: Path) -> None:
    filename = "widget_response_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["allOf"] = []
    _commit_schema_change(repo, "add-empty-allof", changed, "add empty allOf", filename)

    result = _run_gate(repo, "master", "add-empty-allof")

    assert result.returncode == 0, result.stdout
    assert "empty allOf appeared" in result.stdout


@pytest.mark.parametrize(
    "placeholder",
    [
        "",
        "   ",
        "TODO",
        "todo",
        "TBD",
        "N/A",
        "see PR",
        "See PR #333",
        "see above",
        "#330",
        "PR #330",
        "issue #330",
        "approved",
        "intentional",
        "breaking change",
        "short reason",  # 13 chars, under the 20-char floor
        "onewordreasonwithnospaces",  # long enough, but not a sentence
    ],
)
def test_placeholder_reasons_are_rejected(placeholder: str) -> None:
    assert (
        gate.reason_rejection(placeholder) is not None
    ), f"{placeholder!r} should have been rejected as a placeholder"


@pytest.mark.parametrize(
    "real_reason",
    [
        "Product decided all widgets must declare a color for the new catalog UI (#330).",
        (
            "Bound-hardening sweep: caps a previously-unconstrained string per the input-bounds "
            "policy; no legitimate client sends values anywhere near this length."
        ),
        "narrowed per the security review; see PR #333 for the audit trail",
    ],
)
def test_real_reasons_are_accepted(real_reason: str) -> None:
    assert (
        gate.reason_rejection(real_reason) is None
    ), f"{real_reason!r} should NOT have been rejected"


def test_placeholder_allowlist_reason_does_not_grant_opt_out(widget_repo: Path) -> None:
    """The bar for an allowlist `reason` is "explains WHY", not "is a non-empty string" —
    pin the exact class of failure this workspace has hit before (an evidence field that
    accepted any non-empty string accepted a placeholder as if it were a real answer).
    """
    changed = json.loads(json.dumps(BASELINE_SCHEMA))
    changed["required"] = ["name", "color"]
    _commit_schema_change(widget_repo, "require-color", changed, "make color required")

    allowlist = widget_repo / "placeholder_allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "file": "widgets/widget_request_schema.json",
                        "rule": "required",
                        "reason": "TODO",
                        "version": "9.9.9",
                        "pr": "#0",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--check",
            "--repo-root",
            str(widget_repo),
            "--base-ref",
            "master",
            "--head-ref",
            "require-color",
            "--allowlist",
            str(allowlist),
        ],
        env=_sanitized_git_env(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1, result.stdout
    assert "existing entry rejected" in result.stdout
    assert "placeholder" in result.stdout


def test_real_allowlist_reason_grants_opt_out(widget_repo: Path) -> None:
    changed = json.loads(json.dumps(BASELINE_SCHEMA))
    changed["required"] = ["name", "color"]
    _commit_schema_change(widget_repo, "require-color", changed, "make color required")

    allowlist = widget_repo / "real_allowlist.json"
    allowlist.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "file": "widgets/widget_request_schema.json",
                        "rule": "required",
                        "reason": (
                            "Product decided all widgets must declare a color for the new "
                            "catalog UI; reviewed in #330."
                        ),
                        "version": "9.9.9",
                        "pr": "#0",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--check",
            "--repo-root",
            str(widget_repo),
            "--base-ref",
            "master",
            "--head-ref",
            "require-color",
            "--allowlist",
            str(allowlist),
        ],
        env=_sanitized_git_env(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout


def test_exact_identity_allowlist_accepts_only_listed_findings() -> None:
    finding = gate.Finding(
        file="widgets/widget_request_schema.json",
        pointer="#/properties/color",
        rule="required",
        severity="BREAKING",
        role="request",
        message="color became required",
    )
    entry = {
        "file": finding.file,
        "rule": finding.rule,
        "findings": [
            _stored_identity(finding),
            _stored_identity(finding, pointer="#/properties/size"),
        ],
        "reason": "This deliberate v0 contract tightening was reviewed.",
        "version": "5.8.0",
        "pr": "#123",
    }

    assert gate.find_allow_entry(finding, [entry]).entry == entry
    assert (
        gate.find_allow_entry(
            finding,
            [
                {
                    **entry,
                    "findings": [
                        _stored_identity(finding, pointer="#/properties/size")
                    ],
                }
            ],
        ).entry
        is None
    )
    assert (
        gate.find_allow_entry(
            finding,
            [
                {
                    **entry,
                    "findings": [
                        _stored_identity(finding, pointer="#/properties/color/child")
                    ],
                }
            ],
        ).entry
        is None
    )


def test_exact_identity_allowlist_does_not_treat_invalid_entries_as_wildcards() -> None:
    finding = gate.Finding(
        file="widgets/widget_request_schema.json",
        pointer="#/properties/color",
        rule="required",
        severity="BREAKING",
        role="request",
        message="color became required",
    )
    base = {
        "file": finding.file,
        "rule": finding.rule,
        "reason": "This deliberate v0 contract tightening was reviewed.",
        "version": "5.8.0",
        "pr": "#123",
    }

    for findings in ([], None, [{"pointer": "#/properties/color"}, 7]):
        entry = {**base, "findings": findings}
        assert gate.find_allow_entry(finding, [entry]).entry is None

    pointer_only = {**base, "pointer": finding.pointer}
    assert gate.find_allow_entry(finding, [pointer_only]).entry is None


def _fixture_group(entry: dict) -> tuple[str, str, frozenset[str]]:
    identities = entry.get("findings")
    fingerprints = (
        (identity["fingerprint"] for identity in identities)
        if identities is not None
        else entry["fingerprints"]
    )
    return (
        entry["file"],
        entry["rule"],
        frozenset(fingerprints),
    )


def _select_historical_fixture_entries(
    entries: list[dict], fixture_entries: list[dict]
) -> list[dict]:
    """Select exactly the fixture-described groups, ignoring unrelated future entries."""
    expected_groups = [_fixture_group(entry) for entry in fixture_entries]
    assert len(expected_groups) == len(
        set(expected_groups)
    ), "historical fixture must not contain duplicate groups"
    expected_set = set(expected_groups)
    candidates: dict[tuple[str, str, frozenset[str]], list[dict]] = {}
    for entry in entries:
        if not entry.get("findings"):
            continue
        group = _fixture_group(entry)
        if group in expected_set:
            candidates.setdefault(group, []).append(entry)

    assert (
        set(candidates) == expected_set
    ), "fixture groups must have an exact entry bijection"
    assert all(
        len(group_entries) == 1 for group_entries in candidates.values()
    ), "each historical fixture group must select exactly one allowlist entry"
    return [candidates[group][0] for group in expected_groups]


def test_certified_agent_v0_allowlist_covers_historical_findings_only() -> None:
    """The v0 acknowledgements cover immutable history, not future identities.

    The fixture's source refs are provenance labels only.  Its digest fields are
    self-consistency/corruption checks over committed fixture content, not tamper resistance,
    provenance authentication, or trust evidence.  The test deliberately does not re-run the
    history replay, because doing so would make a regression depend on moving refs.
    """
    entries = gate.load_allowlist(
        REPO_ROOT / "scripts" / "breaking_schema_allowlist.json", REPO_ROOT
    )
    fixture = json.loads(
        (
            REPO_ROOT / "tests" / "data" / "certified_agent_v0_allowlist_history.json"
        ).read_text(encoding="utf-8")
    )
    # The PR #439 acknowledgement is deliberately outside this #440 census: it is
    # separately pinned below because it has a different historical source commit.
    exact_entries = _select_historical_fixture_entries(entries, fixture["entries"])
    assert len(exact_entries) == len(fixture["entries"])
    assert fixture["source_commit"] == "6235eb5d3b3e3a79064ad8e509305ec239dd8dc4"
    assert fixture["source_parent"] == "799641743d733a5bacaf9f2aa2ffb8a2c338bac4"
    assert (
        fixture["entries_sha256"]
        == hashlib.sha256(
            json.dumps(
                fixture["entries"], sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )
    fixture_without_content_digest = {
        key: value for key, value in fixture.items() if key != "content_sha256"
    }
    assert (
        fixture["content_sha256"]
        == hashlib.sha256(
            json.dumps(
                fixture_without_content_digest, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
    )
    assert all("pointer_prefix" not in entry for entry in exact_entries)

    expected_groups = [
        (entry["file"], entry["rule"], frozenset(entry["fingerprints"]))
        for entry in fixture["entries"]
    ]
    actual_groups = [_fixture_group(entry) for entry in exact_entries]
    assert actual_groups == expected_groups

    unrelated_future_finding = gate.Finding(
        file="certification/agent_certificate_v0_schema.json",
        pointer="#",
        rule="required",
        severity="BREAKING",
        role="conservative",
        message="synthetic unrelated future required field",
        subject="future_required_field",
        old=False,
        new=True,
    )
    unrelated_future_entry = {
        "file": unrelated_future_finding.file,
        "rule": unrelated_future_finding.rule,
        "findings": [_stored_identity(unrelated_future_finding)],
        "reason": "This reviewed future tightening is unrelated to the historical fixture.",
        "version": "5.8.0",
        "pr": "#999",
    }
    augmented_entries = _select_historical_fixture_entries(
        [*entries, unrelated_future_entry], fixture["entries"]
    )
    assert [_fixture_group(entry) for entry in augmented_entries] == actual_groups
    stored_fingerprints = [
        fingerprint
        for _, _, fingerprints in actual_groups
        for fingerprint in fingerprints
    ]
    historical_exact_identities = len(stored_fingerprints)
    assert len(set(stored_fingerprints)) == historical_exact_identities

    for entry in exact_entries:
        for identity in entry["findings"]:
            assert set(identity) - {"content"} == {
                "fingerprint",
                "new",
                "old",
                "pointer",
                "role",
                "subject",
            }
            finding = gate.Finding(
                file=entry["file"],
                pointer=identity["pointer"],
                rule=entry["rule"],
                severity="BREAKING",
                role=identity["role"],
                message="historical acknowledged finding",
                subject=identity["subject"],
                old=identity["old"],
                new=identity["new"],
                content=identity.get("content"),
            )
            assert identity["fingerprint"] == finding.fingerprint()
            assert gate.find_allow_entry(finding, entries).entry is entry
            future = gate.Finding(
                file=entry["file"],
                pointer=f"{identity['pointer']}/future-sibling",
                rule=entry["rule"],
                severity="BREAKING",
                role=identity["role"],
                message="synthetic future finding",
                subject=identity["subject"],
                old=identity["old"],
                new=identity["new"],
                content=identity.get("content"),
            )
            assert gate.find_allow_entry(future, entries).entry is None

    # Coverage census: derive the exact identity counts from the loaded allowlist and
    # root entry, then compare them with the fixture's recorded evidence.
    pr439 = fixture["pr439_audit_report"]
    assert pr439["source_commit"] == "799641743d733a5bacaf9f2aa2ffb8a2c338bac4"
    assert pr439["source_parent"] == "93364aece08b82acb4f8fab258c69d6996bf896f"
    root_entry = next(
        entry
        for entry in entries
        if entry.get("file") == pr439["file"]
        and entry.get("rule") == pr439["rule"]
        and entry.get("pr") == pr439["pr"]
    )
    assert "pointer_prefix" not in root_entry
    assert root_entry["findings"] == [pr439["identity"]]
    assert pr439["identity"]["fingerprint"] == gate._fingerprint_for_identity(
        pr439["file"],
        pr439["rule"],
        {
            key: pr439["identity"][key]
            for key in ("pointer", "role", "subject", "old", "new")
        },
    )
    combined_exact_identities = historical_exact_identities + len(
        root_entry["findings"]
    )
    census = fixture["coverage_census"]
    assert census["after"]["historical_exact_identities"] == historical_exact_identities
    assert census["after"]["combined_exact_identities"] == combined_exact_identities
    assert census["after"]["added_exact_identities"] == len(root_entry["findings"])
    audit_report = gate.Finding(
        file=pr439["file"],
        pointer=pr439["identity"]["pointer"],
        rule=pr439["rule"],
        severity="BREAKING",
        role=pr439["identity"]["role"],
        message="historical audit_report acknowledgement",
        subject=pr439["identity"]["subject"],
        old=pr439["identity"]["old"],
        new=pr439["identity"]["new"],
    )
    assert gate.find_allow_entry(audit_report, entries).entry is root_entry
    newly_unacknowledged = fixture["pr440_required_newly_unacknowledged"]
    assert (
        len(newly_unacknowledged)
        == census["after"]["pr440_required_newly_unacknowledged"]
    )
    newly_unacknowledged_fingerprints = []
    for identity in newly_unacknowledged:
        assert set(identity) == {
            "fingerprint",
            "new",
            "old",
            "pointer",
            "role",
            "subject",
        }
        finding = gate.Finding(
            file=pr439["file"],
            pointer=identity["pointer"],
            rule=pr439["rule"],
            severity="BREAKING",
            role=identity["role"],
            message="historical PR #440 newly-required finding",
            subject=identity["subject"],
            old=identity["old"],
            new=identity["new"],
            content=identity.get("content"),
        )
        assert identity["fingerprint"] == finding.fingerprint()
        # PR #443 left these five unacknowledged on purpose so that the develop->main
        # promotion would have to review them exactly. The 5.8.0 promotion (PR #448) did:
        # each is now matched by ONE exact-fingerprint entry, never a pointer_prefix wildcard.
        promotion_entry, promotion_identity = _exact_allow_entry(
            entries, pr439["file"], pr439["rule"], identity["pointer"], identity["fingerprint"]
        )
        assert gate.find_allow_entry(finding, entries).entry is promotion_entry
        assert "pointer_prefix" not in promotion_entry
        assert promotion_entry["pr"] == "https://github.com/Traigent/TraigentSchema/pull/448"
        assert promotion_entry["version"] == "5.8.0"
        assert promotion_identity["subject"] == identity["subject"]
        newly_unacknowledged_fingerprints.append(identity["fingerprint"])
    assert len(set(newly_unacknowledged_fingerprints)) == len(newly_unacknowledged)
    unrelated = gate.Finding(
        file=pr439["file"],
        pointer=pr439["identity"]["pointer"],
        rule=pr439["rule"],
        severity="BREAKING",
        role=pr439["identity"]["role"],
        message="synthetic unrelated newly-required field",
        subject="future_required_field",
        old=False,
        new=True,
    )
    assert gate.find_allow_entry(unrelated, entries).entry is None


def _exact_allow_entry(
    entries: list[dict], file: str, rule: str, pointer: str, fingerprint: str
) -> tuple[dict, dict]:
    """Return the one (entry, identity) pinned to this exact lookup key.

    (file, rule) alone is not unique -- this allowlist carries several entries for the
    same (file, rule), including entries with no ``findings`` at all (``pointer_prefix``
    opt-outs) and multiple distinct historical identities (see PR #439 vs PR #447 on
    ``agent_certificate_v0_schema.json`` / ``allOf_branch_count_changed``). Selecting by
    list position (``matches[-1]``) meant appending a future entry with the same
    (file, rule) -- including one with no findings -- could silently swap in a different
    fixture or raise IndexError. Matching on the full identity instead means an unrelated
    append, with or without findings, can never change what is selected; a missing or
    duplicated intended identity fails loudly here instead of silently downstream.
    """

    matches = []
    for entry in entries:
        if entry.get("file") != file or entry.get("rule") != rule:
            continue
        for identity in entry.get("findings") or []:
            if identity.get("pointer") == pointer and identity.get("fingerprint") == fingerprint:
                matches.append((entry, identity))
    assert matches, f"no allowlist entry for {file} / {rule} / {pointer} / {fingerprint}"
    assert len(matches) == 1, (
        f"expected exactly one allowlist entry for {file} / {rule} / {pointer} / "
        f"{fingerprint}, found {len(matches)}"
    )
    return matches[0]


def test_exact_identity_rejects_same_pointer_semantic_drift() -> None:
    entries = gate.load_allowlist(
        REPO_ROOT / "scripts" / "breaking_schema_allowlist.json", REPO_ROOT
    )

    required_entry, required_identity = _exact_allow_entry(
        entries,
        "certification/certificate_claim_payloads_v0_schema.json",
        "required",
        "#/allOf/0/oneOf/5/properties/params",
        "606ec6f8683fcaec80529342e014ee8d4463a2124884d95e6407dc858e81686a",
    )
    sibling = {**required_identity, "subject": "future_size"}

    pattern_entry, pattern_identity = _exact_allow_entry(
        entries,
        "certification/agent_certificate_v0_schema.json",
        "pattern",
        "#/properties/claims/items/properties/payload/oneOf/6/properties/params/properties/client_key_ref",
        "5cef859ecd3d1e634640a724f27c74b94beb2d33963dc9ca27e03bfa5a971a23",
    )
    pattern_drift = {**pattern_identity, "new": "^ckr:[A-Za-z0-9_-]{42}$"}

    branch_entry, branch_identity = _exact_allow_entry(
        entries,
        "certification/agent_certificate_v0_schema.json",
        "allOf_branch_count_changed",
        "#/properties/signatures/properties/unsigned_manifest/properties/document/properties/claims/items/allOf",
        "e1f8ee75d47b0e48f7a216ae228e9fcfd379058a076751f6fd04a6ce8f6286d1",
    )
    branch_drift = {**branch_identity, "new": branch_identity["new"] + 1}

    for entry, original, identity in (
        (required_entry, required_identity, sibling),
        (pattern_entry, pattern_identity, pattern_drift),
        (branch_entry, branch_identity, branch_drift),
    ):
        original_finding = gate.Finding(
            file=entry["file"],
            pointer=original["pointer"],
            rule=entry["rule"],
            severity="BREAKING",
            role=original["role"],
            message="original finding",
            subject=original["subject"],
            old=original["old"],
            new=original["new"],
            content=original.get("content"),
        )
        finding = gate.Finding(
            file=entry["file"],
            pointer=identity["pointer"],
            rule=entry["rule"],
            severity="BREAKING",
            role=identity["role"],
            message="synthetic same-pointer semantic drift",
            subject=identity["subject"],
            old=identity["old"],
            new=identity["new"],
            content=identity.get("content"),
        )
        assert finding.fingerprint() != original_finding.fingerprint()
        assert gate.find_allow_entry(finding, entries).entry is None


def test_exact_allow_entry_immune_to_unrelated_same_file_rule_appends() -> None:
    """(file, rule) is not unique, so selection must key on the full identity.

    Guards the Terra finding directly: this allowlist already carries several
    entries sharing (file, rule) -- see the PR #439 vs #447 root branch-count
    identities pinned in this same test below. Appending unrelated entries with
    that identical (file, rule), including one with no findings at all and
    another with a real but different identity, must not change which entry
    ``_exact_allow_entry`` selects. A missing or duplicated intended identity
    must fail loudly instead of silently substituting the wrong fixture.
    """
    entries = gate.load_allowlist(
        REPO_ROOT / "scripts" / "breaking_schema_allowlist.json", REPO_ROOT
    )
    file_name = "certification/agent_certificate_v0_schema.json"
    rule = "allOf_branch_count_changed"
    pointer = "#/allOf"
    fingerprint = "53180aaaf25ba89ad1cdaa3638df62dbd6a9a609ec0b3cf49fcdb26f9cf4c153"

    expected, expected_identity = _exact_allow_entry(
        entries, file_name, rule, pointer, fingerprint
    )
    assert expected["pr"] == "https://github.com/Traigent/TraigentSchema/pull/439"
    assert expected_identity is expected["findings"][0]

    empty_findings_entry = {
        "file": file_name,
        "rule": rule,
        "findings": [],
        "reason": "Synthetic no-findings entry appended for the regression test.",
        "version": "5.8.0",
        "pr": "#999001",
    }
    other_identity_entry = {
        "file": file_name,
        "rule": rule,
        "findings": [
            {
                "pointer": pointer,
                "role": "conservative",
                "subject": "allOf",
                "old": 2,
                "new": 5,
                "fingerprint": "0" * 64,
            }
        ],
        "reason": "Synthetic unrelated future identity appended for the regression test.",
        "version": "5.8.0",
        "pr": "#999002",
    }
    preceded_entry = {
        **expected,
        "findings": [other_identity_entry["findings"][0], expected_identity],
    }
    preceded, preceded_identity = _exact_allow_entry(
        [preceded_entry], file_name, rule, pointer, fingerprint
    )
    assert preceded is preceded_entry
    assert preceded_identity is preceded_entry["findings"][1]

    augmented = [*entries, empty_findings_entry, other_identity_entry]
    selected, selected_identity = _exact_allow_entry(
        augmented, file_name, rule, pointer, fingerprint
    )
    assert selected is expected
    assert selected_identity is expected_identity

    with pytest.raises(AssertionError, match="no allowlist entry"):
        _exact_allow_entry(entries, file_name, rule, pointer, "0" * 64)

    with pytest.raises(AssertionError, match="expected exactly one allowlist entry"):
        _exact_allow_entry([*entries, dict(expected)], file_name, rule, pointer, fingerprint)

    duplicate_identity_entry = {
        **expected,
        "findings": [expected_identity, dict(expected_identity)],
    }
    with pytest.raises(AssertionError, match="expected exactly one allowlist entry"):
        _exact_allow_entry([duplicate_identity_entry], file_name, rule, pointer, fingerprint)


def test_root_branch_count_allowlist_entries_are_exact() -> None:
    entries = gate.load_allowlist(
        REPO_ROOT / "scripts" / "breaking_schema_allowlist.json", REPO_ROOT
    )
    file_name = "certification/agent_certificate_v0_schema.json"
    rule = "allOf_branch_count_changed"
    pr439 = "https://github.com/Traigent/TraigentSchema/pull/439"
    pr447 = "https://github.com/Traigent/TraigentSchema/pull/447"
    expected = {
        pr439: {
            "pointer": "#/allOf",
            "role": "conservative",
            "subject": "allOf",
            "old": 1,
            "new": 2,
            "content": {
                "new": "f2ab25b864abb378524000217047e6be22211a2e5d3149e4363c2f42ae40a7e7",
                "old": "8e1074bb0d896f302cf766100d779ddd39b249ae15f8e856e86be2290830cd38",
            },
            "fingerprint": "53180aaaf25ba89ad1cdaa3638df62dbd6a9a609ec0b3cf49fcdb26f9cf4c153",
        },
        pr447: {
            "pointer": "#/allOf",
            "role": "conservative",
            "subject": "allOf",
            "old": 3,
            "new": 2,
            "content": {
                "new": "d752a0da589ccbbd91b8901a96ff149eb283ee08a934e1fa72419a8fbe3ba212",
                "old": "1fe07dcc2c5fdc9dac27d672f901db7c47a9c4a21628b825a56174d0abcfddb1",
            },
            "fingerprint": "357487a0411b958f5781239ecdfd92fbc309618d29896ff5ee5afe3fc862cce3",
        },
    }
    root_entries = {
        entry["pr"]: entry
        for entry in entries
        if entry.get("file") == file_name
        and entry.get("rule") == rule
        and entry.get("pr") in expected
        and entry.get("findings")
        and entry["findings"][0].get("pointer") == "#/allOf"
    }
    assert set(root_entries) == set(expected)
    for pr, entry in root_entries.items():
        assert "pointer_prefix" not in entry
        assert entry["findings"] == [expected[pr]]
        identity = entry["findings"][0]
        finding = gate.Finding(
            file=file_name,
            pointer=identity["pointer"],
            rule=rule,
            severity="BREAKING",
            role=identity["role"],
            message="exact historical root branch-count finding",
            subject=identity["subject"],
            old=identity["old"],
            new=identity["new"],
            content=identity.get("content"),
        )
        assert identity["fingerprint"] == finding.fingerprint()
        assert gate.find_allow_entry(finding, entries).entry is entry

    future = gate.Finding(
        file=file_name,
        pointer="#/allOf",
        rule=rule,
        severity="BREAKING",
        role="conservative",
        message="future root branch-count finding",
        subject="allOf",
        old=2,
        new=3,
    )
    assert future.fingerprint() == (
        "916507b533a60bc52f4966d5715f195c39603ef3cfcb812d4abf782ca540decd"
    )
    assert gate.find_allow_entry(future, entries).entry is None


def test_structured_acknowledgement_requires_an_exact_nonempty_rule() -> None:
    finding = gate.Finding(
        file="widgets/widget_request_schema.json",
        pointer="#/properties/color",
        rule="required",
        severity="BREAKING",
        role="request",
        message="color became required",
        subject="color",
        old=False,
        new=True,
    )
    base = {
        "file": finding.file,
        "reason": "This deliberate v0 contract tightening was reviewed.",
        "version": "5.8.0",
        "pr": "#123",
        "findings": [_stored_identity(finding)],
    }
    missing_rule = {key: value for key, value in base.items() if key != "rule"}
    for entry in (missing_rule, {**base, "rule": ""}, {**base, "rule": "type"}):
        assert gate.find_allow_entry(finding, [entry]).entry is None


def test_structured_identity_does_not_alias_booleans_and_integers() -> None:
    finding = gate.Finding(
        file="widgets/widget_request_schema.json",
        pointer="#/properties/color",
        rule="required",
        severity="BREAKING",
        role="request",
        message="color became required",
        subject="color",
        old=False,
        new=True,
    )
    entry = {
        "file": finding.file,
        "rule": finding.rule,
        "reason": "This deliberate v0 contract tightening was reviewed.",
        "version": "5.8.0",
        "pr": "#123",
        "findings": [_stored_identity(finding)],
    }

    old_alias = _stored_identity(finding, old=0)
    new_alias = _stored_identity(finding, new=1)
    assert gate.find_allow_entry(finding, [entry]).entry is entry
    assert (
        gate.find_allow_entry(finding, [{**entry, "findings": [old_alias]}]).entry
        is None
    )
    assert (
        gate.find_allow_entry(finding, [{**entry, "findings": [new_alias]}]).entry
        is None
    )


def test_structured_acknowledgement_requires_a_verified_fingerprint() -> None:
    finding = gate.Finding(
        file="widgets/widget_request_schema.json",
        pointer="#/properties/color",
        rule="required",
        severity="BREAKING",
        role="request",
        message="color became required",
        subject="color",
        old=False,
        new=True,
    )
    stored = _stored_identity(finding)
    entry = {
        "file": finding.file,
        "rule": finding.rule,
        "reason": "This deliberate v0 contract tightening was reviewed.",
        "version": "5.8.0",
        "pr": "#123",
        "findings": [stored],
    }

    missing = {key: value for key, value in stored.items() if key != "fingerprint"}
    identity_tamper = {**stored, "subject": "future_size"}
    digest_tamper = {**stored, "fingerprint": "0" * 64}
    malformed_digest = {**stored, "fingerprint": True}
    for candidate in (missing, identity_tamper, digest_tamper, malformed_digest):
        assert (
            gate.find_allow_entry(finding, [{**entry, "findings": [candidate]}]).entry
            is None
        )

    assert gate.find_allow_entry(finding, [entry]).entry is entry


def test_run_git_ignores_inherited_git_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression for the incident this module's helpers must never repeat: a
    pre-push hook (or any parent process) can export GIT_DIR/GIT_WORK_TREE for
    ITS OWN repo. `git -C <path>` does NOT override an inherited GIT_DIR, so a
    naive `subprocess.run(["git", "-C", tmp_repo, ...])` silently operates on the
    inherited repo instead of tmp_repo — which is exactly how a previous run of
    these fixtures wrote 27 baseline commits onto this branch's real ref, index,
    and config.

    Reproduce the hazard with a SACRIFICIAL repo (created fresh under tmp_path,
    never this worktree or its common gitdir) standing in for "the caller's
    repo", poison the process environment with its GIT_DIR/GIT_WORK_TREE, and
    prove `_run_git` still only ever touches the repo path it was explicitly
    given — never the sacrificial one."""
    sacrificial_repo = tmp_path / "sacrificial_repo"
    sacrificial_repo.mkdir()
    _run_git(sacrificial_repo, "init", "-q")
    _run_git(sacrificial_repo, "config", "user.email", "sacrificial@example.com")
    _run_git(sacrificial_repo, "config", "user.name", "Sacrificial Caller Repo")
    (sacrificial_repo / "seed.txt").write_text("seed\n", encoding="utf-8")
    _run_git(sacrificial_repo, "add", "-A")
    _run_git(sacrificial_repo, "commit", "-q", "-m", "sacrificial baseline")

    sacrificial_head_before = _run_git(sacrificial_repo, "rev-parse", "HEAD").strip()
    sacrificial_config_before = _run_git(
        sacrificial_repo, "config", "--local", "--list"
    )
    sacrificial_log_count_before = _run_git(
        sacrificial_repo, "rev-list", "--count", "HEAD"
    ).strip()
    sacrificial_index_before = (sacrificial_repo / ".git" / "index").read_bytes()

    # Poison the process environment the way an inheriting caller (e.g. an
    # unsanitized pre-push hook) would: GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE
    # pinned to the sacrificial repo, for the entire duration of the target
    # repo's setup.
    monkeypatch.setenv("GIT_DIR", str(sacrificial_repo / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(sacrificial_repo))
    monkeypatch.setenv("GIT_INDEX_FILE", str(sacrificial_repo / ".git" / "index"))

    target_repo = tmp_path / "target_repo"
    target_repo.mkdir()
    _run_git(target_repo, "init", "-q")
    _run_git(target_repo, "config", "user.email", "target@example.com")
    _run_git(target_repo, "config", "user.name", "Target Repo")
    (target_repo / "file.txt").write_text("hello\n", encoding="utf-8")
    _run_git(target_repo, "add", "-A")
    _run_git(target_repo, "commit", "-q", "-m", "target baseline")

    # _run_git must have initialized and committed in tmp_path/target_repo only.
    assert (target_repo / ".git").is_dir()
    target_head = _run_git(target_repo, "rev-parse", "HEAD").strip()
    assert target_head != sacrificial_head_before

    # The sacrificial repo's ref, commit count, and config must be untouched —
    # not overwritten, not gained a second commit, not reconfigured.
    assert (
        _run_git(sacrificial_repo, "rev-parse", "HEAD").strip()
        == sacrificial_head_before
    )
    assert (
        _run_git(sacrificial_repo, "rev-list", "--count", "HEAD").strip()
        == sacrificial_log_count_before
    )
    assert (
        _run_git(sacrificial_repo, "config", "--local", "--list")
        == sacrificial_config_before
    )
    # The sacrificial index must be byte-for-byte unchanged -- not just "same
    # HEAD", but never staged/rewritten by the target repo's add/commit calls.
    assert (
        sacrificial_repo / ".git" / "index"
    ).read_bytes() == sacrificial_index_before
    # The target's file must never have landed in the sacrificial working tree.
    assert not (sacrificial_repo / "file.txt").exists()


def test_pre_push_hook_clears_git_local_env_before_exec(tmp_path: Path) -> None:
    """End-to-end regression at the actual hook boundary (not just the helper):
    install the real tracked hooks/pre-push into a disposable tmp_path repo,
    push it to a disposable tmp_path bare remote with GIT_DIR/GIT_WORK_TREE/
    GIT_INDEX_FILE already pinned to that same source repo -- the "pusher's
    local Git environment... still exported" scenario the hook's own comment
    describes -- and prove the hook clears every `git rev-parse
    --local-env-vars` name before exec'ing the gate.

    A source-repo-local scripts/local_gate.sh stub (this test's own, not the
    real gate) stands in for the real gate: it fails and writes a "still set"
    marker if ANY such name is still exported when it starts, and writes "ok"
    otherwise. This is network-free and touches only tmp_path repos -- the
    poisoned env vars are set only on the dict passed to this one `git push`
    subprocess call, never on the test process's own os.environ.
    """
    source_repo = tmp_path / "push_source_repo"
    bare_remote = tmp_path / "push_remote.git"
    source_repo.mkdir(parents=True)
    bare_remote.mkdir(parents=True)

    _run_git(source_repo, "init", "-q")
    _run_git(source_repo, "config", "user.email", "pusher@example.com")
    _run_git(source_repo, "config", "user.name", "Pusher Repo")
    (source_repo / "README.md").write_text("hook boundary test\n", encoding="utf-8")
    _run_git(source_repo, "add", "-A")
    _run_git(source_repo, "commit", "-q", "-m", "initial commit")
    current_branch = _run_git(source_repo, "branch", "--show-current").strip()

    _run_git(bare_remote, "init", "--bare", "-q")
    _run_git(source_repo, "remote", "add", "origin", str(bare_remote))

    hook_src = REPO_ROOT / "hooks" / "pre-push"
    hook_dst = source_repo / ".git" / "hooks" / "pre-push"
    hook_dst.write_bytes(hook_src.read_bytes())
    hook_dst.chmod(0o755)

    marker = tmp_path / "hook_ran_clean.marker"
    gate_stub = source_repo / "scripts" / "local_gate.sh"
    gate_stub.parent.mkdir(parents=True)
    gate_stub.write_text(
        "#!/usr/bin/env bash\n"
        "set -uo pipefail\n"
        'marker="${PRE_PUSH_TEST_MARKER:?PRE_PUSH_TEST_MARKER not set}"\n'
        "while IFS= read -r name; do\n"
        '  [[ -z "$name" ]] && continue\n'
        '  if [[ -n "${!name-}" ]]; then\n'
        '    printf \'still set: %s=%s\\n\' "$name" "${!name}" > "$marker"\n'
        "    exit 1\n"
        "  fi\n"
        'done <<< "$(git rev-parse --local-env-vars)"\n'
        'echo ok > "$marker"\n',
        encoding="utf-8",
    )
    gate_stub.chmod(0o755)

    repo_root_head_before = _run_git(REPO_ROOT, "rev-parse", "HEAD").strip()

    push_env = dict(_sanitized_git_env())
    push_env["PRE_PUSH_TEST_MARKER"] = str(marker)
    # The exact hazard hooks/pre-push's own comment describes: the pusher's
    # shell already has this repo's local git-env vars exported (e.g. from a
    # prior script/hook in the same session) when `git push` runs.
    push_env["GIT_DIR"] = str(source_repo / ".git")
    push_env["GIT_WORK_TREE"] = str(source_repo)
    push_env["GIT_INDEX_FILE"] = str(source_repo / ".git" / "index")

    result = subprocess.run(
        ["git", "push", "origin", current_branch],
        cwd=source_repo,
        capture_output=True,
        text=True,
        env=push_env,
    )

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    assert (
        marker.exists()
    ), "scripts/local_gate.sh stub never ran -- hook did not reach exec"
    assert marker.read_text().strip() == "ok", marker.read_text()

    # No repo/ref/config/index outside tmp_path was touched: this worktree's
    # own HEAD (read via a call with a sanitized, not poisoned, env) is
    # unchanged.
    assert _run_git(REPO_ROOT, "rev-parse", "HEAD").strip() == repo_root_head_before


# --- response schema wrapped in allOf that still contains the old schema (#616) -------------
def _endpoints_doc(schema: dict) -> dict:
    return {
        "paths": {
            "/w": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"409": {"content": {"application/json": {"schema": schema}}}},
                }
            }
        }
    }


def _allof_repo(tmp_path: Path, name: str, baseline_schema: dict) -> tuple[Path, str]:
    filename = "widget_endpoints.json"
    repo = _response_schema_repo(tmp_path / name, filename, _endpoints_doc(baseline_schema))
    return repo, filename


ENVELOPE_REF = {"$ref": "./widget_response_schema.json"}


def _allof_envelope_repo(tmp_path: Path, name: str) -> tuple[Path, str]:
    repo, filename = _allof_repo(tmp_path, name, ENVELOPE_REF)
    (repo / "traigent_schema" / "schemas" / "widgets" / "widget_response_schema.json").write_text(
        json.dumps(_closed_response_schema(), indent=2) + "\n", encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "add envelope")
    return repo, filename


def test_response_allof_containing_old_ref_is_not_breaking(tmp_path: Path) -> None:
    repo, filename = _allof_envelope_repo(tmp_path, "ok")
    extra = {"type": "object", "properties": {"id": {"type": "string"}}}
    _commit_schema_change(
        repo, "wrap", _endpoints_doc({"allOf": [extra, ENVELOPE_REF]}), "wrap", filename
    )
    result = _run_gate(repo, "master", "wrap")
    assert result.returncode == 0, result.stdout
    assert "response_narrowed_by_allof" in result.stdout


@pytest.mark.parametrize(
    ("wrapped", "expected_finding"),
    [
        ({"allOf": [{}]}, "additionalProperties closed"),
        (
            {"allOf": [{"type": "object", "properties": {"id": {"type": "string"}}}]},
            "additionalProperties closed",
        ),
        # a sibling constraint keyword next to allOf: the shortcut must not fire, so the
        # root-level findings are reported exactly as before
        ({"allOf": [ENVELOPE_REF], "type": "object"}, "additionalProperties closed"),
        ({"allOf": [ENVELOPE_REF], "required": ["extra"]}, "additionalProperties closed"),
    ],
)
def test_response_allof_without_the_old_schema_stays_breaking(
    tmp_path: Path, wrapped: dict, expected_finding: str
) -> None:
    repo, filename = _allof_envelope_repo(tmp_path, "bad")
    _commit_schema_change(repo, "wrap", _endpoints_doc(wrapped), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert result.returncode == 1, result.stdout
    assert "response_narrowed_by_allof" not in result.stdout
    assert "[BREAKING]" in result.stdout
    assert expected_finding in result.stdout, result.stdout


def test_narrowing_inside_a_oneof_branch_is_not_waved_through(tmp_path: Path) -> None:
    old = {"oneOf": [{"type": "string"}, {"enum": ["a"]}]}
    new = {"oneOf": [{"allOf": [{"type": "string"}, {"enum": ["b"]}]}, {"enum": ["a"]}]}
    repo, filename = _allof_repo(tmp_path, "oneof", old)
    _commit_schema_change(repo, "wrap", _endpoints_doc(new), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert result.returncode == 1, result.stdout
    assert "response_narrowed_by_allof" not in result.stdout


def test_wrapped_ref_whose_target_widened_is_breaking(tmp_path: Path) -> None:
    ref = {"$ref": "./widget_defs.json#/definitions/X"}
    old_defs = {"definitions": {"X": {"type": "string"}}}
    repo, filename = _allof_repo(tmp_path, "widen", ref)
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    (schema_dir / "widget_defs.json").write_text(json.dumps(old_defs), encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "defs")
    _run_git(repo, "checkout", "-q", "-b", "widen")
    (schema_dir / "widget_defs.json").write_text(
        json.dumps({"definitions": {"X": {"type": ["string", "integer"]}}}), encoding="utf-8"
    )
    (schema_dir / filename).write_text(
        json.dumps(_endpoints_doc({"allOf": [ref, {"type": "object"}]})), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "widen and wrap")
    _run_git(repo, "checkout", "-q", "master")
    result = _run_gate(repo, "master", "widen")
    assert result.returncode == 1, result.stdout
    assert "response_narrowed_by_allof" not in result.stdout


def test_ref_shaped_literals_in_enum_are_not_resolved(tmp_path: Path) -> None:
    old = {"type": "object", "enum": [{"$ref": "./a.json"}]}
    new = {"allOf": [{"type": "object", "enum": [{"$ref": "./b.json"}]}]}
    repo, filename = _allof_repo(tmp_path, "literal", old)
    _commit_schema_change(repo, "wrap", _endpoints_doc(new), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout
    # identical to the pre-change checker for this change: 1 unacknowledged BREAKING, exit 1
    assert result.returncode == 1, result.stdout
    assert "BREAKING (unacked):   1" in result.stdout, result.stdout


def test_typed_equality_distinguishes_true_from_one(tmp_path: Path) -> None:
    repo, filename = _allof_repo(tmp_path, "typed", {"enum": [1]})
    _commit_schema_change(
        repo, "wrap", _endpoints_doc({"allOf": [{"enum": [True]}]}), "wrap", filename
    )
    result = _run_gate(repo, "master", "wrap")
    # {"enum":[1]} and {"enum":[true]} must NOT be equal, so the shortcut does not fire and the
    # ordinary comparison reports its own findings. (The ordinary comparator classifies a
    # response enum removal as INFO, so exit status is the comparator's, not asserted here.)
    assert "response_narrowed_by_allof" not in result.stdout
    assert "enum constraint removed entirely" in result.stdout, result.stdout


def test_request_side_allof_narrowing_stays_breaking(tmp_path: Path) -> None:
    filename = "widget_endpoints.json"
    base = {
        "paths": {
            "/w": {
                "post": {
                    "requestBody": {"content": {"application/json": {"schema": ENVELOPE_REF}}},
                    "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}},
                }
            }
        }
    }
    repo = _response_schema_repo(tmp_path / "req", filename, base)
    (repo / "traigent_schema" / "schemas" / "widgets" / "widget_response_schema.json").write_text(
        json.dumps(_closed_response_schema(), indent=2) + "\n", encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "add schema")
    changed = json.loads(json.dumps(base))
    changed["paths"]["/w"]["post"]["requestBody"]["content"]["application/json"]["schema"] = {
        "allOf": [ENVELOPE_REF, {"type": "object", "required": ["id"]}]
    }
    _commit_schema_change(repo, "req-wrap", changed, "req wrap", filename)
    result = _run_gate(repo, "master", "req-wrap")
    assert result.returncode == 1, result.stdout
    assert "response_narrowed_by_allof" not in result.stdout


def _closed_obj(prop: dict) -> dict:
    return {"type": "object", "additionalProperties": False, "properties": {"a": prop}}


@pytest.mark.parametrize("keyword", ["$id", "id", "$anchor", "$dynamicAnchor", "$recursiveAnchor"])
def test_base_changing_keyword_disables_the_allof_shortcut(tmp_path: Path, keyword: str) -> None:
    old = _closed_obj({keyword: "urn:n", "type": "string"})
    repo, filename = _allof_repo(tmp_path, "kw", old)
    _commit_schema_change(repo, "wrap", _endpoints_doc({"allOf": [old]}), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


def test_same_wrap_without_a_base_changing_keyword_still_gets_the_shortcut(tmp_path: Path) -> None:
    old = _closed_obj({"type": "string"})
    repo, filename = _allof_repo(tmp_path, "nokw", old)
    _commit_schema_change(repo, "wrap", _endpoints_doc({"allOf": [old]}), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert result.returncode == 0, result.stdout
    assert "response_narrowed_by_allof" in result.stdout


def test_nested_id_whose_type_changes_is_breaking(tmp_path: Path) -> None:
    old = _closed_obj({"$id": "urn:n", "type": "string"})
    new = {"allOf": [_closed_obj({"$id": "urn:n", "type": "integer"})]}
    repo, filename = _allof_repo(tmp_path, "nested", old)
    _commit_schema_change(repo, "wrap", _endpoints_doc(new), "wrap", filename)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout
    assert result.returncode == 1, result.stdout


def test_root_id_must_equal_the_registry_key_used_to_reach_the_file() -> None:
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    uri = "https://schemas.example/x.json"
    doc = {"$id": uri, "type": "string"}
    reg = Registry().with_resource(uri, Resource(contents=doc, specification=DRAFT7))
    # root $id equal to the key it was reached by: allowed
    gate._refuse_base_changing_keywords(reg.contents(uri), uri, reg)
    assert gate._fully_resolved_bytes({"$ref": uri}, uri, reg)
    # same root reached under a different key: refused (the $id does not match)
    with pytest.raises(gate.UnresolvedRef):
        gate._refuse_base_changing_keywords(doc, "https://schemas.example/other.json", reg)
    # a non-root node carrying the same $id: refused
    with pytest.raises(gate.UnresolvedRef):
        gate._refuse_base_changing_keywords({"$id": uri}, uri, reg)


def _ref_sibling_repo(tmp_path: Path, name: str, ref_node: dict) -> tuple[Path, Path, str]:
    repo, filename = _allof_repo(tmp_path, name, ref_node)
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    (schema_dir / "sub").mkdir()
    closed = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string"}},
    }
    (schema_dir / "x_schema.json").write_text(json.dumps(closed), encoding="utf-8")
    (schema_dir / "sub" / "x_schema.json").write_text(json.dumps(closed), encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "targets")
    return repo, schema_dir, filename


def test_ref_with_id_sibling_does_not_get_the_shortcut(tmp_path: Path) -> None:
    node = {"$id": "sub/", "$ref": "x_schema.json"}
    repo, schema_dir, filename = _ref_sibling_repo(tmp_path, "idsib", node)
    _run_git(repo, "checkout", "-q", "-b", "wrap")
    widened = {"$schema": "http://json-schema.org/draft-07/schema#", "type": "object",
               "additionalProperties": False,
               "properties": {"a": {"type": ["string", "integer"]}}}
    (schema_dir / "sub" / "x_schema.json").write_text(json.dumps(widened), encoding="utf-8")
    (schema_dir / filename).write_text(
        json.dumps(_endpoints_doc({"allOf": [node, {"type": "object"}]})), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "wrap")
    _run_git(repo, "checkout", "-q", "master")
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout
    assert "unresolved_ref" not in result.stdout, result.stdout  # failed on the guard, not on a typo
    assert "additionalProperties closed" in result.stdout, result.stdout


@pytest.mark.parametrize("sibling", [{"$anchor": "a"}, {"type": "object"}, {"$recursiveRef": "#"}])
def test_ref_with_non_annotation_sibling_does_not_get_the_shortcut(
    tmp_path: Path, sibling: dict
) -> None:
    node = {"$ref": "./x_schema.json", **sibling}
    repo, _dir, filename = _ref_sibling_repo(tmp_path, "sib", node)
    _commit_schema_change(
        repo, "wrap", _endpoints_doc({"allOf": [node, {"type": "object"}]}), "wrap", filename
    )
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout


def test_ref_with_only_annotation_siblings_is_still_eligible(tmp_path: Path) -> None:
    node = {**ENVELOPE_REF, "description": "the envelope"}
    repo, filename = _allof_envelope_repo(tmp_path, "ann")
    _commit_schema_change(
        repo, "wrap", _endpoints_doc({"allOf": [node, {"type": "object"}]}), "wrap", filename
    )
    result = _run_gate(repo, "master", "wrap")
    assert result.returncode == 0, result.stdout
    assert "response_narrowed_by_allof" in result.stdout


def test_pointer_crossing_an_ancestor_with_id_gets_no_shortcut(tmp_path: Path) -> None:
    """defs.json#/definitions/container/definitions/response crosses `container`, which
    carries "$id": "sub/". Its inner {"$ref": "x_schema.json"} really means sub/x_schema.json,
    but a walker blind to the ancestor resolves it to widgets/x_schema.json (unchanged) and
    would wave the wrap through. Only sub/x_schema.json widens."""
    draft = "http://json-schema.org/draft-07/schema#"
    closed = {
        "$schema": draft,
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string"}},
    }
    widened = {**closed, "properties": {"a": {"type": ["string", "integer"]}}}
    node = {"$ref": "./widget_defs_schema.json#/definitions/container/definitions/response"}
    defs = {
        "$schema": draft,
        "definitions": {
            "container": {
                "$id": "sub/",
                "definitions": {"response": {"$ref": "x_schema.json"}},
            }
        },
    }
    repo, filename = _allof_repo(tmp_path, "container", node)
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    (schema_dir / "sub").mkdir()
    (schema_dir / "widget_defs_schema.json").write_text(json.dumps(defs), encoding="utf-8")
    (schema_dir / "x_schema.json").write_text(json.dumps(closed), encoding="utf-8")
    (schema_dir / "sub" / "x_schema.json").write_text(json.dumps(closed), encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "defs")
    _run_git(repo, "checkout", "-q", "-b", "wrap")
    (schema_dir / "sub" / "x_schema.json").write_text(json.dumps(widened), encoding="utf-8")
    (schema_dir / filename).write_text(
        json.dumps(_endpoints_doc({"allOf": [node, {"type": "object"}]})), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "wrap")
    _run_git(repo, "checkout", "-q", "master")
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert "unresolved_ref" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


def test_property_named_id_does_not_disable_the_shortcut() -> None:
    assert not gate._document_changes_base(
        {"$id": "u", "properties": {"id": {"type": "string"}, "$id": {"type": "string"}}}
    )
    assert gate._document_changes_base({"$id": "u", "definitions": {"c": {"$id": "sub/"}}})
    assert gate._document_changes_base({"$anchor": "a"})


def _wrapped_ref_widening_repo(tmp_path: Path, name: str, holder: dict) -> Path:
    """`holder` is the response schema embedding a $ref to widgets/t_schema.json, which widens
    string -> [string, integer] on the head side; the head wraps the holder in allOf."""
    draft = "http://json-schema.org/draft-07/schema#"
    repo, filename = _allof_repo(tmp_path, name, holder)
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    (schema_dir / "t_schema.json").write_text(
        json.dumps({"$schema": draft, "type": "string"}), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "target")
    _run_git(repo, "checkout", "-q", "-b", "wrap")
    (schema_dir / "t_schema.json").write_text(
        json.dumps({"$schema": draft, "type": ["string", "integer"]}), encoding="utf-8"
    )
    (schema_dir / filename).write_text(
        json.dumps(_endpoints_doc({"allOf": [holder, {"type": "object"}]})), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "wrap")
    _run_git(repo, "checkout", "-q", "master")
    return repo


def test_ref_under_prefixitems_whose_target_widened_is_breaking(tmp_path: Path) -> None:
    holder = {"type": "array", "prefixItems": [{"$ref": "./t_schema.json"}]}
    repo = _wrapped_ref_widening_repo(tmp_path, "prefix", holder)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


def test_unknown_keyword_beside_a_wrapped_schema_disables_the_shortcut(tmp_path: Path) -> None:
    holder = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string"}},
        "foo": {"$ref": "./t_schema.json"},
    }
    repo = _wrapped_ref_widening_repo(tmp_path, "foo", holder)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


def test_keyword_classification_is_closed() -> None:
    for key in ("prefixItems", "unevaluatedItems", "unevaluatedProperties", "if", "dependentSchemas"):
        assert key in gate._SCHEMA_KEYWORDS | gate._SCHEMA_MAP_KEYWORDS
    assert not (gate._LITERAL_KEYWORDS & (gate._SCHEMA_KEYWORDS | gate._SCHEMA_MAP_KEYWORDS))
    assert gate._is_literal_keyword("x-content-class")
    assert not gate._is_literal_keyword("foo")


def test_discriminator_mapping_to_a_widened_child_gets_no_shortcut(tmp_path: Path) -> None:
    holder = {
        "type": "object",
        "discriminator": {"propertyName": "kind", "mapping": {"child": "./t_schema.json"}},
    }
    repo = _wrapped_ref_widening_repo(tmp_path, "discr", holder)
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


def test_discriminator_is_not_a_literal_keyword() -> None:
    assert not gate._is_literal_keyword("discriminator")


def test_dependencies_array_values_are_kept_literally() -> None:
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    uri = "https://schemas.example/d.json"
    doc = {"$id": uri, "dependencies": {"a": ["b"], "c": {"type": "string"}}}
    reg = Registry().with_resource(uri, Resource(contents=doc, specification=DRAFT7))
    out = gate._fully_resolved_bytes({"$ref": uri}, uri, reg)
    assert out is not None
    assert b'"a":["b"]' in out and b'"c":{"type":"string"}' in out


def test_dialect_switch_in_a_referenced_document_gets_no_shortcut(tmp_path: Path) -> None:
    d7, d4 = "http://json-schema.org/draft-07/schema#", "http://json-schema.org/draft-04/schema#"
    obj = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "array", "contains": {"type": "string"}}},
    }

    def defs(dialect: str) -> dict:
        return {"$schema": dialect, "definitions": {"obj": obj}}

    node = {"$ref": "./widget_defs_schema.json#/definitions/obj"}
    repo, filename = _allof_repo(tmp_path, "dialect", node)
    schema_dir = repo / "traigent_schema" / "schemas" / "widgets"
    (schema_dir / "widget_defs_schema.json").write_text(json.dumps(defs(d7)), encoding="utf-8")
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "defs")
    _run_git(repo, "checkout", "-q", "-b", "wrap")
    (schema_dir / "widget_defs_schema.json").write_text(json.dumps(defs(d4)), encoding="utf-8")
    (schema_dir / filename).write_text(
        json.dumps(_endpoints_doc({"allOf": [node, {"type": "object"}]})), encoding="utf-8"
    )
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "wrap")
    _run_git(repo, "checkout", "-q", "master")
    result = _run_gate(repo, "master", "wrap")
    assert "response_narrowed_by_allof" not in result.stdout, result.stdout
    assert "unresolved_ref" not in result.stdout, result.stdout
    assert result.returncode == 1, result.stdout


# --- response-level $ref is resolved before bodies are compared ------------------------------
def _ref_response_doc(response: dict, component: dict | None = None) -> dict:
    doc: dict = {
        "paths": {"/w": {"get": {"responses": {"200": response}}}},
    }
    if component is not None:
        doc["components"] = {"responses": {"Widget": component}}
    return doc


def _widget_component(required: list[str], media_type: str = "application/json") -> dict:
    return {
        "description": "widget",
        "content": {
            media_type: {
                "schema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
                    "required": required,
                }
            }
        },
    }


_WIDGET_REF = {"$ref": "#/components/responses/Widget"}


def _response_ref_gate(tmp_path: Path, name: str, old_doc: dict, new_doc: dict):
    filename = "widget_endpoints.json"
    repo = _response_schema_repo(tmp_path / name, filename, old_doc)
    _commit_schema_change(repo, "change", new_doc, "change", filename)
    return _run_gate(repo, "master", "change")


def test_response_ref_component_dropping_required_field_is_breaking(tmp_path: Path) -> None:
    old = _ref_response_doc(_WIDGET_REF, _widget_component(["id", "name"]))
    new = _ref_response_doc(_WIDGET_REF, _widget_component(["id"]))
    result = _response_ref_gate(tmp_path, "drop", old, new)
    assert result.returncode == 1, result.stdout
    assert "role=response" in result.stdout, result.stdout


def test_response_ref_component_media_type_change_is_breaking(tmp_path: Path) -> None:
    old = _ref_response_doc(_WIDGET_REF, _widget_component(["id"]))
    new = _ref_response_doc(_WIDGET_REF, _widget_component(["id"], "application/xml"))
    result = _response_ref_gate(tmp_path, "media", old, new)
    assert result.returncode == 1, result.stdout
    assert "schema_removed" in result.stdout, result.stdout


def test_identical_response_ref_has_no_finding(tmp_path: Path) -> None:
    doc = _ref_response_doc(_WIDGET_REF, _widget_component(["id", "name"]))
    other = json.loads(json.dumps(doc))
    other["info"] = {"title": "unrelated edit"}
    result = _response_ref_gate(tmp_path, "same", doc, other)
    assert result.returncode == 0, result.stdout
    assert "role=response" not in result.stdout, result.stdout


def test_response_changing_from_inline_to_equivalent_ref_is_not_breaking(tmp_path: Path) -> None:
    component = _widget_component(["id", "name"])
    old = _ref_response_doc(json.loads(json.dumps(component)))
    new = _ref_response_doc(_WIDGET_REF, component)
    result = _response_ref_gate(tmp_path, "inline2ref", old, new)
    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout, result.stdout


def test_unresolvable_response_ref_is_breaking_not_silent(tmp_path: Path) -> None:
    old = _ref_response_doc(_WIDGET_REF, _widget_component(["id"]))
    new = _ref_response_doc({"$ref": "#/components/responses/Missing"}, _widget_component(["id"]))
    result = _response_ref_gate(tmp_path, "dangling", old, new)
    assert result.returncode == 1, result.stdout
    assert "unresolved_ref" in result.stdout, result.stdout
    assert "HEAD side" in result.stdout, result.stdout


# ---------------------------------------------------------------------------
# definitions / $defs are walked, not only the file root
# ---------------------------------------------------------------------------


def _defs_schema(keyword: str, defs: dict) -> dict:
    """A bare-named (conservative role) schema whose root references nothing, so a change
    inside `definitions`/`$defs` is invisible to a root-only walk."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://schemas.traigent.ai/widgets/widget_schema.json",
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": False,
        keyword: defs,
    }


def _gate_defs_change(tmp_path: Path, baseline: dict, mutate) -> subprocess.CompletedProcess:
    repo = _response_schema_repo(tmp_path, "widget_schema.json", baseline)
    changed = json.loads(json.dumps(baseline))
    mutate(changed)
    _commit_schema_change(repo, "change-defs", changed, "change defs", "widget_schema.json")
    return _run_gate(repo, "master", "change-defs")


@pytest.mark.parametrize("keyword", ["definitions", "$defs"])
def test_type_widened_inside_a_definition_is_breaking(tmp_path: Path, keyword: str) -> None:
    baseline = _defs_schema(
        keyword,
        {
            "ExperimentRead": {
                "type": "object",
                "properties": {"agent_ref": {"type": "string", "minLength": 1}},
                "required": ["agent_ref"],
                "additionalProperties": False,
            }
        },
    )

    def mutate(c: dict) -> None:
        c[keyword]["ExperimentRead"]["properties"]["agent_ref"]["type"] = ["string", "null"]

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 1, result.stdout
    assert f"#/{keyword}/ExperimentRead/properties/agent_ref" in result.stdout


@pytest.mark.parametrize("keyword", ["definitions", "$defs"])
def test_required_removed_inside_a_definition_is_breaking(
    tmp_path: Path, keyword: str
) -> None:
    baseline = _defs_schema(
        keyword,
        {
            "Y": {
                "type": "object",
                "properties": {"a": {"type": "string"}},
                "required": ["a"],
            }
        },
    )

    def mutate(c: dict) -> None:
        c[keyword]["Y"]["required"] = []

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 1, result.stdout
    assert f"#/{keyword}/Y" in result.stdout
    assert "'a' removed from required" in result.stdout


def test_change_in_a_definition_reached_only_through_another_definition_is_breaking(
    tmp_path: Path,
) -> None:
    baseline = _defs_schema(
        "definitions",
        {
            "Outer": {
                "type": "object",
                "properties": {"inner": {"$ref": "#/definitions/Inner"}},
            },
            "Inner": {"type": "object", "properties": {"n": {"type": "integer"}}},
        },
    )

    def mutate(c: dict) -> None:
        c["definitions"]["Inner"]["properties"]["n"]["type"] = ["integer", "null"]

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 1, result.stdout
    assert "#/definitions/Inner/properties/n" in result.stdout


def test_change_in_a_nested_definitions_block_is_breaking(tmp_path: Path) -> None:
    baseline = _defs_schema(
        "definitions",
        {
            "Outer": {
                "type": "object",
                "definitions": {"Deep": {"type": "string", "maxLength": 10}},
            }
        },
    )

    def mutate(c: dict) -> None:
        c["definitions"]["Outer"]["definitions"]["Deep"]["type"] = ["string", "null"]

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 1, result.stdout
    assert "#/definitions/Outer/definitions/Deep" in result.stdout


@pytest.mark.parametrize("keyword", ["definitions", "$defs"])
def test_removed_definition_is_breaking(tmp_path: Path, keyword: str) -> None:
    baseline = _defs_schema(
        keyword,
        {"Gone": {"type": "string"}, "Kept": {"type": "string"}},
    )

    def mutate(c: dict) -> None:
        del c[keyword]["Gone"]

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 1, result.stdout
    assert f"#/{keyword}/Gone" in result.stdout
    assert "definition_removed" in result.stdout


def test_unchanged_and_added_definitions_are_not_breaking(tmp_path: Path) -> None:
    baseline = _defs_schema("definitions", {"Kept": {"type": "string"}})

    def mutate(c: dict) -> None:
        c["definitions"]["Added"] = {"type": "integer"}
        c["description"] = "a harmless annotation change"

    result = _gate_defs_change(tmp_path, baseline, mutate)

    assert result.returncode == 0, result.stdout


# ---------------------------------------------------------------------------
# review round 29: declarations beside a $ref, content-bound identities,
# cross-file refs into inline endpoint definitions, merge-base comparison
# ---------------------------------------------------------------------------


def _write_files(repo: Path, files: dict[str, object]) -> None:
    base = repo / "traigent_schema" / "schemas"
    for rel, doc in files.items():
        path = base / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def _init_repo(tmp_path: Path, files: dict[str, object]) -> Path:
    repo = tmp_path / "multi_repo"
    repo.mkdir()
    _run_git(repo, "init", "-q", "-b", "master")
    _run_git(repo, "config", "user.email", "test@example.com")
    _run_git(repo, "config", "user.name", "Breaking Schema Check Tests")
    _write_files(repo, files)
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "baseline")
    return repo


def _commit_files(
    repo: Path, branch: str, files: dict[str, object], *, create: bool = True
) -> None:
    _run_git(repo, "checkout", "-q", *(["-b"] if create else []), branch)
    _write_files(repo, files)
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", f"change on {branch}")
    _run_git(repo, "checkout", "-q", "master")


def _doc(name: str, **extra: object) -> dict:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": f"https://schemas.traigent.ai/widgets/{name}",
        "type": "object",
        **extra,
    }


def test_definition_declared_beside_a_root_ref_is_walked(tmp_path: Path) -> None:
    """A $ref at the root hides sibling `definitions` from a resolve-first walk, yet the
    declarations stay addressable by other files."""
    shared = _doc(
        "shared_schema.json",
        definitions={"Ref": {"type": "string"}, "Other": {"type": "integer"}},
    )
    shared_root_ref = {**shared, "$ref": "#/definitions/Other"}
    repo = _init_repo(tmp_path, {"shared_schema.json": shared_root_ref})
    changed = json.loads(json.dumps(shared_root_ref))
    del changed["definitions"]["Ref"]
    _commit_files(repo, "drop-ref", {"shared_schema.json": changed})

    result = _run_gate(repo, "master", "drop-ref")

    assert result.returncode == 1, result.stdout
    assert "#/definitions/Ref" in result.stdout
    assert "definition_removed" in result.stdout


def test_definition_declared_beside_a_nested_ref_is_walked(tmp_path: Path) -> None:
    base = _doc(
        "nested_schema.json",
        definitions={"Leaf": {"type": "string"}},
        properties={
            "p": {"$ref": "#/definitions/Leaf", "definitions": {"Hidden": {"type": "string"}}}
        },
    )
    repo = _init_repo(tmp_path, {"nested_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["properties"]["p"]["definitions"]["Hidden"]["type"] = ["string", "null"]
    _commit_files(repo, "widen", {"nested_schema.json": changed})

    result = _run_gate(repo, "master", "widen")

    assert result.returncode == 1, result.stdout
    assert "/properties/p/definitions/Hidden" in result.stdout


def test_nested_definition_change_is_reported_once(tmp_path: Path) -> None:
    base = _doc(
        "once_schema.json",
        definitions={
            "Outer": {
                "type": "object",
                "definitions": {"Deep": {"type": "string"}},
            }
        },
        properties={"o": {"$ref": "#/definitions/Outer"}},
    )
    repo = _init_repo(tmp_path, {"once_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["definitions"]["Outer"]["definitions"]["Deep"]["type"] = ["string", "null"]
    _commit_files(repo, "widen", {"once_schema.json": changed})

    result = _run_gate(repo, "master", "widen")

    assert result.returncode == 1, result.stdout
    assert result.stdout.count("#/definitions/Outer/definitions/Deep  (type") == 1, result.stdout


def _anyof_doc(branches: list[dict]) -> dict:
    return _doc(
        "perm_schema.json",
        definitions={"PermissionValue": {"type": "string", "anyOf": branches}},
    )


def _branch_list(prefix: str, n: int) -> list[dict]:
    return [{"type": "string", "enum": [f"{prefix}{i}"]} for i in range(n)]


def test_combinator_acknowledgement_is_bound_to_the_changed_content(tmp_path: Path) -> None:
    """A 3 -> 4 anyOf acknowledgement must not approve a different 3 -> 4 change."""
    old_branches = _branch_list("a", 3)
    approved = _branch_list("a", 3) + [{"type": "string", "enum": ["approved"]}]
    other = _branch_list("b", 4)
    repo = _init_repo(tmp_path, {"perm_schema.json": _anyof_doc(old_branches)})
    _commit_files(repo, "approved", {"perm_schema.json": _anyof_doc(approved)})
    _commit_files(repo, "other", {"perm_schema.json": _anyof_doc(other)})

    def findings_for(branch: str) -> list:
        base_tree = gate.load_tree_from_ref(repo, "master", repo / f"x_base_{branch}", repo)
        head_tree = gate.load_tree_from_ref(repo, branch, repo / f"x_{branch}", repo)
        changed = gate.changed_schema_files(repo, "master", branch)
        report = gate.compare_trees(base_tree, head_tree, changed, [])
        return [f for f in report.breaking_unacked if f.rule == "anyOf_branch_count_changed"]

    (approved_finding,) = findings_for("approved")
    (other_finding,) = findings_for("other")
    entry = {
        "file": approved_finding.file,
        "rule": approved_finding.rule,
        "findings": [_stored_identity(approved_finding)],
        "reason": "Reviewed: the permission vocabulary gained one value in this change.",
        "version": "Unreleased",
    }
    allowlist = repo / "ack.json"
    allowlist.write_text(json.dumps({"entries": [entry]}), encoding="utf-8")

    def run(branch: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--check", "--repo-root", str(repo),
             "--base-ref", "master", "--head-ref", branch, "--allowlist", str(allowlist)],
            env=_sanitized_git_env(), capture_output=True, text=True,
        )

    assert run("approved").returncode == 0
    other_run = run("other")
    assert other_run.returncode == 1, other_run.stdout
    assert approved_finding.fingerprint() != other_finding.fingerprint()


def test_inline_endpoint_definition_referenced_from_another_file_is_compared(
    tmp_path: Path,
) -> None:
    endpoint_ref = (
        "widget_endpoints.json#/paths/~1x/post/requestBody/content/application~1json"
        "/schema/definitions/X"
    )
    endpoints = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "definitions": {"X": {"type": "string"}},
                                    "properties": {"a": {"$ref": "#/definitions/X"}},
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    consumer = _doc("consumer_schema.json", properties={"x": {"$ref": endpoint_ref}})
    repo = _init_repo(
        tmp_path, {"widget_endpoints.json": endpoints, "consumer_schema.json": consumer}
    )
    changed = json.loads(json.dumps(endpoints))
    schema = changed["paths"]["/x"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    schema["definitions"]["X"]["type"] = "integer"
    _commit_files(repo, "retype", {"widget_endpoints.json": changed})

    result = _run_gate(repo, "master", "retype")

    assert result.returncode == 1, result.stdout
    assert "definitions/X" in result.stdout


def test_unreferenced_inline_endpoint_definition_stays_private(tmp_path: Path) -> None:
    endpoints = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "definitions": {"X": {"type": "string"}},
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    repo = _init_repo(tmp_path, {"widget_endpoints.json": endpoints})
    changed = json.loads(json.dumps(endpoints))
    schema = changed["paths"]["/x"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    schema["definitions"]["X"]["type"] = "integer"
    _commit_files(repo, "retype", {"widget_endpoints.json": changed})

    assert _run_gate(repo, "master", "retype").returncode == 0


def test_gate_compares_against_the_merge_base_not_the_target_tip(tmp_path: Path) -> None:
    """A stale PR branch must not be charged with removing what the target branch added
    after the PR branched off."""
    base = _doc("stale_schema.json", definitions={"Old": {"type": "string"}})
    repo = _init_repo(tmp_path, {"stale_schema.json": base})
    pr_doc = json.loads(json.dumps(base))
    pr_doc["definitions"]["Mine"] = {"type": "string"}
    _commit_files(repo, "pr", {"stale_schema.json": pr_doc})
    target_doc = json.loads(json.dumps(base))
    target_doc["definitions"]["Landed"] = {"type": "string"}
    _write_files(repo, {"stale_schema.json": target_doc})
    _run_git(repo, "add", "-A")
    _run_git(repo, "commit", "-q", "-m", "target moves on")

    result = _run_gate(repo, "master", "pr")

    assert result.returncode == 0, result.stdout
    assert "Landed" not in result.stdout


def test_legacy_content_less_identity_never_matches_a_content_bearing_finding() -> None:
    """A stored identity without content must not approve a finding that carries content,
    marker or not: `content_unbound` is gone, so a replay of an old oneOf change with
    unrelated branches is not suppressed by the old 'oneOf 4 -> 5' acknowledgement."""
    finding = gate.Finding(
        file="widgets/widget_schema.json",
        pointer="#/properties/a/oneOf",
        rule="oneOf_branch_count_changed",
        severity="BREAKING",
        role="conservative",
        message="oneOf branch count changed (4 -> 5)",
        subject="oneOf",
        old=4,
        new=5,
        content={"old": "a" * 64, "new": "b" * 64},
    )
    legacy_identity = {k: v for k, v in finding.identity().items() if k != "content"}
    legacy = {
        **legacy_identity,
        "fingerprint": gate._fingerprint_for_identity(finding.file, finding.rule, legacy_identity),
    }
    entry = {
        "file": finding.file,
        "rule": finding.rule,
        "findings": [legacy],
        "reason": "Reviewed and released with the readiness target change.",
        "version": "Unreleased",
    }
    assert gate.find_allow_entry(finding, [entry]).entry is None
    assert gate.find_allow_entry(finding, [{**entry, "content_unbound": True}]).entry is None
    exact = {**entry, "findings": [_stored_identity(finding)]}
    assert gate.find_allow_entry(finding, [exact]).entry
    other = gate.Finding(**{**finding.__dict__, "content": {"old": "a" * 64, "new": "c" * 64}})
    assert gate.find_allow_entry(other, [exact]).entry is None


def _inline_endpoints_doc(definition: dict, *, schema_id: str | None = None) -> dict:
    doc = {
        "openapi": "3.0.0",
        "paths": {
            "/x": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "definitions": {"X": definition},
                                        "properties": {"a": {"$ref": "#/definitions/X"}},
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }
    if schema_id:
        doc["$id"] = schema_id
    return doc


_RESPONSE_X_REF = (
    "widget_endpoints.json#/paths/~1x/get/responses/200/content/application~1json"
    "/schema/definitions/X"
)


def test_cross_file_target_is_judged_by_the_referencing_consumer_role(tmp_path: Path) -> None:
    """An unchanged REQUEST schema refs an inline RESPONSE definition; removing an enum
    value narrows what the request accepts, so it must not be judged as a response."""
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    consumer = _doc("consumer_request_schema.json", properties={"x": {"$ref": _RESPONSE_X_REF}})
    repo = _init_repo(
        tmp_path, {"widget_endpoints.json": endpoints, "consumer_request_schema.json": consumer}
    )
    changed = json.loads(json.dumps(endpoints))
    schema = changed["paths"]["/x"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    schema["definitions"]["X"]["enum"] = ["a"]
    _commit_files(repo, "narrow", {"widget_endpoints.json": changed})

    result = _run_gate(repo, "master", "narrow")

    assert result.returncode == 1, result.stdout
    assert "role=request" in result.stdout


def test_cross_file_ref_through_a_registered_id_is_compared(tmp_path: Path) -> None:
    other_id = "https://schemas.traigent.ai/custom/ep_v2.json"
    endpoints = _inline_endpoints_doc({"type": "string"}, schema_id=other_id)
    ref = other_id + _RESPONSE_X_REF.removeprefix("widget_endpoints.json")
    consumer = _doc("consumer_schema.json", properties={"x": {"$ref": ref}})
    repo = _init_repo(
        tmp_path, {"widget_endpoints.json": endpoints, "consumer_schema.json": consumer}
    )
    changed = json.loads(json.dumps(endpoints))
    schema = changed["paths"]["/x"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    schema["definitions"]["X"]["type"] = "integer"
    _commit_files(repo, "retype", {"widget_endpoints.json": changed})

    result = _run_gate(repo, "master", "retype")

    assert result.returncode == 1, result.stdout
    assert "definitions/X" in result.stdout


def test_response_allof_shortcut_does_not_hide_a_removed_declaration(tmp_path: Path) -> None:
    inner = {
        "type": "object",
        "definitions": {"X": {"type": "string"}},
        "properties": {"a": {"type": "string"}},
    }
    base = _doc("wrap_response_schema.json", properties={"p": inner})
    repo = _init_repo(tmp_path, {"wrap_response_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["properties"]["p"] = {"allOf": [inner]}
    _commit_files(repo, "wrap", {"wrap_response_schema.json": changed})

    result = _run_gate(repo, "master", "wrap")

    assert result.returncode == 1, result.stdout
    assert "#/properties/p/definitions/X" in result.stdout
    assert "definition_removed" in result.stdout


def _narrow_inline_enum(repo: Path, endpoints: dict, branch: str) -> subprocess.CompletedProcess:
    changed = json.loads(json.dumps(endpoints))
    schema = changed["paths"]["/x"]["get"]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]
    schema["definitions"]["X"]["enum"] = ["a"]
    _commit_files(repo, branch, {"widget_endpoints.json": changed})
    return _run_gate(repo, "master", branch)


def _consumer_endpoints_doc(section: str, ref: str) -> dict:
    schema = {"content": {"application/json": {"schema": {"$ref": ref}}}}
    operation = (
        {"requestBody": schema, "responses": {"200": {"description": "ok"}}}
        if section == "request"
        else {"responses": {"200": {"description": "ok", **schema}}}
    )
    return {"openapi": "3.0.0", "paths": {"/y": {"post": operation}}}


def test_endpoint_consumer_using_the_definition_only_in_a_response_is_a_response(
    tmp_path: Path,
) -> None:
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    consumer = _consumer_endpoints_doc("response", _RESPONSE_X_REF)
    repo = _init_repo(
        tmp_path, {"widget_endpoints.json": endpoints, "other_endpoints.json": consumer}
    )

    result = _narrow_inline_enum(repo, endpoints, "narrow")

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout, result.stdout


def test_endpoint_consumer_using_the_definition_only_in_a_request_is_a_request(
    tmp_path: Path,
) -> None:
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    consumer = _consumer_endpoints_doc("request", _RESPONSE_X_REF)
    repo = _init_repo(
        tmp_path, {"widget_endpoints.json": endpoints, "other_endpoints.json": consumer}
    )

    result = _narrow_inline_enum(repo, endpoints, "narrow")

    assert result.returncode == 1, result.stdout
    assert "role=request" in result.stdout


def test_request_reaching_the_definition_through_a_custom_id_intermediate_is_a_request(
    tmp_path: Path,
) -> None:
    mid_id = "https://schemas.traigent.ai/custom/mid_v2.json"
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    absolute_ref = "https://schemas.traigent.ai/" + _RESPONSE_X_REF
    mid = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": mid_id,
        "type": "object",
        "properties": {"x": {"$ref": absolute_ref}},
    }
    request = _consumer_endpoints_doc("request", mid_id)
    repo = _init_repo(
        tmp_path,
        {
            "widget_endpoints.json": endpoints,
            "mid_response_schema.json": mid,
            "req_endpoints.json": request,
        },
    )

    result = _narrow_inline_enum(repo, endpoints, "narrow")

    assert result.returncode == 1, result.stdout


_MID_Y_REF = (
    "mid_endpoints.json#/paths/~1m/get/responses/200/content/application~1json"
    "/schema/definitions/Y"
)


def _mid_endpoints_doc() -> dict:
    return {
        "openapi": "3.0.0",
        "paths": {
            "/m": {
                "get": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "definitions": {"Y": {"$ref": _RESPONSE_X_REF}},
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }


def _chain_repo(tmp_path: Path, endpoints: dict, section: str) -> Path:
    return _init_repo(
        tmp_path,
        {
            "widget_endpoints.json": endpoints,
            "mid_endpoints.json": _mid_endpoints_doc(),
            "other_endpoints.json": _consumer_endpoints_doc(section, _MID_Y_REF),
        },
    )


def test_request_reaching_the_definition_through_another_endpoints_response_is_breaking(
    tmp_path: Path,
) -> None:
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    repo = _chain_repo(tmp_path, endpoints, "request")

    result = _narrow_inline_enum(repo, endpoints, "narrow")

    assert result.returncode == 1, result.stdout


def test_response_only_endpoint_chain_stays_a_response(tmp_path: Path) -> None:
    endpoints = _inline_endpoints_doc({"type": "string", "enum": ["a", "b"]})
    repo = _chain_repo(tmp_path, endpoints, "response")

    result = _narrow_inline_enum(repo, endpoints, "narrow")

    assert result.returncode == 0, result.stdout


def test_allof_shortcut_does_not_descend_into_extension_metadata(tmp_path: Path) -> None:
    inner = {
        "type": "object",
        "properties": {"a": {"type": "string"}},
        "x-example-metadata": {"definitions": {"X": {"type": "string"}}},
    }
    base = _doc("meta_response_schema.json", properties={"p": inner})
    repo = _init_repo(tmp_path, {"meta_response_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["properties"]["p"] = {"allOf": [inner]}
    _commit_files(repo, "wrap", {"meta_response_schema.json": changed})

    result = _run_gate(repo, "master", "wrap")

    assert result.returncode == 0, result.stdout
    assert "definition_removed" not in result.stdout


def test_response_allof_shortcut_does_not_hide_a_removal_one_property_deeper(
    tmp_path: Path,
) -> None:
    child = {
        "type": "object",
        "definitions": {"X": {"type": "string"}},
        "properties": {"a": {"type": "string"}},
    }
    inner = {"type": "object", "properties": {"c": child}}
    base = _doc("deepwrap_response_schema.json", properties={"p": inner})
    repo = _init_repo(tmp_path, {"deepwrap_response_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["properties"]["p"] = {"allOf": [inner]}
    _commit_files(repo, "wrap", {"deepwrap_response_schema.json": changed})

    result = _run_gate(repo, "master", "wrap")

    assert result.returncode == 1, result.stdout
    assert "#/properties/p/properties/c/definitions/X" in result.stdout
    assert "definition_removed" in result.stdout


def test_definition_below_a_dereferenced_node_is_reported_once(tmp_path: Path) -> None:
    base = _doc(
        "below_schema.json",
        definitions={
            "Outer": {
                "type": "object",
                "properties": {
                    "child": {"type": "object", "definitions": {"Inner": {"type": "string"}}}
                },
            }
        },
        properties={"o": {"$ref": "#/definitions/Outer"}},
    )
    repo = _init_repo(tmp_path, {"below_schema.json": base})
    changed = json.loads(json.dumps(base))
    changed["definitions"]["Outer"]["properties"]["child"]["definitions"]["Inner"]["type"] = [
        "string",
        "null",
    ]
    _commit_files(repo, "widen", {"below_schema.json": changed})

    result = _run_gate(repo, "master", "widen")

    assert result.returncode == 1, result.stdout
    assert result.stdout.count("/definitions/Inner  (type") == 1, result.stdout


def test_pull_request_gate_uses_the_event_base_sha_like_the_classifier() -> None:
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    start = text.index("- name: Resolve base/head refs for this event")
    step = text[start : text.index("- name: Run the breaking-change gate", start)]
    assert "PR_BASE_SHA: ${{ github.event.pull_request.base.sha }}" in step
    assert 'git fetch origin "$PR_BASE_SHA"' in step
    assert 'base_ref=${PR_BASE_SHA}' in step
    assert "PR_BASE_REF" not in step
