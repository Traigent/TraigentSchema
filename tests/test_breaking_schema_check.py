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

import importlib.util
import json
import os
import subprocess
import sys
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
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # dataclasses' string-annotation resolution (from __future__ import annotations) looks
    # the module up via sys.modules[cls.__module__] — register it before exec_module runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate_module()

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


def test_removing_a_property_fails_and_names_it(widget_repo: Path) -> None:
    changed = dict(BASELINE_SCHEMA)
    baseline_properties: dict = BASELINE_SCHEMA["properties"]
    changed["properties"] = {k: v for k, v in baseline_properties.items() if k != "color"}
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
    _commit_schema_change(widget_repo, "add-weight", changed, "add optional weight property")

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
    (schema_dir / filename).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
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


def test_bare_closed_schema_added_property_is_conservatively_breaking(tmp_path: Path) -> None:
    """A bare schema may be used as a response, so it must retain the strict-consumer
    protection rather than inheriting request-only permissiveness."""
    filename = "widget_schema.json"
    baseline = _closed_response_schema(filename)
    repo = _response_schema_repo(tmp_path, filename, baseline)
    changed = json.loads(json.dumps(baseline))
    changed["properties"]["evidence_case"] = {"type": "object"}
    _commit_schema_change(repo, "add-evidence-case", changed, "add bare schema property", filename)

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
    _commit_schema_change(repo, "add-pattern", changed, "add bare pattern property", filename)

    result = _run_gate(repo, "master", "add-pattern")

    assert result.returncode == 1, result.stdout
    assert "patternProperties_added, role=conservative" in result.stdout


def test_nested_closed_response_added_pattern_property_is_breaking(tmp_path: Path) -> None:
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
    changed["properties"]["payload"]["patternProperties"] = {
        "^x-": {"type": "string"}
    }
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
    expected_breaking = role == "conservative" or (
        role == "request" and direction == "added"
    ) or (role == "response" and direction == "removed")

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
    assert gate.reason_rejection(placeholder) is not None, (
        f"{placeholder!r} should have been rejected as a placeholder"
    )


@pytest.mark.parametrize(
    "real_reason",
    [
        "Product decided all widgets must declare a color for the new catalog UI (#330).",
        "Bound-hardening sweep: caps a previously-unconstrained string per the input-bounds "
        "policy; no legitimate client sends values anywhere near this length.",
        "narrowed per the security review; see PR #333 for the audit trail",
    ],
)
def test_real_reasons_are_accepted(real_reason: str) -> None:
    assert gate.reason_rejection(real_reason) is None, (
        f"{real_reason!r} should NOT have been rejected"
    )


def test_placeholder_allowlist_reason_does_not_grant_opt_out(widget_repo: Path) -> None:
    """The bar for an allowlist `reason` is "explains WHY", not "is a non-empty string" —
    pin the exact class of failure this workspace has hit before (an evidence field that
    accepted any non-empty string accepted a placeholder as if it were a real answer)."""
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
    sacrificial_config_before = _run_git(sacrificial_repo, "config", "--local", "--list")
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
        _run_git(sacrificial_repo, "rev-parse", "HEAD").strip() == sacrificial_head_before
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
    assert (sacrificial_repo / ".git" / "index").read_bytes() == sacrificial_index_before
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
        "done <<< \"$(git rev-parse --local-env-vars)\"\n"
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
    assert marker.exists(), "scripts/local_gate.sh stub never ran -- hook did not reach exec"
    assert marker.read_text().strip() == "ok", marker.read_text()

    # No repo/ref/config/index outside tmp_path was touched: this worktree's
    # own HEAD (read via a call with a sanitized, not poisoned, env) is
    # unchanged.
    assert _run_git(REPO_ROOT, "rev-parse", "HEAD").strip() == repo_root_head_before
