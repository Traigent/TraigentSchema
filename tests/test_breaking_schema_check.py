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
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "breaking_schema_check.py"


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
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
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
    field from `required` (walking back a guarantee) is BREAKING; adding one is not."""
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
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout
    assert "BREAKING (unacked):   0" in result.stdout
