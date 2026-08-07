"""Negative-control tests for scripts/check_required_gate.py.

`ci-required` is this repo's single required status check: it decides
whether a PR is allowed to merge based on what its dependency jobs reported.
A regression here either wrongly blocks every legitimate PR (a docs-only or
workflow-only change that touches no schema file), or -- much worse --
silently turns the gate green when `breaking-schema-check` never ran because
the `changes` classifier is broken. These tests exercise the decision
function directly (fast, precise) plus the actual CLI entry point (end-to-end,
proves the NEEDS_JSON wiring works).

Design under test: `UNCONDITIONAL_SKIP_OK` jobs (`test`, `package`) may skip
with no further checks -- their skip depends only on `lint-type`, itself an
independently-checked dependency. The one classifier-gated job,
`breaking-schema-check`, may skip ONLY when
`verify_breaking_schema_check_skip` proves it safe: `changes` succeeded, and
either `event_applicable` is literally `'false'` (no PR/merge_group diff
range for this event) or `schema_relevant` is literally `'false'` AND
`changed_file_count` is a positive integer. Anything else -- `cancelled`, an
empty/missing output, a zero file count, an unsuccessful `changes` run --
fails the gate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "check_required_gate.py"

sys.path.insert(0, str(SCRIPT.parent))
import check_required_gate as gate  # noqa: E402  (path insert must precede this)


def _job(result: str, outputs: dict | None = None) -> dict:
    entry: dict = {"result": result}
    if outputs is not None:
        entry["outputs"] = outputs
    return entry


def _base_needs(**overrides: dict) -> dict:
    """A fully-green `needs` map for lint-type/test/package/changes/
    breaking-schema-check, with `overrides` replacing individual entries."""
    needs = {
        "lint-type": _job("success"),
        "test": _job("success"),
        "package": _job("success"),
        "changes": _job(
            "success",
            {"event_applicable": "true", "schema_relevant": "true", "changed_file_count": "3"},
        ),
        "breaking-schema-check": _job("success"),
    }
    needs.update(overrides)
    return needs


def _run_cli(needs: dict) -> subprocess.CompletedProcess[str]:
    """Invoke the real script exactly as the workflow does: via NEEDS_JSON."""
    env = {**os.environ, "NEEDS_JSON": json.dumps(needs)}
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


class TestAllSuccess:
    def test_everything_succeeded_passes(self) -> None:
        result = gate.evaluate(_base_needs())
        assert result.ok, result.problems


class TestUnconditionalSkipOk:
    def test_test_and_package_skip_when_lint_type_failed(self) -> None:
        needs = _base_needs(
            **{
                "lint-type": _job("failure"),
                "test": _job("skipped"),
                "package": _job("skipped"),
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "2",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        # lint-type=failure is independently caught; the cascaded skips are not
        # themselves new problems.
        assert not result.ok
        assert any("lint-type" in p for p in result.problems)
        assert not any(p.startswith("test=") for p in result.problems)
        assert not any(p.startswith("package=") for p in result.problems)

    def test_stale_allowlist_entry_fails_closed(self) -> None:
        needs = _base_needs()
        del needs["test"]
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("UNCONDITIONAL_SKIP_OK names 'test'" in p for p in result.problems)


class TestClassifierGatedSkip_EventNotApplicable:
    def test_skip_accepted_when_event_not_applicable(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "false",
                        "schema_relevant": "false",
                        "changed_file_count": "0",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert result.ok, result.problems
        assert any("event_applicable" in j for j in result.justifications)

    def test_event_applicable_garbage_value_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "maybe",
                        "schema_relevant": "false",
                        "changed_file_count": "1",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("event_applicable" in p for p in result.problems)


class TestClassifierGatedSkip_SchemaNotRelevant:
    def test_skip_accepted_when_classifier_says_false_with_files(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "4",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert result.ok, result.problems
        assert any("schema_relevant='false'" in j for j in result.justifications)

    def test_changes_not_success_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "failure",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "4",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("did not succeed" in p for p in result.problems)

    def test_changes_cancelled_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job("cancelled", {}),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("did not succeed" in p for p in result.problems)

    def test_schema_relevant_missing_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success", {"event_applicable": "true", "changed_file_count": "4"}
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("schema_relevant' is missing entirely" in p for p in result.problems)

    def test_schema_relevant_empty_string_fails_closed(self) -> None:
        """The critical case: an empty string is falsy-looking in bash but is NOT
        the literal string 'false' -- must be rejected, not silently accepted."""
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "",
                        "changed_file_count": "4",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("expected the literal string 'false'" in p for p in result.problems)

    def test_schema_relevant_true_but_job_skipped_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "true",
                        "changed_file_count": "4",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("expected the literal string 'false'" in p for p in result.problems)

    def test_zero_changed_files_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "0",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("changed files in a PR/merge_group range" in p for p in result.problems)

    def test_changed_file_count_missing_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success", {"event_applicable": "true", "schema_relevant": "false"}
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("changed_file_count' is missing entirely" in p for p in result.problems)

    def test_changed_file_count_not_an_integer_fails_closed(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "not-a-number",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("is not a valid integer" in p for p in result.problems)


class TestBreakingSchemaCheckRealResults:
    def test_breaking_schema_check_failure_is_red(self) -> None:
        """A real BREAKING finding: the job runs and fails -- caught by the
        plain fallback rule, no skip-verification path involved at all."""
        needs = _base_needs(**{"breaking-schema-check": _job("failure")})
        result = gate.evaluate(needs)
        assert not result.ok
        assert any(p == "breaking-schema-check='failure'" for p in result.problems)

    def test_breaking_schema_check_cancelled_is_red(self) -> None:
        needs = _base_needs(**{"breaking-schema-check": _job("cancelled")})
        result = gate.evaluate(needs)
        assert not result.ok
        assert any(p == "breaking-schema-check='cancelled'" for p in result.problems)

    def test_breaking_schema_check_missing_from_needs_fails_closed(self) -> None:
        needs = _base_needs()
        del needs["breaking-schema-check"]
        result = gate.evaluate(needs)
        assert not result.ok
        assert any(
            "'breaking-schema-check' is not a declared dependency" in p for p in result.problems
        )


class TestEmptyNeeds:
    def test_empty_needs_fails_closed(self) -> None:
        result = gate.evaluate({})
        assert not result.ok
        assert any("needs map is empty" in p for p in result.problems)


class TestCli:
    def test_cli_passes_on_healthy_needs(self) -> None:
        proc = _run_cli(_base_needs())
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "ci-required passed" in proc.stdout

    def test_cli_fails_on_real_failure(self) -> None:
        proc = _run_cli(_base_needs(**{"lint-type": _job("failure")}))
        assert proc.returncode == 1
        assert "::error::" in proc.stdout

    def test_cli_fails_on_classifier_bug_empty_string(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "",
                        "changed_file_count": "4",
                    },
                ),
            }
        )
        proc = _run_cli(needs)
        assert proc.returncode == 1
        assert "expected the literal string 'false'" in proc.stdout

    def test_cli_rejects_missing_needs_json(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "NEEDS_JSON"}
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True, env=env, check=False
        )
        assert proc.returncode == 1
        assert "NEEDS_JSON is empty or unset" in proc.stdout

    def test_cli_rejects_malformed_json(self) -> None:
        env = {**os.environ, "NEEDS_JSON": "{not valid json"}
        proc = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True, env=env, check=False
        )
        assert proc.returncode == 1
        assert "not valid JSON" in proc.stdout
