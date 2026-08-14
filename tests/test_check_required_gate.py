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
`changed_file_count` is a positive integer, or the changes job proves the
exact immutable ancestry-only topology and emits `ancestry_only='true'`.
Anything else -- `cancelled`, an empty/missing output, a zero file count, an
unsuccessful `changes` run -- fails the gate.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
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
            {
                "event_applicable": "true",
                "schema_relevant": "true",
                "changed_file_count": "3",
                "ancestry_only": "false",
            },
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

    def test_verified_ancestry_only_zero_changed_files_passes(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "0",
                        "ancestry_only": "true",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert result.ok, result.problems
        assert any("ancestry-only topology" in j for j in result.justifications)

    def test_zero_changed_files_with_false_ancestry_flag_stays_red(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "0",
                        "ancestry_only": "false",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok

    def test_nonzero_changed_files_rejects_ancestry_flag(self) -> None:
        needs = _base_needs(
            **{
                "breaking-schema-check": _job("skipped"),
                "changes": _job(
                    "success",
                    {
                        "event_applicable": "true",
                        "schema_relevant": "false",
                        "changed_file_count": "2",
                        "ancestry_only": "true",
                    },
                ),
            }
        )
        result = gate.evaluate(needs)
        assert not result.ok
        assert any("non-zero changed_file_count" in p for p in result.problems)

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


def test_zero_diff_ancestry_exception_is_fail_closed_for_each_event_shape() -> None:
    """Lock the workflow proof's adversarial event/topology guards."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    required_fragments = {
        "pull_request": (
            'if [ "$EVENT_NAME" = "pull_request" ]; then',
            'base_sha="$PR_BASE_SHA"',
            'head_sha="$PR_HEAD_SHA"',
        ),
        "merge_group": (
            'if [ "$EVENT_NAME" = "merge_group" ]; then',
            'base_sha="$MG_BASE_SHA"',
            'head_sha="$MG_HEAD_SHA"',
            'read -r -a candidate_parents <<< "$(git show -s --format=%P "$head_sha")"',
        ),
        "fork": (
            'if [ "$PR_HEAD_REPOSITORY" = "$REPOSITORY" ]',
            'pr_head_repository="$(gh api "repos/${REPOSITORY}/commits/${pr_head_sha}/pulls"',
        ),
        "malformed_refs": (
            'if [ -z "$base_sha" ] || [ -z "$head_sha" ]; then',
            'base_tree="$(git rev-parse "${base_sha}^{tree}")"',
        ),
        "mutable_main_ref": (
            "git fetch --no-tags origin main",
            'expected_main_sha="$(git rev-parse FETCH_HEAD)"',
        ),
        "extra_parents": ('if [ "${#head_parents[@]}" -ne 2 ]; then',),
        "tree_mismatch": (
            'expected_main_tree="$(git rev-parse "${expected_main_sha}^{tree}")"',
            '"$expected_main_tree" != "$base_tree"',
            '"$candidate_tree" = "$base_tree"',
            '"$pr_head_tree" = "$base_tree"',
        ),
        "normal_zero_diff": (
            'echo "ancestry_only=false" >> "$GITHUB_OUTPUT"',
            'if [ "$changed_file_count" -ne 0 ]; then',
        ),
    }
    for scenario, fragments in required_fragments.items():
        for fragment in fragments:
            assert fragment in workflow, f"{scenario}: missing {fragment!r}"

    changed_step = _changed_step_script()
    assert "${{" not in changed_step
    assert "github.event" not in changed_step


def _git(cwd: Path, *args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _changed_step_script() -> str:
    """Extract the real classifier shell from ci.yml for executable tests."""
    lines = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    ).splitlines()
    run_index = next(
        index
        for index, line in enumerate(lines)
        if line.strip() == "run: |"
        and any("id: changed" in previous for previous in lines[max(0, index - 20) : index])
    )
    body: list[str] = []
    for line in lines[run_index + 1 :]:
        if line and not line.startswith("          "):
            break
        body.append(line[10:] if line else "")
    return "\n".join(body) + "\n"


def _topology(root: Path, *, main_tree_mismatch: bool = False) -> dict[str, str]:
    origin = root / "origin.git"
    work = root / "work"
    _git(root, "init", "--bare", str(origin))
    work.mkdir()
    _git(work, "init", "-b", "main")
    _git(work, "config", "user.email", "ci-tests@example.invalid")
    _git(work, "config", "user.name", "CI topology test")
    _git(work, "remote", "add", "origin", str(origin))
    (work / "tracked.txt").write_text("base\n", encoding="utf-8")
    _git(work, "add", "tracked.txt")
    _git(work, "commit", "-m", "base")
    base = _git(work, "rev-parse", "HEAD")
    _git(work, "branch", "develop", base)
    _git(work, "push", "origin", "develop")

    if main_tree_mismatch:
        (work / "main-only.txt").write_text("main\n", encoding="utf-8")
        _git(work, "add", "main-only.txt")
        _git(work, "commit", "-m", "main differs")
    else:
        _git(work, "commit", "--allow-empty", "-m", "main refresh")
    main = _git(work, "rev-parse", "HEAD")
    _git(work, "push", "origin", "main")
    base_tree = _git(work, "rev-parse", f"{base}^{{tree}}")

    head = _git(
        work,
        "commit-tree",
        base_tree,
        "-p",
        base,
        "-p",
        main,
        input_text="ancestry sync\n\nTraigent-Ancestry-Only: true\n",
    )
    candidate = _git(
        work,
        "commit-tree",
        base_tree,
        "-p",
        base,
        "-p",
        head,
        input_text="merge queue candidate\n",
    )
    base_mismatch = _git(
        work,
        "commit-tree",
        base_tree,
        "-p",
        base,
        input_text="different base identity\n",
    )
    (work / "candidate-only.txt").write_text("candidate\n", encoding="utf-8")
    _git(work, "add", "candidate-only.txt")
    _git(work, "commit", "-m", "candidate tree")
    candidate_tree = _git(work, "rev-parse", "HEAD^{tree}")
    tree_mismatch_candidate = _git(
        work,
        "commit-tree",
        candidate_tree,
        "-p",
        base,
        "-p",
        head,
        input_text="tree mismatch candidate\n",
    )
    return {
        "work": str(work),
        "base": base,
        "main": main,
        "head": head,
        "candidate": candidate,
        "base_mismatch": base_mismatch,
        "tree_mismatch_candidate": tree_mismatch_candidate,
    }


def _write_gh_stub(root: Path, mode: str, repository: str) -> Path:
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    gh = bin_dir / "gh"
    gh.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        'case "${GH_STUB_MODE:-ok}" in\n'
        "  api-fail) exit 1 ;;\n"
        "  ambiguous) printf '\\n' ;;\n"
        '  *) printf \'%s\\n\' "$GH_STUB_REPO" ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    gh.chmod(0o755)
    return bin_dir


def _run_classifier(
    root: Path,
    topology: dict[str, str],
    *,
    event: str,
    base: str,
    head: str,
    source_repository: str,
    gh_mode: str = "ok",
    gh_repository: str = "Traigent/TraigentSchema",
) -> dict[str, str]:
    output = root / "github-output"
    env = {
        **os.environ,
        "EVENT_NAME": event,
        "PR_BASE_SHA": base if event == "pull_request" else "",
        "PR_HEAD_SHA": head if event == "pull_request" else "",
        "MG_BASE_SHA": base if event == "merge_group" else "",
        "MG_HEAD_SHA": head if event == "merge_group" else "",
        "REPOSITORY": "Traigent/TraigentSchema",
        "PR_HEAD_REPOSITORY": source_repository,
        "GH_TOKEN": "test-token",
        "GH_STUB_MODE": gh_mode,
        "GH_STUB_REPO": gh_repository,
        "GITHUB_OUTPUT": str(output),
    }
    env["PATH"] = str(_write_gh_stub(root, gh_mode, gh_repository)) + os.pathsep + env["PATH"]
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", _changed_step_script()],
        cwd=topology["work"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in output.read_text(encoding="utf-8").splitlines()
        if "=" in line
    }


def test_classifier_executes_pull_request_topology_proofs() -> None:
    cases = (
        ("same-repository ancestry sync", "Traigent/TraigentSchema", False, True),
        ("fork ancestry sync", "attacker/fork", False, False),
        ("main tree mismatch", "Traigent/TraigentSchema", True, False),
        ("ordinary zero diff", "Traigent/TraigentSchema", False, False),
    )
    for name, source_repository, main_mismatch, expected in cases:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            topology = _topology(root, main_tree_mismatch=main_mismatch)
            head = topology["head"] if name != "ordinary zero diff" else topology["base"]
            outputs = _run_classifier(
                root,
                topology,
                event="pull_request",
                base=topology["base"],
                head=head,
                source_repository=source_repository,
            )
            assert (outputs.get("ancestry_only") == "true") is expected, name


def test_classifier_executes_merge_group_topology_proofs() -> None:
    cases = (
        ("same-repository queue", "Traigent/TraigentSchema", "ok", "candidate", True),
        ("fork queue", "attacker/fork", "ok", "candidate", False),
        ("ambiguous source", "", "ambiguous", "candidate", False),
        ("API failure", "", "api-fail", "candidate", False),
        (
            "candidate tree mismatch",
            "Traigent/TraigentSchema",
            "ok",
            "tree_mismatch_candidate",
            False,
        ),
        ("base mismatch", "Traigent/TraigentSchema", "ok", "candidate", False),
    )
    for name, source_repository, gh_mode, candidate_key, expected in cases:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            topology = _topology(root)
            base = topology["base_mismatch"] if name == "base mismatch" else topology["base"]
            outputs = _run_classifier(
                root,
                topology,
                event="merge_group",
                base=base,
                head=topology[candidate_key],
                source_repository=source_repository,
                gh_mode=gh_mode,
                gh_repository=source_repository or "attacker/fork",
            )
            assert (outputs.get("ancestry_only") == "true") is expected, name
