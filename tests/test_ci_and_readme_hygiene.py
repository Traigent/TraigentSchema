from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
CI_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
README_PATH = REPO_ROOT / "README.md"
VERSION_PATH = REPO_ROOT / "traigent_schema" / "version.py"


def _ci_workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(CI_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), "ci.yml must parse as a workflow mapping"
    return workflow


def _setup_python_steps() -> list[tuple[str, dict[str, Any]]]:
    steps: list[tuple[str, dict[str, Any]]] = []
    for job_name, job in _ci_workflow()["jobs"].items():
        for step in job.get("steps", []):
            if isinstance(step, dict) and str(step.get("uses", "")).startswith(
                "actions/setup-python@"
            ):
                steps.append((job_name, step))
    return steps


def _package_version() -> str:
    match = re.search(
        r'^__version__\s*=\s*"(?P<version>\d+\.\d+\.\d+)"$',
        VERSION_PATH.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, "traigent_schema/version.py must define __version__"
    return match.group("version")


def test_ci_workflow_uses_pip_cache_for_all_setup_python_jobs() -> None:
    steps = _setup_python_steps()
    assert len(steps) == 4, (
        "ci.yml should set up Python in lint-type, test, package, and "
        "breaking-schema-check jobs"
    )

    # The rule is "key the cache from the manifest this job actually installs
    # from", not "key it from pyproject.toml". Those were the same thing until
    # breaking-schema-check moved to a pinned `-r requirements.txt` install
    # (SonarCloud githubactions:S8544/S8541 -- an unpinned `pip install -e .[dev]`
    # resolves versions at runtime and can execute setup scripts). Keying that
    # job from pyproject.toml would leave its cache stale exactly when the pinned
    # versions change, which is the failure this test exists to prevent.
    expected_manifest = {
        "breaking-schema-check": "requirements.txt",
        "package": "pyproject.toml\nrequirements.txt\nrequirements-dev.txt\n",
    }

    for job_name, step in steps:
        config = step.get("with", {})
        assert config.get("cache") == "pip", f"{job_name} must enable setup-python pip caching"
        expected = expected_manifest.get(job_name, "pyproject.toml")
        assert config.get("cache-dependency-path") == expected, (
            f"{job_name} must key pip cache from {expected} -- the manifest it installs from"
        )


def test_ci_workflow_cancels_superseded_runs() -> None:
    # merge_group events must NOT cancel — a cancelled queue candidate fails its
    # required gate and stalls the merge queue.  Only cancel-in-progress for PRs.
    concurrency = _ci_workflow().get("concurrency")
    assert concurrency is not None, "ci.yml must define a concurrency block"
    assert "group" in concurrency, "concurrency block must define a group key"
    cancel = concurrency.get("cancel-in-progress")
    assert cancel is not None, "concurrency block must define cancel-in-progress"
    # A bare boolean `true` cancels in-progress runs for EVERY event — including
    # merge_group — which fails a queued candidate's required gate and stalls the
    # merge queue. The only merge-queue-safe form is an expression that gates
    # cancellation on pull_request events ONLY, so merge_group runs are never
    # cancelled. Reject the bare boolean and any expression that does not tie
    # cancellation to `github.event_name == 'pull_request'`.
    assert not isinstance(cancel, bool), (
        "cancel-in-progress must be a conditional expression, not a bare boolean: "
        "`true` cancels merge_group runs and stalls the merge queue"
    )
    expr = str(cancel).replace(" ", "").replace('"', "'")
    assert "github.event_name=='pull_request'" in expr, (
        "cancel-in-progress must gate cancellation on "
        "`github.event_name == 'pull_request'` so merge_group runs are never cancelled "
        f"(got: {cancel!r})"
    )


def test_ci_workflow_caps_all_jobs_with_timeouts() -> None:
    jobs = _ci_workflow()["jobs"]
    missing = [name for name, job in jobs.items() if "timeout-minutes" not in job]
    assert not missing, f"ci.yml jobs missing timeout-minutes: {missing}"


def test_ci_workflow_pull_request_trigger_has_no_paths_filter() -> None:
    """Locks in the fix for TraigentSchema#392.

    A workflow-LEVEL `on.pull_request.paths:` filter means a PR touching none
    of those paths produces NO check-run at all for every job in this file --
    unusable for a required context, since a required context that never
    reports leaves such a PR pending forever. That is exactly what
    breaking-schema-check.yml did before it was folded into this workflow
    (see the `breaking-schema-check` job's own history comment). If someone
    ever re-adds a `paths:` filter here to silence a noisy job, they would
    silently reintroduce that bug for every job in ci.yml, including
    `ci-required` itself. `on:` is a PyYAML 1.1 boolean keyword (parses as
    `True`, not the string `'on'`) -- see https://github.com/yaml/pyyaml/issues/376.
    """
    workflow = _ci_workflow()
    on_block = workflow.get(True, workflow.get("on"))
    assert on_block is not None, "ci.yml must define an `on:` block"
    pull_request_trigger = on_block.get("pull_request")
    assert pull_request_trigger is not None, "ci.yml must trigger on pull_request"
    assert "paths" not in pull_request_trigger, (
        "ci.yml's pull_request trigger must NOT have a `paths:` filter -- it would "
        "silently stop every job in this file (including ci-required) from posting "
        "a check-run on PRs that don't match, reintroducing TraigentSchema#392"
    )
    assert "paths-ignore" not in pull_request_trigger, (
        "same hazard as `paths:` -- a `paths-ignore:` filter also suppresses "
        "check-runs for non-matching PRs"
    )


def test_ci_required_gates_breaking_schema_check_via_classifier_not_blanket_skip() -> None:
    """`breaking-schema-check` must be a real `needs:` dependency of
    `ci-required`, and its `skipped` result must be verified by
    `scripts/check_required_gate.py`'s classifier-gated rule -- never
    accepted by an unconditional allowlist (that was the hole TraigentSchema
    #392 closed: an unconditional `success|skipped` accept can't tell a
    classifier bug from a legitimate skip).
    """
    jobs = _ci_workflow()["jobs"]
    ci_required_needs = jobs["ci-required"]["needs"]
    assert "breaking-schema-check" in ci_required_needs
    assert "changes" in ci_required_needs

    gate_source = (REPO_ROOT / "scripts" / "check_required_gate.py").read_text(encoding="utf-8")
    assert '"breaking-schema-check"' not in gate_source.split("UNCONDITIONAL_SKIP_OK")[1].split(
        "}"
    )[0], (
        "breaking-schema-check must not be listed in UNCONDITIONAL_SKIP_OK -- its "
        "skip must go through verify_breaking_schema_check_skip(), not a blanket accept"
    )


def test_readme_points_to_canonical_x_extension_registry() -> None:
    text = README_PATH.read_text(encoding="utf-8")
    assert "Canonical `x-*` extension list and descriptions:" in text
    assert "`traigent_schema/schemas/x_extensions_meta_schema.json`" in text


def test_readme_release_line_matches_runtime_version() -> None:
    expected_version = _package_version()
    text = README_PATH.read_text(encoding="utf-8")
    line = next(
        (
            candidate
            for candidate in text.splitlines()
            if candidate.startswith("Current release line:")
        ),
        "",
    )

    assert line, "README.md must document the current release line"

    match = re.search(r"(\d+\.\d+\.\d+)", line)
    assert match, "README.md release line must include the current package version"
    assert match.group(1) == expected_version, (
        f"README.md release line {match.group(1)} must match version.py {expected_version}"
    )
    assert "`traigent_schema/version.py`" in line
    assert "`CHANGELOG.md`" in line
