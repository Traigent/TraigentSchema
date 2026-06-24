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
    assert len(steps) == 3, "ci.yml should set up Python in lint-type, test, and package jobs"

    for job_name, step in steps:
        config = step.get("with", {})
        assert config.get("cache") == "pip", f"{job_name} must enable setup-python pip caching"
        assert config.get("cache-dependency-path") == "pyproject.toml", (
            f"{job_name} must key pip cache from pyproject.toml"
        )


def test_ci_workflow_cancels_superseded_runs() -> None:
    concurrency = _ci_workflow().get("concurrency")
    assert concurrency == {
        "group": "schema-ci-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": True,
    }


def test_ci_workflow_caps_all_jobs_with_timeouts() -> None:
    jobs = _ci_workflow()["jobs"]
    missing = [name for name, job in jobs.items() if "timeout-minutes" not in job]
    assert not missing, f"ci.yml jobs missing timeout-minutes: {missing}"


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
