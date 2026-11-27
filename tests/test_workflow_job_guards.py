"""Every workflow job is bounded, and every pull_request workflow is cancellable.

A job without ``timeout-minutes`` runs to GitHub's 6 hour default when it hangs,
and a pull_request workflow without a ``concurrency`` group keeps burning runners
on superseded pushes. #701 found three PR workflows and nine jobs with neither
guard; this pins the convention ci.yml already follows so a new workflow cannot
drift back.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"


def _workflows() -> dict[str, dict[str, Any]]:
    paths = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert paths, f"no workflows found under {WORKFLOWS_DIR}"
    parsed: dict[str, dict[str, Any]] = {}
    for path in paths:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict), f"{path.name} must parse as a workflow mapping"
        parsed[path.name] = document
    return parsed


def _triggers(workflow: dict[str, Any]) -> set[str]:
    # PyYAML reads the bare `on:` key as the boolean True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(on)
    if isinstance(on, dict):
        return set(on)
    return set()


def test_every_job_declares_an_integer_timeout_minutes() -> None:
    missing = [
        f"{name}:{job_id}"
        for name, workflow in _workflows().items()
        for job_id, job in (workflow.get("jobs") or {}).items()
        if not isinstance(job.get("timeout-minutes"), int)
    ]

    assert not missing, f"jobs without an integer timeout-minutes: {missing}"


def test_every_pull_request_workflow_declares_a_concurrency_group() -> None:
    missing = [
        name
        for name, workflow in _workflows().items()
        if "pull_request" in _triggers(workflow)
        and not (
            isinstance(workflow.get("concurrency"), dict)
            and workflow["concurrency"].get("group")
        )
    ]

    assert not missing, f"pull_request workflows without a concurrency group: {missing}"
