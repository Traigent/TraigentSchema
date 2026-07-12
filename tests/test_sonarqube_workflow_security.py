"""Security invariants for the privileged local SonarQube workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOW_PATH = _REPO_ROOT / ".github" / "workflows" / "sonarqube-local.yml"


def _workflow() -> dict[str, Any]:
    workflow = yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), "sonarqube-local.yml must parse as a mapping"
    return workflow


def test_privileged_sonarqube_job_has_only_trusted_triggers() -> None:
    workflow = _workflow()
    job = workflow["jobs"]["sonarqube-quality-gate"]
    triggers = workflow.get("on", workflow.get(True))

    assert job["runs-on"] == "large"
    assert "SONAR_TOKEN" in workflow["env"]
    assert isinstance(triggers, dict)
    assert "pull_request" not in triggers
    assert "pull_request_target" not in triggers
    assert triggers["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in triggers
    assert "schedule" not in triggers
    assert "if" not in job


def test_checkout_uses_only_the_exact_trusted_event_sha() -> None:
    workflow = _workflow()
    steps = workflow["jobs"]["sonarqube-quality-gate"]["steps"]

    checkouts = [step for step in steps if step.get("uses") == "actions/checkout@v7"]
    assert len(checkouts) == 1
    trusted_checkout = checkouts[0]
    assert trusted_checkout["name"] == "Checkout trusted event ref"
    assert "if" not in trusted_checkout
    assert trusted_checkout["with"]["ref"] == "${{ github.sha }}"
    assert trusted_checkout["with"]["persist-credentials"] is False


def test_privileged_tool_downloads_are_versioned_and_integrity_checked() -> None:
    workflow = _workflow()
    env = workflow["env"]
    steps = workflow["jobs"]["sonarqube-quality-gate"]["steps"]
    install = next(
        step for step in steps if step["name"] == "Install kubectl + sonar-scanner (arm64)"
    )

    assert env["KUBECTL_VERSION"].startswith("v")
    assert len(env["KUBECTL_SHA256"]) == 64
    assert env["SONAR_SCANNER_VERSION"]
    assert len(env["SONAR_SCANNER_SHA256"]) == 64
    assert "release/stable.txt" not in install["run"]
    assert 'echo "${KUBECTL_SHA256}  /tmp/kubectl" | sha256sum -c -' in install["run"]
    assert 'echo "${SONAR_SCANNER_SHA256}  /tmp/sc.zip" | sha256sum -c -' in install["run"]
