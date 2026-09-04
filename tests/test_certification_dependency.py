"""Offline structural guard for the package job's certification witness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"


def _jobs() -> dict[str, Any]:
    workflow = yaml.safe_load(_CI_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict), "ci.yml must parse as a workflow mapping"
    jobs = workflow.get("jobs")
    assert isinstance(jobs, dict), "ci.yml must define jobs"
    return jobs


def _named_step(job: dict[str, Any], name: str) -> dict[str, Any]:
    matching = [step for step in job.get("steps", []) if step.get("name") == name]
    assert len(matching) == 1, f"package job must contain exactly one {name!r} step"
    return matching[0]


def test_required_package_job_owns_plain_certification_wheel_witness() -> None:
    """The required package job, not ordinary pytest, proves the installed wheel."""
    jobs = _jobs()
    package_job = jobs["package"]
    ci_required_needs = jobs["ci-required"]["needs"]

    assert "package" in ci_required_needs
    assert package_job.get("needs") == "lint-type"

    install_tools = str(_named_step(package_job, "Install packaging tools").get("run", ""))
    assert "pip==26.2.1" in install_tools
    assert "build==1.5.0 twine==7.0.0" in install_tools
    assert install_tools.count("--only-binary :all:") == 2

    witness = str(
        _named_step(package_job, "Test installation from built wheel").get("run", "")
    )
    assert "python -m venv test_env" in witness
    assert "--only-binary :all:" in witness
    assert "--constraint requirements-dev.txt dist/*.whl" in witness
    assert "[certification]" not in witness
    assert 'metadata("traigent-schema")' in witness
    assert 'get_all("Requires-Dist")' in witness
    assert 'get_all("Provides-Extra")' in witness
    assert '"certification" in' in witness
    assert "import cryptography" in witness
    assert "from traigent_schema.certification import relying_party_verifier" in witness
