"""Offline structural guard for the package job's certification witness."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_PROVENANCE_FRAGMENTS = (
    "python -I - <<'PY'",
    "Path(sys.prefix).resolve()",
    "site.getsitepackages()",
    "for module in (traigent_schema, relying_party_verifier)",
    "ClientCoAttestationContext,",
    "derive_client_key_ref,",
    "prepare_client_co_attestation,",
    "Path(module.__file__).resolve()",
    "module_path.is_relative_to(environment_root)",
    "any(module_path.is_relative_to(path) for path in site_packages)",
)


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


def _assert_installed_module_provenance(witness: str) -> None:
    for fragment in _PROVENANCE_FRAGMENTS:
        assert fragment in witness, f"wheel witness lost provenance guard: {fragment}"


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
    _assert_installed_module_provenance(witness)


@pytest.mark.parametrize("fragment", _PROVENANCE_FRAGMENTS)
def test_wheel_witness_provenance_guard_rejects_each_removed_check(fragment: str) -> None:
    package_job = _jobs()["package"]
    witness = str(
        _named_step(package_job, "Test installation from built wheel").get("run", "")
    )
    mutated = witness.replace(fragment, "", 1)

    with pytest.raises(AssertionError, match="lost provenance guard"):
        _assert_installed_module_provenance(mutated)
