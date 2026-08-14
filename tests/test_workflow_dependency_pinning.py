from __future__ import annotations

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_WORKFLOWS = (
    "auth-taxonomy-parity.yml",
    "parity-check.yml",
    "publish.yml",
    "sonarqube-local.yml",
    "spine-trail-gate.yml",
)


@pytest.mark.parametrize("workflow_name", _WORKFLOWS)
def test_release_workflows_do_not_upgrade_unlocked_pip(workflow_name: str) -> None:
    workflow = (_REPO_ROOT / ".github" / "workflows" / workflow_name).read_text(
        encoding="utf-8"
    )

    assert "pip install --upgrade" not in workflow
    assert 'pip install -e ".[dev]"' not in workflow
    assert "pip install --no-deps -e ." not in workflow


def test_schema_workflows_install_locked_dependencies() -> None:
    for workflow_name in (
        "auth-taxonomy-parity.yml",
        "parity-check.yml",
        "publish.yml",
        "sonarqube-local.yml",
    ):
        workflow = (_REPO_ROOT / ".github" / "workflows" / workflow_name).read_text(
            encoding="utf-8"
        )
        assert "pip==26.2.1" in workflow
        assert "-r requirements-dev.txt" in workflow


def test_package_installation_verification_requires_exact_artifact_hashes() -> None:
    publish = (_REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )

    assert "built-wheel-requirements.txt" in publish
    assert "published-package-requirements.txt" in publish
    assert publish.count("--require-hashes") == 2
    assert "--no-deps" in publish

    verify_publication = publish.split("  verify-publication:", maxsplit=1)[1]
    assert "ref: ${{ github.sha }}" in verify_publication
    assert "ref: ${{ needs.verify-release-ref.outputs.verified_sha }}" not in (
        verify_publication
    )
    assert "Verify checkout matches the approved dispatch" in verify_publication
    assert "uv==0.12.4" in verify_publication
    assert "uv sync --frozen --no-dev --no-build --no-install-project" in (
        verify_publication
    )
    assert "-r requirements-dev.txt" not in verify_publication


def test_release_only_tools_are_exactly_versioned() -> None:
    publish = (_REPO_ROOT / ".github" / "workflows" / "publish.yml").read_text(
        encoding="utf-8"
    )
    sonar = (_REPO_ROOT / ".github" / "workflows" / "sonarqube-local.yml").read_text(
        encoding="utf-8"
    )
    spine = (_REPO_ROOT / ".github" / "workflows" / "spine-trail-gate.yml").read_text(
        encoding="utf-8"
    )

    assert "build==1.5.0 twine==7.0.0" in publish
    assert "pytest-timeout==2.4.0" in sonar
    assert "uv==0.12.4" in spine
    assert "uv sync --frozen --no-dev" in spine
    assert "--no-build --no-install-project" in spine
    assert "-m validation_spine.cli" in spine
