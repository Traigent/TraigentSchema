from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _read(relative_path: str) -> str:
    return (_REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_package_metadata_supports_python_310_and_newer() -> None:
    pyproject = _read("pyproject.toml")

    assert 'requires-python = ">=3.10"' in pyproject
    assert '"Programming Language :: Python :: 3.9"' not in pyproject
    assert '"Programming Language :: Python :: 3.10"' in pyproject
    assert '"pytest>=9.0.3"' in pyproject
    assert "python_version < '3.10'" not in pyproject
    assert 'target-version = "py310"' in pyproject
    assert 'python_version = "3.10"' in pyproject


def test_ci_and_sonar_match_the_supported_python_matrix() -> None:
    ci_workflow = _read(".github/workflows/ci.yml")
    sonar = _read("sonar-project.local.properties")

    assert "full Python matrix (3.10-3.12)" in ci_workflow
    assert '\'["3.10","3.11","3.12"]\'' in ci_workflow
    assert '"3.9"' not in ci_workflow
    assert "sonar.python.version=3.10,3.11,3.12" in sonar
    assert "sonar.python.version=3.9" not in sonar


def test_development_lock_uses_only_patched_pytest() -> None:
    requirements = _read("requirements-dev.txt")
    uv_lock = _read("uv.lock")

    assert "pytest==9.1.1  # CVE-2025-71176" in requirements
    assert "pytest==8.4.2" not in requirements
    assert "python_version" not in requirements

    assert 'requires-python = ">=3.10"' in uv_lock
    assert 'name = "pytest"\nversion = "9.1.1"' in uv_lock
    assert 'version = "8.4.2"' not in uv_lock
    assert "python_full_version < '3.10'" not in uv_lock


def test_cryptography_is_a_base_dependency_with_compatibility_extra() -> None:
    metadata = tomllib.loads(_read("pyproject.toml"))
    dependencies = metadata["project"]["dependencies"]
    extras = metadata["project"]["optional-dependencies"]

    assert "cryptography>=46.0.0,<51.0.0" in dependencies
    assert extras["certification"] == []
    assert "cryptography==50.0.1" in _read("requirements-dev.txt")
    assert not any(
        line.startswith("cryptography") for line in _read("requirements.txt").splitlines()
    )
