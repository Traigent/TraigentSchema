"""Packaging witnesses for the public certification verifier dependency."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMMAND_TIMEOUT_SECONDS = 120


def _run(
    command: list[str], *, cwd: Path, env: dict[str, str], label: str
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=_COMMAND_TIMEOUT_SECONDS,
            cwd=cwd,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"{label} timed out after {_COMMAND_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise AssertionError(f"{label} could not start: {exc}") from exc
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise AssertionError(f"{label} failed with exit code {result.returncode}: {detail}")
    return result


def _venv_python(venv_dir: Path) -> Path:
    scripts_dir = "Scripts" if os.name == "nt" else "bin"
    python_name = "python.exe" if os.name == "nt" else "python"
    return venv_dir / scripts_dir / python_name


def test_plain_install_witness_imports_relying_party_verifier() -> None:
    """A wheel installed without extras must include cryptography for the verifier."""
    witness_env = os.environ.copy()
    for variable in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV"):
        witness_env.pop(variable, None)
    witness_env["PYTHONNOUSERSITE"] = "1"

    with tempfile.TemporaryDirectory() as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        build_venv_dir = temp_dir / "build-venv"
        _run(
            [sys.executable, "-m", "venv", str(build_venv_dir)],
            cwd=temp_dir,
            env=witness_env,
            label="stdlib build venv creation",
        )
        build_python = _venv_python(build_venv_dir)
        assert build_python.is_file()

        dist_dir = temp_dir / "dist"
        _run(
            [
                str(build_python),
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--wheel-dir",
                str(dist_dir),
                str(_REPO_ROOT),
            ],
            cwd=temp_dir,
            env=witness_env,
            label="PEP 517 wheel build",
        )
        wheels = sorted(dist_dir.glob("*.whl"))
        assert len(wheels) == 1

        venv_dir = temp_dir / "install-venv"
        _run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=temp_dir,
            env=witness_env,
            label="stdlib venv creation",
        )
        venv_python = _venv_python(venv_dir)
        assert venv_python.is_file()
        _run(
            [str(venv_python), "-m", "pip", "install", "--no-input", str(wheels[0])],
            cwd=temp_dir,
            env=witness_env,
            label="plain wheel installation",
        )
        result = _run(
            [
                str(venv_python),
                "-c",
                (
                    "import cryptography; "
                    "from pathlib import Path; "
                    "import sys; "
                    "import traigent_schema.certification.relying_party_verifier as verifier; "
                    "module_path = Path(verifier.__file__).resolve(); "
                    "assert module_path.is_relative_to(Path(sys.prefix).resolve()), module_path; "
                    "assert 'site-packages' in module_path.parts, module_path; "
                    "print(verifier.__name__)"
                ),
            ],
            cwd=temp_dir,
            env=witness_env,
            label="installed verifier import",
        )
        assert result.stdout.strip() == "traigent_schema.certification.relying_party_verifier"
