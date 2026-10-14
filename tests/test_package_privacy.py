"""Exercise artifact privacy checks with real synthetic archive headers."""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_package_privacy.py"
FAILURE = "Package artifact privacy check failed.\n"


def run_guard(*paths: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *(str(path) for path in paths)],
        capture_output=True,
        text=True,
        check=False,
    )


def write_archive(path: Path, names: list[str], link: bool = False) -> None:
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "w:gz") as archive:
            for name in names:
                member = tarfile.TarInfo(name)
                if link:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "reports/private/README.md"
                    archive.addfile(member)
                else:
                    member.size = 9
                    archive.addfile(member, io.BytesIO(b"synthetic"))
    else:
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                member = zipfile.ZipInfo(name)
                if link:
                    member.create_system = 3
                    member.external_attr = 0o120777 << 16
                archive.writestr(member, "synthetic")


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
def test_accepts_public_members_and_nested_reports(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    prefix = "example-1.0/" if suffix == ".tar.gz" else ""
    write_archive(
        path,
        [
            prefix + name
            for name in (
                "README.md",
                "LICENSE",
                "package/module.py",
                "package/reports/README.md",
                "reports-like/README.md",
                "package/reports.md",
            )
        ],
    )
    result = run_guard(path)
    assert result.returncode == 0
    assert result.stdout == "Package artifact privacy check passed.\n"
    assert result.stderr == ""


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
@pytest.mark.parametrize(
    "relative", ["reports/README.md", "./reports/LICENSE", "reports"]
)
def test_rejects_root_reports_without_disclosing_names(
    tmp_path: Path, suffix: str, relative: str
) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    name = f"example-1.0/{relative}" if suffix == ".tar.gz" else relative
    write_archive(path, [name])
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE
    assert result.stdout == ""


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
@pytest.mark.parametrize(
    "relative",
    [
        "../README.md",
        "/reports/README.md",
        "a/../LICENSE",
        "reports\\README.md",
        "C:/README.md",
    ],
)
def test_rejects_unsafe_member_paths(
    tmp_path: Path, suffix: str, relative: str
) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    name = f"example-1.0/{relative}" if suffix == ".tar.gz" else relative
    write_archive(path, [name])
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
def test_rejects_links(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    name = "example-1.0/README.md" if suffix == ".tar.gz" else "README.md"
    write_archive(path, [name], link=True)
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


def test_rejects_mismatched_sdist_root(tmp_path: Path) -> None:
    path = tmp_path / "example-1.0.tar.gz"
    write_archive(path, ["different-1.0/README.md"])
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
def test_rejects_empty_and_corrupt_archives(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    write_archive(path, [])
    assert run_guard(path).stderr == FAILURE
    path.write_bytes(b"not an archive")
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


def test_rejects_absent_missing_and_unsupported_artifacts(tmp_path: Path) -> None:
    unsupported = tmp_path / "example.zip"
    unsupported.write_bytes(b"not a supported archive")
    for paths in [(), (tmp_path / "missing.whl",), (unsupported,), (tmp_path,)]:
        result = run_guard(*paths)
        assert result.returncode == 1
        assert result.stderr == FAILURE
        assert result.stdout == ""


def test_checks_every_supplied_artifact(tmp_path: Path) -> None:
    valid = tmp_path / "example-1.0.whl"
    invalid = tmp_path / "example-1.0.tar.gz"
    write_archive(valid, ["package/module.py"])
    write_archive(invalid, ["example-1.0/reports/private/README.md"])
    result = run_guard(valid, invalid)
    assert result.returncode == 1
    assert result.stderr == FAILURE


def test_accepts_dot_prefixed_sdist_members(tmp_path: Path) -> None:
    path = tmp_path / "example-1.0.tar.gz"
    write_archive(path, ["./example-1.0/./README.md"])
    assert run_guard(path).returncode == 0


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_rejects_special_tar_members(tmp_path: Path, kind: bytes) -> None:
    path = tmp_path / "example-1.0.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        member = tarfile.TarInfo("example-1.0/README.md")
        member.type = kind
        member.linkname = "example-1.0/reports/private/README.md"
        archive.addfile(member)
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


@pytest.mark.parametrize("suffix", [".tar.gz", ".whl"])
def test_rejects_directory_only_archives(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"example-1.0{suffix}"
    if suffix == ".tar.gz":
        with tarfile.open(path, "w:gz") as archive:
            member = tarfile.TarInfo("example-1.0/")
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
    else:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("package/", "")
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE


@pytest.mark.parametrize("name", [".", "./.", "././"])
def test_rejects_dot_only_wheel_members(tmp_path: Path, name: str) -> None:
    path = tmp_path / "example-1.0.whl"
    write_archive(path, [name])
    result = run_guard(path)
    assert result.returncode == 1
    assert result.stderr == FAILURE
