"""Reject report-tree members at the package artifact boundary without extracting."""

from __future__ import annotations

import stat
import sys
import tarfile
import zipfile
from pathlib import Path

UNSAFE_MEMBER = "unsafe archive member"


def _validate_member_syntax(name: str) -> None:
    """Reject empty names and non-portable raw archive path syntax."""
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError(UNSAFE_MEMBER)


def _member_parts(name: str) -> list[str]:
    """Normalize harmless dot components while rejecting ambiguous or unsafe paths."""
    _validate_member_syntax(name)
    parts = name.rstrip("/").split("/")
    if any(part in ("", "..") or ":" in part for part in parts):
        raise ValueError(UNSAFE_MEMBER)
    normalized = [part for part in parts if part != "."]
    if not normalized:
        raise ValueError(UNSAFE_MEMBER)
    return normalized


def _check_reports(parts: list[str]) -> None:
    if parts and parts[0] == "reports":
        raise ValueError("report-tree member")


def _check_sdist(path: Path) -> int:
    """Check root-prefixed tar headers and count regular files without extracting."""
    count = 0
    expected_root = path.name[:-7]
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            parts = _member_parts(member.name)
            if parts[0] != expected_root:
                raise ValueError("invalid source-distribution root")
            if not (member.isfile() or member.isdir()):
                raise ValueError("unsupported archive member")
            _check_reports(parts[1:])
            count += member.isfile()
    return count


def _check_wheel(path: Path) -> int:
    """Check ZIP headers and count wheel files without extracting their content."""
    count = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            parts = _member_parts(member.filename)
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("unsupported archive member")
            _check_reports(parts)
            count += not member.is_dir()
    return count


def check_artifact(path: Path) -> None:
    """Inspect member headers in a wheel or root-prefixed source distribution."""
    if path.name.endswith(".tar.gz"):
        count = _check_sdist(path)
    elif path.name.endswith(".whl"):
        count = _check_wheel(path)
    else:
        raise ValueError("unsupported package format")
    if not count:
        raise ValueError("empty package artifact")


def main(args: list[str]) -> int:
    """Check artifacts within the invocation workspace with generic diagnostics."""
    try:
        if not args:
            raise ValueError("missing package artifacts")
        workspace = Path.cwd().resolve()
        for argument in args:
            try:
                artifact = Path(argument).resolve(strict=True)
            except RuntimeError as error:
                raise ValueError("invalid artifact path") from error
            artifact.relative_to(workspace)
            if not artifact.is_file():
                raise ValueError("not a regular artifact file")
            check_artifact(artifact)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile, EOFError):
        print("Package artifact privacy check failed.", file=sys.stderr)
        return 1
    print("Package artifact privacy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
