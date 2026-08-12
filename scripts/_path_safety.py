"""Shared path- and git-ref-containment helpers for the scripts/ CLIs.

WHY THIS MODULE EXISTS
----------------------
``breaking_schema_check.py`` and ``refresh_consumer_schema_references.py`` were hardened
in the same pass and ended up with byte-identical copies of these helpers. Two copies of
a security control is worse than one: they drift, and a fix applied to whichever file the
author had open silently leaves the other exposed. That already happened here —
``_validate_tar_members_stay_within`` was added to only one of the two, leaving the other
extracting a git archive with no member checking at all.

Every consumer is a script run as ``python scripts/<name>.py``, so ``scripts/`` is on
``sys.path`` automatically. Tests that load a script via ``spec_from_file_location`` do
not get that, so each consumer inserts its own directory on ``sys.path`` before importing
this module.

These are defence-in-depth controls, not the primary trust boundary: the inputs are git
refs and paths supplied by a maintainer or by CI. They exist so that a malicious or
accidental value (a ref starting with ``-`` that git reads as a flag, a tar member with
``..`` in its path, a symlink pointing out of the extraction root) cannot turn a
schema-diffing script into an arbitrary-file-read.
"""

from __future__ import annotations

import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal

__all__ = [
    "MAX_GIT_REF_LEN",
    "SAFE_GIT_REF_RE",
    "extract_validated_tar_members",
    "is_relative_to",
    "resolve_existing_dir",
    "resolve_path_within",
    "safe_git_ref",
    "validate_tar_members_stay_within",
]

SAFE_GIT_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-^~]*$")
MAX_GIT_REF_LEN = 200


def is_relative_to(path: Path, root: Path) -> bool:
    """True if ``path`` is at or below ``root``. (Path.is_relative_to is 3.9+ only.)"""
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_path_within(raw_path: str | Path, root: Path, arg_name: str) -> Path:
    """Resolve ``raw_path`` and require the result to stay at or below ``root``.

    Both sides are ``resolve()``d first, so ``..`` segments and symlinked parents are
    collapsed before the comparison rather than after.
    """
    resolved_root = Path(root).expanduser().resolve()
    resolved_path = Path(raw_path).expanduser().resolve()
    if resolved_path != resolved_root and not is_relative_to(resolved_path, resolved_root):
        raise ValueError(f"{arg_name} must stay inside {resolved_root}, got {resolved_path}")
    return resolved_path


def resolve_existing_dir(raw_path: str | Path, arg_name: str) -> Path:
    path = Path(raw_path).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"{arg_name} is not a directory: {path}")
    return path


def safe_git_ref(raw_ref: str, arg_name: str) -> str:
    """Reject anything that is not plainly a git ref before it reaches a git argv.

    The leading-dash check is the load-bearing one: ``git archive --upload-pack=...``
    smuggled in as a "ref" would be read by git as a flag.
    """
    ref = raw_ref.strip()
    if ref != raw_ref or not ref:
        raise ValueError(f"{arg_name} must be a non-empty git ref without surrounding whitespace")
    if len(ref) > MAX_GIT_REF_LEN:
        raise ValueError(f"{arg_name} is too long to be accepted as a git ref")
    if ref.startswith("-"):
        raise ValueError(f"{arg_name} must not start with '-': {ref!r}")
    if not SAFE_GIT_REF_RE.fullmatch(ref):
        raise ValueError(
            f"{arg_name} contains characters outside the accepted git-ref set: {ref!r}"
        )
    bad_shape = ".." in ref or "//" in ref or "@{" in ref or ref.endswith(("/", ".", ".lock"))
    if bad_shape:
        raise ValueError(f"{arg_name} is not an accepted git ref shape: {ref!r}")
    return ref


def _safe_tar_relative_path(raw_path: str, description: str) -> PurePosixPath:
    """Return a cross-platform-safe archive-relative path, or raise before extraction."""
    posix_path = PurePosixPath(raw_path)
    windows_path = PureWindowsPath(raw_path)
    if (
        not raw_path
        or raw_path in {".", "./"}
        or "\x00" in raw_path
        or "\\" in raw_path
        or posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
        or ".." in posix_path.parts
        or ".." in windows_path.parts
    ):
        raise ValueError(f"unsafe tar {description}: {raw_path!r}")
    return posix_path


def _member_destination(member: tarfile.TarInfo, resolved_dest: Path) -> tuple[PurePosixPath, Path]:
    relative_path = _safe_tar_relative_path(member.name, "member path")
    member_path = (resolved_dest / relative_path).resolve()
    if member_path == resolved_dest or not is_relative_to(member_path, resolved_dest):
        raise ValueError(f"tar member escapes destination: {member.name!r}")
    return relative_path, member_path


def _validate_tar_link_stays_within(
    member: tarfile.TarInfo, member_path: Path, resolved_dest: Path
) -> None:
    link_name = member.linkname
    link_posix = PurePosixPath(link_name)
    link_windows = PureWindowsPath(link_name)
    if (
        not link_name
        or "\x00" in link_name
        or "\\" in link_name
        or link_posix.is_absolute()
        or link_windows.is_absolute()
        or link_windows.drive
    ):
        raise ValueError(f"unsafe tar link target: {member.name!r}")

    # tarfile resolves hard-link names from the archive root, but symlink targets from
    # the symlink's parent. Both forms must stay within the untrusted archive's root.
    link_base = member_path.parent if member.issym() else resolved_dest
    link_target = (link_base / link_posix).resolve()
    if link_target != resolved_dest and not is_relative_to(link_target, resolved_dest):
        raise ValueError(f"git archive link escapes destination: {member.name!r}")


def _validate_tar_members_stay_within(members: list[tarfile.TarInfo], resolved_dest: Path) -> None:
    for member in members:
        _, member_path = _member_destination(member, resolved_dest)
        if member.issym() or member.islnk():
            _validate_tar_link_stays_within(member, member_path, resolved_dest)


def validate_tar_members_stay_within(tar: tarfile.TarFile, dest: Path) -> None:
    """Refuse a tar whose members, or whose links, would land outside ``dest``."""
    _validate_tar_members_stay_within(tar.getmembers(), Path(dest).resolve())


def _prevalidate_tar_members(
    tar: tarfile.TarFile,
    dest: Path,
    *,
    special_member_policy: Literal["reject", "skip"],
    required_paths: tuple[str, ...],
) -> list[tuple[tarfile.TarInfo, Path, PurePosixPath]]:
    """Approve every archive operation before the first destination write."""
    if special_member_policy not in {"reject", "skip"}:
        raise ValueError(f"unsupported special-member policy: {special_member_policy!r}")

    resolved_dest = Path(dest).resolve()
    members = tar.getmembers()
    _validate_tar_members_stay_within(members, resolved_dest)

    plans: list[tuple[tarfile.TarInfo, Path, PurePosixPath]] = []
    planned_by_destination: dict[Path, tarfile.TarInfo] = {}
    for member in members:
        relative_path, member_path = _member_destination(member, resolved_dest)
        if not (member.isfile() or member.isdir()):
            if special_member_policy == "reject":
                raise ValueError(f"unsafe tar member type: {member.name!r}")
            continue
        if member_path in planned_by_destination:
            raise ValueError(f"duplicate tar member destination: {member.name!r}")
        planned_by_destination[member_path] = member
        plans.append((member, member_path, relative_path))

    for member, member_path, _ in plans:
        parent = member_path.parent
        while parent != resolved_dest:
            parent_member = planned_by_destination.get(parent)
            if parent_member is not None and not parent_member.isdir():
                raise ValueError(
                    f"tar member has a non-directory parent: {member.name!r} under "
                    f"{parent_member.name!r}"
                )
            parent = parent.parent

    required_relative_paths = tuple(
        _safe_tar_relative_path(path, "required path") for path in required_paths
    )
    for required_path in required_relative_paths:
        if not any(path == required_path and member.isdir() for member, _, path in plans):
            raise ValueError(f"required tar directory is missing: {required_path.as_posix()!r}")
    return plans


def extract_validated_tar_members(
    tar: tarfile.TarFile,
    dest: Path,
    *,
    special_member_policy: Literal["reject", "skip"] = "reject",
    required_paths: tuple[str, ...] = (),
) -> None:
    """Materialize only prevalidated regular files and directories from ``tar``.

    Schema archives use the default ``reject`` policy: links and special members cannot
    stand in for a required schema path. Consumer archives use ``skip`` so unrelated,
    tracked symlinks do not abort source scanning; skipped members are never materialized.
    Every member name, link target, type, destination collision, required-path condition,
    and policy decision is checked before any directory or file is created.
    """
    plans = _prevalidate_tar_members(
        tar,
        dest,
        special_member_policy=special_member_policy,
        required_paths=required_paths,
    )
    for member, member_path, _ in plans:
        if member.isdir():
            member_path.mkdir(parents=True, exist_ok=True)
            continue

        payload = tar.extractfile(member)
        if payload is None:
            raise ValueError(f"tar member has no readable payload: {member.name!r}")
        member_path.parent.mkdir(parents=True, exist_ok=True)
        with payload, member_path.open("xb") as output:
            shutil.copyfileobj(payload, output)
