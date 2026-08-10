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
import tarfile
from pathlib import Path

__all__ = [
    "MAX_GIT_REF_LEN",
    "SAFE_GIT_REF_RE",
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
    bad_shape = (
        ".." in ref
        or "//" in ref
        or "@{" in ref
        or ref.endswith(("/", ".", ".lock"))
    )
    if bad_shape:
        raise ValueError(f"{arg_name} is not an accepted git ref shape: {ref!r}")
    return ref


def validate_tar_members_stay_within(tar: tarfile.TarFile, dest: Path) -> None:
    """Refuse a tar whose members, or whose links, would land outside ``dest``.

    Checks the member path itself (``../`` traversal) and, for symlinks and hard links,
    where the link would point. Call this BEFORE extracting.
    """
    resolved_dest = Path(dest).resolve()
    for member in tar.getmembers():
        member_path = (resolved_dest / member.name).resolve()
        if member_path != resolved_dest and not is_relative_to(member_path, resolved_dest):
            raise ValueError(f"git archive member escapes destination: {member.name!r}")
        if member.issym() or member.islnk():
            link_target = (member_path.parent / member.linkname).resolve()
            if link_target != resolved_dest and not is_relative_to(link_target, resolved_dest):
                raise ValueError(f"git archive link escapes destination: {member.name!r}")
