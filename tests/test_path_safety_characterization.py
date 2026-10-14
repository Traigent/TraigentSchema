"""Characterization tests for ``_prevalidate_tar_members`` in scripts/_path_safety.py.

Pins the ordered extraction plan for every accepted archive, and the exception message for
every rejected one: unsafe member names and link targets, special members under each
policy, duplicate destinations, non-directory parents, and missing or unsafe required
paths. Archives are built in memory. The expected values in
tests/data/path_safety_characterization.json were recorded from the implementation before
the function was split into smaller helpers. The cases reach every branch of it.
"""

from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import pytest

from tests._characterization import REPO_ROOT, Case, load_golden, load_script, observe

GOLDEN_FILE = "path_safety_characterization.json"
TARGET = load_script(
    "path_safety_characterization_target", REPO_ROOT / "scripts" / "_path_safety.py"
)

# ---------------------------------------------------------------------------
# _prevalidate_tar_members
# ---------------------------------------------------------------------------

DIR, FILE, SYM, LNK, FIFO, CHR = "dir", "file", "sym", "lnk", "fifo", "chr"


def _tar(members: list[tuple[str, str, str]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for kind, name, link in members:
            info = tarfile.TarInfo(name)
            data = b""
            if kind == DIR:
                info.type = tarfile.DIRTYPE
            elif kind == FILE:
                data = name.encode()
                info.size = len(data)
            elif kind == SYM:
                info.type, info.linkname = tarfile.SYMTYPE, link
            elif kind == LNK:
                info.type, info.linkname = tarfile.LNKTYPE, link
            elif kind == FIFO:
                info.type = tarfile.FIFOTYPE
            else:
                info.type = tarfile.CHRTYPE
            tar.addfile(info, io.BytesIO(data) if data else None)
    return buffer.getvalue()


def _plan(
    members: list[tuple[str, str, str]],
    policy: Any = "reject",
    required: tuple[str, ...] = (),
) -> Case:
    payload = _tar(members)

    def run(m: Any) -> Any:
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "dest"
            dest.mkdir()
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r") as tar:
                plans = m._prevalidate_tar_members(
                    tar, dest, special_member_policy=policy, required_paths=required
                )
            resolved = dest.resolve()
            return [
                [member.name, path.relative_to(resolved).as_posix(), rel.as_posix()]
                for member, path, rel in plans
            ]

    return run


BASIC = [(DIR, "schemas", ""), (FILE, "schemas/a.json", ""), (DIR, "schemas/sub", "")]

TAR_CASES: dict[str, Case] = {
    "empty_archive": _plan([]),
    "files_and_dirs": _plan(BASIC + [(FILE, "schemas/sub/b.json", ""), (FILE, "top.txt", "")]),
    "dot_prefixed_names": _plan([(DIR, "./x", ""), (FILE, "./x/y.json", "")]),
    "required_dir_present": _plan(BASIC, required=("schemas", "schemas/sub")),
    "required_dir_missing": _plan(BASIC, required=("schemas/other",)),
    "required_path_is_file": _plan(BASIC, required=("schemas/a.json",)),
    "required_path_unsafe": _plan(BASIC, required=("../schemas",)),
    "required_path_dot": _plan(BASIC, required=(".",)),
    "invalid_policy": _plan(BASIC, policy="allow"),
    "invalid_policy_checked_first": _plan([(FILE, "../evil", "")], policy="allow"),
    "absolute_member": _plan([(FILE, "/etc/passwd", "")]),
    "parent_traversal_member": _plan([(FILE, "a/../../b", "")]),
    "backslash_member": _plan([(FILE, "a\\b", "")]),
    "drive_member": _plan([(FILE, "C:x", "")]),
    "member_is_destination_root": _plan([(DIR, "a/..", "")]),
    "symlink_inside_reject": _plan(BASIC + [(SYM, "schemas/link", "a.json")]),
    "symlink_inside_skip": _plan(BASIC + [(SYM, "schemas/link", "a.json")], policy="skip"),
    "symlink_escapes_skip": _plan([(SYM, "link", "../../outside")], policy="skip"),
    "symlink_absolute_target": _plan([(SYM, "link", "/etc/passwd")], policy="skip"),
    "symlink_empty_target": _plan([(SYM, "link", "")], policy="skip"),
    "hardlink_inside_skip": _plan(BASIC + [(LNK, "hard", "schemas/a.json")], policy="skip"),
    "hardlink_escapes": _plan([(LNK, "hard", "../x")], policy="skip"),
    "fifo_reject": _plan(BASIC + [(FIFO, "schemas/pipe", "")]),
    "fifo_skip": _plan(BASIC + [(FIFO, "schemas/pipe", "")], policy="skip"),
    "char_device_skip": _plan([(CHR, "dev", ""), (FILE, "f", "")], policy="skip"),
    "duplicate_file": _plan([(FILE, "a.json", ""), (FILE, "a.json", "")]),
    "duplicate_via_dot_segment": _plan([(DIR, "d", ""), (DIR, "./d", "")]),
    "file_parent_of_file": _plan([(FILE, "a", ""), (FILE, "a/b", "")]),
    "file_grandparent": _plan([(FILE, "a", ""), (DIR, "a/b", ""), (FILE, "a/b/c", "")]),
    "file_grandparent_implicit_parent": _plan([(FILE, "a", ""), (FILE, "a/b/c", "")]),
    "implicit_parent_dirs": _plan([(FILE, "x/y/z.json", "")], required=("x",)),
    "skipped_member_not_a_parent": _plan(
        [(FIFO, "p", ""), (FILE, "p/f", "")], policy="skip"
    ),
}

ALL_CASES: dict[str, Case] = TAR_CASES


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], TARGET) == _golden()[case_id]
