#!/usr/bin/env python3
"""Compile ``changelog.d/`` fragments into a dated ``CHANGELOG.md`` section.

Fragments are named ``<slug>.<type>.md`` (see ``changelog.d/README.md``).

    python scripts/compile_changelog.py --check
    python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD [--dry-run]

Exit codes: 0 success, 2 invalid fragments, arguments or changelog state.
"""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

# Fragment type -> CHANGELOG heading, in the order the headings are emitted.
TYPES: dict[str, str] = {
    "breaking": "Breaking",
    "added": "Added",
    "changed": "Changed",
    "deprecated": "Deprecated",
    "removed": "Removed",
    "fixed": "Fixed",
}

FRAGMENT_RE = re.compile(r"(?P<slug>[a-z0-9][a-z0-9-]*)\.(?P<type>[a-z]+)\.md")
VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
BULLET_RE = re.compile(r"- +\S.*")
CONTINUATION_RE = re.compile(r" {2,}\S.*")
POINTER = (
    "Unreleased changes are kept as fragments in changelog.d/; "
    "see changelog.d/README.md"
)
_IGNORED = {"README.md", ".gitkeep"}

Fragment = tuple[str, str, Path, str]


class ChangelogError(Exception):
    """Raised for any condition that must exit with status 2."""


def _unlink(path: Path) -> None:
    path.unlink()


def _check_body(name: str, body: str) -> str | None:
    """Return an error message when ``body`` is not valid fragment content."""
    lines = [ln for ln in body.split("\n") if ln.strip()]
    if not lines:
        return f"{name}: fragment is empty"
    column = -1
    for ln in lines:
        bullet = BULLET_RE.fullmatch(ln)
        if bullet:
            column = len(ln) - len(ln[2:].lstrip(" "))
            continue
        if column < 0:
            return f"{name}: content must start with a markdown bullet ('- text')"
        indent = len(ln) - len(ln.lstrip(" "))
        if not CONTINUATION_RE.fullmatch(ln) or indent < column:
            return (
                f"{name}: line {ln!r} must be a '- text' bullet or a continuation "
                f"indented to the bullet text (column {column})"
            )
    return None


def collect_fragments(fragments_dir: Path) -> list[Fragment]:
    """Return validated ``(type, slug, path, body)`` tuples, sorted by slug."""
    if fragments_dir.is_symlink() or (
        hasattr(fragments_dir, "is_junction") and fragments_dir.is_junction()
    ):
        raise ChangelogError(f"{fragments_dir} must not be a symlink or junction")
    if not fragments_dir.is_dir():
        raise ChangelogError(f"fragment directory not found: {fragments_dir}")
    base = Path(os.path.join(os.path.realpath(fragments_dir.parent), fragments_dir.name))
    if os.path.realpath(fragments_dir) != str(base):
        raise ChangelogError(f"{fragments_dir} must be a real directory directly under the repository root")
    errors: list[str] = []
    found: list[Fragment] = []
    for path in sorted(fragments_dir.iterdir()):
        mode = os.lstat(path).st_mode
        if not stat.S_ISREG(mode):
            errors.append(f"{path.name}: must be a regular file (no symlinks or directories)")
            continue
        if Path(os.path.realpath(path)).parent != base:
            errors.append(f"{path.name}: resolves outside {fragments_dir.name}/")
            continue
        if path.name in _IGNORED:
            continue
        match = FRAGMENT_RE.fullmatch(path.name)
        if not match:
            errors.append(f"{path.name}: name must be <slug>.<type>.md (lowercase slug)")
            continue
        ftype = match.group("type")
        if ftype not in TYPES:
            errors.append(
                f"{path.name}: unknown type '{ftype}' (expected one of {', '.join(TYPES)})"
            )
            continue
        raw = path.read_bytes().decode("utf-8")
        if re.search(r"\r(?!\n)", raw):
            errors.append(f"{path.name}: bare carriage return (CR without LF) is not allowed")
            continue
        body = raw.replace("\r\n", "\n").strip("\n")
        problem = _check_body(path.name, body)
        if problem:
            errors.append(problem)
            continue
        found.append((ftype, match.group("slug"), path, body.rstrip()))
    if errors:
        raise ChangelogError("\n".join(errors))
    found.sort(key=lambda item: item[1])
    return found


def render_section(version: str, date: str, fragments: list[Fragment]) -> str:
    """Render ``## [version] - date`` with headings in TYPES order (LF endings)."""
    parts = [f"## [{version}] - {date}\n"]
    for ftype, heading in TYPES.items():
        bodies = [body for t, _slug, _path, body in fragments if t == ftype]
        if bodies:
            parts.append(f"### {heading}\n" + "\n".join(bodies) + "\n")
    return "\n".join(parts)


def _headings_outside_fences(text: str) -> list[tuple[int, str]]:
    """Return ``(offset, line)`` for each ``## [`` heading outside fenced code blocks."""
    found: list[tuple[int, str]] = []
    fence: tuple[str, int] | None = None
    offset = 0
    for raw in text.splitlines(keepends=True):
        line = raw.rstrip("\r\n")
        stripped = line.lstrip(" ")
        if len(line) - len(stripped) <= 3 and stripped[:3] in ("```", "~~~"):
            marker = stripped[0]
            run_len = len(stripped) - len(stripped.lstrip(marker))
            if fence is None:
                fence = (marker, run_len)
            elif marker == fence[0] and run_len >= fence[1] and not stripped[run_len:].strip():
                fence = None
        elif fence is None and line.startswith("## ["):
            found.append((offset, line))
        offset += len(raw)
    return found


def insert_section(changelog: str, version: str, section: str) -> str:
    """Insert ``section`` directly below the current ``[Unreleased]`` pointer.

    Line endings of ``changelog`` are preserved; ``section`` uses LF. Only
    headings outside fenced code blocks count.
    """
    headings = _headings_outside_fences(changelog)
    if any(line.startswith(f"## [{version}]") for _o, line in headings):
        raise ChangelogError(f"CHANGELOG.md already has a section for {version}")
    first_unreleased = next((i for i, (_o, ln) in enumerate(headings) if ln.startswith("## [Unreleased]")), None)
    first_dated = next((i for i, (_o, ln) in enumerate(headings) if re.match(r"## \[\d+\.\d+\.\d+\]", ln)), None)
    if first_unreleased is None or (first_dated is not None and first_dated < first_unreleased):
        raise ChangelogError(
            "CHANGELOG.md must have its [Unreleased] pointer (outside code fences) "
            "before the first dated release"
        )
    eol = "\r\n" if "\r\n" in changelog else "\n"
    end = headings[first_unreleased + 1][0] if first_unreleased + 1 < len(headings) else len(changelog)
    head = changelog[:end].rstrip("\r\n")
    tail = changelog[end:]
    body = section.replace("\n", eol)
    return f"{head}{eol}{eol}{body}{eol}{tail}"


def _fsync_dir(path: Path) -> None:
    """Flush a directory entry to disk (POSIX only)."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` (UTF-8) via a same-directory temp file."""
    mode = path.stat().st_mode
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".changelog-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            print(f"error: could not remove temporary file {tmp_name}", file=sys.stderr)
        raise
    try:  # restore the original mode after the replace, best effort
        os.chmod(path, stat.S_IMODE(mode))
    except OSError:
        pass


def _read_changelog(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _remove_all(fragments: list[Fragment], version: str) -> int:
    remaining = []
    for _t, _s, path, _b in fragments:
        try:
            _unlink(path)
        except OSError:
            remaining.append(str(path))
    if remaining:
        print(
            f"error: CHANGELOG.md was updated; these fragments were already compiled into "
            f"{version} but could not be deleted, remove them with `git rm`:\n  "
            + "\n  ".join(remaining),
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", help="release version, X.Y.Z")
    parser.add_argument("--date", help="release date, YYYY-MM-DD")
    parser.add_argument("--check", action="store_true", help="only validate fragments")
    parser.add_argument("--dry-run", action="store_true", help="print the section, write nothing")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent,
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    fragments_dir = args.root / "changelog.d"
    changelog_path = args.root / "CHANGELOG.md"
    try:
        fragments = collect_fragments(fragments_dir)
        if args.check:
            print(f"ok: {len(fragments)} changelog fragment(s) valid")
            return 0
        if not args.version or not args.date:
            raise ChangelogError("--version and --date are required unless --check is given")
        if not VERSION_RE.fullmatch(args.version):
            raise ChangelogError(f"invalid --version '{args.version}' (expected X.Y.Z)")
        if not DATE_RE.fullmatch(args.date):
            raise ChangelogError(f"invalid --date '{args.date}' (expected YYYY-MM-DD)")
        if not fragments:
            raise ChangelogError("no changelog fragments to compile")
        section = render_section(args.version, args.date, fragments)
        updated = insert_section(_read_changelog(changelog_path), args.version, section)
        if args.dry_run:
            print(section)
            return 0
        try:
            write_atomic(changelog_path, updated)
        except OSError as exc:
            print(f"error: could not write CHANGELOG.md (unchanged, fragments kept): {exc}",
                  file=sys.stderr)
            return 1
        try:
            _fsync_dir(changelog_path.parent)
        except OSError:
            pass
        status = _remove_all(fragments, args.version)
        if status == 0:
            print(f"compiled {len(fragments)} fragment(s) into CHANGELOG.md [{args.version}]")
        return status
    except ChangelogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
