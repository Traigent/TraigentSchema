#!/usr/bin/env python3
"""Compile ``changelog.d/`` fragments into a dated ``CHANGELOG.md`` section.

Fragments are named ``<slug>.<type>.md`` (see ``changelog.d/README.md``).

    python scripts/compile_changelog.py --check
    python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD [--dry-run]

Exit codes: 0 success; 1 write, durability or delete failure after validation;
2 validation or usage error.
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
LINK_REF_RE = re.compile(r"\s*(-\s+)?\[[^\]]+\]:\s.*")
POINTER = (
    "Unreleased changes are kept as fragments in changelog.d/; "
    "see changelog.d/README.md"
)
_IGNORED = {"README.md", ".gitkeep"}

Fragment = tuple[str, str, Path, str, bytes]  # type, slug, path, body, raw bytes


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
        if LINK_REF_RE.fullmatch(ln):
            return f"{name}: link reference definitions are not allowed ({ln!r})"
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
        raw_bytes = path.read_bytes()
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{path.name}: not valid UTF-8")
            continue
        if re.search(r"\r(?!\n)", raw):
            errors.append(f"{path.name}: bare carriage return (CR without LF) is not allowed")
            continue
        body = raw.replace("\r\n", "\n").strip("\n")
        problem = _check_body(path.name, body)
        if problem:
            errors.append(problem)
            continue
        found.append((ftype, match.group("slug"), path, body.rstrip(), raw_bytes))
    if errors:
        raise ChangelogError("\n".join(errors))
    found.sort(key=lambda item: item[1])
    return found


def render_section(version: str, date: str, fragments: list[Fragment]) -> str:
    """Render ``## [version] - date`` with headings in TYPES order (LF endings)."""
    parts = [f"## [{version}] - {date}\n"]
    for ftype, heading in TYPES.items():
        bodies = [body for t, _slug, _path, body, _raw in fragments if t == ftype]
        if bodies:
            parts.append(f"### {heading}\n" + "\n".join(bodies) + "\n")
    return "\n".join(parts)


DATED_HEADING_RE = re.compile(r"## \[\d+\.\d+\.\d+\] - \d{4}-\d{2}-\d{2}")


def insert_section(changelog: str, version: str, section: str) -> str:
    """Insert ``section`` directly below the ``[Unreleased]`` pointer section.

    The file must start with the fixed structure: the first ``## `` line is
    ``## [Unreleased]``, followed by the pointer sentence and a blank line, then
    the next ``## `` line is a dated release heading. Line endings are preserved;
    ``section`` uses LF.
    """
    lines = changelog.splitlines(keepends=True)
    if any(ln.lstrip().startswith(f"## [{version}]") for ln in lines):
        raise ChangelogError(f"CHANGELOG.md already mentions a section for {version}")
    offsets = []
    pos = 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln)
    text_lines = [ln.rstrip("\r\n") for ln in lines]
    structure = (
        "CHANGELOG.md must start with '## [Unreleased]', the line '"
        + POINTER
        + "', a blank line, then a dated '## [X.Y.Z] - YYYY-MM-DD' release heading"
    )
    heads = [i for i, ln in enumerate(text_lines) if ln.startswith("## ")]
    if len(heads) < 2 or text_lines[heads[0]] != "## [Unreleased]":
        raise ChangelogError(structure)
    first, nxt = heads[0], heads[1]
    for ln in text_lines[:first]:
        if ln.lstrip(" ").startswith(("```", "~~~", "<!--")):
            raise ChangelogError(
                "CHANGELOG.md has a code fence or HTML comment before the [Unreleased] pointer"
            )
    body = [ln for ln in text_lines[first + 1 : nxt]]
    while body and not body[0].strip():
        body.pop(0)
    if len(body) < 2 or body[0] != POINTER or body[1].strip() or any(x.strip() for x in body[2:]):
        raise ChangelogError(structure)
    if not DATED_HEADING_RE.fullmatch(text_lines[nxt]):
        raise ChangelogError(structure)
    release_line = lines[nxt]
    eol = "\r\n" if release_line.endswith("\r\n") else "\n"
    end = offsets[nxt]
    return f"{changelog[:end]}{section.replace(chr(10), eol)}{eol}{changelog[end:]}"


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
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChangelogError(f"{path.name} is not valid UTF-8: {exc.reason}") from None
    except OSError as exc:
        raise ChangelogError(f"cannot read {path.name}: {exc.strerror or exc}") from None


TEMP_PREFIX = ".compiling-"


def _remove_all(fragments: list[Fragment], version: str) -> int:
    """Delete compiled fragments safely.

    Each fragment is first renamed to a hidden temporary name, so a later save by
    an editor creates a new file that is never touched. The renamed file is deleted
    only if its bytes equal the compiled bytes.
    """
    remaining: list[str] = []
    changed: list[str] = []
    for _t, _s, path, _body, raw in fragments:
        temp = path.with_name(TEMP_PREFIX + path.name)
        try:
            os.replace(path, temp)
        except OSError:
            remaining.append(str(path))
            continue
        try:
            same = temp.read_bytes() == raw
        except OSError:
            same = False
        if same:
            try:
                _unlink(temp)
                continue
            except OSError:
                pass
        # Different bytes or a failed delete: put it back if the original name is free.
        shown = str(temp)
        if not path.exists():
            try:
                os.replace(temp, path)
                shown = str(path)
            except OSError:
                pass
        (remaining if same else changed).append(shown)
    status = 0
    if changed:
        print(
            "error: these fragments changed during compilation; their new text is not in "
            "CHANGELOG.md and they were NOT deleted:\n  " + "\n  ".join(changed),
            file=sys.stderr,
        )
        status = 1
    if remaining:
        print(
            f"error: CHANGELOG.md was updated; these fragments were already compiled into "
            f"{version} but could not be deleted, remove them with `git rm`:\n  "
            + "\n  ".join(remaining),
            file=sys.stderr,
        )
        status = 1
    return status


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
            print(
                f"error: could not write CHANGELOG.md (unchanged); fragments kept:\n  "
                + "\n  ".join(str(f[2]) for f in fragments)
                + f"\n({exc})",
                file=sys.stderr,
            )
            return 1
        try:
            _fsync_dir(changelog_path.parent)
        except OSError as exc:
            print(
                f"error: CHANGELOG.md was replaced but could not be confirmed durable ({exc}); "
                "fragments were NOT deleted and are still present:\n  "
                + "\n  ".join(str(f[2]) for f in fragments),
                file=sys.stderr,
            )
            return 1
        status = _remove_all(fragments, args.version)
        if status == 0:
            print(f"compiled {len(fragments)} fragment(s) into CHANGELOG.md [{args.version}]")
        return status
    except ChangelogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
