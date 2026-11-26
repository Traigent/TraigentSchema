#!/usr/bin/env python3
"""Compile ``changelog.d/`` fragments into a dated ``CHANGELOG.md`` section.

Fragments are named ``<slug>.<type>.md`` (see ``changelog.d/README.md``).

    python scripts/compile_changelog.py --check
    python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD [--dry-run]

Exit codes: 0 success, 2 invalid fragments, arguments or changelog state.
"""

from __future__ import annotations

import argparse
import re
import sys
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

FRAGMENT_RE = re.compile(r"^(?P<slug>[a-z0-9][a-z0-9-]*)\.(?P<type>[a-z]+)\.md$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
POINTER = (
    "Unreleased changes are kept as fragments in changelog.d/; "
    "see changelog.d/README.md"
)
_IGNORED = {"README.md", ".gitkeep"}


class ChangelogError(Exception):
    """Raised for any condition that must exit with status 2."""


def collect_fragments(fragments_dir: Path) -> list[tuple[str, str, Path, str]]:
    """Return validated ``(type, slug, path, body)`` tuples, sorted by slug."""
    if not fragments_dir.is_dir():
        raise ChangelogError(f"fragment directory not found: {fragments_dir}")
    errors: list[str] = []
    found: list[tuple[str, str, Path, str]] = []
    for path in sorted(fragments_dir.iterdir()):
        if path.name in _IGNORED or path.is_dir():
            continue
        match = FRAGMENT_RE.match(path.name)
        if not match:
            errors.append(f"{path.name}: name must be <slug>.<type>.md (lowercase slug)")
            continue
        ftype = match.group("type")
        if ftype not in TYPES:
            errors.append(
                f"{path.name}: unknown type '{ftype}' (expected one of {', '.join(TYPES)})"
            )
            continue
        body = path.read_text(encoding="utf-8").strip("\n")
        if not body.strip():
            errors.append(f"{path.name}: fragment is empty")
            continue
        if not body.lstrip().startswith("- "):
            errors.append(f"{path.name}: content must start with a markdown bullet ('- ')")
            continue
        found.append((ftype, match.group("slug"), path, body.rstrip()))
    if errors:
        raise ChangelogError("\n".join(errors))
    found.sort(key=lambda item: item[1])
    return found


def render_section(
    version: str, date: str, fragments: list[tuple[str, str, Path, str]]
) -> str:
    """Render ``## [version] - date`` with headings in TYPES order."""
    parts = [f"## [{version}] - {date}\n"]
    for ftype, heading in TYPES.items():
        bodies = [body for t, _slug, _path, body in fragments if t == ftype]
        if bodies:
            parts.append(f"### {heading}\n" + "\n".join(bodies) + "\n")
    return "\n".join(parts)


def insert_section(changelog: str, version: str, section: str) -> str:
    """Insert ``section`` directly below the first ``[Unreleased]`` section."""
    if re.search(rf"^## \[{re.escape(version)}\]", changelog, re.MULTILINE):
        raise ChangelogError(f"CHANGELOG.md already has a section for {version}")
    lines = changelog.split("\n")
    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith("## [Unreleased]"))
    except StopIteration:
        raise ChangelogError("CHANGELOG.md has no [Unreleased] section") from None
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## [")),
        len(lines),
    )
    head = "\n".join(lines[:end]).rstrip("\n")
    tail = "\n".join(lines[end:])
    return f"{head}\n\n{section}\n{tail}"


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
        if not VERSION_RE.match(args.version):
            raise ChangelogError(f"invalid --version '{args.version}' (expected X.Y.Z)")
        if not DATE_RE.match(args.date):
            raise ChangelogError(f"invalid --date '{args.date}' (expected YYYY-MM-DD)")
        if not fragments:
            raise ChangelogError("no changelog fragments to compile")
        section = render_section(args.version, args.date, fragments)
        updated = insert_section(changelog_path.read_text(encoding="utf-8"), args.version, section)
        if args.dry_run:
            print(section)
            return 0
        changelog_path.write_text(updated, encoding="utf-8")
        for _t, _s, path, _b in fragments:
            path.unlink()
        print(f"compiled {len(fragments)} fragment(s) into CHANGELOG.md [{args.version}]")
        return 0
    except ChangelogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
