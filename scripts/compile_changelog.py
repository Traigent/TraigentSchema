#!/usr/bin/env python3
"""Compile ``changelog.d/`` fragments into a dated ``CHANGELOG.md`` section.

Fragments are named ``<slug>.<type>.md`` (see ``changelog.d/README.md``).

    python scripts/compile_changelog.py --check
    python scripts/compile_changelog.py --version X.Y.Z --date YYYY-MM-DD [--dry-run]

Exit codes: 0 success; 1 write, durability or delete failure after validation;
2 validation or usage error.

git is resolved through PATH and is run from the repository root.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

CHANGELOG_NAME = "CHANGELOG.md"
FRAGMENTS_DIRNAME = "changelog.d"

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
TEMP_PREFIX = ".compiling-"

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


# Closed table of git invocations: every argument vector is a constant tuple, looked
# up by operation name. No value from the command line or from a file name is ever
# part of an argument vector; git runs with the repository root as its working
# directory instead.
_GIT_ARGV: dict[str, tuple[str, ...]] = {
    "toplevel": ("git", "rev-parse", "--show-toplevel"),
    "object-format": ("git", "rev-parse", "--show-object-format"),
    "status": (
        "git", "status", "--porcelain=v1", "-z", "--untracked-files=all",
        "--ignored=matching", "--", FRAGMENTS_DIRNAME, CHANGELOG_NAME,
    ),
    "batch": ("git", "cat-file", "--batch"),
    "tree": (
        "git", "ls-tree", "-r", "-z", "--full-tree", "HEAD", "--",
        FRAGMENTS_DIRNAME, CHANGELOG_NAME,
    ),
}


def _git(root: Path, op: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """Run one operation of the closed git table in ``root``; ``stdin`` is data, not argv."""
    argv = _GIT_ARGV.get(op)
    if argv is None:
        raise ChangelogError("unknown git operation")
    return subprocess.run(  # noqa: S603
        argv, cwd=root, capture_output=True, check=False, shell=False, input=stdin
    )


def _hash_function(root: Path) -> str:
    """Return the hashlib name of the repository's object format."""
    result = _git(root, "object-format")
    if result.returncode != 0:
        return "sha1"  # git older than --show-object-format only knows sha1
    name = result.stdout.decode().strip()
    if name in ("", "--show-object-format"):
        return "sha1"  # an old git echoes the unknown flag and exits 0
    if name not in ("sha1", "sha256"):
        raise ChangelogError(f"unsupported git object format {name!r}")
    return name


def _head_blobs(root: Path, message: str) -> dict[str, str]:
    """Return ``{path: blob id}`` for the changelog inputs committed at HEAD."""
    result = _git(root, "tree")
    blobs: dict[str, str] = {}
    if result.returncode != 0:
        return blobs  # no commit yet: every input is untracked
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        meta, _tab, raw_path = entry.partition(b"\t")
        fields = meta.decode().split()
        if len(fields) != 3:
            raise ChangelogError(f"{message} (unreadable git tree)")
        blobs[raw_path.decode("utf-8", "surrogateescape")] = fields[2]
    return blobs


def _blob_id(algorithm: str, data: bytes) -> str:
    header = b"blob %d\0" % len(data)
    return hashlib.new(algorithm, header + data).hexdigest()


def _fragment_inputs(root: Path) -> list[str]:
    """Return the changelog inputs, relative to the repository root."""
    inputs = [CHANGELOG_NAME]
    fragments_dir = root / FRAGMENTS_DIRNAME
    if fragments_dir.is_dir():
        for p in sorted(fragments_dir.iterdir()):
            if p.name in _IGNORED:
                continue
            if any(ch in p.name for ch in ("\n", "\r", "\\")):
                raise ChangelogError(
                    f"fragment name {p.name!r} contains an unsafe character"
                )
            inputs.append(f"{FRAGMENTS_DIRNAME}/{p.name}")
    return inputs


def _check_input_at_head(
    root: Path, rel: str, message: str, blobs: dict[str, str], algorithm: str
) -> tuple[str, str, bytes] | None:
    """Return ``(rel, blob id, working-tree bytes)`` for a matching input."""
    path = root / rel
    if not path.is_file() or path.is_symlink():
        return None  # reported by the regular validation
    if rel not in blobs:
        raise ChangelogError(f"{message} ({rel} is untracked or ignored)")
    try:
        current = path.read_bytes()
    except OSError as exc:
        raise ChangelogError(f"cannot read {rel}: {exc.strerror or exc}") from None
    if _blob_id(algorithm, current) != blobs[rel]:
        raise ChangelogError(f"{message} ({rel} differs from HEAD)")
    return rel, blobs[rel], current


def _check_readable(root: Path, entries: list[tuple[str, str, bytes]], message: str) -> None:
    """Require every committed blob to exist and to equal the working-tree bytes."""
    if not entries:
        return
    stdin = b"".join(blob.encode() + b"\n" for _rel, blob, _data in entries)
    result = _git(root, "batch", stdin)
    out = result.stdout
    pos = 0
    for rel, blob, data in entries:
        end = out.find(b"\n", pos)
        fields = out[pos:end].split() if end >= 0 else []
        if result.returncode != 0 or len(fields) != 3 or fields[0] != blob.encode() or fields[1] != b"blob":
            raise ChangelogError(f"{message} ({rel} is not readable at HEAD)")
        try:
            size = int(fields[2])
        except ValueError:
            raise ChangelogError(f"{message} ({rel} is not readable at HEAD)") from None
        start = end + 1
        if size != len(data) or out[start : start + size] != data:
            raise ChangelogError(f"{message} ({rel} differs from HEAD)")
        pos = start + size + 1


def require_clean_git(root: Path) -> None:
    """Compile mode needs every input committed at HEAD and unmodified.

    The per-file check (tracked at HEAD, working-tree bytes hash to HEAD's blob) is the
    guarantee; ``git status`` is only an extra refusal. Everything the compile removes
    is then recoverable from git.
    """
    message = "commit or stash changelog changes before compiling"
    try:
        top = _git(root, "toplevel")
        if top.returncode != 0 or os.path.realpath(top.stdout.decode().strip()) != os.path.realpath(root):
            raise ChangelogError(f"{message} (the repository root must be a git work tree)")
        algorithm = _hash_function(root)
        blobs = _head_blobs(root, message)
        checked = [
            entry for rel in _fragment_inputs(root)
            if (entry := _check_input_at_head(root, rel, message, blobs, algorithm))
        ]
        _check_readable(root, checked, message)
        status = _git(root, "status")
    except OSError:
        raise ChangelogError(f"{message} (git is not available)") from None
    if status.returncode != 0 or status.stdout.strip():
        raise ChangelogError(message)


def _check_fragments_dir(fragments_dir: Path) -> Path:
    """Validate the directory and return its real base path."""
    if fragments_dir.is_symlink() or (
        hasattr(fragments_dir, "is_junction") and fragments_dir.is_junction()
    ):
        raise ChangelogError(f"{fragments_dir} must not be a symlink or junction")
    if not fragments_dir.is_dir():
        raise ChangelogError(f"fragment directory not found: {fragments_dir}")
    base = Path(os.path.join(os.path.realpath(fragments_dir.parent), fragments_dir.name))
    if os.path.realpath(fragments_dir) != str(base):
        raise ChangelogError(f"{fragments_dir} must be a real directory directly under the repository root")
    return base


def _location_error(path: Path, base: Path, fragments_dir: Path) -> str | None:
    if not stat.S_ISREG(os.lstat(path).st_mode):
        return f"{path.name}: must be a regular file (no symlinks or directories)"
    if Path(os.path.realpath(path)).parent != base:
        return f"{path.name}: resolves outside {fragments_dir.name}/"
    return None


def _parse_name(path: Path) -> tuple[re.Match[str] | None, str | None]:
    if path.name.startswith(TEMP_PREFIX):
        return None, f"{path.name}: leftover from an interrupted compile; inspect it with git and remove it"
    match = FRAGMENT_RE.fullmatch(path.name)
    if not match:
        return None, f"{path.name}: name must be <slug>.<type>.md (lowercase slug)"
    ftype = match.group("type")
    if ftype not in TYPES:
        return None, f"{path.name}: unknown type '{ftype}' (expected one of {', '.join(TYPES)})"
    return match, None


def _read_body(path: Path) -> tuple[bytes, str, str | None]:
    """Return raw bytes, the normalized body and an error message, if any."""
    raw_bytes = path.read_bytes()
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return raw_bytes, "", f"{path.name}: not valid UTF-8"
    if re.search(r"\r(?!\n)", raw):
        return raw_bytes, "", f"{path.name}: bare carriage return (CR without LF) is not allowed"
    body = raw.replace("\r\n", "\n").strip("\n")
    return raw_bytes, body, _check_body(path.name, body)


def _load_fragment(path: Path, base: Path, fragments_dir: Path) -> Fragment | str | None:
    """Return a fragment, an error message, or None for an ignored file."""
    problem = _location_error(path, base, fragments_dir)
    if problem or path.name in _IGNORED:
        return problem
    match, problem = _parse_name(path)
    if match is None:
        return problem
    raw_bytes, body, problem = _read_body(path)
    if problem:
        return problem
    return (match.group("type"), match.group("slug"), path, body.rstrip(), raw_bytes)


def collect_fragments(fragments_dir: Path) -> list[Fragment]:
    """Return validated ``(type, slug, path, body)`` tuples, sorted by slug."""
    base = _check_fragments_dir(fragments_dir)
    errors: list[str] = []
    found: list[Fragment] = []
    for path in sorted(fragments_dir.iterdir()):
        loaded = _load_fragment(path, base, fragments_dir)
        if isinstance(loaded, str):
            errors.append(loaded)
        elif loaded is not None:
            found.append(loaded)
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


def _structure_message() -> str:
    return (
        "CHANGELOG.md must start with '## [Unreleased]', the line '"
        + POINTER
        + "', a blank line, then a dated '## [X.Y.Z] - YYYY-MM-DD' release heading"
    )


def _check_pointer_section(text_lines: list[str]) -> tuple[int, int]:
    """Validate the pointer section; return the indexes of its heading and the next."""
    structure = _structure_message()
    heads = [i for i, ln in enumerate(text_lines) if ln.startswith("## ")]
    if len(heads) < 2 or text_lines[heads[0]] != "## [Unreleased]":
        raise ChangelogError(structure)
    first, nxt = heads[0], heads[1]
    for ln in text_lines[:first]:
        if ln.lstrip(" ").startswith(("```", "~~~", "<!--")):
            raise ChangelogError(
                "CHANGELOG.md has a code fence or HTML comment before the [Unreleased] pointer"
            )
    body = list(text_lines[first + 1 : nxt])
    while body and not body[0].strip():
        body.pop(0)
    if len(body) < 2 or body[0] != POINTER or body[1].strip() or any(x.strip() for x in body[2:]):
        raise ChangelogError(structure)
    if not DATED_HEADING_RE.fullmatch(text_lines[nxt]):
        raise ChangelogError(structure)
    return first, nxt


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
    _first, nxt = _check_pointer_section(text_lines)
    eol = "\r\n" if lines[nxt].endswith("\r\n") else "\n"
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


def _restore(temp: Path, path: Path) -> str:
    """Give ``temp`` back its original name without ever overwriting a file.

    Returns ``restored``, ``both`` (linked, but the temporary name could not be
    removed) or ``kept`` (could not link; only the temporary name exists).
    """
    try:
        os.link(temp, path)
    except OSError:
        return "kept"
    try:
        os.unlink(temp)
    except OSError:
        return "both"
    return "restored"


def _cleanup_one(path: Path, raw: bytes) -> tuple[str, str] | None:
    """Delete one compiled fragment safely.

    Returns None when deleted, else ``(bucket, item)`` for the report.
    """
    temp = path.with_name(TEMP_PREFIX + path.name)
    try:
        os.replace(path, temp)
    except OSError:
        return "unmoved", str(path)
    unreadable_now = False
    try:
        same = temp.read_bytes() == raw
    except OSError:
        same = False
        unreadable_now = True
    if same:
        try:
            _unlink(temp)
            return None
        except OSError:
            pass
    state = _restore(temp, path)
    if state == "both":
        return "both", f"{path} and {temp}"
    if state == "kept":
        return "kept", str(temp)
    if same:
        return "undeleted", str(path)
    return ("unreadable" if unreadable_now else "changed"), str(path)


def _list_items(items: list[str]) -> str:
    return "\n  ".join(items)


# Bucket -> message builder (version, items), in the order the reports are printed.
_REPORTS: tuple[tuple[str, Callable[[str, list[str]], str]], ...] = (
    ("changed", lambda _v, items: (
        "error: these fragments changed during compilation; their new text is not in "
        "CHANGELOG.md and they were NOT deleted:\n  " + _list_items(items))),
    ("unreadable", lambda _v, items: (
        "error: these fragments could not be read back during cleanup, so they were NOT "
        "deleted; check `git diff` before removing them:\n  " + _list_items(items))),
    ("undeleted", lambda v, items: (
        "error: CHANGELOG.md was updated; these fragments were already compiled into "
        f"{v} but could not be deleted, remove them with `git rm`:\n  " + _list_items(items))),
    ("both", lambda _v, items: (
        "error: both the fragment and its temporary copy exist for these; compare them "
        "with `git diff` and remove the `.compiling-` copy by hand:\n  " + _list_items(items))),
    ("kept", lambda _v, items: (
        "error: these fragments are kept under their temporary names; check `git diff` and "
        "compare or rename them by hand:\n  " + _list_items(items))),
    ("unmoved", lambda _v, items: (
        "error: cleanup could not move these fragments aside; their committed text is "
        "in CHANGELOG.md. Check `git diff -- <path>` before removing each one:\n  "
        + _list_items([f"{p} (git diff -- {p})" for p in items]))),
)


def _remove_all(fragments: list[Fragment], version: str) -> int:
    """Delete compiled fragments safely.

    Each fragment is first renamed to a hidden temporary name, so a later save by
    an editor creates a new file that is never touched. The renamed file is deleted
    only if its bytes equal the compiled bytes; otherwise it is given back its name
    when that name is free, and never overwrites anything.
    """
    buckets: dict[str, list[str]] = {name: [] for name, _build in _REPORTS}
    for _t, _s, path, _body, raw in fragments:
        outcome = _cleanup_one(path, raw)
        if outcome is not None:
            buckets[outcome[0]].append(outcome[1])
    status = 0
    for name, build in _REPORTS:
        if buckets[name]:
            print(build(version, buckets[name]), file=sys.stderr)
            status = 1
    return status


def _listing(fragments: list[Fragment]) -> str:
    return "\n  ".join(str(f[2]) for f in fragments)


def _preflight(args: argparse.Namespace, fragments_dir: Path, changelog_path: Path) -> None:
    if fragments_dir.is_symlink() or (
        hasattr(fragments_dir, "is_junction") and fragments_dir.is_junction()
    ):
        raise ChangelogError(f"{fragments_dir} must not be a symlink or junction")
    if changelog_path.is_symlink():
        raise ChangelogError("CHANGELOG.md must not be a symlink")
    if os.path.lexists(changelog_path) and not stat.S_ISREG(os.lstat(changelog_path).st_mode):
        raise ChangelogError("CHANGELOG.md must be a regular file")
    if not args.check and not args.dry_run:
        require_clean_git(args.root)


def _validate_release(args: argparse.Namespace, fragments: list[Fragment]) -> None:
    if not args.version or not args.date:
        raise ChangelogError("--version and --date are required unless --check is given")
    if not VERSION_RE.fullmatch(args.version):
        raise ChangelogError(f"invalid --version '{args.version}' (expected X.Y.Z)")
    if not DATE_RE.fullmatch(args.date):
        raise ChangelogError(f"invalid --date '{args.date}' (expected YYYY-MM-DD)")
    if not fragments:
        raise ChangelogError("no changelog fragments to compile")


def _publish(changelog_path: Path, updated: str, fragments: list[Fragment], version: str) -> int:
    try:
        write_atomic(changelog_path, updated)
    except OSError as exc:
        print(
            "error: could not write CHANGELOG.md (unchanged); fragments kept:\n  "
            + _listing(fragments)
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
            + _listing(fragments),
            file=sys.stderr,
        )
        return 1
    status = _remove_all(fragments, version)
    if status == 0:
        print(f"compiled {len(fragments)} fragment(s) into CHANGELOG.md [{version}]")
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
    fragments_dir = args.root / FRAGMENTS_DIRNAME
    changelog_path = args.root / CHANGELOG_NAME
    try:
        _preflight(args, fragments_dir, changelog_path)
        fragments = collect_fragments(fragments_dir)
        if args.check:
            print(f"ok: {len(fragments)} changelog fragment(s) valid")
            return 0
        _validate_release(args, fragments)
        section = render_section(args.version, args.date, fragments)
        updated = insert_section(_read_changelog(changelog_path), args.version, section)
        if args.dry_run:
            print(section)
            return 0
        return _publish(changelog_path, updated, fragments, args.version)
    except ChangelogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
