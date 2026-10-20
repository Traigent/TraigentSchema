"""Prose must cite the shipped data corpora at the path they ship from.

The fp2 corpora moved out of `tests/data/` into the package
(`traigent_schema/data/`) in #439. Six comments, notes and config lines went on
citing the old locations for months (#578) because nothing executes those
strings. This test pins every mention of a shipped corpus to the directory it
actually ships from, so the next move cannot leave prose behind.

Deliberately narrow: it does not assert that *every* path mentioned anywhere
resolves. Some citations name a file that is absent on purpose - for example
`tests/test_x_extensions_governance.py` guards that the retired
`tests/data/x_extensions_registry.json` is never re-created (#220).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SHIPPED_DATA_DIR = _REPO_ROOT / "traigent_schema" / "data"

# Scanned file types. Extension-less tracked files carry prose too (`Makefile`,
# `NOTICE`, `hooks/pre-push`), so they are scanned as well - see `_is_text`.
_TEXT_SUFFIXES = {
    ".cfg",
    ".json",
    ".md",
    ".properties",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

# `CHANGELOG.md` records where a file lived at the time of each release; prose
# about the past is not drift.
_EXEMPT = {"CHANGELOG.md"}

# A character that may appear inside a path segment. Used to walk back from a
# corpus basename over the directory part that precedes it.
_PATH_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/"
)


def _git(*args: str) -> str:
    """Run git against this checkout, ignoring any inherited git environment.

    The pre-push hook runs this suite with git's "local" variables exported -
    `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_WORK_TREE` and the rest of
    `git rev-parse --local-env-vars`. Any of them would point the command at
    the hook's repository or index instead of this checkout, so they are all
    dropped and `cwd` is left to decide.
    """
    env = dict(os.environ)
    local_vars = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env={k: v for k, v in env.items() if not k.startswith("GIT_")},
    ).stdout.split()
    for name in local_vars:
        env.pop(name, None)
    return subprocess.run(
        ["git", *args],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout


def _is_text(name: str) -> bool:
    suffix = Path(name).suffix
    return suffix in _TEXT_SUFFIXES or suffix == ""


def _tracked_text_files() -> list[Path]:
    listing = _git("ls-files", "-z")
    return [
        _REPO_ROOT / name
        for name in listing.split("\0")
        if name and name not in _EXEMPT and _is_text(name)
    ]


def _shipped_corpora() -> dict[str, set[str]]:
    """basename -> the set of directories it ships from, as posix prefixes."""
    corpora: dict[str, set[str]] = {}
    for path in _SHIPPED_DATA_DIR.rglob("*.json"):
        prefix = path.parent.relative_to(_REPO_ROOT).as_posix()
        corpora.setdefault(path.name, set()).add(prefix)
    return corpora


def _cited_prefix(text: str, basename_start: int) -> str | None:
    """The directory part immediately preceding a basename, or None.

    Returns None when the mention is not a repository-relative path citation:

    * not preceded by `/` at all - a bare mention (`fp2_conformance.json`) or
      the tail of a longer identifier (`my_fp2_conformance.json`);
    * part of a URI (`https://schemas.traigent.ai/identity/...`, which is a
      canonical `$id`, not a file location).

    Each of those was a false positive before this guard.
    """
    if basename_start == 0 or text[basename_start - 1] != "/":
        return None
    start = basename_start - 1  # the separator itself
    while start > 0 and text[start - 1] in _PATH_CHARS:
        start -= 1
    prefix = text[start : basename_start - 1]
    is_uri = prefix.startswith("//") or (start > 0 and text[start - 1] == ":")
    return None if is_uri else prefix


def test_shipped_data_corpora_are_cited_at_their_shipped_path() -> None:
    corpora = _shipped_corpora()
    assert corpora, f"no shipped corpora found under {_SHIPPED_DATA_DIR}"

    files = _tracked_text_files()
    assert files, "git ls-files matched no text files - the walk itself is broken"

    wrong: list[str] = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for name, shipped_prefixes in corpora.items():
            at = text.find(name)
            while at != -1:
                prefix = _cited_prefix(text, at)
                # A citation is wrong only when it names a directory that is
                # not one this corpus ships from. A prefix that merely ENDS
                # with the shipped directory (a URL, a quoted absolute path)
                # still points at the right place.
                if prefix is not None and not any(
                    prefix == shipped or prefix.endswith("/" + shipped)
                    for shipped in shipped_prefixes
                ):
                    wrong.append(
                        f"{path.relative_to(_REPO_ROOT)} cites {prefix}/{name}; "
                        f"it ships at {sorted(shipped_prefixes)[0]}/{name}"
                    )
                at = text.find(name, at + len(name))

    assert not wrong, "stale shipped-corpus citations:\n  " + "\n  ".join(sorted(set(wrong)))
