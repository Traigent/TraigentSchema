"""Prose must cite the shipped data corpora at the path they ship from.

The fp2 corpora moved out of `tests/data/` into the package
(`traigent_schema/data/`) in #439. Six comments, notes and config lines went on
citing the old `tests/data/...` locations for months (#578) because nothing
executes those strings. This test pins every mention of a shipped corpus to the
directory it actually ships from, so the next move cannot leave prose behind.

Deliberately narrow: it does not assert that *every* path mentioned anywhere
resolves. Some citations name a file that is absent on purpose — for example
`tests/test_x_extensions_governance.py` guards that the retired
`tests/data/x_extensions_registry.json` is never re-created (#220).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SHIPPED_DATA_DIR = _REPO_ROOT / "traigent_schema" / "data"
_CORRECT_PREFIX = "traigent_schema/data"

_TEXT_SUFFIXES = {".py", ".json", ".md", ".yml", ".yaml", ".properties", ".toml", ".txt", ".cfg"}

# `CHANGELOG.md` records where a file lived at the time of each release; prose
# about the past is not drift.
_EXEMPT = {"CHANGELOG.md"}


def _tracked_text_files() -> list[Path]:
    # The pre-push hook runs this suite with GIT_DIR / GIT_WORK_TREE exported,
    # which would point `git ls-files` at the hook's repository instead of this
    # checkout. Drop them so `cwd` decides.
    env = {k: v for k, v in os.environ.items() if k not in ("GIT_DIR", "GIT_WORK_TREE")}
    listing = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=_REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout
    return [
        _REPO_ROOT / name
        for name in listing.split("\0")
        if name and name not in _EXEMPT and Path(name).suffix in _TEXT_SUFFIXES
    ]


def _shipped_corpus_names() -> list[str]:
    return sorted(path.name for path in _SHIPPED_DATA_DIR.glob("*.json"))


def test_shipped_data_corpora_are_cited_at_their_shipped_path() -> None:
    corpora = _shipped_corpus_names()
    assert corpora, f"no shipped corpora found under {_SHIPPED_DATA_DIR}"

    # Characters that can precede a basename inside a path: for a citation
    # "<some>/<dirs>/<corpus>.json" these walk back over the "<some>/<dirs>"
    # part so it can be compared with the directory the corpus ships from.
    # (No literal corpus path appears here on purpose — this file is scanned
    # too, and an example would be read as a citation.)
    path_chars = re.compile(r"[A-Za-z0-9._/-]")

    wrong: list[str] = []
    for path in _tracked_text_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in corpora:
            # Cheap prescreen: most files never mention the corpus at all.
            start = text.find(name)
            while start != -1:
                end = start
                while start > 0 and path_chars.match(text[start - 1]):
                    start -= 1
                prefix = text[start : end - 1] if end > start else ""
                if prefix and prefix != _CORRECT_PREFIX:
                    wrong.append(
                        f"{path.relative_to(_REPO_ROOT)} cites {prefix}/{name}; "
                        f"it ships at {_CORRECT_PREFIX}/{name}"
                    )
                start = text.find(name, end + len(name))

    assert not wrong, "stale shipped-corpus citations:\n  " + "\n  ".join(sorted(set(wrong)))
