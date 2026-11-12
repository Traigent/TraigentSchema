"""Regression gate: no JSON file in the repo may repeat an object key.

Standard JSON parsers keep the last value of a repeated key and drop the rest
silently, so a duplicated "description" (or a duplicated validating keyword such
as "type" or "required") changes the contract without any error. This test
parses every JSON file with an object_pairs_hook that rejects repeated keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
_SKIPPED_DIR_NAMES = {"node_modules", "__pycache__"}


def _json_files() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.rglob("*.json"):
        relative = path.relative_to(REPO_ROOT)
        if any(part.startswith(".") or part in _SKIPPED_DIR_NAMES for part in relative.parts):
            continue
        files.append(path)
    return sorted(files)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            duplicates.add(key)
        seen.add(key)
    if duplicates:
        raise ValueError(f"duplicate object keys: {sorted(duplicates)}")
    return dict(pairs)


JSON_FILES = _json_files()


def test_json_file_discovery_finds_schema_files() -> None:
    # Guards against the scan silently matching nothing.
    assert len(JSON_FILES) > 100


@pytest.mark.parametrize(
    "path", JSON_FILES, ids=[str(p.relative_to(REPO_ROOT)) for p in JSON_FILES]
)
def test_json_file_has_no_duplicate_object_keys(path: Path) -> None:
    with path.open(encoding="utf-8") as handle:
        json.load(handle, object_pairs_hook=_reject_duplicate_keys)
