"""Governance for the canonical x-* extension vocabulary.

The shipped x_extensions_meta_schema.json file is the single source of truth for
allowed x-* schema extensions. Every used x-* key must be declared there with a
non-empty description, and the meta-schema must not accumulate dead entries.
"""

from __future__ import annotations

import json
from collections.abc import Generator
from pathlib import Path

from traigent_schema.utils import get_all_schema_files

TESTS_DIR = Path(__file__).resolve().parent
SCHEMA_DIR = TESTS_DIR.parent / "traigent_schema" / "schemas"
META_SCHEMA_PATH = SCHEMA_DIR / "x_extensions_meta_schema.json"
LEGACY_REGISTRY_PATH = TESTS_DIR / "data" / "x_extensions_registry.json"


def _meta_schema() -> dict[str, object]:
    return json.loads(META_SCHEMA_PATH.read_text(encoding="utf-8"))


def _allowed_x_extensions() -> dict[str, dict[str, object]]:
    properties = _meta_schema().get("properties")
    assert isinstance(
        properties, dict
    ), "x_extensions_meta_schema.json must define a properties map"
    return properties


def _walk_x_keys(
    node: object, file_name: str
) -> Generator[tuple[str, str], None, None]:
    """Yield ``(x_key, file_name)`` for every x-* key found recursively in *node*."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.startswith("x-"):
                yield key, file_name
            yield from _walk_x_keys(value, file_name)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_x_keys(item, file_name)


def _used_x_extensions() -> dict[str, list[str]]:
    used: dict[str, list[str]] = {}
    for path in get_all_schema_files():
        if path.resolve() == META_SCHEMA_PATH.resolve():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for key, file_name in _walk_x_keys(data, path.name):
            files = used.setdefault(key, [])
            if file_name not in files:
                files.append(file_name)
    return used


def test_meta_schema_is_the_only_x_extension_registry() -> None:
    assert not LEGACY_REGISTRY_PATH.exists(), (
        "tests/data/x_extensions_registry.json re-introduces a second x-* registry. "
        "Keep x_extensions_meta_schema.json as the single source of truth."
    )


def test_meta_schema_itself_is_valid_json() -> None:
    meta = _meta_schema()
    assert isinstance(meta, dict), "x_extensions_meta_schema.json must be a JSON object"

    allowed = _allowed_x_extensions()
    assert allowed, "x_extensions_meta_schema.json defines no allowed x-* keys"
    assert all(key.startswith("x-") for key in allowed), (
        "x_extensions_meta_schema.json may only declare x-* extension keys"
    )


def test_meta_schema_entries_have_descriptions() -> None:
    missing = [
        key
        for key, schema in _allowed_x_extensions().items()
        if not str(schema.get("description", "")).strip()
    ]
    assert not missing, (
        "x-* entries missing descriptions in x_extensions_meta_schema.json: "
        f"{missing}"
    )


def test_every_used_x_extension_is_declared_in_meta_schema() -> None:
    allowed = set(_allowed_x_extensions())
    used = _used_x_extensions()
    violations = {key: files for key, files in used.items() if key not in allowed}

    assert not violations, (
        "x-* extension keyword(s) used in schemas but missing from "
        "traigent_schema/schemas/x_extensions_meta_schema.json:\n"
        + "\n".join(
            f"  - {key}  (in: {', '.join(sorted(files))})"
            for key, files in sorted(violations.items())
        )
    )


def test_meta_schema_has_no_stale_unused_entries() -> None:
    allowed = set(_allowed_x_extensions())
    used = set(_used_x_extensions())
    stale = sorted(allowed - used)

    assert not stale, (
        "x_extensions_meta_schema.json declares x-* keyword(s) that no schema uses:\n"
        + "\n".join(f"  - {key}" for key in stale)
    )
