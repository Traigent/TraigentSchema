"""Governance for the canonical x-* extension vocabulary.

The shipped x_extensions_meta_schema.json file is the single source of truth for
allowed x-* schema extensions. Every used x-* key must be declared there with a
non-empty description, and the meta-schema must not accumulate dead entries.
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from pathlib import Path

import jsonschema
import pytest

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


# --------------------------------------------------------------------------- #
# #573 — value conformance. The key-level tests above check that every x-* key
# is declared; until this was added, nothing checked that its VALUE matched the
# declaration, and 88 values did not: 80 `"x-reference": true` sites against a
# `"type": "string"` declaration, 7 `x-privacy-classification: "metadata"`
# values outside the closed 12-value enum, and one free-text `description`
# inside a map the meta-schema declares as objects.
# --------------------------------------------------------------------------- #

README_PATH = TESTS_DIR.parent / "README.md"

# Boolean `x-reference` means "references a canonical identifier, target not yet
# pinned". It is a tolerated legacy form (see the meta-schema entry), ratcheted
# here: this number may only go DOWN as sites are given a real pointer. A new
# site must use the pointer form, so raising this number is not a fix.
MAX_BOOLEAN_X_REFERENCE_SITES = 80

# "| `user_content` | ..." in the README's privacy-classification table.
_README_PRIVACY_ROW = re.compile(r"^\|\s*`([a-z_]+)`\s*\|", re.MULTILINE)


def _walk_x_values(
    node: object, file_name: str, pointer: str = ""
) -> Generator[tuple[str, str, str, object], None, None]:
    """Yield ``(x_key, file_name, json_pointer, value)`` for every x-* value."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{pointer}/{key}"
            if isinstance(key, str) and key.startswith("x-"):
                yield key, file_name, here, value
            yield from _walk_x_values(value, file_name, here)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _walk_x_values(item, file_name, f"{pointer}/{index}")


def _x_extension_value_violations(declarations: dict[str, dict[str, object]]) -> list[str]:
    violations: list[str] = []
    for path in get_all_schema_files():
        if path.resolve() == META_SCHEMA_PATH.resolve():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for key, file_name, pointer, value in _walk_x_values(data, path.name):
            declaration = declarations.get(key)
            if declaration is None:
                continue  # key-level governance above owns undeclared keys
            try:
                jsonschema.validate(value, declaration)
            except jsonschema.ValidationError as error:
                violations.append(f"{file_name}{pointer}: {error.message}")
    return violations


def test_every_x_extension_value_conforms_to_meta_schema() -> None:
    violations = _x_extension_value_violations(_allowed_x_extensions())

    assert not violations, (
        f"{len(violations)} x-* value(s) do not conform to their "
        "x_extensions_meta_schema.json declaration:\n"
        + "\n".join(f"  - {violation}" for violation in sorted(violations))
    )


def test_value_conformance_check_catches_a_broken_value() -> None:
    """The checker must fail on a deliberately broken sample, not just pass."""
    declarations = dict(_allowed_x_extensions())
    # Tighten one real declaration so every shipped use of it becomes a
    # violation. If the walk or the validation were inert, this would still
    # report zero.
    declarations["x-privacy-classification"] = {"enum": ["__no_schema_uses_this__"]}

    violations = _x_extension_value_violations(declarations)
    assert violations, "the value-conformance walk reports no violation on a broken declaration"
    assert any("x-privacy-classification" in violation for violation in violations)


def test_boolean_x_reference_sites_do_not_increase() -> None:
    boolean_sites = [
        f"{file_name}{pointer}"
        for path in get_all_schema_files()
        if path.resolve() != META_SCHEMA_PATH.resolve()
        for key, file_name, pointer, value in _walk_x_values(
            json.loads(path.read_text(encoding="utf-8")), path.name
        )
        if key == "x-reference" and value is True
    ]

    assert len(boolean_sites) <= MAX_BOOLEAN_X_REFERENCE_SITES, (
        f"{len(boolean_sites)} boolean `x-reference` sites, baseline is "
        f"{MAX_BOOLEAN_X_REFERENCE_SITES}. A new reference must use the pointer form "
        "(a relative path or JSON Pointer to the canonical definition); do not raise "
        f"the baseline. New or moved sites include: {sorted(boolean_sites)[:5]}"
    )
    if len(boolean_sites) < MAX_BOOLEAN_X_REFERENCE_SITES:
        pytest.fail(
            f"{len(boolean_sites)} boolean `x-reference` sites — below the "
            f"{MAX_BOOLEAN_X_REFERENCE_SITES} baseline. Lower "
            "MAX_BOOLEAN_X_REFERENCE_SITES to lock the improvement in."
        )


def test_readme_privacy_table_lists_exactly_the_meta_schema_enum() -> None:
    declared = _allowed_x_extensions()["x-privacy-classification"]
    enum = set(declared["enum"])  # type: ignore[arg-type]

    readme = README_PATH.read_text(encoding="utf-8")
    heading = "#### Field-level privacy classification (`x-privacy-classification`)"
    assert heading in readme, "the README privacy-classification section was renamed"
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    documented = set(_README_PRIVACY_ROW.findall(section))

    assert documented == enum, (
        "the README privacy-classification table and the meta-schema enum disagree. "
        f"In the enum but undocumented: {sorted(enum - documented)}; "
        f"documented but not in the enum: {sorted(documented - enum)}"
    )
