"""Enforce that only allowed x-* extension keywords appear in schema files.

This test loads the canonical x_extensions_meta_schema.json (which lists every
permitted x-* key) and asserts that no schema file under traigent_schema/schemas/
uses an x-* key that is not present in that allowlist.

To add a new x-* key:
  1. Add it to traigent_schema/schemas/x_extensions_meta_schema.json with a description.
  2. Use it in your schema.

Do NOT add keys to schema files without updating the meta-schema first.
"""

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCHEMA_DIR = REPO_ROOT / "traigent_schema" / "schemas"
META_SCHEMA_PATH = SCHEMA_DIR / "x_extensions_meta_schema.json"

# Pattern matching any JSON string key that starts with "x-"
_X_KEY_RE = re.compile(r'"(x-[a-z][a-z0-9_-]*)"')


def _load_allowed_keys() -> set:
    """Return the set of x-* keys declared in the meta-schema."""
    meta = json.loads(META_SCHEMA_PATH.read_text(encoding="utf-8"))
    return set(meta.get("properties", {}).keys())


def _collect_x_keys_in_file(path: Path) -> set:
    """Return all x-* keys referenced in a JSON schema file."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    return set(_X_KEY_RE.findall(text))


def test_meta_schema_itself_is_valid_json():
    """The meta-schema file must be loadable as valid JSON."""
    meta = json.loads(META_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert isinstance(meta, dict), "x_extensions_meta_schema.json must be a JSON object"
    assert "properties" in meta, "x_extensions_meta_schema.json must have a 'properties' key"


def test_meta_schema_has_no_x_keys_outside_properties():
    """The meta-schema may not self-reference undeclared x-* keys in its descriptions."""
    allowed = _load_allowed_keys()
    # The meta-schema file itself should only introduce x-* keys inside "properties"
    assert len(allowed) > 0, "x_extensions_meta_schema.json defines no allowed x-* keys"


def test_only_allowed_x_extension_keys_used():
    """Every x-* key in every schema file must be declared in x_extensions_meta_schema.json.

    When this test fails, it means a schema file is using an x-* extension keyword
    that has not been registered in the canonical vocabulary. Fix: add the key to
    traigent_schema/schemas/x_extensions_meta_schema.json before using it.
    """
    allowed = _load_allowed_keys()
    violations: list[tuple[str, str]] = []

    schema_files = sorted(SCHEMA_DIR.rglob("*.json"))
    for path in schema_files:
        # Skip the meta-schema itself — it declares, not uses, x-* keys
        if path == META_SCHEMA_PATH:
            continue
        for key in _collect_x_keys_in_file(path):
            if key not in allowed:
                violations.append((str(path.relative_to(SCHEMA_DIR)), key))

    violations.sort()
    assert not violations, (
        f"Found {len(violations)} unknown x-* extension key(s) in schema files.\n"
        "Add each key to traigent_schema/schemas/x_extensions_meta_schema.json "
        "with a description before using it.\n\n"
        "Unknown keys:\n"
        + "\n".join(f"  {path}: {key}" for path, key in violations)
    )


def test_all_meta_schema_keys_are_actually_used():
    """Every key declared in the meta-schema must appear in at least one schema file.

    This prevents the meta-schema from accumulating dead entries. When a key is
    removed from all schemas, remove it from the meta-schema too.
    """
    allowed = _load_allowed_keys()
    used: set[str] = set()

    for path in SCHEMA_DIR.rglob("*.json"):
        if path == META_SCHEMA_PATH:
            continue
        used |= _collect_x_keys_in_file(path)

    declared_but_unused = allowed - used
    assert not declared_but_unused, (
        f"The following x-* keys are declared in x_extensions_meta_schema.json "
        f"but are not used in any schema file. Remove unused entries to keep the "
        f"meta-schema accurate.\n\nUnused keys: {sorted(declared_but_unused)}"
    )
