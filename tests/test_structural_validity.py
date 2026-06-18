# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""#131: structural-validity CI gate.

`test_schemas.py` only checks that schema files *parse* as JSON. Nothing enforced
that every file is a meta-valid Draft-7 schema, or that every cross-file ``$ref``
points at a file/definition that actually exists — so a malformed schema or a
dangling cross-file ``$ref`` (which would break ``SchemaValidator`` at runtime)
could merge green. This module closes that gap, plus a version/CHANGELOG
consistency check so the released version can be read from the contract.

Scope note on ``$ref`` resolution: internal ``#/...`` pointers inside the
OpenAPI-style ``*_endpoints.json`` catalogs are intentionally resolved by
``SchemaValidator`` against the *extracted operation subschema*, not the document
root, so they are validated by ``SchemaValidator``'s own tests (and the
best-config closure test), not here. This module validates **cross-file** refs
(``./x.json``, ``../x.json``, ``https://schemas.traigent.ai/...``) and their
fragments, which resolve against the target document root in the normal way.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft7Validator

from traigent_schema.utils import get_all_schema_files, get_schemas_dir

_HTTP_PREFIX = "https://schemas.traigent.ai/"
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load(path: Path) -> object:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _iter_refs(node: object):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_refs(value)


def _resolve_pointer(doc: object, fragment: str) -> object:
    cur = doc
    for raw in fragment.strip("/").split("/"):
        if raw == "":
            continue
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(token)]
        else:
            cur = cur[token]
    return cur


def test_all_schema_files_are_meta_valid() -> None:
    """Every schema file must be a valid Draft-7 schema (check_schema)."""
    failures: dict[str, str] = {}
    for path in get_all_schema_files():
        try:
            Draft7Validator.check_schema(_load(path))
        except Exception as exc:  # noqa: BLE001 - report all, not just the first
            failures[path.name] = f"{type(exc).__name__}: {exc}"
    assert not failures, (
        "schema files that fail Draft-7 check_schema (#131):\n"
        + "\n".join(f"  - {name}: {err}" for name, err in sorted(failures.items()))
    )


def test_all_cross_file_refs_resolve() -> None:
    """Every cross-file ``$ref`` target file (and ``/definitions`` fragment) must exist."""
    schemas_dir = get_schemas_dir()
    failures: list[str] = []
    for path in get_all_schema_files():
        doc = _load(path)
        for ref in _iter_refs(doc):
            file_part, _, fragment = ref.partition("#")
            if file_part == "":
                # internal pointer — resolved by SchemaValidator subschema extraction
                continue
            if file_part.startswith(_HTTP_PREFIX):
                target = schemas_dir / file_part[len(_HTTP_PREFIX):]
            else:
                target = (path.parent / file_part).resolve()
            if not target.exists():
                failures.append(f"{path.name}: $ref -> missing file '{ref}'")
                continue
            if fragment:
                try:
                    _resolve_pointer(_load(target), fragment)
                except Exception:  # noqa: BLE001
                    failures.append(f"{path.name}: $ref -> unresolved fragment '{ref}'")
    assert not failures, "dangling cross-file $ref(s) (#131):\n" + "\n".join(
        f"  - {f}" for f in sorted(failures)
    )


def test_version_matches_newest_dated_changelog_section() -> None:
    """version.py must match the newest *dated* CHANGELOG section (no version desync)."""
    version_src = (_REPO_ROOT / "traigent_schema" / "version.py").read_text(encoding="utf-8")
    version_match = re.search(r'__version__\s*=\s*"([^"]+)"', version_src)
    assert version_match, "could not read __version__ from version.py"
    version = version_match.group(1)

    changelog = (_REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    dated = re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}", changelog, re.MULTILINE)
    assert dated, "no dated CHANGELOG sections found"
    assert dated[0] == version, (
        f"version.py is {version} but the newest dated CHANGELOG section is "
        f"[{dated[0]}] (#131: reconcile version.py with a dated CHANGELOG entry)"
    )
