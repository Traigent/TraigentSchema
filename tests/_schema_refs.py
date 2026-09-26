"""$ref-resolving JSON Schema helpers shared by the contract tests.

Resolution rule matches SchemaValidator: a schema without ``$id`` is addressed by
its package-relative path under ``SCHEMA_ID_BASE``; ``*_endpoints`` files are
inventories, not schemas, and are left out of the registry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir

SCHEMA_ID_BASE = "https://schemas.traigent.ai/"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_registry(schemas_dir: Path | None = None) -> Registry:
    root = schemas_dir or get_schemas_dir()
    resources = []
    for path in root.rglob("*.json"):
        if "_endpoints" in path.name:
            continue
        document = load_json(path)
        if not isinstance(document, dict):
            continue
        schema_id = document.get("$id") or (SCHEMA_ID_BASE + path.relative_to(root).as_posix())
        document = {**document, "$id": schema_id}
        resources.append((schema_id, Resource.from_contents(document)))
    return Registry().with_resources(resources)


def ref_errors(registry: Registry, ref: str, instance: Any) -> list[str]:
    validator = Draft7Validator({"$ref": ref}, registry=registry)
    return [error.message for error in validator.iter_errors(instance)]
