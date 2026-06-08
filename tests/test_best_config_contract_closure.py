"""Best-config schema ref closure tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, RefResolver

from traigent_schema.utils import get_schemas_dir


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _schema_store(root: Path) -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*.json"):
        schema = _load(path)
        store[path.as_uri()] = schema
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            store[schema_id] = schema
    return store


def _validator(schema_path: str) -> Draft7Validator:
    schemas_dir = get_schemas_dir()
    schema = _load(schemas_dir / schema_path)

    def _deny_remote(uri: str) -> None:
        raise AssertionError(f"schema ref escaped packaged closure: {uri}")

    resolver = RefResolver.from_schema(
        schema,
        store=_schema_store(schemas_dir),
        handlers={"http": _deny_remote, "https": _deny_remote},
    )
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, resolver=resolver)


def _best_config() -> dict[str, Any]:
    return {
        "schema_version": "traigent.best_config.v1",
        "config_id": "support-answerer",
        "function_ref": "tests.best_config:answer",
        "environment": "default",
        "config": {
            "model": "gpt-4o-mini",
            "temperature": 0.2,
            "max_tokens": 512,
        },
        "provenance": {
            "algorithm": "tpe",
            "optimization_id": "opt_cloud_123",
        },
    }


def test_best_config_optimization_ref_targets_are_packaged() -> None:
    schemas_dir = get_schemas_dir()

    assert (schemas_dir / "optimization" / "best_config_schema.json").is_file()
    assert (schemas_dir / "optimization" / "optimization_strategy_schema.json").is_file()


def test_best_config_execution_contract_resolves_refs_locally() -> None:
    publish_errors = list(
        _validator("execution/best_config_publish_request_schema.json").iter_errors(
            {"spec": _best_config(), "environment": "default"}
        )
    )
    assert publish_errors == []

    response_errors = list(
        _validator("execution/best_config_response_schema.json").iter_errors(
            {
                "config_id": "support-answerer",
                "environment": "default",
                "version": 1,
                "etag": 'W/"1-abcdef"',
                "spec_hash": "sha256:" + "a" * 64,
                "config_hash": "sha256:" + "b" * 64,
                "spec": _best_config(),
                "created_at": "2026-06-08T00:00:00Z",
                "updated_at": "2026-06-08T00:00:00Z",
            }
        )
    )
    assert response_errors == []

    rollback_errors = list(
        _validator("execution/best_config_rollback_request_schema.json").iter_errors(
            {"version": 1, "environment": "default"}
        )
    )
    assert rollback_errors == []
