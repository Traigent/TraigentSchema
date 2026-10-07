"""POST /api/v1/sessions response contract (SessionCreateResponseDTO).

project_id / tenant_id are the server-issued owning scope the SDKs need to
build the portal link. They are optional, omitted (never null) when absent,
and never empty strings.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft7Validator

from traigent_schema.utils import get_schemas_dir

SCHEMA_PATH = get_schemas_dir() / "optimization" / "session_create_response_schema.json"


def _schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validator() -> Draft7Validator:
    # Relative $ref (warm_start_transfer) is not resolved unless metadata carries it.
    return Draft7Validator(_schema())


def _response(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session_id": "11111111-1111-1111-1111-111111111111",
        "status": "created",
        "project_id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "33333333-3333-3333-3333-333333333333",
        "optimization_strategy": {"algorithm": "grid"},
        "metadata": {
            "experiment_id": "44444444-4444-4444-4444-444444444444",
            "experiment_run_id": "55555555-5555-5555-5555-555555555555",
            "total_configurations": 9,
            "agent_id": None,
            "function_name": "support_router",
            "dataset_size": 12,
        },
    }
    payload.update(overrides)
    return payload


def _errors(payload: dict[str, Any]) -> list[str]:
    return [e.message for e in _validator().iter_errors(payload)]


def test_schema_file_is_valid_draft7() -> None:
    Draft7Validator.check_schema(_schema())
    assert _schema()["title"] == "SessionCreateResponseDTO"
    assert _schema()["$id"] == (
        "https://schemas.traigent.ai/optimization/session_create_response_schema.json"
    )


def test_typed_response_with_scope_validates() -> None:
    assert _errors(_response()) == []


def test_response_without_scope_validates() -> None:
    payload = _response()
    del payload["project_id"]
    del payload["tenant_id"]
    assert _errors(payload) == []


def test_legacy_and_extra_keys_are_tolerated() -> None:
    payload = _response(
        message="Session created successfully",
        success=True,
        data={"anything": 1},
        warnings=[{"code": "x"}],
        future_field="ok",
    )
    assert _errors(payload) == []


def test_metadata_agent_id_may_be_string() -> None:
    payload = _response()
    payload["metadata"]["agent_id"] = "66666666-6666-6666-6666-666666666666"
    assert _errors(payload) == []


@pytest.mark.parametrize("field", ["project_id", "tenant_id"])
def test_empty_scope_id_is_rejected(field: str) -> None:
    assert _errors(_response(**{field: ""})) != []


@pytest.mark.parametrize("field", ["project_id", "tenant_id"])
def test_null_scope_id_is_rejected(field: str) -> None:
    assert _errors(_response(**{field: None})) != []


@pytest.mark.parametrize("field", ["session_id", "status"])
def test_missing_required_field_is_rejected(field: str) -> None:
    payload = _response()
    del payload[field]
    assert _errors(payload) != []


def test_create_endpoint_201_declares_scope_ids() -> None:
    endpoints = json.loads(
        (get_schemas_dir() / "optimization" / "optimization_endpoints.json").read_text(
            encoding="utf-8"
        )
    )
    props = endpoints["paths"]["/api/v1/sessions"]["post"]["responses"]["201"]["content"][
        "application/json"
    ]["schema"]["properties"]
    for field in ("project_id", "tenant_id"):
        assert props[field]["type"] == "string"
        assert props[field]["minLength"] == 1
