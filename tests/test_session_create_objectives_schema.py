"""Pin objective propagation through session and hybrid creation requests."""

from __future__ import annotations

import json
from copy import deepcopy

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _typed_objectives() -> list[dict[str, object]]:
    return [
        {
            "name": "accuracy",
            "orientation": "maximize",
            "weight": 0.7,
            "normalization": "min_max",
        },
        {
            "name": "latency",
            "orientation": "minimize",
            "weight": 0.3,
            "normalization": "min_max",
        },
    ]


def _session_create_payload(objectives: object) -> dict[str, object]:
    return {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": objectives,
    }


def _hybrid_create_payload(objectives: object | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "config_space": [
            {"temperature": 0.1, "model": "fast"},
            {"temperature": 0.8, "model": "accurate"},
        ],
        "task_description": "Optimize support reply quality.",
    }
    if objectives is not None:
        payload["objectives"] = objectives
    return payload


def test_session_create_accepts_typed_objective_definitions() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(_typed_objectives()),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_rejects_untyped_objective_objects() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    objectives = deepcopy(_typed_objectives())
    objectives[0].pop("orientation")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(objectives),
    )

    assert errors, "Expected validation errors when a typed objective omits orientation"


def test_hybrid_create_accepts_optional_typed_objectives() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_create_payload(_typed_objectives()),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_hybrid_create_rejects_untyped_objective_objects() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    objectives = deepcopy(_typed_objectives())
    objectives[0].pop("weight")

    errors = validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_create_payload(objectives),
    )

    assert errors, "Expected validation errors when a typed objective omits weight"


def test_creation_endpoints_wire_objective_contracts() -> None:
    with open(
        get_schemas_dir() / "optimization" / "optimization_endpoints.json",
        encoding="utf-8",
    ) as handle:
        endpoints = json.load(handle)

    session_objectives = endpoints["paths"]["/api/v1/sessions"]["post"][
        "requestBody"
    ]["content"]["application/json"]["schema"]["properties"]["objectives"]
    assert session_objectives["oneOf"][0]["$ref"] == "#/definitions/TypedObjectiveArray"

    with open(
        get_schemas_dir() / "optimization" / "hybrid_session_create_request_schema.json",
        encoding="utf-8",
    ) as handle:
        hybrid_schema = json.load(handle)

    assert (
        hybrid_schema["definitions"]["CanonicalTypedObjectiveDefinition"]["allOf"][0]["$ref"]
        == "https://schemas.traigent.ai/optimization/objective_definition_schema.json"
    )
