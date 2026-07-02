"""Contract tests for smart pruning and intermediate trial reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
SMART_SCHEMA_FILE = OPT_DIR / "smart_pruning_schema.json"
INTERMEDIATE_SCHEMA_FILE = OPT_DIR / "intermediate_report_schema.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _errors(schema: dict[str, Any], payload: Any) -> list[Any]:
    Draft7Validator.check_schema(schema)
    return list(Draft7Validator(schema).iter_errors(payload))


def _session_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def test_smart_pruning_accepts_label_only_and_optional_params() -> None:
    schema = _load(SMART_SCHEMA_FILE)

    assert _errors(schema, {"label": "balanced"}) == []
    assert _errors(
        schema,
        {
            "label": "aggressive",
            "min_completed_trials": 1,
            "warmup_steps": 0,
            "epsilon": 0,
            "cost_threshold": 0,
            "confidence": 0.95,
            "min_samples_per_config": 1,
            "warmup_trials": 0,
        },
    ) == []


def test_smart_pruning_rejects_unknown_label_bounds_and_extra_fields() -> None:
    schema = _load(SMART_SCHEMA_FILE)

    assert _errors(schema, {})
    assert _errors(schema, {"label": "fast"})
    assert _errors(schema, {"label": "balanced", "min_completed_trials": 0})
    assert _errors(schema, {"label": "balanced", "warmup_steps": -1})
    assert _errors(schema, {"label": "balanced", "epsilon": -0.01})
    assert _errors(schema, {"label": "balanced", "cost_threshold": -0.01})
    assert _errors(schema, {"label": "balanced", "confidence": 0})
    assert _errors(schema, {"label": "balanced", "confidence": 1})
    assert _errors(schema, {"label": "balanced", "min_samples_per_config": 0})
    assert _errors(schema, {"label": "balanced", "warmup_trials": -1})
    assert _errors(schema, {"label": "balanced", "secret": True})


def test_smart_pruning_attaches_to_session_create_request() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(smart_pruning={"label": "conservative"}),
    ) == []

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(smart_pruning={"label": "balanced", "confidence": 1}),
    )

    assert errors
    assert any("smart_pruning" in error for error in errors)


def test_session_create_contract_references_smart_pruning_schema() -> None:
    endpoints = _load(get_schemas_dir() / "optimization" / "optimization_endpoints.json")

    smart_pruning = endpoints["paths"]["/api/v1/sessions"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]["properties"]["smart_pruning"]

    assert (
        smart_pruning["$ref"]
        == "https://schemas.traigent.ai/optimization/smart_pruning_schema.json"
    )


def test_intermediate_report_request_schema_validates() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    payload = {
        "session_id": "sess_abc",
        "trial_id": "trial_1",
        "running_score": 0.82,
        "examples_attempted": 10,
        "partial_cost_usd": 0.13,
        "objective_name": "accuracy",
    }

    assert validator.validate_json(payload, "intermediate_report_schema") == []
    assert (
        validator.validate_request(
            "/api/v1/sessions/sess_abc/intermediate-report",
            "POST",
            payload,
        )
        == []
    )


def test_intermediate_report_request_rejects_missing_bounds_and_extra_fields() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    base_payload = {
        "session_id": "sess_abc",
        "trial_id": "trial_1",
        "running_score": 0.82,
        "examples_attempted": 10,
    }

    assert validator.validate_json(base_payload, "intermediate_report_schema") == []
    assert validator.validate_json(
        {k: v for k, v in base_payload.items() if k != "running_score"},
        "intermediate_report_schema",
    )
    assert validator.validate_json(
        {**base_payload, "examples_attempted": -1},
        "intermediate_report_schema",
    )
    assert validator.validate_json(
        {**base_payload, "partial_cost_usd": -0.01},
        "intermediate_report_schema",
    )
    assert validator.validate_json(
        {**base_payload, "extra": True},
        "intermediate_report_schema",
    )


def test_intermediate_report_response_schema_validates_prune_signal() -> None:
    schema = _load(INTERMEDIATE_SCHEMA_FILE)["definitions"]["IntermediateReportResponse"]

    assert _errors(schema, {"prune": True, "prune_reason": "low confidence"}) == []
    assert _errors(schema, {"prune": False, "prune_reason": None}) == []
    assert _errors(schema, {"prune": True})
    assert _errors(schema, {"prune": False, "prune_reason": 123})
    assert _errors(schema, {"prune": False, "prune_reason": None, "extra": True})


def test_intermediate_report_endpoint_references_request_and_response_pair() -> None:
    endpoints = _load(get_schemas_dir() / "optimization" / "optimization_endpoints.json")

    operation = endpoints["paths"]["/api/v1/sessions/{session_id}/intermediate-report"][
        "post"
    ]
    request_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]

    assert request_ref == "./intermediate_report_schema.json"
    assert response_ref == (
        "./intermediate_report_schema.json#/definitions/IntermediateReportResponse"
    )
