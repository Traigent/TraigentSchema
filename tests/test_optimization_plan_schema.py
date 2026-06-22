"""Contract tests for allowlisted pre-run optimization plans."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OPT_DIR = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas" / "optimization"
REQUEST_SCHEMA_FILE = OPT_DIR / "optimization_plan_request_schema.json"
RESPONSE_SCHEMA_FILE = OPT_DIR / "optimization_plan_response_schema.json"
ENDPOINTS_FILE = OPT_DIR / "optimization_plan_endpoints.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _errors(schema: dict[str, Any], payload: Any) -> list[Any]:
    Draft7Validator.check_schema(schema)
    return list(Draft7Validator(schema).iter_errors(payload))


def _request_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "task_description": "Optimize support routing quality before running trials.",
        "task_type": "support_routing",
        "agent_shape": "router_agent",
        "dataset": {
            "size": 120,
            "has_holdout": True,
        },
        "objectives": [
            "accuracy",
            "latency_ms",
        ],
        "weights": {
            "accuracy": 0.8,
            "latency_ms": 0.2,
        },
        "budget": {
            "max_trials": 20,
            "cost_limit_usd": 5.0,
        },
        "offline": False,
    }
    payload.update(overrides)
    return payload


def _response_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "phase": "P1_STATIC",
        "plan": {
            "objectives": [
                {
                    "name": "accuracy",
                    "weight": 0.8,
                    "orientation": "maximize",
                },
                {
                    "name": "latency_ms",
                    "weight": 0.2,
                    "orientation": "minimize",
                },
            ],
            "models": [
                "fast-model",
                "accurate-model",
            ],
            "knobs": [
                {
                    "name": "prompt_style",
                    "values": [
                        "direct",
                        "structured",
                    ],
                }
            ],
            "algorithm": "tpe",
            "max_trials": 20,
            "cost_limit_usd": 5.0,
            "offline": False,
        },
        "steps": [
            {
                "id": "review_plan",
                "label": "Review plan",
                "command_template": "traigent optimize --plan {plan_id} --review-only",
            },
            {
                "id": "start_run",
                "label": "Start run",
                "command_template": "traigent optimize --plan {plan_id}",
            },
        ],
        "evidence_level": "medium",
        "caveat": "Plan is advisory until a run is started.",
        "advisory": True,
    }
    payload.update(overrides)
    return payload


def test_optimization_plan_request_schema_accepts_minimal_typed_request() -> None:
    schema = _load(REQUEST_SCHEMA_FILE)

    assert _errors(schema, _request_payload()) == []
    assert _errors(
        schema,
        _request_payload(
            task_type=None,
            agent_shape=None,
            weights=None,
            offline=None,
        ),
    )
    assert (
        _errors(
            schema,
            {
                "task_description": "Optimize answer quality.",
                "dataset": {"size": 10, "has_holdout": False},
                "objectives": ["accuracy"],
                "budget": {"max_trials": 5, "cost_limit_usd": 1.0},
            },
        )
        == []
    )


def test_optimization_plan_request_rejects_extra_fields_and_bad_weights() -> None:
    schema = _load(REQUEST_SCHEMA_FILE)

    assert _errors(schema, _request_payload(raw_prompt="do not pass through"))
    assert _errors(
        schema,
        _request_payload(dataset={"size": 120, "has_holdout": True, "split_seed": 7}),
    )
    assert _errors(schema, _request_payload(weights={"bad-key": 1.0}))
    assert _errors(schema, _request_payload(weights={"accuracy": "high"}))
    assert _errors(schema, _request_payload(objectives=["accuracy", "bad-key"]))
    assert _errors(schema, _request_payload(budget={"max_trials": 0, "cost_limit_usd": 1.0}))


def test_optimization_plan_response_schema_accepts_allowlisted_plan() -> None:
    schema = _load(RESPONSE_SCHEMA_FILE)

    assert _errors(schema, _response_payload()) == []


def test_optimization_plan_response_rejects_internal_or_unallowlisted_fields() -> None:
    schema = _load(RESPONSE_SCHEMA_FILE)

    with_extra_plan_field = _response_payload()
    with_extra_plan_field["plan"]["score_threshold"] = 0.97
    assert _errors(schema, with_extra_plan_field)

    with_extra_objective_field = _response_payload()
    with_extra_objective_field["plan"]["objectives"][0]["formula"] = "secret"
    assert _errors(schema, with_extra_objective_field)

    numeric_knob_values = _response_payload()
    numeric_knob_values["plan"]["knobs"][0]["values"] = [0.1, 0.2]
    assert _errors(schema, numeric_knob_values)

    not_advisory = _response_payload(advisory=False)
    assert _errors(schema, not_advisory)


def test_optimization_plan_response_property_names_stay_allowlisted() -> None:
    schema = _load(RESPONSE_SCHEMA_FILE)
    forbidden_tokens = ("score", "threshold", "formula", "irt", "signal", "rank")
    property_names: set[str] = set()

    def collect_property_names(node: Any) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                property_names.update(properties)
            for value in node.values():
                collect_property_names(value)
        elif isinstance(node, list):
            for item in node:
                collect_property_names(item)

    collect_property_names(schema)

    offenders = sorted(
        name
        for name in property_names
        if any(token in name.lower() for token in forbidden_tokens)
    )
    assert offenders == []


def test_optimization_plan_endpoint_wires_request_and_response_schemas() -> None:
    endpoints = _load(ENDPOINTS_FILE)
    operation = endpoints["paths"]["/api/v1/optimization/plan"]["post"]

    request_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]

    assert request_ref == "./optimization_plan_request_schema.json"
    assert response_ref == "./optimization_plan_response_schema.json"


def test_optimization_plan_route_validates_through_backend_and_sdk_catalogs() -> None:
    payload = _request_payload()
    backend = SchemaValidator(contract="backend")
    sdk = SchemaValidator(contract="sdk_tuning")

    assert backend._endpoint_schemas["POST:/api/v1/optimization/plan"] == (
        "optimization_plan_request_schema"
    )
    assert sdk._endpoint_schemas["POST:/api/v1/optimization/plan"] == (
        "optimization_plan_request_schema"
    )
    assert backend.validate_request("/api/v1/optimization/plan", "POST", payload) == []
    assert sdk.validate_request("/api/v1/optimization/plan", "POST", payload) == []

    bad_payload = deepcopy(payload)
    bad_payload["plan"] = {"should_not": "be accepted"}
    assert backend.validate_request("/api/v1/optimization/plan", "POST", bad_payload)


def test_optimization_plan_schema_ids_are_canonical() -> None:
    request_schema = _load(REQUEST_SCHEMA_FILE)
    response_schema = _load(RESPONSE_SCHEMA_FILE)

    assert request_schema["$id"] == (
        "https://schemas.traigent.ai/optimization/optimization_plan_request_schema.json"
    )
    assert response_schema["$id"] == (
        "https://schemas.traigent.ai/optimization/optimization_plan_response_schema.json"
    )
    assert (get_schemas_dir() / "optimization" / "optimization_plan_endpoints.json").exists()
