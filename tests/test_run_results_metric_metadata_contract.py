"""Schema-first contract for per-metric direction/role on the run-results response.

TraigentSchema#255: the optimization objective schema already carries a
``direction`` enum (maximize/minimize/band), but the results-side contract
(``execution/run_results_response_schema.json``) carried no per-metric
direction or role, forcing FE consumers to re-derive it by matching metric
names (TraigentFrontend#1713, #1721). This adds an optional, nullable
``metric_metadata`` map alongside the existing ``metrics`` map, reusing the
objective ``direction`` enum and coordinated with the resolved contract shape
in TraigentBackend#1830.
"""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_PATH = "execution/run_results_response_schema.json"


def _load_schema() -> dict[str, Any]:
    with (get_schemas_dir() / SCHEMA_PATH).open(encoding="utf-8") as handle:
        return json.load(handle)


def _validator() -> Draft7Validator:
    return Draft7Validator(
        _load_schema(),
        registry=SchemaValidator()._registry,
        format_checker=FormatChecker(),
    )


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "run_id": "run_1",
        "experiment_id": "experiment_1",
        "configurations": [],
        "metrics": {"accuracy": 0.91, "total_cost": 0.0042, "latency_ms": 820.0},
    }
    payload.update(overrides)
    return payload


def _errors(payload: dict[str, Any]) -> list[Any]:
    return list(_validator().iter_errors(payload))


def test_metric_metadata_property_is_optional_and_nullable() -> None:
    without_field = _payload()
    with_null = _payload(metric_metadata=None)

    assert "metric_metadata" not in without_field
    assert _errors(without_field) == []
    assert _errors(with_null) == []


def test_metric_metadata_reuses_objective_direction_enum() -> None:
    schema = _load_schema()
    direction_ref = schema["definitions"]["MetricMetadataEntry"]["properties"]["direction"]
    refs = [branch["$ref"] for branch in direction_ref["oneOf"] if "$ref" in branch]

    assert refs == [
        "../optimization/objective_definition_schema.json#/definitions/ObjectiveDirection"
    ]

    valid = _payload(
        metric_metadata={
            "accuracy": {"direction": "maximize", "role": "quality"},
            "total_cost": {"direction": "minimize", "role": "cost"},
            "latency_ms": {"direction": "minimize", "role": "latency"},
        }
    )
    assert _errors(valid) == []

    banded = _payload(
        metric_metadata={"accuracy": {"direction": "band", "role": None}}
    )
    assert _errors(banded) == []

    bad_direction = _payload(
        metric_metadata={"accuracy": {"direction": "descending", "role": "quality"}}
    )
    assert _errors(bad_direction)


def test_metric_metadata_role_enum_is_quality_cost_latency_tokens() -> None:
    schema = _load_schema()
    role_enum = schema["definitions"]["MetricRole"]["enum"]

    assert role_enum == ["quality", "cost", "latency", "tokens"]

    valid = _payload(
        metric_metadata={"response_tokens": {"direction": None, "role": "tokens"}}
    )
    assert _errors(valid) == []

    bad_role = _payload(
        metric_metadata={"response_tokens": {"direction": None, "role": "throughput"}}
    )
    assert _errors(bad_role)


def test_metric_metadata_ad_hoc_measure_is_honestly_unknown_not_defaulted() -> None:
    """No backing objective and no resolvable role -> {direction: null, role: null},
    never a silent default to 'maximize' (the ask's "what happens with no
    objective" question, answered as nullable rather than omitted/defaulted)."""
    unknown = _payload(
        metric_metadata={"some_adhoc_measure": {"direction": None, "role": None}}
    )
    assert _errors(unknown) == []


def test_metric_metadata_entry_requires_both_keys_even_when_null() -> None:
    missing_role = _payload(
        metric_metadata={"accuracy": {"direction": "maximize"}}
    )
    missing_direction = _payload(
        metric_metadata={"accuracy": {"role": "quality"}}
    )
    extra_key = _payload(
        metric_metadata={
            "accuracy": {"direction": "maximize", "role": "quality", "unit": "pct"}
        }
    )

    assert _errors(missing_role)
    assert _errors(missing_direction)
    assert _errors(extra_key)


def test_run_results_get_endpoint_still_references_run_results_response_schema() -> None:
    """Sanity check that this contract change did not disturb the endpoint wiring
    verified by test_success_envelope_and_response_coverage.py."""
    with (get_schemas_dir() / "execution/execution_endpoints.json").open(
        encoding="utf-8"
    ) as handle:
        spec = json.load(handle)

    ref = spec["paths"]["/api/v1/experiment-runs/runs/{run_id}/results"]["get"][
        "responses"
    ]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("run_results_response_schema.json"), ref
