"""Contract tests for the semantic saturation stop-condition schema.

The schema is the diagnostics/config contract for the SDK
``SemanticSaturationStopCondition`` (feature FR-SDK-SEMANTIC-SATURATION-V1).
It is a standalone contract — not embedded in an endpoint — so these tests
give it real reachability and coverage, and pin the privacy boundary:
example-level diagnostics may carry ``example_id`` values but never raw inputs,
outputs, expected outputs, or example content.
"""

import json

import jsonschema
import pytest

from traigent_schema.utils import get_schema_path

SCHEMA_REL = "optimization/semantic_saturation_schema.json"


@pytest.fixture(scope="module")
def schema() -> dict:
    path = get_schema_path("semantic_saturation_schema")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _validate(instance: dict, schema: dict) -> None:
    jsonschema.validate(instance=instance, schema=schema)


def test_schema_parses_and_defines_diagnostics_symbol(schema):
    # The catalog construct binds symbol `SemanticSaturationDiagnostics`.
    assert "SemanticSaturationDiagnostics" in schema["definitions"]
    assert "SemanticSaturationConfig" in schema["definitions"]


def test_valid_config_accepted(schema):
    _validate(
        {
            "enabled": True,
            "window": 4,
            "min_trials": 4,
            "churn_threshold": 0.0,
            "min_overlap": 0.8,
            "objectives": "auto",
            "example_score_metrics": ["accuracy"],
            "continuous_objectives": ["cost"],
            "include_example_ids": True,
            "max_example_ids": 50,
        },
        schema,
    )


def test_valid_diagnostics_payload_accepted(schema):
    _validate(
        {
            "condition": "semantic_saturation",
            "decision": "stop",
            "reason_detail": "all_objectives_saturated",
            "window": 4,
            "min_trials": 4,
            "trials_considered": ["cfg-1", "cfg-2"],
            "objectives": {
                "accuracy": {
                    "regime": "example_vector",
                    "saturated": True,
                    "reason_detail": "quality_saturated",
                    "max_churn": 0.0,
                    "churn_threshold": 0.0,
                    "overlap_ratio": 1.0,
                    "examples_compared": 20,
                    "stable_example_count": 20,
                    "changed_example_count": 0,
                    "changed_example_ids": [],
                    "stable_example_ids": ["ex-1", "ex-2"],
                },
                "cost": {
                    "regime": "continuous",
                    "saturated": True,
                    "reason_detail": "continuous_saturated",
                    "direction": "minimize",
                    "best": 0.42,
                    "improvement": 0.0,
                    "improvement_threshold": 0.01,
                },
            },
        },
        schema,
    )


def test_privacy_boundary_rejects_content_fields(schema):
    # additionalProperties:false must reject any attempt to smuggle example
    # content / model output into the sanitized diagnostic.
    leaking = {
        "condition": "semantic_saturation",
        "decision": "stop",
        "reason_detail": "all_objectives_saturated",
        "window": 4,
        "min_trials": 4,
        "trials_considered": ["cfg-1"],
        "objectives": {
            "accuracy": {
                "regime": "example_vector",
                "saturated": True,
                "reason_detail": "quality_saturated",
                "stable_example_ids": ["ex-1"],
                "model_output_text": "leaked completion",
            }
        },
    }
    with pytest.raises(jsonschema.ValidationError):
        _validate(leaking, schema)


def test_diagnostics_requires_decision(schema):
    incomplete = {
        "condition": "semantic_saturation",
        "reason_detail": "warmup",
        "window": 4,
        "min_trials": 4,
        "trials_considered": [],
        "objectives": {},
    }
    with pytest.raises(jsonschema.ValidationError):
        _validate(incomplete, schema)
