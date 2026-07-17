"""Measure resource schema contract tests."""

from __future__ import annotations

import json
from typing import Any

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "measure_schema"


def _load_measure_schema() -> dict[str, Any]:
    with open(
        get_schemas_dir() / "measures" / "measure_schema.json",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def _backend_measure(**overrides: Any) -> dict[str, Any]:
    payload = {
        "id": "measure-categorical-1",
        "version": "1.0.0",
        "label": "Outcome label",
        "description": "Categorical outcome.",
        "category": "Quality",
        "measure_type": "quality",
        "evaluation_method": "deterministic",
        "target_aspect": "overall",
        "metric_type": "single_turn",
        "output_type": "discrete",
        "agent_types": ["chat"],
        "domain_min": None,
        "domain_max": None,
        "inverse": False,
        "is_custom": True,
    }
    payload.update(overrides)
    return payload


def test_measure_resource_declares_typed_scoring_fields() -> None:
    schema = _load_measure_schema()

    assert schema["additionalProperties"] is False
    # value_type is deliberately a free-form label at the measure-definition level
    # (#320): a bounded string, NOT a closed enum, so custom measures round-trip.
    value_type = schema["properties"]["value_type"]
    assert value_type["type"] == "string"
    assert value_type["maxLength"] == 255
    assert "enum" not in value_type
    assert schema["properties"]["categories"] == {
        "type": "array",
        "items": {
            "type": "string",
            "maxLength": 255,
        },
        "maxItems": 1000,
        "description": "Allowed category labels for categorical measures.",
    }
    assert "value_type" not in schema["required"]
    assert "categories" not in schema["required"]


def test_categorical_backend_measure_validates_against_resource_schema() -> None:
    errors = SchemaValidator(contract="backend").validate_json(
        _backend_measure(value_type="categorical", categories=["a", "b"]),
        SCHEMA_NAME,
    )

    assert errors == []


def test_legacy_backend_measure_without_typed_scoring_fields_still_validates() -> None:
    errors = SchemaValidator(contract="backend").validate_json(
        _backend_measure(),
        SCHEMA_NAME,
    )

    assert errors == []
