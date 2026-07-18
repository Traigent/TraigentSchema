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


# ---------------------------------------------------------------------------
# #321 conditional measure_type vocabulary, exercised through the ACTUAL
# endpoint request mappings (PUT /api/v1/measures/{measure_id} consumes
# measure_schema.json; POST /api/v1/measures consumes
# measure_create_request_schema.json — see measures_endpoints.json).
# ---------------------------------------------------------------------------


def test_put_measure_custom_round_trips_novel_measure_type() -> None:
    """#321 escape hatch: a custom measure keeps its novel label on the write path."""
    errors = SchemaValidator(contract="backend").validate_request(
        "/api/v1/measures/measure-1",
        "PUT",
        _backend_measure(measure_type="my_novel_metric", is_custom=True),
    )

    assert errors == []


def test_put_measure_standard_rejects_non_standard_measure_type() -> None:
    """is_custom=false keeps the closed MeasureType vocabulary on PUT."""
    errors = SchemaValidator(contract="backend").validate_request(
        "/api/v1/measures/measure-1",
        "PUT",
        _backend_measure(measure_type="my_novel_metric", is_custom=False),
    )

    assert errors != []


def test_put_measure_rejects_blank_measure_type_even_when_custom() -> None:
    """The custom escape hatch is bounded: blank labels never validate."""
    errors = SchemaValidator(contract="backend").validate_request(
        "/api/v1/measures/measure-1",
        "PUT",
        _backend_measure(measure_type="", is_custom=True),
    )

    assert errors != []


def test_put_measure_standard_still_accepts_canonical_measure_type() -> None:
    errors = SchemaValidator(contract="backend").validate_request(
        "/api/v1/measures/measure-1",
        "PUT",
        _backend_measure(measure_type="latency", is_custom=False),
    )

    assert errors == []


def test_create_then_read_back_round_trip_for_custom_measure() -> None:
    """#321 end-to-end: the create-request tolerates a declared-custom novel
    label (mirroring the backend's extra=allow create DTO), and the canonical
    read-back schema accepts the stored result via the is_custom conditional.

    NOTE the create request deliberately stays backend-modeled (free string —
    see test_create_request_contracts.py); server-side enforcement of the
    conditional vocabulary on create is a TraigentBackend follow-up, not a
    schema-side tightening.
    """
    v = SchemaValidator(contract="backend")

    create_body = {"label": "L", "measure_type": "my_novel_metric", "is_custom": True}
    assert v.validate_request("/api/v1/measures", "POST", create_body) == []

    stored = _backend_measure(measure_type="my_novel_metric", is_custom=True)
    assert v.validate_json(stored, SCHEMA_NAME) == []
