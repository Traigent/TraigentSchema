"""Contract tests for server-side cost accounting fields (TraigentSchema #382/#383 follow-on).

Pins: reasoning_tokens as a nullable usage class on every usage surface; the
unreported-usage vocabulary naming it; and the additive read-side cost fields on
the observation read schema.  ``total_cost_usd`` nullability is a documented
FUTURE change (owner decision pending) and must NOT change here.
"""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

COST_STATUSES = ["priced", "unpriced", "partial", "not_applicable"]
COST_SOURCES = ["declared", "computed", "none"]
COST_READ_FIELDS = (
    "cost_status",
    "cost_source",
    "cost_usd_declared",
    "cost_usd_computed",
    "priced_cost_usd",
    "priced_model",
    "price_catalogue_version",
)


def _schema(*parts):
    path = get_schemas_dir()
    for part in parts:
        path = path / part
    with open(path) as handle:
        return json.load(handle)


def test_reasoning_tokens_is_nullable_canonical_definition():
    definition = _schema("common_types_schema.json")["definitions"]["ReasoningTokens"]
    assert definition["type"] == ["integer", "null"]
    assert definition["minimum"] == 0


def test_unreported_vocabulary_names_reasoning_tokens():
    items = _schema("common_types_schema.json")["definitions"]["UnreportedUsageFields"]["items"]
    assert "reasoning_tokens" in items["enum"]


def test_every_usage_surface_carries_reasoning_tokens():
    observation = _schema("observability", "observation_schema.json")["properties"]
    cost_item = _schema("costs", "cost_user_usage_item_schema.json")["properties"]
    for name, props in (("observation", observation), ("cost item", cost_item)):
        assert "reasoning_tokens" in props, name
        assert "common_types_schema.json#/definitions/ReasoningTokens" in props[
            "reasoning_tokens"
        ]["$ref"]
    ingest = _schema("observability", "observation_ingest_schema.json")["definitions"]
    levels = [n for n in ingest if n.startswith("Observation_d")]
    assert len(levels) >= 6
    for level in levels:
        assert "reasoning_tokens" in ingest[level]["properties"], level


def test_ingest_accepts_reasoning_tokens_int_and_null():
    validator = SchemaValidator()
    for value in (0, 512, None):
        errors = validator.validate_json(
            {
                "id": "obs_r",
                "type": "generation",
                "name": "provider.call",
                "reasoning_tokens": value,
            },
            "observation_ingest_schema",
        )
        assert errors == [], errors


def test_ingest_rejects_negative_reasoning_tokens():
    errors = SchemaValidator().validate_json(
        {"id": "o", "type": "generation", "name": "n", "reasoning_tokens": -1},
        "observation_ingest_schema",
    )
    assert errors != []


def test_ingest_accepts_unreported_reasoning_tokens_attribution():
    errors = SchemaValidator().validate_json(
        {
            "id": "o",
            "type": "generation",
            "name": "n",
            "reasoning_tokens": None,
            "unreported_usage_fields": ["reasoning_tokens"],
        },
        "observation_ingest_schema",
    )
    assert errors == [], errors


def test_read_schema_declares_all_cost_fields_additively():
    props = _schema("observability", "observation_schema.json")["properties"]
    required = _schema("observability", "observation_schema.json")["required"]
    for field in COST_READ_FIELDS:
        assert field in props, field
        assert field not in required, f"{field} must stay optional (additive)"
    defs = _schema("common_types_schema.json")["definitions"]
    assert defs["ObservationCostStatus"]["enum"] == COST_STATUSES
    assert defs["ObservationCostSource"]["enum"] == COST_SOURCES


def test_read_schema_cost_fields_validate_and_reject_bad_status():
    validator = SchemaValidator()
    base = {"id": "o", "type": "generation", "name": "n"}
    ok = {
        **base,
        "cost_status": "partial",
        "cost_source": "computed",
        "cost_usd_declared": None,
        "cost_usd_computed": 0.0012,
        "priced_cost_usd": 0.0012,
        "priced_model": "example-model",
        "price_catalogue_version": "1",
    }
    assert validator.validate_json(ok, "observation_schema") == []
    assert validator.validate_json({**base, "cost_status": "free"}, "observation_schema") != []
    assert validator.validate_json({**base, "cost_usd_computed": -1}, "observation_schema") != []


def test_backend_shaped_unpriced_and_partial_observations_validate():
    """The backend emits cost_usd: null for unpriced/partial observations."""
    validator = SchemaValidator()
    base = {"id": "o", "type": "generation", "name": "n", "cost_usd": None}
    unpriced = {
        **base,
        "cost_status": "unpriced",
        "cost_source": "none",
        "cost_usd_declared": None,
        "cost_usd_computed": None,
        "priced_cost_usd": None,
    }
    partial = {**unpriced, "cost_status": "partial", "cost_source": "computed", "priced_cost_usd": 0.001}
    assert validator.validate_json(unpriced, "observation_schema") == []
    assert validator.validate_json(partial, "observation_schema") == []
    # nullability is the only widening: a negative or non-numeric cost_usd is still rejected
    assert validator.validate_json({**base, "cost_usd": -1}, "observation_schema") != []
    assert validator.validate_json({**base, "cost_usd": "1"}, "observation_schema") != []


def test_total_cost_usd_contract_is_unchanged_by_this_change():
    """Nullable trace/session total_cost_usd is a documented FUTURE change (owner)."""
    session = _schema("observability", "session_schema.json")["properties"]["total_cost_usd"]
    assert session == {"type": ["number", "null"], "minimum": 0}
    assert "total_cost_usd" not in _schema("observability", "trace_schema.json")["properties"]
