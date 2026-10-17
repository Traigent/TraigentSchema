"""Unknown evaluator run cost is null, never zero (owner rulings, Sept-Oct 2026)."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

SCHEMAS = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "observability"
BASE = {
    "id": "r1",
    "evaluator_id": "e1",
    "measure_id": "m1",
    "target_type": "observability_trace",
    "target_id": "t1",
    "status": "completed",
}


def _schema():
    return json.loads((SCHEMAS / "evaluator_run_schema.json").read_text())


def test_cost_usd_declared_nullable_with_minimum():
    prop = _schema()["properties"]["cost_usd"]
    assert set(prop["type"]) == {"number", "null"}
    assert prop["minimum"] == 0


@pytest.mark.parametrize("value", [None, 0, 0.0123])
def test_cost_usd_accepts_null_and_non_negative(value):
    Draft7Validator(_schema()).validate({**BASE, "cost_usd": value})


def test_cost_usd_rejects_negative():
    assert list(Draft7Validator(_schema()).iter_errors({**BASE, "cost_usd": -0.01}))
