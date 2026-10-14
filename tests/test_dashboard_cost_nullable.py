"""Unknown dashboard cost is null, never zero (owner rulings, Sept-Oct 2026)."""
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "projects"

# file -> JSON-pointer-ish paths of the USD cost properties that must allow null
CASES = {
    "project_scoped_evaluator_quality_dashboard_schema.json": [
        ("summary_cards", "total_cost_usd_in_range"),
        ("recent_evaluators", "total_cost_usd"),
    ],
    "project_scoped_optimization_overview_dashboard_schema.json": [
        ("summary_cards", "total_cost_usd_in_range"),
        ("recent_experiments", "total_cost_usd"),
    ],
    "project_scoped_project_usage_dashboard_schema.json": [
        ("summary_cards", "total_cost_usd_in_range"),
        ("usage_trend", "cost_usd"),
        ("top_experiments", "total_cost_usd"),
    ],
    "project_scoped_analytics_summary_schema.json": [
        ("usage_summary", "total_cost_usd"),
        ("usage_summary", "avg_cost_usd"),
    ],
}


def _prop(schema, section, name):
    node = schema["properties"][section]
    if node.get("type") == "array":
        node = node["items"]
    return node["properties"][name]


@pytest.mark.parametrize(
    "fname,section,name",
    [(f, s, n) for f, items in CASES.items() for s, n in items],
)
def test_cost_field_allows_null_and_keeps_minimum(fname, section, name):
    schema = json.loads((ROOT / fname).read_text())
    prop = _prop(schema, section, name)
    assert set(prop["type"]) == {"number", "null"}
    assert prop["minimum"] == 0
    container = schema["properties"][section]
    container = container.get("items", container)
    assert name in container["required"]
