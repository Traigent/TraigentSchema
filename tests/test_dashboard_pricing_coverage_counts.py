"""Optional pricing-coverage counts on the project-usage dashboard top_experiments[].

An all-unpriced aggregate otherwise reads as $0; the counts let clients tell an
unmeasured cost from a real zero. The fields are additive and optional.

The evaluator-quality dashboard deliberately does NOT carry these counts: evaluator
runs store cost as a non-null 0, so an unpriced count there would be fake.
"""

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator

USAGE = "project_scoped_project_usage_dashboard_schema"
QUALITY_FILE = (
    Path(__file__).resolve().parent.parent
    / "traigent_schema"
    / "schemas"
    / "projects"
    / "project_scoped_evaluator_quality_dashboard_schema.json"
)
CTX = {
    "tenant_id": "t1",
    "project_id": "p1",
    "generated_at": "2026-10-13T00:00:00Z",
    "privacy_classification": "aggregate_safe",
}


def _usage():
    return {
        "context": CTX,
        "range_days": 30,
        "resolved_bucket": "day",
        "summary_cards": {
            "experiment_runs_in_range": 1,
            "configuration_runs_in_range": 2,
            "priced_configuration_runs_in_range": 0,
            "unpriced_configuration_runs_in_range": 2,
            "total_cost_usd_in_range": 0,
            "total_tokens_in_range": 0,
            "avg_latency_ms_in_range": 0,
            "p95_latency_ms_in_range": 0,
        },
        "usage_trend": [],
        "top_experiments": [
            {
                "experiment_id": "x1",
                "name": "n",
                "configuration_runs": 2,
                "total_cost_usd": 0,
                "total_tokens": 0,
                "avg_latency_ms": None,
                "privacy_classification": "aggregate_safe",
            }
        ],
    }


def _errors(payload):
    return SchemaValidator().validate_json(payload, USAGE)


def test_baseline_valid_without_new_fields():
    assert _errors(_usage()) == []


def test_usage_accepts_counts_on_top_experiments():
    p = _usage()
    p["top_experiments"][0].update(priced_configuration_runs=1, unpriced_configuration_runs=1)
    assert _errors(p) == []


@pytest.mark.parametrize("key", ["priced_configuration_runs", "unpriced_configuration_runs"])
def test_usage_rejects_negative_item_counts(key):
    p = _usage()
    p["top_experiments"][0][key] = -1
    assert _errors(p)


@pytest.mark.parametrize("key", ["priced_configuration_runs", "unpriced_configuration_runs"])
def test_counts_must_be_integers(key):
    p = _usage()
    p["top_experiments"][0][key] = 1.5
    assert _errors(p)


def test_evaluator_quality_schema_has_no_pricing_counts():
    text = QUALITY_FILE.read_text()
    json.loads(text)
    assert "priced_configuration_runs" not in text
    assert "unpriced_configuration_runs" not in text
