"""Optional pricing-coverage counts on the evaluator-quality and project-usage dashboards.

An all-unpriced aggregate otherwise reads as $0; the counts let clients tell an
unmeasured cost from a real zero. The fields are additive and optional.
"""

import pytest

from traigent_schema import SchemaValidator

QUALITY = "project_scoped_evaluator_quality_dashboard_schema"
USAGE = "project_scoped_project_usage_dashboard_schema"
CTX = {
    "tenant_id": "t1",
    "project_id": "p1",
    "generated_at": "2026-10-13T00:00:00Z",
    "privacy_classification": "aggregate_safe",
}


def _quality():
    return {
        "context": CTX,
        "range_days": 30,
        "resolved_bucket": "day",
        "summary_cards": {
            "evaluator_definitions_total": 1,
            "evaluator_runs_in_range": 2,
            "completed_runs_in_range": 2,
            "failed_runs_in_range": 0,
            "scored_runs_in_range": 2,
            "avg_numeric_score_in_range": None,
            "total_cost_usd_in_range": 0,
        },
        "quality_trend": [],
        "recent_evaluators": [
            {
                "evaluator_id": "e1",
                "name": "n",
                "target_type": "t",
                "measure_id": "m",
                "measure_label": "M",
                "run_count": 2,
                "completed_runs": 2,
                "failed_runs": 0,
                "scored_runs": 2,
                "avg_numeric_score": None,
                "avg_latency_ms": None,
                "total_cost_usd": 0,
                "last_run_at": None,
                "privacy_classification": "aggregate_safe",
            }
        ],
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


def _errors(payload, schema):
    return SchemaValidator().validate_json(payload, schema)


def test_baselines_valid_without_new_fields():
    assert _errors(_quality(), QUALITY) == []
    assert _errors(_usage(), USAGE) == []


def test_quality_accepts_counts_on_cards_and_items():
    p = _quality()
    p["summary_cards"].update(
        priced_configuration_runs_in_range=0, unpriced_configuration_runs_in_range=2
    )
    p["recent_evaluators"][0].update(priced_configuration_runs=0, unpriced_configuration_runs=2)
    assert _errors(p, QUALITY) == []


def test_usage_accepts_counts_on_top_experiments():
    p = _usage()
    p["top_experiments"][0].update(priced_configuration_runs=1, unpriced_configuration_runs=1)
    assert _errors(p, USAGE) == []


@pytest.mark.parametrize(
    "key",
    ["priced_configuration_runs_in_range", "unpriced_configuration_runs_in_range"],
)
def test_quality_rejects_negative_card_counts(key):
    p = _quality()
    p["summary_cards"][key] = -1
    assert _errors(p, QUALITY)


@pytest.mark.parametrize("key", ["priced_configuration_runs", "unpriced_configuration_runs"])
def test_quality_rejects_negative_item_counts(key):
    p = _quality()
    p["recent_evaluators"][0][key] = -1
    assert _errors(p, QUALITY)


@pytest.mark.parametrize("key", ["priced_configuration_runs", "unpriced_configuration_runs"])
def test_usage_rejects_negative_item_counts(key):
    p = _usage()
    p["top_experiments"][0][key] = -1
    assert _errors(p, USAGE)


@pytest.mark.parametrize(
    "build, schema, where, key",
    [
        pytest.param(
            _quality,
            QUALITY,
            lambda p: p["summary_cards"],
            "priced_configuration_runs_in_range",
            id="quality-card-priced",
        ),
        pytest.param(
            _quality,
            QUALITY,
            lambda p: p["summary_cards"],
            "unpriced_configuration_runs_in_range",
            id="quality-card-unpriced",
        ),
        pytest.param(
            _quality,
            QUALITY,
            lambda p: p["recent_evaluators"][0],
            "priced_configuration_runs",
            id="quality-item-priced",
        ),
        pytest.param(
            _quality,
            QUALITY,
            lambda p: p["recent_evaluators"][0],
            "unpriced_configuration_runs",
            id="quality-item-unpriced",
        ),
        pytest.param(
            _usage,
            USAGE,
            lambda p: p["top_experiments"][0],
            "priced_configuration_runs",
            id="usage-item-priced",
        ),
        pytest.param(
            _usage,
            USAGE,
            lambda p: p["top_experiments"][0],
            "unpriced_configuration_runs",
            id="usage-item-unpriced",
        ),
    ],
)
def test_counts_must_be_integers(build, schema, where, key):
    p = build()
    where(p)[key] = 1.5
    assert _errors(p, schema)
