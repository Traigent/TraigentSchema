"""Serializer-shaped conformance for observability cost/usage read fields (MT3-06, MT3-07).

Fixtures copy the JSON *shapes* the Backend emits (ObservabilityTrace.to_dict,
ObservabilitySession.to_dict, ObservabilityObservation._base_dict and the analytics
summary), not Backend code.  null means unknown / not reported, never zero.
"""

import pytest

from traigent_schema import SchemaValidator

TS = "2026-09-30T10:00:00+00:00"
STATUSES = ["priced", "partial", "unpriced", "not_applicable", None]  # None = legacy declared


def _trace(status, total, **extra):
    payload = {
        "id": "ot_" + "a" * 40,
        "name": "agent.run",
        "status": "completed",
        "session_id": None,
        "started_at": TS,
        "ended_at": TS,
        "total_cost_usd": total,
        **extra,
    }
    if status:
        payload["cost_status"] = status
    return payload


TRACES = {
    "priced": _trace("priced", 0.0123, priced_cost_usd=0.0123, unpriced_observation_count=0),
    "partial": _trace("partial", None, priced_cost_usd=0.004, unpriced_observation_count=2),
    "unpriced": _trace("unpriced", None, priced_cost_usd=0.0, unpriced_observation_count=3),
    "not_applicable": _trace("not_applicable", 0.0),
    "legacy_declared": _trace(None, 1.5),
}


@pytest.mark.parametrize("name", sorted(TRACES))
def test_trace_cost_shapes_validate(name):
    assert SchemaValidator().validate_json(TRACES[name], "trace_schema") == []


@pytest.mark.parametrize("name", sorted(TRACES))
def test_session_cost_shapes_validate(name):
    trace = TRACES[name]
    session = {
        "id": "os_" + "b" * 40,
        "tags": [],
        "metadata": {},
        "trace_count": 1,
        "average_latency_ms": None,
        **{k: v for k, v in trace.items() if k in (
            "total_cost_usd", "cost_status", "priced_cost_usd", "unpriced_observation_count")},
    }
    assert SchemaValidator().validate_json(session, "session_schema") == []


def test_trace_and_session_reject_bad_cost_values():
    v = SchemaValidator()
    for schema, base in (("trace_schema", TRACES["priced"]), ("session_schema", {"id": "s"})):
        assert v.validate_json({**base, "cost_status": "free"}, schema) != []
        assert v.validate_json({**base, "total_cost_usd": -0.01}, schema) != []
        assert v.validate_json({**base, "total_cost_usd": "1"}, schema) != []
        assert v.validate_json({**base, "unpriced_observation_count": -1}, schema) != []


def _observation(**extra):
    return {
        "id": "oo_" + "c" * 40,
        "type": "generation",
        "name": "llm.call",
        "status": "completed",
        "started_at": TS,
        "ended_at": TS,
        "latency_ms": 12,
        "input_tokens": 10,
        "output_tokens": 5,
        "total_tokens": 15,
        "cost_usd": 0.001,
        **extra,
    }


def test_observation_priced_partial_unpriced_validate():
    v = SchemaValidator()
    priced = _observation(cost_status="priced", cost_source="computed", priced_cost_usd=0.001)
    partial = _observation(cost_usd=None, cost_status="partial", cost_source="none", priced_cost_usd=0.0005)
    unpriced = _observation(cost_usd=None, cost_status="unpriced", cost_source="none", priced_cost_usd=None)
    for obs in (priced, partial, unpriced):
        assert v.validate_json(obs, "observation_schema") == []


def test_non_usage_span_reports_null_tokens_not_zero():
    """OTLP tool/agent/chain/span observations carry no usage: tokens are null (MT3-07)."""
    v = SchemaValidator()
    span = _observation(
        type="span",
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        cost_usd=None,
        cost_status="not_applicable",
        cost_source="none",
        unreported_usage_fields=[],
    )
    assert v.validate_json(span, "observation_schema") == []
    assert v.validate_json({**span, "input_tokens": -1}, "observation_schema") != []
    assert v.validate_json({**span, "output_tokens": "5"}, "observation_schema") != []


def _summary(cards, top):
    return {
        "context": {
            "tenant_id": "t",
            "project_id": "p",
            "generated_at": TS,
            "privacy_classification": "aggregate_safe",
        },
        "range_days": 30,
        "resolved_bucket": "day",
        "summary_cards": {
            "sessions_in_range": 1,
            "traces_in_range": 2,
            "observations_in_range": 3,
            "bookmarked_traces_in_range": 0,
            "published_traces_in_range": 0,
            "commented_traces_in_range": 0,
            "total_tokens_in_range": 100,
            **cards,
        },
        "activity_trend": [],
        "top_traces": top,
    }


def _top(status, total, **extra):
    return {
        "trace_id": "t1",
        "session_id": None,
        "name": "agent.run",
        "status": "completed",
        "observation_count": 3,
        "total_cost_usd": total,
        "cost_status": status,
        "priced_cost_usd": 0.004,
        "unpriced_observation_count": 1,
        "total_tokens": 10,
        "total_latency_ms": 5,
        "is_bookmarked": False,
        "is_published": False,
        "started_at": TS,
        "privacy_classification": "aggregate_safe",
        **extra,
    }


@pytest.mark.parametrize(
    "status,total",
    [("priced", 1.25), ("partial", None), ("unpriced", None), ("not_applicable", None)],
)
def test_analytics_summary_cost_rollup_validates(status, total):
    cards = {
        "total_cost_usd": total,
        "total_cost_usd_in_range": total,  # deprecated alias, same nullable value
        "cost_status": status,
        "priced_cost_usd": 0.004,
        "unpriced_trace_count": 0 if status == "priced" else 2,
    }
    doc = _summary(cards, [_top(status, total)])
    assert SchemaValidator().validate_json(doc, "project_scoped_observability_summary_dashboard_schema") == []


def test_analytics_summary_rejects_bad_status_and_negative_totals():
    v = SchemaValidator()
    name = "project_scoped_observability_summary_dashboard_schema"
    good = {"total_cost_usd": 1.0, "total_cost_usd_in_range": 1.0, "cost_status": "priced"}
    assert v.validate_json(_summary({**good, "cost_status": "free"}, []), name) != []
    assert v.validate_json(_summary({**good, "total_cost_usd": -1}, []), name) != []
    assert v.validate_json(_summary(good, [_top("bogus", 1.0)]), name) != []
