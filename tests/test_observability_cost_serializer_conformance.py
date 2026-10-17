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


def test_declared_cost_with_partial_or_unavailable_computation_validates():
    """cost_status describes the displayed cost; cost_source is provenance (declared)."""
    v = SchemaValidator()
    declared_unavailable = _observation(
        cost_usd=0.002,
        cost_status="priced",
        cost_source="declared",
        cost_usd_declared=0.002,
        cost_usd_computed=None,
        priced_cost_usd=None,
    )
    declared_partial = _observation(
        cost_usd=0.002,
        cost_status="priced",
        cost_source="declared",
        cost_usd_declared=0.002,
        cost_usd_computed=None,
        priced_cost_usd=0.0005,
    )
    for obs in (declared_unavailable, declared_partial):
        assert v.validate_json(obs, "observation_schema") == []
        assert obs["priced_cost_usd"] != obs["cost_usd"]


def test_cost_mismatch_true_false_omitted_and_string_rejected():
    v = SchemaValidator()
    base = _observation(cost_status="priced", cost_source="declared", cost_usd_declared=0.001)
    assert v.validate_json({**base, "cost_mismatch": True}, "observation_schema") == []
    assert v.validate_json({**base, "cost_mismatch": False}, "observation_schema") == []
    assert v.validate_json(base, "observation_schema") == []
    assert "cost_mismatch" not in base
    assert v.validate_json({**base, "cost_mismatch": "true"}, "observation_schema") != []
    assert v.validate_json({**base, "cost_mismatch": None}, "observation_schema") != []


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


def _bucket(status, total, **extra):
    return {
        "bucket_start": TS,
        "bucket_label": "2026-09-30",
        "traces": 2,
        "observations": 4,
        "total_cost_usd": total,
        "cost_status": status,
        "priced_cost_usd": 0.004,
        "unpriced_trace_count": 0 if status in ("priced", "not_applicable") else 1,
        "total_tokens": 10,
        **extra,
    }


@pytest.mark.parametrize(
    "status,total",
    [("priced", 1.25), ("partial", None), ("unpriced", None), ("not_applicable", None)],
)
def test_activity_trend_bucket_cost_rollup_validates(status, total):
    doc = _summary({"total_cost_usd": 1.0, "total_cost_usd_in_range": 1.0, "cost_status": "priced"}, [])
    doc["activity_trend"] = [_bucket(status, total)]
    name = "project_scoped_observability_summary_dashboard_schema"
    assert SchemaValidator().validate_json(doc, name) == []


def test_activity_trend_rejects_bad_bucket_cost_values():
    v = SchemaValidator()
    name = "project_scoped_observability_summary_dashboard_schema"
    for bad in ({"cost_status": "free"}, {"total_cost_usd": -1}, {"unpriced_trace_count": -1}):
        doc = _summary({"total_cost_usd": 1.0, "total_cost_usd_in_range": 1.0, "cost_status": "priced"}, [])
        doc["activity_trend"] = [_bucket("priced", 1.0, **bad)]
        assert v.validate_json(doc, name) != []


# --- tool analysis / cohort comparison producer payloads (Sol 6.1 P1-2) ---------------------

def _tool_item(total, status, priced, unpriced):
    return {
        "normalized_tool_id": "search", "trace_count": 2, "attempt_count": 3,
        "success_count": 3, "failure_count": 0, "retry_count": 0, "fallback_count": 0,
        "failure_rate": 0.0, "retry_rate": 0.0, "fallback_rate": 0.0,
        "p50_latency_ms": 10.0, "p95_latency_ms": 12.0,
        "total_cost_usd": total, "cost_status": status, "priced_cost_usd": priced,
        "unpriced_attempt_count": unpriced, "issue_ids": [],
    }


TOOL_ITEMS = {
    "priced": _tool_item(0.03, "priced", 0.03, 0),
    "partial": _tool_item(None, "partial", 0.02, 1),
    "unpriced": _tool_item(None, "unpriced", 0.0, 3),
}


def _tool_response(item):
    return {"project_id": "p1", "start_time": TS, "end_time": TS, "items": [item], "generated_at": TS}


@pytest.mark.parametrize("name", sorted(TOOL_ITEMS))
def test_tool_analysis_cost_shapes_validate(name):
    assert SchemaValidator().validate_json(_tool_response(TOOL_ITEMS[name]), "tool_analysis_response_schema") == []


def test_tool_analysis_rejects_bad_cost_and_unknown_fields():
    v = SchemaValidator()
    item = TOOL_ITEMS["partial"]
    assert v.validate_json(_tool_response({**item, "cost_status": "free"}), "tool_analysis_response_schema") != []
    assert v.validate_json(_tool_response({**item, "total_cost_usd": -1}), "tool_analysis_response_schema") != []
    assert v.validate_json(_tool_response({**item, "surprise": 1}), "tool_analysis_response_schema") != []


def _cohort(cost_metric):
    return {"trace_count": 3, "metrics": [cost_metric]}


COHORT_METRICS = {
    "priced": {"metric": "cost_usd", "sample_count": 3, "mean": 0.01, "median": 0.01, "p95": 0.02,
               "unknown_count": 0, "cost_status": "priced"},
    "partial": {"metric": "cost_usd", "sample_count": 2, "mean": None, "median": None, "p95": None,
                "unknown_count": 1, "cost_status": "partial"},
    "unpriced": {"metric": "cost_usd", "sample_count": 0, "mean": None, "median": None, "p95": None,
                 "unknown_count": 3, "cost_status": "unpriced"},
}


@pytest.mark.parametrize("name", sorted(COHORT_METRICS))
def test_cohort_comparison_cost_shapes_validate(name):
    payload = {
        "project_id": "p1", "reference": _cohort(COHORT_METRICS[name]),
        "comparison": _cohort(COHORT_METRICS[name]), "matched_pair_count": 0,
        "deltas": [], "generated_at": TS,
    }
    assert SchemaValidator().validate_json(payload, "cohort_comparison_response_schema") == []


# --- negative controls for the tool / cohort additions (each must fail if its constraint is removed)

@pytest.mark.parametrize(
    "patch",
    [
        {"cost_status": "free"},
        {"cost_status": None},
        {"cost_status": 1},
        {"priced_cost_usd": -0.01},
        {"priced_cost_usd": "0.02"},
        {"unpriced_attempt_count": -1},
        {"unpriced_attempt_count": 1.5},
        {"unpriced_attempt_count": "1"},
        {"unpriced_attempt_count": None},
        {"total_cost_usd": "0.03"},
    ],
    ids=lambda p: next(iter(p)) + "=" + repr(next(iter(p.values()))),
)
def test_tool_analysis_rejects_invalid_cost_additions(patch):
    item = {**TOOL_ITEMS["partial"], **patch}
    assert SchemaValidator().validate_json(_tool_response(item), "tool_analysis_response_schema") != []


@pytest.mark.parametrize(
    "patch",
    [
        {"cost_status": "free"},
        {"cost_status": 1},
        {"unknown_count": -1},
        {"unknown_count": 1.5},
        {"unknown_count": "2"},
        {"unknown_count": None},
    ],
    ids=lambda p: next(iter(p)) + "=" + repr(next(iter(p.values()))),
)
def test_cohort_comparison_rejects_invalid_cost_additions(patch):
    metric = {**COHORT_METRICS["partial"], **patch}
    payload = {
        "project_id": "p1", "reference": _cohort(metric), "comparison": _cohort(metric),
        "matched_pair_count": 0, "deltas": [], "generated_at": TS,
    }
    assert SchemaValidator().validate_json(payload, "cohort_comparison_response_schema") != []
