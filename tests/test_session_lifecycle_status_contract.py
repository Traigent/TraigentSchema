"""Session lifecycle status, next-trial consistency, results body and 413 (issues 619, 621-623).

Pins, against the wire the Backend serves:
* one lowercase session-lifecycle enum bound to the hybrid status ``status`` and the next-trial
  ``session_status`` (``complete`` and ``completed`` are both on the wire today);
* the next-trial response rejects a terminal status that still offers work;
* the typed next-trial fields, the ``/results`` 200 body and the 413 response on the session POSTs;
* the dead ``HealthStatus`` definition is gone.
"""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import SCHEMA_ID_BASE, build_registry, load_json, ref_errors
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
ENDPOINTS = SCHEMAS / "optimization" / "optimization_endpoints.json"
NEXT_TRIAL = SCHEMA_ID_BASE + "optimization/session_next_trial_response_schema.json"
RESULTS = SCHEMA_ID_BASE + "optimization/session_results_response_schema.json"
LIFECYCLE = SCHEMA_ID_BASE + "optimization/session_lifecycle_status_schema.json"
HYBRID_SESSION = SCHEMA_ID_BASE + "execution/hybrid_session_schema.json#/definitions/SessionStatus"

REGISTRY = build_registry()

# Every lowercase literal the Backend normalizer can emit (SessionStatus, ExperimentStatus,
# ExperimentRunStatus, ConfigurationRunStatus, HybridSessionPhase, plus the SDK public set).
WIRE_STATUSES = {
    "aborted", "active", "awaiting_results", "cancelled", "cold_start_a", "cold_start_b",
    "complete", "completed", "created", "elimination_round", "expired", "failed",
    "not_started", "partially_deleted", "paused", "pending", "pruned", "registered",
    "running", "starting", "unknown",
}  # fmt: skip
TERMINAL = ("completed", "complete", "failed", "cancelled", "aborted", "expired")

TRIAL = {
    "trial_id": "trial_0123456789abcdef",
    "agent_specification": {"model_parameters": {"model": "m", "temperature": 0.2}},
    "dataset_subset_indices": {"indices": [0, 1], "strategy": "random"},
    "metadata": {},
}


def _next(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "has_next": True,
        "trial": deepcopy(TRIAL),
        "remaining_trials": 2,
        "session_status": "active",
    }
    payload.update(overrides)
    return payload


def _errors(ref: str, instance: Any) -> list[str]:
    return ref_errors(REGISTRY, ref, instance)


def _endpoint_response_errors(path: str, method: str, code: str, instance: Any) -> list[str]:
    operation = load_json(ENDPOINTS)["paths"][path][method]
    node = operation["responses"][code]["content"]["application/json"]["schema"]
    wrapped = {"$id": SCHEMA_ID_BASE + "optimization/optimization_endpoints.json", **node}
    return [e.message for e in Draft7Validator(wrapped, registry=REGISTRY).iter_errors(instance)]


# --- 619 ---------------------------------------------------------------------------------


def test_health_status_definition_is_gone() -> None:
    status = load_json(SCHEMAS / "status_schema.json")
    assert "HealthStatus" not in status["definitions"]
    assert "failing" not in json.dumps(status)


# --- 621 ---------------------------------------------------------------------------------


def test_lifecycle_enum_is_the_full_lowercase_wire_set() -> None:
    enum = load_json(SCHEMAS / "optimization" / "session_lifecycle_status_schema.json")["enum"]
    assert set(enum) == WIRE_STATUSES
    assert len(enum) == len(set(enum))


def test_next_trial_inlines_exactly_the_shared_enum() -> None:
    shared = load_json(SCHEMAS / "optimization" / "session_lifecycle_status_schema.json")["enum"]
    inline = load_json(SCHEMAS / "optimization" / "session_next_trial_response_schema.json")[
        "properties"
    ]["session_status"]["enum"]
    assert inline == shared


@pytest.mark.parametrize("value", sorted(WIRE_STATUSES))
def test_every_wire_status_validates_on_both_bound_fields(value: str) -> None:
    assert _errors(LIFECYCLE, value) == []
    assert _endpoint_response_errors(
        "/api/v1/hybrid/sessions/{session_id}/status", "get", "200", {"status": value}
    ) == []
    has_next = value not in TERMINAL
    payload = _next(session_status=value, has_next=has_next)
    if not has_next:
        payload.update(trial=None, remaining_trials=0)
    assert _errors(NEXT_TRIAL, payload) == []


@pytest.mark.parametrize("value", ["ok", "COMPLETED", "done", "finished", ""])
def test_a_value_the_backend_never_emits_is_rejected(value: str) -> None:
    assert _errors(LIFECYCLE, value)
    assert _endpoint_response_errors(
        "/api/v1/hybrid/sessions/{session_id}/status", "get", "200", {"status": value}
    )
    assert _errors(NEXT_TRIAL, _next(session_status=value))


def test_hybrid_complete_validates_and_the_record_schema_shares_the_enum() -> None:
    assert _endpoint_response_errors(
        "/api/v1/hybrid/sessions/{session_id}/status",
        "get",
        "200",
        {"session_id": "s", "status": "complete"},
    ) == []
    assert _errors(HYBRID_SESSION, "complete") == []
    assert _errors(HYBRID_SESSION, "completed") == []
    assert _errors(HYBRID_SESSION, "bogus")


# --- 622 ---------------------------------------------------------------------------------


@pytest.mark.parametrize("status", TERMINAL)
def test_terminal_status_with_available_work_is_rejected(status: str) -> None:
    # The concrete BE#4479 payload: completed + has_next true + a trial + remaining work.
    assert _errors(NEXT_TRIAL, _next(session_status=status))


def test_final_allocated_trial_with_zero_remaining_stays_valid() -> None:
    assert _errors(NEXT_TRIAL, _next(remaining_trials=0, session_status="active")) == []


def test_exhausted_terminal_response_stays_valid() -> None:
    exhausted = _next(has_next=False, trial=None, remaining_trials=0, session_status="completed")
    assert _errors(NEXT_TRIAL, exhausted) == []


def test_classic_exhausted_reply_without_status_fields_stays_valid() -> None:
    assert _errors(NEXT_TRIAL, {"has_next": False, "trial": None, "message": "done"}) == []


def test_has_next_false_cannot_carry_a_trial_or_remaining_work() -> None:
    assert _errors(NEXT_TRIAL, _next(has_next=False, remaining_trials=0, session_status="running"))
    assert _errors(
        NEXT_TRIAL, _next(has_next=False, trial=None, remaining_trials=3, session_status="running")
    )


def test_has_next_true_requires_a_trial_object() -> None:
    assert _errors(NEXT_TRIAL, _next(trial=None))
    assert _errors(NEXT_TRIAL, {"has_next": True, "remaining_trials": 1})


# --- 623 ---------------------------------------------------------------------------------


def _typed_reply(**overrides: Any) -> dict[str, Any]:
    payload = _next(
        suggestion=deepcopy(TRIAL),
        should_continue=True,
        reason=None,
        stop_reason=None,
    )
    payload.update(overrides)
    return payload


def test_next_trial_declares_the_typed_fields() -> None:
    props = load_json(SCHEMAS / "optimization" / "session_next_trial_response_schema.json")[
        "properties"
    ]
    for key in ("suggestion", "should_continue", "reason", "stop_reason"):
        assert key in props


def test_typed_next_trial_reply_validates_and_is_typed() -> None:
    assert _errors(NEXT_TRIAL, _typed_reply()) == []
    stopped = _typed_reply(
        has_next=False,
        trial=None,
        suggestion=None,
        should_continue=False,
        reason="search_complete",
        stop_reason="search_complete",
        remaining_trials=0,
        session_status="completed",
    )
    assert _errors(NEXT_TRIAL, stopped) == []
    assert _errors(NEXT_TRIAL, _typed_reply(should_continue="yes"))
    assert _errors(NEXT_TRIAL, _typed_reply(stop_reason="free text from a customer"))


def test_typed_fields_must_agree_with_has_next() -> None:
    assert _errors(NEXT_TRIAL, _typed_reply(should_continue=False))
    stopped = _typed_reply(has_next=False, trial=None, remaining_trials=0, session_status="running")
    assert _errors(NEXT_TRIAL, stopped)  # should_continue true / suggestion set but has_next false


def test_results_200_has_a_body_with_continue_optimization() -> None:
    props = _results_props()
    assert "continue_optimization" in props
    body = {"success": True, "continue_optimization": True, "message": "Results submitted successfully"}
    assert _endpoint_response_errors("/api/v1/sessions/{session_id}/results", "post", "200", body) == []
    assert _errors(RESULTS, {"success": True})  # continue_optimization is required
    assert _errors(RESULTS, {"success": True, "continue_optimization": "no"})
    assert _errors(RESULTS, {**body, "extra": 1})  # closed


def _results_props() -> dict[str, Any]:
    return load_json(SCHEMAS / "optimization" / "session_results_response_schema.json")["properties"]


SESSION_POSTS_PARSING_A_JSON_BODY = (
    "/api/v1/sessions",
    "/api/v1/sessions/{session_id}/next-trial",
    "/api/v1/sessions/{session_id}/intermediate-report",
    "/api/v1/sessions/{session_id}/results",
    "/api/v1/sessions/{session_id}/finalize",
)


@pytest.mark.parametrize("path", SESSION_POSTS_PARSING_A_JSON_BODY)
def test_session_posts_list_413(path: str) -> None:
    responses = load_json(ENDPOINTS)["paths"][path]["post"]["responses"]
    assert "413" in responses
    # Same closed error envelope the neighbouring 400 uses; the Backend serves PAYLOAD_TOO_LARGE in it.
    assert responses["413"]["content"] == responses["400"]["content"]
    assert "PAYLOAD_TOO_LARGE" in responses["413"]["description"]
