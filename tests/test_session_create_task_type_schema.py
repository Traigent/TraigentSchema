"""Coarse task_type hint on POST /api/v1/sessions (evaluator-quality anchor policy).

The backend's anchor resolver (``anchor_policy.resolve_anchor_policy``) accepts a
client-declared coarse ``task_type`` and maps it server-side to an anchor type.
Until this field existed on the session-create contract, the only way to reach it
was an untyped key the SDK never sent -- so ``mcq_exact`` was unreachable for every
real run. This pins the field's shape so both SDKs and the backend agree.
"""

from __future__ import annotations

from typing import Any

from traigent_schema import SchemaValidator


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "mcq_agent",
        "configuration_space": {"temperature": [0.0, 0.7]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _validator() -> SchemaValidator:
    return SchemaValidator(contract="sdk_tuning")


def test_accepts_a_coarse_task_type() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(task_type="multiple_choice")
    )
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_task_type_is_optional() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload())
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_unknown_task_type_is_still_a_valid_request() -> None:
    """The server maps unknown values to 'no anchor'; the contract must not enumerate."""
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(task_type="some_future_task_kind")
    )
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_task_type_rejects_empty_string() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload(task_type=""))
    assert errors, "an empty task_type is not a hint; omit the field instead"


def test_task_type_rejects_non_string() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(task_type={"kind": "mcq"})
    )
    assert errors, "task_type is a coarse string token, never an object the client shapes"


def test_task_type_rejects_over_length() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(task_type="x" * 129)
    )
    assert errors, "task_type is capped at 128 characters, matching the plan request"


def test_task_type_shape_matches_the_plan_request_field() -> None:
    """One vocabulary, one shape: the plan request already carries this field."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas" / "optimization"
    sessions = json.loads((root / "optimization_endpoints.json").read_text())
    session_field = sessions["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["properties"]["task_type"]
    plan_field = json.loads((root / "optimization_plan_request_schema.json").read_text())[
        "properties"
    ]["task_type"]
    for key in ("type", "minLength", "maxLength"):
        assert session_field[key] == plan_field[key], key
