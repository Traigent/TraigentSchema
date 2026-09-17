"""Client-driven trial sequencing flag on session create (Schema#323).

Connected grid/random runs that decide trials LOCALLY (post-Traigent#1421 exhaustive
enumeration) were being early-stopped by the backend's own optimizer budget, because
the session-create contract had no way for a caller to say "I am sequencing trials
myself; do not stop me from your budget." ``trial_sequencing`` closes that gap:
``"backend"`` (default, fully backward-compatible) preserves today's behaviour;
``"client"`` tells the server to allocate trial ids on demand and treat its own
budget accounting as informational only, never as an early-stop trigger.

Before this field existed, the request schemas used ``additionalProperties: true``,
so a client sending ``trial_sequencing`` in any shape (a typo'd string, a number, an
object) validated cleanly with zero errors -- the contract enforced nothing. This
pins the field's shape on both session-create surfaces so the SDKs and the backend
agree.
"""

from __future__ import annotations

from typing import Any

from traigent_schema import SchemaValidator


def _session_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _hybrid_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "config_space": [
            {"temperature": 0.1, "model": "fast"},
            {"temperature": 0.8, "model": "accurate"},
        ],
        "task_description": "Optimize support reply quality.",
    }
    payload.update(overrides)
    return payload


def _validator() -> SchemaValidator:
    return SchemaValidator(contract="sdk_tuning")


def test_session_create_trial_sequencing_is_optional() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _session_payload())
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_accepts_client_driven_sequencing() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _session_payload(trial_sequencing="client")
    )
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_accepts_backend_sequencing() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _session_payload(trial_sequencing="backend")
    )
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_rejects_unknown_sequencing_value() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _session_payload(trial_sequencing="cloud")
    )
    assert errors, "trial_sequencing is a closed enum: client or backend only"


def test_session_create_rejects_non_string_sequencing() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _session_payload(trial_sequencing=12345)
    )
    assert errors, "trial_sequencing must be a string, not a smuggled number"


def test_hybrid_create_trial_sequencing_is_optional() -> None:
    errors = _validator().validate_request("/api/v1/hybrid/sessions", "POST", _hybrid_payload())
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_hybrid_create_accepts_client_driven_sequencing() -> None:
    errors = _validator().validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_payload(trial_sequencing="client"),
    )
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_hybrid_create_rejects_unknown_sequencing_value() -> None:
    errors = _validator().validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_payload(trial_sequencing="edge"),
    )
    assert errors, "trial_sequencing is a closed enum: client or backend only"


def test_session_and_hybrid_create_agree_on_trial_sequencing_shape() -> None:
    """One vocabulary, one shape: both session-create surfaces must match exactly."""
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas" / "optimization"
    endpoints = json.loads((root / "optimization_endpoints.json").read_text())
    session_field = endpoints["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["properties"]["trial_sequencing"]
    hybrid_field = json.loads((root / "hybrid_session_create_request_schema.json").read_text())[
        "properties"
    ]["trial_sequencing"]

    assert session_field["enum"] == hybrid_field["enum"] == ["client", "backend"]
    assert session_field["default"] == hybrid_field["default"] == "backend"
