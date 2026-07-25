"""Behavioral validation tests for hybrid execution session records."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from traigent_schema import SchemaValidator

SCHEMA = "hybrid_session_schema"


def _hybrid_session_payload() -> dict[str, Any]:
    return {
        "id": "98b92992-2c6b-4f01-9fb7-8ac1c4bff001",
        "session_id": "hybrid-session-001",
        "experiment_id": "af0f8c80-0f3a-4b05-9aa2-92e68c37d002",
        "customer_id": "e2d6879c-7fc3-436f-a26a-94740c3d9003",
        "status": "active",
        "token_info": {
            "token_hash": "a" * 64,
            "issued_at": "2026-07-25T09:00:00Z",
            "expires_at": "2026-07-25T10:00:00Z",
            "token_id": "jwt-token-001",
        },
        "optimizer_endpoint": "https://optimizer.example.com/sessions/hybrid-session-001",
        "session_metrics": {
            "metrics_submitted": 3,
            "configurations_evaluated": 2,
            "last_metric_at": "2026-07-25T09:15:00Z",
            "error_count": 0,
        },
        "metadata": {
            "client_version": "1.2.3",
            "search_space": {"temperature": [0.0, 1.0]},
            "tags": ["hybrid", "acceptance"],
        },
        "created_at": "2026-07-25T09:00:00Z",
        "expires_at": "2026-07-25T11:00:00Z",
    }


def test_hybrid_session_schema_accepts_valid_tenant_scoped_session() -> None:
    assert SchemaValidator().validate_json(_hybrid_session_payload(), SCHEMA) == []


@pytest.mark.parametrize(
    "required_field",
    (
        "id",
        "session_id",
        "experiment_id",
        "customer_id",
        "status",
        "token_info",
        "optimizer_endpoint",
        "created_at",
        "expires_at",
    ),
)
def test_hybrid_session_schema_rejects_missing_required_fields(
    required_field: str,
) -> None:
    payload = _hybrid_session_payload()
    del payload[required_field]

    assert SchemaValidator().validate_json(payload, SCHEMA), required_field


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    (
        ("id", 1),
        ("session_id", 1),
        ("experiment_id", 1),
        ("customer_id", 1),
        ("status", 1),
        ("token_info", "not-token-info"),
        ("optimizer_endpoint", False),
        ("created_at", None),
        ("expires_at", 1),
    ),
)
def test_hybrid_session_schema_rejects_wrong_types(
    field: str,
    invalid_value: Any,
) -> None:
    payload = _hybrid_session_payload()
    payload[field] = invalid_value

    assert SchemaValidator().validate_json(payload, SCHEMA), field


@pytest.mark.parametrize(
    "path",
    (
        (),
        ("token_info",),
        ("session_metrics",),
    ),
)
def test_hybrid_session_schema_rejects_unknown_fields_in_closed_objects(
    path: tuple[str, ...],
) -> None:
    payload = _hybrid_session_payload()
    target: dict[str, Any] = payload
    for field in path:
        target = target[field]
    target["unexpected_property"] = "must not be accepted"

    assert SchemaValidator().validate_json(deepcopy(payload), SCHEMA), path
