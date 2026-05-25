"""Pin GET /api/v1/audit/health response shape.

Advances TraigentSchema#35 by covering the audit-pipeline health endpoint. The
TraigentBackend audit_routes.get_audit_health handler returns one of two
deterministic shapes:

* `success=true` with a nested `data` snapshot containing rolling counters,
  warnings, and an ISO-8601 timestamp.
* `success=false` (HTTP 500) with `error` and `message` strings.

Both paths are pinned so the admin dashboard never reads through a shape that
neither side has declared.
"""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "health_response_schema"


def _backend_success_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "status": "healthy",
            "recent_events": 12,
            "critical_events_24h": 0,
            "scope_violations_24h": 0,
            "scope_discrepancies_24h": 0,
            "warnings": [],
            "timestamp": "2026-05-24T09:31:12+00:00",
        },
    }


def _backend_warning_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "status": "warning",
            "recent_events": 4,
            "critical_events_24h": 2,
            "scope_violations_24h": 1,
            "scope_discrepancies_24h": 0,
            "warnings": [
                "2 critical security events in last 24 hours",
                "1 tenant/project scope violations in last 24 hours",
            ],
            "timestamp": "2026-05-24T09:31:12+00:00",
        },
    }


def _backend_failure_payload() -> dict[str, object]:
    return {
        "success": False,
        "error": "Failed to check audit health",
        "message": "database connection refused",
    }


def test_health_schema_file_present() -> None:
    path = get_schemas_dir() / "audit" / "health_response_schema.json"
    assert path.exists()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "AuditHealthSnapshot" in payload["definitions"]


def test_audit_endpoints_references_health_schema() -> None:
    path = get_schemas_dir() / "audit" / "audit_endpoints.json"
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)

    responses = spec["paths"]["/api/v1/audit/health"]["get"]["responses"]
    assert "200" in responses
    ok_ref = responses["200"]["content"]["application/json"]["schema"]["$ref"]
    err_ref = responses["500"]["content"]["application/json"]["schema"]["$ref"]
    assert ok_ref.endswith("health_response_schema.json")
    assert err_ref.endswith("health_response_schema.json")


def test_success_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_success_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_warning_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_warning_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_failure_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_failure_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_success_payload_missing_data_fails() -> None:
    """A `success=true` response must always carry a `data` snapshot."""
    validator = SchemaValidator()
    bad = _backend_success_payload()
    bad.pop("data")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when `data` is missing on success path"


def test_success_payload_missing_required_snapshot_field_fails() -> None:
    """Each snapshot must surface every canonical counter the dashboard reads."""
    validator = SchemaValidator()
    bad = _backend_success_payload()
    bad["data"].pop("timestamp")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("timestamp" in error for error in errors), errors


def test_failure_payload_missing_message_fails() -> None:
    """A `success=false` response must carry both `error` and `message`."""
    validator = SchemaValidator()
    bad = _backend_failure_payload()
    bad.pop("message")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when `message` is missing on failure path"


def test_unknown_status_value_fails() -> None:
    """Status enum must be enforced so backend rollups stay machine-checkable."""
    validator = SchemaValidator()
    bad = _backend_success_payload()
    bad["data"]["status"] = "totally-fine"
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("status" in error for error in errors), errors
