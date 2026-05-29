"""Pin GET /api/v1/audit/alerts response shape.

Advances TraigentSchema#35 by covering the audit alerts endpoint. The backend
handler emits both canonical `data` and dashboard `alerts` lists, static
threshold configuration, and observed 24-hour metrics. The failure path uses
the standard error envelope (success=false, error, message).
"""

from __future__ import annotations

import json
from copy import deepcopy

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "alerts_response_schema"


def _backend_failure_payload() -> dict[str, object]:
    return {
        "success": False,
        "message": "Internal server error",
        "error": "database timeout",
    }


def _backend_payload() -> dict[str, object]:
    active_alerts = [
        {
            "alert_id": "default_security_watch",
            "severity": "critical",
            "summary": "Critical security events exceeded daily threshold",
            "observed_value": 7,
        },
        {
            "alert_id": "scope_violation_watch",
            "severity": "high",
            "summary": "Tenant or project scope violations detected",
            "observed_value": 2,
        },
    ]
    return {
        "success": True,
        "data": [dict(alert) for alert in active_alerts],
        "alerts": [dict(alert) for alert in active_alerts],
        "configuration": {
            "alert_id": "default_security_watch",
            "name": "Security Event Thresholds",
            "description": "Alerts when abnormal security activity is detected.",
            "conditions": {
                "critical_events_per_day": 5,
                "brute_force_attempts": 10,
                "suspicious_activity": 20,
                "scope_violations_per_day": 1,
                "scope_discrepancies_per_day": 1,
            },
            "channels": ["email", "pager"],
            "enabled": True,
        },
        "metrics": {
            "critical_events_24h": 7,
            "total_security_events_24h": 15,
            "scope_violations_24h": 2,
            "scope_discrepancies_24h": 0,
        },
    }


def test_alerts_schema_file_present() -> None:
    path = get_schemas_dir() / "audit" / "alerts_response_schema.json"
    assert path.exists()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "AuditAlertConfiguration" in payload["definitions"]


def test_audit_endpoints_references_alerts_schema() -> None:
    path = get_schemas_dir() / "audit" / "audit_endpoints.json"
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)

    responses = spec["paths"]["/api/v1/audit/alerts"]["get"]["responses"]
    ok_ref = responses["200"]["content"]["application/json"]["schema"]["$ref"]
    err_ref = responses["500"]["content"]["application/json"]["schema"]["$ref"]
    assert ok_ref.endswith("alerts_response_schema.json")
    assert err_ref.endswith("alerts_response_schema.json")


def test_backend_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_failure_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_failure_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_failure_payload_missing_message_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_failure_payload())
    bad.pop("message")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when failure payload omits message"


def test_empty_active_alerts_payload_validates() -> None:
    validator = SchemaValidator()
    payload = deepcopy(_backend_payload())
    payload["data"] = []
    payload["alerts"] = []
    errors = validator.validate_json(payload, SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_payload_missing_alerts_alias_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_payload())
    bad.pop("alerts")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when success payload omits alerts alias"


def test_payload_missing_configuration_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_payload())
    bad.pop("configuration")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when success payload omits configuration"


def test_payload_missing_metrics_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_payload())
    bad.pop("metrics")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when success payload omits metrics"


def test_configuration_missing_condition_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_payload())
    bad["configuration"]["conditions"].pop("scope_discrepancies_per_day")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("scope_discrepancies_per_day" in error for error in errors), errors


def test_alert_missing_observed_value_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_payload())
    bad["data"][0].pop("observed_value")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("observed_value" in error for error in errors), errors
