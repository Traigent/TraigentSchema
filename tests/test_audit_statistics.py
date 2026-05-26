"""Pin GET /api/v1/audit/statistics response shape.

Advances TraigentSchema#35 by covering the audit statistics endpoint. The
backend handler returns summary counts, event-type counts, and the requested
date range under `data`; failures use the standard error envelope.
"""

from __future__ import annotations

import json
from copy import deepcopy

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "statistics_response_schema"


def _backend_success_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "summary": {
                "total_events": 17,
                "success_events": 13,
                "failure_events": 4,
                "success_rate": 76.47,
                "security_events": 3,
            },
            "event_types": [
                {"event_type": "login_failed", "count": 2},
                {"event_type": "suspicious_activity", "count": 1},
            ],
            "date_range": {
                "start": "2026-05-25T09:31:12+00:00",
                "end": "2026-05-26T09:31:12+00:00",
            },
        },
    }


def _backend_failure_payload() -> dict[str, object]:
    return {
        "success": False,
        "message": "Internal server error",
        "error": "database timeout",
    }


def test_statistics_schema_file_present() -> None:
    path = get_schemas_dir() / "audit" / "statistics_response_schema.json"
    assert path.exists()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "AuditStatisticsSummary" in payload["definitions"]


def test_audit_endpoints_references_statistics_schema() -> None:
    path = get_schemas_dir() / "audit" / "audit_endpoints.json"
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)

    responses = spec["paths"]["/api/v1/audit/statistics"]["get"]["responses"]
    ok_ref = responses["200"]["content"]["application/json"]["schema"]["$ref"]
    err_ref = responses["500"]["content"]["application/json"]["schema"]["$ref"]
    assert ok_ref.endswith("statistics_response_schema.json")
    assert err_ref.endswith("statistics_response_schema.json")


def test_success_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_success_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_failure_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_failure_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_success_payload_missing_summary_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_success_payload())
    bad["data"].pop("summary")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("summary" in error for error in errors), errors


def test_success_payload_missing_date_range_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_success_payload())
    bad["data"].pop("date_range")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("date_range" in error for error in errors), errors


def test_summary_missing_success_rate_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_success_payload())
    bad["data"]["summary"].pop("success_rate")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("success_rate" in error for error in errors), errors


def test_event_type_count_missing_count_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_success_payload())
    bad["data"]["event_types"][0].pop("count")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("count" in error for error in errors), errors


def test_failure_payload_missing_message_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_backend_failure_payload())
    bad.pop("message")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert errors, "Expected validation errors when failure payload omits message"
