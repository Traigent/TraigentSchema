"""Pin GET /api/v1/audit/security/incidents response shape.

Closes the first acceptance criterion of TraigentSchema#35. Shape is mirrored
from TraigentBackend's SecurityMonitor.get_recent_incidents aggregation: the
backend emits both canonical (`timestamp`/`severity`) and dashboard alias
(`detected_at`/`threat_level`) fields so either side drifting is detectable.
"""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "security_incidents_response_schema"


def _backend_payload() -> dict[str, object]:
    incidents = [
        {
            "id": "brute_force_attempt:user_abc",
            "timestamp": "2026-05-21T09:31:12+00:00",
            "detected_at": "2026-05-21T09:31:12+00:00",
            "first_detected_at": "2026-05-21T09:30:12+00:00",
            "last_detected_at": "2026-05-21T09:31:12+00:00",
            "incident_type": "brute_force_attempt",
            "anomaly_type": "brute_force_attempt",
            "severity": "high",
            "threat_level": "high",
            "source_ip": "203.0.113.7",
            "user_id": "user_abc",
            "actor": "user_abc",
            "resource": "session/sess_42",
            "affected_users": ["user_abc"],
            "affected_resources": ["session/sess_42"],
            "description": "Repeated failed logins from same source",
            "evidence": [
                {
                    "event_id": 7421,
                    "event_type": "brute_force_attempt",
                    "detected_at": "2026-05-21T09:31:12+00:00",
                    "reason": "Repeated failed logins from same source",
                    "source_ip": "203.0.113.7",
                    "user_id": "user_abc",
                }
            ],
            "event_count": 14,
            "recommended_actions": ["Block source IP temporarily"],
            "auto_response_taken": False,
            "resolved": False,
            "resolved_at": None,
            "resolution_notes": None,
            "outcome": "denied",
            "additional_context": {"attempts": 14},
            "soc2_control": "CC6.1",
        },
        {
            "id": "rate_limit_exceeded:system",
            "timestamp": "2026-05-21T09:32:01+00:00",
            "detected_at": "2026-05-21T09:32:01+00:00",
            "first_detected_at": "2026-05-21T09:32:01+00:00",
            "last_detected_at": "2026-05-21T09:32:01+00:00",
            "incident_type": "rate_limit_exceeded",
            "anomaly_type": "rate_limit_exceeded",
            "severity": "medium",
            "threat_level": "medium",
            "source_ip": None,
            "user_id": None,
            "actor": "system",
            "resource": None,
            "affected_users": [],
            "affected_resources": [],
            "description": None,
            "evidence": [],
            "event_count": 1,
            "recommended_actions": [],
            "auto_response_taken": False,
            "resolved": True,
            "resolved_at": "2026-05-21T09:35:01+00:00",
            "resolution_notes": "Reviewed",
            "outcome": None,
            "additional_context": None,
            "soc2_control": None,
        },
    ]
    summary = {
        "total_incidents": 2,
        "all_incidents": 2,
        "total_incident_groups": 2,
        "active_incident_groups": 1,
        "active_event_count": 14,
        "resolved_incidents": 1,
        "resolved_event_count": 1,
        "resolved_incident_groups": 1,
        "critical_severity": 0,
        "high_severity": 1,
        "medium_severity": 1,
        "low_severity": 0,
        "window_days": 7,
    }
    return {
        "success": True,
        "data": [dict(incident) for incident in incidents],
        "incidents": [dict(incident) for incident in incidents],
        "summary": summary,
    }


def test_security_incidents_schema_file_present() -> None:
    path = (
        get_schemas_dir() / "audit" / "security_incidents_response_schema.json"
    )
    assert path.exists()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "SecurityIncident" in payload["definitions"]
    assert "SecurityIncidentSummary" in payload["definitions"]


def test_audit_endpoints_references_security_incidents_schema() -> None:
    path = get_schemas_dir() / "audit" / "audit_endpoints.json"
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)

    for route in (
        "/api/v1/audit/security/incidents",
        "/api/v1/audit/soc2/security-incidents",
    ):
        response = spec["paths"][route]["get"]["responses"]["200"]
        schema_ref = response["content"]["application/json"]["schema"]["$ref"]
        assert schema_ref.endswith("security_incidents_response_schema.json")


def test_backend_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_payload_missing_dashboard_aliases_fails() -> None:
    """Dropping dashboard aliases must trip the schema before FE drift ships."""
    validator = SchemaValidator()
    bad = _backend_payload()
    bad["incidents"][0].pop("detected_at")
    bad["incidents"][0].pop("threat_level")
    bad["data"][0].pop("detected_at")
    bad["data"][0].pop("threat_level")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("detected_at" in error or "threat_level" in error for error in errors), errors


def test_payload_null_required_timestamps_fails() -> None:
    """Required incident timestamps are non-null in backend aggregation output."""
    validator = SchemaValidator()
    bad = _backend_payload()
    bad["incidents"][0]["timestamp"] = None
    bad["incidents"][0]["detected_at"] = None
    bad["data"][0]["timestamp"] = None
    bad["data"][0]["detected_at"] = None
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("timestamp" in error or "detected_at" in error for error in errors), errors
