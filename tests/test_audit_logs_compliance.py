"""Pin audit log and SOC2 compliance response shapes.

Advances TraigentSchema#35 by replacing the remaining unschematized audit
responses with shapes grounded in TraigentBackend/src/routes/audit_routes.py
and SecurityAuditLogger._event_to_dict.
"""

from __future__ import annotations

import json
from copy import deepcopy

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _audit_log_entry() -> dict[str, object]:
    return {
        "id": 42,
        "event_type": "access_granted",
        "timestamp": "2026-05-24T09:31:12+00:00",
        "user_id": "user_123",
        "api_key_id": None,
        "resource": "audit_log/log_42",
        "permission": "audit.read",
        "action": "read",
        "outcome": "success",
        "reason": "Audit log access granted",
        "is_admin_action": True,
        "ip_address": "203.0.113.10",
        "event_data": {"scope_mode": "global", "scope_tenant_id": None},
        "checksum": "0" * 64,
    }


def _pagination() -> dict[str, object]:
    return {
        "page": 1,
        "per_page": 20,
        "total": 1,
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    }


def _audit_log_list_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "logs": [_audit_log_entry()],
            "pagination": _pagination(),
        },
    }


def _audit_log_detail_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": _audit_log_entry(),
    }


def _audit_log_export_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "logs": [_audit_log_entry()],
            "total_exported": 1,
            "export_timestamp": "2026-05-24T09:32:12+00:00",
            "filters_applied": {
                "start_date": "2026-05-23T09:31:12+00:00",
                "end_date": "2026-05-24T09:31:12+00:00",
                "event_type": "access_granted",
                "user_id": "user_123",
                "outcome": "success",
                "resource_type": "audit_log",
            },
        },
    }


def _criterion(
    metrics: dict[str, int],
    *,
    compliance_score: float = 100,
    status: str = "COMPLIANT",
) -> dict[str, object]:
    return {
        "description": "Logical and physical access controls",
        "metrics": metrics,
        "compliance_score": compliance_score,
        "status": status,
    }


def _soc2_compliance_payload() -> dict[str, object]:
    return {
        "success": True,
        "data": {
            "report_metadata": {
                "report_type": "SOC 2 Type I Compliance Report",
                "generated_at": "2026-05-24T09:31:12+00:00",
                "period_start": "2026-04-24T09:31:12+00:00",
                "period_end": "2026-05-24T09:31:12+00:00",
                "period_days": 30,
                "generated_by": "user_123",
            },
            "trust_service_criteria": {
                "CC6.1_logical_access_controls": _criterion(
                    {
                        "total_access_attempts": 20,
                        "successful_access": 19,
                        "denied_access": 1,
                    }
                ),
                "CC6.2_authorization": _criterion(
                    {
                        "login_attempts": 10,
                        "successful_logins": 9,
                        "failed_logins": 1,
                    },
                    compliance_score=90,
                ),
                "CC6.3_access_management": _criterion(
                    {
                        "api_key_events": 3,
                        "api_key_validation_failures": 0,
                    }
                ),
                "CC6.6_vulnerability_management": _criterion(
                    {
                        "security_scans_detected": 0,
                        "suspicious_activities": 0,
                        "brute_force_attempts": 0,
                    },
                    compliance_score=0,
                    status="MONITORING",
                ),
                "CC6.7_data_protection": _criterion(
                    {
                        "data_exports": 1,
                        "data_deletions": 0,
                        "bulk_operations": 0,
                    }
                ),
                "CC7.1_security_monitoring": _criterion(
                    {
                        "rate_limit_violations": 2,
                        "admin_actions": 4,
                    }
                ),
            },
            "overall_compliance": {
                "average_score": 97.5,
                "status": "COMPLIANT",
                "audit_log_coverage": "COMPREHENSIVE",
                "recommendations": [
                    "Maintain current access control monitoring",
                    "Continue comprehensive audit logging",
                ],
            },
        },
    }


def test_audit_log_response_schema_files_present() -> None:
    for schema_name in (
        "audit_log_entry_response_schema.json",
        "audit_log_list_response_schema.json",
        "audit_log_export_response_schema.json",
        "soc2_compliance_report_response_schema.json",
    ):
        assert (get_schemas_dir() / "audit" / schema_name).exists()


def test_audit_endpoints_reference_log_and_compliance_schemas() -> None:
    with open(get_schemas_dir() / "audit" / "audit_endpoints.json", encoding="utf-8") as handle:
        spec = json.load(handle)

    paths = spec["paths"]
    assert "default" not in paths["/api/v1/audit/logs"]["get"]["responses"]
    assert "default" not in paths["/api/v1/audit/logs/export"]["post"]["responses"]
    assert "default" not in paths["/api/v1/audit/logs/{log_id}"]["get"]["responses"]
    assert "default" not in paths["/api/v1/audit/soc2/compliance-report"]["get"]["responses"]

    assert (
        paths["/api/v1/audit/logs"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "./audit_log_list_response_schema.json"
    )
    assert (
        paths["/api/v1/audit/logs/{log_id}"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "./audit_log_entry_response_schema.json"
    )
    assert (
        paths["/api/v1/audit/logs/export"]["post"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "./audit_log_export_response_schema.json"
    )
    assert (
        paths["/api/v1/audit/soc2/compliance-report"]["get"]["responses"]["200"][
            "content"
        ]["application/json"]["schema"]["$ref"]
        == "./soc2_compliance_report_response_schema.json"
    )
    assert (
        paths["/api/v1/audit/logs/export"]["post"]["responses"]["200"]["content"][
            "text/csv"
        ]["schema"]["type"]
        == "string"
    )


def test_audit_log_list_payload_validates() -> None:
    validator = SchemaValidator()

    errors = validator.validate_json(
        _audit_log_list_payload(),
        "audit_log_list_response_schema",
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_audit_log_list_missing_pagination_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_audit_log_list_payload())
    bad["data"].pop("pagination")

    errors = validator.validate_json(bad, "audit_log_list_response_schema")

    assert any("pagination" in error for error in errors), errors


def test_audit_log_entry_payload_validates() -> None:
    validator = SchemaValidator()

    errors = validator.validate_json(
        _audit_log_detail_payload(),
        "audit_log_entry_response_schema",
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_audit_log_entry_missing_backend_field_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_audit_log_detail_payload())
    bad["data"].pop("checksum")

    errors = validator.validate_json(bad, "audit_log_entry_response_schema")

    assert any("checksum" in error for error in errors), errors


def test_audit_log_export_payload_validates() -> None:
    validator = SchemaValidator()

    errors = validator.validate_json(
        _audit_log_export_payload(),
        "audit_log_export_response_schema",
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_audit_log_export_missing_count_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_audit_log_export_payload())
    bad["data"].pop("total_exported")

    errors = validator.validate_json(bad, "audit_log_export_response_schema")

    assert any("total_exported" in error for error in errors), errors


def test_soc2_compliance_payload_validates() -> None:
    validator = SchemaValidator()

    errors = validator.validate_json(
        _soc2_compliance_payload(),
        "soc2_compliance_report_response_schema",
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_soc2_compliance_missing_trust_criterion_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_soc2_compliance_payload())
    bad["data"]["trust_service_criteria"].pop("CC7.1_security_monitoring")

    errors = validator.validate_json(bad, "soc2_compliance_report_response_schema")

    assert any("CC7.1_security_monitoring" in error for error in errors), errors


def test_soc2_compliance_missing_overall_status_fails() -> None:
    validator = SchemaValidator()
    bad = deepcopy(_soc2_compliance_payload())
    bad["data"]["overall_compliance"].pop("status")

    errors = validator.validate_json(bad, "soc2_compliance_report_response_schema")

    assert any("status" in error for error in errors), errors
