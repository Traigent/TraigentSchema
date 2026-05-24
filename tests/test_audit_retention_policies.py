"""Pin GET /api/v1/audit/retention-policies response shape.

Advances TraigentSchema#35 by covering the retention-policies endpoint with the
same canonical-vs-alias enforcement pattern used for security incidents. The
backend handler in TraigentBackend audit_routes.get_retention_policies emits
both `data` and `policies` lists referencing identical records; either side
dropping a field must be detectable here.
"""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA_NAME = "retention_policies_response_schema"


def _backend_payload() -> dict[str, object]:
    policies = [
        {
            "policy_id": "default_audit_policy",
            "name": "Default Audit Retention",
            "description": "Retention defaults applied to audit and security logs.",
            "retention_days": 365,
            "grace_period_days": 30,
            "applies_to": ["audit_logs", "security_events"],
            "status": "active",
            "enforced": True,
        }
    ]
    return {
        "success": True,
        "data": [dict(policy) for policy in policies],
        "policies": [dict(policy) for policy in policies],
    }


def test_retention_policies_schema_file_present() -> None:
    path = (
        get_schemas_dir() / "audit" / "retention_policies_response_schema.json"
    )
    assert path.exists()
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)
    assert "RetentionPolicy" in payload["definitions"]


def test_audit_endpoints_references_retention_policies_schema() -> None:
    path = get_schemas_dir() / "audit" / "audit_endpoints.json"
    with open(path, encoding="utf-8") as handle:
        spec = json.load(handle)

    response = spec["paths"]["/api/v1/audit/retention-policies"]["get"]["responses"]["200"]
    schema_ref = response["content"]["application/json"]["schema"]["$ref"]
    assert schema_ref.endswith("retention_policies_response_schema.json")


def test_backend_payload_validates() -> None:
    validator = SchemaValidator()
    errors = validator.validate_json(_backend_payload(), SCHEMA_NAME)
    assert errors == [], f"Expected clean validation, got: {errors}"


def test_payload_missing_policies_alias_fails() -> None:
    """Dropping the `policies` alias must trip the schema before FE drift ships."""
    validator = SchemaValidator()
    bad = _backend_payload()
    bad.pop("policies")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("policies" in error for error in errors), errors


def test_payload_missing_required_policy_field_fails() -> None:
    """Each policy record must surface all canonical fields the dashboard reads."""
    validator = SchemaValidator()
    bad = _backend_payload()
    bad["data"][0].pop("retention_days")
    errors = validator.validate_json(bad, SCHEMA_NAME)
    assert any("retention_days" in error for error in errors), errors
