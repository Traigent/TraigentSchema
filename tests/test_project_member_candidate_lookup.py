"""Pin GET /api/v1beta/projects/{project_id}/membership-candidates contract.

Closes TraigentSchema#46. The endpoint backs the FE project-membership picker
and replaces the raw user-id field used today; it is added to the *planned*
projects contract because the backend route does not exist yet. These tests
exist so a backend implementation cannot ship without matching the response
shape, query bounds, and error envelope the FE will compile against.
"""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

CANDIDATE_SCHEMA = "project_member_candidate_schema"
LIST_RESPONSE_SCHEMA = "project_member_candidate_list_response_schema"
ERROR_SCHEMA = "project_member_lookup_error_schema"


def _valid_candidate() -> dict[str, object]:
    return {
        "user_id": "user_abc",
        "tenant_id": "tenant_acme",
        "email": "ada@acme.example",
        "display_name": "Ada Lovelace",
        "status": "active",
        "is_existing_member": False,
        "existing_role": None,
    }


def _valid_list_response() -> dict[str, object]:
    return {
        "items": [
            _valid_candidate(),
            {
                **_valid_candidate(),
                "user_id": "user_xyz",
                "email": "grace@acme.example",
                "display_name": None,
                "is_existing_member": True,
                "existing_role": "editor",
            },
        ],
        "pagination": {
            "page": 1,
            "per_page": 20,
            "total": 2,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        },
        "query": {
            "q": "ada",
            "email": None,
            "exclude_existing_members": False,
        },
    }


def test_candidate_schema_files_exist() -> None:
    projects_dir = get_schemas_dir() / "projects"
    for filename in (
        "project_member_candidate_schema.json",
        "project_member_candidate_list_response_schema.json",
        "project_member_lookup_error_schema.json",
    ):
        assert (projects_dir / filename).exists(), filename


def test_candidate_schema_loads_and_pins_privacy_classification() -> None:
    path = (
        get_schemas_dir()
        / "projects"
        / "project_member_candidate_schema.json"
    )
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)

    assert payload["x-privacy-classification"] == "tenant_admin_safe"
    assert payload["x-required-permission"] == "project:membership:manage"
    required = set(payload["required"])
    assert {
        "user_id",
        "tenant_id",
        "email",
        "status",
        "is_existing_member",
        "existing_role",
    }.issubset(required)


def test_valid_candidate_payload_validates() -> None:
    validator = SchemaValidator(contract="planned_projects")
    errors = validator.validate_json(_valid_candidate(), CANDIDATE_SCHEMA)
    assert errors == [], errors


def test_valid_list_response_validates() -> None:
    validator = SchemaValidator(contract="planned_projects")
    errors = validator.validate_json(_valid_list_response(), LIST_RESPONSE_SCHEMA)
    assert errors == [], errors


def test_empty_items_is_valid_200_payload() -> None:
    """Empty items[] is the FE's 'no match' signal; it MUST validate."""
    validator = SchemaValidator(contract="planned_projects")
    payload = _valid_list_response()
    payload["items"] = []
    payload["pagination"]["total"] = 0
    payload["pagination"]["total_pages"] = 0
    errors = validator.validate_json(payload, LIST_RESPONSE_SCHEMA)
    assert errors == [], errors


def test_candidate_rejects_unknown_fields() -> None:
    """additionalProperties=false guards against PII leakage via drift."""
    validator = SchemaValidator(contract="planned_projects")
    payload = _valid_candidate()
    payload["phone_number"] = "+1-555-0100"
    errors = validator.validate_json(payload, CANDIDATE_SCHEMA)
    assert any("phone_number" in error for error in errors), errors


def test_candidate_rejects_invalid_email() -> None:
    validator = SchemaValidator(contract="planned_projects")
    payload = _valid_candidate()
    payload["email"] = "not-an-email"
    errors = validator.validate_json(payload, CANDIDATE_SCHEMA)
    assert any("email" in error for error in errors), errors


def test_existing_role_must_be_in_enum_or_null() -> None:
    validator = SchemaValidator(contract="planned_projects")
    payload = _valid_candidate()
    payload["existing_role"] = "owner"  # not in {admin, editor, viewer, null}
    errors = validator.validate_json(payload, CANDIDATE_SCHEMA)
    assert any("existing_role" in error or "enum" in error for error in errors), errors


def test_list_response_per_page_cap() -> None:
    """items[] is capped at 50 to match the per_page server-side cap."""
    validator = SchemaValidator(contract="planned_projects")
    payload = _valid_list_response()
    payload["items"] = [
        {**_valid_candidate(), "user_id": f"user_{idx}", "email": f"u{idx}@acme.example"}
        for idx in range(51)
    ]
    errors = validator.validate_json(payload, LIST_RESPONSE_SCHEMA)
    assert any("maxItems" in error or "too long" in error for error in errors), errors


def test_error_envelope_pins_inline_fe_codes() -> None:
    validator = SchemaValidator(contract="planned_projects")
    for code in (
        "PROJECT_CONTEXT_REQUIRED",
        "PROJECT_NOT_FOUND",
        "PROJECT_ACCESS_DENIED",
        "INSUFFICIENT_PERMISSIONS",
        "INVALID_LOOKUP_QUERY",
        "USER_NOT_FOUND",
    ):
        payload = {"error_code": code, "message": "denied"}
        errors = validator.validate_json(payload, ERROR_SCHEMA)
        assert errors == [], f"{code}: {errors}"


def test_error_envelope_rejects_unknown_code() -> None:
    """FE switches on error_code; an unknown code is a contract bug, not a 500."""
    validator = SchemaValidator(contract="planned_projects")
    payload = {"error_code": "WHO_KNOWS", "message": "nope"}
    errors = validator.validate_json(payload, ERROR_SCHEMA)
    assert any("error_code" in error or "enum" in error for error in errors), errors


def test_error_envelope_rejects_user_input_echo() -> None:
    """The envelope MUST NOT contain user_id/email — that would enable cross-tenant probing."""
    validator = SchemaValidator(contract="planned_projects")
    for leaky_field in ("user_id", "email", "q"):
        payload = {
            "error_code": "PROJECT_ACCESS_DENIED",
            "message": "denied",
            leaky_field: "ada@acme.example",
        }
        errors = validator.validate_json(payload, ERROR_SCHEMA)
        assert any(leaky_field in error or "additional" in error.lower() for error in errors), (
            leaky_field,
            errors,
        )


def test_planned_contract_registers_membership_candidate_route() -> None:
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "planned_projects_endpoints.json", encoding="utf-8") as handle:
        spec = json.load(handle)

    path = spec["paths"]["/api/v1beta/projects/{project_id}/membership-candidates"]
    operation = path["get"]
    assert operation["operationId"] == "lookupProjectMembershipCandidates"
    assert operation["x-required-permission"] == "project:membership:manage"

    response_ok = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert response_ok.endswith("project_member_candidate_list_response_schema.json")

    for status in ("400", "403", "404"):
        ref = operation["responses"][status]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("project_member_lookup_error_schema.json"), status


def test_planned_contract_pins_query_bounds() -> None:
    """per_page MUST be capped at 50 and q MUST require >=2 chars to keep
    casual directory scraping bounded. These are part of the contract, not a
    backend implementation detail."""
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "planned_projects_endpoints.json", encoding="utf-8") as handle:
        spec = json.load(handle)

    parameters = spec["paths"][
        "/api/v1beta/projects/{project_id}/membership-candidates"
    ]["get"]["parameters"]
    by_name = {param["name"]: param for param in parameters}

    assert by_name["per_page"]["schema"]["maximum"] == 50
    assert by_name["q"]["schema"]["minLength"] == 2
    assert by_name["email"]["schema"]["format"] == "email"
    assert by_name["require_match"]["schema"]["default"] is False
    assert by_name["exclude_existing_members"]["schema"]["default"] is False


def test_canonical_backend_contract_does_not_register_route() -> None:
    """The endpoint is *planned*; it MUST NOT appear in the canonical backend
    surface until BE ships, per repo policy on fake endpoints."""
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "mep_endpoints.json", encoding="utf-8") as handle:
        spec = json.load(handle)

    assert (
        "/api/v1beta/projects/{project_id}/membership-candidates"
        not in spec.get("paths", {})
    )
