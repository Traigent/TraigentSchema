"""Contract tests for auth onboarding / identity gaps (TraigentSchema#178).

Three gaps closed:
  1. POST /auth/register 200 response schema (register_response_schema.json).
  2. Shared auth user identity shape (auth_user_identity_schema.json) wired into
     login / token-refresh / SSO-callback user fields.
  3. auth_me.data requires id + email (no longer zero required fields).
  4. provisioned_workspace_schema.json was deleted (orphaned, conflicting field
     default_project_id vs device_token_success_schema.json's project_id).
"""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schemas_dir

REGISTER_RESPONSE = "register_response_schema"
AUTH_USER_IDENTITY = "auth_user_identity_schema"


# ---------------------------------------------------------------------------
# 1. register_response_schema
# ---------------------------------------------------------------------------


def test_register_response_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(REGISTER_RESPONSE))


def test_register_response_accepts_full_payload() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Registration successful. Please verify your email.",
        "user": {
            "id": "user_abc123",
            "email": "alice@example.com",
            "email_verified": False,
            "onboarding_completed": False,
        },
        "requires_email_verification": True,
        "email_sent": True,
    }
    assert v.validate_json(payload, REGISTER_RESPONSE) == []


def test_register_response_accepts_minimal_payload() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Registration successful.",
        "user": {"id": "u1", "email": "a@b.com"},
        "requires_email_verification": True,
        "email_sent": True,
    }
    assert v.validate_json(payload, REGISTER_RESPONSE) == []


def test_register_response_requires_all_top_level_fields() -> None:
    v = SchemaValidator()
    base = {
        "success": True,
        "message": "ok",
        "user": {"id": "u1", "email": "a@b.com"},
        "requires_email_verification": True,
        "email_sent": True,
    }
    for field in ("success", "message", "user", "requires_email_verification", "email_sent"):
        payload = {k: val for k, val in base.items() if k != field}
        errors = v.validate_json(payload, REGISTER_RESPONSE)
        assert errors, f"register response should require '{field}'"


def test_register_response_rejects_unknown_top_level_fields() -> None:
    """additionalProperties: false — no extra top-level keys allowed."""
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "ok",
        "user": {"id": "u1", "email": "a@b.com"},
        "requires_email_verification": True,
        "email_sent": True,
        "access_token": "should-not-be-here",
    }
    assert v.validate_json(payload, REGISTER_RESPONSE), (
        "register response must not carry access_token at registration time"
    )


def test_register_response_user_requires_id_and_email() -> None:
    v = SchemaValidator()
    base_user = {"id": "u1", "email": "a@b.com"}
    for missing in ("id", "email"):
        user = {k: val for k, val in base_user.items() if k != missing}
        payload = {
            "success": True,
            "message": "ok",
            "user": user,
            "requires_email_verification": True,
            "email_sent": True,
        }
        assert v.validate_json(payload, REGISTER_RESPONSE), (
            f"register user must require '{missing}'"
        )


def test_register_response_is_wired_in_auth_endpoints() -> None:
    """The POST /auth/register 200 must reference register_response_schema.json."""
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "auth" / "auth_endpoints.json", encoding="utf-8") as fh:
        spec = json.load(fh)
    response_200 = spec["paths"]["/api/v1/auth/register"]["post"]["responses"]["200"]
    ref = response_200.get("content", {}).get("application/json", {}).get("schema", {}).get("$ref", "")
    assert ref.endswith("register_response_schema.json"), (
        f"POST /auth/register 200 must $ref register_response_schema.json; got: {ref!r}"
    )


def test_register_response_is_registered_by_runtime_discovery() -> None:
    assert REGISTER_RESPONSE in set(SchemaValidator().available_schemas)


# ---------------------------------------------------------------------------
# 2. auth_user_identity_schema (shared user identity sub-type)
# ---------------------------------------------------------------------------


def test_auth_user_identity_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(AUTH_USER_IDENTITY))


def test_auth_user_identity_accepts_minimum_required_fields() -> None:
    v = SchemaValidator()
    assert v.validate_json({"id": "u1", "email": "a@b.com"}, AUTH_USER_IDENTITY) == []


def test_auth_user_identity_accepts_optional_onboarding_fields() -> None:
    v = SchemaValidator()
    payload = {
        "id": "u1",
        "email": "a@b.com",
        "email_verified": False,
        "onboarding_completed": False,
    }
    assert v.validate_json(payload, AUTH_USER_IDENTITY) == []


def test_auth_user_identity_accepts_additional_claims() -> None:
    """additionalProperties: true — extra claims (name, role, org) are permitted."""
    v = SchemaValidator()
    payload = {
        "id": "u1",
        "email": "a@b.com",
        "name": "Alice",
        "role": "member",
        "organization": "ACME",
    }
    assert v.validate_json(payload, AUTH_USER_IDENTITY) == []


def test_auth_user_identity_allows_null() -> None:
    """The user field is typed [object, null] so null is valid (e.g. minimal login response)."""
    # The identity schema itself has type ["object", "null"] so null should be valid
    v = SchemaValidator()
    assert v.validate_json(None, AUTH_USER_IDENTITY) == []


def test_auth_user_identity_requires_id_and_email() -> None:
    v = SchemaValidator()
    for missing in ("id", "email"):
        payload = {"id": "u1", "email": "a@b.com"}
        del payload[missing]
        assert v.validate_json(payload, AUTH_USER_IDENTITY), (
            f"auth_user_identity must require '{missing}'"
        )


def test_auth_user_identity_is_registered_by_runtime_discovery() -> None:
    assert AUTH_USER_IDENTITY in set(SchemaValidator().available_schemas)


# ---------------------------------------------------------------------------
# 3. login / token-refresh / SSO-callback user fields are now pinned
# ---------------------------------------------------------------------------


def test_login_response_user_requires_id_and_email() -> None:
    """login_response_schema.user now uses auth_user_identity_schema (id+email required)."""
    v = SchemaValidator()
    # A non-null user without id must be rejected
    payload = {
        "success": True,
        "message": "ok",
        "data": {
            "access_token": "eyJ.tok",
            "refresh_token": "ref",
            "user": {"email": "a@b.com"},
        },
    }
    assert v.validate_json(payload, "login_response_schema"), (
        "login user without 'id' must fail"
    )
    # Add the id — should pass
    payload["data"]["user"]["id"] = "u1"
    assert v.validate_json(payload, "login_response_schema") == []


def test_token_refresh_response_user_requires_id_and_email() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "ok",
        "data": {
            "access_token": "eyJ.tok",
            "refresh_token": "ref",
            "user": {"id": "u1"},
        },
    }
    assert v.validate_json(payload, "token_refresh_response_schema"), (
        "token_refresh user without 'email' must fail"
    )
    payload["data"]["user"]["email"] = "a@b.com"
    assert v.validate_json(payload, "token_refresh_response_schema") == []


def test_sso_oidc_callback_response_user_requires_id_and_email() -> None:
    v = SchemaValidator()
    minimal_callback = {
        "success": True,
        "message": "ok",
        "data": {
            "access_token": "eyJ.tok",
            "refresh_token": "ref",
            "csrf_token": "csrf",
            "user": {"id": "u1"},
            "sso": {"provider": "oidc", "tenant_id": "t1", "tenant_slug": "acme"},
        },
    }
    assert v.validate_json(minimal_callback, "sso_oidc_callback_response_schema"), (
        "SSO callback user without 'email' must fail"
    )
    minimal_callback["data"]["user"]["email"] = "a@b.com"
    assert v.validate_json(minimal_callback, "sso_oidc_callback_response_schema") == []


# ---------------------------------------------------------------------------
# 4. auth_me.data requires id + email
# ---------------------------------------------------------------------------


def test_auth_me_data_requires_id() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "ok",
        "data": {"email": "a@b.com"},
    }
    assert v.validate_json(payload, "auth_me_response_schema"), (
        "auth_me data without 'id' must fail"
    )


def test_auth_me_data_requires_email() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "ok",
        "data": {"id": "u1"},
    }
    assert v.validate_json(payload, "auth_me_response_schema"), (
        "auth_me data without 'email' must fail"
    )


def test_auth_me_data_accepts_minimal_id_and_email() -> None:
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "ok",
        "data": {"id": "u1", "email": "a@b.com"},
    }
    assert v.validate_json(payload, "auth_me_response_schema") == []


# ---------------------------------------------------------------------------
# 5. provisioned_workspace_schema is removed (orphan with conflicting field name)
# ---------------------------------------------------------------------------


def test_provisioned_workspace_schema_is_removed() -> None:
    """provisioned_workspace_schema.json was deleted (TraigentSchema#178).
    The schema had default_project_id which conflicts with device_token_success_schema.json
    project_id and was never referenced by any endpoint. Workspace provisioning details
    are surfaced via the device-flow (project_id in device_token_success_schema.json)."""
    available = set(SchemaValidator().available_schemas)
    assert "provisioned_workspace_schema" not in available, (
        "provisioned_workspace_schema must be removed (orphan with conflicting field name)"
    )
