"""Contract tests for auth/platform role vocabulary disambiguation (TraigentSchema#179).

Three schema gaps closed:
  1. auth_me_response: is_admin annotated as authoritative platform-admin signal;
     role annotated as non-authoritative legacy label; onboarding_completed described.
  2. register_request: role field marked x-inert: true (backend always ignores it — AUTH-002).
  3. rbac_privilege_vocabulary: x-admin-disambiguation added to clarify platform admin
     (is_admin=true on /auth/me) vs project admin (project_membership.role=admin).
"""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schemas_dir

AUTH_ME_SCHEMA = "auth_me_response_schema"
REGISTER_REQUEST_SCHEMA = "register_request_schema"
RBAC_VOCABULARY_SCHEMA = "rbac_privilege_vocabulary_schema"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_me_payload(**data_overrides):
    data = {
        "id": "user_1",
        "email": "a@example.com",
        "is_admin": False,
        "role": "member",
        "onboarding_completed": True,
    }
    data.update(data_overrides)
    return {"success": True, "message": "Success", "data": data}


def _load_raw_schema(filename: str) -> dict:
    """Load a raw JSON schema file from the auth directory by filename stem."""
    schemas_dir = get_schemas_dir()
    path = schemas_dir / "auth" / f"{filename}.json"
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# 1. auth_me_response: is_admin is the authoritative platform-admin signal
# ---------------------------------------------------------------------------


def test_auth_me_response_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(AUTH_ME_SCHEMA))


def test_auth_me_response_has_is_admin_property() -> None:
    """is_admin must be present as a boolean property in data."""
    schema = _load_raw_schema("auth_me_response_schema")
    data_props = schema["properties"]["data"]["properties"]
    assert "is_admin" in data_props, "auth_me_response.data must define is_admin"
    assert data_props["is_admin"]["type"] == "boolean"


def test_auth_me_is_admin_carries_authoritative_signal_annotation() -> None:
    """is_admin must carry x-authoritative-signal to document it as the canonical gate."""
    schema = _load_raw_schema("auth_me_response_schema")
    is_admin_prop = schema["properties"]["data"]["properties"]["is_admin"]
    assert "x-authoritative-signal" in is_admin_prop, (
        "is_admin must have x-authoritative-signal annotation (platform-admin gate)"
    )
    assert is_admin_prop["x-authoritative-signal"] == "is_admin"


def test_auth_me_role_is_string_or_null_not_conflicting_enum() -> None:
    """role must be [string, null] — must NOT include 'admin' in an enum that
    would conflict with is_admin's authoritative-signal semantics."""
    schema = _load_raw_schema("auth_me_response_schema")
    role_prop = schema["properties"]["data"]["properties"]["role"]
    assert role_prop["type"] == ["string", "null"], (
        "auth_me_response.data.role must be type [string, null]"
    )
    # Must not have an enum that includes 'admin' — that would re-introduce the overload
    enum = role_prop.get("enum")
    if enum is not None:
        assert "admin" not in enum, (
            "auth_me_response.data.role must not include 'admin' in enum — "
            "platform-admin is signalled by is_admin, not role"
        )


def test_auth_me_role_has_non_authoritative_description() -> None:
    """role.description must call out that is_admin is the authoritative signal."""
    schema = _load_raw_schema("auth_me_response_schema")
    role_prop = schema["properties"]["data"]["properties"]["role"]
    desc = role_prop.get("description", "")
    assert "is_admin" in desc, (
        "auth_me_response.role description must reference is_admin as the authoritative signal"
    )


def test_auth_me_onboarding_completed_has_description() -> None:
    """onboarding_completed must carry a description explaining when it is set/cleared."""
    schema = _load_raw_schema("auth_me_response_schema")
    onboarding_prop = schema["properties"]["data"]["properties"]["onboarding_completed"]
    desc = onboarding_prop.get("description", "")
    assert desc, "auth_me_response.onboarding_completed must have a description"
    # Description should mention both set-true and set-false lifecycle events
    assert "False" in desc or "false" in desc, (
        "onboarding_completed description must explain when it is set to False (at register)"
    )
    assert "True" in desc or "true" in desc, (
        "onboarding_completed description must explain when it is set to True"
    )


def test_auth_me_accepts_is_admin_true() -> None:
    """A payload with is_admin=True (platform admin) must validate."""
    v = SchemaValidator()
    payload = _auth_me_payload(is_admin=True, role="developer")
    assert v.validate_json(payload, AUTH_ME_SCHEMA) == []


def test_auth_me_accepts_null_role_for_sso_users() -> None:
    """role may be null — SSO-provisioned users may lack a legacy label."""
    v = SchemaValidator()
    payload = _auth_me_payload(role=None)
    assert v.validate_json(payload, AUTH_ME_SCHEMA) == []


def test_auth_me_accepts_member_role() -> None:
    v = SchemaValidator()
    assert v.validate_json(_auth_me_payload(role="member"), AUTH_ME_SCHEMA) == []


def test_auth_me_accepts_developer_role() -> None:
    v = SchemaValidator()
    assert v.validate_json(_auth_me_payload(role="developer"), AUTH_ME_SCHEMA) == []


# ---------------------------------------------------------------------------
# 2. register_request: role field is x-inert (backend ignores it — AUTH-002)
# ---------------------------------------------------------------------------


def test_register_request_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(REGISTER_REQUEST_SCHEMA))


def test_register_request_role_has_x_inert_annotation() -> None:
    """register_request.role must carry x-inert: true to document AUTH-002."""
    schema = _load_raw_schema("register_request_schema")
    role_prop = schema["properties"]["role"]
    assert role_prop.get("x-inert") is True, (
        "register_request.role must have x-inert: true — backend always assigns "
        "the server-side default role (AUTH-002)"
    )


def test_register_request_role_description_references_auth_002() -> None:
    """Description must mention AUTH-002 (or server-side default) so consumers know."""
    schema = _load_raw_schema("register_request_schema")
    desc = schema["properties"]["role"].get("description", "")
    assert "AUTH-002" in desc or "server-side default" in desc.lower() or "always assigns" in desc.lower(), (
        "register_request.role description must document that backend always assigns "
        "the server-side default (AUTH-002)"
    )


def test_register_request_role_not_required() -> None:
    """role must remain optional — omitting it is the recommended client behaviour."""
    schema = _load_raw_schema("register_request_schema")
    required = schema.get("required", [])
    assert "role" not in required, "register_request.role must not be required"


def test_register_request_still_validates_without_role() -> None:
    v = SchemaValidator()
    payload = {"email": "new@example.com", "password": "s3cr3t!"}
    assert v.validate_json(payload, REGISTER_REQUEST_SCHEMA) == []


def test_register_request_accepts_role_field_when_provided() -> None:
    """Schema should still accept role if client sends it (not enum-constrained yet)."""
    v = SchemaValidator()
    payload = {"email": "new@example.com", "password": "s3cr3t!", "role": "developer"}
    assert v.validate_json(payload, REGISTER_REQUEST_SCHEMA) == []


# ---------------------------------------------------------------------------
# 3. rbac_privilege_vocabulary: x-admin-disambiguation clarifies overloaded token
# ---------------------------------------------------------------------------


def test_rbac_vocabulary_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(load_schema(RBAC_VOCABULARY_SCHEMA))


def test_rbac_vocabulary_has_x_admin_disambiguation() -> None:
    """x-admin-disambiguation must be present at the top level of the vocabulary schema."""
    schema = _load_raw_schema("rbac_privilege_vocabulary_schema")
    assert "x-admin-disambiguation" in schema, (
        "rbac_privilege_vocabulary must have x-admin-disambiguation to resolve the "
        "admin token overload (platform admin vs project admin)"
    )


def test_rbac_x_admin_disambiguation_has_platform_key() -> None:
    """platform entry must reference is_admin on auth/me."""
    schema = _load_raw_schema("rbac_privilege_vocabulary_schema")
    disambiguation = schema["x-admin-disambiguation"]
    assert "platform" in disambiguation, (
        "x-admin-disambiguation must have a 'platform' key"
    )
    platform_desc = disambiguation["platform"]
    assert "is_admin" in platform_desc, (
        "platform entry must reference is_admin (the authoritative auth/me signal)"
    )


def test_rbac_x_admin_disambiguation_has_project_key() -> None:
    """project entry must reference project_membership.role."""
    schema = _load_raw_schema("rbac_privilege_vocabulary_schema")
    disambiguation = schema["x-admin-disambiguation"]
    assert "project" in disambiguation, (
        "x-admin-disambiguation must have a 'project' key"
    )
    project_desc = disambiguation["project"]
    assert "project_membership" in project_desc or "project-scoped" in project_desc.lower(), (
        "project entry must reference project_membership to distinguish project-admin "
        "from platform-admin"
    )


def test_rbac_admin_privilege_role_description_mentions_is_admin() -> None:
    """The admin privilege-role description must call out is_admin as the signal."""
    schema = _load_raw_schema("rbac_privilege_vocabulary_schema")
    admin_desc = schema["x-privilege-roles"]["admin"]["description"]
    assert "is_admin" in admin_desc, (
        "rbac admin privilege-role description must mention is_admin "
        "to disambiguate from project_membership.role=admin"
    )


def test_rbac_admin_privilege_role_mentions_project_membership_distinction() -> None:
    """The admin description must distinguish platform-admin from project-admin."""
    schema = _load_raw_schema("rbac_privilege_vocabulary_schema")
    admin_desc = schema["x-privilege-roles"]["admin"]["description"]
    assert "project_membership" in admin_desc or "project-scoped" in admin_desc.lower(), (
        "rbac admin privilege-role description must distinguish platform admin "
        "from project_membership.role=admin"
    )
