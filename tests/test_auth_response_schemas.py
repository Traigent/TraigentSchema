"""Contract tests for auth response DTOs + CSRF endpoint (TraigentSchema#58, #62).

Shapes mirror the backend ground truth (TraigentBackend develop, auth_routes.py):
the {success, message, data} envelope; session expiry is carried by the
X-Session-Expires-At header, NOT in the login/refresh body.
"""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _login(**data_overrides):
    data = {
        "access_token": "eyJ.jwt.token",
        "refresh_token": "refresh-abc",
        "user": {"id": "u1", "email": "a@example.com", "role": "member"},
        "mfa_enabled": False,
    }
    data.update(data_overrides)
    return {"success": True, "message": "Login successful", "data": data}


# --- LoginResponseDTO ------------------------------------------------------


def test_login_accepts_full_and_minimal():
    v = SchemaValidator()
    assert v.validate_json(_login(), "login_response_schema") == []
    minimal = {
        "success": True,
        "message": "ok",
        "data": {"access_token": "a", "refresh_token": "r"},
    }
    assert v.validate_json(minimal, "login_response_schema") == []


def test_login_allows_null_user():
    v = SchemaValidator()
    assert v.validate_json(_login(user=None), "login_response_schema") == []


def test_login_requires_tokens():
    v = SchemaValidator()
    for missing in ("access_token", "refresh_token"):
        data = {"access_token": "a", "refresh_token": "r"}
        del data[missing]
        payload = {"success": True, "message": "ok", "data": data}
        assert v.validate_json(payload, "login_response_schema"), missing


def test_login_body_rejects_session_expiry_field():
    """Session expiry is the X-Session-Expires-At header, not a body field —
    the contract must reject it in the body to prevent drift."""
    v = SchemaValidator()
    assert v.validate_json(_login(expires_at="2026-06-02T12:00:00Z"), "login_response_schema")
    assert v.validate_json(_login(expires_in=3600), "login_response_schema")


def test_login_rejects_unknown_top_level():
    v = SchemaValidator()
    payload = _login()
    payload["token"] = "leak"
    assert v.validate_json(payload, "login_response_schema")


# --- AuthMeResponseDTO -----------------------------------------------------


def test_auth_me_accepts_session_expiry_alias():
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Success",
        "data": {
            "id": "user_1",
            "email": "a@example.com",
            "name": "A User",
            "display_name": "A User",
            "is_admin": False,
            "subscription_tier": "pro",
            "email_verified": True,
            "team_id": "team_1",
            "role": "member",
            "onboarding_completed": True,
            "expires_at": "2026-06-02T12:00:00Z",
            "_source": "claims",
        },
    }

    assert v.validate_json(payload, "auth_me_response_schema") == []


def test_auth_me_allows_db_fallback_without_session_expiry():
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Success",
        "data": {
            "id": "user_1",
            "email": "a@example.com",
            "settings": {"theme": "dark"},
        },
    }

    assert v.validate_json(payload, "auth_me_response_schema") == []


def test_auth_me_rejects_unknown_top_level():
    v = SchemaValidator()
    payload = {"success": True, "message": "Success", "data": {}, "expires_at": "leak"}
    assert v.validate_json(payload, "auth_me_response_schema")


# --- TokenRefreshResponseDTO ----------------------------------------------


def test_refresh_accepts_rotated_tokens():
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Token refreshed",
        "data": {"access_token": "new", "refresh_token": "rotated"},
    }
    assert v.validate_json(payload, "token_refresh_response_schema") == []


def test_refresh_requires_tokens():
    v = SchemaValidator()
    payload = {"success": True, "message": "ok", "data": {"access_token": "a"}}
    assert v.validate_json(payload, "token_refresh_response_schema")


# --- CSRF token response ---------------------------------------------------


def test_csrf_accepts_token():
    v = SchemaValidator()
    payload = {"success": True, "message": "CSRF token refreshed", "data": {"csrf_token": "tok"}}
    assert v.validate_json(payload, "csrf_token_response_schema") == []


def test_csrf_requires_token():
    v = SchemaValidator()
    payload = {"success": True, "message": "x", "data": {}}
    assert v.validate_json(payload, "csrf_token_response_schema")


# --- endpoint wiring -------------------------------------------------------


def test_auth_endpoints_wire_the_new_dtos():
    with open(get_schemas_dir() / "auth" / "auth_endpoints.json", encoding="utf-8") as fh:
        spec = json.load(fh)
    paths = spec["paths"]

    auth_me = paths["/api/v1/auth/me"]["get"]["responses"]
    assert auth_me["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "auth_me_response_schema.json"
    )
    for code in ("401", "404", "500"):
        assert auth_me[code]["content"]["application/json"]["schema"]["$ref"].endswith(
            "error_envelope_schema.json"
        )

    login = paths["/api/v1/auth/login"]["post"]["responses"]["200"]
    assert login["content"]["application/json"]["schema"]["$ref"].endswith(
        "login_response_schema.json"
    )
    assert "X-Session-Expires-At" in login["headers"]

    refresh = paths["/api/v1/auth/refresh"]["post"]["responses"]["200"]
    assert refresh["content"]["application/json"]["schema"]["$ref"].endswith(
        "token_refresh_response_schema.json"
    )
    assert "X-Session-Expires-At" in refresh["headers"]

    csrf = paths["/api/v1/auth/csrf-token"]["get"]["responses"]
    assert csrf["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "csrf_token_response_schema.json"
    )
    for code in ("401", "403"):
        assert csrf[code]["content"]["application/json"]["schema"]["$ref"].endswith(
            "error_envelope_schema.json"
        )
