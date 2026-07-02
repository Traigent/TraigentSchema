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


def _oidc_sso_callback(**data_overrides):
    data = {
        "access_token": "eyJ.jwt.token",
        "refresh_token": "refresh-abc",
        "csrf_token": "csrf-abc",
        "user": {"id": "u1", "email": "alice@example.com", "role": "member"},
        "sso": {
            "provider": "oidc",
            "tenant_id": "tenant_123",
            "tenant_slug": "tenant-acme",
        },
    }
    data.update(data_overrides)
    return {"success": True, "message": "SSO login successful", "data": data}


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


def test_auth_me_response_email_rejects_invalid_format():
    """#223 — auth_me response email must carry format:email (enforced via FormatChecker)."""
    v = SchemaValidator()
    payload = {
        "success": True,
        "message": "Success",
        "data": {"id": "user_1", "email": "not-an-email"},
    }
    errors = v.validate_json(payload, "auth_me_response_schema")
    assert errors, "expected format:email rejection for 'not-an-email'"


def test_auth_me_response_email_rejects_oversized():
    """#223 — auth_me response email must be capped at maxLength:320."""
    v = SchemaValidator()
    long_email = "a" * 316 + "@b.co"  # 321 chars — one over the 320 cap
    payload = {
        "success": True,
        "message": "Success",
        "data": {"id": "user_1", "email": long_email},
    }
    errors = v.validate_json(payload, "auth_me_response_schema")
    assert errors, "expected maxLength:320 rejection"


def test_auth_me_response_email_field_has_format_and_maxlength():
    """#223 — schema structural guard: format:email + maxLength:320 on data.email."""
    from traigent_schema.utils import get_schemas_dir
    import json

    with open(get_schemas_dir() / "auth" / "auth_me_response_schema.json") as f:
        schema = json.load(f)
    email_field = schema["properties"]["data"]["properties"]["email"]
    assert email_field.get("format") == "email", "data.email must carry format:email"
    assert email_field.get("maxLength") == 320, "data.email must carry maxLength:320"


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


# --- OIDC SSO callback response -------------------------------------------


def test_oidc_sso_callback_accepts_token_response():
    v = SchemaValidator()
    assert v.validate_json(_oidc_sso_callback(), "sso_oidc_callback_response_schema") == []


def test_oidc_sso_callback_requires_sso_context():
    v = SchemaValidator()
    body = _oidc_sso_callback()
    del body["data"]["sso"]["tenant_slug"]
    assert v.validate_json(body, "sso_oidc_callback_response_schema")


def test_oidc_sso_callback_rejects_unknown_and_wrong_provider():
    v = SchemaValidator()
    leaky = _oidc_sso_callback()
    leaky["data"]["id_token"] = "raw-idp-token"
    assert v.validate_json(leaky, "sso_oidc_callback_response_schema")

    wrong_provider = _oidc_sso_callback(
        sso={"provider": "saml", "tenant_id": "tenant_123", "tenant_slug": "tenant-acme"}
    )
    assert v.validate_json(wrong_provider, "sso_oidc_callback_response_schema")


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


def test_auth_endpoints_wire_oidc_sso_contracts():
    with open(get_schemas_dir() / "auth" / "auth_endpoints.json", encoding="utf-8") as fh:
        spec = json.load(fh)
    paths = spec["paths"]

    login = paths["/api/v1/auth/sso/oidc/login"]["get"]
    login_params = {param["name"]: param for param in login["parameters"]}
    assert {"tenant_id", "tenant_slug", "return_to", "login_hint"} <= set(login_params)
    assert login["responses"]["302"]["headers"]["Location"]["schema"]["format"] == "uri"
    assert "Set-Cookie" in login["responses"]["302"]["headers"]
    for code in ("400", "404"):
        assert login["responses"][code]["content"]["application/json"]["schema"]["$ref"].endswith(
            "error_envelope_schema.json"
        )
    assert login["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "rate_limit_info_schema.json"
    )

    callback = paths["/api/v1/auth/sso/oidc/callback"]["get"]
    callback_params = {param["name"]: param for param in callback["parameters"]}
    assert {"code", "state", "error"} <= set(callback_params)
    assert callback["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("sso_oidc_callback_response_schema.json")
    assert "Location" in callback["responses"]["302"]["headers"]
    assert "X-Session-Expires-At" in callback["responses"]["200"]["headers"]
    assert "X-Session-Expires-At" in callback["responses"]["302"]["headers"]
    for code in ("400", "401", "403", "404", "500", "502"):
        assert callback["responses"][code]["content"]["application/json"]["schema"][
            "$ref"
        ].endswith("error_envelope_schema.json")
