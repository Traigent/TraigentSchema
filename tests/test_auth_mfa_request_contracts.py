"""#133: auth/MFA/audit-export write ops must declare a requestBody schema (or an
explicit bodyless marker), plus error-response contracts on the credential boundary.

The backend reads documented keys and ignores unknown ones (never 422s on extras),
so every request schema here is additionalProperties:true — the contract must not
reject a body the backend accepts.
"""
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()

# Non-secret placeholder values used only to exercise required-field validation.
SAMPLE = "sample-value"
SAMPLE_EMAIL = "user@example.test"

WRITE_METHODS = {"post", "put", "patch", "delete"}
# Routes that legitimately consume no body (cookie/session or server-generated).
BODYLESS = {
    ("/api/v1/auth/logout", "post"),
    ("/api/v1/mfa/setup", "post"),
    ("/api/v1/mfa/disable", "delete"),
}
WRITE_CATALOGS = ("auth/auth_endpoints.json", "mfa/mfa_endpoints.json")


def _catalog(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


def test_every_auth_mfa_write_op_declares_a_body_contract():
    for rel in WRITE_CATALOGS:
        cat = _catalog(rel)
        for path, methods in cat["paths"].items():
            for method, op in methods.items():
                if method.lower() not in WRITE_METHODS:
                    continue
                if (path, method.lower()) in BODYLESS:
                    assert "x-traigent-body" in op, f"{method} {path} bodyless but unmarked"
                    continue
                assert "requestBody" in op, f"{method.upper()} {path} declares no requestBody"
                ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
                assert ref.endswith("_request_schema.json"), f"{path} bad body ref: {ref}"


def test_audit_export_declares_request_body():
    cat = _catalog("audit/audit_endpoints.json")
    export = cat["paths"]["/api/v1/audit/logs/export"]["post"]
    assert "requestBody" in export
    assert export["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "audit_log_export_request_schema.json"
    )


def test_login_declares_401_and_request_schema():
    cat = _catalog("auth/auth_endpoints.json")
    login = cat["paths"]["/api/v1/auth/login"]["post"]
    assert "requestBody" in login
    assert "401" in login["responses"]
    assert login["responses"]["401"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "error_envelope_schema.json"
    )


def test_credential_routes_resolve_and_validate():
    v = SchemaValidator(contract="backend")
    # required fields enforced (was fail-open before)
    assert v.validate_request("/api/v1/auth/login", "POST", {})
    assert v.validate_request(
        "/api/v1/auth/login", "POST", {"email": SAMPLE_EMAIL, "password": SAMPLE}
    ) == []
    assert v.validate_request("/api/v1/mfa/verify", "POST", {})
    assert v.validate_request("/api/v1/mfa/verify", "POST", {"token": SAMPLE}) == []
    # missing required field still rejected
    assert v.validate_request("/api/v1/auth/reset-password", "POST", {"reset_token": SAMPLE})


def test_request_bodies_accept_unknown_keys_matching_backend():
    """The backend ignores unknown keys, so the contract must too (no false rejection)."""
    v = SchemaValidator(contract="backend")
    assert v.validate_request(
        "/api/v1/auth/login", "POST",
        {"email": SAMPLE_EMAIL, "password": SAMPLE, "remember_me": True},
    ) == []
    assert v.validate_request(
        "/api/v1/auth/reset-password", "POST",
        {"reset_token": SAMPLE, "new_password": SAMPLE, "client_only_field": 1},
    ) == []
    for rel in (
        "auth/login_request_schema.json", "auth/forgot_password_request_schema.json",
        "auth/reset_password_request_schema.json", "mfa/mfa_verify_request_schema.json",
        "mfa/mfa_recovery_request_schema.json",
    ):
        assert _catalog(rel)["additionalProperties"] is True, rel


def test_request_schemas_are_valid_and_typed():
    for rel in (
        "auth/login_request_schema.json", "auth/register_request_schema.json",
        "auth/forgot_password_request_schema.json", "auth/reset_password_request_schema.json",
        "mfa/mfa_verify_request_schema.json", "mfa/mfa_recovery_request_schema.json",
        "audit/audit_log_export_request_schema.json",
    ):
        spec = _catalog(rel)
        assert spec["type"] == "object"
        assert "properties" in spec and spec["properties"]
        assert spec["$id"].startswith("https://schemas.traigent.ai/")
