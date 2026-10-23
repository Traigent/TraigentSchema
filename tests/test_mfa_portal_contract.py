"""Portal MFA flow contract (setup secret, login 403/429 bodies, step-up, admin reset).

Pins the contract the portal's MFA screens depend on. Bodies mirror what
TraigentBackend emits (src/routes/mfa_routes.py, auth_routes.py, admin_routes.py).
"""

import json

import jsonschema
import pytest

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _load(rel):
    return json.loads((S / rel).read_text(encoding="utf-8"))


def _validator(rel):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in S.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = "https://schemas.traigent.ai/" + path.relative_to(S).as_posix()
        registry = registry.with_resource(
            uri, Resource.from_contents(doc, default_specification=DRAFT7)
        )
    return jsonschema.Draft7Validator(_load(rel), registry=registry), rel


SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
URI = f"otpauth://totp/Traigent:user%40example.test?secret={SECRET}&issuer=Traigent"


def _ok(rel, body):
    v, _ = _validator(rel)
    errors = list(v.iter_errors(body))
    assert not errors, [e.message for e in errors]


def _bad(rel, body):
    v, _ = _validator(rel)
    assert list(v.iter_errors(body))


def test_setup_response_carries_secret_and_otpauth_uri():
    good = {
        "success": True,
        "data": {"setup_token": "t", "message": "m", "secret": SECRET, "otpauth_uri": URI},
    }
    _ok("mfa/mfa_setup_response_schema.json", good)
    for missing in ("secret", "otpauth_uri", "setup_token", "message"):
        bad = json.loads(json.dumps(good))
        del bad["data"][missing]
        _bad("mfa/mfa_setup_response_schema.json", bad)
    wrong = json.loads(json.dumps(good))
    wrong["data"]["otpauth_uri"] = "https://example.test/"
    _bad("mfa/mfa_setup_response_schema.json", wrong)


def test_setup_op_declares_typed_200_and_no_default_on_mfa_ops():
    cat = _load("mfa/mfa_endpoints.json")
    for path, methods in cat["paths"].items():
        for method, op in methods.items():
            assert "default" not in op["responses"], f"{method} {path} still has default"
            assert "200" in op["responses"], f"{method} {path} has no 200"
    ref = cat["paths"]["/api/v1/mfa/setup"]["post"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    assert ref == "./mfa_setup_response_schema.json"
    qr = cat["paths"]["/api/v1/mfa/setup/qr"]["get"]["responses"]["200"]["content"]
    assert "image/png" in qr


@pytest.mark.parametrize(
    "path,method", [("/api/v1/mfa/backup-codes", "get"), ("/api/v1/mfa/disable", "delete")]
)
def test_step_up_header_and_errors_documented(path, method):
    op = _load("mfa/mfa_endpoints.json")["paths"][path][method]
    assert any(p["name"] == "X-MFA-Code" and p["in"] == "header" for p in op["parameters"])
    for status, code in (("400", "MFA_STEP_UP_REQUIRED"), ("401", "MFA_STEP_UP_INVALID")):
        ref = op["responses"][status]["content"]["application/json"]["schema"]["$ref"]
        assert ref == "./mfa_step_up_error_schema.json"
        enum = _load("mfa/mfa_step_up_error_schema.json")["allOf"][1]["properties"]["error_code"][
            "enum"
        ]
        assert code in enum
    _ok("mfa/mfa_step_up_request_schema.json", {"code": "123456"})
    _bad("mfa/mfa_step_up_request_schema.json", {})


def test_login_403_bodies_and_mfa_token():
    rel = "auth/login_mfa_response_schema.json"
    _ok(
        rel,
        {
            "success": False,
            "mfa_setup_required": True,
            "user_id": "u",
            "access_token": "a",
            "message": "m",
        },
    )
    _ok(
        rel,
        {
            "success": False,
            "error": "MFA verification required",
            "mfa_required": True,
            "user_id": "u",
        },
    )
    _bad(rel, {"success": False, "mfa_required": True, "user_id": "u", "extra": 1})
    login = _load("auth/auth_endpoints.json")["paths"]["/api/v1/auth/login"]["post"]["responses"]
    assert (
        login["403"]["content"]["application/json"]["schema"]["$ref"]
        == "./login_mfa_response_schema.json"
    )
    assert "mfa_token" in _load("auth/login_request_schema.json")["properties"]


def test_mfa_rate_limited_is_distinct_429():
    rel = "mfa/mfa_rate_limited_response_schema.json"
    body = {
        "success": False,
        "message": "Too many MFA attempts",
        "error": "Too many requests",
        "error_code": "MFA_RATE_LIMITED",
        "details": {"scope": "mfa_login", "retry_after": 120},
    }
    _ok(rel, body)
    generic = dict(body, error_code="RATE_LIMIT_EXCEEDED")
    _bad(rel, generic)
    r429 = _load("auth/auth_endpoints.json")["paths"]["/api/v1/auth/login"]["post"]["responses"][
        "429"
    ]
    refs = [o["$ref"] for o in r429["content"]["application/json"]["schema"]["oneOf"]]
    assert "../mfa/mfa_rate_limited_response_schema.json" in refs


def test_admin_reset_op():
    cat = _load("mfa/mfa_endpoints.json")
    op = cat["paths"]["/api/v1/admin/users/{user_id}/mfa/reset"]["post"]
    assert op["parameters"][0]["name"] == "user_id" and op["parameters"][0]["in"] == "path"
    assert op["requestBody"]["required"] is True
    _ok("mfa/mfa_admin_reset_request_schema.json", {"reason": "lost device and recovery codes"})
    _bad("mfa/mfa_admin_reset_request_schema.json", {})
    _bad("mfa/mfa_admin_reset_request_schema.json", {"reason": "x" * 501})
    _ok("mfa/mfa_admin_reset_response_schema.json", {"success": True, "data": {"ok": True}})
    for status in ("403", "404", "503"):
        assert status in op["responses"]
