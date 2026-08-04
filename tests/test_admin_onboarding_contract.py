"""#180: admin-onboarding contract governance.

Three gaps closed by this commit:
1. POST /api/v1/keys (create API key) was unmodeled — now in auth/keys_endpoints.json
   and wired into the canonical mep_endpoints.json module list.
2. Project/membership provisioning write routes in planned_projects_endpoints.json
   lacked 403 (Forbidden) responses.
3. planned_projects_endpoints.json was not annotated as pre-release / not backend-asserted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
KEYS_ENDPOINTS = SCHEMAS / "auth" / "keys_endpoints.json"
PLANNED_PROJECTS = SCHEMAS / "planned_projects_endpoints.json"
MEP_ENDPOINTS = SCHEMAS / "mep_endpoints.json"
ERROR_ENVELOPE_REF = "./error_envelope_schema.json"
AUTH_ERROR_ENVELOPE_REF = "../error_envelope_schema.json"

# Write HTTP methods whose response contracts must include 403.
WRITE_METHODS = {"post", "put", "patch", "delete"}


def _load(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Step 1: POST /api/v1/keys is modeled
# ---------------------------------------------------------------------------


def test_keys_endpoints_file_exists() -> None:
    assert KEYS_ENDPOINTS.exists(), (
        "auth/keys_endpoints.json does not exist; POST /api/v1/keys must be modeled"
    )


def test_api_keys_post_endpoint_modeled() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    paths = catalog.get("paths", {})
    assert "/api/v1/keys" in paths, (
        "POST /api/v1/keys is absent from auth/keys_endpoints.json"
    )
    assert "post" in paths["/api/v1/keys"], (
        "POST method not declared on /api/v1/keys"
    )


def test_api_keys_post_has_request_body() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    post_op = catalog["paths"]["/api/v1/keys"]["post"]
    assert "requestBody" in post_op, "POST /api/v1/keys must declare a requestBody"
    schema_ref = (
        post_op["requestBody"]
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
        .get("$ref", "")
    )
    assert schema_ref, "POST /api/v1/keys requestBody must reference a schema via $ref"


def test_api_keys_post_has_201() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    responses = catalog["paths"]["/api/v1/keys"]["post"].get("responses", {})
    assert "201" in responses, "POST /api/v1/keys must declare a 201 Created response"


def test_api_keys_post_has_403() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    responses = catalog["paths"]["/api/v1/keys"]["post"].get("responses", {})
    assert "403" in responses, (
        "POST /api/v1/keys must declare a 403 Forbidden response — "
        "only project members or admins may create project-scoped keys"
    )


def test_api_keys_post_has_401_and_409() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    responses = catalog["paths"]["/api/v1/keys"]["post"].get("responses", {})
    assert "401" in responses, "POST /api/v1/keys must declare a 401 Unauthorized response"
    assert "409" in responses, "POST /api/v1/keys must declare a 409 Conflict response"


def test_api_keys_post_error_responses_ref_envelope() -> None:
    catalog = _load(KEYS_ENDPOINTS)
    responses = catalog["paths"]["/api/v1/keys"]["post"].get("responses", {})
    for code, response in responses.items():
        if code[0] in {"4", "5"} and code != "429":
            if response.get("$ref", "").startswith("#/components/responses/"):
                continue
            ref = (
                response.get("content", {})
                .get("application/json", {})
                .get("schema", {})
                .get("$ref", "")
            )
            assert ref == AUTH_ERROR_ENVELOPE_REF, (
                f"POST /api/v1/keys response {code} must $ref the canonical error envelope, "
                f"got {ref!r}"
            )


def test_keys_endpoints_wired_into_mep() -> None:
    mep = _load(MEP_ENDPOINTS)
    paths_files = [m.get("paths_file", "") for m in mep.get("x-endpoint-modules", [])]
    assert any("keys_endpoints.json" in pf for pf in paths_files), (
        "keys_endpoints.json is not wired into mep_endpoints.json x-endpoint-modules; "
        "SchemaValidator will never load it"
    )


# ---------------------------------------------------------------------------
# Step 2: Write routes in planned_projects have 403
# ---------------------------------------------------------------------------


def _write_routes_missing_403(catalog: dict) -> list[str]:
    """Return list of 'METHOD /path' write routes missing a 403 response."""
    missing = []
    for path, methods in catalog.get("paths", {}).items():
        for method, op in methods.items():
            if method.lower() not in WRITE_METHODS:
                continue
            responses = op.get("responses", {})
            if "403" not in responses:
                missing.append(f"{method.upper()} {path}")
    return missing


def test_planned_projects_write_routes_have_403() -> None:
    catalog = _load(PLANNED_PROJECTS)
    missing = _write_routes_missing_403(catalog)
    assert not missing, (
        f"The following write routes in planned_projects_endpoints.json are missing "
        f"403 Forbidden responses: {missing}"
    )


def test_planned_projects_write_routes_403_refs_envelope() -> None:
    catalog = _load(PLANNED_PROJECTS)
    for path, methods in catalog.get("paths", {}).items():
        for method, op in methods.items():
            if method.lower() not in WRITE_METHODS:
                continue
            response_403 = op.get("responses", {}).get("403", {})
            if not response_403:
                continue
            ref = (
                response_403.get("content", {})
                .get("application/json", {})
                .get("schema", {})
                .get("$ref", "")
            )
            assert ref == ERROR_ENVELOPE_REF, (
                f"{method.upper()} {path} 403 must $ref {ERROR_ENVELOPE_REF!r}, got {ref!r}"
            )


# ---------------------------------------------------------------------------
# Step 3: planned_projects is annotated as pre-release
# ---------------------------------------------------------------------------


def test_planned_projects_marked_prerelease() -> None:
    catalog = _load(PLANNED_PROJECTS)
    stability = catalog.get("x-stability")
    assert stability == "pre-release", (
        f"planned_projects_endpoints.json must have x-stability='pre-release', "
        f"got {stability!r}"
    )


def test_planned_projects_marked_not_backend_asserted() -> None:
    catalog = _load(PLANNED_PROJECTS)
    asserted = catalog.get("x-asserted-against-backend")
    assert asserted is False, (
        f"planned_projects_endpoints.json must have x-asserted-against-backend=false, "
        f"got {asserted!r}"
    )


# ---------------------------------------------------------------------------
# Step 4: New schemas load and are structurally valid JSON
# ---------------------------------------------------------------------------


def test_api_key_create_request_schema_is_valid_json() -> None:
    path = SCHEMAS / "auth" / "api_key_create_request_schema.json"
    assert path.exists(), "api_key_create_request_schema.json does not exist"
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema.get("type") == "object"
    assert "key_name" in schema.get("required", [])
    assert "name" not in schema.get("properties", {})


def test_api_key_resource_schema_is_valid_json() -> None:
    path = SCHEMAS / "auth" / "api_key_resource_schema.json"
    assert path.exists(), "api_key_resource_schema.json does not exist"
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema.get("type") == "object"
    required = schema.get("required", [])
    for field in ("key", "key_id", "key_prefix", "key_name"):
        assert field in required, f"{field} must be required in api_key_resource_schema"


def test_api_key_resource_schema_has_privacy_annotation() -> None:
    path = SCHEMAS / "auth" / "api_key_resource_schema.json"
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    key_prop = schema.get("properties", {}).get("key", {})
    assert key_prop.get("x-one-time-field") is True, (
        "key must be annotated x-one-time-field=true"
    )


# ---------------------------------------------------------------------------
# API-key lifecycle contract (#302)
# ---------------------------------------------------------------------------


def test_api_key_lifecycle_routes_are_catalogued() -> None:
    paths = _load(KEYS_ENDPOINTS)["paths"]
    for path, method in (
        ("/api/v1/keys", "get"),
        ("/api/v1/keys/{key_id}", "put"),
        ("/api/v1/keys/{key_id}", "delete"),
        ("/api/v1/keys/{key_id}/rotate", "post"),
        ("/api/v1/keys/{key_id}/suspend", "post"),
        ("/api/v1/keys/{key_id}/reactivate", "post"),
        ("/api/v1/keys/validate", "post"),
    ):
        assert method in paths[path], f"{method.upper()} {path} is absent"


def test_rotate_request_defaults_and_rejects_legacy_fields() -> None:
    validator = SchemaValidator()
    path = "/api/v1/keys/key_123/rotate"

    assert validator.validate_request(path, "POST", {}) == []
    assert validator.validate_request(
        path, "POST", {"strategy": "gradual", "reason": "planned cutover"}
    ) == []
    for legacy_field in ("grace_period_hours", "notify_users", "force_rotation"):
        errors = validator.validate_request(path, "POST", {legacy_field: True})
        assert errors, f"{legacy_field} must not be accepted by rotate"
    assert validator.validate_request(path, "POST", {"strategy": "later"})


def test_rotate_response_models_one_time_secret() -> None:
    validator = SchemaValidator()
    response = {
        "success": True,
        "message": "API key rotated successfully",
        "data": {
            "old_key_id": "key_old",
            "new_key_id": "key_new",
            "new_key": "sk_example",
            "strategy": "immediate",
        },
    }
    assert validator.validate_json(response, "api_key_rotate_response_schema") == []
    schema = _load(SCHEMAS / "auth" / "api_key_rotate_response_schema.json")
    new_key = schema["properties"]["data"]["properties"]["new_key"]
    assert new_key["x-privacy-classification"] == "secret"
    assert new_key["x-one-time-field"] is True


def test_lifecycle_action_and_validation_request_shapes() -> None:
    validator = SchemaValidator()
    assert validator.validate_request(
        "/api/v1/keys/key_123/suspend", "POST", {"reason": "temporary hold"}
    ) == []
    assert validator.validate_request(
        "/api/v1/keys/validate", "POST", {"api_key": "sk_example"}
    ) == []
    assert validator.validate_request(
        "/api/v1/keys/validate", "POST", {"api_key": "sk_example", "extra": True}
    ) == []


def test_create_and_update_rotation_fields_match_route_defaults() -> None:
    validator = SchemaValidator()
    create = {
        "key_name": "automation",
        "rotation_enabled": True,
        "rotation_interval_days": 90,
        "auto_rotate": False,
    }
    assert validator.validate_request("/api/v1/keys", "POST", create) == []
    assert validator.validate_request("/api/v1/keys", "POST", {"name": "stale"})
    assert validator.validate_request(
        "/api/v1/keys/key_123", "PUT", {"rotation_interval_days": 91, "auto_rotate": True}
    ) == []


def test_list_filters_match_public_route_vocabulary() -> None:
    params = _load(KEYS_ENDPOINTS)["paths"]["/api/v1/keys"]["get"]["parameters"]
    names = {param["name"]: param["schema"] for param in params}
    assert names["page"]["default"] == 1
    assert names["per_page"]["default"] == 20
    assert names["per_page"]["maximum"] == 100
    assert names["include_expired"]["default"] is False
    assert names["scope"]["enum"] == ["all", "user"]
    assert names["scope"]["default"] == "user"


def _api_key_detail() -> dict:
    return {
        "id": 1,
        "key_id": "key_123",
        "key_prefix": "sk_test",
        "user_id": "user_123",
        "tenant_id": "tenant_123",
        "project_id": None,
        "key_type": "user",
        "key_name": "automation",
        "description": None,
        "status": "ACTIVE",
        "version": 1,
        "parent_key_id": None,
        "permissions": ["read"],
        "scopes": ["experiments:read"],
        "rate_limit_tier": "standard",
        "custom_rate_limits": None,
        "rotation_enabled": True,
        "rotation_interval_days": 90,
        "last_rotated_at": None,
        "next_rotation_at": None,
        "expires_at": None,
        "last_used_at": None,
        "usage_count": 0,
        "created_at": "2026-08-04T00:00:00Z",
        "updated_at": "2026-08-04T00:00:00Z",
        "is_active": True,
        "needs_rotation": False,
    }


@pytest.mark.parametrize(
    ("endpoint", "method", "request_data", "request_schema", "response_schema", "response"),
    [
        (
            "/api/v1/keys",
            "POST",
            {"key_name": "automation"},
            "api_key_create_request_schema",
            "api_key_create_response_schema",
            {
                "success": True,
                "message": "API key created successfully",
                "data": {
                    "key": "sk_example",
                    "key_id": "key_123",
                    "key_prefix": "sk_test",
                    "key_name": "automation",
                    "key_type": "user",
                    "created_at": "2026-08-04T00:00:00Z",
                },
            },
        ),
        (
            "/api/v1/keys",
            "GET",
            {},
            None,
            "api_key_list_response_schema",
            {
                "success": True,
                "data": {
                    "items": [_api_key_detail()],
                    "pagination": {
                        "page": 1,
                        "per_page": 20,
                        "total": 1,
                        "total_pages": 1,
                        "has_next": False,
                        "has_prev": False,
                    },
                },
            },
        ),
        (
            "/api/v1/keys/key_123",
            "GET",
            {},
            None,
            "api_key_detail_response_schema",
            {
                "success": True,
                "data": _api_key_detail()
                | {
                    "allowed_ips": ["127.0.0.1"],
                    "custom_metadata": {"label": "value"},
                    "last_used_ip": "127.0.0.1",
                    "analytics": {"requests": 1},
                },
            },
        ),
        (
            "/api/v1/keys/key_123",
            "PUT",
            {"rotation_enabled": True, "rotation_interval_days": 90},
            "api_key_update_request_schema",
            "api_key_detail_response_schema",
            {"success": True, "message": "API key updated successfully", "data": _api_key_detail()},
        ),
        (
            "/api/v1/keys/key_123",
            "DELETE",
            {},
            None,
            "api_key_action_response_schema",
            {"success": True, "message": "API key revoked successfully"},
        ),
        (
            "/api/v1/keys/key_123/rotate",
            "POST",
            {"strategy": "immediate"},
            "api_key_rotate_request_schema",
            "api_key_rotate_response_schema",
            {
                "success": True,
                "message": "API key rotated successfully",
                "data": {
                    "old_key_id": "key_old",
                    "new_key_id": "key_new",
                    "new_key": "sk_example",
                    "strategy": "immediate",
                },
            },
        ),
        (
            "/api/v1/keys/key_123/suspend",
            "POST",
            {"reason": "temporary hold", "ignored_by_live_route": True},
            "api_key_action_request_schema",
            "api_key_action_response_schema",
            {"success": True, "message": "API key suspended successfully"},
        ),
        (
            "/api/v1/keys/key_123/reactivate",
            "POST",
            {},
            None,
            "api_key_action_response_schema",
            {"success": True, "message": "API key reactivated successfully"},
        ),
        (
            "/api/v1/keys/validate",
            "POST",
            {"api_key": "sk_example", "ignored_by_live_route": True},
            "api_key_validate_request_schema",
            "api_key_validate_response_schema",
            {"valid": True},
        ),
    ],
)
def test_lifecycle_concrete_request_and_response_matrix(
    endpoint: str,
    method: str,
    request_data: dict,
    request_schema: str | None,
    response_schema: str,
    response: dict,
) -> None:
    validator = SchemaValidator()
    catalog = _load(KEYS_ENDPOINTS)
    normalized_endpoint = validator._normalize_endpoint(method, endpoint)
    catalog_endpoint = endpoint.replace("key_123", "{key_id}")

    if request_schema is None:
        assert "requestBody" not in catalog["paths"][catalog_endpoint][method.lower()]
    else:
        assert validator.validate_request(endpoint, method, request_data) == []
        assert validator._endpoint_schemas[f"{method}:{normalized_endpoint}"] == request_schema

    assert validator.validate_json(response, response_schema) == []


def test_validate_header_form_is_catalogued_without_a_json_body_requirement() -> None:
    operation = _load(KEYS_ENDPOINTS)["paths"]["/api/v1/keys/validate"]["post"]
    header = next(
        parameter for parameter in operation["parameters"] if parameter["name"] == "X-API-Key"
    )
    assert header["in"] == "header"
    assert header.get("required") is not True
    assert operation["requestBody"].get("required") is not True


def test_defaults_are_explicit_schema_metadata() -> None:
    rotate = _load(SCHEMAS / "auth" / "api_key_rotate_request_schema.json")
    create = _load(SCHEMAS / "auth" / "api_key_create_request_schema.json")
    list_params = _load(KEYS_ENDPOINTS)["paths"]["/api/v1/keys"]["get"]["parameters"]
    list_defaults = {item["name"]: item["schema"].get("default") for item in list_params}

    assert rotate["properties"]["strategy"]["default"] == "immediate"
    assert create["properties"]["key_type"]["default"] == "user"
    assert create["properties"]["permissions"]["default"] == ["read"]
    assert create["properties"]["scope_preset"]["default"] == "minimal"
    assert create["properties"]["rotation_enabled"]["default"] is True
    assert create["properties"]["rotation_interval_days"]["default"] == 90
    assert create["properties"]["auto_rotate"]["default"] is False
    assert list_defaults == {
        "page": 1,
        "per_page": 20,
        "status": None,
        "key_type": None,
        "search": None,
        "include_expired": False,
        "scope": "user",
    }
