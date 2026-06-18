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
    assert "name" in schema.get("required", [])


def test_api_key_resource_schema_is_valid_json() -> None:
    path = SCHEMAS / "auth" / "api_key_resource_schema.json"
    assert path.exists(), "api_key_resource_schema.json does not exist"
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    assert schema.get("type") == "object"
    required = schema.get("required", [])
    for field in ("key_id", "name", "prefix"):
        assert field in required, f"{field} must be required in api_key_resource_schema"


def test_api_key_resource_schema_has_privacy_annotation() -> None:
    path = SCHEMAS / "auth" / "api_key_resource_schema.json"
    with open(path, encoding="utf-8") as fh:
        schema = json.load(fh)
    # create_secret must be marked as one-time
    create_secret_prop = schema.get("properties", {}).get("create_secret", {})
    assert create_secret_prop.get("x-one-time-field") is True, (
        "create_secret must be annotated x-one-time-field=true to prevent caching/re-transmission"
    )
