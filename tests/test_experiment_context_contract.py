"""Contract tests for the experiment deep-link context-resolution read route.

New route: GET /api/v1beta/experiments/{experiment_id}/context
New schema: evaluation/experiment_context_schema.json
Operation added to the existing execution/execution_endpoints.json module (already
registered in mep_endpoints.json's x-endpoint-modules; no new endpoints module needed).

Recovers SDK/Claude Code deep links (.../experiments/view/{id}) that open under the
wrong tenant: the caller's own ACTIVE tenant memberships are probed, the experiment
detail route's real visibility policy is reused per tenant, and the response is the
resolved {experiment_id, project_id, tenant_id} the frontend pins before retrying the
experiment fetch. Absent and inaccessible experiments return the exact same closed 404;
API-key principals are rejected uniformly before any lookup; an exhausted membership
probe is a retryable 503, never a false 404.
"""

from __future__ import annotations

from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
SCHEMA_PATH = SCHEMAS / "evaluation" / "experiment_context_schema.json"
ENDPOINTS_PATH = SCHEMAS / "execution" / "execution_endpoints.json"
ROUTE = "/api/v1beta/experiments/{experiment_id}/context"

_load = load_json
_REGISTRY = build_registry(SCHEMAS)
_SCHEMA_DOC = _load(SCHEMA_PATH)
_SCHEMA_ID = _SCHEMA_DOC["$id"]


def _ref(fragment: str) -> str:
    return f"{_SCHEMA_ID}#/definitions/{fragment}"


def _errors(ref: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, ref, instance)


def _response(
    *,
    experiment_id: str = "exp_1",
    project_id: str = "proj_1",
    tenant_id: str = "tenant_1",
    tenant_name: str | None = None,
    project_name: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "experiment_id": experiment_id,
        "project_id": project_id,
        "tenant_id": tenant_id,
    }
    if tenant_name is not None:
        body["tenant_name"] = tenant_name
    if project_name is not None:
        body["project_name"] = project_name
    return body


# ---------------------------------------------------------------------------
# Schema self-validity
# ---------------------------------------------------------------------------


def test_schema_is_valid_draft7_and_discoverable() -> None:
    assert "experiment_context_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_SCHEMA_DOC)


def test_all_definitions_are_closed_objects() -> None:
    for name, definition in _SCHEMA_DOC["definitions"].items():
        assert definition.get("type") == "object", name
        assert definition.get("additionalProperties") is False, name


# ---------------------------------------------------------------------------
# 200 response — valid fixtures
# ---------------------------------------------------------------------------


def test_valid_minimal_response() -> None:
    assert _errors(_ref("ExperimentContextResponse"), _response()) == []


def test_valid_response_with_optional_names() -> None:
    instance = _response(tenant_name="Acme", project_name="Prod Evals")
    assert _errors(_ref("ExperimentContextResponse"), instance) == []


@pytest.mark.parametrize("missing", ["experiment_id", "project_id", "tenant_id"])
def test_rejects_response_missing_a_required_field(missing: str) -> None:
    instance = _response()
    del instance[missing]
    assert _errors(_ref("ExperimentContextResponse"), instance)


def test_rejects_extra_top_level_field() -> None:
    instance = _response()
    instance["role"] = "viewer"
    assert _errors(_ref("ExperimentContextResponse"), instance)


@pytest.mark.parametrize("field", ["experiment_id", "project_id", "tenant_id"])
def test_rejects_empty_string_identifiers(field: str) -> None:
    instance = _response()
    instance[field] = ""
    assert _errors(_ref("ExperimentContextResponse"), instance)


def test_rejects_empty_string_optional_names() -> None:
    instance = _response(tenant_name="", project_name="Prod")
    assert _errors(_ref("ExperimentContextResponse"), instance)


# ---------------------------------------------------------------------------
# Error envelopes — one closed shape per status
# ---------------------------------------------------------------------------


def _valid_not_found() -> dict[str, Any]:
    return {
        "success": False,
        "message": "Experiment not found",
        "error": "Not found",
        "error_code": "NOT_FOUND",
    }


def _valid_authentication_required() -> dict[str, Any]:
    return {
        "success": False,
        "message": "Authentication required",
        "error": "Unauthorized",
        "error_code": "UNAUTHORIZED",
    }


def _valid_api_key_rejected() -> dict[str, Any]:
    return {
        "success": False,
        "message": "This endpoint requires a human session.",
        "error": "Forbidden",
        "error_code": "CONTEXT_RESOLUTION_HUMAN_ONLY",
    }


def _valid_budget_exceeded() -> dict[str, Any]:
    return {
        "success": False,
        "message": "Context resolution is temporarily unavailable. Try again shortly.",
        "error": "Service unavailable",
        "error_code": "CONTEXT_RESOLUTION_BUDGET_EXCEEDED",
    }


@pytest.mark.parametrize(
    "definition,factory",
    [
        ("ExperimentContextNotFoundError", _valid_not_found),
        ("ExperimentContextAuthenticationRequiredError", _valid_authentication_required),
        ("ExperimentContextApiKeyRejectedError", _valid_api_key_rejected),
        ("ExperimentContextBudgetExceededError", _valid_budget_exceeded),
    ],
)
def test_valid_error_envelope(definition: str, factory) -> None:
    assert _errors(_ref(definition), factory()) == []


@pytest.mark.parametrize(
    "definition,factory",
    [
        ("ExperimentContextNotFoundError", _valid_not_found),
        ("ExperimentContextAuthenticationRequiredError", _valid_authentication_required),
        ("ExperimentContextApiKeyRejectedError", _valid_api_key_rejected),
        ("ExperimentContextBudgetExceededError", _valid_budget_exceeded),
    ],
)
def test_error_envelope_rejects_extra_field(definition: str, factory) -> None:
    instance = factory()
    instance["details"] = {"experiment_id": "exp_1"}
    assert _errors(_ref(definition), instance)


@pytest.mark.parametrize(
    "definition,factory",
    [
        ("ExperimentContextNotFoundError", _valid_not_found),
        ("ExperimentContextAuthenticationRequiredError", _valid_authentication_required),
        ("ExperimentContextApiKeyRejectedError", _valid_api_key_rejected),
        ("ExperimentContextBudgetExceededError", _valid_budget_exceeded),
    ],
)
def test_error_envelope_rejects_wrong_error_code(definition: str, factory) -> None:
    instance = factory()
    instance["error_code"] = "SOMETHING_ELSE"
    assert _errors(_ref(definition), instance)


def test_not_found_is_identical_regardless_of_absent_vs_inaccessible_reason() -> None:
    """The route's whole 404 contract is that absent and inaccessible experiments
    produce the exact same body. At the schema level this means there is exactly
    ONE valid instance of the closed NotFoundError shape -- so any caller-supplied
    reason text could never validate as a second, distinguishing variant."""
    absent = _valid_not_found()
    inaccessible = _valid_not_found()
    assert absent == inaccessible
    assert _errors(_ref("ExperimentContextNotFoundError"), absent) == []
    assert _errors(_ref("ExperimentContextNotFoundError"), inaccessible) == []


# ---------------------------------------------------------------------------
# Endpoint registration
# ---------------------------------------------------------------------------


def test_endpoint_registered_with_expected_shape() -> None:
    inventory = _load(ENDPOINTS_PATH)
    assert ROUTE in inventory["paths"]
    op = inventory["paths"][ROUTE]["get"]
    assert op["x-asserted-against-backend"] is False
    assert op["x-wrap-status"] == "bare"

    params = {p["name"]: p for p in op["parameters"]}
    assert params["experiment_id"]["in"] == "path"
    assert params["experiment_id"]["required"] is True

    responses = op["responses"]
    assert responses["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "experiment_context_schema.json#/definitions/ExperimentContextResponse"
    )
    assert responses["200"]["headers"]["Cache-Control"]["schema"]["const"] == "private, no-store"

    for status, fragment in (
        ("401", "ExperimentContextAuthenticationRequiredError"),
        ("403", "ExperimentContextApiKeyRejectedError"),
        ("404", "ExperimentContextNotFoundError"),
        ("503", "ExperimentContextBudgetExceededError"),
    ):
        assert responses[status]["content"]["application/json"]["schema"]["$ref"].endswith(
            f"experiment_context_schema.json#/definitions/{fragment}"
        )

    assert responses["429"]["content"]["application/json"]["schema"]["$ref"] == (
        "../rate_limit_info_schema.json"
    )


def test_route_does_not_require_v1_only_project_or_tenant_path_params() -> None:
    """Context-independent: the only path parameter is experiment_id -- no
    project_id/tenant_id segment, unlike the project-scoped agent-readiness family."""
    inventory = _load(ENDPOINTS_PATH)
    op = inventory["paths"][ROUTE]["get"]
    names = {p["name"] for p in op["parameters"]}
    assert names == {"experiment_id"}
