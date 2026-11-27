# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""The six project analytics reads sit on project-scoped paths and keep their operation ids."""

from __future__ import annotations

import json

import pytest

from traigent_schema.utils import get_schemas_dir

CATALOG = json.loads(
    (get_schemas_dir() / "analytics" / "analytics_endpoints.json").read_text(encoding="utf-8")
)
PATHS = CATALOG["paths"]
PROJECT_SUFFIXES = {
    "summary": "get_project_analytics_summary",
    "pricing-catalog": "get_project_pricing_catalog",
    "dashboards/optimization-overview": "get_project_optimization_overview_dashboard",
    "dashboards/evaluator-quality": "get_project_evaluator_quality_dashboard",
    "dashboards/project-usage": "get_project_usage_dashboard",
    "dashboards/observability-summary": "get_project_observability_summary_dashboard",
}
PROJECT_OPS = [
    (
        f"/api/v1/analytics/{s}",
        f"/api/v1/projects/{{project_id}}/analytics/{s}",
        "get",
        f"analytics.{n}",
    )
    for s, n in PROJECT_SUFFIXES.items()
]
ALL_OPS = PROJECT_OPS


def _non_path(op: dict) -> list:
    return [p for p in op.get("parameters", []) if p["in"] != "path"]


def _query(name: str, description: str, maximum: int, default: int) -> dict:
    return {
        "name": name,
        "in": "query",
        "required": False,
        "description": description,
        "schema": {"type": "integer", "minimum": 1, "maximum": maximum, "default": default},
    }


DAYS = _query("days", "Look-back window in days.", 3660, 30)
LIMIT = _query("limit", "Maximum number of ranked rows in the dashboard.", 25, 5)
_C = "#/components/responses/"
_ANALYTICS_429 = {
    "description": "Too many requests: rate limit exceeded.",
    "content": {"application/json": {"schema": {"$ref": "../rate_limit_info_schema.json"}}},
}


def _ok(description: str, schema_ref: str) -> dict:
    return {
        "description": description,
        "content": {"application/json": {"schema": {"$ref": schema_ref}}},
    }


def _analytics_responses(ok: dict, *, with_422: bool) -> dict:
    out = {
        "200": ok,
        "401": {"$ref": _C + "AnalyticsUnauthenticated"},
        "403": {"$ref": _C + "AnalyticsForbidden"},
        "404": {"$ref": _C + "AnalyticsProjectNotFound"},
    }
    if with_422:
        out["422"] = {"$ref": _C + "AnalyticsValidationFailed"}
    out["429"] = _ANALYTICS_429
    out["500"] = {"$ref": _C + "AnalyticsInternalError"}
    return out


_BODY_SUFFIX = (
    " The body is the success envelope {success, message, data} with the payload under data."
)
# Exact non-path parameters, request body and responses of the six reads.
EXPECTED = {}
_P = "/api/v1/projects/{project_id}/analytics/"
EXPECTED[_P + "summary"] = {
    "non_path": [DAYS],
    "requestBody": None,
    "responses": _analytics_responses(
        _ok(
            "Analytics summary retrieved successfully." + _BODY_SUFFIX,
            "./project_analytics_summary_response_schema.json",
        ),
        with_422=True,
    ),
}
EXPECTED[_P + "pricing-catalog"] = {
    "non_path": [],
    "requestBody": None,
    "responses": _analytics_responses(
        _ok(
            "Pricing catalog retrieved successfully." + _BODY_SUFFIX,
            "./project_pricing_catalog_response_schema.json",
        ),
        with_422=False,
    ),
}
for _s, _label, _ref in [
    (
        "optimization-overview",
        "Optimization overview dashboard",
        "./optimization_overview_dashboard_response_schema.json",
    ),
    (
        "evaluator-quality",
        "Evaluator quality dashboard",
        "./project_evaluator_quality_dashboard_response_schema.json",
    ),
    ("project-usage", "Project usage dashboard", "./project_usage_dashboard_response_schema.json"),
    (
        "observability-summary",
        "Observability summary dashboard",
        "./project_observability_summary_dashboard_response_schema.json",
    ),
]:
    EXPECTED[f"{_P}dashboards/{_s}"] = {
        "non_path": [DAYS, LIMIT],
        "requestBody": None,
        "responses": _analytics_responses(
            _ok(f"{_label} retrieved successfully." + _BODY_SUFFIX, _ref), with_422=True
        ),
    }


@pytest.mark.parametrize("legacy,canonical,method,op_id", ALL_OPS)
def test_canonical_path_exists_with_only_that_method(legacy, canonical, method, op_id):
    assert list(PATHS[canonical]) == [method]
    assert PATHS[canonical][method]["operationId"] == op_id


@pytest.mark.parametrize("legacy,canonical,method,op_id", ALL_OPS)
def test_non_path_parameters_request_body_and_responses_are_exact(legacy, canonical, method, op_id):
    op = PATHS[canonical][method]
    expected = EXPECTED[canonical]
    assert _non_path(op) == expected["non_path"]
    assert op.get("requestBody") == expected["requestBody"]
    assert op["responses"] == expected["responses"]
    assert {p["name"] for p in op["parameters"] if p["in"] == "path"} == {"project_id"}
    assert len(op["parameters"]) == len(expected["non_path"]) + 1


def test_expected_table_covers_exactly_the_six_ops():
    assert set(EXPECTED) == {canonical for _, canonical, _, _ in ALL_OPS}


@pytest.mark.parametrize("legacy,canonical,method,op_id", ALL_OPS)
def test_project_id_parameter(legacy, canonical, method, op_id):
    params = {p["name"]: p for p in PATHS[canonical][method]["parameters"] if p["in"] == "path"}
    pid = params["project_id"]
    assert pid["required"] is True
    assert pid["schema"] == {"type": "string", "minLength": 1, "maxLength": 128}


@pytest.mark.parametrize("legacy,canonical,method,op_id", ALL_OPS)
def test_canonical_op_is_not_deprecated_and_has_no_replacement_text(
    legacy, canonical, method, op_id
):
    op = PATHS[canonical][method]
    assert "deprecated" not in op
    assert "DEPRECATED" not in op["description"]
    assert "requestBody" in op or method == "get"
    assert "200" in op["responses"] or "201" in op["responses"]


@pytest.mark.parametrize("legacy,canonical,method,op_id", PROJECT_OPS)
def test_project_ops_declare_project_not_found(legacy, canonical, method, op_id):
    responses = PATHS[canonical][method]["responses"]
    assert responses["404"] == {"$ref": "#/components/responses/AnalyticsProjectNotFound"}


@pytest.mark.parametrize("legacy,canonical,method,op_id", ALL_OPS)
def test_legacy_path_is_absent(legacy, canonical, method, op_id):
    assert legacy not in PATHS


def test_no_legacy_analytics_paths_reappear():
    legacy_exact = {legacy for legacy, _, _, _ in PROJECT_OPS}
    for path in PATHS:
        assert path not in legacy_exact


def test_exactly_these_six_ids_sit_on_the_canonical_paths():
    for _, canonical, method, op_id in ALL_OPS:
        assert PATHS[canonical][method]["operationId"] == op_id
    assert len(ALL_OPS) == 6
    assert len({op_id for *_, op_id in ALL_OPS}) == 6


def test_operation_ids_are_unique():
    ids = [
        op["operationId"] for item in PATHS.values() for op in item.values() if "operationId" in op
    ]
    assert len(ids) == len(set(ids))


def test_beta_project_mount_is_untouched():
    for suffix, name in PROJECT_SUFFIXES.items():
        op = PATHS[f"/api/v1beta/projects/{{project_id}}/analytics/{suffix}"]["get"]
        assert op["operationId"] == f"project_analytics.{name}"
        assert "deprecated" not in op
