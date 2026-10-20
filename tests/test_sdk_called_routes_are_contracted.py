# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Routes the published SDKs call must be declared in a catalog they validate against.

`GET /api/v1/analytics/dashboards/optimization-overview` is called by the Python
SDK (`traigent/cloud/analytics_client.py`) and the JS SDK
(`src/core-metrics/index.ts`, `src/analytics/analytics-client.ts`), and is served
by the backend's `analytics_bp` under `/api/v1`. Only the project-scoped
`/api/v1beta/...` twin was contracted, so `SchemaValidator` answered
`UNVALIDATED_ENDPOINT` for the path the SDKs actually use and the response shape
was pinned by nothing (#581).

`SDK_CALLED_ROUTES` is a hand-maintained list, not a derivation from the SDKs:
nothing here can notice an SDK calling something new. What it does enforce is
that a route once contracted stays contracted.
"""

from __future__ import annotations

import json

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

UNVALIDATED = "UNVALIDATED_ENDPOINT"

# (contract, method, concrete path as an SDK sends it)
SDK_CALLED_ROUTES = [
    ("backend", "GET", "/api/v1/analytics/dashboards/optimization-overview"),
    # Controls: neighbouring analytics routes the same SDK clients call.
    ("backend", "GET", "/api/v1/analytics/runs/r1/pareto"),
    ("backend", "GET", "/api/v1/analytics/runs/r1/leaderboard"),
]

V1_OVERVIEW = "/api/v1/analytics/dashboards/optimization-overview"
V1BETA_OVERVIEW = "/api/v1beta/projects/{project_id}/analytics/dashboards/optimization-overview"


@pytest.mark.parametrize(("contract", "method", "path"), SDK_CALLED_ROUTES)
def test_sdk_called_route_is_contracted(contract: str, method: str, path: str) -> None:
    errors = SchemaValidator(contract=contract).validate_request(path, method, None)
    assert not [e for e in errors if UNVALIDATED in e], (
        f"{method} {path} is not declared in the {contract!r} catalog: {errors}"
    )


def _operation(endpoints_file: str, path: str) -> dict:
    document = json.loads((get_schemas_dir() / endpoints_file).read_text(encoding="utf-8"))
    assert path in document["paths"], f"{path} missing from {endpoints_file}"
    return document["paths"][path]["get"]


def test_v1_and_v1beta_overview_declare_the_same_contract() -> None:
    """One backend handler serves both mounts, so one contract must describe both.

    Cross-checked against the twin rather than against literals retyped here:
    a literal only pins the copy the author wrote, while this catches drift on
    either side, which is the failure the two mounts can actually have.
    """
    v1 = _operation("analytics/analytics_endpoints.json", V1_OVERVIEW)
    v1beta = _operation("planned_projects_endpoints.json", V1BETA_OVERVIEW)

    def response_target(operation: dict) -> str:
        ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        # The two catalogs sit at different depths, so compare the target.
        return ref.split("/")[-1]

    assert response_target(v1) == response_target(v1beta) == (
        "project_scoped_optimization_overview_dashboard_schema.json"
    )
    assert v1["parameters"] == v1beta["parameters"], (
        "the v1 and v1beta optimization-overview mounts declare different query "
        "parameters, but one backend handler serves both"
    )


def test_v1_overview_declares_the_query_bounds_the_backend_enforces() -> None:
    """`ProjectOptimizationOverviewDashboardQuery`: days 1-3660 (30), limit 1-25 (5).

    The twin comparison above would stay green if BOTH mounts drifted together,
    so the bounds the backend's request model actually enforces are pinned once
    here as well.
    """
    operation = _operation("analytics/analytics_endpoints.json", V1_OVERVIEW)
    parameters = {p["name"]: p for p in operation["parameters"]}

    assert parameters["days"]["schema"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 3660,
        "default": 30,
    }
    assert parameters["limit"]["schema"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 25,
        "default": 5,
    }
    assert all(not p["required"] for p in parameters.values())


def test_v1beta_overview_entry_is_not_rewritten_by_the_v1_addition() -> None:
    """The v1beta entry is untouched: same operation, same response definition.

    Deliberately does NOT pin its response-code set. v1beta declares only
    200/429 while the new v1 entry follows this module's fuller convention, and
    bringing the twin into line is a reasonable follow-up that this test must
    not turn red.
    """
    v1beta = _operation("planned_projects_endpoints.json", V1BETA_OVERVIEW)
    assert v1beta["operationId"] == "getProjectOptimizationOverviewDashboard"
    assert v1beta["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "./projects/project_scoped_optimization_overview_dashboard_schema.json"
    }


def test_v1_overview_declares_the_error_responses_its_siblings_do() -> None:
    """404 is reachable here: the project id resolves from `X-Project-Id`, and an
    unknown one raises `PROJECT_NOT_FOUND` with status 404. Every contracted
    `runs/{run_id}/*` neighbour declares the same set."""
    v1 = _operation("analytics/analytics_endpoints.json", V1_OVERVIEW)
    assert sorted(v1["responses"]) == ["200", "400", "401", "403", "404", "429", "500"]
