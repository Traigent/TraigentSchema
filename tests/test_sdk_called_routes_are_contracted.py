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
        "optimization_overview_dashboard_response_schema.json"
    ), (
        "both mounts must declare the success envelope. The handler returns "
        "success_response(...), so the wire body is {success, message, data}; "
        "pointing a 200 at the bare payload describes a body the server never sends."
    )
    # Query parameters only. The v1beta path template carries `{project_id}`,
    # so declaring that path parameter there is a correct future fix; comparing
    # the whole list would turn this red for it.
    def query_parameters(operation: dict) -> list[dict]:
        return [p for p in operation["parameters"] if p.get("in") == "query"]

    assert query_parameters(v1) == query_parameters(v1beta), (
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


def test_v1beta_overview_entry_keeps_its_identity_and_payload() -> None:
    """The v1beta entry's 200 moved to the envelope; nothing else about it changed.

    This test previously asserted the entry was untouched and pinned its bare
    `$ref`, which made it a guard FOR the defect: the declared body described a
    shape the handler never sends. The envelope fix is the thing being pinned
    now. What must still hold is that the operation is the same one and that
    the payload definition underneath is unchanged - SDK clients unwrap and
    validate against that payload, so moving the wire declaration must not move
    the payload.

    Deliberately does NOT pin its response-code set. v1beta declares only
    200/429 while the v1 entry follows the analytics module's fuller
    convention, and bringing the twin into line is a reasonable follow-up that
    this test must not turn red.
    """
    v1beta = _operation("planned_projects_endpoints.json", V1BETA_OVERVIEW)
    assert v1beta["operationId"] == "getProjectOptimizationOverviewDashboard"
    assert v1beta["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "./analytics/optimization_overview_dashboard_response_schema.json"
    }

    envelope = json.loads(
        (
            get_schemas_dir()
            / "analytics"
            / "optimization_overview_dashboard_response_schema.json"
        ).read_text(encoding="utf-8")
    )
    assert envelope["properties"]["data"] == {
        "$ref": "../projects/project_scoped_optimization_overview_dashboard_schema.json"
    }


def test_v1_overview_declares_the_error_responses_its_siblings_do() -> None:
    """404 is reachable here and every contracted neighbour declares it.

    The project id resolves from `X-Project-Id` (which the Python SDK always
    sends) and an unknown one raises `PROJECT_NOT_FOUND` with status 404.

    The expected set is derived from the `runs/{run_id}/*` siblings rather than
    retyped, so a change in the module's convention shows up here instead of
    being silently out of date. `director-evidence` additionally declares 503,
    so the shared set is the intersection.
    """
    document = json.loads(
        (get_schemas_dir() / "analytics" / "analytics_endpoints.json").read_text(
            encoding="utf-8"
        )
    )
    sibling_sets = [
        set(operation["responses"])
        for path, operations in document["paths"].items()
        if path.startswith("/api/v1/analytics/runs/{run_id}/")
        for operation in operations.values()
    ]
    assert len(sibling_sets) >= 8, f"expected the runs/* family, found {len(sibling_sets)}"
    shared = set.intersection(*sibling_sets)
    assert shared == {"200", "400", "401", "403", "404", "429", "500"}, (
        f"the runs/* response convention changed to {sorted(shared)}; "
        "decide whether the dashboard entry should follow it"
    )

    v1 = _operation("analytics/analytics_endpoints.json", V1_OVERVIEW)
    assert set(v1["responses"]) == shared
