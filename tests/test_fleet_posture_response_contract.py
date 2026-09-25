"""Contract tests for the server-computed fleet posture (debt/verdict) response.

See TraigentFrontend `src/utils/fleetPosture.ts` (deriveAgentDebtItems / computeVerdict /
wilsonInterval / rankValidateFirst / summarizeFleet): the backend computes each agent's
debt items + fleet verdict; the frontend only displays.

New route: GET /api/v1beta/projects/{project_id}/agent-readiness/fleet-posture
New schema: agent_readiness/fleet_posture_response_schema.json
New endpoints module: agent_readiness/fleet_posture_endpoints.json (registered in
mep_endpoints.json; a separate module because agent_readiness_endpoints.json's path set
is pinned by test_endpoint_inventory_registers_project_scoped_read_and_target_routes).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READINESS = SCHEMAS / "agent_readiness"
RESPONSE_SCHEMA_PATH = READINESS / "fleet_posture_response_schema.json"
ENDPOINTS_PATH = READINESS / "fleet_posture_endpoints.json"
READINESS_ENDPOINTS_PATH = READINESS / "agent_readiness_endpoints.json"
ERROR_SCHEMA_PATH = READINESS / "agent_readiness_error_schema.json"
CASES_PATH = (
    Path(__file__).parent / "data" / "agent_readiness" / "fleet_posture_verdict_cases.json"
)
SCHEMA_ID_BASE = "https://schemas.traigent.ai/"
ROUTE = "/api/v1beta/projects/{project_id}/agent-readiness/fleet-posture"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    """Same resolution rule as SchemaValidator: a schema without $id is
    addressed by its package-relative path under SCHEMA_ID_BASE."""
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        if "_endpoints" in path.name:
            continue
        document = _load(path)
        if not isinstance(document, dict):
            continue
        schema_id = document.get("$id") or (
            SCHEMA_ID_BASE + path.relative_to(SCHEMAS).as_posix()
        )
        document = {**document, "$id": schema_id}
        resources.append((schema_id, Resource.from_contents(document)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()


def _ref_validator(ref: str) -> Draft7Validator:
    return Draft7Validator({"$ref": ref}, registry=_REGISTRY)


def _errors(ref: str, instance: Any) -> list[str]:
    return [error.message for error in _ref_validator(ref).iter_errors(instance)]


_CASES = _load(CASES_PATH)["cases"]


# ---------------------------------------------------------------------------
# Fixture corpus (valid + invalid)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_fixture_case_matches_expected_outcome(case: dict[str, Any]) -> None:
    errors = _errors(case["schema_ref"], case["instance"])
    if case["valid"]:
        assert errors == [], (case["why"], errors)
    else:
        assert errors, case["why"]


def test_fixture_corpus_covers_valid_and_invalid_for_every_definition() -> None:
    by_ref: dict[str, set[bool]] = {}
    for case in _CASES:
        key = case["schema_ref"].split("#", 1)[1].removeprefix("/definitions/") or "root"
        by_ref.setdefault(key, set()).add(case["valid"])
    for definition in (
        "root",
        "AgentPostureEntry",
        "DebtItem",
        "Policy",
        "FleetSummary",
        "ValidateFirstEntry",
    ):
        assert by_ref[definition] == {True, False}, definition


def test_schema_is_valid_draft7_and_discoverable() -> None:
    validator = SchemaValidator()
    Draft7Validator.check_schema(_load(RESPONSE_SCHEMA_PATH))
    assert RESPONSE_SCHEMA_PATH.stem in validator.available_schemas


# ---------------------------------------------------------------------------
# Structural invariants beyond the fixture corpus
# ---------------------------------------------------------------------------


def test_debt_item_id_pillar_mapping_is_exhaustive_and_fixed() -> None:
    """Every DebtItemId maps to exactly one Pillar, matching
    DEBT_ITEM_DEFINITIONS in fleetPosture.ts, and no other pairing validates."""
    expected = {
        "AG-1": "agent",
        "AG-2": "agent",
        "AG-3": "agent",
        "ES-1": "evaluator",
        "ES-2": "evaluator",
        "ES-3": "evaluation_dataset",
        "ES-4": "evaluation_dataset",
        "ES-5": "evaluation_dataset",
    }
    ref = "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/DebtItem"
    for debt_id, pillar in expected.items():
        assert _errors(ref, {"id": debt_id, "pillar": pillar}) == []
        for other_pillar in {"agent", "evaluator", "evaluation_dataset"} - {pillar}:
            assert _errors(ref, {"id": debt_id, "pillar": other_pillar}), (debt_id, other_pillar)


def test_policy_constants_match_fleet_posture_ts() -> None:
    policy = _load(RESPONSE_SCHEMA_PATH)["definitions"]["Policy"]["properties"]
    assert policy["min_sample_size"]["const"] == 30
    assert policy["saturation_ceiling"]["const"] == 0.95
    assert policy["stale_days"]["const"] == 30
    assert policy["min_reproductions"]["const"] == 2
    assert policy["journey_window"]["const"] == 25
    assert policy["interval_method"]["const"] == "wilson"
    assert policy["interval_z"]["const"] == 1.96


def test_criticality_used_reuses_agent_posture_criticality() -> None:
    criticality = _load(RESPONSE_SCHEMA_PATH)["definitions"]["Criticality"]
    assert criticality["$ref"] == (
        "https://schemas.traigent.ai/agent_readiness/agent_posture_schema.json#/definitions/Criticality"
    )


def test_validity_level_is_wider_than_the_common_schema_level() -> None:
    """fleetPosture.ts's ValidityLevel is V0/V1/V2; the common schema's
    EvaluationSystemValidity.level is V0/V1 only (V2 is a documented future
    widening there). This response's ValidityLevel must stay a LOCAL
    definition (not a $ref to the common one) so it can already carry V2."""
    validity_level = _load(RESPONSE_SCHEMA_PATH)["definitions"]["ValidityLevel"]
    assert "$ref" not in validity_level
    assert set(validity_level["enum"]) == {"V0", "V1", "V2"}


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def test_fleet_posture_route_is_registered_correctly() -> None:
    inventory = _load(ENDPOINTS_PATH)
    assert set(inventory["paths"]) == {ROUTE}
    operation = inventory["paths"][ROUTE]["get"]
    assert operation["x-asserted-against-backend"] is False
    assert [p["name"] for p in operation["parameters"]] == ["project_id"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ] == "./fleet_posture_response_schema.json"
    for status in ("400", "401", "403"):
        assert operation["responses"][status]["content"]["application/json"]["schema"][
            "$ref"
        ] == "./agent_readiness_error_schema.json"
    # No body/no 404: this is a project-scoped collection read, same auth shape as the
    # portfolio list route (no per-agent lookup, so no agent-not-found case).
    assert "requestBody" not in operation
    assert "404" not in operation["responses"]


def test_fleet_posture_route_does_not_reuse_the_pinned_agent_readiness_path_set() -> None:
    """agent_readiness_endpoints.json's path set is pinned by
    test_endpoint_inventory_registers_project_scoped_read_and_target_routes; the new
    route must live in its own module, not be folded into that file."""
    readiness_paths = _load(READINESS_ENDPOINTS_PATH)["paths"]
    assert ROUTE not in readiness_paths


def test_fleet_posture_module_is_registered_exactly_once_in_mep_endpoints() -> None:
    root = _load(SCHEMAS / "mep_endpoints.json")
    modules = [
        module
        for module in root["x-endpoint-modules"]
        if module.get("paths_file") == "./agent_readiness/fleet_posture_endpoints.json"
    ]
    assert len(modules) == 1


def test_error_responses_resolve_to_the_shared_agent_readiness_error_schema() -> None:
    error_schema = _load(ERROR_SCHEMA_PATH)
    assert error_schema["$id"].endswith("agent_readiness_error_schema.json")
