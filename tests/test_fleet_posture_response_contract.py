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

from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, load_json, ref_errors
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
ROUTE = "/api/v1beta/projects/{project_id}/agent-readiness/fleet-posture"


_load = load_json
_REGISTRY = build_registry(SCHEMAS)


def _errors(ref: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, ref, instance)


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
# Pagination
# ---------------------------------------------------------------------------


def test_pagination_is_required_and_mirrors_the_portfolio_response() -> None:
    schema = _load(RESPONSE_SCHEMA_PATH)
    assert "pagination" in schema["required"]
    pagination = schema["properties"]["pagination"]
    portfolio_pagination = _load(
        READINESS / "agent_readiness_portfolio_response_schema.json"
    )["properties"]["pagination"]
    assert pagination["allOf"] == portfolio_pagination["allOf"]


def test_response_without_pagination_fails_validation() -> None:
    valid_case = next(
        case
        for case in _CASES
        if case["name"] == "fleet_posture_response_valid_populated_fleet"
    )
    missing_pagination = {
        key: value for key, value in valid_case["instance"].items() if key != "pagination"
    }
    assert _errors(
        "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#",
        missing_pagination,
    )


# ---------------------------------------------------------------------------
# criticality_source / verdict_reason (agent-row provenance)
# ---------------------------------------------------------------------------


def test_criticality_source_and_verdict_reason_are_required_on_every_agent_row() -> None:
    entry = _load(RESPONSE_SCHEMA_PATH)["definitions"]["AgentPostureEntry"]
    assert "criticality_source" in entry["required"]
    assert "verdict_reason" in entry["required"]


def test_criticality_source_enum_is_closed() -> None:
    definition = _load(RESPONSE_SCHEMA_PATH)["definitions"]["CriticalitySource"]
    assert set(definition["enum"]) == {"fixed_default", "declared", "undeclared_fail_closed"}


def test_verdict_reason_enum_is_closed() -> None:
    definition = _load(RESPONSE_SCHEMA_PATH)["definitions"]["VerdictReason"]
    assert set(definition["enum"]) == {
        "NO_ANCHOR_RUN",
        "VALIDITY_BELOW_BAR",
        "TARGET_NOT_DECLARED",
        "TARGET_CANNOT_DETERMINE",
        "INTERVAL_STRADDLES_TARGET",
        "BELOW_TARGET",
        "CRITICALITY_UNDECLARED",
        "VALIDITY_BELOW_STAY_BAR",
        "OPEN_EVALUATION_SYSTEM_DEBT",
        "MEETS_TARGET",
    }


def test_not_yet_scored_and_no_anchor_run_reason_pair_bidirectionally() -> None:
    ref = "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/AgentPostureEntry"
    base = {
        "agent_id": "agent-1",
        "agent_name": "Support Bot",
        "debt_items": [{"id": "AG-1", "pillar": "agent"}],
        "effective_validity_level": "V0",
        "served_validity_level": None,
        "validity_decayed": False,
        "criticality_used": "medium",
        "accuracy": None,
        "sample_size": None,
        "interval": None,
        "reproductions_in_window": None,
        "dataset_ref_id": None,
        "evaluator_ref_id": None,
        "has_anchor_run": False,
        "score_credible": False,
        "pillar_review_status": {"evaluator": None, "evaluation_dataset": None},
        "criticality_source": "fixed_default",
    }

    valid = {**base, "verdict": "NOT_YET_SCORED", "verdict_reason": "NO_ANCHOR_RUN"}
    assert _errors(ref, valid) == []

    mismatched_reason = {
        **base,
        "verdict": "NOT_YET_SCORED",
        "verdict_reason": "TARGET_NOT_DECLARED",
    }
    assert _errors(ref, mismatched_reason)

    mismatched_verdict = {
        **base,
        "verdict": "CANT_TELL",
        "verdict_reason": "NO_ANCHOR_RUN",
        "has_anchor_run": True,
        "served_validity_level": "V0",
        "accuracy": 0.5,
        "sample_size": 12,
        "interval": {"lower": 0.2, "upper": 0.8},
        "reproductions_in_window": 0,
        "dataset_ref_id": "dataset-v1",
        "evaluator_ref_id": "eval-v1",
        "pillar_review_status": {"evaluator": "unreviewed", "evaluation_dataset": "unreviewed"},
    }
    assert _errors(ref, mismatched_verdict)


_CANT_TELL_FAMILY_REASONS = (
    "VALIDITY_BELOW_BAR",
    "TARGET_NOT_DECLARED",
    "TARGET_CANNOT_DETERMINE",
    "INTERVAL_STRADDLES_TARGET",
    "CRITICALITY_UNDECLARED",
    "VALIDITY_BELOW_STAY_BAR",
    "OPEN_EVALUATION_SYSTEM_DEBT",
)


def _scored_base() -> dict[str, Any]:
    return {
        "agent_id": "agent-2",
        "agent_name": "Reconciliation Agent",
        "debt_items": [],
        "effective_validity_level": "V1",
        "served_validity_level": "V1",
        "validity_decayed": False,
        "criticality_used": "medium",
        "criticality_source": "declared",
        "accuracy": 0.9,
        "sample_size": 200,
        "interval": {"lower": 0.85, "upper": 0.95},
        "reproductions_in_window": 3,
        "dataset_ref_id": "dataset-v1",
        "evaluator_ref_id": "eval-v1",
        "has_anchor_run": True,
        "score_credible": True,
        "pillar_review_status": {"evaluator": "reviewed", "evaluation_dataset": "reviewed"},
    }


def test_verdict_reason_mapping_is_closed_for_every_verdict() -> None:
    """The full (verdict, verdict_reason) pairing is enforced bidirectionally:
    STAY<->MEETS_TARGET, INTERVENE_QUALITY<->BELOW_TARGET, and
    CANT_TELL<->any of the seven CANT_TELL-family reasons. Together with the
    NOT_YET_SCORED<->NO_ANCHOR_RUN pair (tested above) this exhausts every
    VerdictReason member, so every combination is closed."""
    ref = "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/AgentPostureEntry"

    stay = {**_scored_base(), "verdict": "STAY", "verdict_reason": "MEETS_TARGET"}
    assert _errors(ref, stay) == []
    assert _errors(ref, {**stay, "verdict_reason": "TARGET_NOT_DECLARED"})
    assert _errors(ref, {**stay, "verdict": "CANT_TELL"})  # reason MEETS_TARGET now orphaned

    intervene = {**_scored_base(), "verdict": "INTERVENE_QUALITY", "verdict_reason": "BELOW_TARGET"}
    assert _errors(ref, intervene) == []
    assert _errors(ref, {**intervene, "verdict_reason": "MEETS_TARGET"})
    assert _errors(ref, {**intervene, "verdict": "STAY"})  # reason BELOW_TARGET now orphaned

    for reason in _CANT_TELL_FAMILY_REASONS:
        cant_tell = {**_scored_base(), "verdict": "CANT_TELL", "verdict_reason": reason}
        assert _errors(ref, cant_tell) == [], reason
        # Every CANT_TELL-family reason must reject a non-CANT_TELL verdict.
        assert _errors(ref, {**cant_tell, "verdict": "STAY"}), reason

    # A CANT_TELL verdict rejects any reason outside its seven-member family.
    assert _errors(ref, {**_scored_base(), "verdict": "CANT_TELL", "verdict_reason": "NO_ANCHOR_RUN"})
    assert _errors(ref, {**_scored_base(), "verdict": "CANT_TELL", "verdict_reason": "MEETS_TARGET"})
    assert _errors(ref, {**_scored_base(), "verdict": "CANT_TELL", "verdict_reason": "BELOW_TARGET"})


def test_criticality_source_constrains_criticality_used() -> None:
    """fixed_default => medium and undeclared_fail_closed => high are enforced
    one-directionally; declared carries no constraint (any Criticality value)."""
    ref = "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/AgentPostureEntry"
    base = {**_scored_base(), "verdict": "CANT_TELL", "verdict_reason": "TARGET_NOT_DECLARED"}

    assert _errors(ref, {**base, "criticality_source": "fixed_default", "criticality_used": "medium"}) == []
    assert _errors(ref, {**base, "criticality_source": "fixed_default", "criticality_used": "high"})
    assert _errors(ref, {**base, "criticality_source": "fixed_default", "criticality_used": "low"})

    assert (
        _errors(
            ref, {**base, "criticality_source": "undeclared_fail_closed", "criticality_used": "high"}
        )
        == []
    )
    assert _errors(
        ref, {**base, "criticality_source": "undeclared_fail_closed", "criticality_used": "medium"}
    )

    for used in ("low", "medium", "high"):
        assert (
            _errors(ref, {**base, "criticality_source": "declared", "criticality_used": used}) == []
        ), used


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


def test_fleet_posture_route_is_registered_correctly() -> None:
    inventory = _load(ENDPOINTS_PATH)
    assert set(inventory["paths"]) == {ROUTE}
    operation = inventory["paths"][ROUTE]["get"]
    assert operation["x-asserted-against-backend"] is False
    assert [p["name"] for p in operation["parameters"]] == [
        "project_id",
        "page",
        "per_page",
        "agent_id",
    ]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"][
        "$ref"
    ] == "./fleet_posture_response_schema.json"
    for status in ("400", "401", "403"):
        assert operation["responses"][status]["content"]["application/json"]["schema"][
            "$ref"
        ] == "./agent_readiness_error_schema.json"
    # No body/no 404: this is a project-scoped collection read, same auth shape as the
    # portfolio list route (no per-agent lookup, so no agent-not-found case) -- the
    # optional agent_id query filter does not change that: unknown/inaccessible ids
    # return 200 with an empty `agents` array, per its own parameter description.
    assert "requestBody" not in operation
    assert "404" not in operation["responses"]


def test_fleet_posture_paging_params_mirror_the_portfolio_route() -> None:
    """page/per_page must have the same names/types/bounds/defaults as the portfolio
    list route's paging params (agent_readiness_endpoints.json), except per_page's
    default (24, the fleet-posture page size) which is intentionally NOT mirrored --
    see the endpoint description."""
    fleet_params = {
        p["name"]: p for p in _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["parameters"]
    }
    portfolio_params = {
        p["name"]: p
        for p in _load(READINESS_ENDPOINTS_PATH)["paths"][
            "/api/v1beta/projects/{project_id}/agent-readiness"
        ]["get"]["parameters"]
    }

    assert fleet_params["page"]["schema"] == portfolio_params["page"]["schema"]
    assert fleet_params["page"]["required"] is False
    assert fleet_params["page"]["in"] == "query"

    fleet_per_page = fleet_params["per_page"]["schema"]
    portfolio_per_page = portfolio_params["per_page"]["schema"]
    assert fleet_per_page["type"] == portfolio_per_page["type"]
    assert fleet_per_page["minimum"] == portfolio_per_page["minimum"]
    assert fleet_per_page["maximum"] == portfolio_per_page["maximum"] == 100
    assert fleet_per_page["default"] == 24
    assert fleet_params["per_page"]["required"] is False
    assert fleet_params["per_page"]["in"] == "query"

    unpaged_line = "Unpaged calls return the first page (24 agents), the same as the endpoint's previous behaviour."
    assert unpaged_line in fleet_params["page"]["description"]
    assert unpaged_line in fleet_params["per_page"]["description"]


def test_fleet_posture_agent_id_filter_param_is_declared() -> None:
    params = {
        p["name"]: p for p in _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["parameters"]
    }
    agent_id_param = params["agent_id"]
    assert agent_id_param["in"] == "query"
    assert agent_id_param["required"] is False
    assert agent_id_param["schema"] == {"type": "string", "minLength": 1}


def test_fleet_posture_agent_id_param_states_the_no_match_privacy_invariant() -> None:
    """Unknown and inaccessible agent_id must be documented as INDISTINGUISHABLE, with
    the exact empty-fleet response shape spelled out, and the id must never be echoed."""
    params = {
        p["name"]: p for p in _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["parameters"]
    }
    description = params["agent_id"]["description"]
    for phrase in (
        "INDISTINGUISHABLE",
        "agents: []",
        "failed_agent_ids: []",
        "validate_first: []",
        "summary.total: 0",
        "total: 0, total_pages: 0",
        "never echoed",
        "never 404",
    ):
        assert phrase in description, phrase

    schema = _load(RESPONSE_SCHEMA_PATH)
    assert "INDISTINGUISHABLE" in schema["description"] or "indistinguishable" in schema["description"]
    assert "never echoed" in schema["description"]
    pagination_description = schema["properties"]["pagination"]["description"]
    assert "IGNORED" in pagination_description
    assert "indistinguishable" in pagination_description.lower()


def test_no_match_agent_id_response_fixture_matches_the_documented_shape() -> None:
    case = next(
        c
        for c in _CASES
        if c["name"] == "fleet_posture_response_valid_agent_id_no_match"
    )
    instance = case["instance"]
    assert instance["agents"] == []
    assert instance["failed_agent_ids"] == []
    assert instance["validate_first"] == []
    assert instance["summary"] == {
        "total": 0,
        "counts_by_verdict": {
            "NOT_YET_SCORED": 0,
            "CANT_TELL": 0,
            "STAY": 0,
            "INTERVENE_QUALITY": 0,
        },
    }
    assert instance["pagination"]["page"] == 1
    assert instance["pagination"]["total"] == 0
    assert instance["pagination"]["total_pages"] == 0
    assert "agent_id" not in instance
    assert _errors(
        "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#",
        instance,
    ) == []


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
