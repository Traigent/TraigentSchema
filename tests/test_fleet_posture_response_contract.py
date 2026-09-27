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
        "DECLARED_POLICY_OFF",
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
    "DECLARED_POLICY_OFF",
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
    CANT_TELL<->any of the eight CANT_TELL-family reasons. Together with the
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
        base = _scored_base()
        if reason == "DECLARED_POLICY_OFF":
            # DECLARED_POLICY_OFF only pairs with criticality_source: fixed_default
            # (see test_declared_policy_off_reason_constrains_criticality_source);
            # _scored_base()'s default "declared" would fail for this reason alone.
            base = {**base, "criticality_source": "fixed_default"}
        cant_tell = {**base, "verdict": "CANT_TELL", "verdict_reason": reason}
        assert _errors(ref, cant_tell) == [], reason
        # Every CANT_TELL-family reason must reject a non-CANT_TELL verdict.
        assert _errors(ref, {**cant_tell, "verdict": "STAY"}), reason

    # A CANT_TELL verdict rejects any reason outside its eight-member family.
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


def test_declared_policy_off_reason_constrains_criticality_source() -> None:
    """DECLARED_POLICY_OFF only pairs with criticality_source: fixed_default
    (one-directional) -- it means the declared-accuracy policy is not enabled, the
    same today's-legacy-behaviour flag-off world as criticality_source's own
    fixed_default. declared/undeclared_fail_closed are rejected even though the
    verdict itself (CANT_TELL) is otherwise valid."""
    ref = "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/AgentPostureEntry"
    base = {
        **_scored_base(),
        "verdict": "CANT_TELL",
        "verdict_reason": "DECLARED_POLICY_OFF",
    }

    assert (
        _errors(ref, {**base, "criticality_source": "fixed_default", "criticality_used": "medium"})
        == []
    )
    assert _errors(
        ref, {**base, "criticality_source": "declared", "criticality_used": "medium"}
    )
    assert _errors(
        ref,
        {**base, "criticality_source": "undeclared_fail_closed", "criticality_used": "high"},
    )

    # TARGET_NOT_DECLARED (a different CANT_TELL-family reason) carries no such
    # constraint -- it is free to pair with any criticality_source.
    assert (
        _errors(
            ref,
            {
                **base,
                "verdict_reason": "TARGET_NOT_DECLARED",
                "criticality_source": "declared",
                "criticality_used": "medium",
            },
        )
        == []
    )


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
        "verdict",
        "stage",
        "deployment_stage",
        "search",
        "include_project_summary",
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
    assert "503" in operation["responses"]


# ---------------------------------------------------------------------------
# New filters: verdict / stage / deployment_stage / search / include_project_summary
# ---------------------------------------------------------------------------


def _fleet_param(name: str) -> dict[str, Any]:
    params = {
        p["name"]: p for p in _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["parameters"]
    }
    return params[name]


def _fleet_param_ref(parameter: dict[str, Any]) -> str:
    file_part, fragment = parameter["schema"]["items"]["$ref"].split("#", 1)
    target = (ENDPOINTS_PATH.parent / file_part).resolve()
    return f"{_load(target)['$id']}#{fragment}"


@pytest.mark.parametrize(
    ("name", "accepted", "rejected"),
    [
        (
            "verdict",
            ["NOT_YET_SCORED", "CANT_TELL", "STAY", "INTERVENE_QUALITY"],
            ["not_yet_scored", "MAYBE", ""],
        ),
        (
            "stage",
            ["NO_RUNS", "RUNS_RECORDED", "EVALUATION_COMPLETED"],
            ["no_runs", "IN_PROGRESS", ""],
        ),
        (
            "deployment_stage",
            ["development", "staging", "production", "testing"],
            ["prod", "deployed", "PRODUCTION", ""],
        ),
    ],
)
def test_fleet_posture_repeatable_filters_are_form_explode_arrays_with_exact_enums(
    name: str, accepted: list[str], rejected: list[str]
) -> None:
    """verdict/stage/deployment_stage are repeatable (style=form, explode=true) arrays
    whose item enum is taken EXACTLY from the existing source-of-truth schema
    definitions (never re-forked/hand-copied here)."""
    parameter = _fleet_param(name)
    assert parameter["in"] == "query"
    assert parameter["required"] is False
    assert parameter["style"] == "form"
    assert parameter["explode"] is True
    assert parameter["schema"]["type"] == "array"
    ref = _fleet_param_ref(parameter)
    for value in accepted:
        assert _errors(ref, value) == [], value
    for value in rejected:
        assert _errors(ref, value), value


def test_fleet_posture_verdict_filter_items_ref_the_response_schemas_own_verdict_enum() -> None:
    parameter = _fleet_param("verdict")
    assert parameter["schema"]["items"]["$ref"] == "./fleet_posture_response_schema.json#/definitions/Verdict"
    verdict_enum = _load(RESPONSE_SCHEMA_PATH)["definitions"]["Verdict"]["enum"]
    assert set(verdict_enum) == {"NOT_YET_SCORED", "CANT_TELL", "STAY", "INTERVENE_QUALITY"}


def test_fleet_posture_stage_filter_items_ref_the_common_process_stage_enum() -> None:
    parameter = _fleet_param("stage")
    assert parameter["schema"]["items"]["$ref"] == "./agent_readiness_common_schema.json#/definitions/ProcessStage"
    stage_enum = _load(READINESS / "agent_readiness_common_schema.json")["definitions"]["ProcessStage"]["enum"]
    assert set(stage_enum) == {"NO_RUNS", "RUNS_RECORDED", "EVALUATION_COMPLETED"}


def test_fleet_posture_deployment_stage_filter_items_ref_the_agent_posture_deployment_stage() -> None:
    parameter = _fleet_param("deployment_stage")
    assert parameter["schema"]["items"]["$ref"] == "./agent_posture_schema.json#/definitions/DeploymentStage"
    # DeploymentStage itself $refs agents/agent_deployment_schema.json#/definitions/Environment
    # (agent_posture_schema.json) -- never forked -- so resolve one hop further for the enum.
    deployment_stage = _load(READINESS / "agent_posture_schema.json")["definitions"]["DeploymentStage"]
    assert "enum" not in deployment_stage, "DeploymentStage must reference, not fork, the enum"
    environment_enum = _load(SCHEMAS / "agents" / "agent_deployment_schema.json")["definitions"][
        "Environment"
    ]["enum"]
    assert set(environment_enum) == {"development", "staging", "production", "testing"}


def test_fleet_posture_search_param_is_a_bounded_singleton_string() -> None:
    """The machine schema enforces exactly one rule (maxLength: 200 on the RAW
    value, no minLength) so it never contradicts the trim/blank-is-absent prose:
    a raw empty string is schema-valid (and semantically absent, not a filter),
    a raw 200-char value is schema-valid, and only a raw value over 200 chars is
    a 400 -- independent of how much of it is whitespace."""
    parameter = _fleet_param("search")
    assert parameter["in"] == "query"
    assert parameter["required"] is False
    assert "style" not in parameter and "explode" not in parameter
    assert parameter["schema"] == {"type": "string", "maxLength": 200}
    for phrase in (
        "trim", "casefold", "literal", "wildcard", "AND", "pagination", "400",
        "blank", "absent",
    ):
        assert phrase.lower() in parameter["description"].lower(), phrase
    validator = Draft7Validator(parameter["schema"])
    assert validator.is_valid("")
    assert validator.is_valid("   ")
    assert validator.is_valid("x" * 200)
    assert not validator.is_valid("x" * 201)


def test_fleet_posture_include_project_summary_param_is_boolean_default_false() -> None:
    parameter = _fleet_param("include_project_summary")
    assert parameter["in"] == "query"
    assert parameter["required"] is False
    assert parameter["schema"] == {"type": "boolean", "default": False}
    for phrase in ("independent of every filter", "agent_id", "identical whether"):
        assert phrase in parameter["description"], phrase


def test_fleet_posture_new_filters_apply_before_pagination_and_state_and_or_semantics() -> None:
    description = _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["description"]
    for phrase in (
        "BEFORE pagination",
        "OR within",
        "AND",
        "REJECTED",
        "never echoed",
        "agent_id no-existence-oracle",
        "de-duplicated",
        "ENHANCED PATH",
    ):
        assert phrase in description, phrase


def test_fleet_posture_operation_documents_ordering_with_backend_file_and_tiebreaker() -> None:
    """Pinned against the Backend's actual ordering (read from origin/develop, not a
    parked checkout): AgentReadinessService.list_portfolio orders by stage_rank asc,
    last_activity asc nullsfirst, agent_id asc (agent_readiness_service.py:1143-1145 and
    the page-window pass at :1222-1224); fleet_posture_service.get_fleet_posture calls
    list_portfolio directly, so fleet-posture rows share this exact ordering + tiebreaker."""
    description = _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["description"]
    for phrase in (
        "list_portfolio",
        "agent_readiness_service.py",
        "stage ascending",
        "last-activity ascending",
        "nulls first",
        "agent_id ascending",
        "tiebreaker",
    ):
        assert phrase in description, phrase


def test_fleet_posture_enhanced_path_definition_excludes_blank_search_and_false_flag() -> None:
    """The enhanced path (and its 500-agent bound) must NOT fire for a blank/absent
    search or an explicit include_project_summary=false -- only for verdict/stage/
    deployment_stage presence, a non-blank search, or include_project_summary=true."""
    description = _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["description"]
    assert "ENHANCED PATH" in description
    assert "non-blank" in description
    assert "blank/whitespace-only search" in description
    assert "include_project_summary=false" in description
    assert "page-only path" in description


def test_fleet_posture_service_unavailable_documents_both_triggers_and_uses_a_local_envelope() -> None:
    """The 503 body is FLEET-POSTURE-LOCAL (FleetPostureUnavailable), NOT the shared
    agent_readiness_error_schema.json: that file is shared across agent_readiness/
    agent_posture/evaluation_system_validation routes, so widening its closed oneOf/
    enums for one route's 503 would widen every OTHER route's 400/401/403 too (and
    error_code: 'service_unavailable' would break its UPPER_SNAKE error_code
    convention). This route's 400/401/403 keep $ref-ing that shared schema unchanged
    (see test_fleet_posture_route_is_registered_correctly) -- verified structurally,
    not via a live git-diff against a ref this suite cannot rely on always having
    fetched."""
    response = _load(ENDPOINTS_PATH)["paths"][ROUTE]["get"]["responses"]["503"]
    description = response["description"]
    assert "500" in description
    assert "truncat" in description.lower()
    for phrase in (
        "verdict", "stage", "deployment_stage", "search", "include_project_summary",
        "non-archived", "computation failure", "never partial", "page-only path",
        "FleetPostureUnavailable",
    ):
        assert phrase in description, phrase
    assert "not the shared" in description.lower()
    assert response["content"]["application/json"]["schema"]["$ref"] == (
        "./fleet_posture_response_schema.json#/definitions/FleetPostureUnavailable"
    )
    # The body must actually validate against the NEW local envelope as a real variant.
    body = {
        "success": False,
        "message": "Service unavailable",
        "error": "service_unavailable",
        "error_code": "FLEET_POSTURE_UNAVAILABLE",
    }
    assert _errors(
        "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#/definitions/FleetPostureUnavailable",
        body,
    ) == []
    # And error_code follows the shared envelope's UPPER_SNAKE convention for a
    # route-specific code (PROJECT_ACCESS_DENIED, TENANT_NOT_FOUND, ...).
    assert body["error_code"].isupper()


# ---------------------------------------------------------------------------
# project_summary (opt-in, project-wide, filter-independent verdict totals)
# ---------------------------------------------------------------------------


def test_project_summary_and_summary_both_ref_fleet_summary_directly() -> None:
    """Minimised restructuring (sol review round 2): FleetSummary is back to its
    ORIGINAL concrete closed shape (only its description became scope-neutral); no
    VerdictTotals/ProjectSummary split, no allOf indirection, so this repo's own
    breaking-change differ sees the exact same type/required/additionalProperties
    it always did. Both summary and project_summary $ref FleetSummary directly,
    each with its own scope-stating sibling description."""
    schema = _load(RESPONSE_SCHEMA_PATH)
    assert "project_summary" not in schema["required"]
    assert schema["properties"]["summary"]["$ref"] == "#/definitions/FleetSummary"
    assert schema["properties"]["project_summary"]["$ref"] == "#/definitions/FleetSummary"
    assert "description" in schema["properties"]["summary"]
    assert "description" in schema["properties"]["project_summary"]
    assert "ProjectSummary" not in schema["definitions"]
    assert "VerdictTotals" not in schema["definitions"]
    fleet_summary_def = schema["definitions"]["FleetSummary"]
    assert fleet_summary_def["type"] == "object"
    assert fleet_summary_def["additionalProperties"] is False
    assert set(fleet_summary_def["required"]) == {"total", "counts_by_verdict"}
    assert "allOf" not in fleet_summary_def
    counts = fleet_summary_def["properties"]["counts_by_verdict"]
    assert counts["additionalProperties"] is False
    assert set(counts["required"]) == {
        "NOT_YET_SCORED", "CANT_TELL", "STAY", "INTERVENE_QUALITY",
    }


def test_fleet_summary_description_is_scope_neutral_and_documents_both_scopes() -> None:
    """FleetSummary's own description no longer claims there is NO project-wide
    equivalent (that became false once project_summary shipped); it now states the
    sum invariant and defers scope entirely to the referencing property."""
    description = _load(RESPONSE_SCHEMA_PATH)["definitions"]["FleetSummary"]["description"]
    assert "there is no" not in description.lower()
    assert "sum" in description.lower()
    for phrase in ("summary", "project_summary"):
        assert phrase in description, phrase
    assert "referencing property" in description.lower()


def test_project_summary_property_description_states_the_independent_scope_invariant() -> None:
    description = _load(RESPONSE_SCHEMA_PATH)["properties"]["project_summary"]["description"]
    for phrase in (
        "independent of every filter",
        "agent_id",
        "summary",
        "500",
        "computation failure",
    ):
        assert phrase in description, phrase
    assert "identical whether" in description.lower()
    assert "never partial" in description.lower()


def test_summary_property_description_states_the_page_scope() -> None:
    description = _load(RESPONSE_SCHEMA_PATH)["properties"]["summary"]["description"]
    assert "page" in description.lower()
    assert "project_summary" in description
    assert "pagination.total" in description


def test_project_summary_fixture_case_counts_sum_to_total() -> None:
    case = next(
        c
        for c in _CASES
        if c["name"] == "fleet_posture_response_valid_with_project_summary"
    )
    project_summary = case["instance"]["project_summary"]
    assert sum(project_summary["counts_by_verdict"].values()) == project_summary["total"]
    assert _errors(
        "https://schemas.traigent.ai/agent_readiness/fleet_posture_response_schema.json#",
        case["instance"],
    ) == []


@pytest.mark.parametrize(
    "case_name",
    [
        "fleet_posture_response_invalid_project_summary_missing_verdict_key",
        "fleet_posture_response_invalid_project_summary_extra_verdict_key",
        "fleet_posture_response_invalid_project_summary_negative_count",
    ],
)
def test_project_summary_malformed_fixture_cases_fail_validation(case_name: str) -> None:
    case = next(c for c in _CASES if c["name"] == case_name)
    assert case["valid"] is False
    assert _errors(case["schema_ref"], case["instance"])


# ---------------------------------------------------------------------------
# sum(counts_by_verdict) == total invariant (documented, not JSON-Schema-expressible)
# ---------------------------------------------------------------------------

# JSON Schema cannot state "total equals the sum of these four fields", so the schema
# accepts a mismatched total (a probe confirmed zero validation errors for
# total=999 with every count 0). This fixture is intentionally SCHEMA-VALID
# (case["valid"] is True) but is a KNOWN VIOLATION of the documented invariant; the
# dedicated test below -- not JSON Schema -- is what must catch it.
_SUM_INVARIANT_KNOWN_VIOLATIONS = frozenset(
    {"fleet_posture_response_schema_valid_but_summary_total_mismatches_sum"}
)


def _summary_like_objects(instance: Any) -> list[dict[str, Any]]:
    """Extract every {total, counts_by_verdict}-shaped object reachable from a
    fixture instance: the instance itself (a direct FleetSummary-ref case), or its
    summary/project_summary members (a root response case)."""
    if not isinstance(instance, dict):
        return []
    if "counts_by_verdict" in instance and "total" in instance:
        return [instance]
    found = []
    if isinstance(instance.get("summary"), dict):
        found.append(instance["summary"])
    if isinstance(instance.get("project_summary"), dict):
        found.append(instance["project_summary"])
    return found


def test_summary_and_project_summary_counts_sum_to_total_for_every_valid_fixture() -> None:
    checked = 0
    for case in _CASES:
        if not case["valid"]:
            continue
        for summary in _summary_like_objects(case["instance"]):
            checked += 1
            matches = sum(summary["counts_by_verdict"].values()) == summary["total"]
            if case["name"] in _SUM_INVARIANT_KNOWN_VIOLATIONS:
                assert not matches, (case["name"], "expected a known sum-mismatch")
            else:
                assert matches, (case["name"], summary)
    # Sanity: the loop actually exercised real fixtures, and the known-violation
    # fixture exists and was reached (a typo'd name would silently check nothing).
    assert checked >= 10
    assert _SUM_INVARIANT_KNOWN_VIOLATIONS <= {c["name"] for c in _CASES if c["valid"]}


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


def test_no_match_agent_id_with_project_summary_keeps_legacy_shape_but_populates_project_summary() -> None:
    """sol review item 5: an unknown/inaccessible agent_id combined with
    include_project_summary=true must keep the EXACT documented no-match legacy shape
    (agents/failed_agent_ids/validate_first empty, summary all-zero, pagination
    0/0) while project_summary is independently populated -- proving its scope truly
    does not depend on whether agent_id matched."""
    case = next(
        c
        for c in _CASES
        if c["name"] == "fleet_posture_response_valid_agent_id_no_match_with_project_summary"
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
    project_summary = instance["project_summary"]
    assert project_summary["total"] > 0
    assert sum(project_summary["counts_by_verdict"].values()) == project_summary["total"]
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
