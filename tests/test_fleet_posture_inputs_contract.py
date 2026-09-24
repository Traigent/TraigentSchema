"""Contract tests for the three fleet-posture inputs (E1, E4, E5).

See business/product-personas/fleet-posture-census.md ("Smallest extensions")
and the 2026-09-24 owner rulings in fleet-spec-merged.md:

- E1: the readiness portfolio item carries the anchor run's evaluation-dataset
  ref, evaluator-version ref, accuracy (+ its sample count) and reported
  example-evaluation count, so the fleet view needs no per-agent detail fetch.
- E4: a manager-set Agent posture (deployment_stage reusing the
  agent_deployment Environment enum, criticality {low, medium, high}) written
  as immutable revisions and read on the portfolio item and detail response.
- E5: the team target-revision contract gains an accuracy metric whose named
  confidence-interval bound must clear a proportion threshold.
"""

from __future__ import annotations

import importlib.util
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
POSTURE_SCHEMA_PATH = READINESS / "agent_posture_schema.json"
POSTURE_ENDPOINTS_PATH = READINESS / "agent_posture_endpoints.json"
TARGET_SCHEMA_PATH = READINESS / "agent_readiness_target_schema.json"
READINESS_ENDPOINTS_PATH = READINESS / "agent_readiness_endpoints.json"
PORTFOLIO_SCHEMA_PATH = READINESS / "agent_readiness_portfolio_response_schema.json"
DETAIL_SCHEMA_PATH = READINESS / "agent_readiness_detail_response_schema.json"
COMMON_SCHEMA_PATH = READINESS / "agent_readiness_common_schema.json"
DEPLOYMENT_SCHEMA_PATH = SCHEMAS / "agents" / "agent_deployment_schema.json"
CASES_PATH = (
    Path(__file__).parent / "data" / "agent_readiness" / "fleet_posture_inputs_cases.json"
)
SCHEMA_ID_BASE = "https://schemas.traigent.ai/"

E1_MEMBERS = (
    "anchor_evaluation_dataset_ref",
    "anchor_evaluator_version_ref",
    "anchor_accuracy",
    "anchor_accuracy_sample_count",
    "anchor_reported_example_evaluations",
)


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


def _readiness_fixtures() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_agent_readiness_contract_fixtures",
        Path(__file__).parent / "test_agent_readiness_contract.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_FIXTURES = _readiness_fixtures()
PORTFOLIO = "agent_readiness_portfolio_response_schema"
DETAIL = "agent_readiness_detail_response_schema"


def _portfolio() -> dict[str, Any]:
    return _FIXTURES._portfolio_payload()


def _detail() -> dict[str, Any]:
    return _FIXTURES._detail_payload()


def _anchored_portfolio() -> dict[str, Any]:
    portfolio = _portfolio()
    item = portfolio["items"][0]
    item.update(
        anchor_run_id="run-anchor",
        anchor_experiment_id="experiment-anchor",
        anchor_completed_at="2026-09-19T23:00:00Z",
        next_action_experiment_id="experiment-anchor",
        next_action_run_id="run-anchor",
        next_action_code="REVIEW_RECORDED_EVIDENCE",
        attention_state="NO_PORTAL_ACTION",
        anchor_evaluation_dataset_ref={"kind": "evaluation_dataset", "id": "dataset-v1"},
        anchor_evaluator_version_ref={"kind": "evaluator_version", "id": "eval-v1"},
        anchor_accuracy={
            "kind": "ACCURACY",
            "value": 0.91,
            "unit": "UNIT_NOT_RECORDED",
            "source_key": "accuracy.mean",
            "observation_basis": "client_reported",
        },
        anchor_accuracy_sample_count=400,
        anchor_reported_example_evaluations=400,
    )
    item["process"]["stage"] = "EVALUATION_COMPLETED"
    return portfolio


def _valid(payload: dict[str, Any], schema: str) -> list[str]:
    return SchemaValidator().validate_json(payload, schema)


def _declared_posture() -> dict[str, Any]:
    return {
        "state": "DECLARED",
        "revision": {
            "revision_id": "posture-rev-1",
            "previous_revision_id": None,
            "agent_id": "agent-1",
            "deployment_stage": "production",
            "criticality": "high",
            "declared_by": {"principal_kind": "USER", "principal_ref": "user-7"},
            "declared_at": "2026-09-24T10:00:00Z",
        },
    }


def _case(name: str) -> dict[str, Any]:
    return next(case for case in _load(CASES_PATH)["cases"] if case["name"] == name)


# ---------------------------------------------------------------------------
# Fixture corpus (valid + invalid)
# ---------------------------------------------------------------------------


_CASES = _load(CASES_PATH)["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_fixture_case_matches_expected_outcome(case: dict[str, Any]) -> None:
    errors = _errors(case["schema_ref"], case["instance"])
    if case["valid"]:
        assert errors == [], (case["why"], errors)
    else:
        assert errors, case["why"]


def test_fixture_corpus_covers_valid_and_invalid_for_every_contract() -> None:
    by_ref: dict[str, set[bool]] = {}
    for case in _CASES:
        by_ref.setdefault(case["schema_ref"].split("#/definitions/")[1], set()).add(
            case["valid"]
        )
    for definition in (
        "PostureDeclarationRequest",
        "DeclaredPosture",
        "AgentPosture",
        "TargetDeclarationRequest",
        "DeclaredAccuracyTarget",
    ):
        assert by_ref[definition] == {True, False}, definition


def test_new_schemas_are_valid_draft7_and_discoverable() -> None:
    validator = SchemaValidator()
    for path in (POSTURE_SCHEMA_PATH, TARGET_SCHEMA_PATH):
        Draft7Validator.check_schema(_load(path))
        assert path.stem in validator.available_schemas


# ---------------------------------------------------------------------------
# E1: anchor refs on the portfolio item
# ---------------------------------------------------------------------------


def test_e1_members_are_optional_so_the_backend_can_roll_out_independently() -> None:
    portfolio = _portfolio()
    assert not set(E1_MEMBERS) & set(portfolio["items"][0])
    assert _valid(portfolio, PORTFOLIO) == []
    required = _load(PORTFOLIO_SCHEMA_PATH)["properties"]["items"]["items"]["required"]
    assert not set(E1_MEMBERS) & set(required)


def test_e1_anchored_item_with_all_members_is_valid() -> None:
    assert _valid(_anchored_portfolio(), PORTFOLIO) == []


def test_e1_members_are_null_on_an_unanchored_item() -> None:
    portfolio = _portfolio()
    portfolio["items"][0].update({member: None for member in E1_MEMBERS})
    assert _valid(portfolio, PORTFOLIO) == []

    anchored_values = _anchored_portfolio()["items"][0]
    for member in E1_MEMBERS:
        portfolio = _portfolio()
        portfolio["items"][0].update({m: None for m in E1_MEMBERS})
        portfolio["items"][0][member] = anchored_values[member]
        assert _valid(portfolio, PORTFOLIO), member

    portfolio = _portfolio()
    portfolio["items"][0].update({m: None for m in E1_MEMBERS})
    portfolio["items"][0]["anchor_accuracy"] = anchored_values["anchor_accuracy"]
    portfolio["items"][0]["anchor_accuracy_sample_count"] = 400
    assert _valid(portfolio, PORTFOLIO)


def test_e1_members_are_emitted_together_or_not_at_all() -> None:
    for member in E1_MEMBERS:
        portfolio = _anchored_portfolio()
        del portfolio["items"][0][member]
        assert _valid(portfolio, PORTFOLIO), member


def test_e1_sample_count_requires_a_mean_accuracy() -> None:
    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_accuracy"] = None
    assert _valid(portfolio, PORTFOLIO)

    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_accuracy"]["source_key"] = "accuracy"
    assert _valid(portfolio, PORTFOLIO)

    portfolio["items"][0]["anchor_accuracy_sample_count"] = None
    assert _valid(portfolio, PORTFOLIO) == []

    # Reverse direction (review nit 4): an accuracy.mean value needs its count.
    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_accuracy_sample_count"] = None
    assert _valid(portfolio, PORTFOLIO)

    for count in (0, -1, 1.5, "400"):
        portfolio = _anchored_portfolio()
        portfolio["items"][0]["anchor_accuracy_sample_count"] = count
        assert _valid(portfolio, PORTFOLIO), count


def test_e1_refs_and_accuracy_reuse_the_detail_and_common_shapes() -> None:
    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_evaluation_dataset_ref"]["kind"] = "evaluator_version"
    assert _valid(portfolio, PORTFOLIO)

    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_evaluator_version_ref"]["kind"] = "evaluation_dataset"
    assert _valid(portfolio, PORTFOLIO)

    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_accuracy"].update(
        kind="COST", unit="USD", source_key="cost_usd"
    )
    portfolio["items"][0]["anchor_accuracy_sample_count"] = None
    assert _valid(portfolio, PORTFOLIO)

    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_accuracy"]["observation_basis"] = "backend_observed"
    assert _valid(portfolio, PORTFOLIO)

    portfolio = _anchored_portfolio()
    portfolio["items"][0]["anchor_reported_example_evaluations"] = -1
    assert _valid(portfolio, PORTFOLIO)

    item = _load(PORTFOLIO_SCHEMA_PATH)["properties"]["items"]["items"]["properties"]
    assert item["anchor_evaluation_dataset_ref"]["oneOf"][0]["$ref"].endswith(
        "agent_readiness_detail_response_schema.json#/definitions/EvaluationDatasetRef"
    )
    assert item["anchor_evaluator_version_ref"]["oneOf"][0]["$ref"].endswith(
        "agent_readiness_detail_response_schema.json#/definitions/EvaluatorVersionRef"
    )
    assert item["anchor_accuracy"]["oneOf"][0]["$ref"].endswith(
        "agent_readiness_common_schema.json#/definitions/AccuracyMetric"
    )


# ---------------------------------------------------------------------------
# E4: manager-set agent posture
# ---------------------------------------------------------------------------


def test_e4_deployment_stage_reuses_the_agent_deployment_environment_enum() -> None:
    stage = _load(POSTURE_SCHEMA_PATH)["definitions"]["DeploymentStage"]
    assert stage["$ref"] == (
        "https://schemas.traigent.ai/agents/agent_deployment_schema.json"
        "#/definitions/Environment"
    )
    assert "enum" not in stage, "DeploymentStage must reference, not fork, the enum"
    environment = _load(DEPLOYMENT_SCHEMA_PATH)["definitions"]["Environment"]["enum"]
    ref = "https://schemas.traigent.ai/agent_readiness/agent_posture_schema.json#/definitions/DeploymentStage"
    for value in environment:
        assert _errors(ref, value) == []
    assert _errors(ref, "deployed")


def test_e4_criticality_is_the_owner_ruled_vocabulary() -> None:
    criticality = _load(POSTURE_SCHEMA_PATH)["definitions"]["Criticality"]
    assert criticality["enum"] == ["low", "medium", "high"]


def test_e4_posture_is_optional_for_rollout_but_validated_when_present() -> None:
    # Optional until TraigentBackend emits it, so unrelated Backend schema-pin
    # bumps keep validating today's bodies (review nit 1).
    assert "agent_posture" not in (
        _load(PORTFOLIO_SCHEMA_PATH)["properties"]["items"]["items"]["required"]
    )
    assert "agent_posture" not in _load(DETAIL_SCHEMA_PATH)["required"]
    for schema_path in (PORTFOLIO_SCHEMA_PATH, DETAIL_SCHEMA_PATH):
        assert "becomes required once TraigentBackend emits it" in json.dumps(
            _load(schema_path)
        )

    portfolio = _portfolio()
    portfolio["items"][0]["agent_posture"] = _declared_posture()
    assert _valid(portfolio, PORTFOLIO) == []
    del portfolio["items"][0]["agent_posture"]
    assert _valid(portfolio, PORTFOLIO) == []
    portfolio["items"][0]["agent_posture"] = {"state": "DECLARED"}
    assert _valid(portfolio, PORTFOLIO)

    detail = _detail()
    detail["agent_posture"] = _declared_posture()
    assert _valid(detail, DETAIL) == []
    del detail["agent_posture"]
    assert _valid(detail, DETAIL) == []
    detail["agent_posture"] = {"state": "UNKNOWN"}
    assert _valid(detail, DETAIL)


def test_e4_undeclared_posture_fails_closed_to_high_criticality() -> None:
    description = _load(POSTURE_SCHEMA_PATH)["definitions"]["AgentPosture"]["description"]
    assert "MUST treat an Agent with NONE_DECLARED" in description
    assert "criticality high" in description


def test_e4_read_rejects_client_shaped_or_api_key_posture() -> None:
    posture = _declared_posture()
    posture["revision"]["declared_by"]["principal_kind"] = "API_KEY"
    detail = _detail()
    detail["agent_posture"] = posture
    assert _valid(detail, DETAIL)

    detail = _detail()
    detail["agent_posture"] = {"state": "DECLARED", "deployment_stage": "production"}
    assert _valid(detail, DETAIL)


def test_e4_posture_write_follows_the_target_revision_convention() -> None:
    endpoints = _load(POSTURE_ENDPOINTS_PATH)
    readiness = _load(READINESS_ENDPOINTS_PATH)
    posture_path = (
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/posture-revisions"
    )
    target_path = (
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/target-revisions"
    )
    assert set(endpoints["paths"]) == {posture_path}
    assert posture_path.rsplit("/", 1)[0] == target_path.rsplit("/", 1)[0]
    operation = endpoints["paths"][posture_path]["post"]
    target_operation = readiness["paths"][target_path]["post"]
    assert set(endpoints["paths"][posture_path]) == {"post"}
    assert operation["x-asserted-against-backend"] is False
    assert operation["requestBody"]["content"]["application/json"]["schema"][
        "$ref"
    ] == "./agent_posture_schema.json#/definitions/PostureDeclarationRequest"
    assert operation["responses"]["201"]["content"]["application/json"]["schema"][
        "$ref"
    ] == "./agent_posture_schema.json#/definitions/DeclaredPosture"
    assert set(operation["responses"]) == set(target_operation["responses"])
    conflict = operation["responses"]["409"]["content"]["application/json"]["schema"]
    assert conflict["additionalProperties"] is False
    assert conflict["properties"]["error_code"] == {"const": "revision_conflict"}
    forbidden = operation["responses"]["403"]["description"].lower()
    assert "human session" in forbidden
    assert "owner" in forbidden and "admin" in forbidden
    assert "api-key" in forbidden

    root = _load(SCHEMAS / "mep_endpoints.json")
    modules = [
        module
        for module in root["x-endpoint-modules"]
        if module.get("paths_file") == "./agent_readiness/agent_posture_endpoints.json"
    ]
    assert len(modules) == 1


def _request_ref(endpoints_path: Path, path: str) -> str:
    """Resolve an endpoint's relative requestBody $ref to its absolute schema URI."""
    relative = _load(endpoints_path)["paths"][path]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["$ref"]
    file_part, fragment = relative.split("#", 1)
    target = (endpoints_path.parent / file_part).resolve()
    return f"{_load(target)['$id']}#{fragment}"


def test_e4_posture_route_request_body_resolves_and_rejects_server_fields() -> None:
    ref = _request_ref(
        POSTURE_ENDPOINTS_PATH,
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/posture-revisions",
    )
    assert _errors(ref, _case("posture_request_first_declaration")["instance"]) == []
    assert _errors(ref, _case("posture_request_client_declared_by")["instance"])


_LIST_PATH = "/api/v1beta/projects/{project_id}/agent-readiness"


def _list_parameter(name: str) -> dict[str, Any]:
    parameters = _load(READINESS_ENDPOINTS_PATH)["paths"][_LIST_PATH]["get"]["parameters"]
    matches = [parameter for parameter in parameters if parameter["name"] == name]
    assert len(matches) == 1, name
    return matches[0]


def _parameter_ref(parameter: dict[str, Any]) -> str:
    file_part, fragment = parameter["schema"]["$ref"].split("#", 1)
    target = (READINESS_ENDPOINTS_PATH.parent / file_part).resolve()
    return f"{_load(target)['$id']}#{fragment}"


@pytest.mark.parametrize(
    ("name", "definition", "accepted", "rejected"),
    [
        (
            "deployment_stage",
            "DeploymentStage",
            ["development", "staging", "production", "testing"],
            ["prod", "deployed", "PRODUCTION", ""],
        ),
        ("criticality", "Criticality", ["low", "medium", "high"], ["critical", "HIGH", ""]),
    ],
)
def test_e4_portfolio_list_filters_by_posture(
    name: str, definition: str, accepted: list[str], rejected: list[str]
) -> None:
    parameter = _list_parameter(name)
    stage = _list_parameter("stage")
    assert parameter["in"] == stage["in"] == "query"
    assert parameter["required"] is False
    # Same single-value convention as the existing stage/attention filters.
    assert set(parameter["schema"]) == {"$ref"}
    assert parameter["schema"]["$ref"] == (
        f"./agent_posture_schema.json#/definitions/{definition}"
    )
    ref = _parameter_ref(parameter)
    for value in accepted:
        assert _errors(ref, value) == [], value
    for value in rejected:
        assert _errors(ref, value), value
    list_bad_request = _load(READINESS_ENDPOINTS_PATH)["paths"][_LIST_PATH]["get"][
        "responses"
    ]["400"]["description"]
    assert name in list_bad_request


# ---------------------------------------------------------------------------
# E5: accuracy target on the team target-revision contract
# ---------------------------------------------------------------------------


def test_e5_accuracy_metric_reuses_the_readiness_accuracy_vocabulary() -> None:
    target = _load(TARGET_SCHEMA_PATH)["definitions"]
    common = _load(COMMON_SCHEMA_PATH)["definitions"]
    accuracy_branch = next(
        branch
        for branch in common["ReportedMetric"]["oneOf"]
        if branch["properties"]["kind"] == {"const": "ACCURACY"}
    )
    source_key = target["AccuracyRequirement"]["properties"]["source_key"]["const"]
    assert source_key in accuracy_branch["properties"]["source_key"]["enum"]
    assert source_key == "accuracy.mean"
    assert target["AccuracyRequirement"]["properties"]["metric_id"] == {
        "const": "SDK_MEAN_ACCURACY"
    }
    assert target["AccuracyRequirement"]["properties"]["comparison"] == {
        "const": "at_least"
    }
    assert target["AccuracyRequirement"]["properties"]["clearing_ci_bound"]["enum"] == [
        "lower"
    ]
    assert target["AccuracyRequirementDeclaration"]["properties"]["clearing_ci_bound"][
        "enum"
    ] == ["lower"]


def test_e5_latency_target_shape_is_unchanged() -> None:
    target = _load(TARGET_SCHEMA_PATH)["definitions"]
    latency = target["DeclaredLatencyTarget"]
    assert latency["properties"]["revision"] == {"$ref": "#/definitions/TargetRevision"}
    assert latency["properties"]["evaluation"] == {"$ref": "#/definitions/Evaluation"}
    assert target["TargetRevision"]["properties"]["requirement"] == {
        "$ref": "#/definitions/LatencyRequirement"
    }
    ref = (
        "https://schemas.traigent.ai/agent_readiness/agent_readiness_target_schema.json"
        "#/definitions/TargetDeclarationRequest"
    )
    assert _errors(ref, _case("target_request_latency_unchanged")["instance"]) == []


def test_e5_detail_keeps_latency_and_accuracy_chains_separate() -> None:
    declared_accuracy = _case("declared_accuracy_target_met")["instance"]

    detail = _detail()
    detail["team_accuracy_requirement"] = declared_accuracy
    assert _valid(detail, DETAIL) == []

    detail = _detail()
    detail["team_requirement"] = declared_accuracy
    assert _valid(detail, DETAIL)

    detail = _detail()
    del detail["team_accuracy_requirement"]
    assert _valid(detail, DETAIL) == []  # optional for rollout (review nit 1)
    assert "team_accuracy_requirement" not in _load(DETAIL_SCHEMA_PATH)["required"]


def _declared_latency_target() -> dict[str, Any]:
    accuracy = _case("declared_accuracy_target_met")["instance"]
    revision = {
        **accuracy["revision"],
        "revision_id": "lat-rev-1",
        "requirement": {
            "metric_id": "SDK_MEAN_RESPONSE_TIME",
            "source_key": "response_time_ms.mean",
            "unit": "MILLISECONDS",
            "direction": "minimize",
            "comparison": "at_most",
            "threshold_ms": "1500",
            "accepted_observation_basis": "client_reported",
        },
    }
    evaluation = {
        "result": "MET",
        "reason_codes": [],
        "source_run_id": "run-anchor",
        "source_configuration_run_id": "config-1",
        "observed_value_ms": "900",
        "unit": "MILLISECONDS",
        "observation_basis": "client_reported",
        "observed_count": 400,
        "evaluated_at": "2026-09-24T10:00:01Z",
    }
    return {"state": "DECLARED", "revision": revision, "evaluation": evaluation}


def test_e5_accuracy_slot_rejects_a_latency_target() -> None:
    latency = _declared_latency_target()
    detail = _detail()
    detail["team_requirement"] = latency
    assert _valid(detail, DETAIL) == []  # control: the latency target is well-formed

    detail = _detail()
    detail["team_accuracy_requirement"] = latency
    assert _valid(detail, DETAIL)


def test_e5_evaluation_confidence_level_is_exactly_095_and_method_is_closed() -> None:
    ref = (
        "https://schemas.traigent.ai/agent_readiness/agent_readiness_target_schema.json"
        "#/definitions/AccuracyEvaluation"
    )
    met = _case("declared_accuracy_target_met")["instance"]["evaluation"]
    assert _errors(ref, met) == []
    for value in ("0.9", "0.950", "95", 0.95, None):
        assert _errors(ref, {**met, "confidence_level": value}), value
    for value in ("bootstrap", "wilson", None):
        assert _errors(ref, {**met, "ci_method": value}), value
    description = _load(TARGET_SCHEMA_PATH)["definitions"]["AccuracyEvaluation"][
        "properties"
    ]["ci_method"]["description"]
    assert "never client-supplied" in description


def test_target_schema_root_lists_every_revision_shape() -> None:
    root = [branch["$ref"] for branch in _load(TARGET_SCHEMA_PATH)["oneOf"]]
    assert "#/definitions/AccuracyTargetRevision" in root
    assert "#/definitions/TargetRevision" in root
    accuracy_revision = _case("declared_accuracy_target_met")["instance"]["revision"]
    assert _valid(accuracy_revision, "agent_readiness_target_schema") == []


def test_e5_target_route_accepts_accuracy_and_still_answers_declared_target() -> None:
    readiness = _load(READINESS_ENDPOINTS_PATH)
    operation = readiness["paths"][
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/target-revisions"
    ]["post"]
    assert operation["x-asserted-against-backend"] is False
    assert operation["responses"]["201"]["content"]["application/json"]["schema"][
        "$ref"
    ].endswith("#/definitions/DeclaredTarget")
    ref = _request_ref(
        READINESS_ENDPOINTS_PATH,
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/target-revisions",
    )
    assert _errors(ref, _case("target_request_accuracy")["instance"]) == []
    assert _errors(ref, _case("target_request_latency_unchanged")["instance"]) == []
    assert _errors(ref, _case("target_request_accuracy_middle_bound")["instance"])


def test_e5_met_and_not_met_need_the_interval_and_its_count() -> None:
    ref = (
        "https://schemas.traigent.ai/agent_readiness/agent_readiness_target_schema.json"
        "#/definitions/AccuracyEvaluation"
    )
    met = _case("declared_accuracy_target_met")["instance"]["evaluation"]
    for result in ("MET", "NOT_MET"):
        evaluation = {**met, "result": result}
        assert _errors(ref, evaluation) == []
        for member in ("observed_value", "ci_lower", "ci_upper", "observed_count"):
            assert _errors(ref, {**evaluation, member: None}), (result, member)
        assert _errors(ref, {**evaluation, "source_configuration_run_id": None})
        assert _errors(ref, {**evaluation, "observation_basis": None})


# ---------------------------------------------------------------------------
# Closedness over the new / changed documents
# ---------------------------------------------------------------------------


def test_new_objects_are_closed_and_carry_no_content_names() -> None:
    forbidden = {
        "prompt",
        "output",
        "results",
        "measures",
        "metadata",
        "payload",
        "score",
        "notes",
        "note",
        "reason",
        "recommendation",
    }

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                if "oneOf" in node and "properties" not in node:
                    # A typed union wrapper delegates closedness to its branches:
                    # each must be a $ref (walked where defined) or closed inline.
                    for branch in node["oneOf"]:
                        assert "$ref" in branch or (
                            branch.get("additionalProperties") is False
                        ), branch
                else:
                    assert node.get("additionalProperties") is False, node
            if "properties" in node:
                assert not forbidden.intersection(node["properties"]), node["properties"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(_load(POSTURE_SCHEMA_PATH))
    walk(_load(TARGET_SCHEMA_PATH))
    walk(_load(POSTURE_ENDPOINTS_PATH))

