"""Contract tests for the closed, content-free Agent readiness projection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir() / "agent_readiness"
MATRIX = Path(__file__).parent / "data" / "agent_readiness" / "check_state_matrix.json"
CHECK_IDS = {
    "AGENT_RECORD_AVAILABLE",
    "COMPLETED_EVALUATION_RUN",
    "ACCURACY_MEASURE_RECORDED",
    "UNIT_BEARING_EFFICIENCY_MEASURE_RECORDED",
    "EVALUATOR_VERSION_SNAPSHOT_RECORDED",
    "EVALUATOR_EXECUTION_LINK_ASSESSED",
    "EVALUATOR_STABILITY_ASSESSED",
    "RUN_DATASET_IDENTITY_RECORDED",
    "EVALUATED_EXAMPLE_COUNT_RECORDED",
    "DATASET_QUALITY_ASSESSMENT_RECORDED",
    "EXPERIMENT_PATH_RECORDED",
    "SELECTED_CONFIGURATION_RECORDED",
    "SELECTION_LEDGER_MATCH_ASSESSED",
}
NEXT_ACTIONS = {
    "ESTABLISH_BASELINE_EVALUATION",
    "COMPLETE_EVALUATION_RUN",
    "EVALUATE_DATASET_EXAMPLES",
    "RECORD_ACCURACY_MEASURE",
    "REVIEW_RECORDED_EVIDENCE",
}


def _check(
    check_id: str,
    state: str,
    basis: str,
    evidence_ref: dict[str, str] | None,
    observed_at: str | None = "2026-09-20T00:00:00Z",
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "state": state,
        "observation_basis": basis,
        "observed_at": observed_at,
        "evidence_ref": evidence_ref,
    }


def _summary(supported: int, gap: int, unknown: int, top_gap: str | None = None) -> dict[str, Any]:
    return {
        "coverage_state": "GAPS_RECORDED"
        if gap
        else ("CHECKS_RECORDED" if unknown == 0 else "EVIDENCE_INCOMPLETE"),
        "supported_checks": supported,
        "gap_checks": gap,
        "unknown_checks": unknown,
        "top_gap_code": top_gap,
    }


def _portfolio_payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "as_of": "2026-09-20T00:00:00Z",
        "items": [
            {
                "agent": {"id": "agent-1", "name": "Support agent", "status": "running"},
                "anchor_run_id": None,
                "anchor_completed_at": None,
                "pillars": {
                    "agent": _summary(1, 0, 3),
                    "evaluator": _summary(0, 0, 3),
                    "evaluation_dataset": _summary(0, 0, 3),
                },
                "process": {
                    "stage": "NO_RUNS",
                    "coverage_state": "EVIDENCE_INCOMPLETE",
                    "supported_checks": 0,
                    "gap_checks": 0,
                    "unknown_checks": 3,
                },
                "last_activity_at": None,
                "next_action_code": "ESTABLISH_BASELINE_EVALUATION",
            }
        ],
        "ordering": "STAGE_THEN_LEAST_RECENT_ACTIVITY",
        "pagination": {
            "page": 1,
            "per_page": 25,
            "total": 1,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        },
    }


def _detail_payload() -> dict[str, Any]:
    def unknown(check_id: str) -> dict[str, Any]:
        return _check(check_id, "UNKNOWN", "not_assessed", None, None)

    return {
        "schema_version": "1.0.0",
        "as_of": "2026-09-20T00:00:00Z",
        "agent": {"id": "agent-1", "name": "Support agent", "status": None},
        "anchor_run_id": "run-anchor",
        "anchor_completed_at": "2026-09-19T23:00:00Z",
        "agent_updated_after_anchor": True,
        "pillars": {
            "agent": {
                "coverage_state": "CHECKS_RECORDED",
                "checks": [
                    _check(
                        "AGENT_RECORD_AVAILABLE",
                        "SUPPORTED",
                        "backend_observed",
                        {"kind": "agent", "id": "agent-1"},
                    ),
                    _check(
                        "COMPLETED_EVALUATION_RUN",
                        "SUPPORTED",
                        "backend_observed",
                        {"kind": "experiment_run", "id": "run-anchor"},
                    ),
                    _check(
                        "ACCURACY_MEASURE_RECORDED",
                        "SUPPORTED",
                        "client_reported",
                        {"kind": "configuration_run", "id": "config-1"},
                    ),
                    _check(
                        "UNIT_BEARING_EFFICIENCY_MEASURE_RECORDED",
                        "UNKNOWN",
                        "not_assessed",
                        None,
                        None,
                    ),
                ],
            },
            "evaluator": {
                "coverage_state": "EVIDENCE_INCOMPLETE",
                "checks": [
                    _check(
                        "EVALUATOR_VERSION_SNAPSHOT_RECORDED",
                        "SUPPORTED",
                        "server_recorded_client_declaration",
                        {"kind": "evaluator_version", "id": "eval-v1"},
                    ),
                    unknown("EVALUATOR_EXECUTION_LINK_ASSESSED"),
                    unknown("EVALUATOR_STABILITY_ASSESSED"),
                ],
            },
            "evaluation_dataset": {
                "coverage_state": "GAPS_RECORDED",
                "checks": [
                    _check(
                        "RUN_DATASET_IDENTITY_RECORDED",
                        "SUPPORTED",
                        "server_recorded_client_declaration",
                        {"kind": "evaluation_dataset", "id": "dataset-v1"},
                    ),
                    _check(
                        "EVALUATED_EXAMPLE_COUNT_RECORDED",
                        "GAP",
                        "client_reported",
                        {"kind": "configuration_run", "id": "config-1"},
                    ),
                    unknown("DATASET_QUALITY_ASSESSMENT_RECORDED"),
                ],
            },
        },
        "process_assurance": {
            "coverage_state": "EVIDENCE_INCOMPLETE",
            "stage": "EVALUATION_COMPLETED",
            "checks": [
                _check(
                    "EXPERIMENT_PATH_RECORDED",
                    "SUPPORTED",
                    "backend_observed",
                    {"kind": "experiment", "id": "experiment-1"},
                ),
                unknown("SELECTED_CONFIGURATION_RECORDED"),
                unknown("SELECTION_LEDGER_MATCH_ASSESSED"),
            ],
            "certificate_match": "NOT_ASSESSED",
        },
        "current_context": {
            "evaluation_dataset_association": {
                "experiment_id": "experiment-1",
                "evaluation_dataset_ref": {"kind": "evaluation_dataset", "id": "dataset-current"},
                "observed_at": "2026-09-20T00:00:00Z",
            }
        },
        "journey": {
            "items": [
                {
                    "experiment_id": "experiment-1",
                    "experiment_name": "Baseline",
                    "run_id": "run-history",
                    "is_anchor": False,
                    "status": "COMPLETED",
                    "started_at": "2026-09-18T23:00:00Z",
                    "completed_at": "2026-09-18T23:05:00Z",
                    "evaluation_dataset_ref": {"kind": "evaluation_dataset", "id": "dataset-v1"},
                    "evaluator_version_ref": {"kind": "evaluator_version", "id": "eval-v1"},
                    "identity_snapshot_state": "RECORDED",
                    "metric_configuration_run_id": "config-1",
                    "reported_example_evaluations": 0,
                    "reported_metrics": [
                        {
                            "kind": "COST",
                            "value": 0.0,
                            "unit": "USD",
                            "source_key": "cost_usd",
                            "observation_basis": "client_reported",
                        }
                    ],
                    "record_observation_basis": "backend_observed",
                    "dataset_reference_change": "FIRST_RECORDED_REFERENCE",
                    "evaluator_reference_change": "FIRST_RECORDED_REFERENCE",
                }
            ],
            "pagination": {
                "page": 2,
                "per_page": 1,
                "total": 2,
                "total_pages": 2,
                "has_next": False,
                "has_prev": True,
            },
        },
        "next_action_code": "EVALUATE_DATASET_EXAMPLES",
    }


def test_schema_files_are_valid_draft7_and_discoverable() -> None:
    validator = SchemaValidator()
    for name in (
        "agent_readiness_common_schema",
        "agent_readiness_portfolio_response_schema",
        "agent_readiness_detail_response_schema",
        "agent_readiness_error_schema",
    ):
        assert name in validator.available_schemas
        schema = json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8"))
        Draft7Validator.check_schema(schema)


def test_zero_run_portfolio_fixture_is_valid() -> None:
    assert (
        SchemaValidator().validate_json(
            _portfolio_payload(), "agent_readiness_portfolio_response_schema"
        )
        == []
    )


def test_completed_detail_fixture_is_valid_and_allows_page_without_anchor() -> None:
    errors = SchemaValidator().validate_json(
        _detail_payload(), "agent_readiness_detail_response_schema"
    )
    assert errors == []
    assert _detail_payload()["anchor_run_id"] == "run-anchor"
    assert all(not row["is_anchor"] for row in _detail_payload()["journey"]["items"])


def test_detail_check_order_is_closed() -> None:
    payload = _detail_payload()
    payload["pillars"]["agent"]["checks"][0], payload["pillars"]["agent"]["checks"][1] = (
        payload["pillars"]["agent"]["checks"][1],
        payload["pillars"]["agent"]["checks"][0],
    )
    assert SchemaValidator().validate_json(payload, "agent_readiness_detail_response_schema")


def test_unknown_fields_and_composite_claims_are_rejected() -> None:
    validator = SchemaValidator()
    portfolio = _portfolio_payload()
    portfolio["readiness_score"] = 1.0
    assert validator.validate_json(portfolio, "agent_readiness_portfolio_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"][0]["metadata"] = {"canary": "private"}
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_metric_allowlist_rejects_generic_or_wrong_unit_values() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    metric = detail["journey"]["items"][0]["reported_metrics"][0]
    metric["source_key"] = "cost"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    metric = detail["journey"]["items"][0]["reported_metrics"][0]
    metric["unit"] = "UNIT_NOT_RECORDED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_reported_metrics_reject_duplicate_kinds() -> None:
    detail = _detail_payload()
    metric = detail["journey"]["items"][0]["reported_metrics"][0]
    detail["journey"]["items"][0]["reported_metrics"] = [
        metric,
        {**metric, "value": 1.0, "source_key": "total_cost_usd"},
    ]
    assert SchemaValidator().validate_json(detail, "agent_readiness_detail_response_schema")


def test_evidence_state_basis_ref_and_time_combinations_are_closed() -> None:
    validator = SchemaValidator()
    invalid = (
        ("SUPPORTED", "not_assessed", None, None),
        ("UNKNOWN", "backend_observed", {"kind": "agent", "id": "agent-1"}, None),
        ("UNKNOWN", "not_assessed", None, "2026-09-20T00:00:00Z"),
        ("GAP", "not_assessed", None, None),
    )
    for state, basis, evidence_ref, observed_at in invalid:
        detail = _detail_payload()
        detail["pillars"]["agent"]["checks"][0].update(
            state=state,
            observation_basis=basis,
            evidence_ref=evidence_ref,
            observed_at=observed_at,
        )
        assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_named_references_and_record_basis_are_kind_and_source_closed() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    detail["journey"]["items"][0]["evaluation_dataset_ref"]["kind"] = "agent"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"][0]["evaluator_version_ref"]["kind"] = "agent"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["current_context"]["evaluation_dataset_association"]["evaluation_dataset_ref"][
        "kind"
    ] = "agent"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"][0]["record_observation_basis"] = "client_reported"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_anchor_null_and_pagination_limits_are_enforced() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    detail["anchor_run_id"] = None
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["pagination"]["per_page"] = 51
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"] = detail["journey"]["items"] * 51
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    portfolio = _portfolio_payload()
    portfolio["pagination"]["per_page"] = 101
    assert validator.validate_json(portfolio, "agent_readiness_portfolio_response_schema")

    portfolio = _portfolio_payload()
    portfolio["items"] = portfolio["items"] * 101
    assert validator.validate_json(portfolio, "agent_readiness_portfolio_response_schema")


def test_readiness_error_envelope_rejects_private_sentinels_and_details() -> None:
    validator = SchemaValidator()
    valid = {
        "success": False,
        "message": "Not found",
        "error": "not_found",
        "error_code": "not_found",
    }
    assert validator.validate_json(valid, "agent_readiness_error_schema") == []

    for field in ("message", "error", "error_code"):
        invalid = {**valid, field: "private_prompt_output_canary"}
        assert validator.validate_json(invalid, "agent_readiness_error_schema")

    invalid = {**valid, "details": {"canary": "private_prompt_output_canary"}}
    assert validator.validate_json(invalid, "agent_readiness_error_schema")


def test_normative_matrix_covers_every_check_and_next_action() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    assert {row["check_id"] for row in matrix["checks"]} == CHECK_IDS
    assert {row["code"] for row in matrix["next_actions"]} == NEXT_ACTIONS
    assert matrix["anchor_rule"]["journey_page_may_omit_anchor"] is True
    assert matrix["checks"][4]["resolution_rule"].startswith(
        "Only evaluator_version_resolution=resolved"
    )
    assert all("existing_ui_flow_or_sdk_call" in row for row in matrix["next_actions"])
    completion_action = next(
        row for row in matrix["next_actions"] if row["code"] == "COMPLETE_EVALUATION_RUN"
    )
    assert (
        "hybrid.ts:2870 submitOptimizationTrialResult"
        in completion_action["existing_ui_flow_or_sdk_call"]
    )
    assert ":2891 finalizeOptimizationSession" in completion_action["existing_ui_flow_or_sdk_call"]
    assert (
        "hybrid-backend-smoke.mjs:73 then :86" in completion_action["existing_ui_flow_or_sdk_call"]
    )
    assert (
        next(row for row in matrix["next_actions"] if row["code"] == "REVIEW_RECORDED_EVIDENCE")[
            "kind"
        ]
        == "GUIDANCE_ONLY"
    )


def test_endpoint_inventory_registers_both_project_scoped_get_routes() -> None:
    inventory = json.loads((SCHEMAS / "agent_readiness_endpoints.json").read_text(encoding="utf-8"))
    paths = inventory["paths"]
    assert set(paths) == {
        "/api/v1beta/projects/{project_id}/agent-readiness",
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}",
    }
    assert paths["/api/v1beta/projects/{project_id}/agent-readiness"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"]["$ref"].endswith(
        "agent_readiness_portfolio_response_schema.json"
    )
    assert paths["/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}"]["get"][
        "responses"
    ]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "agent_readiness_detail_response_schema.json"
    )
    assert (
        paths["/api/v1beta/projects/{project_id}/agent-readiness"]["get"][
            "x-asserted-against-backend"
        ]
        is False
    )
    assert (
        paths["/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}"]["get"][
            "x-asserted-against-backend"
        ]
        is False
    )
    for path in paths.values():
        for response in path["get"]["responses"].values():
            if response.get("content"):
                assert (
                    response["content"]["application/json"]["schema"]["$ref"]
                    == "./agent_readiness_error_schema.json"
                    or response["content"]["application/json"]["schema"]["$ref"].endswith(
                        "agent_readiness_portfolio_response_schema.json"
                    )
                    or response["content"]["application/json"]["schema"]["$ref"].endswith(
                        "agent_readiness_detail_response_schema.json"
                    )
                )

    root = json.loads((get_schemas_dir() / "mep_endpoints.json").read_text(encoding="utf-8"))
    modules = [
        m
        for m in root["x-endpoint-modules"]
        if m.get("paths_file") == "./agent_readiness/agent_readiness_endpoints.json"
    ]
    assert len(modules) == 1


def test_response_objects_are_closed_and_forbidden_content_names_are_absent() -> None:
    forbidden = {
        "prompt",
        "output",
        "results",
        "measures",
        "metadata",
        "evaluator_config",
        "generator_config",
        "payload",
        "digest",
        "score",
        "recommendation",
    }

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, node
            if "properties" in node:
                assert not forbidden.intersection(node["properties"]), node["properties"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for name in (
        "agent_readiness_common_schema",
        "agent_readiness_portfolio_response_schema",
        "agent_readiness_detail_response_schema",
    ):
        walk(json.loads((SCHEMAS / f"{name}.json").read_text(encoding="utf-8")))
