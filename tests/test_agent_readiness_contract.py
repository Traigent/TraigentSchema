"""Contract tests for the closed, content-free Agent readiness projection."""

from __future__ import annotations

import json
from copy import deepcopy
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


def _summary(
    supported: int, gap: int, unknown: int, top_gap: str | None = None
) -> dict[str, Any]:
    return {
        "coverage_state": (
            "GAPS_RECORDED"
            if gap
            else ("CHECKS_RECORDED" if unknown == 0 else "EVIDENCE_INCOMPLETE")
        ),
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
                "agent": {
                    "id": "agent-1",
                    "name": "Support agent",
                    "status": "running",
                },
                "anchor_run_id": None,
                "anchor_experiment_id": None,
                "anchor_completed_at": None,
                "next_action_experiment_id": None,
                "next_action_run_id": None,
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
                    "top_gap_code": None,
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
        "anchor_experiment_id": "experiment-anchor",
        "anchor_completed_at": "2026-09-19T23:00:00Z",
        "next_action_experiment_id": "experiment-anchor",
        "next_action_run_id": "run-anchor",
        "agent_updated_after_anchor": True,
        "pillars": {
            "agent": {
                "coverage_state": "EVIDENCE_INCOMPLETE",
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
                "evaluation_dataset_ref": {
                    "kind": "evaluation_dataset",
                    "id": "dataset-current",
                },
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
                    "evaluation_dataset_ref": {
                        "kind": "evaluation_dataset",
                        "id": "dataset-v1",
                    },
                    "evaluator_version_ref": {
                        "kind": "evaluator_version",
                        "id": "eval-v1",
                    },
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
        "anchor_summary": {
            "experiment_id": "experiment-anchor",
            "experiment_name": "Anchor",
            "run_id": "run-anchor",
            "is_anchor": True,
            "status": "COMPLETED",
            "started_at": "2026-09-19T22:55:00Z",
            "completed_at": "2026-09-19T23:00:00Z",
            "evaluation_dataset_ref": {
                "kind": "evaluation_dataset",
                "id": "dataset-v1",
            },
            "evaluator_version_ref": {"kind": "evaluator_version", "id": "eval-v1"},
            "identity_snapshot_state": "RECORDED",
            "metric_configuration_run_id": "config-1",
            "reported_example_evaluations": 1,
            "reported_metrics": [],
            "record_observation_basis": "backend_observed",
            "dataset_reference_change": "REFERENCE_CONTINUITY_UNKNOWN",
            "evaluator_reference_change": "REFERENCE_CONTINUITY_UNKNOWN",
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


def test_anchor_summary_is_required_and_completed_when_anchor_exists() -> None:
    validator = SchemaValidator()
    invalid = _detail_payload()
    invalid["anchor_summary"] = None
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    invalid = _detail_payload()
    invalid["anchor_summary"]["status"] = "RUNNING"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")


def test_next_action_targets_are_closed_for_each_action_state() -> None:
    validator = SchemaValidator()
    for code in sorted(NEXT_ACTIONS):
        detail = _detail_payload()
        detail["next_action_code"] = code
        if code == "ESTABLISH_BASELINE_EVALUATION":
            detail["next_action_experiment_id"] = None
            detail["next_action_run_id"] = None
        elif code == "COMPLETE_EVALUATION_RUN":
            detail["next_action_experiment_id"] = "experiment-in-progress"
            detail["next_action_run_id"] = "run-in-progress"
        else:
            detail["next_action_experiment_id"] = "experiment-anchor"
            detail["next_action_run_id"] = "run-anchor"
        assert (
            validator.validate_json(detail, "agent_readiness_detail_response_schema")
            == []
        )

    invalid = _detail_payload()
    invalid["next_action_code"] = "ESTABLISH_BASELINE_EVALUATION"
    invalid["next_action_experiment_id"] = "must-not-be-present"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    for code in sorted(NEXT_ACTIONS):
        portfolio = _portfolio_payload()
        item = portfolio["items"][0]
        item["next_action_code"] = code
        if code == "ESTABLISH_BASELINE_EVALUATION":
            item["next_action_experiment_id"] = None
            item["next_action_run_id"] = None
        elif code == "COMPLETE_EVALUATION_RUN":
            item["process"]["stage"] = "RUNS_RECORDED"
            item["next_action_experiment_id"] = "experiment-in-progress"
            item["next_action_run_id"] = "run-in-progress"
        else:
            item["anchor_run_id"] = "run-anchor"
            item["anchor_experiment_id"] = "experiment-anchor"
            item["anchor_completed_at"] = "2026-09-19T23:00:00Z"
            item["process"]["stage"] = "EVALUATION_COMPLETED"
            item["next_action_experiment_id"] = "experiment-anchor"
            item["next_action_run_id"] = "run-anchor"
        assert (
            validator.validate_json(
                portfolio, "agent_readiness_portfolio_response_schema"
            )
            == []
        )

    invalid = _detail_payload()
    invalid["next_action_code"] = "COMPLETE_EVALUATION_RUN"
    invalid["next_action_experiment_id"] = None
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    terminal_only = _detail_payload()
    terminal_only["next_action_code"] = "COMPLETE_EVALUATION_RUN"
    terminal_only["next_action_experiment_id"] = None
    terminal_only["next_action_run_id"] = None
    assert (
        validator.validate_json(terminal_only, "agent_readiness_detail_response_schema")
        == []
    )


def test_detail_check_order_is_closed() -> None:
    payload = _detail_payload()
    (
        payload["pillars"]["agent"]["checks"][0],
        payload["pillars"]["agent"]["checks"][1],
    ) = (
        payload["pillars"]["agent"]["checks"][1],
        payload["pillars"]["agent"]["checks"][0],
    )
    assert SchemaValidator().validate_json(
        payload, "agent_readiness_detail_response_schema"
    )


def test_unknown_fields_and_composite_claims_are_rejected() -> None:
    validator = SchemaValidator()
    portfolio = _portfolio_payload()
    portfolio["readiness_score"] = 1.0
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

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


def test_accuracy_metric_source_key_is_closed_and_value_is_nonnegative_numeric() -> (
    None
):
    validator = SchemaValidator()

    for source_key in ("accuracy", "accuracy.mean"):
        detail = _detail_payload()
        detail["journey"]["items"][0]["reported_metrics"] = [
            {
                "kind": "ACCURACY",
                "value": 0.0,
                "unit": "UNIT_NOT_RECORDED",
                "source_key": source_key,
                "observation_basis": "client_reported",
            }
        ]
        assert (
            validator.validate_json(detail, "agent_readiness_detail_response_schema")
            == []
        )

    for source_key in ("accuracy.aggregate", "accuracy_mean", "metrics.accuracy.mean"):
        detail = _detail_payload()
        detail["journey"]["items"][0]["reported_metrics"][0].update(
            kind="ACCURACY",
            unit="UNIT_NOT_RECORDED",
            source_key=source_key,
        )
        assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    for value in (-0.001, True, "0.5", None):
        detail = _detail_payload()
        detail["journey"]["items"][0]["reported_metrics"][0].update(
            kind="ACCURACY",
            unit="UNIT_NOT_RECORDED",
            source_key="accuracy.mean",
            value=value,
        )
        assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_reported_metrics_reject_duplicate_kinds() -> None:
    detail = _detail_payload()
    metric = detail["journey"]["items"][0]["reported_metrics"][0]
    detail["journey"]["items"][0]["reported_metrics"] = [
        metric,
        {**metric, "value": 1.0, "source_key": "total_cost_usd"},
    ]
    assert SchemaValidator().validate_json(
        detail, "agent_readiness_detail_response_schema"
    )


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
    detail["current_context"]["evaluation_dataset_association"][
        "evaluation_dataset_ref"
    ]["kind"] = "agent"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"][0]["record_observation_basis"] = "client_reported"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_anchor_null_and_pagination_limits_are_enforced() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    detail["anchor_run_id"] = None
    detail["process_assurance"]["stage"] = "RUNS_RECORDED"
    detail["next_action_code"] = "COMPLETE_EVALUATION_RUN"
    detail["next_action_experiment_id"] = "experiment-in-progress"
    detail["next_action_run_id"] = "run-in-progress"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["pagination"]["per_page"] = 51
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"] = detail["journey"]["items"] * 51
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    portfolio = _portfolio_payload()
    portfolio["pagination"]["per_page"] = 101
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    portfolio = _portfolio_payload()
    portfolio["items"] = portfolio["items"] * 101
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )


def test_anchor_stage_implications_and_page_anchor_rule_are_closed() -> None:
    validator = SchemaValidator()

    portfolio = _portfolio_payload()
    portfolio["items"][0]["process"]["stage"] = "EVALUATION_COMPLETED"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    portfolio = _portfolio_payload()
    portfolio["items"][0]["anchor_run_id"] = "run-anchor"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    detail = _detail_payload()
    detail["process_assurance"]["stage"] = "RUNS_RECORDED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["anchor_run_id"] = None
    detail["anchor_experiment_id"] = None
    detail["anchor_completed_at"] = None
    detail["anchor_summary"] = None
    detail["process_assurance"]["stage"] = "EVALUATION_COMPLETED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["anchor_run_id"] = None
    detail["anchor_experiment_id"] = None
    detail["anchor_completed_at"] = None
    detail["anchor_summary"] = None
    detail["process_assurance"]["stage"] = "RUNS_RECORDED"
    detail["journey"]["items"][0]["is_anchor"] = True
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    completed_undated = _detail_payload()
    completed_undated["anchor_completed_at"] = None
    completed_undated["agent_updated_after_anchor"] = False
    assert (
        validator.validate_json(
            completed_undated, "agent_readiness_detail_response_schema"
        )
        == []
    )


def test_journey_metric_and_identity_implications_are_closed() -> None:
    validator = SchemaValidator()

    detail = _detail_payload()
    item = detail["journey"]["items"][0]
    item["metric_configuration_run_id"] = None
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    item = detail["journey"]["items"][0]
    item["metric_configuration_run_id"] = None
    item["reported_metrics"] = []
    item["reported_example_evaluations"] = 0
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    item = detail["journey"]["items"][0]
    item["metric_configuration_run_id"] = None
    item["reported_metrics"] = []
    item["reported_example_evaluations"] = None
    assert (
        validator.validate_json(detail, "agent_readiness_detail_response_schema") == []
    )

    detail = _detail_payload()
    item = detail["journey"]["items"][0]
    item["identity_snapshot_state"] = "NOT_RECORDED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    item = detail["journey"]["items"][0]
    item["identity_snapshot_state"] = "NOT_RECORDED"
    item["evaluation_dataset_ref"] = None
    item["evaluator_version_ref"] = None
    assert (
        validator.validate_json(detail, "agent_readiness_detail_response_schema") == []
    )


def test_readiness_error_envelope_rejects_private_sentinels_and_details() -> None:
    validator = SchemaValidator()
    valid = {
        "success": False,
        "message": "Not found",
        "error": "not_found",
        "error_code": "not_found",
    }
    assert validator.validate_json(valid, "agent_readiness_error_schema") == []

    for code, message in (
        ("PROJECT_ACCESS_DENIED", "Authorization denied"),
        ("PROJECT_NOT_FOUND", "Project not found"),
        ("TENANT_ACCESS_DENIED", "Authorization denied"),
        ("TENANT_NOT_FOUND", "Not found"),
    ):
        error = "authorization_denied" if "ACCESS_DENIED" in code else "not_found"
        payload = {
            "success": False,
            "message": message,
            "error": error,
            "error_code": code,
        }
        assert validator.validate_json(payload, "agent_readiness_error_schema") == []
        assert validator.validate_json(
            {**payload, "details": {"canary": "private_prompt_output_canary"}},
            "agent_readiness_error_schema",
        )

    for field in ("message", "error", "error_code"):
        invalid = {**valid, field: "private_prompt_output_canary"}
        assert validator.validate_json(invalid, "agent_readiness_error_schema")

    invalid = {**valid, "details": {"canary": "private_prompt_output_canary"}}
    assert validator.validate_json(invalid, "agent_readiness_error_schema")


def test_opaque_ids_and_experiment_names_allow_512_but_reject_513() -> None:
    validator = SchemaValidator()
    long_id = "a" * 512

    portfolio = _portfolio_payload()
    portfolio["items"][0]["agent"]["id"] = long_id
    assert (
        validator.validate_json(portfolio, "agent_readiness_portfolio_response_schema")
        == []
    )

    portfolio["items"][0]["agent"]["id"] = long_id + "a"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    detail = _detail_payload()
    detail["agent"]["id"] = long_id
    detail["journey"]["items"][0]["experiment_name"] = long_id
    assert (
        validator.validate_json(detail, "agent_readiness_detail_response_schema") == []
    )

    detail["agent"]["id"] = long_id + "a"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["journey"]["items"][0]["experiment_name"] = long_id + "a"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")


def test_coverage_state_is_derived_from_checks_and_counts() -> None:
    validator = SchemaValidator()

    detail = _detail_payload()
    detail["pillars"]["agent"]["coverage_state"] = "CHECKS_RECORDED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail = _detail_payload()
    detail["process_assurance"]["coverage_state"] = "CHECKS_RECORDED"
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    for pillar in ("evaluator", "evaluation_dataset"):
        detail = _detail_payload()
        detail["pillars"][pillar]["coverage_state"] = "CHECKS_RECORDED"
        assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    portfolio = _portfolio_payload()
    portfolio["items"][0]["pillars"]["agent"]["coverage_state"] = "CHECKS_RECORDED"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    portfolio = _portfolio_payload()
    portfolio["items"][0]["pillars"]["agent"]["top_gap_code"] = "AGENT_RECORD_AVAILABLE"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )

    portfolio = _portfolio_payload()
    portfolio["items"][0]["process"]["coverage_state"] = "CHECKS_RECORDED"
    assert validator.validate_json(
        portfolio, "agent_readiness_portfolio_response_schema"
    )


def test_undated_anchor_requires_false_updated_flag() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    detail["anchor_completed_at"] = None
    assert validator.validate_json(detail, "agent_readiness_detail_response_schema")

    detail["agent_updated_after_anchor"] = False
    assert (
        validator.validate_json(detail, "agent_readiness_detail_response_schema") == []
    )


def test_anchor_and_stage_gate_run_dependent_check_states() -> None:
    validator = SchemaValidator()
    detail = _detail_payload()
    detail["anchor_run_id"] = None
    detail["anchor_experiment_id"] = None
    detail["anchor_summary"] = None
    detail["anchor_completed_at"] = None
    detail["agent_updated_after_anchor"] = False
    detail["process_assurance"]["stage"] = "RUNS_RECORDED"
    detail["next_action_code"] = "COMPLETE_EVALUATION_RUN"
    detail["next_action_experiment_id"] = "experiment-in-progress"
    detail["next_action_run_id"] = "run-in-progress"

    agent_checks = detail["pillars"]["agent"]["checks"]
    agent_checks[1] = _check(
        "COMPLETED_EVALUATION_RUN",
        "GAP",
        "backend_observed",
        {"kind": "agent", "id": "agent-1"},
    )
    agent_checks[2] = _check(
        "ACCURACY_MEASURE_RECORDED", "UNKNOWN", "not_assessed", None, None
    )
    agent_checks[3] = _check(
        "UNIT_BEARING_EFFICIENCY_MEASURE_RECORDED",
        "UNKNOWN",
        "not_assessed",
        None,
        None,
    )
    detail["pillars"]["agent"]["coverage_state"] = "GAPS_RECORDED"
    evaluator_checks = detail["pillars"]["evaluator"]["checks"]
    evaluator_checks[0] = _check(
        "EVALUATOR_VERSION_SNAPSHOT_RECORDED", "UNKNOWN", "not_assessed", None, None
    )
    detail["pillars"]["evaluator"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    dataset_checks = detail["pillars"]["evaluation_dataset"]["checks"]
    for index, check in enumerate(dataset_checks):
        dataset_checks[index] = _check(
            check["check_id"], "UNKNOWN", "not_assessed", None, None
        )
    detail["pillars"]["evaluation_dataset"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    assert (
        validator.validate_json(detail, "agent_readiness_detail_response_schema") == []
    )

    invalid = deepcopy(detail)
    invalid["pillars"]["agent"]["checks"][2] = _check(
        "ACCURACY_MEASURE_RECORDED",
        "SUPPORTED",
        "client_reported",
        {"kind": "configuration_run", "id": "config-1"},
    )
    invalid["pillars"]["agent"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    invalid = deepcopy(detail)
    invalid["anchor_run_id"] = "run-anchor"
    invalid["process_assurance"]["stage"] = "EVALUATION_COMPLETED"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    invalid = deepcopy(detail)
    invalid["process_assurance"]["stage"] = "NO_RUNS"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    invalid = deepcopy(detail)
    invalid["process_assurance"]["checks"][0] = _check(
        "EXPERIMENT_PATH_RECORDED", "UNKNOWN", "not_assessed", None, None
    )
    invalid["process_assurance"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    valid_no_runs = deepcopy(detail)
    valid_no_runs["process_assurance"]["stage"] = "NO_RUNS"
    valid_no_runs["process_assurance"]["checks"][0] = _check(
        "EXPERIMENT_PATH_RECORDED", "UNKNOWN", "not_assessed", None, None
    )
    valid_no_runs["pillars"]["agent"]["checks"][1] = _check(
        "COMPLETED_EVALUATION_RUN", "UNKNOWN", "not_assessed", None, None
    )
    valid_no_runs["pillars"]["agent"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    assert (
        validator.validate_json(valid_no_runs, "agent_readiness_detail_response_schema")
        == []
    )

    invalid = deepcopy(valid_no_runs)
    invalid["pillars"]["agent"]["checks"][1] = _check(
        "COMPLETED_EVALUATION_RUN",
        "GAP",
        "backend_observed",
        {"kind": "agent", "id": "agent-1"},
    )
    invalid["pillars"]["agent"]["coverage_state"] = "GAPS_RECORDED"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")

    invalid = deepcopy(detail)
    invalid["pillars"]["agent"]["checks"][1] = _check(
        "COMPLETED_EVALUATION_RUN", "UNKNOWN", "not_assessed", None, None
    )
    invalid["pillars"]["agent"]["coverage_state"] = "EVIDENCE_INCOMPLETE"
    assert validator.validate_json(invalid, "agent_readiness_detail_response_schema")


def test_normative_matrix_covers_every_check_and_next_action() -> None:
    matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
    assert {row["check_id"] for row in matrix["checks"]} == CHECK_IDS
    assert {row["code"] for row in matrix["next_actions"]} == NEXT_ACTIONS
    assert matrix["anchor_rule"]["journey_page_may_omit_anchor"] is True
    assert matrix["coverage_rule"]["detail_and_process"]["gap_precedence"].startswith(
        "GAPS_RECORDED"
    )
    assert matrix["checks"][4]["resolution_rule"].startswith(
        "Only evaluator_version_resolution=resolved"
    )
    accuracy_check = next(
        row
        for row in matrix["checks"]
        if row["check_id"] == "ACCURACY_MEASURE_RECORDED"
    )
    assert accuracy_check["conditions"][0]["condition"] == (
        "anchor_configuration_run_has_scalar_accuracy_or_"
        "eligible_accuracy_mean_with_positive_count"
    )
    accuracy_action = next(
        row
        for row in matrix["next_actions"]
        if row["code"] == "RECORD_ACCURACY_MEASURE"
    )
    assert (
        "eligible accuracy.mean aggregate with positive count"
        in accuracy_action["driven_by"]
    )
    assert all("existing_ui_flow_or_sdk_call" in row for row in matrix["next_actions"])
    completion_action = next(
        row
        for row in matrix["next_actions"]
        if row["code"] == "COMPLETE_EVALUATION_RUN"
    )
    assert (
        "hybrid.ts:2870 submitOptimizationTrialResult"
        in completion_action["existing_ui_flow_or_sdk_call"]
    )
    assert (
        ":2891 finalizeOptimizationSession"
        in completion_action["existing_ui_flow_or_sdk_call"]
    )
    assert (
        "hybrid-backend-smoke.mjs:73 then :86"
        in completion_action["existing_ui_flow_or_sdk_call"]
    )
    assert (
        next(
            row
            for row in matrix["next_actions"]
            if row["code"] == "REVIEW_RECORDED_EVIDENCE"
        )["kind"]
        == "GUIDANCE_ONLY"
    )


def test_endpoint_inventory_registers_both_project_scoped_get_routes() -> None:
    inventory = json.loads(
        (SCHEMAS / "agent_readiness_endpoints.json").read_text(encoding="utf-8")
    )
    paths = inventory["paths"]
    assert set(paths) == {
        "/api/v1beta/projects/{project_id}/agent-readiness",
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}",
    }
    assert paths["/api/v1beta/projects/{project_id}/agent-readiness"]["get"][
        "responses"
    ]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
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
                    or response["content"]["application/json"]["schema"][
                        "$ref"
                    ].endswith("agent_readiness_portfolio_response_schema.json")
                    or response["content"]["application/json"]["schema"][
                        "$ref"
                    ].endswith("agent_readiness_detail_response_schema.json")
                )

    root = json.loads(
        (get_schemas_dir() / "mep_endpoints.json").read_text(encoding="utf-8")
    )
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
                assert not forbidden.intersection(node["properties"]), node[
                    "properties"
                ]
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
