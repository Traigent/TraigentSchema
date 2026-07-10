from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _schema(name: str) -> dict:
    path = get_schemas_dir() / "smartops_v2" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_v2_routes_are_reachable_without_changing_v1() -> None:
    validator = SchemaValidator(contract="backend")
    assert validator._endpoint_schemas[
        "POST:/api/v2/experiment-runs/{run_id}/next-decision"
    ] == "next_decision_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/lifecycles/{lifecycle_id}/decisions/{decision_id}/receipts"
    ] == "receipt_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/lifecycles/{lifecycle_id}/reopen"
    ] == "reopen_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/internal/smartops/shadow-evaluate"
    ] == "shadow_evaluate_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v1/analytics/experiments/{experiment_run_id}/next-steps/{decision_id}/receipt"
    ] == "next_steps_receipt_request_schema"


def test_submitted_receipt_requires_result_ref() -> None:
    validator = SchemaValidator(contract="backend")
    base = {
        "attempt_id": "attempt_0123456789abcdef",
        "status": "submitted",
    }
    assert validator.validate_request(
        "/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/decision_0123456789abcdef/receipts",
        "POST",
        base,
    )
    assert not validator.validate_request(
        "/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/decision_0123456789abcdef/receipts",
        "POST",
        {**base, "result_ref": "result_0123456789abcdef"},
    )
    for status in ("started", "failed", "skipped"):
        assert validator.validate_request(
            "/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/decision_0123456789abcdef/receipts",
            "POST",
            {
                "attempt_id": "attempt_0123456789abcdef",
                "status": status,
                "result_ref": "result_0123456789abcdef",
            },
        )


def test_public_command_and_private_argv_are_shell_free() -> None:
    response = _schema("next_decision_response_schema.json")
    command = response["properties"]["decision"]["properties"]["action"]["properties"][
        "command_template"
    ]
    assert "traigent guidance execute --decision" in command["pattern"]
    assert "x-content" not in json.dumps(response)

    resolved = _schema("resolve_decision_response_schema.json")
    assert resolved["properties"]["argv"]["type"] == "array"
    assert resolved["properties"]["execution_spec"]["additionalProperties"] is False


def test_internal_numeric_certificate_never_appears_in_public_decision() -> None:
    public = json.dumps(_schema("next_decision_response_schema.json"))
    internal = json.dumps(_schema("shadow_evaluate_response_schema.json"))
    assert "advantage_lcb" not in public
    assert "advantage_lcb" in internal
    assert "internal_confidential" in internal


def _decision_payload(**overrides: object) -> dict:
    decision = {
        "id": "decision_0123456789abcdef",
        "mode": "rules_control",
        "category": "score_evaluation_set",
        "source_engine": "rules",
        "baseline_rule_category": "score_evaluation_set",
        "utility_profile": "balanced",
        "certificate_ref": None,
        "advantage_label": "not_applicable",
        "evidence_snapshot_hash": "ev_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "rationale": "rules control selected the next safe lifecycle action",
        "action": {
            "kind": "cli",
            "variant": "score_probe_32",
            "command_template": (
                "traigent guidance execute --decision decision_0123456789abcdef"
            ),
        },
        "evidence_level": "medium",
    }
    decision.update(overrides)
    return {
        "schema_version": "2.0.0",
        "lifecycle_id": "lifecycle_0123456789abcdef",
        "run_id": "run_123",
        "decision": decision,
        "meta": {
            "requested_variant": "rules_control",
            "served_variant": "rules_control",
            "selector_engine": "rules",
            "context_status": "complete",
            "policy_version": None,
            "rule_version": "rules-v2",
            "calibration_version": None,
            "shield_version": "shield-v2",
            "fallback_reason": None,
        },
    }


def test_rules_control_semantics_and_rationale_are_closed() -> None:
    validator = SchemaValidator(contract="backend")
    assert not validator.validate_json(
        _decision_payload(), "next_decision_response_schema"
    )
    for mutation in (
        {"source_engine": "policy"},
        {"advantage_label": "parity"},
        {"evidence_level": "low"},
        {"rationale": "policy agreed with the safe rule action"},
        {"baseline_rule_category": "audit_evaluator_quality"},
        {
            "category": "wait",
            "baseline_rule_category": "wait",
            "action": {"kind": "none", "variant": "wait", "command_template": ""},
        },
    ):
        assert validator.validate_json(
            _decision_payload(**mutation), "next_decision_response_schema"
        )


def test_policy_modes_cannot_masquerade_as_terminal_actions() -> None:
    validator = SchemaValidator(contract="backend")
    for mode, label, level, rationale in (
        (
            "policy_override",
            "model_certified_positive",
            "high",
            "policy selected a model-certified improvement over rules",
        ),
        ("rules_parity", "parity", "medium", "policy agreed with the safe rule action"),
        (
            "rules_fallback",
            "unavailable",
            "low",
            "policy or calibration was unavailable; safe rules were used",
        ),
    ):
        payload = _decision_payload(
            mode=mode,
            category="wait",
            baseline_rule_category="wait",
            source_engine="policy" if mode == "policy_override" else "rules",
            advantage_label=label,
            evidence_level=level,
            certificate_ref=(
                "certificate_0123456789abcdef" if mode == "policy_override" else None
            ),
            rationale=rationale,
            action={"kind": "none", "variant": "wait", "command_template": ""},
        )
        assert validator.validate_json(payload, "next_decision_response_schema")


def test_mode_and_meta_treatment_semantics_are_closed() -> None:
    validator = SchemaValidator(contract="backend")
    base = _decision_payload()
    for meta_mutation in (
        {"requested_variant": "policy_override"},
        {"served_variant": "policy_override"},
        {"selector_engine": "policy"},
        {"fallback_reason": "policy_unavailable"},
    ):
        payload = json.loads(json.dumps(base))
        payload["meta"].update(meta_mutation)
        assert validator.validate_json(payload, "next_decision_response_schema")

    parity = _decision_payload(
        mode="rules_parity",
        advantage_label="parity",
        rationale="policy agreed with the safe rule action",
    )
    parity["meta"].update(
        requested_variant="policy_override",
        served_variant="policy_override",
        selector_engine="policy",
        policy_version="policy-v2",
        calibration_version="calibration-v2",
    )
    assert not validator.validate_json(parity, "next_decision_response_schema")
    for field, value in (
        ("served_variant", "rules_control"),
        ("selector_engine", "rules"),
        ("policy_version", None),
        ("calibration_version", None),
        ("fallback_reason", "policy_unavailable"),
    ):
        payload = json.loads(json.dumps(parity))
        payload["meta"][field] = value
        assert validator.validate_json(payload, "next_decision_response_schema")

    fallback = _decision_payload(
        mode="rules_fallback",
        advantage_label="unavailable",
        evidence_level="low",
        rationale="policy or calibration was unavailable; safe rules were used",
    )
    fallback["meta"].update(
        requested_variant="policy_override",
        served_variant="policy_override",
        selector_engine="rules",
        fallback_reason="policy_unavailable",
    )
    assert not validator.validate_json(fallback, "next_decision_response_schema")
    fallback["meta"]["fallback_reason"] = None
    assert validator.validate_json(fallback, "next_decision_response_schema")


def test_reopen_is_reason_only_without_hidden_run_backdoor() -> None:
    validator = SchemaValidator(contract="backend")
    endpoint = "/api/v2/lifecycles/lifecycle_0123456789abcdef/reopen"
    assert not validator.validate_request(endpoint, "POST", {"reason": "budget"})
    assert validator.validate_request(
        endpoint,
        "POST",
        {"reason": "budget", "root_run_id": "run_foreign"},
    )
