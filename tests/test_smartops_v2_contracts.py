from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _schema(name: str) -> dict:
    path = get_schemas_dir() / "smartops_v2" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_v2_routes_are_reachable_without_changing_v1() -> None:
    validator = SchemaValidator(contract="backend")
    assert (
        validator._endpoint_schemas["POST:/api/v2/experiment-runs/{run_id}/next-decision"]
        == "next_decision_request_schema"
    )
    assert (
        validator._endpoint_schemas[
            "POST:/api/v2/lifecycles/{lifecycle_id}/decisions/{decision_id}/receipts"
        ]
        == "receipt_request_schema"
    )
    assert (
        validator._endpoint_schemas["POST:/api/v2/lifecycles/{lifecycle_id}/reopen"]
        == "reopen_request_schema"
    )
    assert (
        validator._endpoint_schemas["POST:/api/v2/internal/smartops/shadow-evaluate"]
        == "shadow_evaluate_request_schema"
    )
    assert (
        validator._endpoint_schemas[
            "POST:/api/v1/analytics/experiments/{experiment_run_id}/next-steps/{decision_id}/receipt"
        ]
        == "next_steps_receipt_request_schema"
    )


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
            "command_template": ("traigent guidance execute --decision decision_0123456789abcdef"),
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
    assert not validator.validate_json(_decision_payload(), "next_decision_response_schema")
    for mutation in (
        {"source_engine": "policy"},
        {"advantage_label": "no_certified_override"},
        {"evidence_level": "low"},
        {"rationale": "no certified override applies; safe rule action retained"},
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
            "certified_session_utility_advantage_no_kpi_guarantee",
            "high",
            "certified session-utility advantage selected; no product KPI guarantee",
        ),
        (
            "rules_parity",
            "no_certified_override",
            "medium",
            "no certified override applies; safe rule action retained",
        ),
        (
            "rules_fallback",
            "unavailable",
            "low",
            "policy artifact or certificate unavailable; safe rules were used",
        ),
    ):
        payload = _decision_payload(
            mode=mode,
            category="wait",
            baseline_rule_category="wait",
            source_engine="policy" if mode == "policy_override" else "rules",
            advantage_label=label,
            evidence_level=level,
            certificate_ref=("certificate_0123456789abcdef" if mode == "policy_override" else None),
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
        advantage_label="no_certified_override",
        rationale="no certified override applies; safe rule action retained",
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
        rationale="policy artifact or certificate unavailable; safe rules were used",
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


def _exact_action(*, optimize: bool = False) -> dict[str, object]:
    if optimize:
        return {
            "operation_kind": "run_optimization",
            "variant": "optimize_probe",
            "target": "agent",
            "cost_units": 2,
            "reservation_units": 2,
            "max_budget_fraction": 0.15,
            "max_trials": 4,
            "sample_limit": None,
            "action_signature": "run_optimization:optimize_probe:agent:2:2:0.15:4:None",
        }
    return {
        "operation_kind": "score_examples",
        "variant": "score_probe_32",
        "target": "dataset",
        "cost_units": 1,
        "reservation_units": 1,
        "max_budget_fraction": None,
        "max_trials": None,
        "sample_limit": 32,
        "action_signature": "score_examples:score_probe_32:dataset:1:1:None:None:32",
    }


def test_public_category_is_bound_to_action_variant() -> None:
    validator = SchemaValidator(contract="backend")
    payload = _decision_payload()
    payload["decision"]["action"]["variant"] = "audit_full"
    assert validator.validate_json(payload, "next_decision_response_schema")


def test_resolved_execution_is_exactly_bound_to_action_economics() -> None:
    validator = SchemaValidator(contract="backend")
    decision_id = "decision_0123456789abcdef"
    action = _exact_action(optimize=True)
    payload = {
        "schema_version": "2.0.0",
        "decision_id": decision_id,
        "argv": [
            "traigent",
            "guidance",
            "execute-resolved",
            "--attempt",
            "attempt_0123456789abcdef",
        ],
        "execution_spec": {
            **action,
            "economics_hash": "df7d6d7c95e61716a55eec42f829c7ca2bb66c285ce4013e66f5dc1cac956d02",
            "attempt_id": "attempt_0123456789abcdef",
            "receipt_url": (
                f"/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/{decision_id}/receipts"
            ),
            "lease_expires_at": "2099-07-10T10:30:00Z",
        },
        "signature": "sig_" + "A" * 43,
        "expires_at": "2099-07-10T10:30:00Z",
    }
    assert not validator.validate_json(payload, "resolve_decision_response_schema")

    for field, value in (
        ("variant", "promote"),
        ("max_trials", 1),
        ("cost_units", 1),
        ("sample_limit", 32),
    ):
        changed = json.loads(json.dumps(payload))
        changed["execution_spec"][field] = value
        assert validator.validate_json(changed, "resolve_decision_response_schema")

    wrong_argv = json.loads(json.dumps(payload))
    wrong_argv["argv"][-1] = "attempt_abcdef0123456789"
    # JSON Schema validates opaque shape; the SDK performs cross-field equality.
    assert not validator.validate_json(wrong_argv, "resolve_decision_response_schema")


def test_shadow_is_exact_support_and_never_certifies_global_backoff() -> None:
    validator = SchemaValidator(contract="backend")
    base = {
        "schema_version": "2.0.0",
        "evidence_snapshot_hash": "ev_0123456789abcdefghijklmnopqrstuvwxyzAB",
        "profile": "balanced",
        "rules": _exact_action(),
        "policy": _exact_action(),
        "disagrees": False,
        "diagnostics": {
            "advantage_point": None,
            "advantage_lcb": None,
            "advantage_ucb": None,
            "support_n": 0,
            "effective_support_n": 0,
            "support_status": "none",
            "certified": False,
            "certificate_ref": None,
            "cell_fingerprint": None,
        },
        "pins": {
            "rules_version": "planner-v2-rules-2026.07.4",
            "rules_hash": "a" * 64,
            "shield_version": "planner-v2-shield-2026.07.4",
            "shield_hash": "b" * 64,
            "economics_hash": "df7d6d7c95e61716a55eec42f829c7ca2bb66c285ce4013e66f5dc1cac956d02",
            "artifact_version": "planner-v2-overrides-2026.07.4",
            "artifact_hash": "d" * 64,
            "claim_scope": "formal_safety_admissibility_accounting_lineage_only_no_kpi_proof",
        },
        "evaluated_at": "2026-07-10T09:00:00Z",
    }
    assert not validator.validate_json(base, "shadow_evaluate_response_schema")

    certified = json.loads(json.dumps(base))
    certified.update(policy=_exact_action(optimize=True), disagrees=True)
    certified["diagnostics"].update(
        advantage_point=0.2,
        advantage_lcb=0.1,
        advantage_ucb=0.3,
        support_n=128,
        effective_support_n=128,
        support_status="exact",
        certified=True,
        certificate_ref="certificate_0123456789abcdef",
        cell_fingerprint="e" * 64,
    )
    assert not validator.validate_json(certified, "shadow_evaluate_response_schema")
    insufficient_support = json.loads(json.dumps(certified))
    insufficient_support["diagnostics"].update(
        support_n=127,
        effective_support_n=127,
    )
    assert validator.validate_json(
        insufficient_support, "shadow_evaluate_response_schema"
    )
    honest_unknown_ucb = json.loads(json.dumps(certified))
    honest_unknown_ucb["diagnostics"]["advantage_ucb"] = None
    assert not validator.validate_json(
        honest_unknown_ucb, "shadow_evaluate_response_schema"
    )

    global_certified = json.loads(json.dumps(certified))
    global_certified["diagnostics"]["support_status"] = "global"
    assert validator.validate_json(global_certified, "shadow_evaluate_response_schema")
    missing_certificate = json.loads(json.dumps(certified))
    missing_certificate["diagnostics"]["certificate_ref"] = None
    assert validator.validate_json(missing_certificate, "shadow_evaluate_response_schema")
    false_agreement = json.loads(json.dumps(certified))
    false_agreement["disagrees"] = False
    assert validator.validate_json(false_agreement, "shadow_evaluate_response_schema")


def test_receipt_response_status_verification_combinations_are_closed() -> None:
    validator = SchemaValidator(contract="backend")
    payload = {
        "schema_version": "2.0.0",
        "receipt_id": "receipt_0123456789abcdef",
        "lifecycle_id": "lifecycle_0123456789abcdef",
        "decision_id": "decision_0123456789abcdef",
        "attempt_id": "attempt_0123456789abcdef",
        "status": "started",
        "verification_status": "pending",
        "idempotent_replay": False,
        "updated_at": "2026-07-10T09:00:00Z",
    }
    assert not validator.validate_json(payload, "receipt_response_schema")
    payload["verification_status"] = "verified"
    assert validator.validate_json(payload, "receipt_response_schema")
    payload.update(status="failed", verification_status="rejected")
    assert not validator.validate_json(payload, "receipt_response_schema")
    payload["verification_status"] = "verified"
    assert validator.validate_json(payload, "receipt_response_schema")
