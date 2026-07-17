# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for economics telemetry (WI-B): exposure funnel, run economics,
and machine-verifiable receipts.

The point of this contract is that a claim of value cannot be made by narrative,
so these tests are mostly ADVERSARIAL: each one submits the payload a motivated
agent would send to get paid without producing evidence, and asserts the contract
rejects it. The positive cases exist to prove the strictness did not also reject
honest telemetry.

Invariants JSON Schema cannot enforce (tenant ownership, funnel order,
proposer != verifier, immutable/idempotent persistence) are NOT tested here —
they are not provable here. They are asserted to be *declared* as backend
obligations, so the next packet inherits a visible list rather than an assumption.
"""

from __future__ import annotations

import json
from copy import deepcopy

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

ECON = get_schemas_dir() / "economics"

INGEST = "economics_telemetry_ingest_request_schema"
RESPONSE = "economics_telemetry_ingest_response_schema"
RECEIPT = "economics_receipt_event_schema"
RUN = "economics_run_event_schema"
FUNNEL = "economics_funnel_event_schema"


def _v() -> SchemaValidator:
    return SchemaValidator(contract="planned_projects")


def _load(name: str) -> dict:
    with open(ECON / name, encoding="utf-8") as fh:
        return json.load(fh)


def _ok(payload: dict, schema: str) -> bool:
    return _v().validate_json(payload, schema) == []


def _rejected(payload: dict, schema: str) -> bool:
    return _v().validate_json(payload, schema) != []


# --------------------------------------------------------------------------- #
# fixtures
# --------------------------------------------------------------------------- #
def _funnel_event(**extra) -> dict:
    event = {
        "event_type": "funnel_event",
        "event_id": "evt-funnel-1",
        "occurred_at": "2026-07-17T10:00:00Z",
        "project_ref": "proj-1",
        "stage": "advice_shown",
        "outcome": "entered",
    }
    event.update(extra)
    return event


def _interval(**extra) -> dict:
    interval = {
        "estimate": 0.07,
        "lower": 0.02,
        "upper": 0.12,
        "level": 0.95,
        "unit": "proportion",
    }
    interval.update(extra)
    return interval


def _run_event(**extra) -> dict:
    event = {
        "event_type": "run_economics",
        "event_id": "evt-run-1",
        "occurred_at": "2026-07-17T10:00:00Z",
        "project_ref": "proj-1",
        "run_id": "run-1",
        "archetype": "solo_coding_builder",
        "characterization": {
            "bands": {
                "value_channel": "save_expert_time",
                "daily_volume_band": "under_100",
                "error_cost_band": "human_correction_1_to_50_usd",
            },
            "overrides": {"observed_daily_volume": 3100},
            "field_reports": [
                {
                    "field": "value_channel",
                    "provenance": "asked",
                    "confidence": 1.0,
                    "sharing_outcome": "shared",
                },
                {
                    "field": "observed_daily_volume",
                    "provenance": "inferred",
                    "confidence": 0.8,
                    "sharing_outcome": "shared",
                    "evidence_status": "provided",
                    "evidence_pointer": "traces show ~3.1k runs/day over 14 days",
                },
            ],
            "asked_count": 2,
        },
        "budget": {
            "authored_by": "backend",
            "recommended_daily_usd": 5.0,
            "cap_usd": 50.0,
            "policy_version": "budget-policy-v0",
            "credit_backed": True,
        },
        "actual_spend_usd": 4.25,
        "usage": {"input_tokens": 120000, "output_tokens": 8000, "model_calls": 240},
        "model_prices": [
            {
                "model_id": "claude-haiku-4-5",
                "input_usd_per_mtok": 1.0,
                "output_usd_per_mtok": 5.0,
                "price_source": "provider_published",
                "as_of": "2026-07-17T00:00:00Z",
            }
        ],
        "evidence_identity": {
            "baseline_run_id": "run-base",
            "candidate_run_id": "run-1",
            "dataset_hash": "a" * 64,
            "holdout_hash": "b" * 64,
            "evaluator_version": "exec-match-v2",
            "objective_weights": [{"objective": "accuracy", "weight": 1.0}],
            "effect_estimate": _interval(),
            "support": {"n_examples": 300, "n_paired": 300},
            "exclusions": [{"reason": "parse_failure", "count": 2}],
        },
        "advisory": {
            "recommended_action": "run_optimization",
            "client_action": "followed",
            "adherence_probability": 0.6,
            "planner_blind_information": "none_known",
        },
        "labor_proxies": {"manual_interventions": 1, "tuning_cycles": 2},
    }
    event.update(extra)
    return event


def _attestation(**extra) -> dict:
    attestation = {
        "proposer_id": "agent-1",
        "verifier_id": "reviewer-9",
        "verifier_kind": "human_reviewer",
        "verified_at": "2026-07-17T11:00:00Z",
    }
    attestation.update(extra)
    return attestation


def _winner_receipt(**extra) -> dict:
    event = {
        "event_type": "receipt",
        "event_id": "evt-receipt-w1",
        "occurred_at": "2026-07-17T11:00:00Z",
        "project_ref": "proj-1",
        "receipt_kind": "winner",
        "attestation": _attestation(verifier_kind="platform_statistics"),
        "winner": {
            "run_identity": {"run_id": "run-1", "run_immutable_hash": "c" * 64},
            "actual_cost_usd": 4.25,
            "paired_delta": _interval(),
            "paired": True,
            "selected_config_hash": "d" * 64,
            "promotion": {"status": "promoted", "promoted_at": "2026-07-17T12:00:00Z"},
            "production_follow_up": {"status": "scheduled", "due_at": "2026-07-24T12:00:00Z"},
        },
    }
    event.update(extra)
    return event


def _defect_receipt(**extra) -> dict:
    event = {
        "event_type": "receipt",
        "event_id": "evt-receipt-d1",
        "occurred_at": "2026-07-17T11:00:00Z",
        "project_ref": "proj-1",
        "receipt_kind": "defect",
        "attestation": _attestation(),
        "defect": {
            "example_hash": "e" * 64,
            "defect_class": "wrong_label",
            "disposition": {
                "verdict": "confirmed_defect",
                "disposed_by": "human_reviewer",
                "disposed_at": "2026-07-17T10:55:00Z",
            },
            "reviewer_minutes": 5,
            "correction": {"kind": "corrected_example", "reference": "fix-123"},
            "duplicate_check": {"performed": True, "result": "unique"},
        },
    }
    event.update(extra)
    return event


def _savings_receipt(**extra) -> dict:
    event = {
        "event_type": "receipt",
        "event_id": "evt-receipt-s1",
        "occurred_at": "2026-07-17T11:00:00Z",
        "project_ref": "proj-1",
        "receipt_kind": "savings",
        "attestation": _attestation(verifier_kind="platform_meter"),
        "savings": {
            "measurement_method": "metered",
            "meter_source": "provider_invoice",
            "measured_at": "2026-07-17T11:00:00Z",
            "window": {"start": "2026-07-10T00:00:00Z", "end": "2026-07-17T00:00:00Z"},
            "tokens_saved": 400000,
            "usd_saved": 12.5,
        },
    }
    event.update(extra)
    return event


def _batch(*events, **extra) -> dict:
    body = {
        "contract": "economics_telemetry",
        "contract_version": "1.0.0",
        "batch_id": "batch-1",
        "idempotency_key": "batch-key-0001",
        "sent_at": "2026-07-17T12:00:00Z",
        "source": {"kind": "python_sdk", "name": "traigent", "version": "0.11.4"},
        "events": list(events) or [_funnel_event()],
    }
    body.update(extra)
    return body


# --------------------------------------------------------------------------- #
# wiring / posture
# --------------------------------------------------------------------------- #
def test_route_binds_the_ingest_request_schema() -> None:
    validator = _v()
    assert (
        validator._endpoint_schemas.get("POST:/api/v1/economics/telemetry") == INGEST
    ), "economics telemetry route must resolve through SchemaValidator, not fail open"
    assert validator.validate_request("/api/v1/economics/telemetry", "POST", _batch()) == []
    assert validator.validate_request("/api/v1/economics/telemetry", "POST", {}) != []


def test_route_is_not_claimed_as_canonical_backend_truth() -> None:
    """Contract-first honesty: no backend serves this yet, so it must not sit in
    the canonical `backend` root, which means 'current backend truth'."""
    assert (
        SchemaValidator(contract="backend")._endpoint_schemas.get(
            "POST:/api/v1/economics/telemetry"
        )
        is None
    )
    catalog = _load("economics_endpoints.json")
    assert catalog["x-stability"] == "pre-release"
    assert catalog["x-asserted-against-backend"] is False


def test_full_batch_of_every_event_kind_validates() -> None:
    body = _batch(
        _funnel_event(), _run_event(), _winner_receipt(), _defect_receipt(), _savings_receipt()
    )
    assert _ok(body, INGEST)


# --------------------------------------------------------------------------- #
# envelope: idempotency, batch bounds, stable identifiers
# --------------------------------------------------------------------------- #
def test_envelope_requires_stable_contract_and_version_identifiers() -> None:
    assert _rejected(_batch(contract="observability_telemetry"), INGEST)
    assert _rejected(_batch(contract_version="1.1.0"), INGEST)
    for missing in (
        "contract", "contract_version", "batch_id", "idempotency_key", "sent_at", "source"
    ):
        body = _batch()
        del body[missing]
        assert _rejected(body, INGEST), missing


def test_envelope_rejects_unknown_fields_and_unbounded_batches() -> None:
    assert _rejected(_batch(tenant_id="t-other"), INGEST), (
        "a client-asserted tenant field must not be representable"
    )
    assert _rejected(_batch(events=[]), INGEST)
    assert _rejected(_batch(events=[_funnel_event() for _ in range(501)]), INGEST)
    assert _ok(_batch(events=[_funnel_event() for _ in range(500)]), INGEST)


def test_idempotency_key_is_bounded_and_shaped() -> None:
    assert _rejected(_batch(idempotency_key="short"), INGEST)
    assert _rejected(_batch(idempotency_key="has spaces in it"), INGEST)
    assert _rejected(_batch(idempotency_key="k" * 129), INGEST)


def test_unknown_event_type_matches_no_branch() -> None:
    assert _rejected(_batch(_funnel_event(event_type="mystery_event")), INGEST)
    assert _rejected(_batch({"event_type": "run_economics"}), INGEST)


# --------------------------------------------------------------------------- #
# funnel: every exit carries a closed reason
# --------------------------------------------------------------------------- #
def test_every_funnel_stage_is_representable() -> None:
    stages = _load("economics_funnel_event_schema.json")["properties"]["stage"]["enum"]
    assert stages == [
        "eligible",
        "advice_shown",
        "budget_allocated",
        "run_started",
        "completed",
        "recommendation_accepted",
        "executed",
        "promoted",
        "production_retained",
    ]
    for stage in stages:
        assert _ok(_funnel_event(stage=stage), FUNNEL), stage


def test_exit_requires_a_reason_and_entry_forbids_one() -> None:
    assert _rejected(_funnel_event(outcome="exited"), FUNNEL)
    assert _ok(_funnel_event(outcome="exited", exit_reason="budget_exhausted"), FUNNEL)
    assert _rejected(
        _funnel_event(outcome="entered", exit_reason="budget_exhausted"), FUNNEL
    ), "an 'entered' event carrying an exit reason is incoherent"


def test_exit_reason_vocabulary_is_closed() -> None:
    for reason in ("other", "misc", "", "user declined"):
        assert _rejected(_funnel_event(outcome="exited", exit_reason=reason), FUNNEL), reason


def test_exit_detail_cannot_stand_in_for_a_reason_code() -> None:
    assert _rejected(
        _funnel_event(outcome="exited", exit_detail="they just did not want to"), FUNNEL
    )
    assert _rejected(
        _funnel_event(outcome="entered", exit_detail="a note"), FUNNEL
    )
    assert _ok(
        _funnel_event(outcome="exited", exit_reason="user_declined", exit_detail="note"),
        FUNNEL,
    )


def test_funnel_rejects_unknown_stage_and_unknown_field() -> None:
    assert _rejected(_funnel_event(stage="thinking_about_it"), FUNNEL)
    assert _rejected(_funnel_event(surprise=1), FUNNEL)


# --------------------------------------------------------------------------- #
# characterization provenance / sharing (telemetry only)
# --------------------------------------------------------------------------- #
def _with_reports(*reports) -> dict:
    event = _run_event()
    event["characterization"]["field_reports"] = list(reports)
    return event


def test_inferred_value_must_account_for_its_evidence() -> None:
    assert _rejected(
        _with_reports(
            {
                "field": "observed_daily_volume",
                "provenance": "inferred",
                "sharing_outcome": "shared",
            }
        ),
        RUN,
    ), "an inferred value with no evidence status is an unsupported guess"


def test_inferred_evidence_may_be_withheld_but_not_leaked() -> None:
    # the honest withholding case: evidence exists, policy kept it local
    assert _ok(
        _with_reports(
            {
                "field": "loss_per_bad_output_usd",
                "provenance": "inferred",
                "sharing_outcome": "withheld_by_policy",
                "evidence_status": "withheld_by_policy",
            }
        ),
        RUN,
    )
    # withheld evidence must not ride along in the pointer field
    assert _rejected(
        _with_reports(
            {
                "field": "loss_per_bad_output_usd",
                "provenance": "inferred",
                "sharing_outcome": "withheld_by_policy",
                "evidence_status": "withheld_by_policy",
                "evidence_pointer": "incident ledger shows $4k median escalation",
            }
        ),
        RUN,
    )
    # claiming the evidence was provided while omitting it is also incoherent
    assert _rejected(
        _with_reports(
            {
                "field": "loss_per_bad_output_usd",
                "provenance": "inferred",
                "sharing_outcome": "shared",
                "evidence_status": "provided",
            }
        ),
        RUN,
    )


def test_asked_and_defaulted_values_cannot_claim_inference_evidence() -> None:
    for provenance in ("asked", "defaulted"):
        assert _rejected(
            _with_reports(
                {
                    "field": "value_channel",
                    "provenance": provenance,
                    "sharing_outcome": "shared",
                    "evidence_status": "provided",
                    "evidence_pointer": "made this up",
                }
            ),
            RUN,
        ), provenance


def test_a_field_declared_withheld_cannot_ship_its_value_anyway() -> None:
    """The closed-pipe promise: 'withheld_by_policy' must mean the value did not
    leave the machine. Draft-07 CAN enforce this — it is a presence check keyed on
    a closed enum, not a comparison of two values — so it is enforced here rather
    than deferred to the backend, and this test is the proof that it bites."""
    # a band declared withheld while its value rides along in `bands`
    event = _run_event()
    event["characterization"]["bands"]["lifecycle_stage"] = "full_production_we_pay"
    event["characterization"]["field_reports"] = [
        {
            "field": "lifecycle_stage",
            "provenance": "asked",
            "sharing_outcome": "withheld_by_policy",
        }
    ]
    assert _rejected(event, RUN), (
        "declaring a field withheld while shipping its value must be unrepresentable"
    )

    # the honest withholding: declared withheld, absent from bands
    del event["characterization"]["bands"]["lifecycle_stage"]
    assert _ok(event, RUN), "an honestly withheld field must still be reportable"

    # the same rule for a typed override, not just a band
    event = _run_event()
    event["characterization"]["overrides"]["observed_daily_volume"] = 3100
    event["characterization"]["field_reports"] = [
        {
            "field": "observed_daily_volume",
            "provenance": "inferred",
            "sharing_outcome": "withheld_by_policy",
            "evidence_status": "withheld_by_policy",
        }
    ]
    assert _rejected(event, RUN), "the egress rule must cover overrides, not only bands"
    del event["characterization"]["overrides"]["observed_daily_volume"]
    assert _ok(event, RUN)


def test_the_withheld_egress_rule_covers_every_allowlisted_field() -> None:
    """A per-field conditional is only as good as its coverage: one field left out
    of the expansion is a silent hole, and the hole is exactly a privacy leak."""
    vocab = _load("economics_characterization_vocabulary_schema.json")["definitions"]
    bands = set(vocab["CharacterizationBands"]["properties"])
    overrides = set(vocab["CharacterizationOverrides"]["properties"])
    sample = {
        "value_channel": "save_expert_time",
        "daily_volume_band": "under_100",
        "error_cost_band": "not_measured",
        "lifecycle_stage": "full_production_we_pay",
        "human_cycle_hours_band": "1_to_8h",
        "value_per_task_usd": 2.5,
        "loss_per_bad_output_usd": 40.0,
        "observed_daily_volume": 3100,
        "forecast_daily_volume": 9000,
        "human_minutes_per_example": 5,
    }
    assert set(sample) == bands | overrides, "sample must cover the whole allowlist"

    for field, value in sample.items():
        event = _run_event()
        event["characterization"]["bands"] = {}
        event["characterization"]["overrides"] = {}
        container = "bands" if field in bands else "overrides"
        event["characterization"][container][field] = value
        report = {"field": field, "provenance": "asked", "sharing_outcome": "withheld_by_policy"}
        event["characterization"]["field_reports"] = [report]
        assert _rejected(event, RUN), f"{field}: withheld value can still egress"
        # and the same payload passes once the value is actually withheld
        del event["characterization"][container][field]
        assert _ok(event, RUN), f"{field}: honest withholding must not be rejected"


def test_shared_fields_are_unaffected_by_the_withheld_rule() -> None:
    """Guard against the rule passing for the wrong reason: it must key on the
    sharing outcome, not simply forbid bands that have a field report."""
    event = _run_event()
    event["characterization"]["bands"]["lifecycle_stage"] = "full_production_we_pay"
    event["characterization"]["field_reports"] = [
        {"field": "lifecycle_stage", "provenance": "asked", "sharing_outcome": "shared"}
    ]
    assert _ok(event, RUN), "a shared field must be able to carry its value"


def test_only_allowlisted_characterization_fields_can_egress() -> None:
    assert _rejected(
        _with_reports(
            {"field": "customer_name", "provenance": "asked", "sharing_outcome": "shared"}
        ),
        RUN,
    )
    event = _run_event()
    event["characterization"]["bands"]["internal_revenue_forecast"] = "big"
    assert _rejected(event, RUN)
    event = _run_event()
    event["characterization"]["agent_display_name"] = "our QA agent"
    assert _rejected(event, RUN), "presentation-only fields must not egress as telemetry"


def test_allowlist_exactly_mirrors_the_band_and_override_properties() -> None:
    vocab = _load("economics_characterization_vocabulary_schema.json")["definitions"]
    allowlist = set(vocab["CharacterizationFieldName"]["enum"])
    declared = set(vocab["CharacterizationBands"]["properties"]) | set(
        vocab["CharacterizationOverrides"]["properties"]
    )
    assert allowlist == declared, "the egress allowlist and the declared fields must not drift"


def test_provenance_and_sharing_vocabularies_are_closed() -> None:
    assert _rejected(
        _with_reports(
            {"field": "value_channel", "provenance": "guessed", "sharing_outcome": "shared"}
        ),
        RUN,
    )
    assert _rejected(
        _with_reports(
            {"field": "value_channel", "provenance": "asked", "sharing_outcome": "sold"}
        ),
        RUN,
    )


def test_characterization_overrides_are_typed_and_nonnegative() -> None:
    event = _run_event()
    event["characterization"]["overrides"] = {"observed_daily_volume": "about 3k"}
    assert _rejected(event, RUN)
    event = _run_event()
    event["characterization"]["overrides"] = {"loss_per_bad_output_usd": -5}
    assert _rejected(event, RUN)


# --------------------------------------------------------------------------- #
# run economics: budget authorship, amounts, evidence identity, advisory, labor
# --------------------------------------------------------------------------- #
def test_budget_recommendation_and_cap_are_backend_authored() -> None:
    agent_authored = {"authored_by": "agent", "recommended_daily_usd": 500.0, "cap_usd": 500.0}
    assert _rejected(_run_event(budget=agent_authored), RUN)
    event = _run_event()
    del event["budget"]["cap_usd"]
    assert _rejected(event, RUN), "a budget without a cap is not a bounded investment"


def test_monetary_and_count_fields_are_typed_nonnegative_and_bounded() -> None:
    assert _rejected(_run_event(actual_spend_usd=-1), RUN)
    assert _rejected(_run_event(actual_spend_usd="4.25"), RUN)
    assert _rejected(_run_event(actual_spend_usd=1e12), RUN)
    event = _run_event()
    event["usage"]["input_tokens"] = -5
    assert _rejected(event, RUN)
    event = _run_event()
    event["usage"]["input_tokens"] = 1.5
    assert _rejected(event, RUN), "token counts are integers"


def test_effect_estimate_must_carry_an_interval_and_its_level() -> None:
    event = _run_event()
    event["evidence_identity"]["effect_estimate"] = {"estimate": 0.07, "unit": "proportion"}
    assert _rejected(event, RUN), "a point estimate is not evidence"
    event = _run_event()
    interval = _interval()
    del interval["level"]
    event["evidence_identity"]["effect_estimate"] = interval
    assert _rejected(event, RUN), "an interval without its level cannot be read as a bound"


def test_evidence_identity_requires_baseline_dataset_and_evaluator() -> None:
    for field in ("baseline_run_id", "candidate_run_id", "dataset_hash", "evaluator_version"):
        event = _run_event()
        del event["evidence_identity"][field]
        assert _rejected(event, RUN), field


def test_hashes_must_be_real_digests() -> None:
    event = _run_event()
    event["evidence_identity"]["dataset_hash"] = "the-training-set"
    assert _rejected(event, RUN)
    event = _run_event()
    event["evidence_identity"]["dataset_hash"] = "A" * 64
    assert _rejected(event, RUN), "digests are lowercase hex"


def test_exclusion_reasons_are_closed() -> None:
    event = _run_event()
    event["evidence_identity"]["exclusions"] = [{"reason": "looked_wrong", "count": 40}]
    assert _rejected(event, RUN)


def test_off_menu_client_action_must_be_classified() -> None:
    event = _run_event()
    event["advisory"]["client_action"] = "off_menu"
    assert _rejected(event, RUN), "an unexplained off-menu action is a hole in the adherence model"
    event["advisory"]["off_menu_action_class"] = "manual_change_outside_platform"
    assert _ok(event, RUN)
    event = _run_event()
    event["advisory"]["off_menu_action_class"] = "escalated_to_human"
    assert _rejected(event, RUN), "client_action=followed cannot carry an off-menu class"


def test_advisory_requires_both_the_recommendation_and_what_the_client_did() -> None:
    for field in ("recommended_action", "client_action"):
        event = _run_event()
        del event["advisory"][field]
        assert _rejected(event, RUN), field


def test_claimed_hours_avoided_require_human_confirmation() -> None:
    event = _run_event()
    event["labor_proxies"]["user_confirmed_hours_avoided"] = 12
    assert _rejected(event, RUN), "an agent cannot confirm its own labor savings"
    event["labor_proxies"]["hours_confirmed_by"] = "end_user_confirmation"
    assert _ok(event, RUN)
    event = _run_event()
    event["labor_proxies"]["user_confirmed_hours_avoided"] = 12
    event["labor_proxies"]["hours_confirmed_by"] = "the_agent"
    assert _rejected(event, RUN)


def test_model_prices_cannot_be_agent_asserted() -> None:
    event = _run_event()
    event["model_prices"][0]["price_source"] = "agent_estimate"
    assert _rejected(event, RUN)


# --------------------------------------------------------------------------- #
# receipts: closed kinds, kind-specific evidence
# --------------------------------------------------------------------------- #
def test_receipt_kinds_are_closed() -> None:
    assert _load("economics_receipt_event_schema.json")["properties"]["receipt_kind"]["enum"] == [
        "winner",
        "defect",
        "savings",
    ]
    assert _rejected(_winner_receipt(receipt_kind="improvement"), RECEIPT)


def test_every_receipt_needs_an_attestation() -> None:
    event = _winner_receipt()
    del event["attestation"]
    assert _rejected(event, RECEIPT)


def test_the_proposing_agent_is_not_a_permitted_verifier_kind() -> None:
    assert _rejected(
        _winner_receipt(attestation=_attestation(verifier_kind="proposing_agent")), RECEIPT
    )
    assert _rejected(
        _defect_receipt(attestation=_attestation(verifier_kind="self")), RECEIPT
    )


def test_receipt_kind_binds_its_own_evidence_block() -> None:
    assert _rejected(_winner_receipt(receipt_kind="savings"), RECEIPT)
    event = _winner_receipt()
    del event["winner"]
    assert _rejected(event, RECEIPT)


def test_a_receipt_cannot_carry_another_kinds_block() -> None:
    event = _savings_receipt()
    event["winner"] = _winner_receipt()["winner"]
    assert _rejected(event, RECEIPT), "cross-kind contamination must be unrepresentable"


def test_winner_receipt_requires_immutable_identity_cost_and_paired_delta() -> None:
    for field in (
        "run_identity", "actual_cost_usd", "paired_delta", "paired", "selected_config_hash",
        "promotion",
    ):
        event = _winner_receipt()
        del event["winner"][field]
        assert _rejected(event, RECEIPT), field
    event = _winner_receipt()
    del event["winner"]["run_identity"]["run_immutable_hash"]
    assert _rejected(event, RECEIPT), "a winner against a mutable run label is not checkable"


def test_pairing_cannot_be_evaded_by_declaring_it_false_or_staying_silent() -> None:
    """`paired` is a REQUIRED const, not an optional one: an optional const is
    satisfied by omission, which would let the cheapest unpaired claim through."""
    event = _winner_receipt()
    event["winner"]["paired"] = False
    assert _rejected(event, RECEIPT), "an unpaired winner receipt is not a winner receipt"
    event = _winner_receipt()
    del event["winner"]["paired"]
    assert _rejected(event, RECEIPT), "silence about pairing must not be a way around the const"


def test_winner_promotion_status_and_timestamps_must_agree() -> None:
    event = _winner_receipt()
    event["winner"]["promotion"] = {"status": "promoted"}
    assert _rejected(event, RECEIPT), "promoted without a promotion time"
    event["winner"]["promotion"] = {"status": "not_promoted", "promoted_at": "2026-07-17T12:00:00Z"}
    assert _rejected(event, RECEIPT)
    event["winner"]["promotion"] = {
        "status": "reverted",
        "promoted_at": "2026-07-17T12:00:00Z",
        "reverted_at": "2026-07-18T12:00:00Z",
    }
    assert _ok(event, RECEIPT)
    event["winner"]["promotion"] = {"status": "not_promoted"}
    assert _ok(event, RECEIPT), "a supported result the client declined is still a valid receipt"


def test_production_follow_up_can_report_a_contradiction_and_must_measure_it() -> None:
    event = _winner_receipt()
    event["winner"]["production_follow_up"] = {"status": "contradicted"}
    assert _rejected(event, RECEIPT), "a contradiction claim must carry its measurement"
    event["winner"]["production_follow_up"] = {
        "status": "contradicted",
        "measured_at": "2026-07-24T12:00:00Z",
        "production_delta": _interval(estimate=-0.03, lower=-0.08, upper=0.01),
    }
    assert _ok(event, RECEIPT), "eval-to-production reversal must be reportable"


def test_defect_receipt_requires_independent_disposition_and_review_cost() -> None:
    for field in (
        "example_hash", "defect_class", "disposition", "reviewer_minutes", "duplicate_check"
    ):
        event = _defect_receipt()
        del event["defect"][field]
        assert _rejected(event, RECEIPT), field
    event = _defect_receipt()
    event["defect"]["disposition"]["disposed_by"] = "flagging_agent"
    assert _rejected(event, RECEIPT), "the agent that flagged the example cannot dispose of it"


def test_confirmed_defect_requires_a_correction_or_validating_test() -> None:
    event = _defect_receipt()
    del event["defect"]["correction"]
    assert _rejected(event, RECEIPT), "a confirmed defect with nothing fixed produced no value"
    # a non-confirmed verdict does not need a correction — and must stay reportable
    event["defect"]["disposition"]["verdict"] = "not_a_defect"
    assert _ok(event, RECEIPT)


def test_defect_duplicate_check_is_mandatory_and_coherent() -> None:
    event = _defect_receipt()
    event["defect"]["duplicate_check"] = {"performed": False, "result": "unique"}
    assert _rejected(event, RECEIPT), "the duplicate check cannot be declared skipped"
    event["defect"]["duplicate_check"] = {"performed": True, "result": "duplicate_of_known_defect"}
    assert _rejected(event, RECEIPT), "a duplicate must name what it duplicates"
    event["defect"]["duplicate_check"] = {
        "performed": True,
        "result": "duplicate_of_known_defect",
        "duplicate_of": "defect-77",
    }
    assert _ok(event, RECEIPT)
    event["defect"]["duplicate_check"] = {
        "performed": True,
        "result": "unique",
        "duplicate_of": "defect-77",
    }
    assert _rejected(event, RECEIPT)


def test_defect_downstream_metric_change_may_be_negative() -> None:
    event = _defect_receipt()
    event["defect"]["downstream_metric_change"] = {
        "metric": "accuracy",
        "delta": -0.01,
        "unit": "proportion",
        "measured_at": "2026-07-18T12:00:00Z",
    }
    assert _ok(event, RECEIPT), "fixing a defect can move a metric the wrong way"


def test_savings_receipt_rejects_agent_authored_estimates() -> None:
    estimated = {**_savings_receipt()["savings"], "measurement_method": "estimated"}
    assert _rejected(
        _savings_receipt(savings=estimated), RECEIPT
    ), "there is no 'estimated' savings receipt"
    for source in ("agent_estimate", "sdk_calculation", "user_assertion", "model_self_report"):
        event = _savings_receipt()
        event["savings"]["meter_source"] = source
        assert _rejected(event, RECEIPT), source


def test_savings_receipt_requires_a_meter_a_window_and_a_metered_quantity() -> None:
    for field in ("measurement_method", "meter_source", "measured_at", "window"):
        event = _savings_receipt()
        del event["savings"][field]
        assert _rejected(event, RECEIPT), field
    event = _savings_receipt()
    for quantity in ("tokens_saved", "usd_saved"):
        del event["savings"][quantity]
    assert _rejected(event, RECEIPT), "a savings receipt that meters nothing is empty"


def test_savings_quantities_are_signed() -> None:
    event = _savings_receipt()
    event["savings"]["usd_saved"] = -3.0
    event["savings"]["tokens_saved"] = -1000
    assert _ok(event, RECEIPT), "a meter that can only report savings is not a meter"


def test_receipts_reject_unknown_fields() -> None:
    assert _rejected(_winner_receipt(narrative="this was a great run"), RECEIPT)
    event = _savings_receipt()
    event["savings"]["estimated_usd_saved"] = 999.0
    assert _rejected(event, RECEIPT)


# --------------------------------------------------------------------------- #
# response
# --------------------------------------------------------------------------- #
def _response(**extra) -> dict:
    body = {
        "contract": "economics_telemetry",
        "contract_version": "1.0.0",
        "batch_id": "batch-1",
        "idempotency_key": "batch-key-0001",
        "received_at": "2026-07-17T12:00:01Z",
        "replayed": False,
        "counts": {"submitted": 3, "accepted": 2, "duplicate": 0, "rejected": 1},
        "rejections": [
            {
                "event_index": 2,
                "event_id": "evt-receipt-s1",
                "reason": "meter_reconciliation_failed",
            }
        ],
    }
    body.update(extra)
    return body


def test_response_reports_disposition_counts_and_closed_rejection_reasons() -> None:
    assert _ok(_response(), RESPONSE)
    assert _ok(_response(replayed=True), RESPONSE)
    for field in ("submitted", "accepted", "duplicate", "rejected"):
        body = _response()
        del body["counts"][field]
        assert _rejected(body, RESPONSE), field
    body = _response()
    body["rejections"][0]["reason"] = "because"
    assert _rejected(body, RESPONSE)
    body = _response()
    body["counts"]["accepted"] = -1
    assert _rejected(body, RESPONSE)
    assert _rejected(_response(surprise=True), RESPONSE)


def test_response_rejection_reasons_cover_the_backend_only_checks() -> None:
    """The checks JSON Schema cannot make must at least be reportable."""
    reasons = set(
        _load("economics_telemetry_ingest_response_schema.json")["properties"]["rejections"][
            "items"
        ]["properties"]["reason"]["enum"]
    )
    assert {
        "tenant_scope_violation",
        "funnel_order_violation",
        "attestation_not_independent",
        "duplicate_event_id",
        "meter_reconciliation_failed",
    } <= reasons


# --------------------------------------------------------------------------- #
# the schema boundary: cross-field checks Draft-07 cannot make
#
# These tests assert the LIMIT, not the guarantee. Each pins a payload the
# contract ACCEPTS and must not, so the gap is a visible, executable fact rather
# than a sentence in a report — and so the day a future contract closes one of
# them, the test fails loudly and gets rewritten as a rejection.
# --------------------------------------------------------------------------- #
def test_boundary_duplicate_field_names_are_accepted_because_uniqueitems_compares_objects() -> None:
    """`uniqueItems` deduplicates whole objects, so one field reported twice with
    DIFFERENT metadata passes. Backend obligation: duplicate_characterization_field."""
    contradictory = [
        {"field": "error_cost_band", "provenance": "asked", "sharing_outcome": "shared"},
        {
            "field": "error_cost_band",
            "provenance": "inferred",
            "confidence": 0.3,
            "sharing_outcome": "shared",
            "evidence_status": "provided",
            "evidence_pointer": "a second, conflicting story about the same field",
        },
    ]
    assert _ok(_with_reports(*contradictory), RUN), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the duplicate_characterization_field backend obligation"
    )
    # the byte-identical repeat IS caught, which is the narrow thing uniqueItems buys
    same = {"field": "error_cost_band", "provenance": "asked", "sharing_outcome": "shared"}
    assert _rejected(_with_reports(same, deepcopy(same)), RUN), (
        "uniqueItems must at least stop an identical repeat"
    )


def test_boundary_inverted_confidence_intervals_are_accepted() -> None:
    """lower <= estimate <= upper is not expressible in Draft-07: the three numbers
    are bounded independently and cannot be related. This is the interval that
    manufactures a positive lower bound from a losing result — the economics model
    leads with the lower bound, so it would be believed.
    Backend obligation: interval_bounds_inconsistent."""
    inverted = _interval(estimate=0.01, lower=0.9, upper=0.02)
    event = _run_event()
    event["evidence_identity"]["effect_estimate"] = inverted
    assert _ok(event, RUN), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the interval_bounds_inconsistent backend obligation"
    )
    # the same hole on the receipt, where it unlocks budget
    receipt = _winner_receipt()
    receipt["winner"]["paired_delta"] = inverted
    assert _ok(receipt, RECEIPT)


def test_boundary_support_counts_are_not_related_to_each_other() -> None:
    """n_paired <= n_examples is not expressible: more pairs than examples is
    impossible but contract-valid. Backend obligation: support_counts_inconsistent."""
    event = _run_event()
    event["evidence_identity"]["support"] = {"n_examples": 10, "n_paired": 10_000}
    assert _ok(event, RUN), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the support_counts_inconsistent backend obligation"
    )


def test_boundary_gaps_each_have_a_named_closed_rejection_reason() -> None:
    """A gap the backend cannot NAME cannot be actioned by the emitter. Each
    boundary above must map to a specific code, not to schema_violation."""
    reasons = set(
        _load("economics_telemetry_ingest_response_schema.json")["properties"]["rejections"][
            "items"
        ]["properties"]["reason"]["enum"]
    )
    assert {
        "duplicate_characterization_field",
        "interval_bounds_inconsistent",
        "support_counts_inconsistent",
        "withheld_field_value_present",
    } <= reasons


# --------------------------------------------------------------------------- #
# honesty: what this contract does NOT prove
# --------------------------------------------------------------------------- #
def test_unenforceable_invariants_are_declared_as_backend_obligations() -> None:
    """These are NOT proven by the contract. They must be visible as obligations
    for the backend packet, not quietly assumed."""
    obligations = {
        "economics_telemetry_ingest_request_schema.json": (
            "IDEMPOTENT", "TENANT OWNERSHIP", "IMMUTAB",
        ),
        "economics_receipt_event_schema.json": (
            "PROPOSER != VERIFIER", "IMMUTABLE PERSISTENCE", "INTERVAL ORDERING",
        ),
        "economics_funnel_event_schema.json": ("Funnel ORDER", "TENANT OWNERSHIP"),
        "economics_run_event_schema.json": (
            "TENANT OWNERSHIP",
            "BUDGET AUTHORSHIP",
            "UNIQUE CHARACTERIZATION FIELDS",
            "INTERVAL ORDERING",
            "SUPPORT COUNTS",
            "WITHHELD VALUES ARE NOT LOGGED",
        ),
    }
    for file_name, required in obligations.items():
        declared = _load(file_name).get("x-backend-obligations")
        assert declared, f"{file_name}: missing x-backend-obligations"
        blob = " ".join(declared)
        for marker in required:
            assert marker in blob, f"{file_name}: obligation '{marker}' not declared"


def test_survey_vocabulary_is_not_a_survey_submission_contract() -> None:
    """WI-B publishes the characterization VOCABULARY for telemetry only. The closed
    survey submission + calculator response contract is a later, separate deliverable."""
    vocab = _load("economics_characterization_vocabulary_schema.json")
    assert vocab["x-source-of-truth"] == "economics_characterization_vocabulary"
    assert "type" not in vocab, "a vocabulary declares definitions, not a payload shape"

    # No submission/calculator FIELD may be declared here (prose may discuss them).
    declared: set[str] = set()
    for definition in vocab["definitions"].values():
        declared.update(definition.get("properties", {}))
    for absent in (
        "sharing_policy",
        "recommended_daily_budget",
        "payback_days",
        "stop_rule",
        "receipt_requirement",
        "why",
    ):
        assert absent not in declared, (
            f"{absent} belongs to the survey submission/calculator contract, not the vocabulary"
        )


def test_deep_copy_fixtures_are_independent() -> None:
    """Guard the fixtures themselves: a shared mutable default would make the
    negative cases pass for the wrong reason."""
    first = _run_event()
    first["characterization"]["field_reports"].clear()
    assert deepcopy(_run_event())["characterization"]["field_reports"], "fixtures must be fresh"
