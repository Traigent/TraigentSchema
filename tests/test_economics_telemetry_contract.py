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
RESPONSE_REPLAY = "economics_telemetry_ingest_response_replay_schema"
RESPONSE_INITIAL = "economics_telemetry_ingest_response_initial_schema"
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
#: The stages at which each join key becomes mandatory, mirrored from the contract.
_ADVICE_STAGES = (
    "advice_shown",
    "budget_allocated",
    "run_started",
    "completed",
    "recommendation_accepted",
    "executed",
    "promoted",
    "production_retained",
)
_RUN_STAGES = (
    "run_started",
    "completed",
    "recommendation_accepted",
    "executed",
    "promoted",
    "production_retained",
)


def _funnel_event(**extra) -> dict:
    event = {
        "event_type": "funnel_event",
        "event_id": "evt-funnel-1",
        "occurred_at": "2026-07-17T10:00:00Z",
        "project_ref": "proj-1",
        "stage": "advice_shown",
        "outcome": "entered",
        "advice_id": "advice-1",
    }
    event.update(extra)
    return event


def _funnel_at(stage: str, **extra) -> dict:
    """A funnel event carrying exactly the join keys its stage requires."""
    event = _funnel_event(stage=stage, **extra)
    if stage not in _ADVICE_STAGES:
        event.pop("advice_id", None)
    if stage in _RUN_STAGES:
        event.setdefault("run_id", "run-1")
    if stage == "production_retained":
        # a production-retention observation is only honest in production
        event.setdefault("occurred_in_environment", "production")
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


def _report(field: str, **extra) -> dict:
    """A complete, honest field report. Defaults to the cheapest valid shape so a
    test that overrides one key is exercising exactly that key."""
    report = {
        "field": field,
        "provenance": "asked",
        "confidence": 1.0,
        "sharing_outcome": "shared",
    }
    report.update(extra)
    return report


def _run_event(**extra) -> dict:
    event = {
        "event_type": "run_economics",
        "event_id": "evt-run-1",
        "occurred_at": "2026-07-17T10:00:00Z",
        "project_ref": "proj-1",
        "run_id": "run-1",
        "archetype": "solo_coding_builder",
        # Every transmitted value below is reported; the one withheld field is
        # reported AND absent. The fixture is the worked example of the rule.
        "characterization": {
            "bands": {
                "value_channel": "save_expert_time",
                "daily_volume_band": "under_100",
                "error_cost_band": "human_correction_1_to_50_usd",
            },
            "overrides": {"observed_daily_volume": 3100},
            "field_reports": [
                _report("value_channel"),
                _report("daily_volume_band", provenance="inferred", confidence=0.7,
                        evidence_status="provided", evidence_pointer="14d of run counts"),
                _report("error_cost_band", provenance="defaulted", confidence=0.4),
                _report(
                    "observed_daily_volume",
                    provenance="inferred",
                    confidence=0.8,
                    evidence_status="provided",
                    evidence_pointer="traces show ~3.1k runs/day over 14 days",
                ),
                # withheld: reported, and its value is nowhere in the payload
                _report(
                    "loss_per_bad_output_usd",
                    provenance="inferred",
                    confidence=0.5,
                    sharing_outcome="withheld_by_policy",
                    evidence_status="withheld_by_policy",
                ),
            ],
            "sharing_policy_version": "sharing-policy-v0",
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
            "advice_id": "advice-1",
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
        assert _ok(_funnel_at(stage), FUNNEL), stage


def test_late_stages_must_name_the_advice_they_are_about() -> None:
    """A stage past eligibility exists BECAUSE a specific piece of advice was shown.
    Without advice_id it is an unjoinable count: 'someone was shown something, and
    separately someone promoted something' is not evidence that the promotion
    followed the advice, which is the entire claim the funnel exists to support."""
    for stage in _ADVICE_STAGES:
        event = _funnel_at(stage)
        del event["advice_id"]
        assert _rejected(event, FUNNEL), f"{stage}: unjoinable to the advice it is about"
        assert _ok(_funnel_at(stage), FUNNEL), stage


def test_late_stages_must_name_the_run_that_produced_them() -> None:
    """From run_started onward a run exists by definition. Without run_id the stage
    cannot be joined to the run_economics record holding the spend and the effect —
    a promotion whose evidence sits in an unlinkable record."""
    for stage in _RUN_STAGES:
        event = _funnel_at(stage)
        del event["run_id"]
        assert _rejected(event, FUNNEL), f"{stage}: unjoinable to its run"
        assert _ok(_funnel_at(stage), FUNNEL), stage


def test_production_retention_is_only_claimable_in_production() -> None:
    """production_retained is the numerator of the production-retention rate, and a
    retention claim is only meaningful where production actually ran. Without this
    conditional, occurred_in_environment could be omitted, `development`, or `staging`
    at production_retained and still count as retention — inflating the numerator with
    runs that never reached production."""
    # the honest positive: retained, observed in production
    assert _ok(_funnel_at("production_retained", occurred_in_environment="production"), FUNNEL)

    # omitting the environment is not a production claim
    missing = _funnel_at("production_retained")
    missing.pop("occurred_in_environment", None)
    assert _rejected(missing, FUNNEL), "production_retained without an environment is not a claim"

    # naming a non-production environment is rejected decisively
    for env in ("development", "staging"):
        assert _rejected(
            _funnel_at("production_retained", occurred_in_environment=env), FUNNEL
        ), env

    # the rule keys on the stage, not the outcome: an EXIT at production_retained is
    # still a claim about production and must obey the same rule
    assert _rejected(
        _funnel_at(
            "production_retained",
            outcome="exited",
            exit_reason="production_regression",
            occurred_in_environment="staging",
        ),
        FUNNEL,
    ), "an exit at production_retained must still be a production observation"
    assert _ok(
        _funnel_at(
            "production_retained",
            outcome="exited",
            exit_reason="production_regression",
            occurred_in_environment="production",
        ),
        FUNNEL,
    )

    # earlier stages are unconstrained: an event can be observed pre-production, or
    # record no environment at all
    assert _ok(_funnel_at("promoted", occurred_in_environment="staging"), FUNNEL)
    assert _ok(_funnel_at("promoted"), FUNNEL), "environment is optional before production_retained"


def test_the_stages_before_a_run_do_not_have_to_invent_one() -> None:
    """The boundaries of both rules, in the honest direction: requiring an id that
    cannot exist yet would force emitters to fabricate one, which is worse than the
    gap. eligible precedes any advice; nothing before run_started has a run."""
    assert _ok(
        {
            "event_type": "funnel_event",
            "event_id": "evt-funnel-0",
            "occurred_at": "2026-07-17T10:00:00Z",
            "project_ref": "proj-1",
            "stage": "eligible",
            "outcome": "entered",
        },
        FUNNEL,
    ), "eligibility precedes advice: no advice_id to name"

    for stage in ("advice_shown", "budget_allocated"):
        event = _funnel_at(stage)
        assert "run_id" not in event
        assert _ok(event, FUNNEL), f"{stage}: no run exists yet"

    # an id that legitimately exists early is still allowed to be named
    assert _ok(_funnel_at("budget_allocated", run_id="run-1"), FUNNEL)


def test_an_exit_still_has_to_name_its_stages_ids() -> None:
    """The rules key on the stage, not the outcome: a drop at `executed` is exactly
    where the join matters most — it is the advice that did not stick."""
    event = _funnel_at("executed", outcome="exited", exit_reason="promotion_reverted")
    assert _ok(event, FUNNEL)
    del event["advice_id"]
    assert _rejected(event, FUNNEL), "an exit must still say which advice it abandoned"


def test_exit_requires_a_reason_and_entry_forbids_one() -> None:
    assert _rejected(_funnel_event(outcome="exited"), FUNNEL)
    assert _ok(_funnel_event(outcome="exited", exit_reason="budget_exhausted"), FUNNEL)
    assert _rejected(
        _funnel_event(outcome="entered", exit_reason="budget_exhausted"), FUNNEL
    ), "an 'entered' event carrying an exit reason is incoherent"


def test_exit_reason_vocabulary_is_closed() -> None:
    for reason in ("other", "misc", "", "user declined"):
        assert _rejected(_funnel_event(outcome="exited", exit_reason=reason), FUNNEL), reason


def test_exit_detail_free_text_is_not_representable() -> None:
    """exit_detail was REMOVED from the ingest contract. A free-text note bypasses
    field-level sharing (it may echo client context the sharing policy would withhold)
    and analysis never reads it — the closed exit_reason code is the whole record. An
    exit that fits no code is a versioned enum addition, not a prose escape hatch, so
    exit_detail is now an unknown field rejected by additionalProperties:false — even
    alongside a valid reason code, which is where the old contract still admitted it."""
    assert _rejected(
        _funnel_event(outcome="exited", exit_reason="user_declined", exit_detail="note"),
        FUNNEL,
    ), "exit_detail must not be representable even alongside a valid reason code"
    assert _rejected(
        _funnel_event(outcome="exited", exit_detail="they just did not want to"), FUNNEL
    )
    assert _rejected(_funnel_event(outcome="entered", exit_detail="a note"), FUNNEL)
    # the closed reason code alone is the honest, complete exit record
    assert _ok(_funnel_event(outcome="exited", exit_reason="user_declined"), FUNNEL)
    # exit_detail is gone from the schema entirely, not merely constrained
    assert "exit_detail" not in _load("economics_funnel_event_schema.json")["properties"]


def test_funnel_rejects_unknown_stage_and_unknown_field() -> None:
    assert _rejected(_funnel_event(stage="thinking_about_it"), FUNNEL)
    assert _rejected(_funnel_event(surprise=1), FUNNEL)


# --------------------------------------------------------------------------- #
# characterization provenance / sharing (telemetry only)
# --------------------------------------------------------------------------- #
def _with_reports(*reports, bands=None, overrides=None) -> dict:
    """A run event whose characterization transmits ONLY the values passed here and
    reports ONLY the reports passed here.

    The full fixture's own bands/overrides are cleared deliberately. Leaving them in
    would make every payload here fail the coverage rule as well as the rule under
    test, and a test that passes for two reasons is not evidence about either.
    """
    event = _run_event()
    event["characterization"]["bands"] = dict(bands or {})
    event["characterization"]["overrides"] = dict(overrides or {})
    event["characterization"]["field_reports"] = [deepcopy(r) for r in reports]
    return event


def test_inferred_value_must_account_for_its_evidence() -> None:
    assert _rejected(
        _with_reports(_report("observed_daily_volume", provenance="inferred", confidence=0.8)),
        RUN,
    ), "an inferred value with no evidence status is an unsupported guess"


def test_every_report_must_state_its_confidence() -> None:
    """Confidence is required on EVERY report, not only inferred ones: an omitted
    confidence reads downstream as a certain value, and the guesses are exactly the
    ones an emitter is tempted to leave silent."""
    for provenance in ("asked", "inferred", "defaulted"):
        report = _report("value_channel", provenance=provenance)
        if provenance == "inferred":
            report["evidence_status"] = "withheld_by_policy"
        del report["confidence"]
        # transmit the value so the ONLY defect is the missing confidence (a shared
        # report with no transmitted value is independently rejected — see the
        # substance rule), keeping this test about confidence alone
        assert _rejected(_transmitting("value_channel", report), RUN), provenance
        report["confidence"] = 0.25
        assert _ok(_transmitting("value_channel", report), RUN), provenance


def test_inferred_evidence_may_be_withheld_but_not_leaked() -> None:
    # the honest withholding case: evidence exists, policy kept it local
    assert _ok(
        _with_reports(
            _report(
                "loss_per_bad_output_usd",
                provenance="inferred",
                confidence=0.5,
                sharing_outcome="withheld_by_policy",
                evidence_status="withheld_by_policy",
            )
        ),
        RUN,
    )
    # withheld evidence must not ride along in the pointer field
    assert _rejected(
        _with_reports(
            _report(
                "loss_per_bad_output_usd",
                provenance="inferred",
                confidence=0.5,
                sharing_outcome="withheld_by_policy",
                evidence_status="withheld_by_policy",
                evidence_pointer="incident ledger shows $4k median escalation",
            )
        ),
        RUN,
    )
    # claiming the evidence was provided while omitting it is also incoherent
    assert _rejected(
        _with_reports(
            _report(
                "loss_per_bad_output_usd",
                provenance="inferred",
                confidence=0.5,
                evidence_status="provided",
            )
        ),
        RUN,
    )


def test_a_withheld_field_cannot_claim_its_evidence_was_provided() -> None:
    """`withheld_by_policy` is a promise about the whole field: neither the value nor
    the pointer left the machine. A withheld field claiming evidence_status=provided
    contradicts itself — nothing was provided, because nothing egressed — and the
    pointer is prose derived from the client's own traces, so it leaks by describing
    the very number the withholding kept back."""
    leaked = _report(
        "loss_per_bad_output_usd",
        provenance="inferred",
        confidence=0.5,
        sharing_outcome="withheld_by_policy",
        evidence_status="provided",
        evidence_pointer="incident ledger shows $4k median escalation",
    )
    assert _rejected(_with_reports(leaked), RUN), "a withheld field must not ship a pointer"

    # the contradiction is rejected even with the pointer stripped: `provided` is
    # itself the false claim, not merely the field that carries it
    del leaked["evidence_pointer"]
    assert _rejected(_with_reports(leaked), RUN), (
        "evidence_status=provided on a withheld field is a self-contradiction"
    )

    leaked["evidence_status"] = "withheld_by_policy"
    assert _ok(_with_reports(leaked), RUN), "the honest withholding must still be reportable"


def test_asked_and_defaulted_values_cannot_claim_inference_evidence() -> None:
    for provenance in ("asked", "defaulted"):
        assert _rejected(
            _with_reports(
                _report(
                    "value_channel",
                    provenance=provenance,
                    evidence_status="provided",
                    evidence_pointer="made this up",
                )
            ),
            RUN,
        ), provenance


#: One transmittable value per allowlisted field, and the container it rides in.
_SAMPLE_VALUES = {
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


def _containers() -> tuple[set, set]:
    vocab = _load("economics_characterization_vocabulary_schema.json")["definitions"]
    return (
        set(vocab["CharacterizationBands"]["properties"]),
        set(vocab["CharacterizationOverrides"]["properties"]),
    )


def _transmitting(field: str, *reports) -> dict:
    """A run event transmitting exactly one field's value, with the given reports."""
    bands, _ = _containers()
    container = "bands" if field in bands else "overrides"
    return _with_reports(*reports, **{container: {field: _SAMPLE_VALUES[field]}})


def test_a_field_declared_withheld_cannot_ship_its_value_anyway() -> None:
    """The closed-pipe promise: 'withheld_by_policy' must mean the value did not
    leave the machine. Draft-07 CAN enforce this — it is a presence check keyed on
    a closed enum, not a comparison of two values — so it is enforced here rather
    than deferred to the backend, and this test is the proof that it bites."""
    withheld = _report("lifecycle_stage", sharing_outcome="withheld_by_policy")
    assert _rejected(_transmitting("lifecycle_stage", withheld), RUN), (
        "declaring a field withheld while shipping its value must be unrepresentable"
    )
    # the honest withholding: declared withheld, absent from bands
    assert _ok(_with_reports(withheld), RUN), "an honestly withheld field must still be reportable"

    # the same rule for a typed override, not just a band
    withheld_override = _report(
        "observed_daily_volume",
        provenance="inferred",
        confidence=0.8,
        sharing_outcome="withheld_by_policy",
        evidence_status="withheld_by_policy",
    )
    assert _rejected(_transmitting("observed_daily_volume", withheld_override), RUN), (
        "the egress rule must cover overrides, not only bands"
    )
    assert _ok(_with_reports(withheld_override), RUN)


def test_a_second_shared_report_cannot_launder_a_withheld_value() -> None:
    """The duplicate-alibi payload, and the reason the egress rule is kept alongside
    the coverage rule rather than folded into it: `uniqueItems` compares whole
    objects, so an emitter may ship BOTH a withheld report and a shared report for
    the same field. That satisfies coverage — a shared report exists — and the
    value would ride through on the second, contradictory story. The egress rule is
    what denies it."""
    event = _transmitting(
        "lifecycle_stage",
        _report("lifecycle_stage", sharing_outcome="withheld_by_policy"),
        _report("lifecycle_stage", provenance="defaulted", confidence=0.9),
    )
    assert _rejected(event, RUN), "a withheld value must not egress behind a second shared report"


def test_every_transmitted_value_must_carry_its_own_shared_report() -> None:
    """Coverage, the other direction of the egress rule. Without it, provenance is
    opt-in: a value shipped with no report for it is unaccounted — nobody asked,
    nobody inferred — yet it still reaches the recommendation, while every rate we
    compute (withholding, asked-vs-inferred, confidence) is computed over reports
    and silently excludes it."""
    bands, overrides = _containers()
    assert set(_SAMPLE_VALUES) == bands | overrides, "sample must cover the whole allowlist"

    for field in _SAMPLE_VALUES:
        # a report for some OTHER field does not account for this one
        decoy = _report("value_channel" if field != "value_channel" else "lifecycle_stage")
        assert _rejected(_transmitting(field, decoy), RUN), f"{field}: value with no report"

        # ... and the honest payload passes
        assert _ok(_transmitting(field, _report(field)), RUN), f"{field}: reported value rejected"


def test_a_transmitted_value_may_only_be_reported_as_shared() -> None:
    """The coverage rule requires the matching report to say `shared`, not merely to
    exist: 'here is the value, which I withheld' must not be sayable per field."""
    for field in _SAMPLE_VALUES:
        report = _report(field, sharing_outcome="withheld_by_policy")
        assert _rejected(_transmitting(field, report), RUN), f"{field}: transmitted yet 'withheld'"


def test_a_shared_report_with_no_transmitted_value_is_an_empty_alibi() -> None:
    """The substance rule (3), the converse of coverage: a report claiming a field was
    `shared` MUST transmit that field's value. Without it an emitter satisfies the
    required, non-empty field_reports slot with a report that names a provenance and a
    sharing outcome while carrying nothing the recommendation can read — the
    characterization half of a blank settlement, which looks instrumented and asserts
    no value. Every allowlisted field is probed."""
    for field in _SAMPLE_VALUES:
        # a shared report whose value is transmitted nowhere
        assert _rejected(_with_reports(_report(field)), RUN), f"{field}: shared but no value"
        # ... and transmitting the value makes the same report honest
        assert _ok(_transmitting(field, _report(field)), RUN), f"{field}: reported value rejected"
    # the honest all-withheld characterization stays representable: its reports are
    # withheld_by_policy (not shared), so the substance rule does not fire
    withheld = _report(
        "loss_per_bad_output_usd",
        provenance="inferred",
        confidence=0.5,
        sharing_outcome="withheld_by_policy",
        evidence_status="withheld_by_policy",
    )
    assert _ok(_with_reports(withheld), RUN), "an all-withheld characterization is honest telemetry"


def test_the_full_fixture_reports_every_field_it_transmits() -> None:
    """The fixture is the worked example of the rule, so it must obey it. This is the
    guard on the previous round's actual defect: the fixture transmitted five values
    and reported two, and every positive assertion built on it inherited that hole."""
    characterization = _run_event()["characterization"]
    transmitted = set(characterization["bands"]) | set(characterization["overrides"])
    shared = {
        report["field"]
        for report in characterization["field_reports"]
        if report["sharing_outcome"] == "shared"
    }
    assert transmitted <= shared, f"unreported values in the fixture: {transmitted - shared}"
    assert all("confidence" in report for report in characterization["field_reports"])
    withheld = {
        report["field"]
        for report in characterization["field_reports"]
        if report["sharing_outcome"] == "withheld_by_policy"
    }
    assert withheld, "the fixture must exercise the withholding path, not only the happy one"
    assert not (withheld & transmitted), "a withheld field must not appear in the payload"


def test_shared_fields_are_unaffected_by_the_withheld_rule() -> None:
    """Guard against the rule passing for the wrong reason: it must key on the
    sharing outcome, not simply forbid bands that have a field report."""
    assert _ok(
        _transmitting("lifecycle_stage", _report("lifecycle_stage")), RUN
    ), "a shared field must be able to carry its value"


def test_characterization_must_report_something() -> None:
    """An empty characterization is a blank alibi: it names no value, accounts for
    nothing, and would satisfy the required `characterization` slot."""
    event = _run_event()
    event["characterization"] = {}
    assert _rejected(event, RUN), "characterization with no field reports is not telemetry"
    event["characterization"] = {"field_reports": []}
    assert _rejected(event, RUN), "an empty field_reports array reports nothing"


def test_only_allowlisted_characterization_fields_can_egress() -> None:
    assert _rejected(_with_reports(_report("customer_name")), RUN)
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
    assert _rejected(_with_reports(_report("value_channel", provenance="guessed")), RUN)
    assert _rejected(_with_reports(_report("value_channel", sharing_outcome="sold")), RUN)


def test_characterization_overrides_are_typed_and_nonnegative() -> None:
    # each payload is fully reported, so the ONLY thing left to reject is the value
    assert _rejected(
        _with_reports(
            _report("observed_daily_volume", provenance="inferred", confidence=0.8,
                    evidence_status="withheld_by_policy"),
            overrides={"observed_daily_volume": "about 3k"},
        ),
        RUN,
    )
    assert _rejected(
        _with_reports(
            _report("loss_per_bad_output_usd"),
            overrides={"loss_per_bad_output_usd": -5},
        ),
        RUN,
    )


# --------------------------------------------------------------------------- #
# run economics: budget authorship, amounts, evidence identity, advisory, labor
# --------------------------------------------------------------------------- #
def test_a_settled_run_record_must_carry_the_whole_economics_record() -> None:
    """run_economics is the SETTLED economics of a finished, measured run. When only
    identity was required, `{event_type, event_id, occurred_at, project_ref, run_id}`
    validated: a record that names a run and asserts nothing, while counting as an
    economics observation. That is the cheapest way to look instrumented without
    producing evidence — precisely what this contract exists to stop."""
    minimal = {
        "event_type": "run_economics",
        "event_id": "evt-run-1",
        "occurred_at": "2026-07-17T10:00:00Z",
        "project_ref": "proj-1",
        "run_id": "run-1",
    }
    assert _rejected(minimal, RUN), "a run economics event that asserts nothing is not a record"
    assert _rejected(_batch(minimal), INGEST), "and it must not enter through the batch either"
    # the discriminated union is oneOf, so a rejected run event matches NO branch
    # rather than falling through to another one — check the route, not just the schema
    assert (
        _v().validate_request("/api/v1/economics/telemetry", "POST", _batch(minimal)) != []
    ), "the blank record must be rejected at the endpoint, not only in isolation"
    assert _v().validate_request("/api/v1/economics/telemetry", "POST", _batch(_run_event())) == []

    for field in (
        "archetype",
        "characterization",
        "budget",
        "actual_spend_usd",
        "usage",
        "model_prices",
        "evidence_identity",
        "advisory",
        "labor_proxies",
    ):
        event = _run_event()
        del event[field]
        assert _rejected(event, RUN), f"{field}: settlement is incomplete without it"


def test_a_failed_run_is_a_funnel_exit_not_a_blank_settlement() -> None:
    """The honest path for the case the blank record was standing in for. A run that
    failed or produced no supported effect is reported as an exit carrying a closed
    reason — strictly more informative than an empty settlement, which is why
    requiring the full record costs no expressiveness."""
    for reason in ("run_failed", "cost_cap_reached", "insufficient_evidence",
                   "no_positive_lower_bound"):
        assert _ok(
            _funnel_at("completed", outcome="exited", exit_reason=reason), FUNNEL
        ), reason


def test_a_settled_run_meters_its_usage_explicitly() -> None:
    """Empty usage was the cost half of a blank settlement: `usage: {}` satisfied the
    required slot while metering nothing. A settled run meters input/output tokens and
    model calls explicitly; a genuinely free run reports explicit zeros — the spend-$0
    case the model must always show — which is distinguishable from 'never measured'."""
    assert _rejected(_run_event(usage={}), RUN), "an empty usage object meters nothing"
    for field in ("input_tokens", "output_tokens", "model_calls"):
        event = _run_event()
        del event["usage"][field]
        assert _rejected(event, RUN), field
    assert _ok(
        _run_event(usage={"input_tokens": 0, "output_tokens": 0, "model_calls": 0}), RUN
    ), "the spend-$0 case reports explicit zeros, not an empty object"


def test_a_settled_run_records_the_measured_effect_support_and_exclusions() -> None:
    """run_economics is emitted only for a run whose effect WAS measured (a failure is a
    funnel exit), so the measured evidence is not optional: without effect_estimate,
    support, exclusions, and the objective weights in force, the record names an
    evidence identity that measures nothing — the evidence half of a blank settlement."""
    for field in ("effect_estimate", "support", "exclusions", "objective_weights"):
        event = _run_event()
        del event["evidence_identity"][field]
        assert _rejected(event, RUN), f"{field}: a settled effect claim is incomplete without it"
    # exclusions must be EXPLICIT, but an empty array is the honest 'nothing was dropped'
    event = _run_event()
    event["evidence_identity"]["exclusions"] = []
    assert _ok(event, RUN), "an explicit empty exclusions array asserts nothing was excluded"
    # holdout stays optional: an effect measured without a holdout is a real fact the
    # transfer analysis needs, so requiring it would reject honest no-holdout telemetry
    event = _run_event()
    del event["evidence_identity"]["holdout_hash"]
    assert _ok(event, RUN), "measuring without a holdout is a methodological fact, not a gap"


def test_the_composed_blank_settlement_shell_is_rejected_and_the_honest_exit_is_not() -> None:
    """Defect 1 in one payload: a run_economics event that combines every empty shell —
    zero-metering usage, an evidence identity with no measured effect, and a
    characterization whose only report is a `shared` alibi with no value — must be
    rejected as a body, and its honest alternative (report the drop as a funnel exit
    carrying a closed reason) must stay valid. The strictness costs no expressiveness."""
    shell = _run_event()
    shell["usage"] = {}
    del shell["evidence_identity"]["effect_estimate"]
    del shell["evidence_identity"]["support"]
    shell["characterization"] = {"field_reports": [_report("value_channel")]}
    assert _rejected(shell, RUN), "a blank settlement shell must not pass as a settled run"
    assert _rejected(_batch(shell), INGEST), "and it must not enter through the batch either"
    assert (
        _v().validate_request("/api/v1/economics/telemetry", "POST", _batch(shell)) != []
    ), "the shell must be rejected at the endpoint, not only in isolation"
    for reason in ("run_failed", "cost_cap_reached", "insufficient_evidence"):
        assert _ok(
            _funnel_at("completed", outcome="exited", exit_reason=reason), FUNNEL
        ), reason


def test_the_settled_run_must_join_to_the_advice_it_answers() -> None:
    """Adherence is a claim about ONE recommendation. Without advice_id the record
    cannot be joined to the advice it followed or to the funnel stages tracking the
    same advice, and adherence_probability has no outcome to be scored against."""
    event = _run_event()
    del event["advisory"]["advice_id"]
    assert _rejected(event, RUN), "an unjoinable adherence record measures nothing"


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
# timestamps: the prose and the contract must agree
# --------------------------------------------------------------------------- #
def test_timestamps_must_be_utc_with_a_trailing_z() -> None:
    """`format: date-time` also admits a local offset, so the prose ('emitted with a
    trailing Z') and the contract disagreed. An offset-bearing timestamp read as UTC
    silently moves an event by hours: it reorders a funnel, shifts a metering window,
    and backdates an attestation. New contract, no emitters to break — so the stated
    form is enforced rather than described."""
    for bad in (
        "2026-07-17T13:00:00+03:00",  # the same instant, read three hours early
        "2026-07-17T10:00:00-05:00",
        "2026-07-17T10:00:00",  # no zone at all
        "2026-07-17 10:00:00Z",  # not RFC-3339
        "2026-07-17T10:00:00z",  # lowercase z is not the stated form
        "2026-07-17",
        "yesterday",
        "",
    ):
        assert _rejected(_run_event(occurred_at=bad), RUN), bad

    for good in ("2026-07-17T10:00:00Z", "2026-07-17T10:00:00.123Z", "2026-07-17T10:00:00.123456Z"):
        assert _ok(_run_event(occurred_at=good), RUN), good


def test_the_utc_rule_reaches_every_timestamp_not_just_the_event_time() -> None:
    """One shared primitive, so the rule must hold wherever a time is recorded —
    including the ones that gate money and attestation."""
    event = _run_event()
    event["model_prices"][0]["as_of"] = "2026-07-17T00:00:00+02:00"
    assert _rejected(event, RUN), "a priced-at time with an offset misdates the price"

    receipt = _winner_receipt()
    receipt["attestation"]["verified_at"] = "2026-07-17T11:00:00+02:00"
    assert _rejected(receipt, RECEIPT), "an attestation must not be backdatable by offset"

    receipt = _savings_receipt()
    receipt["savings"]["window"]["end"] = "2026-07-17T00:00:00+02:00"
    assert _rejected(receipt, RECEIPT), "a metering window must be unambiguous"

    body = _batch(sent_at="2026-07-17T12:00:00+02:00")
    assert _rejected(body, INGEST)

    assert _rejected(_response(received_at="2026-07-17T12:00:01+02:00"), RESPONSE)


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
    # not_promoted forbids a production follow-up (see the dedicated test below), so
    # drop the default fixture's follow-up to keep this case about promotion timestamps
    del event["winner"]["production_follow_up"]
    assert _ok(event, RECEIPT), "a supported result the client declined is still a valid receipt"


def test_a_promoted_or_reverted_winner_must_carry_its_production_follow_up() -> None:
    """Promotion puts the eval claim into production, and eval-to-production transfer is
    a decision-sensitive assumption: a winner that promotes (or reverts) while omitting
    its production follow-up is the exact shape that can only report success. A pending
    follow-up is truthful, not absent — status=scheduled with a due_at."""
    for status, extra in (
        ("promoted", {"promoted_at": "2026-07-17T12:00:00Z"}),
        (
            "reverted",
            {"promoted_at": "2026-07-17T12:00:00Z", "reverted_at": "2026-07-18T12:00:00Z"},
        ),
    ):
        event = _winner_receipt()
        event["winner"]["promotion"] = {"status": status, **extra}
        del event["winner"]["production_follow_up"]
        assert _rejected(event, RECEIPT), f"{status}: promotion without a production follow-up"
        # a truthful pending follow-up satisfies it
        event["winner"]["production_follow_up"] = {
            "status": "scheduled",
            "due_at": "2026-07-24T12:00:00Z",
        }
        assert _ok(event, RECEIPT), f"{status}: a scheduled follow-up is a truthful pending record"
        # ... but a pending 'scheduled' follow-up must still say when it is due
        del event["winner"]["production_follow_up"]["due_at"]
        assert _rejected(event, RECEIPT), f"{status}: a scheduled follow-up must carry due_at"
    # not_promoted needs no follow-up: nothing was put into production to follow up on,
    # and that a supported result was declined is itself the uptake measurement
    event = _winner_receipt()
    event["winner"]["promotion"] = {"status": "not_promoted"}
    del event["winner"]["production_follow_up"]
    assert _ok(event, RECEIPT), "a declined winner needs no production follow-up"


def test_a_not_promoted_winner_must_not_carry_a_production_follow_up() -> None:
    """The complement of the rule above, and the hole it closes: requiring the follow-up
    only for promoted/reverted left `not_promoted` free to carry one anyway. A production
    follow-up on a configuration the client declared never deployed is production-transfer
    evidence for a transfer that by definition never happened — a never-deployed config
    claiming production uptake. So a not_promoted receipt is valid ONLY without a
    production follow-up; both the pending `scheduled` variant and a resolved `confirmed`
    variant are rejected."""
    # the honest not_promoted receipt carries no follow-up
    event = _winner_receipt()
    event["winner"]["promotion"] = {"status": "not_promoted"}
    del event["winner"]["production_follow_up"]
    assert _ok(event, RECEIPT), "a declined winner without a follow-up is the honest shape"

    # a scheduled follow-up (the shape the default fixture and the old tests admitted)
    # is now rejected: there is nothing scheduled to measure on a config never deployed
    event["winner"]["production_follow_up"] = {
        "status": "scheduled",
        "due_at": "2026-07-24T12:00:00Z",
    }
    assert _rejected(event, RECEIPT), (
        "a never-deployed config must not schedule a production check"
    )

    # a confirmed follow-up is rejected too: it claims production evidence for a
    # transfer that never happened — the exact non-gameability hole this rule closes
    event["winner"]["production_follow_up"] = {
        "status": "confirmed",
        "measured_at": "2026-07-24T12:00:00Z",
        "production_delta": _interval(),
    }
    assert _rejected(event, RECEIPT), (
        "a never-deployed config must not claim confirmed production-transfer evidence"
    )


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
# ShortLabel: an opaque identifier grammar, not a free-form egress channel
#
# ShortLabel is consumed by model_id, the emitting-surface name, evaluator_version,
# objective, the metric name, and the policy-version fields. Left free-form (any
# 1-128 char string), each of those is a channel through which sensitive prose or
# PII could egress. These tests drive one label VALUE through EVERY consuming field
# and assert the grammar bites the same way in each — a rule that guarded only
# model_id would leave the other five open.
# --------------------------------------------------------------------------- #
def _through_every_short_label_field(value):
    """(field-name, payload, schema) for every field that consumes a ShortLabel,
    with just that field set to `value` and the rest of the payload left valid."""
    model_id = _run_event()
    model_id["model_prices"][0]["model_id"] = value

    evaluator_version = _run_event()
    evaluator_version["evidence_identity"]["evaluator_version"] = value

    objective = _run_event()
    objective["evidence_identity"]["objective_weights"][0]["objective"] = value

    policy_version = _run_event()
    policy_version["characterization"]["sharing_policy_version"] = value

    metric = _defect_receipt()
    metric["defect"]["downstream_metric_change"] = {
        "metric": value,
        "delta": -0.01,
        "unit": "proportion",
        "measured_at": "2026-07-18T12:00:00Z",
    }

    source_name = _batch()
    source_name["source"]["name"] = value

    return (
        ("model_id", model_id, RUN),
        ("evaluator_version", evaluator_version, RUN),
        ("objective", objective, RUN),
        ("sharing_policy_version", policy_version, RUN),
        ("downstream_metric_change.metric", metric, RECEIPT),
        ("source.name", source_name, INGEST),
    )


#: Content-shaped labels a free-form string would have leaked. Each is prose, PII,
#: whitespace, a control character, a quote, or email text — never an identifier.
_CONTENT_SHAPED_LABELS = (
    "Alice Smith SSN 123-45-6789",  # Terra's example: a name + PII, carried as spaces + prose
    "patient note: see chart",       # plain prose with a colon
    "line one\nline two",            # embedded newline
    "accuracy\n",                     # a valid id with a TRAILING newline — the `$`-only bypass
    "col\tumn",                       # embedded tab (a control character)
    "nul\x00byte",               # embedded NUL (a control character)
    'he said "ship it"',             # quotes + spaces
    "alice@example.com",             # at-sign / email text
    "this is a free form note",      # prose
    "-leading-hyphen",               # leading separator: not an identifier
    "trailing-hyphen-",              # trailing separator: not an identifier
    "___",                            # pure separators, no alphanumerics
    "café-au-lait",             # non-ASCII letter
)


def test_short_label_rejects_content_shaped_values_through_every_consuming_field() -> None:
    """Not free-form: a label carrying prose, PII, whitespace, control characters,
    quotes, or email text is rejected wherever a ShortLabel is consumed — so none of
    model_id, evaluator_version, objective, the sharing-policy version, the metric name,
    or the source name is an egress channel for sensitive content. Terra's example
    `Alice Smith SSN 123-45-6789` is rejected through all six."""
    for label in _CONTENT_SHAPED_LABELS:
        for field, payload, schema in _through_every_short_label_field(label):
            assert _rejected(payload, schema), (
                f"{field} must reject content-shaped label {label!r}"
            )


#: Representative real identifiers the grammar must NOT reject — it bought no safety
#: if it also rejects honest model ids, versions, metric names, and objectives.
_REAL_IDENTIFIERS = (
    "gpt-4o-mini",
    "anthropic/claude-3.5",
    "accuracy_v2",
    "1.0.0",
    "exec-match-v2",
    "claude-haiku-4-5",
    "text:embedding-3",
    "x",  # a single alphanumeric is a valid one-character identifier
)


def test_short_label_accepts_representative_real_identifiers() -> None:
    """The grammar must not have bought its safety by rejecting honest identifiers:
    real model ids, versions, metric names, and objective names still validate through
    every consuming field."""
    for label in _REAL_IDENTIFIERS:
        for field, payload, schema in _through_every_short_label_field(label):
            assert _ok(payload, schema), f"{field} must accept real identifier {label!r}"


def test_short_label_is_pattern_constrained_not_merely_bounded() -> None:
    """Pin the control itself: the prose says 'not free-form', so the type must carry a
    pattern, not just length bounds. A future edit that drops the pattern (reverting to
    any 1-128 char string) fails here rather than silently re-opening the egress."""
    short_label = _load("economics_common_schema.json")["definitions"]["ShortLabel"]
    assert "pattern" in short_label, "ShortLabel must be pattern-constrained, not free-form"
    assert short_label["maxLength"] == 128 and short_label["minLength"] == 1


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
        "winner_receipt_reconciliation_failed",
    } <= reasons


def test_response_always_carries_a_rejections_array() -> None:
    """rejections is REQUIRED, defaulting to an empty array when nothing was rejected,
    so an emitter tells 'none rejected' from 'the reasons were omitted' without diffing
    counts. That the array's length equals counts.rejected is a backend obligation."""
    body = _response()
    del body["rejections"]
    assert _rejected(body, RESPONSE), "a response that omits rejections is ambiguous"
    # a clean batch still carries the (empty) array
    assert _ok(
        _response(
            counts={"submitted": 2, "accepted": 2, "duplicate": 0, "rejected": 0},
            rejections=[],
        ),
        RESPONSE,
    )


def test_per_status_response_schemas_bind_the_replay_flag() -> None:
    """200 replay and 201 initial ingest are distinct persistence outcomes, so the body
    binds replayed per status: the 200 schema rejects replayed=false and the 201 schema
    rejects replayed=true. A status line and a body that disagree about whether state
    was written would tell a retrying emitter the wrong thing on the replay path."""
    assert _ok(_response(replayed=True), RESPONSE_REPLAY)
    assert _rejected(
        _response(replayed=False), RESPONSE_REPLAY
    ), "a 200 replay response cannot claim replayed=false"
    assert _ok(_response(replayed=False), RESPONSE_INITIAL)
    assert _rejected(
        _response(replayed=True), RESPONSE_INITIAL
    ), "a 201 initial-ingest response cannot claim replayed=true"
    # the per-status schemas still inherit every base constraint
    body = _response(replayed=True)
    body["counts"]["accepted"] = -1
    assert _rejected(body, RESPONSE_REPLAY), "a per-status schema must inherit the base counts rule"
    body = _response(replayed=True)
    del body["rejections"]
    assert _rejected(body, RESPONSE_REPLAY), "a per-status schema must inherit required rejections"


def test_the_endpoint_binds_each_status_to_its_replay_schema() -> None:
    """The contract-native replay binding is only real if the route serves each status
    with the matching per-status schema."""
    responses = _load("economics_endpoints.json")["paths"]["/api/v1/economics/telemetry"][
        "post"
    ]["responses"]
    assert responses["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "economics_telemetry_ingest_response_replay_schema.json"
    )
    assert responses["201"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "economics_telemetry_ingest_response_initial_schema.json"
    )


def test_boundary_rejections_length_is_not_related_to_the_rejected_count() -> None:
    """counts.rejected is an integer and rejections is an array; Draft-07 cannot relate
    an array's length to a sibling integer, so a response claiming rejected>0 while
    carrying an empty rejections array is contract-valid and must be caught at the
    backend boundary. Backend obligation: REJECTIONS RECONCILE WITH COUNT."""
    lying = _response(
        counts={"submitted": 3, "accepted": 2, "duplicate": 0, "rejected": 1},
        rejections=[],
    )
    assert _ok(lying, RESPONSE), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the REJECTIONS RECONCILE WITH COUNT backend obligation"
    )
    obligations = " ".join(
        _load("economics_telemetry_ingest_response_schema.json")["x-backend-obligations"]
    )
    for marker in (
        "COUNT RECONCILIATION",
        "REJECTIONS RECONCILE WITH COUNT",
        "REPLAY PERSISTENCE",
        "STATUS/FLAG AGREEMENT",
    ):
        assert marker in obligations, marker


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
        _report("error_cost_band"),
        _report(
            "error_cost_band",
            provenance="inferred",
            confidence=0.3,
            evidence_status="provided",
            evidence_pointer="a second, conflicting story about the same field",
        ),
    ]
    # transmit the value so the substance rule is satisfied and the ONLY thing left
    # for the contract to catch is the duplicate field name — which it cannot
    assert _ok(_transmitting("error_cost_band", *contradictory), RUN), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the duplicate_characterization_field backend obligation"
    )
    # the byte-identical repeat IS caught, which is the narrow thing uniqueItems buys
    same = _report("error_cost_band")
    assert _rejected(_transmitting("error_cost_band", same, deepcopy(same)), RUN), (
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


def test_boundary_a_contradictory_winner_receipt_is_schema_valid_and_pins_the_backend() -> None:
    """A winner receipt's load-bearing fields — actual_cost_usd, paired_delta,
    selected_config_hash, the immutable run identity, and the promotion evidence — are
    only CLAIMS until reconciled, as a set, against the immutable stored run. Draft-07
    validates one payload in isolation and has no stored run to compare against, so a
    STRUCTURALLY valid winner receipt whose fields contradict the real run is
    contract-valid. This receipt is internally well-formed but mutually incoherent as a
    claim: a strongly positive paired delta on a run that cost almost nothing, against a
    config/run hash that need correspond to nothing stored, promoted with a follow-up
    already 'confirmed' in its favour. The contract accepts it; only cross-record
    reconciliation can reject it.
    Backend obligation: WINNER RECEIPT RECONCILIATION / winner_receipt_reconciliation_failed."""
    contradictory = _winner_receipt()
    contradictory["winner"]["actual_cost_usd"] = 0.01
    contradictory["winner"]["paired_delta"] = _interval(estimate=0.95, lower=0.94, upper=0.96)
    contradictory["winner"]["run_identity"] = {
        "run_id": "run-that-need-not-exist",
        "run_immutable_hash": "f" * 64,
    }
    contradictory["winner"]["selected_config_hash"] = "9" * 64
    contradictory["winner"]["promotion"] = {
        "status": "promoted",
        "promoted_at": "2026-07-17T12:00:00Z",
    }
    contradictory["winner"]["production_follow_up"] = {
        "status": "confirmed",
        "measured_at": "2026-07-24T12:00:00Z",
        "production_delta": _interval(estimate=0.95, lower=0.94, upper=0.96),
    }
    assert _ok(contradictory, RECEIPT), (
        "if this now REJECTS, the contract has closed the gap — rewrite this test as a "
        "rejection and drop the WINNER RECEIPT RECONCILIATION backend obligation"
    )
    # the gap is named precisely, not buried in schema_violation
    reasons = set(
        _load("economics_telemetry_ingest_response_schema.json")["properties"]["rejections"][
            "items"
        ]["properties"]["reason"]["enum"]
    )
    assert "winner_receipt_reconciliation_failed" in reasons
    # and the obligation that must catch it is declared on the receipt contract
    obligations = " ".join(_load("economics_receipt_event_schema.json")["x-backend-obligations"])
    assert "WINNER RECEIPT RECONCILIATION" in obligations


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
        "winner_receipt_reconciliation_failed",
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
            "WINNER RECEIPT RECONCILIATION",
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
        "economics_telemetry_ingest_response_schema.json": (
            "COUNT RECONCILIATION",
            "REJECTIONS RECONCILE WITH COUNT",
            "REPLAY PERSISTENCE",
            "STATUS/FLAG AGREEMENT",
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
