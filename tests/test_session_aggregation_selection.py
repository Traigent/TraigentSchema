# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for SessionAggregationDTO.selection (R3 selection receipt).

Pins the discriminated union on ``disposition`` (accepted / rejected_inconsistent),
closed shapes at every level, id-list bounds, digest shape, numeric bounds, the
closed rejection-reason enum, and the wiring through both ``$ref`` users (the
finalize request in optimization_endpoints.json and the finalize response).
Rules JSON Schema cannot express (sorted ids, count == len(ids), runner_up !=
winner, digest correctness, n_configs relation, ci95 lo <= hi) are Backend-
enforced and deliberately NOT faked here.
"""

from __future__ import annotations

import copy

from traigent_schema import SchemaValidator

_VALIDATOR = SchemaValidator()
_SDK_VALIDATOR = SchemaValidator(contract="sdk_tuning")

AGG = "session_aggregation_schema"
FINALIZE = "session_finalize_response_schema"
FINALIZE_PATH = "/api/v1/sessions/sess-123/finalize"

_DIGEST = "sha256:" + "0" * 64


def _errors(instance: dict) -> list:
    return _VALIDATOR.validate_json(instance, AGG)


def _margin() -> dict:
    return {
        "runner_up_trial_id": "trial_b",
        "delta": 0.042,
        "ci95": [0.01, 0.07],
        "p_value": 0.003,
        "verdict": "clear",
        "test": "paired_bootstrap",
        "n_shared_examples": 120,
        "effective_alpha": 0.025,
        "n_configs": 3,
    }


def _accepted(*, margin: bool = True) -> dict:
    selection: dict = {
        "disposition": "accepted",
        "attestation": "client_attested_server_bound",
        "reason_code": None,
        "winner_trial_id": "trial_a",
        "eligible_trial_ids": ["trial_a", "trial_b", "trial_c"],
        "eligible_trial_count": 3,
        "eligible_trial_ids_digest": _DIGEST,
        "margin": _margin() if margin else None,
    }
    return {"selection_mode": "aggregated_mean", "selection": selection}


def _rejected() -> dict:
    return {
        "selection": {
            "disposition": "rejected_inconsistent",
            "reason": "winner_not_best",
        }
    }


def _with(mutator) -> dict:  # type: ignore[no-untyped-def]
    payload = copy.deepcopy(_accepted())
    mutator(payload["selection"])
    return payload


class TestValidSelection:
    def test_accepted_with_margin(self) -> None:
        assert not _errors(_accepted())

    def test_accepted_without_margin(self) -> None:
        assert not _errors(_accepted(margin=False))

    def test_accepted_margin_and_optional_fields_omitted(self) -> None:
        payload = _accepted()
        for key in ("margin", "attestation", "reason_code"):
            del payload["selection"][key]
        assert not _errors(payload)

    def test_accepted_with_reason_code_label(self) -> None:
        assert not _errors(_with(lambda s: s.update(reason_code="SELECTED_BEST")))

    def test_rejected(self) -> None:
        assert not _errors(_rejected())

    def test_every_rejection_reason(self) -> None:
        for reason in (
            "unknown_trial",
            "winner_not_best",
            "winner_not_eligible",
            "runner_up_not_eligible",
            "runner_up_is_winner",
            "count_mismatch",
            "duplicate_ids",
            "non_finite",
            "out_of_range",
            "exceeds_max_trials",
            "digest_mismatch",
        ):
            payload = _rejected()
            payload["selection"]["reason"] = reason
            assert not _errors(payload), reason

    def test_selection_is_optional(self) -> None:
        assert not _errors({"selection_mode": "aggregated_mean"})


class TestInvalidSelection:
    def test_unknown_disposition(self) -> None:
        assert _errors(_with(lambda s: s.update(disposition="server_verified")))

    def test_extra_property_on_accepted(self) -> None:
        assert _errors(_with(lambda s: s.update(best_config={"model": "x"})))

    def test_extra_property_on_margin(self) -> None:
        assert _errors(_with(lambda s: s["margin"].update(winner_score=0.9)))

    def test_extra_property_on_rejected(self) -> None:
        payload = _rejected()
        payload["selection"]["winner_trial_id"] = "trial_a"
        assert _errors(payload)

    def test_empty_ids(self) -> None:
        assert _errors(_with(lambda s: s.update(eligible_trial_ids=[])))

    def test_too_many_ids(self) -> None:
        ids = [f"t{i:05d}" for i in range(10001)]
        assert _errors(_with(lambda s: s.update(eligible_trial_ids=ids)))

    def test_duplicate_ids(self) -> None:
        assert _errors(_with(lambda s: s.update(eligible_trial_ids=["trial_a", "trial_a"])))

    def test_bad_digest(self) -> None:
        assert _errors(_with(lambda s: s.update(eligible_trial_ids_digest="sha256:ABC")))

    def test_p_value_above_one(self) -> None:
        assert _errors(_with(lambda s: s["margin"].update(p_value=1.5)))

    def test_n_configs_one(self) -> None:
        assert _errors(_with(lambda s: s["margin"].update(n_configs=1)))

    def test_ci95_three_items(self) -> None:
        assert _errors(_with(lambda s: s["margin"].update(ci95=[0.0, 0.1, 0.2])))

    def test_unknown_reason(self) -> None:
        payload = _rejected()
        payload["selection"]["reason"] = "looked_wrong_to_me"
        assert _errors(payload)

    def test_free_text_smuggled_into_label(self) -> None:
        assert _errors(_with(lambda s: s["margin"].update(test="the prompt was: hello world")))

    def test_free_text_field_smuggled_on_rejected(self) -> None:
        payload = _rejected()
        payload["selection"]["detail"] = "trial trial_z is not in this session"
        assert _errors(payload)

    def test_attestation_other_value(self) -> None:
        assert _errors(_with(lambda s: s.update(attestation="server_verified")))

    def test_trial_id_with_whitespace(self) -> None:
        assert _errors(_with(lambda s: s.update(winner_trial_id="trial a")))


class TestRefUsers:
    def test_finalize_request_accepts_selection(self) -> None:
        body = {"include_full_history": False, "session_aggregation": _accepted()}
        assert not _SDK_VALIDATOR.validate_request(FINALIZE_PATH, "POST", body)

    def test_finalize_request_rejects_bad_selection(self) -> None:
        body = {"session_aggregation": _with(lambda s: s.update(disposition="nope"))}
        assert _SDK_VALIDATOR.validate_request(FINALIZE_PATH, "POST", body)

    def test_finalize_response_accepts_selection(self) -> None:
        resp = {
            "session_id": "s-1",
            "best_config": {"model": "gpt-4o-mini"},
            "selection_basis": "objective_best",
            "total_trials": 3,
            "session_aggregation": _accepted(),
        }
        assert not _VALIDATOR.validate_json(resp, FINALIZE)

    def test_finalize_response_accepts_rejected_selection(self) -> None:
        resp = {
            "session_id": "s-1",
            "best_config": {"model": "gpt-4o-mini"},
            "selection_basis": "objective_best",
            "total_trials": 3,
            "session_aggregation": _rejected(),
        }
        assert not _VALIDATOR.validate_json(resp, FINALIZE)
