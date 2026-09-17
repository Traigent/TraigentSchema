# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for SessionAggregationDTO.selection (R3 selection receipt).

Pins the discriminated union on ``disposition`` (accepted / rejected_inconsistent),
closed shapes at every level, id-list bounds, the digest shape and preimage, numeric
bounds, the verdict-keyed margin shapes the Python SDK really emits, the closed
rejection-reason enum, and the wiring through both ``$ref`` users (the finalize
request in optimization_endpoints.json and the finalize response).

Negative tests validate against the specific ``definitions/Selection*`` sub-schema
and assert the exact set of ``(keyword, instance path)`` pairs that fail, so each
test pins the rule it is about rather than "some error exists".

Rules JSON Schema cannot express (sorted ids, count == len(ids), runner_up != winner,
digest correctness, n_configs <= eligible_trial_count, ci95 lo <= hi, finiteness)
are Backend-enforced and deliberately NOT faked here.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

import traigent_schema
from traigent_schema import SchemaValidator

_VALIDATOR = SchemaValidator()
_SDK_VALIDATOR = SchemaValidator(contract="sdk_tuning")

AGG = "session_aggregation_schema"
FINALIZE = "session_finalize_response_schema"
FINALIZE_PATH = "/api/v1/sessions/sess-123/finalize"

_SCHEMA = json.loads(
    (
        Path(traigent_schema.__file__).parent
        / "schemas"
        / "optimization"
        / "session_aggregation_schema.json"
    ).read_text(encoding="utf-8")
)

# Known answer: sha256 over the UTF-8 bytes of '["trial_a","trial_b","trial_c"]'.
_KAT_DIGEST_HEX = "4a31e7194d0ef1862bfa5db184d1486776997a10810f1a72c67ab24aef08e005"
_DIGEST = "sha256:" + _KAT_DIGEST_HEX

Errors = set[tuple[str, tuple[Any, ...]]]


def _errors(instance: dict) -> list:
    return _VALIDATOR.validate_json(instance, AGG)


def _rule_errors(definition: str, instance: Any) -> Errors:
    schema = {"$ref": f"#/definitions/{definition}", "definitions": _SCHEMA["definitions"]}
    return {
        (str(error.validator), tuple(error.absolute_path))
        for error in Draft7Validator(schema).iter_errors(instance)
    }


def _digest(ids: list[str]) -> str:
    preimage = json.dumps(sorted(ids), separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(preimage.encode("utf-8")).hexdigest()


# Margins projected (schema fields only) from the SDK's compute_best_config_margin
# payloads, Traigent traigent/core/stat_significance.py.
def _margin_mcnemar_clear() -> dict:
    return {
        "winner_trial_id": "trial_a",
        "runner_up_trial_id": "trial_b",
        "delta": 0.25,
        "ci95": [0.06, 0.44],
        "p_value": 0.0063,
        "verdict": "clear",
        "test": "mcnemar_exact",
        "n_shared_examples": 40,
        "effective_alpha": 0.025,
        "n_configs": 3,
    }


def _margin_paired_t_tie() -> dict:
    return {
        "winner_trial_id": "trial_a",
        "runner_up_trial_id": "trial_b",
        "delta": -0.01,
        "ci95": [-0.05, 0.03],
        "p_value": 0.61,
        "verdict": "statistical_tie",
        "test": "paired_t",
        "n_shared_examples": 5,
        "effective_alpha": 0.05,
        "n_configs": 2,
    }


def _margin_na(delta: float | None = 0.1) -> dict:
    return {
        "winner_trial_id": "trial_a",
        "runner_up_trial_id": "trial_b",
        "delta": delta,
        "ci95": None,
        "p_value": None,
        "verdict": "na",
        "test": "none",
        "n_shared_examples": 0,
        "effective_alpha": 0.05,
        "n_configs": 2,
    }


def _selection() -> dict:
    return {
        "disposition": "accepted",
        "attestation": "client_attested_server_bound",
        "selection_reason": None,
        "winner_trial_id": "trial_a",
        "eligible_trial_ids": ["trial_a", "trial_b", "trial_c"],
        "eligible_trial_count": 3,
        "eligible_trial_ids_digest": _DIGEST,
        "margin": _margin_mcnemar_clear(),
    }


def _accepted(*, margin: bool = True) -> dict:
    selection = _selection()
    if not margin:
        selection["margin"] = None
    return {"selection_mode": "aggregated_mean", "selection": selection}


def _rejected_selection() -> dict:
    return {"disposition": "rejected_inconsistent", "reason": "winner_not_best"}


def _rejected() -> dict:
    return {"selection": _rejected_selection()}


def _sel(**updates: Any) -> dict:
    selection = _selection()
    selection.update(updates)
    return selection


def _mar(base: dict | None = None, **updates: Any) -> dict:
    margin = copy.deepcopy(base) if base is not None else _margin_mcnemar_clear()
    margin.update(updates)
    return margin


class TestValidSelection:
    def test_accepted_with_margin(self) -> None:
        assert not _errors(_accepted())

    def test_accepted_margin_null(self) -> None:
        assert not _errors(_accepted(margin=False))
        assert _rule_errors("SelectionAccepted", _sel(margin=None)) == set()

    def test_accepted_margin_and_optional_fields_omitted(self) -> None:
        payload = _accepted()
        for key in ("margin", "attestation", "selection_reason"):
            del payload["selection"][key]
        assert not _errors(payload)

    def test_accepted_with_selection_reason_label(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(selection_reason="SELECTED_BEST")) == set()

    def test_trial_id_at_max_length(self) -> None:
        tid = "t" * 128
        assert _rule_errors("SelectionAccepted", _sel(winner_trial_id=tid)) == set()

    def test_ten_thousand_ids(self) -> None:
        ids = [f"t{i:05d}" for i in range(10000)]
        instance = _sel(eligible_trial_ids=ids, eligible_trial_count=10000)
        assert _rule_errors("SelectionAccepted", instance) == set()

    def test_rejected(self) -> None:
        assert not _errors(_rejected())

    @pytest.mark.parametrize(
        "reason",
        [
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
        ],
    )
    def test_every_rejection_reason(self, reason: str) -> None:
        payload = _rejected()
        payload["selection"]["reason"] = reason
        assert not _errors(payload)

    def test_selection_is_optional(self) -> None:
        assert not _errors({"selection_mode": "aggregated_mean"})


class TestSdkMarginShapes:
    """Every margin shape compute_best_config_margin can emit validates."""

    @pytest.mark.parametrize(
        "margin",
        [
            _margin_mcnemar_clear(),
            _margin_paired_t_tie(),
            _margin_na(delta=0.1),
            _margin_na(delta=None),
        ],
        ids=["mcnemar_clear", "paired_t_tie", "na_with_delta", "na_null_delta"],
    )
    def test_sdk_shape_validates(self, margin: dict) -> None:
        assert _rule_errors("SelectionMargin", margin) == set()
        assert not _errors({"selection": _sel(margin=margin)})

    def test_label_at_max_length(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(test="a" * 64)) == set()


class TestDigest:
    def test_known_answer(self) -> None:
        ids = ["trial_b", "trial_c", "trial_a"]
        preimage = json.dumps(sorted(ids), separators=(",", ":"), ensure_ascii=False)
        assert preimage.encode("utf-8") == b'["trial_a","trial_b","trial_c"]'
        assert hashlib.sha256(preimage.encode("utf-8")).hexdigest() == _KAT_DIGEST_HEX
        assert _digest(ids) == _DIGEST

    def test_known_answer_digest_validates(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_ids_digest=_DIGEST)) == set()

    @pytest.mark.parametrize(
        "digest",
        [
            "sha256:" + _KAT_DIGEST_HEX.upper(),
            "sha256:" + _KAT_DIGEST_HEX[:32],
            _DIGEST + "\n",
            _KAT_DIGEST_HEX,
            "sha256:ABC",
        ],
        ids=["uppercase", "32_hex", "trailing_newline", "no_prefix", "short"],
    )
    def test_bad_digest(self, digest: str) -> None:
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_ids_digest=digest)) == {
            ("pattern", ("eligible_trial_ids_digest",))
        }


class TestInvalidAccepted:
    @pytest.mark.parametrize(
        "field",
        [
            "disposition",
            "winner_trial_id",
            "eligible_trial_ids",
            "eligible_trial_count",
            "eligible_trial_ids_digest",
        ],
    )
    def test_required_field_deleted(self, field: str) -> None:
        instance = _selection()
        del instance[field]
        assert _rule_errors("SelectionAccepted", instance) == {("required", ())}
        assert _errors({"selection": instance})

    def test_unknown_disposition(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(disposition="server_verified")) == {
            ("const", ("disposition",))
        }
        assert _errors({"selection": _sel(disposition="server_verified")})

    def test_extra_property(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(best_config={"model": "x"})) == {
            ("additionalProperties", ())
        }

    def test_attestation_other_value(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(attestation="server_verified")) == {
            ("const", ("attestation",))
        }

    def test_empty_ids(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_ids=[])) == {
            ("minItems", ("eligible_trial_ids",))
        }

    def test_too_many_ids(self) -> None:
        ids = [f"t{i:05d}" for i in range(10001)]
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_ids=ids)) == {
            ("maxItems", ("eligible_trial_ids",))
        }

    def test_duplicate_ids(self) -> None:
        assert _rule_errors(
            "SelectionAccepted", _sel(eligible_trial_ids=["trial_a", "trial_a"])
        ) == {("uniqueItems", ("eligible_trial_ids",))}

    @pytest.mark.parametrize("count", [0, 10001])
    def test_count_out_of_bounds(self, count: int) -> None:
        keyword = "minimum" if count < 1 else "maximum"
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_count=count)) == {
            (keyword, ("eligible_trial_count",))
        }

    @pytest.mark.parametrize(
        "tid", ["trial a", "trial_a\n", "trial/a"], ids=["space", "trailing_newline", "slash"]
    )
    def test_bad_winner_trial_id(self, tid: str) -> None:
        assert _rule_errors("SelectionAccepted", _sel(winner_trial_id=tid)) == {
            ("pattern", ("winner_trial_id",))
        }

    def test_trailing_newline_in_eligible_id(self) -> None:
        ids = ["trial_a", "trial_b\n"]
        assert _rule_errors("SelectionAccepted", _sel(eligible_trial_ids=ids)) == {
            ("pattern", ("eligible_trial_ids", 1))
        }

    def test_trial_id_too_long(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(winner_trial_id="t" * 129)) == {
            ("maxLength", ("winner_trial_id",)),
            ("pattern", ("winner_trial_id",)),
        }

    @pytest.mark.parametrize("reason", ["free text reason", 5, "x" * 65])
    def test_bad_selection_reason(self, reason: Any) -> None:
        assert _rule_errors("SelectionAccepted", _sel(selection_reason=reason)) == {
            ("oneOf", ("selection_reason",))
        }

    def test_margin_not_object_or_null(self) -> None:
        assert _rule_errors("SelectionAccepted", _sel(margin="clear")) == {("oneOf", ("margin",))}


class TestInvalidMargin:
    @pytest.mark.parametrize(
        "field",
        [
            "winner_trial_id",
            "runner_up_trial_id",
            "delta",
            "ci95",
            "p_value",
            "verdict",
            "test",
            "n_shared_examples",
            "effective_alpha",
            "n_configs",
        ],
    )
    def test_required_field_deleted(self, field: str) -> None:
        margin = _margin_mcnemar_clear()
        del margin[field]
        assert _rule_errors("SelectionMargin", margin) == {("required", ())}

    def test_extra_property(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(winner_score=0.9)) == {
            ("additionalProperties", ())
        }

    @pytest.mark.parametrize(
        ("field", "value", "keyword"),
        [
            ("p_value", 1.5, "maximum"),
            ("p_value", -0.1, "minimum"),
            ("effective_alpha", 1.5, "maximum"),
            ("effective_alpha", -0.1, "minimum"),
            ("n_configs", 1, "minimum"),
        ],
    )
    def test_numeric_bounds(self, field: str, value: float, keyword: str) -> None:
        assert _rule_errors("SelectionMargin", _mar(**{field: value})) == {(keyword, (field,))}

    def test_n_configs_one_on_na(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(_margin_na(), n_configs=1)) == {
            ("minimum", ("n_configs",))
        }

    def test_n_shared_examples_negative_without_verdict(self) -> None:
        margin = _mar(n_shared_examples=-1)
        del margin["verdict"]
        assert _rule_errors("SelectionMargin", margin) == {
            ("required", ()),
            ("minimum", ("n_shared_examples",)),
        }

    def test_ci95_one_item(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(ci95=[0.1])) == {("minItems", ("ci95",))}

    def test_ci95_three_items(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(ci95=[0.0, 0.1, 0.2])) == {
            ("maxItems", ("ci95",))
        }

    def test_ci95_non_numeric_items(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(ci95=["lo", "hi"])) == {
            ("type", ("ci95", 0)),
            ("type", ("ci95", 1)),
        }

    @pytest.mark.parametrize("verdict", ["maybe", "CLEAR"])
    def test_unknown_verdict(self, verdict: str) -> None:
        assert _rule_errors("SelectionMargin", _mar(verdict=verdict)) == {("enum", ("verdict",))}

    @pytest.mark.parametrize(
        "label",
        ["the prompt was: hello world", "a" * 65, "bad/label", "none\n"],
        ids=["free_text", "too_long", "slash", "trailing_newline"],
    )
    def test_bad_test_label(self, label: str) -> None:
        assert _rule_errors("SelectionMargin", _mar(test=label)) == {("pattern", ("test",))}

    @pytest.mark.parametrize(
        "margin_factory",
        [_margin_mcnemar_clear, _margin_paired_t_tie, _margin_na],
        ids=["clear", "statistical_tie", "na"],
    )
    def test_winner_trial_id_required_in_every_verdict(self, margin_factory: Any) -> None:
        margin = margin_factory()
        del margin["winner_trial_id"]
        assert _rule_errors("SelectionMargin", margin) == {("required", ())}

    @pytest.mark.parametrize(
        ("tid", "keywords"),
        [
            ("trial_a\n", {"pattern"}),
            ("trial a", {"pattern"}),
            ("", {"pattern", "minLength"}),
            ("a" * 129, {"pattern", "maxLength"}),
        ],
        ids=["trailing_newline", "space", "empty", "too_long"],
    )
    def test_bad_winner_trial_id(self, tid: str, keywords: set[str]) -> None:
        assert _rule_errors("SelectionMargin", _mar(winner_trial_id=tid)) == {
            (keyword, ("winner_trial_id",)) for keyword in keywords
        }

    def test_bad_runner_up_id(self) -> None:
        assert _rule_errors("SelectionMargin", _mar(runner_up_trial_id="trial_b\n")) == {
            ("pattern", ("runner_up_trial_id",))
        }


class TestVerdictKeyedShapes:
    @pytest.mark.parametrize("verdict", ["clear", "statistical_tie"])
    @pytest.mark.parametrize("field", ["delta", "ci95", "p_value"])
    def test_tested_verdict_requires_numbers(self, verdict: str, field: str) -> None:
        margin = _mar(verdict=verdict, **{field: None})
        assert _rule_errors("SelectionMargin", margin) == {("type", (field,))}

    @pytest.mark.parametrize("verdict", ["clear", "statistical_tie"])
    def test_tested_verdict_requires_shared_examples(self, verdict: str) -> None:
        margin = _mar(verdict=verdict, n_shared_examples=0)
        assert _rule_errors("SelectionMargin", margin) == {("minimum", ("n_shared_examples",))}

    @pytest.mark.parametrize(
        ("field", "value", "keyword"),
        [
            ("ci95", [0.0, 0.1], "type"),
            ("p_value", 0.5, "type"),
            ("n_shared_examples", 5, "const"),
            ("delta", "big", "type"),
        ],
    )
    def test_na_shape(self, field: str, value: Any, keyword: str) -> None:
        margin = _mar(_margin_na(), **{field: value})
        assert _rule_errors("SelectionMargin", margin) == {(keyword, (field,))}


class TestInvalidRejected:
    @pytest.mark.parametrize("field", ["disposition", "reason"])
    def test_required_field_deleted(self, field: str) -> None:
        instance = _rejected_selection()
        del instance[field]
        assert _rule_errors("SelectionRejectedInconsistent", instance) == {("required", ())}

    def test_unknown_reason(self) -> None:
        instance = {**_rejected_selection(), "reason": "looked_wrong_to_me"}
        assert _rule_errors("SelectionRejectedInconsistent", instance) == {("enum", ("reason",))}
        assert _errors({"selection": instance})

    @pytest.mark.parametrize(
        "extra",
        [{"winner_trial_id": "trial_a"}, {"detail": "trial trial_z is not in this session"}],
        ids=["accepted_field", "free_text"],
    )
    def test_extra_property(self, extra: dict) -> None:
        instance = {**_rejected_selection(), **extra}
        assert _rule_errors("SelectionRejectedInconsistent", instance) == {
            ("additionalProperties", ())
        }
        assert _errors({"selection": instance})

    def test_non_object_selection(self) -> None:
        assert _errors({"selection": "accepted"})


class TestRefUsers:
    def test_finalize_request_accepts_selection(self) -> None:
        body = {"include_full_history": False, "session_aggregation": _accepted()}
        assert not _SDK_VALIDATOR.validate_request(FINALIZE_PATH, "POST", body)

    def test_finalize_request_accepts_na_margin(self) -> None:
        body = {"session_aggregation": {"selection": _sel(margin=_margin_na(delta=None))}}
        assert not _SDK_VALIDATOR.validate_request(FINALIZE_PATH, "POST", body)

    def test_finalize_request_rejects_bad_selection(self) -> None:
        body = {"session_aggregation": {"selection": _sel(disposition="nope")}}
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
