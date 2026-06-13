# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the activation v1 envelope and adjudication schemas.

The activation layer's privacy posture is the whole point: the request envelope
carries optimization results + content-free abstractions only, and the response
is structured data the client's coding-agent LLM narrates (no server prose).
"""

from __future__ import annotations

from traigent_schema import SchemaValidator

_VALIDATOR = SchemaValidator()

ENVELOPE = "activation_envelope_schema"
ADJUDICATION = "activation_adjudication_schema"


def _errors(schema_name: str, instance: dict) -> list:
    return _VALIDATOR.validate_json(instance, schema_name)


def _valid_envelope() -> dict:
    return {
        "envelope_version": "activation/v1",
        "session_id": "camp_abc",
        "phase": "accuracy",
        "eval_manifest": {
            "scorer_id": "execaccuracy",
            "scorer_kind": "execution",
            "split_sizes": {"train": 60, "selection": 30, "test": 30},
            "repeated_run_count": 3,
            "unscoreable_count": 1,
        },
        "search_space_summary": {
            "tvars": [
                {
                    "name": "schema_context",
                    "kind": "enum",
                    "cardinality": 2,
                    "domain_summary": "context_toggle",
                },
                {"name": "model", "kind": "enum", "cardinality": 3, "domain_summary": "model_tier"},
            ],
            "composite_measures_present": ["composite_route_count"],
        },
        "trial_summaries": [
            {
                "config_hash": "cfg_9",
                "tvar_value_labels": {"schema_context": "on", "model": "tier_a"},
                "scores": {"accuracy": 0.71, "cost": 0.02},
                "cost_usd": 0.02,
                "latency_ms": 800,
                "tokens": 1200,
                "trial_count": 30,
            }
        ],
        "per_example_vectors": [
            {
                "example_id": "ex_hmac_1",
                "config_hash": "cfg_9",
                "passed": False,
                "score": 0.0,
                "error_enum": "execution_error",
            }
        ],
        "budget": {"spent_usd": 12.4, "remaining_usd": 37.6},
    }


def _valid_adjudication() -> dict:
    return {
        "envelope_version": "activation/v1",
        "session_id": "camp_abc",
        "directive_id": "dir_42",
        "campaign_state": {"phase": "accuracy", "round": 2, "best_score": 0.71},
        "observations": [
            {
                "observation_id": "obs_1",
                "kind": "knob_effect",
                "metrics": {"tvar": "schema_context", "effect": 0.18, "n": 40},
                "confidence_label": "high",
                "subject_refs": ["schema_context"],
            }
        ],
        "implications": [
            {
                "implication_code": "knob_dominant",
                "observation_ids": ["obs_1"],
                "severity": "advisory",
            }
        ],
        "candidate_actions": [
            {
                "action_id": "act_1",
                "type": "narrow_space",
                "params": {"max_new_tvars": 2, "allowed_tvar_classes": ["repair_policy"]},
                "rationale_codes": ["knob_dominant"],
                "expected_effect": {"accuracy": "up", "cost": "flat"},
                "viability": "recommended",
                "required_evidence": ["trial_summaries", "per_example_vectors"],
            },
            {"action_id": "act_stop", "type": "stop", "viability": "discouraged"},
        ],
        "assessment": {
            "recommended_action_id": "act_1",
            "stop_eligible": False,
            "why_codes": ["knob_dominant"],
        },
        "agent_directive": {
            "instruction": (
                "Summarize the observations and implications for the user, recommend a "
                "course, explain why using only the provided metrics, then execute the "
                "chosen action and return the required evidence."
            ),
            "must_cite_observation_ids": True,
        },
    }


class TestActivationEnvelope:
    def test_valid_envelope_accepted(self) -> None:
        assert not _errors(ENVELOPE, _valid_envelope())

    def test_minimal_envelope_accepted(self) -> None:
        minimal = {
            "envelope_version": "activation/v1",
            "session_id": "c1",
            "phase": "scope",
            "eval_manifest": {"scorer_id": "s", "split_sizes": {"selection": 10}},
            "search_space_summary": {"tvars": []},
            "trial_summaries": [],
        }
        assert not _errors(ENVELOPE, minimal)

    def test_bad_envelope_version_rejected(self) -> None:
        env = _valid_envelope()
        env["envelope_version"] = "v1"
        assert _errors(ENVELOPE, env)

    def test_unknown_phase_rejected(self) -> None:
        env = _valid_envelope()
        env["phase"] = "optimize"
        assert _errors(ENVELOPE, env)

    def test_raw_content_field_rejected_envelope(self) -> None:
        env = _valid_envelope()
        env["trial_summaries"][0]["raw_prompt"] = "You are an expert SQL assistant..."
        assert _errors(ENVELOPE, env)

    def test_raw_content_field_rejected_per_example(self) -> None:
        env = _valid_envelope()
        env["per_example_vectors"][0]["actual_output"] = "SELECT * FROM customers"
        assert _errors(ENVELOPE, env)

    def test_tvar_requires_name_and_kind(self) -> None:
        env = _valid_envelope()
        env["search_space_summary"]["tvars"].append({"name": "x"})
        assert _errors(ENVELOPE, env)


class TestActivationAdjudication:
    def test_valid_adjudication_accepted(self) -> None:
        assert not _errors(ADJUDICATION, _valid_adjudication())

    def test_candidate_actions_nonempty(self) -> None:
        adj = _valid_adjudication()
        adj["candidate_actions"] = []
        assert _errors(ADJUDICATION, adj)

    def test_assessment_requires_stop_eligible(self) -> None:
        adj = _valid_adjudication()
        del adj["assessment"]["stop_eligible"]
        assert _errors(ADJUDICATION, adj)

    def test_unknown_action_type_rejected(self) -> None:
        adj = _valid_adjudication()
        adj["candidate_actions"][0]["type"] = "rewrite_everything"
        assert _errors(ADJUDICATION, adj)

    def test_unknown_observation_kind_rejected(self) -> None:
        adj = _valid_adjudication()
        adj["observations"][0]["kind"] = "vibes"
        assert _errors(ADJUDICATION, adj)

    def test_agent_directive_required(self) -> None:
        adj = _valid_adjudication()
        del adj["agent_directive"]
        assert _errors(ADJUDICATION, adj)

    def test_cost_certificate_optional_and_validated(self) -> None:
        adj = _valid_adjudication()
        adj["campaign_state"]["phase"] = "cost"
        adj["cost_certificate"] = {
            "winner_config_hash": "cfg_4",
            "accuracy_floor": 0.84,
            "accuracy_at_winner": 0.84,
            "cost_delta_pct": -60.0,
            "confidence_label": "high",
        }
        assert not _errors(ADJUDICATION, adj)
