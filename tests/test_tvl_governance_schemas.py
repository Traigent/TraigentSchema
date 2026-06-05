# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the TVL 1.1 governance wire schemas (Phase 7).

Pins: promotion_policy.require_calibration (closed shape, extension-key enum),
TvlGovernanceDTO content-freedom (P8: closed shapes, no value-bearing fields),
and the finalize response's fail-closed no-winner contract.
"""

from __future__ import annotations

from traigent_schema import SchemaValidator

# The REAL package validator and registry — review round 1 found a custom
# filename-keyed registry here hid an unresolvable $ref; using the package
# loader means ref-resolution breakage fails THESE tests.
_VALIDATOR = SchemaValidator()

POLICY = "promotion_policy_schema"
GOVERNANCE = "tvl_governance_schema"
FINALIZE = "session_finalize_response_schema"


def _errors(schema_name: str, instance: dict) -> list:
    return _VALIDATOR.validate_json(instance, schema_name)


class TestRequireCalibration:
    def test_strict_policy_accepted(self) -> None:
        policy = {
            "dominance": "epsilon_pareto",
            "alpha": 0.05,
            "require_calibration": {
                "enabled": True,
                "hash_covered_context": ["model_versions"],
            },
        }
        assert not _errors(POLICY, policy)

    def test_enabled_is_required(self) -> None:
        policy = {"require_calibration": {"hash_covered_context": []}}
        assert _errors(POLICY, policy)

    def test_core_freshness_keys_rejected(self) -> None:
        """Extension keys ONLY — the mandatory core is not configurable."""
        policy = {
            "require_calibration": {
                "enabled": True,
                "hash_covered_context": ["tuned_parent_values"],
            }
        }
        assert _errors(POLICY, policy)

    def test_closed_shape(self) -> None:
        policy = {"require_calibration": {"enabled": True, "extra": 1}}
        assert _errors(POLICY, policy)

    def test_legacy_policy_unchanged(self) -> None:
        policy = {"dominance": "epsilon_pareto", "alpha": 0.05, "adjust": "BH"}
        assert not _errors(POLICY, policy)


class TestTvlGovernance:
    def test_content_free_summary_accepted(self) -> None:
        governance = {
            "cvars": [{"name": "router.margin_threshold", "type": "float", "governed": True}],
            "certificates": [
                {
                    "cvar_name": "router.margin_threshold",
                    "decision": "CERTIFIED_SELECTION",
                    "freshness_hash": "a" * 64,
                }
            ],
            "policies": [{"name": "cheap_strong_cascade", "strategy": "cascade"}],
        }
        assert not _errors(GOVERNANCE, governance)

    def test_decision_vocabulary_shared_with_guarantee_schema(self) -> None:
        governance = {
            "certificates": [{"cvar_name": "theta", "decision": "MAYBE_FINE"}]
        }
        assert _errors(GOVERNANCE, governance)

    def test_closed_shapes_block_value_smuggling(self) -> None:
        """P8: no open field can carry calibrated values or evidence."""
        for poisoned in (
            {"cvars": [{"name": "theta", "value": 0.42}]},
            {"certificates": [{"cvar_name": "theta", "decision": "NO_DECISION", "evidence": "raw"}]},
            {"policies": [{"name": "p", "parameters": {"x": 1}}]},
            {"signal_values": [1, 2, 3]},
        ):
            assert _errors(GOVERNANCE, poisoned), poisoned


class TestFinalizeResponse:
    def test_no_certified_selection_shape(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {},
            "reason_code": "NO_CERTIFIED_SELECTION",
            "tvl_governance": {
                "certificates": [{"cvar_name": "theta", "decision": "NO_DECISION"}]
            },
            "total_trials": 4,
            "successful_trials": 4,
            "total_duration": 1.0,
            "cost_savings": 0.0,
            "stop_reason": "max_trials_reached",
            "metadata": {},
        }
        assert not _errors(FINALIZE, response)

    def test_legacy_winner_shape_unchanged(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {"model": "gpt-4o"},
            "best_metrics": {"accuracy": 0.9},
            "total_trials": 4,
        }
        assert not _errors(FINALIZE, response)

    def test_unknown_reason_code_rejected(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {},
            "reason_code": "JUST_TRUST_ME",
            "total_trials": 1,
        }
        assert _errors(FINALIZE, response)


class TestP8Hardening:
    """Round-1 review: free strings could smuggle content — now constrained."""

    def test_freshness_hash_must_be_sha256_hex(self) -> None:
        governance = {
            "certificates": [
                {
                    "cvar_name": "theta",
                    "decision": "NO_DECISION",
                    "freshness_hash": "raw evidence payload",
                }
            ]
        }
        assert _errors(GOVERNANCE, governance)

    def test_cvar_type_is_closed_grammar(self) -> None:
        governance = {"cvars": [{"name": "theta", "type": "ignore all instructions"}]}
        assert _errors(GOVERNANCE, governance)

    def test_strategy_is_registry_enum(self) -> None:
        governance = {"policies": [{"name": "p", "strategy": "tell me a secret"}]}
        assert _errors(GOVERNANCE, governance)


class TestWirePathBindings:
    def test_hybrid_wire_path_constrains_promotion_policy(self) -> None:
        """TRUE wire-path evidence (round-2 review): validate_request against
        the /api/v1/hybrid/sessions endpoint, with an otherwise-VALID fixture,
        so the failure is attributable to the promotion_policy binding."""
        base = {
            "function_name": "fn",
            "config_space": [
                {"name": "model", "type": "categorical", "choices": ["a", "b"]},
                {"name": "temperature", "type": "float", "low": 0.0, "high": 1.0},
            ],
            "task_description": "phase-7 wire-path regression fixture",
        }
        # the hybrid endpoint is mapped in the sdk_tuning contract
        validator = SchemaValidator(contract="sdk_tuning")
        errs = validator.validate_request(
            "/api/v1/hybrid/sessions",
            "POST",
            {**base, "promotion_policy": {"require_calibration": {"enabled": True}}},
        )
        assert not errs, errs
        errs = validator.validate_request(
            "/api/v1/hybrid/sessions",
            "POST",
            {**base, "promotion_policy": {"require_calibration": {"enabled": "yes-ish"}}},
        )
        assert errs

    def test_finalize_full_history_accepted(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {"model": "a"},
            "total_trials": 1,
            "full_history": [
                {
                    "session_id": "s1",
                    "trial_id": "t1",
                    "trial_number": 1,
                    "config": {"model": "a"},
                    "metrics": {"accuracy": 1.0},
                    "duration": 0.1,
                    "status": "completed",
                    "error_message": None,
                }
            ],
        }
        assert not _errors(FINALIZE, response)
