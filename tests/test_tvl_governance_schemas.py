# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the TVL 1.1 governance wire schemas (Phase 7).

Pins: promotion_policy.require_calibration (closed shape, extension-key enum),
TvlGovernanceDTO content-freedom (P8: closed shapes, no value-bearing fields),
and the finalize response's fail-closed no-winner contract.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
POLICY_FILE = OPT_DIR / "promotion_policy_schema.json"
GOVERNANCE_FILE = OPT_DIR / "tvl_governance_schema.json"
FINALIZE_FILE = OPT_DIR / "session_finalize_response_schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (POLICY_FILE, GOVERNANCE_FILE, FINALIZE_FILE):
        contents = _load(path)
        # older schemas (promotion_policy) predate $id — key by filename
        resources.append((contents.get("$id", path.name), Resource.from_contents(contents, default_specification=DRAFT7)))
    return Registry().with_resources(resources)


def _errors(path: Path, instance: dict) -> list:
    validator = Draft7Validator(_load(path), registry=_registry())
    return list(validator.iter_errors(instance))


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
        assert not _errors(POLICY_FILE, policy)

    def test_enabled_is_required(self) -> None:
        policy = {"require_calibration": {"hash_covered_context": []}}
        assert _errors(POLICY_FILE, policy)

    def test_core_freshness_keys_rejected(self) -> None:
        """Extension keys ONLY — the mandatory core is not configurable."""
        policy = {
            "require_calibration": {
                "enabled": True,
                "hash_covered_context": ["tuned_parent_values"],
            }
        }
        assert _errors(POLICY_FILE, policy)

    def test_closed_shape(self) -> None:
        policy = {"require_calibration": {"enabled": True, "extra": 1}}
        assert _errors(POLICY_FILE, policy)

    def test_legacy_policy_unchanged(self) -> None:
        policy = {"dominance": "epsilon_pareto", "alpha": 0.05, "adjust": "BH"}
        assert not _errors(POLICY_FILE, policy)


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
        assert not _errors(GOVERNANCE_FILE, governance)

    def test_decision_vocabulary_shared_with_guarantee_schema(self) -> None:
        governance = {
            "certificates": [{"cvar_name": "theta", "decision": "MAYBE_FINE"}]
        }
        assert _errors(GOVERNANCE_FILE, governance)

    def test_closed_shapes_block_value_smuggling(self) -> None:
        """P8: no open field can carry calibrated values or evidence."""
        for poisoned in (
            {"cvars": [{"name": "theta", "value": 0.42}]},
            {"certificates": [{"cvar_name": "theta", "decision": "NO_DECISION", "evidence": "raw"}]},
            {"policies": [{"name": "p", "parameters": {"x": 1}}]},
            {"signal_values": [1, 2, 3]},
        ):
            assert _errors(GOVERNANCE_FILE, poisoned), poisoned


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
        assert not _errors(FINALIZE_FILE, response)

    def test_legacy_winner_shape_unchanged(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {"model": "gpt-4o"},
            "best_metrics": {"accuracy": 0.9},
            "total_trials": 4,
        }
        assert not _errors(FINALIZE_FILE, response)

    def test_unknown_reason_code_rejected(self) -> None:
        response = {
            "session_id": "s1",
            "best_config": {},
            "reason_code": "JUST_TRUST_ME",
            "total_trials": 1,
        }
        assert _errors(FINALIZE_FILE, response)
