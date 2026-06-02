# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for TVAR catalog entry and observation schemas."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator

OPT_DIR = (
    Path(__file__).resolve().parent.parent
    / "traigent_schema"
    / "schemas"
    / "optimization"
)
CATALOG_ENTRY_FILE = OPT_DIR / "tvar_catalog_entry_schema.json"
OBSERVATION_FILE = OPT_DIR / "tvar_observation_schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator(path: Path) -> Draft7Validator:
    return Draft7Validator(_load(path))


def _errors(path: Path, instance: dict) -> list:
    return list(_validator(path).iter_errors(instance))


def _valid_catalog_entry() -> dict:
    return {
        "entry_id": "cat_temperature_low_cost_v1",
        "schema_version": "1.0.0",
        "name": "Lower temperature for deterministic support answers",
        "range_type": "Range",
        "range_kwargs": {"low": 0.0, "high": 0.4},
        "kind": "value",
        "effectuation_status": "executable",
        "effectuation_strategy": "set_range_kwargs",
        "category": "generation",
        "reasoning": "Aggregate trials showed lower variance without quality loss.",
        "impact_estimate": "medium",
        "agent_types": ["rag", "chat", "general_llm"],
        "evidence_refs": [
            {
                "artifact_path": "artifacts/tvar/temperature.json",
                "run_id": "run_20260602_temperature",
                "scope": "heldout",
                "metric": "quality_score",
                "n": 128,
                "model": "gpt-5-mini",
                "baseline": "temperature=0.7",
                "candidate": "temperature=0.2",
                "delta": 0.03,
                "limitations": ["Support QA workload only"],
            }
        ],
        "apply_guidance": "Use for deterministic customer-support answer generation.",
        "status": "active",
        "version": "2026.06.02",
    }


def _valid_observation() -> dict:
    return {
        "schema_version": "1.0.0",
        "session_id": "sess_123",
        "trial_id": "trial_456",
        "config_space_id": "config_space_support_v1",
        "agent_type": "rag",
        "catalog_entry_ids": ["cat_temperature_low_cost_v1"],
        "variables": [
            {"name": "temperature", "value": 0.2, "kind": "value"},
            {"name": "rerank_enabled", "value": True, "kind": "topology"},
            {"name": "route_policy", "value": "strict", "kind": "policy"},
        ],
        "metrics": {"quality_score": 0.91, "latency_ms": 842.5},
        "primary_metric": "quality_score",
        "comparability": {"scope": "heldout", "n": 64},
        "policy_events_summary": {"escalated": 3, "total": 64},
        "prompt_artifact_refs": [
            {
                "hash": "sha256:" + "a" * 64,
                "ref": "prompt_registry/support_answer/v7",
            }
        ],
        "privacy": {"raw_content_included": False},
        "sdk_version": "0.12.0",
    }


def test_schemas_are_valid_draft7() -> None:
    for path in (CATALOG_ENTRY_FILE, OBSERVATION_FILE):
        Draft7Validator.check_schema(_load(path))


def test_valid_catalog_entry_passes() -> None:
    assert _errors(CATALOG_ENTRY_FILE, _valid_catalog_entry()) == []


def test_catalog_entry_missing_kind_fails() -> None:
    invalid = _valid_catalog_entry()
    del invalid["kind"]

    assert _errors(CATALOG_ENTRY_FILE, invalid)


def test_catalog_entry_rejects_strategy_unless_executable() -> None:
    invalid = _valid_catalog_entry()
    invalid["effectuation_status"] = "manual_guidance"

    assert _errors(CATALOG_ENTRY_FILE, invalid)


def test_valid_observation_passes() -> None:
    assert _errors(OBSERVATION_FILE, _valid_observation()) == []


def test_observation_raw_content_flag_fails() -> None:
    invalid = copy.deepcopy(_valid_observation())
    invalid["privacy"]["raw_content_included"] = True

    assert _errors(OBSERVATION_FILE, invalid)


def test_observation_rejects_raw_prompt_content_field() -> None:
    invalid = _valid_observation()
    invalid["raw_prompt"] = "Never include prompt text in a TVAR observation."

    assert _errors(OBSERVATION_FILE, invalid)


def test_observation_rejects_per_input_policy_rows() -> None:
    invalid = copy.deepcopy(_valid_observation())
    invalid["policy_events_summary"] = {
        "events": [{"input_id": "example_1", "escalated": True}]
    }

    assert _errors(OBSERVATION_FILE, invalid)


def test_schemas_are_registered_by_runtime_discovery() -> None:
    available = set(SchemaValidator().available_schemas)

    assert "tvar_catalog_entry_schema" in available
    assert "tvar_observation_schema" in available
