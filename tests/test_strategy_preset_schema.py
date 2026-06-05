# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for advisory optimization strategy preset metadata."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
SCHEMA_FILE = OPT_DIR / "strategy_preset_schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft7Validator:
    schema = _load(SCHEMA_FILE)
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema)


def _errors(payload: dict) -> list:
    return list(_validator().iter_errors(payload))


def _preset(preset_name: str, params: dict, selection_grade: str = "advisory") -> dict:
    return {
        "preset_name": preset_name,
        "params": params,
        "selection_grade": selection_grade,
        "selection_rationale": "sdk preset",
    }


@pytest.mark.parametrize(
    "payload",
    [
        _preset("max_accuracy_then_cheapest_within_epsilon", {"epsilon": 0.05}),
        _preset("max_accuracy_then_cheapest_within_epsilon", {"epsilon": 1}),
        _preset("quality_floor_min_cost", {"floor": 0}),
        _preset("quality_floor_min_cost", {"floor": 1}),
        _preset("pareto_frontier", {}),
    ],
)
def test_valid_strategy_presets_with_params_pass(payload: dict) -> None:
    assert _errors(payload) == []


def test_unknown_preset_is_rejected() -> None:
    assert _errors(_preset("secret_best_config", {}))


@pytest.mark.parametrize(
    "payload",
    [
        _preset("max_accuracy_then_cheapest_within_epsilon", {"epsilon": 0}),
        _preset("max_accuracy_then_cheapest_within_epsilon", {"epsilon": 1.01}),
        _preset("max_accuracy_then_cheapest_within_epsilon", {"floor": 0.9}),
        _preset("quality_floor_min_cost", {"floor": -0.01}),
        _preset("quality_floor_min_cost", {"floor": 1.01}),
        _preset("quality_floor_min_cost", {"epsilon": 0.05}),
        _preset("pareto_frontier", {"epsilon": 0.05}),
    ],
)
def test_strategy_preset_params_are_typed_and_bounded(payload: dict) -> None:
    assert _errors(payload)


def test_selection_grade_is_advisory_only() -> None:
    assert _errors(_preset("pareto_frontier", {}, selection_grade="certified"))


def test_session_and_run_metadata_without_strategy_preset_still_valid() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            "function_name": "support_router",
            "configuration_space": {"temperature": [0.1, 0.9]},
            "objectives": ["accuracy"],
            "metadata": {"sdk_version": "2.0.0"},
        },
    ) == []
    assert validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        {
            "problem_statement": "Optimize tone and retrieval quality",
            "search_space": {"temperature": [0.0, 1.0]},
            "optimization_config": {"max_trials": 10},
            "metadata": {"sdk_version": "2.0.0"},
        },
    ) == []
    assert validator.validate_request(
        "/api/v1/sessions/sess_abc/results",
        "POST",
        {
            "trial_id": "trial-sdk-local-1",
            "metrics": {"accuracy": 0.875},
            "metadata": {"sdk_version": "2.0.0"},
        },
    ) == []


def test_strategy_preset_attaches_to_session_and_trial_metadata() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    strategy_preset = _preset(
        "max_accuracy_then_cheapest_within_epsilon",
        {"epsilon": 0.05},
    )

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            "function_name": "support_router",
            "configuration_space": {"temperature": [0.1, 0.9]},
            "objectives": ["accuracy"],
            "metadata": {"strategy_preset": strategy_preset},
        },
    ) == []
    assert validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        {
            "problem_statement": "Optimize tone and retrieval quality",
            "search_space": {"temperature": [0.0, 1.0]},
            "optimization_config": {"max_trials": 10},
            "metadata": {"strategy_preset": strategy_preset},
        },
    ) == []
    assert validator.validate_request(
        "/api/v1/sessions/sess_abc/results",
        "POST",
        {
            "trial_id": "trial-sdk-local-1",
            "metrics": {"accuracy": 0.875},
            "metadata": {"strategy_preset": strategy_preset},
        },
    ) == []


def test_invalid_strategy_preset_rejected_on_wire_metadata() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    invalid_strategy_preset = _preset("quality_floor_min_cost", {"floor": 1.1})

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            "function_name": "support_router",
            "configuration_space": {"temperature": [0.1, 0.9]},
            "objectives": ["accuracy"],
            "metadata": {"strategy_preset": invalid_strategy_preset},
        },
    )

    assert errors
    assert any("strategy_preset" in error for error in errors)


def test_strategy_preset_attaches_to_execution_run_metadata() -> None:
    validator = SchemaValidator()
    strategy_preset = _preset("quality_floor_min_cost", {"floor": 0.82})

    assert validator.validate_json(
        {
            "id": "experiment_run_123",
            "experiment_id": "experiment_123",
            "experiment_data": {},
            "metadata": {"strategy_preset": strategy_preset},
        },
        "experiment_run_schema",
    ) == []
    assert validator.validate_json(
        {
            "id": "configuration_run_123",
            "experiment_run_id": "experiment_run_123",
            "experiment_parameters": {
                "infrastructure": {
                    "infrastructure_id": "infra_123",
                    "compute": "cpu",
                    "memory": "8GB",
                    "timeout": 300,
                }
            },
            "metadata": {"strategy_preset": strategy_preset},
        },
        "configuration_run_schema",
    ) == []
