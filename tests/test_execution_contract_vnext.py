"""vNext SDK optimize execution-contract tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _load_schema(relative_path: str) -> dict[str, Any]:
    with (get_schemas_dir() / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def _session_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _hybrid_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "problem_statement": "Optimize tone and retrieval quality",
        "search_space": {"temperature": [0.0, 1.0]},
        "optimization_config": {"max_trials": 10},
    }
    payload.update(overrides)
    return payload


def _hybrid_api_options() -> dict[str, Any]:
    return {
        "endpoint": "https://eval.example.com/score",
        "transport_type": "auto",
        "batch_size": 2,
        "batch_parallelism": 3,
        "keep_alive": True,
        "heartbeat_interval": 30,
        "timeout": None,
        "auth_header": None,
        "auto_discover_tvars": False,
        "tunable_id": None,
    }


def test_algorithm_auto_validates_strategy_schema_and_sdk_requests() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_json("auto", "optimization_strategy_schema") == []
    assert validator.validate_json({"algorithm": "auto"}, "optimization_strategy_schema") == []
    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(algorithm="auto"),
    ) == []
    assert validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_create_payload(algorithm="auto"),
    ) == []


def test_offline_true_validates_on_sdk_requests() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(offline=True),
    ) == []
    assert validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_create_payload(offline=True),
    ) == []


def test_legacy_execution_modes_still_validate_local_is_preferred() -> None:
    validator = SchemaValidator()
    execution_schema = _load_schema("execution/execution_mode_schema.json")
    strategy_schema = _load_schema("optimization/optimization_strategy_schema.json")

    for mode in ("local", "edge_analytics", "hybrid"):
        assert validator.validate_json(
            {"execution_mode": mode, "experiment_id": "experiment_123"},
            "execution_mode_schema",
        ) == []

    assert execution_schema["definitions"]["ExecutionMode"]["enum"] == [
        "local",
        "edge_analytics",
        "hybrid",
        "hybrid_api",
    ]
    assert execution_schema["definitions"]["ExecutionMode"]["deprecated"] is True
    assert (
        execution_schema["definitions"]["ExecutionMode"]["x-preferred-values"]["local"]
        == "Preferred name for client-side local orchestration (grid, random algorithms)."
    )
    assert "edge_analytics" in execution_schema["definitions"]["ExecutionMode"][
        "x-deprecated-values"
    ]
    assert execution_schema["properties"]["execution_mode"]["deprecated"] is True
    assert strategy_schema["definitions"]["OptimizationExecutionMode"]["enum"] == [
        "local",
        "edge_analytics",
        "hybrid",
        "hybrid_api",
    ]
    assert strategy_schema["definitions"]["OptimizationExecutionMode"]["deprecated"] is True
    assert strategy_schema["x-traigent-optimization-capabilities"]["grid"][
        "execution_mode"
    ] == "local"
    assert strategy_schema["x-traigent-optimization-capabilities"]["random"][
        "execution_mode"
    ] == "local"
    assert strategy_schema["x-traigent-optimization-capabilities"]["grid"][
        "deprecated_execution_modes"
    ] == ["edge_analytics"]
    assert strategy_schema["x-traigent-optimization-capabilities"]["random"][
        "deprecated_execution_modes"
    ] == ["edge_analytics"]


def test_sdk_session_create_accepts_local_and_edge_analytics_execution_modes() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    for mode in ("local", "edge_analytics"):
        assert validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(
                algorithm="grid",
                offline=True,
                execution_mode=mode,
            ),
        ) == []


def test_native_local_grid_random_create_and_submit_validate() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    for algorithm in ("grid", "random"):
        assert validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(
                algorithm=algorithm,
                offline=True,
                execution_mode="local",
                metadata={"tracking": "native-local"},
            ),
        ) == []

    assert validator.validate_request(
        "/api/v1/sessions/session_local_123/results",
        "POST",
        {
            "trial_id": "trial-local-1",
            "metrics": {"accuracy": 0.91},
            "config": {"temperature": 0.2, "top_k": 3},
            "duration": 0.25,
            "status": "COMPLETED",
            "metadata": {"tracking": "native-local"},
        },
    ) == []


def test_hybrid_api_options_validate_on_schema_and_sdk_requests() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    options = _hybrid_api_options()

    assert validator.validate_json(options, "hybrid_api_options_schema") == []
    assert validator.validate_json(
        {
            "execution_mode": "hybrid_api",
            "experiment_id": "experiment_123",
            "hybrid_api_options": options,
        },
        "execution_mode_schema",
    ) == []
    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(hybrid_api_options=options),
    ) == []
    assert validator.validate_request(
        "/api/v1/hybrid/sessions",
        "POST",
        _hybrid_create_payload(hybrid_api_options=options),
    ) == []


def test_hybrid_api_options_schema_is_reachable_from_contract_graph() -> None:
    assert Path(get_schemas_dir() / "optimization" / "hybrid_api_options_schema.json").is_file()
