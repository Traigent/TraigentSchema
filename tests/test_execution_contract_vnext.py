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


def test_session_create_rejects_execution_mode_legacy_values() -> None:
    """Traigent#2271: execution_mode is a removed request selector, not deprecated.

    It was previously a free-form string (never enum-constrained at the request
    level) so any value — including the two most commonly deployed ones, local
    and edge_analytics — must now fail validation.
    """
    validator = SchemaValidator(contract="sdk_tuning")

    for mode in ("local", "edge_analytics", "hybrid", "hybrid_api", "cloud", "standard"):
        errors = validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(algorithm="grid", offline=True, execution_mode=mode),
        )
        assert errors != [], f"execution_mode={mode!r} must be rejected on session create"


def test_hybrid_session_create_rejects_execution_mode_legacy_values() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    for mode in ("local", "edge_analytics", "hybrid", "hybrid_api"):
        errors = validator.validate_request(
            "/api/v1/hybrid/sessions",
            "POST",
            _hybrid_create_payload(execution_mode=mode),
        )
        assert errors != [], f"execution_mode={mode!r} must be rejected on hybrid session create"


def test_session_create_rejects_flat_hybrid_api_keys() -> None:
    """Flat hybrid_api_* keys are removed; hybrid_api_options (nested) is canonical."""
    validator = SchemaValidator(contract="sdk_tuning")

    assert (
        validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(hybrid_api_endpoint="https://eval.example.com/score"),
        )
        != []
    )
    assert (
        validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(
                hybrid_api_endpoint="https://eval.example.com/score",
                hybrid_api_transport_type="http",
            ),
        )
        != []
    )


def test_hybrid_session_create_rejects_flat_hybrid_api_keys() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert (
        validator.validate_request(
            "/api/v1/hybrid/sessions",
            "POST",
            _hybrid_create_payload(hybrid_api_endpoint="https://eval.example.com/score"),
        )
        != []
    )


def test_native_local_grid_random_create_and_submit_validate() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    for algorithm in ("grid", "random"):
        assert validator.validate_request(
            "/api/v1/sessions",
            "POST",
            _session_create_payload(
                algorithm=algorithm,
                offline=True,
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


def test_optimization_strategy_capabilities_use_only_local_or_cloud_execution_modes() -> None:
    """Traigent#2271: capability metadata is canonical local/cloud only — no hybrid,
    hybrid_api, or edge_analytics value, and no deprecated_execution_modes alias list."""
    strategy_schema = _load_schema("optimization/optimization_strategy_schema.json")
    capabilities = strategy_schema["x-traigent-optimization-capabilities"]

    assert "OptimizationExecutionMode" not in strategy_schema["definitions"]
    allowed = {"local", "cloud"}
    for name, capability in capabilities.items():
        assert capability["execution_mode"] in allowed, (
            f"{name}: execution_mode={capability['execution_mode']!r} not in {allowed}"
        )
        assert "deprecated_execution_modes" not in capability

    definition = strategy_schema["definitions"]["OptimizationCapability"]
    assert "deprecated_execution_modes" not in definition["properties"]
    exec_mode_def = strategy_schema["definitions"]["OptimizationCapabilityExecutionMode"]
    assert exec_mode_def["enum"] == ["local", "cloud"]


def test_hybrid_api_options_schema_is_reachable_from_contract_graph() -> None:
    assert Path(get_schemas_dir() / "optimization" / "hybrid_api_options_schema.json").is_file()
