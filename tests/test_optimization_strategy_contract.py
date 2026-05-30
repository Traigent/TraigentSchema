"""Tests for the canonical optimization strategy capability contract."""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _load_strategy_schema() -> dict:
    schema_path = (
        get_schemas_dir() / "optimization" / "optimization_strategy_schema.json"
    )
    with open(schema_path, encoding="utf-8") as handle:
        return json.load(handle)


def test_each_advertised_optimization_algorithm_has_capability_mapping():
    schema = _load_strategy_schema()
    advertised = set(
        schema["definitions"]["AdvertisedOptimizationAlgorithmName"]["enum"]
    )
    capabilities = schema["x-traigent-optimization-capabilities"]

    assert set(capabilities) == advertised


def test_optimization_capabilities_match_supported_implementation_status():
    schema = _load_strategy_schema()
    capabilities = schema["x-traigent-optimization-capabilities"]

    expected = {
        "grid": ("grid", "supported", "local_default", None),
        "random": ("random", "supported", "local_default", None),
        "optuna": ("optuna", "supported", "smart_backend", None),
        "bayesian": ("optuna", "supported", "smart_backend", "tpe"),
        "tpe": ("optuna", "supported", "smart_backend", "tpe"),
        "hyperband": ("hyperband", "deprecated_unsupported", "unsupported", None),
    }

    for name, (canonical, status, execution_mode, sampler) in expected.items():
        capability = capabilities[name]
        assert capability["canonical_algorithm"] == canonical
        assert capability["implementation_status"] == status
        assert capability["execution_mode"] == execution_mode
        assert capability.get("sampler") == sampler


def test_supported_strategy_enum_matches_supported_capabilities():
    schema = _load_strategy_schema()
    supported_enum = set(
        schema["definitions"]["SupportedOptimizationStrategyName"]["enum"]
    )
    supported_capabilities = {
        name
        for name, capability in schema[
            "x-traigent-optimization-capabilities"
        ].items()
        if capability["implementation_status"] == "supported"
    }

    assert supported_enum == supported_capabilities


def test_supported_optimization_strategy_names_validate_and_hyperband_rejects():
    validator = SchemaValidator(contract="sdk_tuning")

    for algorithm in ("grid", "random", "optuna", "bayesian", "tpe"):
        errors = validator.validate_json(
            {"algorithm": algorithm},
            "optimization_strategy_schema",
        )
        assert errors == []

    assert validator.validate_json("bayesian", "optimization_strategy_schema") == []
    assert (
        validator.validate_json(
            {
                "type": "optuna",
                "sampler": "random",
                "startup_trials": 5,
                "n_startup_trials": 2,
                "random_seed": 123,
                "tracking_mode": "backend_guided",
                "backend_specific_knob": "preserved",
            },
            "optimization_strategy_schema",
        )
        == []
    )

    errors = validator.validate_json(
        {"algorithm": "hyperband"},
        "optimization_strategy_schema",
    )
    assert errors


def test_optimization_session_endpoint_uses_constrained_strategy_contract():
    endpoints_path = (
        get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    )
    with open(endpoints_path, encoding="utf-8") as handle:
        endpoints = json.load(handle)

    request_schema = (
        endpoints["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
            "application/json"
        ]["schema"]
    )
    strategy_schema = request_schema["properties"]["optimization_strategy"]

    assert strategy_schema == {
        "$ref": "./optimization_strategy_schema.json#/definitions/OptimizationStrategyConfig",
        "description": "Canonical optimization strategy selection constrained to implemented or explicitly aliased algorithms.",
    }


def test_sdk_session_request_validates_constrained_optimization_strategy():
    validator = SchemaValidator(contract="sdk_tuning")
    base_payload = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }

    valid_errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            **base_payload,
            "optimization_strategy": {"algorithm": "bayesian"},
        },
    )
    assert valid_errors == []

    invalid_errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            **base_payload,
            "optimization_strategy": {"algorithm": "hyperband"},
        },
    )
    assert invalid_errors
