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


def _assert_invalid_strategy(validator: SchemaValidator, payload: dict):
    errors = validator.validate_json(payload, "optimization_strategy_schema")
    assert errors
    assert not any("Schema not found" in error for error in errors)
    assert not any("Validation error:" in error for error in errors)
    return errors


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
        "grid": ("grid", "supported", "local_default", None, None),
        "random": ("random", "supported", "local_default", None, None),
        "optuna": ("optuna", "supported", "smart_backend", None, None),
        "bayesian": ("optuna", "supported", "smart_backend", "tpe", None),
        "tpe": ("optuna", "supported", "smart_backend", "tpe", None),
        "hyperband": ("optuna", "supported", "smart_backend", "tpe", "hyperband"),
    }

    for name, (canonical, status, execution_mode, sampler, pruner) in expected.items():
        capability = capabilities[name]
        assert capability["canonical_algorithm"] == canonical
        assert capability["implementation_status"] == status
        assert capability["execution_mode"] == execution_mode
        assert capability.get("sampler") == sampler
        assert capability.get("pruner") == pruner

        if status == "supported":
            assert capability.get("deprecated") is not True


def test_only_grid_and_random_are_local_default_basic_algorithms():
    schema = _load_strategy_schema()
    capabilities = schema["x-traigent-optimization-capabilities"]

    local_default_algorithms = {
        name
        for name, capability in capabilities.items()
        if capability["execution_mode"] == "local_default"
    }

    assert local_default_algorithms == {"grid", "random"}
    assert capabilities["hyperband"]["execution_mode"] == "smart_backend"


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


def test_supported_optimization_strategy_names_validate_with_hyperband_pruning():
    validator = SchemaValidator(contract="sdk_tuning")

    for algorithm in ("grid", "random", "optuna", "bayesian", "tpe", "hyperband"):
        errors = validator.validate_json(
            {"algorithm": algorithm},
            "optimization_strategy_schema",
        )
        assert errors == []

    assert validator.validate_json("bayesian", "optimization_strategy_schema") == []
    assert validator.validate_json("hyperband", "optimization_strategy_schema") == []
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

    assert (
        validator.validate_json(
            {
                "algorithm": "hyperband",
                "sampler": "tpe",
                "startup_trials": 5,
                "n_startup_trials": 2,
                "random_seed": 123,
                "min_resource": 1,
                "max_resource": 27,
                "reduction_factor": 3,
                "bootstrap_count": 1,
            },
            "optimization_strategy_schema",
        )
        == []
    )
    assert (
        validator.validate_json(
            {
                "algorithm": "optuna",
                "sampler": "random",
                "pruner": "hyperband",
                "min_resource": 1,
                "max_resource": "auto",
                "reduction_factor": 4,
                "bootstrap_count": 0,
                "random_seed": 321,
            },
            "optimization_strategy_schema",
        )
        == []
    )

    for payload in (
        {"algorithm": "hyperband", "sampler": "hyperband"},
        {"algorithm": "optuna", "pruner": "median"},
        {"algorithm": "hyperband", "min_resource": 0},
        {"algorithm": "hyperband", "min_resource": "auto"},
        {"algorithm": "optuna", "pruner": "hyperband", "reduction_factor": 1},
        {"algorithm": "optuna", "pruner": "hyperband", "bootstrap_count": -1},
        {"algorithm": "grid", "pruner": "hyperband"},
        {"algorithm": "random", "min_resource": 1},
        {"algorithm": "optuna", "min_resource": 1},
        {"algorithm": "bayesian", "pruner": "hyperband"},
    ):
        _assert_invalid_strategy(validator, payload)


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

    hyperband_errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            **base_payload,
            "optimization_strategy": {"algorithm": "hyperband"},
        },
    )
    assert hyperband_errors == []

    optuna_hyperband_errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            **base_payload,
            "optimization_strategy": {
                "algorithm": "optuna",
                "pruner": "hyperband",
                "min_resource": 1,
                "max_resource": 9,
                "reduction_factor": 3,
                "bootstrap_count": 0,
            },
        },
    )
    assert optuna_hyperband_errors == []

    invalid_local_default_errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        {
            **base_payload,
            "optimization_strategy": {"algorithm": "grid", "pruner": "hyperband"},
        },
    )
    assert invalid_local_default_errors
