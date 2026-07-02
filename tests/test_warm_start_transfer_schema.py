# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for session warm-start transfer metadata."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
TRANSFER_SCHEMA_FILE = OPT_DIR / "warm_start_transfer_schema.json"
ENDPOINTS_FILE = OPT_DIR / "optimization_endpoints.json"
FINALIZE_SCHEMA = "session_finalize_response_schema"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _errors(schema: dict[str, Any], payload: Any) -> list[Any]:
    Draft7Validator.check_schema(schema)
    return list(Draft7Validator(schema).iter_errors(payload))


def _transfer(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "transfer_mode": "model_prior",
        "final_warm_start_weight": "medium",
        "search_space_overlap": "partial",
        "n_seed_configs_applied": 3,
        "refused_reason": None,
    }
    payload.update(overrides)
    return payload


def _session_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def test_warm_start_transfer_schema_accepts_only_declared_fields() -> None:
    schema = _load(TRANSFER_SCHEMA_FILE)

    assert set(schema["properties"]) == {
        "transfer_mode",
        "final_warm_start_weight",
        "search_space_overlap",
        "n_seed_configs_applied",
        "refused_reason",
    }
    assert set(schema["required"]) == set(schema["properties"])
    assert _errors(schema, _transfer()) == []
    assert _errors(schema, _transfer(refused_reason="not_requested")) == []
    assert _errors(schema, _transfer(n_seed_configs_applied=0)) == []
    assert _errors(schema, {k: v for k, v in _transfer().items() if k != "transfer_mode"})
    assert _errors(schema, _transfer(source_session_id="sess_prev"))
    assert _errors(schema, _transfer(confidence=0.8))
    assert _errors(schema, _transfer(metric_name="accuracy"))


def test_warm_start_transfer_schema_enforces_enums_and_count_bounds() -> None:
    schema = _load(TRANSFER_SCHEMA_FILE)

    assert schema["properties"]["transfer_mode"]["enum"] == [
        "cold",
        "replay_only",
        "model_prior",
    ]
    assert schema["properties"]["final_warm_start_weight"]["enum"] == [
        "none",
        "low",
        "medium",
        "high",
    ]
    assert schema["properties"]["search_space_overlap"]["enum"] == [
        "unknown",
        "none",
        "low",
        "partial",
        "high",
        "exact",
    ]
    assert schema["properties"]["refused_reason"]["enum"] == [
        None,
        "not_requested",
        "not_supported_for_tracking_mode",
        "seed_retrieval_error",
        "no_seed_configs",
        "identity_unavailable",
        "identity_changed",
        "insufficient_search_space_overlap",
        "no_projectable_seed_configs",
        "model_prior_not_supported",
        "guard_error",
    ]
    assert _errors(schema, _transfer(transfer_mode="seed_search"))
    assert _errors(schema, _transfer(final_warm_start_weight="full"))
    assert _errors(schema, _transfer(search_space_overlap="medium"))
    assert _errors(schema, _transfer(n_seed_configs_applied=-1))
    assert _errors(schema, _transfer(refused_reason="unsupported"))


def test_warm_start_from_is_declared_on_session_create_request() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(warm_start_from="sess_previous"),
    ) == []
    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(warm_start_from=None),
    ) == []

    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(warm_start_from=""),
    )
    assert validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(warm_start_from="x" * 257),
    )


def test_session_create_response_metadata_references_warm_start_transfer() -> None:
    endpoints = _load(ENDPOINTS_FILE)
    response_schema = endpoints["paths"]["/api/v1/sessions"]["post"]["responses"]["201"][
        "content"
    ]["application/json"]["schema"]
    metadata = response_schema["properties"]["metadata"]

    assert metadata["additionalProperties"] is True
    assert (
        metadata["properties"]["warm_start_transfer"]["$ref"]
        == "./warm_start_transfer_schema.json"
    )


def test_status_response_metadata_references_warm_start_transfer() -> None:
    endpoints = _load(ENDPOINTS_FILE)
    response_schema = endpoints["paths"]["/api/v1/hybrid/sessions/{session_id}/status"][
        "get"
    ]["responses"]["200"]["content"]["application/json"]["schema"]
    metadata = response_schema["properties"]["metadata"]

    assert metadata["additionalProperties"] is True
    assert (
        metadata["properties"]["warm_start_transfer"]["$ref"]
        == "./warm_start_transfer_schema.json"
    )


def test_finalize_response_accepts_warm_start_transfer_metadata() -> None:
    validator = SchemaValidator()

    response = {
        "session_id": "s1",
        "best_config": {"model": "a"},
        "selection_basis": "objective_best",
        "total_trials": 3,
        "metadata": {"warm_start_transfer": _transfer()},
    }

    assert validator.validate_json(response, FINALIZE_SCHEMA) == []


def test_finalize_response_rejects_invalid_warm_start_transfer_metadata() -> None:
    validator = SchemaValidator()

    response = {
        "session_id": "s1",
        "best_config": {"model": "a"},
        "selection_basis": "objective_best",
        "total_trials": 3,
        "metadata": {"warm_start_transfer": _transfer(source_session_id="sess_prev")},
    }

    errors = validator.validate_json(response, FINALIZE_SCHEMA)
    assert errors
    assert any("warm_start_transfer" in error for error in errors)


def test_endpoint_cross_file_refs_stay_package_local() -> None:
    schemas_dir = get_schemas_dir()
    assert (schemas_dir / "optimization" / "warm_start_transfer_schema.json").exists()
