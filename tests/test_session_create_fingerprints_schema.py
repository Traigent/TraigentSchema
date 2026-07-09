"""Session-create fingerprint provenance contract."""

from __future__ import annotations

import json
from typing import Any

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _session_create_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _fingerprints() -> dict[str, str | None]:
    return {
        "dataset": "fp1:0123456789abcdef",
        "agent": "fp1:abcdef0123456789",
        "evaluator": None,
        "config_space": "fp1:1111222233334444",
    }


def _fingerprint_meta() -> dict[str, object]:
    return {
        "algorithm": "fp1",
        "dataset_example_count": 12,
        "source_available": True,
    }


def test_session_create_accepts_optional_artifact_fingerprints() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            artifact_fingerprints=_fingerprints(),
            fingerprint_meta=_fingerprint_meta(),
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_without_artifact_fingerprints_still_validates() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_accepts_explicit_registered_evaluator_identity() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            evaluator_definition_id="eval_registered_1",
            artifact_fingerprints=_fingerprints(),
            fingerprint_meta=_fingerprint_meta(),
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_accepts_legacy_evaluator_identity_alias() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(evaluator_id="eval_registered_1"),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_rejects_both_evaluator_identity_aliases() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            evaluator_id="eval_registered_1",
            evaluator_definition_id="eval_registered_1",
        ),
    )

    assert errors


def test_session_create_rejects_blank_evaluator_definition_identity() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(evaluator_definition_id=""),
    )

    assert errors
    assert any("evaluator_definition_id" in error for error in errors)


def test_session_create_rejects_overlong_evaluator_definition_identity() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(evaluator_definition_id="x" * 201),
    )

    assert errors
    assert any("evaluator_definition_id" in error for error in errors)


def test_session_create_rejects_unknown_artifact_fingerprint_property() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    fingerprints = _fingerprints()
    fingerprints["prompt"] = "fp1:unexpected"

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            artifact_fingerprints=fingerprints,
            fingerprint_meta=_fingerprint_meta(),
        ),
    )

    assert errors
    assert any("artifact_fingerprints" in error for error in errors)


def test_session_create_rejects_non_string_artifact_fingerprint() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    fingerprints: dict[str, object] = _fingerprints()
    fingerprints["dataset"] = 123

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            artifact_fingerprints=fingerprints,
            fingerprint_meta=_fingerprint_meta(),
        ),
    )

    assert errors
    assert any("artifact_fingerprints.dataset" in error for error in errors)


def test_session_create_rejects_invalid_fingerprint_meta() -> None:
    validator = SchemaValidator(contract="sdk_tuning")

    errors = validator.validate_request(
        "/api/v1/sessions",
        "POST",
        _session_create_payload(
            artifact_fingerprints=_fingerprints(),
            fingerprint_meta={
                "algorithm": "fp2",
                "dataset_example_count": -1,
                "source_available": True,
            },
        ),
    )

    assert errors
    assert any("fingerprint_meta.algorithm" in error for error in errors)
    assert any("fingerprint_meta.dataset_example_count" in error for error in errors)


def test_session_create_contract_documents_fingerprints_as_opaque_hashes() -> None:
    endpoints = json.loads(
        (get_schemas_dir() / "optimization" / "optimization_endpoints.json").read_text(
            encoding="utf-8"
        )
    )
    schema = endpoints["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    properties = schema["properties"]

    assert "artifact_fingerprints" in properties
    assert "fingerprint_meta" in properties
    assert "artifact_fingerprints" not in schema["required"]
    assert "fingerprint_meta" not in schema["required"]
    assert (
        properties["artifact_fingerprints"]["description"]
        == "Optional opaque content fingerprints for SDK session-create provenance. "
        "Values are privacy-safe hashes only and never carry content."
    )
