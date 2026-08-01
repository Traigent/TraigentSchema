"""Hosted-dataset reference contract (FR-OPT-IDENTITY-VERSIONING-V1)."""

from __future__ import annotations

from typing import Any

from traigent_schema import SchemaValidator


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _validator() -> SchemaValidator:
    return SchemaValidator(contract="sdk_tuning")


def test_accepts_hosted_dataset_ref() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(hosted_dataset_ref={"dataset_id": "bench_01HZY8Q4"}),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_hosted_dataset_ref_is_optional() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload())

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_hosted_dataset_ref_requires_a_dataset_id() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(hosted_dataset_ref={})
    )

    assert errors, "hosted_dataset_ref must carry a dataset_id"


def test_hosted_dataset_ref_rejects_extra_properties() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(hosted_dataset_ref={"dataset_id": "bench_01HZY8Q4", "name": "refunds"}),
    )

    assert errors, "hosted_dataset_ref is a closed object: no smuggled fields"


def test_hosted_dataset_ref_rejects_empty_dataset_id() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(hosted_dataset_ref={"dataset_id": ""})
    )

    assert errors, "An empty hosted dataset id must be rejected"
