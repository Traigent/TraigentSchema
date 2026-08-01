"""Declared optimization identity contract (FR-OPT-IDENTITY-VERSIONING-V1).

Identity is declared, never inferred. An over-length identity is rejected
rather than truncated: silently shortening an identity merges two distinct
agents, and their two optimization histories, into one.
"""

from __future__ import annotations

import json
from typing import Any

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


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


def test_session_create_accepts_declared_identity() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(
            agent_id="ticket-classifier",
            agent_id_source="declared",
            dataset_id="refunds-golden",
            dataset_id_source="declared",
            evaluator_id_source="declared",
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_session_create_without_identity_still_validates() -> None:
    """Old SDKs send none of these fields and must stay bit-identical."""
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload())

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_identity_accepts_explicit_null_as_absent() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(agent_id=None, dataset_id=None),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_unknown_is_a_valid_identity_source() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(agent_id=None, agent_id_source="unknown")
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_over_length_identity_is_rejected_not_truncated() -> None:
    for field in ("agent_id", "dataset_id"):
        errors = _validator().validate_request(
            "/api/v1/sessions", "POST", _payload(**{field: "x" * 256})
        )
        assert errors, f"{field} of 256 chars must be rejected, not truncated"


def test_identity_at_the_limit_is_accepted() -> None:
    for field in ("agent_id", "dataset_id"):
        errors = _validator().validate_request(
            "/api/v1/sessions", "POST", _payload(**{field: "x" * 255})
        )
        assert errors == [], f"{field} of 255 chars must be servable, got: {errors}"


def test_empty_string_identity_is_rejected() -> None:
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload(agent_id=""))

    assert errors, "Empty-string identity must be rejected; use null or omit"


def test_identity_source_rejects_values_outside_the_enum() -> None:
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(agent_id_source="derived")
    )

    assert errors, "'derived' is not a valid source: identity is never inferred"


def test_every_new_identity_field_declares_a_privacy_classification() -> None:
    """Disclosure-register rule: no new client->server field ships unclassified."""
    schema_path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    properties = _session_create_properties(document)

    for field in (
        "agent_id",
        "dataset_id",
        "agent_id_source",
        "dataset_id_source",
        "evaluator_id_source",
    ):
        assert field in properties, f"{field} missing from session-create"
        assert (
            "x-privacy-classification" in properties[field]
        ), f"{field} has no x-privacy-classification"


def test_existing_evaluator_id_is_not_redefined() -> None:
    """evaluator_id predates this feature: registered-alias semantics, 200-char limit.

    Redefining it would change an existing property's meaning and break its
    mutual exclusion with evaluator_definition_id.
    """
    schema_path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    evaluator_id = _session_create_properties(document)["evaluator_id"]

    assert evaluator_id["type"] == "string"
    assert evaluator_id["maxLength"] == 200


def _session_create_properties(document: dict[str, Any]) -> dict[str, Any]:
    """Locate the session-create request properties block."""
    node = document["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"]
    return node["application/json"]["schema"]["properties"]
