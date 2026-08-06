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
            # evaluator_id is the PRE-EXISTING field (200-char, registered-alias
            # semantics) and is untouched by this feature. It is paired with its
            # source here because a source without its value is contradictory --
            # see test_evaluator_source_cannot_contradict_its_own_value.
            evaluator_id="exact-match-v3",
            evaluator_id_source="declared",
        ),
    )

    assert errors == [], f"Expected clean validation, got: {errors}"


def test_evaluator_source_cannot_contradict_its_own_value() -> None:
    """Same correlation rule as agent and dataset, applied to the evaluator.

    Evaluator identity stays optional under every version -- it is not part of
    the (agent, dataset) cohort key -- but once a caller states a source, the
    source and the value must agree.
    """
    declared_without_value = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(evaluator_id_source="declared")
    )
    assert declared_without_value, "'declared' with no evaluator_id is unreadable"

    unknown_with_value = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _payload(evaluator_id="exact-match-v3", evaluator_id_source="unknown"),
    )
    assert unknown_with_value, "'unknown' while carrying an evaluator_id is contradictory"

    omitted_entirely = _validator().validate_request("/api/v1/sessions", "POST", _payload())
    assert omitted_entirely == [], "evaluator identity must stay fully optional"


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


def _v2(**overrides: Any) -> dict[str, Any]:
    """A complete, honest identity_version 2 payload."""
    payload = _payload(
        identity_version=2,
        agent_id="ticket-classifier",
        agent_id_source="declared",
        dataset_id="refunds-golden",
        dataset_id_source="declared",
        artifact_versions={
            "agent": {"schema": "afp2", "digest": "sha256:" + "a" * 64, "state": "verified"},
            "dataset": {"schema": "dfp2o", "digest": "sha256:" + "b" * 64, "state": "verified"},
            "evaluator": {"schema": "efp2", "digest": None, "state": "unknown"},
            "config_space": {"schema": "cfp2", "digest": "sha256:" + "c" * 64, "state": "verified"},
        },
    )
    payload.update(overrides)
    return payload


def test_declaring_v2_and_sending_no_identity_is_rejected() -> None:
    """v2 means 'I speak declared identity'; saying it and sending nothing
    leaves the server to fall back on function_name/agent_key derivation,
    which is the inference this whole contract exists to remove."""
    errors = _validator().validate_request(
        "/api/v1/sessions", "POST", _payload(identity_version=2)
    )

    assert errors, "identity_version 2 with no declared identity must be rejected"


def test_v2_requires_every_identity_source() -> None:
    for field in ("agent_id_source", "dataset_id_source"):
        payload = _v2()
        payload.pop(field)
        errors = _validator().validate_request("/api/v1/sessions", "POST", payload)
        assert errors, f"v2 must require {field}"


def test_a_source_cannot_contradict_its_own_value() -> None:
    """'declared' with no value, or 'unknown' with one, is unreadable: a
    consumer cannot tell which half to believe."""
    contradictions = (
        ("agent claims declared but is null", {"agent_id_source": "declared", "agent_id": None}),
        ("agent claims unknown but has a value", {"agent_id_source": "unknown", "agent_id": "a"}),
        (
            "dataset claims declared but is null",
            {"dataset_id_source": "declared", "dataset_id": None},
        ),
        (
            "dataset claims unknown but has a value",
            {"dataset_id_source": "unknown", "dataset_id": "d"},
        ),
    )
    for label, overrides in contradictions:
        errors = _validator().validate_request("/api/v1/sessions", "POST", _v2(**overrides))
        assert errors, label


def test_a_null_source_cannot_bypass_the_v2_correlations() -> None:
    """Requiring only the KEY is no requirement at all.

    The source type admits null, so a null source satisfied 'required' while
    firing none of the const-based value correlations: a caller could opt into
    v2, send two nulls, and be back to function_name/agent_key inference -- or
    pair a null source with a real id. 'unknown' is how you say you don't know;
    null is not.
    """
    both_null = _v2(agent_id=None, agent_id_source=None, dataset_id=None, dataset_id_source=None)
    assert _validator().validate_request("/api/v1/sessions", "POST", both_null), (
        "v2 with null sources must be rejected"
    )

    smuggled = _v2(agent_id="smuggled", agent_id_source=None)
    assert _validator().validate_request("/api/v1/sessions", "POST", smuggled), (
        "a null source paired with a real id must be rejected"
    )

    # Outside v2 a null source stays legal: v1 callers are untouched.
    legacy = _payload(agent_id_source=None, agent_id=None)
    assert _validator().validate_request("/api/v1/sessions", "POST", legacy) == []


def test_an_honestly_unknown_v2_payload_is_accepted() -> None:
    """Unknown must stay expressible, or callers will fake a value to get through."""
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _v2(
            agent_id=None,
            agent_id_source="unknown",
            dataset_id=None,
            dataset_id_source="unknown",
        ),
    )

    assert errors == [], f"an explicitly unknown v2 run must validate: {errors}"


def test_dataset_id_and_hosted_dataset_ref_are_mutually_exclusive() -> None:
    """Accepting both forces the server to pick a winner between two
    caller-supplied identities, which is inference by another name."""
    errors = _validator().validate_request(
        "/api/v1/sessions",
        "POST",
        _v2(hosted_dataset_ref={"dataset_id": "bench_01HZY8Q4"}),
    )

    assert errors, "dataset_id and hosted_dataset_ref must not both be accepted"


def test_registered_dataset_requires_the_hosted_reference() -> None:
    payload = _v2(dataset_id_source="registered")
    payload.pop("dataset_id")
    errors = _validator().validate_request("/api/v1/sessions", "POST", payload)
    assert errors, "'registered' with no hosted_dataset_ref has nothing to resolve"

    payload["hosted_dataset_ref"] = {"dataset_id": "bench_01HZY8Q4"}
    errors = _validator().validate_request("/api/v1/sessions", "POST", payload)
    assert errors == [], f"the hosted-dataset flow must validate: {errors}"


def test_unknown_dataset_cannot_smuggle_a_hosted_reference() -> None:
    payload = _v2(dataset_id_source="unknown", dataset_id=None)
    payload["hosted_dataset_ref"] = {"dataset_id": "bench_01HZY8Q4"}
    errors = _validator().validate_request("/api/v1/sessions", "POST", payload)

    assert errors, "a hosted reference IS an identity; 'unknown' contradicts it"


def test_legacy_callers_are_unaffected_by_every_v2_constraint() -> None:
    """The whole point of versioning: none of this reaches an old SDK."""
    for payload in (_payload(), _payload(identity_version=1), _payload(agent_id="a")):
        errors = _validator().validate_request("/api/v1/sessions", "POST", payload)
        assert errors == [], f"legacy payload must stay valid: {errors}"


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
