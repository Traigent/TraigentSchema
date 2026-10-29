"""Declared optimization identity contract (FR-OPT-IDENTITY-VERSIONING-V1).

Identity is declared, never inferred. An over-length identity is rejected
rather than truncated: silently shortening an identity merges two distinct
agents, and their two optimization histories, into one.
"""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft7Validator

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
        assert "x-privacy-classification" in properties[field], (
            f"{field} has no x-privacy-classification"
        )


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
    errors = _validator().validate_request("/api/v1/sessions", "POST", _payload(identity_version=2))

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


def test_response_agent_id_is_the_resolved_backend_row_not_the_declared_identity() -> None:
    """The create response's `agent_id` is a different field from the request's.

    The request's `agent_id` (tested throughout this file) is a caller-declared,
    free-form identity string used for cohort grouping (max 255 chars, no
    reference semantics). The response's `agent_id` is the server's OWN
    resolution of the backend Agent row (agents.id) for this session -- the SDK
    needs it, unmodified, to call POST /best-configs (X-Traigent-Agent-Id
    header) and GET /best-configs/agent-heads/<agent_id>. The two must never be
    confused: this test locks the response field to reference the Agent
    resource's primary key rather than redeclaring the request's free-text
    identity shape.
    """
    schema_path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))

    response_properties = _session_create_response_properties(document)
    assert "agent_id" in response_properties, "session-create response must expose agent_id"

    response_agent_id = response_properties["agent_id"]
    assert response_agent_id["type"] == ["string", "null"]
    assert response_agent_id.get("x-reference") == "../agents/agent_schema.json#/properties/id"

    # It must not carry the request field's free-text constraints (a 255-char
    # cap and x-content) -- those would misdescribe a resolved backend id.
    assert "maxLength" not in response_agent_id
    assert "x-content" not in response_agent_id


def test_response_agent_id_is_additive_and_optional() -> None:
    """New field, old servers: absence must stay schema-valid.

    The 201 response object declares no `required` list at all (session_id and
    status are equally unenforced today), so adding `agent_id` without a
    `required` entry keeps a caller that omits it -- e.g. a server build that
    predates this feature -- schema-valid.
    """
    schema_path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(schema_path.read_text(encoding="utf-8"))

    response_schema = document["paths"]["/api/v1/sessions"]["post"]["responses"]["201"]["content"][
        "application/json"
    ]["schema"]

    assert "required" not in response_schema
    assert response_schema["additionalProperties"] is True

    Draft7Validator.check_schema(response_schema)
    validator = Draft7Validator(response_schema)

    with_agent_id = {"session_id": "s1", "status": "created", "agent_id": "agt_01HZY8Q4"}
    without_agent_id = {"session_id": "s1", "status": "created"}
    explicit_null = {"session_id": "s1", "status": "created", "agent_id": None}

    for payload in (with_agent_id, without_agent_id, explicit_null):
        errors = list(validator.iter_errors(payload))
        assert errors == [], f"Expected clean validation, got: {errors}"


def _session_create_properties(document: dict[str, Any]) -> dict[str, Any]:
    """Locate the session-create request properties block."""
    node = document["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"]
    return node["application/json"]["schema"]["properties"]


def _session_create_response_properties(document: dict[str, Any]) -> dict[str, Any]:
    """Locate the session-create 201 response properties block."""
    node = document["paths"]["/api/v1/sessions"]["post"]["responses"]["201"]["content"]
    return node["application/json"]["schema"]["properties"]


# ---------------------------------------------------------------------------
# evaluator_code_digest: identity of an unregistered user-code evaluator
# (identified, never validated). Legal only in the identity_version 2 typed
# shape, only instead of every evaluator alias, never in the content-less shape.
# ---------------------------------------------------------------------------

_CODE_DIGEST = "sha256:" + "ab12" * 16


def _v2_code_payload(**overrides: Any) -> dict[str, Any]:
    """A v2 typed create body that omits every evaluator alias."""
    payload = _payload(
        identity_version=2,
        agent_id="ticket-classifier",
        agent_id_source="declared",
        dataset_id="refunds-golden",
        dataset_id_source="declared",
        artifact_versions={
            "agent": {"schema": "fp1", "digest": "sha256:" + "1" * 64, "state": "verified"},
            "dataset": {"schema": "fp1", "digest": "sha256:" + "2" * 64, "state": "verified"},
            "evaluator": {"schema": "fp1", "digest": "sha256:" + "3" * 64, "state": "verified"},
            "config_space": {"schema": "fp1", "digest": "sha256:" + "4" * 64, "state": "verified"},
        },
        evaluator_code_digest=_CODE_DIGEST,
    )
    payload.update(overrides)
    return payload


def _errors(payload: dict[str, Any]) -> list[Any]:
    return _validator().validate_request("/api/v1/sessions", "POST", payload)


def test_code_digest_accepted_alone_in_v2_shape() -> None:
    # The fixture omits evaluator_id (null is rejected, so it must be absent).
    payload = _v2_code_payload()
    assert "evaluator_id" not in payload
    assert _errors(payload) == []


def test_code_digest_accepted_with_unknown_evaluator_source() -> None:
    assert _errors(_v2_code_payload(evaluator_id_source="unknown")) == []


def _assert_only_the_digest_rule_rejects(payload: dict[str, Any], label: str) -> list[Any]:
    """The payload is invalid WITH evaluator_code_digest and valid WITHOUT it.

    That proves the new allOf branch is the only failing constraint, so the test
    cannot pass because of some unrelated, pre-existing rule.
    """
    with_digest = _errors(payload)
    assert with_digest, f"{label}: must be rejected next to evaluator_code_digest"
    without_digest = {k: v for k, v in payload.items() if k != "evaluator_code_digest"}
    assert _errors(without_digest) == [], f"{label}: masked, fails without the digest too"
    return with_digest


def test_code_digest_rejected_with_each_alias() -> None:
    aliases: dict[str, Any] = {
        "evaluator_id": "exact-match-v3",
        "evaluator_definition_id": "exact-match-v3",
        "evaluator_ref": "evaluatorref_" + "0" * 32,  # valid per label_common_schema
    }
    for alias, value in aliases.items():
        _assert_only_the_digest_rule_rejects(_v2_code_payload(**{alias: value}), alias)


def test_code_digest_rejected_with_declared_or_registered_source() -> None:
    # A declared/registered source needs evaluator_id under the pre-existing rule,
    # so evaluator_id is supplied; the payload is valid without the digest. The
    # source restriction cannot be isolated from the alias exclusion here, so also
    # assert the error is attributed to evaluator_id_source (the new branch).
    for source in ("declared", "registered"):
        errs = _assert_only_the_digest_rule_rejects(
            _v2_code_payload(evaluator_id_source=source, evaluator_id="exact-match-v3"), source
        )
        assert any(str(e).startswith("evaluator_id_source:") for e in errs), (source, errs)


def test_code_digest_rejected_in_content_less_shape() -> None:
    _assert_only_the_digest_rule_rejects(
        # A content-less session carries no customer-chosen agent name (TraigentSchema#616),
        # so the fixture's declared agent_id is replaced by the 'unknown' identity.
        _v2_code_payload(
            capabilities=["content_less_v1"], agent_id=None, agent_id_source="unknown"
        ),
        "content_less_v1",
    )


def test_code_digest_rejected_unless_identity_version_is_2() -> None:
    legacy = _v2_code_payload()
    del legacy["identity_version"]
    _assert_only_the_digest_rule_rejects(legacy, "absent identity_version")
    _assert_only_the_digest_rule_rejects(_v2_code_payload(identity_version=1), "version 1")
    # identity_version null / 3 also fail the pre-existing enum without the digest,
    # so they are not new-branch proofs; kept as plain rejection checks.
    assert _errors(_v2_code_payload(identity_version=None)), "null identity_version"
    assert _errors(_v2_code_payload(identity_version=3)), "identity_version 3 is not in the enum"


def test_code_digest_malformed_values_rejected() -> None:
    bad_values: list[Any] = [
        "sha256:" + "AB12" * 16,  # uppercase hex
        "sha256:" + "ab12" * 15,  # too short
        "sha256:" + "ab12" * 16 + "0",  # too long
        "sha512:" + "ab12" * 16,  # wrong prefix
        "fp1:" + "ab12" * 16,  # legacy prefix
        "ab12" * 16,  # no prefix
        "sha256:" + "zz" * 32,  # not hex
        "",
        None,  # null never counts as absent for this field
        123,
    ]
    for bad in bad_values:
        assert _errors(_v2_code_payload(evaluator_code_digest=bad)), repr(bad)


def test_code_digest_null_still_triggers_alias_exclusion() -> None:
    # Presence is tested with `required`, so a null digest still fires the branch.
    # The type error also rejects null, so assert the branch's own error is reported.
    errs = _errors(_v2_code_payload(evaluator_code_digest=None, evaluator_id="x"))
    assert any("should not be valid under" in str(e) for e in errs), errs


def test_code_digest_is_classed_as_digest_in_manifest() -> None:
    manifest = json.loads(
        (get_schemas_dir().parent.parent / "docs" / "content-class-manifest.json").read_text()
    )
    suffix = "/properties/evaluator_code_digest"
    classes = [v for k, v in manifest["classes"].items() if k.endswith(suffix)]
    assert classes and set(classes) == {"digest"}, classes
