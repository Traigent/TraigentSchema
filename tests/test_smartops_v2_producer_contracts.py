from __future__ import annotations

from traigent_schema import SchemaValidator

LIFECYCLE_ID = "lifecycle_0123456789abcdef"
DECISION_ID = "decision_0123456789abcdef"
ATTEMPT_ID = "attempt_0123456789abcdef"
RESULT_REF = "result_0123456789abcdef"
REVISION_REF = "revision_0123456789abcdef"
EVIDENCE_HASH = "ev_0123456789abcdefghijklmnopqrstuvwxyzAB"


def _result_request(**payload_overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "result_type": "optimization_result",
        "result_payload": {
            "schema_version": "1.0.0",
            "producer_version": "optimizer-2026.07",
            "decision_id": DECISION_ID,
            "attempt_id": ATTEMPT_ID,
            "action_signature": "run_optimization:optimize_probe:agent:2:2:0.15:4:none",
            "evidence_snapshot_hash": EVIDENCE_HASH,
            "operation_kind": "run_optimization",
        },
        "source_run_id": "run_123",
        "result_ref": RESULT_REF,
    }
    payload.update(payload_overrides)
    return payload


def test_producer_routes_are_in_the_backend_contract_catalog() -> None:
    validator = SchemaValidator(contract="backend")
    assert validator._endpoint_schemas[
        "POST:/api/v2/internal/smartops/lifecycles/{lifecycle_id}/results"
    ] == "register_authoritative_result_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/internal/smartops/lifecycles/{lifecycle_id}/revisions"
    ] == "register_artifact_revision_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/internal/smartops/revisions/{revision_ref}/consume"
    ] == "consume_artifact_revision_request_schema"


def test_authoritative_result_requires_exact_execution_binding() -> None:
    validator = SchemaValidator(contract="backend")
    path = f"/api/v2/internal/smartops/lifecycles/{LIFECYCLE_ID}/results"
    assert not validator.validate_request(path, "POST", _result_request())
    for missing in (
        "decision_id",
        "attempt_id",
        "action_signature",
        "evidence_snapshot_hash",
        "operation_kind",
    ):
        nested = dict(_result_request()["result_payload"])
        nested.pop(missing)
        assert validator.validate_request(
            path, "POST", _result_request(result_payload=nested)
        )
    assert validator.validate_request(path, "POST", {**_result_request(), "extra": True})


def test_revision_registration_and_consumption_are_closed_objects() -> None:
    validator = SchemaValidator(contract="backend")
    revision_path = f"/api/v2/internal/smartops/lifecycles/{LIFECYCLE_ID}/revisions"
    revision = {
        "artifact_kind": "dataset",
        "fingerprint": "dataset-fingerprint-v2",
        "source_result_ref": RESULT_REF,
    }
    assert not validator.validate_request(revision_path, "POST", revision)
    assert validator.validate_request(revision_path, "POST", {**revision, "extra": True})

    consume_path = f"/api/v2/internal/smartops/revisions/{REVISION_REF}/consume"
    consume = {"successor_run_id": "run_123", "fingerprint": "dataset-fingerprint-v2"}
    assert not validator.validate_request(consume_path, "POST", consume)
    assert validator.validate_request(consume_path, "POST", {**consume, "extra": True})


def test_producer_responses_are_exact_and_hash_pinned() -> None:
    validator = SchemaValidator(contract="backend")
    result_response = {
        "schema_version": "2.0.0",
        "lifecycle_id": LIFECYCLE_ID,
        "result_ref": RESULT_REF,
        "result_type": "optimization_result",
        "payload_sha256": "a" * 64,
    }
    assert not validator.validate_json(
        result_response, "register_authoritative_result_response_schema"
    )
    assert validator.validate_json(
        {**result_response, "payload_sha256": "not-a-hash"},
        "register_authoritative_result_response_schema",
    )

    revision_response = {
        "schema_version": "2.0.0",
        "lifecycle_id": LIFECYCLE_ID,
        "revision_ref": REVISION_REF,
        "artifact_kind": "dataset",
        "verification_status": "verified",
    }
    assert not validator.validate_json(
        revision_response, "register_artifact_revision_response_schema"
    )
    consume_response = {
        "schema_version": "2.0.0",
        "revision_ref": REVISION_REF,
        "successor_run_id": "run_123",
        "verification_status": "verified",
    }
    assert not validator.validate_json(
        consume_response, "consume_artifact_revision_response_schema"
    )
