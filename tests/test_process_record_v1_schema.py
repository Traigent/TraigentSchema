"""Contract tests for the closed process-record v1 schema family."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
SCHEMA_PATH = SCHEMAS / "certification" / "process_record_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SHA = "sha256:" + "a" * 64
PROJECT = "project-v1"
BUILD = "build:" + "b" * 8
RECEIPT = "receipt:" + "r" * 8


def _registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(definition: str | None = None) -> Draft7Validator:
    if definition is None:
        document = SCHEMA
    else:
        document = {
            "$schema": SCHEMA["$schema"],
            "$id": f"{SCHEMA['$id']}#test-{definition}",
            "definitions": SCHEMA["definitions"],
            "allOf": [{"$ref": f"#/definitions/{definition}"}],
        }
    return Draft7Validator(document, registry=REGISTRY)


def _errors(value: object, definition: str | None = None) -> list:
    return list(_validator(definition).iter_errors(value))


def _receipt(
    *,
    stream_id: str = "receipt_event_stream",
    step_id: str = "evaluate",
    seq: int = 0,
    receipt_ref: str = RECEIPT,
    digest: str = SHA,
) -> dict:
    return {
        "schema_version": "traigent.process_record.receipt.v1",
        "receipt_ref": receipt_ref,
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "stream_id": stream_id,
        "seq": seq,
        "step_id": step_id,
        "observation_basis": "backend_observed",
        "observed_at": "2026-09-05T10:11:12.123456Z",
        "registered_values": {
            "status_code": "completed",
            "accuracy_ppm": 950000,
            "evaluated_count": 100,
            "cost_microusd": 1250,
            "latency_us": 28000,
        },
        "receipt_digest": digest,
    }


def _present_row(step_id: str, receipt: dict) -> dict:
    return {
        "step_id": step_id,
        "status": "present",
        "observation_kind": "backend_observed",
        "receipt_digest": receipt["receipt_digest"],
        "registered_values": copy.deepcopy(receipt["registered_values"]),
    }


def _report(receipts: list[dict] | None = None) -> dict:
    receipts = receipts or [
        _receipt(
            step_id=step,
            seq=index,
            receipt_ref=f"receipt:{'r' * 7}{index}",
            digest="sha256:" + chr(ord("a") + index) * 64,
        )
        for index, step in enumerate(
            ("prepare", "evaluate", "aggregate", "select", "finalize")
        )
    ]
    rows = [
        _present_row(receipt["step_id"], receipt) for receipt in receipts
    ]
    return {
        "schema_version": "traigent.process_record.report.v1",
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "capture_policy": {
            "policy_id": "traigent.capture_policy.asap.v1",
            "policy_version": "1.0.0",
            "policy_digest": SHA,
        },
        "process_definition": {
            "definition_id": "traigent.process_definition.asap.v1",
            "definition_version": "1.0.0",
            "definition_digest": SHA,
        },
        "expected_step_count": 5,
        "rows": rows,
        "present_count": 5,
        "missing_count": 0,
        "backend_observed_present_count": 5,
        "client_attested_present_count": 0,
        "report_digest": SHA,
    }


def test_schema_is_valid_and_all_external_refs_resolve() -> None:
    Draft7Validator.check_schema(SCHEMA)
    assert _errors({})  # The bundle is intentionally not a minimal object.
    for definition in SCHEMA["definitions"]:
        Draft7Validator.check_schema(
            {
                "$schema": SCHEMA["$schema"],
                "$id": f"{SCHEMA['$id']}#check-{definition}",
                "definitions": SCHEMA["definitions"],
                "allOf": [{"$ref": f"#/definitions/{definition}"}],
            }
        )


def test_receipt_accepts_fixed_unit_numeric_values_without_content() -> None:
    receipt = _receipt()
    assert _errors(receipt, "ProcessRecordReceiptV1") == []
    assert receipt["registered_values"]["accuracy_ppm"] == 950000
    assert receipt["registered_values"]["cost_microusd"] == 1250


@pytest.mark.parametrize(
    "field,value",
    [("seq", -1), ("seq", 2147483648), ("registered_values", {"accuracy_ppm": 1000001})],
)
def test_receipt_rejects_out_of_bounds_values(field: str, value: object) -> None:
    receipt = _receipt()
    receipt[field] = value
    assert _errors(receipt, "ProcessRecordReceiptV1")


@pytest.mark.parametrize("field", ["prompt", "response", "payload", "metadata"])
def test_receipt_rejects_content_and_unregistered_fields(field: str) -> None:
    receipt = _receipt()
    receipt[field] = "customer-content"
    assert _errors(receipt, "ProcessRecordReceiptV1")


def test_receipt_streams_are_three_closed_bounded_arrays() -> None:
    bundle = {
        "schema_version": "traigent.process_record.receipt_bundle.v1",
        "decision_stream": [],
        "receipt_event_stream": [_receipt()],
        "transition_stream": [],
        "receipt_bundle_digest": SHA,
    }
    assert _errors(bundle, "ProcessRecordReceiptBundleV1") == []
    bundle["unexpected_stream"] = []
    assert _errors(bundle, "ProcessRecordReceiptBundleV1")


def test_report_requires_fixed_five_rows_and_typed_values_match_receipt_fixture() -> None:
    receipts = [
        _receipt(
            step_id=step,
            seq=index,
            receipt_ref=f"receipt:{'r' * 7}{index}",
            digest="sha256:" + chr(ord("a") + index) * 64,
        )
        for index, step in enumerate(
            ("prepare", "evaluate", "aggregate", "select", "finalize")
        )
    ]
    report = _report(receipts)
    assert _errors(report, "ProcessRecordReportV1") == []
    assert [row["step_id"] for row in report["rows"]] == [
        "prepare",
        "evaluate",
        "aggregate",
        "select",
        "finalize",
    ]
    evaluate = report["rows"][1]
    assert (
        evaluate["registered_values"]["accuracy_ppm"]
        == receipts[1]["registered_values"]["accuracy_ppm"]
    )
    assert "receipt_digest" in evaluate
    assert "receipt_digests" not in evaluate
    evaluate["receipt_digests"] = [evaluate["receipt_digest"]]
    assert _errors(report, "ProcessRecordReportV1")
    evaluate.pop("receipt_digests")
    report["rows"] = report["rows"][1:]
    assert _errors(report, "ProcessRecordReportV1")
    reordered = _report()
    reordered["rows"][0], reordered["rows"][1] = reordered["rows"][1], reordered["rows"][0]
    assert _errors(reordered, "ProcessRecordReportV1")


def test_missing_report_row_cannot_carry_values_or_receipts() -> None:
    report = _report()
    row = report["rows"][2]
    row["status"] = "missing"
    assert _errors(report, "ProcessRecordReportV1")
    row.pop("receipt_digest")
    row.pop("registered_values")
    assert _errors(report, "ProcessRecordReportV1")
    row.pop("observation_kind")
    report["missing_count"] = 1
    report["present_count"] = 4
    assert _errors(report, "ProcessRecordReportV1") == []


def test_proc1_support_row_is_abstained_or_positive_only_with_full_bindings() -> None:
    abstained = {
        "claim_id": "PROC1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }
    assert _errors(abstained, "ProcessRecordClaimSupportRowV1") == []
    positive = {
        "claim_id": "PROC1",
        "evidence_basis": "issuer_verified",
        "assertion_digest": SHA,
        "process_report_digest": SHA,
        "receipt_bundle_digest": SHA,
        "verifier_result": "pass",
        "claim_material_digest": SHA,
    }
    assert _errors(positive, "ProcessRecordClaimSupportRowV1") == []
    positive.pop("process_report_digest")
    assert _errors(positive, "ProcessRecordClaimSupportRowV1")


def test_proc1_does_not_widen_v0_claim_id_vocabulary() -> None:
    row = {
        "claim_id": "B1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }
    assert _errors(row, "ProcessRecordClaimSupportRowV1")
    assertion = {
        "schema_version": "traigent.process_record.assertion.v1",
        "claim_id": "PROC1",
        "assertion_template_id": "process_record_correctness_v1",
        "capture_policy": {
            "policy_id": "traigent.capture_policy.asap.v1",
            "policy_version": "1.0.0",
            "policy_digest": SHA,
        },
        "rendered_text": SCHEMA["definitions"]["ProcessRecordAssertionV1"]["properties"][
            "rendered_text"
        ]["const"],
        "assertion_digest": SHA,
    }
    assert _errors(assertion, "ProcessRecordAssertionV1") == []
    assertion["rendered_text"] = "caller supplied claim"
    assert _errors(assertion, "ProcessRecordAssertionV1")


def test_registry_documents_are_closed_and_bind_same_fixed_workflow() -> None:
    policy = {
        "schema_version": "traigent.capture_policy_document.v1",
        "policy_id": "traigent.capture_policy.asap.v1",
        "policy_version": "1.0.0",
        "observable_surfaces": ["decision_stream", "receipt_event_stream", "transition_stream"],
        "expected_steps": ["prepare", "evaluate", "aggregate", "select", "finalize"],
        "canonicalization": "jcs_v1",
        "policy_digest": SHA,
    }
    process = {
        "schema_version": "traigent.process_definition_document.v1",
        "definition_id": "traigent.process_definition.asap.v1",
        "definition_version": "1.0.0",
        "expected_steps": ["prepare", "evaluate", "aggregate", "select", "finalize"],
        "stream_ids": ["decision_stream", "receipt_event_stream", "transition_stream"],
        "canonicalization": "jcs_v1",
        "definition_digest": SHA,
    }
    assert _errors(policy, "CapturePolicyDocumentV1") == []
    policy["observable_surfaces"] = ["receipt_event_stream"]
    assert _errors(policy, "CapturePolicyDocumentV1")
    policy["observable_surfaces"] = [
        "transition_stream",
        "receipt_event_stream",
        "decision_stream",
    ]
    assert _errors(policy, "CapturePolicyDocumentV1")
    policy["observable_surfaces"] = [
        "decision_stream",
        "receipt_event_stream",
        "transition_stream",
    ]
    assert _errors(process, "ProcessDefinitionDocumentV1") == []
    process["label"] = "free text"
    assert _errors(process, "ProcessDefinitionDocumentV1")


def test_registry_digests_have_explicit_non_circular_preimages() -> None:
    definitions = SCHEMA["definitions"]
    assert "policy_digest excluded" in definitions["CapturePolicyDocumentV1"]["description"]
    assert "definition_digest excluded" in definitions["ProcessDefinitionDocumentV1"]["description"]
    for name in (
        "TrustStatusSnapshotV1",
        "TrustStatusSignatureV1",
        "TrustStatusEnvelopeV1",
        "KeyStatusEntryV1",
        "CertificateStatusEntryV1",
    ):
        assert name in definitions
    assert "jcs_v1(this body)" in definitions["TrustStatusSnapshotV1"]["description"]
    assert (
        definitions["ProcessRecordDigestDomainRegistryV1"]["properties"]["expected_steps"][
            "const"
        ]
        == "traigent.process_record.expected_steps.v1"
    )
    assert "expected_steps.v1" in definitions["ProcessRecordUnsignedManifestV1"][
        "properties"
    ]["expected_steps_digest"]["description"]


def test_manifest_and_receipt_digest_bindings_are_explicit() -> None:
    definitions = SCHEMA["definitions"]
    assert "8,192 bytes" in definitions["ProcessRecordReceiptV1"]["description"]
    manifest_digest = definitions["ProcessRecordUnsignedManifestV1"]["properties"][
        "base_unsigned_manifest_digest"
    ]["description"]
    assert "declared manifest_digest" in manifest_digest
    signature_digest = definitions["ProcessRecordSignatureV1"]["properties"][
        "unsigned_manifest_digest"
    ]["description"]
    assert "full V1 unsigned manifest" in signature_digest
    assert "issuer_signature.v1" in signature_digest


def test_integer_value_fields_document_strict_python_type_obligation() -> None:
    description = SCHEMA["definitions"]["RegisteredValuesV1"]["description"]
    assert "decoded booleans" in description
    assert "floating-point values" in description
    assert "not expressible by this schema alone" in description


def test_unsigned_manifest_coverage_excludes_signature_and_report_documents() -> None:
    coverage = SCHEMA["definitions"]["ProcessRecordUnsignedManifestV1"]["properties"][
        "coverage"
    ]["const"]
    assert "signature" not in coverage
    assert "report" not in coverage
    assert "claim_support_rows" not in coverage
    assert "receipts" not in coverage


def test_digest_domain_registry_pins_every_v1_preimage_role() -> None:
    document = {
        name: definition["const"]
        for name, definition in SCHEMA["definitions"]["ProcessRecordDigestDomainRegistryV1"][
            "properties"
        ].items()
    }
    assert _errors(document, "ProcessRecordDigestDomainRegistryV1") == []
    assert _errors(
        {**document, "report": "traigent.process_record.receipt.v1"},
        "ProcessRecordDigestDomainRegistryV1",
    )
    preimage = {
        "domain": "traigent.process_record.issuer_signature.v1",
        "framing": "UTF8(domain) || 0x00 || jcs_v1(unsigned_manifest)",
        "signed_projection": "unsigned_manifest",
    }
    assert _errors(preimage, "ProcessRecordSignaturePreimageV1") == []


def test_error_code_is_closed_and_receipt_limit_code_is_v1_only() -> None:
    valid = {
        "schema_version": "traigent.process_record.error.v1",
        "code": "process_record_receipt_limit_exceeded",
    }
    assert _errors(valid, "ProcessRecordErrorV1") == []
    invalid = {"schema_version": "traigent.process_record.error.v1", "code": "new_v0_code"}
    assert _errors(invalid, "ProcessRecordErrorV1")


def test_wire_error_enum_is_coarser_than_the_verifier_error_vocabulary() -> None:
    """The two error vocabularies are deliberately disjoint, not a mirror.

    ``ProcessRecordErrorV1.code`` is the four-value lowercase vocabulary that
    crosses the API boundary; ``PROCESS_RECORD_ERROR_CODES`` is the verifier's
    much finer uppercase set of local exception codes. Neither is derived from
    the other, and there is no sync obligation between them: adding a new
    verifier code (e.g. ``COMMITMENT_REF_MISMATCH``) must NOT widen the wire
    enum, because the boundary's coarseness is the privacy property. This test
    exists because that relationship is easy to misread as a broken mirror.
    """
    from traigent_schema.certification import PROCESS_RECORD_ERROR_CODES

    wire_codes = set(
        SCHEMA["definitions"]["ProcessRecordErrorV1"]["properties"]["code"]["enum"]
    )
    assert wire_codes == {
        "process_record_receipt_limit_exceeded",
        "process_record_invalid_receipt",
        "process_record_invalid_report",
        "process_record_verification_failed",
    }
    assert wire_codes.isdisjoint(PROCESS_RECORD_ERROR_CODES)
    assert all(code == code.lower() for code in wire_codes)
    assert all(code == code.upper() for code in PROCESS_RECORD_ERROR_CODES)
    assert len(wire_codes) < len(PROCESS_RECORD_ERROR_CODES)


# --------------------------------------------------------------------------
# Trust status (the fourth verification input)
# --------------------------------------------------------------------------

TRUST_ANCHOR_REF = "anchor:" + "a" * 8
ISSUER_KEY_REF = "issuerkey:" + "k" * 8
TRUST_RING_REF = "ring:" + "r" * 8
CERT_REF = "certificate:" + "c" * 8
SIGNATURE_BYTES = "A" * 86 + "=="


def _trust_status_envelope() -> dict:
    snapshot = {
        "schema_version": "traigent.process_record.trust_status.v1",
        "trust_anchor_ref": TRUST_ANCHOR_REF,
        "trust_policy_id": "traigent.trust_policy.process_record.v1",
        "max_age_seconds": 86400,
        "effective_time": "2026-09-05T10:11:12Z",
        "key_status": [
            {
                "key_ref": ISSUER_KEY_REF,
                "trust_ring_ref": TRUST_RING_REF,
                "status": "active",
                "revoked_at": None,
                "reason": None,
            }
        ],
        "certificate_status": [
            {
                "certificate_ref": CERT_REF,
                "status": "active",
                "revoked_at": None,
                "reason": None,
            }
        ],
    }
    signature = {
        "schema_version": "traigent.process_record.trust_status_signature.v1",
        "algorithm": "ed25519",
        "trust_anchor_ref": TRUST_ANCHOR_REF,
        "signed_payload": "trust_status_snapshot",
        "snapshot_digest": SHA,
        "signature": SIGNATURE_BYTES,
    }
    return {
        "schema_version": "traigent.process_record.trust_status_envelope.v1",
        "snapshot": snapshot,
        "signature": signature,
    }


def test_trust_status_state_vocabulary_matches_the_v0_retrieval_contract() -> None:
    """Set-equality against the v0 retrieval catalog's own vocabulary, so
    this schema's deliberately-duplicated (not $ref'd, see
    ``TrustStatusStateV1``'s description) enum cannot silently drift."""
    endpoints_path = SCHEMAS / "certification" / "certification_endpoints_v0.json"
    endpoints = json.loads(endpoints_path.read_text(encoding="utf-8"))
    certificate_status = endpoints["components"]["schemas"]["CertificateRetrievalResponseV0"][
        "properties"
    ]["certificate_status"]
    v0_status_enum = set(certificate_status["properties"]["status"]["enum"])
    v0_reason_enum = set(certificate_status["properties"]["reason"]["enum"])

    v1_status_enum = set(SCHEMA["definitions"]["TrustStatusStateV1"]["enum"])
    v1_reason_enum = set(SCHEMA["definitions"]["TrustStatusReasonV1"]["enum"])

    assert v1_status_enum == v0_status_enum
    assert v1_reason_enum == v0_reason_enum


def test_trust_status_definitions_are_closed_and_reject_free_text() -> None:
    envelope = _trust_status_envelope()
    assert _errors(envelope, "TrustStatusEnvelopeV1") == []
    for definition, instance in (
        ("TrustStatusEnvelopeV1", envelope),
        ("TrustStatusSnapshotV1", envelope["snapshot"]),
        ("TrustStatusSignatureV1", envelope["signature"]),
        ("KeyStatusEntryV1", envelope["snapshot"]["key_status"][0]),
        ("CertificateStatusEntryV1", envelope["snapshot"]["certificate_status"][0]),
    ):
        assert _errors(instance, definition) == []
        assert _errors({**instance, "note": "free text"}, definition)


def test_digest_domain_registry_pins_the_trust_status_roles() -> None:
    """Extends ``test_digest_domain_registry_pins_every_v1_preimage_role``:
    that test already builds its document from every registry property, so
    the two new consts are picked up automatically once ``required`` lists
    them -- this test pins their literal values."""
    document = {
        name: definition["const"]
        for name, definition in SCHEMA["definitions"]["ProcessRecordDigestDomainRegistryV1"][
            "properties"
        ].items()
    }
    assert document["trust_status"] == "traigent.process_record.trust_status.v1"
    assert document["trust_anchor_spki"] == "traigent.process_record.trust_anchor_spki_der.v1"
    assert _errors(document, "ProcessRecordDigestDomainRegistryV1") == []
    missing_trust_status = {k: v for k, v in document.items() if k != "trust_status"}
    assert _errors(missing_trust_status, "ProcessRecordDigestDomainRegistryV1")


def test_trust_status_envelope_is_not_reachable_from_the_certificate_bundle() -> None:
    bundle_def = SCHEMA["definitions"]["ProcessRecordCertificateBundleV1"]
    assert "trust_status" not in bundle_def["properties"]
    assert "trust_status" not in bundle_def["required"]
    manifest_coverage = SCHEMA["definitions"]["ProcessRecordUnsignedManifestV1"]["properties"][
        "coverage"
    ]["const"]
    assert "trust_status" not in manifest_coverage


def test_trust_status_state_rejects_unknown_value_and_unbounded_string() -> None:
    envelope = _trust_status_envelope()
    bad_status = copy.deepcopy(envelope)
    bad_status["snapshot"]["key_status"][0]["status"] = "not_a_real_status"
    assert _errors(bad_status, "TrustStatusEnvelopeV1")

    unbounded_ref = copy.deepcopy(envelope)
    unbounded_ref["snapshot"]["trust_anchor_ref"] = "anchor:" + "a" * 200
    assert _errors(unbounded_ref, "TrustStatusEnvelopeV1")


def test_snapshot_entry_lists_are_bounded() -> None:
    envelope = _trust_status_envelope()
    entry = envelope["snapshot"]["key_status"][0]

    over_cap = copy.deepcopy(envelope)
    over_cap["snapshot"]["key_status"] = [
        {**entry, "key_ref": f"issuerkey:{'k' * 7}{i}"} for i in range(65)
    ]
    assert _errors(over_cap, "TrustStatusEnvelopeV1")

    at_cap = copy.deepcopy(envelope)
    at_cap["snapshot"]["key_status"] = [
        {**entry, "key_ref": f"issuerkey:{'k' * 7}{i}"} for i in range(64)
    ]
    assert _errors(at_cap, "TrustStatusEnvelopeV1") == []


def test_utc_timestamp_pattern_is_anchored_and_rejects_malformed_variants() -> None:
    """``UtcTimestampV1`` is a regex over fixed-width digit groups, so it can
    only ever check SHAPE (anchored start/end, literal ``T``/``Z``, an
    optional 1-6 digit fraction) -- never calendar or clock-field RANGES
    (day-per-month, hour <= 23, minute/second <= 59). That range enforcement
    is the verifier's job (``process_record_verifier._parse_utc_timestamp``,
    review finding T1); this test pins only what the pattern itself, being
    anchored with ``^``/``$`` and a ``maxLength``, already guarantees."""
    assert _errors("2026-09-05T10:11:12Z", "UtcTimestampV1") == []
    assert _errors("2026-09-05T10:11:12.123456Z", "UtcTimestampV1") == []
    # Leading/trailing garbage a non-anchored pattern would let through.
    assert _errors("x2026-09-05T10:11:12Z", "UtcTimestampV1")
    assert _errors("2026-09-05T10:11:12Zx", "UtcTimestampV1")
    # Space instead of the literal 'T' separator.
    assert _errors("2026-09-05 10:11:12Z", "UtcTimestampV1")
    # A non-'Z' UTC offset -- the pattern requires the literal 'Z' suffix.
    assert _errors("2026-09-05T10:11:12+00:00", "UtcTimestampV1")
    # Lowercase 't'/'z' -- the pattern's literals are case-sensitive.
    assert _errors("2026-09-05t10:11:12z", "UtcTimestampV1")
    assert _errors("2026-09-05T10:11:12z", "UtcTimestampV1")
    # A 7-digit fraction exceeds the pattern's 1-6 digit bound.
    assert _errors("2026-09-05T10:11:12.1234567Z", "UtcTimestampV1")
    # An empty fraction after the dot is not "1-6 digits".
    assert _errors("2026-09-05T10:11:12.Z", "UtcTimestampV1")
