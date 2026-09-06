# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Deterministic offline controls for the Process Record v1 verifier.

Fixtures are signed locally with the same deterministic test keys used by the
v0 relying-party verifier tests. No Backend module or network service is
imported by the verifier under test.
"""

from __future__ import annotations

import copy
import hashlib
from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from tests.test_agent_certificate_v0_schemas import _b1_claim
from tests.test_certificate_relying_party_verifier import (
    _high_s,
    _materials_fixture,
    _private_keys,
    _sign,
    _sign_fixture,
)
from traigent_schema import fp2
from traigent_schema.certification import (
    PROCESS_RECORD_ERROR_CODES,
    ProcessRecordVerificationContext,
    ProcessRecordVerificationError,
    ProcessRecordVerificationResult,
    verify_process_record_certificate,
)
from traigent_schema.certification import process_record_verifier as pr_impl

PROJECT = "project_contract001"
BUILD = "bsn:" + "a" * 43

RECEIPT_DOMAIN = b"traigent.process_record.receipt.v1"
RECEIPT_BUNDLE_DOMAIN = b"traigent.process_record.receipt_bundle.v1"
REPORT_DOMAIN = b"traigent.process_record.report.v1"
ASSERTION_DOMAIN = b"traigent.process_record.assertion.v1"
CLAIM_MATERIAL_DOMAIN = b"traigent.process_record.claim_material.v1"
CLAIM_SUPPORT_ROWS_DOMAIN = b"traigent.process_record.claim_support_rows.v1"
UNSIGNED_MANIFEST_DOMAIN = b"traigent.process_record.unsigned_manifest.v1"
CAPTURE_POLICY_DOMAIN = b"traigent.process_record.capture_policy.v1"
PROCESS_DEFINITION_DOMAIN = b"traigent.process_record.process_definition.v1"
EXPECTED_STEPS_DOMAIN = b"traigent.process_record.expected_steps.v1"
ISSUER_SIGNATURE_DOMAIN = b"traigent.process_record.issuer_signature.v1"

STREAM_IDS = ("decision_stream", "receipt_event_stream", "transition_stream")
EXPECTED_STEPS = ["prepare", "evaluate", "aggregate", "select", "finalize"]

ASSERTION_RENDERED_TEXT = (
    "For capture policy traigent.capture_policy.asap.v1@1.0.0, this certificate "
    "records the five declared process steps; uncaptured steps are not detectable; "
    "client-reported receipts are attestations, not independent evidence."
)


def _digest(domain: bytes, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


CAPTURE_POLICY_DOCUMENT = {
    "schema_version": "traigent.capture_policy_document.v1",
    "policy_id": "traigent.capture_policy.asap.v1",
    "policy_version": "1.0.0",
    "observable_surfaces": list(STREAM_IDS),
    "expected_steps": list(EXPECTED_STEPS),
    "canonicalization": "jcs_v1",
}
PROCESS_DEFINITION_DOCUMENT = {
    "schema_version": "traigent.process_definition_document.v1",
    "definition_id": "traigent.process_definition.asap.v1",
    "definition_version": "1.0.0",
    "expected_steps": list(EXPECTED_STEPS),
    "stream_ids": list(STREAM_IDS),
    "canonicalization": "jcs_v1",
}
CAPTURE_POLICY_DIGEST = _digest(CAPTURE_POLICY_DOMAIN, CAPTURE_POLICY_DOCUMENT)
PROCESS_DEFINITION_DIGEST = _digest(PROCESS_DEFINITION_DOMAIN, PROCESS_DEFINITION_DOCUMENT)
EXPECTED_STEPS_DIGEST = _digest(EXPECTED_STEPS_DOMAIN, EXPECTED_STEPS)
CAPTURE_POLICY_IDENTITY = {
    "policy_id": "traigent.capture_policy.asap.v1",
    "policy_version": "1.0.0",
    "policy_digest": CAPTURE_POLICY_DIGEST,
}
PROCESS_DEFINITION_IDENTITY = {
    "definition_id": "traigent.process_definition.asap.v1",
    "definition_version": "1.0.0",
    "definition_digest": PROCESS_DEFINITION_DIGEST,
}

_COVERAGE = (
    "base_unsigned_manifest_digest",
    "capture_policy",
    "process_definition",
    "project_ref",
    "build_session_ref",
    "agent_commitment_ref",
    "dataset_commitment_ref",
    "evaluator_commitment_ref",
    "build_definition_commitment_ref",
    "expected_steps",
    "expected_steps_digest",
    "decision_stream",
    "receipt_event_stream",
    "transition_stream",
    "assertion_digest",
    "process_report_digest",
    "receipt_bundle_digest",
    "client_evidence_manifest_digest",
    "process_claim_support_rows_digest",
    "trust_ring_ref",
    "issuer_key_ref",
    "issuer_signature_algorithm",
)


def _receipt(
    *,
    stream_id: str,
    step_id: str,
    seq: int,
    tag: str,
    observation_basis: str = "backend_observed",
    registered_values: dict[str, Any] | None = None,
) -> dict[str, Any]:
    values = registered_values or {
        "status_code": "completed",
        "accuracy_ppm": 950000,
        "evaluated_count": 100,
        "cost_microusd": 1250,
        "latency_us": 28000,
    }
    receipt = {
        "schema_version": "traigent.process_record.receipt.v1",
        "receipt_ref": f"receipt:{tag}",
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "stream_id": stream_id,
        "seq": seq,
        "step_id": step_id,
        "observation_basis": observation_basis,
        "observed_at": "2026-09-05T10:11:12.123456Z",
        "registered_values": values,
    }
    receipt["receipt_digest"] = _digest(RECEIPT_DOMAIN, receipt)
    return receipt


def _stream_index(receipts: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "sequence_values": [r["seq"] for r in receipts],
        "receipt_digests": [r["receipt_digest"] for r in receipts],
        "first_seq": receipts[0]["seq"] if receipts else None,
        "last_seq": receipts[-1]["seq"] if receipts else None,
        "receipt_count": len(receipts),
    }


def _default_streams() -> dict[str, list[dict[str, Any]]]:
    return {
        "decision_stream": [
            _receipt(stream_id="decision_stream", step_id="prepare", seq=0, tag="dec00001"),
            _receipt(stream_id="decision_stream", step_id="evaluate", seq=1, tag="dec00002"),
        ],
        "receipt_event_stream": [
            _receipt(stream_id="receipt_event_stream", step_id="aggregate", seq=0, tag="evt00001"),
        ],
        "transition_stream": [
            _receipt(stream_id="transition_stream", step_id="select", seq=0, tag="trn00001"),
            _receipt(stream_id="transition_stream", step_id="finalize", seq=1, tag="trn00002"),
        ],
    }


def _build_bundle(
    algorithm: str = "ed25519",
    streams: dict[str, list[dict[str, Any]]] | None = None,
) -> tuple[dict[str, Any], ProcessRecordVerificationContext, dict[str, list[dict[str, Any]]]]:
    v0_cert, issuer_public_key, v0_context, policy = _sign_fixture(
        algorithm, claim_factory=_b1_claim, claims=[_b1_claim()], with_co=False
    )
    materials = _materials_fixture(v0_cert, issuer_public_key, v0_context, policy)

    streams = streams if streams is not None else _default_streams()
    receipt_bundle_no_digest = {
        "schema_version": "traigent.process_record.receipt_bundle.v1",
        **{name: streams[name] for name in STREAM_IDS},
    }
    receipt_bundle_digest = _digest(RECEIPT_BUNDLE_DOMAIN, receipt_bundle_no_digest)
    receipt_bundle = {**receipt_bundle_no_digest, "receipt_bundle_digest": receipt_bundle_digest}

    flattened = [receipt for stream_name in STREAM_IDS for receipt in streams[stream_name]]
    # A dict comprehension keeps the last write per key, i.e. exactly the
    # "last matching receipt in flattened order" selection rule under test.
    step_receipt = {r["step_id"]: r for r in flattened}
    rows = []
    present_count = 0
    backend_count = 0
    client_count = 0
    for step in EXPECTED_STEPS:
        r = step_receipt.get(step)
        if r is None:
            rows.append({"step_id": step, "status": "missing"})
            continue
        present_count += 1
        if r["observation_basis"] == "backend_observed":
            backend_count += 1
        elif r["observation_basis"] == "client_attested":
            client_count += 1
        rows.append(
            {
                "step_id": step,
                "status": "present",
                "observation_kind": r["observation_basis"],
                "receipt_digest": r["receipt_digest"],
                "registered_values": copy.deepcopy(r["registered_values"]),
            }
        )
    report_no_digest = {
        "schema_version": "traigent.process_record.report.v1",
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "capture_policy": copy.deepcopy(CAPTURE_POLICY_IDENTITY),
        "process_definition": copy.deepcopy(PROCESS_DEFINITION_IDENTITY),
        "expected_step_count": 5,
        "rows": rows,
        "present_count": present_count,
        "missing_count": 5 - present_count,
        "backend_observed_present_count": backend_count,
        "client_attested_present_count": client_count,
    }
    report_digest = _digest(REPORT_DOMAIN, report_no_digest)
    report = {**report_no_digest, "report_digest": report_digest}

    assertion_no_digest = {
        "schema_version": "traigent.process_record.assertion.v1",
        "claim_id": "PROC1",
        "assertion_template_id": "process_record_correctness_v1",
        "capture_policy": copy.deepcopy(CAPTURE_POLICY_IDENTITY),
        "rendered_text": ASSERTION_RENDERED_TEXT,
    }
    assertion_digest = _digest(ASSERTION_DOMAIN, assertion_no_digest)
    assertion = {**assertion_no_digest, "assertion_digest": assertion_digest}

    claim_material = {
        "claim_id": "PROC1",
        "tier": 3,
        "assertion_template_id": "process_record_correctness_v1",
        "rendered_text": ASSERTION_RENDERED_TEXT,
        "assertion_digest": assertion_digest,
    }
    claim_material_digest = _digest(CLAIM_MATERIAL_DOMAIN, claim_material)
    claim_support_row = {
        "claim_id": "PROC1",
        "evidence_basis": "issuer_verified",
        "assertion_digest": assertion_digest,
        "process_report_digest": report_digest,
        "receipt_bundle_digest": receipt_bundle_digest,
        "verifier_result": "pass",
        "claim_material_digest": claim_material_digest,
    }
    claim_support_rows = [claim_support_row]
    claim_support_rows_digest = _digest(CLAIM_SUPPORT_ROWS_DOMAIN, claim_support_rows)

    issuer_signature = v0_cert["signatures"]["issuer_signature"]
    v0_manifest_digest = v0_cert["signatures"]["unsigned_manifest"]["manifest_digest"]

    unsigned_manifest = {
        "schema_version": "traigent.process_record.unsigned_manifest.v1",
        "base_unsigned_manifest_digest": v0_manifest_digest,
        "capture_policy": copy.deepcopy(CAPTURE_POLICY_IDENTITY),
        "process_definition": copy.deepcopy(PROCESS_DEFINITION_IDENTITY),
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "agent_commitment_ref": "sha256:" + "1" * 64,
        "dataset_commitment_ref": "sha256:" + "2" * 64,
        "evaluator_commitment_ref": "sha256:" + "3" * 64,
        "build_definition_commitment_ref": "sha256:" + "4" * 64,
        "expected_steps": list(EXPECTED_STEPS),
        "expected_steps_digest": EXPECTED_STEPS_DIGEST,
        "decision_stream": _stream_index(streams["decision_stream"]),
        "receipt_event_stream": _stream_index(streams["receipt_event_stream"]),
        "transition_stream": _stream_index(streams["transition_stream"]),
        "assertion_digest": assertion_digest,
        "process_report_digest": report_digest,
        "receipt_bundle_digest": receipt_bundle_digest,
        "client_evidence_manifest_digest": v0_cert["audit_report"]["client_evidence_manifest_root"],
        "process_claim_support_rows_digest": claim_support_rows_digest,
        "trust_ring_ref": issuer_signature["trust_ring_ref"],
        "issuer_key_ref": issuer_signature["issuer_key_ref"],
        "issuer_signature_algorithm": algorithm,
        "coverage": list(_COVERAGE),
    }
    unsigned_manifest_digest = _digest(UNSIGNED_MANIFEST_DOMAIN, unsigned_manifest)

    issuer_private_key, _client_key = _private_keys(algorithm)
    material = ISSUER_SIGNATURE_DOMAIN + b"\x00" + fp2.canonicalize(unsigned_manifest).encode()
    signature_bytes = _sign(issuer_private_key, algorithm, material)

    signature = {
        "schema_version": "traigent.process_record.signature.v1",
        "algorithm": algorithm,
        "issuer_key_ref": issuer_signature["issuer_key_ref"],
        "trust_ring_ref": issuer_signature["trust_ring_ref"],
        "signed_payload": "unsigned_process_manifest",
        "unsigned_manifest_digest": unsigned_manifest_digest,
        "signature": signature_bytes,
    }

    bundle = {
        "schema_version": "traigent.process_record.certificate_bundle.v1",
        "base_certificate_v0": v0_cert,
        "unsigned_manifest": unsigned_manifest,
        "signature": signature,
        "assertion": assertion,
        "claim_support_rows": claim_support_rows,
        "report": report,
        "receipts": receipt_bundle,
        "verification_materials_v0": materials,
    }

    context = ProcessRecordVerificationContext(
        expected_materials_digest=materials["materials_digest"],
        certificate_ref=materials["certificate_ref"],
        base_context=v0_context,
        expected_project_ref=PROJECT,
        expected_build_session_ref=BUILD,
    )
    return bundle, context, streams


def _resign(bundle: dict[str, Any], algorithm: str) -> None:
    """Re-sign after a legitimate (non-adversarial) unsigned-manifest edit."""
    issuer_private_key, _client_key = _private_keys(algorithm)
    unsigned = bundle["unsigned_manifest"]
    unsigned_manifest_digest = _digest(UNSIGNED_MANIFEST_DOMAIN, unsigned)
    material = ISSUER_SIGNATURE_DOMAIN + b"\x00" + fp2.canonicalize(unsigned).encode()
    bundle["signature"]["unsigned_manifest_digest"] = unsigned_manifest_digest
    bundle["signature"]["signature"] = _sign(issuer_private_key, algorithm, material)


def _expect_error(bundle: object, context: object, code: str) -> ProcessRecordVerificationError:
    with pytest.raises(ProcessRecordVerificationError) as exc_info:
        verify_process_record_certificate(bundle, context=context)
    assert exc_info.value.code == code
    assert code in PROCESS_RECORD_ERROR_CODES
    assert str(exc_info.value) == code
    return exc_info.value


# --------------------------------------------------------------------------
# Positive controls
# --------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_valid_bundle_verifies_and_reports_value_to_receipt_agreement(algorithm: str) -> None:
    bundle, context, streams = _build_bundle(algorithm)
    result = verify_process_record_certificate(bundle, context=context)

    assert isinstance(result, ProcessRecordVerificationResult)
    assert result.valid is True
    assert result.code == "PROCESS_RECORD_VERIFIED"
    assert result.base_certificate_status_evidence == "not_checked"
    assert result.project_ref == PROJECT
    assert result.build_session_ref == BUILD
    assert result.present_count == 5
    assert result.missing_count == 0
    assert result.backend_observed_present_count == 5
    assert result.client_attested_present_count == 0
    assert result.receipt_count == 5
    assert result.process_report_digest == bundle["report"]["report_digest"]
    assert result.receipt_bundle_digest == bundle["receipts"]["receipt_bundle_digest"]
    assert result.assertion_digest == bundle["assertion"]["assertion_digest"]
    assert (
        result.process_claim_support_rows_digest
        == bundle["unsigned_manifest"]["process_claim_support_rows_digest"]
    )
    assert result.agent_commitment_ref == bundle["unsigned_manifest"]["agent_commitment_ref"]

    # Tampering with the exact value the statement is about -- a registered
    # value on a receipt that a present report row claims to carry -- must be
    # detected: this is the decisive value-to-receipt property, not merely a
    # schema check.
    tampered = copy.deepcopy(bundle)
    tampered["receipts"]["decision_stream"][0]["registered_values"]["accuracy_ppm"] = 1
    _expect_error(tampered, context, "RECEIPT_DIGEST_MISMATCH")


def test_report_selects_last_matching_receipt_in_flattened_order() -> None:
    """Two receipts for the same step: flatten order picks the later stream's."""
    streams = _default_streams()
    later_evaluate = _receipt(
        stream_id="transition_stream", step_id="evaluate", seq=2, tag="trn00003"
    )
    streams["transition_stream"].append(later_evaluate)
    bundle, context, _ = _build_bundle("ed25519", streams=streams)

    result = verify_process_record_certificate(bundle, context=context)
    assert result.valid is True
    evaluate_row = next(r for r in bundle["report"]["rows"] if r["step_id"] == "evaluate")
    assert evaluate_row["receipt_digest"] == later_evaluate["receipt_digest"]


def test_missing_step_report_row_has_no_digest_or_values() -> None:
    streams = _default_streams()
    del streams["receipt_event_stream"][:]  # no "aggregate" receipt anywhere
    bundle, context, _ = _build_bundle("ed25519", streams=streams)

    result = verify_process_record_certificate(bundle, context=context)
    assert result.present_count == 4
    assert result.missing_count == 1
    aggregate_row = next(r for r in bundle["report"]["rows"] if r["step_id"] == "aggregate")
    assert aggregate_row == {"step_id": "aggregate", "status": "missing"}


# --------------------------------------------------------------------------
# Context / bundle shape
# --------------------------------------------------------------------------


def test_context_must_be_process_record_verification_context() -> None:
    bundle, context, _ = _build_bundle()
    _expect_error(bundle, object(), "CONTEXT")


def test_bundle_must_be_a_dict() -> None:
    _, context, _ = _build_bundle()
    _expect_error(["not", "a", "dict"], context, "BUNDLE_SHAPE")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"expected_materials_digest": "not-a-digest"},
        {"certificate_ref": ""},
        {"expected_project_ref": "bad ref with spaces"},
        {"expected_build_session_ref": "not-opaque-ref"},
    ],
)
def test_context_rejects_malformed_fields(kwargs: dict[str, str]) -> None:
    _, context, _ = _build_bundle()
    base = {
        "expected_materials_digest": context.expected_materials_digest,
        "certificate_ref": context.certificate_ref,
        "base_context": context.base_context,
        "expected_project_ref": context.expected_project_ref,
        "expected_build_session_ref": context.expected_build_session_ref,
    }
    base.update(kwargs)
    with pytest.raises(ProcessRecordVerificationError, match="^CONTEXT$"):
        ProcessRecordVerificationContext(**base)


def test_context_rejects_non_v0_base_context() -> None:
    _, context, _ = _build_bundle()
    with pytest.raises(ProcessRecordVerificationError, match="^CONTEXT$"):
        ProcessRecordVerificationContext(
            expected_materials_digest=context.expected_materials_digest,
            certificate_ref=context.certificate_ref,
            base_context=object(),  # type: ignore[arg-type]
            expected_project_ref=context.expected_project_ref,
            expected_build_session_ref=context.expected_build_session_ref,
        )


def test_context_and_result_are_frozen() -> None:
    bundle, context, _ = _build_bundle()
    with pytest.raises(FrozenInstanceError):
        context.expected_project_ref = "other"  # type: ignore[misc]
    result = verify_process_record_certificate(bundle, context=context)
    with pytest.raises(FrozenInstanceError):
        result.present_count = 0  # type: ignore[misc]


def test_verification_result_rejects_non_true_valid_and_wrong_code() -> None:
    with pytest.raises(ValueError, match="^PROCESS_RECORD_VERIFICATION_RESULT$"):
        ProcessRecordVerificationResult(valid=False)
    with pytest.raises(ValueError, match="^PROCESS_RECORD_VERIFICATION_RESULT$"):
        ProcessRecordVerificationResult(code="OTHER")


# --------------------------------------------------------------------------
# Schema
# --------------------------------------------------------------------------


def test_schema_rejects_missing_required_field() -> None:
    bundle, context, _ = _build_bundle()
    del bundle["assertion"]
    _expect_error(bundle, context, "SCHEMA")


def test_schema_rejects_additional_property() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["free_text_field"] = "customer content"
    _expect_error(bundle, context, "SCHEMA")


# --------------------------------------------------------------------------
# Strict Python integer typing (bool/float aliasing), before canonicalization
# --------------------------------------------------------------------------


def test_strict_integer_rejects_float_seq() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["seq"] = 0.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_registered_value() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["registered_values"]["accuracy_ppm"] = 950000.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_report_counter() -> None:
    bundle, context, _ = _build_bundle()
    bundle["report"]["present_count"] = 5.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_expected_step_count() -> None:
    bundle, context, _ = _build_bundle()
    bundle["report"]["expected_step_count"] = 5.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_stream_index_receipt_count() -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"]["decision_stream"]["receipt_count"] = 2.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_stream_index_sequence_value() -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"]["decision_stream"]["sequence_values"][0] = 0.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_first_seq() -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"]["decision_stream"]["first_seq"] = 0.0
    _expect_error(bundle, context, "STRICT_INTEGER")


def test_strict_integer_rejects_float_report_row_registered_value() -> None:
    bundle, context, _ = _build_bundle()
    bundle["report"]["rows"][0]["registered_values"]["evaluated_count"] = 100.0
    _expect_error(bundle, context, "STRICT_INTEGER")


@pytest.mark.parametrize(
    "value",
    [True, False, 1.5],
)
def test_require_int_rejects_bool_and_non_integral_float_directly(value: object) -> None:
    """White-box: schema already blocks bool at the JSON layer (jsonschema's
    integer type checker excludes bool), so a bundle-level bool mutation
    never reaches this Python-level guard. Exercise ``_require_int`` itself
    to prove the ``type(value) is int`` obligation holds independently of
    schema behavior."""
    with pytest.raises(ProcessRecordVerificationError, match="^STRICT_INTEGER$"):
        pr_impl._require_int(value)


def test_bool_seq_is_rejected_by_schema_before_strict_integer_check() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["seq"] = True
    _expect_error(bundle, context, "SCHEMA")


# --------------------------------------------------------------------------
# Base v0 certificate
# --------------------------------------------------------------------------


def test_base_certificate_invalid_signature() -> None:
    bundle, context, _ = _build_bundle()
    raw_sig = bundle["base_certificate_v0"]["signatures"]["issuer_signature"]["signature"]
    corrupted = ("A" if raw_sig[0] != "A" else "B") + raw_sig[1:]
    bundle["base_certificate_v0"]["signatures"]["issuer_signature"]["signature"] = corrupted
    _expect_error(bundle, context, "BASE_CERTIFICATE_INVALID")


# --------------------------------------------------------------------------
# Scope
# --------------------------------------------------------------------------


def test_scope_mismatch_context_vs_v0_subject() -> None:
    bundle, context, _ = _build_bundle()
    other_context = replace(context, expected_project_ref="project_contract002")
    _expect_error(bundle, other_context, "SCOPE_MISMATCH")


def test_scope_mismatch_receipt_project_ref() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["project_ref"] = "project_contract002"
    _expect_error(bundle, context, "SCOPE_MISMATCH")


def test_base_manifest_digest_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"]["base_unsigned_manifest_digest"] = "sha256:" + "0" * 64
    _expect_error(bundle, context, "BASE_MANIFEST_DIGEST_MISMATCH")


# --------------------------------------------------------------------------
# Receipts
# --------------------------------------------------------------------------


def test_receipt_placed_in_wrong_stream() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["stream_id"] = "transition_stream"
    _expect_error(bundle, context, "RECEIPT_STREAM_MISMATCH")


def test_receipt_out_of_order_seq() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][1]["seq"] = 0
    _expect_error(bundle, context, "RECEIPT_ORDER")


def test_receipt_duplicate_ref_across_streams() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["transition_stream"][0]["receipt_ref"] = bundle["receipts"][
        "decision_stream"
    ][0]["receipt_ref"]
    _expect_error(bundle, context, "RECEIPT_DUPLICATE")


def test_receipt_duplicate_digest_across_streams() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["transition_stream"][0]["receipt_digest"] = bundle["receipts"][
        "decision_stream"
    ][0]["receipt_digest"]
    _expect_error(bundle, context, "RECEIPT_DUPLICATE")


def test_receipt_digest_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["decision_stream"][0]["receipt_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "RECEIPT_DIGEST_MISMATCH")


def test_receipt_bundle_digest_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["receipts"]["receipt_bundle_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "RECEIPT_BUNDLE_DIGEST_MISMATCH")


def test_receipt_stream_limit_exceeded_white_box() -> None:
    """The per-stream 2048 cap is already schema-enforced; probe the
    verifier's own defensive redundant check directly (task requirement:
    "even if Schema already checks part"). The length check runs before any
    per-item inspection, so placeholder items are sufficient."""
    oversized_bundle = {
        "receipts": {
            "decision_stream": [{}] * 2049,
            "receipt_event_stream": [],
            "transition_stream": [],
        }
    }
    with pytest.raises(ProcessRecordVerificationError, match="^RECEIPT_LIMIT_EXCEEDED$"):
        pr_impl._check_receipts(oversized_bundle, PROJECT, BUILD)


def test_receipt_size_exceeded_white_box() -> None:
    """8,192-byte receipt cap is unreachable through schema-valid field
    lengths alone (OpaqueRef/ProjectRefV0 bounds keep a real receipt under
    ~1KB); probe the verifier's explicit size guard directly."""
    huge_ref = "receipt:" + "r" * 20000
    receipt = _receipt(stream_id="decision_stream", step_id="prepare", seq=0, tag="x" * 8)
    receipt["receipt_ref"] = huge_ref
    receipt["receipt_digest"] = _digest(
        RECEIPT_DOMAIN, {k: v for k, v in receipt.items() if k != "receipt_digest"}
    )
    oversized_bundle = {
        "receipts": {
            "decision_stream": [receipt],
            "receipt_event_stream": [],
            "transition_stream": [],
        }
    }
    with pytest.raises(ProcessRecordVerificationError, match="^RECEIPT_SIZE_EXCEEDED$"):
        pr_impl._check_receipts(oversized_bundle, PROJECT, BUILD)


# --------------------------------------------------------------------------
# Stream indexes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("receipt_count", 99),
        ("first_seq", 7),
        ("last_seq", 7),
        ("sequence_values", [0, 99]),
    ],
)
def test_stream_index_mismatch(field: str, value: object) -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"]["decision_stream"][field] = value
    _expect_error(bundle, context, "STREAM_INDEX_MISMATCH")


# --------------------------------------------------------------------------
# Report derivation -- the decisive value-to-receipt property
# --------------------------------------------------------------------------


def test_report_mismatch_reported_metric_changed() -> None:
    bundle, context, _ = _build_bundle()
    bundle["report"]["rows"][0]["registered_values"]["cost_microusd"] = 1
    _expect_error(bundle, context, "REPORT_MISMATCH")


def test_report_mismatch_row_references_receipt_from_another_step() -> None:
    bundle, context, _ = _build_bundle()
    prepare_row = next(r for r in bundle["report"]["rows"] if r["step_id"] == "prepare")
    evaluate_row = next(r for r in bundle["report"]["rows"] if r["step_id"] == "evaluate")
    evaluate_row["receipt_digest"] = prepare_row["receipt_digest"]
    evaluate_row["registered_values"] = copy.deepcopy(prepare_row["registered_values"])
    _expect_error(bundle, context, "REPORT_MISMATCH")


def test_report_mismatch_row_points_to_non_selected_earlier_receipt() -> None:
    streams = _default_streams()
    later_evaluate = _receipt(
        stream_id="transition_stream", step_id="evaluate", seq=2, tag="trn00003"
    )
    streams["transition_stream"].append(later_evaluate)
    bundle, context, _ = _build_bundle("ed25519", streams=streams)
    earlier_evaluate = streams["decision_stream"][1]
    evaluate_row = next(r for r in bundle["report"]["rows"] if r["step_id"] == "evaluate")
    evaluate_row["receipt_digest"] = earlier_evaluate["receipt_digest"]
    evaluate_row["registered_values"] = copy.deepcopy(earlier_evaluate["registered_values"])
    _expect_error(bundle, context, "REPORT_MISMATCH")


def test_report_row_count_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["report"]["rows"] = bundle["report"]["rows"][:4]
    _expect_error(bundle, context, "SCHEMA")


# --------------------------------------------------------------------------
# Assertion / claim material / support row / claim-support digest
# --------------------------------------------------------------------------


def test_assertion_digest_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["assertion"]["assertion_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "ASSERTION_DIGEST_MISMATCH")


def test_capture_policy_mismatch_in_assertion() -> None:
    bundle, context, _ = _build_bundle()
    bundle["assertion"]["capture_policy"]["policy_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "CAPTURE_POLICY_MISMATCH")


def test_claim_support_row_abstained_cannot_return_positive_result() -> None:
    bundle, context, _ = _build_bundle()
    bundle["claim_support_rows"][0] = {
        "claim_id": "PROC1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }
    _expect_error(bundle, context, "CLAIM_NOT_VERIFIED")


def test_claim_support_row_material_digest_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["claim_support_rows"][0]["claim_material_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "CLAIM_SUPPORT_ROW_MISMATCH")


def test_claim_support_row_receipt_bundle_binding_mismatch() -> None:
    bundle, context, _ = _build_bundle()
    bundle["claim_support_rows"][0]["receipt_bundle_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "CLAIM_SUPPORT_ROW_MISMATCH")


# --------------------------------------------------------------------------
# Unsigned-manifest bindings (pillar commitments)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("trust_ring_ref", "ring:zzzzzzzzzzzzzzzz"),
        ("issuer_key_ref", "ikey:zzzzzzzzzzzzzzzz"),
        ("issuer_signature_algorithm", "ecdsa_p256_sha256"),
        ("client_evidence_manifest_digest", "sha256:" + "9" * 64),
        ("assertion_digest", "sha256:" + "9" * 64),
        ("process_report_digest", "sha256:" + "9" * 64),
        ("receipt_bundle_digest", "sha256:" + "9" * 64),
        ("process_claim_support_rows_digest", "sha256:" + "9" * 64),
    ],
)
def test_unsigned_manifest_pillar_commitment_changed_after_signing(
    field: str, value: object
) -> None:
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"][field] = value
    _expect_error(bundle, context, "UNSIGNED_MANIFEST_MISMATCH")


def test_commitment_refs_are_caller_pass_through_not_independently_pinned() -> None:
    """agent/dataset/evaluator/build-definition commitment refs are not in
    the relying-party context (per the task's explicit context scope): the
    verifier surfaces them in the result for the caller to compare against
    its own expectations, rather than failing on an unexpected value."""
    bundle, context, _ = _build_bundle()
    other_ref = "sha256:" + "7" * 64
    bundle["unsigned_manifest"]["agent_commitment_ref"] = other_ref
    _resign(bundle, "ed25519")
    result = verify_process_record_certificate(bundle, context=context)
    assert result.agent_commitment_ref == other_ref


# --------------------------------------------------------------------------
# Signature / key ring
# --------------------------------------------------------------------------


def test_unsigned_manifest_digest_mismatch_in_signature_block() -> None:
    bundle, context, _ = _build_bundle()
    bundle["signature"]["unsigned_manifest_digest"] = "sha256:" + "9" * 64
    _expect_error(bundle, context, "UNSIGNED_MANIFEST_DIGEST_MISMATCH")


def test_key_ring_mismatch_signature_algorithm_vs_pinned_materials() -> None:
    bundle, context, _ = _build_bundle("ed25519")
    bundle["signature"]["algorithm"] = "ecdsa_p256_sha256"
    _expect_error(bundle, context, "KEY_RING_MISMATCH")


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_issuer_signature_invalid(algorithm: str) -> None:
    bundle, context, _ = _build_bundle(algorithm)
    raw_sig = bundle["signature"]["signature"]
    bundle["signature"]["signature"] = ("A" if raw_sig[0] != "A" else "B") + raw_sig[1:]
    _expect_error(bundle, context, "ISSUER_SIGNATURE_INVALID")


def test_issuer_signature_high_s_rejected() -> None:
    bundle, context, _ = _build_bundle("ecdsa_p256_sha256")
    bundle["signature"]["signature"] = _high_s(bundle["signature"]["signature"])
    _expect_error(bundle, context, "ISSUER_SIGNATURE_INVALID")


# --------------------------------------------------------------------------
# Privacy: rejected input never leaks into the error surface
# --------------------------------------------------------------------------


def test_rejected_input_sentinel_never_appears_in_error() -> None:
    bundle, context, _ = _build_bundle()
    sentinel = "ZZZPRIVACYCANARYZZZ"
    # OpaqueRef body accepts alnum/underscore/hyphen, so this stays schema
    # valid; the stale receipt_digest still trips a specific failure.
    bundle["receipts"]["decision_stream"][0]["receipt_ref"] = f"receipt:{sentinel}0000"
    error = _expect_error(bundle, context, "RECEIPT_DIGEST_MISMATCH")
    assert sentinel not in str(error)
    assert sentinel not in repr(error)
    assert all(sentinel not in str(arg) for arg in error.args)


# --------------------------------------------------------------------------
# Error vocabulary closure
# --------------------------------------------------------------------------


def test_error_code_is_the_entire_exception_string() -> None:
    error = ProcessRecordVerificationError("SOME_CODE")
    assert str(error) == "SOME_CODE"
    assert error.code == "SOME_CODE"


def test_process_record_error_codes_are_all_stable_short_strings() -> None:
    assert PROCESS_RECORD_ERROR_CODES
    for code in PROCESS_RECORD_ERROR_CODES:
        assert isinstance(code, str)
        assert code == code.upper()
        assert " " not in code
