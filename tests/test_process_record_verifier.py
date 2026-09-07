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
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import FrozenInstanceError, asdict, fields, replace
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from referencing.exceptions import Unresolvable

from tests.test_agent_certificate_v0_schemas import _b1_claim
from tests.test_certificate_relying_party_verifier import (
    _MATERIALS_DOMAIN,
    _high_s,
    _materials_fixture,
    _private_keys,
    _public_key_der_b64,
    _public_key_digest,
    _retrieval_wrapper,
    _sign,
    _sign_fixture,
)
from tests.test_certificate_relying_party_verifier import _digest as _v0_digest
from tests.test_process_record_v1_schema import _errors as _schema_errors
from traigent_schema import fp2
from traigent_schema.certification import (
    PROCESS_RECORD_ERROR_CODES,
    ProcessRecordVerificationContext,
    ProcessRecordVerificationError,
    ProcessRecordVerificationResult,
    TrustAnchorKeyV1,
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
TRUST_STATUS_DOMAIN = b"traigent.process_record.trust_status.v1"
TRUST_POLICY_ID = "traigent.trust_policy.process_record.v1"
TRUST_MAX_AGE_SECONDS = 86400

STREAM_IDS = ("decision_stream", "receipt_event_stream", "transition_stream")
EXPECTED_STEPS = ["prepare", "evaluate", "aggregate", "select", "finalize"]

ASSERTION_RENDERED_TEXT = (
    "For capture policy traigent.capture_policy.asap.v1@1.0.0, this certificate "
    "records the five declared process steps; uncaptured steps are not detectable; "
    "client-reported receipts are attestations, not independent evidence."
)


def _digest(domain: bytes, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


def _shift_timestamp(timestamp: str, *, seconds: float = 0, microseconds: int = 0) -> str:
    """A ``UtcTimestampV1``-shaped string, offset from ``timestamp``.

    Test-only helper: the production module deliberately parses these
    strings itself (see ``_utc_microseconds``'s "never datetime tz
    inference" note) rather than through ``datetime``; this helper builds
    fixtures, it is not the code under test.
    """
    base = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    shifted = base + timedelta(seconds=seconds, microseconds=microseconds)
    return shifted.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _registry_document(filename: str) -> dict[str, Any]:
    """Load a canonical registry document from shipped package data.

    The test deliberately reads the same ``traigent_schema/data/certification``
    artifact the verifier loads instead of re-declaring the literal: a
    duplicated copy would keep passing while the shipped document drifted
    (review finding F4). The digest oracle below stays independent -- it is
    this file's own ``_digest``, never the implementation's ``_role_digest``.
    """
    text = (
        resources.files("traigent_schema")
        .joinpath("data")
        .joinpath("certification")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )
    return json.loads(text)  # type: ignore[no-any-return]


CAPTURE_POLICY_DOCUMENT = _registry_document("capture_policy_document.json")
PROCESS_DEFINITION_DOCUMENT = _registry_document("process_definition_document.json")

# Frozen at HEAD 1bab1a5, i.e. computed over the pre-move Python-literal
# registry documents. Moving the documents to package data must not disturb
# any digest an already-issued certificate carries, so these hex values are
# hardcoded rather than recomputed.
HEAD_CAPTURE_POLICY_DIGEST = (
    "sha256:ab7cd0277dd494515d884aad2970365389849a1ef7a5cdb78005dda8646bd10f"
)
HEAD_PROCESS_DEFINITION_DIGEST = (
    "sha256:1ffea9cef9cf15fe8f7a5e95b2d2128da12bb8d3e549cec8c830746fa1b3d5c7"
)

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

# The four pillar commitments the fixture is FOR. One source of truth: the
# signed manifest and the relying-party context both read these, so a test
# that swaps one of them is swapping it on exactly one side.
AGENT_COMMITMENT_REF = "sha256:" + "1" * 64
DATASET_COMMITMENT_REF = "sha256:" + "2" * 64
EVALUATOR_COMMITMENT_REF = "sha256:" + "3" * 64
BUILD_DEFINITION_COMMITMENT_REF = "sha256:" + "4" * 64
COMMITMENT_REF_FIELDS = (
    "agent_commitment_ref",
    "dataset_commitment_ref",
    "evaluator_commitment_ref",
    "build_definition_commitment_ref",
)
OTHER_COMMITMENT_REF = "sha256:" + "7" * 64

SENTINEL = "ZZZPRIVACYCANARYZZZ"

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


DEFAULT_VERIFICATION_TIME = "2026-09-05T10:11:12.123456Z"


def _trust_anchor_private_key(algorithm: str) -> object:
    """A trust-anchor keypair, deliberately distinct from the fixture's
    issuer and client keys (which live at byte ranges 0-31 / 32-63 for
    ed25519 and derivation seeds 1 / 2 for ECDSA in
    ``tests.test_certificate_relying_party_verifier._private_keys``)."""
    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(96, 128)))
    return ec.derive_private_key(9, ec.SECP256R1())


def _trust_anchor_key(
    algorithm: str, private_key: object, key_ref: str = "anchor:" + "a" * 8
) -> TrustAnchorKeyV1:
    public_key = private_key.public_key()
    return TrustAnchorKeyV1(
        key_ref=key_ref,
        algorithm=algorithm,
        public_key_der_b64=_public_key_der_b64(public_key),
        public_key_digest=_public_key_digest(public_key, pr_impl._TRUST_ANCHOR_SPKI_DOMAIN),
    )


def _trust_status_snapshot(
    *,
    trust_anchor_ref: str,
    issuer_key_ref: str,
    trust_ring_ref: str,
    certificate_ref: str,
    effective_time: str = DEFAULT_VERIFICATION_TIME,
    trust_policy_id: str = TRUST_POLICY_ID,
    max_age_seconds: int = TRUST_MAX_AGE_SECONDS,
    key_status: str = "active",
    key_revoked_at: str | None = None,
    key_reason: str | None = None,
    cert_status: str = "active",
    cert_revoked_at: str | None = None,
    cert_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "traigent.process_record.trust_status.v1",
        "trust_anchor_ref": trust_anchor_ref,
        "trust_policy_id": trust_policy_id,
        "max_age_seconds": max_age_seconds,
        "effective_time": effective_time,
        "key_status": [
            {
                "key_ref": issuer_key_ref,
                "trust_ring_ref": trust_ring_ref,
                "status": key_status,
                "revoked_at": key_revoked_at,
                "reason": key_reason,
            }
        ],
        "certificate_status": [
            {
                "certificate_ref": certificate_ref,
                "status": cert_status,
                "revoked_at": cert_revoked_at,
                "reason": cert_reason,
            }
        ],
    }


def _sign_trust_status(
    snapshot: dict[str, Any], algorithm: str, private_key: object, trust_anchor_ref: str
) -> dict[str, Any]:
    snapshot_digest = _digest(TRUST_STATUS_DOMAIN, snapshot)
    material = TRUST_STATUS_DOMAIN + b"\x00" + fp2.canonicalize(snapshot).encode()
    signature_bytes = _sign(private_key, algorithm, material)
    return {
        "schema_version": "traigent.process_record.trust_status_signature.v1",
        "algorithm": algorithm,
        "trust_anchor_ref": trust_anchor_ref,
        "signed_payload": "trust_status_snapshot",
        "snapshot_digest": snapshot_digest,
        "signature": signature_bytes,
    }


def _trust_status_envelope(snapshot: dict[str, Any], signature: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "traigent.process_record.trust_status_envelope.v1",
        "snapshot": snapshot,
        "signature": signature,
    }


def _build_trust_status(
    bundle: dict[str, Any],
    context: ProcessRecordVerificationContext,
    algorithm: str = "ed25519",
    *,
    anchor_private_key: object | None = None,
    anchor_key: TrustAnchorKeyV1 | None = None,
    effective_time: str = DEFAULT_VERIFICATION_TIME,
    verification_time: str = DEFAULT_VERIFICATION_TIME,
    trust_policy_id: str = TRUST_POLICY_ID,
    max_age_seconds: int = TRUST_MAX_AGE_SECONDS,
    key_status: str = "active",
    key_revoked_at: str | None = None,
    key_reason: str | None = None,
    cert_status: str = "active",
    cert_revoked_at: str | None = None,
    cert_reason: str | None = None,
) -> tuple[dict[str, Any], ProcessRecordVerificationContext]:
    """A fresh, active, correctly-signed trust-status envelope plus a matching
    context (``verification_time`` + ``trust_anchor`` set).

    ``anchor_private_key`` / ``anchor_key`` let a caller reuse the same
    anchor across a scenario (e.g. to prove a snapshot is authentic while
    varying only its content) or substitute a DIFFERENT anchor (the
    signature-fails-with-wrong-anchor test).
    """
    unsigned = bundle["unsigned_manifest"]
    private_key = anchor_private_key or _trust_anchor_private_key(algorithm)
    key = anchor_key or _trust_anchor_key(algorithm, private_key)
    snapshot = _trust_status_snapshot(
        trust_anchor_ref=key.key_ref,
        issuer_key_ref=unsigned["issuer_key_ref"],
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref=context.certificate_ref,
        effective_time=effective_time,
        trust_policy_id=trust_policy_id,
        max_age_seconds=max_age_seconds,
        key_status=key_status,
        key_revoked_at=key_revoked_at,
        key_reason=key_reason,
        cert_status=cert_status,
        cert_revoked_at=cert_revoked_at,
        cert_reason=cert_reason,
    )
    signature = _sign_trust_status(snapshot, algorithm, private_key, key.key_ref)
    envelope = _trust_status_envelope(snapshot, signature)
    new_context = replace(context, verification_time=verification_time, trust_anchor=key)
    return envelope, new_context


def _default_trust_anchor(algorithm: str) -> TrustAnchorKeyV1:
    return _trust_anchor_key(algorithm, _trust_anchor_private_key(algorithm))


def _build_bundle(
    algorithm: str = "ed25519",
    streams: dict[str, list[dict[str, Any]]] | None = None,
    *,
    allow_unchecked_base_status: bool = True,
    verification_time: str = DEFAULT_VERIFICATION_TIME,
    trust_anchor: TrustAnchorKeyV1 | None = None,
) -> tuple[dict[str, Any], ProcessRecordVerificationContext, dict[str, list[dict[str, Any]]]]:
    """Build a matching (bundle, context) pair.

    The context always pins the same four pillar commitments the manifest
    declares, so every caller of this helper gets a context that agrees with
    its bundle without copy-pasting one. ``allow_unchecked_base_status``
    defaults to ``True`` so most fixtures don't need a trust anchor at all;
    when ``False``, a default trust-anchor key is constructed automatically
    (``verification_time``/``trust_anchor`` can still be overridden) so the
    context stays valid on its own -- callers that also want a checked-status
    PASS additionally build a snapshot via ``_build_trust_status``, see
    ``test_checked_status_arrives_by_snapshot_not_by_a_retrieval_wrapper``.
    """
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
        "agent_commitment_ref": AGENT_COMMITMENT_REF,
        "dataset_commitment_ref": DATASET_COMMITMENT_REF,
        "evaluator_commitment_ref": EVALUATOR_COMMITMENT_REF,
        "build_definition_commitment_ref": BUILD_DEFINITION_COMMITMENT_REF,
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

    if not allow_unchecked_base_status and trust_anchor is None:
        trust_anchor = _default_trust_anchor(algorithm)
    context = ProcessRecordVerificationContext(
        expected_materials_digest=materials["materials_digest"],
        certificate_ref=materials["certificate_ref"],
        base_context=v0_context,
        expected_project_ref=PROJECT,
        expected_build_session_ref=BUILD,
        expected_agent_commitment_ref=AGENT_COMMITMENT_REF,
        expected_dataset_commitment_ref=DATASET_COMMITMENT_REF,
        expected_evaluator_commitment_ref=EVALUATOR_COMMITMENT_REF,
        expected_build_definition_commitment_ref=BUILD_DEFINITION_COMMITMENT_REF,
        allow_unchecked_base_status=allow_unchecked_base_status,
        verification_time=verification_time,
        trust_anchor=trust_anchor,
    )
    return bundle, context, streams


def _context_kwargs(context: ProcessRecordVerificationContext) -> dict[str, Any]:
    """Every context field by name, without recursing into ``base_context``.

    ``dataclasses.asdict`` would turn the v0 ``VerificationContext`` into a
    plain dict and defeat the isinstance guard under test.
    """
    return {field.name: getattr(context, field.name) for field in fields(context)}


def _resign(bundle: dict[str, Any], algorithm: str) -> None:
    """Re-sign after a legitimate (non-adversarial) unsigned-manifest edit."""
    issuer_private_key, _client_key = _private_keys(algorithm)
    unsigned = bundle["unsigned_manifest"]
    unsigned_manifest_digest = _digest(UNSIGNED_MANIFEST_DOMAIN, unsigned)
    material = ISSUER_SIGNATURE_DOMAIN + b"\x00" + fp2.canonicalize(unsigned).encode()
    bundle["signature"]["unsigned_manifest_digest"] = unsigned_manifest_digest
    bundle["signature"]["signature"] = _sign(issuer_private_key, algorithm, material)


def _expect_error(
    bundle: object, context: object, code: str, *, trust_status: object | None = None
) -> ProcessRecordVerificationError:
    with pytest.raises(ProcessRecordVerificationError) as exc_info:
        verify_process_record_certificate(bundle, context=context, trust_status=trust_status)
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
    # The fixture opts out of the v0 dynamic status check, so the success code
    # must say so rather than reading as an unqualified pass (finding F1).
    assert result.code == "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"
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
        # The four pillar pins take the same Sha256Digest shape the schema
        # gives agent_commitment_ref et al.; anything else fails closed.
        {"expected_agent_commitment_ref": "not-a-digest"},
        {"expected_dataset_commitment_ref": "sha256:" + "A" * 64},
        {"expected_evaluator_commitment_ref": "sha256:" + "3" * 63},
        {"expected_build_definition_commitment_ref": ""},
        # A required bool, not a truthy stand-in: the caller must choose.
        {"allow_unchecked_base_status": "true"},
        {"allow_unchecked_base_status": 1},
    ],
)
def test_context_rejects_malformed_fields(kwargs: dict[str, object]) -> None:
    _, context, _ = _build_bundle()
    base = _context_kwargs(context)
    base.update(kwargs)
    with pytest.raises(ProcessRecordVerificationError, match="^CONTEXT$"):
        ProcessRecordVerificationContext(**base)


def test_context_rejects_non_v0_base_context() -> None:
    _, context, _ = _build_bundle()
    base = _context_kwargs(context)
    base["base_context"] = object()
    with pytest.raises(ProcessRecordVerificationError, match="^CONTEXT$"):
        ProcessRecordVerificationContext(**base)


def test_context_requires_every_pillar_pin_and_the_status_choice() -> None:
    """No pillar pin and no status choice may be silently defaulted."""
    _, context, _ = _build_bundle()
    required = (
        "expected_agent_commitment_ref",
        "expected_dataset_commitment_ref",
        "expected_evaluator_commitment_ref",
        "expected_build_definition_commitment_ref",
        "allow_unchecked_base_status",
    )
    for name in required:
        base = _context_kwargs(context)
        del base[name]
        with pytest.raises(TypeError):
            ProcessRecordVerificationContext(**base)


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
    # The success vocabulary is exactly two codes -- a checked-status pass and
    # an explicitly status-unchecked pass. Nothing else may be constructed.
    # Each must be paired with its own matching trust_status_evidence.
    assert (
        ProcessRecordVerificationResult(
            code="PROCESS_RECORD_VERIFIED", trust_status_evidence="trust_status_snapshot"
        ).valid
        is True
    )
    assert (
        ProcessRecordVerificationResult(
            code="PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED", trust_status_evidence="not_checked"
        ).valid
        is True
    )
    with pytest.raises(ValueError, match="^PROCESS_RECORD_VERIFICATION_RESULT$"):
        ProcessRecordVerificationResult(code="PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED_EXTRA")


def test_result_cannot_pair_a_checked_code_with_unchecked_evidence() -> None:
    """The (code, trust_status_evidence) pairing is closed: neither success
    code may carry the other's evidence value."""
    with pytest.raises(ValueError, match="^PROCESS_RECORD_VERIFICATION_RESULT$"):
        ProcessRecordVerificationResult(
            code="PROCESS_RECORD_VERIFIED", trust_status_evidence="not_checked"
        )
    with pytest.raises(ValueError, match="^PROCESS_RECORD_VERIFICATION_RESULT$"):
        ProcessRecordVerificationResult(
            code="PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED",
            trust_status_evidence="trust_status_snapshot",
        )


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


def test_unchecked_base_status_is_not_reported_as_a_plain_pass() -> None:
    """allow_unchecked_base_status=True verifies, but says so in the code.

    Before the fix the same bundle returned ``PROCESS_RECORD_VERIFIED`` -- a
    result shape indistinguishable from one whose base certificate had been
    checked and found active (review finding F1).
    """
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=True)
    result = verify_process_record_certificate(bundle, context=context)
    assert result.code == "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"
    assert result.base_certificate_status_evidence == "not_checked"
    assert result.code != "PROCESS_RECORD_VERIFIED"


def test_absent_snapshot_under_required_status_is_unavailable() -> None:
    """allow_unchecked_base_status=False must not return any success value
    when no trust_status snapshot is supplied.

    The embedded v0 base certificate is now ALWAYS verified with
    ``require_status=False`` (the retrieval wrapper v0 would need is never
    representable as ``base_certificate_v0`` -- see the next test), so v0
    itself no longer fails here. Dynamic status is established at the V1
    level instead: with no snapshot supplied, status is simply unavailable.
    The decisive assertion is that no ``ProcessRecordVerificationResult`` is
    produced at all.
    """
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    _expect_error(bundle, context, "REVOCATION_STATUS_UNAVAILABLE")


def test_checked_status_arrives_by_snapshot_not_by_a_retrieval_wrapper() -> None:
    """Checked status is reached via the trust_status snapshot, not a v0 wrapper.

    ``ProcessRecordCertificateBundleV1.base_certificate_v0`` ``$ref``s
    ``agent_certificate_v0_schema.json``, which is ``additionalProperties:
    false`` over a bare certificate. The retrieval wrapper that carries v0's
    own ``certificate_status`` is therefore still rejected by the V1 schema
    -- that boundary is unchanged and deliberate. But
    ``allow_unchecked_base_status=False`` is no longer a fail-closed mode
    with no passing input: supplying a fresh, active ``trust_status``
    snapshot over the fourth verification input reaches
    ``PROCESS_RECORD_VERIFIED``.
    """
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    wrapper = _retrieval_wrapper(
        bundle["base_certificate_v0"], bundle["verification_materials_v0"]
    )
    assert wrapper["certificate_status"]["status"] == "active"
    wrapped_bundle = copy.deepcopy(bundle)
    wrapped_bundle["base_certificate_v0"] = wrapper
    _expect_error(wrapped_bundle, context, "SCHEMA")

    trust_status, status_context = _build_trust_status(bundle, context)
    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert result.code == "PROCESS_RECORD_VERIFIED"
    assert result.trust_status_evidence == "trust_status_snapshot"


# --------------------------------------------------------------------------
# Trust status (the fourth verification input)
# --------------------------------------------------------------------------


def test_fresh_active_snapshot_reaches_process_record_verified() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(bundle, context)
    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert result.code == "PROCESS_RECORD_VERIFIED"
    assert result.trust_status_evidence == "trust_status_snapshot"
    assert result.trust_anchor_ref == status_context.trust_anchor.key_ref
    assert result.trust_status_effective_time == trust_status["snapshot"]["effective_time"]


def test_base_certificate_status_evidence_is_still_not_checked_on_a_verified_result() -> None:
    """Pins the Q5 honesty finding: v0's own status check never runs for this
    bundle shape, so ``base_certificate_status_evidence`` stays
    ``"not_checked"`` even on a checked-status ``PROCESS_RECORD_VERIFIED``.
    Dynamic status is established by ``trust_status_evidence`` instead.
    """
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(bundle, context)
    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert result.code == "PROCESS_RECORD_VERIFIED"
    assert result.base_certificate_status_evidence == "not_checked"


def test_allow_unchecked_true_without_snapshot_still_reports_status_unchecked() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=True)
    result = verify_process_record_certificate(bundle, context=context)
    assert result.code == "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"
    assert result.trust_status_evidence == "not_checked"
    assert result.trust_anchor_ref == ""
    assert result.trust_status_effective_time == ""


def test_supplying_a_snapshot_with_allow_unchecked_true_is_a_context_error() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=True)
    with pytest.raises(ProcessRecordVerificationError, match="^CONTEXT$"):
        verify_process_record_certificate(bundle, context=context, trust_status={})


def test_revoked_issuer_key_in_snapshot_fails_closed() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        key_status="revoked_after_issuance",
        key_reason="compromise",
        key_revoked_at=DEFAULT_VERIFICATION_TIME,
    )
    _expect_error(bundle, status_context, "KEY_REVOKED", trust_status=trust_status)


def test_revoked_certificate_in_snapshot_fails_closed() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        cert_status="revoked_after_issuance",
        cert_reason="administrative",
        cert_revoked_at=DEFAULT_VERIFICATION_TIME,
    )
    _expect_error(bundle, status_context, "CERTIFICATE_REVOKED", trust_status=trust_status)


def test_key_revocation_is_checked_before_certificate_revocation() -> None:
    """Both entries revoked: the result must be KEY_REVOKED, pinning order."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        key_status="untrusted_compromise",
        key_reason="compromise",
        key_revoked_at=DEFAULT_VERIFICATION_TIME,
        cert_status="revoked_after_issuance",
        cert_reason="administrative",
        cert_revoked_at=DEFAULT_VERIFICATION_TIME,
    )
    _expect_error(bundle, status_context, "KEY_REVOKED", trust_status=trust_status)


def test_stale_snapshot_is_unavailable_not_a_pass() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        effective_time=_shift_timestamp(DEFAULT_VERIFICATION_TIME, seconds=-86401),
    )
    _expect_error(
        bundle, status_context, "REVOCATION_STATUS_UNAVAILABLE", trust_status=trust_status
    )


def test_snapshot_at_exactly_max_age_still_verifies() -> None:
    """Age exactly 86,400 s passes -- the upper bound is inclusive."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        effective_time=_shift_timestamp(DEFAULT_VERIFICATION_TIME, seconds=-86400),
    )
    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert result.code == "PROCESS_RECORD_VERIFIED"


def test_future_dated_snapshot_is_unavailable() -> None:
    """One microsecond ahead of verification_time is enough -- pins skew=0."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        effective_time=_shift_timestamp(DEFAULT_VERIFICATION_TIME, microseconds=1),
    )
    _expect_error(
        bundle, status_context, "REVOCATION_STATUS_UNAVAILABLE", trust_status=trust_status
    )


def test_snapshot_not_covering_this_key_is_unavailable() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    algorithm = "ed25519"
    unsigned = bundle["unsigned_manifest"]
    private_key = _trust_anchor_private_key(algorithm)
    anchor_key = _trust_anchor_key(algorithm, private_key)
    snapshot = _trust_status_snapshot(
        trust_anchor_ref=anchor_key.key_ref,
        issuer_key_ref="issuerkey:" + "z" * 8,
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref=context.certificate_ref,
    )
    signature = _sign_trust_status(snapshot, algorithm, private_key, anchor_key.key_ref)
    trust_status = _trust_status_envelope(snapshot, signature)
    status_context = replace(
        context, verification_time=DEFAULT_VERIFICATION_TIME, trust_anchor=anchor_key
    )
    _expect_error(
        bundle, status_context, "REVOCATION_STATUS_UNAVAILABLE", trust_status=trust_status
    )


def test_snapshot_not_covering_this_certificate_ref_is_unavailable() -> None:
    """Key covered, certificate_ref not."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    algorithm = "ed25519"
    unsigned = bundle["unsigned_manifest"]
    private_key = _trust_anchor_private_key(algorithm)
    anchor_key = _trust_anchor_key(algorithm, private_key)
    snapshot = _trust_status_snapshot(
        trust_anchor_ref=anchor_key.key_ref,
        issuer_key_ref=unsigned["issuer_key_ref"],
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref="certificate:" + "z" * 8,
    )
    signature = _sign_trust_status(snapshot, algorithm, private_key, anchor_key.key_ref)
    trust_status = _trust_status_envelope(snapshot, signature)
    status_context = replace(
        context, verification_time=DEFAULT_VERIFICATION_TIME, trust_anchor=anchor_key
    )
    _expect_error(
        bundle, status_context, "REVOCATION_STATUS_UNAVAILABLE", trust_status=trust_status
    )


def test_wrong_trust_anchor_key_fails_signature() -> None:
    """Snapshot claims the pinned anchor's ref but was signed by a different
    private key -- the ref check passes, the cryptographic check must not."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    algorithm = "ed25519"
    real_private_key = _trust_anchor_private_key(algorithm)
    real_anchor_key = _trust_anchor_key(algorithm, real_private_key)
    impostor_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))
    trust_status, status_context = _build_trust_status(
        bundle,
        context,
        algorithm,
        anchor_private_key=impostor_private_key,
        anchor_key=real_anchor_key,
    )
    _expect_error(
        bundle, status_context, "TRUST_STATUS_SIGNATURE_INVALID", trust_status=trust_status
    )


def test_snapshot_trust_anchor_ref_must_equal_the_pinned_anchor() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(bundle, context)
    other_anchor = _trust_anchor_key(
        "ed25519", _trust_anchor_private_key("ed25519"), key_ref="anchor:" + "b" * 8
    )
    assert other_anchor.key_ref != status_context.trust_anchor.key_ref
    mismatched_context = replace(status_context, trust_anchor=other_anchor)
    _expect_error(bundle, mismatched_context, "TRUST_ANCHOR_MISMATCH", trust_status=trust_status)


def test_tampered_snapshot_body_fails() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(bundle, context)

    # Flip a status field after signing, recompute the convenience digest to
    # match (an adversary can hash without a private key), but keep the now
    # stale signature -- must fail on the SIGNATURE, not the digest pin.
    tampered = copy.deepcopy(trust_status)
    tampered["snapshot"]["key_status"][0]["status"] = "revoked_after_issuance"
    tampered["snapshot"]["key_status"][0]["reason"] = "compromise"
    tampered["snapshot"]["key_status"][0]["revoked_at"] = DEFAULT_VERIFICATION_TIME
    tampered["signature"]["snapshot_digest"] = _digest(
        TRUST_STATUS_DOMAIN, tampered["snapshot"]
    )
    _expect_error(
        bundle, status_context, "TRUST_STATUS_SIGNATURE_INVALID", trust_status=tampered
    )

    # Corrupt only the digest field, leaving the signed body and the
    # signature bytes both intact and mutually consistent.
    digest_only = copy.deepcopy(trust_status)
    digest_only["signature"]["snapshot_digest"] = "sha256:" + "0" * 64
    _expect_error(
        bundle, status_context, "TRUST_STATUS_DIGEST_MISMATCH", trust_status=digest_only
    )


def test_snapshot_declaring_a_different_policy_is_rejected() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    wrong_id, id_context = _build_trust_status(
        bundle, context, trust_policy_id="traigent.trust_policy.process_record.v2"
    )
    _expect_error(bundle, id_context, "TRUST_POLICY_MISMATCH", trust_status=wrong_id)

    wrong_age, age_context = _build_trust_status(bundle, context, max_age_seconds=3600)
    _expect_error(bundle, age_context, "TRUST_POLICY_MISMATCH", trust_status=wrong_age)


def test_duplicate_entry_for_the_same_key_is_rejected() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    algorithm = "ed25519"
    unsigned = bundle["unsigned_manifest"]
    private_key = _trust_anchor_private_key(algorithm)
    anchor_key = _trust_anchor_key(algorithm, private_key)
    status_context = replace(
        context, verification_time=DEFAULT_VERIFICATION_TIME, trust_anchor=anchor_key
    )

    key_dup_snapshot = _trust_status_snapshot(
        trust_anchor_ref=anchor_key.key_ref,
        issuer_key_ref=unsigned["issuer_key_ref"],
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref=context.certificate_ref,
    )
    key_dup_snapshot["key_status"].append(copy.deepcopy(key_dup_snapshot["key_status"][0]))
    key_dup_signature = _sign_trust_status(
        key_dup_snapshot, algorithm, private_key, anchor_key.key_ref
    )
    key_dup_trust_status = _trust_status_envelope(key_dup_snapshot, key_dup_signature)
    _expect_error(
        bundle, status_context, "TRUST_STATUS_SHAPE", trust_status=key_dup_trust_status
    )

    # ...and the same for certificate_status entries keyed by certificate_ref.
    cert_dup_snapshot = _trust_status_snapshot(
        trust_anchor_ref=anchor_key.key_ref,
        issuer_key_ref=unsigned["issuer_key_ref"],
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref=context.certificate_ref,
    )
    cert_dup_snapshot["certificate_status"].append(
        copy.deepcopy(cert_dup_snapshot["certificate_status"][0])
    )
    cert_dup_signature = _sign_trust_status(
        cert_dup_snapshot, algorithm, private_key, anchor_key.key_ref
    )
    cert_dup_trust_status = _trust_status_envelope(cert_dup_snapshot, cert_dup_signature)
    _expect_error(
        bundle, status_context, "TRUST_STATUS_SHAPE", trust_status=cert_dup_trust_status
    )


def test_result_cannot_pair_a_checked_code_with_unchecked_evidence_via_verifier() -> None:
    """The pairing invariant also holds end-to-end, not just at direct
    ``ProcessRecordVerificationResult`` construction (see the dataclass-level
    test of the same property in the Context/Result section above)."""
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    trust_status, status_context = _build_trust_status(bundle, context)
    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert (result.code, result.trust_status_evidence) == (
        "PROCESS_RECORD_VERIFIED",
        "trust_status_snapshot",
    )


def test_trust_status_sentinel_never_appears_in_error_or_result() -> None:
    bundle, context, _ = _build_bundle(allow_unchecked_base_status=False)
    algorithm = "ed25519"
    unsigned = bundle["unsigned_manifest"]
    private_key = _trust_anchor_private_key(algorithm)
    anchor_key = _trust_anchor_key(algorithm, private_key)
    snapshot = _trust_status_snapshot(
        trust_anchor_ref=anchor_key.key_ref,
        issuer_key_ref=unsigned["issuer_key_ref"],
        trust_ring_ref=unsigned["trust_ring_ref"],
        certificate_ref=context.certificate_ref,
    )
    # An extra, unused entry carrying the sentinel: it never matches the
    # lookup key, so a fully successful verification still rides it through
    # -- and it must not surface anywhere in the accepted result.
    snapshot["key_status"].append(
        {
            "key_ref": f"issuerkey:{SENTINEL}",
            "trust_ring_ref": unsigned["trust_ring_ref"],
            "status": "active",
            "revoked_at": None,
            "reason": None,
        }
    )
    signature = _sign_trust_status(snapshot, algorithm, private_key, anchor_key.key_ref)
    trust_status = _trust_status_envelope(snapshot, signature)
    status_context = replace(
        context, verification_time=DEFAULT_VERIFICATION_TIME, trust_anchor=anchor_key
    )
    assert SENTINEL in json.dumps(trust_status, sort_keys=True)

    result = verify_process_record_certificate(
        bundle, context=status_context, trust_status=trust_status
    )
    assert result.valid is True
    _assert_result_surfaces_are_clean(result)

    # Rejected direction: a wrong-anchor key_ref carrying the sentinel must
    # not leak into the exception surface -- str/repr/args/traceback.
    bad_anchor = _trust_anchor_key(algorithm, private_key, key_ref=f"anchor:{SENTINEL}xx")
    bad_context = replace(status_context, trust_anchor=bad_anchor)
    with pytest.raises(ProcessRecordVerificationError) as exc_info:
        verify_process_record_certificate(
            bundle, context=bad_context, trust_status=trust_status
        )
    assert exc_info.value.code == "TRUST_ANCHOR_MISMATCH"
    assert SENTINEL not in str(exc_info.value)
    assert SENTINEL not in repr(exc_info.value)
    assert all(SENTINEL not in str(arg) for arg in exc_info.value.args)
    formatted = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert SENTINEL not in formatted


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


def _bulk_receipt(stream_id: str, seq: int) -> dict[str, Any]:
    """A minimal receipt carrying only what ``_check_receipts`` reads."""
    receipt = {
        "schema_version": "traigent.process_record.receipt.v1",
        "receipt_ref": f"receipt:{stream_id[:3]}{seq:08d}",
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "stream_id": stream_id,
        "seq": seq,
        "step_id": "prepare",
        "observation_basis": "backend_observed",
        "observed_at": "2026-09-05T10:11:12.123456Z",
        "registered_values": {"status_code": "completed"},
    }
    receipt["receipt_digest"] = _digest(RECEIPT_DOMAIN, receipt)
    return receipt


def _bulk_streams(counts: tuple[int, int, int]) -> dict[str, list[dict[str, Any]]]:
    return {
        stream_id: [_bulk_receipt(stream_id, seq) for seq in range(count)]
        for stream_id, count in zip(STREAM_IDS, counts, strict=True)
    }


def test_combined_receipt_cap_fires_when_stream_caps_would_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The 6,144 combined cap, which no schema-valid input can reach today.

    Three streams x maxItems 2048 is exactly 6,144, so ``total > 6144`` cannot
    fire while the per-stream cap holds -- the branch had zero coverage
    (review finding F3). This raises ONLY the per-stream cap, in-test, to
    model the schema drift the combined cap exists to survive; the shipped
    ``_MAX_STREAM_ITEMS`` and ``_MAX_TOTAL_RECEIPTS`` are unchanged. With the
    per-stream branch unreachable, ``RECEIPT_LIMIT_EXCEEDED`` can only come
    from the combined check.
    """
    monkeypatch.setattr(pr_impl, "_MAX_STREAM_ITEMS", 4096)
    assert pr_impl._MAX_TOTAL_RECEIPTS == 6144

    # 6,144 exactly: at the cap, not over it. Must pass.
    at_cap = {"receipts": _bulk_streams((2048, 2048, 2048))}
    assert sum(len(at_cap["receipts"][name]) for name in STREAM_IDS) == 6144
    pr_impl._check_receipts(at_cap, PROJECT, BUILD)

    # 6,145: one over, and every stream still inside the raised per-stream cap.
    over_cap = {"receipts": _bulk_streams((2049, 2048, 2048))}
    assert sum(len(over_cap["receipts"][name]) for name in STREAM_IDS) == 6145
    assert all(len(over_cap["receipts"][name]) <= 4096 for name in STREAM_IDS)
    with pytest.raises(ProcessRecordVerificationError, match="^RECEIPT_LIMIT_EXCEEDED$"):
        pr_impl._check_receipts(over_cap, PROJECT, BUILD)


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


@pytest.mark.parametrize("field", COMMITMENT_REF_FIELDS)
def test_commitment_ref_swapped_and_resigned_is_rejected(field: str) -> None:
    """A validly-signed record naming a different pillar commitment fails.

    This is the inversion of the pre-fix
    ``test_commitment_refs_are_caller_pass_through_not_independently_pinned``,
    which asserted such a bundle VERIFIED (review finding F2). The re-sign is
    what makes it discriminating: the issuer signature over the mutated
    manifest is valid, so only the caller's own pin can reject it.

    Step 1 establishes that discrimination instead of assuming it. The pin is
    checked BEFORE the issuer signature, so a bundle that was never re-signed
    raises the same ``COMMITMENT_REF_MISMATCH`` -- the rejection on its own
    therefore says nothing about the signature. Verifying the very same bundle
    against a context pinned to the swapped ref first proves the bundle is
    otherwise wholly valid and correctly re-signed; only then does step 2
    isolate the caller's pin as the sole cause of the rejection.
    """
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"][field] = OTHER_COMMITMENT_REF
    _resign(bundle, "ed25519")

    # Step 1: the mutated, re-signed bundle is a fully valid record -- for a
    # caller that actually pinned the swapped commitment.
    matching_context = replace(context, **{f"expected_{field}": OTHER_COMMITMENT_REF})
    result = verify_process_record_certificate(copy.deepcopy(bundle), context=matching_context)
    assert result.valid is True
    assert result.code == "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"
    assert getattr(result, field) == OTHER_COMMITMENT_REF

    # Step 2: same bytes, original pin -- only the caller's expectation differs.
    _expect_error(bundle, context, "COMMITMENT_REF_MISMATCH")


@pytest.mark.parametrize("field", COMMITMENT_REF_FIELDS)
def test_commitment_ref_changed_after_signing_fails_on_the_pin_first(field: str) -> None:
    """The manifest-mutation sweep, extended to the four pillar refs.

    These four cannot reach ``UNSIGNED_MANIFEST_MISMATCH`` like the eight
    fields above: the caller pin is checked first and owns them, so the
    expected code is ``COMMITMENT_REF_MISMATCH``.
    """
    bundle, context, _ = _build_bundle()
    bundle["unsigned_manifest"][field] = OTHER_COMMITMENT_REF
    _expect_error(bundle, context, "COMMITMENT_REF_MISMATCH")


@pytest.mark.parametrize(
    "context_field,manifest_field",
    [(f"expected_{name}", name) for name in COMMITMENT_REF_FIELDS],
)
def test_caller_pinning_a_different_commitment_rejects_an_untouched_bundle(
    context_field: str, manifest_field: str
) -> None:
    """The relying-party direction: the bundle is genuine, the caller wanted
    a different agent/dataset/evaluator/build-definition version."""
    bundle, context, _ = _build_bundle()
    assert bundle["unsigned_manifest"][manifest_field] != OTHER_COMMITMENT_REF
    other_context = replace(context, **{context_field: OTHER_COMMITMENT_REF})
    _expect_error(bundle, other_context, "COMMITMENT_REF_MISMATCH")


def test_result_reports_the_four_pinned_commitment_refs() -> None:
    bundle, context, _ = _build_bundle()
    result = verify_process_record_certificate(bundle, context=context)
    assert result.agent_commitment_ref == context.expected_agent_commitment_ref
    assert result.dataset_commitment_ref == context.expected_dataset_commitment_ref
    assert result.evaluator_commitment_ref == context.expected_evaluator_commitment_ref
    assert (
        result.build_definition_commitment_ref
        == context.expected_build_definition_commitment_ref
    )
    # ...and those are the values the signed manifest actually carries, so the
    # equality above is a binding, not a restatement of the context.
    unsigned = bundle["unsigned_manifest"]
    assert result.agent_commitment_ref == unsigned["agent_commitment_ref"]
    assert result.dataset_commitment_ref == unsigned["dataset_commitment_ref"]
    assert result.evaluator_commitment_ref == unsigned["evaluator_commitment_ref"]
    assert result.build_definition_commitment_ref == unsigned["build_definition_commitment_ref"]


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
    sentinel = SENTINEL
    # OpaqueRef body accepts alnum/underscore/hyphen, so this stays schema
    # valid; the stale receipt_digest still trips a specific failure.
    bundle["receipts"]["decision_stream"][0]["receipt_ref"] = f"receipt:{sentinel}0000"
    error = _expect_error(bundle, context, "RECEIPT_DIGEST_MISMATCH")
    assert sentinel not in str(error)
    assert sentinel not in repr(error)
    assert all(sentinel not in str(arg) for arg in error.args)


def _assert_result_surfaces_are_clean(result: ProcessRecordVerificationResult) -> None:
    assert SENTINEL not in str(result)
    assert SENTINEL not in repr(result)
    assert SENTINEL not in json.dumps(asdict(result), sort_keys=True)


def test_accepted_bundle_sentinel_never_appears_in_the_result() -> None:
    """A bundle that VERIFIES, carrying a sentinel in a receipt ref.

    The rejected-input canary above only covers the exception surface (review
    finding F7). Here the sentinel rides an ``OpaqueRef`` through a fully
    successful verification -- receipts, receipt bundle, stream indexes, and
    the signed manifest are all rebuilt around it -- and must not reach
    ``str`` / ``repr`` / ``dataclasses.asdict`` of the result, which sees only
    digests and counters.
    """
    streams = _default_streams()
    streams["decision_stream"][0] = _receipt(
        stream_id="decision_stream", step_id="prepare", seq=0, tag=SENTINEL
    )
    bundle, context, _ = _build_bundle("ed25519", streams=streams)
    # The plant is live: a no-op plant would make the assertions vacuous.
    assert SENTINEL in json.dumps(bundle, sort_keys=True)

    result = verify_process_record_certificate(bundle, context=context)
    assert result.valid is True
    _assert_result_surfaces_are_clean(result)


def test_non_echoed_context_sentinel_never_appears_in_the_result() -> None:
    """The context direction, using a field the result does not echo.

    ``expected_project_ref``, ``expected_build_session_ref`` and the four
    ``expected_*_commitment_ref`` pins ARE echoed into the result by design,
    so they cannot carry a canary. ``certificate_ref`` is not echoed: it is an
    ``OpaqueRef`` bound to the verification materials, so the sentinel is
    planted on both sides (materials and context) and the materials digest
    re-derived, leaving a bundle that still verifies.
    """
    bundle, context, _ = _build_bundle()
    materials = bundle["verification_materials_v0"]
    materials["certificate_ref"] = f"certificate:{SENTINEL}"
    del materials["materials_digest"]
    materials["materials_digest"] = _v0_digest(_MATERIALS_DOMAIN, materials)
    context = replace(
        context,
        certificate_ref=materials["certificate_ref"],
        expected_materials_digest=materials["materials_digest"],
    )
    assert SENTINEL in context.certificate_ref

    result = verify_process_record_certificate(bundle, context=context)
    assert result.valid is True
    _assert_result_surfaces_are_clean(result)


# --------------------------------------------------------------------------
# Registry documents shipped as package data
# --------------------------------------------------------------------------


def test_registry_document_digests_are_unchanged_by_the_package_data_move() -> None:
    """Moving the two registry documents out of Python literals into
    ``traigent_schema/data/certification`` must not change any digest an
    already-issued certificate carries. The expected hex is hardcoded from
    the pre-move implementation, not recomputed from the new source."""
    assert CAPTURE_POLICY_DIGEST == HEAD_CAPTURE_POLICY_DIGEST
    assert PROCESS_DEFINITION_DIGEST == HEAD_PROCESS_DEFINITION_DIGEST
    assert pr_impl._CAPTURE_POLICY_DIGEST == HEAD_CAPTURE_POLICY_DIGEST
    assert pr_impl._PROCESS_DEFINITION_DIGEST == HEAD_PROCESS_DEFINITION_DIGEST


def test_verifier_and_tests_read_the_same_shipped_registry_documents() -> None:
    """The literal is gone from both sides: one artifact, two readers."""
    assert pr_impl._CAPTURE_POLICY_DOCUMENT == CAPTURE_POLICY_DOCUMENT
    assert pr_impl._PROCESS_DEFINITION_DOCUMENT == PROCESS_DEFINITION_DOCUMENT
    assert CAPTURE_POLICY_DOCUMENT["observable_surfaces"] == list(STREAM_IDS)
    assert PROCESS_DEFINITION_DOCUMENT["expected_steps"] == EXPECTED_STEPS


def test_shipped_registry_documents_validate_against_their_v1_definitions() -> None:
    """Each shipped document, with its real digest, satisfies the schema.

    Per ``CapturePolicyDocumentV1`` / ``ProcessDefinitionDocumentV1``, the
    self-digest is a REQUIRED member of the document but is excluded from its
    own preimage -- so the shipped artifact is the preimage and the digest is
    added beside it here. This is what fails if someone adds a field to either
    schema definition and forgets the package-data document (finding F4).
    """
    assert "policy_digest" not in CAPTURE_POLICY_DOCUMENT
    assert "definition_digest" not in PROCESS_DEFINITION_DOCUMENT

    policy = {**CAPTURE_POLICY_DOCUMENT, "policy_digest": CAPTURE_POLICY_DIGEST}
    process = {**PROCESS_DEFINITION_DOCUMENT, "definition_digest": PROCESS_DEFINITION_DIGEST}
    assert _schema_errors(policy, "CapturePolicyDocumentV1") == []
    assert _schema_errors(process, "ProcessDefinitionDocumentV1") == []

    # The identity blocks the verifier compares against carry the same digests.
    assert CAPTURE_POLICY_IDENTITY["policy_digest"] == CAPTURE_POLICY_DIGEST
    assert PROCESS_DEFINITION_IDENTITY["definition_digest"] == PROCESS_DEFINITION_DIGEST


def test_registry_digests_are_derived_from_the_shipped_package_data() -> None:
    """The module's two digest constants are digests OF the shipped files.

    ``test_registry_document_digests_are_unchanged_by_the_package_data_move``
    pins the hex, and would keep passing if the verifier were reverted to
    Python literals that happened to match. This one is a different property:
    it reads the package-data resource bytes here, parses them, recomputes the
    digest with this file's own oracle (``_digest``, never the module's
    ``_role_digest``), and requires the module constants to equal THAT. If the
    verifier ever digested anything other than the bytes actually shipped in
    ``traigent_schema/data/certification``, this fails (finding T2).
    """
    certification_data = (
        resources.files("traigent_schema").joinpath("data").joinpath("certification")
    )
    policy_bytes = certification_data.joinpath("capture_policy_document.json").read_bytes()
    process_bytes = certification_data.joinpath("process_definition_document.json").read_bytes()

    policy = json.loads(policy_bytes.decode("utf-8"))
    process = json.loads(process_bytes.decode("utf-8"))

    # Same domain-tag / preimage construction as the verifier, re-implemented
    # here rather than imported, so the two sides can actually disagree.
    assert _digest(CAPTURE_POLICY_DOMAIN, policy) == pr_impl._CAPTURE_POLICY_DIGEST
    assert _digest(PROCESS_DEFINITION_DOMAIN, process) == pr_impl._PROCESS_DEFINITION_DIGEST

    # ...and the module read the same objects, not merely digest-equal ones.
    assert policy == pr_impl._CAPTURE_POLICY_DOCUMENT
    assert process == pr_impl._PROCESS_DEFINITION_DOCUMENT


def test_import_time_validation_accepts_both_shipped_registry_documents() -> None:
    """The positive control for the import-time check the verifier now runs."""
    pr_impl._validate_registry_document(
        pr_impl._CAPTURE_POLICY_DOCUMENT,
        "CapturePolicyDocumentV1",
        "policy_digest",
        pr_impl._CAPTURE_POLICY_DOMAIN,
    )
    pr_impl._validate_registry_document(
        pr_impl._PROCESS_DEFINITION_DOCUMENT,
        "ProcessDefinitionDocumentV1",
        "definition_digest",
        pr_impl._PROCESS_DEFINITION_DOMAIN,
    )


@pytest.mark.parametrize(
    "filename,definition,digest_field,domain",
    [
        (
            "capture_policy_document.json",
            "CapturePolicyDocumentV1",
            "policy_digest",
            CAPTURE_POLICY_DOMAIN,
        ),
        (
            "process_definition_document.json",
            "ProcessDefinitionDocumentV1",
            "definition_digest",
            PROCESS_DEFINITION_DOMAIN,
        ),
    ],
)
def test_registry_document_carrying_free_text_is_rejected_by_the_import_check(
    filename: str, definition: str, digest_field: str, domain: bytes
) -> None:
    """A registry document that grew a free-text member never gets digested.

    Before finding T1 the two documents were loaded and hashed without ever
    being validated, so a shipped document carrying customer content -- or any
    member outside the closed schema -- would have been silently digested and
    bound into every issued certificate. ``additionalProperties: false`` in
    ``CapturePolicyDocumentV1`` / ``ProcessDefinitionDocumentV1`` is what
    rejects it, and the import-time call is what makes the schema binding.
    """
    document = copy.deepcopy(_registry_document(filename))
    document["note"] = SENTINEL
    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        pr_impl._validate_registry_document(document, definition, digest_field, domain)
    # Content-free failure: the message names the definition and nothing else.
    assert str(exc_info.value) == f"PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:{definition}"
    assert SENTINEL not in str(exc_info.value)
    assert exc_info.value.definition_name == definition


@pytest.mark.parametrize(
    "filename,definition,digest_field,domain",
    [
        (
            "capture_policy_document.json",
            "CapturePolicyDocumentV1",
            "policy_digest",
            CAPTURE_POLICY_DOMAIN,
        ),
        (
            "process_definition_document.json",
            "ProcessDefinitionDocumentV1",
            "definition_digest",
            PROCESS_DEFINITION_DOMAIN,
        ),
    ],
)
def test_registry_document_with_drifted_expected_steps_is_rejected_by_the_import_check(
    filename: str, definition: str, digest_field: str, domain: bytes
) -> None:
    """Drift inside a closed member fails too, not just extra members."""
    document = copy.deepcopy(_registry_document(filename))
    document["expected_steps"] = ["prepare", "evaluate"]
    with pytest.raises(pr_impl.ProcessRecordRegistryError):
        pr_impl._validate_registry_document(document, definition, digest_field, domain)

    # A missing required member is rejected on the same path.
    truncated = copy.deepcopy(_registry_document(filename))
    del truncated["canonicalization"]
    with pytest.raises(pr_impl.ProcessRecordRegistryError):
        pr_impl._validate_registry_document(truncated, definition, digest_field, domain)


def test_registry_document_validation_resolves_cross_file_refs() -> None:
    """The helper reuses the module's ``$ref`` registry, not a second copy.

    Both definitions ``$ref`` ``certification_common_v0_schema.json`` for the
    self-digest, so an unresolvable-``$ref`` regression would surface as a
    rejection of the genuine documents rather than a silent pass. Asserting a
    malformed digest is caught proves that ``$ref`` really is being applied.
    """
    document = copy.deepcopy(pr_impl._CAPTURE_POLICY_DOCUMENT)
    candidate = {**document, "policy_digest": "not-a-sha256-digest"}
    assert _schema_errors(candidate, "CapturePolicyDocumentV1") != []
    validator = pr_impl._definition_validator("CapturePolicyDocumentV1")
    assert list(validator.iter_errors(candidate))
    assert list(validator.iter_errors({**document, "policy_digest": CAPTURE_POLICY_DIGEST})) == []


# --------------------------------------------------------------------------
# Import-time registry enforcement: privacy of the failure, and the boundary
# --------------------------------------------------------------------------


def _rendered_traceback(error: BaseException) -> str:
    """Everything standard traceback logging would print, cause chain included."""
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


def test_registry_validation_failure_leaks_no_content_into_the_traceback() -> None:
    """The rejection is content-free in the traceback, not merely in ``str()``.

    ``test_registry_document_carrying_free_text_is_rejected_by_the_import_check``
    checks the message. That is not the surface that leaks: a chained
    ``jsonschema`` cause carries the offending instance, path, and schema
    fragment, and ``traceback.format_exception`` prints the whole chain --
    which is what an import failure writes to stderr and what a caller's
    logger records. This asserts over the rendered traceback (finding U1).
    """
    document = copy.deepcopy(_registry_document("capture_policy_document.json"))
    document["operator_note"] = SENTINEL
    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        pr_impl._validate_registry_document(
            document, "CapturePolicyDocumentV1", "policy_digest", CAPTURE_POLICY_DOMAIN
        )

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True

    rendered = _rendered_traceback(error)
    assert SENTINEL not in rendered
    assert "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1" in rendered


def test_registry_validation_dependency_failure_is_not_chained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``$ref``-resolution failure path suppresses its cause too.

    This is the branch that used to raise ``from exc``. An ``Unresolvable``
    names the ref it could not resolve, so its message is schema material the
    fixed error code is meant to withhold; ``from None`` is what keeps it out
    of the rendered traceback (finding U1).
    """

    def _unresolvable(definition_name: str) -> Any:
        raise Unresolvable(SENTINEL)

    monkeypatch.setattr(pr_impl, "_definition_validator", _unresolvable)
    document = copy.deepcopy(_registry_document("capture_policy_document.json"))
    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        pr_impl._validate_registry_document(
            document, "CapturePolicyDocumentV1", "policy_digest", CAPTURE_POLICY_DOMAIN
        )

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__suppress_context__ is True
    assert SENTINEL not in _rendered_traceback(error)
    assert str(error) == "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1"


@pytest.mark.parametrize(
    "filename,definition,digest_field,domain",
    [
        (
            "capture_policy_document.json",
            "CapturePolicyDocumentV1",
            "policy_digest",
            CAPTURE_POLICY_DOMAIN,
        ),
        (
            "process_definition_document.json",
            "ProcessDefinitionDocumentV1",
            "definition_digest",
            PROCESS_DEFINITION_DOMAIN,
        ),
    ],
)
def test_registry_document_carrying_its_own_self_digest_is_rejected(
    filename: str, definition: str, digest_field: str, domain: bytes
) -> None:
    """A shipped document must be the bare preimage, never carry its own digest.

    The loader hashes the document as loaded and then overwrites the
    self-digest member before validating. So a pre-existing self-digest field
    with arbitrary content would be inside the hash preimage -- binding into
    every issued certificate -- while the validator only ever sees the
    overwritten copy. The assertions below show exactly that: the injected
    content moves the digest, yet the candidate the loader would have built
    validates clean. Only the presence guard rejects it (finding U2).
    """
    pristine = _registry_document(filename)
    assert digest_field not in pristine

    document = copy.deepcopy(pristine)
    # Format-valid on purpose: a malformed value would be caught by the schema,
    # which would make this test prove nothing about the guard.
    document[digest_field] = "sha256:" + "a" * 64

    assert _digest(domain, document) != _digest(domain, pristine)
    overwritten = {**document, digest_field: _digest(domain, document)}
    assert _schema_errors(overwritten, definition) == []

    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        pr_impl._validate_registry_document(document, definition, digest_field, domain)
    assert str(exc_info.value) == f"PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:{definition}"
    assert exc_info.value.definition_name == definition
    assert exc_info.value.__cause__ is None


def test_expected_steps_check_accepts_both_shipped_registry_documents() -> None:
    """Positive control for the module-constant binding."""
    pr_impl._validate_registry_expected_steps(
        pr_impl._CAPTURE_POLICY_DOCUMENT, "CapturePolicyDocumentV1"
    )
    pr_impl._validate_registry_expected_steps(
        pr_impl._PROCESS_DEFINITION_DOCUMENT, "ProcessDefinitionDocumentV1"
    )
    assert pr_impl._EXPECTED_STEPS == tuple(EXPECTED_STEPS)


@pytest.mark.parametrize(
    "filename,definition,digest_field,domain",
    [
        (
            "capture_policy_document.json",
            "CapturePolicyDocumentV1",
            "policy_digest",
            CAPTURE_POLICY_DOMAIN,
        ),
        (
            "process_definition_document.json",
            "ProcessDefinitionDocumentV1",
            "definition_digest",
            PROCESS_DEFINITION_DOMAIN,
        ),
    ],
)
def test_expected_steps_permutation_is_rejected_by_the_import_check(
    filename: str, definition: str, digest_field: str, domain: bytes
) -> None:
    """Full-length reordering, not just truncation, is drift.

    ``test_registry_document_with_drifted_expected_steps_is_rejected_by_the_import_check``
    only shortens the list, which a length check would also catch. A rotation
    keeps all five ids and the length, so it isolates order (finding U4).
    """
    permuted = EXPECTED_STEPS[1:] + EXPECTED_STEPS[:1]
    assert sorted(permuted) == sorted(EXPECTED_STEPS)
    assert permuted != EXPECTED_STEPS
    assert len(permuted) == len(EXPECTED_STEPS)

    document = copy.deepcopy(_registry_document(filename))
    document["expected_steps"] = permuted

    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        pr_impl._validate_registry_expected_steps(document, definition)
    assert str(exc_info.value) == f"PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:{definition}"
    assert exc_info.value.__cause__ is None

    # Defence in depth: ``ExpectedProcessStepsV1`` is an order-sensitive
    # ``const`` array, so the schema path rejects the same document.
    with pytest.raises(pr_impl.ProcessRecordRegistryError):
        pr_impl._validate_registry_document(document, definition, digest_field, domain)


def test_expected_steps_check_binds_the_module_constant_not_only_the_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gap the schema cannot close.

    ``ExpectedProcessStepsV1`` pins what the two documents may say. Nothing
    pinned ``_EXPECTED_STEPS`` -- the tuple the process report is actually
    derived from -- to them, so editing it would have drifted silently. Drift
    the constant and the genuine shipped document must now be rejected.
    """
    monkeypatch.setattr(
        pr_impl, "_EXPECTED_STEPS", tuple(EXPECTED_STEPS[1:] + EXPECTED_STEPS[:1])
    )
    for document, definition in (
        (pr_impl._CAPTURE_POLICY_DOCUMENT, "CapturePolicyDocumentV1"),
        (pr_impl._PROCESS_DEFINITION_DOCUMENT, "ProcessDefinitionDocumentV1"),
    ):
        with pytest.raises(pr_impl.ProcessRecordRegistryError):
            pr_impl._validate_registry_expected_steps(document, definition)


def _shipped_capture_policy_bytes() -> bytes:
    """The exact bytes the verifier reads for the capture-policy document."""
    return (
        resources.files("traigent_schema")
        .joinpath("data")
        .joinpath("certification")
        .joinpath("capture_policy_document.json")
        .read_bytes()
    )


def _synthetic_registry_root(tmp_path: Path, filename: str, payload: bytes | None) -> Path:
    """A ``data/certification`` tree the registry loader can be pointed at.

    ``payload is None`` writes nothing, i.e. the resource is absent. A
    ``pathlib.Path`` satisfies the ``Traversable`` protocol the loader takes,
    so this exercises the real read/decode path without copying the package.
    """
    directory = tmp_path / "data" / "certification"
    directory.mkdir(parents=True, exist_ok=True)
    if payload is not None:
        (directory / filename).write_bytes(payload)
    return tmp_path


def _load_capture_policy_constant(root: Path) -> tuple[dict[str, Any], str]:
    return pr_impl._load_registry_constant(
        "capture_policy_document.json",
        "CapturePolicyDocumentV1",
        "policy_digest",
        CAPTURE_POLICY_DOMAIN,
        root,
    )


def test_registry_loader_reads_a_synthetic_root_exactly_like_the_shipped_package(
    tmp_path: Path,
) -> None:
    """Control for the three boundary tests below.

    Each of those points the loader at a synthetic ``data/certification`` tree
    and asserts a ``ProcessRecordRegistryError``. Without this control a typo
    in the tree's layout would satisfy all three for the wrong reason -- an
    absent directory rather than the defect under test. Here the same tree
    carries the pristine shipped bytes and must yield the shipped document and
    the frozen digest, so a failure below is attributable to the payload.
    """
    root = _synthetic_registry_root(
        tmp_path, "capture_policy_document.json", _shipped_capture_policy_bytes()
    )
    document, digest = _load_capture_policy_constant(root)
    assert document == CAPTURE_POLICY_DOCUMENT
    assert digest == HEAD_CAPTURE_POLICY_DIGEST


def test_missing_registry_resource_is_a_content_free_registry_error(tmp_path: Path) -> None:
    """An absent package-data file must not put its path in the traceback (V2).

    ``Traversable.read_text`` raises ``FileNotFoundError``, whose message is
    the absolute path it looked for -- a build root, a home directory, or a
    customer's deployment layout. Outside the boundary that path is what the
    failed import prints to stderr and what any caller logging the exception
    records.
    """
    root = _synthetic_registry_root(tmp_path, "capture_policy_document.json", None)
    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        _load_capture_policy_constant(root)

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True

    rendered = _rendered_traceback(error)
    assert tmp_path.name not in rendered
    assert "data/certification" not in rendered
    assert "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1" in rendered


def test_registry_error_raised_inside_a_callers_handler_carries_no_context(
    tmp_path: Path,
) -> None:
    """Importing from inside a caller's ``except`` block must not link that caller's exception.

    ``raise ... from None`` clears ``__cause__`` and suppresses the display of
    ``__context__``, but at raise time the interpreter still LINKS whatever
    exception the caller is currently handling as ``__context__``. The
    registry error must reference nothing outside this module, so the
    boundary clears that link and re-raises the same object.
    """
    root = _synthetic_registry_root(tmp_path, "capture_policy_document.json", None)
    caught: pr_impl.ProcessRecordRegistryError | None = None
    try:
        raise ValueError(SENTINEL)
    except ValueError:
        try:
            _load_capture_policy_constant(root)
        except pr_impl.ProcessRecordRegistryError as err:
            caught = err

    assert caught is not None
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert SENTINEL not in _rendered_traceback(caught)
    assert SENTINEL not in repr(caught)


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(b"\xff\xfe not json " + SENTINEL.encode(), id="undecodable-bytes"),
        pytest.param(('{"operator_note": "' + SENTINEL).encode(), id="unterminated-json"),
    ],
)
def test_corrupt_registry_resource_leaks_no_content_into_the_traceback(
    tmp_path: Path, payload: bytes
) -> None:
    """Decode failures cross the same boundary as schema failures (V2).

    ``UnicodeDecodeError`` names the file it was decoding and
    ``json.JSONDecodeError`` carries the offending document; both are raised
    from the read step, which used to sit outside every ``from None`` in this
    module. The sentinel is planted in the bytes and must not survive into the
    rendered traceback.
    """
    root = _synthetic_registry_root(tmp_path, "capture_policy_document.json", payload)
    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        _load_capture_policy_constant(root)

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True

    rendered = _rendered_traceback(error)
    assert SENTINEL not in rendered
    assert tmp_path.name not in rendered
    assert "data/certification" not in rendered
    assert "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1" in rendered


def test_registry_canonicalization_failure_is_a_registry_error_not_canonicalization(
    tmp_path: Path,
) -> None:
    """The digest step fails as a REGISTRY error, not a verification one (V1).

    ``_role_digest`` -- the step these module constants are taken over --
    converts an ``fp2`` failure into ``_fail("CANONICALIZATION")``: a
    ``ProcessRecordVerificationError`` raised inside an ``except`` block, so
    with implicit chaining. Before the boundary that meant a canonicalizer
    exception (which sees the whole document) reached the import-time
    traceback via ``__context__``, under an error code belonging to bundle
    verification rather than to the registry at all.

    ``NaN`` is the cheap way to reach exactly that step: ``json.loads``
    accepts the literal and ``fp2.canonicalize`` rejects non-finite numbers,
    so the document decodes and then fails to canonicalize.
    """
    document = copy.deepcopy(CAPTURE_POLICY_DOCUMENT)
    document["operator_note"] = float("nan")
    payload = json.dumps(document).encode("utf-8")
    assert b"NaN" in payload, "the fixture must actually ship a non-finite literal"
    root = _synthetic_registry_root(tmp_path, "capture_policy_document.json", payload)

    with pytest.raises(pr_impl.ProcessRecordRegistryError) as exc_info:
        _load_capture_policy_constant(root)

    error = exc_info.value
    assert not isinstance(error, ProcessRecordVerificationError)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert error.__suppress_context__ is True

    rendered = _rendered_traceback(error)
    assert "CANONICALIZATION" not in rendered
    assert tmp_path.name not in rendered
    assert "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1" in rendered


def test_importing_the_verifier_fails_when_shipped_registry_data_is_malformed() -> None:
    """The enforcement is at the import boundary, not only in the helper.

    Every other control here calls ``_validate_registry_document`` directly, so
    all of them would keep passing if the module-level calls were deleted. This
    one copies the package, corrupts one shipped document in the COPY, and
    imports it in a fresh interpreter (finding U3). It doubles as the U1 proof
    at the real boundary: the sentinel must not reach the stderr traceback that
    a failed import prints.

    The control runs FIRST, against the same temp copy before it is corrupted
    (finding V3). Asserting only that a corrupted copy fails to import proves
    nothing on its own: any unrelated breakage inside the copy -- a missing
    sibling file, a wrong ``PYTHONPATH``, a dependency the copy cannot reach --
    would produce a non-zero exit and a traceback without the sentinel just as
    well. Sharing one temp copy between control and treatment is what makes the
    difference attributable to the corruption.
    """
    source_package = Path(str(resources.files("traigent_schema")))
    with tempfile.TemporaryDirectory() as root:
        destination = Path(root) / "traigent_schema"
        shutil.copytree(source_package, destination, ignore=shutil.ignore_patterns("__pycache__"))

        # PYTHONPATH first and cwd both point at the copy, so it wins over any
        # installed ``traigent_schema``.
        env = {**os.environ, "PYTHONPATH": root, "PYTHONDONTWRITEBYTECODE": "1"}

        # CONTROL: the pristine copy, same interpreter, env and cwd as the
        # treatment below. It must import cleanly, and the module it imported
        # must be the one inside the temp copy rather than an installed
        # ``traigent_schema`` that would make the treatment meaningless.
        control = subprocess.run(
            [
                sys.executable,
                "-c",
                "import traigent_schema.certification.process_record_verifier as m\n"
                "print(m.__file__)\n",
            ],
            env=env,
            cwd=root,
            capture_output=True,
            text=True,
        )
        assert control.returncode == 0, control.stderr
        assert Path(control.stdout.strip()).is_relative_to(destination), control.stdout

        corrupted = destination / "data" / "certification" / "capture_policy_document.json"
        document = json.loads(corrupted.read_text(encoding="utf-8"))
        assert document == CAPTURE_POLICY_DOCUMENT, "the copy is the shipped artifact"
        document["operator_note"] = SENTINEL
        corrupted.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

        imported = subprocess.run(
            [sys.executable, "-c", "import traigent_schema.certification.process_record_verifier"],
            env=env,
            cwd=root,
            capture_output=True,
            text=True,
        )
        assert imported.returncode != 0
        assert "ProcessRecordRegistryError" in imported.stderr
        assert (
            "PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:CapturePolicyDocumentV1" in imported.stderr
        )
        assert SENTINEL not in imported.stderr
        assert str(destination) in imported.stderr, "the corrupted copy is what was imported"

        # ...and the half-initialised module is not left behind for a later
        # import to pick up as if it had succeeded.
        probe = (
            "import sys\n"
            "try:\n"
            "    import traigent_schema.certification.process_record_verifier\n"
            "except Exception as exc:\n"
            "    assert type(exc).__name__ == 'ProcessRecordRegistryError', type(exc).__name__\n"
            "    assert exc.__cause__ is None and exc.__suppress_context__, 'cause retained'\n"
            "    name = 'traigent_schema.certification.process_record_verifier'\n"
            "    assert name not in sys.modules, 'partial module left in sys.modules'\n"
            "    print('CLEAN')\n"
            "    sys.exit(0)\n"
            "sys.exit(9)\n"
        )
        probed = subprocess.run(
            [sys.executable, "-c", probe], env=env, cwd=root, capture_output=True, text=True
        )
        assert probed.returncode == 0, probed.stderr
        assert probed.stdout.strip() == "CLEAN"
        assert SENTINEL not in probed.stderr


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
