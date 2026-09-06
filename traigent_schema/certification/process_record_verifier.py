# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline relying-party verifier for Process Record v1.

This module answers exactly one question for a supplied certificate bundle and
explicit relying-party context: for the identified build and the declared
agent, dataset, and evaluator commitments, does every reported step and result
reference a recorded receipt, do the supplied records match the signed
snapshot, and do the reported values agree with those records.

Only public certificate material is consumed. The caller supplies the
independently trusted v0 verification inputs (materials digest, certificate
reference, and v0 ``VerificationContext``) plus the expected project and
build-session scope. No Backend imports, callbacks, network access, database
access, or private-key signing are involved. Tenant authorization is a
Backend/caller responsibility -- this verifier enforces only exact
project/build scope consistency, never tenant identity.

The v0 base certificate is verified with ``require_status=False``: this
milestone deliberately makes no dynamic trust-status or revocation claim, and
that honest classification (``VERIFICATION_RESULT.status_evidence ==
"not_checked"``) is surfaced unchanged in ``ProcessRecordVerificationResult``.

Verification failures expose only stable, content-free error codes. Receipt
and report content may carry customer-controlled values, and exception text
is commonly logged by callers.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NoReturn, cast

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

import traigent_schema.fp2 as fp2
from traigent_schema.certification.relying_party_verifier import (
    _ISSUER_SPKI_DOMAIN,
    RelyingPartyVerificationError,
    VerificationContext,
    _material_public_key,
    _verify_signature,
    verify_certificate_with_materials,
)
from traigent_schema.validator import _FORMAT_CHECKER

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
_CERT_DIR = _SCHEMAS_DIR / "certification"
_PROCESS_RECORD_SCHEMA_PATH = _CERT_DIR / "process_record_v1_schema.json"

_SHA256_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9_-]{8,128}$")

_RECEIPT_DOMAIN = b"traigent.process_record.receipt.v1"
_RECEIPT_BUNDLE_DOMAIN = b"traigent.process_record.receipt_bundle.v1"
_REPORT_DOMAIN = b"traigent.process_record.report.v1"
_ASSERTION_DOMAIN = b"traigent.process_record.assertion.v1"
_CLAIM_MATERIAL_DOMAIN = b"traigent.process_record.claim_material.v1"
_CLAIM_SUPPORT_ROWS_DOMAIN = b"traigent.process_record.claim_support_rows.v1"
_UNSIGNED_MANIFEST_DOMAIN = b"traigent.process_record.unsigned_manifest.v1"
_CAPTURE_POLICY_DOMAIN = b"traigent.process_record.capture_policy.v1"
_PROCESS_DEFINITION_DOMAIN = b"traigent.process_record.process_definition.v1"
_EXPECTED_STEPS_DOMAIN = b"traigent.process_record.expected_steps.v1"
_ISSUER_SIGNATURE_DOMAIN = b"traigent.process_record.issuer_signature.v1"

_EXPECTED_STEPS = ("prepare", "evaluate", "aggregate", "select", "finalize")
_STREAM_IDS = ("decision_stream", "receipt_event_stream", "transition_stream")
_MAX_STREAM_ITEMS = 2048
_MAX_TOTAL_RECEIPTS = 6144
_MAX_RECEIPT_BYTES = 8192
_REGISTERED_VALUE_INT_FIELDS = (
    "accuracy_ppm",
    "evaluated_count",
    "cost_microusd",
    "latency_us",
)

_UNSIGNED_MANIFEST_COVERAGE = (
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


class ProcessRecordVerificationError(ValueError):
    """A fixed-code verification failure that never includes certificate data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    raise ProcessRecordVerificationError(code)


# Public, closed, content-free failure vocabulary. ``ProcessRecordVerificationError``
# never raises a code outside this set.
PROCESS_RECORD_ERROR_CODES = frozenset(
    {
        "CONTEXT",
        "BUNDLE_SHAPE",
        "SCHEMA",
        "SCHEMA_DEPENDENCY",
        "STRICT_INTEGER",
        "BASE_CERTIFICATE_INVALID",
        "SCOPE_MISMATCH",
        "BASE_MANIFEST_DIGEST_MISMATCH",
        "CAPTURE_POLICY_MISMATCH",
        "RECEIPT_STREAM_MISMATCH",
        "RECEIPT_ORDER",
        "RECEIPT_DUPLICATE",
        "RECEIPT_LIMIT_EXCEEDED",
        "RECEIPT_SIZE_EXCEEDED",
        "RECEIPT_DIGEST_MISMATCH",
        "RECEIPT_BUNDLE_DIGEST_MISMATCH",
        "STREAM_INDEX_MISMATCH",
        "REPORT_MISMATCH",
        "ASSERTION_DIGEST_MISMATCH",
        "CLAIM_SUPPORT_ROW_MISMATCH",
        "CLAIM_NOT_VERIFIED",
        "UNSIGNED_MANIFEST_MISMATCH",
        "UNSIGNED_MANIFEST_DIGEST_MISMATCH",
        "KEY_RING_MISMATCH",
        "ISSUER_SIGNATURE_INVALID",
        "CANONICALIZATION",
        "VERIFICATION_FAILED",
    }
)


@dataclass(frozen=True, slots=True)
class ProcessRecordVerificationContext:
    """Fresh, caller-supplied bindings for one Process Record verification.

    ``base_context`` and the two v0 discovery-materials pins
    (``expected_materials_digest``, ``certificate_ref``) are the exact inputs
    ``verify_certificate_with_materials`` requires to verify the embedded v0
    base certificate offline. ``expected_project_ref`` and
    ``expected_build_session_ref`` are the explicit V1-level scope pins: they
    are compared against the v0 subject, the V1 unsigned manifest, the
    derived report, and every receipt, closing the scope loop independently
    of whatever ``base_context`` itself carries.

    Tenant authorization is a Backend/caller responsibility. This context
    intentionally carries no tenant identity; the verifier enforces only
    exact project/build scope consistency.
    """

    expected_materials_digest: str
    certificate_ref: str
    base_context: VerificationContext
    expected_project_ref: str
    expected_build_session_ref: str

    def __post_init__(self) -> None:
        if not isinstance(self.base_context, VerificationContext):
            _fail("CONTEXT")
        if type(self.expected_materials_digest) is not str or not _SHA256_RE.fullmatch(
            self.expected_materials_digest
        ):
            _fail("CONTEXT")
        if type(self.certificate_ref) is not str or not self.certificate_ref:
            _fail("CONTEXT")
        if type(self.expected_project_ref) is not str or not _PROJECT_REF_RE.fullmatch(
            self.expected_project_ref
        ):
            _fail("CONTEXT")
        if type(self.expected_build_session_ref) is not str or not _REF_RE.fullmatch(
            self.expected_build_session_ref
        ):
            _fail("CONTEXT")


@dataclass(frozen=True, slots=True)
class ProcessRecordVerificationResult:
    """Bounded, content-free success result.

    Only digest strings, opaque refs, and counters are carried. No example,
    source, evaluator code, prompt, response, arbitrary metadata, or raw
    registered value ever crosses into this object.

    ``base_certificate_status_evidence`` mirrors the embedded v0 result's
    ``status_evidence`` unchanged (``"not_checked"`` under
    ``require_status=False``), so a signature-only base certificate can never
    be reported as if its dynamic trust status had been checked.
    """

    valid: bool = True
    code: str = "PROCESS_RECORD_VERIFIED"
    base_certificate_status_evidence: str = "not_checked"
    project_ref: str = ""
    build_session_ref: str = ""
    agent_commitment_ref: str = ""
    dataset_commitment_ref: str = ""
    evaluator_commitment_ref: str = ""
    build_definition_commitment_ref: str = ""
    base_unsigned_manifest_digest: str = ""
    unsigned_manifest_digest: str = ""
    assertion_digest: str = ""
    process_report_digest: str = ""
    receipt_bundle_digest: str = ""
    process_claim_support_rows_digest: str = ""
    present_count: int = 0
    missing_count: int = 0
    backend_observed_present_count: int = 0
    client_attested_present_count: int = 0
    receipt_count: int = 0

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ValueError("PROCESS_RECORD_VERIFICATION_RESULT")
        if self.code != "PROCESS_RECORD_VERIFIED":
            raise ValueError("PROCESS_RECORD_VERIFICATION_RESULT")


@lru_cache(maxsize=1)
def _process_record_validator() -> Draft7Validator:
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    schema = json.loads(_PROCESS_RECORD_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


def _role_digest(domain: bytes, projection: Any) -> str:
    try:
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    return _SHA256_PREFIX + hashlib.sha256(domain + b"\x00" + canonical).hexdigest()


_CAPTURE_POLICY_DOCUMENT: dict[str, Any] = {
    "schema_version": "traigent.capture_policy_document.v1",
    "policy_id": "traigent.capture_policy.asap.v1",
    "policy_version": "1.0.0",
    "observable_surfaces": list(_STREAM_IDS),
    "expected_steps": list(_EXPECTED_STEPS),
    "canonicalization": "jcs_v1",
}
_PROCESS_DEFINITION_DOCUMENT: dict[str, Any] = {
    "schema_version": "traigent.process_definition_document.v1",
    "definition_id": "traigent.process_definition.asap.v1",
    "definition_version": "1.0.0",
    "expected_steps": list(_EXPECTED_STEPS),
    "stream_ids": list(_STREAM_IDS),
    "canonicalization": "jcs_v1",
}
_CAPTURE_POLICY_DIGEST = _role_digest(_CAPTURE_POLICY_DOMAIN, _CAPTURE_POLICY_DOCUMENT)
_PROCESS_DEFINITION_DIGEST = _role_digest(_PROCESS_DEFINITION_DOMAIN, _PROCESS_DEFINITION_DOCUMENT)
_EXPECTED_STEPS_DIGEST = _role_digest(_EXPECTED_STEPS_DOMAIN, list(_EXPECTED_STEPS))
_CAPTURE_POLICY_IDENTITY: dict[str, Any] = {
    "policy_id": "traigent.capture_policy.asap.v1",
    "policy_version": "1.0.0",
    "policy_digest": _CAPTURE_POLICY_DIGEST,
}
_PROCESS_DEFINITION_IDENTITY: dict[str, Any] = {
    "definition_id": "traigent.process_definition.asap.v1",
    "definition_version": "1.0.0",
    "definition_digest": _PROCESS_DEFINITION_DIGEST,
}


def _require_int(value: object) -> None:
    if type(value) is not int:
        _fail("STRICT_INTEGER")


def _require_nullable_int(value: object) -> None:
    if value is not None:
        _require_int(value)


def _check_registered_values_strict(values: dict[str, Any]) -> None:
    for field in _REGISTERED_VALUE_INT_FIELDS:
        if field in values:
            _require_int(values[field])


def _check_strict_integers(bundle: dict[str, Any]) -> None:
    """Reject decoded bool/float aliases for every V1 integer field.

    This MUST run before any canonicalization or digest work: fp2 rejects
    floats outright, so the aliasing risk is entirely in Python's own
    ``bool``-is-``int`` and ``1.0 == 1`` equality before that point.
    """
    unsigned = bundle["unsigned_manifest"]
    receipts = bundle["receipts"]
    for stream_name in _STREAM_IDS:
        stream_index = unsigned[stream_name]
        for value in stream_index["sequence_values"]:
            _require_int(value)
        _require_nullable_int(stream_index["first_seq"])
        _require_nullable_int(stream_index["last_seq"])
        _require_int(stream_index["receipt_count"])
        for receipt in receipts[stream_name]:
            _require_int(receipt["seq"])
            _check_registered_values_strict(receipt["registered_values"])
    report = bundle["report"]
    _require_int(report["expected_step_count"])
    for field in (
        "present_count",
        "missing_count",
        "backend_observed_present_count",
        "client_attested_present_count",
    ):
        _require_int(report[field])
    for row in report["rows"]:
        if row["status"] == "present":
            _check_registered_values_strict(row["registered_values"])


def _validate_schema(bundle: dict[str, Any]) -> None:
    try:
        validator = _process_record_validator()
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail("SCHEMA_DEPENDENCY")
    try:
        errors = list(validator.iter_errors(bundle))
    except Unresolvable:
        _fail("SCHEMA_DEPENDENCY")
    if errors:
        _fail("SCHEMA")


def _verify_base_certificate(
    bundle: dict[str, Any], context: ProcessRecordVerificationContext
) -> Any:
    try:
        return verify_certificate_with_materials(
            bundle["base_certificate_v0"],
            bundle["verification_materials_v0"],
            expected_materials_digest=context.expected_materials_digest,
            certificate_ref=context.certificate_ref,
            context=context.base_context,
            require_status=False,
        )
    except RelyingPartyVerificationError:
        _fail("BASE_CERTIFICATE_INVALID")


def _check_receipts(
    bundle: dict[str, Any], expected_project_ref: str, expected_build_session_ref: str
) -> None:
    receipts = bundle["receipts"]
    total = 0
    seen_refs: set[str] = set()
    seen_digests: set[str] = set()
    for stream_name in _STREAM_IDS:
        stream = receipts[stream_name]
        if len(stream) > _MAX_STREAM_ITEMS:
            _fail("RECEIPT_LIMIT_EXCEEDED")
        total += len(stream)
        prev_seq: int | None = None
        for receipt in stream:
            if receipt["stream_id"] != stream_name:
                _fail("RECEIPT_STREAM_MISMATCH")
            if (
                receipt["project_ref"] != expected_project_ref
                or receipt["build_session_ref"] != expected_build_session_ref
            ):
                _fail("SCOPE_MISMATCH")
            seq = receipt["seq"]
            if prev_seq is not None and seq <= prev_seq:
                _fail("RECEIPT_ORDER")
            prev_seq = seq
            ref = receipt["receipt_ref"]
            digest = receipt["receipt_digest"]
            if ref in seen_refs or digest in seen_digests:
                _fail("RECEIPT_DUPLICATE")
            seen_refs.add(ref)
            seen_digests.add(digest)
            projection = {k: v for k, v in receipt.items() if k != "receipt_digest"}
            if _role_digest(_RECEIPT_DOMAIN, projection) != digest:
                _fail("RECEIPT_DIGEST_MISMATCH")
            try:
                size = len(cast(str, fp2.canonicalize(receipt)).encode("utf-8"))
            except Exception:
                _fail("CANONICALIZATION")
            if size > _MAX_RECEIPT_BYTES:
                _fail("RECEIPT_SIZE_EXCEEDED")
    if total > _MAX_TOTAL_RECEIPTS:
        _fail("RECEIPT_LIMIT_EXCEEDED")


def _compute_stream_indexes(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    receipts = bundle["receipts"]
    unsigned = bundle["unsigned_manifest"]
    indexes: dict[str, dict[str, Any]] = {}
    for stream_name in _STREAM_IDS:
        stream = receipts[stream_name]
        sequence_values = [receipt["seq"] for receipt in stream]
        receipt_digests = [receipt["receipt_digest"] for receipt in stream]
        expected_index = {
            "sequence_values": sequence_values,
            "receipt_digests": receipt_digests,
            "first_seq": sequence_values[0] if sequence_values else None,
            "last_seq": sequence_values[-1] if sequence_values else None,
            "receipt_count": len(sequence_values),
        }
        if expected_index != unsigned[stream_name]:
            _fail("STREAM_INDEX_MISMATCH")
        indexes[stream_name] = expected_index
    return indexes


def _derive_report(
    bundle: dict[str, Any], expected_project_ref: str, expected_build_session_ref: str
) -> tuple[str, dict[str, Any]]:
    receipts = bundle["receipts"]
    flattened = [receipt for stream_name in _STREAM_IDS for receipt in receipts[stream_name]]
    rows: list[dict[str, Any]] = []
    present_count = 0
    backend_observed_present_count = 0
    client_attested_present_count = 0
    for step in _EXPECTED_STEPS:
        selected: dict[str, Any] | None = None
        for receipt in flattened:
            if receipt["step_id"] == step:
                selected = receipt
        if selected is None:
            rows.append({"step_id": step, "status": "missing"})
            continue
        present_count += 1
        basis = selected["observation_basis"]
        if basis == "backend_observed":
            backend_observed_present_count += 1
        elif basis == "client_attested":
            client_attested_present_count += 1
        rows.append(
            {
                "step_id": step,
                "status": "present",
                "observation_kind": basis,
                "receipt_digest": selected["receipt_digest"],
                "registered_values": copy.deepcopy(selected["registered_values"]),
            }
        )
    report_without_digest = {
        "schema_version": "traigent.process_record.report.v1",
        "project_ref": expected_project_ref,
        "build_session_ref": expected_build_session_ref,
        "capture_policy": _CAPTURE_POLICY_IDENTITY,
        "process_definition": _PROCESS_DEFINITION_IDENTITY,
        "expected_step_count": 5,
        "rows": rows,
        "present_count": present_count,
        "missing_count": 5 - present_count,
        "backend_observed_present_count": backend_observed_present_count,
        "client_attested_present_count": client_attested_present_count,
    }
    report_digest = _role_digest(_REPORT_DOMAIN, report_without_digest)
    return report_digest, {**report_without_digest, "report_digest": report_digest}


def _check_assertion(bundle: dict[str, Any]) -> str:
    assertion = bundle["assertion"]
    if assertion["capture_policy"] != _CAPTURE_POLICY_IDENTITY:
        _fail("CAPTURE_POLICY_MISMATCH")
    projection = {k: v for k, v in assertion.items() if k != "assertion_digest"}
    digest = _role_digest(_ASSERTION_DOMAIN, projection)
    if digest != assertion["assertion_digest"]:
        _fail("ASSERTION_DIGEST_MISMATCH")
    return digest


def _claim_material_digest(assertion: dict[str, Any], assertion_digest: str) -> str:
    claim_material = {
        "claim_id": "PROC1",
        "tier": 3,
        "assertion_template_id": assertion["assertion_template_id"],
        "rendered_text": assertion["rendered_text"],
        "assertion_digest": assertion_digest,
    }
    return _role_digest(_CLAIM_MATERIAL_DOMAIN, claim_material)


def _check_receipt_bundle(bundle: dict[str, Any]) -> str:
    receipts = bundle["receipts"]
    projection = {k: v for k, v in receipts.items() if k != "receipt_bundle_digest"}
    digest = _role_digest(_RECEIPT_BUNDLE_DOMAIN, projection)
    if digest != receipts["receipt_bundle_digest"]:
        _fail("RECEIPT_BUNDLE_DIGEST_MISMATCH")
    return digest


def _check_support_row(
    bundle: dict[str, Any],
    assertion_digest: str,
    report_digest: str,
    receipt_bundle_digest: str,
    claim_material_digest: str,
) -> None:
    row = bundle["claim_support_rows"][0]
    if row["evidence_basis"] != "issuer_verified":
        _fail("CLAIM_NOT_VERIFIED")
    expected_row = {
        "claim_id": "PROC1",
        "evidence_basis": "issuer_verified",
        "assertion_digest": assertion_digest,
        "process_report_digest": report_digest,
        "receipt_bundle_digest": receipt_bundle_digest,
        "verifier_result": "pass",
        "claim_material_digest": claim_material_digest,
    }
    if row != expected_row:
        _fail("CLAIM_SUPPORT_ROW_MISMATCH")


def _verify(
    bundle: dict[str, Any], context: ProcessRecordVerificationContext
) -> ProcessRecordVerificationResult:
    _validate_schema(bundle)
    _check_strict_integers(bundle)

    v0_result = _verify_base_certificate(bundle, context)
    v0_cert = bundle["base_certificate_v0"]
    v0_subject = v0_cert["subject"]
    expected_project_ref = context.expected_project_ref
    expected_build_session_ref = context.expected_build_session_ref
    if (
        v0_subject["project_ref"] != expected_project_ref
        or v0_subject["build_session_ref"] != expected_build_session_ref
    ):
        _fail("SCOPE_MISMATCH")

    unsigned = bundle["unsigned_manifest"]
    v0_manifest_digest = v0_cert["signatures"]["unsigned_manifest"]["manifest_digest"]
    if unsigned["base_unsigned_manifest_digest"] != v0_manifest_digest:
        _fail("BASE_MANIFEST_DIGEST_MISMATCH")

    _check_receipts(bundle, expected_project_ref, expected_build_session_ref)
    computed_streams = _compute_stream_indexes(bundle)
    report_digest, derived_report = _derive_report(
        bundle, expected_project_ref, expected_build_session_ref
    )
    if derived_report != bundle["report"]:
        _fail("REPORT_MISMATCH")

    assertion_digest = _check_assertion(bundle)
    claim_material_digest = _claim_material_digest(bundle["assertion"], assertion_digest)
    receipt_bundle_digest = _check_receipt_bundle(bundle)
    claim_support_rows_digest = _role_digest(
        _CLAIM_SUPPORT_ROWS_DOMAIN, bundle["claim_support_rows"]
    )
    _check_support_row(
        bundle, assertion_digest, report_digest, receipt_bundle_digest, claim_material_digest
    )

    v0_materials_issuer = bundle["verification_materials_v0"]["issuer"]
    expected_unsigned = {
        "schema_version": "traigent.process_record.unsigned_manifest.v1",
        "base_unsigned_manifest_digest": v0_manifest_digest,
        "capture_policy": _CAPTURE_POLICY_IDENTITY,
        "process_definition": _PROCESS_DEFINITION_IDENTITY,
        "project_ref": expected_project_ref,
        "build_session_ref": expected_build_session_ref,
        "agent_commitment_ref": unsigned.get("agent_commitment_ref"),
        "dataset_commitment_ref": unsigned.get("dataset_commitment_ref"),
        "evaluator_commitment_ref": unsigned.get("evaluator_commitment_ref"),
        "build_definition_commitment_ref": unsigned.get("build_definition_commitment_ref"),
        "expected_steps": list(_EXPECTED_STEPS),
        "expected_steps_digest": _EXPECTED_STEPS_DIGEST,
        "decision_stream": computed_streams["decision_stream"],
        "receipt_event_stream": computed_streams["receipt_event_stream"],
        "transition_stream": computed_streams["transition_stream"],
        "assertion_digest": assertion_digest,
        "process_report_digest": report_digest,
        "receipt_bundle_digest": receipt_bundle_digest,
        "client_evidence_manifest_digest": v0_cert["audit_report"]["client_evidence_manifest_root"],
        "process_claim_support_rows_digest": claim_support_rows_digest,
        "trust_ring_ref": v0_materials_issuer["trust_ring_ref"],
        "issuer_key_ref": v0_materials_issuer["key_ref"],
        "issuer_signature_algorithm": v0_materials_issuer["algorithm"],
        "coverage": list(_UNSIGNED_MANIFEST_COVERAGE),
    }
    if expected_unsigned != unsigned:
        _fail("UNSIGNED_MANIFEST_MISMATCH")

    unsigned_manifest_digest = _role_digest(_UNSIGNED_MANIFEST_DOMAIN, unsigned)
    signature = bundle["signature"]
    if signature["unsigned_manifest_digest"] != unsigned_manifest_digest:
        _fail("UNSIGNED_MANIFEST_DIGEST_MISMATCH")
    if (
        signature["issuer_key_ref"] != v0_materials_issuer["key_ref"]
        or signature["trust_ring_ref"] != v0_materials_issuer["trust_ring_ref"]
        or signature["algorithm"] != v0_materials_issuer["algorithm"]
    ):
        _fail("KEY_RING_MISMATCH")

    issuer_public_key = _material_public_key(
        bundle["verification_materials_v0"]["issuer"], _ISSUER_SPKI_DOMAIN
    )
    try:
        canonical_manifest = cast(str, fp2.canonicalize(unsigned)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    material = _ISSUER_SIGNATURE_DOMAIN + b"\x00" + canonical_manifest
    try:
        _verify_signature(
            issuer_public_key, signature["algorithm"], material, signature["signature"]
        )
    except RelyingPartyVerificationError:
        _fail("ISSUER_SIGNATURE_INVALID")

    return ProcessRecordVerificationResult(
        base_certificate_status_evidence=v0_result.status_evidence,
        project_ref=expected_project_ref,
        build_session_ref=expected_build_session_ref,
        agent_commitment_ref=unsigned["agent_commitment_ref"],
        dataset_commitment_ref=unsigned["dataset_commitment_ref"],
        evaluator_commitment_ref=unsigned["evaluator_commitment_ref"],
        build_definition_commitment_ref=unsigned["build_definition_commitment_ref"],
        base_unsigned_manifest_digest=v0_manifest_digest,
        unsigned_manifest_digest=unsigned_manifest_digest,
        assertion_digest=assertion_digest,
        process_report_digest=report_digest,
        receipt_bundle_digest=receipt_bundle_digest,
        process_claim_support_rows_digest=claim_support_rows_digest,
        present_count=derived_report["present_count"],
        missing_count=derived_report["missing_count"],
        backend_observed_present_count=derived_report["backend_observed_present_count"],
        client_attested_present_count=derived_report["client_attested_present_count"],
        receipt_count=sum(idx["receipt_count"] for idx in computed_streams.values()),
    )


def verify_process_record_certificate(
    bundle: object, *, context: ProcessRecordVerificationContext
) -> ProcessRecordVerificationResult:
    """Verify a Process Record v1 certificate bundle entirely offline.

    ``context`` must be a :class:`ProcessRecordVerificationContext`. Tenant
    authorization is a Backend/caller responsibility; this function enforces
    only exact project/build scope consistency across the v0 base
    certificate, the V1 unsigned manifest, the derived report, and every
    receipt -- it never inspects or asserts tenant identity.

    A successful result does not establish current validity or non-revocation
    of the embedded v0 base certificate: it is verified with
    ``require_status=False`` and the result's
    ``base_certificate_status_evidence`` reports that honestly.
    """
    if not isinstance(context, ProcessRecordVerificationContext):
        _fail("CONTEXT")
    if type(bundle) is not dict:
        _fail("BUNDLE_SHAPE")
    try:
        return _verify(cast(dict[str, Any], bundle), context)
    except ProcessRecordVerificationError:
        raise
    except Exception:
        raise ProcessRecordVerificationError("VERIFICATION_FAILED") from None


__all__ = [
    "PROCESS_RECORD_ERROR_CODES",
    "ProcessRecordVerificationContext",
    "ProcessRecordVerificationError",
    "ProcessRecordVerificationResult",
    "verify_process_record_certificate",
]
