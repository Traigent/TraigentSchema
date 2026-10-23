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

The v0 base certificate's dynamic trust-status/revocation check is a caller
opt-in via ``ProcessRecordVerificationContext.allow_unchecked_base_status``.
The embedded v0 base certificate is ALWAYS verified with
``require_status=False``: ``ProcessRecordCertificateBundleV1.base_certificate_v0``
``$ref``s the bare v0 certificate schema, so the retrieval wrapper v0 would
need to read a status from it is never representable in this bundle, and a
V1-level ``require_status=True`` call would therefore always fail closed with
no passing input (see the module's own trust-status-snapshot mechanism
below). Dynamic status is instead established by a caller-supplied, fourth
verification input: an authenticated ``trust_status`` snapshot signed by a
trust anchor the caller pins in ``ProcessRecordVerificationContext.trust_anchor``.

``allow_unchecked_base_status`` and ``trust_status`` are mutually exclusive.
With ``allow_unchecked_base_status=True`` (and no ``trust_status``), status is
knowingly skipped and the result's honest classification is surfaced as
``code="PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"`` with
``base_certificate_status_evidence == "not_checked"`` and
``trust_status_evidence == "not_checked"``, never as if status had been
checked. Passing a ``trust_status`` snapshot together with
``allow_unchecked_base_status=True`` is a caller contradiction and fails with
``CONTEXT``. With ``allow_unchecked_base_status=False``, a ``trust_status``
snapshot is required: it is verified against the caller-pinned trust anchor,
checked for freshness against ``context.verification_time`` (age must be
``<= 86400`` seconds and not future-dated, both under skew ``0``), and then
consulted for the issuer key's and the certificate's status. An absent
snapshot, a stale or future-dated snapshot, or a snapshot that does not cover
the key or certificate in question all fail closed with
``REVOCATION_STATUS_UNAVAILABLE`` -- this snapshot mechanism establishes
status ONLY as of its own ``effective_time``; it makes no fresh-presentation
or replay-resistance claim. A covered key or certificate whose status is not
``"active"`` fails with ``KEY_REVOKED`` or ``CERTIFICATE_REVOKED``
respectively (key checked first). Only when every one of these checks passes
does the result carry ``code="PROCESS_RECORD_VERIFIED"`` with
``trust_status_evidence == "checked_active"``.

Verification failures expose only stable, content-free error codes. Receipt
and report content may carry customer-controlled values, and exception text
is commonly logged by callers.

Privacy boundary caveat: ``OpaqueRef``-typed fields (``receipt_ref``,
``build_session_ref``, ``trust_ring_ref``, ``issuer_key_ref``, ...) admit up
to 128 arbitrary characters in their identifier body. This module's "only
public certificate material is consumed" guarantee holds only insofar as the
issuer assigns these refs honestly; the schema cannot itself prove a ref
carries no content.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
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
_TRUST_STATUS_DOMAIN = b"traigent.process_record.trust_status.v1"
_TRUST_ANCHOR_SPKI_DOMAIN = b"traigent.process_record.trust_anchor_spki_der.v1"

_TRUST_POLICY_ID = "traigent.trust_policy.process_record.v1"
_TRUST_MAX_AGE_SECONDS = 86400
_TRUST_SKEW_SECONDS = 0
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()

_EXPECTED_STEPS = ("prepare", "evaluate", "aggregate", "select", "finalize")
_STREAM_IDS = ("decision_stream", "receipt_event_stream", "transition_stream")
_MAX_STREAM_ITEMS = 2048
_MAX_TOTAL_RECEIPTS = 6144
_MAX_RECEIPT_BYTES = 8192
# Mirrors TrustStatusSnapshotV1's key_status/certificate_status maxItems (the
# schema is the source of truth; this constant exists only so the cheap
# length guard in _check_trust_status_list_caps can run BEFORE schema
# validation walks the list -- see that function's docstring).
_MAX_TRUST_STATUS_ENTRIES = 64
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


class ProcessRecordRegistryError(RuntimeError):
    """A shipped registry document failed its own v1 schema definition.

    Raised at import time only, and only from
    :func:`_load_registry_constant` -- the boundary around the whole registry
    read/validate/digest sequence -- or from the
    :func:`_validate_registry_document` /
    :func:`_validate_registry_expected_steps` helpers it wraps. The message is
    the schema definition name -- a fixed identifier owned by this module --
    so no document content, and no filesystem path, can reach an import-time
    traceback or a caller's logs.

    Every raise uses ``from None``: a chained ``jsonschema`` or ``referencing``
    cause carries the offending instance, path, and schema fragment, and
    ``traceback.format_exception`` prints the whole cause chain, so the
    content-free message would otherwise be accompanied by the content.
    """

    def __init__(self, definition_name: str) -> None:
        self.definition_name = definition_name
        super().__init__(f"PROCESS_RECORD_REGISTRY_DOCUMENT_INVALID:{definition_name}")


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
        "COMMITMENT_REF_MISMATCH",
        "UNSIGNED_MANIFEST_MISMATCH",
        "UNSIGNED_MANIFEST_DIGEST_MISMATCH",
        "KEY_RING_MISMATCH",
        "ISSUER_SIGNATURE_INVALID",
        "CANONICALIZATION",
        "VERIFICATION_FAILED",
        "TRUST_STATUS_SHAPE",
        "TRUST_STATUS_SCHEMA",
        "TRUST_STATUS_DIGEST_MISMATCH",
        "TRUST_ANCHOR_MISMATCH",
        "TRUST_STATUS_SIGNATURE_INVALID",
        "TRUST_POLICY_MISMATCH",
        "REVOCATION_STATUS_UNAVAILABLE",
        "KEY_REVOKED",
        "CERTIFICATE_REVOKED",
    }
)


@dataclass(frozen=True, slots=True)
class TrustAnchorKeyV1:
    """Caller-pinned trust-anchor verification key, never taken from the bundle.

    Shaped like v0's ``IssuerVerificationKeyV0`` minus ``trust_ring_ref`` --
    a trust anchor is not scoped to one trust ring -- so
    :func:`traigent_schema.certification.relying_party_verifier._material_public_key`
    is reused unchanged under the dedicated ``_TRUST_ANCHOR_SPKI_DOMAIN`` role.
    ``public_key_digest`` is role-separated SHA-256 over
    ``UTF8(traigent.process_record.trust_anchor_spki_der.v1) || 0x00 || DER``.
    """

    key_ref: str
    algorithm: str
    public_key_der_b64: str
    public_key_digest: str


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

    The four ``expected_*_commitment_ref`` fields are the caller's four-pillar
    pins: the identified agent, dataset, evaluator, and build-definition
    commitments this verification is FOR. They are required (no default), so
    every caller must supply its own expectation; the verifier fails closed
    with ``COMMITMENT_REF_MISMATCH`` before comparing anything else in the
    unsigned manifest if the bundle names different commitments than pinned
    here. Without this pin a caller could only scope to (project, build), and
    a record naming a different agent/dataset/evaluator commitment for that
    same build would verify undetected.

    ``allow_unchecked_base_status`` is a required, explicit opt-in/opt-out for
    the dynamic trust-status/revocation check (see the module docstring).
    There is no default so every caller must make this choice deliberately
    rather than inheriting a silent one. Its scope now covers both the base
    certificate's issuer key and the certificate itself, not the base
    certificate alone -- the name is kept because it is still an accurate,
    already-public field three tests pin by name; only its docstring widens.

    ``verification_time`` is the caller's own clock (this verifier is
    offline and owns none) and is required unconditionally, even when the
    caller opts out of the status check, so the context shape never depends
    on a boolean. ``trust_anchor`` is the caller-pinned
    :class:`TrustAnchorKeyV1` used to authenticate a supplied ``trust_status``
    snapshot; it is required iff ``allow_unchecked_base_status`` is ``False``
    and must be ``None`` iff it is ``True`` -- a mismatch fails ``CONTEXT``.

    Tenant authorization is a Backend/caller responsibility. This context
    intentionally carries no tenant identity; the verifier enforces only
    exact project/build scope consistency.
    """

    expected_materials_digest: str
    certificate_ref: str
    base_context: VerificationContext
    expected_project_ref: str
    expected_build_session_ref: str
    expected_agent_commitment_ref: str
    expected_dataset_commitment_ref: str
    expected_evaluator_commitment_ref: str
    expected_build_definition_commitment_ref: str
    allow_unchecked_base_status: bool
    verification_time: str
    trust_anchor: TrustAnchorKeyV1 | None

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
        for commitment_ref in (
            self.expected_agent_commitment_ref,
            self.expected_dataset_commitment_ref,
            self.expected_evaluator_commitment_ref,
            self.expected_build_definition_commitment_ref,
        ):
            if type(commitment_ref) is not str or not _SHA256_RE.fullmatch(commitment_ref):
                _fail("CONTEXT")
        if type(self.allow_unchecked_base_status) is not bool:
            _fail("CONTEXT")
        if type(self.verification_time) is not str or _parse_utc_timestamp(
            self.verification_time
        ) is None:
            _fail("CONTEXT")
        # trust_anchor is required iff the caller requires the status check;
        # it must be exactly None when the caller opts out. Both directions of
        # this mismatch are a caller contradiction, not a missing-value case.
        if (self.trust_anchor is None) != self.allow_unchecked_base_status:
            _fail("CONTEXT")
        if self.trust_anchor is not None:
            if not isinstance(self.trust_anchor, TrustAnchorKeyV1):
                _fail("CONTEXT")
            if type(self.trust_anchor.key_ref) is not str or not _REF_RE.fullmatch(
                self.trust_anchor.key_ref
            ):
                _fail("CONTEXT")
            if self.trust_anchor.algorithm not in ("ed25519", "ecdsa_p256_sha256"):
                _fail("CONTEXT")
            if (
                type(self.trust_anchor.public_key_der_b64) is not str
                or not self.trust_anchor.public_key_der_b64
            ):
                _fail("CONTEXT")
            if type(
                self.trust_anchor.public_key_digest
            ) is not str or not _SHA256_RE.fullmatch(self.trust_anchor.public_key_digest):
                _fail("CONTEXT")


@dataclass(frozen=True, slots=True)
class ProcessRecordVerificationResult:
    """Bounded, content-free success result.

    Only digest strings, opaque refs, and counters are carried. No example,
    source, evaluator code, prompt, response, arbitrary metadata, or raw
    registered value ever crosses into this object.

    ``base_certificate_status_evidence`` mirrors the embedded v0 result's
    ``status_evidence`` unchanged. The embedded v0 base certificate is ALWAYS
    verified with ``require_status=False`` now (see the module docstring), so
    this field is ALWAYS ``"not_checked"``, even on a ``PROCESS_RECORD_VERIFIED``
    result -- v0's own status check never runs for this bundle shape. It is
    kept, unrepointed, so nobody later "fixes" it by asserting v0 checked
    something; dynamic status is established by ``trust_status_evidence``
    below instead, which is the field that actually varies.

    ``trust_status_evidence`` is ``"checked_active"`` iff a supplied
    ``trust_status`` snapshot was verified against the caller-pinned trust
    anchor, found fresh, and found to cover an active issuer key and an
    active certificate; it is ``"not_checked"`` iff the caller explicitly
    opted out via ``allow_unchecked_base_status=True``. ``trust_anchor_ref``
    and ``trust_status_effective_time`` echo the verified snapshot's own
    values and are empty when status was not checked.

    ``code`` is ``"PROCESS_RECORD_VERIFIED"`` only when the caller required
    the trust-status check (``allow_unchecked_base_status=False``) and a
    supplied ``trust_status`` snapshot verified as fresh, anchor-authentic,
    and active for both the issuer key and the certificate; it is
    ``"PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"`` when the caller explicitly
    opted out of that check. Under ``allow_unchecked_base_status=False`` an
    absent, stale, future-dated, non-covering, or revoked status never
    reaches either success code -- it fails closed instead, with no result
    object constructed. ``code`` and ``trust_status_evidence`` are pairwise
    coupled by ``__post_init__``: a checked-status code can never carry
    unchecked evidence, and vice versa.
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
    trust_status_evidence: str = "not_checked"
    trust_anchor_ref: str = ""
    trust_status_effective_time: str = ""

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ValueError("PROCESS_RECORD_VERIFICATION_RESULT")
        if self.code not in ("PROCESS_RECORD_VERIFIED", "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"):
            raise ValueError("PROCESS_RECORD_VERIFICATION_RESULT")
        if (self.code, self.trust_status_evidence) not in (
            ("PROCESS_RECORD_VERIFIED", "checked_active"),
            ("PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED", "not_checked"),
        ):
            raise ValueError("PROCESS_RECORD_VERIFICATION_RESULT")


@lru_cache(maxsize=1)
def _process_record_schema() -> tuple[Registry, dict[str, Any]]:
    """The v1 schema document plus a ``$ref`` registry over every shipped schema.

    One loader, so the bundle validator and the registry-document validators
    resolve ``$ref``s through the same registry instead of a second copy that
    could drift.
    """
    schema_resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            schema_resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(schema_resources)
    schema = cast(
        dict[str, Any],
        json.loads(_PROCESS_RECORD_SCHEMA_PATH.read_text(encoding="utf-8")),
    )
    return registry, schema


@lru_cache(maxsize=1)
def _process_record_validator() -> Draft7Validator:
    registry, schema = _process_record_schema()
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


@lru_cache(maxsize=4)
def _definition_validator(definition_name: str) -> Draft7Validator:
    """A validator anchored at one ``#/definitions/<name>`` of the v1 schema.

    Reuses :func:`_process_record_schema`'s registry so cross-file ``$ref``s
    (e.g. ``certification_common_v0_schema.json#/definitions/Sha256Digest``)
    resolve exactly as they do for a full bundle.
    """
    registry, schema = _process_record_schema()
    document = {
        "$schema": schema["$schema"],
        "$id": f"{schema['$id']}#definition-{definition_name}",
        "definitions": schema["definitions"],
        "allOf": [{"$ref": f"#/definitions/{definition_name}"}],
    }
    return Draft7Validator(document, registry=registry, format_checker=_FORMAT_CHECKER)


def _role_digest(domain: bytes, projection: Any) -> str:
    # Mirrors relying_party_verifier._role_digest's SHA-256(domain || 0x00 ||
    # jcs(x)) construction (a second implementation, not a shared import) --
    # if that framing ever changes, this copy must change in lockstep.
    try:
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    return _SHA256_PREFIX + hashlib.sha256(domain + b"\x00" + canonical).hexdigest()


def _validate_registry_document(
    document: dict[str, Any],
    definition_name: str,
    digest_field: str,
    domain: bytes,
) -> None:
    """Validate a shipped registry document against its own v1 schema definition.

    Each document ships as its own digest preimage: the schema requires the
    self-digest member but excludes it from the preimage, so the digest is
    recomputed here and added beside the document before validating -- the
    same shape the schema definitions describe.

    This runs at import so a registry document that gained a free-text member,
    lost a required one, or drifted from a ``const`` cannot be digested and
    shipped as canonical. Failure raises :class:`ProcessRecordRegistryError`
    naming only ``definition_name``; document content is never echoed.

    The shipped document must be the bare preimage, i.e. must NOT already
    carry ``digest_field``. A pre-existing self-digest member would be hashed
    into the digest below and then overwritten in ``candidate``, so its
    content would bind into every issued certificate while never being seen by
    the validator -- invisible to the very check this function performs. That
    is rejected here, before anything is hashed.
    """
    if digest_field in document:
        raise ProcessRecordRegistryError(definition_name) from None
    candidate = {**document, digest_field: _role_digest(domain, document)}
    try:
        # Counted, not collected: a retained ``ValidationError`` list would keep
        # the offending instance alive in this frame's locals.
        error_count = sum(1 for _ in _definition_validator(definition_name).iter_errors(candidate))
    except (OSError, UnicodeError, KeyError, json.JSONDecodeError, Unresolvable):
        raise ProcessRecordRegistryError(definition_name) from None
    if error_count:
        raise ProcessRecordRegistryError(definition_name) from None


def _validate_registry_expected_steps(
    document: dict[str, Any],
    definition_name: str,
) -> None:
    """Bind ``_EXPECTED_STEPS`` to the ``expected_steps`` the document ships.

    The verifier derives its report from the module constant while the shipped
    documents carry their own list, so there were two sources of truth for the
    same five steps. ``ExpectedProcessStepsV1`` is a ``const`` array, which
    pins the documents -- but nothing pinned the module constant to them, so a
    hand-edit of ``_EXPECTED_STEPS`` would have drifted silently. Order is
    part of the identity: a permutation is drift, not a reordering.

    Content-free failure, ``from None``, exactly as
    :func:`_validate_registry_document`.
    """
    steps = document.get("expected_steps")
    if not isinstance(steps, list) or tuple(steps) != _EXPECTED_STEPS:
        raise ProcessRecordRegistryError(definition_name) from None


def _load_registry_document(
    filename: str,
    root: Traversable | None = None,
) -> dict[str, Any]:
    """Load a canonical registry document shipped as package data.

    Uses the same ``importlib.resources`` mechanism as
    ``traigent_schema/data/fp2_conformance.json`` so these documents are
    ordinary package data rather than Python literals duplicated between
    this module and its tests.

    ``root`` overrides the package the document is read from. Production
    callers pass nothing; it exists so a test can point the loader at a
    synthetic tree (an absent file, undecodable bytes) and exercise the read
    path directly instead of only through a whole-package copy in a
    subprocess.

    Reading and decoding are content-bearing: ``FileNotFoundError`` and
    ``UnicodeDecodeError`` name a filesystem path and
    ``json.JSONDecodeError`` quotes the offending document text. This
    function therefore has no error handling of its own and MUST only be
    called from inside :func:`_load_registry_constant`'s boundary.
    """
    # Chained single-argument joinpath: ``Traversable.joinpath`` is typed as
    # taking one child name, so the multi-argument form does not type-check.
    package = resources.files("traigent_schema") if root is None else root
    text = package.joinpath("data").joinpath("certification").joinpath(filename).read_text(
        encoding="utf-8"
    )
    return cast(dict[str, Any], json.loads(text))


def _load_registry_constant(
    filename: str,
    definition_name: str,
    digest_field: str,
    domain: bytes,
    root: Traversable | None = None,
) -> tuple[dict[str, Any], str]:
    """Read, validate, tie and digest one shipped registry document.

    The single content-free boundary for the whole registry path. Every step
    it wraps can raise something that carries content:

    * the read/decode raises ``FileNotFoundError`` or ``UnicodeDecodeError``
      naming a filesystem path, or ``json.JSONDecodeError`` quoting the
      document text;
    * :func:`_validate_registry_document` can surface a ``jsonschema`` or
      ``referencing`` error carrying the offending instance;
    * :func:`_role_digest` converts an ``fp2`` canonicalization failure into
      ``ProcessRecordVerificationError("CANONICALIZATION")`` -- a
      *verification* error, raised with implicit chaining, whose
      ``__context__`` is the canonicalizer's own exception.

    The per-site ``from None`` raises inside those helpers cover only the
    cases they were written for; this boundary is what makes the property
    hold for the sequence as a whole. It converts every ``Exception`` -- schema,
    decode, digest, or a ``ProcessRecordVerificationError`` from ``_fail`` --
    into the fixed :class:`ProcessRecordRegistryError` naming only
    ``definition_name``, a constant owned by this module. ``BaseException``
    control-flow exceptions (``KeyboardInterrupt``, ``SystemExit``,
    ``GeneratorExit``) are deliberately outside the guarantee and propagate
    unchanged.

    The raise is deliberately placed AFTER the handler has exited rather than
    inside it. ``raise ... from None`` clears ``__cause__`` and stops
    ``traceback.format_exception`` from printing ``__context__``, but inside a
    handler the interpreter still LINKS the caught exception as
    ``__context__`` -- and that object holds the content: a
    ``UnicodeDecodeError`` carries the undecodable bytes, a
    ``json.JSONDecodeError`` the document text, a ``ValidationError`` the
    offending instance. Suppressed from printing is not absent; anything that
    walks the chain explicitly, or reprs the exception, would still see it.
    Once the handler has exited there is no exception being handled, so
    ``__context__`` is genuinely ``None`` and the caught exception -- with its
    traceback and its frames' locals -- becomes unreachable. One case remains:
    when this module is imported from inside some other caller's ``except``
    block, the raise links the caller's in-flight exception as ``__context__``
    (``from None`` only suppresses its display), so the error is caught once
    more, its ``__context__`` cleared, and the same object re-raised.
    """
    loaded: tuple[dict[str, Any], str] | None
    try:
        document = _load_registry_document(filename, root)
        _validate_registry_document(document, definition_name, digest_field, domain)
        _validate_registry_expected_steps(document, definition_name)
        loaded = (document, _role_digest(domain, document))
    except Exception:
        loaded = None
    if loaded is None:
        failure = ProcessRecordRegistryError(definition_name)
        try:
            raise failure from None
        except ProcessRecordRegistryError:
            # ``from None`` clears ``__cause__`` and suppresses display, but if
            # this module is imported from inside a caller's own ``except``
            # block the interpreter still links that caller's exception as
            # ``__context__`` at raise time. Clear the link and re-raise the
            # same object so the registry error references nothing outside
            # this module.
            failure.__context__ = None
            raise
    return loaded


# The digests below are only as trustworthy as the documents they cover, so each
# shipped document is read, checked against its schema definition, tied to
# ``_EXPECTED_STEPS``, and only then hashed -- at import, and all four steps
# inside one ``_load_registry_constant`` boundary. Validating BEFORE hashing is
# what makes the self-digest guard in ``_validate_registry_document`` reach the
# preimage these constants are taken over, not just the copy the validator sees;
# doing the read and the digest inside the boundary is what keeps a missing
# file, undecodable bytes, or a canonicalization failure from putting a
# filesystem path or document content into the import-time traceback.
# ``expected_steps`` is carried by both shipped documents and ``_EXPECTED_STEPS``
# is the third copy -- the one the report is built from -- so the boundary ties
# the constant to each document before that document's digest is taken.
_CAPTURE_POLICY_DOCUMENT, _CAPTURE_POLICY_DIGEST = _load_registry_constant(
    "capture_policy_document.json",
    "CapturePolicyDocumentV1",
    "policy_digest",
    _CAPTURE_POLICY_DOMAIN,
)
_PROCESS_DEFINITION_DOCUMENT, _PROCESS_DEFINITION_DIGEST = _load_registry_constant(
    "process_definition_document.json",
    "ProcessDefinitionDocumentV1",
    "definition_digest",
    _PROCESS_DEFINITION_DOMAIN,
)
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
    """Verify the embedded v0 base certificate, always signature-only.

    ``require_status`` is always ``False`` here: the retrieval wrapper v0
    would need in order to read a status from a certificate is never
    representable as ``ProcessRecordCertificateBundleV1.base_certificate_v0``
    (a bare-certificate ``$ref``), so a ``True`` call would always fail
    closed with no passing input. Dynamic status is instead established at
    the V1 level via the caller's ``trust_status`` snapshot -- see
    :func:`_verify_trust_status` and the module docstring.
    """
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
    """Reject oversized, misordered, duplicate, or misrouted receipts.

    The per-receipt ``_MAX_RECEIPT_BYTES`` (8,192) cap is unreachable through
    any schema-valid receipt today -- OpaqueRef/ProjectRefV0 field-length
    bounds keep a real canonical receipt under ~1 KB -- and is retained
    anyway as a schema-drift backstop: it fails independently of any future
    widening of those bounds.
    """
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
        # "pass" is a schema const the row must carry; it is not itself
        # evidence that a verifier ran -- the four digest bindings above are
        # the substance, established by the reader's own successful
        # verification, not by this literal.
        "verifier_result": "pass",
        "claim_material_digest": claim_material_digest,
    }
    if row != expected_row:
        _fail("CLAIM_SUPPORT_ROW_MISMATCH")


def _parse_utc_timestamp(value: str) -> tuple[int, int, int, int, int, int, int] | None:
    """Strictly parse a ``UtcTimestampV1``-shaped string, or ``None`` if it is
    not a real UTC instant.

    ``_UTC_RE`` only checks digit shape -- it accepts ``24:00:00Z``,
    ``23:60:00Z``, ``2026-02-30T...Z``, and ``2026-13-01T...Z`` just as
    happily as a real instant, because a regex over fixed-width digit groups
    cannot express calendar or clock-field range constraints (day-per-month,
    leap years, hour <= 23, minute/second <= 59). Constructing a
    :class:`datetime.datetime` from the parsed components is what actually
    enforces those ranges: it raises ``ValueError`` for every one of the
    examples above, including leap-year edge cases (``2028-02-29`` accepted,
    ``2026-02-29`` rejected). Two callers share this parser --
    ``ProcessRecordVerificationContext.__post_init__`` for
    ``verification_time`` and :func:`_utc_microseconds` for a trust-status
    snapshot's ``effective_time`` -- so both the caller-supplied clock and the
    signed snapshot are held to the same strict range check, not just the
    regex.
    """
    if _UTC_RE.fullmatch(value) is None:
        return None
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    dot_index = value.find(".")
    frac = value[dot_index + 1 : -1] if dot_index != -1 else ""
    frac_us = int((frac + "000000")[:6]) if frac else 0
    try:
        datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
    return year, month, day, hour, minute, second, frac_us


def _utc_microseconds(value: str) -> int:
    """Integer microseconds since the Unix epoch, parsed strictly from a
    ``UtcTimestampV1``-shaped string -- never via ``datetime`` tz inference.

    Delegates the shape-and-range parse to :func:`_parse_utc_timestamp`; a
    ``None`` result (bad shape OR an out-of-range calendar/clock field) fails
    ``REVOCATION_STATUS_UNAVAILABLE``, the pre-existing code for a
    ``effective_time`` this module cannot use. The caller SHOULD already know
    ``value`` matches ``_UTC_RE`` (schema validation covers the shape for
    ``snapshot["effective_time"]`` before :func:`_verify_trust_status` reaches
    this point), but the range check below is NOT redundant with anything
    upstream -- ``_UTC_RE`` alone never rejected ``24:00:00Z`` or
    ``23:60:00Z``.
    """
    parsed = _parse_utc_timestamp(value)
    if parsed is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE")
    year, month, day, hour, minute, second, frac_us = parsed
    days = date(year, month, day).toordinal() - _EPOCH_ORDINAL
    seconds = days * 86400 + hour * 3600 + minute * 60 + second
    return seconds * 1_000_000 + frac_us


def _check_trust_status_list_caps(snapshot: dict[str, Any]) -> None:
    """Enforce ``key_status``/``certificate_status``'s ``maxItems`` (64) via a
    cheap ``len()`` check, BEFORE anything else -- schema validation or
    duplicate detection -- walks either list.

    ``trust_status`` is an unauthenticated, caller-supplied fourth input (its
    own signature is not yet checked at this point in the call sequence): an
    adversary can present a snapshot with an arbitrarily large ``key_status``
    or ``certificate_status`` array. ``len()`` on a Python list is O(1)
    regardless of length, so this guard costs nothing to run first and
    rejects an oversized list before :func:`_check_trust_status_no_duplicates`
    would otherwise pay O(n) time and memory building lookup sets over it, and
    before the jsonschema validator's own array walk reaches the same
    ``maxItems`` bound. Only the list length is inspected -- entries
    themselves are never touched here, so a list of malformed or even
    non-dict entries is rejected purely on size without evaluating any of
    them. The failure code, ``TRUST_STATUS_SCHEMA``, is the same one schema
    validation would produce for this exact ``maxItems`` violation; this is a
    cheaper enforcement of that constraint, not a new one.
    """
    key_entries = snapshot.get("key_status")
    cert_entries = snapshot.get("certificate_status")
    if not isinstance(key_entries, list) or not isinstance(cert_entries, list):
        _fail("TRUST_STATUS_SHAPE")
    if (
        len(key_entries) > _MAX_TRUST_STATUS_ENTRIES
        or len(cert_entries) > _MAX_TRUST_STATUS_ENTRIES
    ):
        _fail("TRUST_STATUS_SCHEMA")


def _check_trust_status_no_duplicates(snapshot: dict[str, Any]) -> None:
    """Reject a snapshot carrying two entries for the same key or certificate.

    Draft-07 cannot express uniqueness across object fields within an array,
    so this is a verifier obligation the schema's own description names
    explicitly (``KeyStatusEntryV1`` / ``CertificateStatusEntryV1``). Called
    only AFTER :func:`_check_trust_status_list_caps` and full schema
    validation have both passed, so every entry here is already known to be a
    schema-valid object within the ``maxItems`` bound -- see
    :func:`_verify_trust_status`'s docstring for the full ordering rationale.
    """
    key_entries = snapshot.get("key_status")
    cert_entries = snapshot.get("certificate_status")
    if not isinstance(key_entries, list) or not isinstance(cert_entries, list):
        _fail("TRUST_STATUS_SHAPE")
    seen_keys: set[tuple[Any, Any]] = set()
    for entry in key_entries:
        if not isinstance(entry, dict):
            _fail("TRUST_STATUS_SHAPE")
        pair = (entry.get("key_ref"), entry.get("trust_ring_ref"))
        if pair in seen_keys:
            _fail("TRUST_STATUS_SHAPE")
        seen_keys.add(pair)
    seen_certs: set[Any] = set()
    for entry in cert_entries:
        if not isinstance(entry, dict):
            _fail("TRUST_STATUS_SHAPE")
        ref = entry.get("certificate_ref")
        if ref in seen_certs:
            _fail("TRUST_STATUS_SHAPE")
        seen_certs.add(ref)


def _verify_trust_status(
    trust_status: object, context: ProcessRecordVerificationContext
) -> dict[str, Any]:
    """Authenticate and freshness-check a caller-supplied trust-status snapshot.

    Returns the verified, schema-valid snapshot body. Every failure here is a
    raise -- no partial result is ever returned. Order: absence/shape, the
    policy-identity pre-check (a dedicated code ahead of generic schema
    validation, mirroring the ``COMMITMENT_REF_MISMATCH``-before-
    ``UNSIGNED_MANIFEST_MISMATCH`` pattern below), the cheap ``len()``
    list-length cap check (before anything else touches ``key_status``/
    ``certificate_status`` -- an unauthenticated, arbitrarily large snapshot
    must be rejected on size alone, not after the schema validator or the
    duplicate-entry check have already walked it), full schema validation,
    the schema-inexpressible duplicate-entry check (now over a
    length-bounded, schema-valid list), the digest pin, the trust-anchor
    identity pin, the anchor signature, then freshness -- exactly the order
    the design table implies (anchor signature before freshness; policy
    identity before either).
    """
    if trust_status is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE")
    if type(trust_status) is not dict:
        _fail("TRUST_STATUS_SHAPE")
    envelope = cast(dict[str, Any], trust_status)
    snapshot = envelope.get("snapshot")
    signature = envelope.get("signature")
    if type(snapshot) is not dict or type(signature) is not dict:
        _fail("TRUST_STATUS_SHAPE")
    snapshot = cast(dict[str, Any], snapshot)
    signature = cast(dict[str, Any], signature)

    if (
        snapshot.get("trust_policy_id") != _TRUST_POLICY_ID
        or snapshot.get("max_age_seconds") != _TRUST_MAX_AGE_SECONDS
    ):
        _fail("TRUST_POLICY_MISMATCH")

    _check_trust_status_list_caps(snapshot)

    try:
        errors = list(_definition_validator("TrustStatusEnvelopeV1").iter_errors(envelope))
    except Unresolvable:
        _fail("SCHEMA_DEPENDENCY")
    if errors:
        _fail("TRUST_STATUS_SCHEMA")

    _check_trust_status_no_duplicates(snapshot)

    computed_digest = _role_digest(_TRUST_STATUS_DOMAIN, snapshot)
    if signature["snapshot_digest"] != computed_digest:
        _fail("TRUST_STATUS_DIGEST_MISMATCH")

    trust_anchor = context.trust_anchor
    if trust_anchor is None:
        # The public entry point already rejects a snapshot without a pinned anchor
        # as CONTEXT; this is the fail-closed backstop for direct callers. An
        # `assert` would vanish under PYTHONOPTIMIZE and surface as AttributeError.
        _fail("CONTEXT")
    if (
        snapshot["trust_anchor_ref"] != trust_anchor.key_ref
        or signature["trust_anchor_ref"] != trust_anchor.key_ref
    ):
        _fail("TRUST_ANCHOR_MISMATCH")

    try:
        anchor_public_key = _material_public_key(
            {
                "public_key_der_b64": trust_anchor.public_key_der_b64,
                "public_key_digest": trust_anchor.public_key_digest,
                "algorithm": trust_anchor.algorithm,
            },
            _TRUST_ANCHOR_SPKI_DOMAIN,
        )
    except RelyingPartyVerificationError:
        _fail("CONTEXT")
    try:
        canonical_snapshot = cast(str, fp2.canonicalize(snapshot)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    material = _TRUST_STATUS_DOMAIN + b"\x00" + canonical_snapshot
    try:
        _verify_signature(
            anchor_public_key, signature["algorithm"], material, signature["signature"]
        )
    except RelyingPartyVerificationError:
        _fail("TRUST_STATUS_SIGNATURE_INVALID")

    effective_us = _utc_microseconds(snapshot["effective_time"])
    verification_us = _utc_microseconds(context.verification_time)
    if effective_us > verification_us + _TRUST_SKEW_SECONDS * 1_000_000:
        _fail("REVOCATION_STATUS_UNAVAILABLE")
    if verification_us - effective_us > _TRUST_MAX_AGE_SECONDS * 1_000_000:
        _fail("REVOCATION_STATUS_UNAVAILABLE")

    return snapshot


def _check_trust_status_coverage(
    snapshot: dict[str, Any],
    issuer_key_ref: str,
    trust_ring_ref: str,
    certificate_ref: str,
) -> None:
    """Look up issuer-key and certificate status; key is checked first.

    A covering entry that is not ``"active"`` fails closed with the specific
    ``KEY_REVOKED`` / ``CERTIFICATE_REVOKED`` code; a missing entry -- the
    snapshot simply does not speak to this key or this certificate -- fails
    with ``REVOCATION_STATUS_UNAVAILABLE``, never a pass.
    """
    key_entry = None
    for entry in snapshot["key_status"]:
        if entry["key_ref"] == issuer_key_ref and entry["trust_ring_ref"] == trust_ring_ref:
            key_entry = entry
            break
    if key_entry is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE")
    if key_entry["status"] != "active":
        _fail("KEY_REVOKED")

    cert_entry = None
    for entry in snapshot["certificate_status"]:
        if entry["certificate_ref"] == certificate_ref:
            cert_entry = entry
            break
    if cert_entry is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE")
    if cert_entry["status"] != "active":
        _fail("CERTIFICATE_REVOKED")


def _verify(
    bundle: dict[str, Any], context: ProcessRecordVerificationContext, trust_status: object
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

    # Four-pillar caller pinning: the bundle's commitment refs must match the
    # caller's own expectations BEFORE any further comparison. Checking this
    # first -- rather than folding it into the general expected_unsigned
    # equality below -- gives it a dedicated, closed error code and makes the
    # pin impossible to satisfy via a tautological self-comparison.
    if (
        unsigned.get("agent_commitment_ref") != context.expected_agent_commitment_ref
        or unsigned.get("dataset_commitment_ref") != context.expected_dataset_commitment_ref
        or unsigned.get("evaluator_commitment_ref")
        != context.expected_evaluator_commitment_ref
        or unsigned.get("build_definition_commitment_ref")
        != context.expected_build_definition_commitment_ref
    ):
        _fail("COMMITMENT_REF_MISMATCH")

    v0_materials_issuer = bundle["verification_materials_v0"]["issuer"]
    expected_unsigned = {
        "schema_version": "traigent.process_record.unsigned_manifest.v1",
        "base_unsigned_manifest_digest": v0_manifest_digest,
        "capture_policy": _CAPTURE_POLICY_IDENTITY,
        "process_definition": _PROCESS_DEFINITION_IDENTITY,
        "project_ref": expected_project_ref,
        "build_session_ref": expected_build_session_ref,
        "agent_commitment_ref": context.expected_agent_commitment_ref,
        "dataset_commitment_ref": context.expected_dataset_commitment_ref,
        "evaluator_commitment_ref": context.expected_evaluator_commitment_ref,
        "build_definition_commitment_ref": context.expected_build_definition_commitment_ref,
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

    # v0's own VerificationResult never distinguishes a checked-and-active
    # status from a skipped one in its (code, status_evidence) pair (both
    # require_status branches return the same default), and v0 is now always
    # called with require_status=False regardless of the caller's choice (see
    # _verify_base_certificate), so dynamic status is established here, at
    # the V1 level, via the caller's trust_status snapshot rather than v0's.
    if context.allow_unchecked_base_status:
        trust_status_evidence = "not_checked"
        trust_anchor_ref = ""
        trust_status_effective_time = ""
    else:
        trust_snapshot = _verify_trust_status(trust_status, context)
        _check_trust_status_coverage(
            trust_snapshot,
            issuer_key_ref=v0_materials_issuer["key_ref"],
            trust_ring_ref=v0_materials_issuer["trust_ring_ref"],
            certificate_ref=context.certificate_ref,
        )
        trust_status_evidence = "checked_active"
        trust_anchor_ref = trust_snapshot["trust_anchor_ref"]
        trust_status_effective_time = trust_snapshot["effective_time"]

    success_code = (
        "PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"
        if context.allow_unchecked_base_status
        else "PROCESS_RECORD_VERIFIED"
    )
    return ProcessRecordVerificationResult(
        code=success_code,
        base_certificate_status_evidence=v0_result.status_evidence,
        trust_status_evidence=trust_status_evidence,
        trust_anchor_ref=trust_anchor_ref,
        trust_status_effective_time=trust_status_effective_time,
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
    bundle: object,
    *,
    context: ProcessRecordVerificationContext,
    trust_status: object | None = None,
) -> ProcessRecordVerificationResult:
    """Verify a Process Record v1 certificate bundle entirely offline.

    ``context`` must be a :class:`ProcessRecordVerificationContext`. Tenant
    authorization is a Backend/caller responsibility; this function enforces
    only exact project/build scope consistency across the v0 base
    certificate, the V1 unsigned manifest, the derived report, and every
    receipt -- it never inspects or asserts tenant identity.

    ``trust_status`` is the fourth verification input: an authenticated
    ``TrustStatusEnvelopeV1``-shaped snapshot, signed by the trust anchor
    pinned at ``context.trust_anchor``, establishing whether the base
    certificate's issuer key and the certificate itself were active as of
    the snapshot's own ``effective_time``. It is a SEPARATE artifact from
    ``bundle``, never embedded in it, because the issuer cannot sign at
    issuance a value a different signer produces hours later with its own
    24-hour lifetime.

    Whether a successful result establishes current validity / non-revocation
    is the caller's explicit choice via ``context.allow_unchecked_base_status``,
    and ``trust_status`` must agree with that choice -- the two are mutually
    exclusive:

    * ``allow_unchecked_base_status=True``, ``trust_status=None``: status is
      knowingly skipped. The result carries
      ``code="PROCESS_RECORD_VERIFIED_STATUS_UNCHECKED"`` and
      ``trust_status_evidence="not_checked"``.
    * ``allow_unchecked_base_status=True``, ``trust_status`` supplied: a
      caller contradiction ("I opted out of checking" plus "here is a status
      to check") -- raises ``CONTEXT``, no result constructed.
    * ``allow_unchecked_base_status=False``, ``trust_status`` supplied: the
      snapshot is verified against the pinned trust anchor, checked for
      freshness against ``context.verification_time`` (age <= 86400 s, not
      future-dated, both at zero skew), and consulted for the issuer key's
      and the certificate's status. Only when both are found ``"active"``
      does the result carry ``code="PROCESS_RECORD_VERIFIED"`` and
      ``trust_status_evidence="checked_active"``; a revoked key or
      certificate raises ``KEY_REVOKED`` / ``CERTIFICATE_REVOKED``
      (key checked first).
    * ``allow_unchecked_base_status=False``, ``trust_status=None``, stale,
      future-dated, or not covering this key/certificate: raises
      ``REVOCATION_STATUS_UNAVAILABLE`` -- a failure code, never a pass. This
      mechanism establishes status ONLY as of the snapshot's own
      ``effective_time``; it makes no fresh-presentation or
      replay-resistance claim.

    The embedded v0 base certificate is verified first in every case (a
    ``BASE_CERTIFICATE_INVALID`` failure precedes all of the above), always
    with ``require_status=False`` -- see the module docstring for why.
    """
    if not isinstance(context, ProcessRecordVerificationContext):
        _fail("CONTEXT")
    if context.allow_unchecked_base_status and trust_status is not None:
        _fail("CONTEXT")
    if type(bundle) is not dict:
        _fail("BUNDLE_SHAPE")
    try:
        return _verify(cast(dict[str, Any], bundle), context, trust_status)
    except ProcessRecordVerificationError:
        raise
    except Exception:
        raise ProcessRecordVerificationError("VERIFICATION_FAILED") from None


__all__ = [
    "PROCESS_RECORD_ERROR_CODES",
    "ProcessRecordVerificationContext",
    "ProcessRecordVerificationError",
    "ProcessRecordVerificationResult",
    "TrustAnchorKeyV1",
    "verify_process_record_certificate",
]
