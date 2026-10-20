# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Commitment-linkage sidecar: commitment function and offline reader (C1 step 1).

The sidecar (``commitment_linkage_v1_schema.json``) is a SEPARATELY SIGNED
artifact bound to one unchanged process-record certificate by that record's
``unsigned_manifest_digest``. Nothing here touches the process-record
envelope, so previously signed bytes verify exactly as before.

Claim scope (read before relying on a result). A verified linkage entry says:
"the client declared this fingerprint (fp1) at session start, and the issuer
checked equality with that session's recorded declaration." It is NOT proof of
the version that ran and NOT proof of execution. ``COMMITMENT_OPENED_MATCH``
means the supplied fingerprint and opening reproduce the commitment found in
an AUTHENTICATED linkage; it is not artifact recomputation. A dishonest client
can declare copied fingerprints at session start. The build definition is
deliberately unbound (no role exists for it).

Commitment construction (normative; reference implementation below)::

    P = lp(b"traigent.commitment-linkage.v1")
        || lp(UTF8(role)) || lp(UTF8(basis))
        || lp(b"fp1") || lp(UTF8(fp_digest))
        || lp(opening)
    commitment = "sha256:" + hex(SHA-256(P))      lp(x) = uint64_be(len(x)) || x

``fp_digest`` is the 71-character string ``sha256:<64 lowercase hex>``, byte
for byte the ``digest`` member of the identity-v2 snapshot slot
``{schema: "fp1", digest: "sha256:..."}``; it is never re-encoded or re-hashed.
``opening`` is exactly 32 bytes from a CSPRNG (:func:`new_opening`), fresh and
independent per artifact role per issuance, generated and kept client-side. The
issuing Backend learns it at issuance and must neither persist nor log it.
The commitment hides the fingerprint only while the opening stays secret;
disclosing the opening lets the holder prove, and anyone confirm, a candidate.

Failures raise :class:`CommitmentLinkageError` with a fixed code and never
echo envelope, fingerprint, opening, or role values.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, NoReturn, cast

from jsonschema import Draft7Validator
from referencing import Registry, Resource

import traigent_schema.fp2 as fp2
from traigent_schema.certification.relying_party_verifier import (
    _ISSUER_SPKI_DOMAIN,
    RelyingPartyVerificationError,
    _material_public_key,
    _verify_signature,
)
from traigent_schema.validator import _FORMAT_CHECKER

COMMITMENT_DOMAIN = b"traigent.commitment-linkage.v1"
UNSIGNED_LINKAGE_DOMAIN = b"traigent.commitment_linkage.unsigned.v1"
ISSUER_SIGNATURE_DOMAIN = b"traigent.commitment_linkage.issuer_signature.v1"
FP_SCHEMA = b"fp1"
OPENING_BYTES = 32

COMMITMENT_OPENED_MATCH = "COMMITMENT_OPENED_MATCH"
COMMITMENT_OPENED_MISMATCH = "COMMITMENT_OPENED_MISMATCH"
COMMITMENT_UNAVAILABLE = "COMMITMENT_UNAVAILABLE"

COMMITMENT_LINKAGE_ERROR_CODES = frozenset(
    {
        "CONTEXT",
        "ENVELOPE_SHAPE",
        "SCHEMA",
        "CANONICALIZATION",
        "UNSIGNED_LINKAGE_DIGEST_MISMATCH",
        "KEY_MISMATCH",
        "KEY_MATERIAL",
        "SIGNATURE_INVALID",
        "RECORD_BINDING_MISMATCH",
        "SCOPE_MISMATCH",
        "DUPLICATE_ROLE",
        "OPENING_SHAPE",
        "FINGERPRINT_SHAPE",
        "ROLE_SHAPE",
        "VERIFICATION_FAILED",
    }
)

_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent
    / "schemas"
    / "certification"
    / "commitment_linkage_v1_schema.json"
)
_SCHEMAS_DIR = _SCHEMA_PATH.parent.parent
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9_-]{8,128}$")
# Evaluator roles are a CLOSED, service-assigned vocabulary. Customer labels are
# content and stay customer-side; they never appear in a role token.
_ROLES = frozenset(
    {
        "agent",
        "dataset",
        "config_space",
        "evaluator:primary",
        *(f"evaluator:r{i}" for i in range(8)),
    }
)
_BASES = frozenset(
    {
        "source_text",
        "name_only",
        "endpoint_only",
        "order_free_multiset",
        "config_space",
        "unavailable",
    }
)


class CommitmentLinkageError(ValueError):
    """A fixed-code failure that never includes envelope or caller data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> NoReturn:
    """Raise a closed error that references no other exception.

    ``from None`` clears ``__cause__`` and hides ``__context__`` from display,
    but at raise time the interpreter still links whatever exception the caller
    is handling. Catch our own error once, clear that link, re-raise the same
    object (same discipline as ``process_record_verifier``).
    """
    failure = CommitmentLinkageError(code)
    try:
        raise failure from None
    except CommitmentLinkageError:
        failure.__context__ = None
        raise


def _lp(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def new_opening() -> bytes:
    """Return a fresh 32-byte opening from the OS CSPRNG.

    Call once per artifact role per issuance; never reuse, never derive.
    """
    return secrets.token_bytes(OPENING_BYTES)


def compute_commitment(*, role: str, basis: str, fp_digest: str, opening: bytes) -> str:
    """Reference commitment function (see the module docstring for the spec).

    Raises :class:`CommitmentLinkageError` (``ROLE_SHAPE``, ``FINGERPRINT_SHAPE``
    or ``OPENING_SHAPE``) on malformed input; ``basis`` must be a committed
    basis (``unavailable`` carries no commitment).
    """
    if type(role) is not str or role not in _ROLES:
        _fail("ROLE_SHAPE")
    if type(basis) is not str or basis not in _BASES or basis == "unavailable":
        _fail("ROLE_SHAPE")
    if type(fp_digest) is not str or not _SHA256_RE.fullmatch(fp_digest):
        _fail("FINGERPRINT_SHAPE")
    if type(opening) is not bytes or len(opening) != OPENING_BYTES:
        _fail("OPENING_SHAPE")
    preimage = (
        _lp(COMMITMENT_DOMAIN)
        + _lp(role.encode("utf-8"))
        + _lp(basis.encode("utf-8"))
        + _lp(FP_SCHEMA)
        + _lp(fp_digest.encode("ascii"))
        + _lp(opening)
    )
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


@dataclass(frozen=True, slots=True)
class LinkageIssuerKeyV1:
    """Caller-pinned issuer verification key for the sidecar signature.

    Take it from the already-verified process record's issuer materials
    (``verification_materials_v0.issuer``): the sidecar is signed by the same
    issuer key as the record it binds. It is never read from the sidecar.
    ``public_key_digest`` is role-separated exactly as for the v0 issuer key.
    """

    key_ref: str
    trust_ring_ref: str
    algorithm: str
    public_key_der_b64: str
    public_key_digest: str


@dataclass(frozen=True, slots=True)
class CommitmentLinkageVerificationContext:
    """Independently supplied expectations for one sidecar verification."""

    expected_process_record_digest: str
    expected_project_ref: str
    expected_build_session_ref: str
    issuer_key: LinkageIssuerKeyV1

    def __post_init__(self) -> None:
        if type(self.expected_process_record_digest) is not str or not _SHA256_RE.fullmatch(
            self.expected_process_record_digest
        ):
            _fail("CONTEXT")
        if type(self.expected_project_ref) is not str or not _PROJECT_REF_RE.fullmatch(
            self.expected_project_ref
        ):
            _fail("CONTEXT")
        if type(self.expected_build_session_ref) is not str or not _REF_RE.fullmatch(
            self.expected_build_session_ref
        ):
            _fail("CONTEXT")
        key = self.issuer_key
        if not isinstance(key, LinkageIssuerKeyV1):
            _fail("CONTEXT")
        for ref in (key.key_ref, key.trust_ring_ref):
            if type(ref) is not str or not _REF_RE.fullmatch(ref):
                _fail("CONTEXT")
        if key.algorithm not in ("ed25519", "ecdsa_p256_sha256"):
            _fail("CONTEXT")
        if type(key.public_key_der_b64) is not str or not key.public_key_der_b64:
            _fail("CONTEXT")
        if type(key.public_key_digest) is not str or not _SHA256_RE.fullmatch(
            key.public_key_digest
        ):
            _fail("CONTEXT")


@dataclass(frozen=True, slots=True)
class VerifiedCommitmentLinkage:
    """Authenticated linkage: signature, record binding and scope all checked.

    Only :func:`verify_commitment_linkage` constructs a meaningful instance.
    A caller-constructed instance is NOT authenticated and no public function
    accepts one for opening; use :func:`verify_and_open_commitment`.
    ``entries`` maps role to ``(role, basis, commitment-or-None)``.
    """

    process_record_digest: str
    unsigned_linkage_digest: str
    entries: tuple[tuple[str, str, str | None], ...]


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


def _role_digest(domain: bytes, projection: Any) -> str:
    try:
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    return "sha256:" + hashlib.sha256(domain + b"\x00" + canonical).hexdigest()


def verify_commitment_linkage(
    envelope: object, *, context: CommitmentLinkageVerificationContext
) -> VerifiedCommitmentLinkage:
    """Verify a sidecar offline: shape, digest, signature, record binding, scope.

    A sidecar issued for certificate A fails ``RECORD_BINDING_MISMATCH`` against
    the digest of certificate B. Success authenticates the linkage only; see
    the module docstring for what an entry does and does not claim.
    """
    if not isinstance(context, CommitmentLinkageVerificationContext):
        _fail("CONTEXT")
    if type(envelope) is not dict:
        _fail("ENVELOPE_SHAPE")
    # Translate to a closed code OUTSIDE any except block so no underlying
    # exception (and its offending value) stays attached as __context__.
    try:
        return _verify(cast(dict[str, Any], envelope), context)
    except CommitmentLinkageError as err:
        code = err.code
    except Exception:
        code = "VERIFICATION_FAILED"
    _fail(code)


def _verify(
    envelope: dict[str, Any], context: CommitmentLinkageVerificationContext
) -> VerifiedCommitmentLinkage:
    try:
        errors = next(iter(_validator().iter_errors(envelope)), None)
    except Exception:
        _fail("SCHEMA")
    if errors is not None:
        _fail("SCHEMA")

    unsigned = envelope["unsigned_linkage"]
    signature = envelope["signature"]

    roles = [entry["role"] for entry in unsigned["entries"]]
    if any(type(role) is not str or role not in _ROLES for role in roles):
        _fail("ROLE_SHAPE")
    if len(set(roles)) != len(roles):
        _fail("DUPLICATE_ROLE")

    digest = _role_digest(UNSIGNED_LINKAGE_DOMAIN, unsigned)
    if signature["unsigned_linkage_digest"] != digest:
        _fail("UNSIGNED_LINKAGE_DIGEST_MISMATCH")

    key = context.issuer_key
    if (
        signature["issuer_key_ref"] != key.key_ref
        or signature["trust_ring_ref"] != key.trust_ring_ref
        or signature["algorithm"] != key.algorithm
    ):
        _fail("KEY_MISMATCH")

    if not (key.public_key_der_b64.isascii() and key.public_key_digest.isascii()):
        _fail("KEY_MATERIAL")
    try:
        public_key = _material_public_key(
            {
                "public_key_der_b64": key.public_key_der_b64,
                "public_key_digest": key.public_key_digest,
                "algorithm": key.algorithm,
            },
            _ISSUER_SPKI_DOMAIN,
        )
    except RelyingPartyVerificationError:
        _fail("KEY_MATERIAL")
    try:
        canonical = cast(str, fp2.canonicalize(unsigned)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    material = ISSUER_SIGNATURE_DOMAIN + b"\x00" + canonical
    try:
        _verify_signature(public_key, signature["algorithm"], material, signature["signature"])
    except RelyingPartyVerificationError:
        _fail("SIGNATURE_INVALID")

    # Binding checks come after authentication so only a genuinely issued
    # sidecar can reach them; all three are exact-equality against caller pins.
    if unsigned["process_record_digest"] != context.expected_process_record_digest:
        _fail("RECORD_BINDING_MISMATCH")
    if (
        unsigned["project_ref"] != context.expected_project_ref
        or unsigned["build_session_ref"] != context.expected_build_session_ref
    ):
        _fail("SCOPE_MISMATCH")

    return VerifiedCommitmentLinkage(
        process_record_digest=unsigned["process_record_digest"],
        unsigned_linkage_digest=digest,
        entries=tuple(
            (entry["role"], entry["basis"], entry.get("commitment"))
            for entry in unsigned["entries"]
        ),
    )


def _open_commitment(
    linkage: VerifiedCommitmentLinkage, *, role: str, fp_digest: str, opening: bytes
) -> str:
    """INTERNAL: open one role's commitment against an AUTHENTICATED linkage.

    Not public: ``VerifiedCommitmentLinkage`` can be constructed by any caller,
    so only :func:`verify_and_open_commitment` (which verifies first) is exported.

    Returns ``COMMITMENT_OPENED_MATCH`` iff ``compute_commitment`` over the
    entry's own role and basis, the supplied ``fp_digest`` and ``opening``
    equals the signed commitment. That is a match against the authenticated
    linkage (a client-declared session-start fingerprint), not proof of
    execution and not recomputation from artifacts. ``COMMITMENT_UNAVAILABLE``
    means the role has no entry or its basis is ``unavailable``. Malformed
    inputs raise a closed :class:`CommitmentLinkageError`; no value is echoed.
    """
    if not isinstance(linkage, VerifiedCommitmentLinkage):
        _fail("CONTEXT")
    if type(role) is not str or role not in _ROLES:
        _fail("ROLE_SHAPE")
    if type(fp_digest) is not str or not _SHA256_RE.fullmatch(fp_digest):
        _fail("FINGERPRINT_SHAPE")
    if type(opening) is not bytes or len(opening) != OPENING_BYTES:
        _fail("OPENING_SHAPE")
    for entry_role, basis, commitment in linkage.entries:
        if entry_role != role:
            continue
        if basis == "unavailable" or commitment is None:
            return COMMITMENT_UNAVAILABLE
        expected = compute_commitment(
            role=entry_role, basis=basis, fp_digest=fp_digest, opening=opening
        )
        if hmac.compare_digest(expected.encode("ascii"), commitment.encode("ascii")):
            return COMMITMENT_OPENED_MATCH
        return COMMITMENT_OPENED_MISMATCH
    return COMMITMENT_UNAVAILABLE


def verify_and_open_commitment(
    envelope: object,
    *,
    context: CommitmentLinkageVerificationContext,
    role: str,
    fp_digest: str,
    opening: bytes,
) -> str:
    """Verify the sidecar, then open one role's commitment (public entry point).

    Runs :func:`verify_commitment_linkage` under the trusted ``context`` and
    only then compares; a result never depends on a caller-built linkage.
    Returns ``COMMITMENT_OPENED_MATCH``, ``COMMITMENT_OPENED_MISMATCH`` or
    ``COMMITMENT_UNAVAILABLE`` (see the module claim scope); failures raise a
    closed :class:`CommitmentLinkageError`.
    """
    linkage = verify_commitment_linkage(envelope, context=context)
    try:
        return _open_commitment(linkage, role=role, fp_digest=fp_digest, opening=opening)
    except CommitmentLinkageError as err:
        code = err.code
    _fail(code)


__all__ = [
    "COMMITMENT_LINKAGE_ERROR_CODES",
    "COMMITMENT_OPENED_MATCH",
    "COMMITMENT_OPENED_MISMATCH",
    "COMMITMENT_UNAVAILABLE",
    "CommitmentLinkageError",
    "CommitmentLinkageVerificationContext",
    "LinkageIssuerKeyV1",
    "VerifiedCommitmentLinkage",
    "compute_commitment",
    "new_opening",
    "verify_and_open_commitment",
    "verify_commitment_linkage",
]
