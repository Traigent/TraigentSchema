# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline relying-party verifier for Agent Certificate v0.

Only public certificate material is consumed here.  The caller must provide
the issuer public key, any client co-attestor public key, expected freshness
and scope bindings, and a pinned policy.  No Backend imports, callbacks,
network access, database access, or private evidence are involved.

The B-v0 seal projection is deliberately opaque: this verifier authenticates
the exact signed seal statement and its fixed stream mapping, but cannot
independently recompute Backend HMAC history or prove ledger completeness,
ordering, or omission resistance from the public roots.

Verification failures expose only stable, content-free error codes.  This is
important because certificate fields may contain customer-controlled strings
and exception text is commonly logged by callers.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, NoReturn, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from jsonschema import Draft7Validator
from referencing import Registry, Resource

import traigent_schema.fp2 as fp2
from traigent_schema.validator import _FORMAT_CHECKER, SchemaDependencyError, SchemaValidator

_CERT_DIR = Path(__file__).resolve().parent.parent / "schemas" / "certification"
_SCHEMAS_DIR = _CERT_DIR.parent
_CERTIFICATE_ENDPOINTS_ID = (
    "https://schemas.traigent.ai/certification/certification_endpoints_v0.json"
)

_AUDIT_DOMAIN = b"traigent.agent_certificate.audit_report.v1"
_CLAIM_MATERIAL_DOMAIN = b"traigent.agent_certificate.claim_material.v1"
_UNSIGNED_DOMAIN = b"traigent.agent_certificate.unsigned_manifest.v1"
_SEAL_DOMAIN = b"traigent.agent_certificate.seal_statement.v1"
_CLIENT_DOMAIN = b"traigent.agent_certificate.client_co_attestation.v0"
_ISSUER_DOMAIN = b"traigent.agent_certificate.issuer_signature.v0"
_SHA256_PREFIX = "sha256:"
_MATERIALS_DOMAIN = b"traigent.agent_certificate.verification_materials.v0"
_ISSUER_SPKI_DOMAIN = b"traigent.agent_certificate.issuer_spki_der.v0"
_CLIENT_SPKI_DOMAIN = b"traigent.agent_certificate.client_spki_der.v0"

_COMPILER_REGISTER_KEYS = (
    "compiler_version",
    "semantics_manifest_digest",
    "claim_template_catalog_digest",
    "prohibited_register_digest",
    "verifier_catalog_digest",
    "non_claim_reason_catalog_digest",
)
_SEMANTICS_KEYS = _COMPILER_REGISTER_KEYS[1:]
_VERIFIER_POLICY_IDS = ("G1",)
_BUILD_LEDGER_CHAIN_SCHEMA_VERSION = "traigent.cert_build_ledger.v0"
_BUILD_LEDGER_STREAM_STATUSES = {
    "decision_stream": "empty_sealed",
    "receipt_event_stream": "sealed",
    "transition_stream": "sealed",
}
_ZERO_DIGEST = _SHA256_PREFIX + "0" * 64
_AUDIT_ROWS = ("B1", "REG1", "C1", "D2", "F1", "G1", "G3")
_ABSTENTION_CODES = {
    "B1": "verifier_not_run_or_not_pass",
    "REG1": "unregistered_claim_id",
    "C1": "verifier_not_run_or_not_pass",
    "D2": "verifier_not_run_or_not_pass",
    "F1": "verifier_not_run_or_not_pass",
    "G1": "verifier_not_run_or_not_pass",
    "G3": "verifier_not_run_or_not_pass",
}
_NON_CLAIMS = (
    ("A3", "tmpl.noncert.a3_no_deployment_binding.v1"),
    ("A4", "tmpl.noncert.a4_no_drift_detection.v1"),
    ("B2", "tmpl.noncert.b2_no_closeout_reconciliation.v1"),
    ("E2", "tmpl.noncert.e2_statistical_validity_suspended.v1"),
    ("E3", "tmpl.noncert.e3_winner_stability_suspended.v1"),
    ("F3", "tmpl.noncert.f3_no_offline_verifiability.v1"),
    ("G2", "tmpl.noncert.g2_no_selective_disclosure.v1"),
    ("H1", "tmpl.noncert.h1_no_criteria_epochs.v1"),
    ("NC_STEP_CAPTURE", "tmpl.noncert.nc_step_capture.v1"),
    ("NC_PRESEAL_RECORDER", "tmpl.noncert.nc_preseal_recorder.v1"),
    ("NC_TIER4_GAPCHECKED", "tmpl.noncert.nc_tier4_gapchecked.v1"),
    ("NC_TARGET_MINIMIZED", "tmpl.noncert.nc_target_minimized.v1"),
    ("NC_CURRENT_ONLINE_FREETEXT", "tmpl.noncert.nc_current_online_freetext.v1"),
    ("NC_BUILD_SESSION_SCOPE", "tmpl.noncert.nc_build_session_scope.v1"),
)
_STREAM_FAMILIES = {
    "decision_stream": "decision",
    "receipt_event_stream": "receipt_event",
    "transition_stream": "transition",
}
_SEALED_STATES = frozenset({"sealed", "empty_sealed"})
_COVERAGE = (
    "subject",
    "seal",
    "claims",
    "tiers",
    "evidence_digests",
    "non_claims",
    "disclosure_profile",
    "privacy_mode",
    "sdk_identity",
    "compiler_register_versions",
    "key_ring_identifiers",
    "freshness",
)
_ECDSA_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_ECDSA_HALF_ORDER = _ECDSA_ORDER // 2
_SIG_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9_-]{8,128}$")


class RelyingPartyVerificationError(ValueError):
    """A fixed-code verification failure that never includes certificate data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


VerificationError = RelyingPartyVerificationError


@dataclass(frozen=True)
class VerificationContext:
    """Fresh, caller-supplied bindings for one relying-party verification."""

    expected_nonce: str
    expected_build_session_ref: str
    expected_issuer_key_ref: str
    expected_issuer_algorithm: str
    expected_trust_ring_ref: str
    expected_client_key_ref: str | None
    expected_client_algorithm: str | None
    client_public_key: object | None = None


@dataclass(frozen=True)
class RelyingPartyPolicy:
    """Explicit pinned compiler-register and verifier expectations.

    Tuples preserve the contract's order and make accidental mutation by a
    caller impossible.  The policy is intentionally not loaded from a file or
    fetched remotely: the relying party owns and pins its trust material.
    """

    compiler_register_versions: tuple[tuple[str, str], ...]
    verifier_bindings: tuple[tuple[str, str, str], ...]

    def __post_init__(self) -> None:
        if type(self.compiler_register_versions) is not tuple or any(
            type(row) is not tuple or len(row) != 2 for row in self.compiler_register_versions
        ):
            raise ValueError("POLICY")
        if tuple(row[0] for row in self.compiler_register_versions) != _COMPILER_REGISTER_KEYS:
            raise ValueError("POLICY")
        if any(
            type(key) is not str or type(value) is not str
            for key, value in self.compiler_register_versions
        ):
            raise ValueError("POLICY")
        if type(self.verifier_bindings) is not tuple or any(
            type(row) is not tuple or len(row) != 3 for row in self.verifier_bindings
        ):
            raise ValueError("POLICY")
        if tuple(row[0] for row in self.verifier_bindings) != _VERIFIER_POLICY_IDS:
            raise ValueError("POLICY")
        if any(any(type(value) is not str for value in row) for row in self.verifier_bindings):
            raise ValueError("POLICY")


@dataclass(frozen=True)
class VerificationResult:
    """Successful result; no certificate content is retained."""

    valid: bool = True
    code: str = "VERIFIED"


@lru_cache(maxsize=1)
def _certificate_validator() -> Draft7Validator:
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    schema = json.loads(
        (_CERT_DIR / "agent_certificate_v0_schema.json").read_text(encoding="utf-8")
    )
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


@lru_cache(maxsize=1)
def _certificate_retrieval_validator() -> Draft7Validator:
    """Validate retrieval wrappers against the canonical endpoint component.

    ``CertificateRetrievalResponseV0`` is defined as an OpenAPI component rather
    than a standalone schema file.  Keep that component authoritative by loading
    it directly from the endpoint catalog and placing the catalog's components in
    a draft-07 resource for local ``#/components`` references.  The registry also
    contains the packaged schemas referenced by the component, so this path cannot
    silently drift into a hand-maintained duplicate wrapper schema.
    """
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))

    catalog = json.loads(
        (_CERT_DIR / "certification_endpoints_v0.json").read_text(encoding="utf-8")
    )
    components = catalog.get("components")
    if type(components) is not dict:
        raise ValueError("CERTIFICATE_RETRIEVAL_SCHEMA")
    catalog_resource = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": _CERTIFICATE_ENDPOINTS_ID,
        "components": components,
    }
    resources.append((_CERTIFICATE_ENDPOINTS_ID, Resource.from_contents(catalog_resource)))
    registry = Registry().with_resources(resources)
    return Draft7Validator(
        {"$ref": _CERTIFICATE_ENDPOINTS_ID + "#/components/schemas/CertificateRetrievalResponseV0"},
        registry=registry,
        format_checker=_FORMAT_CHECKER,
    )


def _fail(code: str) -> NoReturn:
    raise RelyingPartyVerificationError(code)


def _role_digest(role: bytes, document: Any) -> str:
    if type(role) is not bytes or not role or any(byte > 0x7F for byte in role):
        _fail("DIGEST_ROLE")
    try:
        role.decode("ascii")
        canonical = cast(str, fp2.canonicalize(document)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    return _SHA256_PREFIX + hashlib.sha256(role + b"\x00" + canonical).hexdigest()


def _manifest_bytes(manifest: dict[str, Any]) -> bytes:
    if type(manifest) is not dict or any(type(key) is not str for key in manifest):
        _fail("MANIFEST_SHAPE")
    expected = {
        "subject",
        "seal",
        "claims",
        "tiers",
        "evidence_digests",
        "non_claims",
        "privacy_mode",
        "sdk_identity",
        "compiler_register_versions",
        "key_ring_identifiers",
        "freshness",
        "disclosure_profile",
    }
    if set(manifest) != expected:
        _fail("MANIFEST_SHAPE")
    try:
        errors = list(_unsigned_manifest_validator().iter_errors(manifest))
    except Exception:
        _fail("MANIFEST_SCHEMA")
    if errors:
        _fail("MANIFEST_SCHEMA")
    try:
        return cast(str, fp2.canonicalize(manifest)).encode("utf-8")
    except Exception:
        _fail("MANIFEST_NOT_FP2")


@lru_cache(maxsize=1)
def _unsigned_manifest_validator() -> Draft7Validator:
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    schema = json.loads(
        (_CERT_DIR / "certificate_unsigned_manifest_v0_schema.json").read_text(encoding="utf-8")
    )
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


@lru_cache(maxsize=1)
def _verification_materials_validator() -> SchemaValidator:
    return SchemaValidator(contract="backend")


def _material_public_key(projection: dict[str, Any], digest_domain: bytes) -> object:
    encoded = projection["public_key_der_b64"]
    try:
        der = base64.b64decode(encoded.encode("ascii"), validate=True)
        if base64.b64encode(der).decode("ascii") != encoded:
            _fail("MATERIALS_KEY")
        key = serialization.load_der_public_key(der)
        canonical = key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (UnicodeEncodeError, ValueError, TypeError, IndexError, UnsupportedAlgorithm):
        _fail("MATERIALS_KEY")
    if canonical != der:
        _fail("MATERIALS_KEY")
    if (
        projection["public_key_digest"]
        != _SHA256_PREFIX + hashlib.sha256(digest_domain + b"\x00" + der).hexdigest()
    ):
        _fail("MATERIALS_KEY")
    algorithm = projection["algorithm"]
    if algorithm == "ed25519" and not isinstance(key, ed25519.Ed25519PublicKey):
        _fail("MATERIALS_KEY")
    curve = getattr(key, "curve", None)
    if algorithm == "ecdsa_p256_sha256" and (
        not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(curve, ec.SECP256R1)
    ):
        _fail("MATERIALS_KEY")
    return key


def _materials_policy(document: dict[str, Any]) -> RelyingPartyPolicy:
    try:
        policy = document["relying_party_policy"]
        register_versions = policy["compiler_register_versions"]
        registers = tuple((key, register_versions[key]) for key in _COMPILER_REGISTER_KEYS)
        bindings = tuple(
            (
                binding["verifier_id"],
                binding["verifier_ref"],
                binding["verifier_version"],
            )
            for binding in policy["verifier_bindings"]
        )
        return RelyingPartyPolicy(registers, bindings)
    except (KeyError, TypeError, ValueError):
        _fail("MATERIALS_POLICY")


def _check_materials_digest(document: dict[str, Any], expected_materials_digest: str) -> None:
    recomputed = _role_digest(
        _MATERIALS_DOMAIN,
        {key: value for key, value in document.items() if key != "materials_digest"},
    )
    if (
        type(expected_materials_digest) is not str
        or document.get("materials_digest") != expected_materials_digest
        or recomputed != expected_materials_digest
    ):
        _fail("MATERIALS_DIGEST")


def _check_materials_bindings(
    certificate: dict[str, Any],
    document: dict[str, Any],
    certificate_ref: str,
    context: VerificationContext,
) -> None:
    try:
        if document["certificate_ref"] != certificate_ref:
            _fail("CERTIFICATE_REF")
        issuer = document["issuer"]
        unsigned = certificate["signatures"]["unsigned_manifest"]["document"]
        ring = unsigned["key_ring_identifiers"]
        signatures = certificate["signatures"]
        has_claims = bool(unsigned["claims"])
        has_co = "co_attestation" in signatures
        requires_client = has_claims or has_co
        client = document.get("client")
        if requires_client != (client is not None):
            _fail("MATERIALS_BINDING")
        if (
            issuer["key_ref"] != context.expected_issuer_key_ref
            or issuer["algorithm"] != context.expected_issuer_algorithm
            or issuer["trust_ring_ref"] != context.expected_trust_ring_ref
        ):
            _fail("MATERIALS_BINDING")
        if requires_client:
            if (
                not isinstance(client, dict)
                or client["key_ref"] != context.expected_client_key_ref
                or client["algorithm"] != context.expected_client_algorithm
            ):
                _fail("MATERIALS_BINDING")
            co = signatures["co_attestation"]
            client_bindings_match = (
                ring["client_key_ref"] == client["key_ref"]
                and ring["client_signature_algorithm"] == client["algorithm"]
                and co["client_key_ref"] == client["key_ref"]
                and co["algorithm"] == client["algorithm"]
            )
        else:
            if (
                context.expected_client_key_ref is not None
                or context.expected_client_algorithm is not None
                or context.client_public_key is not None
            ):
                _fail("MATERIALS_BINDING")
            client_bindings_match = (
                "client_key_ref" not in ring and "client_signature_algorithm" not in ring
            )
        if (
            ring["issuer_key_ref"] != issuer["key_ref"]
            or ring["issuer_signature_algorithm"] != issuer["algorithm"]
            or ring["trust_ring_ref"] != issuer["trust_ring_ref"]
            or not client_bindings_match
        ):
            _fail("MATERIALS_BINDING")
    except (KeyError, TypeError):
        _fail("MATERIALS_BINDING")


def _check_retrieval_wrapper_bindings(wrapper: dict[str, Any], certificate: dict[str, Any]) -> None:
    """Bind retrieval projections to fields authoritative in the signed envelope.

    The retrieval contract's ``id``, ``tenant_id``, ``project_id``, and
    ``created_at`` are server projection metadata and have no counterpart in
    the signed certificate, so their shape is checked by the canonical
    retrieval schema but they are not compared here.
    """
    try:
        if wrapper["build_session_ref"] != certificate["subject"]["build_session_ref"]:
            _fail("SESSION_REF")
        if wrapper["schema_version"] != certificate["schema_version"]:
            _fail("SCHEMA")
        if (
            wrapper["manifest_digest"]
            != certificate["signatures"]["unsigned_manifest"]["manifest_digest"]
        ):
            _fail("MANIFEST_DIGEST")
    except (KeyError, TypeError):
        _fail("CERTIFICATE_STATUS")


def verify_certificate_with_materials(
    certificate: object,
    verification_materials: object,
    *,
    expected_materials_digest: str,
    certificate_ref: str,
    context: VerificationContext,
    require_status: bool = True,
) -> VerificationResult:
    """Verify a certificate using a validated discovery-materials bundle.

    The caller still supplies the certificate reference and fresh context pins;
    the bundle supplies only the matching public keys and frozen G1 policy.

    By default, ``certificate`` must be the complete retrieval response and its
    status must be ``active`` with null revocation fields.  Passing
    ``require_status=False`` is an explicit opt-out for offline signature-only
    verification of a bare certificate; a supplied retrieval wrapper is still
    checked and cannot bypass revocation status.
    """
    try:
        if not isinstance(context, VerificationContext):
            _fail("CONTEXT")
        if type(require_status) is not bool:
            _fail("CERTIFICATE_STATUS")
        if type(verification_materials) is not dict:
            _fail("MATERIALS_SCHEMA")
        if type(certificate_ref) is not str:
            _fail("ENVELOPE_SHAPE")
        document = cast(dict[str, Any], verification_materials)
        if _verification_materials_validator().validate_json(
            document, "certificate_verification_materials_v0_schema"
        ):
            _fail("MATERIALS_SCHEMA")
        if type(certificate) is not dict:
            _fail("ENVELOPE_SHAPE")
        # These two members are disjoint from the signed certificate envelope,
        # so they are the unambiguous marker for a retrieval wrapper.  A
        # wrapper missing either one still takes the status path and fails its
        # canonical retrieval-schema check rather than being treated as an
        # offline certificate.
        wrapper: dict[str, Any] | None = None
        if "signed_certificate" in certificate or "certificate_status" in certificate:
            wrapper = cast(dict[str, Any], certificate)
            try:
                wrapper_errors = list(_certificate_retrieval_validator().iter_errors(wrapper))
            except Exception:
                _fail("CERTIFICATE_STATUS")
            if wrapper_errors:
                _fail("CERTIFICATE_STATUS")
            status = wrapper.get("certificate_status")
            if (
                not isinstance(status, dict)
                or set(status) != {"status", "revoked_at", "reason"}
                or status.get("status") != "active"
                or status.get("revoked_at") is not None
                or status.get("reason") is not None
            ):
                _fail("CERTIFICATE_STATUS")
            if wrapper.get("certificate_ref") != certificate_ref:
                _fail("CERTIFICATE_REF")
            certificate = wrapper.get("signed_certificate")
        elif require_status:
            _fail("CERTIFICATE_STATUS_UNKNOWN")
        if type(certificate) is not dict:
            _fail("ENVELOPE_SHAPE")
        envelope = cast(dict[str, Any], certificate)
        _check_materials_digest(document, expected_materials_digest)
        _check_materials_bindings(envelope, document, certificate_ref, context)
        issuer_public_key = _material_public_key(document["issuer"], _ISSUER_SPKI_DOMAIN)
        client_projection = document.get("client")
        client_public_key = (
            _material_public_key(client_projection, _CLIENT_SPKI_DOMAIN)
            if client_projection is not None
            else None
        )
        bound_context = replace(context, client_public_key=client_public_key)
        policy = _materials_policy(document)
        result = verify_certificate(
            envelope,
            issuer_public_key=issuer_public_key,
            context=bound_context,
            policy=policy,
        )
        if wrapper is not None:
            _check_retrieval_wrapper_bindings(wrapper, envelope)
        return result
    except (RelyingPartyVerificationError, SchemaDependencyError):
        raise
    except Exception:
        raise RelyingPartyVerificationError("VERIFICATION_FAILED") from None


def _decode_signature(encoded: object) -> bytes:
    if type(encoded) is not str or not _SIG_RE.fullmatch(encoded):
        _fail("SIGNATURE_BASE64")
    encoded_text = cast(str, encoded)
    try:
        raw = base64.b64decode(encoded_text.encode("ascii"), validate=True)
    except UnicodeEncodeError:
        _fail("SIGNATURE_BASE64")
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != encoded_text:
        _fail("SIGNATURE_BASE64")
    return raw


def _client_material(manifest_bytes: bytes) -> bytes:
    if type(manifest_bytes) is not bytes or len(manifest_bytes) >= 2**64:
        _fail("MATERIAL")
    return _CLIENT_DOMAIN + b"\x00" + struct.pack(">Q", len(manifest_bytes)) + manifest_bytes


def _issuer_material(manifest_bytes: bytes, co_raw: bytes = b"") -> bytes:
    if type(manifest_bytes) is not bytes or type(co_raw) is not bytes:
        _fail("MATERIAL")
    if len(manifest_bytes) >= 2**64 or len(co_raw) >= 2**64:
        _fail("MATERIAL")
    return (
        _ISSUER_DOMAIN
        + b"\x00"
        + struct.pack(">Q", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(co_raw))
        + co_raw
    )


def _verify_signature(
    public_key: object, algorithm: object, material: bytes, encoded: object
) -> None:
    if algorithm not in {"ed25519", "ecdsa_p256_sha256"}:
        _fail("ALGORITHM")
    raw = _decode_signature(encoded)
    try:
        if algorithm == "ed25519":
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                _fail("KEY_ALGORITHM")
            cast(ed25519.Ed25519PublicKey, public_key).verify(raw, material)
            return
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            _fail("KEY_ALGORITHM")
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        if not 1 <= r < _ECDSA_ORDER or not 1 <= s < _ECDSA_ORDER:
            _fail("SIGNATURE_SCALAR")
        if s > _ECDSA_HALF_ORDER:
            _fail("SIGNATURE_HIGH_S")
        cast(ec.EllipticCurvePublicKey, public_key).verify(
            utils.encode_dss_signature(r, s), material, ec.ECDSA(hashes.SHA256())
        )
    except RelyingPartyVerificationError:
        raise
    except (InvalidSignature, ValueError):
        _fail("SIGNATURE_INVALID")
    except Exception:
        _fail("VERIFICATION_FAILED")


def _compute_seal_digest(seal: dict[str, Any]) -> str:
    if type(seal) is not dict or set(seal) != {
        "seal_ref",
        "chain_schema_version",
        "build_session_ref",
        "expected_stream_projection",
        "seal_statement_digest",
    }:
        _fail("SEAL_DIGEST")
    projection = dict(seal)
    projection.pop("seal_statement_digest")
    try:
        encoded = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("SEAL_DIGEST")
    return _SHA256_PREFIX + hashlib.sha256(_SEAL_DOMAIN + b"\x00" + encoded).hexdigest()


def _check_streams(seal: dict[str, Any]) -> None:
    if seal.get("chain_schema_version") != _BUILD_LEDGER_CHAIN_SCHEMA_VERSION:
        _fail("LEDGER_PROFILE")
    if seal.get("seal_statement_digest") != _compute_seal_digest(seal):
        _fail("SEAL_DIGEST")
    projection = seal.get("expected_stream_projection")
    if type(projection) is not dict or set(projection) != set(_STREAM_FAMILIES):
        _fail("LEDGER_STREAM")
    projection_dict = cast(dict[str, Any], projection)
    for name, family in _STREAM_FAMILIES.items():
        stream = projection_dict[name]
        if (
            type(stream) is not dict
            or stream.get("stream_family") != family
            or stream.get("chain_status") != _BUILD_LEDGER_STREAM_STATUSES[name]
            or "root_commitment" not in stream
            or stream["root_commitment"] == _ZERO_DIGEST
        ):
            _fail("LEDGER_STREAM")


def _claim_material(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "claim_id": claim["claim_id"],
        "tier": claim["tier"],
        "payload": claim["payload"],
        "verifier": claim["verifier"],
        "evidence_refs": [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] != "audit_report_digest"
        ],
    }


def _check_policy(
    certificate: dict[str, Any], unsigned: dict[str, Any], policy: RelyingPartyPolicy
) -> None:
    if not isinstance(policy, RelyingPartyPolicy):
        _fail("POLICY")
    expected = dict(policy.compiler_register_versions)
    if unsigned["compiler_register_versions"] != expected:
        _fail("POLICY")
    if {key: certificate["semantics"][key] for key in _SEMANTICS_KEYS} != {
        key: expected[key] for key in _SEMANTICS_KEYS
    }:
        _fail("POLICY")
    allowed = {row[0]: (row[1], row[2]) for row in policy.verifier_bindings}
    for claim in certificate["claims"]:
        try:
            verifier = claim["verifier"]
            expected_verifier = allowed[claim["claim_id"]]
        except (KeyError, TypeError):
            _fail("POLICY")
        if (verifier["verifier_id"], verifier["verifier_version"]) != expected_verifier:
            _fail("POLICY")


def _check_projections(
    certificate: dict[str, Any], unsigned: dict[str, Any], audit_digest: str
) -> None:
    for key, code in (
        ("subject", "SUBJECT_BINDING"),
        ("seal", "SEAL_BINDING"),
        ("claims", "CLAIMS_BINDING"),
        ("non_claims", "NON_CLAIMS_BINDING"),
        ("disclosure_profile", "DISCLOSURE_PROFILE_BINDING"),
    ):
        if unsigned[key] != certificate["ledger_seal_projection" if key == "seal" else key]:
            _fail(code)
    if (
        certificate["subject"]["build_session_ref"]
        != certificate["ledger_seal_projection"]["build_session_ref"]
    ):
        _fail("SESSION_REF")
    expected_non_claims = [
        {"record_type": "non_claim", "non_claim_id": ident, "reason_template_id": template}
        for ident, template in _NON_CLAIMS
    ]
    if certificate["non_claims"] != expected_non_claims:
        _fail("NON_CLAIMS")
    expected_tiers = [
        {"claim_id": claim["claim_id"], "tier": claim["tier"]} for claim in certificate["claims"]
    ]
    if unsigned["tiers"] != expected_tiers:
        _fail("TIERS")
    expected_evidence = [{"evidence_kind": "audit_report_digest", "evidence_digest": audit_digest}]
    seen = {("audit_report_digest", audit_digest)}
    for claim in certificate["claims"]:
        for ref in claim["evidence_refs"]:
            marker = (ref["evidence_kind"], ref["evidence_digest"])
            if marker not in seen:
                seen.add(marker)
                expected_evidence.append(dict(ref))
    if unsigned["evidence_digests"] != expected_evidence:
        _fail("EVIDENCE_PROJECTION")


def _check_printed_claims(
    certificate: dict[str, Any], audit: dict[str, Any], audit_digest: str
) -> dict[str, dict[str, Any]]:
    claims = certificate["claims"]
    by_id = {claim["claim_id"]: claim for claim in claims}
    if len(by_id) != len(claims) or set(by_id) - {"G1"}:
        _fail("CLAIM_ID")
    for claim in claims:
        audit_refs = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] == "audit_report_digest"
        ]
        if len(audit_refs) != 1 or audit_refs[0]["evidence_digest"] != audit_digest:
            _fail("AUDIT_BINDING")
        if claim["tier"] != 1 or claim["verifier"]["result"] != "PASS":
            _fail("CLAIM_STATUS")
        params = claim["payload"]["params"]
        root = params["manifest_root_digest"]
        if root == _ZERO_DIGEST or root != audit["client_evidence_manifest_root"]:
            _fail("CLIENT_ROOT")
        refs = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] != "audit_report_digest"
        ]
        if (
            len(refs) != 1
            or refs[0]["evidence_kind"] != "client_commitment_digest"
            or refs[0]["evidence_digest"] != root
        ):
            _fail("CLIENT_ROOT")
    return by_id


def _check_audit_rows(audit: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> None:
    rows = audit["claim_support_rows"]
    if [row["claim_id"] for row in rows] != list(_AUDIT_ROWS):
        _fail("AUDIT_ROWS")
    for row in rows:
        if row["claim_id"] == "D2" and (
            row["support_status"] != "abstained"
            or row["abstention_code"] != _ABSTENTION_CODES["D2"]
        ):
            _fail("AUDIT_STATUS")
        claim = by_id.get(row["claim_id"])
        if claim is None:
            if (
                row["support_status"] != "abstained"
                or row["abstention_code"] != _ABSTENTION_CODES[row["claim_id"]]
            ):
                _fail("AUDIT_STATUS")
        else:
            if row["support_status"] != "supported" or row["verifier"] != claim["verifier"]:
                _fail("AUDIT_STATUS")
            if row["claim_material_digest"] != _role_digest(
                _CLAIM_MATERIAL_DOMAIN, _claim_material(claim)
            ):
                _fail("CLAIM_MATERIAL")


def _check_audit_bindings(
    certificate: dict[str, Any],
    unsigned: dict[str, Any],
    audit: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
) -> None:
    if audit["build_session_ref"] != certificate["subject"]["build_session_ref"]:
        _fail("SESSION_REF")
    if (
        audit["ledger_seal_statement_digest"]
        != certificate["ledger_seal_projection"]["seal_statement_digest"]
    ):
        _fail("SEAL_DIGEST")
    if audit["compiler_register_versions"] != unsigned["compiler_register_versions"]:
        _fail("COMPILER_REGISTERS")
    if "G1" in by_id:
        if (
            audit["client_evidence_manifest_root"]
            != by_id["G1"]["payload"]["params"]["manifest_root_digest"]
        ):
            _fail("CLIENT_ROOT")
    elif audit["client_evidence_manifest_root"] is not None:
        _fail("CLIENT_ROOT")


def _check_claims_and_audit(
    certificate: dict[str, Any], unsigned: dict[str, Any], audit: dict[str, Any], audit_digest: str
) -> None:
    by_id = _check_printed_claims(certificate, audit, audit_digest)
    _check_audit_rows(audit, by_id)
    _check_audit_bindings(certificate, unsigned, audit, by_id)


def _check_context(
    unsigned: dict[str, Any], signatures: dict[str, Any], context: VerificationContext
) -> None:
    if not isinstance(context, VerificationContext):
        _fail("CONTEXT")
    ring = unsigned["key_ring_identifiers"]
    issuer = signatures["issuer_signature"]
    if not (
        context.expected_nonce == unsigned["freshness"]["nonce"]
        and context.expected_build_session_ref == unsigned["subject"]["build_session_ref"]
        and context.expected_issuer_key_ref == ring["issuer_key_ref"]
        and context.expected_issuer_algorithm == ring["issuer_signature_algorithm"]
        and context.expected_trust_ring_ref == ring["trust_ring_ref"]
        and issuer["issuer_key_ref"] == ring["issuer_key_ref"]
        and issuer["algorithm"] == ring["issuer_signature_algorithm"]
        and issuer["trust_ring_ref"] == ring["trust_ring_ref"]
    ):
        _fail("CONTEXT")
    has_client = "client_key_ref" in ring
    if has_client != ("client_signature_algorithm" in ring):
        _fail("KEY_RING")
    if has_client:
        if (
            context.expected_client_key_ref != ring["client_key_ref"]
            or context.expected_client_algorithm != ring["client_signature_algorithm"]
        ):
            _fail("CONTEXT")
    elif (
        context.expected_client_key_ref is not None or context.expected_client_algorithm is not None
    ):
        _fail("CLIENT_KEY_CONTEXT")


def _validated_document(
    certificate: object, policy: RelyingPartyPolicy
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], bytes, str, str]:
    if type(certificate) is not dict:
        _fail("ENVELOPE_SHAPE")
    try:
        if list(_certificate_validator().iter_errors(certificate)):
            _fail("SCHEMA")
    except RelyingPartyVerificationError:
        raise
    except Exception:
        _fail("SCHEMA")
    document = cast(dict[str, Any], certificate)
    signatures = document["signatures"]
    unsigned_ref = signatures["unsigned_manifest"]
    unsigned = unsigned_ref["document"]
    manifest_bytes = _manifest_bytes(unsigned)
    expected_manifest_digest = _role_digest(_UNSIGNED_DOMAIN, unsigned)
    audit = document["audit_report"]
    audit_digest = _role_digest(_AUDIT_DOMAIN, audit)
    if unsigned_ref["manifest_digest"] != expected_manifest_digest:
        _fail("MANIFEST_DIGEST")
    _check_policy(document, unsigned, policy)
    if tuple(unsigned_ref["coverage"]) != _COVERAGE:
        _fail("COVERAGE")
    if audit["build_session_ref"] != document["subject"]["build_session_ref"]:
        _fail("SESSION_REF")
    if (
        audit["ledger_seal_statement_digest"]
        != document["ledger_seal_projection"]["seal_statement_digest"]
    ):
        _fail("SEAL_DIGEST")
    if document["semantics"] != {
        key: unsigned["compiler_register_versions"][key] for key in document["semantics"]
    }:
        _fail("SEMANTICS")
    if document["disclosure_profile"] != unsigned["disclosure_profile"]:
        _fail("DISCLOSURE_PROFILE")
    _check_streams(document["ledger_seal_projection"])
    _check_projections(document, unsigned, audit_digest)
    _check_claims_and_audit(document, unsigned, audit, audit_digest)
    return document, signatures, unsigned, manifest_bytes, expected_manifest_digest, audit_digest


def _verify_co_attestation(
    document: dict[str, Any],
    signatures: dict[str, Any],
    unsigned: dict[str, Any],
    manifest_bytes: bytes,
    expected_manifest_digest: str,
    context: VerificationContext,
) -> tuple[bytes, list[str]]:
    has_claims = bool(document["claims"])
    has_co = "co_attestation" in signatures
    if has_claims != has_co:
        _fail("CO_REQUIRED" if has_claims else "CO_ZERO_CLAIMS")
    if not has_claims and (
        any(
            key in unsigned["key_ring_identifiers"]
            for key in ("client_key_ref", "client_signature_algorithm")
        )
        or context.expected_client_key_ref is not None
        or context.expected_client_algorithm is not None
        or context.client_public_key is not None
    ):
        _fail("CLIENT_KEY_CONTEXT")
    if not has_co:
        return b"", ["unsigned_manifest"]
    co = signatures["co_attestation"]
    if context.client_public_key is None:
        _fail("CLIENT_KEY_REQUIRED")
    if co["client_key_ref"] != unsigned["key_ring_identifiers"]["client_key_ref"]:
        _fail("KEY_REF")
    if (
        co["algorithm"] != unsigned["key_ring_identifiers"]["client_signature_algorithm"]
        or co["algorithm"] != context.expected_client_algorithm
    ):
        _fail("ALGORITHM")
    if co["nonce"] != unsigned["freshness"]["nonce"] or co["nonce"] != context.expected_nonce:
        _fail("NONCE")
    if co["signed_manifest_digest"] != expected_manifest_digest:
        _fail("MANIFEST_DIGEST")
    co_raw = _decode_signature(co["signature"])
    if (
        co["algorithm"] == "ecdsa_p256_sha256"
        and int.from_bytes(co_raw[32:], "big") > _ECDSA_HALF_ORDER
    ):
        _fail("CLIENT_SIGNATURE_NON_CANONICAL")
    _verify_signature(
        context.client_public_key,
        co["algorithm"],
        _client_material(manifest_bytes),
        co["signature"],
    )
    return co_raw, ["unsigned_manifest", "co_attestation"]


def _verify(
    certificate: object,
    issuer_public_key: object,
    context: VerificationContext,
    policy: RelyingPartyPolicy,
) -> None:
    document, signatures, unsigned, manifest_bytes, manifest_digest, _ = _validated_document(
        certificate, policy
    )
    _check_context(unsigned, signatures, context)
    co_raw, expected_payload = _verify_co_attestation(
        document, signatures, unsigned, manifest_bytes, manifest_digest, context
    )
    issuer_signature = signatures["issuer_signature"]
    if issuer_signature["signed_payload"] != expected_payload:
        _fail("SIGNED_PAYLOAD")
    _verify_signature(
        issuer_public_key,
        issuer_signature["algorithm"],
        _issuer_material(manifest_bytes, co_raw),
        issuer_signature["signature"],
    )


def verify_certificate(
    certificate: object,
    *,
    issuer_public_key: object,
    context: VerificationContext,
    policy: RelyingPartyPolicy,
) -> VerificationResult:
    """Verify an Agent Certificate v0 envelope entirely offline."""

    try:
        _verify(certificate, issuer_public_key, context, policy)
    except RelyingPartyVerificationError:
        raise
    except Exception:
        raise RelyingPartyVerificationError("VERIFICATION_FAILED") from None
    return VerificationResult()


verify = verify_certificate
verify_agent_certificate = verify_certificate

__all__ = [
    "RelyingPartyPolicy",
    "RelyingPartyVerificationError",
    "VerificationContext",
    "VerificationError",
    "VerificationResult",
    "verify_certificate",
    "verify_agent_certificate",
    "verify_certificate_with_materials",
    "verify",
]
