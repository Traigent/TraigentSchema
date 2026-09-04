# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline relying-party verifier for Agent Certificate v0.

Only public certificate material is consumed here.  The caller must provide
the issuer public key, any client co-attestor public key, expected freshness
and scope bindings, and a pinned policy.  No Backend imports, callbacks,
network access, database access, or private evidence are involved.

The B-v0 seal projection is deliberately opaque: the optional B1 assertion
authenticates the exact issuer-signed seal statement and fixed stream
mapping, but cannot independently recompute Backend HMAC history or prove
ledger completeness, ordering, or omission resistance from public roots.

Verification failures expose only stable, content-free error codes.  This is
important because certificate fields may contain customer-controlled strings
and exception text is commonly logged by callers.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource
from referencing.exceptions import CannotDetermineSpecification, Unresolvable
from referencing.jsonschema import UnknownDialect

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
_CLIENT_CERTIFICATE_DOMAIN = b"traigent.agent_certificate.client_certificate_projection.v0"
_ISSUER_DOMAIN = b"traigent.agent_certificate.issuer_signature.v0"
_SHA256_PREFIX = "sha256:"
_MATERIALS_DOMAIN = b"traigent.agent_certificate.verification_materials.v0"
_ISSUER_SPKI_DOMAIN = b"traigent.agent_certificate.issuer_spki_der.v0"
_CLIENT_SPKI_DOMAIN = b"traigent.agent_certificate.client_spki_der.v0"
_CLIENT_KEY_REF_DOMAIN = b"traigent.agent_certificate.client_key_ref.v0"

_COMPILER_REGISTER_KEYS = (
    "compiler_version",
    "semantics_manifest_digest",
    "claim_template_catalog_digest",
    "prohibited_register_digest",
    "verifier_catalog_digest",
    "non_claim_reason_catalog_digest",
)
_SEMANTICS_KEYS = _COMPILER_REGISTER_KEYS[1:]
_VERIFIER_POLICY_IDS = ("B1", "G1")
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
_CLIENT_KEY_REF_RE = re.compile(r"^ckr:[A-Za-z0-9_-]{43}$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
_SEMVER_RE = re.compile(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$")
_VERIFIER_ID_RE = re.compile(r"^ver\.cert\.[a-z0-9_]{1,64}$")
_NONCE_RE = re.compile(r"^[a-f0-9]{32,64}$")
_PRIVACY_MODES = frozenset({"offline", "current_online"})
_DISCLOSURE_PROFILE_IDS = frozenset({"public", "customer_internal", "auditor_only"})
_SIGNATURE_ALGORITHMS = frozenset({"ed25519", "ecdsa_p256_sha256"})
_COMMITMENT_SCHEMES = frozenset({"sha256_secret_blinded_v1"})

_CLIENT_CO_ATTESTATION_PIN_BINDINGS = (
    ("expected_project_ref", "subject.project_ref"),
    ("expected_build_session_ref", "subject.build_session_ref"),
    ("expected_session_commitment_digest", "subject.session_commitment_digest"),
    ("expected_nonce", "unsigned.freshness.nonce"),
    ("expected_privacy_mode", "unsigned.privacy_mode.declared_mode"),
    ("expected_sdk_ref", "unsigned.sdk_identity.sdk_ref"),
    ("expected_sdk_version", "unsigned.sdk_identity.sdk_version"),
    ("expected_disclosure_profile_id", "unsigned.disclosure_profile.profile_id"),
    ("expected_issuer_key_ref", "unsigned.key_ring_identifiers.issuer_key_ref"),
    ("expected_trust_ring_ref", "unsigned.key_ring_identifiers.trust_ring_ref"),
    (
        "expected_issuer_algorithm",
        "unsigned.key_ring_identifiers.issuer_signature_algorithm",
    ),
    (
        "expected_compiler_register_versions",
        "unsigned.compiler_register_versions",
    ),
    ("expected_g1_verifier_id", "g1.verifier.verifier_id"),
    ("expected_g1_verifier_version", "g1.verifier.verifier_version"),
    ("manifest_root_digest", "g1.payload.params.manifest_root_digest"),
    ("commitment_scheme", "g1.payload.params.commitment_scheme"),
    ("client_attestor_version", "g1.payload.params.client_attestor_version"),
    (
        "expected_client_algorithm",
        "unsigned.key_ring_identifiers.client_signature_algorithm",
    ),
    ("client_public_key", "unsigned.key_ring_identifiers.client_key_ref"),
)
CLIENT_CO_ATTESTATION_CONTEXT_FIELDS = tuple(
    field_name for field_name, _ in _CLIENT_CO_ATTESTATION_PIN_BINDINGS
)

# Public preparation exposes only this closed, content-free failure vocabulary.
CLIENT_CO_ATTESTATION_ERROR_CODES = frozenset(
    {"CO_CONTEXT", "CO_G1_REQUIRED", "CO_PROJECTION", "CO_SCHEMA_DEPENDENCY"}
)

# Structural ownership partitions.  Tests compare these sets with the packaged
# schemas so a newly added unsigned-manifest, subject, or G1 parameter cannot
# silently escape client pinning or explicit issuer/compiler classification.
_UNSIGNED_MANIFEST_CLIENT_PINNED_SECTIONS = frozenset(
    {
        "subject",
        "disclosure_profile",
        "privacy_mode",
        "sdk_identity",
        "compiler_register_versions",
        "key_ring_identifiers",
        "freshness",
    }
)
_UNSIGNED_MANIFEST_ISSUER_EVIDENCE_SECTIONS = frozenset(
    {"seal", "claims", "tiers", "evidence_digests", "non_claims"}
)
_UNSIGNED_MANIFEST_NESTED_LEAF_OWNERSHIP: Mapping[
    str, Mapping[str, frozenset[str]]
] = MappingProxyType(
    {
        "subject": MappingProxyType(
            {
                "client_pinned": frozenset(
                    {"project_ref", "build_session_ref", "session_commitment_digest"}
                ),
                "schema_owned_constant": frozenset({"subject_kind", "hash_algorithm"}),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "disclosure_profile": MappingProxyType(
            {
                "client_pinned": frozenset({"profile_id"}),
                "schema_owned_constant": frozenset({"selective_disclosure_line"}),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "privacy_mode": MappingProxyType(
            {
                "client_pinned": frozenset({"declared_mode"}),
                "schema_owned_constant": frozenset(),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "sdk_identity": MappingProxyType(
            {
                "client_pinned": frozenset({"sdk_ref", "sdk_version"}),
                "schema_owned_constant": frozenset(),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "compiler_register_versions": MappingProxyType(
            {
                "client_pinned": frozenset(_COMPILER_REGISTER_KEYS),
                "schema_owned_constant": frozenset(),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "key_ring_identifiers": MappingProxyType(
            {
                "client_pinned": frozenset(
                    {
                        "issuer_key_ref",
                        "trust_ring_ref",
                        "issuer_signature_algorithm",
                        "client_key_ref",
                        "client_signature_algorithm",
                    }
                ),
                "schema_owned_constant": frozenset(),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
        "freshness": MappingProxyType(
            {
                "client_pinned": frozenset({"nonce"}),
                "schema_owned_constant": frozenset(),
                "issuer_compiler_evidence": frozenset(),
            }
        ),
    }
)
_UNSIGNED_MANIFEST_CLIENT_PINNED_LEAF_PATHS = frozenset(
    f"{section}.{field}"
    for section, ownership in _UNSIGNED_MANIFEST_NESTED_LEAF_OWNERSHIP.items()
    for field in ownership["client_pinned"]
)
_UNSIGNED_MANIFEST_SCHEMA_CONSTANT_LEAF_PATHS = frozenset(
    f"{section}.{field}"
    for section, ownership in _UNSIGNED_MANIFEST_NESTED_LEAF_OWNERSHIP.items()
    for field in ownership["schema_owned_constant"]
)
_SUBJECT_CLIENT_PINNED_FIELDS = _UNSIGNED_MANIFEST_NESTED_LEAF_OWNERSHIP["subject"][
    "client_pinned"
]
_SUBJECT_SCHEMA_CONSTANT_FIELDS = _UNSIGNED_MANIFEST_NESTED_LEAF_OWNERSHIP["subject"][
    "schema_owned_constant"
]
_G1_CLIENT_PINNED_PARAM_FIELDS = frozenset(
    {
        "manifest_root_digest",
        "commitment_scheme",
        "client_attestor_version",
        "build_session_ref",
        "client_key_ref",
    }
)
_G1_CLIENT_PINNED_VERIFIER_FIELDS = frozenset({"verifier_id", "verifier_version"})
_G1_SCHEMA_CONSTANT_VERIFIER_FIELDS = frozenset({"result"})
_G1_CROSS_BOUND_PARAM_PATHS = {
    "build_session_ref": "subject.build_session_ref",
    "client_key_ref": "unsigned.key_ring_identifiers.client_key_ref",
}


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
    expected_project_ref: str
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
    """Successful result; no certificate content is retained.

    ``status_evidence`` is deliberately a plain closed-vocabulary string so a
    signature-only result cannot be confused with one that also inspected an
    issuer-supplied status snapshot.
    """

    valid: bool = True
    code: str = "VERIFIED_SIGNATURE_ONLY"
    status_evidence: str = "not_checked"

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ValueError("VERIFICATION_RESULT")
        if (self.code, self.status_evidence) not in (
            ("VERIFIED_SIGNATURE_ONLY", "not_checked"),
            ("VERIFIED", "issuer_status_snapshot"),
        ):
            raise ValueError("VERIFICATION_RESULT")


@dataclass(frozen=True, slots=True)
class ClientCertificateProjection:
    """Prepared, content-free input for a client's co-attestation.

    ``projection`` is a defensive, mutable copy for callers that need to add
    the co-attestation after signing.  The canonical bytes and digest are
    independent immutable values, so mutating that copy cannot change the
    bytes that were prepared.  This object never accepts a private key and
    performs no signing, network access, writes, or external-state changes.
    """

    projection: dict[str, Any]
    projection_bytes: bytes
    signing_bytes: bytes
    signed_manifest_digest: str


@dataclass(frozen=True, slots=True)
class ClientCoAttestationContext:
    """Client-owned expectations that must match before signing a prepare response.

    Only public verification material is accepted.  The helper derives the
    project-scoped key reference from ``client_public_key``; callers cannot ask
    it to trust an independently supplied key reference.  Compiler/register
    pins are an immutable tuple of tuples in the contract's canonical order.
    """

    expected_project_ref: str
    expected_build_session_ref: str
    expected_session_commitment_digest: str
    expected_nonce: str
    expected_privacy_mode: str
    expected_sdk_ref: str
    expected_sdk_version: str
    expected_disclosure_profile_id: str
    expected_issuer_key_ref: str
    expected_trust_ring_ref: str
    expected_issuer_algorithm: str
    expected_compiler_register_versions: tuple[tuple[str, str], ...]
    expected_g1_verifier_id: str
    expected_g1_verifier_version: str
    manifest_root_digest: str
    commitment_scheme: str
    client_attestor_version: str
    expected_client_algorithm: str
    client_public_key: object

    def __post_init__(self) -> None:
        patterned_values = (
            (self.expected_project_ref, _PROJECT_REF_RE),
            (self.expected_build_session_ref, _REF_RE),
            (self.expected_session_commitment_digest, _SHA256_RE),
            (self.expected_nonce, _NONCE_RE),
            (self.expected_sdk_ref, _GIT_SHA_RE),
            (self.expected_sdk_version, _SEMVER_RE),
            (self.expected_issuer_key_ref, _REF_RE),
            (self.expected_trust_ring_ref, _REF_RE),
            (self.expected_g1_verifier_id, _VERIFIER_ID_RE),
            (self.expected_g1_verifier_version, _SEMVER_RE),
            (self.manifest_root_digest, _SHA256_RE),
            (self.client_attestor_version, _SEMVER_RE),
        )
        if any(
            type(value) is not str or not pattern.fullmatch(value)
            for value, pattern in patterned_values
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if (
            type(self.expected_privacy_mode) is not str
            or self.expected_privacy_mode not in _PRIVACY_MODES
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if (
            type(self.expected_disclosure_profile_id) is not str
            or self.expected_disclosure_profile_id not in _DISCLOSURE_PROFILE_IDS
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if (
            type(self.commitment_scheme) is not str
            or self.commitment_scheme not in _COMMITMENT_SCHEMES
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if (
            type(self.expected_issuer_algorithm) is not str
            or self.expected_issuer_algorithm not in _SIGNATURE_ALGORITHMS
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if (
            type(self.expected_client_algorithm) is not str
            or self.expected_client_algorithm not in _SIGNATURE_ALGORITHMS
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        registers = self.expected_compiler_register_versions
        if type(registers) is not tuple or any(
            type(row) is not tuple or len(row) != 2 for row in registers
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if tuple(row[0] for row in registers) != _COMPILER_REGISTER_KEYS:
            raise RelyingPartyVerificationError("CO_CONTEXT")
        if any(type(key) is not str or type(value) is not str for key, value in registers):
            raise RelyingPartyVerificationError("CO_CONTEXT")
        register_values = dict(registers)
        register_patterns = {
            key: _SEMVER_RE if key == "compiler_version" else _SHA256_RE
            for key in _COMPILER_REGISTER_KEYS
        }
        if any(
            not register_patterns[key].fullmatch(register_values[key])
            for key in _COMPILER_REGISTER_KEYS
        ):
            raise RelyingPartyVerificationError("CO_CONTEXT")


def derive_client_key_ref(
    project_ref: str, signature_algorithm: str, client_public_key: object
) -> str:
    """Derive the project-scoped client key reference from canonical public material.

    This is intentionally public so SDK/Backend consumers share one exact formula.
    It accepts only the two registered key algorithms and canonical SPKI DER; no
    private key or certificate content is involved.
    """
    if type(project_ref) is not str or not _PROJECT_REF_RE.fullmatch(project_ref):
        _fail("CLIENT_KEY_REF")
    if type(signature_algorithm) is not str or signature_algorithm not in _SIGNATURE_ALGORITHMS:
        _fail("CLIENT_KEY_REF")
    if signature_algorithm == "ed25519" and not isinstance(
        client_public_key, ed25519.Ed25519PublicKey
    ):
        _fail("CLIENT_KEY_REF")
    if signature_algorithm == "ecdsa_p256_sha256" and (
        not isinstance(client_public_key, ec.EllipticCurvePublicKey)
        or not isinstance(client_public_key.curve, ec.SECP256R1)
    ):
        _fail("CLIENT_KEY_REF")
    verified_public_key = cast(
        ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey, client_public_key
    )
    try:
        spki = verified_public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception:
        _fail("CLIENT_KEY_REF")
    digest = hashlib.sha256(
        _length_prefixed_fields(
            _CLIENT_KEY_REF_DOMAIN,
            project_ref.encode("utf-8"),
            signature_algorithm.encode("ascii"),
            spki,
        )
    ).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    result = "ckr:" + encoded
    if not _CLIENT_KEY_REF_RE.fullmatch(result):
        _fail("CLIENT_KEY_REF")
    return result


@lru_cache(maxsize=1)
def _g1_template_text() -> str:
    """Read the sole G1 sentence from the canonical Schema template catalog."""
    try:
        catalog = json.loads(
            (_CERT_DIR / "certificate_claim_templates_v0_schema.json").read_text(encoding="utf-8")
        )
        return cast(
            str,
            catalog["definitions"]["TemplateG1V2"]["properties"]["template_text"]["const"],
        )
    except Exception:
        _fail("CLAIM_RENDERING")


def _render_g1_text(params: dict[str, Any]) -> str:
    try:
        return _g1_template_text().format(
            manifest_root_digest=params["manifest_root_digest"],
            commitment_scheme=params["commitment_scheme"],
            client_attestor_version=params["client_attestor_version"],
        )
    except (KeyError, ValueError):
        _fail("CLAIM_RENDERING")


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
def _certificate_preparation_validator() -> Draft7Validator:
    """Validate the exact issuer-signed projection returned by ``prepare``.

    The final certificate schema conditionally requires ``co_attestation``
    for G1/tier-1 claims.  The prepare response is intentionally the same
    closed envelope with that one outer member absent, so it has its own
    canonical endpoint component rather than an ad-hoc partial validator.
    """
    resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            try:
                resource = Resource.from_contents(document)
            except (CannotDetermineSpecification, UnknownDialect) as error:
                raise SchemaDependencyError("CERTIFICATE_PREPARATION_SCHEMA") from error
            resources.append((document["$id"], resource))
    catalog = json.loads(
        (_CERT_DIR / "certification_endpoints_v0.json").read_text(encoding="utf-8")
    )
    if type(catalog) is not dict:
        raise SchemaDependencyError("CERTIFICATE_PREPARATION_SCHEMA")
    components = catalog.get("components")
    if (
        type(components) is not dict
        or type(components.get("schemas")) is not dict
        or type(components["schemas"].get("PrepareResponseV0")) is not dict
    ):
        raise SchemaDependencyError("CERTIFICATE_PREPARATION_SCHEMA")
    try:
        Draft7Validator.check_schema(components["schemas"]["PrepareResponseV0"])
    except SchemaError as error:
        raise SchemaDependencyError("CERTIFICATE_PREPARATION_SCHEMA") from error
    catalog_resource = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": _CERTIFICATE_ENDPOINTS_ID,
        "components": components,
    }
    try:
        catalog_resource_entry = Resource.from_contents(catalog_resource)
    except (CannotDetermineSpecification, UnknownDialect) as error:
        raise SchemaDependencyError("CERTIFICATE_PREPARATION_SCHEMA") from error
    resources.append((_CERTIFICATE_ENDPOINTS_ID, catalog_resource_entry))
    registry = Registry().with_resources(resources)
    return Draft7Validator(
        {"$ref": _CERTIFICATE_ENDPOINTS_ID + "#/components/schemas/PrepareResponseV0"},
        registry=registry,
        format_checker=_FORMAT_CHECKER,
    )


# Conservative upper bound for every schema-valid PrepareResponseV0.  The
# variable portion is bounded by the packaged schemas: at most 1,024 evidence
# projection entries (each <= 384 compact-JSON bytes), plus 16 claims in each
# of the printed and signed-manifest copies (each <= 2,048 bytes).  The closed
# envelope, audit, non-claims, signatures, keys, punctuation, and array commas
# fit within the remaining 64 KiB.  Tests construct the max-cardinality,
# max-length shape and independently prove every component bound.
_MAX_SCHEMA_EVIDENCE_PROJECTION_ITEMS = 1_024
_MAX_SCHEMA_EVIDENCE_REF_BYTES = 384
_MAX_SCHEMA_CLAIMS = 16
_MAX_SCHEMA_CLAIM_BYTES = 2_048
_MAX_SCHEMA_FIXED_PREPARE_BYTES = 64 * 1_024
_MAX_CLIENT_CERTIFICATE_PROJECTION_BYTES = (
    _MAX_SCHEMA_EVIDENCE_PROJECTION_ITEMS * _MAX_SCHEMA_EVIDENCE_REF_BYTES
    + 2 * _MAX_SCHEMA_CLAIMS * _MAX_SCHEMA_CLAIM_BYTES
    + _MAX_SCHEMA_FIXED_PREPARE_BYTES
)
_MAX_CLIENT_CERTIFICATE_NODES = 100_000


def _preflight_client_projection(value: object) -> None:
    """Reject non-JSON values and obviously unbounded input before validation."""
    if type(value) is not dict:
        _fail("CO_PROJECTION")
    pending: list[tuple[object, bool]] = [(value, False)]
    active: set[int] = set()
    estimated_size = 0
    nodes = 0
    while pending:
        current, leaving = pending.pop()
        if leaving:
            active.discard(id(current))
            continue
        nodes += 1
        if nodes > _MAX_CLIENT_CERTIFICATE_NODES:
            _fail("CO_PROJECTION")
        if type(current) is dict:
            identity = id(current)
            if identity in active:
                _fail("CO_PROJECTION")
            active.add(identity)
            estimated_size += 2
            pending.append((current, True))
            for key, item in current.items():
                if type(key) is not str:
                    _fail("CO_PROJECTION")
                # ensure_ascii=True is an upper bound for the UTF-8 bytes used
                # by canonical JSON, including quotes and escaping.
                estimated_size += len(json.dumps(key, ensure_ascii=True)) + 2
                pending.append((item, False))
        elif type(current) is list:
            identity = id(current)
            if identity in active:
                _fail("CO_PROJECTION")
            active.add(identity)
            estimated_size += 2 + len(current)
            pending.append((current, True))
            pending.extend((item, False) for item in current)
        elif type(current) is str:
            estimated_size += len(json.dumps(current, ensure_ascii=True))
        elif type(current) is int:
            if abs(current) > 2**53 - 1:
                _fail("CO_PROJECTION")
            estimated_size += len(str(current))
        elif current is None or type(current) is bool:
            estimated_size += 5
        elif type(current) is float:
            _fail("CO_PROJECTION")
        else:
            _fail("CO_PROJECTION")
        if estimated_size > _MAX_CLIENT_CERTIFICATE_PROJECTION_BYTES:
            _fail("CO_PROJECTION")


def _prepare_client_projection(
    document: dict[str, Any],
) -> ClientCertificateProjection:
    """Build signing material from an already validated certificate projection."""
    projection = copy.deepcopy(document)
    signatures = projection["signatures"]
    if type(signatures) is not dict:
        _fail("CO_PROJECTION")
    signatures.pop("co_attestation", None)
    try:
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
        digest = _role_digest(_CLIENT_CERTIFICATE_DOMAIN, projection)
    except fp2.Fp2UnsupportedValue:
        _fail("CO_PROJECTION")
    except RelyingPartyVerificationError as error:
        if error.code == "CANONICALIZATION":
            _fail("CO_PROJECTION")
        raise
    return ClientCertificateProjection(
        projection=projection,
        projection_bytes=canonical,
        signing_bytes=_client_material(canonical),
        signed_manifest_digest=digest,
    )


def _validate_client_preparation_context(
    document: dict[str, Any], context: ClientCoAttestationContext
) -> None:
    """Fail closed unless the issuer projection matches the client's intent."""
    if not isinstance(context, ClientCoAttestationContext):
        _fail("CO_CONTEXT")
    signatures = document["signatures"]
    unsigned_ref = signatures["unsigned_manifest"]
    unsigned = unsigned_ref["document"]
    audit = document["audit_report"]
    g1_claims = [claim for claim in document["claims"] if claim["claim_id"] == "G1"]
    if len(g1_claims) != 1 or g1_claims[0]["tier"] != 1:
        _fail("CO_G1_REQUIRED")
    audit_digest = _role_digest(_AUDIT_DOMAIN, audit)
    if unsigned_ref["manifest_digest"] != _role_digest(_UNSIGNED_DOMAIN, unsigned):
        _fail("CO_PROJECTION")
    if tuple(unsigned_ref["coverage"]) != _COVERAGE:
        _fail("CO_PROJECTION")
    compiler_register_versions = unsigned["compiler_register_versions"]
    # These exact register values bind the public semantics section; the
    # client pins the complete ordered register tuple below.
    if set(document["semantics"]) != set(_SEMANTICS_KEYS) or document["semantics"] != {
        key: compiler_register_versions[key] for key in _SEMANTICS_KEYS
    }:
        _fail("CO_PROJECTION")
    _check_streams(document["ledger_seal_projection"])
    _check_projections(document, unsigned, audit_digest)
    _check_claims_and_audit(document, unsigned, audit, audit_digest)

    params = g1_claims[0]["payload"]["params"]
    ring = unsigned["key_ring_identifiers"]
    issuer = signatures["issuer_signature"]
    if any(
        field not in ring for field in ("client_key_ref", "client_signature_algorithm")
    ):
        _fail("CO_PROJECTION")
    try:
        derived_key_ref = derive_client_key_ref(
            context.expected_project_ref,
            context.expected_client_algorithm,
            context.client_public_key,
        )
    except RelyingPartyVerificationError:
        _fail("CO_CONTEXT")
    if not (
        issuer["signed_payload"] == ["unsigned_manifest"]
        and issuer["issuer_key_ref"] == ring["issuer_key_ref"]
        and issuer["algorithm"] == ring["issuer_signature_algorithm"]
        and issuer["trust_ring_ref"] == ring["trust_ring_ref"]
    ):
        _fail("CO_PROJECTION")
    cross_bound_roots = {"subject": document["subject"], "unsigned": unsigned}
    for param_name, projection_path in _G1_CROSS_BOUND_PARAM_PATHS.items():
        root_name, *path_parts = projection_path.split(".")
        cross_bound_value: Any = cross_bound_roots[root_name]
        for path_part in path_parts:
            cross_bound_value = cross_bound_value[path_part]
        if params[param_name] != cross_bound_value:
            _fail("CO_PROJECTION")
    if audit["client_evidence_manifest_root"] != params["manifest_root_digest"]:
        _fail("CO_PROJECTION")

    expected_pins = {
        field_name: getattr(context, field_name)
        for field_name in CLIENT_CO_ATTESTATION_CONTEXT_FIELDS
    }
    expected_pins["client_public_key"] = derived_key_ref
    roots = {"subject": document["subject"], "unsigned": unsigned, "g1": g1_claims[0]}
    projection_pins: dict[str, Any] = {}
    for field_name, projection_path in _CLIENT_CO_ATTESTATION_PIN_BINDINGS:
        root_name, *path_parts = projection_path.split(".")
        value: Any = roots[root_name]
        for path_part in path_parts:
            value = value[path_part]
        if field_name == "expected_compiler_register_versions":
            value = tuple((key, value[key]) for key in _COMPILER_REGISTER_KEYS)
        projection_pins[field_name] = value
    if projection_pins != expected_pins:
        _fail("CO_CONTEXT")

    # The client pins every client-originated or trust-defining manifest
    # field above.  Seal/claim/tier/evidence/non-claim and audit material is
    # issuer/compiler evidence: the client co-signs its exact bytes but does
    # not assert its truth.  Their deterministic cross-projections are still
    # checked before any signing bytes are returned.  Fixed envelope scope
    # lines are schema-owned constants.  G1 verifier identity/version select
    # client trust semantics, so the client pins both above; only verifier
    # result=PASS is a schema-owned constant.


def prepare_client_co_attestation(
    prepare_response: object, *, context: ClientCoAttestationContext
) -> ClientCertificateProjection:
    """Prepare signing bytes from an issuer prepare response after intent checks.

    ``prepare_response`` must be the exact content-free, pre-co-attestation
    projection returned by the prepare endpoint.  ``context`` is frozen
    client-owned intent: scope, freshness, privacy and SDK identity, disclosure
    profile, compiler/register semantics, issuer trust pins, commitment
    parameters, the expected client algorithm, and the client's public key.
    Every value is compared before signing material is returned, preventing a
    caller from blindly signing a different project, session, trust context, or
    G1 commitment.

    This helper does not accept a final certificate or a private key, perform
    signing, authenticate the issuer signature, use the network, or write.  A
    cold call reads installed packaged Schema resources to construct cached
    validators; later calls reuse them.
    """
    _preflight_client_projection(prepare_response)
    document = cast(dict[str, Any], prepare_response)
    try:
        validator = _certificate_preparation_validator()
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaDependencyError):
        _fail("CO_SCHEMA_DEPENDENCY")
    try:
        errors = list(validator.iter_errors(document))
    except Unresolvable:
        _fail("CO_SCHEMA_DEPENDENCY")
    if errors:
        _fail("CO_PROJECTION")
    try:
        _validate_client_preparation_context(document, context)
    except RelyingPartyVerificationError as error:
        if error.code in CLIENT_CO_ATTESTATION_ERROR_CODES:
            raise
        _fail("CO_PROJECTION")
    return _prepare_client_projection(document)


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


def _public_key_der(public_key: object) -> bytes:
    """Return canonical public-key bytes for caller/bundle identity comparison."""
    try:
        return cast(
            bytes,
            cast(Any, public_key).public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
    except Exception:
        _fail("MATERIALS_BINDING")


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
    bundle_client_public_key: object | None,
) -> None:
    try:
        if document["certificate_ref"] != certificate_ref:
            _fail("CERTIFICATE_REF")
        issuer = document["issuer"]
        unsigned = certificate["signatures"]["unsigned_manifest"]["document"]
        ring = unsigned["key_ring_identifiers"]
        signatures = certificate["signatures"]
        requires_client_claim = any(
            claim["claim_id"] == "G1" or claim["tier"] == 1 for claim in unsigned["claims"]
        )
        has_co = "co_attestation" in signatures
        requires_client = requires_client_claim or has_co
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
            if context.expected_project_ref is None or bundle_client_public_key is None:
                _fail("MATERIALS_BINDING")
            if (
                derive_client_key_ref(
                    context.expected_project_ref,
                    client["algorithm"],
                    bundle_client_public_key,
                )
                != client["key_ref"]
            ):
                _fail("MATERIALS_BINDING")
            if (
                context.client_public_key is not None
                and (
                    context.expected_project_ref is None
                    or context.expected_client_algorithm is None
                )
            ):
                _fail("MATERIALS_BINDING")
            if context.client_public_key is not None:
                try:
                    caller_key_ref = derive_client_key_ref(
                        context.expected_project_ref,
                        cast(str, context.expected_client_algorithm),
                        context.client_public_key,
                    )
                except RelyingPartyVerificationError:
                    _fail("MATERIALS_BINDING")
                if caller_key_ref != client["key_ref"]:
                    _fail("MATERIALS_BINDING")
            if (
                context.client_public_key is not None
                and _public_key_der(context.client_public_key)
                != _public_key_der(bundle_client_public_key)
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


def _check_retrieval_wrapper_bindings(
    wrapper: dict[str, Any], certificate: dict[str, Any], context: VerificationContext
) -> None:
    """Bind retrieval projections to fields authoritative in the signed envelope.

    The retrieval contract's ``id``, ``tenant_id``, ``project_id``, and
    ``created_at`` are server projection metadata and have no counterpart in
    the signed certificate, so their shape is checked by the canonical
    retrieval schema but they are not trusted as scope authority.  Scope is
    bound only through the caller's trusted opaque project_ref and the signed
    certificate subject.
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
        if certificate["subject"]["project_ref"] != context.expected_project_ref:
            _fail("PROJECT_CONTEXT")
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
    checked and cannot bypass revocation status.  Wrapper status is unsigned and
    shape-checked; it cannot elevate the signature-only result or prove current
    validity or non-revocation.
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
        issuer_public_key = _material_public_key(document["issuer"], _ISSUER_SPKI_DOMAIN)
        client_projection = document.get("client")
        client_public_key = (
            _material_public_key(client_projection, _CLIENT_SPKI_DOMAIN)
            if client_projection is not None
            else None
        )
        _check_materials_bindings(
            envelope,
            document,
            certificate_ref,
            context,
            client_public_key,
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
            _check_retrieval_wrapper_bindings(wrapper, envelope, context)
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


def _length_prefixed_fields(domain: bytes, *fields: bytes) -> bytes:
    """Encode a domain and a fixed tuple of binary fields unambiguously."""
    if type(domain) is not bytes or not domain or any(type(field) is not bytes for field in fields):
        _fail("MATERIAL")
    if any(len(field) >= 2**64 for field in fields):
        _fail("MATERIAL")
    return domain + b"".join(struct.pack(">Q", len(field)) + field for field in fields)


def _client_material(projection_bytes: bytes) -> bytes:
    if type(projection_bytes) is not bytes or len(projection_bytes) >= 2**64:
        _fail("MATERIAL")
    return _length_prefixed_fields(_CLIENT_DOMAIN, projection_bytes)


def _issuer_material(manifest_bytes: bytes) -> bytes:
    if type(manifest_bytes) is not bytes:
        _fail("MATERIAL")
    return _length_prefixed_fields(_ISSUER_DOMAIN, manifest_bytes)


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
        "rendered_text": claim["rendered_text"],
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
    if len(by_id) != len(claims) or set(by_id) - {"B1", "G1"}:
        _fail("CLAIM_ID")
    for claim in claims:
        audit_refs = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] == "audit_report_digest"
        ]
        if len(audit_refs) != 1 or audit_refs[0]["evidence_digest"] != audit_digest:
            _fail("AUDIT_BINDING")
        if claim["verifier"]["result"] != "PASS":
            _fail("CLAIM_STATUS")
        params = claim["payload"]["params"]
        refs = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] != "audit_report_digest"
        ]
        if claim["claim_id"] == "G1":
            if claim["tier"] != 1:
                _fail("CLAIM_STATUS")
            root = params["manifest_root_digest"]
            if root == _ZERO_DIGEST or root != audit["client_evidence_manifest_root"]:
                _fail("CLIENT_ROOT")
            if (
                len(refs) != 1
                or refs[0]["evidence_kind"] != "client_commitment_digest"
                or refs[0]["evidence_digest"] != root
            ):
                _fail("CLIENT_ROOT")
            if claim.get("rendered_text") != _render_g1_text(params):
                _fail("CLAIM_RENDERING")
        else:
            if claim["tier"] != 3:
                _fail("CLAIM_STATUS")
            # B1 is the only issuer-verified claim in this release. Its
            # evidence must identify the exact issuer-sealed projection.
            seal = audit.get("ledger_seal_statement_digest")
            if (
                params["seal_statement_digest"] != seal
                or params["seal_ref"] != certificate["ledger_seal_projection"]["seal_ref"]
            ):
                _fail("SEAL_BINDING")
            if (
                len(refs) != 1
                or refs[0]["evidence_kind"] != "seal_statement"
                or refs[0]["evidence_digest"] != seal
            ):
                _fail("SEAL_BINDING")
            expected_text = (
                "The issuer signed this seal statement: seal "
                + params["seal_ref"]
                + ", canonical seal-statement digest "
                + params["seal_statement_digest"]
                + "."
            )
            if claim.get("rendered_text") != expected_text:
                _fail("CLAIM_RENDERING")
    return by_id


def _check_audit_rows(audit: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> None:
    rows = audit["claim_support_rows"]
    if [row["claim_id"] for row in rows] != list(_AUDIT_ROWS):
        _fail("AUDIT_ROWS")
    for row in rows:
        basis = row["evidence_basis"]
        if row["claim_id"] == "B1":
            if row["claim_id"] in by_id:
                if basis != "issuer_verified":
                    _fail("AUDIT_STATUS")
            elif basis != "abstained" or row["abstention_code"] != _ABSTENTION_CODES["B1"]:
                _fail("AUDIT_STATUS")
        elif row["claim_id"] == "G1":
            if row["claim_id"] in by_id:
                if basis != "client_declared":
                    _fail("AUDIT_STATUS")
            elif basis != "abstained" or row["abstention_code"] != _ABSTENTION_CODES["G1"]:
                _fail("AUDIT_STATUS")
        claim = by_id.get(row["claim_id"])
        if claim is None:
            if (
                basis != "abstained"
                or row["abstention_code"] != _ABSTENTION_CODES[row["claim_id"]]
            ):
                _fail("AUDIT_STATUS")
        else:
            expected_basis = "issuer_verified" if row["claim_id"] == "B1" else "client_declared"
            if basis != expected_basis or row["verifier"] != claim["verifier"]:
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
    if context.expected_project_ref is None or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,128}", context.expected_project_ref
    ):
        _fail("PROJECT_CONTEXT")
    ring = unsigned["key_ring_identifiers"]
    issuer = signatures["issuer_signature"]
    if not (
        context.expected_nonce == unsigned["freshness"]["nonce"]
        and context.expected_build_session_ref == unsigned["subject"]["build_session_ref"]
        and context.expected_project_ref == unsigned["subject"]["project_ref"]
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
        if context.expected_project_ref is None or context.client_public_key is None:
            _fail("CLIENT_KEY_CONTEXT")
        if (
            derive_client_key_ref(
                context.expected_project_ref,
                ring["client_signature_algorithm"],
                context.client_public_key,
            )
            != ring["client_key_ref"]
        ):
            _fail("CLIENT_KEY_CONTEXT")
        for claim in unsigned["claims"]:
            if claim["claim_id"] == "G1":
                params = claim["payload"]["params"]
                if (
                    params["build_session_ref"] != unsigned["subject"]["build_session_ref"]
                    or params["client_key_ref"] != ring["client_key_ref"]
                ):
                    _fail("G1_BINDING")
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
    context: VerificationContext,
) -> None:
    requires_co = any(
        claim["claim_id"] == "G1" or claim["tier"] == 1 for claim in document["claims"]
    )
    has_co = "co_attestation" in signatures
    if requires_co != has_co:
        _fail("CO_REQUIRED" if requires_co else "CO_ZERO_CLAIMS")
    if not has_co and (
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
        return
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
    prepared = _prepare_client_projection(document)
    if co["signed_manifest_digest"] != prepared.signed_manifest_digest:
        _fail("CO_PROJECTION")
    co_raw = _decode_signature(co["signature"])
    if (
        co["algorithm"] == "ecdsa_p256_sha256"
        and int.from_bytes(co_raw[32:], "big") > _ECDSA_HALF_ORDER
    ):
        _fail("CLIENT_SIGNATURE_NON_CANONICAL")
    _verify_signature(
        context.client_public_key,
        co["algorithm"],
        prepared.signing_bytes,
        co["signature"],
    )


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
    issuer_signature = signatures["issuer_signature"]
    expected_payload = ["unsigned_manifest"]
    if issuer_signature["signed_payload"] != expected_payload:
        _fail("SIGNED_PAYLOAD")
    _verify_signature(
        issuer_public_key,
        issuer_signature["algorithm"],
        _issuer_material(manifest_bytes),
        issuer_signature["signature"],
    )
    _verify_co_attestation(document, signatures, unsigned, context)


def verify_certificate(
    certificate: object,
    *,
    issuer_public_key: object,
    context: VerificationContext,
    policy: RelyingPartyPolicy,
) -> VerificationResult:
    """Verify an Agent Certificate v0 envelope entirely offline.

    A successful signature-only result does not establish current validity or
    non-revocation.
    """

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
    "CLIENT_CO_ATTESTATION_ERROR_CODES",
    "CLIENT_CO_ATTESTATION_CONTEXT_FIELDS",
    "ClientCertificateProjection",
    "ClientCoAttestationContext",
    "derive_client_key_ref",
    "RelyingPartyPolicy",
    "RelyingPartyVerificationError",
    "VerificationContext",
    "VerificationError",
    "VerificationResult",
    "verify_certificate",
    "verify_agent_certificate",
    "verify_certificate_with_materials",
    "prepare_client_co_attestation",
    "verify",
]
