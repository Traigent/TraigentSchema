# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Agent Certificate v0 family (certification/).

Pins the Wave-C C6/C1 reconciled design rules structurally:

1. Tier 4 is PRESENT in the ClaimTier enum but UNCONSTRUCTIBLE in any v0 claim
   (C6: "Keep tier 4 in the schema, but make v0 emission of it a compile error").
2. ``Claim | NonClaim`` is a discriminated union with the empty-verifier compiler
   rule: a claim without a populated PASS verifier has no representable form
   (rejection, not downgrade), and a non-claim structurally forbids a verifier.
3. One explicit payload type per claim ID — only B1/B3/C1/D2/D5/G1/G3 are
   representable; the struck invented IDs B1c/D6a are not.
4. Claim sentences are versioned templates: no user-controlled free text is
   reachable from any certificate or registry record (every string is
   const/enum/pattern-bound; every object is closed).
5. The certificate prints its FOURTEEN mandatory NON-claims, in order, plus the
   const title "Agent Certificate" and the build-session scope line.
6. Claim B1 uses C1's NARROWER wording — "the issuer signed this seal
   statement" — never "the sealed history is intact".
7. Registry records are minimal blinded commitments: no counts, no date
   buckets, no timestamps.
8. The free-text quarantine: the certification family's transitive $ref closure
   never reaches an ``x-content``/``user_content`` carrier (the current-online
   tuned free-text exception stays a separate message family).

SCHEMA-1 (2026-08-25) pre-issuance correction — closes the signed-contract
gaps identified against the 2026-08-24 gap report (C0-C7): the unsigned
manifest is now a typed document with concrete content for all twelve
promised coverage sections (certificate_unsigned_manifest_v0_schema.json),
the co-attestation nonce is bound into that signed manifest's freshness
section, claims F1/G3 no longer require a self-referential manifest digest,
a fixed client-local evidence manifest exists for claim G1's commitment
root (certificate_client_evidence_manifest_v0_schema.json), and a typed
content-free pre-issuance audit report binds build session, evidence root,
ledger seal, and per-claim support/abstention rows
(certificate_audit_report_v0_schema.json). See TestUnsignedManifest,
TestClientEvidenceManifest, TestAuditReport, TestNonCircularClaims, and
TestCanonicalizationConformance below.

SCHEMA-1 P0/P1 FIX PASS (2026-08-24, same date, second pass) — closes four
false-green gaps a captain+Terra review caught in the correction above:
(P0) the unsigned manifest is now actually TRANSMITTED: CertificateSignaturesV0
.unsigned_manifest carries the complete typed document, not just an
unresolvable digest (certificate_signatures_v0_schema.json#/definitions/
UnsignedManifestRefV0); (P1) AuditReportV0.claim_support_rows is now a
canonical FIXED seven-item tuple, one row per registered claim ID in a
pinned order, rejecting missing/duplicate/reordered/extra IDs; (P1) every
printed ClaimV0 must carry an audit_report_digest evidence reference
(certificate_claims_v0_schema.json#/definitions/ClaimV0); (P1) a supported
audit row now binds claim_material_digest — a jcs_v1 digest of the exact
printed claim material (claim_id, tier, payload, verifier, non-audit
evidence_refs) — closing the gap where a supported row bound only a
claim_id + verifier pair. See TestSignedManifestEmbedding and
TestContractVerifier below (the latter implements a small deterministic
contract-verifier helper, _verify_certificate_contract, for the cross-field
equality obligations Draft-07 cannot itself express).

Referenced schema files (also anchors the orphan-schema ratchet in
tests/test_schemas.py):
    certification_common_v0_schema.json
    agent_certificate_v0_schema.json
    certificate_claims_v0_schema.json
    certificate_claim_payloads_v0_schema.json
    certificate_claim_templates_v0_schema.json
    certificate_evidence_refs_v0_schema.json
    certificate_ledger_seals_v0_schema.json
    certificate_signatures_v0_schema.json
    certificate_registry_agent_revision_v0_schema.json
    certificate_registry_measurement_contract_v0_schema.json
    certificate_rejection_v0_schema.json
    certificate_unsigned_manifest_v0_schema.json
    certificate_client_evidence_manifest_v0_schema.json
    certificate_audit_report_v0_schema.json
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
from importlib import resources
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas"
CERT_DIR = SCHEMAS_DIR / "certification"
_BUILD_SESSION_REF = "bsn:" + "a" * 43

CERT_FILES = [
    "certification_common_v0_schema.json",
    "agent_certificate_v0_schema.json",
    "certificate_claims_v0_schema.json",
    "certificate_claim_payloads_v0_schema.json",
    "certificate_claim_templates_v0_schema.json",
    "certificate_evidence_refs_v0_schema.json",
    "certificate_ledger_seals_v0_schema.json",
    "certificate_signatures_v0_schema.json",
    "certificate_registry_agent_revision_v0_schema.json",
    "certificate_registry_measurement_contract_v0_schema.json",
    "certificate_rejection_v0_schema.json",
    "certificate_unsigned_manifest_v0_schema.json",
    "certificate_client_evidence_manifest_v0_schema.json",
    "certificate_audit_report_v0_schema.json",
]

_SCHEMA_BASE = "https://schemas.traigent.ai/"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS_DIR.rglob("*.json"):
        contents = _load(path)
        if isinstance(contents, dict) and "$id" in contents:
            resources.append((contents["$id"], Resource.from_contents(contents)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()


def _validator(file_name: str) -> Draft7Validator:
    return Draft7Validator(_load(CERT_DIR / file_name), registry=_REGISTRY)


def _errors(file_name: str, instance: object) -> list:
    return list(_validator(file_name).iter_errors(instance))


_SHA = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64
_ZERO_SHA = "sha256:" + "0" * 64
_SIG_RAW = bytes(range(64))
_SIG = base64.b64encode(_SIG_RAW).decode("ascii")
_NONCE = "ab" * 16
_SDK_SHA = "e97b030f88d78a22dddb482d2aecf94a515b1938"
_SLOT_COMMITMENT_DOMAIN = b"traigent.cert.v0.slot_commitment.v1"
_SLOT_ARTIFACT_KINDS = frozenset(
    {"agent_revision", "evaluation_dataset", "evaluator", "build_process_evidence"}
)
_DIGEST_ROLE_UNSIGNED_MANIFEST = b"traigent.agent_certificate.unsigned_manifest.v1"
_DIGEST_ROLE_AUDIT_REPORT = b"traigent.agent_certificate.audit_report.v1"
_DIGEST_ROLE_CLAIM_MATERIAL = b"traigent.agent_certificate.claim_material.v1"
_DIGEST_ROLE_CLIENT_EVIDENCE_ROOT = b"traigent.agent_certificate.client_evidence_manifest_root.v1"

_COVERAGE = [
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
]

_NON_CLAIM_ORDER = [
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
]


def _seal_statement() -> dict:
    return {
        "seal_ref": "seal:abcdef0123456789",
        "chain_schema_version": "traigent.cert_build_ledger.v0",
        "build_session_ref": _BUILD_SESSION_REF,
        "expected_stream_projection": {
            "decision_stream": {
                "stream_family": "decision",
                "chain_status": "empty_sealed",
                "root_commitment": _SHA,
            },
            "receipt_event_stream": {
                "stream_family": "receipt_event",
                "chain_status": "sealed",
                "root_commitment": _SHA_B,
            },
            "transition_stream": {
                "stream_family": "transition",
                "chain_status": "sealed",
                "root_commitment": _SHA,
            },
        },
        "seal_statement_digest": _SHA,
    }


def _b1_claim(tier: int = 3) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "B1",
        "tier": tier,
        "payload": {
            "claim_id": "B1",
            "template_id": "tmpl.cert.b1.issuer_signed_seal_statement.v1",
            "params": {
                "seal_ref": "seal:abcdef0123456789",
                "seal_statement_digest": _SHA,
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.seal_signature",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "seal_statement", "evidence_digest": _SHA},
            # Placeholder binding; tests that care about the *real* audit
            # report replace this via _finalize_claims_with_audit.
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
        "rendered_text": (
            "The issuer signed this seal statement: seal seal:abcdef0123456789, "
            "canonical seal-statement digest " + _SHA + "."
        ),
    }


def _g1_claim(tier: int = 1) -> dict:
    root = _client_evidence_root_digest(_client_evidence_manifest())
    client_key_ref = "ckr:" + "A" * 43
    return {
        "record_type": "claim",
        "claim_id": "G1",
        "tier": tier,
        "payload": {
            "claim_id": "G1",
            "template_id": "tmpl.cert.g1.client_evidence_manifest_commitment.v2",
            "params": {
                "manifest_root_digest": root,
                "commitment_scheme": "sha256_secret_blinded_v1",
                "client_attestor_version": "0.1.0",
                "build_session_ref": _BUILD_SESSION_REF,
                "client_key_ref": client_key_ref,
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.manifest_commitment",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {
                "evidence_kind": "client_commitment_digest",
                "evidence_digest": _client_evidence_root_digest(_client_evidence_manifest()),
            },
            # Placeholder binding; tests that care about the *real* audit
            # report replace this via _finalize_claims_with_audit.
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
        "rendered_text": (
            "The pinned client key co-signed the declaration that evidence-manifest root "
            f"{root} uses scheme sha256_secret_blinded_v1 and client attestor version 0.1.0. "
            "The declaration is unopened; correspondence to, possession of, and completeness "
            "of any underlying evidence are not proven."
        ),
    }


def _non_claims() -> list:
    return [
        {
            "record_type": "non_claim",
            "non_claim_id": ncid,
            "reason_template_id": tmpl,
        }
        for ncid, tmpl in _NON_CLAIM_ORDER
    ]


def _co_attestation(manifest_digest: str, nonce: str) -> dict:
    return {
        "algorithm": "ed25519",
        "client_key_ref": "ckr:" + "A" * 43,
        "signed_manifest_digest": manifest_digest,
        "nonce": nonce,
        "signature": _SIG,
    }


def _signatures(
    with_co: bool = False,
    claims: list | None = None,
    audit_report_digest: str | None = None,
) -> dict:
    # SCHEMA-1 P0 fix (2026-08-24): the signatures block now embeds the
    # complete unsigned-manifest *document*, not just its digest+coverage
    # label list. Building the manifest here (rather than a fixed constant)
    # keeps every certificate fixture cross-consistent by construction: the
    # embedded document's role-separated SHA-256 over fp2/JCS canonical bytes
    # is what manifest_digest carries,
    # and (when a co-attestation is requested) the co-attestation's nonce and
    # signed_manifest_digest are drawn from that same manifest -- exactly the
    # bindings a relying-party verifier checks.
    claims = claims if claims is not None else [_g1_claim(tier=1)]
    # Materialize the embedded manifest projection from the certificate claims;
    # the contract verifier checks the two signed projections for exact
    # equality rather than treating either copy as an independently mutable
    # client input.
    manifest = _unsigned_manifest(
        claims=copy.deepcopy(claims),
        with_co=with_co,
        audit_report_digest=audit_report_digest,
    )
    manifest_digest = _unsigned_manifest_digest(manifest)
    block = {
        "unsigned_manifest": {
            "manifest_digest": manifest_digest,
            "coverage": list(_COVERAGE),
            "document": manifest,
        },
        "issuer_signature": {
            "algorithm": "ed25519",
            "issuer_key_ref": "ikey:abcdef0123456789",
            "trust_ring_ref": "ring:abcdef0123456789",
            "signed_payload": ["unsigned_manifest"],
            "signature": _SIG,
        },
    }
    if with_co:
        block["co_attestation"] = _co_attestation(manifest_digest, manifest["freshness"]["nonce"])
    return block


def _certificate(
    claims: list | None = None,
    with_co: bool = True,
    audit_report: dict | None = None,
) -> dict:
    claims = claims if claims is not None else [_g1_claim(tier=1)]
    if audit_report is None:
        # SCHEMA-1 FINAL fix (2026-08-24): the envelope now requires the
        # complete typed audit report, not merely a claim-side digest.
        # Callers that already built a real, claim-material-bound report
        # (_build_valid_fixture) pass it in; schema-only fixtures get one
        # that is valid in isolation (supported rows for whatever claim_ids
        # are present, abstained otherwise -- including the zero-claims
        # case, where all seven rows abstain).
        audit_report = _audit_report_for_claims(claims)
    certificate = {
        "schema_version": "traigent.agent_certificate.v0",
        "certificate_title": "Agent Certificate",
        "build_session_scope_line": (
            "Build-session scope: this certificate concerns a build session, not "
            "the deployed agent. It makes no deployment-identity, "
            "deployment-binding, drift-detection, or deployed-runtime claim."
        ),
        "certificate_scope_line": (
            "Scope: Certified Agent v0 verifies signatures, build-session binding, and an "
            "unopened client declaration. It does not certify the contents, quality, "
            "correctness, correspondence, possession, or completeness of the agent, "
            "evaluation dataset, evaluator, or build-process evidence."
        ),
        "subject": {
            "subject_kind": "build_session",
            "hash_algorithm": "v1",
            "project_ref": "project_contract001",
            "build_session_ref": _BUILD_SESSION_REF,
            "session_commitment_digest": _SHA,
        },
        "semantics": {
            "semantics_manifest_digest": _SHA,
            "claim_template_catalog_digest": _SHA,
            "prohibited_register_digest": _SHA,
            "verifier_catalog_digest": _SHA,
            "non_claim_reason_catalog_digest": _SHA,
        },
        "disclosure_profile": {
            "profile_id": "customer_internal",
            "selective_disclosure_line": (
                "Data omitted from this disclosure profile is simply absent; "
                "selective disclosure is not proven."
            ),
        },
        "ledger_seal_projection": _seal_statement(),
        "claims": claims,
        "non_claims": _non_claims(),
        "signatures": _signatures(
            with_co=with_co,
            claims=claims,
            audit_report_digest=_audit_report_digest(audit_report),
        ),
        "audit_report": audit_report,
    }
    if with_co:
        _rebind_co_projection_digest(certificate)
    return certificate


ENVELOPE = "agent_certificate_v0_schema.json"
CLAIMS = "certificate_claims_v0_schema.json"
LEDGER = "certificate_ledger_seals_v0_schema.json"
REJECTION = "certificate_rejection_v0_schema.json"
REG_AR = "certificate_registry_agent_revision_v0_schema.json"
REG_MC = "certificate_registry_measurement_contract_v0_schema.json"
SIGNATURES = "certificate_signatures_v0_schema.json"
PAYLOADS = "certificate_claim_payloads_v0_schema.json"
TEMPLATES = "certificate_claim_templates_v0_schema.json"
UNSIGNED_MANIFEST = "certificate_unsigned_manifest_v0_schema.json"
CLIENT_EVIDENCE_MANIFEST = "certificate_client_evidence_manifest_v0_schema.json"
AUDIT_REPORT = "certificate_audit_report_v0_schema.json"

_DIGEST_PATTERN = re.compile(r"^sha256:[a-f0-9]{64}$")


def _role_digest(role_domain: bytes, document: dict) -> str:
    """Compute a load-bearing certificate digest with explicit role separation."""
    if not isinstance(role_domain, bytes) or not role_domain:
        raise ValueError("role_domain must be non-empty ASCII bytes")
    try:
        role_domain.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("role_domain must be ASCII") from exc
    canonical = fp2.canonicalize(document).encode("utf-8")
    return "sha256:" + hashlib.sha256(role_domain + b"\x00" + canonical).hexdigest()


def _unsigned_manifest_digest(document: dict) -> str:
    return _role_digest(_DIGEST_ROLE_UNSIGNED_MANIFEST, document)


def _audit_report_digest(document: dict) -> str:
    return _role_digest(_DIGEST_ROLE_AUDIT_REPORT, document)


def _rebind_co_projection_digest(cert: dict) -> None:
    co = cert["signatures"].get("co_attestation")
    if co is None:
        return
    projection = copy.deepcopy(cert)
    projection["signatures"].pop("co_attestation", None)
    co["signed_manifest_digest"] = _role_digest(
        b"traigent.agent_certificate.client_certificate_projection.v0", projection
    )


def _claim_material_role_digest(document: dict) -> str:
    return _role_digest(_DIGEST_ROLE_CLAIM_MATERIAL, document)


def _client_evidence_root_digest(document: dict) -> str:
    return _role_digest(_DIGEST_ROLE_CLIENT_EVIDENCE_ROOT, document)


def _strict_signature_raw(value: str) -> bytes:
    """Decode the exact v0 signature encoding; shape checks are not crypto."""
    if not re.fullmatch(r"[A-Za-z0-9+/]{86}==", value):
        raise ValueError("signature is not canonical 64-byte RFC4648 base64")
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 64:
        raise ValueError("signature must decode to exactly 64 bytes")
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("signature is not canonical RFC4648 base64")
    return raw


def _client_signed_material(manifest_jcs_bytes: bytes) -> bytes:
    return (
        b"traigent.agent_certificate.client_co_attestation.v0"
        + len(manifest_jcs_bytes).to_bytes(8, "big")
        + manifest_jcs_bytes
    )


def _issuer_signed_material(manifest_jcs_bytes: bytes) -> bytes:
    return (
        b"traigent.agent_certificate.issuer_signature.v0"
        + len(manifest_jcs_bytes).to_bytes(8, "big")
        + manifest_jcs_bytes
    )


def _slot_commitment_digest(
    *,
    blind: bytes,
    artifact_kind: str,
    artifact_document: dict,
    used_blinds: set[bytes],
) -> str:
    """Executable client-local reference for sha256_secret_blinded_v1.

    The set is deliberately supplied by the caller: a build owns one set and
    uses it to reject accidental blind reuse across its four slots.
    """
    if not isinstance(blind, bytes) or len(blind) != 32:
        raise ValueError("blind must be exactly 32 bytes")
    if blind in used_blinds:
        raise ValueError("blind must not be reused")
    if artifact_kind not in _SLOT_ARTIFACT_KINDS:
        raise ValueError("artifact_kind is not a fixed slot enum")
    if not isinstance(artifact_document, dict):
        raise TypeError("artifact_document must be a JSON object")
    if any(isinstance(value, float) for value in _walk_json_values(artifact_document)):
        raise TypeError("artifact_document must not contain floats")
    canonical = fp2.canonicalize(artifact_document)
    used_blinds.add(blind)
    preimage = (
        _SLOT_COMMITMENT_DOMAIN
        + b"\x00"
        + artifact_kind.encode("utf-8")
        + b"\x00"
        + canonical.encode("utf-8")
    )
    return "sha256:" + hmac.new(blind, preimage, hashlib.sha256).hexdigest()


def _walk_json_values(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_json_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json_values(child)


_FP2_CONFORMANCE = json.loads(
    resources.files("traigent_schema")
    .joinpath("data", "fp2_conformance.json")
    .read_text(encoding="utf-8")
)
_FP2_CASES_BY_NAME = {case["name"]: case for case in _FP2_CONFORMANCE["cases"]}


def _tiers_projection(claims: list) -> list:
    return [{"claim_id": c["claim_id"], "tier": c["tier"]} for c in claims]


def _evidence_digests_projection(claims: list, audit_report_digest: str | None = None) -> list:
    """Pin the leading audit binding, then first-occurrence claim refs."""
    if audit_report_digest is None:
        audit_refs = [
            ref
            for claim in claims
            for ref in claim["evidence_refs"]
            if ref["evidence_kind"] == "audit_report_digest"
        ]
        audit_report_digest = audit_refs[0]["evidence_digest"] if audit_refs else _SHA_B
    seen: list = [
        {
            "evidence_kind": "audit_report_digest",
            "evidence_digest": audit_report_digest,
        }
    ]
    for claim in claims:
        for ref in claim["evidence_refs"]:
            if ref not in seen:
                seen.append(ref)
    return seen


def _compiler_register_versions() -> dict:
    return {
        "compiler_version": "0.1.0",
        "semantics_manifest_digest": _SHA,
        "claim_template_catalog_digest": _SHA,
        "prohibited_register_digest": _SHA,
        "verifier_catalog_digest": _SHA,
        "non_claim_reason_catalog_digest": _SHA,
    }


def _key_ring_identifiers(with_client: bool = False) -> dict:
    block = {
        "issuer_key_ref": "ikey:abcdef0123456789",
        "trust_ring_ref": "ring:abcdef0123456789",
        "issuer_signature_algorithm": "ed25519",
    }
    if with_client:
        block["client_key_ref"] = "ckr:" + "A" * 43
        block["client_signature_algorithm"] = "ed25519"
    return block


def _unsigned_manifest(
    claims: list | None = None,
    with_co: bool = False,
    audit_report_digest: str | None = None,
) -> dict:
    claims = claims if claims is not None else [_g1_claim(tier=1)]
    return {
        "subject": {
            "subject_kind": "build_session",
            "hash_algorithm": "v1",
            "project_ref": "project_contract001",
            "build_session_ref": _BUILD_SESSION_REF,
            "session_commitment_digest": _SHA,
        },
        "seal": _seal_statement(),
        "claims": claims,
        "tiers": _tiers_projection(claims),
        "evidence_digests": _evidence_digests_projection(
            claims, audit_report_digest=audit_report_digest
        ),
        "non_claims": _non_claims(),
        "disclosure_profile": {
            "profile_id": "customer_internal",
            "selective_disclosure_line": (
                "Data omitted from this disclosure profile is simply absent; "
                "selective disclosure is not proven."
            ),
        },
        "privacy_mode": {"declared_mode": "offline"},
        "sdk_identity": {"sdk_ref": _SDK_SHA, "sdk_version": "0.1.0"},
        "compiler_register_versions": _compiler_register_versions(),
        "key_ring_identifiers": _key_ring_identifiers(with_client=with_co),
        "freshness": {"nonce": _NONCE},
    }


def _client_evidence_manifest_slot(kind: str) -> dict:
    return {
        "artifact_kind": kind,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "slot_commitment_digest": _SHA,
    }


def _client_evidence_manifest() -> dict:
    return {
        "schema_version": "traigent.certificate_client_evidence_manifest.v0",
        "agent_revision": _client_evidence_manifest_slot("agent_revision"),
        "evaluation_dataset": _client_evidence_manifest_slot("evaluation_dataset"),
        "evaluator": _client_evidence_manifest_slot("evaluator"),
        "build_process_evidence": _client_evidence_manifest_slot("build_process_evidence"),
    }


# Canonical claim_support_rows tuple order pinned by
# certificate_audit_report_v0_schema.json#/definitions/ClaimSupportRowsV0.
_AUDIT_ROW_ORDER = ["B1", "REG1", "C1", "D2", "F1", "G1", "G3"]
_ABSTENTION_CODE_BY_ID = {
    "B1": "verifier_not_run_or_not_pass",
    "REG1": "unregistered_claim_id",
    "C1": "verifier_not_run_or_not_pass",
    "D2": "verifier_not_run_or_not_pass",
    "F1": "verifier_not_run_or_not_pass",
    "G1": "verifier_not_run_or_not_pass",
    "G3": "verifier_not_run_or_not_pass",
}


def _audit_row_supported(claim_id: str, claim_material_digest: str = _SHA) -> dict:
    verifier_by_claim = {
        "B1": "ver.cert.seal_signature",
        "C1": "ver.cert.artifact_scope",
        "D2": "ver.cert.offline_egress_witness",
        "F1": "ver.cert.issuer_signature_validity",
        "G1": "ver.cert.manifest_commitment",
        "G3": "ver.cert.cosigner_identity",
        "REG1": "ver.cert.registry_receipt",
    }
    return {
        "claim_id": claim_id,
        "evidence_basis": "client_declared" if claim_id == "G1" else "issuer_verified",
        "verifier": {
            "verifier_id": verifier_by_claim[claim_id],
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "claim_material_digest": claim_material_digest,
    }


def _audit_row_abstained(claim_id: str, code: str | None = None) -> dict:
    return {
        "claim_id": claim_id,
        "evidence_basis": "abstained",
        "abstention_code": _ABSTENTION_CODE_BY_ID[claim_id] if code is None else code,
    }


def _replace_row(rows: list, claim_id: str, replacement: dict) -> list:
    """Swap in `replacement` for the row matching claim_id, preserving the
    fixed seven-item tuple order/length of the rest."""
    return [replacement if r["claim_id"] == claim_id else copy.deepcopy(r) for r in rows]


def _audit_report(rows: list | None = None) -> dict:
    if rows is None:
        rows = [_audit_row_abstained(cid) for cid in _AUDIT_ROW_ORDER]
    return {
        "schema_version": "traigent.certificate_audit_report.v0",
        "build_session_ref": _BUILD_SESSION_REF,
        "client_evidence_manifest_root": None,
        "ledger_seal_statement_digest": _SHA,
        "compiler_register_versions": _compiler_register_versions(),
        "claim_support_rows": rows,
    }


def _claim_material_projection(claim: dict) -> dict:
    """certificate_audit_report_v0_schema.json#/definitions/ClaimSupportRowV0
    's claim_material_digest projection: claim_id, tier, payload, verifier,
    and evidence_refs with every audit_report_digest-kind entry removed
    (remaining entries keep their original order)."""
    remaining_evidence = [
        ref for ref in claim["evidence_refs"] if ref.get("evidence_kind") != "audit_report_digest"
    ]
    projection = {
        "claim_id": claim["claim_id"],
        "tier": claim["tier"],
        "payload": claim["payload"],
        "verifier": claim["verifier"],
        "evidence_refs": remaining_evidence,
    }
    if "rendered_text" in claim:
        projection["rendered_text"] = claim["rendered_text"]
    return projection


def _claim_material_digest(claim: dict) -> str:
    return _claim_material_role_digest(_claim_material_projection(claim))


def _audit_report_for_claims(claims: list) -> dict:
    """Build a pre-issuance audit report whose claim_support_rows mark every
    claim_id present in `claims` as supported (with a real
    claim_material_digest computed over that claim's own material) and every
    other registered claim_id as abstained -- the zero-claims case abstains
    all seven. Shared by _finalize_claims_with_audit (which additionally
    binds the report's digest back into each claim's evidence_refs) and by
    _certificate's default (a schema-valid report for fixtures that do not
    care about full cross-document consistency)."""
    material_digests = {c["claim_id"]: _claim_material_digest(c) for c in claims}
    rows = [
        _audit_row_supported(cid, material_digests[cid])
        if cid in material_digests and cid in {"B1", "G1"}
        else _audit_row_abstained(cid)
        for cid in _AUDIT_ROW_ORDER
    ]
    g1_claim = next((c for c in claims if c["claim_id"] == "G1"), None)
    manifest_root = (
        g1_claim["payload"]["params"]["manifest_root_digest"] if g1_claim is not None else None
    )
    return {
        "schema_version": "traigent.certificate_audit_report.v0",
        "build_session_ref": _BUILD_SESSION_REF,
        "client_evidence_manifest_root": manifest_root,
        "ledger_seal_statement_digest": _SHA,
        "compiler_register_versions": _compiler_register_versions(),
        "claim_support_rows": rows,
    }


def _finalize_claims_with_audit(claims: list) -> tuple[list, dict]:
    """Build the pre-issuance audit report FIRST (per claim_material_digest,
    computed over each claim's material with any audit_report_digest
    evidence entry excluded -- so this never depends on the report's own
    digest), then bind the report's digest into each claim's evidence_refs
    as the (single, replaced) audit_report_digest entry. Returns
    (finalized_claims, audit_report) with every printed claim referencing the
    SAME audit_report_digest and every audit row's claim_material_digest
    matching the exact finalized claim material.
    """
    audit_report = _audit_report_for_claims(claims)
    audit_digest = _audit_report_digest(audit_report)

    finalized = []
    for claim in claims:
        claim = copy.deepcopy(claim)
        claim["evidence_refs"] = [
            ref
            for ref in claim["evidence_refs"]
            if ref.get("evidence_kind") != "audit_report_digest"
        ] + [{"evidence_kind": "audit_report_digest", "evidence_digest": audit_digest}]
        finalized.append(claim)
    return finalized, audit_report


def _g3_claim(tier: int = 1) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "G3",
        "tier": tier,
        "payload": {
            "claim_id": "G3",
            "template_id": "tmpl.cert.g3.cosigner_identity_binding.v1",
            "params": {"client_key_ref": "ckr:" + "A" * 43},
        },
        "verifier": {
            "verifier_id": "ver.cert.cosigner_identity",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "verifier_report_digest", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
    }


def _d2_claim(tier: int = 1) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "D2",
        "tier": tier,
        "payload": {
            "claim_id": "D2",
            "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
            "params": {
                "declared_mode": "offline",
                "witness_kind": "strace_network_trace",
                "sdk_ref": _SDK_SHA,
                "workload_class": ("mock_grid_no_integrations_no_analytics_no_langfuse"),
                "witness_bundle_digest": _SHA,
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.offline_egress_witness",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "sdk_witness_bundle", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
    }


def _c1_claim(tier: int = 3) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "C1",
        "tier": tier,
        "payload": {
            "claim_id": "C1",
            "template_id": "tmpl.cert.c1.artifact_scoped_no_unsupported_claims.v1",
            "params": {
                "compiler_version": "0.1.0",
                "semantics_manifest_digest": _SHA,
                "prohibited_register_digest": _SHA,
                "verifier_catalog_digest": _SHA,
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.artifact_scope",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "verifier_report_digest", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
    }


def _f1_claim(tier: int = 3) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "F1",
        "tier": tier,
        "payload": {
            "claim_id": "F1",
            "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
            "params": {
                "signature_scheme": "ed25519",
                "issuer_key_ref": "ikey:abcdef0123456789",
                "trust_ring_ref": "ring:abcdef0123456789",
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.issuer_signature_validity",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "verifier_report_digest", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ],
    }


class ContractViolation(AssertionError):
    """Raised by _verify_certificate_contract for a cross-field equality
    obligation this contract family's descriptions document but Draft-07
    cannot itself check (only an opaque digest, or nothing at all, crosses
    the schema boundary for these fields). This is a small, deterministic,
    test-only independent verifier -- not a stand-in for a production
    verifier -- built to exercise those obligations against mutated
    fixtures rather than leave them as unexercised prose."""


def _verify_certificate_contract(cert: dict) -> None:
    manifest = cert["signatures"]["unsigned_manifest"]["document"]
    audit_report = cert["audit_report"]

    if cert["signatures"]["unsigned_manifest"]["manifest_digest"] != _unsigned_manifest_digest(
        manifest
    ):
        raise ContractViolation("manifest_digest != unsigned-manifest role digest")

    if cert["subject"] != manifest["subject"]:
        raise ContractViolation("certificate.subject != document.subject")
    if cert["claims"] != manifest["claims"]:
        raise ContractViolation("certificate.claims != document.claims")
    if cert["non_claims"] != manifest["non_claims"]:
        raise ContractViolation("certificate.non_claims != document.non_claims")
    if cert["disclosure_profile"] != manifest["disclosure_profile"]:
        raise ContractViolation("certificate.disclosure_profile != document.disclosure_profile")
    if cert["ledger_seal_projection"] != manifest["seal"]:
        raise ContractViolation("certificate.ledger_seal_projection != document.seal")
    if cert["subject"]["build_session_ref"] != cert["ledger_seal_projection"]["build_session_ref"]:
        raise ContractViolation(
            "subject.build_session_ref != ledger_seal_projection.build_session_ref"
        )

    if manifest["tiers"] != _tiers_projection(manifest["claims"]):
        raise ContractViolation("tiers projection disagrees with claims")
    crv = manifest["compiler_register_versions"]
    sem = cert["semantics"]
    for key in (
        "semantics_manifest_digest",
        "claim_template_catalog_digest",
        "prohibited_register_digest",
        "verifier_catalog_digest",
        "non_claim_reason_catalog_digest",
    ):
        if crv[key] != sem[key]:
            raise ContractViolation(f"compiler_register_versions.{key} mismatch")

    kri = manifest["key_ring_identifiers"]
    issuer_sig = cert["signatures"]["issuer_signature"]
    if kri["issuer_key_ref"] != issuer_sig["issuer_key_ref"]:
        raise ContractViolation("key_ring_identifiers.issuer_key_ref mismatch")
    if kri["trust_ring_ref"] != issuer_sig["trust_ring_ref"]:
        raise ContractViolation("key_ring_identifiers.trust_ring_ref mismatch")
    if kri["issuer_signature_algorithm"] != issuer_sig["algorithm"]:
        raise ContractViolation(
            "key_ring_identifiers.issuer_signature_algorithm != issuer_signature.algorithm"
        )

    co = cert["signatures"].get("co_attestation")
    if co is not None:
        if kri.get("client_key_ref") != co["client_key_ref"]:
            raise ContractViolation("key_ring_identifiers.client_key_ref mismatch")
        if "client_signature_algorithm" not in kri:
            raise ContractViolation(
                "key_ring_identifiers.client_signature_algorithm missing with co_attestation"
            )
        if kri["client_signature_algorithm"] != co["algorithm"]:
            raise ContractViolation(
                "key_ring_identifiers.client_signature_algorithm != co_attestation.algorithm"
            )
        if manifest["freshness"]["nonce"] != co["nonce"]:
            raise ContractViolation("freshness.nonce != co_attestation.nonce")
        projection = copy.deepcopy(cert)
        projection["signatures"].pop("co_attestation", None)
        if co["signed_manifest_digest"] != _role_digest(
            b"traigent.agent_certificate.client_certificate_projection.v0", projection
        ):
            raise ContractViolation(
                "co_attestation.signed_manifest_digest != certificate projection"
            )
    elif "client_key_ref" in kri or "client_signature_algorithm" in kri:
        raise ContractViolation("client key/algorithm present without co_attestation")

    for claim in manifest["claims"]:
        if claim["claim_id"] == "G3":
            if co is None:
                raise ContractViolation("G3 claim printed without co_attestation")
            if claim["payload"]["params"]["client_key_ref"] != co["client_key_ref"]:
                raise ContractViolation("G3 claim client_key_ref != co_attestation")
        if claim["claim_id"] == "B1":
            params = claim["payload"]["params"]
            seal = cert["ledger_seal_projection"]
            if params["seal_ref"] != seal["seal_ref"]:
                raise ContractViolation("B1 claim seal_ref != ledger_seal_projection.seal_ref")
            if params["seal_statement_digest"] != seal["seal_statement_digest"]:
                raise ContractViolation(
                    "B1 claim seal_statement_digest != ledger_seal_projection.seal_statement_digest"
                )
        if claim["claim_id"] == "C1":
            params = claim["payload"]["params"]
            for key in (
                "compiler_version",
                "semantics_manifest_digest",
                "prohibited_register_digest",
                "verifier_catalog_digest",
            ):
                if params[key] != manifest["compiler_register_versions"][key]:
                    raise ContractViolation(
                        f"C1 claim {key} != manifest.compiler_register_versions.{key}"
                    )
        if claim["claim_id"] == "F1":
            params = claim["payload"]["params"]
            if params["signature_scheme"] != issuer_sig["algorithm"]:
                raise ContractViolation("F1 claim signature_scheme != issuer_signature.algorithm")
            if params["issuer_key_ref"] != issuer_sig["issuer_key_ref"]:
                raise ContractViolation(
                    "F1 claim issuer_key_ref != issuer_signature.issuer_key_ref"
                )
            if params["trust_ring_ref"] != issuer_sig["trust_ring_ref"]:
                raise ContractViolation(
                    "F1 claim trust_ring_ref != issuer_signature.trust_ring_ref"
                )

    if audit_report["build_session_ref"] != cert["subject"]["build_session_ref"]:
        raise ContractViolation("audit_report.build_session_ref mismatch")
    if (
        audit_report["ledger_seal_statement_digest"]
        != cert["ledger_seal_projection"]["seal_statement_digest"]
    ):
        raise ContractViolation("audit_report.ledger_seal_statement_digest mismatch")
    if audit_report["compiler_register_versions"] != manifest["compiler_register_versions"]:
        raise ContractViolation(
            "audit_report.compiler_register_versions != manifest.compiler_register_versions"
        )
    for claim in manifest["claims"]:
        if claim["claim_id"] == "G1":
            root = claim["payload"]["params"]["manifest_root_digest"]
            if root == _ZERO_SHA:
                raise ContractViolation("G1 manifest_root_digest must be nonzero")
            if audit_report["client_evidence_manifest_root"] != root:
                raise ContractViolation("audit_report.client_evidence_manifest_root mismatch")
    if not any(claim["claim_id"] == "G1" for claim in manifest["claims"]):
        if audit_report["client_evidence_manifest_root"] is not None:
            raise ContractViolation(
                "audit_report.client_evidence_manifest_root must be null without G1"
            )

    audit_digest = _audit_report_digest(audit_report)
    for claim in manifest["claims"]:
        audit_refs = [
            r for r in claim["evidence_refs"] if r["evidence_kind"] == "audit_report_digest"
        ]
        if len(audit_refs) != 1:
            raise ContractViolation(
                f"claim {claim['claim_id']} does not carry exactly one "
                "audit_report_digest evidence reference"
            )
        if audit_refs[0]["evidence_digest"] != audit_digest:
            raise ContractViolation(
                f"claim {claim['claim_id']} audit_report_digest does not match the audit report"
            )

    expected_evidence_digests = _evidence_digests_projection(
        manifest["claims"],
        _audit_report_digest(audit_report) if not manifest["claims"] else None,
    )
    if manifest["evidence_digests"] != expected_evidence_digests:
        raise ContractViolation("evidence_digests projection disagrees with claims")

    printed_ids = [claim["claim_id"] for claim in manifest["claims"]]
    if len(printed_ids) != len(set(printed_ids)):
        raise ContractViolation("duplicate printed claim_id in claims array")
    printed_id_set = set(printed_ids)

    rows_by_id = {row["claim_id"]: row for row in audit_report["claim_support_rows"]}
    for row in audit_report["claim_support_rows"]:
        if (
            row["evidence_basis"] in {"issuer_verified", "client_declared"}
            and row["claim_id"] not in printed_id_set
        ):
            raise ContractViolation(
                f"audit row {row['claim_id']} is supported but not printed as a claim"
            )

    for claim in manifest["claims"]:
        row = rows_by_id.get(claim["claim_id"])
        if row is None or row["evidence_basis"] not in {"issuer_verified", "client_declared"}:
            raise ContractViolation(
                f"printed claim {claim['claim_id']} has no supporting audit row"
            )
        if row["claim_material_digest"] != _claim_material_digest(claim):
            raise ContractViolation(f"claim_material_digest mismatch for {claim['claim_id']}")
        if row["verifier"] != claim["verifier"]:
            raise ContractViolation(
                f"audit row {row['claim_id']} verifier != printed claim verifier"
            )


def _build_valid_fixture(bare_claims: list, with_co: bool = False) -> dict:
    """Build a fully cross-consistent certificate -- every claim's
    audit_report_digest evidence reference bound to the real, embedded
    top-level `audit_report` whose claim_material_digest rows match the
    exact printed claim material, and the embedded manifest document's
    digest equal to the signatures block's manifest_digest. Positive control
    for _verify_certificate_contract: passing this certificate through it
    must raise nothing."""
    claims, audit_report = _finalize_claims_with_audit([copy.deepcopy(c) for c in bare_claims])
    return _certificate(claims=claims, with_co=with_co, audit_report=audit_report)


def _apply_claim_mutation(cert: dict, index: int, mutator) -> None:
    """Mutate claim `index` identically in the certificate AND its embedded
    manifest document (so no spurious claims-mismatch violation), then
    re-derive the tiers/evidence_digests projections and manifest_digest
    (so no spurious projection/digest violation either) -- isolating
    whichever specific obligation the caller is probing as the only thing
    left stale."""
    mutator(cert["claims"][index])
    document = cert["signatures"]["unsigned_manifest"]["document"]
    mutator(document["claims"][index])
    document["tiers"] = _tiers_projection(document["claims"])
    document["evidence_digests"] = _evidence_digests_projection(
        document["claims"], _audit_report_digest(cert["audit_report"])
    )
    manifest_digest = _unsigned_manifest_digest(document)
    cert["signatures"]["unsigned_manifest"]["manifest_digest"] = manifest_digest
    co = cert["signatures"].get("co_attestation")
    if co is not None:
        _rebind_co_projection_digest(cert)


def _rebind_audit_report_digest(cert: dict) -> None:
    """Rebind every printed claim to the current report, then re-sign parents."""
    audit_digest = _audit_report_digest(cert["audit_report"])
    for claims in (
        cert["claims"],
        cert["signatures"]["unsigned_manifest"]["document"]["claims"],
    ):
        for claim in claims:
            claim["evidence_refs"] = [
                ref
                for ref in claim["evidence_refs"]
                if ref.get("evidence_kind") != "audit_report_digest"
            ] + [{"evidence_kind": "audit_report_digest", "evidence_digest": audit_digest}]
    document = cert["signatures"]["unsigned_manifest"]["document"]
    document["tiers"] = _tiers_projection(document["claims"])
    document["evidence_digests"] = _evidence_digests_projection(document["claims"], audit_digest)
    manifest_digest = _unsigned_manifest_digest(document)
    cert["signatures"]["unsigned_manifest"]["manifest_digest"] = manifest_digest
    co = cert["signatures"].get("co_attestation")
    if co is not None:
        _rebind_co_projection_digest(cert)


def _rebind_claim_material_and_audit(cert: dict) -> None:
    """Rebind supported rows, then the report digest and signed manifest."""
    claims = cert["claims"]
    rows = cert["audit_report"]["claim_support_rows"]
    for row in rows:
        if row["evidence_basis"] in {"issuer_verified", "client_declared"}:
            claim = next(c for c in claims if c["claim_id"] == row["claim_id"])
            row["claim_material_digest"] = _claim_material_digest(claim)
    _rebind_audit_report_digest(cert)


def _mutate_payload(claim: dict) -> None:
    claim["payload"]["claim_id"] = "D2"


def _mutate_tier(claim: dict) -> None:
    claim["tier"] = 2


def _mutate_verifier(claim: dict) -> None:
    claim["verifier"]["verifier_version"] = "9.9.9"


def _mutate_non_audit_evidence(claim: dict) -> None:
    for ref in claim["evidence_refs"]:
        if ref["evidence_kind"] != "audit_report_digest":
            ref["evidence_digest"] = _SHA_B
            return


class TestEnvelope:
    def test_v2_g1_rendering_and_scope_are_exact(self) -> None:
        certificate = _certificate()
        claim = certificate["claims"][0]
        root = claim["payload"]["params"]["manifest_root_digest"]
        assert claim["payload"]["template_id"] == (
            "tmpl.cert.g1.client_evidence_manifest_commitment.v2"
        )
        assert claim["rendered_text"] == (
            "The pinned client key co-signed the declaration that evidence-manifest root "
            f"{root} uses scheme sha256_secret_blinded_v1 and client attestor version 0.1.0. "
            "The declaration is unopened; correspondence to, possession of, and completeness "
            "of any underlying evidence are not proven."
        )
        assert certificate["certificate_scope_line"] == (
            "Scope: Certified Agent v0 verifies signatures, build-session binding, and an "
            "unopened client declaration. It does not certify the contents, quality, "
            "correctness, correspondence, possession, or completeness of the agent, "
            "evaluation dataset, evaluator, or build-process evidence."
        )

    def test_g1_old_possession_wording_is_rejected(self) -> None:
        claim = _g1_claim()
        claim["rendered_text"] = (
            "The client committed evidence-manifest root sha256:"
            + "a" * 64
            + " under scheme sha256_secret_blinded_v1 using client attestor version 0.1.0. "
            "The commitment proves the client held this manifest at commit time; it does not "
            "prove the manifest is complete."
        )
        assert _errors(CLAIMS, claim)

    def test_audit_rows_are_all_present_with_pinned_abstentions(self) -> None:
        rows = _certificate()["audit_report"]["claim_support_rows"]
        assert [row["claim_id"] for row in rows] == ["B1", "REG1", "C1", "D2", "F1", "G1", "G3"]
        assert all(row["evidence_basis"] == "abstained" for row in rows if row["claim_id"] != "G1")
        assert [row["abstention_code"] for row in rows if row["claim_id"] != "G1"] == [
            "verifier_not_run_or_not_pass",
            "unregistered_claim_id",
            "verifier_not_run_or_not_pass",
            "verifier_not_run_or_not_pass",
            "verifier_not_run_or_not_pass",
            "verifier_not_run_or_not_pass",
        ]

    def test_audit_basis_is_closed_and_legacy_status_is_rejected(self) -> None:
        report = _audit_report()
        report["claim_support_rows"][0]["evidence_basis"] = "server_verified"
        assert _errors(AUDIT_REPORT, report)
        report = _audit_report()
        report["claim_support_rows"][0]["support_status"] = "abstained"
        assert _errors(AUDIT_REPORT, report)

    def test_g1_cannot_be_promoted_to_issuer_verified(self) -> None:
        report = _audit_report_for_claims([_g1_claim()])
        row = next(row for row in report["claim_support_rows"] if row["claim_id"] == "G1")
        row["evidence_basis"] = "issuer_verified"
        assert _errors(AUDIT_REPORT, report)

    def test_b1_issuer_verified_row_is_schema_valid(self) -> None:
        claim = _b1_claim(tier=3)
        report = _audit_report_for_claims([claim])
        assert report["claim_support_rows"][0]["evidence_basis"] == "issuer_verified"
        assert not _errors(AUDIT_REPORT, report)

    def test_valid_certificate_accepted(self) -> None:
        assert not _errors(ENVELOPE, _certificate())

    def test_zero_g1_root_rejected(self) -> None:
        claim = _g1_claim(tier=1)
        claim["payload"]["params"]["manifest_root_digest"] = _ZERO_SHA
        assert _errors(CLAIMS, claim)

    def test_zero_claims_certificate_accepted(self) -> None:
        # Every v0 claim is conditional; a claims-empty certificate that still
        # prints all fourteen NON-claims is the honest v0 shape.
        assert not _errors(ENVELOPE, _certificate(claims=[]))

    def test_title_is_pinned(self) -> None:
        cert = _certificate()
        cert["certificate_title"] = "Agent Build Certificate"  # struck rename
        assert _errors(ENVELOPE, cert)

    def test_scope_line_is_pinned(self) -> None:
        cert = _certificate()
        cert["build_session_scope_line"] = "scope: build session"
        assert _errors(ENVELOPE, cert)

    def test_unknown_field_rejected(self) -> None:
        cert = _certificate()
        cert["narrative"] = "free text"
        assert _errors(ENVELOPE, cert)

    def test_subject_kind_is_build_session_only(self) -> None:
        cert = _certificate()
        cert["subject"]["subject_kind"] = "deployed_agent"
        assert _errors(ENVELOPE, cert)

    def test_hash_algorithm_rejects_sha256_default(self) -> None:
        # C0: the pre-correction compiler defaulted subject.hash_algorithm to
        # "sha256"; the pinned enum (best_config_hash_contract's
        # hash_algorithm) is exactly ["v1"], so that default produced a
        # schema-invalid certificate. An unknown value fails closed rather
        # than being tolerated or silently coerced.
        cert = _certificate()
        cert["subject"]["hash_algorithm"] = "sha256"
        assert _errors(ENVELOPE, cert)

    def test_hash_algorithm_rejects_unknown_value(self) -> None:
        cert = _certificate()
        cert["subject"]["hash_algorithm"] = "v2"
        assert _errors(ENVELOPE, cert)


class TestNonClaimPrintList:
    def test_thirteen_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"] = cert["non_claims"][:13]
        assert _errors(ENVELOPE, cert)

    def test_fifteen_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"] = cert["non_claims"] + [cert["non_claims"][0]]
        assert _errors(ENVELOPE, cert)

    def test_reordered_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"][0], cert["non_claims"][1] = (
            cert["non_claims"][1],
            cert["non_claims"][0],
        )
        assert _errors(ENVELOPE, cert)

    def test_non_claim_with_verifier_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"][0]["verifier"] = {
            "verifier_id": "ver.cert.smuggled",
            "verifier_version": "0.1.0",
            "result": "PASS",
        }
        assert _errors(ENVELOPE, cert)


class TestTierFour:
    """C6: tier 4 stays in the enum; emitting it is a compile error."""

    def test_tier_enum_still_contains_four(self) -> None:
        common = _load(CERT_DIR / "certification_common_v0_schema.json")
        assert common["definitions"]["ClaimTier"]["enum"] == [1, 2, 3, 4]

    def test_tier_four_claim_is_unconstructible(self) -> None:
        assert _errors(CLAIMS, _b1_claim(tier=4))

    def test_tier_four_certificate_is_unconstructible(self) -> None:
        assert _errors(ENVELOPE, _certificate(claims=[_b1_claim(tier=4)]))

    def test_only_g1_tier_one_constructible(self) -> None:
        assert _errors(CLAIMS, _d2_claim(tier=1))
        assert not _errors(CLAIMS, _g1_claim(tier=1))
        for claim in (_d2_claim(tier=2), _d2_claim(tier=3), _g1_claim(tier=2), _g1_claim(tier=3)):
            assert _errors(CLAIMS, claim)


class TestClaimNonClaimUnion:
    def test_claim_without_verifier_rejected(self) -> None:
        claim = _b1_claim()
        del claim["verifier"]
        assert _errors(CLAIMS, claim)

    def test_claim_with_null_verifier_rejected(self) -> None:
        # verifier=None must compile only to NonClaim — as a claim it is
        # rejected outright, never downgraded.
        claim = _b1_claim()
        claim["verifier"] = None
        assert _errors(CLAIMS, claim)

    def test_claim_with_failed_verifier_rejected(self) -> None:
        claim = _b1_claim()
        claim["verifier"]["result"] = "FAIL"
        assert _errors(CLAIMS, claim)

    def test_claim_with_versionless_verifier_rejected(self) -> None:
        claim = _b1_claim()
        del claim["verifier"]["verifier_version"]
        assert _errors(CLAIMS, claim)

    def test_claim_without_evidence_rejected(self) -> None:
        claim = _b1_claim()
        claim["evidence_refs"] = []
        assert _errors(CLAIMS, claim)

    def test_unregistered_claim_ids_rejected(self) -> None:
        # B1c and D6a are struck invented IDs; A1/B4 are real matrix rows but
        # outside the conditional v0 allowlist. "D5" and "B3" are the C6
        # rulings' colliding aliases (D5 -> matrix F1 issuer signature; B3 is
        # the matrix's adverse-history row, NOT the registry receipt) — the
        # matrix IDs are canonical on the wire, so both raw aliases must be
        # rejected rather than silently accepted with the wrong semantics.
        for bogus in ("B1c", "D6a", "A1", "B4", "D5", "B3"):
            claim = _b1_claim()
            claim["claim_id"] = bogus
            claim["payload"]["claim_id"] = bogus
            assert _errors(CLAIMS, claim), bogus

    def test_claim_id_reconciliation_documented(self) -> None:
        # The claim-ID reconciliation (rulings namespace -> canonical matrix
        # IDs) must stay documented in the wire schema so matrix B3 (adverse
        # history, amendment A8) is visibly pending, never silently dropped.
        claims = _load(CERT_DIR / CLAIMS)
        doc = claims["definitions"]["ClaimIdV0"]["description"]
        assert "RECONCILIATION TABLE" in doc
        assert "Adverse history" in doc.replace("ADVERSE HISTORY", "Adverse history")
        assert "A8" in doc
        assert "F1" in doc and "REG1" in doc

    def test_payload_claim_id_mismatch_rejected(self) -> None:
        claim = _b1_claim()
        claim["payload"] = _g1_claim()["payload"]
        assert _errors(CLAIMS, claim)

    def test_free_text_param_rejected(self) -> None:
        claim = _b1_claim()
        claim["payload"]["params"]["note"] = "free text"
        assert _errors(CLAIMS, claim)

    def test_claim_sentence_field_unrepresentable(self) -> None:
        claim = _b1_claim()
        claim["claim_sentence"] = "The ledger is intact."
        assert _errors(CLAIMS, claim)


class TestTemplates:
    def test_b1_template_uses_narrow_wording(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        text = catalog["definitions"]["TemplateB1V1"]["properties"]["template_text"]["const"]
        assert text.startswith("The issuer signed this seal statement")
        assert "intact" not in text
        assert "complete build history" not in text

    def test_exactly_seven_templates_pinned(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        ids = set()
        for definition in catalog["definitions"].values():
            ids.add(definition["properties"]["template_id"]["const"])
        assert len(ids) == 7
        for claim_id in ("b1", "c1", "d2", "f1", "g1", "g3", "reg1"):
            assert any(f".{claim_id}." in tid for tid in ids), claim_id

    def test_template_records_validate(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        for name, definition in catalog["definitions"].items():
            record = {
                "template_id": definition["properties"]["template_id"]["const"],
                "template_text": definition["properties"]["template_text"]["const"],
                "parameter_slots": definition["properties"]["parameter_slots"]["const"],
            }
            assert not _errors(TEMPLATES, record), name

    def test_template_slots_match_payload_params(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        payloads = _load(CERT_DIR / "certificate_claim_payloads_v0_schema.json")
        slot_map = {}
        for definition in catalog["definitions"].values():
            tid = definition["properties"]["template_id"]["const"]
            slot_map[tid] = set(definition["properties"]["parameter_slots"]["const"])
        for name, payload in payloads["definitions"].items():
            if name == "ClaimPayloadV0":
                continue
            tid = payload["properties"]["template_id"]["const"]
            required = set(payload["properties"]["params"]["required"])
            assert slot_map[tid] <= required | set(payload["properties"]["params"]["properties"]), (
                name
            )


class TestCoAttestationBinding:
    def test_tier_one_claim_requires_co_attestation(self) -> None:
        cert = _certificate(claims=[_g1_claim(tier=1)], with_co=False)
        assert _errors(ENVELOPE, cert)

    def test_tier_one_claim_with_co_attestation_accepted(self) -> None:
        cert = _certificate(claims=[_g1_claim(tier=1)], with_co=True)
        assert not _errors(ENVELOPE, cert)

    def test_issuer_never_covers_present_co_attestation(self) -> None:
        sigs = _signatures(with_co=True)
        assert sigs["issuer_signature"]["signed_payload"] == ["unsigned_manifest"]
        assert not _errors(SIGNATURES, sigs)

    def test_issuer_payload_is_unchanged_for_b1_only_certificate(self) -> None:
        sigs = _signatures(with_co=False)
        assert sigs["issuer_signature"]["signed_payload"] == ["unsigned_manifest"]
        assert not _errors(SIGNATURES, sigs)

    def test_manifest_coverage_is_pinned(self) -> None:
        sigs = _signatures()
        sigs["unsigned_manifest"]["coverage"] = ["subject", "seal"]
        assert _errors(SIGNATURES, sigs)


class TestSignatureProtocol:
    """Shape/protocol vectors; these tests do not perform cryptography."""

    def test_signature_bytes_are_exact_64_raw_bytes_in_canonical_base64(self) -> None:
        assert _strict_signature_raw(_SIG) == _SIG_RAW
        for value in (
            "A" * 84 + "===",
            "A" * 86 + "=",
            "!" * 86 + "==",
            "A" * 85 + "B==",
        ):
            with pytest.raises(ValueError):
                _strict_signature_raw(value)

    def test_client_signed_material_known_answer(self) -> None:
        material = _client_signed_material(b'{"a":1}')
        assert material.hex() == (
            "7472616967656e742e6167656e745f63657274696669636174652e"
            "636c69656e745f636f5f6174746573746174696f6e2e763000000000"
            "000000077b2261223a317d"
        )
        assert hashlib.sha256(material).hexdigest() == (
            "54fed555c8cdab557d927b6bc9c27690ca8fab11403fb8e65e6f8238fb9ae56b"
        )

    def test_issuer_signed_material_known_answer(self) -> None:
        material = _issuer_signed_material(b'{"a":1}')
        assert material.hex() == (
            "7472616967656e742e6167656e745f63657274696669636174652e"
            "6973737565725f7369676e61747572652e763000000000000000077b"
            "2261223a317d"
        )
        assert hashlib.sha256(material).hexdigest() == (
            "bbbd57422094b975fc9e7ad3a5fcadc59747fe654b9f0d1b0a4124e27bdec628"
        )

    def test_published_signature_preimage_wording_matches_vectors(self) -> None:
        signatures_description = _load(CERT_DIR / SIGNATURES)["description"]
        common_description = _load(CERT_DIR / "certification_common_v0_schema.json")["definitions"][
            "SignedMaterialDomainTagV0"
        ]["description"]
        issuer_phrase = (
            "UTF8(`traigent.agent_certificate.issuer_signature.v0`) || "
            "uint64be(len(manifest_jcs_bytes)) || manifest_jcs_bytes"
        )
        client_phrase = (
            "UTF8(`traigent.agent_certificate.client_co_attestation.v0`) || "
            "uint64be(len(certificate_projection_jcs_bytes)) || "
            "certificate_projection_jcs_bytes"
        )
        assert issuer_phrase in signatures_description
        assert client_phrase in signatures_description
        assert issuer_phrase in common_description
        assert client_phrase in common_description
        assert "0x00" not in signatures_description
        assert "co_signature_raw" not in signatures_description

    def test_signed_material_length_framing_and_role_substitution_mutate_answer(
        self,
    ) -> None:
        manifest = b'{"a":1}'
        client = _client_signed_material(manifest)
        assert _client_signed_material(manifest + b" ") != client
        assert _issuer_signed_material(manifest) != (
            b"traigent.agent_certificate.client_co_attestation.v0"
            + client[len(b"traigent.agent_certificate.client_co_attestation.v0") :]
        )

    def test_signed_payload_is_always_the_unsigned_manifest(self) -> None:
        assert not _errors(SIGNATURES, _signatures(with_co=False))
        assert not _errors(SIGNATURES, _signatures(with_co=True))
        absent = _signatures(with_co=False)
        absent["issuer_signature"]["signed_payload"] = ["unsigned_manifest", "co_attestation"]
        assert _errors(SIGNATURES, absent)
        present = _signatures(with_co=True)
        present["issuer_signature"]["signed_payload"] = ["unsigned_manifest"]
        assert not _errors(SIGNATURES, present)


class TestLedgerSeals:
    def test_valid_seal_statement_accepted(self) -> None:
        assert not _errors(LEDGER, _seal_statement())

    def test_missing_stream_rejected(self) -> None:
        seal = _seal_statement()
        del seal["expected_stream_projection"]["transition_stream"]
        assert _errors(LEDGER, seal)

    def test_sealed_stream_without_root_rejected(self) -> None:
        seal = _seal_statement()
        del seal["expected_stream_projection"]["decision_stream"]["root_commitment"]
        assert _errors(LEDGER, seal)

    def test_legacy_stream_with_root_rejected(self) -> None:
        # legacy-NULL-chain presented as chained: a legacy stream may not carry
        # a root commitment.
        seal = _seal_statement()
        entry = seal["expected_stream_projection"]["decision_stream"]
        entry["chain_status"] = "legacy_unsealed"
        assert _errors(LEDGER, seal)

    def test_legacy_stream_without_root_rejected_for_b_v0(self) -> None:
        seal = _seal_statement()
        entry = seal["expected_stream_projection"]["decision_stream"]
        entry["chain_status"] = "legacy_unsealed"
        del entry["root_commitment"]
        assert _errors(LEDGER, seal)

    def test_b_v0_requires_exact_real_stream_profile(self) -> None:
        seal = _seal_statement()
        projection = seal["expected_stream_projection"]
        assert set(seal) == {
            "seal_ref",
            "chain_schema_version",
            "build_session_ref",
            "expected_stream_projection",
            "seal_statement_digest",
        }
        assert all(
            set(entry) == {"stream_family", "chain_status", "root_commitment"}
            for entry in projection.values()
        )
        assert projection["decision_stream"]["chain_status"] == "empty_sealed"
        assert projection["receipt_event_stream"]["chain_status"] == "sealed"
        assert projection["transition_stream"]["chain_status"] == "sealed"
        assert not _errors(LEDGER, seal)

    @pytest.mark.parametrize(
        ("stream", "status"),
        [
            ("decision_stream", "sealed"),
            ("receipt_event_stream", "empty_sealed"),
            ("transition_stream", "empty_sealed"),
        ],
    )
    def test_b_v0_rejects_wrong_stream_status(self, stream: str, status: str) -> None:
        seal = _seal_statement()
        seal["expected_stream_projection"][stream]["chain_status"] = status
        assert _errors(LEDGER, seal)

    def test_zero_root_commitment_is_synthetic_and_rejected(self) -> None:
        seal = _seal_statement()
        seal["expected_stream_projection"]["decision_stream"]["root_commitment"] = _ZERO_SHA
        assert _errors(LEDGER, seal)

    def test_unsupported_build_ledger_profile_rejected(self) -> None:
        seal = _seal_statement()
        seal["chain_schema_version"] = "traigent.cert_ledger.v0"
        assert _errors(LEDGER, seal)

    def test_null_chain_status_rejected(self) -> None:
        seal = _seal_statement()
        seal["expected_stream_projection"]["decision_stream"]["chain_status"] = None
        assert _errors(LEDGER, seal)

    def test_counts_and_terminal_seq_unrepresentable(self) -> None:
        seal = _seal_statement()
        seal["event_count"] = 12
        assert _errors(LEDGER, seal)
        seal = _seal_statement()
        seal["expected_stream_projection"]["decision_stream"]["terminal_seq"] = 7
        assert _errors(LEDGER, seal)

    @pytest.mark.parametrize(
        "private_field",
        [
            "chain_id",
            "event_ref",
            "event_refs",
            "entry_count",
            "terminal_seq",
            "sequence",
            "hmac",
            "hmac_key_id",
            "key_id",
            "contents",
            "paths",
            "filenames",
            "blinds",
        ],
    )
    def test_private_ledger_material_is_unrepresentable(self, private_field: str) -> None:
        seal = _seal_statement()
        seal[private_field] = "private"
        assert _errors(LEDGER, seal)

    @pytest.mark.parametrize("status", ["legacy_unsealed", "not_applicable"])
    def test_envelope_rejects_nonsealed_stream_statuses(self, status: str) -> None:
        cert = _certificate(claims=[])
        entry = cert["ledger_seal_projection"]["expected_stream_projection"]["decision_stream"]
        entry["chain_status"] = status
        entry.pop("root_commitment", None)
        cert["signatures"]["unsigned_manifest"]["document"]["seal"] = copy.deepcopy(
            cert["ledger_seal_projection"]
        )
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _unsigned_manifest_digest(
            cert["signatures"]["unsigned_manifest"]["document"]
        )
        assert _errors(ENVELOPE, cert)


class TestRegistries:
    def _agent_revision_record(self) -> dict:
        return {
            "schema_version": "traigent.certificate_registry.agent_revision.v0",
            "revision_id": "arv:abcdef0123456789",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization_profile": "jcs_v1",
            "blinded_revision_commitment": _SHA,
            "canonical_record_digest": _SHA_B,
        }

    def _measurement_contract_record(self) -> dict:
        return {
            "schema_version": ("traigent.certificate_registry.measurement_contract.v0"),
            "contract_id": "mct:abcdef0123456789",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization_profile": "jcs_v1",
            "blinded_contract_commitment": _SHA,
            "canonical_record_digest": _SHA_B,
        }

    def test_valid_records_accepted(self) -> None:
        assert not _errors(REG_AR, self._agent_revision_record())
        assert not _errors(REG_MC, self._measurement_contract_record())

    def test_parent_ref_is_optional_declared_link(self) -> None:
        record = self._agent_revision_record()
        record["parent_revision_ref"] = "arv:fedcba9876543210"
        assert not _errors(REG_AR, record)

    def test_counts_unrepresentable(self) -> None:
        for field in ("material_kind_counts", "item_count", "event_count"):
            record = self._agent_revision_record()
            record[field] = 3
            assert _errors(REG_AR, record), field

    def test_date_buckets_and_timestamps_unrepresentable(self) -> None:
        for field in ("created_at", "created_bucket", "registration_date"):
            record = self._agent_revision_record()
            record[field] = "2026-08-11"
            assert _errors(REG_AR, record), field
            record = self._measurement_contract_record()
            record[field] = "2026-08-11"
            assert _errors(REG_MC, record), field

    def test_measurement_detail_fields_unrepresentable(self) -> None:
        # Metric IDs, dataset size, split policy, and seed stay inside the
        # committed client-local document.
        for field, value in (
            ("metric_ids", ["accuracy"]),
            ("dataset_size", 100),
            ("split_policy", "holdout"),
            ("seed", 42),
        ):
            record = self._measurement_contract_record()
            record[field] = value
            assert _errors(REG_MC, record), field

    def test_free_text_name_unrepresentable(self) -> None:
        record = self._agent_revision_record()
        record["name"] = "my agent"
        assert _errors(REG_AR, record)


class TestRejection:
    def test_valid_rejection_accepted(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "tier4_emission_attempt",
            "structural_path": [
                {"segment_kind": "property", "property_name": "claims"},
                {"segment_kind": "index", "index": 0},
                {"segment_kind": "property", "property_name": "tier"},
            ],
        }
        assert not _errors(REJECTION, rejection)

    def test_rejected_value_unrepresentable(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "unknown_field",
            "structural_path": [],
            "rejected_value": "tuned free text",
        }
        assert _errors(REJECTION, rejection)

    def test_message_field_unrepresentable(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "unknown_field",
            "structural_path": [],
            "message": "boom",
        }
        assert _errors(REJECTION, rejection)

    def test_unsupported_definition_codes_present(self) -> None:
        # C6 Ruling 3(ii): the operational definition of "unsupported".
        schema = _load(CERT_DIR / REJECTION)
        codes = set(schema["definitions"]["RejectionCodeV0"]["enum"])
        assert {
            "unregistered_claim_id",
            "missing_or_versionless_verifier",
            "verifier_not_run_or_not_pass",
            "missing_evidence_binding",
            "prohibited_register_violation",
        } <= codes


def _walk(node: object):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


class TestBoundaryDiscipline:
    """Structural lint: no free-text channel exists anywhere in the family."""

    def test_every_string_is_bounded(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "string":
                    assert "const" in node or "enum" in node or "pattern" in node, (
                        f"{file_name}: unconstrained string node {node}"
                    )

    def test_every_object_is_closed(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "object" and "properties" in node:
                    assert node.get("additionalProperties") is False, (
                        f"{file_name}: open object node {sorted(node['properties'])}"
                    )

    def test_every_array_is_bounded(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "array":
                    assert "maxItems" in node, f"{file_name}: unbounded array node"

    def test_no_x_content_carrier_reachable(self) -> None:
        """The free-text quarantine (C1 Ruling 5): the certification family's
        transitive $ref closure must never reach an x-content / user_content
        carrier, and must not reach the known current-online free-text carrier
        files at all."""
        forbidden_files = {
            "execution/metric_submission_schema.json",
            "optimization/optimization_endpoints.json",
        }
        seen: set[str] = set()

        def resolve(current: Path, ref: str) -> Path | None:
            ref = ref.split("#")[0]
            if not ref:
                return None
            if ref.startswith(_SCHEMA_BASE):
                return SCHEMAS_DIR / ref[len(_SCHEMA_BASE) :]
            if ref.startswith(("http://", "https://", "urn:")):
                return None
            return (current.parent / ref).resolve()

        def visit(path: Path) -> None:
            rel = path.resolve().relative_to(SCHEMAS_DIR.resolve()).as_posix()
            if rel in seen:
                return
            seen.add(rel)
            for match in re.finditer(r'"\$ref"\s*:\s*"([^"]+)"', path.read_text(encoding="utf-8")):
                target = resolve(path, match.group(1))
                if target is not None and target.exists():
                    visit(target)

        for file_name in CERT_FILES:
            visit(CERT_DIR / file_name)

        assert not (seen & forbidden_files), seen & forbidden_files
        for rel in seen:
            assert not rel.startswith(("observability/", "datasets/")), rel
            content = (SCHEMAS_DIR / rel).read_text(encoding="utf-8")
            data = json.loads(content)
            for node in _walk(data):
                assert node.get("x-content") is not True, (
                    f"{rel}: x-content carrier reachable from certification/"
                )
                assert node.get("x-privacy-classification") != "user_content", (
                    f"{rel}: user_content carrier reachable from certification/"
                )

    def test_schemas_are_valid_draft7(self) -> None:
        for file_name in CERT_FILES:
            Draft7Validator.check_schema(_load(CERT_DIR / file_name))


class TestClaimIdAllowlist:
    def test_exactly_seven_claim_ids(self) -> None:
        claims = _load(CERT_DIR / CLAIMS)
        assert claims["definitions"]["ClaimIdV0"]["enum"] == [
            "B1",
            "C1",
            "D2",
            "F1",
            "G1",
            "G3",
            "REG1",
        ]

    def test_fourteen_non_claim_ids(self) -> None:
        claims = _load(CERT_DIR / CLAIMS)
        assert len(claims["definitions"]["NonClaimIdV0"]["enum"]) == 14

    def test_all_seven_payloads_constructible(self) -> None:
        payload_examples = {
            "B1": _b1_claim()["payload"],
            "REG1": {
                "claim_id": "REG1",
                "template_id": "tmpl.cert.reg1.registry_commitment_receipt.v1",
                "params": {
                    "registry_kind": "agent_revision",
                    "registry_record_ref": "arv:abcdef0123456789",
                    "commitment_scheme": "sha256_secret_blinded_v1",
                    "canonical_record_digest": _SHA,
                },
            },
            "C1": {
                "claim_id": "C1",
                "template_id": ("tmpl.cert.c1.artifact_scoped_no_unsupported_claims.v1"),
                "params": {
                    "compiler_version": "0.1.0",
                    "semantics_manifest_digest": _SHA,
                    "prohibited_register_digest": _SHA,
                    "verifier_catalog_digest": _SHA,
                },
            },
            "D2": {
                "claim_id": "D2",
                "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
                "params": {
                    "declared_mode": "offline",
                    "witness_kind": "strace_network_trace",
                    "sdk_ref": _SDK_SHA,
                    "workload_class": ("mock_grid_no_integrations_no_analytics_no_langfuse"),
                    "witness_bundle_digest": _SHA,
                },
            },
            "F1": {
                "claim_id": "F1",
                "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
                "params": {
                    "signature_scheme": "ed25519",
                    "issuer_key_ref": "ikey:abcdef0123456789",
                    "trust_ring_ref": "ring:abcdef0123456789",
                },
            },
            "G1": _g1_claim()["payload"],
            "G3": {
                "claim_id": "G3",
                "template_id": "tmpl.cert.g3.cosigner_identity_binding.v1",
                "params": {
                    "client_key_ref": "ckr:" + "A" * 43,
                },
            },
        }
        for claim_id, payload in payload_examples.items():
            claim = _b1_claim()
            claim["claim_id"] = claim_id
            claim["payload"] = copy.deepcopy(payload)
            assert not _errors(PAYLOADS, payload), claim_id

    def test_d2_workload_class_is_closed(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "D2"
        claim["payload"] = {
            "claim_id": "D2",
            "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
            "params": {
                "declared_mode": "offline",
                "witness_kind": "strace_network_trace",
                "sdk_ref": _SDK_SHA,
                "workload_class": "any workload we like",
                "witness_bundle_digest": _SHA,
            },
        }
        assert _errors(CLAIMS, claim)

    def test_d2_requires_full_sha_pin(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "D2"
        claim["payload"] = {
            "claim_id": "D2",
            "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
            "params": {
                "declared_mode": "offline",
                "witness_kind": "strace_network_trace",
                "sdk_ref": "e97b030f",  # short SHA: witness must be full-ref pinned
                "workload_class": ("mock_grid_no_integrations_no_analytics_no_langfuse"),
                "witness_bundle_digest": _SHA,
            },
        }
        assert _errors(CLAIMS, claim)

    def test_d2_requires_sdk_witness_bundle_evidence(self) -> None:
        claim = _d2_claim(tier=1)
        claim["evidence_refs"] = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] != "sdk_witness_bundle"
        ]
        assert _errors(CLAIMS, claim)

    def test_d2_rejects_distinct_duplicate_sdk_evidence_shapes_at_schema(self) -> None:
        claim = _d2_claim(tier=1)
        claim["evidence_refs"].append(
            {"evidence_kind": "sdk_witness_bundle", "evidence_digest": _SHA_B}
        )
        assert _errors(CLAIMS, claim)

    @pytest.mark.parametrize("claim_id", ["C1", "F1", "G3"])
    def test_current_v0_rejects_self_referential_or_postfinalization_claims(self, claim_id) -> None:
        claim = {
            "B1": _b1_claim,
            "C1": _c1_claim,
            "F1": _f1_claim,
            "G3": _g3_claim,
        }[claim_id]()
        assert _errors(CLAIMS, claim)

    def test_current_v0_allows_narrow_b1_issuer_assertion(self) -> None:
        assert not _errors(CLAIMS, _b1_claim(tier=3))

    def test_current_v0_rejects_pending_reg1_emission(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "REG1"
        claim["payload"] = {
            "claim_id": "REG1",
            "template_id": "tmpl.cert.reg1.registry_commitment_receipt.v1",
            "params": {
                "registry_kind": "agent_revision",
                "registry_record_ref": "arv:abcdef0123456789",
                "commitment_scheme": "sha256_secret_blinded_v1",
                "canonical_record_digest": _SHA,
            },
        }
        assert _errors(CLAIMS, claim)

    @pytest.mark.parametrize("claim_id", ["D2", "G1"])
    def test_current_v0_rejects_tier_inflation(self, claim_id) -> None:
        claim_factory = _d2_claim if claim_id == "D2" else _g1_claim
        if claim_id == "D2":
            assert _errors(CLAIMS, claim_factory(tier=1))
            return
        assert not _errors(CLAIMS, claim_factory(tier=1))
        for tier in (2, 3, 4):
            assert _errors(CLAIMS, claim_factory(tier=tier))


class TestUnsignedManifest:
    """SCHEMA-1 gap C1: the twelve promised coverage sections each have
    concrete typed preimage data in UnsignedManifestV0, not just a label in
    UnsignedManifestCoverageV0."""

    def test_valid_manifest_accepted(self) -> None:
        assert not _errors(UNSIGNED_MANIFEST, _unsigned_manifest())

    def test_zero_claims_manifest_accepted(self) -> None:
        assert not _errors(UNSIGNED_MANIFEST, _unsigned_manifest(claims=[]))

    def test_zero_claims_manifest_still_carries_leading_audit_binding(self) -> None:
        manifest = _unsigned_manifest(claims=[], audit_report_digest=_SHA)
        assert manifest["evidence_digests"] == [
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA}
        ]
        assert not _errors(UNSIGNED_MANIFEST, manifest)
        manifest["evidence_digests"] = []
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_each_required_section_is_mandatory(self) -> None:
        for section in _COVERAGE:
            manifest = _unsigned_manifest()
            del manifest[section]
            assert _errors(UNSIGNED_MANIFEST, manifest), section

    def test_thirteenth_section_rejected(self) -> None:
        manifest = _unsigned_manifest()
        manifest["narrative"] = "free text"
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_coverage_list_matches_manifest_required_sections(self) -> None:
        # Keeps UnsignedManifestCoverageV0's const list (signatures schema)
        # and UnsignedManifestV0's required-property list (this schema) from
        # drifting apart -- the correspondence both schemas' docstrings
        # promise since they cannot $ref each other without a file cycle.
        manifest_schema = _load(CERT_DIR / UNSIGNED_MANIFEST)
        required = manifest_schema["definitions"]["UnsignedManifestV0"]["required"]
        assert sorted(required) == sorted(_COVERAGE)

    def test_evidence_projection_order_is_audit_then_claim_first_occurrence(self) -> None:
        first = _g1_claim(tier=1)
        first["evidence_refs"] = [
            {"evidence_kind": "client_commitment_digest", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ]
        second = _g1_claim(tier=1)
        second["evidence_refs"] = [
            {"evidence_kind": "client_commitment_digest", "evidence_digest": _SHA},
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
        ]
        projection = _evidence_digests_projection([first, second], audit_report_digest=_SHA_B)
        assert projection == [
            {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA_B},
            {"evidence_kind": "client_commitment_digest", "evidence_digest": _SHA},
        ]
        manifest = _unsigned_manifest(claims=[first], audit_report_digest=_SHA_B)
        assert not _errors(UNSIGNED_MANIFEST, manifest)
        manifest["evidence_digests"].reverse()
        assert _errors(UNSIGNED_MANIFEST, manifest) is not None

    def test_schema_oracle_rejects_locator_on_leading_audit_entry(self) -> None:
        # Build the two item instances independently of the fixture/projection
        # helpers, then ask Draft-07 to oracle the loaded schema directly.
        schema = _load(CERT_DIR / UNSIGNED_MANIFEST)
        first_item = copy.deepcopy(schema["definitions"]["EvidenceDigestsProjectionV0"]["items"][0])
        first_item["allOf"][0]["$ref"] = (
            "https://schemas.traigent.ai/certification/"
            "certificate_evidence_refs_v0_schema.json#/definitions/EvidenceRefV0"
        )
        first_validator = Draft7Validator(first_item, registry=_REGISTRY)
        leading = {
            "evidence_kind": "audit_report_digest",
            "evidence_digest": _SHA,
            "evidence_ref": "evidence:locator001",
        }
        assert list(first_validator.iter_errors(leading))

        generic_validator = Draft7Validator(
            {
                "$ref": (
                    "https://schemas.traigent.ai/certification/"
                    "certificate_evidence_refs_v0_schema.json#/definitions/EvidenceRefV0"
                )
            },
            registry=_REGISTRY,
        )
        later = {
            "evidence_kind": "client_commitment_digest",
            "evidence_digest": _SHA,
            "evidence_ref": "evidence:locator001",
        }
        assert not list(generic_validator.iter_errors(later))

    def test_privacy_mode_enum_is_closed(self) -> None:
        manifest = _unsigned_manifest()
        manifest["privacy_mode"]["declared_mode"] = "hybrid"
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_freshness_requires_nonce(self) -> None:
        manifest = _unsigned_manifest()
        del manifest["freshness"]["nonce"]
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_freshness_carries_no_timestamp_field(self) -> None:
        # Explicit SCHEMA-1 boundary: freshness carries only the nonce
        # pending its own Disclosure Register ruling on precise timestamps.
        manifest = _unsigned_manifest()
        manifest["freshness"]["issued_at"] = "2026-08-24T00:00:00Z"
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_key_ring_identifiers_client_key_ref_optional(self) -> None:
        manifest = _unsigned_manifest(with_co=False)
        assert "client_key_ref" not in manifest["key_ring_identifiers"]
        assert "client_signature_algorithm" not in manifest["key_ring_identifiers"]
        assert manifest["key_ring_identifiers"]["issuer_signature_algorithm"] == "ed25519"
        assert not _errors(UNSIGNED_MANIFEST, manifest)

        manifest_with_co = _unsigned_manifest(with_co=True)
        assert "client_key_ref" in manifest_with_co["key_ring_identifiers"]
        assert manifest_with_co["key_ring_identifiers"]["client_signature_algorithm"] == "ed25519"
        assert not _errors(UNSIGNED_MANIFEST, manifest_with_co)

    def test_key_ring_client_algorithm_is_an_iff_pair(self) -> None:
        manifest = _unsigned_manifest(with_co=False)
        manifest["key_ring_identifiers"]["client_signature_algorithm"] = "ed25519"
        assert _errors(UNSIGNED_MANIFEST, manifest)

        manifest = _unsigned_manifest(with_co=True)
        del manifest["key_ring_identifiers"]["client_signature_algorithm"]
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_key_ring_issuer_algorithm_is_required(self) -> None:
        manifest = _unsigned_manifest()
        del manifest["key_ring_identifiers"]["issuer_signature_algorithm"]
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_hash_algorithm_rejects_sha256_default(self) -> None:
        manifest = _unsigned_manifest()
        manifest["subject"]["hash_algorithm"] = "sha256"
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_malformed_semantics_digest_rejected(self) -> None:
        manifest = _unsigned_manifest()
        manifest["compiler_register_versions"]["semantics_manifest_digest"] = "not-a-digest"
        assert _errors(UNSIGNED_MANIFEST, manifest)

    def test_malformed_key_ref_rejected(self) -> None:
        manifest = _unsigned_manifest()
        manifest["key_ring_identifiers"]["issuer_key_ref"] = "not an opaque ref"
        assert _errors(UNSIGNED_MANIFEST, manifest)


class TestClientEvidenceManifest:
    """SCHEMA-1 gap C5: the fixed four-slot client-local evidence manifest
    for agent revision, evaluation dataset, evaluator, and build-process
    evidence -- only the canonical root ever crosses the Backend boundary."""

    def test_valid_manifest_accepted(self) -> None:
        assert not _errors(CLIENT_EVIDENCE_MANIFEST, _client_evidence_manifest())

    def test_each_slot_is_mandatory(self) -> None:
        for slot in (
            "agent_revision",
            "evaluation_dataset",
            "evaluator",
            "build_process_evidence",
        ):
            manifest = _client_evidence_manifest()
            del manifest[slot]
            assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest), slot

    def test_fifth_slot_rejected(self) -> None:
        manifest = _client_evidence_manifest()
        manifest["dataset_name"] = "my_eval_set"
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

    def test_artifact_kind_cannot_be_copied_across_slots(self) -> None:
        # Duplicate-kinds-under-different-slots fixture class: each slot's
        # artifact_kind is const-pinned to its own property name, so a
        # commitment cannot be relabeled into a different slot.
        manifest = _client_evidence_manifest()
        manifest["evaluator"]["artifact_kind"] = "evaluation_dataset"
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

    def test_unknown_commitment_scheme_rejected(self) -> None:
        manifest = _client_evidence_manifest()
        manifest["agent_revision"]["commitment_scheme"] = "sha256_public_salt_v1"
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

    def test_malformed_slot_digest_rejected(self) -> None:
        manifest = _client_evidence_manifest()
        manifest["evaluator"]["slot_commitment_digest"] = "sha256:deadbeef"
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

    def test_no_blind_or_content_field_representable(self) -> None:
        manifest = _client_evidence_manifest()
        manifest["evaluation_dataset"]["blind"] = "a" * 64
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

        manifest = _client_evidence_manifest()
        manifest["evaluation_dataset"]["artifact_document"] = {"rows": 1}
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

        manifest = _client_evidence_manifest()
        manifest["evaluation_dataset"]["row_count"] = 100
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

        manifest = _client_evidence_manifest()
        manifest["agent_revision"]["filename"] = "agent.py"
        assert _errors(CLIENT_EVIDENCE_MANIFEST, manifest)

    def test_sha256_secret_blinded_v1_known_answer(self) -> None:
        used_blinds: set[bytes] = set()
        assert (
            _slot_commitment_digest(
                blind=bytes(range(32)),
                artifact_kind="evaluator",
                artifact_document={"alpha": "beta", "n": 1},
                used_blinds=used_blinds,
            )
            == "sha256:1229bb640ae4b62da3e6a7ac66bf935e38b3b75fdb0b494b9402d336816f9e14"
        )

    def test_sha256_secret_blinded_v1_domain_kind_content_and_blind_bindings(
        self,
    ) -> None:
        blind = bytes(range(32))
        digest = _slot_commitment_digest(
            blind=blind,
            artifact_kind="evaluator",
            artifact_document={"alpha": "beta", "n": 1},
            used_blinds=set(),
        )

        def _direct_digest(domain: bytes, kind: str, content: dict, key: bytes) -> str:
            preimage = (
                domain
                + b"\x00"
                + kind.encode("utf-8")
                + b"\x00"
                + fp2.canonicalize(content).encode("utf-8")
            )
            return "sha256:" + hmac.new(key, preimage, hashlib.sha256).hexdigest()

        assert digest != _direct_digest(
            b"traigent.cert.v0.slot_commitment.v2",
            "evaluator",
            {"alpha": "beta", "n": 1},
            blind,
        )
        assert digest != _direct_digest(
            _SLOT_COMMITMENT_DOMAIN,
            "evaluation_dataset",
            {"alpha": "beta", "n": 1},
            blind,
        )
        assert digest != _direct_digest(
            _SLOT_COMMITMENT_DOMAIN,
            "evaluator",
            {"alpha": "gamma", "n": 1},
            blind,
        )
        assert digest != _direct_digest(
            _SLOT_COMMITMENT_DOMAIN,
            "evaluator",
            {"alpha": "beta", "n": 1},
            bytes(reversed(range(32))),
        )

    def test_sha256_secret_blinded_v1_rejects_invalid_blind_and_reuse(self) -> None:
        used_blinds: set[bytes] = set()
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            _slot_commitment_digest(
                blind=b"short",
                artifact_kind="evaluator",
                artifact_document={},
                used_blinds=used_blinds,
            )

        blind = bytes(range(32))
        _slot_commitment_digest(
            blind=blind,
            artifact_kind="evaluator",
            artifact_document={},
            used_blinds=used_blinds,
        )
        with pytest.raises(ValueError, match="must not be reused"):
            _slot_commitment_digest(
                blind=blind,
                artifact_kind="agent_revision",
                artifact_document={},
                used_blinds=used_blinds,
            )

    def test_sha256_secret_blinded_v1_rejects_non_fp2_artifact_document(self) -> None:
        with pytest.raises(TypeError):
            _slot_commitment_digest(
                blind=bytes(range(32)),
                artifact_kind="evaluator",
                artifact_document={"score": 0.5},
                used_blinds=set(),
            )

    def test_manifest_root_is_computable_and_bindable_to_g1(self) -> None:
        manifest = _client_evidence_manifest()
        root = _client_evidence_root_digest(manifest)
        assert _DIGEST_PATTERN.match(root)

        g1_claim = _g1_claim()
        g1_claim["payload"]["params"]["manifest_root_digest"] = root
        assert not _errors(CLAIMS, g1_claim)

    def test_different_manifests_produce_different_roots(self) -> None:
        manifest_a = _client_evidence_manifest()
        manifest_b = _client_evidence_manifest()
        manifest_b["evaluator"]["slot_commitment_digest"] = _SHA_B
        assert _client_evidence_root_digest(manifest_a) != _client_evidence_root_digest(manifest_b)


class TestAuditReport:
    """SCHEMA-1 gap C4: a typed, content-free, acyclic pre-issuance audit
    report -- distinct from the not-yet-defined post-issuance relying-party
    VerificationReport sidecar."""

    def test_valid_report_accepted(self) -> None:
        assert not _errors(AUDIT_REPORT, _audit_report())

    def test_all_zero_client_root_is_not_a_valid_audit_commitment(self) -> None:
        report = _audit_report()
        report["client_evidence_manifest_root"] = _ZERO_SHA
        assert _errors(AUDIT_REPORT, report)

    def test_all_abstained_accepted(self) -> None:
        # The zero-printed-claims equivalent under the fixed seven-item
        # tuple (SCHEMA-1 P1 fix): every row abstains, but all seven IDs are
        # still present, in order.
        rows = [_audit_row_abstained(cid) for cid in _AUDIT_ROW_ORDER]
        assert not _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_empty_rows_rejected(self) -> None:
        # SCHEMA-1 P1 fix: claim_support_rows is now a fixed seven-item
        # tuple, not a 0..7 bounded array -- an empty list no longer names
        # "nothing printed", it is simply invalid.
        assert _errors(AUDIT_REPORT, _audit_report(rows=[]))

    def test_supported_row_without_verifier_rejected(self) -> None:
        report = _audit_report()
        rows = _replace_row(
            report["claim_support_rows"],
            "B1",
            {
                "claim_id": "B1",
                "evidence_basis": "issuer_verified",
                "claim_material_digest": _SHA,
            },
        )
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_supported_row_without_claim_material_digest_rejected(self) -> None:
        # SCHEMA-1 P1 fix: a supported row must bind the exact claim
        # material, not just carry a verifier next to a claim_id.
        report = _audit_report()
        rows = _replace_row(
            report["claim_support_rows"],
            "B1",
            {
                "claim_id": "B1",
                "evidence_basis": "issuer_verified",
                "verifier": {
                    "verifier_id": "ver.cert.seal_signature",
                    "verifier_version": "0.1.0",
                    "result": "PASS",
                },
            },
        )
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_abstained_row_without_reason_rejected(self) -> None:
        report = _audit_report()
        rows = _replace_row(
            report["claim_support_rows"],
            "D2",
            {"claim_id": "D2", "evidence_basis": "abstained"},
        )
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_supported_row_with_abstention_reason_rejected(self) -> None:
        report = _audit_report()
        row = _audit_row_supported("B1")
        row["abstention_code"] = "missing_evidence_binding"
        rows = _replace_row(report["claim_support_rows"], "B1", row)
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_abstained_row_with_verifier_rejected(self) -> None:
        report = _audit_report()
        row = _audit_row_abstained("D2")
        row["verifier"] = {
            "verifier_id": "ver.cert.seal_signature",
            "verifier_version": "0.1.0",
            "result": "PASS",
        }
        rows = _replace_row(report["claim_support_rows"], "D2", row)
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_abstained_row_with_claim_material_digest_rejected(self) -> None:
        # SCHEMA-1 P1 fix: an abstained row supports no claim material, so
        # it cannot carry a claim_material_digest either.
        report = _audit_report()
        row = _audit_row_abstained("D2")
        row["claim_material_digest"] = _SHA
        rows = _replace_row(report["claim_support_rows"], "D2", row)
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_extra_row_rejected(self) -> None:
        report = _audit_report()
        rows = report["claim_support_rows"] + [_audit_row_abstained("B1")]
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_missing_row_rejected(self) -> None:
        # SCHEMA-1 P1 fix: previously 0..7 rows were permitted, so a report
        # missing one of the seven registered IDs validated. Now the tuple
        # is fixed-length; dropping one ID shortens the tuple and fails.
        report = _audit_report()
        rows = report["claim_support_rows"][:-1]
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_duplicate_row_rejected(self) -> None:
        # A duplicate ID necessarily displaces a different required ID from
        # its fixed position -- the const-pinned claim_id per position
        # rejects it there, not merely on cardinality.
        report = _audit_report()
        rows = list(report["claim_support_rows"])
        rows[-1] = copy.deepcopy(rows[0])  # G3 slot now holds a B1 row
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_reordered_rows_rejected(self) -> None:
        report = _audit_report()
        rows = list(report["claim_support_rows"])
        rows[0], rows[1] = rows[1], rows[0]
        assert _errors(AUDIT_REPORT, _audit_report(rows=rows))

    def test_unknown_field_rejected(self) -> None:
        report = _audit_report()
        report["notes"] = "free text"
        assert _errors(AUDIT_REPORT, report)

    def test_schema_version_pinned(self) -> None:
        report = _audit_report()
        report["schema_version"] = "traigent.certificate_audit_report.v1"
        assert _errors(AUDIT_REPORT, report)

    def test_build_session_ref_and_evidence_root_are_mandatory_bindings(
        self,
    ) -> None:
        for field in (
            "build_session_ref",
            "client_evidence_manifest_root",
            "ledger_seal_statement_digest",
        ):
            report = _audit_report()
            del report[field]
            assert _errors(AUDIT_REPORT, report), field

    def test_report_for_different_build_session_produces_different_object(
        self,
    ) -> None:
        # Cross-report binding (build_session_ref/root/seal equality against
        # the certificate this report audited) is a verifier obligation this
        # schema cannot express directly across separate documents -- but a
        # report for a different build session is a structurally distinct,
        # digest-different object, which is what that equality check compares.
        report_a = _audit_report()
        report_b = _audit_report()
        report_b["build_session_ref"] = "bsn:fedcba9876543210"
        assert not _errors(AUDIT_REPORT, report_a)
        assert not _errors(AUDIT_REPORT, report_b)
        assert _audit_report_digest(report_a) != _audit_report_digest(report_b)

    def test_no_self_referencing_or_signature_field_representable(self) -> None:
        # Acyclic by construction: the report cannot name the final
        # manifest_digest, a certificate signature, or its own digest.
        schema = _load(CERT_DIR / AUDIT_REPORT)
        properties = set(schema["definitions"]["AuditReportV0"]["properties"])
        assert properties.isdisjoint(
            {
                "manifest_digest",
                "signature",
                "certificate_digest",
                "audit_report_digest",
            }
        )

    def test_abstention_codes_are_subset_of_rejection_codes(self) -> None:
        audit_schema = _load(CERT_DIR / AUDIT_REPORT)
        rejection_schema = _load(CERT_DIR / REJECTION)
        abstention_codes = set(audit_schema["definitions"]["AbstentionCodeV0"]["enum"])
        rejection_codes = set(rejection_schema["definitions"]["RejectionCodeV0"]["enum"])
        assert abstention_codes <= rejection_codes

    def test_audit_report_digest_is_a_distinct_registered_evidence_kind(
        self,
    ) -> None:
        evidence_schema = _load(CERT_DIR / "certificate_evidence_refs_v0_schema.json")
        kinds = set(evidence_schema["definitions"]["EvidenceKindV0"]["enum"])
        assert "audit_report_digest" in kinds
        assert "verifier_report_digest" in kinds
        assert "client_commitment_digest" in kinds

    def test_report_digest_computable_and_bindable_as_evidence(self) -> None:
        report = _audit_report()
        digest = _audit_report_digest(report)
        assert _DIGEST_PATTERN.match(digest)

        claim = _g1_claim(tier=1)
        # Replace (not append to) the placeholder audit_report_digest ref
        # _d2_claim() carries by default, so the claim ends up with exactly
        # one such reference, bound to this real report's digest.
        claim["evidence_refs"] = [
            ref for ref in claim["evidence_refs"] if ref["evidence_kind"] != "audit_report_digest"
        ] + [{"evidence_kind": "audit_report_digest", "evidence_digest": digest}]
        assert not _errors(CLAIMS, claim)


class TestNonCircularClaims:
    """SCHEMA-1 gap C3: F1/G3 no longer require a self-referential manifest
    digest inside their own payload -- the claims live inside `claims`, one
    of the sections the unsigned manifest hashes, so requiring the payload to
    equal that digest was a fixed point with no constructible preimage."""

    def test_f1_params_do_not_declare_a_manifest_digest_field(self) -> None:
        schema = _load(CERT_DIR / "certificate_claim_payloads_v0_schema.json")
        f1_params = schema["definitions"]["ClaimPayloadF1V0"]["properties"]["params"]
        assert "signed_manifest_digest" not in f1_params["properties"]

    def test_g3_params_do_not_declare_a_manifest_digest_field(self) -> None:
        schema = _load(CERT_DIR / "certificate_claim_payloads_v0_schema.json")
        g3_params = schema["definitions"]["ClaimPayloadG3V0"]["properties"]["params"]
        assert "cosigned_manifest_digest" not in g3_params["properties"]

    def test_f1_rejects_legacy_signed_manifest_digest_field(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "F1"
        claim["payload"] = {
            "claim_id": "F1",
            "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
            "params": {
                "signature_scheme": "ed25519",
                "issuer_key_ref": "ikey:abcdef0123456789",
                "trust_ring_ref": "ring:abcdef0123456789",
                "signed_manifest_digest": _SHA,
            },
        }
        assert _errors(PAYLOADS, claim["payload"])

    def test_g3_rejects_legacy_cosigned_manifest_digest_field(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "G3"
        claim["payload"] = {
            "claim_id": "G3",
            "template_id": "tmpl.cert.g3.cosigner_identity_binding.v1",
            "params": {
                "client_key_ref": "ckr:" + "A" * 43,
                "cosigned_manifest_digest": _SHA,
            },
        }
        assert _errors(PAYLOADS, claim["payload"])

    def test_f1_and_g3_constructible_without_any_digest_field(self) -> None:
        # Positive control: proves the two rejections above are about the
        # extra field specifically, not about F1/G3 being unconstructible.
        f1 = _b1_claim()
        f1["claim_id"] = "F1"
        f1["payload"] = {
            "claim_id": "F1",
            "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
            "params": {
                "signature_scheme": "ed25519",
                "issuer_key_ref": "ikey:abcdef0123456789",
                "trust_ring_ref": "ring:abcdef0123456789",
            },
        }
        assert not _errors(PAYLOADS, f1["payload"])

        g3 = _b1_claim()
        g3["claim_id"] = "G3"
        g3["payload"] = {
            "claim_id": "G3",
            "template_id": "tmpl.cert.g3.cosigner_identity_binding.v1",
            "params": {"client_key_ref": "ckr:" + "A" * 43},
        }
        assert not _errors(PAYLOADS, g3["payload"])

    def test_f1_claim_coexists_with_sibling_issuer_signature_in_certificate(
        self,
    ) -> None:
        # F1 sits inside the certificate's `claims` array while the digest it
        # would otherwise have needed sits in the sibling `signatures` block
        # -- proving the two are structurally disjoint at the envelope level.
        f1_claim = _b1_claim()
        f1_claim["claim_id"] = "F1"
        f1_claim["payload"] = {
            "claim_id": "F1",
            "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
            "params": {
                "signature_scheme": "ed25519",
                "issuer_key_ref": "ikey:abcdef0123456789",
                "trust_ring_ref": "ring:abcdef0123456789",
            },
        }
        cert = _certificate(claims=[f1_claim])
        assert _errors(ENVELOPE, cert)


class TestCanonicalizationConformance:
    """SCHEMA-1 gap C6: the declared jcs_v1 (RFC 8785) canonicalization is
    executable against the certification family's own typed documents, not
    merely a name in a description -- and the pinned fp2 reference
    implementation's non-BMP/RFC 8785 conformance corpus actually runs."""

    def test_unsigned_manifest_end_to_end_round_trip(self) -> None:
        # compile -> build audit report -> bind it as claim evidence ->
        # embed the manifest document on the wire -> schema validate ->
        # independent verify, the exact round trip the gap report's C0
        # finding showed the pre-correction compiler/fixture suites never
        # performed, now extended (SCHEMA-1 P0/P1 fix pass) to cover the
        # embedded document and the audit-report binding, not just the bare
        # digest.
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        manifest = cert["signatures"]["unsigned_manifest"]["document"]
        assert not _errors(UNSIGNED_MANIFEST, manifest)
        assert not _errors(AUDIT_REPORT, cert["audit_report"])
        assert not _errors(ENVELOPE, cert)

        # Independent verification: a relying party recomputes the digest
        # from the manifest embedded ON THE CERTIFICATE ITSELF and compares
        # it to the value the certificate carries -- no issuer database
        # involved, since the document now crosses the wire in full.
        assert (
            _unsigned_manifest_digest(manifest)
            == cert["signatures"]["unsigned_manifest"]["manifest_digest"]
        )
        _verify_certificate_contract(cert)  # no violation raised

    def test_unsigned_manifest_with_co_attestation_round_trip(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        manifest = cert["signatures"]["unsigned_manifest"]["document"]
        assert not _errors(UNSIGNED_MANIFEST, manifest)
        assert not _errors(AUDIT_REPORT, cert["audit_report"])
        assert not _errors(ENVELOPE, cert)
        _verify_certificate_contract(cert)  # no violation raised

    def test_mutating_each_coverage_section_changes_digest(self) -> None:
        base = _unsigned_manifest(claims=[_d2_claim(tier=1)], with_co=False)
        base_digest = _unsigned_manifest_digest(base)

        def _mutate_subject(m: dict) -> None:
            m["subject"]["session_commitment_digest"] = _SHA_B

        def _mutate_seal(m: dict) -> None:
            m["seal"]["seal_ref"] = "seal:fedcba9876543210"

        def _mutate_claims(m: dict) -> None:
            m["claims"][0]["verifier"]["verifier_version"] = "0.2.0"

        def _mutate_tiers(m: dict) -> None:
            m["tiers"][0]["tier"] = 2

        def _mutate_evidence_digests(m: dict) -> None:
            m["evidence_digests"][0]["evidence_digest"] = _SHA

        def _mutate_non_claims(m: dict) -> None:
            m["non_claims"][0], m["non_claims"][1] = (
                m["non_claims"][1],
                m["non_claims"][0],
            )

        def _mutate_disclosure_profile(m: dict) -> None:
            m["disclosure_profile"]["profile_id"] = "public"

        def _mutate_privacy_mode(m: dict) -> None:
            m["privacy_mode"]["declared_mode"] = "current_online"

        def _mutate_sdk_identity(m: dict) -> None:
            m["sdk_identity"]["sdk_version"] = "0.2.0"

        def _mutate_compiler_register_versions(m: dict) -> None:
            m["compiler_register_versions"]["compiler_version"] = "0.2.0"

        def _mutate_key_ring_identifiers(m: dict) -> None:
            m["key_ring_identifiers"]["issuer_key_ref"] = "ikey:fedcba9876543210"

        def _mutate_freshness(m: dict) -> None:
            m["freshness"]["nonce"] = "cd" * 16

        mutations = {
            "subject": _mutate_subject,
            "seal": _mutate_seal,
            "claims": _mutate_claims,
            "tiers": _mutate_tiers,
            "evidence_digests": _mutate_evidence_digests,
            "non_claims": _mutate_non_claims,
            "disclosure_profile": _mutate_disclosure_profile,
            "privacy_mode": _mutate_privacy_mode,
            "sdk_identity": _mutate_sdk_identity,
            "compiler_register_versions": _mutate_compiler_register_versions,
            "key_ring_identifiers": _mutate_key_ring_identifiers,
            "freshness": _mutate_freshness,
        }
        assert set(mutations) == set(_COVERAGE)

        for section, mutate in mutations.items():
            mutated = copy.deepcopy(base)
            mutate(mutated)
            assert _unsigned_manifest_digest(mutated) != base_digest, section

    def test_nonce_substitution_is_detectable_via_digest_change(self) -> None:
        # Gap C2 correction: the nonce now sits inside the signed freshness
        # section, so swapping it (replay/substitution) changes the digest
        # the client signed -- whereas before the correction it did not.
        manifest = _unsigned_manifest()
        original_digest = _unsigned_manifest_digest(manifest)
        manifest["freshness"]["nonce"] = "ff" * 16
        assert _unsigned_manifest_digest(manifest) != original_digest

    def test_key_ref_substitution_is_detectable_via_digest_change(self) -> None:
        # Gap C1 correction: issuer/trust-ring key references are fixed
        # inside key_ring_identifiers before signing, so a post-hoc
        # key-substitution attack changes the signed digest.
        manifest = _unsigned_manifest()
        original_digest = _unsigned_manifest_digest(manifest)
        manifest["key_ring_identifiers"]["trust_ring_ref"] = "ring:fedcba9876543210"
        assert _unsigned_manifest_digest(manifest) != original_digest

    @pytest.mark.parametrize(
        "case_name",
        [
            "empty_object",
            "empty_array",
            "flat_object",
            "uppercase_sorts_before_lowercase",
            "nested",
            "astral_key_sorts_before_bmp_key",
            "astral_key_ordering_after_common_prefix",
        ],
    )
    def test_rfc8785_and_non_bmp_conformance_vectors_execute(self, case_name: str) -> None:
        # Proves jcs_v1 (RFC 8785, non-BMP key ordering by UTF-16 code unit)
        # is executable against the pinned fp2 corpus, not just a name this
        # contract family declares in prose.
        case = _FP2_CASES_BY_NAME[case_name]
        assert fp2.canonicalize(case["value"]) == case["canonical"]
        assert fp2.digest(case["value"]) == case["digest"]

    def test_non_bmp_key_ordering_matches_certification_family_documents(
        self,
    ) -> None:
        # The astral/BMP ordering rule fp2 implements is the same rule this
        # family's manifests, client evidence manifests, and audit reports
        # are canonicalized under -- exercised here directly on an object
        # shaped like this family's records rather than only on fp2's own
        # synthetic corpus.
        astral_first = {"\U0001f600": 1, "Ａ": 2}
        assert fp2.canonicalize(astral_first) == '{"\U0001f600":1,"Ａ":2}'
        digest_value = fp2.digest(astral_first)
        assert _DIGEST_PATTERN.match(digest_value)


class TestRoleSeparatedDigests:
    def test_role_digest_known_answers(self) -> None:
        document = {"a": 1}
        assert _unsigned_manifest_digest(document) == (
            "sha256:0bd6131af9f205e59dc875b7a32649a45bfa56dc00b23c2ee5f18bae0e7e94e8"
        )
        assert _audit_report_digest(document) == (
            "sha256:e736480b4800b2caaa021a1999671deddbf636ef390bc7eef440ff6688067179"
        )
        assert _claim_material_role_digest(document) == (
            "sha256:a85444e768b759632165c1b8902c9f469f6bc9d3ab11f0c5d2ce4b4efc7f1a1c"
        )
        assert _client_evidence_root_digest(document) == (
            "sha256:9490377278d364402a848d08e06cc939363d880bc14ac9b4fa5c534ae173323d"
        )

    def test_role_substitution_changes_digest(self) -> None:
        document = {"a": 1}
        assert _unsigned_manifest_digest(document) != _audit_report_digest(document)
        assert _audit_report_digest(document) != _claim_material_role_digest(document)
        assert _claim_material_role_digest(document) != _client_evidence_root_digest(document)

    def test_role_digest_requires_jcs_document_and_nul_framing(self) -> None:
        document = {"b": 2, "a": 1}
        canonical = fp2.canonicalize(document).encode("utf-8")
        expected = (
            "sha256:"
            + hashlib.sha256(_DIGEST_ROLE_UNSIGNED_MANIFEST + b"\x00" + canonical).hexdigest()
        )
        assert _unsigned_manifest_digest(document) == expected
        assert (
            _unsigned_manifest_digest(document)
            != "sha256:" + hashlib.sha256(_DIGEST_ROLE_UNSIGNED_MANIFEST + canonical).hexdigest()
        )


class TestSignedManifestEmbedding:
    """SCHEMA-1 P0 fix (2026-08-24): CertificateSignaturesV0.unsigned_manifest
    now embeds the complete UnsignedManifestV0 document, not merely an
    unresolvable digest -- closing the gap where five of the twelve signed
    coverage sections had no wire-level resolver and an independent verifier
    needed an issuer database to obtain the manifest it was checking a
    signature over."""

    def test_document_is_required(self) -> None:
        sigs = _signatures()
        del sigs["unsigned_manifest"]["document"]
        assert _errors(SIGNATURES, sigs)

    def test_document_must_validate_as_unsigned_manifest(self) -> None:
        sigs = _signatures()
        sigs["unsigned_manifest"]["document"] = {"not": "a manifest"}
        assert _errors(SIGNATURES, sigs)

    def test_valid_signatures_block_with_document_accepted(self) -> None:
        assert not _errors(SIGNATURES, _signatures())

    def test_certificate_embeds_document_matching_its_own_fields(self) -> None:
        # The default fixture is cross-consistent by construction (not
        # merely schema-valid in isolation): the embedded document's
        # deterministic-projection sections equal the certificate's own
        # fields, and manifest_digest equals the unsigned-manifest role digest.
        cert = _certificate()
        document = cert["signatures"]["unsigned_manifest"]["document"]
        assert document["subject"] == cert["subject"]
        assert document["claims"] == cert["claims"]
        assert document["non_claims"] == cert["non_claims"]
        assert document["disclosure_profile"] == cert["disclosure_profile"]
        assert document["seal"] == cert["ledger_seal_projection"]
        assert (
            _unsigned_manifest_digest(document)
            == cert["signatures"]["unsigned_manifest"]["manifest_digest"]
        )


class TestContractVerifier:
    """Adversarial coverage for the cross-field equality obligations this
    contract family's descriptions document but Draft-07 cannot itself
    check -- exercised via _verify_certificate_contract against a positive
    control (_build_valid_fixture) with exactly one independent aspect
    mutated per test. Each test starts from a certificate that is genuinely
    valid end-to-end (never a tautology: not comparing a value to itself,
    and not starting from an already-broken fixture) and requires the
    mutation to produce a NAMED failure."""

    def test_valid_fixture_raises_nothing(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        _verify_certificate_contract(cert)

    def test_manifest_digest_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _SHA_B
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_bare_fp2_manifest_digest_rejected_at_signature_surface(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        bare_digest = fp2.digest(cert["signatures"]["unsigned_manifest"]["document"])
        assert bare_digest != cert["signatures"]["unsigned_manifest"]["manifest_digest"]
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = bare_digest
        cert["signatures"]["co_attestation"]["signed_manifest_digest"] = bare_digest
        assert not _errors(ENVELOPE, cert)
        with pytest.raises(
            ContractViolation, match="manifest_digest != unsigned-manifest role digest"
        ):
            _verify_certificate_contract(cert)

    def test_bare_fp2_audit_digest_rejected_at_audit_reference_surface(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        bare_digest = fp2.digest(cert["audit_report"])
        for claims in (
            cert["claims"],
            cert["signatures"]["unsigned_manifest"]["document"]["claims"],
        ):
            for claim in claims:
                for ref in claim["evidence_refs"]:
                    if ref["evidence_kind"] == "audit_report_digest":
                        ref["evidence_digest"] = bare_digest
        document = cert["signatures"]["unsigned_manifest"]["document"]
        document["evidence_digests"] = _evidence_digests_projection(document["claims"], bare_digest)
        manifest_digest = _unsigned_manifest_digest(document)
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = manifest_digest
        _rebind_co_projection_digest(cert)
        assert not _errors(ENVELOPE, cert)
        with pytest.raises(
            ContractViolation,
            match="claim G1 audit_report_digest does not match the audit report",
        ):
            _verify_certificate_contract(cert)

    def test_bare_fp2_client_root_rejected_at_g1_reference_surface(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        bare_root = fp2.digest(_client_evidence_manifest())
        for claims in (
            cert["claims"],
            cert["signatures"]["unsigned_manifest"]["document"]["claims"],
        ):
            for claim in claims:
                if claim["claim_id"] == "G1":
                    claim["payload"]["params"]["manifest_root_digest"] = bare_root
        document = cert["signatures"]["unsigned_manifest"]["document"]
        document["evidence_digests"] = _evidence_digests_projection(
            document["claims"], _audit_report_digest(cert["audit_report"])
        )
        manifest_digest = _unsigned_manifest_digest(document)
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = manifest_digest
        _rebind_co_projection_digest(cert)
        assert not _errors(ENVELOPE, cert)
        with pytest.raises(
            ContractViolation, match="audit_report.client_evidence_manifest_root mismatch"
        ):
            _verify_certificate_contract(cert)

    def test_subject_vs_document_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["subject"]["session_commitment_digest"] = _SHA_B
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_claims_vs_document_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["claims"][0]["verifier"]["verifier_version"] = "9.9.9"
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_non_claims_vs_document_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["non_claims"][0], cert["non_claims"][1] = (
            cert["non_claims"][1],
            cert["non_claims"][0],
        )
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_disclosure_profile_vs_document_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["disclosure_profile"]["profile_id"] = "public"
        with pytest.raises(ContractViolation, match="disclosure_profile"):
            _verify_certificate_contract(cert)

    def test_subject_ledger_build_session_rebind_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["subject"]["build_session_ref"] = "bsn:fedcba9876543210"
        cert["signatures"]["unsigned_manifest"]["document"]["subject"] = copy.deepcopy(
            cert["subject"]
        )
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _unsigned_manifest_digest(
            cert["signatures"]["unsigned_manifest"]["document"]
        )
        cert["signatures"]["co_attestation"]["signed_manifest_digest"] = cert["signatures"][
            "unsigned_manifest"
        ]["manifest_digest"]
        with pytest.raises(
            ContractViolation,
            match="subject.build_session_ref != ledger_seal_projection.build_session_ref",
        ):
            _verify_certificate_contract(cert)

    def test_b1_seal_ref_rebind_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])

        def _mutate_b1(claim: dict) -> None:
            claim["payload"]["params"]["seal_ref"] = "seal:fedcba9876543210"

        _apply_claim_mutation(cert, 0, _mutate_b1)
        with pytest.raises(
            ContractViolation, match="B1 claim seal_ref != ledger_seal_projection.seal_ref"
        ):
            _verify_certificate_contract(cert)

    def test_b1_seal_statement_digest_rebind_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])

        def _mutate_b1(claim: dict) -> None:
            claim["payload"]["params"]["seal_statement_digest"] = _SHA_B

        _apply_claim_mutation(cert, 0, _mutate_b1)
        with pytest.raises(
            ContractViolation,
            match="B1 claim seal_statement_digest != ledger_seal_projection.seal_statement_digest",
        ):
            _verify_certificate_contract(cert)

    def test_supported_row_verifier_rebind_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)])
        row = next(
            row for row in cert["audit_report"]["claim_support_rows"] if row["claim_id"] == "G1"
        )
        row["verifier"]["verifier_version"] = "9.9.9"
        _rebind_audit_report_digest(cert)
        with pytest.raises(
            ContractViolation,
            match="audit row G1 verifier != printed claim verifier",
        ):
            _verify_certificate_contract(cert)

    def test_g1_manifest_root_rebind_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["audit_report"]["client_evidence_manifest_root"] = _SHA
        _rebind_audit_report_digest(cert)
        with pytest.raises(
            ContractViolation, match="audit_report.client_evidence_manifest_root mismatch"
        ):
            _verify_certificate_contract(cert)

    def test_printed_claim_requires_supported_row_not_abstention(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)])
        rows = _replace_row(
            cert["audit_report"]["claim_support_rows"],
            "G1",
            _audit_row_abstained("G1"),
        )
        cert["audit_report"]["claim_support_rows"] = rows
        _rebind_audit_report_digest(cert)
        with pytest.raises(ContractViolation, match="printed claim G1 has no supporting audit row"):
            _verify_certificate_contract(cert)

    def test_nonce_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["signatures"]["co_attestation"]["nonce"] = "ff" * 16
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_issuer_key_ref_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["signatures"]["issuer_signature"]["issuer_key_ref"] = "ikey:fedcba9876543210"
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_trust_ring_ref_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["signatures"]["issuer_signature"]["trust_ring_ref"] = "ring:fedcba9876543210"
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_issuer_algorithm_substitution_detected_with_schema_valid_shape(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["signatures"]["issuer_signature"]["algorithm"] = "ecdsa_p256_sha256"
        assert not _errors(ENVELOPE, cert)
        with pytest.raises(
            ContractViolation,
            match="key_ring_identifiers.issuer_signature_algorithm != issuer_signature.algorithm",
        ):
            _verify_certificate_contract(cert)

    def test_client_algorithm_substitution_detected_with_schema_valid_shape(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["signatures"]["co_attestation"]["algorithm"] = "ecdsa_p256_sha256"
        assert not _errors(ENVELOPE, cert)
        with pytest.raises(
            ContractViolation,
            match="key_ring_identifiers.client_signature_algorithm != co_attestation.algorithm",
        ):
            _verify_certificate_contract(cert)

    def test_algorithm_presence_asymmetry_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        del cert["signatures"]["unsigned_manifest"]["document"]["key_ring_identifiers"][
            "client_signature_algorithm"
        ]
        manifest = cert["signatures"]["unsigned_manifest"]["document"]
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _unsigned_manifest_digest(
            manifest
        )
        cert["signatures"]["co_attestation"]["signed_manifest_digest"] = cert["signatures"][
            "unsigned_manifest"
        ]["manifest_digest"]
        with pytest.raises(
            ContractViolation,
            match="key_ring_identifiers.client_signature_algorithm missing with co_attestation",
        ):
            _verify_certificate_contract(cert)

        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=False)
        cert["signatures"]["unsigned_manifest"]["document"]["key_ring_identifiers"][
            "client_signature_algorithm"
        ] = "ed25519"
        manifest = cert["signatures"]["unsigned_manifest"]["document"]
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _unsigned_manifest_digest(
            manifest
        )
        with pytest.raises(
            ContractViolation, match="client key/algorithm present without co_attestation"
        ):
            _verify_certificate_contract(cert)

    def test_g3_client_key_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_g3_claim(tier=1)], with_co=True)
        cert["signatures"]["co_attestation"]["client_key_ref"] = "ckr:" + "B" * 43
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_tier_projection_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        document = cert["signatures"]["unsigned_manifest"]["document"]
        document["tiers"][0]["tier"] = 2
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_evidence_digests_projection_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        document = cert["signatures"]["unsigned_manifest"]["document"]
        document["evidence_digests"][0]["evidence_digest"] = _SHA_B
        with pytest.raises(ContractViolation):
            _verify_certificate_contract(cert)

    def test_missing_audit_report_digest_reference_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])

        def _drop_audit_ref(claim: dict) -> None:
            claim["evidence_refs"] = [
                r for r in claim["evidence_refs"] if r["evidence_kind"] != "audit_report_digest"
            ]

        _apply_claim_mutation(cert, 0, _drop_audit_ref)
        with pytest.raises(
            ContractViolation,
            match="claim B1 does not carry exactly one audit_report_digest evidence reference",
        ):
            _verify_certificate_contract(cert)

    def test_multiple_different_audit_report_digest_references_detected(
        self,
    ) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])

        def _add_extra_audit_ref(claim: dict) -> None:
            claim["evidence_refs"] = claim["evidence_refs"] + [
                {"evidence_kind": "audit_report_digest", "evidence_digest": _SHA}
            ]

        _apply_claim_mutation(cert, 0, _add_extra_audit_ref)
        with pytest.raises(
            ContractViolation,
            match="claim B1 does not carry exactly one audit_report_digest evidence reference",
        ):
            _verify_certificate_contract(cert)

    def test_two_claims_with_different_audit_report_digest_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3), _g1_claim(tier=1)], with_co=True)

        def _diverge_audit_ref(claim: dict) -> None:
            for ref in claim["evidence_refs"]:
                if ref["evidence_kind"] == "audit_report_digest":
                    ref["evidence_digest"] = _SHA

        _apply_claim_mutation(cert, 1, _diverge_audit_ref)
        with pytest.raises(
            ContractViolation,
            match="claim G1 audit_report_digest does not match the audit report",
        ):
            _verify_certificate_contract(cert)

    @pytest.mark.parametrize(
        "mutate",
        [_mutate_payload, _mutate_tier, _mutate_verifier, _mutate_non_audit_evidence],
        ids=["payload", "tier", "verifier", "non_audit_evidence"],
    )
    def test_claim_material_digest_stale_after_mutation_detected(self, mutate) -> None:
        # The audit report's claim_material_digest row was computed for the
        # ORIGINAL claim material and is never recomputed here -- only the
        # printed claim (and its manifest copy, kept in lockstep) changes.
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        _apply_claim_mutation(cert, 0, mutate)
        with pytest.raises(
            ContractViolation,
            match="claim_material_digest mismatch for B1",
        ):
            _verify_certificate_contract(cert)

    def test_altered_audit_report_bytes_orphan_the_claim_reference(self) -> None:
        # The claims still carry the ORIGINAL report's digest; altering a
        # field of the embedded top-level audit_report that no OTHER check
        # compares for a B1-only claim set (client_evidence_manifest_root is
        # compared only when a G1 claim is printed) isolates exactly the
        # orphaned-reference obligation: the report's own digest changes, so
        # it no longer matches what the claims reference -- this is the
        # "substituted audit report" fixture class (SCHEMA-1 FINAL fix).
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        original_digest = _audit_report_digest(cert["audit_report"])
        altered_report = copy.deepcopy(cert["audit_report"])
        altered_report["claim_support_rows"][0]["abstention_code"] = (
            "missing_or_versionless_verifier"
        )
        assert _audit_report_digest(altered_report) != original_digest
        cert["audit_report"] = altered_report
        with pytest.raises(
            ContractViolation,
            match="claim B1 audit_report_digest does not match the audit report",
        ):
            _verify_certificate_contract(cert)

    def test_missing_audit_report_field_rejected_at_envelope(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        del cert["audit_report"]
        assert _errors(ENVELOPE, cert)

    def test_zero_claims_certificate_requires_audit_report_all_abstained(
        self,
    ) -> None:
        cert = _build_valid_fixture([])
        assert not _errors(ENVELOPE, cert)
        rows = cert["audit_report"]["claim_support_rows"]
        assert len(rows) == 7
        assert {row["evidence_basis"] for row in rows} == {"abstained"}

    def test_absent_g1_requires_null_audit_root(self) -> None:
        cert = _build_valid_fixture([])
        assert cert["audit_report"]["client_evidence_manifest_root"] is None
        _verify_certificate_contract(cert)
        cert["audit_report"]["client_evidence_manifest_root"] = _SHA_B
        with pytest.raises(
            ContractViolation,
            match="client_evidence_manifest_root must be null without G1",
        ):
            _verify_certificate_contract(cert)

    def test_g1_requires_nonzero_audit_root(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["audit_report"]["client_evidence_manifest_root"] = _ZERO_SHA
        for claims in (
            cert["claims"],
            cert["signatures"]["unsigned_manifest"]["document"]["claims"],
        ):
            for claim in claims:
                if claim["claim_id"] == "G1":
                    claim["payload"]["params"]["manifest_root_digest"] = _ZERO_SHA
        document = cert["signatures"]["unsigned_manifest"]["document"]
        manifest_digest = _unsigned_manifest_digest(document)
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = manifest_digest
        _rebind_co_projection_digest(cert)
        with pytest.raises(ContractViolation, match="G1 manifest_root_digest must be nonzero"):
            _verify_certificate_contract(cert)

    def test_substituted_audit_report_for_different_build_session_detected(
        self,
    ) -> None:
        # A structurally different (schema-valid on its own) report swapped
        # into a valid certificate: not merely mismatched bytes, but a
        # complete report for the WRONG build session.
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        substitute = _audit_report_for_claims([_d2_claim(tier=1)])
        substitute["build_session_ref"] = "bsn:fedcba9876543210"
        assert not _errors(AUDIT_REPORT, substitute)
        cert["audit_report"] = substitute
        _rebind_audit_report_digest(cert)
        with pytest.raises(
            ContractViolation,
            match="audit_report.build_session_ref mismatch",
        ):
            _verify_certificate_contract(cert)

    def test_co_attestation_signed_manifest_digest_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_g1_claim(tier=1)], with_co=True)
        cert["signatures"]["co_attestation"]["signed_manifest_digest"] = _SHA_B
        with pytest.raises(
            ContractViolation,
            match="co_attestation.signed_manifest_digest != certificate projection",
        ):
            _verify_certificate_contract(cert)

    def test_d2_claim_is_not_supported_by_contract_verifier(self) -> None:
        cert = _build_valid_fixture([_d2_claim(tier=1)], with_co=True)
        with pytest.raises(ContractViolation, match="printed claim D2 has no supporting audit row"):
            _verify_certificate_contract(cert)

    def test_d2_claim_remains_unrepresentable_after_payload_mutation(self) -> None:
        cert = _build_valid_fixture([_d2_claim(tier=1)], with_co=True)
        _apply_claim_mutation(
            cert,
            0,
            lambda claim: claim["payload"]["params"].update(declared_mode="current_online"),
        )
        with pytest.raises(ContractViolation, match="printed claim D2 has no supporting audit row"):
            _verify_certificate_contract(cert)

    def test_d2_duplicate_sdk_witness_refs_fail_closed_at_schema(self) -> None:
        cert = _build_valid_fixture([_d2_claim(tier=1)], with_co=True)

        def _add_duplicate_sdk_ref(claim: dict) -> None:
            claim["evidence_refs"].append(
                {"evidence_kind": "sdk_witness_bundle", "evidence_digest": _SHA_B}
            )

        _apply_claim_mutation(cert, 0, _add_duplicate_sdk_ref)
        _rebind_claim_material_and_audit(cert)
        assert _errors(ENVELOPE, cert)
        assert _errors(UNSIGNED_MANIFEST, cert["signatures"]["unsigned_manifest"]["document"])

    @pytest.mark.parametrize(
        ("claim_factory", "extra_kind"),
        [(_g1_claim, "ledger_entry_commitment")],
    )
    def test_printable_claim_rejects_extra_ledger_reference_in_envelope_and_manifest(
        self, claim_factory, extra_kind: str
    ) -> None:
        cert = _build_valid_fixture([claim_factory(tier=1)], with_co=True)
        assert not _errors(ENVELOPE, cert)
        document = cert["signatures"]["unsigned_manifest"]["document"]
        assert not _errors(UNSIGNED_MANIFEST, document)
        extra = {"evidence_kind": extra_kind, "evidence_digest": _SHA_B}
        cert["claims"][0]["evidence_refs"].append(copy.deepcopy(extra))
        document["claims"][0]["evidence_refs"].append(extra)
        assert _errors(ENVELOPE, cert)
        assert _errors(UNSIGNED_MANIFEST, document)

    def test_d2_sdk_ref_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_d2_claim(tier=1)], with_co=True)

        def _mutate_sdk_ref(claim: dict) -> None:
            claim["payload"]["params"]["sdk_ref"] = "f" * 40

        _apply_claim_mutation(cert, 0, _mutate_sdk_ref)
        with pytest.raises(ContractViolation, match="printed claim D2 has no supporting audit row"):
            _verify_certificate_contract(cert)

    @pytest.mark.parametrize(
        "field,new_value",
        [
            ("compiler_version", "9.9.9"),
            ("semantics_manifest_digest", _SHA_B),
            ("prohibited_register_digest", _SHA_B),
            ("verifier_catalog_digest", _SHA_B),
        ],
    )
    def test_c1_register_param_mismatch_detected(self, field: str, new_value: str) -> None:
        cert = _build_valid_fixture([_c1_claim(tier=3)])

        def _mutate_c1(claim: dict) -> None:
            claim["payload"]["params"][field] = new_value

        _apply_claim_mutation(cert, 0, _mutate_c1)
        with pytest.raises(
            ContractViolation,
            match=rf"C1 claim {field} != manifest\.compiler_register_versions\.{field}",
        ):
            _verify_certificate_contract(cert)

    def test_f1_signature_scheme_mismatch_detected(self) -> None:
        # issuer_signature itself is a sibling of `claims`, not inside the
        # signed manifest document -- mutate the F1 CLAIM's own payload
        # param instead (via _apply_claim_mutation, which keeps the
        # manifest_digest/tiers/evidence_digests projections in lockstep so
        # only this one obligation goes stale), rather than issuer_signature
        # itself, which the pre-existing key_ring_identifiers check would
        # catch first and mask the new F1-specific check below.
        cert = _build_valid_fixture([_f1_claim(tier=3)])

        def _mutate_signature_scheme(claim: dict) -> None:
            claim["payload"]["params"]["signature_scheme"] = "ecdsa_p256_sha256"

        _apply_claim_mutation(cert, 0, _mutate_signature_scheme)
        with pytest.raises(
            ContractViolation,
            match="F1 claim signature_scheme != issuer_signature.algorithm",
        ):
            _verify_certificate_contract(cert)

    def test_f1_issuer_key_ref_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_f1_claim(tier=3)])

        def _mutate_issuer_key_ref(claim: dict) -> None:
            claim["payload"]["params"]["issuer_key_ref"] = "ikey:fedcba9876543210"

        _apply_claim_mutation(cert, 0, _mutate_issuer_key_ref)
        with pytest.raises(
            ContractViolation,
            match="F1 claim issuer_key_ref != issuer_signature.issuer_key_ref",
        ):
            _verify_certificate_contract(cert)

    def test_f1_trust_ring_ref_mismatch_detected(self) -> None:
        cert = _build_valid_fixture([_f1_claim(tier=3)])

        def _mutate_trust_ring_ref(claim: dict) -> None:
            claim["payload"]["params"]["trust_ring_ref"] = "ring:fedcba9876543210"

        _apply_claim_mutation(cert, 0, _mutate_trust_ring_ref)
        with pytest.raises(
            ContractViolation,
            match="F1 claim trust_ring_ref != issuer_signature.trust_ring_ref",
        ):
            _verify_certificate_contract(cert)

    def test_audit_report_compiler_register_versions_mismatch_detected(
        self,
    ) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        cert["audit_report"]["compiler_register_versions"]["compiler_version"] = "9.9.9"
        _rebind_audit_report_digest(cert)
        with pytest.raises(
            ContractViolation,
            match="audit_report.compiler_register_versions != manifest.compiler_register_versions",
        ):
            _verify_certificate_contract(cert)

    def test_duplicate_printed_claim_id_detected(self) -> None:
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        duplicate = copy.deepcopy(cert["claims"][0])
        cert["claims"].append(duplicate)
        document = cert["signatures"]["unsigned_manifest"]["document"]
        document["claims"].append(copy.deepcopy(duplicate))
        document["tiers"] = _tiers_projection(document["claims"])
        document["evidence_digests"] = _evidence_digests_projection(document["claims"])
        cert["signatures"]["unsigned_manifest"]["manifest_digest"] = _unsigned_manifest_digest(
            document
        )
        with pytest.raises(
            ContractViolation,
            match="duplicate printed claim_id in claims array",
        ):
            _verify_certificate_contract(cert)

    def test_supported_row_for_unprinted_claim_detected(self) -> None:
        # A audit row claims G1 is supported, but no G1 claim is printed --
        # the "supported implies printed" half of the support-iff-printed
        # obligation (the converse, "printed implies supported", is already
        # covered by test_missing_audit_report_digest_reference_detected's
        # sibling checks above).
        cert = _build_valid_fixture([_b1_claim(tier=3)])
        phantom_g1 = _g1_claim(tier=1)
        phantom_digest = _claim_material_digest(phantom_g1)
        rows = _replace_row(
            cert["audit_report"]["claim_support_rows"],
            "G1",
            _audit_row_supported("G1", phantom_digest),
        )
        cert["audit_report"]["claim_support_rows"] = rows
        _rebind_audit_report_digest(cert)
        with pytest.raises(
            ContractViolation,
            match="audit row G1 is supported but not printed as a claim",
        ):
            _verify_certificate_contract(cert)

    def test_d2_c1_f1_printed_together_positive_fixture(self) -> None:
        # Unsupported claims remain rejected even when combined with other
        # isolated future-evolution payloads.
        cert = _build_valid_fixture([_d2_claim(tier=3), _c1_claim(tier=3), _f1_claim(tier=3)])
        assert _errors(ENVELOPE, cert)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
