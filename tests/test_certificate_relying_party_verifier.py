"""Deterministic offline relying-party verifier controls.

The fixtures are the same typed G1 shapes used by the Schema contract tests. They
are signed locally with deterministic keys; no Backend module or network service is
imported by the verifier under test.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import struct
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from tests.test_agent_certificate_v0_schemas import (
    _build_valid_fixture,
    _d2_claim,
    _g1_claim,
    _rebind_audit_report_digest,
)
from traigent_schema import fp2
from traigent_schema.certification import (
    RelyingPartyPolicy,
    VerificationContext,
    VerificationError,
    verify_certificate,
)

_SEAL_DOMAIN = b"traigent.agent_certificate.seal_statement.v1"
_AUDIT_DOMAIN = b"traigent.agent_certificate.audit_report.v1"
_UNSIGNED_DOMAIN = b"traigent.agent_certificate.unsigned_manifest.v1"
_CLIENT_DOMAIN = b"traigent.agent_certificate.client_co_attestation.v0"
_ISSUER_DOMAIN = b"traigent.agent_certificate.issuer_signature.v0"
_SESSION = "bsn:abcdef0123456789"
_NONCE = "ab" * 16
_ECDSA_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _run_without_cryptography(source: str) -> subprocess.CompletedProcess[str]:
    block_import = """
import builtins

_real_import = builtins.__import__

def _without_cryptography(name, *args, **kwargs):
    if name == "cryptography" or name.startswith("cryptography."):
        raise ModuleNotFoundError("cryptography intentionally unavailable", name="cryptography")
    return _real_import(name, *args, **kwargs)

builtins.__import__ = _without_cryptography
"""
    return subprocess.run(
        [sys.executable, "-c", block_import + "\n" + source],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )


def test_plain_package_import_does_not_require_cryptography() -> None:
    result = _run_without_cryptography("import traigent_schema")
    assert result.returncode == 0, result.stderr


def test_lazy_certification_export_reports_missing_cryptography() -> None:
    result = _run_without_cryptography("from traigent_schema import RelyingPartyPolicy")
    assert result.returncode != 0
    assert "cryptography" in result.stderr.lower()
    assert "optional" in result.stderr.lower()


def test_root_certification_exports_preserve_public_api() -> None:
    from traigent_schema import RelyingPartyPolicy as RootRelyingPartyPolicy

    assert RootRelyingPartyPolicy is RelyingPartyPolicy


def _digest(domain: bytes, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


def _private_keys(algorithm: str) -> tuple[object, object]:
    if algorithm == "ed25519":
        return (
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
            ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))),
        )
    return (
        ec.derive_private_key(1, ec.SECP256R1()),
        ec.derive_private_key(2, ec.SECP256R1()),
    )


def _sign(private_key: object, algorithm: str, material: bytes) -> str:
    if algorithm == "ed25519":
        raw = private_key.sign(material)
    else:
        der = private_key.sign(material, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        s = min(s, _ECDSA_ORDER - s)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.b64encode(raw).decode("ascii")


def _high_s(encoded: str) -> str:
    raw = base64.b64decode(encoded)
    s = _ECDSA_ORDER - int.from_bytes(raw[32:], "big")
    return base64.b64encode(raw[:32] + s.to_bytes(32, "big")).decode("ascii")


def _sign_fixture(
    algorithm: str = "ed25519", claim_factory: Callable[[], dict] = _g1_claim
) -> tuple[dict, object, VerificationContext, RelyingPartyPolicy]:
    cert = _build_valid_fixture([claim_factory()], with_co=True)
    seal = cert["ledger_seal_projection"]
    seal["seal_statement_digest"] = _digest(
        _SEAL_DOMAIN,
        {key: value for key, value in seal.items() if key != "seal_statement_digest"},
    )
    unsigned = cert["signatures"]["unsigned_manifest"]["document"]
    unsigned["seal"] = copy.deepcopy(seal)
    cert["audit_report"]["ledger_seal_statement_digest"] = seal["seal_statement_digest"]
    for row in cert["audit_report"]["claim_support_rows"]:
        if row["support_status"] == "abstained":
            row["abstention_code"] = (
                "unregistered_claim_id"
                if row["claim_id"] == "REG1"
                else "verifier_not_run_or_not_pass"
                if row["claim_id"] == "C1"
                else "verifier_not_run_or_not_pass"
            )
    audit_digest = _digest(_AUDIT_DOMAIN, cert["audit_report"])
    for claims in (cert["claims"], unsigned["claims"]):
        for claim in claims:
            for ref in claim["evidence_refs"]:
                if ref["evidence_kind"] == "audit_report_digest":
                    ref["evidence_digest"] = audit_digest
    claim_ref = next(
        ref
        for ref in unsigned["claims"][0]["evidence_refs"]
        if ref["evidence_kind"] != "audit_report_digest"
    )
    unsigned["evidence_digests"] = [
        {"evidence_kind": "audit_report_digest", "evidence_digest": audit_digest},
        copy.deepcopy(claim_ref),
    ]
    issuer_key, client_key = _private_keys(algorithm)
    unsigned["key_ring_identifiers"]["issuer_signature_algorithm"] = algorithm
    unsigned["key_ring_identifiers"]["client_signature_algorithm"] = algorithm
    cert["signatures"]["issuer_signature"]["algorithm"] = algorithm
    co = cert["signatures"]["co_attestation"]
    co["algorithm"] = algorithm
    manifest_digest = _digest(_UNSIGNED_DOMAIN, unsigned)
    unsigned_ref = cert["signatures"]["unsigned_manifest"]
    unsigned_ref["manifest_digest"] = manifest_digest
    manifest_bytes = fp2.canonicalize(unsigned).encode()
    co["signed_manifest_digest"] = manifest_digest
    co_material = _CLIENT_DOMAIN + b"\0" + struct.pack(">Q", len(manifest_bytes)) + manifest_bytes
    co["signature"] = _sign(client_key, algorithm, co_material)
    issuer_material = (
        _ISSUER_DOMAIN
        + b"\0"
        + struct.pack(">Q", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", 64)
        + base64.b64decode(co["signature"])
    )
    cert["signatures"]["issuer_signature"]["signature"] = _sign(
        issuer_key, algorithm, issuer_material
    )
    issuer = cert["signatures"]["issuer_signature"]
    context = VerificationContext(
        expected_nonce=_NONCE,
        expected_build_session_ref=_SESSION,
        expected_issuer_key_ref=issuer["issuer_key_ref"],
        expected_issuer_algorithm=algorithm,
        expected_trust_ring_ref=issuer["trust_ring_ref"],
        expected_client_key_ref=co["client_key_ref"],
        expected_client_algorithm=algorithm,
        client_public_key=client_key.public_key(),
    )
    policy = RelyingPartyPolicy(
        tuple(unsigned["compiler_register_versions"].items()),
        (("G1", "ver.cert.manifest_commitment", "0.1.0"),),
    )
    return cert, issuer_key.public_key(), context, policy


def _resign_issuer(cert: dict, algorithm: str) -> None:
    issuer_key, _ = _private_keys(algorithm)
    unsigned = cert["signatures"]["unsigned_manifest"]["document"]
    manifest_bytes = fp2.canonicalize(unsigned).encode()
    co_raw = base64.b64decode(cert["signatures"]["co_attestation"]["signature"])
    material = (
        _ISSUER_DOMAIN
        + b"\0"
        + struct.pack(">Q", len(manifest_bytes))
        + manifest_bytes
        + struct.pack(">Q", len(co_raw))
        + co_raw
    )
    cert["signatures"]["issuer_signature"]["signature"] = _sign(issuer_key, algorithm, material)


def _resign_fixture(cert: dict, algorithm: str) -> None:
    """Re-sign a fixture after a deliberate signed-manifest mutation."""
    _, client_key = _private_keys(algorithm)
    unsigned = cert["signatures"]["unsigned_manifest"]["document"]
    manifest_bytes = fp2.canonicalize(unsigned).encode()
    manifest_digest = _digest(_UNSIGNED_DOMAIN, unsigned)
    unsigned_ref = cert["signatures"]["unsigned_manifest"]
    unsigned_ref["manifest_digest"] = manifest_digest
    co = cert["signatures"]["co_attestation"]
    co["signed_manifest_digest"] = manifest_digest
    co_material = _CLIENT_DOMAIN + b"\0" + struct.pack(">Q", len(manifest_bytes)) + manifest_bytes
    co["signature"] = _sign(client_key, algorithm, co_material)
    _resign_issuer(cert, algorithm)


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_g1_certificate_is_verified_offline(algorithm: str) -> None:
    cert, issuer, context, policy = _sign_fixture(algorithm)
    result = verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)
    assert result.valid and result.code == "VERIFIED"


def test_c1_truthful_abstention_is_required() -> None:
    cert, issuer, context, policy = _sign_fixture()
    c1_row = next(
        row for row in cert["audit_report"]["claim_support_rows"] if row["claim_id"] == "C1"
    )
    assert c1_row["abstention_code"] == "verifier_not_run_or_not_pass"
    result = verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)
    assert result.valid and result.code == "VERIFIED"

    c1_row["abstention_code"] = "prohibited_register_violation"
    _rebind_audit_report_digest(cert)
    _resign_fixture(cert, "ed25519")
    with pytest.raises(VerificationError, match="^AUDIT_STATUS$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_d2_certificate_is_rejected_by_production_verifier() -> None:
    cert, issuer, context, policy = _sign_fixture(claim_factory=_d2_claim)
    with pytest.raises(VerificationError, match="^SCHEMA$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_forged_non_abstained_d2_audit_row_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    d2_row = next(
        row for row in cert["audit_report"]["claim_support_rows"] if row["claim_id"] == "D2"
    )
    d2_row.update(
        {
            "support_status": "supported",
            "verifier": {
                "verifier_id": "ver.cert.offline_egress_witness",
                "verifier_version": "0.1.0",
                "result": "PASS",
            },
            "claim_material_digest": "sha256:" + "f" * 64,
        }
    )
    with pytest.raises(VerificationError, match="^SCHEMA$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_wrong_issuer_key_is_rejected(algorithm: str) -> None:
    cert, _, context, policy = _sign_fixture(algorithm)
    wrong_issuer, _ = _private_keys(
        "ed25519" if algorithm == "ecdsa_p256_sha256" else "ecdsa_p256_sha256"
    )
    with pytest.raises(VerificationError):
        verify_certificate(
            cert,
            issuer_public_key=wrong_issuer.public_key(),
            context=context,
            policy=policy,
        )


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_wrong_client_key_is_rejected(algorithm: str) -> None:
    cert, issuer, context, policy = _sign_fixture(algorithm)
    wrong_client, _ = _private_keys(
        "ed25519" if algorithm == "ecdsa_p256_sha256" else "ecdsa_p256_sha256"
    )
    changed_context = replace(context, client_public_key=wrong_client.public_key())
    with pytest.raises(VerificationError):
        verify_certificate(
            cert,
            issuer_public_key=issuer,
            context=changed_context,
            policy=policy,
        )


def test_high_s_issuer_signature_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture("ecdsa_p256_sha256")
    cert["signatures"]["issuer_signature"]["signature"] = _high_s(
        cert["signatures"]["issuer_signature"]["signature"]
    )
    with pytest.raises(VerificationError, match="^SIGNATURE_HIGH_S$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_high_s_client_signature_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture("ecdsa_p256_sha256")
    co = cert["signatures"]["co_attestation"]
    co["signature"] = _high_s(co["signature"])
    _resign_issuer(cert, "ecdsa_p256_sha256")
    with pytest.raises(VerificationError, match="^CLIENT_SIGNATURE_NON_CANONICAL$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


@pytest.mark.parametrize("mutation", ["audit", "non_claim", "seal", "claim"])
def test_certificate_structure_mutations_fail_closed(mutation: str) -> None:
    cert, issuer, context, policy = _sign_fixture()
    changed = copy.deepcopy(cert)
    if mutation == "audit":
        changed["audit_report"]["client_evidence_manifest_root"] = "sha256:" + "f" * 64
    elif mutation == "non_claim":
        changed["non_claims"] = changed["non_claims"][:-1]
    elif mutation == "seal":
        changed["ledger_seal_projection"]["expected_stream_projection"]["decision_stream"][
            "root_commitment"
        ] = "sha256:" + "f" * 64
    else:
        changed["claims"][0]["payload"]["params"]["manifest_root_digest"] = "sha256:" + "f" * 64
    with pytest.raises(VerificationError):
        verify_certificate(changed, issuer_public_key=issuer, context=context, policy=policy)


def test_omitted_audit_report_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    cert.pop("audit_report")
    with pytest.raises(VerificationError, match="^SCHEMA$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_omitted_mandatory_non_claim_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    cert["non_claims"].pop()
    with pytest.raises(VerificationError, match="^SCHEMA$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_wrong_policy_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    wrong_policy = replace(policy, verifier_bindings=(("G1", "ver.cert.other", "0.1.0"),))
    with pytest.raises(VerificationError, match="^POLICY$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=wrong_policy)


def test_replayed_build_session_context_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    replay_context = replace(context, expected_build_session_ref="bsn:fedcba9876543210")
    with pytest.raises(VerificationError, match="^CONTEXT$"):
        verify_certificate(cert, issuer_public_key=issuer, context=replay_context, policy=policy)


def test_all_empty_projection_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    for stream in cert["ledger_seal_projection"]["expected_stream_projection"].values():
        stream["root_commitment"] = "sha256:" + "0" * 64
    with pytest.raises(VerificationError):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


@pytest.mark.parametrize(
    ("stream", "family"),
    [("decision_stream", "receipt_event"), ("receipt_event_stream", "decision")],
)
def test_wrong_stream_family_is_rejected(stream: str, family: str) -> None:
    cert, issuer, context, policy = _sign_fixture()
    cert["ledger_seal_projection"]["expected_stream_projection"][stream]["stream_family"] = family
    with pytest.raises(VerificationError):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_unsupported_build_ledger_profile_is_rejected() -> None:
    cert, issuer, context, policy = _sign_fixture()
    cert["ledger_seal_projection"]["chain_schema_version"] = "traigent.cert_ledger.v0"
    with pytest.raises(VerificationError, match="^SCHEMA$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)


def test_seal_and_subject_substitution_is_rejected_before_signature_acceptance() -> None:
    cert, issuer, context, policy = _sign_fixture()
    cert["ledger_seal_projection"]["seal_ref"] = "seal:fedcba9876543210"
    with pytest.raises(VerificationError, match="^SEAL_DIGEST$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)

    cert, issuer, context, policy = _sign_fixture()
    cert["subject"]["build_session_ref"] = "bsn:fedcba9876543210"
    with pytest.raises(VerificationError, match="^SESSION_REF$"):
        verify_certificate(cert, issuer_public_key=issuer, context=context, policy=policy)
