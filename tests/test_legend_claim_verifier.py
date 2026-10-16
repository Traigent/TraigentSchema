# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Golden vectors and negatives for the signed Pillar Legend claim statement verifier.

The signing key below is TEST-ONLY: a fixed, public seed generated for this file. It is not,
and must never be replaced by, a real key. Ed25519 is deterministic, so the committed vector
file is regenerated here and compared byte for byte.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from jsonschema import Draft7Validator

import traigent_schema.certification.relying_party_verifier as rpv
from tests._schema_refs import build_registry
from traigent_schema.legend_claim_verifier import (
    LEGEND_SIGNATURE_DOMAIN,
    LegendClaimVerificationError,
    TrustedLegendKey,
    canonical_subject_json,
    legend_signing_material,
    verify_legend_claim_statement,
)

ROOT = Path(__file__).resolve().parents[1]
schemas_dir = ROOT / "traigent_schema" / "schemas"
STATEMENT_PATH = schemas_dir / "legend" / "legend_claim_statement_v0.json"
VECTORS_PATH = Path(__file__).with_name("legend_claim_statement_v0_vectors.json")
PROCESS_RECORD_DOMAIN = b"traigent.process_record.issuer_signature.v1"  # Backend issuer_signer.py

# TEST-ONLY seed (32 bytes). Not a secret, not a real key.
TEST_SEED = b"TEST-ONLY-legend-claim-vector-k0"
TEST_KEY_ID = "test-only-legend-key-1"
H64 = "a" * 64
HEX32 = "0123456789abcdef0123456789abcdef"
TS = "2026-10-15T10:00:00Z"
TEXT = "The client's SDK reported a capture of this version, with the stated coverage."


def _subject() -> dict[str, Any]:
    return {
        "schema_version": "traigent.legend_claim_subject.v0",
        "policy_version": "legend.claims.v0",
        "statement": {
            "type": "captured",
            "text": TEXT,
            "evidence_source": "client_sdk_reported",
            "source_label": "client-reported (SDK-computed)",
        },
        "version": {
            "version_ref": f"versionref_{HEX32}",
            "kind": "agent",
            "fingerprint_scheme": "agent_build_digest_v1",
            "key_id": None,
            "fingerprint": "sha256:" + H64,
        },
        "commitments": {
            "recovery_manifest_fingerprint": "rmf0:sha256:" + "b" * 64,
            "run_tuple_digest": None,
            "trial_ref": None,
            "evaluated_subset_root": None,
            "evaluation_protocol": None,
        },
        "coverage_status": "complete",
        "supporting_event_refs": [f"eventref_{HEX32}"],
        "ledger_cutoff_position": 5,
        "as_of": TS,
        "issued_at": "2026-10-15T10:00:01Z",
        "predicate_digest": "sha256:" + "c" * 64,
    }


_PRIV = ed25519.Ed25519PrivateKey.from_private_bytes(TEST_SEED)
TRUSTED = {TEST_KEY_ID: TrustedLegendKey("ed25519", _PRIV.public_key())}


def _sign(subject: dict[str, Any], domain: bytes = LEGEND_SIGNATURE_DOMAIN) -> str:
    material = domain + b"\x00" + canonical_subject_json(subject).encode("utf-8")
    return base64.b64encode(_PRIV.sign(material)).decode("ascii")


def _statement(subject: dict[str, Any] | None = None, **sig: Any) -> dict[str, Any]:
    subject = subject if subject is not None else _subject()
    signature = {
        "domain": LEGEND_SIGNATURE_DOMAIN.decode("ascii"),
        "algorithm": "ed25519",
        "key_id": TEST_KEY_ID,
        "encoding": "base64",
        "value": _sign(subject),
    }
    signature.update(sig)
    return {"subject": subject, "signature": signature}


def _vectors() -> dict[str, Any]:
    valid = _statement()
    tampered = copy.deepcopy(valid)
    tampered["subject"]["ledger_cutoff_position"] = 6
    process_domain = _statement(
        value=_sign(_subject(), PROCESS_RECORD_DOMAIN),
        domain=PROCESS_RECORD_DOMAIN.decode("ascii"),
    )
    return {
        "_comment": "TEST-ONLY vectors; key seed is public, see the test module.",
        "test_public_key_raw_b64": base64.b64encode(_PRIV.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
        "trusted_key_id": TEST_KEY_ID,
        "canonical_subject_json": canonical_subject_json(valid["subject"]),
        "valid": {"statement": valid, "expect": "VERIFIED"},
        "negative": {
            "tampered_subject": {"statement": tampered, "expect": "SIGNATURE_INVALID"},
            "wrong_domain_process_record": {"statement": process_domain, "expect": "DOMAIN"},
            "wrong_domain_signature_under_legend_label": {
                "statement": _statement(value=_sign(_subject(), PROCESS_RECORD_DOMAIN)),
                "expect": "SIGNATURE_INVALID",
            },
            "unknown_key_id": {
                "statement": _statement(key_id="test-only-other-key"),
                "expect": "UNKNOWN_KEY",
            },
            "wrong_algorithm": {
                "statement": _statement(algorithm="ecdsa_p256_sha256"),
                "expect": "ALGORITHM",
            },
        },
    }


def _code(statement: Any, trusted: Any = TRUSTED) -> str:
    try:
        verify_legend_claim_statement(statement, trusted)
    except LegendClaimVerificationError as exc:
        return exc.code
    return "VERIFIED"


def test_vector_file_matches_regeneration() -> None:
    assert json.loads(VECTORS_PATH.read_text(encoding="utf-8")) == _vectors()


def test_golden_vectors_verify_as_expected() -> None:
    vec = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert _code(vec["valid"]["statement"]) == "VERIFIED"
    for name, case in vec["negative"].items():
        assert _code(case["statement"]) == case["expect"], name


def test_canonical_bytes_are_pinned_and_match_backend_construction() -> None:
    subject = _subject()
    text = canonical_subject_json(subject)
    # Backend legend_claims._canonical_json: sort_keys, (",", ":"), ensure_ascii=False, no NaN.
    assert text == json.dumps(
        subject, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    assert text.startswith('{"as_of":"2026-10-15T10:00:00Z","commitments":{')
    assert legend_signing_material(subject) == (
        b"traigent.legend_claim_subject.signature.v0\x00" + text.encode("utf-8")
    )
    # For schema-valid (ASCII) subjects the bytes equal the RFC 8785 style fp2 canonical form.
    import traigent_schema.fp2 as fp2

    assert fp2.canonicalize(subject) == text


def test_result_returns_verified_subject() -> None:
    result = verify_legend_claim_statement(_statement(), TRUSTED)
    assert result.subject == _subject() and result.key_id == TEST_KEY_ID


def test_extra_top_level_key_refused() -> None:
    assert _code({**_statement(), "extra": 1}) == "STRUCTURE"


def test_all_zero_signature_is_invalid_not_malformed() -> None:
    assert _code(_statement(value="A" * 86 + "==")) == "SIGNATURE_INVALID"


@pytest.mark.parametrize("junk", [None, [], "x", {"subject": {}}, {"subject": {}, "signature": 1}])
def test_structure_refused(junk: Any) -> None:
    assert _code(junk) == "STRUCTURE"


def test_key_reordering_is_not_tampering_but_value_change_is() -> None:
    stmt = _statement()
    stmt["subject"] = dict(reversed(list(stmt["subject"].items())))
    assert _code(stmt) == "VERIFIED"
    stmt["subject"]["statement"]["type"] = "declared"
    assert _code(stmt) in {"SCHEMA", "SIGNATURE_INVALID"}


def test_legend_signature_does_not_verify_as_process_record_issuer_signature() -> None:
    subject = _subject()
    raw = base64.b64decode(_statement(subject)["signature"]["value"])
    canonical = canonical_subject_json(subject).encode("utf-8")
    with pytest.raises(rpv.RelyingPartyVerificationError):
        rpv._verify_signature(
            _PRIV.public_key(),
            "ed25519",
            rpv._issuer_material(canonical),
            base64.b64encode(raw).decode(),
        )
    assert LEGEND_SIGNATURE_DOMAIN != PROCESS_RECORD_DOMAIN


def test_wrong_key_for_trusted_id_refused() -> None:
    other = ed25519.Ed25519PrivateKey.from_private_bytes(b"TEST-ONLY-legend-claim-other-k00")
    trusted = {TEST_KEY_ID: TrustedLegendKey("ed25519", other.public_key())}
    assert _code(_statement(), trusted) == "SIGNATURE_INVALID"


def test_trusted_key_pinned_to_other_algorithm_refused() -> None:
    trusted = {TEST_KEY_ID: TrustedLegendKey("ecdsa_p256_sha256", _PRIV.public_key())}
    assert _code(_statement(), trusted) == "ALGORITHM"


def test_key_object_mismatching_declared_algorithm_refused() -> None:
    trusted = {TEST_KEY_ID: TrustedLegendKey("ecdsa_p256_sha256", _PRIV.public_key())}
    stmt = _statement(algorithm="ecdsa_p256_sha256")
    assert _code(stmt, trusted) == "KEY_ALGORITHM"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s["subject"].update(extra=1),
        lambda s: s["signature"].update(extra=1),
        lambda s: s["subject"]["statement"].update(text="free text"),
        lambda s: s["subject"]["statement"].update(source_label="witnessed by Traigent"),
        lambda s: s["subject"]["statement"].update(evidence_source="server_recorded"),
        lambda s: s["signature"].update(encoding="hex"),
        lambda s: s["subject"].update(policy_version="Legend Claims"),
        lambda s: s["subject"].update(ledger_cutoff_position=True),
    ],
)
def test_closed_schema_refuses(mutate: Any) -> None:
    stmt = _statement()
    mutate(stmt)
    assert _code(stmt) == "SCHEMA"


@pytest.mark.parametrize("value", ["", "!" * 88, base64.b64encode(b"x" * 63).decode()])
def test_malformed_signature_value_refused(value: str) -> None:
    assert _code(_statement(value=value)) in {"SCHEMA", "SIGNATURE_BASE64"}


def test_ecdsa_p256_round_trip_and_high_s_refused() -> None:
    key = ec.generate_private_key(ec.SECP256R1())  # throwaway, test-only
    subject = _subject()
    der = key.sign(legend_signing_material(subject), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    low = s if s <= order // 2 else order - s
    trusted = {"test-only-p256": TrustedLegendKey("ecdsa_p256_sha256", key.public_key())}

    def enc(sv: int) -> str:
        return base64.b64encode(r.to_bytes(32, "big") + sv.to_bytes(32, "big")).decode()

    def stmt(sv: int) -> dict[str, Any]:
        return _statement(
            subject, algorithm="ecdsa_p256_sha256", key_id="test-only-p256", value=enc(sv)
        )

    assert _code(stmt(low), trusted) == "VERIFIED"
    assert _code(stmt(order - low), trusted) == "SIGNATURE_HIGH_S"


def test_statement_schema_is_valid_draft7_and_accepts_vector() -> None:
    schema = json.loads(STATEMENT_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, registry=build_registry())
    assert list(validator.iter_errors(_statement())) == []
