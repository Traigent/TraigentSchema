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
DIGEST_ALG = "traigent-fp2-sha256"
STRONG = "This version was evaluated by Traigent."
WEAK = "Traigent evaluated this version; the evaluation was not shown able to fail."
TEXT = "The client's SDK reported a capture of this version, with the stated coverage."


def _subject() -> dict[str, Any]:
    return {
        "schema_version": "traigent.legend_claim_subject.v0",
        "policy_version": "legend.claims.v0",
        "digest_alg": DIGEST_ALG,
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


def _evaluated_subject(discrimination: str, text: str | None = None) -> dict[str, Any]:
    """A witnessed-evaluation subject; ``text`` defaults to the template the rule allows."""
    s = _subject()
    s["statement"] = {
        "type": "evaluated_traigent_witnessed",
        "text": text or (WEAK if discrimination == "none" else STRONG),
        "evidence_source": "traigent_witnessed",
        "source_label": "witnessed by Traigent",
    }
    s["commitments"].update(
        recovery_manifest_fingerprint=None,
        run_tuple_digest="sha256:" + "d" * 64,
        evaluated_subset_root="msr1:k0123456789abcdef:" + "e" * 64,
        evaluation_protocol="holdout",
        evaluation_outcome="pass",
        discrimination=discrimination,
        discrimination_event_ref=None if discrimination == "none" else f"eventref_{HEX32}",
    )
    s["coverage_status"] = None
    return s


# Canonicalization vectors: INPUT is JSON text (so a non-Python reader parses the literal itself).
# fp2 emits 0 for -0 and ECMAScript number text for floats. "in_w3c_jcs_sha256_profile" is false
# where the W3C jcs-sha256 profile (no floats) would refuse the value; the digest id is ours.
CANONICALIZATION_INPUTS = [
    ('{"n":-0}', True),
    ('{"n":-0.0}', False),
    ('{"n":0}', True),
    ('{"n":5.0}', False),
    ('{"n":1e21}', False),
    ('{"n":1e-7}', False),
    ('{"n":0.1}', False),
    ('{"n":9007199254740991}', True),
]


def _canonicalization_vectors() -> list[dict[str, Any]]:
    import traigent_schema.fp2 as fp2

    return [
        {
            "input_json": text,
            "digest_alg": DIGEST_ALG,
            "canonical": fp2.canonicalize(json.loads(text)),
            "digest": fp2.digest(json.loads(text)),
            "in_w3c_jcs_sha256_profile": in_profile,
        }
        for text, in_profile in CANONICALIZATION_INPUTS
    ]


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


def _subject_with(**changes: Any) -> dict[str, Any]:
    s = _subject()
    s.update(changes)
    return s


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
        "digest_alg": DIGEST_ALG,
        "canonicalization": _canonicalization_vectors(),
        "valid": {"statement": valid, "expect": "VERIFIED"},
        "valid_evaluated": {
            "witnessed_discrimination_none_weak_text": {
                "statement": _statement(_evaluated_subject("none")),
                "expect": "VERIFIED",
            },
            "witnessed_discrimination_control_strong_text": {
                "statement": _statement(_evaluated_subject("control")),
                "expect": "VERIFIED",
            },
        },
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
            "unknown_digest_alg": {
                "statement": _statement(_subject_with(digest_alg="jcs-sha256")),
                "expect": "DIGEST_ALG",
            },
            "witnessed_strong_text_without_discrimination": {
                "statement": _statement(_evaluated_subject("none", STRONG)),
                "expect": "SCHEMA",
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
    # For integer-only ASCII subjects the RFC 8785 profile equals the old json.dumps profile.
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


def _statement_schema_valid(statement: dict[str, Any]) -> bool:
    schema = json.loads(STATEMENT_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=build_registry()).is_valid(statement)


@pytest.mark.parametrize("literal", ["5", "5.0", "5e0", "0.5e1", "50e-1"])
def test_integral_number_spellings_canonicalize_and_verify_identically(literal: str) -> None:
    """RFC 8785: 5, 5.0 and 5e0 are one number; a schema-valid float position must verify."""
    base = _subject()
    text = json.dumps(base).replace(
        '"ledger_cutoff_position": 5', f'"ledger_cutoff_position": {literal}'
    )
    parsed = json.loads(text)
    assert _statement_schema_valid({"subject": parsed, "signature": _statement()["signature"]})
    assert canonical_subject_json(parsed) == canonical_subject_json(base)
    assert legend_signing_material(parsed) == legend_signing_material(base)
    statement = _statement(base)  # signed over the integer spelling
    statement["subject"] = parsed
    assert _code(statement) == "VERIFIED"


def test_float_position_is_emitted_without_fraction_and_non_finite_refused() -> None:
    subject = _subject()
    subject["ledger_cutoff_position"] = 5.0
    assert '"ledger_cutoff_position":5,' in canonical_subject_json(subject)
    for bad in (float("nan"), float("inf"), 2**53):
        subject["ledger_cutoff_position"] = bad
        with pytest.raises(TypeError):
            canonical_subject_json(subject)


def test_vector_canonicalization_cases_recompute_and_pin_negative_zero() -> None:
    import traigent_schema.fp2 as fp2

    vec = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    assert vec["digest_alg"] == DIGEST_ALG
    by_input = {c["input_json"]: c for c in vec["canonicalization"]}
    for case in vec["canonicalization"]:
        parsed = json.loads(case["input_json"])
        assert fp2.canonicalize(parsed) == case["canonical"]
        assert fp2.digest(parsed) == case["digest"]
        assert case["digest"].startswith("sha256:") and len(case["digest"]) == 71
    # -0 and 0 are one value; so are 5.0 and 5; floats keep ECMAScript text
    assert by_input['{"n":-0}']["canonical"] == by_input['{"n":0}']["canonical"] == '{"n":0}'
    assert by_input['{"n":-0}']["digest"] == by_input['{"n":0}']["digest"]
    assert by_input['{"n":-0.0}']["canonical"] == '{"n":0}'
    assert by_input['{"n":5.0}']["canonical"] == '{"n":5}'
    assert by_input['{"n":1e21}']["canonical"] == '{"n":1e+21}'
    assert by_input['{"n":1e-7}']["canonical"] == '{"n":1e-7}'
    # float-bearing values are ours only: a jcs-sha256 reader refuses them
    assert by_input['{"n":0.1}']["in_w3c_jcs_sha256_profile"] is False
    assert by_input['{"n":-0}']["in_w3c_jcs_sha256_profile"] is True
    assert fp2.canonicalize({"n": float("-0.0")}) == '{"n":0}'


def test_valid_evaluated_vectors_verify() -> None:
    vec = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))
    for name, case in vec["valid_evaluated"].items():
        assert _code(case["statement"]) == case["expect"], name


@pytest.mark.parametrize("bad", ["jcs-sha256", "traigent-fp2-sha512", "", "TRAIGENT-FP2-SHA256"])
def test_unknown_digest_alg_is_refused_before_schema(bad: str) -> None:
    assert _code(_statement(_subject_with(digest_alg=bad))) == "DIGEST_ALG"


@pytest.mark.parametrize("bad", [None, 1, ["traigent-fp2-sha256"], {"a": 1}])
def test_non_string_digest_alg_is_refused(bad: Any) -> None:
    assert _code(_statement(_subject_with(digest_alg=bad))) == "DIGEST_ALG"


def test_missing_digest_alg_is_refused() -> None:
    subject = _subject()
    del subject["digest_alg"]
    assert _code(_statement(subject)) == "DIGEST_ALG"


def test_digest_alg_is_signed_so_swapping_it_is_tampering_when_both_ids_known() -> None:
    stmt = _statement()
    stmt["subject"]["digest_alg"] = "traigent-fp2-sha256 "
    assert _code(stmt) == "DIGEST_ALG"


def test_witnessed_strong_text_requires_discrimination() -> None:
    assert _statement_schema_valid(_statement(_evaluated_subject("none")))
    assert _statement_schema_valid(_statement(_evaluated_subject("control")))
    # "evaluated by Traigent" without a discriminating check is refused ...
    assert not _statement_schema_valid(_statement(_evaluated_subject("none", STRONG)))
    # ... and the weak text cannot hide a discriminating one
    for d in ("shown_by_run", "control", "prior_run"):
        assert not _statement_schema_valid(_statement(_evaluated_subject(d, WEAK)))
        assert _code(_statement(_evaluated_subject(d, WEAK))) == "SCHEMA"


def test_discrimination_ref_is_non_null_exactly_when_not_none() -> None:
    s = _evaluated_subject("prior_run")
    s["commitments"]["discrimination_event_ref"] = None
    assert not _statement_schema_valid(_statement(s))
    s = _evaluated_subject("none")
    s["commitments"]["discrimination_event_ref"] = f"eventref_{HEX32}"
    assert not _statement_schema_valid(_statement(s))


def test_signed_outcome_is_a_verdict_only_and_evaluated_fields_are_type_scoped() -> None:
    for bad in ("not_exercised", "inconclusive", "void", "maybe"):
        s = _evaluated_subject("control")
        s["commitments"]["evaluation_outcome"] = bad
        assert not _statement_schema_valid(_statement(s)), bad
    s = _evaluated_subject("control")
    del s["commitments"]["discrimination"]
    assert not _statement_schema_valid(_statement(s))
    # a non-evaluation statement may not carry evaluation fields
    s = _subject()
    s["commitments"]["discrimination"] = "none"
    assert not _statement_schema_valid(_statement(s))
    # a client-reported evaluation carries the fields but keeps its own text
    c = _evaluated_subject("none")
    c["statement"] = {
        "type": "evaluated_client_reported",
        "text": "The client reported an evaluation of this version; Traigent did not witness it.",
        "evidence_source": "client_reported",
        "source_label": "client-reported",
    }
    assert _statement_schema_valid(_statement(c))
