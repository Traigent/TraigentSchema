"""Contract + reader tests for the commitment-linkage sidecar (C1 step 1)."""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jsonschema import Draft7Validator
from referencing import Registry, Resource

import traigent_schema.certification.commitment_linkage as cl
from traigent_schema.certification.relying_party_verifier import _ISSUER_SPKI_DOMAIN

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
SCHEMA_PATH = SCHEMAS / "certification" / "commitment_linkage_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

FP = "sha256:" + "ab" * 32
RECORD_A = "sha256:" + "a1" * 32
RECORD_B = "sha256:" + "b2" * 32
PROJECT = "project-v1"
BUILD = "build:" + "b" * 8
KEY_REF = "key:issuerkey1"
RING_REF = "ring:ringref001"

# Fixed vectors: fp_digest = FP, openings as listed. Hard-coded expected values.
VECTORS = [
    (
        "agent",
        "source_text",
        bytes(range(32)),
        "sha256:ce08bd39cdfca68fe28e9d385f592a306dc0836cf5abaf0c21094577d5ac8f77",
    ),
    (
        "dataset",
        "order_free_multiset",
        bytes(32),
        "sha256:817ddb572f30bbcc5545e3409d0ce1e2f22c3f419d11f0fec03c1f138f0b9051",
    ),
    (
        "evaluator:primary",
        "endpoint_only",
        bytes([255]) * 32,
        "sha256:a00fe05ab05069ae5ad9003fdfb632569ab9533084dbe9725016d26f1773a92d",
    ),
    (
        "config_space",
        "config_space",
        bytes(range(32)),
        "sha256:e1df83679bedf6748c08e7f2e05209ba701d9b50a6fc7182451e984af7ff8a65",
    ),
]

# Legacy-bytes guard: these files are covered by recorded verifier fingerprints /
# already-signed bytes; changing them needs an owner card, not a drive-by edit.
PINNED_FILES = {
    "traigent_schema/schemas/certification/process_record_v1_schema.json": "1844ecf3e8e22110d5c8827e59c9219159fba3a05f0a60c3f681b534eca2b8ef",  # noqa: E501
    "traigent_schema/certification/agent_quality_verifier.py": "ad4b6e620e6b858d1e76beffd555dcbce22443102d18e48674b1b349fd0c3c42",  # noqa: E501
    "traigent_schema/certification/evaluator_quality_verifier.py": "e961613b87dbab5fab60c7cb984c8ee76fc8fb7cfbc7b1791aa63b32479624ab",  # noqa: E501
}


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("$id"), str):
            resources.append((doc["$id"], Resource.from_contents(doc)))
    return Registry().with_resources(resources)


VALIDATOR = Draft7Validator(SCHEMA, registry=_registry())


def _valid(value: object) -> bool:
    return not list(VALIDATOR.iter_errors(value))


# ---------------------------------------------------------------- signing helpers
_PRIVATE = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(64, 96)))
_DER = _PRIVATE.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
ISSUER_KEY = cl.LinkageIssuerKeyV1(
    key_ref=KEY_REF,
    trust_ring_ref=RING_REF,
    algorithm="ed25519",
    public_key_der_b64=base64.b64encode(_DER).decode("ascii"),
    public_key_digest="sha256:" + hashlib.sha256(_ISSUER_SPKI_DOMAIN + b"\x00" + _DER).hexdigest(),
)


def _entries() -> list[dict]:
    return [
        {
            "role": "agent",
            "basis": "source_text",
            "attestation": "client_declared",
            "commitment": VECTORS[0][3],
        },
        {
            "role": "dataset",
            "basis": "order_free_multiset",
            "attestation": "client_declared",
            "commitment": VECTORS[1][3],
        },
        {
            "role": "evaluator:primary",
            "basis": "endpoint_only",
            "attestation": "client_declared",
            "commitment": VECTORS[2][3],
        },
        {"role": "config_space", "basis": "unavailable", "attestation": "client_declared"},
    ]


def _sign(unsigned: dict, private=_PRIVATE) -> dict:
    import traigent_schema.fp2 as fp2

    canonical = fp2.canonicalize(unsigned).encode("utf-8")
    digest = (
        "sha256:" + hashlib.sha256(cl.UNSIGNED_LINKAGE_DOMAIN + b"\x00" + canonical).hexdigest()
    )
    raw = private.sign(cl.ISSUER_SIGNATURE_DOMAIN + b"\x00" + canonical)
    return {
        "schema_version": "traigent.commitment_linkage.v1",
        "unsigned_linkage": unsigned,
        "signature": {
            "schema_version": "traigent.commitment_linkage.signature.v1",
            "algorithm": "ed25519",
            "issuer_key_ref": KEY_REF,
            "trust_ring_ref": RING_REF,
            "signed_payload": "unsigned_commitment_linkage",
            "unsigned_linkage_digest": digest,
            "signature": base64.b64encode(raw).decode("ascii"),
        },
    }


def _unsigned(record: str = RECORD_A, entries: list[dict] | None = None) -> dict:
    return {
        "schema_version": "traigent.commitment_linkage.unsigned.v1",
        "process_record_digest": record,
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "entries": entries if entries is not None else _entries(),
    }


def _ctx(record: str = RECORD_A, **over) -> cl.CommitmentLinkageVerificationContext:
    args = dict(
        expected_process_record_digest=record,
        expected_project_ref=PROJECT,
        expected_build_session_ref=BUILD,
        issuer_key=ISSUER_KEY,
    )
    args.update(over)
    return cl.CommitmentLinkageVerificationContext(**args)


def _code(envelope: object, ctx=None) -> str:
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        cl.verify_commitment_linkage(envelope, context=ctx or _ctx())
    assert exc.value.code in cl.COMMITMENT_LINKAGE_ERROR_CODES
    return exc.value.code


# ------------------------------------------------------------------ commitment vectors
@pytest.mark.parametrize(("role", "basis", "opening", "expected"), VECTORS)
def test_commitment_fixed_vectors(role, basis, opening, expected):
    assert cl.compute_commitment(role=role, basis=basis, fp_digest=FP, opening=opening) == expected


@pytest.mark.parametrize(("role", "basis", "opening", "expected"), VECTORS)
def test_commitment_matches_independent_byte_construction(role, basis, opening, expected):
    def lp(b: bytes) -> bytes:
        return struct.pack(">Q", len(b)) + b

    p = (
        lp(b"traigent.commitment-linkage.v1")
        + lp(role.encode())
        + lp(basis.encode())
        + lp(b"fp1")
        + lp(FP.encode())
        + lp(opening)
    )
    assert "sha256:" + hashlib.sha256(p).hexdigest() == expected


def test_commitment_domain_separation_each_input_matters():
    op = bytes(range(32))
    base = cl.compute_commitment(role="agent", basis="source_text", fp_digest=FP, opening=op)
    variants = [
        cl.compute_commitment(role="agent", basis="name_only", fp_digest=FP, opening=op),
        cl.compute_commitment(role="dataset", basis="source_text", fp_digest=FP, opening=op),
        cl.compute_commitment(
            role="agent", basis="source_text", fp_digest="sha256:" + "cd" * 32, opening=op
        ),
        cl.compute_commitment(role="agent", basis="source_text", fp_digest=FP, opening=bytes(32)),
    ]
    assert len({base, *variants}) == 5


def test_new_opening_is_32_fresh_bytes():
    a, b = cl.new_opening(), cl.new_opening()
    assert len(a) == len(b) == 32 and a != b


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        (
            dict(role="build_definition", basis="source_text", fp_digest=FP, opening=bytes(32)),
            "ROLE_SHAPE",
        ),
        (dict(role="agent", basis="unavailable", fp_digest=FP, opening=bytes(32)), "ROLE_SHAPE"),
        (
            dict(role="agent", basis="source_text", fp_digest="fp1:abc", opening=bytes(32)),
            "FINGERPRINT_SHAPE",
        ),
        (
            dict(role="agent", basis="source_text", fp_digest=FP.upper(), opening=bytes(32)),
            "FINGERPRINT_SHAPE",
        ),
        (dict(role="agent", basis="source_text", fp_digest=FP, opening=bytes(31)), "OPENING_SHAPE"),
        (dict(role="agent", basis="source_text", fp_digest=FP, opening="x" * 32), "OPENING_SHAPE"),
    ],
)
def test_compute_commitment_refuses_bad_input(kwargs, code):
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        cl.compute_commitment(**kwargs)
    assert exc.value.code == code
    assert FP not in str(exc.value)


# --------------------------------------------------------------------- schema
def test_schema_accepts_signed_example():
    assert _valid(_sign(_unsigned()))


def _mutated(path_fn):
    env = _sign(_unsigned())
    path_fn(env)
    return env


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.update(extra=1),
        lambda e: e["unsigned_linkage"].update(extra=1),
        lambda e: e["signature"].update(extra=1),
        lambda e: e["unsigned_linkage"]["entries"][0].update(extra=1),
        lambda e: e["unsigned_linkage"]["entries"][0].update(attestation="backend_observed"),
        lambda e: e["unsigned_linkage"]["entries"][0].update(basis="source"),
        lambda e: e["unsigned_linkage"]["entries"][0].update(role="build_definition"),
        lambda e: e["unsigned_linkage"]["entries"][0].update(role="evaluator:Bad Role"),
        lambda e: e["unsigned_linkage"]["entries"][0].update(commitment="sha256:xyz"),
        lambda e: e["unsigned_linkage"]["entries"][0].pop("commitment"),
        lambda e: e["unsigned_linkage"]["entries"][3].update(
            commitment=FP
        ),  # unavailable + commitment
        lambda e: e["unsigned_linkage"]["entries"][0].update(
            basis="order_free_multiset"
        ),  # agent/dataset basis
        lambda e: e["unsigned_linkage"]["entries"][1].update(basis="source_text"),
        lambda e: e["unsigned_linkage"]["entries"][2].update(basis="config_space"),
        lambda e: e["unsigned_linkage"].update(entries=[]),
        lambda e: e["unsigned_linkage"].pop("process_record_digest"),
        lambda e: e["unsigned_linkage"].update(process_record_digest="abc"),
        lambda e: e["unsigned_linkage"].update(schema_version="x"),
        lambda e: e["signature"].update(algorithm="rsa"),
        lambda e: e["signature"].update(signature="AAAA"),
    ],
)
def test_schema_refuses(mutate):
    assert not _valid(_mutated(mutate))


def test_schema_has_no_build_definition_role():
    role_def = SCHEMA["definitions"]["CommitmentRoleV1"]
    assert role_def["anyOf"][0]["enum"] == ["agent", "dataset", "config_space"]
    entry = _unsigned(
        entries=[
            {"role": "build_definition", "basis": "unavailable", "attestation": "client_declared"}
        ]
    )
    assert not _valid(_sign(entry))


# ---------------------------------------------------------------------- reader
def test_verify_ok_and_open_results():
    linkage = cl.verify_commitment_linkage(_sign(_unsigned()), context=_ctx())
    assert linkage.process_record_digest == RECORD_A
    for role, _basis, opening, _ in VECTORS[:3]:
        assert (
            cl.open_commitment(linkage, role=role, fp_digest=FP, opening=opening)
            == cl.COMMITMENT_OPENED_MATCH
        )
    # wrong opening / wrong fingerprint -> MISMATCH
    assert (
        cl.open_commitment(linkage, role="agent", fp_digest=FP, opening=bytes(32))
        == cl.COMMITMENT_OPENED_MISMATCH
    )
    assert (
        cl.open_commitment(
            linkage, role="agent", fp_digest="sha256:" + "00" * 32, opening=VECTORS[0][2]
        )
        == cl.COMMITMENT_OPENED_MISMATCH
    )
    # opening of the dataset entry used for the agent role -> MISMATCH
    assert (
        cl.open_commitment(linkage, role="agent", fp_digest=FP, opening=VECTORS[1][2])
        == cl.COMMITMENT_OPENED_MISMATCH
    )
    # unavailable basis, and an absent role -> UNAVAILABLE
    assert (
        cl.open_commitment(linkage, role="config_space", fp_digest=FP, opening=bytes(32))
        == cl.COMMITMENT_UNAVAILABLE
    )
    assert (
        cl.open_commitment(linkage, role="evaluator:other", fp_digest=FP, opening=bytes(32))
        == cl.COMMITMENT_UNAVAILABLE
    )


def test_open_refuses_malformed_inputs_and_unverified_linkage():
    linkage = cl.verify_commitment_linkage(_sign(_unsigned()), context=_ctx())
    for kw, code in [
        (dict(role="nope", fp_digest=FP, opening=bytes(32)), "ROLE_SHAPE"),
        (dict(role="agent", fp_digest="x", opening=bytes(32)), "FINGERPRINT_SHAPE"),
        (dict(role="agent", fp_digest=FP, opening=b"short"), "OPENING_SHAPE"),
    ]:
        with pytest.raises(cl.CommitmentLinkageError) as exc:
            cl.open_commitment(linkage, **kw)
        assert exc.value.code == code
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        cl.open_commitment(_sign(_unsigned()), role="agent", fp_digest=FP, opening=bytes(32))  # type: ignore[arg-type]
    assert exc.value.code == "CONTEXT"


def test_sidecar_for_record_a_does_not_verify_against_record_b():
    envelope = _sign(_unsigned(RECORD_A))
    assert _code(envelope, _ctx(RECORD_B)) == "RECORD_BINDING_MISMATCH"


def test_sidecar_rebound_to_b_without_resigning_is_refused():
    envelope = _sign(_unsigned(RECORD_A))
    envelope["unsigned_linkage"]["process_record_digest"] = RECORD_B
    assert _code(envelope, _ctx(RECORD_B)) == "UNSIGNED_LINKAGE_DIGEST_MISMATCH"


def test_tampered_commitment_with_recomputed_digest_fails_signature():
    envelope = _sign(_unsigned())
    entries = envelope["unsigned_linkage"]["entries"]
    entries[0]["commitment"] = "sha256:" + "00" * 32
    import traigent_schema.fp2 as fp2

    canonical = fp2.canonicalize(envelope["unsigned_linkage"]).encode("utf-8")
    envelope["signature"]["unsigned_linkage_digest"] = (
        "sha256:" + hashlib.sha256(cl.UNSIGNED_LINKAGE_DOMAIN + b"\x00" + canonical).hexdigest()
    )
    assert _code(envelope) == "SIGNATURE_INVALID"


def test_wrong_signer_refused():
    other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(100, 132)))
    assert _code(_sign(_unsigned(), private=other)) == "SIGNATURE_INVALID"


def test_scope_mismatch_refused():
    envelope = _sign(_unsigned())
    assert _code(envelope, _ctx(expected_project_ref="other-project")) == "SCOPE_MISMATCH"
    assert _code(envelope, _ctx(expected_build_session_ref="build:" + "c" * 8)) == "SCOPE_MISMATCH"


def test_key_mismatch_refused():
    envelope = _sign(_unsigned())
    other_key = cl.LinkageIssuerKeyV1(
        key_ref="key:differentkey",
        trust_ring_ref=RING_REF,
        algorithm="ed25519",
        public_key_der_b64=ISSUER_KEY.public_key_der_b64,
        public_key_digest=ISSUER_KEY.public_key_digest,
    )
    assert _code(envelope, _ctx(issuer_key=other_key)) == "KEY_MISMATCH"


def test_bad_key_material_refused():
    envelope = _sign(_unsigned())
    bad = cl.LinkageIssuerKeyV1(
        key_ref=KEY_REF,
        trust_ring_ref=RING_REF,
        algorithm="ed25519",
        public_key_der_b64=ISSUER_KEY.public_key_der_b64,
        public_key_digest="sha256:" + "00" * 32,
    )
    assert _code(envelope, _ctx(issuer_key=bad)) == "KEY_MATERIAL"


def test_duplicate_role_refused():
    entries = _entries()
    entries.append(dict(entries[0]))
    assert _code(_sign(_unsigned(entries=entries))) == "DUPLICATE_ROLE"


def test_shape_and_schema_refusals():
    assert _code("not a dict") == "ENVELOPE_SHAPE"
    assert _code({}) == "SCHEMA"
    env = _sign(_unsigned())
    env["extra"] = 1
    assert _code(env) == "SCHEMA"


def test_context_validation():
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        _ctx(expected_process_record_digest="nope")
    assert exc.value.code == "CONTEXT"
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        cl.verify_commitment_linkage(_sign(_unsigned()), context=object())  # type: ignore[arg-type]
    assert exc.value.code == "CONTEXT"


def test_errors_never_echo_values():
    secret_role = "evaluator:Alice_has_diabetes"
    entries = _entries()
    entries[0]["role"] = secret_role
    with pytest.raises(cl.CommitmentLinkageError) as exc:
        cl.verify_commitment_linkage(_sign(_unsigned(entries=entries)), context=_ctx())
    assert "Alice" not in str(exc.value) and "Alice" not in repr(exc.value)
    assert exc.value.__cause__ is None


# ------------------------------------------------------------- legacy bytes unchanged
@pytest.mark.parametrize(("rel", "digest"), sorted(PINNED_FILES.items()))
def test_legacy_signed_surfaces_are_byte_identical(rel, digest):
    assert hashlib.sha256((ROOT / rel).read_bytes()).hexdigest() == digest


def test_process_record_schema_still_rejects_a_linkage_field():
    schema = json.loads((SCHEMAS / "certification" / "process_record_v1_schema.json").read_text())
    bundle_def = schema["definitions"]["ProcessRecordCertificateBundleV1"]
    assert bundle_def["additionalProperties"] is False
    assert "commitment_linkage" not in bundle_def["properties"]
    unsigned_def = schema["definitions"]["ProcessRecordUnsignedManifestV1"]
    assert "commitment_linkage" not in unsigned_def["properties"]
