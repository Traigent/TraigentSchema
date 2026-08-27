"""Strict, privacy-preserving verification-material distribution contract."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from importlib import resources

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2

SCHEMA_NAME = "certificate_verification_materials_v0_schema.json"
SCHEMA_PATH = (
    resources.files("traigent_schema")
    .joinpath("schemas", "certification", SCHEMA_NAME)
)
DOMAIN = b"traigent.agent_certificate.verification_materials.v0"


def _registry() -> Registry:
    root = resources.files("traigent_schema").joinpath("schemas")
    found: list[tuple[str, Resource]] = []
    for item in root.joinpath("certification").iterdir():
        if item.name.endswith(".json"):
            document = json.loads(item.read_text(encoding="utf-8"))
            if isinstance(document, dict) and isinstance(document.get("$id"), str):
                found.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(found)


def _validator() -> Draft7Validator:
    return Draft7Validator(
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")), registry=_registry()
    )


def _der(public_key: object) -> str:
    encoded = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(encoded).decode("ascii")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(DOMAIN + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


def _valid_materials(*, client_algorithm: str = "ed25519") -> dict:
    issuer_public = ec.generate_private_key(ec.SECP256R1()).public_key()
    client_public = (
        ed25519.Ed25519PrivateKey.generate().public_key()
        if client_algorithm == "ed25519"
        else ec.generate_private_key(ec.SECP256R1()).public_key()
    )
    document = {
        "schema_version": "traigent.certificate_verification_materials.v0",
        "distribution_role": "discovery_only",
        "requires_independent_pins": True,
        "certificate_ref": "certificate:opaque0001234",
        "issuer": {
            "key_ref": "issuer-key:opaque0001",
            "trust_ring_ref": "trust-ring:opaque001",
            "algorithm": "ecdsa_p256_sha256",
            "public_key_der_b64": _der(issuer_public),
            "public_key_digest": "sha256:" + "a" * 64,
        },
        "client": {
            "key_ref": "client-key:opaque0001",
            "algorithm": client_algorithm,
            "public_key_der_b64": _der(client_public),
            "public_key_digest": "sha256:" + "b" * 64,
        },
        "relying_party_policy": {
            "compiler_register_versions": {
                "compiler_version": "1.0.0",
                "semantics_manifest_digest": "sha256:" + "c" * 64,
                "claim_template_catalog_digest": "sha256:" + "d" * 64,
                "prohibited_register_digest": "sha256:" + "e" * 64,
                "verifier_catalog_digest": "sha256:" + "f" * 64,
                "non_claim_reason_catalog_digest": "sha256:" + "0" * 64,
            },
            "verifier_bindings": [
                {
                    "verifier_id": "D2",
                    "verifier_ref": "ver.cert.offline_mode_witness",
                    "verifier_version": "1.0.0",
                },
                {
                    "verifier_id": "G1",
                    "verifier_ref": "ver.cert.client_manifest_commitment",
                    "verifier_version": "1.0.0",
                },
            ],
        },
    }
    document["materials_digest"] = _digest(document)
    return document


def _errors(document: object) -> list:
    return list(_validator().iter_errors(document))


def test_schema_is_packaged_and_validates_ed25519_and_p256_clients() -> None:
    assert SCHEMA_PATH.is_file()
    assert _errors(_valid_materials(client_algorithm="ed25519")) == []
    assert _errors(_valid_materials(client_algorithm="ecdsa_p256_sha256")) == []


def test_materials_digest_is_domain_separated_fp2_digest_of_bundle_without_it() -> None:
    document = _valid_materials()
    expected = dict(document)
    expected.pop("materials_digest")
    assert document["materials_digest"] == _digest(expected)
    changed = copy.deepcopy(document)
    changed["distribution_role"] = "not_discovery"
    assert _errors(changed)


@pytest.mark.parametrize(
    "field",
    (
        "nonce",
        "expected_nonce",
        "build_session_ref",
        "tenant_id",
        "project_id",
        "manifest_digest",
        "certificate_status",
        "revoked_at",
        "kms_key_arn",
        "account_id",
        "region",
        "source",
        "examples",
        "evaluator_code",
        "blind",
        "private_key",
        "signed_certificate",
    ),
)
def test_hard_banned_fields_are_rejected_at_any_object_level(field: str) -> None:
    document = _valid_materials()
    document["issuer"][field] = "sentinel"
    assert _errors(document)
    nested = _valid_materials()
    nested["relying_party_policy"][field] = {"sentinel": True}
    assert _errors(nested)


@pytest.mark.parametrize(
    "mutator",
    (
        lambda d: d.update(schema_version="wrong"),
        lambda d: d.update(distribution_role="authenticated"),
        lambda d: d.update(requires_independent_pins=False),
        lambda d: d.update(materials_digest="not-a-digest"),
        lambda d: d["issuer"].update(algorithm="ed25519"),
        lambda d: d["issuer"].update(public_key_der_b64="not-base64"),
        lambda d: d["issuer"].update(public_key_der_b64="A" * 61),
        lambda d: d["client"].update(algorithm="rsa"),
        lambda d: d["relying_party_policy"]["verifier_bindings"].reverse(),
        lambda d: d["relying_party_policy"]["verifier_bindings"].append(
            {
                "verifier_id": "D2",
                "verifier_ref": "ver.cert.extra",
                "verifier_version": "1.0.0",
            }
        ),
        lambda d: d["relying_party_policy"]["compiler_register_versions"].update(extra="x"),
    ),
)
def test_wrong_literals_order_count_policy_names_and_encodings_fail(mutator) -> None:
    document = _valid_materials()
    mutator(document)
    assert _errors(document)


def test_recursive_extra_objects_are_not_a_side_channel() -> None:
    document = _valid_materials()
    document["client"]["nested"] = {"source": {"examples": ["sentinel"]}}
    assert _errors(document)
