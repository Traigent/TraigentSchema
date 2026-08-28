"""Strict, privacy-preserving verification-material distribution contract."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from importlib import resources

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import SchemaValidator, fp2
from traigent_schema.certification import relying_party_verifier as verifier_impl
from traigent_schema.validator import _FORMAT_CHECKER

SCHEMA_NAME = "certificate_verification_materials_v0_schema.json"
SCHEMA_PATH = resources.files("traigent_schema").joinpath("schemas", "certification", SCHEMA_NAME)
DOMAIN = b"traigent.agent_certificate.verification_materials.v0"
ISSUER_SPKI_DOMAIN = b"traigent.agent_certificate.issuer_spki_der.v0"
CLIENT_SPKI_DOMAIN = b"traigent.agent_certificate.client_spki_der.v0"


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
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
        registry=_registry(),
        format_checker=_FORMAT_CHECKER,
    )


def _der(public_key: object) -> str:
    return base64.b64encode(_der_bytes(public_key)).decode("ascii")


def _der_bytes(public_key: object) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _spki_digest(public_key: object, domain: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + _der_bytes(public_key)).hexdigest()


def _private_der(private_key: object) -> str:
    encoded = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return base64.b64encode(encoded).decode("ascii")


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(DOMAIN + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


def _valid_materials(
    *, client_algorithm: str = "ed25519", issuer_algorithm: str = "ecdsa_p256_sha256"
) -> dict:
    issuer_public = (
        ed25519.Ed25519PrivateKey.generate().public_key()
        if issuer_algorithm == "ed25519"
        else ec.generate_private_key(ec.SECP256R1()).public_key()
    )
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
            "algorithm": issuer_algorithm,
            "public_key_der_b64": _der(issuer_public),
            "public_key_digest": _spki_digest(issuer_public, ISSUER_SPKI_DOMAIN),
        },
        "client": {
            "key_ref": "client-key:opaque0001",
            "algorithm": client_algorithm,
            "public_key_der_b64": _der(client_public),
            "public_key_digest": _spki_digest(client_public, CLIENT_SPKI_DOMAIN),
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
    errors = []
    for error in _validator().iter_errors(document):
        if error.validator == "format" and str(error.validator_value).startswith("canonical-"):
            errors.append("invalid public-key encoding")
        else:
            errors.append(error)
    return errors


def test_schema_is_packaged_and_validates_ed25519_and_p256_clients() -> None:
    assert SCHEMA_PATH.is_file()
    assert _errors(_valid_materials(client_algorithm="ed25519")) == []
    assert _errors(_valid_materials(client_algorithm="ecdsa_p256_sha256")) == []


@pytest.mark.parametrize("issuer_algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_schema_validates_both_supported_issuer_algorithms(issuer_algorithm: str) -> None:
    assert _errors(_valid_materials(issuer_algorithm=issuer_algorithm)) == []


def test_zero_claim_materials_can_omit_client_projection() -> None:
    document = _valid_materials()
    document.pop("client")
    document["materials_digest"] = _digest(
        {key: value for key, value in document.items() if key != "materials_digest"}
    )
    assert _errors(document) == []


def test_spki_digest_descriptions_match_verifier_role_domains() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    role_definitions = {
        "issuer": "IssuerVerificationKeyV0",
        "client": "PublicKeyProjectionV0",
    }

    for role, definition_name in role_definitions.items():
        description = schema["definitions"][definition_name]["properties"][
            "public_key_digest"
        ]["description"]
        domain = getattr(verifier_impl, f"_{role.upper()}_SPKI_DOMAIN").decode("ascii")
        assert f"Role-separated {role} SPKI digest" in description
        assert domain in description


@pytest.mark.parametrize("location", ["issuer", "client"])
@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_fresh_pkcs8_private_der_is_rejected_without_echoing_key_bytes(
    location: str, algorithm: str
) -> None:
    document = _valid_materials()
    private_key = (
        ed25519.Ed25519PrivateKey.generate()
        if algorithm == "ed25519"
        else ec.generate_private_key(ec.SECP256R1())
    )
    encoded = _private_der(private_key)
    document[location]["algorithm"] = algorithm
    document[location]["public_key_der_b64"] = encoded
    errors = _errors(document)
    assert errors
    assert encoded not in str(errors)


def test_long_rsa_pkcs8_private_der_is_redacted_from_all_validator_errors() -> None:
    document = _valid_materials()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    encoded = _private_der(private_key)
    document["issuer"]["public_key_der_b64"] = encoded
    errors = SchemaValidator(contract="backend").validate_json(
        document, "certificate_verification_materials_v0_schema"
    )
    assert errors
    assert encoded not in str(errors)
    assert any("invalid public-key encoding" in error for error in errors)


def test_public_spki_must_match_declared_algorithm() -> None:
    document = _valid_materials(client_algorithm="ed25519")
    document["client"]["algorithm"] = "ecdsa_p256_sha256"
    assert _errors(document)


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
        lambda d: d["issuer"].update(algorithm="rsa4096"),
        lambda d: d["issuer"].update(public_key_der_b64="not-base64"),
        lambda d: d["issuer"].update(public_key_der_b64="A" * 61),
        lambda d: d["client"].update(algorithm="rsa"),
        lambda d: d["relying_party_policy"]["verifier_bindings"][0].update(verifier_id="D2"),
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
