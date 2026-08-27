# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Wire-contract tests for the backend Agent Certificate v0 routes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
CATALOG = SCHEMAS / "certification" / "certification_endpoints_v0.json"
MEP = SCHEMAS / "mep_endpoints.json"
BUILD_REF = "bsn:" + "A" * 43
DIGEST = "sha256:" + "a" * 64
OPAQUE_REF = "clientkey:contract001"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _request_schema(catalog: dict, path: str, method: str) -> dict:
    return catalog["paths"][path][method.lower()]["requestBody"]["content"]["application/json"][
        "schema"
    ]


def test_certificate_catalog_is_wired_as_a_canonical_backend_module() -> None:
    catalog = _load(CATALOG)
    mep = _load(MEP)

    assert catalog["x-traigent-contract"] == {
        "name": "certificate_v0",
        "status": "canonical",
        "description": catalog["x-traigent-contract"]["description"],
    }
    assert catalog["x-asserted-against-backend"] is True
    assert any(
        module.get("paths_file") == "./certification/certification_endpoints_v0.json"
        for module in mep["x-endpoint-modules"]
    )


def test_catalog_matches_the_nine_backend_certificate_operations() -> None:
    catalog = _load(CATALOG)
    expected = {
        ("POST", "/api/v1beta/certificate-build-sessions"),
        ("POST", "/api/v1beta/certificate-build-sessions/bind-g1"),
        ("POST", "/api/v1beta/certificate-build-sessions/prepare"),
        ("POST", "/api/v1beta/certificate-build-sessions/finalize"),
        ("POST", "/api/v1beta/certificate-client-keys"),
        ("POST", "/api/v1beta/certificate-client-keys/revoke"),
        ("DELETE", "/api/v1beta/certificate-client-keys"),
        ("GET", "/api/v1beta/certificates/{certificate_ref}"),
        ("GET", "/api/v1beta/certificates/{certificate_ref}/verification-materials"),
    }
    actual = {
        (method.upper(), path)
        for path, operations in catalog["paths"].items()
        for method in operations
        if method in {"post", "delete", "get"}
    }
    assert actual == expected


@pytest.mark.parametrize(
    ("path", "method", "valid", "invalid"),
    [
        (
            "/api/v1beta/certificate-build-sessions",
            "POST",
            {"nonce": "a" * 64},
            {"nonce": "a" * 64, "build_session_ref": BUILD_REF},
        ),
        (
            "/api/v1beta/certificate-build-sessions/bind-g1",
            "POST",
            {
                "build_session_ref": BUILD_REF,
                "manifest_root_digest": DIGEST,
                "commitment_scheme": "sha256_secret_blinded_v1",
                "client_attestor_version": "1.0.0",
                "client_key_ref": OPAQUE_REF,
                "client_signature_algorithm": "ed25519",
                "declared_mode": "offline",
                "sdk_ref": "a" * 40,
                "sdk_version": "1.0.0",
            },
            {
                "build_session_ref": BUILD_REF,
                "manifest_root_digest": DIGEST,
                "commitment_scheme": "sha256_secret_blinded_v1",
                "client_attestor_version": "1.0.0",
                "client_key_ref": OPAQUE_REF,
                "client_signature_algorithm": "ed25519",
                "declared_mode": "offline",
                "sdk_ref": "a" * 39,
                "sdk_version": "1.0.0",
            },
        ),
        (
            "/api/v1beta/certificate-build-sessions/prepare",
            "POST",
            {"build_session_ref": BUILD_REF, "nonce": "a" * 64},
            {"build_session_ref": "bad", "nonce": "a" * 64},
        ),
        (
            "/api/v1beta/certificate-build-sessions/finalize",
            "POST",
            {"build_session_ref": BUILD_REF, "nonce": "a" * 64},
            {"build_session_ref": BUILD_REF, "nonce": "a" * 64, "unexpected": 1},
        ),
        (
            "/api/v1beta/certificate-client-keys",
            "POST",
            {
                "client_key_ref": OPAQUE_REF,
                "algorithm": "ed25519",
                "public_key_der_b64": "A" * 44,
            },
            {
                "client_key_ref": OPAQUE_REF,
                "algorithm": "ed25519",
                "public_key_der_b64": "A" * 44,
                "private_key": "must not cross",
            },
        ),
        (
            "/api/v1beta/certificate-client-keys/revoke",
            "POST",
            {"client_key_ref": OPAQUE_REF, "algorithm": "ed25519"},
            {"client_key_ref": OPAQUE_REF, "algorithm": "rsa4096"},
        ),
        (
            "/api/v1beta/certificate-client-keys",
            "DELETE",
            {"client_key_ref": OPAQUE_REF, "algorithm": "ed25519"},
            {"client_key_ref": OPAQUE_REF},
        ),
    ],
)
def test_request_shapes_are_registered_and_fail_closed(
    path: str, method: str, valid: dict, invalid: dict
) -> None:
    validator = SchemaValidator(contract="backend")
    assert validator.validate_request(path, method, valid) == []
    assert validator.validate_request(path, method, invalid)


def test_finalize_co_attestation_is_the_existing_content_free_signature_shape() -> None:
    catalog = _load(CATALOG)
    schema = _request_schema(catalog, "/api/v1beta/certificate-build-sessions/finalize", "POST")
    co_attestation = schema["properties"]["co_attestation"]["anyOf"]
    assert {item["$ref"] for item in co_attestation if "$ref" in item} == {
        "./certificate_signatures_v0_schema.json#/definitions/CoAttestationV0"
    }
    assert "private_key" not in json.dumps(catalog).lower()


def test_success_responses_bind_to_typed_content_free_projections() -> None:
    catalog = _load(CATALOG)
    paths = catalog["paths"]

    assert (
        paths["/api/v1beta/certificates/{certificate_ref}"]["get"]["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        == "#/components/schemas/CertificateRetrievalResponseV0"
    )
    assert (
        paths["/api/v1beta/certificates/{certificate_ref}/verification-materials"]["get"][
            "responses"
        ]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "./certificate_verification_materials_v0_schema.json"
    )
    retrieval = catalog["components"]["schemas"]["CertificateRetrievalResponseV0"]
    assert retrieval["additionalProperties"] is False
    assert retrieval["properties"]["signed_certificate"]["$ref"] == (
        "./agent_certificate_v0_schema.json"
    )
