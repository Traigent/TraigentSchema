# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Wire-contract tests for the backend Agent Certificate v0 routes."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from jsonschema import Draft7Validator
from referencing.jsonschema import DRAFT7

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
CATALOG = SCHEMAS / "certification" / "certification_endpoints_v0.json"
MEP = SCHEMAS / "mep_endpoints.json"
BUILD_REF = "bsn:" + "A" * 43
DIGEST = "sha256:" + "a" * 64
ZERO_DIGEST = "sha256:" + "0" * 64
OPAQUE_REF = "ckr:" + "A" * 43
PUBLIC_KEY_DER_B64 = base64.b64encode(
    ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    .public_key()
    .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
).decode("ascii")

CERTIFICATE_ERROR_SCHEMA = SCHEMAS / "certification" / "certificate_error_v0_schema.json"
ERROR_CODE_BY_STATUS = {
    "400": "invalid_request",
    "401": "authentication_required",
    "403": "authorization_denied",
    "404": "not_found",
    "409": "state_conflict",
    "413": "request_too_large",
    "500": "internal_error",
    "503": "service_unavailable",
}
ERROR_DEFINITION_BY_STATUS = {
    "400": "InvalidRequestV0",
    "401": "AuthenticationRequiredV0",
    "403": "AuthorizationDeniedV0",
    "404": "NotFoundV0",
    "409": "StateConflictV0",
    "413": "RequestTooLargeV0",
    "500": "InternalErrorV0",
    "503": "ServiceUnavailableV0",
}
ERROR_COMPONENT_BY_STATUS = {
    "400": "BadRequest",
    "401": "Unauthorized",
    "403": "Forbidden",
    "404": "NotFound",
    "409": "Conflict",
    "413": "RequestTooLarge",
    "500": "InternalError",
    "503": "ServiceUnavailable",
}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _private_der_b64(algorithm: str) -> str:
    key = (
        ed25519.Ed25519PrivateKey.generate()
        if algorithm == "ed25519"
        else ec.generate_private_key(ec.SECP256R1())
    )
    return base64.b64encode(
        key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    ).decode("ascii")


def _request_schema(catalog: dict, path: str, method: str) -> dict:
    return catalog["paths"][path][method.lower()]["requestBody"]["content"]["application/json"][
        "schema"
    ]


def _g1_response_validator() -> Draft7Validator:
    catalog = _load(CATALOG)
    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://schemas.traigent.ai/certification/_g1_response_test.json",
        "components": copy.deepcopy(catalog["components"]),
        "$ref": "#/components/schemas/G1BindingResponseV0",
    }

    def absolutize_refs(value: object) -> None:
        if isinstance(value, dict):
            reference = value.get("$ref")
            if isinstance(reference, str) and reference.startswith("./"):
                value["$ref"] = "https://schemas.traigent.ai/certification/" + reference[2:]
            for nested in value.values():
                absolutize_refs(nested)
        elif isinstance(value, list):
            for nested in value:
                absolutize_refs(nested)

    absolutize_refs(schema["components"]["schemas"]["G1BindingResponseV0"])
    return Draft7Validator(schema, registry=SchemaValidator(contract="backend")._registry)


def _valid_g1_response() -> dict:
    return {
        "binding_id": "binding_contract001",
        "tenant_id": "tenant_contract001",
        "project_id": "project_contract001",
        "build_session_ref": BUILD_REF,
        "session_commitment_digest": DIGEST,
        "manifest_root_digest": DIGEST,
        "seal_ref": "seal:contract001",
        "seal_statement_digest": DIGEST,
        "has_g1_binding": True,
    }


def test_certificate_catalog_is_wired_as_a_canonical_backend_module() -> None:
    catalog = _load(CATALOG)
    mep = _load(MEP)

    assert catalog["x-traigent-contract"] == {
        "name": "certificate_v0",
        "status": "canonical",
        "description": catalog["x-traigent-contract"]["description"],
    }
    assert catalog["x-asserted-against-backend"] is False
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
            "/api/v1beta/certificate-build-sessions/finalize",
            "POST",
            {
                "build_session_ref": BUILD_REF,
                "nonce": "a" * 64,
                "co_attestation": {
                    "algorithm": "ed25519",
                    "client_key_ref": OPAQUE_REF,
                    "signed_manifest_digest": DIGEST,
                    "nonce": "a" * 64,
                    "signature": "A" * 86 + "==",
                },
            },
            {"build_session_ref": BUILD_REF, "nonce": "a" * 64, "unexpected": 1},
        ),
        (
            "/api/v1beta/certificate-client-keys",
            "POST",
            {
                "algorithm": "ed25519",
                "public_key_der_b64": PUBLIC_KEY_DER_B64,
            },
            {
                "algorithm": "ed25519",
                "public_key_der_b64": PUBLIC_KEY_DER_B64,
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


def test_g1_prepare_and_b1_or_g1_finalize_are_distinct_protocol_branches() -> None:
    catalog = _load(CATALOG)
    signatures_catalog = _load(SCHEMAS / "certification" / "certificate_signatures_v0_schema.json")
    prepare_operation = catalog["paths"]["/api/v1beta/certificate-build-sessions/prepare"][
        "post"
    ]
    finalize_operation = catalog["paths"]["/api/v1beta/certificate-build-sessions/finalize"][
        "post"
    ]
    finalize_schema = _request_schema(
        catalog, "/api/v1beta/certificate-build-sessions/finalize", "POST"
    )
    assert finalize_schema["required"] == ["build_session_ref", "nonce"]
    assert finalize_schema["properties"]["co_attestation"]["$ref"] == (
        "./certificate_signatures_v0_schema.json#/definitions/CoAttestationV0"
    )
    assert "co_attestation" not in finalize_schema["required"]
    prepare_response = catalog["components"]["schemas"]["PrepareResponseV0"]
    assert prepare_response["required"] == [
        "schema_version",
        "certificate_title",
        "build_session_scope_line",
        "certificate_scope_line",
        "subject",
        "semantics",
        "disclosure_profile",
        "ledger_seal_projection",
        "claims",
        "non_claims",
        "signatures",
        "audit_report",
    ]
    prepare_signatures = prepare_response["properties"]["signatures"]
    assert prepare_signatures["allOf"] == [
        {
            "$ref": (
                "./certificate_signatures_v0_schema.json"
                "#/definitions/CertificateSignaturesV0"
            )
        },
        {"not": {"required": ["co_attestation"]}},
    ]
    base_signatures = signatures_catalog["definitions"]["CertificateSignaturesV0"]
    assert "co_attestation" in base_signatures["properties"]
    assert "co_attestation" not in base_signatures["required"]
    assert prepare_response["properties"]["ledger_seal_projection"]["$ref"] == (
        "./certificate_ledger_seals_v0_schema.json#/definitions/SealStatementV0"
    )
    assert prepare_response["allOf"][0]["properties"]["claims"]["contains"] == {
        "properties": {
            "claim_id": {"const": "G1"},
            "tier": {"const": 1},
        },
        "required": ["claim_id", "tier"],
    }
    assert "always declares G1 at tier 1" in prepare_response["description"]
    assert "B1-only final certificates are not prepare responses" in prepare_response["description"]
    assert prepare_operation["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/PrepareResponseV0"
    }
    finalize_description = finalize_operation["responses"]["201"]["description"]
    assert "B1-only issuance is an issuer-internal finalize path" in finalize_description
    assert "does not produce or consume a public PrepareResponseV0" in finalize_description
    assert "prepared projection contains G1" in finalize_description
    assert finalize_operation["responses"]["201"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ArtifactProjectionV0"
    }

    prepare_response_uses = []
    for path, operations in catalog["paths"].items():
        for method, operation in operations.items():
            if method not in {"get", "post", "delete"}:
                continue
            for status, response in operation.get("responses", {}).items():
                schema = response.get("content", {}).get("application/json", {}).get("schema", {})
                if schema.get("$ref") == "#/components/schemas/PrepareResponseV0":
                    prepare_response_uses.append((path, method, status))
    assert prepare_response_uses == [
        ("/api/v1beta/certificate-build-sessions/prepare", "post", "200")
    ]
    assert "private_key" not in json.dumps(catalog).lower()


def test_bind_g1_request_rejects_zero_manifest_root_digest() -> None:
    request = {
        "build_session_ref": BUILD_REF,
        "manifest_root_digest": ZERO_DIGEST,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "client_attestor_version": "1.0.0",
        "client_key_ref": OPAQUE_REF,
        "client_signature_algorithm": "ed25519",
        "declared_mode": "offline",
        "sdk_ref": "a" * 40,
        "sdk_version": "1.0.0",
    }
    assert SchemaValidator(contract="backend").validate_request(
        "/api/v1beta/certificate-build-sessions/bind-g1", "POST", request
    )


@pytest.mark.parametrize("algorithm", ["ed25519", "ecdsa_p256_sha256"])
def test_client_key_request_rejects_fresh_pkcs8_private_der_without_echoing_key_bytes(
    algorithm: str,
) -> None:
    encoded = _private_der_b64(algorithm)
    request = {
        "algorithm": algorithm,
        "public_key_der_b64": encoded,
    }
    errors = SchemaValidator(contract="backend").validate_request(
        "/api/v1beta/certificate-client-keys", "POST", request
    )
    assert errors
    assert encoded not in str(errors)


def test_client_key_request_requires_declared_algorithm_to_match_public_spki() -> None:
    request = {
        "client_key_ref": OPAQUE_REF,
        "algorithm": "ecdsa_p256_sha256",
        "public_key_der_b64": PUBLIC_KEY_DER_B64,
    }
    assert SchemaValidator(contract="backend").validate_request(
        "/api/v1beta/certificate-client-keys", "POST", request
    )


def test_g1_binding_response_rejects_zero_manifest_root_digest() -> None:
    validator = _g1_response_validator()
    assert not list(validator.iter_errors(_valid_g1_response()))
    response = _valid_g1_response()
    response["manifest_root_digest"] = ZERO_DIGEST
    assert list(validator.iter_errors(response))


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


def test_certificate_error_schema_is_the_closed_content_free_route_boundary() -> None:
    schema = _load(CERTIFICATE_ERROR_SCHEMA)

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["success", "message", "error", "error_code"]
    assert set(schema["properties"]) == {"success", "message", "error", "error_code"}
    assert schema["properties"]["success"]["const"] is False
    assert len(schema["oneOf"]) == 8
    assert set(schema["definitions"]) == {
        "InvalidRequestV0",
        "AuthenticationRequiredV0",
        "AuthorizationDeniedV0",
        "NotFoundV0",
        "StateConflictV0",
        "RequestTooLargeV0",
        "InternalErrorV0",
        "ServiceUnavailableV0",
    }


def _definition_body(schema: dict, definition_name: str) -> dict[str, object]:
    definition = schema["definitions"][definition_name]
    return {
        name: property_schema["const"] for name, property_schema in definition["properties"].items()
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("message", "customer response sentinel"),
        ("error", "agent/evaluator code sentinel"),
        ("details", {"dataset_example": "sentinel"}),
        ("nested", {"message": "nested sentinel"}),
    ],
)
def test_certificate_error_rejects_content_sentinels_and_unknown_fields(
    field: str, value: object
) -> None:
    validator = Draft7Validator(_load(CERTIFICATE_ERROR_SCHEMA))
    body = _definition_body(_load(CERTIFICATE_ERROR_SCHEMA), "InvalidRequestV0")
    body[field] = value

    assert list(validator.iter_errors(body)), field


def test_certificate_error_accepts_only_minimal_closed_codes() -> None:
    schema = _load(CERTIFICATE_ERROR_SCHEMA)
    validator = Draft7Validator(schema)
    for definition_name in ERROR_DEFINITION_BY_STATUS.values():
        body = _definition_body(schema, definition_name)
        assert not list(validator.iter_errors(body)), definition_name


def test_certificate_error_rejects_wrong_status_code_pin() -> None:
    schema = _load(CERTIFICATE_ERROR_SCHEMA)
    root_validator = Draft7Validator(schema)
    for expected_status, expected_definition in ERROR_DEFINITION_BY_STATUS.items():
        expected_validator = Draft7Validator(schema["definitions"][expected_definition])
        for actual_status, actual_definition in ERROR_DEFINITION_BY_STATUS.items():
            body = _definition_body(schema, actual_definition)
            if expected_status != actual_status:
                assert list(expected_validator.iter_errors(body)), (
                    expected_status,
                    actual_status,
                )
                mismatched = dict(body)
                mismatched["error_code"] = _definition_body(schema, expected_definition)[
                    "error_code"
                ]
                assert list(root_validator.iter_errors(mismatched)), (
                    expected_status,
                    actual_status,
                )


def test_certificate_error_response_refs_resolve_through_schema_registry() -> None:
    catalog = _load(CATALOG)
    registry = SchemaValidator(contract="backend")._registry
    assert registry is not None
    endpoint_uri = "https://schemas.traigent.ai/certification/certification_endpoints_v0.json"

    for status, component_name in ERROR_COMPONENT_BY_STATUS.items():
        response_schema = catalog["components"]["responses"][component_name]["content"][
            "application/json"
        ]["schema"]
        rooted_response_schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "$id": endpoint_uri,
            "allOf": [response_schema],
        }
        endpoint_resource = DRAFT7.create_resource(rooted_response_schema)
        validator = Draft7Validator(
            {"$ref": endpoint_uri},
            registry=registry.with_resource(endpoint_uri, endpoint_resource),
        )
        body = _definition_body(_load(CERTIFICATE_ERROR_SCHEMA), ERROR_DEFINITION_BY_STATUS[status])
        assert not list(validator.iter_errors(body)), (status, validator)
        wrong_status = next(
            candidate for candidate in ERROR_DEFINITION_BY_STATUS if candidate != status
        )
        wrong_body = _definition_body(
            _load(CERTIFICATE_ERROR_SCHEMA), ERROR_DEFINITION_BY_STATUS[wrong_status]
        )
        assert list(validator.iter_errors(wrong_body)), (status, wrong_status)


def _assert_certificate_error_response_refs(catalog: dict) -> None:
    for _path, methods in catalog["paths"].items():
        for method, operation in methods.items():
            if method not in {"post", "delete", "get"}:
                continue
            non_2xx_statuses = {
                status
                for status in operation["responses"]
                if not (
                    isinstance(status, str)
                    and len(status) == 3
                    and status.isdigit()
                    and status[0] == "2"
                )
            }
            assert non_2xx_statuses <= set(ERROR_COMPONENT_BY_STATUS)
            for status in non_2xx_statuses:
                response = operation["responses"][status]
                assert "$ref" in response
                assert response["$ref"] == (
                    f"#/components/responses/{ERROR_COMPONENT_BY_STATUS[status]}"
                )

    for status, component_name in ERROR_COMPONENT_BY_STATUS.items():
        schema = catalog["components"]["responses"][component_name]["content"]["application/json"][
            "schema"
        ]
        assert schema["$ref"].startswith("./certificate_error_v0_schema.json#/definitions/")
        definition_name = schema["$ref"].rsplit("/", 1)[1]
        error_schema = _load(CERTIFICATE_ERROR_SCHEMA)
        assert definition_name == ERROR_DEFINITION_BY_STATUS[status]
        assert (
            error_schema["definitions"][definition_name]["properties"]["error_code"]["const"]
            == ERROR_CODE_BY_STATUS[status]
        )


def test_certificate_error_response_components_pin_every_declared_http_status() -> None:
    _assert_certificate_error_response_refs(_load(CATALOG))


@pytest.mark.parametrize("status", ["422", "default"])
def test_certificate_error_privacy_gate_rejects_unmapped_response_status(status: str) -> None:
    catalog = copy.deepcopy(_load(CATALOG))
    catalog["paths"]["/api/v1beta/certificate-build-sessions"]["post"]["responses"][status] = {
        "description": "generic error",
        "content": {"application/json": {"schema": {"$ref": "../error_envelope_schema.json"}}},
    }

    with pytest.raises(AssertionError):
        _assert_certificate_error_response_refs(catalog)


def test_certificate_error_privacy_gate_rejects_inlined_mapped_response() -> None:
    catalog = copy.deepcopy(_load(CATALOG))
    catalog["paths"]["/api/v1beta/certificate-build-sessions"]["post"]["responses"]["400"] = {
        "description": "generic error",
        "content": {"application/json": {"schema": {"type": "object"}}},
    }

    with pytest.raises(AssertionError):
        _assert_certificate_error_response_refs(catalog)
