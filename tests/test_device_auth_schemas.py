"""Contract tests for the self-service device authorization flow."""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schemas_dir


DEVICE_AUTH_REQUEST = "device_authorization_request_schema"
DEVICE_AUTH_RESPONSE = "device_authorization_response_schema"
DEVICE_DECISION_REQUEST = "device_decision_request_schema"
DEVICE_DECISION_RESPONSE = "device_decision_response_schema"
DEVICE_DECISION_SUCCESS = "device_decision_success_schema"
DEVICE_TOKEN_REQUEST = "device_token_request_schema"
DEVICE_TOKEN_RESPONSE = "device_token_response_schema"
DEVICE_TOKEN_SUCCESS = "device_token_success_schema"
PROVISIONED_WORKSPACE = "provisioned_workspace_schema"
DEVICE_CODE = "Abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFG"
USER_CODE = "BCDF-GHJK"


def _device_authorization_response() -> dict:
    return {
        "success": True,
        "message": "Device authorization started",
        "data": {
            "device_code": DEVICE_CODE,
            "user_code": USER_CODE,
            "verification_uri": "https://app.traigent.ai/device",
            "verification_uri_complete": f"https://app.traigent.ai/device?user_code={USER_CODE}",
            "expires_in": 900,
            "interval": 5,
        },
    }


def _device_token_request() -> dict:
    return {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": DEVICE_CODE,
        "client_id": "traigent-python-cli",
    }


def _device_decision_request() -> dict:
    return {
        "user_code": USER_CODE,
        "decision": "approved",
    }


def _device_decision_success_payload() -> dict:
    return {
        "user_code": USER_CODE,
        "decision": "approved",
        "client": {
            "masked_client_id": "traigent-python-cli",
            "device_hint": "macOS CLI",
        },
        "project": {
            "id": "project_default_123",
            "name": "Default Project",
        },
        "subscription_tier": "free",
    }


def _device_decision_success_response() -> dict:
    return {
        "success": True,
        "message": "Device authorization approved",
        "data": _device_decision_success_payload(),
    }


def _device_decision_error(error: str, **overrides) -> dict:
    payload = {
        "success": False,
        "message": "Device authorization cannot be decided",
        "error": error,
    }
    payload.update(overrides)
    return payload


def _device_token_success_payload() -> dict:
    return {
        "api_key": "sk_abcdefghijklmnopqrstuvwxyz123456",
        "tenant_id": "tenant_personal_123",
        "project_id": "project_default_123",
        "user": {"id": "user_123", "email": "alice@example.com"},
        "subscription_tier": "free",
        "quota": {"trial_limit": 25, "api_call_limit": 1000},
    }


def _device_token_success_response() -> dict:
    return {
        "success": True,
        "message": "Device authorization approved",
        "data": _device_token_success_payload(),
    }


def _device_token_error(error: str, **overrides) -> dict:
    payload = {
        "success": False,
        "message": "Device authorization is still pending",
        "error": error,
    }
    payload.update(overrides)
    return payload


def test_device_flow_schemas_are_valid_draft7() -> None:
    for schema_name in (
        DEVICE_AUTH_REQUEST,
        DEVICE_AUTH_RESPONSE,
        DEVICE_DECISION_REQUEST,
        DEVICE_DECISION_RESPONSE,
        DEVICE_DECISION_SUCCESS,
        DEVICE_TOKEN_REQUEST,
        DEVICE_TOKEN_RESPONSE,
        DEVICE_TOKEN_SUCCESS,
        PROVISIONED_WORKSPACE,
    ):
        Draft7Validator.check_schema(load_schema(schema_name))


def test_device_authorization_request_accepts_public_cli_client() -> None:
    payload = {"client_id": "traigent-python-cli", "scope": "api:project"}

    assert SchemaValidator().validate_json(payload, DEVICE_AUTH_REQUEST) == []


def test_device_authorization_request_rejects_unknown_fields() -> None:
    payload = {"client_id": "traigent-python-cli", "unexpected_field": "never"}

    errors = SchemaValidator().validate_json(payload, DEVICE_AUTH_REQUEST)

    assert errors
    assert any("Additional properties" in error for error in errors)


def test_device_authorization_response_uses_rfc8628_fields_under_envelope() -> None:
    assert SchemaValidator().validate_json(
        _device_authorization_response(),
        DEVICE_AUTH_RESPONSE,
    ) == []


def test_device_authorization_response_requires_all_rfc8628_fields() -> None:
    payload = _device_authorization_response()
    del payload["data"]["verification_uri_complete"]

    assert SchemaValidator().validate_json(payload, DEVICE_AUTH_RESPONSE)


def test_device_authorization_response_rejects_lowercase_user_code() -> None:
    payload = _device_authorization_response()
    payload["data"]["user_code"] = "bcdf-ghjk"

    assert SchemaValidator().validate_json(payload, DEVICE_AUTH_RESPONSE)


def test_device_authorization_response_rejects_ambiguous_user_code_chars() -> None:
    payload = _device_authorization_response()
    payload["data"]["user_code"] = "BCDI-GHJK"

    assert SchemaValidator().validate_json(payload, DEVICE_AUTH_RESPONSE)


def test_device_authorization_response_rejects_unformatted_user_code() -> None:
    payload = _device_authorization_response()
    payload["data"]["user_code"] = "BCDFGHJK"

    assert SchemaValidator().validate_json(payload, DEVICE_AUTH_RESPONSE)


def test_device_authorization_response_rejects_weak_device_code_shape() -> None:
    validator = SchemaValidator()

    for device_code in ("short-code", "Abcdefghijklmnopqrstuvwxyz0123456789_.ABCDEFG"):
        payload = _device_authorization_response()
        payload["data"]["device_code"] = device_code
        assert validator.validate_json(payload, DEVICE_AUTH_RESPONSE)


def test_device_token_request_accepts_device_code_grant() -> None:
    assert SchemaValidator().validate_json(_device_token_request(), DEVICE_TOKEN_REQUEST) == []


def test_device_decision_request_accepts_portal_decision() -> None:
    assert SchemaValidator().validate_json(_device_decision_request(), DEVICE_DECISION_REQUEST) == []


def test_device_decision_request_rejects_bad_user_code_charset() -> None:
    validator = SchemaValidator()

    for user_code in ("bcdf-ghjk", "BCDI-GHJK", "BCDFGHJK"):
        payload = _device_decision_request()
        payload["user_code"] = user_code
        assert validator.validate_json(payload, DEVICE_DECISION_REQUEST)


def test_device_decision_request_rejects_invalid_decision_value() -> None:
    payload = _device_decision_request()
    payload["decision"] = "approve"

    assert SchemaValidator().validate_json(payload, DEVICE_DECISION_REQUEST)


def test_device_decision_request_rejects_unknown_fields() -> None:
    payload = _device_decision_request()
    payload["api_key"] = "sk_should_never_be_here"

    errors = SchemaValidator().validate_json(payload, DEVICE_DECISION_REQUEST)

    assert errors
    assert any("Additional properties" in error for error in errors)


def test_device_decision_success_response_confirms_safe_summary() -> None:
    assert SchemaValidator().validate_json(
        _device_decision_success_response(),
        DEVICE_DECISION_RESPONSE,
    ) == []


def test_device_decision_success_response_accepts_denied_decision() -> None:
    payload = _device_decision_success_response()
    payload["message"] = "Device authorization denied"
    payload["data"]["decision"] = "denied"

    assert SchemaValidator().validate_json(payload, DEVICE_DECISION_RESPONSE) == []


def test_device_decision_success_response_rejects_extra_data_fields() -> None:
    payload = _device_decision_success_response()
    payload["data"]["api_key"] = "sk_should_never_be_here"

    assert SchemaValidator().validate_json(payload, DEVICE_DECISION_RESPONSE)


def test_device_decision_success_schema_has_no_api_key_property() -> None:
    def property_names(schema: dict) -> set[str]:
        names: set[str] = set()
        if isinstance(schema.get("properties"), dict):
            names.update(schema["properties"])
            for subschema in schema["properties"].values():
                if isinstance(subschema, dict):
                    names.update(property_names(subschema))
        for keyword in ("oneOf", "anyOf", "allOf"):
            for subschema in schema.get(keyword, []):
                if isinstance(subschema, dict):
                    names.update(property_names(subschema))
        return names

    assert "api_key" not in property_names(load_schema(DEVICE_DECISION_REQUEST))
    assert "api_key" not in property_names(load_schema(DEVICE_DECISION_SUCCESS))
    assert "api_key" not in property_names(load_schema(DEVICE_DECISION_RESPONSE))


def test_device_decision_response_accepts_domain_errors() -> None:
    validator = SchemaValidator()

    for error in (
        "unknown_user_code",
        "expired_user_code",
        "already_decided_user_code",
    ):
        assert validator.validate_json(_device_decision_error(error), DEVICE_DECISION_RESPONSE) == []
        assert (
            validator.validate_json(
                _device_decision_error(error, error_code=error, details={"user_code": USER_CODE}),
                DEVICE_DECISION_RESPONSE,
            )
            == []
        )


def test_device_decision_response_rejects_unknown_domain_error() -> None:
    payload = _device_decision_error("authorization_pending")

    assert SchemaValidator().validate_json(payload, DEVICE_DECISION_RESPONSE)


def test_device_decision_response_rejects_mismatched_error_code() -> None:
    payload = _device_decision_error(
        "expired_user_code",
        error_code="already_decided_user_code",
    )

    assert SchemaValidator().validate_json(payload, DEVICE_DECISION_RESPONSE)


def test_device_token_request_rejects_wrong_grant() -> None:
    payload = _device_token_request()
    payload["grant_type"] = "authorization_code"

    assert SchemaValidator().validate_json(payload, DEVICE_TOKEN_REQUEST)


def test_device_token_request_rejects_weak_device_code_shape() -> None:
    validator = SchemaValidator()

    for device_code in ("short-code", "Abcdefghijklmnopqrstuvwxyz0123456789_.ABCDEFG"):
        payload = _device_token_request()
        payload["device_code"] = device_code
        assert validator.validate_json(payload, DEVICE_TOKEN_REQUEST)


def test_device_token_success_payload_accepts_project_scoped_key() -> None:
    assert SchemaValidator().validate_json(
        _device_token_success_payload(),
        DEVICE_TOKEN_SUCCESS,
    ) == []


def test_device_token_success_payload_rejects_non_sk_prefix() -> None:
    payload = _device_token_success_payload()
    payload["api_key"] = "pk_abcdefghijklmnopqrstuvwxyz123456"

    assert SchemaValidator().validate_json(payload, DEVICE_TOKEN_SUCCESS)


def test_device_token_success_response_accepts_project_scoped_payload() -> None:
    assert SchemaValidator().validate_json(
        _device_token_success_response(),
        DEVICE_TOKEN_RESPONSE,
    ) == []


def test_device_token_success_response_rejects_extra_user_fields() -> None:
    payload = _device_token_success_response()
    payload["data"]["user"]["role"] = "owner"

    assert SchemaValidator().validate_json(payload, DEVICE_TOKEN_RESPONSE)


def test_device_token_response_accepts_rfc8628_poll_errors() -> None:
    validator = SchemaValidator()

    for error in ("authorization_pending", "access_denied", "expired_token"):
        assert validator.validate_json(_device_token_error(error), DEVICE_TOKEN_RESPONSE) == []
        assert (
            validator.validate_json(
                _device_token_error(error, error_code=error),
                DEVICE_TOKEN_RESPONSE,
            )
            == []
        )

    slow_down = _device_token_error(
        "slow_down",
        message="Polling too quickly",
        error_code="slow_down",
        details={"interval": 10, "retry_after": 10},
    )
    assert validator.validate_json(slow_down, DEVICE_TOKEN_RESPONSE) == []


def test_device_token_response_rejects_unknown_poll_error() -> None:
    payload = _device_token_error("invalid_grant")

    assert SchemaValidator().validate_json(payload, DEVICE_TOKEN_RESPONSE)


def test_device_token_response_rejects_mismatched_error_code() -> None:
    validator = SchemaValidator()
    mismatches = {
        "authorization_pending": "expired_token",
        "slow_down": "expired_token",
        "access_denied": "authorization_pending",
        "expired_token": "slow_down",
    }

    for error, error_code in mismatches.items():
        payload = _device_token_error(error, error_code=error_code)
        if error == "slow_down":
            payload["details"] = {"interval": 10}
        assert validator.validate_json(payload, DEVICE_TOKEN_RESPONSE)


def test_device_token_response_requires_interval_for_slow_down() -> None:
    payload = _device_token_error("slow_down", details={"retry_after": 10})

    assert SchemaValidator().validate_json(payload, DEVICE_TOKEN_RESPONSE)


def test_device_token_response_rejects_slow_down_interval_below_rfc_minimum() -> None:
    validator = SchemaValidator()

    for interval in (5, 0):
        payload = _device_token_error(
            "slow_down",
            error_code="slow_down",
            details={"interval": interval},
        )
        assert validator.validate_json(payload, DEVICE_TOKEN_RESPONSE)


def test_provisioned_workspace_accepts_default_project_shape() -> None:
    payload = {
        "tenant_id": "tenant_personal_123",
        "team_id": "team_personal_123",
        "default_project_id": "project_default_123",
    }

    assert SchemaValidator().validate_json(payload, PROVISIONED_WORKSPACE) == []


def test_provisioned_workspace_requires_default_project_id() -> None:
    payload = {
        "tenant_id": "tenant_personal_123",
        "team_id": "team_personal_123",
    }

    assert SchemaValidator().validate_json(payload, PROVISIONED_WORKSPACE)


def test_device_flow_schemas_are_registered_by_runtime_discovery() -> None:
    available = set(SchemaValidator().available_schemas)

    assert {
        DEVICE_AUTH_REQUEST,
        DEVICE_AUTH_RESPONSE,
        DEVICE_DECISION_REQUEST,
        DEVICE_DECISION_RESPONSE,
        DEVICE_DECISION_SUCCESS,
        DEVICE_TOKEN_REQUEST,
        DEVICE_TOKEN_RESPONSE,
        DEVICE_TOKEN_SUCCESS,
        PROVISIONED_WORKSPACE,
    } <= available


def test_backend_contract_validates_device_flow_requests() -> None:
    validator = SchemaValidator()

    assert validator.validate_request(
        "/api/v1/auth/device/authorize",
        "POST",
        {"client_id": "traigent-python-cli"},
    ) == []
    assert validator.validate_request(
        "/api/v1/auth/device/token",
        "POST",
        _device_token_request(),
    ) == []
    assert validator.validate_request(
        "/api/v1/auth/device/decision",
        "POST",
        _device_decision_request(),
    ) == []

    invalid = _device_token_request()
    invalid["grant_type"] = "authorization_code"
    assert validator.validate_request("/api/v1/auth/device/token", "POST", invalid)

    invalid_decision = _device_decision_request()
    invalid_decision["decision"] = "approve"
    assert validator.validate_request(
        "/api/v1/auth/device/decision",
        "POST",
        invalid_decision,
    )


def test_auth_device_flow_endpoints_are_wired() -> None:
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "mep_endpoints.json", encoding="utf-8") as fh:
        root = json.load(fh)
    assert any(
        module.get("paths_file") == "./auth/auth_endpoints.json"
        for module in root["x-endpoint-modules"]
    )

    with open(schemas_dir / "auth" / "auth_endpoints.json", encoding="utf-8") as fh:
        endpoints = json.load(fh)

    authorize = endpoints["paths"]["/api/v1/auth/device/authorize"]["post"]
    assert authorize["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_authorization_request_schema.json"
    )
    assert authorize["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_authorization_response_schema.json"
    )

    decision = endpoints["paths"]["/api/v1/auth/device/decision"]["post"]
    assert decision["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_decision_request_schema.json"
    )
    assert decision["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_decision_response_schema.json"
    )
    assert decision["responses"]["401"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "error_envelope_schema.json"
    )
    assert decision["responses"]["403"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "error_envelope_schema.json"
    )
    assert decision["responses"]["404"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_decision_response_schema.json"
    )
    assert decision["responses"]["409"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_decision_response_schema.json"
    )
    assert decision["responses"]["410"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_decision_response_schema.json"
    )
    assert decision["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "rate_limit_info_schema.json"
    )
    assert "Retry-After" in decision["responses"]["429"]["headers"]

    token = endpoints["paths"]["/api/v1/auth/device/token"]["post"]
    assert token["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_token_request_schema.json"
    )
    assert token["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_token_response_schema.json"
    )
    assert token["responses"]["400"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_token_response_schema.json"
    )
    assert token["responses"]["403"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_token_response_schema.json"
    )
    assert token["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "device_token_response_schema.json"
    )
    assert "Retry-After" in token["responses"]["429"]["headers"]
