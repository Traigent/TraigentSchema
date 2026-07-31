"""Backward-compatibility checks for newly documented register credentials."""

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import load_schema

REGISTER_PATH = "/api/v1/auth/register"
BASE_REQUEST = {
    "email": "user@example.test",
    "password": "Strong-password-123!",
}


@pytest.fixture(scope="module")
def validator() -> SchemaValidator:
    return SchemaValidator(contract="backend")


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("invite_token", 123),
        ("invite_token", "i" * 513),
        ("registration_code", 123),
        ("registration_code", "r" * 65),
    ),
)
def test_documented_credentials_preserve_former_unknown_key_acceptance(
    validator: SchemaValidator,
    field: str,
    value: object,
) -> None:
    """5.4 must not reject values accepted as unknown properties by 5.3."""
    payload = {**BASE_REQUEST, field: value}

    assert validator.validate_request(REGISTER_PATH, "POST", payload) == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("invite_token", "invite-token"),
        ("registration_code", "AC7F3B21C9"),
        ("registration_code", "ABCD-EFGH-JKLM-NPQR"),
    ),
)
def test_documented_credentials_accept_normal_wire_values(
    validator: SchemaValidator,
    field: str,
    value: str,
) -> None:
    payload = {**BASE_REQUEST, field: value}

    assert validator.validate_request(REGISTER_PATH, "POST", payload) == []


def test_new_credential_properties_are_annotations_only() -> None:
    """Validating keywords on formerly unknown keys require a major release."""
    schema = load_schema("register_request_schema")

    for field in ("invite_token", "registration_code"):
        property_schema = schema["properties"][field]
        assert set(property_schema) == {"description", "x-traigent-note"}
        assert property_schema["description"]
        assert property_schema["x-traigent-note"]
