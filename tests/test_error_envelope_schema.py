"""Contract tests for the canonical error envelope (TraigentSchema#59).

ErrorEnvelopeDTO codifies Shape A ({success, message, error, error_code?, details?})
decided in BE#669; ValidationErrorDTO specializes it for 422 with a
{field: [reason, ...]} details map (BE#671).
"""

from traigent_schema import SchemaValidator


def test_error_envelope_accepts_shape_a():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": False,
            "message": "Agent not found.",
            "error": "agent_not_found",
        },
        "error_envelope_schema",
    )
    assert errors == []


def test_error_envelope_accepts_optional_code_and_details():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": False,
            "message": "Subscription quota exceeded.",
            "error": "quota_exceeded",
            "error_code": "quota_exceeded",
            "details": {"resource_type": "agents", "limit": 1},
        },
        "error_envelope_schema",
    )
    assert errors == []


def test_error_envelope_requires_core_fields():
    validator = SchemaValidator()
    for missing in ("success", "message", "error"):
        payload = {"success": False, "message": "x", "error": "y"}
        del payload[missing]
        errors = validator.validate_json(payload, "error_envelope_schema")
        assert errors, f"missing {missing} should be rejected"


def test_error_envelope_rejects_success_true():
    """success is the discriminator; an error body must set it false."""
    validator = SchemaValidator()
    errors = validator.validate_json(
        {"success": True, "message": "x", "error": "y"},
        "error_envelope_schema",
    )
    assert errors


def test_error_envelope_rejects_leaky_top_level_fields():
    """additionalProperties:false stops raw internals / user-input echo at the contract."""
    validator = SchemaValidator()
    for leaky in ("stack_trace", "sql", "user_id", "email"):
        payload = {
            "success": False,
            "message": "denied",
            "error": "access_denied",
            leaky: "secret-or-pii",
        }
        errors = validator.validate_json(payload, "error_envelope_schema")
        assert errors, f"{leaky} should be rejected as an additional property"


def test_validation_error_accepts_field_reason_map():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": False,
            "message": "Validation failed.",
            "error": "validation_error",
            "details": {"email": ["is required"], "age": ["must be >= 0"]},
        },
        "validation_error_schema",
    )
    assert errors == []


def test_validation_error_requires_details():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {"success": False, "message": "Validation failed.", "error": "validation_error"},
        "validation_error_schema",
    )
    assert errors


def test_validation_error_rejects_non_list_reasons():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": False,
            "message": "Validation failed.",
            "error": "validation_error",
            "details": {"email": "is required"},
        },
        "validation_error_schema",
    )
    assert errors


def test_validation_error_still_enforces_envelope_leak_guard():
    """The composed envelope's additionalProperties:false must still apply."""
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": False,
            "message": "Validation failed.",
            "error": "validation_error",
            "details": {"email": ["is required"]},
            "stack_trace": "Traceback ...",
        },
        "validation_error_schema",
    )
    assert errors
