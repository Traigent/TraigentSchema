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
            "details": {"resource_type": "optimization_samples", "limit": 500},
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


# --------------------------------------------------------------------------- #
# EntitlementRequiredErrorDTO: "authenticated, but not entitled"
#
# The specialization exists to stop one specific confusion: an API key
# authenticates a caller and never entitles one. So the tests below are
# adversarial about the two ways that confusion could re-enter the wire — a
# credential-shaped field, and a consumer branching on prose.
# --------------------------------------------------------------------------- #

_ENTITLEMENT = "entitlement_required_error_schema"


def _entitlement(**extra):
    """A complete, honest entitlement-required body. Overriding one key exercises it."""
    payload = {
        "success": False,
        "message": "Your access period has ended.",
        "error": "entitlement_required",
        "details": {"reason": "access_period_ended"},
    }
    payload.update(extra)
    return payload


def _entitlement_errors(payload):
    return SchemaValidator().validate_json(payload, _ENTITLEMENT)


def _load_entitlement_schema():
    import json

    from traigent_schema.utils import get_schemas_dir

    with open(get_schemas_dir() / "entitlement_required_error_schema.json", encoding="utf-8") as fh:
        return json.load(fh)


def test_entitlement_required_error_resolves_and_both_reasons_validate():
    validator = SchemaValidator()
    assert _ENTITLEMENT in validator.available_schemas, "must auto-discover by filename"
    for reason in ("access_period_ended", "no_active_plan"):
        assert _entitlement_errors(_entitlement(details={"reason": reason})) == [], reason


def test_entitlement_required_error_declares_its_posture():
    """No producer has been asserted against yet (TraigentBackend #2461 is an open issue,
    not merged code), and the obligations this contract cannot enforce — message redaction,
    reason precedence, HTTP status choice — must be enumerated rather than assumed."""
    schema = _load_entitlement_schema()
    assert schema["x-stability"] == "pre-release"
    assert schema["x-asserted-against-backend"] is False
    obligations = schema["x-backend-obligations"]
    assert isinstance(obligations, list) and obligations
    assert all(isinstance(item, str) and item.strip() for item in obligations)


def test_entitlement_required_pins_the_error_token():
    """`error` is the coarse branch key, so it is a const: an adjacent-but-different token
    (`quota_exceeded` — a real sibling in this repo) or a case variant must not pass as
    this error, or a consumer's switch silently falls through to the wrong arm."""
    for bad in ("", "quota_exceeded", "ENTITLEMENT_REQUIRED", "Entitlement_Required",
                "entitlement_required "):
        assert _entitlement_errors(_entitlement(error=bad)), repr(bad)
    missing = _entitlement()
    del missing["error"]
    assert _entitlement_errors(missing), "the envelope still requires `error`"


def test_entitlement_required_reason_vocabulary_is_closed():
    """A new cause is a versioned enum addition, not a free-text escape hatch."""
    for bad in ("expired", "ACCESS_PERIOD_ENDED", "", "access_period_ended ", "trial_over"):
        assert _entitlement_errors(_entitlement(details={"reason": bad})), repr(bad)
    assert _entitlement_errors(_entitlement(details={"reason": 1})), "reason is a string"
    assert _entitlement_errors(_entitlement(details={})), "reason is required inside details"
    no_details = _entitlement()
    del no_details["details"]
    assert _entitlement_errors(no_details), "details is required by the specialization"


def test_entitlement_required_rejects_a_top_level_reason():
    """The load-bearing structural claim of this design, asserted explicitly.

    `reason` lives under `details` and NOT at the top level, because the envelope declares
    `additionalProperties: false` and that keyword only sees properties declared in the
    SAME schema object — it does not see properties contributed by a sibling `allOf`
    branch. So had `reason` been declared top-level in the specialization branch, the
    envelope branch would reject it as an unknown key and NO valid document would exist.
    This test is what stops a future editor from "simplifying" the nesting away.
    """
    assert _entitlement_errors(_entitlement(reason="access_period_ended")), (
        "a top-level reason must be rejected by the envelope's additionalProperties:false"
    )
    # even alongside a correct details block — it is the key itself that is unrepresentable
    assert _entitlement_errors(
        _entitlement(reason="no_active_plan", details={"reason": "no_active_plan"})
    )
    # and the nesting the contract does use is the one that validates
    assert _entitlement_errors(_entitlement()) == []


def test_entitlement_required_carries_no_credential_shaped_field():
    """An entitlement refusal is exactly the response most tempting to decorate with "here
    is the key you'd need" or "here is why, from the stack". Neither is representable:
    top-level keys hit the envelope's closed shape, and `details` keys hit the branch's own
    `additionalProperties: false`."""
    credential_shaped = (
        "api_key", "apiKey", "token", "access_token", "access_code", "lead_token",
        "secret", "password", "credential", "authorization", "stack_trace", "sql",
        "internal_account_id", "upgrade_url", "ended_at",
    )
    for key in credential_shaped:
        assert _entitlement_errors(_entitlement(**{key: "sk-live-not-on-the-wire"})), (
            f"top-level {key} must be rejected"
        )
        assert _entitlement_errors(
            _entitlement(details={"reason": "no_active_plan", key: "sk-live-not-on-the-wire"})
        ), f"details.{key} must be rejected"


def test_entitlement_details_property_set_is_exactly_reason():
    """Structural companion to the test above: the closure is asserted on the schema, not
    only inferred from a sample of rejected keys."""
    branch = _load_entitlement_schema()["allOf"][1]
    details = branch["properties"]["details"]
    assert set(details["properties"]) == {"reason"}
    assert details["additionalProperties"] is False
    assert details["required"] == ["reason"]
    assert set(details["properties"]["reason"]["enum"]) == {
        "access_period_ended",
        "no_active_plan",
    }


def test_message_is_a_bounded_display_string_and_carries_no_branching_information():
    """This replaces freezing the English prose as a `const`.

    Freezing it would block localization and make every marketing reword a contract
    change, so the anti-branching property is proven by behaviour instead: the SAME
    message validates under BOTH reasons, and an arbitrary unrelated message validates
    too. A consumer therefore cannot recover `reason` from `message` — `reason` alone
    distinguishes the cases, which is precisely what "MUST branch on details.reason,
    never on message text" means operationally.
    """
    shared = "Access to this workspace is unavailable."
    for reason in ("access_period_ended", "no_active_plan"):
        same_message = _entitlement(message=shared, details={"reason": reason})
        assert _entitlement_errors(same_message) == [], (
            f"one message must be usable for {reason}: message does not select the branch"
        )
    for arbitrary in (
        "Votre periode d'acces est terminee.",
        "x",
        "Upgrade to continue. Talk to your workspace admin.",
    ):
        assert _entitlement_errors(_entitlement(message=arbitrary)) == [], arbitrary
    # bounded, though: free text is not unbounded text
    assert _entitlement_errors(_entitlement(message="m" * 512)) == []
    assert _entitlement_errors(_entitlement(message="m" * 513)), "message is capped at 512"
    assert _entitlement_errors(_entitlement(message="")), "an empty message is not display text"


def test_entitlement_required_still_enforces_the_envelope_discriminator():
    """The specialization composes the envelope; it does not replace it."""
    assert _entitlement_errors(_entitlement(success=True)), "an error body must set success false"
    no_message = _entitlement()
    del no_message["message"]
    assert _entitlement_errors(no_message)


def test_entitlement_required_forbids_an_unsynchronised_error_code() -> None:
    """The envelope declares `error_code` optional and unconstrained.

    Inheriting it would let a surface emit an error_code that disagrees with
    details.reason -- two machine-readable signals for one state, which is the
    exact divergence this schema exists to prevent. It is also an unbounded free
    string on a PUBLIC contract, so it could carry a credential or a route name.
    Rejecting a pinned const did not imply leaving the field wide open.
    """
    assert _entitlement_errors(_entitlement(details={"reason": "access_period_ended"})) == []
    for smuggled in ("no_active_plan", "ENTITLEMENT_REQUIRED", "uk_live_abc123"):
        payload = _entitlement(details={"reason": "access_period_ended"})
        payload["error_code"] = smuggled
        assert _entitlement_errors(payload) != [], f"error_code={smuggled!r} was accepted"
