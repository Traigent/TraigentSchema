from traigent_schema import SchemaValidator


def test_quota_exceeded_error_schema_accepts_contract_shape():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "error_code": "quota_exceeded",
            "resource_type": "agents",
            "current_usage": 1,
            "limit": 1,
            "reset_at": None,
            "upgrade_url": "/billing",
            "message": "Agent limit reached. Upgrade your plan to add more agents.",
        },
        "quota_exceeded_error_schema",
    )

    assert errors == []


def test_wallet_insufficient_balance_error_schema_accepts_contract_shape():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "error_code": "wallet_insufficient_balance",
            "available_usd": "0.00",
            "required_usd": "0.05",
            "operation_id": "op_123",
            "operation_group_id": None,
            "message": "Add wallet credits to continue generation.",
        },
        "wallet_insufficient_balance_error_schema",
    )

    assert errors == []


def test_wallet_top_up_packs_response_hides_paddle_price_ids():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {"packs": [{"pack_id": "starter", "credit_usd": "5.00"}]},
        "wallet_top_up_packs_response_schema",
    )

    assert errors == []
