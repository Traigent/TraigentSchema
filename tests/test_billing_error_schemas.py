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
        {
            "success": True,
            "message": "Success",
            "data": {"packs": [{"pack_id": "starter", "credit_usd": "5.00"}]},
        },
        "wallet_top_up_packs_response_schema",
    )

    assert errors == []


def test_billing_plans_response_uses_opaque_checkout_options():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "pro",
                    "legacy_ids": ["individual"],
                    "name": "Pro",
                    "description": "For production teams starting paid usage",
                    "price": {"monthly": 49, "annual": 490},
                    "checkout_options": {"monthly": "pro_monthly", "annual": "pro_annual"},
                    "quantity_limits": {
                        "minimum": 1,
                        "maximum": 5,
                        "overflow_route": "enterprise",
                    },
                    "features": ["Email support"],
                    "limits": {"trials": 500, "api_calls": 100000, "agents": 3},
                    "popular": True,
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors == []


def test_billing_plans_response_rejects_paddle_price_ids():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "pro",
                    "name": "Pro",
                    "description": "For production teams starting paid usage",
                    "price": {"monthly": 49, "annual": 490},
                    "price_ids": {"monthly": "pri_secret", "annual": "pri_secret_annual"},
                    "features": ["Email support"],
                    "limits": {"trials": 500, "api_calls": 100000, "agents": 3},
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_plans_response_rejects_mismatched_checkout_cycle():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "pro",
                    "name": "Pro",
                    "description": "For production teams starting paid usage",
                    "price": {"monthly": 49, "annual": 490},
                    "checkout_options": {"monthly": "pro_annual", "annual": "pro_monthly"},
                    "quantity_limits": {
                        "minimum": 1,
                        "maximum": 5,
                        "overflow_route": "enterprise",
                    },
                    "features": ["Email support"],
                    "limits": {"trials": 500, "api_calls": 100000, "agents": 3},
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_plans_response_rejects_paid_plan_missing_checkout_options():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "pro",
                    "name": "Pro",
                    "description": "For production teams starting paid usage",
                    "price": {"monthly": 49, "annual": 490},
                    "features": ["Email support"],
                    "limits": {"trials": 500, "api_calls": 100000, "agents": 3},
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_plans_response_rejects_cross_plan_checkout_options():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "pro",
                    "name": "Pro",
                    "description": "For production teams starting paid usage",
                    "price": {"monthly": 49, "annual": 490},
                    "checkout_options": {
                        "monthly": "team_monthly",
                        "annual": "team_annual",
                    },
                    "quantity_limits": {
                        "minimum": 1,
                        "maximum": 5,
                        "overflow_route": "enterprise",
                    },
                    "features": ["Email support"],
                    "limits": {"trials": 500, "api_calls": 100000, "agents": 3},
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_checkout_request_uses_checkout_id_not_price_id():
    validator = SchemaValidator()

    assert (
        validator.validate_json(
            {
                "checkout_id": "team_annual",
                "quantity": 25,
                "success_url": "https://portal-dev.traigent.ai/billing/success",
            },
            "billing_checkout_request_schema",
        )
        == []
    )

    errors = validator.validate_json(
        {"price_id": "pri_secret"},
        "billing_checkout_request_schema",
    )

    assert errors


def test_billing_checkout_request_caps_quantity_by_plan():
    validator = SchemaValidator()

    assert (
        validator.validate_json(
            {"checkout_id": "pro_monthly", "quantity": 5},
            "billing_checkout_request_schema",
        )
        == []
    )
    assert (
        validator.validate_json(
            {"checkout_id": "team_monthly", "quantity": 25},
            "billing_checkout_request_schema",
        )
        == []
    )
    assert validator.validate_json(
        {"checkout_id": "pro_monthly", "quantity": 6},
        "billing_checkout_request_schema",
    )
    assert validator.validate_json(
        {"checkout_id": "team_monthly", "quantity": True},
        "billing_checkout_request_schema",
    )


def test_billing_plans_response_rejects_paid_plan_missing_quantity_limits():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": [
                {
                    "id": "team",
                    "name": "Team",
                    "description": "For teams running higher-volume evaluation workflows",
                    "price": {"monthly": 249, "annual": 2490},
                    "checkout_options": {"monthly": "team_monthly", "annual": "team_annual"},
                    "features": ["Priority support"],
                    "limits": {"users": 25},
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_checkout_request_rejects_cancel_url():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "checkout_id": "pro_monthly",
            "cancel_url": "https://portal-dev.traigent.ai/billing/canceled",
        },
        "billing_checkout_request_schema",
    )

    assert errors


def test_billing_checkout_response_accepts_success_wrapper():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {
                "checkout_url": "https://portal-dev.traigent.ai/billing/success?_ptxn=txn_123",
                "transaction_id": "txn_123",
            },
        },
        "billing_checkout_response_schema",
    )

    assert errors == []
