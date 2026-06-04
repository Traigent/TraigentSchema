import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


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


def test_subscription_response_accepts_no_subscription_marker():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {"status": "none", "tier": "free"},
        },
        "subscription_response_schema",
    )

    assert errors == []


def test_subscription_response_accepts_public_subscription_shape():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {
                "id": 123,
                "user_id": "user_123",
                "tenant_id": "tenant_123",
                "status": "active",
                "plan_tier": "team",
                "billing_cycle": "monthly",
                "scheduled_plan_tier": "individual",
                "scheduled_billing_cycle": "annual",
                "scheduled_change_at": "2026-06-04T12:00:00+00:00",
                "current_period_start": "2026-06-04T12:00:00+00:00",
                "current_period_end": "2026-07-04T12:00:00+00:00",
                "cancel_at_period_end": False,
                "created_at": "2026-06-04T12:00:00+00:00",
            },
        },
        "subscription_response_schema",
    )

    assert errors == []


def test_subscription_response_rejects_paddle_price_ids():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {
                "id": 123,
                "user_id": "user_123",
                "tenant_id": "tenant_123",
                "status": "active",
                "plan_tier": "team",
                "billing_cycle": "monthly",
                "scheduled_plan_tier": None,
                "scheduled_billing_cycle": None,
                "scheduled_change_at": None,
                "current_period_start": "2026-06-04T12:00:00+00:00",
                "current_period_end": "2026-07-04T12:00:00+00:00",
                "cancel_at_period_end": False,
                "created_at": "2026-06-04T12:00:00+00:00",
                "scheduled_price_id": "pri_secret",
            },
        },
        "subscription_response_schema",
    )

    assert errors


def test_subscription_lifecycle_endpoint_wires_subscription_response_schema():
    with open(
        get_schemas_dir() / "billing" / "subscription_lifecycle_endpoints.json",
        encoding="utf-8",
    ) as fh:
        spec = json.load(fh)

    response = spec["paths"]["/api/v1/billing/subscription"]["get"]["responses"]["200"]
    schema_ref = response["content"]["application/json"]["schema"]["$ref"]

    assert schema_ref.endswith("subscription_response_schema.json")
