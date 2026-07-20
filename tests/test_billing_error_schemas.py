import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def test_quota_exceeded_error_schema_accepts_contract_shape():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "error_code": "quota_exceeded",
            "resource_type": "optimization_samples",
            "current_usage": 500,
            "limit": 500,
            "reset_at": None,
            "upgrade_url": "/billing",
            "message": "Optimization samples limit reached. Upgrade your plan to add more.",
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
                    "limits": {
                        "trials": 500,
                        "optimization_trials": 500,
                        "optimization_samples": 5000,
                        "api_calls": 100000,
                        "benchmarks": 250,
                        "users": 5,
                    },
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
                    "limits": {
                        "trials": 500,
                        "optimization_trials": 500,
                        "optimization_samples": 5000,
                        "api_calls": 100000,
                        "benchmarks": 250,
                        "users": 5,
                    },
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
                    "limits": {
                        "trials": 500,
                        "optimization_trials": 500,
                        "optimization_samples": 5000,
                        "api_calls": 100000,
                        "benchmarks": 250,
                        "users": 5,
                    },
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
                    "limits": {
                        "trials": 500,
                        "optimization_trials": 500,
                        "optimization_samples": 5000,
                        "api_calls": 100000,
                        "benchmarks": 250,
                        "users": 5,
                    },
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
                    "limits": {
                        "trials": 500,
                        "optimization_trials": 500,
                        "optimization_samples": 5000,
                        "api_calls": 100000,
                        "benchmarks": 250,
                        "users": 5,
                    },
                }
            ],
        },
        "billing_plans_response_schema",
    )

    assert errors


def test_billing_plans_response_requires_new_record_limit_fields():
    validator = SchemaValidator()

    payload = {
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
                "limits": {
                    "trials": 500,
                    "optimization_trials": 500,
                    "optimization_samples": 5000,
                    "api_calls": 100000,
                    "users": 5,
                },
            }
        ],
    }

    assert validator.validate_json(payload, "billing_plans_response_schema")


def test_billing_limits_reject_unknown_and_invalid_fields():
    validator = SchemaValidator()

    valid_limits = {
        "trials": 500,
        "optimization_trials": 500,
        "optimization_samples": 5000,
        "api_calls": 100000,
        "benchmarks": 250,
        "users": 5,
    }
    assert validator.validate_json(valid_limits, "billing_limits_schema") == []

    with_unknown = {**valid_limits, "experiments": 10}
    assert validator.validate_json(with_unknown, "billing_limits_schema")

    invalid_type = {**valid_limits, "benchmarks": "250"}
    assert validator.validate_json(invalid_type, "billing_limits_schema")


def test_billing_enforcement_controls_accepts_effective_record_limits():
    validator = SchemaValidator()

    payload = {
        "success": True,
        "message": "Billing enforcement controls retrieved",
        "data": {
            "enforcement_mode": "enforce",
            "effective_limits": {
                "trials": 500,
                "optimization_trials": 500,
                "optimization_samples": 5000,
                "api_calls": 100000,
                "benchmarks": 250,
                "users": 5,
            },
        },
    }

    assert validator.validate_json(payload, "billing_enforcement_controls_response_schema") == []


def test_billing_enforcement_controls_rejects_missing_or_invalid_record_limits():
    validator = SchemaValidator()

    missing_benchmarks = {
        "success": True,
        "message": "Billing enforcement controls retrieved",
        "data": {
            "effective_limits": {
                "trials": 500,
                "optimization_trials": 500,
                "optimization_samples": 5000,
                "api_calls": 100000,
                "users": 5,
            },
        },
    }
    assert validator.validate_json(
        missing_benchmarks, "billing_enforcement_controls_response_schema"
    )

    invalid = {
        **missing_benchmarks,
        "data": {
            "effective_limits": {
                "trials": 500,
                "optimization_trials": 500,
                "optimization_samples": 5000,
                "api_calls": 100000,
                "benchmarks": True,
                "users": 5,
            }
        },
    }
    assert validator.validate_json(invalid, "billing_enforcement_controls_response_schema")


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


def test_subscription_lifecycle_endpoint_wires_enforcement_controls_response_schema():
    with open(
        get_schemas_dir() / "billing" / "subscription_lifecycle_endpoints.json",
        encoding="utf-8",
    ) as fh:
        spec = json.load(fh)

    response = spec["paths"]["/api/v1/billing/enforcement-controls"]["get"]["responses"]["200"]
    schema_ref = response["content"]["application/json"]["schema"]["$ref"]

    assert schema_ref.endswith("billing_enforcement_controls_response_schema.json")
