"""Contract tests for the differentiated-enforcement quota/usage/preflight schemas.

These pin the v1 shapes added for the unified quota/wallet cost model: the extended
quota-exceeded error (action / reserved_usage / enforcement_behavior), the two-dimensional
optimization limits (optimization_trials + optimization_samples), and the read-only
usage-summary and admission-preflight contracts.
"""

from traigent_schema import SchemaValidator


def test_quota_exceeded_error_accepts_extended_fields():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "error_code": "quota_exceeded",
            "resource_type": "optimization_samples",
            "action": "optimization_run",
            "current_usage": 480,
            "reserved_usage": 20,
            "limit": 500,
            "reset_at": None,
            "upgrade_url": "/billing",
            "enforcement_behavior": "block",
            "message": (
                "Optimization samples limit reached. "
                "Upgrade your plan or wait for the next billing period."
            ),
        },
        "quota_exceeded_error_schema",
    )
    assert errors == []


def test_quota_exceeded_error_stays_backward_compatible():
    """The pre-existing minimal shape (no new fields) must still validate."""
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "error_code": "quota_exceeded",
            "resource_type": "agents",
            "current_usage": 1,
            "limit": 1,
            "message": "Agent limit reached.",
        },
        "quota_exceeded_error_schema",
    )
    assert errors == []


def test_billing_limits_accepts_two_dimensional_optimization_keys():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "trials": 50,
            "optimization_trials": 50,
            "optimization_samples": 500,
            "api_calls": 1000,
            "agents": 1,
            "benchmarks": 25,
            "users": 1,
        },
        "billing_limits_schema",
    )
    assert errors == []


def test_usage_summary_response_shape():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {
                "plan_tier": "free",
                "enforcement_mode": "monitor",
                "period_start": "2026-06-01T00:00:00Z",
                "period_end": "2026-07-01T00:00:00Z",
                "resources": [
                    {
                        "resource_type": "optimization_samples",
                        "used": 300,
                        "reserved": 0,
                        "limit": 500,
                        "reset_at": "2026-07-01T00:00:00Z",
                        "enforcement_behavior": "block",
                    },
                    {
                        "resource_type": "observability_traces",
                        "used": 2000,
                        "reserved": 0,
                        "limit": 2000,
                        "reset_at": None,
                        "enforcement_behavior": "drop",
                    },
                ],
            },
        },
        "usage_summary_response_schema",
    )
    assert errors == []


def test_quota_preflight_request_minimal_and_full():
    validator = SchemaValidator()
    assert (
        validator.validate_json(
            {"action": "optimization_run"}, "quota_preflight_request_schema"
        )
        == []
    )
    assert (
        validator.validate_json(
            {
                "action": "optimization_run",
                "requested": {"optimization_trials": 1, "optimization_samples": 100},
            },
            "quota_preflight_request_schema",
        )
        == []
    )


def test_quota_preflight_response_lists_quota_and_wallet_blockers():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {
                "allowed": False,
                "action": "optimization_run",
                "blockers": [
                    {
                        "kind": "quota",
                        "message": "Optimization samples limit reached.",
                        "resource_type": "optimization_samples",
                        "current_usage": 500,
                        "reserved_usage": 0,
                        "requested": 100,
                        "limit": 500,
                        "enforcement_behavior": "block",
                        "upgrade_url": "/billing",
                    },
                    {
                        "kind": "wallet",
                        "message": "Add wallet credits to continue.",
                        "wallet_status": "active",
                        "available_balance_usd": "0.00",
                        "required_reserve_usd": "0.05",
                        "shortfall_usd": "0.05",
                        "top_up_url": "/billing",
                    },
                ],
                "reservation_preview": {
                    "optimization_trials": 1,
                    "optimization_samples": 100,
                    "estimated_cost_usd": "0.05",
                },
            },
        },
        "quota_preflight_response_schema",
    )
    assert errors == []


def test_quota_preflight_response_allowed_has_no_blockers():
    validator = SchemaValidator()
    errors = validator.validate_json(
        {
            "success": True,
            "message": "Success",
            "data": {"allowed": True, "action": "optimization_run", "blockers": []},
        },
        "quota_preflight_response_schema",
    )
    assert errors == []
