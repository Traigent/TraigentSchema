import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def test_cost_users_response_accepts_backend_payload_shape():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "User usage retrieved",
            "data": {
                "items": [
                    {
                        "user_id": "user_123",
                        "email": "finance@example.com",
                        "total_cost": 12.34,
                        "input_tokens": 100,
                        "output_tokens": 50,
                        "total_tokens": 150,
                        "request_count": 3,
                        "last_activity": "2026-06-03T12:00:00+00:00",
                    }
                ],
                "page": 1,
                "per_page": 20,
                "total": 1,
                "sort": "total_cost",
                "order": "desc",
                "period": "30d",
                "start_date": "2026-05-04T12:00:00+00:00",
                "end_date": "2026-06-03T12:00:00+00:00",
                "generated_at": "2026-06-03T12:00:01+00:00",
            },
        },
        "cost_users_response_schema",
    )

    assert errors == []


def test_cost_user_usage_response_accepts_operation_summary():
    validator = SchemaValidator()

    errors = validator.validate_json(
        {
            "success": True,
            "message": "Usage retrieved",
            "data": {
                "user_id": "user_123",
                "email": None,
                "total_cost": 12.34,
                "total_requests": 3,
                "request_count": 3,
                "input_tokens": 100,
                "output_tokens": 50,
                "total_tokens": 150,
                "last_activity": None,
                "summary": {
                    "generation": {"total_cost": 11.0, "request_count": 2},
                    "unknown": {"total_cost": 1.34, "request_count": 1},
                },
                "period": "30d",
                "start_date": "2026-05-04T12:00:00+00:00",
                "end_date": "2026-06-03T12:00:00+00:00",
                "generated_at": "2026-06-03T12:00:01+00:00",
            },
        },
        "cost_user_usage_response_schema",
    )

    assert errors == []


def _usage_payload(**overrides):
    data = {
        "user_id": "user_123",
        "email": None,
        "total_cost": 12.34,
        "total_requests": 3,
        "request_count": 3,
        "input_tokens": 100,
        "output_tokens": 50,
        "total_tokens": 150,
        "last_activity": None,
        "summary": {},
        "period": "30d",
        "start_date": "2026-05-04T12:00:00+00:00",
        "end_date": "2026-06-03T12:00:00+00:00",
        "generated_at": "2026-06-03T12:00:01+00:00",
    }
    data.update(overrides)
    return {"success": True, "message": "ok", "data": data}


def test_cost_user_usage_email_rejects_invalid_format():
    """#223 — cost_user_usage response email must carry format:email when non-null."""
    v = SchemaValidator()
    errors = v.validate_json(_usage_payload(email="not-an-email"), "cost_user_usage_response_schema")
    assert errors, "expected format:email rejection for 'not-an-email'"


def test_cost_user_usage_email_rejects_oversized():
    """#223 — cost_user_usage response email must be capped at maxLength:320."""
    v = SchemaValidator()
    long_email = "a" * 316 + "@b.co"  # 321 chars — one over the 320 cap
    errors = v.validate_json(_usage_payload(email=long_email), "cost_user_usage_response_schema")
    assert errors, "expected maxLength:320 rejection"


def test_cost_user_usage_email_field_has_format_and_maxlength():
    """#223 — schema structural guard: format:email + maxLength:320 on data.email."""
    with open(get_schemas_dir() / "costs" / "cost_user_usage_response_schema.json") as f:
        schema = json.load(f)
    email_field = schema["properties"]["data"]["properties"]["email"]
    assert email_field.get("format") == "email", "data.email must carry format:email"
    assert email_field.get("maxLength") == 320, "data.email must carry maxLength:320"


def test_cost_endpoint_module_is_registered():
    with open(get_schemas_dir() / "mep_endpoints.json", encoding="utf-8") as fh:
        root = json.load(fh)

    assert any(
        module.get("paths_file") == "./costs/costs_endpoints.json"
        for module in root["x-endpoint-modules"]
    )

    with open(get_schemas_dir() / "costs" / "costs_endpoints.json", encoding="utf-8") as fh:
        endpoints = json.load(fh)

    users_response = endpoints["paths"]["/api/v1/costs/users"]["get"]["responses"]["200"]
    assert users_response["content"]["application/json"]["schema"]["$ref"].endswith(
        "cost_users_response_schema.json"
    )
    user_response = endpoints["paths"]["/api/v1/costs/usage/user/{user_id}"]["get"]["responses"][
        "200"
    ]
    assert user_response["content"]["application/json"]["schema"]["$ref"].endswith(
        "cost_user_usage_response_schema.json"
    )
