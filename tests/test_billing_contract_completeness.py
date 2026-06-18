"""#129: the billing contract had placeholder responses, missing request bodies on
mutating routes, and a dangling billing_endpoints.json pointer."""
import json
from pathlib import Path

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

B = get_schemas_dir() / "billing"
CATALOGS = [
    "paddle_endpoints.json", "wallet_endpoints.json",
    "subscription_lifecycle_endpoints.json", "spend_controls_endpoints.json",
]


def _load(name):
    with open(B / name, encoding="utf-8") as fh:
        return json.load(fh)


def test_no_placeholder_responses_remain():
    for name in CATALOGS:
        text = (B / name).read_text(encoding="utf-8")
        assert "Response shape pending" not in text, f"{name} still has a placeholder response"


def test_dangling_billing_endpoints_pointer_removed():
    # billing/billing_endpoints.json never existed; no catalog may reference it.
    assert not (B / "billing_endpoints.json").exists()
    for name in CATALOGS:
        text = (B / name).read_text(encoding="utf-8")
        assert "billing/billing_endpoints.json" not in text, f"{name} references a non-existent file"


def test_mutating_routes_declare_request_bodies():
    expected = {
        ("paddle_endpoints.json", "/api/v1/billing/webhook", "post"): "paddle_webhook_request_schema",
        ("wallet_endpoints.json", "/api/v1/billing/wallet/top-ups", "post"): "wallet_top_up_request_schema",
        ("wallet_endpoints.json", "/api/v1/billing/wallet/admin-adjustments", "post"): "wallet_admin_adjustment_request_schema",
        ("spend_controls_endpoints.json", "/api/v1/billing/spend-approvals", "post"): "spend_approval_request_schema",
        ("spend_controls_endpoints.json", "/api/v1/billing/spend-policy", "patch"): "spend_policy_update_request_schema",
    }
    for (cat, path, method), schema_stem in expected.items():
        op = _load(cat)["paths"][path][method]
        ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith(schema_stem + ".json"), f"{path} -> {ref}"


def test_validator_resolves_billing_write_routes():
    v = SchemaValidator(contract="backend")
    assert v._endpoint_schemas.get("POST:/api/v1/billing/webhook") == "paddle_webhook_request_schema"
    # top-ups requires pack_id (was fail-open before)
    assert v.validate_request("/api/v1/billing/wallet/top-ups", "POST", {})
    assert v.validate_request("/api/v1/billing/wallet/top-ups", "POST", {"pack_id": "starter"}) == []
    # the webhook is unauthenticated + provider-shaped: lenient, but contracted
    assert v.validate_request("/api/v1/billing/webhook", "POST", {"event_type": "x", "data": {}}) == []


def test_placeholder_routes_now_reference_response_schemas():
    checks = [
        ("paddle_endpoints.json", "/api/v1/billing/portal", "get"),
        ("wallet_endpoints.json", "/api/v1/billing/wallet", "get"),
        ("subscription_lifecycle_endpoints.json", "/api/v1/billing/usage", "get"),
        ("subscription_lifecycle_endpoints.json", "/api/v1/billing/usage/check", "get"),
        ("spend_controls_endpoints.json", "/api/v1/billing/spend-policy", "get"),
    ]
    for cat, path, method in checks:
        op = _load(cat)["paths"][path][method]
        ref = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("_response_schema.json"), f"{path} 200 -> {ref}"


def test_response_data_shapes_are_open_not_falsely_precise():
    """Service-backed read responses must not over-constrain `data` (would reject real
    backend bodies). They are enveloped {success,message,data} with open data."""
    for name in ("wallet_response_schema.json", "usage_response_schema.json",
                 "wallet_top_up_response_schema.json", "usage_history_response_schema.json"):
        spec = _load(name)
        assert spec["required"] == ["success", "message", "data"]
        data = spec["properties"]["data"]
        if data.get("type") == "array" or "array" in (data.get("type") or []):
            assert data["items"].get("additionalProperties") is True
        else:
            assert data.get("additionalProperties") is True
            # no required sub-fields invented
            assert "required" not in data


def test_money_request_fields_accept_string_or_number():
    v = SchemaValidator(contract="backend")
    # backend serializes money as strings or numbers — contract must accept both
    assert v.validate_request(
        "/api/v1/billing/spend-approvals", "POST",
        {"operation_group_id": "g", "requested_estimate_usd": "12.50"},
    ) == []
    assert v.validate_request(
        "/api/v1/billing/spend-approvals", "POST",
        {"operation_group_id": "g", "requested_estimate_usd": 12.5},
    ) == []
