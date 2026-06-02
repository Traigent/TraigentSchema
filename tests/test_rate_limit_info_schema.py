"""Contract tests for RateLimitInfoDTO (TraigentSchema#60).

Mirrors the backend's standardized 429 envelope (BE#670, rate_limited_response):
Shape A error envelope with error_code "RATE_LIMIT_EXCEEDED" and a rate-limit
details block. Composes error_envelope_schema.json.
"""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA = "rate_limit_info_schema"


def _body(**details_overrides):
    details = {"scope": "global", "retry_after": 30}
    details.update(details_overrides)
    return {
        "success": False,
        "message": "Rate limit exceeded",
        "error": "Too many requests",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "details": details,
    }


def test_accepts_minimal_429():
    assert SchemaValidator().validate_json(_body(), SCHEMA) == []


def test_accepts_with_header_mirror_fields():
    body = _body(limit="100 per minute", reset_time="2026-06-02T12:00:00Z")
    assert SchemaValidator().validate_json(body, SCHEMA) == []


def test_requires_rate_limit_error_code():
    v = SchemaValidator()
    body = _body()
    body["error_code"] = "SOMETHING_ELSE"
    assert v.validate_json(body, SCHEMA)


def test_requires_details_scope_and_retry_after():
    v = SchemaValidator()
    for missing in ("scope", "retry_after"):
        body = _body()
        del body["details"][missing]
        assert v.validate_json(body, SCHEMA), missing


def test_retry_after_must_be_positive_int():
    v = SchemaValidator()
    assert v.validate_json(_body(retry_after=0), SCHEMA)
    assert v.validate_json(_body(retry_after="30"), SCHEMA)


def test_inherits_envelope_required_and_leak_guard():
    v = SchemaValidator()
    # missing the envelope's required `success`
    body = _body()
    del body["success"]
    assert v.validate_json(body, SCHEMA)
    # envelope additionalProperties:false still rejects a stray top-level field
    leaky = _body()
    leaky["stack_trace"] = "Traceback ..."
    assert v.validate_json(leaky, SCHEMA)
    # details is closed
    closed = _body()
    closed["details"]["sql"] = "SELECT 1"
    assert v.validate_json(closed, SCHEMA)


def test_documents_response_headers():
    with open(get_schemas_dir() / "rate_limit_info_schema.json", encoding="utf-8") as fh:
        schema = json.load(fh)
    headers = schema["x-response-headers"]
    assert "Retry-After" in headers
    for h in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"):
        assert h in headers
