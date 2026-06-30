"""Contract tests for GET /api/v1/sessions (session list response).

Mirrors the live backend shape ``{"sessions": [...], "total": N}`` where each
entry is a lightweight summary (identity + lifecycle state + progress). The
schema is intentionally forward-compatible (extra fields tolerated) so the SDK
can enumerate sessions and clean orphaned 'running' sessions without a schema
bump every time the server adds a field.
"""

from traigent_schema import SchemaValidator

SCHEMA = "optimization_session_list_response_schema"


def _validator() -> SchemaValidator:
    return SchemaValidator(contract="sdk_tuning")


def test_empty_list_is_valid():
    # The live response observed against api-dev: {"sessions": [], "total": 0}.
    assert _validator().validate_json({"sessions": [], "total": 0}, SCHEMA) == []


def test_full_summary_is_valid():
    payload = {
        "sessions": [
            {
                "session_id": "11111111-1111-1111-1111-111111111111",
                "status": "active",
                "created_at": "2026-01-01T00:00:00",
                "progress": {"completed": 5, "total": 10, "failed": 0},
            }
        ],
        "total": 1,
    }
    assert _validator().validate_json(payload, SCHEMA) == []


def test_minimal_summary_requires_only_id_and_status():
    payload = {"sessions": [{"session_id": "s1", "status": "running"}], "total": 1}
    assert _validator().validate_json(payload, SCHEMA) == []


def test_extra_fields_are_tolerated_forward_compat():
    payload = {
        "sessions": [{"session_id": "s1", "status": "running", "future_field": {"x": 1}}],
        "total": 1,
        "next_cursor": "abc",
    }
    assert _validator().validate_json(payload, SCHEMA) == []


def test_missing_total_is_rejected():
    assert _validator().validate_json({"sessions": []}, SCHEMA)


def test_sessions_must_be_an_array():
    assert _validator().validate_json({"sessions": {}, "total": 0}, SCHEMA)


def test_summary_missing_status_is_rejected():
    payload = {"sessions": [{"session_id": "s1"}], "total": 1}
    assert _validator().validate_json(payload, SCHEMA)


def test_summary_missing_session_id_is_rejected():
    payload = {"sessions": [{"status": "running"}], "total": 1}
    assert _validator().validate_json(payload, SCHEMA)
