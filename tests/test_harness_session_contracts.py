"""Privacy-by-construction contracts for coding-harness session telemetry."""

from __future__ import annotations

from copy import deepcopy

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema


HARNESS_SESSION_RECORD = "harness_session_record"
TASK_OUTCOME = "task_outcome"
DESCRIPTION = (
    "Privacy-by-construction: metadata only; this contract cannot carry prompts, "
    "code, file paths, or any free-text content."
)


def _minimal_task_outcome() -> dict:
    return {"schema_version": 1}


def _full_task_outcome() -> dict:
    return {
        "schema_version": 1,
        "session_end_reason": "clear",
        "verification_runs": [
            {
                "category": "test",
                "runs": 2,
                "failures": 0,
            },
            {
                "category": "lint",
                "runs": 1,
                "failures": 0,
            },
        ],
        "commit_count": 1,
        "pr_count": 1,
        "lines_added": 120,
        "lines_removed": 12,
        "success_score": 1,
    }


def _minimal_harness_session() -> dict:
    return {
        "schema_version": 1,
        "session_id": "session_20260610.abc-123",
        "harness": {
            "name": "claude_code",
            "version": "1.2.3",
        },
        "data_sharing_mode": "privacy",
        "timing": {
            "started_at_utc": "2026-06-10T00:00:00Z",
        },
        "ingest_source": "hooks",
    }


def _full_harness_session() -> dict:
    payload = _minimal_harness_session()
    payload.update(
        {
            "data_sharing_mode": "hybrid",
            "repo_ref": {
                "repo_id_hash": "a" * 64,
                "branch_category": "feature",
            },
            "timing": {
                "started_at_utc": "2026-06-10T00:00:00Z",
                "ended_at_utc": "2026-06-10T00:15:00Z",
                "duration_ms": 900000,
                "active_time_ms": 720000,
            },
            "model_usage": [
                {
                    "model": "anthropic/claude-sonnet-4.5",
                    "request_count": 12,
                    "input_tokens": 32000,
                    "output_tokens": 8000,
                    "cache_read_tokens": 2048,
                    "cache_creation_tokens": 1024,
                    "cost_usd": 1.25,
                    "effort": "high",
                }
            ],
            "tool_usage": [
                {
                    "tool_name": "exec_command",
                    "invocations": 8,
                    "failures": 1,
                    "user_rejections": 0,
                    "total_duration_ms": 45000,
                }
            ],
            "interaction": {
                "prompt_count": 2,
                "subagent_count": 0,
                "user_abort_count": 0,
                "api_error_count": 0,
                "permission_request_count": 0,
            },
            "outcome": _full_task_outcome(),
            "ingest_source": "merged",
        }
    )
    return payload


def _walk_schema_nodes(node: object):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_schema_nodes(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_schema_nodes(value)


def test_harness_session_contracts_are_valid_draft7() -> None:
    for schema_name in (HARNESS_SESSION_RECORD, TASK_OUTCOME):
        schema = load_schema(schema_name)
        assert schema["description"] == DESCRIPTION
        Draft7Validator.check_schema(schema)


def test_harness_session_contracts_are_registered_by_package_loader() -> None:
    validator = SchemaValidator()

    assert HARNESS_SESSION_RECORD in validator.available_schemas
    assert TASK_OUTCOME in validator.available_schemas
    assert load_schema(HARNESS_SESSION_RECORD)["$id"].endswith(
        "/harness_session_record.json"
    )
    assert load_schema(TASK_OUTCOME)["$id"].endswith("/task_outcome.json")


def test_harness_privacy_schemas_close_every_object_level() -> None:
    for schema_name in (HARNESS_SESSION_RECORD, TASK_OUTCOME):
        schema = load_schema(schema_name)
        for node in _walk_schema_nodes(schema):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, node


def test_harness_privacy_schemas_constrain_every_string_field() -> None:
    for schema_name in (HARNESS_SESSION_RECORD, TASK_OUTCOME):
        schema = load_schema(schema_name)
        for node in _walk_schema_nodes(schema):
            if node.get("type") != "string":
                continue

            assert any(
                key in node for key in ("enum", "const", "pattern", "format")
            ), node


def test_harness_session_valid_full_example_passes() -> None:
    assert SchemaValidator().validate_json(
        _full_harness_session(),
        HARNESS_SESSION_RECORD,
    ) == []


def test_harness_session_valid_minimal_example_passes() -> None:
    assert SchemaValidator().validate_json(
        _minimal_harness_session(),
        HARNESS_SESSION_RECORD,
    ) == []


def test_task_outcome_valid_full_example_passes() -> None:
    assert SchemaValidator().validate_json(_full_task_outcome(), TASK_OUTCOME) == []


def test_task_outcome_valid_minimal_example_passes() -> None:
    assert SchemaValidator().validate_json(_minimal_task_outcome(), TASK_OUTCOME) == []


def test_content_bearing_extra_field_fails_top_level_and_nested_level() -> None:
    validator = SchemaValidator()

    top_level = _minimal_harness_session()
    top_level["prompt_text"] = "print('code')"

    nested = _minimal_harness_session()
    nested["harness"]["prompt_text"] = "print('code')"

    top_level_errors = validator.validate_json(top_level, HARNESS_SESSION_RECORD)
    nested_errors = validator.validate_json(nested, HARNESS_SESSION_RECORD)

    assert any("root: Additional properties" in error for error in top_level_errors)
    assert any("harness: Additional properties" in error for error in nested_errors)


def test_ingest_source_backfill_accepted() -> None:
    payload = _minimal_harness_session()
    payload["ingest_source"] = "backfill"

    assert SchemaValidator().validate_json(payload, HARNESS_SESSION_RECORD) == []


def test_bad_enum_value_fails() -> None:
    payload = _minimal_harness_session()
    payload["data_sharing_mode"] = "public"

    assert SchemaValidator().validate_json(payload, HARNESS_SESSION_RECORD)


def test_over_long_bounded_string_fails() -> None:
    payload = _minimal_harness_session()
    payload["harness"]["version"] = "a" * 65

    assert SchemaValidator().validate_json(payload, HARNESS_SESSION_RECORD)


def test_pattern_violating_identifier_string_fails() -> None:
    payload = _minimal_harness_session()
    payload["session_id"] = "sessions/contain/no/slashes"

    assert SchemaValidator().validate_json(payload, HARNESS_SESSION_RECORD)


def test_nested_task_outcome_rejects_content_bearing_extra_field() -> None:
    payload = _full_harness_session()
    payload["outcome"] = deepcopy(_minimal_task_outcome())
    payload["outcome"]["prompt_text"] = "print('code')"

    errors = SchemaValidator().validate_json(payload, HARNESS_SESSION_RECORD)

    assert any("outcome: Additional properties" in error for error in errors)
