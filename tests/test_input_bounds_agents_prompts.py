import json
from typing import Any

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS_DIR = get_schemas_dir()

AGENT_ARRAY_LIMITS = {
    "custom_validations": 100,
    "custom_tools": 100,
    "custom_responses": 100,
    "tags": 100,
    "example_sets": 100,
    "retrieval_configs": 50,
    "model_parameters": 50,
    "measure_ids": 100,
}

PROMPT_CHAT_MESSAGE_LIMIT = 50000
PROMPT_CHAT_MESSAGES_LIMIT = 200
PROMPT_LABEL_TAG_LIMIT = 100


def _load_schema(relative_path: str) -> dict[str, Any]:
    with open(SCHEMAS_DIR / relative_path, encoding="utf-8") as fh:
        return json.load(fh)


def _agent_array_item(field: str) -> Any:
    if field in {"example_sets", "retrieval_configs", "model_parameters"}:
        return {}
    return "item"


def _assert_schema_validation_fails(
    validator: SchemaValidator,
    schema_name: str,
    payload: dict[str, Any],
    field: str,
) -> None:
    errors = validator.validate_json(payload, schema_name)
    assert errors, f"{schema_name} accepted over-limit {field}"
    assert any(field in error for error in errors), errors


def test_agent_create_array_bounds_are_declared_and_enforced() -> None:
    schema = _load_schema("agents/agent_create_request_schema.json")
    properties = schema["properties"]
    validator = SchemaValidator(contract="backend")

    for field, limit in AGENT_ARRAY_LIMITS.items():
        assert properties[field]["maxItems"] == limit

        payload = {
            "name": "Support Agent",
            "agent_type_id": "qa",
            field: [_agent_array_item(field) for _ in range(limit + 1)],
        }
        _assert_schema_validation_fails(
            validator,
            "agent_create_request_schema",
            payload,
            field,
        )


def test_chat_prompt_message_content_bound_is_declared_and_enforced() -> None:
    schema = _load_schema("prompts/chat_prompt_message_schema.json")
    assert schema["properties"]["content"]["maxLength"] == PROMPT_CHAT_MESSAGE_LIMIT

    validator = SchemaValidator(contract="planned_projects")
    errors = validator.validate_json(
        {
            "role": "user",
            "content": "x" * (PROMPT_CHAT_MESSAGE_LIMIT + 1),
        },
        "chat_prompt_message_schema",
    )

    assert errors
    assert any("content" in error for error in errors), errors


@pytest.mark.parametrize(
    ("relative_path", "schema_name", "payload"),
    [
        (
            "prompts/prompt_create_request_schema.json",
            "prompt_create_request_schema",
            {
                "name": "support.prompt",
                "prompt_type": "chat",
                "chat_messages": [
                    {"role": "user", "content": "hello"}
                    for _ in range(PROMPT_CHAT_MESSAGES_LIMIT + 1)
                ],
            },
        ),
        (
            "prompts/prompt_version_create_request_schema.json",
            "prompt_version_create_request_schema",
            {
                "chat_messages": [
                    {"role": "user", "content": "hello"}
                    for _ in range(PROMPT_CHAT_MESSAGES_LIMIT + 1)
                ],
            },
        ),
        (
            "prompts/prompt_playground_request_schema.json",
            "prompt_playground_request_schema",
            {
                "chat_messages": [
                    {"role": "user", "content": "hello"}
                    for _ in range(PROMPT_CHAT_MESSAGES_LIMIT + 1)
                ],
            },
        ),
    ],
)
def test_prompt_chat_messages_bounds_are_declared_and_enforced(
    relative_path: str,
    schema_name: str,
    payload: dict[str, Any],
) -> None:
    schema = _load_schema(relative_path)
    assert schema["properties"]["chat_messages"]["maxItems"] == PROMPT_CHAT_MESSAGES_LIMIT

    if schema_name == "prompt_create_request_schema":
        text_branch_chat_messages = schema["allOf"][0]["then"]["properties"]["chat_messages"]
        assert text_branch_chat_messages["maxItems"] == 0

    validator = SchemaValidator(contract="planned_projects")
    _assert_schema_validation_fails(validator, schema_name, payload, "chat_messages")


@pytest.mark.parametrize(
    ("relative_path", "schema_name", "field", "payload"),
    [
        (
            "prompts/prompt_create_request_schema.json",
            "prompt_create_request_schema",
            "labels",
            {
                "name": "support.prompt",
                "prompt_type": "text",
                "prompt_text": "Render a response.",
                "labels": ["label" for _ in range(PROMPT_LABEL_TAG_LIMIT + 1)],
            },
        ),
        (
            "prompts/prompt_create_request_schema.json",
            "prompt_create_request_schema",
            "tags",
            {
                "name": "support.prompt",
                "prompt_type": "text",
                "prompt_text": "Render a response.",
                "tags": ["tag" for _ in range(PROMPT_LABEL_TAG_LIMIT + 1)],
            },
        ),
        (
            "prompts/prompt_version_create_request_schema.json",
            "prompt_version_create_request_schema",
            "labels",
            {
                "labels": ["label" for _ in range(PROMPT_LABEL_TAG_LIMIT + 1)],
            },
        ),
    ],
)
def test_prompt_label_and_tag_array_bounds_are_declared_and_enforced(
    relative_path: str,
    schema_name: str,
    field: str,
    payload: dict[str, Any],
) -> None:
    schema = _load_schema(relative_path)
    assert schema["properties"][field]["maxItems"] == PROMPT_LABEL_TAG_LIMIT

    validator = SchemaValidator(contract="planned_projects")
    _assert_schema_validation_fails(validator, schema_name, payload, field)
