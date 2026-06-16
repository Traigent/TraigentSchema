"""Contract tests for field-level content/privacy annotations (TraigentSchema#63, #78).

#63: trace/observation `metadata` is documented as opaque user data.
#78: content-bearing leaf fields on the hybrid DTOs carry
     `x-content: true` + `x-privacy-classification: user_content`, so a consumer
     can enumerate content-bearing fields purely from the contract.
"""

import json

from traigent_schema.utils import get_schemas_dir


def _load(rel_path):
    with open(get_schemas_dir() / rel_path, encoding="utf-8") as handle:
        return json.load(handle)


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _find_properties(schema, name):
    """Every sub-schema declared for property `name`, anywhere in the schema."""
    found = []
    for node in _walk(schema):
        props = node.get("properties") if isinstance(node, dict) else None
        if isinstance(props, dict) and name in props:
            found.append(props[name])
    return found


CONTENT_FIELDS = {
    "observability/trace_schema.json": ["input_data", "output_data"],
    "observability/observation_schema.json": ["input_data", "output_data"],
    "datasets/example_set_schema.json": ["input", "output"],
    "datasets/evaluation_set_schema.json": ["input_text", "expected_output"],
    # #125: residual content-bearing carriers beyond the #78 hybrid-DTO scope.
    # agent_response.text is raw LLM completion text (both stream/non-stream
    # variants); expected_output is the evaluation reference.
    "agents/agent_response_schema.json": ["text", "expected_output"],
    # user-authored trace comments (read + create-request).
    "observability/trace_comment_schema.json": ["content"],
    "observability/trace_comment_create_request_schema.json": ["content"],
    # execution logs can embed user content (logs[].message); tagged as the
    # governance-safe default (issue #125 judgment call).
    "evaluation/experiment_run_schema.json": ["message"],
}


def test_content_fields_are_annotated_user_content():
    for rel_path, fields in CONTENT_FIELDS.items():
        schema = _load(rel_path)
        for field in fields:
            matches = _find_properties(schema, field)
            assert matches, f"{rel_path}: field {field} not found"
            assert any(
                m.get("x-content") is True
                and m.get("x-privacy-classification") == "user_content"
                for m in matches
            ), f"{rel_path}: field {field} missing content/privacy annotation"


def test_metric_submission_configuration_is_user_content():
    schema = _load("execution/metric_submission_schema.json")
    config = schema["definitions"]["ConfigurationParameters"]
    assert config.get("x-content") is True
    assert config.get("x-privacy-classification") == "user_content"


def test_every_x_content_node_is_classified_user_content():
    """Invariant: x-content always pairs with x-privacy-classification: user_content."""
    for rel_path in [*CONTENT_FIELDS, "execution/metric_submission_schema.json"]:
        schema = _load(rel_path)
        flagged = [n for n in _walk(schema) if n.get("x-content") is True]
        assert flagged, f"{rel_path}: expected at least one x-content field"
        for node in flagged:
            assert node.get("x-privacy-classification") == "user_content", rel_path


def test_trace_and_observation_metadata_documented_opaque():
    for rel_path in (
        "observability/trace_schema.json",
        "observability/observation_schema.json",
    ):
        schema = _load(rel_path)
        desc = schema["properties"]["metadata"].get("description", "")
        assert "opaque" in desc.lower(), rel_path
        assert "correlation_ids" in desc, rel_path
        # structural guarantee unchanged: metadata is still an object
        assert schema["properties"]["metadata"]["type"] == "object", rel_path


def test_annotations_do_not_change_required_or_types():
    """#78 is additive: types and required lists are untouched."""
    trace = _load("observability/trace_schema.json")
    assert trace["required"] == ["id", "name"]
    obs = _load("observability/observation_schema.json")
    assert obs["required"] == ["id", "type", "name"]
    example = _load("datasets/example_set_schema.json")
    assert example["definitions"]["Example"]["properties"]["input"]["type"] == "string"
