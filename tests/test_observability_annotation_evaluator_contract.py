"""#270: the annotation-queue / evaluator-run / trace-feedback-collaboration / prompt-link
/ review-score family (27 schemas under observability/) had zero dedicated semantic
contract tests -- only structural validity (#131, field-level checks explicitly out of
scope) and scattered single-assertion smoke checks (#132 item 1, never followed through).
Mirrors the per-contract pattern in test_datasets_contract.py /
test_billing_contract_completeness.py: required-field-set assertions, enum vocabulary,
and valid/invalid example payloads through SchemaValidator.
"""
import json

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OBS = get_schemas_dir() / "observability"
TARGET_TYPES = {
    "observability_trace", "observability_observation", "configuration_run", "experiment_run",
}
SCORE_SOURCES = {"manual", "evaluator", "api", "human", "user", "llm", "model", "sdk"}


def _load(name):
    with open(OBS / name, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def v():
    return SchemaValidator(contract="backend")


# ---------------------------------------------------------------------------
# Annotation queue family
# ---------------------------------------------------------------------------

def test_annotation_queue_item_required_fields_and_status_vocab():
    schema = _load("annotation_queue_item_schema.json")
    assert set(schema["required"]) == {
        "id", "queue_id", "target_type", "target_id", "status", "score_record_ids",
    }
    assert set(schema["properties"]["status"]["enum"]) == {
        "pending", "in_progress", "completed", "skipped",
    }
    assert set(schema["properties"]["target_type"]["enum"]) == TARGET_TYPES


def test_annotation_queue_item_create_request_shape(v):
    schema = _load("annotation_queue_item_create_request_schema.json")
    assert schema["required"] == ["items"]
    item = schema["properties"]["items"]["items"]
    assert item["required"] == ["target_id"]
    assert set(item["properties"]["target_type"]["enum"]) == TARGET_TYPES

    route = "/api/v1beta/annotation-queues/{queue_id}/items"
    assert v.validate_request(route, "POST", {"items": [{"target_id": "t1"}]}) == []
    assert v.validate_request(route, "POST", {"items": []})  # minItems 1
    assert v.validate_request(
        route, "POST", {"items": [{"target_type": "bogus", "target_id": "t1"}]}
    )


def test_annotation_queue_create_request_requires_name_target_type_measure_ids(v):
    schema = _load("annotation_queue_create_request_schema.json")
    assert set(schema["required"]) == {"name", "target_type", "measure_ids"}
    assert set(schema["properties"]["target_type"]["enum"]) == TARGET_TYPES
    assert set(schema["properties"]["status"]["enum"]) == {"active", "paused", "archived"}

    route = "/api/v1beta/annotation-queues"
    body = {"name": "Q1", "target_type": "observability_trace", "measure_ids": ["m1"]}
    assert v.validate_request(route, "POST", body) == []
    assert v.validate_request(
        route, "POST", {"target_type": "observability_trace", "measure_ids": ["m1"]}
    )  # missing name
    assert v.validate_request(route, "POST", {**body, "measure_ids": []})  # minItems 1


def test_annotation_queue_update_request_is_all_optional_but_typed(v):
    schema = _load("annotation_queue_update_request_schema.json")
    assert "required" not in schema
    assert set(schema["properties"]["status"]["enum"]) == {"active", "paused", "archived"}

    route = "/api/v1beta/annotation-queues/{queue_id}"
    assert v.validate_request(route, "PATCH", {"status": "paused"}) == []
    assert v.validate_request(route, "PATCH", {"status": "bogus-status"})


def test_annotation_queue_item_create_result_wraps_created_items():
    schema = _load("annotation_queue_item_create_result_schema.json")
    assert set(schema["required"]) == {"queue_id", "created_count", "items"}
    assert schema["properties"]["items"]["items"]["$ref"] == "./annotation_queue_item_schema.json"


def test_annotation_queue_item_complete_result_carries_item_and_scores():
    schema = _load("annotation_queue_item_complete_result_schema.json")
    assert set(schema["required"]) == {"queue_id", "item", "scores"}
    assert schema["properties"]["item"]["$ref"] == "./annotation_queue_item_schema.json"
    assert schema["properties"]["scores"]["items"]["$ref"] == "./review_score_schema.json"


def test_annotation_queue_item_list_response_paginated():
    schema = _load("annotation_queue_item_list_response_schema.json")
    assert set(schema["required"]) == {"items", "pagination"}
    assert schema["properties"]["pagination"]["$ref"] == "../pagination_schema.json"
    assert schema["properties"]["items"]["items"]["$ref"] == "./annotation_queue_item_schema.json"


def test_annotation_queue_list_response_paginated():
    schema = _load("annotation_queue_list_response_schema.json")
    assert set(schema["required"]) == {"items", "pagination"}
    assert schema["properties"]["items"]["items"]["$ref"] == "./annotation_queue_schema.json"


# ---------------------------------------------------------------------------
# Evaluator-run / evaluator-definition family
# ---------------------------------------------------------------------------

def test_evaluator_run_required_fields_and_status_vocab():
    schema = _load("evaluator_run_schema.json")
    assert set(schema["required"]) == {
        "id", "evaluator_id", "measure_id", "target_type", "target_id", "status",
    }
    assert set(schema["properties"]["status"]["enum"]) == {
        "pending", "running", "completed", "failed",
    }
    assert set(schema["properties"]["target_type"]["enum"]) == TARGET_TYPES


def test_evaluator_run_list_response_paginated():
    schema = _load("evaluator_run_list_response_schema.json")
    assert set(schema["required"]) == {"items", "pagination"}
    assert schema["properties"]["items"]["items"]["$ref"] == "./evaluator_run_schema.json"


def test_evaluator_run_retry_request_optional_judge_config_override(v):
    schema = _load("evaluator_run_retry_request_schema.json")
    assert schema["additionalProperties"] is False
    route = "/api/v1beta/evaluator-runs/{run_id}/retry"
    assert v.validate_request(route, "POST", {}) == []
    assert v.validate_request(route, "POST", {"override_judge_config": None}) == []
    judge = {"instructions": "score it", "model_id": "gpt-4o", "context_type": "output"}
    assert v.validate_request(route, "POST", {"override_judge_config": judge}) == []
    assert v.validate_request(route, "POST", {"unknown": 1})  # additionalProperties false


def test_evaluator_execute_request_requires_target_and_accepts_judge_override(v):
    schema = _load("evaluator_execute_request_schema.json")
    assert set(schema["required"]) == {"target_type", "target_id"}
    route = "/api/v1beta/evaluators/{evaluator_id}/execute"
    assert v.validate_request(
        route, "POST", {"target_type": "observability_trace", "target_id": "t1"}
    ) == []
    assert v.validate_request(route, "POST", {"target_id": "t1"})  # missing target_type
    assert v.validate_request(
        route, "POST", {"target_type": "not-a-target", "target_id": "t1"}
    )


def test_evaluator_definition_create_request_extra_forbid_and_required(v):
    schema = _load("evaluator_definition_create_request_schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"name", "measure_id", "target_type", "judge_config"}
    route = "/api/v1beta/evaluators"
    judge = {"instructions": "score it", "model_id": "gpt-4o", "context_type": "output"}
    body = {
        "name": "e", "measure_id": "m", "target_type": "observability_trace",
        "judge_config": judge,
    }
    assert v.validate_request(route, "POST", body) == []
    assert v.validate_request(route, "POST", {**body, "id": "server-managed"})  # forbidden
    assert v.validate_request(route, "POST", {**body, "sampling_rate": 1.5})  # out of 0..1


def test_evaluator_update_request_all_optional_shares_judge_config_contract(v):
    schema = _load("evaluator_update_request_schema.json")
    assert "required" not in schema
    route = "/api/v1beta/evaluators/{evaluator_id}"
    assert v.validate_request(route, "PATCH", {"is_active": False}) == []
    incomplete_judge = {"instructions": "x"}  # missing model_id/context_type
    assert v.validate_request(route, "PATCH", {"judge_config": incomplete_judge})


def test_evaluator_backfill_result_required_fields():
    schema = _load("evaluator_backfill_result_schema.json")
    assert set(schema["required"]) == {
        "evaluator_id", "target_type", "submitted_count", "skipped_count",
        "skipped_target_ids", "items",
    }
    assert schema["properties"]["items"]["items"]["$ref"] == "./evaluator_run_schema.json"


def test_evaluator_list_response_wraps_definitions():
    schema = _load("evaluator_list_response_schema.json")
    assert set(schema["required"]) == {"items", "pagination"}
    assert schema["properties"]["items"]["items"]["$ref"] == "./evaluator_definition_schema.json"


# ---------------------------------------------------------------------------
# Trace feedback / collaboration / comments family
# ---------------------------------------------------------------------------

def test_trace_feedback_rating_is_closed_enum():
    schema = _load("trace_feedback_schema.json")
    assert set(schema["required"]) == {"id", "trace_id", "rating"}
    assert set(schema["properties"]["rating"]["enum"]) == {"up", "down"}


def test_trace_feedback_upsert_request_requires_rating_only(v):
    schema = _load("trace_feedback_upsert_request_schema.json")
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["rating"]
    route = "/api/v1beta/observability/traces/{trace_id}/feedback"
    assert v.validate_request(route, "PUT", {"rating": "up"}) == []
    assert v.validate_request(route, "PUT", {"rating": "sideways"})
    assert v.validate_request(route, "PUT", {})  # rating required
    assert v.validate_request(route, "PUT", {"rating": "up", "comment": "x" * 2001})


def test_trace_feedback_response_wraps_trace_feedback_schema():
    schema = _load("trace_feedback_response_schema.json")
    assert schema["allOf"] == [{"$ref": "./trace_feedback_schema.json"}]


def test_trace_collaboration_state_required_fields():
    schema = _load("trace_collaboration_state_schema.json")
    assert set(schema["required"]) == {"trace_id", "is_bookmarked", "is_published"}


def test_trace_collaboration_update_request_needs_at_least_one_field(v):
    schema = _load("trace_collaboration_update_request_schema.json")
    assert schema["additionalProperties"] is False
    route = "/api/v1beta/observability/traces/{trace_id}/collaboration"
    assert v.validate_request(route, "PATCH", {"is_bookmarked": True}) == []
    assert v.validate_request(route, "PATCH", {"is_published": False}) == []
    assert v.validate_request(route, "PATCH", {})  # anyOf: at least one of the two


def test_trace_comments_response_wraps_trace_comment_items():
    schema = _load("trace_comments_response_schema.json")
    assert set(schema["required"]) == {"trace_id", "items"}
    assert schema["properties"]["items"]["items"]["$ref"] == "./trace_comment_schema.json"


# ---------------------------------------------------------------------------
# Prompt link / reference family
# ---------------------------------------------------------------------------

def test_prompt_link_requires_prompt_name_and_trace_id():
    schema = _load("prompt_link_schema.json")
    assert set(schema["required"]) == {"prompt_name", "trace_id"}


def test_prompt_reference_is_closed_and_requires_name():
    schema = _load("prompt_reference_schema.json")
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["name"]
    assert schema["properties"]["label"]["maxLength"] == 64


# ---------------------------------------------------------------------------
# Review score / correlation-ids family
# ---------------------------------------------------------------------------

def test_review_score_create_request_requires_measure_and_target(v):
    schema = _load("review_score_create_request_schema.json")
    score_input = schema["definitions"]["ScoreInput"]
    assert set(score_input["properties"]["source"]["enum"]) == SCORE_SOURCES

    route = "/api/v1beta/scores"
    assert v.validate_request(
        route, "POST", {"measure_id": "m1", "trace_id": "t1", "numeric_value": 0.8}
    ) == []
    assert v.validate_request(route, "POST", {"trace_id": "t1"})  # no measure_id/name
    assert v.validate_request(route, "POST", {"measure_id": "m1"})  # no trace_id/target
    assert v.validate_request(
        route, "POST", {"scores": [{"measure_id": "m1", "trace_id": "t1"}]}
    ) == []
    assert v.validate_request(route, "POST", {"scores": []})  # minItems 1


def test_review_measure_summary_required_fields_and_value_type():
    schema = _load("review_measure_summary_schema.json")
    assert set(schema["required"]) == {"id", "label", "value_type", "categories", "target_types"}
    assert (
        schema["properties"]["value_type"]["$ref"]
        == "../measures/measure_schema.json#/definitions/MeasureValueType"
    )


def test_correlation_ids_is_closed_and_all_optional():
    schema = _load("correlation_ids_schema.json")
    assert schema["additionalProperties"] is False
    assert "required" not in schema
    assert set(schema["properties"]) == {
        "otel_trace_id", "otel_span_id", "otel_parent_span_id",
    }
