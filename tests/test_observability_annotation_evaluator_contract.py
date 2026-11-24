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


# Backend: AnnotationQueueCreateRequest / AnnotationQueueUpdateRequest, description
# max_length=2000 (annotation_queue.py).
@pytest.mark.parametrize(
    ("file_name", "route", "method"),
    [
        ("annotation_queue_create_request_schema.json", "/api/v1beta/annotation-queues", "POST"),
        (
            "annotation_queue_update_request_schema.json",
            "/api/v1beta/annotation-queues/{queue_id}",
            "PATCH",
        ),
    ],
)
def test_annotation_queue_description_cap_matches_backend(v, file_name, route, method):
    assert _load(file_name)["properties"]["description"]["maxLength"] == 2000
    base = {"name": "Q1", "target_type": "observability_trace", "measure_ids": ["m1"]}
    body = base if method == "POST" else {}
    assert v.validate_request(route, method, {**body, "description": "d" * 2000}) == []
    assert v.validate_request(route, method, {**body, "description": "d" * 2001})


# Backend: AnnotationQueueUpdateRequest has extra="forbid" (annotation_queue.py) and
# ensure_update_has_fields rejects an update with no fields (annotation_queue.py).
def test_annotation_queue_update_rejects_empty_body_and_unknown_keys(v):
    schema = _load("annotation_queue_update_request_schema.json")
    assert schema["additionalProperties"] is False
    assert schema["minProperties"] == 1

    route = "/api/v1beta/annotation-queues/{queue_id}"
    assert v.validate_request(route, "PATCH", {})
    assert v.validate_request(route, "PATCH", {"stauts": "paused"})
    assert v.validate_request(route, "PATCH", {"status": "paused", "bogus": 1})


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


# #584: the fields the backend request models accept (extra="forbid") in
# the backend's evaluation request models:
# EvaluatorDefinitionUpdateRequest, EvaluatorExecuteRequest (via
# EvaluationTargetRef), EvaluatorBackfillRequest.
BACKEND_UPDATE_FIELDS = {
    "name", "description", "measure_id", "target_type", "judge_config",
    "sampling_rate", "target_filters", "is_active",
}
BACKEND_EXECUTE_FIELDS = {"target_type", "target_id", "override_judge_config"}
BACKFILL_ROUTE = "/api/v1beta/evaluators/{evaluator_id}/backfill"


def test_evaluator_update_request_declares_no_field_the_backend_forbids(v):
    schema = _load("evaluator_update_request_schema.json")
    assert set(schema["properties"]) <= BACKEND_UPDATE_FIELDS
    assert "primary_measure_id" not in schema["properties"]
    assert set(schema["properties"]["target_type"]["enum"]) == TARGET_TYPES | {None}
    route = "/api/v1beta/evaluators/{evaluator_id}"
    assert v.validate_request(route, "PATCH", {"target_type": "observability_trace"}) == []
    assert v.validate_request(route, "PATCH", {"measure_id": "accuracy"}) == []


def test_evaluator_execute_request_declares_no_field_the_backend_forbids(v):
    schema = _load("evaluator_execute_request_schema.json")
    assert set(schema["properties"]) <= BACKEND_EXECUTE_FIELDS
    assert "source" not in schema["properties"]
    route = "/api/v1beta/evaluators/{evaluator_id}/execute"
    assert v.validate_request(
        route, "POST", {"target_type": "observability_trace", "target_id": "tr_1"}
    ) == []


def test_evaluator_backfill_request_is_a_closed_ref_matching_the_backend_model(v):
    endpoints = _load("observability_endpoints.json")
    body = endpoints["paths"][BACKFILL_ROUTE]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert body == {"$ref": "./evaluator_backfill_request_schema.json"}
    schema = _load("evaluator_backfill_request_schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "target_type", "filters", "limit", "skip_existing_scores",
    }
    assert set(schema["properties"]["target_type"]["enum"]) == TARGET_TYPES | {None}
    assert schema["properties"]["limit"]["minimum"] == 1
    assert schema["properties"]["limit"]["maximum"] == 500
    assert v.validate_request(BACKFILL_ROUTE, "POST", {}) == []
    assert v.validate_request(
        BACKFILL_ROUTE, "POST", {"target_type": "observability_trace", "limit": 10}
    ) == []
    assert v.validate_request(BACKFILL_ROUTE, "POST", {"target_ids": ["tr_1"]})
    assert v.validate_request(BACKFILL_ROUTE, "POST", {"force": True})
    assert v.validate_request(BACKFILL_ROUTE, "POST", {"limit": 501})


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


def test_evaluator_backfill_result_declares_skip_reason_breakdown(v):
    # #648: the backend's evaluation service returns skipped_reasons
    # (target_id -> reason) and skipped_reason_counts (reason -> count).
    schema = _load("evaluator_backfill_result_schema.json")
    reasons = schema["properties"]["skipped_reasons"]
    assert reasons["type"] == "object"
    assert reasons["additionalProperties"] == {"type": "string"}
    counts = schema["properties"]["skipped_reason_counts"]
    assert counts["type"] == "object"
    assert counts["additionalProperties"] == {"type": "integer", "minimum": 1}
    body = {
        "evaluator_id": "ev_1", "target_type": "observability_trace",
        "submitted_count": 1, "skipped_count": 2,
        "skipped_target_ids": ["tr_2", "tr_3"], "items": [],
        "skipped_reasons": {"tr_2": "already_scored", "tr_3": "already_scored"},
        "skipped_reason_counts": {"already_scored": 2},
    }
    assert v.validate_json(body, "evaluator_backfill_result_schema") == []


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


# ---------------------------------------------------------------------------
# Evaluator target_filters: closed contract (environment, release, name, tags)
# ---------------------------------------------------------------------------

_CREATE_BODY = {
    "name": "e", "measure_id": "m", "target_type": "observability_trace",
    "judge_config": {"instructions": "score it", "model_id": "gpt-4o", "context_type": "output"},
}


def _filters_errors(v, filters):
    return v.validate_request("/api/v1beta/evaluators", "POST", {**_CREATE_BODY, "target_filters": filters})


@pytest.mark.parametrize("filters", [
    {},
    {"environment": ["prod"]},
    {"release": ["v1", "v2"]},
    {"name": ["checkout"]},
    {"tags": ["a", "b"]},
    {"environment": ["prod"], "release": ["v1"], "name": ["n"], "tags": ["t"]},
    {"environment": [f"e{i}" for i in range(20)]},
    {"release": [f"r{i}" for i in range(20)]},
    {"name": [f"n{i}" for i in range(20)]},
    {"tags": [f"t{i}" for i in range(20)]},
    {"environment": ["x" * 64], "release": ["x" * 128], "name": ["x" * 255], "tags": ["x" * 128]},
])
def test_target_filters_valid(v, filters):
    assert _filters_errors(v, filters) == []


@pytest.mark.parametrize("filters", [
    {"status": ["running"]},
    {"environment": "prod"},
    {"environment": []},
    {"environment": [""]},
    {"environment": ["x" * 65]},
    {"release": ["x" * 129]},
    {"name": ["x" * 256]},
    {"tags": [f"t{i}" for i in range(21)]},
    {"environment": [f"e{i}" for i in range(21)]},
    {"release": [f"r{i}" for i in range(21)]},
    {"name": [f"n{i}" for i in range(21)]},
    {"tags": ["a", "a"]},
    {"tags": [1]},
])
def test_target_filters_invalid(v, filters):
    assert _filters_errors(v, filters)


def test_target_filters_update_and_response_share_contract(v):
    route = "/api/v1beta/evaluators/{evaluator_id}"
    for m in ("PATCH", "PUT"):
        if f"{m}:{route}" in v._endpoint_schemas:
            assert v.validate_request(route, m, {"target_filters": {"tags": ["a"]}}) == []
            assert v.validate_request(route, m, {"target_filters": {"status": ["x"]}})
    upd = _load("evaluator_update_request_schema.json")["properties"]["target_filters"]
    resp = _load("evaluator_definition_schema.json")["properties"]["target_filters"]
    create = _load("evaluator_definition_create_request_schema.json")["properties"]["target_filters"]
    assert resp == {"$ref": "#/definitions/TargetFilters"}
    assert upd == create == {"$ref": "./evaluator_definition_schema.json#/definitions/TargetFilters"}
    tf = _load("evaluator_definition_schema.json")["definitions"]["TargetFilters"]
    assert tf["additionalProperties"] is False
    assert set(tf["properties"]) == {"environment", "release", "name", "tags"}


def test_target_filters_update_nullability_regressions(v):
    route = "/api/v1beta/evaluators/{evaluator_id}"
    assert v.validate_request(route, "PATCH", {"name": "renamed"}) == []  # omitted
    assert v.validate_request(route, "PATCH", {"target_filters": {}}) == []
    assert v.validate_request(route, "PATCH", {"target_filters": None})  # not nullable


def test_evaluator_definition_response_carries_target_filters(v):
    resp = {
        "id": "ev1", "name": "e", "measure_id": "m", "target_type": "observability_trace",
        "judge_config": _CREATE_BODY["judge_config"],
        "target_filters": {"environment": ["prod"], "tags": ["a", "b"]},
    }
    assert v.validate_json(resp, "evaluator_definition_schema") == []
    assert v.validate_json({**resp, "target_filters": {"status": ["x"]}}, "evaluator_definition_schema")
    assert v.validate_json({**resp, "target_filters": {"tags": []}}, "evaluator_definition_schema")


# #584: the reproduction bodies from the issue, validated through the backend contract.
# Backend EvaluatorDefinitionUpdateRequest and EvaluatorExecuteRequest (via EvaluationTargetRef)
# are extra="forbid" (the backend's evaluation request models), and
# EvaluatorDefinitionUpdateRequest.ensure_update_has_fields rejects an empty body. The request schemas must reject the same bodies.
@pytest.mark.parametrize(
    ("route", "method", "body"),
    [
        ("/api/v1beta/evaluators/{evaluator_id}", "PATCH", {"primary_measure_id": "accuracy"}),
        (
            "/api/v1beta/evaluators/{evaluator_id}/execute",
            "POST",
            {"target_type": "observability_trace", "target_id": "tr_1", "source": "manual"},
        ),
        ("/api/v1beta/evaluators/{evaluator_id}", "PATCH", {}),
    ],
)
def test_evaluator_bodies_the_backend_rejects_fail_schema(v, route, method, body):
    assert v.validate_request(route, method, body)


def test_evaluator_update_and_execute_schemas_are_closed():
    update = _load("evaluator_update_request_schema.json")
    assert update["additionalProperties"] is False
    assert update["minProperties"] == 1
    assert _load("evaluator_execute_request_schema.json")["additionalProperties"] is False


def test_evaluator_update_and_execute_valid_bodies_still_pass(v):
    update = "/api/v1beta/evaluators/{evaluator_id}"
    execute = "/api/v1beta/evaluators/{evaluator_id}/execute"
    assert v.validate_request(update, "PATCH", {"measure_id": "accuracy"}) == []
    assert v.validate_request(update, "PATCH", {"target_type": "observability_trace"}) == []
    assert v.validate_request(update, "PATCH", {"is_active": False}) == []
    assert v.validate_request(
        execute, "POST", {"target_type": "observability_trace", "target_id": "tr_1"}
    ) == []
    assert v.validate_request(
        execute,
        "POST",
        {"target_type": "observability_trace", "target_id": "tr_1", "override_judge_config": None},
    ) == []


# #640: AnnotationQueueCreateRequest is extra="forbid" (the backend's
# annotation queue request model) and the route validates the raw body
# with model_validate (annotation_queue_routes.py), so unknown keys get a 422.
def test_annotation_queue_create_rejects_unknown_keys(v):
    schema = _load("annotation_queue_create_request_schema.json")
    assert schema["additionalProperties"] is False

    route = "/api/v1beta/annotation-queues"
    body = {"name": "Q1", "target_type": "observability_trace", "measure_ids": ["m1"]}
    assert v.validate_request(route, "POST", body) == []
    assert v.validate_request(route, "POST", {**body, "bogus": 1})
    assert v.validate_request(route, "POST", {**body, "measure_id": "m1"})


# Backend EvaluatorBackfillRequest.target_type is EvaluationTargetType | None
# (evaluation_ops.py)
# and the service falls back to the evaluator's own target_type when it is None
# (evaluation_ops_service.py). The route accepts an explicit null.
def test_evaluator_backfill_accepts_null_target_type(v):
    assert v.validate_request(BACKFILL_ROUTE, "POST", {"target_type": None}) == []
    assert v.validate_request(BACKFILL_ROUTE, "POST", {"target_type": "bogus"})


# #723: the update bodies must refuse what the service refuses. A body whose only field is a
# null description is a 422 on both routes (annotation queue: annotation_queue.py strips
# blank strings to None and ensure_update_has_fields rejects an empty result; evaluator:
# evaluation_ops.py dumps with exclude_none). Each update schema carries a root anyOf
# that requires one usable field.
def test_annotation_queue_update_rejects_null_or_blank_only_bodies(v):
    schema = _load("annotation_queue_update_request_schema.json")
    assert schema["minProperties"] == 1
    assert "anyOf" in schema

    route = "/api/v1beta/annotation-queues/{queue_id}"
    assert v.validate_request(route, "PATCH", {"description": None})
    assert v.validate_request(route, "PATCH", {"name": "   "})
    assert v.validate_request(route, "PATCH", {"description": "  "})
    assert v.validate_request(route, "PATCH", {})

    assert v.validate_request(route, "PATCH", {"description": None, "name": "q"}) == []
    assert v.validate_request(route, "PATCH", {"name": "   ", "status": "paused"}) == []
    assert v.validate_request(route, "PATCH", {"measure_ids": [" "]}) == []


def test_evaluator_update_rejects_null_description_only_body(v):
    schema = _load("evaluator_update_request_schema.json")
    assert schema["minProperties"] == 1
    assert "anyOf" in schema

    route = "/api/v1beta/evaluators/{evaluator_id}"
    assert v.validate_request(route, "PATCH", {"description": None})
    assert v.validate_request(route, "PATCH", {})

    assert v.validate_request(route, "PATCH", {"description": None, "name": "q"}) == []
    assert v.validate_request(route, "PATCH", {"description": "  "}) == []


# Parity with EvaluatorDefinitionUpdateRequest (backend evaluation_ops.py):
# target_type is `EvaluationTargetType | None` and a null target_type means "unchanged"
# (dumped with exclude_none). So a null target_type alongside another field is accepted,
# and a body whose only field is a null target_type is refused (422 "at least one field").
def test_evaluator_update_null_target_type_means_unchanged(v):
    route = "/api/v1beta/evaluators/{evaluator_id}"
    assert v.validate_request(route, "PATCH", {"target_type": None, "is_active": True}) == []
    assert v.validate_request(route, "PATCH", {"target_type": None})
    assert v.validate_request(route, "PATCH", {"target_type": "observability_trace"}) == []
    assert v.validate_request(route, "PATCH", {"target_type": "not-a-target"})

def test_evaluator_update_anyof_target_type_enum_matches_the_property_enum() -> None:
    """The anyOf branch repeats the enum (the maxLength lint needs it): it must not drift."""
    schema = _load("evaluator_update_request_schema.json")
    branch = next(b for b in schema["anyOf"] if b.get("required") == ["target_type"])
    assert set(branch["properties"]["target_type"]["enum"]) == TARGET_TYPES
