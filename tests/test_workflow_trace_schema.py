"""Contract tests for the v1 workflow-trace ingest schema (TraigentSchema#64).

Models POST /api/v1/traces/ingest, whose sole producer is the Python SDK
traigent/integrations/observability/workflow_traces.py (WorkflowGraphPayload +
the spans wrapper carrying SpanPayload). Payloads below mirror the SDK to_dict()
outputs field-for-field.
"""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA = "workflow_trace_schema"
TRIAL_RESPONSE_SCHEMA = "workflow_trace_trial_response_schema"


def _valid_span():
    # Mirrors SpanPayload.to_dict() with all required keys.
    return {
        "span_id": "0123456789abcdef",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "configuration_run_id": "cr-1",
        "span_name": "plan_step",
        "span_type": "node",
        "start_time": "2026-06-02T00:00:00Z",
        "status": "COMPLETED",
        "input_tokens": 12,
        "output_tokens": 7,
        "cost_usd": 0.0034,
    }


def _valid_graph():
    # Mirrors WorkflowGraphPayload.to_dict().
    return {
        "experiment_id": "exp-1",
        "nodes": [
            {
                "id": "n1",
                "type": "node",
                "display_name": "Planner",
                "tunable_params": ["temperature"],
                "metadata": {},
            }
        ],
        "edges": [{"from_node": "n1", "to_node": "n2", "edge_type": "default"}],
        "loops": [],
        "sdk_version": "1.0.0",
    }


def _span_batch():
    return {
        "trace_id": "0123456789abcdef0123456789abcdef",
        "configuration_run_id": "cr-1",
        "spans": [_valid_span()],
    }


def _valid_trial_response():
    return {
        "trial_id": "trial-1",
        "configuration_run_id": "cr-1",
        "trace_id": "trace-1",
        "quality_score": None,
        "total_latency_ms": 123.4,
        "total_cost_usd": 0.0123,
        "start_time": "2026-06-02T00:00:00Z",
        "end_time": None,
        "status": "COMPLETED",
    }


def test_accepts_graph_and_spans():
    v = SchemaValidator()
    payload = {"graph": _valid_graph(), "spans": _span_batch()}
    assert v.validate_json(payload, SCHEMA) == []


def test_accepts_graph_only_and_spans_only():
    v = SchemaValidator()
    assert v.validate_json({"graph": _valid_graph()}, SCHEMA) == []
    assert v.validate_json({"spans": _span_batch()}, SCHEMA) == []


def test_rejects_empty_body():
    v = SchemaValidator()
    assert v.validate_json({}, SCHEMA)


def test_rejects_unknown_top_level_field():
    v = SchemaValidator()
    assert v.validate_json({"graph": _valid_graph(), "traces": []}, SCHEMA)


def test_span_requires_core_fields():
    v = SchemaValidator()
    for missing in (
        "span_id",
        "trace_id",
        "configuration_run_id",
        "span_name",
        "span_type",
        "start_time",
        "status",
        "input_tokens",
        "output_tokens",
        "cost_usd",
    ):
        span = _valid_span()
        del span[missing]
        payload = {"spans": {**_span_batch(), "spans": [span]}}
        assert v.validate_json(payload, SCHEMA), f"missing span.{missing} should fail"


def test_span_accepts_langgraph_and_content_fields():
    v = SchemaValidator()
    span = {
        **_valid_span(),
        "parent_span_id": "fedcba9876543210",
        "node_id": "n1",
        "end_time": "2026-06-02T00:00:01Z",
        "error_message": "boom",
        "decision_reason": "score below threshold",
        "input_data": {"prompt": "hi"},
        "output_data": {"text": "hello"},
        "metadata": {"tag": "x"},
    }
    payload = {"spans": {**_span_batch(), "spans": [span]}}
    assert v.validate_json(payload, SCHEMA) == []


def test_span_type_is_free_string_and_status_is_enum_bound():
    """span_type is sourced from an OTel attribute and remains a free string.
    span status is now enum-bound to ObservabilitySpanStatus (TraigentSchema#175):
    canonical UPPER vocab {RUNNING, COMPLETED, FAILED, REJECTED, TIMEOUT, CANCELLED}.
    """
    v = SchemaValidator()
    # span_type is still a free string - custom values are accepted
    span_custom_type = {**_valid_span(), "span_type": "custom_kind", "status": "RUNNING"}
    payload = {"spans": {**_span_batch(), "spans": [span_custom_type]}}
    assert v.validate_json(payload, SCHEMA) == [], "custom span_type should still be accepted"

    # span status is now enum-bound - non-canonical values are rejected
    span_bad_status = {**_valid_span(), "status": "WEIRD_BUT_VALID"}
    payload_bad = {"spans": {**_span_batch(), "spans": [span_bad_status]}}
    errors = v.validate_json(payload_bad, SCHEMA)
    assert len(errors) == 1 and "WEIRD_BUT_VALID" in errors[0], (
        f"non-canonical span status should be rejected (TraigentSchema#175): {errors}"
    )

    # all canonical UPPER values are accepted
    for status in ("RUNNING", "COMPLETED", "FAILED", "REJECTED", "TIMEOUT", "CANCELLED"):
        span_ok = {**_valid_span(), "status": status}
        payload_ok = {"spans": {**_span_batch(), "spans": [span_ok]}}
        assert v.validate_json(payload_ok, SCHEMA) == [], f"canonical span status {status!r} should be accepted"


def test_span_batch_requires_trace_and_config_run():
    v = SchemaValidator()
    for missing in ("trace_id", "configuration_run_id", "spans"):
        batch = _span_batch()
        del batch[missing]
        assert v.validate_json({"spans": batch}, SCHEMA), f"missing {missing} should fail"


def test_span_configuration_run_id_documents_trial_id_linkage():
    with open(
        get_schemas_dir() / "execution" / "workflow_trace_schema.json",
        encoding="utf-8",
    ) as handle:
        spec = json.load(handle)

    for definition_name in ("SpanBatch", "SpanPayload"):
        field = spec["definitions"][definition_name]["properties"]["configuration_run_id"]
        assert "trial_id" in field["description"]
        assert "MUST equal" in field["description"]
        assert field["x-reference"].endswith(
            "evaluation/configuration_run_schema.json#/properties/id"
        )
        assert field["x-equal-to"].endswith(
            "session_submit_results_request_schema.json#/properties/trial_id"
        )


def test_ingest_endpoint_wires_workflow_trace_schema():
    with open(
        get_schemas_dir() / "execution" / "execution_endpoints.json", encoding="utf-8"
    ) as handle:
        spec = json.load(handle)
    body = spec["paths"]["/api/v1/traces/ingest"]["post"]["requestBody"]
    ref = body["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("workflow_trace_schema.json"), ref


def test_trial_response_accepts_required_nullable_quality_score():
    v = SchemaValidator()
    assert v.validate_json(_valid_trial_response(), TRIAL_RESPONSE_SCHEMA) == []


def test_trial_response_documents_trial_and_configuration_run_equivalence():
    with open(
        get_schemas_dir() / "execution" / "workflow_trace_trial_response_schema.json",
        encoding="utf-8",
    ) as handle:
        spec = json.load(handle)

    props = spec["properties"]
    assert "MUST treat them as equal" in spec["$comment"]
    assert props["trial_id"]["x-equal-to"] == "#/properties/configuration_run_id"
    assert props["configuration_run_id"]["x-equal-to"] == "#/properties/trial_id"
    assert "configuration_run_id" in props["trial_id"]["description"]
    assert "trial_id" in props["configuration_run_id"]["description"]


def test_trial_response_accepts_optional_spans():
    v = SchemaValidator()
    payload = {
        **_valid_trial_response(),
        "quality_score": 0.91,
        "spans": [
            {
                "id": "span-1",
                "trace_id": "trace-1",
                "configuration_run_id": "cr-1",
                "span_name": "Generator",
            }
        ],
    }
    assert v.validate_json(payload, TRIAL_RESPONSE_SCHEMA) == []


def test_trial_response_rejects_missing_required_field():
    v = SchemaValidator()
    payload = _valid_trial_response()
    del payload["quality_score"]
    assert v.validate_json(payload, TRIAL_RESPONSE_SCHEMA)


def test_trial_response_rejects_string_quality_score():
    v = SchemaValidator()
    payload = {**_valid_trial_response(), "quality_score": "0.91"}
    assert v.validate_json(payload, TRIAL_RESPONSE_SCHEMA)


def test_trial_response_rejects_additional_properties():
    v = SchemaValidator()
    payload = {**_valid_trial_response(), "weighted_score": 0.91}
    assert v.validate_json(payload, TRIAL_RESPONSE_SCHEMA)
