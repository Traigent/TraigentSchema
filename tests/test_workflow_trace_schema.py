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
        "error_message": None if False else "boom",
        "decision_reason": "score below threshold",
        "input_data": {"prompt": "hi"},
        "output_data": {"text": "hello"},
        "metadata": {"tag": "x"},
    }
    payload = {"spans": {**_span_batch(), "spans": [span]}}
    assert v.validate_json(payload, SCHEMA) == []


def test_span_type_and_status_are_free_strings():
    """The SDK sources span_type from an OTel attribute and accepts arbitrary
    status strings, so the contract must not enum-lock them."""
    v = SchemaValidator()
    span = {**_valid_span(), "span_type": "custom_kind", "status": "WEIRD_BUT_VALID"}
    payload = {"spans": {**_span_batch(), "spans": [span]}}
    assert v.validate_json(payload, SCHEMA) == []


def test_span_batch_requires_trace_and_config_run():
    v = SchemaValidator()
    for missing in ("trace_id", "configuration_run_id", "spans"):
        batch = _span_batch()
        del batch[missing]
        assert v.validate_json({"spans": batch}, SCHEMA), f"missing {missing} should fail"


def test_ingest_endpoint_wires_workflow_trace_schema():
    with open(
        get_schemas_dir() / "execution" / "execution_endpoints.json", encoding="utf-8"
    ) as handle:
        spec = json.load(handle)
    body = spec["paths"]["/api/v1/traces/ingest"]["post"]["requestBody"]
    ref = body["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("workflow_trace_schema.json"), ref
