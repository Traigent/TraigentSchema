"""Contracts for content-free trace analysis, durable issues, and variants."""

from __future__ import annotations

import copy
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

NOW = "2026-07-09T10:00:00Z"
DIGEST = "a" * 64


def _load(name: str) -> dict:
    path = get_schemas_dir() / "observability" / name
    return json.loads(path.read_text(encoding="utf-8"))


def _fingerprint() -> dict:
    return {
        "value": DIGEST,
        "algorithm": "sha256",
        "fingerprint_spec_version": "structural-v1",
        "canonical_event_count": 3,
        "root_count": 1,
    }


def _derivation(deriver: str = "issue_detection") -> dict:
    return {
        "derivation_run_id": "derive-1",
        "deriver": deriver,
        "deriver_version": "1.0.0",
        "input_revision": 1,
        "input_digest": "b" * 64,
        "derived_at": NOW,
    }


def _issue() -> dict:
    return {
        "id": "issue-1",
        "project_id": "project-1",
        "detector_family": "explicit_error",
        "problem_signature": "c" * 64,
        "signature_spec_version": "error-signature-v1",
        "state": "open",
        "severity": "error",
        "occurrence_count": 1,
        "affected_trace_count": 1,
        "reopen_count": 0,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "created_at": NOW,
        "updated_at": NOW,
        "state_changed_at": NOW,
        "superseded_by_issue_id": None,
        "version": 1,
    }


def _occurrence() -> dict:
    return {
        "id": "occurrence-1",
        "issue_id": "issue-1",
        "project_id": "project-1",
        "trace_id": "trace-1",
        "variant_id": "variant-1",
        "detector_rule_version": "explicit-error-v3",
        "detected_at": NOW,
        "fingerprint": _fingerprint(),
        "derivation": _derivation(),
        "evidence": [
            {
                "evidence_type": "explicit_error",
                "trace_id": "trace-1",
                "observation_id": "span-3",
                "start_observation_id": None,
                "end_observation_id": None,
                "start_sequence_index": None,
                "end_sequence_index": None,
                "repeat_count": None,
                "error_category": "timeout",
            }
        ],
    }


def test_execution_context_is_strict_and_accepted_at_ingest() -> None:
    validator = SchemaValidator(contract="backend")
    context = {
        "schema_version": "1.0",
        "agent_id": "agent-1",
        "release_id": "release-7",
        "code_revision": "abc123",
        "intervention_id": "fix-tool-timeout",
    }
    payload = {"traces": [{"id": "trace-1", "name": "run", "execution_context": context}]}
    assert validator.validate_json(payload, "observability_ingest_request_schema") == []

    bad = copy.deepcopy(payload)
    bad["traces"][0]["execution_context"]["metadata"] = {"prompt": "must not leak"}
    assert validator.validate_json(bad, "observability_ingest_request_schema")


def test_issue_identity_excludes_rule_version_but_occurrence_requires_it() -> None:
    validator = SchemaValidator(contract="backend")
    issue_schema = _load("issue_schema.json")
    assert "detector_rule_version" not in issue_schema["properties"]
    assert validator.validate_json(_issue(), "issue_schema") == []

    bad_issue = {**_issue(), "detector_rule_version": "must-not-be-identity"}
    assert validator.validate_json(bad_issue, "issue_schema")

    occurrence = _occurrence()
    assert validator.validate_json(occurrence, "issue_occurrence_schema") == []
    occurrence.pop("detector_rule_version")
    assert validator.validate_json(occurrence, "issue_occurrence_schema")


def test_human_issue_state_updates_cannot_open_or_reopen_issues() -> None:
    validator = SchemaValidator(contract="backend")
    path = "/api/v1beta/projects/project-1/observability/issues/issue-1"
    assert (
        validator.validate_request(
            path,
            "PATCH",
            {"state": "resolved", "reason": "fixed", "expected_version": 1},
        )
        == []
    )
    assert validator.validate_request(
        path,
        "PATCH",
        {"state": "open", "reason": "fixed", "expected_version": 1},
    )
    assert validator.validate_request(
        path,
        "PATCH",
        {"state": "ignored", "reason": "fixed", "expected_version": 1},
    )


def test_variant_lineage_and_content_free_projection_validate() -> None:
    validator = SchemaValidator(contract="backend")
    variant = {
        "id": "variant-1",
        "project_id": "project-1",
        "display_label": "Variant 0A1B2C3D",
        "fingerprint": _fingerprint(),
        "trace_count": 2,
        "first_seen_at": NOW,
        "last_seen_at": NOW,
        "representative_trace_id": "trace-1",
        "boundary_trace_ids": ["trace-2"],
        "status_counts": {"running": 0, "completed": 1, "failed": 1, "rejected": 0},
        "derivation": _derivation("variant_assignment"),
    }
    assert validator.validate_json(variant, "trace_variant_schema") == []

    lineage = {
        "project_id": "project-1",
        "trace_id": "trace-1",
        "execution_context": {
            "schema_version": "1.0",
            "agent_id": "agent-1",
            "intervention_id": "intervention-1",
        },
        "links": [
            {
                "resource_type": "intervention",
                "resource_id": "intervention-1",
                "resource_version": None,
                "relationship": "changed_by",
            }
        ],
        "generated_at": NOW,
    }
    assert validator.validate_json(lineage, "observability_lineage_response_schema") == []

    projection = {
        "project_id": "project-1",
        "trace_id": "trace-1",
        "projection_mode": "content_free",
        "content_included": False,
        "items": [
            {
                "observation_id": "span-1",
                "parent_observation_id": None,
                "semantic_kind": "tool_call",
                "status": "failed",
                "sequence_index": 0,
                "depth": 0,
                "duration_ms": 250,
                "normalized_tool_id": "search",
                "normalized_model_id": None,
                "input_tokens": 0,
                "output_tokens": 0,
                "cost_usd": 0,
                "is_critical_path": True,
                "repeat_group_id": None,
            }
        ],
        "next_cursor": None,
        "has_more": False,
        "generated_at": NOW,
    }
    assert validator.validate_json(projection, "trace_projection_response_schema") == []
    projection["items"][0]["input_data"] = "content-canary"
    assert validator.validate_json(projection, "trace_projection_response_schema")


def test_cohort_comparison_request_is_bounded_and_project_is_not_body_controlled() -> None:
    validator = SchemaValidator(contract="backend")
    cohort = {
        "start_time": "2026-07-01T00:00:00Z",
        "end_time": NOW,
        "trace_statuses": ["completed", "failed"],
        "variant_ids": [],
        "issue_ids": [],
        "environment": "production",
        "sample_limit": 1000,
    }
    payload = {
        "reference": cohort,
        "comparison": {**cohort, "environment": "canary"},
        "metrics": ["quality_score", "cost_usd", "latency_ms"],
    }
    path = "/api/v1beta/projects/project-1/observability/analysis/cohorts/compare"
    assert validator.validate_request(path, "POST", payload) == []

    too_large = copy.deepcopy(payload)
    too_large["comparison"]["sample_limit"] = 5001
    assert validator.validate_request(path, "POST", too_large)
    assert validator.validate_request(path, "POST", {**payload, "project_id": "other"})


def test_project_observability_endpoint_inventory_and_response_bindings() -> None:
    spec = _load("observability_endpoints.json")
    paths = spec["paths"]
    base = "/api/v1beta/projects/{project_id}/observability"
    expected_gets = {
        f"{base}/traces": "trace_list_response_schema.json",
        f"{base}/traces/{{trace_id}}": "trace_schema.json",
        f"{base}/traces/{{trace_id}}/observations": "trace_observations_response_schema.json",
        f"{base}/traces/{{trace_id}}/comments": "trace_comments_response_schema.json",
        f"{base}/sessions": "session_list_response_schema.json",
        f"{base}/sessions/{{session_id}}": "session_schema.json",
        f"{base}/users/{{user_id}}": "user_summary_schema.json",
        f"{base}/issues": "issue_list_response_schema.json",
        f"{base}/issues/{{issue_id}}": "issue_detail_response_schema.json",
        f"{base}/variants": "trace_variant_list_response_schema.json",
        f"{base}/variants/{{variant_id}}": "trace_variant_detail_response_schema.json",
        f"{base}/traces/{{trace_id}}/analysis": "trace_analysis_response_schema.json",
        f"{base}/traces/{{trace_id}}/projection": "trace_projection_response_schema.json",
        f"{base}/traces/{{trace_id}}/lineage": "observability_lineage_response_schema.json",
        f"{base}/analysis/tools": "tool_analysis_response_schema.json",
    }
    for path, schema_name in expected_gets.items():
        response_schema = paths[path]["get"]["responses"]["200"]["content"]["application/json"][
            "schema"
        ]
        assert response_schema["$ref"].endswith(schema_name), path

    projection_parameters = {
        item["name"]: item["schema"]
        for item in paths[f"{base}/traces/{{trace_id}}/projection"]["get"]["parameters"]
    }
    assert projection_parameters["limit"]["maximum"] == 500
