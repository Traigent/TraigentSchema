import json
from pathlib import Path

from jsonschema import Draft202012Validator


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "traigent_schema"
    / "schemas"
    / "observability"
    / "evaluation_dataset_evaluator_plan_schema.json"
)


def _load_schema() -> dict:
    with open(SCHEMA_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def test_evaluation_dataset_evaluator_plan_schema_accepts_minimal_plan():
    schema = _load_schema()
    payload = {
        "plan_id": "evalplan_012345abcdef",
        "spec_version": "2026-05-21.v1",
        "status": "operator_review_required",
        "evaluation_dataset_id": "eval_dataset_001",
        "source_trace_id": "trace_001",
        "evaluators": [
            {
                "evaluator_key": "expected_output_alignment",
                "display_name": "Expected Output Alignment",
                "measure_key": "expected_output_alignment",
                "target_type": "evaluation_dataset_example",
                "target_field": "expected_output",
                "priority": "required",
                "rationale": "The generated example has expected output that should be judged.",
            }
        ],
        "execution": {
            "mode": "manual_review_before_run",
            "can_autorun": False,
            "suggested_sample_size": 1,
        },
        "warnings": ["Operator review required before creating or running evaluators."],
        "provenance": {
            "source": "trace_to_evaluation_dataset_example",
            "signals": ["trace_io", "expected_output_present"],
        },
    }

    Draft202012Validator(schema).validate(payload)


def test_evaluation_dataset_evaluator_plan_schema_rejects_autorun():
    schema = _load_schema()
    payload = {
        "plan_id": "evalplan_012345abcdef",
        "spec_version": "2026-05-21.v1",
        "status": "operator_review_required",
        "evaluation_dataset_id": "eval_dataset_001",
        "source_trace_id": "trace_001",
        "evaluators": [
            {
                "evaluator_key": "expected_output_alignment",
                "display_name": "Expected Output Alignment",
                "measure_key": "expected_output_alignment",
                "target_type": "evaluation_dataset_example",
                "target_field": "expected_output",
                "priority": "required",
                "rationale": "The generated example has expected output that should be judged.",
            }
        ],
        "execution": {
            "mode": "manual_review_before_run",
            "can_autorun": True,
            "suggested_sample_size": 1,
        },
        "warnings": [],
        "provenance": {
            "source": "trace_to_evaluation_dataset_example",
            "signals": ["trace_io"],
        },
    }

    errors = list(Draft202012Validator(schema).iter_errors(payload))

    assert errors
    assert any(list(error.path) == ["execution", "can_autorun"] for error in errors)
