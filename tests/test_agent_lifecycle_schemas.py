"""Tests for agent-build lifecycle schema contracts."""

from __future__ import annotations

import copy
import json

import pytest

from traigent_schema import AnalyticsValidator, SchemaValidator
from traigent_schema.utils import get_schemas_dir


@pytest.fixture
def validator() -> SchemaValidator:
    return SchemaValidator()


@pytest.fixture
def analytics_validator() -> AnalyticsValidator:
    return AnalyticsValidator()


@pytest.fixture
def valid_next_steps_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "experiment_run_id": "exp_123",
        "caveat": "Recommendations are advisory and should be reviewed before promotion.",
        "summary": {
            "winner_config_ref": "config_7",
            "confidence_label": "medium",
            "trade_off_note": "Winner improves quality with a modest latency trade-off.",
        },
        "next_steps": [
            {
                "id": "step_1",
                "category": "expand_dataset",
                "priority": 1,
                "rationale": "Add more coverage before promoting the winning configuration.",
                "action": {
                    "kind": "cli",
                    "command_template": "traigent dataset expand --experiment {experiment_run_id}",
                },
                "evidence_level": "medium",
            }
        ],
    }


@pytest.fixture
def valid_curation_advice_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "experiment_run_id": "exp_123",
        "caveat": "Advice is category-level and does not expose per-example scoring signals.",
        "advice": [
            {
                "category": "add_diverse_examples",
                "affected_count": 12,
                "rationale": "Add examples that cover underrepresented task variants.",
            }
        ],
    }


@pytest.fixture
def valid_agent_playbook_payload() -> dict[str, object]:
    return {
        "playbook_version": "1.0.0",
        "agent": {
            "name": "support-agent",
            "entrypoint": "app.agent:run",
            "agent_type": "rag",
        },
        "stages": {
            "dataset": {
                "status": "pinned",
                "pinned_at": "2026-06-12T09:00:00Z",
                "pin": {
                    "dataset_ref": "traigent://datasets/dataset_123",
                    "revision": 1,
                    "holdout_ref": "data/holdout.jsonl",
                },
            },
            "metric": {
                "status": "pinned",
                "pin": {
                    "measure_type": "quality",
                    "metric_name": "answer_quality",
                    "metric_output_type": "continuous",
                },
            },
            "evaluator": {
                "status": "pinned",
                "pin": {
                    "evaluation_method": "deterministic",
                    "evaluator_ref": "evals.support:score",
                    "audit_ref": "tests/test_evals.py",
                },
            },
            "optimize": {
                "status": "pinned",
                "pin": {
                    "configuration_space_ref": "configs.support:space",
                    "objectives": ["answer_quality"],
                    "last_run_id": "run_123",
                },
            },
            "gate": {
                "status": "pinned",
                "pin": {
                    "baseline_artifact": ".traigent/baseline.json",
                    "budgets": {
                        "max_cost_per_run": 1.25,
                        "max_latency_p95_ms": 800,
                    },
                    "policy": {
                        "alpha": 0.05,
                        "min_effect": 0.01,
                    },
                },
            },
        },
        "provenance": {
            "created_by": "codex",
            "created_at": "2026-06-12T09:00:00Z",
            "recommendations_used": ["rec_expand_dataset"],
        },
    }


def _valid_dataset_payload() -> dict[str, object]:
    return {
        "id": "dataset_123",
        "name": "support_qa_dataset",
        "label": "Support QA Dataset",
        "description": "Evaluation dataset for support-style Q&A flows",
        "type": "input-output",
        "agent_type": "qa",
        "examples_count": 1,
        "generator_config": {
            "id": "generator_123",
            "dataset_id": "dataset_123",
            "model_parameters_id": "model_parameters_123",
            "instructions": "Generate realistic customer support questions",
            "context_type": "text",
            "context_source": "dataset",
        },
        "evaluator_config": {
            "id": "evaluator_123",
            "dataset_id": "dataset_123",
            "model_parameters_id": "model_parameters_123",
            "instructions": "Evaluate answer quality against the reference output",
            "context_type": "text",
            "context_source": "dataset",
        },
    }


def _schema_property_names(schema: object) -> set[str]:
    names: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            properties = node.get("properties")
            if isinstance(properties, dict):
                names.update(properties.keys())
                for child in properties.values():
                    visit(child)

            for key in ("items", "additionalProperties"):
                visit(node.get(key))

            for key in ("definitions", "$defs"):
                children = node.get(key)
                if isinstance(children, dict):
                    for child in children.values():
                        visit(child)

            for key in ("allOf", "anyOf", "oneOf"):
                children = node.get(key)
                if isinstance(children, list):
                    for child in children:
                        visit(child)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(schema)
    return names


class TestNextStepsSchema:
    def test_valid_next_steps_payload(self, validator, valid_next_steps_payload):
        errors = validator.validate_json(valid_next_steps_payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_analytics_validator_lists_next_steps_schema(self, analytics_validator):
        assert "next_steps_schema" in analytics_validator.available_schemas

    def test_analytics_validator_validates_next_steps(self, analytics_validator, valid_next_steps_payload):
        errors = analytics_validator.validate_next_steps(valid_next_steps_payload)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_rejects_bad_category_enum(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["next_steps"][0]["category"] = "inspect_signal_scores"

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("category" in error or "enum" in error for error in errors)

    def test_next_steps_rejects_negative_priority(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["next_steps"][0]["priority"] = -1

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("priority" in error or "minimum" in error for error in errors)

    def test_next_steps_rejects_missing_caveat(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        del payload["caveat"]

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("caveat" in error or "required" in error for error in errors)

    def test_next_steps_rejects_additional_properties(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["next_steps"][0]["action"]["unexpected"] = "not allowed"

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("unexpected" in error or "Additional properties" in error for error in errors)


class TestCurationAdviceSchema:
    def test_valid_curation_advice_payload(self, validator, valid_curation_advice_payload):
        errors = validator.validate_json(valid_curation_advice_payload, "curation_advice_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_analytics_validator_lists_curation_advice_schema(self, analytics_validator):
        assert "curation_advice_schema" in analytics_validator.available_schemas

    def test_analytics_validator_validates_curation_advice(
        self,
        analytics_validator,
        valid_curation_advice_payload,
    ):
        errors = analytics_validator.validate_curation_advice(valid_curation_advice_payload)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_curation_advice_rejects_bad_category_enum(
        self,
        validator,
        valid_curation_advice_payload,
    ):
        payload = copy.deepcopy(valid_curation_advice_payload)
        payload["advice"][0]["category"] = "show_ranked_examples"

        errors = validator.validate_json(payload, "curation_advice_schema")
        assert errors
        assert any("category" in error or "enum" in error for error in errors)

    def test_curation_advice_rejects_negative_affected_count(
        self,
        validator,
        valid_curation_advice_payload,
    ):
        payload = copy.deepcopy(valid_curation_advice_payload)
        payload["advice"][0]["affected_count"] = -1

        errors = validator.validate_json(payload, "curation_advice_schema")
        assert errors
        assert any("affected_count" in error or "minimum" in error for error in errors)

    def test_curation_advice_rejects_missing_caveat(
        self,
        validator,
        valid_curation_advice_payload,
    ):
        payload = copy.deepcopy(valid_curation_advice_payload)
        del payload["caveat"]

        errors = validator.validate_json(payload, "curation_advice_schema")
        assert errors
        assert any("caveat" in error or "required" in error for error in errors)

    def test_curation_advice_rejects_additional_properties(
        self,
        validator,
        valid_curation_advice_payload,
    ):
        payload = copy.deepcopy(valid_curation_advice_payload)
        payload["advice"][0]["example_ids"] = ["ex_abc12345_0"]

        errors = validator.validate_json(payload, "curation_advice_schema")
        assert errors
        assert any("example_ids" in error or "Additional properties" in error for error in errors)


class TestAgentPlaybookSchema:
    def test_agent_playbook_schema_is_discovered(self, validator):
        assert "agent_playbook_schema" in validator.available_schemas

    def test_valid_agent_playbook_payload(self, validator, valid_agent_playbook_payload):
        errors = validator.validate_json(valid_agent_playbook_payload, "agent_playbook_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_agent_playbook_rejects_bad_stage_status_enum(
        self,
        validator,
        valid_agent_playbook_payload,
    ):
        payload = copy.deepcopy(valid_agent_playbook_payload)
        payload["stages"]["dataset"]["status"] = "stale"

        errors = validator.validate_json(payload, "agent_playbook_schema")
        assert errors
        assert any("status" in error or "enum" in error for error in errors)

    def test_agent_playbook_rejects_additional_properties(
        self,
        validator,
        valid_agent_playbook_payload,
    ):
        payload = copy.deepcopy(valid_agent_playbook_payload)
        payload["agent"]["unexpected"] = "not allowed"

        errors = validator.validate_json(payload, "agent_playbook_schema")
        assert errors
        assert any("unexpected" in error or "Additional properties" in error for error in errors)


class TestDatasetVersioning:
    def test_existing_style_dataset_payload_still_validates(self, validator):
        errors = validator.validate_json(_valid_dataset_payload(), "dataset_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_dataset_revision_and_parent_dataset_id_validate(self, validator):
        payload = _valid_dataset_payload()
        payload["revision"] = 1
        payload["parent_dataset_id"] = "dataset_original"

        errors = validator.validate_json(payload, "dataset_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_dataset_revision_zero_fails(self, validator):
        payload = _valid_dataset_payload()
        payload["revision"] = 0

        errors = validator.validate_json(payload, "dataset_schema")
        assert errors
        assert any("revision" in error or "minimum" in error for error in errors)


class TestLifecycleEndpointRegistration:
    def test_analytics_endpoints_reference_lifecycle_response_schemas(self):
        with open(
            get_schemas_dir() / "analytics" / "analytics_endpoints.json",
            encoding="utf-8",
        ) as handle:
            endpoints = json.load(handle)

        next_steps_response = endpoints["paths"][
            "/api/v1/analytics/experiments/{experiment_run_id}/next-steps"
        ]["get"]["responses"]["200"]
        assert (
            next_steps_response["content"]["application/json"]["schema"]["$ref"]
            == "./next_steps_schema.json"
        )

        curation_response = endpoints["paths"][
            "/api/v1/analytics/example-scoring/{experiment_run_id}/curation-advice"
        ]["get"]["responses"]["200"]
        assert (
            curation_response["content"]["application/json"]["schema"]["$ref"]
            == "./curation_advice_schema.json"
        )


class TestClientFacingSchemaLeakGuard:
    @pytest.mark.parametrize(
        "schema_name",
        ["next_steps_schema", "curation_advice_schema"],
    )
    def test_client_safe_schema_property_names_do_not_expose_signals(self, validator, schema_name):
        schema = validator._schemas[schema_name]
        forbidden = {
            "difficulty",
            "informativeness",
            "ambiguity",
            "discriminative",
            "composite_score",
            "example_ids",
        }

        assert _schema_property_names(schema).isdisjoint(forbidden)
