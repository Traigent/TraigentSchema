"""Tests for agent-build lifecycle schema contracts."""

from __future__ import annotations

import copy
import json

import pytest

from traigent_schema import AnalyticsValidator, SchemaValidator
from traigent_schema.utils import get_schemas_dir

LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS = {
    "difficulty",
    "informativeness",
    "irt",
    "fisher",
    "expected_information_gain",
    "threshold",
    "formula",
    "example_ids",
    "task_ids",
    "seed_signal",
}


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
def valid_artifact_lifecycle_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "experiment_run_id": "exp_123",
        "caveat": "server-derived; internal decision details withheld",
        "phase": "LC_V1_DERIVED",
        "smartopt_available": True,
        "artifact_states": [
            {
                "artifact": "dataset",
                "state": "scored",
                "trust_label": "trusted",
                "blockers": [],
                "evidence": ["scoring_completed", "quality_cleared"],
            },
            {
                "artifact": "evaluator",
                "state": "audited",
                "trust_label": "trusted",
                "blockers": [],
                "evidence": ["evaluator_active", "audit_completed"],
            },
            {
                "artifact": "agent",
                "state": "baseline",
                "trust_label": "unknown",
                "blockers": ["agent_not_optimized"],
                "evidence": [],
            },
        ],
        "next_step": {
            "operation": "run_optimization",
            "target_artifact": "agent",
            "priority": "high",
            "reason_code": "needs_optimization",
            "command_template": "traigent optimize --run {experiment_run_id}",
            "evidence_level": "medium",
        },
        "ranked_operations": [
            {
                "operation": "run_optimization",
                "target_artifact": "agent",
                "priority": "high",
                "reason_code": "needs_optimization",
                "command_template": "traigent optimize --run {experiment_run_id}",
                "evidence_level": "medium",
            },
            {
                "operation": "run_holdout",
                "target_artifact": "agent",
                "priority": "medium",
                "reason_code": "needs_holdout",
                "command_template": "traigent holdout --run {experiment_run_id}",
                "evidence_level": "low",
            },
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


def _schema_enum_and_example_values(schema: object) -> set[str]:
    values: set[str] = set()

    def add_value(value: object) -> None:
        if isinstance(value, str):
            values.add(value)
        elif isinstance(value, list):
            for item in value:
                add_value(item)

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"const", "enum", "example", "examples"}:
                    add_value(value)
                visit(value)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(schema)
    return values


def _json_string_values(document: object) -> set[str]:
    values: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, str):
            values.add(node)
        elif isinstance(node, dict):
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(document)
    return values


def _forbidden_substring_matches(
    values: set[str],
    forbidden_substrings: set[str],
) -> list[tuple[str, str]]:
    return sorted(
        (value, forbidden)
        for value in values
        for forbidden in forbidden_substrings
        if forbidden in value.lower()
    )


class TestNextStepsSchema:
    def test_valid_next_steps_payload(self, validator, valid_next_steps_payload):
        errors = validator.validate_json(valid_next_steps_payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_analytics_validator_lists_next_steps_schema(self, analytics_validator):
        assert "next_steps_schema" in analytics_validator.available_schemas

    def test_analytics_validator_validates_next_steps(
        self, analytics_validator, valid_next_steps_payload
    ):
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


class TestArtifactLifecycleSchema:
    def test_valid_artifact_lifecycle_payload(self, validator, valid_artifact_lifecycle_payload):
        errors = validator.validate_json(
            valid_artifact_lifecycle_payload,
            "artifact_lifecycle_schema",
        )
        assert errors == [], f"Unexpected errors: {errors}"

    def test_analytics_validator_lists_artifact_lifecycle_schema(self, analytics_validator):
        assert "artifact_lifecycle_schema" in analytics_validator.available_schemas

    def test_analytics_validator_validates_artifact_lifecycle(
        self,
        analytics_validator,
        valid_artifact_lifecycle_payload,
    ):
        errors = analytics_validator.validate_artifact_lifecycle(valid_artifact_lifecycle_payload)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_artifact_lifecycle_rejects_bad_state_enum(
        self,
        validator,
        valid_artifact_lifecycle_payload,
    ):
        payload = copy.deepcopy(valid_artifact_lifecycle_payload)
        payload["artifact_states"][0]["state"] = "audited"

        errors = validator.validate_json(payload, "artifact_lifecycle_schema")
        assert errors
        assert any("state" in error or "audited" in error or "enum" in error for error in errors)

    def test_artifact_lifecycle_rejects_bad_operation_enum(
        self,
        validator,
        valid_artifact_lifecycle_payload,
    ):
        payload = copy.deepcopy(valid_artifact_lifecycle_payload)
        payload["next_step"]["operation"] = "custom_operation"

        errors = validator.validate_json(payload, "artifact_lifecycle_schema")
        assert errors
        assert any("operation" in error or "enum" in error for error in errors)

    def test_artifact_lifecycle_rejects_unknown_top_level_property(
        self,
        validator,
        valid_artifact_lifecycle_payload,
    ):
        payload = copy.deepcopy(valid_artifact_lifecycle_payload)
        payload["unexpected"] = "not allowed"

        errors = validator.validate_json(payload, "artifact_lifecycle_schema")
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

        lifecycle_response = endpoints["paths"][
            "/api/v1/analytics/experiments/{experiment_run_id}/lifecycle"
        ]["get"]["responses"]["200"]
        assert (
            lifecycle_response["content"]["application/json"]["schema"]["$ref"]
            == "./artifact_lifecycle_schema.json"
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
        [
            "next_steps_schema",
            "curation_advice_schema",
            "artifact_lifecycle_schema",
        ],
    )
    def test_client_safe_schema_property_names_do_not_expose_signals(self, validator, schema_name):
        schema = validator._schemas[schema_name]
        forbidden = {
            *LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
            "ambiguity",
            "discriminative",
            "composite_score",
        }

        matches = _forbidden_substring_matches(_schema_property_names(schema), forbidden)
        assert matches == []

    @pytest.mark.parametrize(
        "schema_name",
        [
            "next_steps_schema",
            "curation_advice_schema",
            "artifact_lifecycle_schema",
        ],
    )
    def test_client_safe_schema_enum_and_example_values_do_not_expose_signals(
        self,
        validator,
        schema_name,
    ):
        schema = validator._schemas[schema_name]

        matches = _forbidden_substring_matches(
            _schema_enum_and_example_values(schema),
            LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
        )
        assert matches == []

    def test_artifact_lifecycle_schema_string_values_do_not_expose_signals(self, validator):
        schema = validator._schemas["artifact_lifecycle_schema"]

        matches = _forbidden_substring_matches(
            _json_string_values(schema),
            LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
        )
        assert matches == []

    def test_valid_artifact_lifecycle_fixture_does_not_expose_signals(
        self,
        valid_artifact_lifecycle_payload,
    ):
        matches = _forbidden_substring_matches(
            _json_string_values(valid_artifact_lifecycle_payload),
            LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
        )
        assert matches == []

    def test_artifact_lifecycle_ip_guard_scans_schema_descriptions_and_fixture_values(
        self,
        validator,
        valid_artifact_lifecycle_payload,
    ):
        schema = copy.deepcopy(validator._schemas["artifact_lifecycle_schema"])
        schema["description"] = "Do not expose fisher details."
        schema_matches = _forbidden_substring_matches(
            _json_string_values(schema),
            LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
        )
        assert ("Do not expose fisher details.", "fisher") in schema_matches

        payload = copy.deepcopy(valid_artifact_lifecycle_payload)
        payload["caveat"] = "Do not expose seed_signal values."
        payload_matches = _forbidden_substring_matches(
            _json_string_values(payload),
            LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
        )
        assert ("Do not expose seed_signal values.", "seed_signal") in payload_matches


def test_dataset_schema_remains_superset_of_evaluation_set() -> None:
    """Guard the inlined dataset schema against drift from evaluation_set_schema.

    dataset_schema.json was converted from an ``allOf`` alias into an explicit
    object (the referenced schema's ``additionalProperties: false`` makes
    allOf-extension impossible), so this invariant is no longer structural:
    every property and every required field of evaluation_set_schema must stay
    accepted by dataset_schema. If evaluation_set_schema gains a field, add it
    to dataset_schema too.
    """
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "datasets" / "dataset_schema.json") as fh:
        dataset = json.load(fh)
    with open(schemas_dir / "datasets" / "evaluation_set_schema.json") as fh:
        evaluation_set = json.load(fh)

    dataset_props = set(dataset["properties"])
    evaluation_props = set(evaluation_set.get("properties", {}))
    missing = evaluation_props - dataset_props
    assert not missing, (
        "dataset_schema.json lost evaluation_set_schema properties: "
        f"{sorted(missing)} — re-sync the inlined copy."
    )
    assert sorted(dataset.get("required", [])) == sorted(evaluation_set.get("required", [])), (
        "dataset_schema required set drifted from evaluation_set_schema"
    )
