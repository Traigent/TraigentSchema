"""Tests for agent-build lifecycle schema contracts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import NamedTuple

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

LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS = {
    "artifact_states",
    "ranked_operations",
    "trust_label",
    "blocker_codes",
    "target_artifact",
    "validated_on_holdout",
    "tied_with_baseline",
    "score_stale",
    "unknown_freshness",
    "scored_needs_tuning",
    "smartopt_available",
    "LC_V1_DERIVED",
    "reason_code",
}

LIFECYCLE_STATE_SURFACE_TIER_2_STRUCTURED_FORBIDDEN_TOKENS = {
    "empty",
    "populated",
    "scored",
    "trusted",
    "degraded",
    "broken",
    "undefined",
    "defined",
    "audited",
    "noisy",
    "baseline",
    "optimizing",
    "optimized",
    "regressed",
    "blocked",
    "promotable",
    "unaudited",
}

# Phase 4A (Backend) introduced a server-internal artifact registry, cross-experiment
# rollups, and score provenance.  None of that vocabulary may appear in any PUBLIC
# TraigentSchema JSON schema, endpoint catalog, or example.
PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS = {
    "artifact_rollup",
    "artifact_registry",
    "artifact_fingerprint_version",
    "score_provenance",
    "scored_against",
    "current_fingerprint",
    "version_partition",
    "config_space_fp",
    "null_project_excluded",
    "aggregate_only_run",
    "rollup_mode",
    "artifact_rollup_cache",
}

OPTIMIZATION_TRACE_IP_FORBIDDEN_SUBSTRINGS = {
    "optimization_trace",
    "trace_step",
    "trace_signature",
    "step_signature",
    "lessons_learned",
    "inferred_optimization_rules",
    "avoid_list",
    "durable_rules",
    "hard_examples",
}

OPTIMIZATION_TRACE_INTERNAL_SCHEMA_FILES = {
    "optimization/optimization_trace_step_signature_schema.json",
    "optimization/optimization_trace_signature_schema.json",
}

ALLOWED_NEXT_STEPS_ACTION_CATEGORIES = {
    "expand_dataset",
    "refine_metric",
    "adjust_config_space",
    "rerun_larger_sample",
    "add_safety_gate",
    "compare_with_baseline",
    "promote_winner",
}

PRE_EXISTING_NON_LIFECYCLE_PUBLIC_TERMS = {
    ("optimization/promotion_policy_schema.json", "reason_code"),
    ("optimization/session_finalize_response_schema.json", "reason_code"),
    ("optimization/tvar_catalog_entry_schema.json", "baseline"),
    ("status_schema.json", "degraded"),
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


def _public_schema_documents() -> list[tuple[str, object]]:
    schemas_dir = get_schemas_dir()
    documents: list[tuple[str, object]] = []

    for path in sorted(schemas_dir.rglob("*.json")):
        with open(path, encoding="utf-8") as handle:
            documents.append((path.relative_to(schemas_dir).as_posix(), json.load(handle)))

    return documents


def _public_endpoint_catalog_documents() -> list[tuple[str, object]]:
    schemas_dir = get_schemas_dir()
    documents: list[tuple[str, object]] = []

    for path in sorted(schemas_dir.rglob("*_endpoints.json")):
        with open(path, encoding="utf-8") as handle:
            documents.append((path.relative_to(schemas_dir).as_posix(), json.load(handle)))

    return documents


def _iter_schema_ref_values(document: object) -> list[str]:
    refs: list[str] = []

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    refs.append(value)
                else:
                    visit(value)
        elif isinstance(node, list):
            for child in node:
                visit(child)

    visit(document)
    return refs


def _resolve_schema_ref(
    relative_document_path: str,
    ref: str,
) -> str | None:
    file_part = ref.partition("#")[0]
    if not file_part:
        return None

    schemas_dir = get_schemas_dir()
    if file_part.startswith("https://schemas.traigent.ai/"):
        target = schemas_dir / file_part.removeprefix("https://schemas.traigent.ai/")
    else:
        target = schemas_dir / Path(relative_document_path).parent / file_part

    schemas_root = schemas_dir.resolve()
    resolved_target = target.resolve()
    if not resolved_target.is_relative_to(schemas_root):
        return None
    if not resolved_target.exists() or not resolved_target.is_file():
        return None

    return resolved_target.relative_to(schemas_root).as_posix()


def _public_endpoint_referenced_schema_documents() -> list[tuple[str, object]]:
    schemas_dir = get_schemas_dir()
    documents: dict[str, object] = {}
    pending: list[str] = []

    for relative_path, document in _public_endpoint_catalog_documents():
        documents[relative_path] = document
        pending.append(relative_path)

    while pending:
        relative_path = pending.pop()
        document = documents[relative_path]
        for ref in _iter_schema_ref_values(document):
            resolved_relative_path = _resolve_schema_ref(relative_path, ref)
            if resolved_relative_path is None or resolved_relative_path in documents:
                continue
            with open(schemas_dir / resolved_relative_path, encoding="utf-8") as handle:
                documents[resolved_relative_path] = json.load(handle)
            pending.append(resolved_relative_path)

    return [(path, documents[path]) for path in sorted(documents)]


def _empty_optimization_trace_signature_section() -> dict[str, object]:
    return {
        "coverage": "none",
        "coverage_reason": "not_extracted",
        "source_counts": {},
        "source_refs": [],
        "redaction_applied": False,
        "items": [],
    }


def _valid_optimization_trace_step_signature_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "config_results": _empty_optimization_trace_signature_section(),
        "insights": _empty_optimization_trace_signature_section(),
        "lessons_learned": _empty_optimization_trace_signature_section(),
        "inferred_optimization_rules": _empty_optimization_trace_signature_section(),
        "benchmark_rules": _empty_optimization_trace_signature_section(),
        "evaluator_rules": _empty_optimization_trace_signature_section(),
        "stability": _empty_optimization_trace_signature_section(),
        "hard_examples": _empty_optimization_trace_signature_section(),
        "provenance": _empty_optimization_trace_signature_section(),
    }


def _valid_optimization_trace_config_result_atom() -> dict[str, object]:
    return {
        "config_ref": "config_7",
        "params": [
            {
                "param_id": "param.temperature",
                "value": "0.2",
            },
            {
                "param_id": "param.model",
                "value": "model:gpt-5.5",
            },
        ],
        "metrics": [
            {
                "metric_id": "metric.accuracy",
                "value": 0.91,
                "n": 12,
            }
        ],
        "rank": 1,
    }


def _valid_optimization_trace_lesson_atom() -> dict[str, object]:
    return {
        "scope_enum": "configuration",
        "subject_id": "param.temperature",
        "value_bucket": "bucket_low",
        "polarity_enum": "prefer",
        "metric_id": "metric.accuracy",
        "delta": 0.03,
        "n": 4,
        "confidence_enum": "medium",
        "limitation_enum": ["small_n"],
    }


def _valid_optimization_trace_rule_atom() -> dict[str, object]:
    return {
        "param_id": "param.temperature",
        "value_bucket": "bucket_low",
        "metric_id": "metric.latency_ms",
        "direction_enum": "decrease",
        "delta": -12.5,
        "n": 4,
        "polarity_enum": "prefer",
        "confidence_enum": "medium",
    }


def _valid_optimization_trace_hard_example_atom() -> dict[str, object]:
    return {
        "example_id": "ex_opaque_1",
        "failure_mode": "wrong_answer",
    }


class SchemaLeakFinding(NamedTuple):
    relative_path: str
    json_path: str
    surface: str
    value: str
    tier: str
    token: str


def _iter_raw_public_surface_strings(
    node: object,
    json_path: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], str]]:
    values: list[tuple[tuple[str, ...], str]] = []

    def add_string(path: tuple[str, ...], value: object) -> None:
        if isinstance(value, str):
            values.append((path, value))

    def add_nested_strings(path: tuple[str, ...], value: object) -> None:
        if isinstance(value, str):
            values.append((path, value))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                add_nested_strings((*path, str(index)), item)
        elif isinstance(value, dict):
            for key, item in value.items():
                add_nested_strings((*path, str(key)), item)

    if isinstance(node, dict):
        for key, value in node.items():
            child_path = (*json_path, str(key))
            add_string(child_path, key)
            add_nested_strings(child_path, value)

            values.extend(_iter_raw_public_surface_strings(value, child_path))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            values.extend(_iter_raw_public_surface_strings(child, (*json_path, str(index))))

    return values


def _iter_structured_public_surface_strings(
    node: object,
    json_path: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], str, str]]:
    values: list[tuple[tuple[str, ...], str, str]] = []

    def add_enum_or_const(
        path: tuple[str, ...],
        surface: str,
        value: object,
    ) -> None:
        if isinstance(value, str):
            values.append((path, surface, value))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                add_enum_or_const((*path, str(index)), surface, item)

    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            for property_name in properties:
                values.append(
                    ((*json_path, "properties", property_name), "property", property_name)
                )

        required = node.get("required")
        if isinstance(required, list):
            for index, property_name in enumerate(required):
                if isinstance(property_name, str):
                    values.append(((*json_path, "required", str(index)), "property", property_name))

        for key, value in node.items():
            child_path = (*json_path, str(key))
            if key == "enum":
                add_enum_or_const(child_path, "enum", value)
            elif key == "const":
                add_enum_or_const(child_path, "const", value)

            values.extend(_iter_structured_public_surface_strings(value, child_path))
    elif isinstance(node, list):
        for index, child in enumerate(node):
            values.extend(_iter_structured_public_surface_strings(child, (*json_path, str(index))))

    return values


def _is_allowed_next_steps_action_category(
    relative_path: str,
    json_path: tuple[str, ...],
    value: str,
) -> bool:
    return (
        relative_path == "analytics/next_steps_schema.json"
        and value in ALLOWED_NEXT_STEPS_ACTION_CATEGORIES
        and "category" in json_path
        and "enum" in json_path
    )


def _is_pre_existing_non_lifecycle_public_term(relative_path: str, token: str) -> bool:
    return (relative_path, token.lower()) in PRE_EXISTING_NON_LIFECYCLE_PUBLIC_TERMS


def _find_public_schema_lifecycle_leaks(
    relative_path: str,
    document: object,
) -> list[SchemaLeakFinding]:
    findings: set[SchemaLeakFinding] = set()

    for json_path, value in _iter_raw_public_surface_strings(document):
        value_lower = value.lower()
        for token in LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS:
            if _is_pre_existing_non_lifecycle_public_term(relative_path, token):
                continue
            if token.lower() in value_lower:
                findings.add(
                    SchemaLeakFinding(
                        relative_path,
                        "/".join(json_path),
                        "raw",
                        value,
                        "TIER-1",
                        token,
                    )
                )

    for json_path, surface, value in _iter_structured_public_surface_strings(document):
        for token in LIFECYCLE_STATE_SURFACE_TIER_2_STRUCTURED_FORBIDDEN_TOKENS:
            if _is_allowed_next_steps_action_category(relative_path, json_path, value):
                continue
            if _is_pre_existing_non_lifecycle_public_term(relative_path, token):
                continue
            if value.lower() == token:
                findings.add(
                    SchemaLeakFinding(
                        relative_path,
                        "/".join(json_path),
                        surface,
                        value,
                        "TIER-2",
                        token,
                    )
                )

    return sorted(
        findings,
        key=lambda finding: (
            finding.relative_path,
            finding.json_path,
            finding.tier,
            finding.token.lower(),
        ),
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

    def test_next_steps_without_posture_remains_valid(self, validator, valid_next_steps_payload):
        assert "posture" not in valid_next_steps_payload

        errors = validator.validate_json(valid_next_steps_payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_accepts_valid_posture(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["posture"] = {
            "summary_text": "Server summary redacted for client display.",
            "generated_at": "2026-06-27T12:00:00Z",
        }

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_rejects_unknown_posture_property(
        self,
        validator,
        valid_next_steps_payload,
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["posture"] = {
            "summary_text": "Server summary redacted for client display.",
            "generated_at": "2026-06-27T12:00:00Z",
            "readiness_cues": [],
        }

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any(
            "readiness_cues" in error or "Additional properties" in error for error in errors
        )

    @pytest.mark.parametrize("missing_field", ["summary_text", "generated_at"])
    def test_next_steps_rejects_incomplete_posture(
        self,
        validator,
        valid_next_steps_payload,
        missing_field,
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["posture"] = {
            "summary_text": "Server summary redacted for client display.",
            "generated_at": "2026-06-27T12:00:00Z",
        }
        del payload["posture"][missing_field]

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any(missing_field in error or "required" in error for error in errors)

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
    def test_analytics_endpoints_reference_remaining_response_schemas(self):
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

    def test_public_artifact_lifecycle_schema_and_endpoint_are_not_exposed(self):
        schemas_dir = get_schemas_dir()
        assert not list(schemas_dir.rglob("*artifact_lifecycle_schema.json"))

        lifecycle_paths: list[tuple[str, str]] = []
        lifecycle_schema_refs: list[str] = []
        for relative_path, endpoints in _public_endpoint_catalog_documents():
            paths = endpoints.get("paths", {})
            if isinstance(paths, dict):
                lifecycle_paths.extend(
                    (relative_path, path) for path in paths if "/lifecycle" in path
                )
            if "artifact_lifecycle_schema" in json.dumps(endpoints):
                lifecycle_schema_refs.append(relative_path)

        assert lifecycle_paths == []
        assert lifecycle_schema_refs == []


class TestClientFacingSchemaLeakGuard:
    @pytest.mark.parametrize(
        "schema_name",
        [
            "next_steps_schema",
            "curation_advice_schema",
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

    def test_public_schema_surface_does_not_expose_artifact_state_vocabulary(self):
        findings: list[SchemaLeakFinding] = []
        for relative_path, document in _public_schema_documents():
            findings.extend(_find_public_schema_lifecycle_leaks(relative_path, document))

        assert findings == []

    def test_artifact_state_canary_detects_tier_1_raw_lifecycle_leaks(self):
        copied_public_schema = {
            "type": "object",
            "properties": {
                "safe_summary": {
                    "type": "string",
                    "description": "Leaked raw artifact_states token from an internal copy.",
                }
            },
        }

        findings = _find_public_schema_lifecycle_leaks(
            "analytics/copied_schema.json",
            copied_public_schema,
        )

        assert any(
            finding.tier == "TIER-1"
            and finding.token == "artifact_states"
            and finding.value == "Leaked raw artifact_states token from an internal copy."
            for finding in findings
        )

    def test_artifact_state_canary_detects_tier_2_enum_lifecycle_leaks(self):
        copied_public_schema = {
            "type": "object",
            "properties": {
                "safe_status": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": ["scored"],
                    },
                }
            },
        }

        findings = _find_public_schema_lifecycle_leaks(
            "analytics/copied_schema.json",
            copied_public_schema,
        )

        assert any(
            finding.tier == "TIER-2"
            and finding.surface == "enum"
            and finding.token == "scored"
            and finding.value == "scored"
            for finding in findings
        )

    def test_artifact_state_canary_allows_public_next_steps_action_categories(self):
        next_steps_category_schema = {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": sorted(ALLOWED_NEXT_STEPS_ACTION_CATEGORIES),
                }
            },
        }

        findings = _find_public_schema_lifecycle_leaks(
            "analytics/next_steps_schema.json",
            next_steps_category_schema,
        )

        assert findings == []


class TestOptimizationTraceInternalSignatureSchemas:
    def test_signature_schema_files_exist_but_are_not_public_endpoint_refs(self):
        schemas_dir = get_schemas_dir()
        missing = sorted(
            relative_path
            for relative_path in OPTIMIZATION_TRACE_INTERNAL_SCHEMA_FILES
            if not (schemas_dir / relative_path).exists()
        )
        assert missing == []

        endpoint_ref_hits: list[tuple[str, str, str]] = []
        endpoint_string_hits: list[tuple[str, str, str]] = []

        for catalog_relative_path, catalog in _public_endpoint_catalog_documents():
            string_values = _json_string_values(catalog)
            for ref in _iter_schema_ref_values(catalog):
                resolved_relative_path = _resolve_schema_ref(catalog_relative_path, ref)
                if resolved_relative_path in OPTIMIZATION_TRACE_INTERNAL_SCHEMA_FILES:
                    endpoint_ref_hits.append(
                        (catalog_relative_path, ref, resolved_relative_path)
                    )

            for internal_relative_path in OPTIMIZATION_TRACE_INTERNAL_SCHEMA_FILES:
                internal_file_name = Path(internal_relative_path).name
                for value in string_values:
                    if internal_relative_path in value or internal_file_name in value:
                        endpoint_string_hits.append(
                            (catalog_relative_path, internal_relative_path, value)
                        )

        assert endpoint_ref_hits == []
        assert endpoint_string_hits == []

    def test_optimization_trace_ip_terms_do_not_appear_in_public_schema_string_values(self):
        leaks: list[tuple[str, str, str]] = []

        for relative_path, document in _public_endpoint_referenced_schema_documents():
            matches = _forbidden_substring_matches(
                _json_string_values(document),
                OPTIMIZATION_TRACE_IP_FORBIDDEN_SUBSTRINGS,
            )
            leaks.extend((relative_path, value, token) for value, token in matches)

        assert leaks == [], (
            "Optimization trace internal vocabulary found in public schema surface:\n"
            + "\n".join(
                f"  {path}  value={value!r}  token={token!r}"
                for path, value, token in sorted(leaks)
            )
        )

    def test_minimal_valid_step_signature_instance_validates(self, validator):
        errors = validator.validate_json(
            _valid_optimization_trace_step_signature_payload(),
            "optimization_trace_step_signature_schema",
        )

        assert errors == []

    def test_step_signature_accepts_content_free_atoms(self, validator):
        payload = _valid_optimization_trace_step_signature_payload()

        lessons = payload["lessons_learned"]
        rules = payload["inferred_optimization_rules"]
        hard_examples = payload["hard_examples"]
        assert isinstance(lessons, dict)
        assert isinstance(rules, dict)
        assert isinstance(hard_examples, dict)

        lessons["items"] = [_valid_optimization_trace_lesson_atom()]
        rules["items"] = [_valid_optimization_trace_rule_atom()]
        hard_examples["items"] = [_valid_optimization_trace_hard_example_atom()]

        errors = validator.validate_json(payload, "optimization_trace_step_signature_schema")

        assert errors == []

    def test_step_signature_accepts_config_result_atoms(self, validator):
        payload = _valid_optimization_trace_step_signature_payload()
        config_results = payload["config_results"]
        assert isinstance(config_results, dict)

        config_results["items"] = [_valid_optimization_trace_config_result_atom()]

        errors = validator.validate_json(payload, "optimization_trace_step_signature_schema")

        assert errors == []

    def test_step_signature_rejects_config_result_values_with_spaces(self, validator):
        payload = _valid_optimization_trace_step_signature_payload()
        config_results = payload["config_results"]
        assert isinstance(config_results, dict)

        atom = _valid_optimization_trace_config_result_atom()
        params = atom["params"]
        assert isinstance(params, list)
        first_param = params[0]
        assert isinstance(first_param, dict)
        first_param["value"] = "raw prompt value"
        config_results["items"] = [atom]

        errors = validator.validate_json(payload, "optimization_trace_step_signature_schema")

        assert errors

    @pytest.mark.parametrize("forbidden_key", ["statement", "evidence"])
    @pytest.mark.parametrize(
        ("section_name", "atom"),
        [
            ("config_results", _valid_optimization_trace_config_result_atom()),
            ("insights", _valid_optimization_trace_lesson_atom()),
            ("lessons_learned", _valid_optimization_trace_lesson_atom()),
            ("inferred_optimization_rules", _valid_optimization_trace_rule_atom()),
            ("benchmark_rules", _valid_optimization_trace_rule_atom()),
            ("evaluator_rules", _valid_optimization_trace_rule_atom()),
            ("stability", _valid_optimization_trace_lesson_atom()),
            ("hard_examples", _valid_optimization_trace_hard_example_atom()),
            ("provenance", _valid_optimization_trace_lesson_atom()),
        ],
    )
    def test_step_signature_rejects_free_text_atom_fields_anywhere(
        self,
        validator,
        section_name,
        atom,
        forbidden_key,
    ):
        payload = _valid_optimization_trace_step_signature_payload()
        section = payload[section_name]
        assert isinstance(section, dict)

        atom_with_forbidden_field = copy.deepcopy(atom)
        atom_with_forbidden_field[forbidden_key] = (
            "raw prose must not fit the atom contract"
        )
        section["items"] = [atom_with_forbidden_field]

        errors = validator.validate_json(payload, "optimization_trace_step_signature_schema")

        assert errors

    def test_minimal_valid_trace_signature_instance_validates(self, validator):
        errors = validator.validate_json(
            {
                "schema_version": "1.0.0",
                "covered_step_count": 0,
            },
            "optimization_trace_signature_schema",
        )

        assert errors == []


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


def test_no_phase4_rollup_registry_terms_in_public_schemas() -> None:
    """Phase 4A (Backend) internal artifact registry / cross-experiment rollup vocabulary
    must not appear in any public JSON schema, endpoint catalog, or example.

    Scans the same public surface as
    ``test_public_schema_surface_does_not_expose_artifact_state_vocabulary``:
    every ``*.json`` file under the schemas directory (via ``_public_schema_documents``),
    which already includes all ``*_endpoints.json`` endpoint catalogs.  All string values
    at every depth are checked case-insensitively against
    ``PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS`` using
    ``_iter_raw_public_surface_strings``.
    """
    leaks: list[tuple[str, str, str]] = []

    for relative_path, document in _public_schema_documents():
        for json_path, value in _iter_raw_public_surface_strings(document):
            value_lower = value.lower()
            for token in PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS:
                if token in value_lower:
                    leaks.append((relative_path, "/".join(json_path), token))

    assert leaks == [], (
        "Phase 4A rollup/registry vocabulary found in public schema surface:\n"
        + "\n".join(
            f"  {path}  @  {json_path}  →  {token!r}" for path, json_path, token in sorted(leaks)
        )
    )
