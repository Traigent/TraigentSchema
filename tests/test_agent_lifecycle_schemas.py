"""Tests for agent-build lifecycle schema contracts."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import NamedTuple

import pytest
from jsonschema import Draft7Validator

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
    "score_evaluation_set",
    "curate_evaluation_set",
    "audit_evaluator_quality",
    "improve_evaluator",
    "adjust_configuration_space",
    "run_optimization",
    "validate_holdout",
    "wait",
}

PRE_EXISTING_NON_LIFECYCLE_PUBLIC_TERMS = {
    ("optimization/promotion_policy_schema.json", "reason_code"),
    ("optimization/session_finalize_response_schema.json", "reason_code"),
    ("optimization/tvar_catalog_entry_schema.json", "baseline"),
    ("status_schema.json", "degraded"),
    # funnel.v1 onboarding-funnel `stage` enum: "baseline" is the funnel stage at
    # which a lead's baseline is measured — the onboarding funnel step, not the
    # artifact-state lifecycle "baseline" state this guard protects.
    ("onboarding/onboarding_funnel_event_schema.json", "baseline"),
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


def _valid_attribution() -> dict[str, object]:
    """Well-formed optional attribution provenance banner (#352)."""
    return {
        "source": "traigent",
        "label": "Traigent",
        "headline": "Traigent recommends expanding the dataset before promotion.",
        "why": "Coverage is thin relative to the objective, which limits confidence.",
        "basis": ["optimization_history", "parameter_importance"],
        "engine": "policy",
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


def _valid_optimization_trace_insight_atom() -> dict[str, object]:
    return {
        "rule_id": "winner_primary_metric",
        "severity": "info",
        "atom_type": "config_metric_winner",
        "metric_id": "metric.accuracy",
        "config_ref": "config_7",
        "value": 0.91,
        "related_config_refs": ["config_3"],
        "n": 12,
    }


def _valid_optimization_trace_stability_atom() -> dict[str, object]:
    return {
        "metric_id": "metric.accuracy",
        "mean": 0.88,
        "stddev": 0.04,
        "n": 12,
        "coefficient_of_variation": 0.045,
    }


def _valid_optimization_trace_provenance_atom() -> dict[str, object]:
    return {
        "data_hash": "hash:abc123",
        "extractor_version": "m2.0",
        "report_id": "report:run_7",
        "source_counts": {
            "aggregated_results": 2,
            "raw_example_results": 12,
            "insights": 1,
        },
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


_AGENT_LIFECYCLE_COMMON_SCHEMA_PATH = "agent_lifecycle_record/agent_lifecycle_common_schema.json"


def _is_allowed_agent_lifecycle_reason_codes_occurrence(
    relative_path: str,
    json_path: tuple[str, ...],
    value: str,
    token: str,
) -> bool:
    """ALR-1101 P1-4 repair: `reason_codes` is a real, closed-vocabulary public
    property name on every axis type in agent_lifecycle_common_schema.json (the
    bounded_reason_vocabulary rule). Unlike a blanket per-file exemption -- which
    would silently disable the `reason_code` leak check for every raw string in
    this file, forever, including future ALR-11xx edits -- this allows the
    literal string ONLY in the two JSON Schema positions it can legitimately
    appear: as a `properties` key, or as a `required` list entry. A
    `reason_code`-flavored string anywhere else in this file (a description, a
    title, a stray sibling key) still fails. Modelled on
    `_is_allowed_next_steps_action_category` above, which scopes by `json_path`
    rather than blanket-exempting a whole document.
    """
    if token != "reason_code":
        return False
    if relative_path != _AGENT_LIFECYCLE_COMMON_SCHEMA_PATH:
        return False
    if value != "reason_codes":
        return False
    if len(json_path) >= 2 and json_path[-2] == "properties" and json_path[-1] == "reason_codes":
        return True
    return len(json_path) >= 2 and json_path[-2] == "required"


def _find_public_schema_lifecycle_leaks(
    relative_path: str,
    document: object,
) -> list[SchemaLeakFinding]:
    findings: set[SchemaLeakFinding] = set()

    for json_path, value in _iter_raw_public_surface_strings(document):
        value_lower = value.lower()
        for token in LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS:
            if _is_allowed_agent_lifecycle_reason_codes_occurrence(
                relative_path, json_path, value, token
            ):
                continue
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

    def test_next_steps_accepts_authoritative_decision_and_guidance_joins(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_123",
            "category": "audit_evaluator_quality",
            "source_engine": "policy",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Audit evaluation quality before another optimization.",
            "action": {
                "kind": "skill",
                "command_template": "traigent-eval-audit",
            },
            "evidence_level": "high",
        }
        payload["guidance_meta"] = {
            "requested_variant": "policy",
            "served_variant": "policy",
            "engine": "policy",
            "policy_table_sha": "table-sha",
            "smartopt_version": "1.0.0",
            "fallback_reason": None,
            "decision_id": "decision_123",
            "evidence_snapshot_hash": "sha256:abc123",
        }
        payload["next_steps"] = []

        errors = validator.validate_json(payload, "next_steps_schema")

        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_decision_rejects_internal_operation_vocabulary(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_123",
            "category": "audit_evaluator",
            "source_engine": "policy",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Audit evaluation quality.",
            "action": {
                "kind": "skill",
                "command_template": "traigent-eval-audit",
            },
            "evidence_level": "high",
        }

        errors = validator.validate_json(payload, "next_steps_schema")

        assert errors
        assert any("decision.category" in error for error in errors)

    def test_authoritative_decision_requires_empty_legacy_steps(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_123",
            "category": "run_optimization",
            "source_engine": "rules",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Run optimization.",
            "action": {
                "kind": "skill",
                "command_template": "traigent-optimize-run",
            },
            "evidence_level": "medium",
        }
        errors = validator.validate_json(payload, "next_steps_schema")

        assert errors

    def test_wait_decision_requires_empty_legacy_mirror(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_wait",
            "category": "wait",
            "source_engine": "rules",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Wait for more evidence.",
            "action": {
                "kind": "none",
                "command_template": "",
            },
            "evidence_level": "low",
        }

        payload["next_steps"] = []
        assert validator.validate_json(payload, "next_steps_schema") == []

    def test_wait_decision_rejects_executable_action(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_wait",
            "category": "wait",
            "source_engine": "rules",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Wait for more evidence.",
            "action": {
                "kind": "skill",
                "command_template": "traigent-analyze-guidance",
            },
            "evidence_level": "low",
        }
        payload["next_steps"] = []

        assert validator.validate_json(payload, "next_steps_schema")

    def test_non_wait_decision_rejects_none_action(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_run",
            "category": "run_optimization",
            "source_engine": "rules",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Run optimization.",
            "action": {"kind": "none", "command_template": ""},
            "evidence_level": "medium",
        }
        payload["next_steps"] = []

        assert validator.validate_json(payload, "next_steps_schema")

    def test_non_wait_decision_rejects_empty_command(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_run",
            "category": "run_optimization",
            "source_engine": "rules",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Run optimization.",
            "action": {"kind": "skill", "command_template": ""},
            "evidence_level": "medium",
        }
        payload["next_steps"] = []

        assert validator.validate_json(payload, "next_steps_schema")

    # ------------------------------------------------------------------
    # attribution provenance banner (#352)
    # ------------------------------------------------------------------

    def test_next_steps_accepts_attribution(self, validator, valid_next_steps_payload):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_without_attribution_remains_valid(
        self, validator, valid_next_steps_payload
    ):
        # attribution is optional: the canonical fixture omits it entirely.
        assert "attribution" not in valid_next_steps_payload
        errors = validator.validate_json(valid_next_steps_payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_next_steps_attribution_rejects_bad_source(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        payload["attribution"]["source"] = "not_traigent"

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("source" in e or "const" in e for e in errors)

    def test_next_steps_attribution_rejects_bad_engine(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        payload["attribution"]["engine"] = "neural"  # not in {rules, policy}

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("engine" in e or "enum" in e for e in errors)

    def test_next_steps_attribution_rejects_empty_basis(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        payload["attribution"]["basis"] = []  # violates minItems: 1

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("basis" in e or "minItems" in e for e in errors)

    def test_next_steps_attribution_rejects_unknown_basis_label(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        payload["attribution"]["basis"] = ["raw_signal_scores"]  # not in enum

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("basis" in e or "enum" in e for e in errors)

    def test_next_steps_attribution_rejects_additional_property(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        payload["attribution"]["raw_signal"] = 0.873  # closed object

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("raw_signal" in e or "Additional properties" in e for e in errors)

    def test_next_steps_attribution_rejects_missing_required_field(
        self, validator, valid_next_steps_payload
    ):
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["attribution"] = _valid_attribution()
        del payload["attribution"]["headline"]

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors
        assert any("headline" in e or "required" in e for e in errors)

    def test_attribution_allowed_alongside_authoritative_decision(
        self, validator, valid_next_steps_payload
    ):
        # A decision is present, so the honesty guard does not apply and the
        # banner may accompany it even though next_steps is the empty mirror.
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["decision"] = {
            "id": "decision_123",
            "category": "run_optimization",
            "source_engine": "policy",
            "evidence_snapshot_hash": "sha256:abc123",
            "rationale": "Run optimization.",
            "action": {"kind": "skill", "command_template": "traigent-optimize-run"},
            "evidence_level": "high",
        }
        payload["next_steps"] = []
        payload["attribution"] = _valid_attribution()

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_degenerate_response_rejects_attribution(
        self, validator, valid_next_steps_payload
    ):
        # Honesty guard: with no decision and no non-empty next_steps there is no
        # produced guidance, so a provenance banner must not be attached.
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["next_steps"] = []
        payload.pop("decision", None)
        payload["attribution"] = _valid_attribution()

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors, "Expected honesty-guard rejection of attribution on a degenerate response"

    def test_degenerate_response_without_attribution_valid(
        self, validator, valid_next_steps_payload
    ):
        # The same empty/degenerate response is valid when it makes no attribution claim.
        payload = copy.deepcopy(valid_next_steps_payload)
        payload["next_steps"] = []
        payload.pop("decision", None)

        errors = validator.validate_json(payload, "next_steps_schema")
        assert errors == [], f"Unexpected errors: {errors}"


class TestNextStepsReceiptSchema:
    def test_valid_completed_receipt_with_allowlisted_outcomes(self, validator):
        payload = {
            "status": "completed",
            "attempt_id": "attempt:123",
            "successor_run_id": "run_456",
            "outcomes": {
                "holdout_status": "passed",
                "safety_gate_status": "not_run",
            },
        }

        errors = validator.validate_json(
            payload, "next_steps_receipt_request_schema"
        )

        assert errors == [], f"Unexpected errors: {errors}"

    def test_receipt_outcomes_require_completed_status(self, validator):
        errors = validator.validate_json(
            {
                "status": "started",
                "attempt_id": "attempt_123",
                "outcomes": {"holdout_status": "passed"},
            },
            "next_steps_receipt_request_schema",
        )

        assert errors

    def test_receipt_rejects_arbitrary_metrics_or_content(self, validator):
        errors = validator.validate_json(
            {
                "status": "completed",
                "attempt_id": "attempt_123",
                "metrics": {"accuracy": 0.95},
            },
            "next_steps_receipt_request_schema",
        )

        assert errors

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


def _load_orthogonal_corpus() -> dict[str, object]:
    path = Path(__file__).parent / "data" / "agent_lifecycle_record" / "orthogonal_cases.json"
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


_ORTHOGONAL_CORPUS = _load_orthogonal_corpus()
_ORTHOGONAL_CASES = _ORTHOGONAL_CORPUS["cases"]
_ORTHOGONAL_VALID_CASES = [case for case in _ORTHOGONAL_CASES if case["kind"] == "valid"]
_ORTHOGONAL_INVALID_CASES = [case for case in _ORTHOGONAL_CASES if case["kind"] == "schema_invalid"]


def _orthogonal_case(case_id: str) -> dict[str, object]:
    return next(case["payload"] for case in _ORTHOGONAL_CASES if case["id"] == case_id)


def _sub_definition_validator(schema: dict[str, object], definition_name: str) -> Draft7Validator:
    """Build a validator for one ``#/definitions/<name>`` sub-schema in isolation.

    ``agent_lifecycle_common_schema.json`` is a resolved definitions target: every
    individual axis type must remain independently usable, not only reachable
    through the root ``AgentLifecycleAxisSet``. Every ``$ref`` in this schema is
    internal (``#/definitions/...``), so wrapping the target definition with the
    same ``definitions`` map resolves them without needing SchemaValidator's
    cross-file registry.
    """
    wrapper = {"$ref": f"#/definitions/{definition_name}", "definitions": schema["definitions"]}
    return Draft7Validator(wrapper)


_EXPECTED_ORTHOGONAL_VALID_CASE_IDS = [
    "record_all_axes_orthogonal_baseline",
    "record_identity_live_unknown_no_declaration",
    "record_identity_historical_reconstructed_legacy_governance_resolves_observed",
    "record_coverage_partial_with_incomplete_reason",
    "record_coverage_unmeasured_no_sealed_evidence_episode",
    "record_verified_without_provenance",
    "record_coverage_complete_with_client_attested_only_reason",
    "record_coverage_partial_with_incomplete_and_client_attested_only_reasons",
]

_EXPECTED_ORTHOGONAL_INVALID_CASE_IDS = [
    "axis_value_identity_unknown_with_server_verified_trust",
    "axis_value_identity_reconstructed_with_backend_observed_trust",
    "axis_value_missing_trust_level",
    "identity_unknown_without_reason_baseline",
    "governance_strict_identity_unknown_without_reason",
    "governance_unknown_legacy_value_rejected",
    "governance_client_attested_trust_rejected",
    "comparability_client_attested_not_applicable_rejected",
    "comparability_missing_reason_rejected",
    "coverage_live_partial_missing_incomplete_reason",
    "coverage_live_duplicate_nonzero_rejected",
    "coverage_legacy_marker_with_commitment_field_rejected",
    "coverage_legacy_marker_with_observed_unique_field_rejected",
    "record_unknown_top_level_field_rejected",
    "identity_reconstructed_wrong_reason_pairing_rejected",
    "coverage_marker_all_counts_not_null_rejected",
    "coverage_unmeasured_basis_reason_mismatch_rejected",
    "bounded_reason_code_rejects_unlisted_value",
    "coverage_live_complete_with_unrelated_reason_rejected",
    "coverage_live_partial_with_disallowed_extra_reason_rejected",
    "record_governance_advisory_invalid_at_record_level",
    "record_governance_strict_invalid_at_record_level",
    "record_comparable_single_subject",
    "record_non_comparable_invalid_at_record_level",
]

_EXPECTED_BOUNDED_REASON_CODE_ENUM = [
    "REGISTERED_PROVENANCE",
    "DECLARED_PROVENANCE",
    "LEGACY_RECONSTRUCTED",
    "REQUIRED_IDENTITY_UNKNOWN",
    "NO_EVIDENCE_EPISODE",
    "NO_SEALED_EVIDENCE_EPISODE",
    "INCOMPLETE_EVIDENCE_EPISODE",
    "SINGLE_SUBJECT",
    "CLIENT_ATTESTED_ONLY",
    "LEGACY_CERTIFIED_SELECTION_NON_AUTHORIZING",
    "CONTRACT_MISMATCH",
    "REQUIRED_CONTRACT_UNKNOWN",
]


class TestAgentLifecycleCommonSchema:
    """ALR-1101: orthogonal lifecycle, trust, authority ceilings, and bounded reasons."""

    def test_agent_lifecycle_common_schema_is_discovered(self, validator):
        assert "agent_lifecycle_common_schema" in validator.available_schemas

    def test_orthogonal_corpus_matches_the_exact_expected_case_ids_p2_2(self):
        """P2-2 repair: anti-vacuity by exact membership, not a loose ``>= 5`` floor
        that a case deletion could silently satisfy. Both the id *sets* and the
        *counts* must match exactly -- catches deletion, catches accidental
        duplication, catches a case silently moved between buckets."""
        actual_valid_ids = [case["id"] for case in _ORTHOGONAL_VALID_CASES]
        actual_invalid_ids = [case["id"] for case in _ORTHOGONAL_INVALID_CASES]

        assert sorted(actual_valid_ids) == sorted(_EXPECTED_ORTHOGONAL_VALID_CASE_IDS)
        assert sorted(actual_invalid_ids) == sorted(_EXPECTED_ORTHOGONAL_INVALID_CASE_IDS)
        assert len(actual_valid_ids) == len(_EXPECTED_ORTHOGONAL_VALID_CASE_IDS) == 8
        assert len(actual_invalid_ids) == len(_EXPECTED_ORTHOGONAL_INVALID_CASE_IDS) == 24
        # No id appears in both buckets and no id repeats within a bucket.
        assert len(set(actual_valid_ids)) == len(actual_valid_ids)
        assert len(set(actual_invalid_ids)) == len(actual_invalid_ids)
        assert set(actual_valid_ids).isdisjoint(actual_invalid_ids)

    @pytest.mark.parametrize(
        "case", _ORTHOGONAL_VALID_CASES, ids=[case["id"] for case in _ORTHOGONAL_VALID_CASES]
    )
    def test_orthogonal_corpus_valid_cases_accept(self, validator, case):
        errors = validator.validate_json(case["payload"], "agent_lifecycle_common_schema")
        assert errors == [], f"{case['id']}: unexpected errors: {errors}"

    @pytest.mark.parametrize(
        "case",
        _ORTHOGONAL_INVALID_CASES,
        ids=[case["id"] for case in _ORTHOGONAL_INVALID_CASES],
    )
    def test_orthogonal_corpus_schema_invalid_cases_reject(self, validator, case):
        errors = validator.validate_json(case["payload"], "agent_lifecycle_common_schema")
        assert errors, f"{case['id']}: expected rejection but payload validated cleanly"

    # ------------------------------------------------------------------
    # AC1: valid record keeps governance, identity, coverage, and
    # comparability orthogonal -- no axis constrains another. Sol's ruling
    # on P1-2 (2026-08-09) distinguishes TYPE (the common axis vocabulary,
    # unconstrained) from PRODUCER (what a Part 1 record may actually carry,
    # narrowed for governance/comparability). Orthogonality at the record
    # level is tested through identity/coverage, which genuinely vary in
    # Part 1; governance/comparability are record-level constants, which is
    # itself a (trivial) form of orthogonality -- they cannot possibly
    # correlate with another axis if they never vary.
    # ------------------------------------------------------------------

    def test_identity_and_coverage_vary_independently_at_record_level(self, validator):
        """The two axes that genuinely have more than one Part 1 record-legal
        branch (identity, coverage) validate in every combination the corpus
        exercises, proving neither one's branch choice narrows the other's."""
        live_identity = {
            "value": "RECONSTRUCTED",
            "trust_level": "client_attested",
            "reason_codes": ["DECLARED_PROVENANCE"],
        }
        unknown_identity = {
            "value": "UNKNOWN",
            "trust_level": "client_attested",
            "reason_codes": ["REQUIRED_IDENTITY_UNKNOWN"],
        }
        complete_coverage = {
            "state": "COMPLETE",
            "basis": "LATEST_SEALED_EVIDENCE_EPISODE",
            "trust_level": "backend_observed",
            "expected": 1, "produced": 1, "cached": 0, "missing": 0,
            "failed": 0, "fallback": 0, "excluded": 0,
            "duplicate": 0, "reason_codes": [],
        }
        unmeasured_coverage = {
            "state": "UNMEASURED",
            "basis": "NO_EVIDENCE_EPISODE",
            "trust_level": "backend_observed",
            "expected": 0, "produced": 0, "cached": 0, "missing": 0,
            "failed": 0, "fallback": 0, "excluded": 0,
            "duplicate": 0, "reason_codes": ["NO_EVIDENCE_EPISODE"],
        }
        base = _orthogonal_case("record_all_axes_orthogonal_baseline")

        for identity, coverage in (
            (live_identity, complete_coverage),
            (live_identity, unmeasured_coverage),
            (unknown_identity, complete_coverage),
            (unknown_identity, unmeasured_coverage),
        ):
            payload = copy.deepcopy(base)
            payload["identity_state"] = identity
            payload["measurement_coverage"] = coverage
            errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
            combo = f"identity={identity['value']} coverage={coverage['state']}"
            assert errors == [], f"{combo}: {errors}"

    def test_governance_profile_type_stays_a_bounded_three_branch_vocabulary(self, validator):
        """Sol ruling P1-2 point 1: GovernanceProfileAxisValue itself must remain a
        wide closed vocabulary (OBSERVED/ADVISORY/STRICT) -- do not collapse to a
        single const. Proven directly against the axis TYPE, not the record."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        governance_validator = _sub_definition_validator(schema, "GovernanceProfileAxisValue")
        for value in ("OBSERVED", "ADVISORY", "STRICT"):
            payload = {"value": value, "trust_level": "backend_observed", "reason_codes": []}
            errors = list(governance_validator.iter_errors(payload))
            assert errors == [], f"GovernanceProfileAxisValue must accept {value}: {errors}"

    def test_comparability_verdict_type_stays_a_bounded_vocabulary(self, validator):
        """Sol ruling P1-2 point 1: ComparabilityVerdictAxisValue itself must remain
        a wide closed vocabulary (COMPARABLE/NON_COMPARABLE/NOT_APPLICABLE) -- do
        not collapse to a single const. Proven directly against the axis TYPE."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        comparability_validator = _sub_definition_validator(schema, "ComparabilityVerdictAxisValue")
        legal_tuples = [
            {
                "value": "NOT_APPLICABLE",
                "trust_level": "backend_observed",
                "reason_codes": ["SINGLE_SUBJECT"],
            },
            {"value": "COMPARABLE", "trust_level": "backend_observed", "reason_codes": []},
            {
                "value": "NON_COMPARABLE",
                "trust_level": "backend_observed",
                "reason_codes": ["CONTRACT_MISMATCH"],
            },
            {
                "value": "NON_COMPARABLE",
                "trust_level": "backend_observed",
                "reason_codes": ["REQUIRED_CONTRACT_UNKNOWN"],
            },
        ]
        for payload in legal_tuples:
            errors = list(comparability_validator.iter_errors(payload))
            assert errors == [], f"ComparabilityVerdictAxisValue must accept {payload}: {errors}"

    @pytest.mark.parametrize("reserved_governance_value", ["ADVISORY", "STRICT"])
    def test_reserved_governance_values_are_invalid_at_the_record_level(
        self, validator, reserved_governance_value
    ):
        """Sol ruling P1-2 point 2: the record composition (AgentLifecycleAxisSet)
        may only ever carry governance_profile=OBSERVED even though ADVISORY/STRICT
        remain legal at the type level (proven above)."""
        payload = copy.deepcopy(_orthogonal_case("record_all_axes_orthogonal_baseline"))
        payload["governance_profile"] = {
            "value": reserved_governance_value,
            "trust_level": "backend_observed",
            "reason_codes": [],
        }
        errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
        assert errors, f"governance_profile={reserved_governance_value}: expected rejection"

    @pytest.mark.parametrize(
        "reserved_comparability_payload",
        [
            {"value": "COMPARABLE", "trust_level": "backend_observed", "reason_codes": []},
            {
                "value": "NON_COMPARABLE",
                "trust_level": "backend_observed",
                "reason_codes": ["CONTRACT_MISMATCH"],
            },
            {
                "value": "NON_COMPARABLE",
                "trust_level": "backend_observed",
                "reason_codes": ["REQUIRED_CONTRACT_UNKNOWN"],
            },
        ],
        ids=[
            "COMPARABLE",
            "NON_COMPARABLE-contract_mismatch",
            "NON_COMPARABLE-required_contract_unknown",
        ],
    )
    def test_reserved_comparability_values_are_invalid_at_the_record_level(
        self, validator, reserved_comparability_payload
    ):
        """Sol ruling P1-2 point 3: a Part 1 record response with
        comparability_verdict != NOT_APPLICABLE is invalid, even though
        COMPARABLE/NON_COMPARABLE remain legal at the type level (proven above).
        This is exactly the corrected 'record_comparable_single_subject' case
        (PART1_CONTRACT_FREEZE_DRAFT.md schema_invalid #17), generalized to both
        NON_COMPARABLE reason branches too."""
        payload = copy.deepcopy(_orthogonal_case("record_all_axes_orthogonal_baseline"))
        payload["comparability_verdict"] = reserved_comparability_payload
        errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
        assert errors, f"comparability_verdict={reserved_comparability_payload}: expected rejection"

    def test_record_comparable_single_subject_corpus_case_is_now_invalid_for_the_right_reason(
        self, validator
    ):
        """Regression guard for the Terra-flagged defect: an earlier submission had
        this exact contract-named case backwards (in the valid bucket, with
        comparability_verdict=NOT_APPLICABLE). It must now be schema_invalid, and
        specifically because its comparability_verdict is COMPARABLE -- not because
        of some unrelated malformation elsewhere in the payload."""
        case = next(
            case for case in _ORTHOGONAL_CASES if case["id"] == "record_comparable_single_subject"
        )
        assert case["kind"] == "schema_invalid"
        assert case["payload"]["comparability_verdict"]["value"] == "COMPARABLE"

        errors = validator.validate_json(case["payload"], "agent_lifecycle_common_schema")
        assert errors

        # Confirm the SAME payload becomes valid once comparability_verdict is
        # corrected to the only record-legal value, isolating comparability as
        # the sole cause of the original rejection.
        corrected = copy.deepcopy(case["payload"])
        corrected["comparability_verdict"] = {
            "value": "NOT_APPLICABLE",
            "trust_level": "backend_observed",
            "reason_codes": ["SINGLE_SUBJECT"],
        }
        assert validator.validate_json(corrected, "agent_lifecycle_common_schema") == []

    # ------------------------------------------------------------------
    # AC2: unknown legacy governance resolves OBSERVED; unknown identity
    # retains its reason and can never become VERIFIED.
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("legacy_token", ["UNSET", "LEGACY", "", "unknown"])
    def test_governance_rejects_every_token_outside_the_closed_vocabulary(
        self, validator, legacy_token
    ):
        payload = copy.deepcopy(_orthogonal_case("record_all_axes_orthogonal_baseline"))
        payload["governance_profile"] = {
            "value": legacy_token,
            "trust_level": "backend_observed",
            "reason_codes": [],
        }
        errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
        assert errors, f"legacy governance token {legacy_token!r} should not validate"

    def test_identity_unknown_can_never_become_verified_by_editing_value_alone(self, validator):
        """Flipping only ``value`` on a live-UNKNOWN identity to VERIFIED must fail:
        VERIFIED requires server_verified trust and REGISTERED_PROVENANCE, which an
        UNKNOWN-shaped record never carries."""
        payload = copy.deepcopy(_orthogonal_case("record_identity_live_unknown_no_declaration"))
        payload["identity_state"]["value"] = "VERIFIED"
        errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
        assert errors, "UNKNOWN identity must not become VERIFIED by relabeling value alone"

    def test_failure_mutation_target_fails_specifically_on_identity_reason_codes(self, validator):
        """Sol ruling P1-2 point 4: keep the STRICT+UNKNOWN-identity-without-reason
        negative (not vacuous), but prove it fails *because a non-default axis
        value requires non-empty bounded reason codes* (AxisValue rule), not
        because STRICT is somehow an unknown/illegal enum value. Isolated at the
        axis-TYPE level, before the Part 1 record-level production narrowing
        (which would otherwise also reject STRICT governance and confound the
        assertion)."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        governance_validator = _sub_definition_validator(schema, "GovernanceProfileAxisValue")
        identity_validator = _sub_definition_validator(schema, "IdentityStateAxisValue")

        strict_governance = {
            "value": "STRICT", "trust_level": "backend_observed", "reason_codes": [],
        }
        unknown_identity_without_reason = {
            "value": "UNKNOWN", "trust_level": "client_attested", "reason_codes": [],
        }
        unknown_identity_with_reason = {
            "value": "UNKNOWN",
            "trust_level": "client_attested",
            "reason_codes": ["REQUIRED_IDENTITY_UNKNOWN"],
        }

        # STRICT alone is legal at the axis-type level -- not the cause of failure.
        assert list(governance_validator.iter_errors(strict_governance)) == []
        # UNKNOWN identity without its bound reason fails on its own, regardless
        # of governance.
        assert list(identity_validator.iter_errors(unknown_identity_without_reason))
        # The identical value/trust with the reason restored is legal -- isolating
        # the missing reason_codes entry, not the UNKNOWN value itself, as the cause.
        assert list(identity_validator.iter_errors(unknown_identity_with_reason)) == []

    # ------------------------------------------------------------------
    # AC3: COMPARABLE requires an identical-contract basis; any unknown
    # required input yields NON_COMPARABLE, never a permissive default.
    # Sol's note: the story text is imprecise here -- Part 1's single-record
    # route cannot produce COMPARABLE/NON_COMPARABLE at all (single-record
    # reads are exactly NOT_APPLICABLE). AC3 is therefore satisfied at the
    # common AXIS-TYPE level, where the comparability semantics genuinely
    # live; the record level is covered separately above by the
    # NOT_APPLICABLE-only narrowing.
    # ------------------------------------------------------------------

    def test_comparable_requires_its_bound_reason_at_the_type_level(self, validator):
        schema = validator._schemas["agent_lifecycle_common_schema"]
        comparability_validator = _sub_definition_validator(schema, "ComparabilityVerdictAxisValue")
        payload = {
            "value": "COMPARABLE",
            "trust_level": "backend_observed",
            "reason_codes": ["CONTRACT_MISMATCH"],
        }
        errors = list(comparability_validator.iter_errors(payload))
        assert errors, "COMPARABLE must reject CONTRACT_MISMATCH -- a reason bound elsewhere"

    def test_non_comparable_is_not_interchangeable_with_comparables_empty_reason(self, validator):
        schema = validator._schemas["agent_lifecycle_common_schema"]
        comparability_validator = _sub_definition_validator(schema, "ComparabilityVerdictAxisValue")
        # Swapping in COMPARABLE's empty reason on a NON_COMPARABLE verdict is not
        # a permissive default -- it is simply a different malformed combination.
        payload = {"value": "NON_COMPARABLE", "trust_level": "backend_observed", "reason_codes": []}
        errors = list(comparability_validator.iter_errors(payload))
        assert errors, "NON_COMPARABLE with an empty reason array must reject, not silently pass"

    def test_non_comparable_unknown_required_input_yields_non_comparable_not_a_default(
        self, validator
    ):
        """AC3 second half, literally: 'any unknown required input yields
        NON_COMPARABLE, never a permissive default.' REQUIRED_CONTRACT_UNKNOWN is
        legal only on NON_COMPARABLE, never on COMPARABLE -- there is no
        permissive branch that lets an unknown-required-input reason validate
        against a COMPARABLE verdict."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        comparability_validator = _sub_definition_validator(schema, "ComparabilityVerdictAxisValue")

        non_comparable_payload = {
            "value": "NON_COMPARABLE",
            "trust_level": "backend_observed",
            "reason_codes": ["REQUIRED_CONTRACT_UNKNOWN"],
        }
        assert list(comparability_validator.iter_errors(non_comparable_payload)) == []

        comparable_with_unknown_input_payload = {
            "value": "COMPARABLE",
            "trust_level": "backend_observed",
            "reason_codes": ["REQUIRED_CONTRACT_UNKNOWN"],
        }
        assert list(comparability_validator.iter_errors(comparable_with_unknown_input_payload)), (
            "REQUIRED_CONTRACT_UNKNOWN must never validate against COMPARABLE -- "
            "that would be exactly the permissive default AC3 forbids"
        )

    # ------------------------------------------------------------------
    # AC4: trust levels are client_attested/backend_observed/server_verified;
    # client-supplied evidence can never raise authority to server_verified.
    # ------------------------------------------------------------------

    def test_trust_level_enum_is_exactly_the_three_closed_values(self, validator):
        schema = validator._schemas["agent_lifecycle_common_schema"]
        trust_level = schema["definitions"]["TrustLevel"]
        assert trust_level["enum"] == ["client_attested", "backend_observed", "server_verified"]

    def test_bounded_reason_code_enum_matches_the_frozen_vocabulary_exactly(self, validator):
        """P1-1 repair: 'bounded' means closed. Assert equality against the frozen
        Part 1 public reason vocabulary (PART1_CONTRACT_FREEZE_DRAFT.md:260/264),
        not merely a subset check -- so neither an invented addition nor a
        silently dropped frozen code can pass."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        bounded_reason_code = schema["definitions"]["BoundedReasonCode"]
        assert bounded_reason_code["enum"] == _EXPECTED_BOUNDED_REASON_CODE_ENUM
        assert len(bounded_reason_code["enum"]) == 12

    @pytest.mark.parametrize(
        "identity_value,identity_reason",
        [
            ("UNKNOWN", "REQUIRED_IDENTITY_UNKNOWN"),
            ("RECONSTRUCTED", "DECLARED_PROVENANCE"),
            ("RECONSTRUCTED", "LEGACY_RECONSTRUCTED"),
        ],
    )
    def test_no_client_shaped_identity_can_claim_server_verified_trust(
        self, validator, identity_value, identity_reason
    ):
        """Every identity branch whose reason is client-suppliable is rejected the
        moment its trust_level is raised to server_verified -- only the single
        Backend-provenance branch (VERIFIED/REGISTERED_PROVENANCE) may carry it."""
        payload = copy.deepcopy(_orthogonal_case("record_all_axes_orthogonal_baseline"))
        payload["identity_state"] = {
            "value": identity_value,
            "trust_level": "server_verified",
            "reason_codes": [identity_reason],
        }
        errors = validator.validate_json(payload, "agent_lifecycle_common_schema")
        assert errors, (
            f"identity value={identity_value} reason={identity_reason} must not be able "
            "to claim server_verified trust"
        )

    def test_axis_value_base_would_permit_the_illegal_combo_the_closed_type_forbids(
        self, validator
    ):
        """Demonstrates why the generic AxisValue base is 'not a public escape hatch'
        (PART1_CONTRACT_FREEZE_DRAFT.md:311): validated directly, it accepts an
        UNKNOWN/server_verified combination that IdentityStateAxisValue correctly
        rejects, because AxisValue alone does not bind trust_level per value."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        illegal_combo = {
            "value": "UNKNOWN",
            "trust_level": "server_verified",
            "reason_codes": ["REQUIRED_IDENTITY_UNKNOWN"],
        }

        base_validator = _sub_definition_validator(schema, "AxisValue")
        assert list(base_validator.iter_errors(illegal_combo)) == [], (
            "AxisValue base is expected to accept this combination in isolation -- "
            "that is exactly why nothing may reference it directly"
        )

        identity_validator = _sub_definition_validator(schema, "IdentityStateAxisValue")
        assert list(identity_validator.iter_errors(illegal_combo)), (
            "IdentityStateAxisValue must reject the same combination AxisValue alone permits"
        )

    def test_nothing_in_this_schema_references_axis_value_directly(self, validator):
        """Structural guard for 'No Part 1 route schema references the generic base
        directly' (PART1_CONTRACT_FREEZE_DRAFT.md:311): scan every ``$ref`` in this
        file and confirm none of them target ``#/definitions/AxisValue``."""
        schema = validator._schemas["agent_lifecycle_common_schema"]

        def iter_refs(node: object):
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "$ref" and isinstance(value, str):
                        yield value
                    else:
                        yield from iter_refs(value)
            elif isinstance(node, list):
                for item in node:
                    yield from iter_refs(item)

        refs = list(iter_refs(schema))
        assert refs, "expected this schema to contain internal $refs at all"
        assert "#/definitions/AxisValue" not in refs

    # ------------------------------------------------------------------
    # AC5: malformed combinations are rejected; unknown fields either
    # preserve or fail closed -- never silently pass.
    # ------------------------------------------------------------------

    def test_every_object_branch_in_this_schema_is_closed_to_additional_properties(
        self, validator
    ):
        """Fail-closed guard: every object branch in every closed axis type sets
        additionalProperties: false, so an unrecognized field is always rejected
        rather than silently preserved-and-ignored or accepted."""
        schema = validator._schemas["agent_lifecycle_common_schema"]

        def iter_object_branches(node: object, path: str = "$"):
            if isinstance(node, dict):
                if node.get("type") == "object" and "properties" in node:
                    yield path, node
                for key, value in node.items():
                    yield from iter_object_branches(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, item in enumerate(node):
                    yield from iter_object_branches(item, f"{path}[{index}]")

        offenders = [
            path
            for path, node in iter_object_branches(schema["definitions"])
            if node.get("additionalProperties") is not False
        ]
        assert offenders == [], f"object branches missing additionalProperties:false: {offenders}"

    def test_no_commitment_or_observed_unique_field_anywhere_in_coverage(self, validator):
        """Owner accounting decision (2026-08-09, simpler contract): commitment and
        observed_unique were both deliberately deleted and must never resurface."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        coverage = schema["definitions"]["RecordMeasurementCoverage"]
        for branch in coverage["oneOf"]:
            properties = set(branch["properties"])
            assert "commitment" not in properties
            assert "observed_unique" not in properties

    def test_deleted_accounting_field_literals_do_not_appear_in_public_schema_text(
        self, validator
    ):
        """P2-1 repair: the literal words 'commitment' and 'observed_unique' must
        not appear anywhere in this schema file's public text (descriptions,
        titles, property names) -- not merely be absent as real properties. This
        scans the schema file only; the corpus's deliberate negative-bait poison
        payloads (coverage_legacy_marker_with_commitment_field_rejected,
        coverage_legacy_marker_with_observed_unique_field_rejected) are a
        separate file and are explicitly exempted from this rule."""
        schema = validator._schemas["agent_lifecycle_common_schema"]

        def iter_all_strings(node: object):
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(key, str):
                        yield key
                    yield from iter_all_strings(value)
            elif isinstance(node, list):
                for item in node:
                    yield from iter_all_strings(item)
            elif isinstance(node, str):
                yield node

        offenders = [
            value
            for value in iter_all_strings(schema)
            for forbidden in ("commitment", "observed_unique")
            if forbidden in value.lower()
        ]
        assert offenders == [], f"deleted-field literals leaked into schema text: {offenders}"

    def test_accepted_duplicate_is_always_fixed_at_zero_or_null(self, validator):
        """Owner accounting decision: duplicate is const 0 on every live/unmeasured
        branch and const null (alongside the other seven counts) on the legacy
        marker branch -- never an open integer."""
        schema = validator._schemas["agent_lifecycle_common_schema"]
        coverage = schema["definitions"]["RecordMeasurementCoverage"]
        for branch in coverage["oneOf"]:
            duplicate_schema = branch["properties"]["duplicate"]
            assert "const" in duplicate_schema, (
                f"duplicate must be schema-const (0 or null), not an open type: {duplicate_schema}"
            )
            assert duplicate_schema["const"] in (0, None), duplicate_schema


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

        receipt = endpoints["paths"][
            "/api/v1/analytics/experiments/{experiment_run_id}/next-steps/{decision_id}/receipt"
        ]["post"]
        assert (
            receipt["requestBody"]["content"]["application/json"]["schema"]["$ref"]
            == "./next_steps_receipt_request_schema.json"
        )
        assert (
            receipt["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
            == "./next_steps_receipt_response_schema.json"
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
                    (relative_path, path)
                    for path in paths
                    if "/lifecycle" in path and "artifact" in path
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

    # ------------------------------------------------------------------
    # ALR-1101 P1-4: the `reason_codes` allowance for
    # agent_lifecycle_common_schema.json must be path-scoped, not a blanket
    # per-file exemption. These two canaries prove the narrow helper still
    # catches a real leak in this exact file while allowing the two
    # legitimate JSON Schema positions the property name needs.
    # ------------------------------------------------------------------

    def test_agent_lifecycle_reason_codes_canary_flags_non_property_occurrence(self):
        """A `reason_code`-bearing string sitting in prose (not a `properties` key
        or a `required` list entry) must still be caught in this file -- proving
        the path-scoped allowance does not silently swallow a real leak the way
        the blanket per-file exemption it replaced did."""
        leaking_document = {
            "type": "object",
            "properties": {
                "some_field": {
                    "type": "string",
                    "description": "an internal reason_code leak in prose, not a property key",
                }
            },
        }

        findings = _find_public_schema_lifecycle_leaks(
            _AGENT_LIFECYCLE_COMMON_SCHEMA_PATH,
            leaking_document,
        )

        assert any(
            finding.tier == "TIER-1" and finding.token == "reason_code" for finding in findings
        ), f"expected the non-property reason_code occurrence to be flagged, got: {findings}"

    def test_agent_lifecycle_reason_codes_canary_allows_legitimate_property_and_required_slots(
        self,
    ):
        """The literal `reason_codes` property key and its `required` list entry
        are the two positions this axis contract actually needs -- both must be
        allowed, and only those two."""
        legitimate_document = {
            "type": "object",
            "required": ["value", "trust_level", "reason_codes"],
            "properties": {
                "value": {"type": "string"},
                "trust_level": {"type": "string"},
                "reason_codes": {"type": "array", "items": {"type": "string"}},
            },
        }

        findings = _find_public_schema_lifecycle_leaks(
            _AGENT_LIFECYCLE_COMMON_SCHEMA_PATH,
            legitimate_document,
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

        insights = payload["insights"]
        lessons = payload["lessons_learned"]
        rules = payload["inferred_optimization_rules"]
        benchmark_rules = payload["benchmark_rules"]
        evaluator_rules = payload["evaluator_rules"]
        stability = payload["stability"]
        hard_examples = payload["hard_examples"]
        provenance = payload["provenance"]
        assert isinstance(insights, dict)
        assert isinstance(lessons, dict)
        assert isinstance(rules, dict)
        assert isinstance(benchmark_rules, dict)
        assert isinstance(evaluator_rules, dict)
        assert isinstance(stability, dict)
        assert isinstance(hard_examples, dict)
        assert isinstance(provenance, dict)

        insights["items"] = [_valid_optimization_trace_insight_atom()]
        lessons["items"] = [_valid_optimization_trace_lesson_atom()]
        rules["items"] = [_valid_optimization_trace_rule_atom()]
        benchmark_rules["items"] = [_valid_optimization_trace_rule_atom()]
        evaluator_rules["items"] = [_valid_optimization_trace_rule_atom()]
        stability["items"] = [_valid_optimization_trace_stability_atom()]
        hard_examples["items"] = [_valid_optimization_trace_hard_example_atom()]
        provenance["items"] = [_valid_optimization_trace_provenance_atom()]

        errors = validator.validate_json(payload, "optimization_trace_step_signature_schema")

        assert errors == []

    @pytest.mark.parametrize(
        "failure_mode",
        ["difficult", "low_value", "redundant"],
    )
    def test_step_signature_accepts_extractor_hard_example_failure_modes(
        self,
        validator,
        failure_mode,
    ):
        payload = _valid_optimization_trace_step_signature_payload()
        hard_examples = payload["hard_examples"]
        assert isinstance(hard_examples, dict)

        atom = _valid_optimization_trace_hard_example_atom()
        atom["failure_mode"] = failure_mode
        hard_examples["items"] = [atom]

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
            ("insights", _valid_optimization_trace_insight_atom()),
            ("lessons_learned", _valid_optimization_trace_lesson_atom()),
            ("inferred_optimization_rules", _valid_optimization_trace_rule_atom()),
            ("benchmark_rules", _valid_optimization_trace_rule_atom()),
            ("evaluator_rules", _valid_optimization_trace_rule_atom()),
            ("stability", _valid_optimization_trace_stability_atom()),
            ("hard_examples", _valid_optimization_trace_hard_example_atom()),
            ("provenance", _valid_optimization_trace_provenance_atom()),
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
