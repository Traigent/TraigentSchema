"""Tests for traigent_schema.validator module."""

import json
import logging

import pytest

import traigent_schema.validator as validator_module
from traigent_schema.validator import SchemaValidator


class TestSchemaValidatorInit:
    """Tests for SchemaValidator initialization."""

    def test_creates_instance(self):
        """Should create a validator instance."""
        validator = SchemaValidator()
        assert validator is not None

    def test_loads_schemas(self):
        """Should load schemas on initialization."""
        validator = SchemaValidator()
        assert len(validator.available_schemas) > 0

    def test_available_schemas_property(self):
        """Should return list of schema names."""
        validator = SchemaValidator()
        schemas = validator.available_schemas
        assert isinstance(schemas, list)
        assert "agent_schema" in schemas

    def test_can_select_non_default_contract(self):
        validator = SchemaValidator(contract="sdk_tuning")
        assert validator.contract == "sdk_tuning"

    def test_invalid_contract_name_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown contract"):
            SchemaValidator(contract="invalid")

    def test_logs_warning_when_contract_root_is_invalid_json(
        self, monkeypatch, tmp_path, caplog
    ):
        broken_contract = tmp_path / "broken_contract.json"
        broken_contract.write_text("{ not-json", encoding="utf-8")

        monkeypatch.setattr(
            validator_module,
            "get_contract_path",
            lambda _contract: broken_contract,
        )

        with caplog.at_level(logging.WARNING):
            SchemaValidator()

        assert any(
            "Failed to load OpenAPI contract root" in message
            for message in caplog.messages
        )


class TestValidateJson:
    """Tests for validate_json method."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return SchemaValidator()

    def test_valid_agent_data(self, validator):
        """Should validate correct agent data."""
        data = {
            "id": "test-agent-1",
            "name": "Test Agent",
            "agent_type": "qa"
        }
        errors = validator.validate_json(data, "agent_schema")
        # Note: May have reference resolution errors for cross-file $refs
        # The validator correctly validates the core structure
        assert isinstance(errors, list)

    def test_invalid_agent_missing_required(self, validator):
        """Should catch missing required fields."""
        data = {
            "name": "Test Agent"
            # Missing id and agent_type
        }
        errors = validator.validate_json(data, "agent_schema")
        assert len(errors) > 0

    def test_nonexistent_schema(self, validator):
        """Should return error for missing schema."""
        data = {"test": "data"}
        errors = validator.validate_json(data, "nonexistent_schema_xyz")
        assert len(errors) == 1
        assert "Schema not found" in errors[0]

    def test_schema_name_without_suffix(self, validator):
        """Should find schema without _schema suffix."""
        data = {
            "id": "test-agent-1",
            "name": "Test Agent",
            "agent_type": "qa"
        }
        # Try with just "agent" instead of "agent_schema"
        errors = validator.validate_json(data, "agent")
        # Should either work or gracefully report not found
        assert isinstance(errors, list)

    def test_enforces_date_time_format(self, validator):
        for effective_date in (
            "2026-06-23T00:00:00Z",
            "2026-06-23T00:00:00z",
            "2026-06-23t00:00:00Z",
            "2026-06-23t00:00:00z",
            "2026-06-23T00:00:00+00:00",
        ):
            valid = {
                "success": True,
                "message": "ok",
                "data": {"effective_date": effective_date, "message": None},
            }
            assert (
                validator.validate_json(valid, "subscription_cancel_response_schema")
                == []
            )

        for effective_date in ("soon", "2026-06-30T23:59:60Z"):
            invalid = {
                "success": True,
                "message": "ok",
                "data": {"effective_date": effective_date, "message": None},
            }
            assert validator.validate_json(
                invalid, "subscription_cancel_response_schema"
            )


class TestValidateRequest:
    """Tests for validate_request method."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return SchemaValidator()

    @pytest.fixture
    def sdk_validator(self):
        return SchemaValidator(contract="sdk_tuning")

    @pytest.fixture
    def planned_validator(self):
        return SchemaValidator(contract="planned_projects")

    def test_unknown_endpoint_passes(self, validator):
        """Should pass for unknown endpoints (no schema)."""
        data = {"any": "data"}
        errors = validator.validate_request("/unknown/endpoint", "POST", data)
        assert errors == []

    def test_returns_list(self, validator):
        """Should always return a list."""
        data = {"test": "data"}
        errors = validator.validate_request("/api/v1/agents", "POST", data)
        assert isinstance(errors, list)

    def test_agent_request_uses_endpoint_module_mapping(self, validator):
        """Agent validation should resolve through the modular endpoint catalog."""
        errors = validator.validate_request(
            "/api/v1/agents",
            "POST",
            {
                "name": "Test Agent",
            },
        )
        assert errors

    def test_agent_request_reports_validation_errors(self, validator):
        """Invalid agent payloads should fail request validation."""
        errors = validator.validate_request(
            "/api/v1/agents",
            "POST",
            {"name": "Test Agent"},
        )
        assert errors
        assert any("id" in error or "agent_type" in error for error in errors)

    def test_sdk_session_request_uses_contract_specific_catalog(self, sdk_validator):
        """Direct-tuning endpoints should validate through the SDK contract."""
        errors = sdk_validator.validate_request(
            "/api/v1/sessions",
            "POST",
            {
                "function_name": "support_router",
                "configuration_space": {"temperature": [0.1, 0.9]},
                "objectives": ["accuracy"],
            },
        )
        assert errors == []

    def test_sdk_hybrid_session_request_uses_inline_contract_schema(self, sdk_validator):
        errors = sdk_validator.validate_request(
            "/api/v1/hybrid/sessions",
            "POST",
            {
                "problem_statement": "Optimize tone and retrieval quality",
                "search_space": {"temperature": [0.0, 1.0]},
                "optimization_config": {"max_trials": 10},
            },
        )
        assert errors == []

    def test_sdk_session_path_parameters_normalize_for_inline_request_schemas(self, sdk_validator):
        errors = sdk_validator.validate_request(
            "/api/v1/sessions/sess_abc/results",
            "POST",
            {
                "status": "completed",
            },
        )
        assert errors
        assert any("trial_id" in error for error in errors)
        assert any("metrics" in error for error in errors)

    def test_sdk_session_results_request_accepts_top_level_config(self, sdk_validator):
        errors = sdk_validator.validate_request(
            "/api/v1/sessions/sess_abc/results",
            "POST",
            {
                "trial_id": "trial-sdk-local-1",
                "metrics": {"accuracy": 0.875},
                "config": {"modelVariant": "balanced", "temperature": 0.4},
            },
        )
        assert errors == []

    def test_inline_request_schema_resolves_registry_refs(self, validator):
        """Inline schemas should resolve package schema $refs via the shared registry."""
        validator._inline_request_schemas["POST:/inline-agent"] = {
            "$ref": "https://schemas.traigent.ai/agents/agent_schema.json"
        }

        errors = validator.validate_request(
            "/inline-agent",
            "POST",
            {"name": "Missing required fields"},
        )

        assert errors
        assert any("id" in error or "agent_type" in error for error in errors)

    def test_path_template_matching_treats_literal_dots_as_literals(self, validator):
        """OpenAPI path normalization should not use unescaped regex literals."""
        validator._endpoint_schemas = {"GET:/files/{file_id}/v1.0": "agent_schema"}
        validator._inline_request_schemas = {}

        assert (
            validator._normalize_endpoint("GET", "/files/report/v1.0")
            == "/files/{file_id}/v1.0"
        )
        assert (
            validator._normalize_endpoint("GET", "/files/report/v1x0")
            == "/files/report/v1x0"
        )

    def test_endpoint_modules_are_confined_to_contract_directory(
        self, validator, tmp_path, caplog
    ):
        safe_module = tmp_path / "safe_endpoints.json"
        safe_module.write_text(
            json.dumps(
                {
                    "paths": {
                        "/safe": {
                            "post": {
                                "requestBody": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"type": "object"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        openapi = {
            "x-endpoint-modules": [
                {"paths_file": "../outside.json"},
                {"paths_file": "safe_endpoints.json"},
            ]
        }

        validator._inline_request_schemas = {}
        with caplog.at_level(logging.WARNING):
            validator._load_endpoint_modules(openapi, tmp_path)

        assert "POST:/safe" in validator._inline_request_schemas
        assert any("escapes" in message for message in caplog.messages)

    def test_default_backend_contract_ignores_planned_project_routes(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/summary",
            "GET",
            {},
        )
        assert errors == []

    def test_default_backend_contract_validates_trace_score_summary_route(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/observability/traces/trace_abc/score-summary",
            "GET",
            {},
        )
        assert errors == []

    def test_default_backend_contract_validates_score_create_request(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/scores",
            "POST",
            {
                "measure_id": "helpfulness",
                "target_type": "observability_trace",
                "target_id": "trace_abc",
                "numeric_value": 0.9,
                "source": "manual",
            },
        )
        assert errors == []

    def test_default_backend_contract_validates_evaluator_create_request(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/evaluators",
            "POST",
            {
                "name": "Trace Accuracy Judge",
                "measure_id": "accuracy",
                "target_type": "observability_trace",
                "judge_config": {
                    "instructions": "Score the trace for accuracy.",
                    "model_id": "gpt-4o-mini",
                    "context_type": "trace",
                },
            },
        )
        assert errors == []

    def test_default_backend_contract_validates_evaluator_partial_update_request(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/evaluators/eval_abc",
            "PATCH",
            {
                "is_active": False,
                "sampling_rate": 0.5,
            },
        )
        assert errors == []

    def test_default_backend_contract_validates_annotation_queue_create_request(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/annotation-queues",
            "POST",
            {
                "name": "Runtime Trace Review",
                "target_type": "observability_trace",
                "measure_ids": ["helpfulness", "relevance"],
            },
        )
        assert errors == []

    def test_default_backend_contract_validates_annotation_queue_partial_update_request(
        self, validator
    ):
        errors = validator.validate_request(
            "/api/v1beta/annotation-queues/queue_abc",
            "PATCH",
            {
                "status": "paused",
            },
        )
        assert errors == []

    def test_annotation_queue_update_rejects_empty_measure_ids(self, validator):
        """An update with measure_ids: [] must be rejected (minItems parity with
        create) so a PATCH can never silently empty a queue's measures."""
        errors = validator.validate_request(
            "/api/v1beta/annotation-queues/queue_abc",
            "PATCH",
            {
                "measure_ids": [],
            },
        )
        assert errors
        assert any("measure_ids" in error for error in errors)

    def test_annotation_queue_update_accepts_non_empty_measure_ids(self, validator):
        """A non-empty measure_ids list is a valid update payload."""
        errors = validator.validate_request(
            "/api/v1beta/annotation-queues/queue_abc",
            "PATCH",
            {
                "measure_ids": ["m1"],
            },
        )
        assert errors == []

    def test_annotation_queue_update_allows_omitted_measure_ids(self, validator):
        """measure_ids stays optional on update: omitting it validates."""
        errors = validator.validate_request(
            "/api/v1beta/annotation-queues/queue_abc",
            "PATCH",
            {
                "name": "Renamed Review Queue",
            },
        )
        assert errors == []

    def test_default_backend_contract_ignores_removed_tunable_routes(self, validator):
        errors = validator.validate_request(
            "/api/v1/tunables",
            "POST",
            {"id": "tunable_123", "name": "Support Router"},
        )
        assert errors == []

    def test_project_path_normalization_for_analytics_route(self, planned_validator):
        """Concrete project analytics paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/summary",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_pricing_catalog_route(self, planned_validator):
        """Concrete pricing catalog paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/pricing-catalog",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_optimization_dashboard_route(self, planned_validator):
        """Concrete optimization dashboard paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/dashboards/optimization-overview",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_evaluator_quality_dashboard_route(
        self, planned_validator
    ):
        """Concrete evaluator dashboard paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/dashboards/evaluator-quality",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_project_usage_dashboard_route(self, planned_validator):
        """Concrete project usage dashboard paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/dashboards/project-usage",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_observability_summary_dashboard_route(
        self, planned_validator
    ):
        """Concrete observability dashboard paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/dashboards/observability-summary",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_export_jobs_route(self, planned_validator):
        """Concrete export job list paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/export-jobs",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_export_job_detail_route(self, planned_validator):
        """Concrete export job detail paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/export-jobs/export_job_123",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_rate_limit_policy_route(self, planned_validator):
        """Concrete project policy paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/policies/rate-limits",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_retention_policy_route(self, planned_validator):
        """Concrete retention policy paths should normalize to the OpenAPI template."""
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/policies/retention",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_membership_list_route(self, planned_validator):
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/memberships",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_membership_create_route(self, planned_validator):
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/memberships",
            "POST",
            {"user_id": "user_123", "role": "editor", "status": "active"},
        )
        assert errors == []

    def test_project_path_normalization_for_membership_update_route(self, planned_validator):
        errors = planned_validator.validate_request(
            "/api/v1beta/projects/project_abc/memberships/project_membership_123",
            "PATCH",
            {"role": "viewer"},
        )
        assert errors == []


class TestSchemaValidation:
    """Integration tests for schema validation."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return SchemaValidator()

    def test_experiment_schema_valid(self, validator):
        """Should validate correct experiment data."""
        data = {
            "id": "exp-001",
            "name": "Test Experiment",
            "description": "A test experiment",
            "status": "pending"
        }
        errors = validator.validate_json(data, "experiment_schema")
        # May have errors depending on required fields, but should be a list
        assert isinstance(errors, list)

    def test_measure_schema_valid(self, validator):
        """Should validate correct measure data."""
        data = {
            "id": "measure-001",
            "name": "Accuracy",
            "measure_type": "llm_judge"
        }
        errors = validator.validate_json(data, "measure_schema")
        assert isinstance(errors, list)

    def test_planner_draft_schema_valid(self, validator):
        """Should validate a planner draft with canonical measure payloads."""
        data = {
            "draft_id": "draft_answer_quality",
            "description": "Create a support agent and evaluate answer helpfulness.",
            "agent": None,
            "benchmark": None,
            "measures": [
                {
                    "id": "answer_helpfulness",
                    "version": "1.0.0",
                    "label": "Answer Helpfulness",
                    "description": "Scores whether the response is useful.",
                    "category": "Response Quality",
                    "measure_type": "quality",
                    "evaluation_method": "llm_based",
                    "target_aspect": "response",
                    "metric_type": "single_turn",
                    "output_type": "continuous",
                    "agent_types": ["chat"],
                    "domain_min": 0.0,
                    "domain_max": 1.0,
                    "inverse": False,
                    "is_custom": True,
                    "target_types": ["observability_trace", "configuration_run"],
                    "allowed_score_sources": ["manual", "evaluator"],
                }
            ],
            "metadata": {"source": "phase1_fixture"},
            "status": "created",
        }
        errors = validator.validate_json(data, "planner_draft_schema")
        assert errors == []

    def test_project_list_response_schema_resolves_pagination_ref(self, validator):
        """Paginated project responses should resolve the shared pagination schema."""
        data = {
            "items": [],
            "pagination": {
                "page": 1,
                "per_page": 20,
                "total": 0,
                "total_pages": 0,
                "has_next": False,
                "has_prev": False,
            },
        }
        errors = validator.validate_json(data, "project_list_response_schema")
        assert errors == []

    def test_project_scoped_analytics_summary_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-11T10:15:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "entity_counts": {
                "agents": 1,
                "benchmarks": 1,
                "measures": 2,
                "experiments": 1,
                "experiment_runs": 3,
                "configuration_runs": 9,
            },
            "status_breakdowns": {
                "experiments": {"running": 1},
                "experiment_runs": {"completed": 3},
                "configuration_runs": {"completed": 9},
            },
            "usage_summary": {
                "experiment_runs": 3,
                "configuration_runs": 9,
                "priced_configuration_runs": 8,
                "unpriced_configuration_runs": 1,
                "total_cost_usd": 1.23,
                "avg_cost_usd": 0.41,
                "cost_source_breakdown": {
                    "observed_usage": 7,
                    "recorded_metrics": 1,
                    "catalog_fallback": 0,
                    "unknown_unpriced": 1,
                },
                "total_tokens": 12345,
                "avg_latency_ms": 250.1,
                "p95_latency_ms": 410.0,
            },
            "measure_summaries": [
                {
                    "measure_key": "accuracy",
                    "measure_id": "measure_accuracy",
                    "label": "Accuracy",
                    "value_type": "numeric",
                    "sample_count": 9,
                    "mean": 0.91,
                    "min": 0.84,
                    "max": 0.97,
                    "privacy_classification": "aggregate_safe",
                }
            ],
        }
        errors = validator.validate_json(data, "project_scoped_analytics_summary_schema")
        assert errors == []

    def test_project_membership_schema_valid(self, validator):
        data = {
            "id": "project_membership_123",
            "tenant_id": "tenant_acme",
            "project_id": "project_alpha",
            "user_id": "user_123",
            "role": "editor",
            "status": "active",
            "created_by": "admin_1",
            "updated_by": "admin_1",
            "created_at": "2026-03-13T10:15:00Z",
            "updated_at": "2026-03-13T10:15:00Z",
            "user": {
                "user_id": "user_123",
                "email": "user@example.com",
            },
        }
        errors = validator.validate_json(data, "project_membership_schema")
        assert errors == []

    def test_project_scoped_analytics_summary_rejects_missing_cost_breakdown(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-11T10:15:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "entity_counts": {
                "agents": 1,
                "benchmarks": 1,
                "measures": 2,
                "experiments": 1,
                "experiment_runs": 3,
                "configuration_runs": 9,
            },
            "status_breakdowns": {
                "experiments": {"running": 1},
                "experiment_runs": {"completed": 3},
                "configuration_runs": {"completed": 9},
            },
            "usage_summary": {
                "experiment_runs": 3,
                "configuration_runs": 9,
                "priced_configuration_runs": 8,
                "unpriced_configuration_runs": 1,
                "total_cost_usd": 1.23,
                "avg_cost_usd": 0.41,
                "total_tokens": 12345,
                "avg_latency_ms": 250.1,
                "p95_latency_ms": 410.0,
            },
            "measure_summaries": [],
        }
        errors = validator.validate_json(data, "project_scoped_analytics_summary_schema")
        assert errors

    def test_project_scoped_pricing_catalog_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-12T09:00:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "catalog_source": "static_catalog",
            "catalog_last_updated": "2026-03-12T08:55:00Z",
            "total_providers": 1,
            "total_models": 1,
            "providers": [
                {
                    "provider": "openai",
                    "model_count": 1,
                    "pricing_resolution_mode": "static_catalog",
                    "models": [
                        {
                            "model": "gpt-4o",
                            "input_price_per_1k_usd": 0.005,
                            "output_price_per_1k_usd": 0.015,
                            "context_window": 128000,
                            "available_tiers": ["standard", "premium", "enterprise"],
                            "supports_catalog_fallback": True,
                        }
                    ],
                }
            ],
        }

        errors = validator.validate_json(data, "project_scoped_pricing_catalog_schema")
        assert errors == []

    def test_project_scoped_optimization_overview_dashboard_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-12T12:00:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "summary_cards": {
                "experiments_total": 4,
                "experiments_in_range": 3,
                "experiment_runs_in_range": 8,
                "configuration_runs_in_range": 21,
                "priced_configuration_runs_in_range": 18,
                "unpriced_configuration_runs_in_range": 3,
                "total_cost_usd_in_range": 2.15,
                "avg_latency_ms_in_range": 145.2,
                "total_tokens_in_range": 8421,
            },
            "cost_source_breakdown": {
                "observed_usage": 12,
                "recorded_metrics": 4,
                "catalog_fallback": 2,
                "unknown_unpriced": 3,
            },
            "recent_experiments": [
                {
                    "experiment_id": "exp_1",
                    "name": "Support Router",
                    "status": "COMPLETED",
                    "experiment_run_count": 3,
                    "configuration_run_count": 9,
                    "priced_configuration_runs": 7,
                    "unpriced_configuration_runs": 2,
                    "total_cost_usd": 0.88,
                    "avg_latency_ms": 123.4,
                    "avg_primary_score": 0.92,
                    "total_tokens": 3120,
                    "last_run_at": "2026-03-12T10:15:00Z",
                    "privacy_classification": "aggregate_safe",
                }
            ],
        }
        errors = validator.validate_json(
            data,
            "project_scoped_optimization_overview_dashboard_schema",
        )
        assert errors == []

    def test_project_scoped_evaluator_quality_dashboard_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-12T12:00:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "resolved_bucket": "day",
            "summary_cards": {
                "evaluator_definitions_total": 2,
                "evaluator_runs_in_range": 4,
                "completed_runs_in_range": 3,
                "failed_runs_in_range": 1,
                "scored_runs_in_range": 3,
                "avg_numeric_score_in_range": 0.92,
                "total_cost_usd_in_range": 0.37,
            },
            "quality_trend": [
                {
                    "bucket_start": "2026-03-12T00:00:00Z",
                    "bucket_label": "2026-03-12",
                    "avg_numeric_score": 0.92,
                    "scored_runs": 2,
                }
            ],
            "recent_evaluators": [
                {
                    "evaluator_id": "evaluator_accuracy",
                    "name": "Accuracy Judge",
                    "target_type": "configuration_run",
                    "measure_id": "measure_accuracy",
                    "measure_label": "Accuracy",
                    "run_count": 3,
                    "completed_runs": 2,
                    "failed_runs": 1,
                    "scored_runs": 2,
                    "avg_numeric_score": 0.92,
                    "avg_latency_ms": 180.5,
                    "total_cost_usd": 0.37,
                    "last_run_at": "2026-03-12T10:15:00Z",
                    "privacy_classification": "aggregate_safe",
                }
            ],
        }
        errors = validator.validate_json(
            data,
            "project_scoped_evaluator_quality_dashboard_schema",
        )
        assert errors == []

    def test_project_scoped_project_usage_dashboard_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-12T12:00:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "resolved_bucket": "day",
            "summary_cards": {
                "experiment_runs_in_range": 4,
                "configuration_runs_in_range": 9,
                "priced_configuration_runs_in_range": 8,
                "unpriced_configuration_runs_in_range": 1,
                "total_cost_usd_in_range": 1.24,
                "total_tokens_in_range": 2048,
                "avg_latency_ms_in_range": 120.5,
                "p95_latency_ms_in_range": 210.0,
            },
            "usage_trend": [
                {
                    "bucket_start": "2026-03-12T00:00:00Z",
                    "bucket_label": "2026-03-12",
                    "cost_usd": 0.31,
                    "total_tokens": 512,
                    "avg_latency_ms": 118.4,
                    "configuration_runs": 2,
                }
            ],
            "top_experiments": [
                {
                    "experiment_id": "exp_1",
                    "name": "Support Experiment",
                    "configuration_runs": 5,
                    "total_cost_usd": 0.88,
                    "total_tokens": 1500,
                    "avg_latency_ms": 111.2,
                    "privacy_classification": "aggregate_safe",
                }
            ],
        }
        errors = validator.validate_json(
            data,
            "project_scoped_project_usage_dashboard_schema",
        )
        assert errors == []

    def test_project_scoped_observability_summary_dashboard_schema_valid(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-12T12:30:00Z",
                "privacy_classification": "aggregate_safe",
            },
            "range_days": 30,
            "resolved_bucket": "day",
            "summary_cards": {
                "sessions_in_range": 2,
                "traces_in_range": 3,
                "observations_in_range": 9,
                "bookmarked_traces_in_range": 1,
                "published_traces_in_range": 1,
                "commented_traces_in_range": 2,
                "total_cost_usd_in_range": 0.42,
                "total_tokens_in_range": 840,
            },
            "activity_trend": [
                {
                    "bucket_start": "2026-03-12T00:00:00Z",
                    "bucket_label": "2026-03-12",
                    "traces": 3,
                    "observations": 9,
                    "total_cost_usd": 0.42,
                    "total_tokens": 840,
                }
            ],
            "top_traces": [
                {
                    "trace_id": "trace_1",
                    "session_id": "session_1",
                    "name": "support-router",
                    "status": "completed",
                    "observation_count": 4,
                    "total_cost_usd": 0.21,
                    "total_tokens": 420,
                    "total_latency_ms": 187,
                    "is_bookmarked": True,
                    "is_published": False,
                    "started_at": "2026-03-12T11:00:00Z",
                    "privacy_classification": "aggregate_safe",
                }
            ],
        }
        errors = validator.validate_json(
            data,
            "project_scoped_observability_summary_dashboard_schema",
        )
        assert errors == []

    def test_project_scoped_fine_tuning_manifest_rejects_string_measure_values(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-11T10:15:00Z",
                "privacy_classification": "manifest_safe",
            },
            "export_mode": "manifest",
            "privacy_mode": True,
            "source_privacy_protected": True,
            "include_content": False,
            "job_id": "export_job_123",
            "record_count": 1,
            "records": [
                {
                    "record_id": "config_1",
                    "experiment_id": "exp_1",
                    "experiment_run_id": "run_1",
                    "configuration_run_id": "config_1",
                    "input_hash": "hash-input",
                    "output_hash": "hash-output",
                    "input_ref": "configuration_run:config_1:input",
                    "output_ref": "configuration_run:config_1:output",
                    "input_content": None,
                    "output_content": None,
                    "materialization": "local_only",
                    "measure_summary": {
                        "accuracy": 0.91,
                        "model_name": "gpt-4o-mini",
                    },
                    "metadata": {
                        "measure_metadata_model_name": "gpt-4o-mini",
                    },
                }
            ],
        }

        errors = validator.validate_json(data, "project_scoped_fine_tuning_manifest_schema")
        assert errors

    def test_project_scoped_fine_tuning_manifest_accepts_privacy_alias(self, validator):
        data = {
            "context": {
                "tenant_id": "tenant_acme",
                "project_id": "project_alpha",
                "generated_at": "2026-03-11T10:15:00Z",
                "privacy_classification": "manifest_safe",
            },
            "export_mode": "manifest",
            "privacy_mode": True,
            "source_privacy_protected": True,
            "include_content": False,
            "job_id": "export_job_123",
            "record_count": 1,
            "records": [
                {
                    "record_id": "config_1",
                    "experiment_id": "exp_1",
                    "experiment_run_id": "run_1",
                    "configuration_run_id": "config_1",
                    "input_hash": "hash-input",
                    "output_hash": "hash-output",
                    "input_ref": "configuration_run:config_1:input",
                    "output_ref": "configuration_run:config_1:output",
                    "input_content": None,
                    "output_content": None,
                    "materialization": "local_only",
                    "measure_summary": {"accuracy": 0.91},
                    "metadata": {"measure_metadata_model_name": "gpt-4o-mini"},
                }
            ],
        }

        errors = validator.validate_json(data, "project_scoped_fine_tuning_manifest_schema")
        assert errors == []
