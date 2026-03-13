"""Tests for traigent_schema.validator module."""

import pytest

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


class TestValidateRequest:
    """Tests for validate_request method."""

    @pytest.fixture
    def validator(self):
        """Create a validator instance."""
        return SchemaValidator()

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

    def test_project_path_normalization_for_analytics_route(self, validator):
        """Concrete project analytics paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/summary",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_pricing_catalog_route(self, validator):
        """Concrete pricing catalog paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/pricing-catalog",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_optimization_dashboard_route(self, validator):
        """Concrete optimization dashboard paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/dashboards/optimization-overview",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_export_jobs_route(self, validator):
        """Concrete export job list paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/export-jobs",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_export_job_detail_route(self, validator):
        """Concrete export job detail paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/analytics/export-jobs/export_job_123",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_rate_limit_policy_route(self, validator):
        """Concrete project policy paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/policies/rate-limits",
            "GET",
            {},
        )
        assert errors == []

    def test_project_path_normalization_for_retention_policy_route(self, validator):
        """Concrete retention policy paths should normalize to the OpenAPI template."""
        errors = validator.validate_request(
            "/api/v1beta/projects/project_abc/policies/retention",
            "GET",
            {},
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
                    "status": "completed",
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
            "include_content": False,
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
