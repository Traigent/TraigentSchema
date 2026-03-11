"""Tests for schema file integrity and structure."""

import json
from pathlib import Path

import pytest

from traigent_schema.utils import get_schemas_dir, get_all_schema_files
from traigent_schema import AnalyticsValidator, SchemaValidator


class TestSchemaFileIntegrity:
    """Tests to verify all schema files are valid JSON."""

    def test_all_json_files_parse(self):
        """All JSON files should parse without errors."""
        schema_files = get_all_schema_files()
        for schema_file in schema_files:
            try:
                with open(schema_file, 'r', encoding='utf-8') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Failed to parse {schema_file}: {e}")

    def test_schema_file_count(self):
        """Should have expected number of schema files."""
        schema_files = get_all_schema_files()
        # We migrated 38 files
        assert len(schema_files) >= 35


class TestSchemaStructure:
    """Tests for schema file structure."""

    @pytest.fixture
    def schemas_dir(self):
        """Get the schemas directory."""
        return get_schemas_dir()

    def test_has_agents_directory(self, schemas_dir):
        """Should have agents subdirectory."""
        agents_dir = schemas_dir / "agents"
        assert agents_dir.exists()
        assert agents_dir.is_dir()

    def test_has_datasets_directory(self, schemas_dir):
        """Should have datasets subdirectory."""
        datasets_dir = schemas_dir / "datasets"
        assert datasets_dir.exists()
        assert datasets_dir.is_dir()

    def test_has_evaluation_directory(self, schemas_dir):
        """Should have evaluation subdirectory."""
        evaluation_dir = schemas_dir / "evaluation"
        assert evaluation_dir.exists()
        assert evaluation_dir.is_dir()

    def test_has_execution_directory(self, schemas_dir):
        """Should have execution subdirectory."""
        execution_dir = schemas_dir / "execution"
        assert execution_dir.exists()
        assert execution_dir.is_dir()

    def test_has_measures_directory(self, schemas_dir):
        """Should have measures subdirectory."""
        measures_dir = schemas_dir / "measures"
        assert measures_dir.exists()
        assert measures_dir.is_dir()

    def test_has_results_directory(self, schemas_dir):
        """Should have results subdirectory."""
        results_dir = schemas_dir / "results"
        assert results_dir.exists()
        assert results_dir.is_dir()


class TestNoBrandingIssues:
    """Tests to verify proper rebranding."""

    def test_no_optigen_references(self):
        """Schema files should not contain OptiGen references."""
        schema_files = get_all_schema_files()
        for schema_file in schema_files:
            with open(schema_file, 'r', encoding='utf-8') as f:
                content = f.read()

            assert "OptiGen" not in content, f"Found 'OptiGen' in {schema_file}"
            assert "optigen" not in content.lower() or "traigent" in content.lower(), \
                f"Found 'optigen' in {schema_file}"


class TestRequiredSchemas:
    """Tests to verify all required schemas exist."""

    @pytest.fixture
    def schemas_dir(self):
        """Get the schemas directory."""
        return get_schemas_dir()

    def test_mep_json_exists(self, schemas_dir):
        """Should have mep.json root file."""
        assert (schemas_dir / "mep.json").exists()

    def test_mep_endpoints_exists(self, schemas_dir):
        """Should have mep_endpoints.json."""
        assert (schemas_dir / "mep_endpoints.json").exists()

    def test_agent_schema_exists(self, schemas_dir):
        """Should have agent_schema.json."""
        assert (schemas_dir / "agents" / "agent_schema.json").exists()

    def test_experiment_schema_exists(self, schemas_dir):
        """Should have experiment_schema.json."""
        assert (schemas_dir / "evaluation" / "experiment_schema.json").exists()

    def test_measure_schema_exists(self, schemas_dir):
        """Should have measure_schema.json."""
        assert (schemas_dir / "measures" / "measure_schema.json").exists()

    def test_project_schema_exists(self, schemas_dir):
        """Should have project_schema.json."""
        assert (schemas_dir / "projects" / "project_schema.json").exists()

    def test_project_analytics_summary_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_analytics_summary_schema.json"
        ).exists()

    def test_project_analytics_trend_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_analytics_trend_schema.json"
        ).exists()

    def test_project_measure_distribution_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_measure_distribution_schema.json"
        ).exists()

    def test_project_fine_tuning_manifest_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_fine_tuning_manifest_schema.json"
        ).exists()


class TestExampleMetricsSchema:
    """Tests for ExampleMetrics nested structure validation.

    The ExampleMetrics structure separates example identification from
    metric values to prevent example_id from being stripped during validation.

    Structure: {"example_id": "ex_...", "metrics": {"score": 0.85, ...}}
    """

    @pytest.fixture
    def validator(self):
        """Create an AnalyticsValidator instance."""
        return AnalyticsValidator()

    def test_valid_nested_format_passes(self, validator):
        """Valid nested format should pass validation."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"score": 0.85, "cost": 0.05}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_nested_format_with_null_metric(self, validator):
        """Valid nested format with null metric values should pass."""
        data = {
            "example_id": "ex_abc12345de_42",
            "metrics": {"score": 0.85, "pending_metric": None}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_nested_format_empty_metrics(self, validator):
        """Valid nested format with empty metrics dict should pass."""
        data = {
            "example_id": "ex_abc12345de_0",
            "metrics": {}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_missing_example_id_fails(self, validator):
        """Missing example_id should fail."""
        data = {"metrics": {"score": 0.85}}
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("example_id" in e for e in errors)

    def test_missing_metrics_fails(self, validator):
        """Missing metrics should fail."""
        data = {"example_id": "ex_a3f4b2c8d1_0"}
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("metrics" in e for e in errors)

    def test_invalid_example_id_format_fails(self, validator):
        """Invalid example_id format should fail."""
        data = {
            "example_id": "invalid_format",
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("example_id" in e.lower() or "format" in e.lower() for e in errors)

    def test_example_id_uppercase_hex_fails(self, validator):
        """Example ID with uppercase hex should fail."""
        data = {
            "example_id": "ex_ABC12345_0",  # Uppercase not allowed
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0

    def test_example_id_wrong_prefix_fails(self, validator):
        """Example ID with wrong prefix should fail."""
        data = {
            "example_id": "example_abc12345_0",  # Should be 'ex_'
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0

    def test_non_numeric_metric_fails(self, validator):
        """Non-numeric metric values should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"score": "not a number"}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("score" in e or "numeric" in e for e in errors)

    def test_boolean_metric_fails(self, validator):
        """Boolean metric values should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"passed": True}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("passed" in e or "numeric" in e for e in errors)

    def test_exceeding_max_metrics_fails(self, validator):
        """More than 50 metrics should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {f"metric_{i}": float(i) for i in range(51)}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("50" in e or "max" in e.lower() for e in errors)

    def test_exactly_50_metrics_passes(self, validator):
        """Exactly 50 metrics should pass."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {f"metric_{i}": float(i) / 100 for i in range(50)}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"


class TestProjectContracts:
    """Tests for project-layer schema contracts and path normalization."""

    @pytest.fixture
    def validator(self):
        return SchemaValidator()

    @pytest.fixture
    def analytics_validator(self):
        return AnalyticsValidator()

    def test_project_create_request_validates_against_schema(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects",
            "POST",
            {
                "name": "Core Platform",
                "slug": "core-platform",
                "description": "Primary project"
            },
        )
        assert errors == []

    def test_project_update_request_uses_templated_path_normalization(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123",
            "PATCH",
            {"name": "Updated Name"},
        )
        assert errors == []

    def test_project_update_request_reports_validation_errors(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123",
            "PATCH",
            {},
        )
        assert errors

    def test_project_analytics_summary_path_normalizes_and_validates(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/analytics/summary",
            "GET",
            {},
        )
        assert errors == []

    def test_project_run_volume_trend_path_normalizes_and_validates(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/analytics/trends/run-volume",
            "GET",
            {},
        )
        assert errors == []

    def test_metrics_not_dict_fails(self, analytics_validator):
        """Metrics as non-dict type should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": [0.85, 0.05]  # Array instead of dict
        }
        errors = analytics_validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("dict" in e for e in errors)

    def test_example_id_not_string_fails(self, analytics_validator):
        """Example ID as non-string type should fail."""
        data = {
            "example_id": 12345,  # Number instead of string
            "metrics": {"score": 0.85}
        }
        errors = analytics_validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("string" in e or "example_id" in e for e in errors)

    def test_project_analytics_schemas_define_privacy_classification(self):
        schemas_dir = get_schemas_dir()
        schema_names = [
            "project_scoped_analytics_summary_schema.json",
            "project_scoped_analytics_trend_schema.json",
            "project_scoped_measure_distribution_schema.json",
            "project_scoped_fine_tuning_manifest_schema.json",
        ]
        for schema_name in schema_names:
            with open(schemas_dir / "projects" / schema_name, encoding="utf-8") as handle:
                payload = json.load(handle)
            assert payload.get("x-privacy-classification") in {"aggregate_safe", "manifest_safe"}
