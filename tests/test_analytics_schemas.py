"""Tests for analytics schemas and validators.

Comprehensive test suite for ExampleScore, DatasetQuality, and ScoringJobStatus
schemas, as well as the AnalyticsValidator helper class.
"""

import json
from pathlib import Path

import pytest

from traigent_schema import AnalyticsValidator, SchemaValidator


@pytest.fixture
def validator():
    """Create a SchemaValidator instance."""
    return SchemaValidator()


@pytest.fixture
def analytics_validator():
    """Create an AnalyticsValidator instance."""
    return AnalyticsValidator()


@pytest.fixture
def test_data_dir():
    """Return path to analytics test data directory."""
    return Path(__file__).parent / "test_data" / "analytics"


class TestExampleScoreSchema:
    """Tests for ExampleScore schema validation."""

    def test_valid_complete_example_score(self, validator, test_data_dir):
        """Should validate complete valid example score."""
        with open(test_data_dir / "example_score_valid.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "example_score_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_minimal_example_score(self, validator, test_data_dir):
        """Should validate minimal valid example score (only required fields)."""
        with open(test_data_dir / "example_score_minimal.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "example_score_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_invalid_example_score_rejects(self, validator, test_data_dir):
        """Should reject invalid example score data."""
        with open(test_data_dir / "example_score_invalid.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0, "Expected validation errors for invalid data"

    def test_score_above_one_rejected(self, validator):
        """Should reject scores above 1.0."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "content_uniqueness": 1.5,  # Invalid: > 1.0
            "algorithm_version": "1.0.0"
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0
        assert any("content_uniqueness" in e or "maximum" in e for e in errors)

    def test_score_below_zero_rejected(self, validator):
        """Should reject scores below 0.0."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "informativeness": -0.1,  # Invalid: < 0.0
            "algorithm_version": "1.0.0"
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0
        assert any("informativeness" in e or "minimum" in e for e in errors)

    def test_invalid_example_id_pattern_rejected(self, validator):
        """Should reject invalid example_id pattern."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "invalid_format",  # Wrong pattern
            "algorithm_version": "1.0.0"
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0
        assert any("example_id" in e or "pattern" in e for e in errors)

    def test_invalid_algorithm_version_rejected(self, validator):
        """Should reject invalid algorithm version."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "algorithm_version": "v1.0"  # Invalid: doesn't match semver
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0
        assert any("algorithm_version" in e or "pattern" in e for e in errors)

    def test_missing_required_fields_rejected(self, validator):
        """Should reject data missing required fields."""
        data = {
            "content_uniqueness": 0.5
            # Missing: experiment_run_id, example_id, algorithm_version
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0

    def test_null_scores_accepted(self, validator):
        """Should accept null scores (valid for partial computation)."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "algorithm_version": "1.0.0",
            "content_uniqueness": None,
            "informativeness": None
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_additional_properties_rejected(self, validator):
        """Should reject unknown properties."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "algorithm_version": "1.0.0",
            "unknown_field": "value"  # Not allowed
        }

        errors = validator.validate_json(data, "example_score_schema")
        assert len(errors) > 0
        assert any("unknown_field" in e or "Additional properties" in e for e in errors)


class TestDatasetQualitySchema:
    """Tests for DatasetQuality schema validation."""

    def test_valid_dataset_quality(self, validator, test_data_dir):
        """Should validate complete valid dataset quality."""
        with open(test_data_dir / "dataset_quality_valid.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_minimal_dataset_quality(self, validator):
        """Should validate minimal dataset quality (only required fields)."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0"
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_top_ids_capped_at_20(self, validator):
        """Should reject top_informative_ids array exceeding 20 items."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "top_informative_ids": [f"ex_abc{i:08d}_0" for i in range(21)]  # 21 items
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert len(errors) > 0
        assert any("maxItems" in e or "top_informative_ids" in e for e in errors)

    def test_redundant_pairs_must_be_pairs(self, validator):
        """Should reject redundant_pairs with wrong number of items."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "redundant_pairs": [
                ["ex_abc12345_0", "ex_abc12345_1"],  # Valid pair
                ["ex_abc12345_2"]  # Invalid: not a pair
            ]
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert len(errors) > 0
        assert any("minItems" in e or "redundant_pairs" in e for e in errors)

    def test_redundant_pairs_capped_at_50(self, validator):
        """Should reject redundant_pairs array exceeding 50 pairs."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "redundant_pairs": [
                [f"ex_a{i:09d}_0", f"ex_b{i:09d}_1"] for i in range(51)  # 51 pairs
            ]
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert len(errors) > 0
        assert any("maxItems" in e or "redundant_pairs" in e for e in errors)

    def test_recommendation_type_enum_validated(self, validator):
        """Should reject invalid recommendation type."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "recommendations": [
                {
                    "type": "invalid_type",  # Not in enum
                    "message": "Test message"
                }
            ]
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert len(errors) > 0
        assert any("type" in e or "enum" in e for e in errors)

    def test_recommendation_action_enum_validated(self, validator):
        """Should reject invalid recommendation action."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "recommendations": [
                {
                    "type": "info",
                    "message": "Test message",
                    "action": "invalid_action"  # Not in enum
                }
            ]
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert len(errors) > 0
        assert any("action" in e or "enum" in e for e in errors)

    def test_valid_recommendation_types(self, validator):
        """Should accept all valid recommendation types."""
        for rec_type in ["info", "warning", "critical"]:
            data = {
                "experiment_run_id": "exp_123",
                "algorithm_version": "1.0.0",
                "recommendations": [
                    {"type": rec_type, "message": "Test"}
                ]
            }
            errors = validator.validate_json(data, "dataset_quality_schema")
            assert errors == [], f"Unexpected errors for type {rec_type}: {errors}"

    def test_valid_recommendation_actions(self, validator):
        """Should accept all valid recommendation actions."""
        for action in ["remove", "add_similar", "review", None]:
            data = {
                "experiment_run_id": "exp_123",
                "algorithm_version": "1.0.0",
                "recommendations": [
                    {"type": "info", "message": "Test", "action": action}
                ]
            }
            errors = validator.validate_json(data, "dataset_quality_schema")
            assert errors == [], f"Unexpected errors for action {action}: {errors}"

    def test_score_distributions_flexible(self, validator):
        """Should accept flexible score distributions structure."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0",
            "score_distributions": {
                "informativeness": {
                    "mean": 0.75,
                    "std": 0.12,
                    "min": 0.45,
                    "max": 0.95,
                    "median": 0.78
                },
                "difficulty": {
                    "mean": 0.65,
                    "std": 0.15
                }
            }
        }

        errors = validator.validate_json(data, "dataset_quality_schema")
        assert errors == [], f"Unexpected errors: {errors}"


class TestScoringJobStatusSchema:
    """Tests for ScoringJobStatus schema validation."""

    def test_running_status_valid(self, validator, test_data_dir):
        """Should validate running status."""
        with open(test_data_dir / "scoring_job_status_running.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_completed_status_valid(self, validator, test_data_dir):
        """Should validate completed status with result."""
        with open(test_data_dir / "scoring_job_status_completed.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_failed_status_valid(self, validator, test_data_dir):
        """Should validate failed status with error."""
        with open(test_data_dir / "scoring_job_status_failed.json") as f:
            data = json.load(f)

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_accepted_status_valid(self, validator):
        """Should validate accepted status without result or error."""
        data = {
            "status": "accepted",
            "job_id": "score_run123_1234567890"
        }

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    @pytest.mark.parametrize(
        "data",
        [
            {
                "status": "completed",
                "job_id": "score_run123_1234567890",
            },
            {
                "status": "completed",
                "job_id": "score_run123_1234567890",
                "result": None,
            },
        ],
    )
    def test_completed_without_result_rejected(self, validator, data):
        """Should reject completed status without an object result."""

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert any("not valid under any of the given schemas" in e for e in errors)

    @pytest.mark.parametrize(
        "data",
        [
            {
                "status": "failed",
                "job_id": "score_run123_1234567890",
            },
            {
                "status": "failed",
                "job_id": "score_run123_1234567890",
                "error": None,
            },
        ],
    )
    def test_failed_without_error_rejected(self, validator, data):
        """Should reject failed status without a string error."""

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert any("not valid under any of the given schemas" in e for e in errors)

    def test_invalid_status_rejected(self, validator):
        """Should reject invalid status value."""
        data = {
            "status": "invalid_status",
            "job_id": "score_run123_1234567890"
        }

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert len(errors) > 0
        assert any("status" in e or "enum" in e for e in errors)

    def test_invalid_job_id_pattern_rejected(self, validator):
        """Should reject invalid job_id pattern."""
        data = {
            "status": "accepted",
            "job_id": "invalid_job_id"  # Doesn't match pattern
        }

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert len(errors) > 0
        assert any("job_id" in e or "pattern" in e for e in errors)

    def test_result_requires_experiment_run_id(self, validator):
        """Should require experiment_run_id in result."""
        data = {
            "status": "completed",
            "job_id": "score_run123_1234567890",
            "result": {
                "num_examples": 50
                # Missing experiment_run_id
            }
        }

        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert len(errors) > 0


class TestAnalyticsValidator:
    """Tests for AnalyticsValidator helper class."""

    def test_creates_instance(self, analytics_validator):
        """Should create validator instance."""
        assert analytics_validator is not None

    def test_available_schemas_property(self, analytics_validator):
        """Should list available analytics schemas."""
        schemas = analytics_validator.available_schemas
        assert "example_score_schema" in schemas
        assert "dataset_quality_schema" in schemas
        assert "scoring_job_status_schema" in schemas

    def test_validate_example_score_returns_errors(self, analytics_validator):
        """Should return validation errors as list."""
        data = {"invalid": "data"}
        errors = analytics_validator.validate_example_score(data)
        assert isinstance(errors, list)
        assert len(errors) > 0

    def test_validate_dataset_quality_returns_errors(self, analytics_validator):
        """Should return validation errors as list."""
        data = {"invalid": "data"}
        errors = analytics_validator.validate_dataset_quality(data)
        assert isinstance(errors, list)
        assert len(errors) > 0

    def test_validate_scoring_job_status_returns_errors(self, analytics_validator):
        """Should return validation errors as list."""
        data = {"invalid": "data"}
        errors = analytics_validator.validate_scoring_job_status(data)
        assert isinstance(errors, list)
        assert len(errors) > 0

    def test_validate_example_id_format_valid(self, analytics_validator):
        """Should validate correct example ID formats."""
        assert analytics_validator.validate_example_id_format("ex_abc12345_0")
        assert analytics_validator.validate_example_id_format("ex_1234abcd_999")
        assert analytics_validator.validate_example_id_format("ex_aabbccdd_0")
        assert analytics_validator.validate_example_id_format("ex_0123456789ab_123")

    def test_validate_example_id_format_invalid(self, analytics_validator):
        """Should reject invalid example ID formats."""
        assert not analytics_validator.validate_example_id_format("invalid")
        assert not analytics_validator.validate_example_id_format("ex_ABC_0")  # Uppercase
        assert not analytics_validator.validate_example_id_format("ex_abc_0")  # Too short hash
        assert not analytics_validator.validate_example_id_format("ex_abc12345")  # Missing index
        assert not analytics_validator.validate_example_id_format("abc12345_0")  # Missing prefix

    def test_validate_job_id_format_valid(self, analytics_validator):
        """Should validate correct job ID formats."""
        assert analytics_validator.validate_job_id_format("score_run123_1234567890")
        assert analytics_validator.validate_job_id_format("score_exp-abc_123")
        assert analytics_validator.validate_job_id_format("score_test_1")

    def test_validate_job_id_format_invalid(self, analytics_validator):
        """Should reject invalid job ID formats."""
        assert not analytics_validator.validate_job_id_format("invalid")
        assert not analytics_validator.validate_job_id_format("job_123_456")  # Wrong prefix
        assert not analytics_validator.validate_job_id_format("score_run")  # Missing timestamp

    def test_validate_score_range_valid(self, analytics_validator):
        """Should validate scores in [0, 1] range."""
        assert analytics_validator.validate_score_range(0.0)
        assert analytics_validator.validate_score_range(0.5)
        assert analytics_validator.validate_score_range(1.0)

    def test_validate_score_range_invalid(self, analytics_validator):
        """Should reject scores outside [0, 1] range."""
        assert not analytics_validator.validate_score_range(-0.1)
        assert not analytics_validator.validate_score_range(1.1)
        assert not analytics_validator.validate_score_range(-1.0)
        assert not analytics_validator.validate_score_range(2.0)

    def test_validate_algorithm_version_valid(self, analytics_validator):
        """Should validate correct semver formats."""
        assert analytics_validator.validate_algorithm_version("1.0.0")
        assert analytics_validator.validate_algorithm_version("2.5.3")
        assert analytics_validator.validate_algorithm_version("10.20.30")

    def test_validate_algorithm_version_invalid(self, analytics_validator):
        """Should reject invalid semver formats."""
        assert not analytics_validator.validate_algorithm_version("v1.0.0")  # v prefix
        assert not analytics_validator.validate_algorithm_version("1.0")  # Missing patch
        assert not analytics_validator.validate_algorithm_version("1.0.0-beta")  # Pre-release
        assert not analytics_validator.validate_algorithm_version("1")  # Only major

    def test_validate_recommendation_type_valid(self, analytics_validator):
        """Should validate valid recommendation types."""
        assert analytics_validator.validate_recommendation_type("info")
        assert analytics_validator.validate_recommendation_type("warning")
        assert analytics_validator.validate_recommendation_type("critical")

    def test_validate_recommendation_type_invalid(self, analytics_validator):
        """Should reject invalid recommendation types."""
        assert not analytics_validator.validate_recommendation_type("error")
        assert not analytics_validator.validate_recommendation_type("notice")
        assert not analytics_validator.validate_recommendation_type("")

    def test_validate_recommendation_action_valid(self, analytics_validator):
        """Should validate valid recommendation actions."""
        assert analytics_validator.validate_recommendation_action("remove")
        assert analytics_validator.validate_recommendation_action("add_similar")
        assert analytics_validator.validate_recommendation_action("review")
        assert analytics_validator.validate_recommendation_action(None)

    def test_validate_recommendation_action_invalid(self, analytics_validator):
        """Should reject invalid recommendation actions."""
        assert not analytics_validator.validate_recommendation_action("delete")
        assert not analytics_validator.validate_recommendation_action("ignore")
        assert not analytics_validator.validate_recommendation_action("")


class TestSchemaDiscovery:
    """Tests to ensure schemas are discovered by the validator."""

    def test_analytics_schemas_discovered(self, validator):
        """Should discover all analytics schemas."""
        schemas = validator.available_schemas
        assert "example_score_schema" in schemas
        assert "dataset_quality_schema" in schemas
        assert "scoring_job_status_schema" in schemas

    def test_example_score_schema_loadable(self, validator):
        """Should be able to validate against example_score_schema."""
        data = {
            "experiment_run_id": "exp_123",
            "example_id": "ex_abc12345_0",
            "algorithm_version": "1.0.0"
        }
        errors = validator.validate_json(data, "example_score_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_dataset_quality_schema_loadable(self, validator):
        """Should be able to validate against dataset_quality_schema."""
        data = {
            "experiment_run_id": "exp_123",
            "algorithm_version": "1.0.0"
        }
        errors = validator.validate_json(data, "dataset_quality_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_scoring_job_status_schema_loadable(self, validator):
        """Should be able to validate against scoring_job_status_schema."""
        data = {
            "status": "accepted",
            "job_id": "score_run123_1234567890"
        }
        errors = validator.validate_json(data, "scoring_job_status_schema")
        assert errors == [], f"Unexpected errors: {errors}"
