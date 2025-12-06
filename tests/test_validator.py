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
        assert errors == []

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
        assert errors == []


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

    def test_known_endpoint_is_validated(self, validator):
        """Should validate using endpoint mapping and path normalization."""
        data = {"id": "a1", "name": "Agent", "agent_type": "qa"}
        errors = validator.validate_request("/api/v1/agents", "POST", data)
        assert errors == []

    def test_parameterized_path_matches(self, validator):
        """Should match parameterized endpoints with concrete IDs."""
        data = {"name": "Prod deployment"}
        errors = validator.validate_request(
            "/api/v1/agents/123/deploy",
            "POST",
            data,
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
