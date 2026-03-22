"""Tests for schema file integrity and structure."""

import json
from pathlib import Path

import pytest

from traigent_schema.utils import get_schemas_dir, get_all_schema_files


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
        """Schema files should not contain old OptiGen branding."""
        schema_files = get_all_schema_files()
        for schema_file in schema_files:
            with open(schema_file, 'r', encoding='utf-8') as f:
                content = f.read()

            assert "OptiGen" not in content, f"Found 'OptiGen' in {schema_file}"
            assert "optigen" not in content.lower(), \
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
