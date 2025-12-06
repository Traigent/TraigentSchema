"""Tests for traigent_schema.utils module."""

import json
from pathlib import Path

import pytest

from traigent_schema.utils import (
    get_schemas_dir,
    get_schema_path,
    get_all_schema_files,
    get_openapi_path,
    load_schema,
)


class TestGetSchemasDir:
    """Tests for get_schemas_dir function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_schemas_dir()
        assert isinstance(result, Path)

    def test_directory_exists(self):
        """Should return a path that exists."""
        result = get_schemas_dir()
        assert result.exists()

    def test_is_directory(self):
        """Should return a path to a directory."""
        result = get_schemas_dir()
        assert result.is_dir()

    def test_contains_schemas(self):
        """Should contain JSON schema files."""
        result = get_schemas_dir()
        json_files = list(result.rglob("*.json"))
        assert len(json_files) > 0


class TestGetSchemaPath:
    """Tests for get_schema_path function."""

    def test_finds_root_schema(self):
        """Should find schemas in the root directory."""
        result = get_schema_path("mep")
        assert result.exists()
        assert result.name == "mep.json"

    def test_finds_schema_with_suffix(self):
        """Should find schemas with _schema suffix."""
        result = get_schema_path("agent_schema")
        assert result.exists()
        assert "agent_schema.json" in result.name

    def test_finds_schema_without_json_extension(self):
        """Should find schemas when .json is omitted."""
        result = get_schema_path("agent_schema")
        assert result.exists()

    def test_finds_schema_with_json_extension(self):
        """Should find schemas when .json is included."""
        result = get_schema_path("agent_schema.json")
        assert result.exists()

    def test_finds_schema_in_subdirectory(self):
        """Should find schemas in subdirectories."""
        result = get_schema_path("agent_schema")
        assert result.exists()
        assert "agents" in str(result)

    def test_raises_for_nonexistent_schema(self):
        """Should raise FileNotFoundError for missing schemas."""
        with pytest.raises(FileNotFoundError):
            get_schema_path("nonexistent_schema_xyz")


class TestGetAllSchemaFiles:
    """Tests for get_all_schema_files function."""

    def test_returns_list(self):
        """Should return a list."""
        result = get_all_schema_files()
        assert isinstance(result, list)

    def test_returns_paths(self):
        """Should return Path objects."""
        result = get_all_schema_files()
        assert all(isinstance(p, Path) for p in result)

    def test_returns_json_files(self):
        """Should return only JSON files."""
        result = get_all_schema_files()
        assert all(p.suffix == ".json" for p in result)

    def test_returns_multiple_files(self):
        """Should return multiple schema files."""
        result = get_all_schema_files()
        assert len(result) >= 30  # We know we have 38 files


class TestGetOpenapiPath:
    """Tests for get_openapi_path function."""

    def test_returns_path(self):
        """Should return a Path object."""
        result = get_openapi_path()
        assert isinstance(result, Path)

    def test_path_is_mep_endpoints(self):
        """Should return path to mep_endpoints.json."""
        result = get_openapi_path()
        assert result.name == "mep_endpoints.json"


class TestLoadSchema:
    """Tests for load_schema function."""

    def test_loads_schema_as_dict(self):
        """Should return a dictionary."""
        result = load_schema("agent_schema")
        assert isinstance(result, dict)

    def test_schema_has_required_fields(self):
        """Should contain expected schema fields."""
        result = load_schema("agent_schema")
        assert "$schema" in result or "type" in result

    def test_loads_different_schemas(self):
        """Should load various schemas correctly."""
        schemas = ["agent_schema", "experiment_schema", "measure_schema"]
        for schema_name in schemas:
            result = load_schema(schema_name)
            assert isinstance(result, dict)
