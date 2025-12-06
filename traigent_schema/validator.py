"""
Schema Validator for the Traigent platform.

Provides validation of API requests and JSON data against Traigent schemas.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jsonschema
from jsonschema import Draft7Validator, ValidationError
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir, get_openapi_path, load_schema


class SchemaValidator:
    """
    Validates API requests and JSON data against Traigent schemas.

    This class loads all schemas on initialization and provides methods
    for validating requests against the appropriate schema based on
    endpoint and method.

    Example:
        validator = SchemaValidator()
        errors = validator.validate_request('/api/v1/agents', 'POST', data)
        if errors:
            print(f"Validation failed: {errors}")
    """

    def __init__(self):
        """Initialize the validator with all available schemas."""
        self._schemas: Dict[str, Dict[str, Any]] = {}
        self._endpoint_schemas: Dict[str, Dict[str, str]] = {}
        self._registry: Optional[Registry] = None
        self._load_schemas()
        self._load_endpoint_mappings()

    def _load_schemas(self) -> None:
        """Load all schema files into memory."""
        schemas_dir = get_schemas_dir()

        for schema_file in schemas_dir.rglob("*.json"):
            if "_endpoints" in schema_file.name:
                continue  # Skip endpoint definition files

            try:
                with open(schema_file, 'r', encoding='utf-8') as f:
                    schema = json.load(f)
                    schema_name = schema_file.stem
                    self._schemas[schema_name] = schema
            except (json.JSONDecodeError, IOError) as e:
                # Log warning but continue loading other schemas
                pass

        self._build_registry()

    def _build_registry(self) -> None:
        """Build a jsonschema Registry for reference resolution."""
        resources = []
        for name, schema in self._schemas.items():
            if "$id" in schema:
                resource = Resource.from_contents(schema)
                resources.append((schema["$id"], resource))

        self._registry = Registry().with_resources(resources)

    def _load_endpoint_mappings(self) -> None:
        """Load endpoint-to-schema mappings from OpenAPI spec."""
        try:
            openapi_path = get_openapi_path()
            if openapi_path.exists():
                with open(openapi_path, 'r', encoding='utf-8') as f:
                    openapi = json.load(f)
                    self._parse_openapi(openapi)
        except (json.JSONDecodeError, IOError):
            pass

    def _parse_openapi(self, openapi: Dict[str, Any]) -> None:
        """Parse OpenAPI spec to extract endpoint-schema mappings."""
        paths = openapi.get("paths", {})
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, spec in methods.items():
                if not isinstance(spec, dict):
                    continue
                request_body = spec.get("requestBody", {})
                content = request_body.get("content", {})
                json_content = content.get("application/json", {})
                schema_ref = json_content.get("schema", {}).get("$ref", "")

                if schema_ref:
                    schema_name = schema_ref.split("/")[-1]
                    key = f"{method.upper()}:{path}"
                    self._endpoint_schemas[key] = schema_name

    def validate_request(
        self,
        endpoint: str,
        method: str,
        data: Dict[str, Any]
    ) -> List[str]:
        """
        Validate a request against the schema for the given endpoint.

        Args:
            endpoint: API endpoint path (e.g., '/api/v1/agents')
            method: HTTP method (e.g., 'POST')
            data: Request body data to validate

        Returns:
            List of validation error messages. Empty if valid.
        """
        key = f"{method.upper()}:{endpoint}"
        schema_name = self._endpoint_schemas.get(key)

        if not schema_name:
            return []  # No schema defined for this endpoint

        return self.validate_json(data, schema_name)

    def validate_json(
        self,
        data: Dict[str, Any],
        schema_name: str
    ) -> List[str]:
        """
        Validate JSON data against a named schema.

        Args:
            data: Data to validate
            schema_name: Name of the schema to validate against

        Returns:
            List of validation error messages. Empty if valid.
        """
        schema = self._schemas.get(schema_name)
        if not schema:
            # Try with _schema suffix
            schema = self._schemas.get(f"{schema_name}_schema")

        if not schema:
            return [f"Schema not found: {schema_name}"]

        try:
            validator = Draft7Validator(schema, registry=self._registry)
            errors = list(validator.iter_errors(data))
            return [self._format_error(e) for e in errors]
        except Exception as e:
            return [f"Validation error: {str(e)}"]

    def _format_error(self, error: ValidationError) -> str:
        """Format a validation error into a readable message."""
        path = ".".join(str(p) for p in error.absolute_path) or "root"
        return f"{path}: {error.message}"

    @property
    def available_schemas(self) -> List[str]:
        """Get list of available schema names."""
        return list(self._schemas.keys())
