"""
Schema Validator for the Traigent platform.

Provides validation of API requests and JSON data against Traigent schemas.
"""

import json
import re
from typing import Any, Optional

from jsonschema import Draft7Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from traigent_schema.utils import get_openapi_path, get_schemas_dir


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
        self._schemas: dict[str, dict[str, Any]] = {}
        self._endpoint_schemas: dict[tuple[str, str], str] = {}
        self._endpoint_patterns: list[tuple[str, re.Pattern[str], str]] = []
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
                with open(schema_file, encoding="utf-8") as f:
                    schema = json.load(f)
                    schema_name = schema_file.stem

                    # Ensure schemas have a stable base URI so relative $refs resolve
                    if "$id" not in schema:
                        schema["$id"] = schema_file.resolve().as_uri()

                    self._schemas[schema_name] = schema
            except (OSError, json.JSONDecodeError):
                # Log warning but continue loading other schemas
                pass

        self._build_registry()

    def _build_registry(self) -> None:
        """Build a jsonschema Registry for reference resolution."""
        resources: list[tuple[str, Resource[dict[str, Any]]]] = []
        for name, schema in self._schemas.items():
            resource_uri = schema.get("$id")
            if not resource_uri:
                continue

            resource: Resource[dict[str, Any]] = Resource.from_contents(
                schema,
                default_specification=DRAFT7,
            )
            resources.append((resource_uri, resource))

            # Register with common alternate identifiers for convenience
            resources.append((name, resource))
            resources.append((f"{name}.json", resource))

        self._registry = Registry().with_resources(resources)

    def _load_endpoint_mappings(self) -> None:
        """Load endpoint-to-schema mappings from all endpoint specs."""
        schemas_dir = get_schemas_dir()
        endpoint_files = list(schemas_dir.rglob("*_endpoints.json"))

        for endpoint_file in endpoint_files:
            try:
                with open(endpoint_file, encoding="utf-8") as f:
                    openapi = json.load(f)
                    self._parse_openapi(openapi)
            except (OSError, json.JSONDecodeError):
                continue

        self._build_endpoint_patterns()

    def _parse_openapi(self, openapi: dict[str, Any]) -> None:
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

                if not schema_ref:
                    continue

                schema_name = self._extract_schema_name(schema_ref)
                if not schema_name:
                    continue

                path_template = self._normalize_path_template(path)
                key = (method.upper(), path_template)
                self._endpoint_schemas[key] = schema_name

    def _build_endpoint_patterns(self) -> None:
        """Precompile regex patterns for parameterized paths."""
        for (method, path_template), schema_name in self._endpoint_schemas.items():
            pattern = re.sub(r"\{[^/}]+\}", r"[^/]+", path_template)
            pattern = f"^{pattern.rstrip('/')}/?$"
            self._endpoint_patterns.append((method, re.compile(pattern), schema_name))

    def _extract_schema_name(self, schema_ref: str) -> str:
        """Extract schema name from a $ref, stripping fragments/extensions."""
        schema_ref = schema_ref.split("#", maxsplit=1)[0]
        stem = re.sub(r"\.json$", "", schema_ref.split("/")[-1])
        return stem

    def _normalize_path_template(self, path: str) -> str:
        """Normalize stored path templates for consistent matching."""
        normalized = path.split("?", maxsplit=1)[0]
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized.rstrip("/") or "/"

    def _normalize_request_path(self, path: str) -> str:
        """Normalize incoming request paths for matching."""
        normalized = path.split("?", maxsplit=1)[0]
        if normalized.startswith("/api/v1"):
            normalized = normalized[len("/api/v1") :]
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized.rstrip("/") or "/"

    def _match_pattern(self, method: str, path: str) -> Optional[str]:
        """Find a schema for a method/path by matching path parameters."""
        for stored_method, pattern, schema_name in self._endpoint_patterns:
            if stored_method == method and pattern.match(path):
                return schema_name
        return None

    def validate_request(
        self,
        endpoint: str,
        method: str,
        data: dict[str, Any],
    ) -> list[str]:
        """
        Validate a request against the schema for the given endpoint.

        Args:
            endpoint: API endpoint path (e.g., '/api/v1/agents')
            method: HTTP method (e.g., 'POST')
            data: Request body data to validate

        Returns:
            List of validation error messages. Empty if valid.
        """
        verb = method.upper()
        normalized_path = self._normalize_request_path(endpoint)
        template_key = (verb, normalized_path)

        schema_name = self._endpoint_schemas.get(template_key)
        if not schema_name:
            schema_name = self._match_pattern(verb, normalized_path)

        if not schema_name:
            return []  # No schema defined for this endpoint

        return self.validate_json(data, schema_name)

    def validate_json(
        self,
        data: dict[str, Any],
        schema_name: str,
    ) -> list[str]:
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
            validator = Draft7Validator(
                schema,
                registry=self._registry,
                format_checker=FormatChecker(),
            )
            errors = list(validator.iter_errors(data))
            return [self._format_error(e) for e in errors]
        except Exception as e:
            return [f"Validation error: {str(e)}"]

    def _format_error(self, error: ValidationError) -> str:
        """Format a validation error into a readable message."""
        path = ".".join(str(p) for p in error.absolute_path) or "root"
        return f"{path}: {error.message}"

    @property
    def available_schemas(self) -> list[str]:
        """Get list of available schema names."""
        return list(self._schemas.keys())
