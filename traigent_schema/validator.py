# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
Schema Validator for the Traigent platform.

Provides validation of API requests and JSON data against Traigent schemas.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker, ValidationError
from referencing import Registry, Resource

from traigent_schema.utils import ContractName, get_contract_path, get_schemas_dir

logger = logging.getLogger(__name__)
SCHEMA_ID_BASE = "https://schemas.traigent.ai/"


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

    def __init__(self, contract: ContractName = "backend"):
        """Initialize the validator with all available schemas."""
        self.contract = contract
        self._schemas: dict[str, dict[str, Any]] = {}
        self._endpoint_schemas: dict[str, str] = {}
        self._inline_request_schemas: dict[str, dict[str, Any]] = {}
        self._registry: Registry | None = None
        self._load_schemas()
        self._load_endpoint_mappings()

    @staticmethod
    def _resolve_package_relative_path(base_dir: Path, relative_path: str) -> Path | None:
        """Resolve an OpenAPI module path without allowing directory escape."""
        raw_path = Path(relative_path)
        if raw_path.is_absolute():
            return None

        base_root = base_dir.resolve()
        resolved_path = (base_dir / raw_path).resolve()
        if not resolved_path.is_relative_to(base_root):
            return None

        return resolved_path

    def _load_schemas(self) -> None:
        """Load all schema files into memory."""
        schemas_dir = get_schemas_dir()

        for schema_file in schemas_dir.rglob("*.json"):
            if "_endpoints" in schema_file.name:
                continue  # Skip endpoint definition files

            try:
                with open(schema_file, encoding='utf-8') as f:
                    schema = json.load(f)
                    if "$id" not in schema:
                        relative_path = schema_file.relative_to(schemas_dir).as_posix()
                        schema["$id"] = f"{SCHEMA_ID_BASE}{relative_path}"
                    schema_name = schema_file.stem
                    self._schemas[schema_name] = schema
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to load schema file %s: %s", schema_file, exc)

        self._build_registry()

    def _build_registry(self) -> None:
        """Build a jsonschema Registry for reference resolution."""
        resources: list[tuple[str, Resource[dict[str, Any]]]] = []
        for _name, schema in self._schemas.items():
            if "$id" in schema:
                resource: Resource[dict[str, Any]] = Resource.from_contents(schema)
                resources.append((schema["$id"], resource))

        self._registry = Registry().with_resources(resources)

    def _load_endpoint_mappings(self) -> None:
        """Load endpoint-to-schema mappings from OpenAPI spec."""
        try:
            openapi_path = get_contract_path(self.contract)
            if not openapi_path.exists():
                logger.warning(
                    "OpenAPI contract root %s does not exist for contract %s",
                    openapi_path,
                    self.contract,
                )
                return

            with open(openapi_path, encoding='utf-8') as f:
                openapi = json.load(f)

            self._parse_openapi(openapi)
            self._load_endpoint_modules(openapi, openapi_path.parent)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(
                "Failed to load OpenAPI contract root for %s: %s",
                self.contract,
                exc,
            )

    def _load_endpoint_modules(
        self,
        openapi: dict[str, Any],
        base_dir: Path,
    ) -> None:
        """Load endpoint mappings from module files referenced by the root spec."""
        for module in openapi.get("x-endpoint-modules", []):
            if not isinstance(module, dict):
                continue

            paths_file = module.get("paths_file")
            if not isinstance(paths_file, str):
                continue

            module_path = self._resolve_package_relative_path(base_dir, paths_file)
            if module_path is None:
                logger.warning(
                    "OpenAPI endpoint module %r referenced by contract %s escapes %s",
                    paths_file,
                    self.contract,
                    base_dir,
                )
                continue

            if not module_path.exists():
                logger.warning(
                    "OpenAPI endpoint module %s referenced by contract %s does not exist",
                    module_path,
                    self.contract,
                )
                continue

            try:
                with open(module_path, encoding="utf-8") as f:
                    module_openapi = json.load(f)
                    self._parse_openapi(module_openapi)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Failed to load endpoint module %s: %s", module_path, exc)
                continue

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
                json_schema = json_content.get("schema", {})
                schema_ref = json_schema.get("$ref", "")
                key = f"{method.upper()}:{path}"

                if schema_ref:
                    schema_name = schema_ref.split("/")[-1]
                    if schema_name.endswith(".json"):
                        schema_name = schema_name[:-5]
                    self._endpoint_schemas[key] = schema_name
                elif isinstance(json_schema, dict) and json_schema:
                    self._inline_request_schemas[key] = json_schema

    def validate_request(
        self,
        endpoint: str,
        method: str,
        data: dict[str, Any]
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
        endpoint = self._normalize_endpoint(method, endpoint)
        key = f"{method.upper()}:{endpoint}"
        schema_name = self._endpoint_schemas.get(key)
        inline_schema = self._inline_request_schemas.get(key)

        if not schema_name and not inline_schema:
            return []  # No schema defined for this endpoint

        if inline_schema:
            return self._validate_inline_schema(data, inline_schema)

        if schema_name is None:
            return [f"Schema not found for endpoint: {method.upper()} {endpoint}"]
        return self.validate_json(data, schema_name)

    @staticmethod
    def _template_matches_endpoint(template: str, endpoint: str) -> bool:
        """Match OpenAPI path templates without compiling dynamic regexes."""
        template_parts = template.split("/")
        endpoint_parts = endpoint.split("/")
        if len(template_parts) != len(endpoint_parts):
            return False

        for template_part, endpoint_part in zip(template_parts, endpoint_parts):
            if template_part.startswith("{") and template_part.endswith("}"):
                if not endpoint_part:
                    return False
                continue
            if template_part != endpoint_part:
                return False

        return True

    def _normalize_endpoint(self, method: str, endpoint: str) -> str:
        """Normalize concrete paths to OpenAPI path templates before lookup."""
        direct_key = f"{method.upper()}:{endpoint}"
        if (
            direct_key in self._endpoint_schemas
            or direct_key in self._inline_request_schemas
        ):
            return endpoint

        candidate_keys = {
            **self._endpoint_schemas,
            **self._inline_request_schemas,
        }
        for candidate_key in candidate_keys:
            candidate_method, candidate_path = candidate_key.split(":", 1)
            if candidate_method != method.upper():
                continue
            if self._template_matches_endpoint(candidate_path, endpoint):
                return candidate_path

        return endpoint

    def validate_json(
        self,
        data: dict[str, Any],
        schema_name: str
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
                format_checker=FormatChecker()
            )
            errors = list(validator.iter_errors(data))
            return [self._format_error(e) for e in errors]
        except Exception as e:
            return [f"Validation error: {str(e)}"]

    def _validate_inline_schema(
        self,
        data: dict[str, Any],
        schema: dict[str, Any],
    ) -> list[str]:
        """Validate JSON data against an inline request schema."""
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
