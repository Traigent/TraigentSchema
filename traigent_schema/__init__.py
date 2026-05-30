# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
Traigent Schema Library

Provides JSON Schema definitions and validation utilities for the Traigent
AI optimization platform. This package serves as the single source of truth
for data contracts across all Traigent services.

Example:
    from traigent_schema import SchemaValidator, get_schemas_dir

    validator = SchemaValidator()
    validator.validate_request('/api/v1/agents', 'POST', request_data)
"""

from traigent_schema.analytics_validators import AnalyticsValidator
from traigent_schema.utils import (
    get_all_schema_files,
    get_contract_path,
    get_openapi_path,
    get_schema_path,
    get_schemas_dir,
    load_schema,
)
from traigent_schema.validator import SchemaValidator
from traigent_schema.version import __version__

__all__ = [
    "AnalyticsValidator",
    "SchemaValidator",
    "get_schemas_dir",
    "get_schema_path",
    "get_all_schema_files",
    "get_contract_path",
    "get_openapi_path",
    "load_schema",
    "__version__",
]
