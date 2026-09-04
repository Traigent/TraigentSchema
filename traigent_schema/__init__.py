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

import importlib

from traigent_schema.analytics_validators import AnalyticsValidator
from traigent_schema.invariants import (
    InvariantComparisonBoundError,
    InvariantDeclarationError,
    InvariantNoncanonicalPayloadError,
    InvariantViolation,
    validate_declared_invariants,
)
from traigent_schema.utils import (
    get_all_schema_files,
    get_contract_path,
    get_openapi_path,
    get_schema_path,
    get_schemas_dir,
    load_schema,
)
from traigent_schema.validator import (
    SchemaDependencyError,
    SchemaValidator,
    UnvalidatedEndpointError,
)
from traigent_schema.version import __version__

_CERTIFICATION_EXPORTS = frozenset(
    {
        "CLIENT_CO_ATTESTATION_CONTEXT_FIELDS",
        "ClientCertificateProjection",
        "ClientCoAttestationContext",
        "derive_client_key_ref",
        "RelyingPartyPolicy",
        "RelyingPartyVerificationError",
        "VerificationContext",
        "VerificationError",
        "VerificationResult",
        "verify",
        "verify_agent_certificate",
        "verify_certificate",
        "verify_certificate_with_materials",
        "prepare_client_co_attestation",
    }
)


def __getattr__(name: str) -> object:
    """Load certification exports lazily while keeping their failure boundary clear."""
    if name not in _CERTIFICATION_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    try:
        certification = importlib.import_module("traigent_schema.certification")
    except ModuleNotFoundError as exc:
        if exc.name == "cryptography" or (exc.name or "").startswith("cryptography."):
            raise ImportError(
                "Certification exports require the base 'cryptography' dependency."
            ) from exc
        raise
    value = getattr(certification, name)
    globals()[name] = value
    return value

# Certification names remain available through explicit lazy imports above, but stay out
# of ``__all__`` to preserve the root package's lazy certification import boundary.
__all__ = [
    "AnalyticsValidator",
    "SchemaDependencyError",
    "InvariantComparisonBoundError",
    "InvariantDeclarationError",
    "InvariantNoncanonicalPayloadError",
    "InvariantViolation",
    "SchemaValidator",
    "UnvalidatedEndpointError",
    "get_schemas_dir",
    "get_schema_path",
    "get_all_schema_files",
    "get_contract_path",
    "get_openapi_path",
    "load_schema",
    "validate_declared_invariants",
    "__version__",
]
