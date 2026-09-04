# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Offline relying-party verification for Agent Certificate v0.

The verifier in this package is deliberately content-free at its failure
boundary.  It accepts a certificate envelope, already-resolved public keys,
fresh relying-party context, and an explicit pinned policy; it does not
resolve keys, contact Traigent, access a database, or inspect private evidence.
"""

from traigent_schema.certification.relying_party_verifier import (
    ClientCertificateProjection,
    RelyingPartyPolicy,
    RelyingPartyVerificationError,
    VerificationContext,
    VerificationError,
    VerificationResult,
    derive_client_key_ref,
    prepare_client_co_attestation,
    verify,
    verify_agent_certificate,
    verify_certificate,
    verify_certificate_with_materials,
)

__all__ = [
    "ClientCertificateProjection",
    "derive_client_key_ref",
    "RelyingPartyPolicy",
    "RelyingPartyVerificationError",
    "VerificationContext",
    "VerificationError",
    "VerificationResult",
    "verify_certificate",
    "verify_agent_certificate",
    "verify",
    "verify_certificate_with_materials",
    "prepare_client_co_attestation",
]
