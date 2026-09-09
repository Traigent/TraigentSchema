# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
"""Private building blocks for the evaluator-quality certificate verifier.

The public verifier is deliberately added in a later packet.  This module
owns the schema-derived vocabulary and the digest/signature primitives used by
that verifier; it does not make a verification decision yet.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from importlib import resources
from typing import Any, NoReturn, cast

import traigent_schema.fp2 as fp2
from traigent_schema.certification.process_record_verifier import (
    _load_registry_constant,
    _material_public_key,
    _verify_signature,
)

_SCHEMA_RESOURCE = (
    resources.files("traigent_schema")
    .joinpath("schemas")
    .joinpath("certification")
    .joinpath("evaluator_quality_v1_schema.json")
)


def _schema_definition(name: str) -> dict[str, Any]:
    document = json.loads(_SCHEMA_RESOURCE.read_text(encoding="utf-8"))
    return cast(dict[str, Any], document["definitions"][name])


def _const_registry(name: str) -> dict[str, str]:
    definition = _schema_definition(name)
    return {
        key: cast(str, value["const"])
        for key, value in cast(dict[str, Any], definition["properties"]).items()
    }


EVALUATOR_QUALITY_FIELD_LOCATIONS = frozenset(
    _schema_definition("EvaluatorQualityFieldLocationV1")["enum"]
)
_DIGEST_DOMAINS = _const_registry("EvaluatorQualityDigestDomainRegistryV1")

_EVALUATOR_QUALITY_REGISTRY_DOMAINS = {
    "measurement_registry": _DIGEST_DOMAINS["measurement_registry"],
    "perturbation_set": _DIGEST_DOMAINS["perturbation_set"],
    "assertion_templates": _DIGEST_DOMAINS["assertion_templates"],
}

# This is the module-owned vocabulary reserved by the complete guard sequence.
# The public entry point and its reachable guards land in later packets; this
# packet deliberately exposes only the shared vocabulary and primitives.
EVALUATOR_QUALITY_ERROR_CODES = frozenset(
    {
        "CONTEXT",
        "EVALUATOR_BUNDLE_SHAPE",
        "EVALUATOR_SCHEMA",
        "EVALUATOR_SCHEMA_DEPENDENCY",
        "EVALUATOR_STRICT_INTEGER",
        "EVALUATOR_CANONICALIZATION",
        "INSTRUMENT_ADEQUACY_MISMATCH",
        "OVERALL_VERDICT_UNSUPPORTED",
        "EVALUATOR_COMMITMENT_MISMATCH",
        "SCOPE_BINDING_MISMATCH",
        "DESCRIPTOR_DIGEST_MISMATCH",
        "DESCRIPTOR_OPENING_INVALID",
        "DESCRIPTOR_DISCLOSURE_MODE_CONFLICT",
        "REFERENCE_STANDARD_DIGEST_MISMATCH",
        "REFERENCE_CEILING_EXCEEDED",
        "REFERENCE_FLOOR_VIOLATED",
        "REFERENCE_RATER_COUPLING",
        "EVALUATION_SCOPE_DIGEST_MISMATCH",
        "SELECTION_SET_OVERLAP",
        "REGISTRY_DIGEST_MISMATCH",
        "ESTIMATOR_NOT_REGISTERED",
        "ESTIMATOR_PARAMS_NOT_ADMISSIBLE",
        "UNIT_NOT_ADMISSIBLE",
        "INTERVAL_MALFORMED",
        "INTERVAL_WIDTH_EXCEEDED",
        "THRESHOLD_NOT_MET",
        "SAMPLE_SIZE_INSUFFICIENT",
        "RESAMPLE_UNIT_MISMATCH",
        "DECLARED_PLAN_DIGEST_MISMATCH",
        "DECLARED_PLAN_SCOPE_VIOLATION",
        "DECLARED_PLAN_ORDER",
        "DECLARED_PLAN_BASIS_INSUFFICIENT",
        "MEASUREMENT_ROLE_DUPLICATE",
        "SENSITIVITY_PAIR_SET_INCOMPLETE",
        "PERTURBATION_SET_MISMATCH",
        "PROBE_COVERAGE_INSUFFICIENT",
        "RELIABILITY_DETERMINISM_CONTRADICTION",
        "RELIABILITY_AXIS_MISSING",
        "AGGREGATION_POLICY_MISMATCH",
        "AGGREGATION_RENORMALIZED",
        "AGGREGATION_DERIVATION_MISMATCH",
        "MEASUREMENT_BASIS_INSUFFICIENT",
        "TRANSCRIPT_DIGEST_MISSING",
        "VERDICT_NOT_SUPPORTED",
        "CLAIM_TIER_MISMATCH",
        "CLAIM_SUPPORT_ROW_MISMATCH",
        "CLAIM_MATERIAL_MISMATCH",
        "NON_CLAIM_TUPLE_MISMATCH",
        "EVALUATOR_ARTIFACT_DIGEST_MISMATCH",
        "EVALUATOR_UNSIGNED_MANIFEST_MISMATCH",
        "EVALUATOR_MANIFEST_DIGEST_MISMATCH",
        "EVALUATOR_KEY_RING_MISMATCH",
        "EVALUATOR_ISSUER_SIGNATURE_INVALID",
        "EVALUATOR_VERIFICATION_FAILED",
    }
)


class EvaluatorQualityVerificationError(ValueError):
    """Content-free, closed-vocabulary verification failure."""

    def __init__(self, code: str, field: str) -> None:
        if code not in EVALUATOR_QUALITY_ERROR_CODES:
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_ERROR_CODE")
        if field not in EVALUATOR_QUALITY_FIELD_LOCATIONS:
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_ERROR_FIELD")
        self.code = code
        self.field = field
        super().__init__(code)


def _fail(code: str, field: str) -> NoReturn:
    failure = EvaluatorQualityVerificationError(code, field)
    try:
        raise failure from None
    except EvaluatorQualityVerificationError:
        failure.__context__ = None
        raise


def _role_digest(domain: str, projection: Any) -> str:
    """Return SHA-256(UTF8(domain) || NUL || jcs_v1(projection))."""
    canonical = b""
    try:
        canonical = fp2.canonicalize(projection).encode("utf-8")
    except Exception:
        _fail("EVALUATOR_CANONICALIZATION", "bundle")
    return "sha256:" + hashlib.sha256(domain.encode() + b"\0" + canonical).hexdigest()


def _strip_self_digest(payload: dict[str, Any], field_name: str) -> dict[str, Any]:
    """Copy a digest-bearing projection without its own digest member."""
    projection = dict(payload)
    projection.pop(field_name, None)
    return projection


def _domain(role: str) -> str:
    return _DIGEST_DOMAINS[role]


def _read_evaluator_quality_package_json(filename: str) -> Any:
    package = resources.files("traigent_schema")
    node = package.joinpath("data").joinpath("certification").joinpath(filename)
    return json.loads(node.read_text(encoding="utf-8"))


@lru_cache(maxsize=3)
def _load_evaluator_quality_document(stem: str) -> dict[str, Any]:
    """Load one registry and verify its content-free, role-separated pin."""
    field = stem if stem in _EVALUATOR_QUALITY_REGISTRY_DOMAINS else "bundle"
    loaded: dict[str, Any] | None
    try:
        domain = _EVALUATOR_QUALITY_REGISTRY_DOMAINS[stem]
        document = _read_evaluator_quality_package_json(f"evaluator_{stem}.json")
        sidecar = _read_evaluator_quality_package_json(f"evaluator_{stem}.digest.json")
        if not isinstance(document, dict) or not isinstance(sidecar, dict):
            raise ValueError("invalid registry")
        digest = sidecar.get("digest")
        if type(digest) is not str or _role_digest(domain, document) != digest:
            raise ValueError("registry digest mismatch")
        loaded = document
    except Exception:
        loaded = None
    if loaded is None:
        failure = EvaluatorQualityVerificationError("REGISTRY_DIGEST_MISMATCH", field)
        try:
            raise failure from None
        except EvaluatorQualityVerificationError:
            failure.__context__ = None
            raise
    return loaded


for _registry_stem in _EVALUATOR_QUALITY_REGISTRY_DOMAINS:
    _load_evaluator_quality_document(_registry_stem)
del _registry_stem


__all__ = [
    "EVALUATOR_QUALITY_ERROR_CODES",
    "EVALUATOR_QUALITY_FIELD_LOCATIONS",
    "EvaluatorQualityVerificationError",
    "_DIGEST_DOMAINS",
    "_domain",
    "_fail",
    "_load_registry_constant",
    "_load_evaluator_quality_document",
    "_EVALUATOR_QUALITY_REGISTRY_DOMAINS",
    "_material_public_key",
    "_role_digest",
    "_strip_self_digest",
    "_verify_signature",
]
