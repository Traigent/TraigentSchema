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
from pathlib import Path
from typing import Any, NoReturn, cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

import traigent_schema.fp2 as fp2
from traigent_schema.certification.process_record_verifier import (
    _ISSUER_SPKI_DOMAIN,
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

_EVALUATOR_BUNDLE_MEMBERS = frozenset(
    {
        "schema_version",
        "descriptor",
        "reference_standard",
        "evaluation_scope",
        "declared_plan",
        "measurements",
        "claim_material",
        "claim_support_rows",
        "non_claims",
        "verification_materials_v0",
        "unsigned_manifest",
        "signature",
    }
)
_EVALUATOR_SCOPE_BINDING_DOMAIN = "traigent.evaluator_quality.scope_binding.v1"
_EVALUATOR_COVERAGE = tuple(
    _schema_definition("EvaluatorQualityUnsignedManifestV1")["properties"]["coverage"]["const"]
)

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


def _walk_strict_values(value: Any) -> None:
    """Reject values fp2 must never be asked to canonicalize."""
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not -(2**53 - 1) <= value <= 2**53 - 1:
        _fail("EVALUATOR_STRICT_INTEGER", "bundle")
    if isinstance(value, float):
        _fail("EVALUATOR_STRICT_INTEGER", "bundle")
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _fail("EVALUATOR_STRICT_INTEGER", "bundle")
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                _fail("EVALUATOR_STRICT_INTEGER", "bundle")
            _walk_strict_values(key)
            _walk_strict_values(child)
    elif isinstance(value, list):
        for child in value:
            _walk_strict_values(child)


@lru_cache(maxsize=1)
def _evaluator_quality_validator() -> Draft7Validator:
    try:
        registry = Registry()
        schema_root = Path(__file__).resolve().parent.parent / "schemas"
        for path in schema_root.rglob("*.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(document, dict) and isinstance(document.get("$id"), str):
                registry = registry.with_resource(document["$id"], Resource.from_contents(document))
        schema = json.loads(_SCHEMA_RESOURCE.read_text(encoding="utf-8"))
        return Draft7Validator(schema, registry=registry)
    except Exception:
        _fail("EVALUATOR_SCHEMA_DEPENDENCY", "bundle")


def _check_bundle_shape(bundle: object) -> dict[str, Any]:
    if not isinstance(bundle, dict) or frozenset(bundle) != _EVALUATOR_BUNDLE_MEMBERS:
        _fail("EVALUATOR_BUNDLE_SHAPE", "bundle")
    _walk_strict_values(bundle)
    return cast(dict[str, Any], bundle)


def _check_schema(bundle: dict[str, Any]) -> None:
    try:
        errors = list(_evaluator_quality_validator().iter_errors(bundle))
    except Unresolvable:
        _fail("EVALUATOR_SCHEMA_DEPENDENCY", "bundle")
    except Exception:
        _fail("EVALUATOR_SCHEMA_DEPENDENCY", "bundle")
    if errors:
        _fail("EVALUATOR_SCHEMA", "bundle")


def _check_semantic_uniqueness(bundle: dict[str, Any]) -> None:
    roles = [row.get("measurement_role") for row in bundle["declared_plan"]["planned_measurements"]]
    if len(roles) != len(set(roles)):
        _fail("MEASUREMENT_ROLE_DUPLICATE", "declared_plan")


def _check_scope_binding(bundle: dict[str, Any], context: object) -> None:
    project_ref = getattr(context, "expected_project_ref", None)
    projection = {"schema_version": _EVALUATOR_SCOPE_BINDING_DOMAIN, "project_ref": project_ref}
    expected = _role_digest(_EVALUATOR_SCOPE_BINDING_DOMAIN, projection)
    if bundle["unsigned_manifest"]["scope_binding_digest"] != expected:
        _fail("SCOPE_BINDING_MISMATCH", "scope_binding")


def _check_artifact_digests(bundle: dict[str, Any]) -> None:
    manifest = bundle["unsigned_manifest"]
    for name, field, role in (
        ("descriptor", "descriptor_digest", "descriptor"),
        ("reference_standard", "reference_standard_digest", "reference_standard"),
        ("evaluation_scope", "evaluation_scope_digest", "evaluation_scope"),
        ("declared_plan", "declared_plan_digest", "declared_plan"),
        ("measurements", "measurement_set_digest", "measurement_set"),
    ):
        computed = _role_digest(_domain(role), _strip_self_digest(bundle[name], field))
        if bundle[name][field] != computed or manifest.get(field) != computed:
            _fail(
                "EVALUATOR_ARTIFACT_DIGEST_MISMATCH",
                {
                    "measurement_set": "measurements",
                    "descriptor": "descriptor",
                    "reference_standard": "reference_standard",
                    "evaluation_scope": "evaluation_scope",
                    "declared_plan": "declared_plan",
                }[role],
            )
    for field, role, payload in (
        ("claim_material_digest", "claim_material", bundle["claim_material"]),
        ("claim_support_rows_digest", "claim_support_rows", bundle["claim_support_rows"]),
        ("non_claims_digest", "non_claims", bundle["non_claims"]),
    ):
        if manifest[field] != _role_digest(_domain(role), payload):
            _fail(
                "EVALUATOR_ARTIFACT_DIGEST_MISMATCH",
                {
                    "claim_material": "claim_material",
                    "claim_support_rows": "claim_support_rows",
                    "non_claims": "non_claims",
                }[role],
            )


def _check_registry_digests(bundle: dict[str, Any]) -> None:
    manifest = bundle["unsigned_manifest"]
    for stem, field in (
        ("measurement_registry", "measurement_registry_digest"),
        ("perturbation_set", "perturbation_set_digest"),
        ("assertion_templates", "assertion_templates_digest"),
    ):
        document = _load_evaluator_quality_document(stem)
        if manifest[field] != _role_digest(_domain(stem), document):
            _fail("REGISTRY_DIGEST_MISMATCH", stem)


def _check_manifest_signature(bundle: dict[str, Any]) -> None:
    manifest = bundle["unsigned_manifest"]
    signature = bundle["signature"]
    if tuple(manifest["coverage"]) != _EVALUATOR_COVERAGE:
        _fail("EVALUATOR_UNSIGNED_MANIFEST_MISMATCH", "unsigned_manifest")
    expected_manifest = _role_digest(_domain("unsigned_manifest"), manifest)
    if signature["unsigned_manifest_digest"] != expected_manifest:
        _fail("EVALUATOR_MANIFEST_DIGEST_MISMATCH", "signature")
    materials = bundle["verification_materials_v0"]
    issuer = materials.get("issuer", {})
    if (
        signature["issuer_key_ref"] != manifest["issuer_key_ref"]
        or signature["trust_ring_ref"] != manifest["trust_ring_ref"]
    ):
        _fail("EVALUATOR_KEY_RING_MISMATCH", "signature")
    try:
        key = _material_public_key(issuer, _ISSUER_SPKI_DOMAIN)
        if (
            issuer.get("key_ref") != manifest["issuer_key_ref"]
            or issuer.get("trust_ring_ref") != manifest["trust_ring_ref"]
        ):
            _fail("EVALUATOR_KEY_RING_MISMATCH", "signature")
        material = (
            _domain("issuer_signature").encode() + b"\0" + fp2.canonicalize(manifest).encode()
        )
        _verify_signature(key, issuer["algorithm"], material, signature["signature"])
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        _fail("EVALUATOR_ISSUER_SIGNATURE_INVALID", "signature")


def _check_commitment(bundle: dict[str, Any], context: object) -> None:
    manifest = bundle["unsigned_manifest"]
    if (
        getattr(context, "expected_evaluator_commitment_ref", None)
        != manifest["evaluator_commitment_ref"]
        or manifest["evaluator_commitment"]["commitment_digest"]
        != manifest["evaluator_commitment_ref"]
    ):
        _fail("EVALUATOR_COMMITMENT_MISMATCH", "commitment_refs")


def _verify_evaluator_quality_private(bundle: object, *, context: object) -> None:
    """Run P3-V.2. The commitment pin must come from a VERIFIED process record."""
    shaped = _check_bundle_shape(bundle)
    _check_schema(shaped)
    _check_semantic_uniqueness(shaped)
    _check_scope_binding(shaped, context)
    _check_artifact_digests(shaped)
    _check_registry_digests(shaped)
    _check_manifest_signature(shaped)
    _check_commitment(shaped, context)
    try:
        fp2.canonicalize(shaped)
    except Exception:
        _fail("EVALUATOR_CANONICALIZATION", "bundle")


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
