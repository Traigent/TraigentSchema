# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
"""Private building blocks for the evaluator-quality certificate verifier.

The public verifier is deliberately added in a later packet.  This module
owns the schema-derived vocabulary and the digest/signature primitives used by
that verifier; it does not make a verification decision yet.

Stricter than the current contract: this verifier enforces
``AXIS_POINT_VALUE_ROLE`` and the reference-limit scope
(``_REFERENCE_STANDARD_SCOPED_ROLES``, including the calibration_slope
ceiling) as verifier-side conventions pending a Schema amendment, not as
schema-declared rules -- so a bundle that is schema-valid on its own can
still be rejected here, and relying parties must expect that gap until the
amendment lands.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
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
    _SHA256_RE,
    TrustAnchorKeyV1,
    _material_public_key,
    _parse_utc_timestamp,
    _verify_signature,
)

_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()

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
        # S10 trust-status codes (P3-V.5). There is no schema-shipped trust
        # status envelope for this bundle family -- see
        # _EVALUATOR_TRUST_STATUS_ENVELOPE_VERSION's docstring -- so these
        # mirror process_record_verifier's vocabulary by convention rather
        # than by a shared schema definition.
        "TRUST_STATUS_SHAPE",
        "TRUST_STATUS_DIGEST_MISMATCH",
        "TRUST_ANCHOR_MISMATCH",
        "TRUST_STATUS_SIGNATURE_INVALID",
        "KEY_REVOKED",
        "REVOCATION_STATUS_UNAVAILABLE",
    }
)

EVALUATOR_QUALITY_VERIFIED = "EVALUATOR_QUALITY_VERIFIED"
EVALUATOR_QUALITY_CLAIMS_PARTIAL = "EVALUATOR_QUALITY_CLAIMS_PARTIAL"

# Codes declared in EVALUATOR_QUALITY_ERROR_CODES that this verifier never
# emits (P3-V.5 sol milestone review finding S1; wording corrected by the
# P3-V.5 team-lead delta review finding F4). Two disjoint classes:
#
# * tripwire -- unreachable because the V1 schema makes the condition they
#   would guard unrepresentable, not because a future stage might reuse the
#   string. Reserved (rather than deleted) so the string cannot be silently
#   repurposed if a schema amendment ever makes the condition representable:
#   - DECLARED_PLAN_ORDER, DECLARED_PLAN_BASIS_INSUFFICIENT: plan ordering
#     is a declared non-claim -- EvaluatorDeclaredPlanV1's own description
#     says the document "carries no basis, no ordering timestamp, and no
#     verdict cap keyed to a plan grade"; the verifier checks containment
#     only, never precedence (see NC_EVQ_PLAN_ORDERING_OUT_OF_SCOPE).
#   - DESCRIPTOR_OPENING_INVALID, DESCRIPTOR_DISCLOSURE_MODE_CONFLICT:
#     EvaluatorDescriptorV1 has no ``opening`` property at all, and
#     ``disclosure_mode`` is a bare enum with no second field it could
#     conflict with.
# * subsumed -- superseded by the generic digest sweep in
#   _check_artifact_digests, which emits EVALUATOR_ARTIFACT_DIGEST_MISMATCH
#   per role rather than these four role-specific codes:
#   DECLARED_PLAN_DIGEST_MISMATCH, DESCRIPTOR_DIGEST_MISMATCH,
#   EVALUATION_SCOPE_DIGEST_MISMATCH, REFERENCE_STANDARD_DIGEST_MISMATCH.
EVALUATOR_QUALITY_RESERVED_CODES: frozenset[str] = frozenset(
    {
        # tripwire
        "DECLARED_PLAN_BASIS_INSUFFICIENT",
        "DECLARED_PLAN_ORDER",
        "DESCRIPTOR_DISCLOSURE_MODE_CONFLICT",
        "DESCRIPTOR_OPENING_INVALID",
        # subsumed by EVALUATOR_ARTIFACT_DIGEST_MISMATCH
        "DECLARED_PLAN_DIGEST_MISMATCH",
        "DESCRIPTOR_DIGEST_MISMATCH",
        "EVALUATION_SCOPE_DIGEST_MISMATCH",
        "REFERENCE_STANDARD_DIGEST_MISMATCH",
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


_WALK_VALUE = 0
_WALK_CLOSE = 1


def _walk_strict_values(root: Any) -> None:
    """Reject values fp2 must never be asked to canonicalize.

    Uses an explicit work stack rather than recursion, and tracks open
    containers by identity, for the same reason fp2's own ``_encode`` does:
    recursion depth is a property of the caller's remaining interpreter
    stack, not of the data, so identical input could canonicalize from one
    call site and crash with ``RecursionError`` from a deeper one. A
    self-referential structure built in Python (never JSON-parsed, so never
    seen by ``json.loads``) reaches this walk before schema validation and
    must fail with a vocabulary code here, not a bare Python exception.
    isinstance() stays deliberately loose here -- str/int/dict/list
    SUBCLASSES are meant to survive this walk unrejected and reach the S11
    fp2.canonicalize() tail, which dispatches on exact type instead.
    """
    open_containers: set[int] = set()
    work: list[tuple[int, Any, int]] = [(_WALK_VALUE, root, 1)]
    while work:
        kind, value, depth = work.pop()
        if kind == _WALK_CLOSE:
            open_containers.discard(value)
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and not -(2**53 - 1) <= value <= 2**53 - 1:
            _fail("EVALUATOR_STRICT_INTEGER", "bundle")
        if isinstance(value, float):
            _fail("EVALUATOR_STRICT_INTEGER", "bundle")
        if isinstance(value, str):
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                _fail("EVALUATOR_STRICT_INTEGER", "bundle")
        elif isinstance(value, (dict, list)):
            if depth > fp2.MAX_DEPTH:
                _fail("EVALUATOR_CANONICALIZATION", "bundle")
            identity = id(value)
            if identity in open_containers:
                _fail("EVALUATOR_CANONICALIZATION", "bundle")
            open_containers.add(identity)
            work.append((_WALK_CLOSE, identity, 0))
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        _fail("EVALUATOR_STRICT_INTEGER", "bundle")
                    work.append((_WALK_VALUE, key, depth + 1))
                    work.append((_WALK_VALUE, child, depth + 1))
            else:
                for child in value:
                    work.append((_WALK_VALUE, child, depth + 1))


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
    """S3: the plan-side duplicate sweep, before any map is built.

    ``measurements.reliability.probe_results[*].measurement.measurement_role``
    is a separate, measurement-side duplicate surface; it is swept by
    :func:`_measurement_role_rows`, which the plan-containment stage (S12)
    owns.
    """
    roles = [row.get("measurement_role") for row in bundle["declared_plan"]["planned_measurements"]]
    if len(roles) != len(set(roles)):
        _fail("MEASUREMENT_ROLE_DUPLICATE", "declared_plan")


def _check_scope_binding(bundle: dict[str, Any], context: object) -> None:
    project_ref = getattr(context, "expected_project_ref", None)
    if type(project_ref) is not str:
        _fail("CONTEXT", "context")
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
    """S7: signature verification.

    EVALUATOR_KEY_RING_MISMATCH is one internal code covering three distinct
    conditions, kept as one name deliberately (see the module's P3-tl-review
    disposition): the signature's own issuer_key_ref/trust_ring_ref
    disagreeing with the manifest's; the issuer's key material in
    verification_materials_v0 failing to parse or reconcile with its own
    declared digest (_material_public_key's MATERIALS_KEY); and the issuer's
    declared key_ref/trust_ring_ref disagreeing with the manifest's. All
    three are key-resolution failures, never a forged-signature finding
    (EVALUATOR_ISSUER_SIGNATURE_INVALID) -- do not rename this code to
    describe only the first condition.
    """
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
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        # Malformed/unmatched issuer key material (RelyingPartyVerificationError
        # "MATERIALS_KEY") is a key-resolution failure, not a forged-signature
        # finding -- keep it distinguishable from EVALUATOR_ISSUER_SIGNATURE_INVALID.
        _fail("EVALUATOR_KEY_RING_MISMATCH", "signature")
    if (
        issuer.get("key_ref") != manifest["issuer_key_ref"]
        or issuer.get("trust_ring_ref") != manifest["trust_ring_ref"]
    ):
        _fail("EVALUATOR_KEY_RING_MISMATCH", "signature")
    material = _domain("issuer_signature").encode() + b"\0" + fp2.canonicalize(manifest).encode()
    try:
        _verify_signature(key, issuer["algorithm"], material, signature["signature"])
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        _fail("EVALUATOR_ISSUER_SIGNATURE_INVALID", "signature")


def _check_commitment(bundle: dict[str, Any], context: object) -> None:
    manifest = bundle["unsigned_manifest"]
    expected_ref = getattr(context, "expected_evaluator_commitment_ref", None)
    if type(expected_ref) is not str:
        _fail("CONTEXT", "context")
    if (
        expected_ref != manifest["evaluator_commitment_ref"]
        or manifest["evaluator_commitment"]["commitment_digest"]
        != manifest["evaluator_commitment_ref"]
    ):
        _fail("EVALUATOR_COMMITMENT_MISMATCH", "commitment_refs")


def _estimator_registry_index() -> dict[str, dict[str, Any]]:
    document = _load_evaluator_quality_document("measurement_registry")
    return {entry["estimator_id"]: entry for entry in document["estimators"]}


def _measurement_role_rows(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """The measurement-side role sweep S3 does not cover (see its docstring).

    Every one of the four measurement blocks is schema-optional
    (EvaluatorMeasurementSetV1's anyOf demands only one of
    calibration/agreement/sensitivity/reliability) -- a schema-VALID bundle
    may omit any of them, so each block is resolved defensively here rather
    than dereferenced unconditionally. An absent block simply contributes no
    rows; callers that need a required axis's evidence to be present enforce
    that themselves (see _check_required_axis_measurement_block).

    ``reliability.repeat_stability`` and ``reliability.position_stability``
    are each full MeasurementV1 objects with a registered MeasurementRoleV1
    (``reliability_repeat`` / ``reliability_position``), same as every probe
    result -- they are included here, when present, for exactly the same
    reason the probe measurements are: so plan containment, registry
    admissibility, interval well-formedness, resample unit, minimum sample
    size, threshold, basis and transcript-digest checks all apply to them
    instead of silently skipping two of the twelve reachable roles.
    """
    measurements = bundle["measurements"]
    calibration = measurements.get("calibration")
    agreement = measurements.get("agreement")
    sensitivity = measurements.get("sensitivity")
    reliability = measurements.get("reliability")
    ordered: list[dict[str, Any]] = []
    if calibration is not None:
        ordered += [calibration["expected_calibration_error"], calibration["calibration_slope"]]
    if agreement is not None:
        ordered.append(agreement["agreement"])
    if sensitivity is not None:
        ordered += [sensitivity["discriminating_power"], sensitivity["false_difference_rate"]]
    if reliability is not None:
        ordered += [
            probe["measurement"]
            for probe in reliability["probe_results"]
            if probe["status"] == "measured"
        ]
        if reliability.get("repeat_stability") is not None:
            ordered.append(reliability["repeat_stability"])
        if reliability.get("position_stability") is not None:
            ordered.append(reliability["position_stability"])
    rows: dict[str, dict[str, Any]] = {}
    for row in ordered:
        role = row["measurement_role"]
        if role in rows:
            _fail("MEASUREMENT_ROLE_DUPLICATE", "measurements")
        rows[role] = row
    return rows


def _registered_estimator(estimator_id: str) -> dict[str, Any]:
    """The registry entry for ``estimator_id``, or fail closed.

    Extracted so the ``.get(...)``-then-``None``-check lives in one place:
    ``_fail`` is typed ``-> NoReturn``, but that annotation is not always
    followed by every static analyzer, which then reports a spurious
    attribute-access-on-``None`` at every call site that dereferences the
    entry after the check. A single non-Optional return type here removes
    the false positive without changing behaviour.
    """
    entry = _estimator_registry_index().get(estimator_id)
    if entry is None:
        _fail("ESTIMATOR_NOT_REGISTERED", "measurements")
    return entry


def _check_measurement_registry_admissibility(row: dict[str, Any]) -> None:
    entry = _registered_estimator(row["estimator_id"])
    if row["value_unit"] != entry["value_unit"] or row["sample_unit"] not in entry["sample_units"]:
        _fail("UNIT_NOT_ADMISSIBLE", "measurements")
    if row["interval_params"]["interval_kind"] not in entry["interval_kinds"]:
        _fail("INTERVAL_MALFORMED", "measurements.interval_params")
    # The registry's measurement_roles column is authority for which roles an
    # estimator may be used for (EstimatorIdV1's description says so); a role
    # not in that list is the same shopping hole as an inadmissible unit.
    if row.get("measurement_role") not in entry["measurement_roles"]:
        _fail("ESTIMATOR_PARAMS_NOT_ADMISSIBLE", "measurements")


def _check_interval_well_formed(row: dict[str, Any]) -> None:
    low, point, high = row["interval_low_value"], row["point_value"], row["interval_high_value"]
    if not low <= point <= high:
        _fail("INTERVAL_MALFORMED", "measurements.interval")
    if row["value_unit"] in ("ppm_unsigned", "ppm_signed"):
        floor = 0 if row["value_unit"] == "ppm_unsigned" else -1000000
        if not (floor <= low <= 1000000 and floor <= high <= 1000000):
            _fail("INTERVAL_MALFORMED", "measurements.interval")


def _check_interval_width(row: dict[str, Any], planned: dict[str, Any]) -> None:
    """maximum_interval_width_ppm is denominated in ppm of a [0, 1000000]
    scale; comparing it against a raw microusd/microsecond width would be a
    unit conflation (latent today because every plannable role in
    PLANNED_ROLE_ORDER happens to be ppm_unsigned), so non-ppm value units
    are rejected here rather than silently compared on the wrong scale.
    """
    if row["value_unit"] not in ("ppm_unsigned", "ppm_signed"):
        _fail("UNIT_NOT_ADMISSIBLE", "measurements.interval")
    width = row["interval_high_value"] - row["interval_low_value"]
    if width > planned["maximum_interval_width_ppm"]:
        _fail("INTERVAL_WIDTH_EXCEEDED", "measurements.interval")


def _check_resample_unit(row: dict[str, Any]) -> None:
    params = row["interval_params"]
    if (
        str(params["interval_kind"]).startswith("bootstrap_")
        and params["resample_unit"] != row["sample_unit"]
    ):
        _fail("RESAMPLE_UNIT_MISMATCH", "measurements.interval_params")


_THRESHOLD_COMPARISON_FOR_DIRECTION = {
    "higher_is_better": "interval_low_ge",
    "lower_is_better": "interval_high_le",
}


def _check_plan_direction_coupling(bundle: dict[str, Any]) -> None:
    """The plan's own threshold_comparison must match its own direction.

    PlannedMeasurementV1 pins the coupling (interval_low_ge for
    higher_is_better, interval_high_le for lower_is_better) in prose only --
    the schema cannot express a cross-field constraint at draft-07. Without
    this check a lower_is_better role (an error rate) could declare
    interval_low_ge with a negative threshold and pass on a 99%
    false-difference rate: shopping the DIRECTION, not just the estimator.
    This is plan-only self-consistency, so it runs over every planned entry
    regardless of whether the role was ever measured.
    """
    for planned in bundle["declared_plan"]["planned_measurements"]:
        direction = planned["estimator_parameters"]["direction"]
        expected = _THRESHOLD_COMPARISON_FOR_DIRECTION[direction]
        if planned["threshold_comparison"] != expected:
            _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.planned_measurements")


def _check_sensitivity_pair_set_binding(bundle: dict[str, Any]) -> None:
    """Plan section 6's own EVQ4 row: 'pair-set digest != the plan's ->
    DECLARED_PLAN_SCOPE_VIOLATION'. EvaluatorDeclaredPlanV1 requires
    ``sensitivity_pair_set`` and SensitivityBlockV1 requires ``pair_set``,
    but nothing at the schema layer compares them -- a measured pair set
    chosen AFTER seeing the results could otherwise validate against a
    preregistered plan that never actually constrained it, on the one axis
    whose entire permitted conclusion is two-sidedness. Compared as a whole
    object (digest, and -- since SensitivityPairSetV1 also carries them --
    known_different_pair_count, known_equivalent_pair_count and
    equivalence_basis), not the digest alone, so a divergence in the counts
    without a matching digest change is caught too.
    """
    sensitivity = bundle["measurements"].get("sensitivity")
    if sensitivity is None:
        return
    if sensitivity["pair_set"] != bundle["declared_plan"]["sensitivity_pair_set"]:
        _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.planned_measurements")


def _check_plan_containment(bundle: dict[str, Any]) -> None:
    """S12: per-role plan containment -- the post-hoc estimator/level-shopping guard.

    Every role the measurement set reports must have a matching plan entry:
    a measured-but-unplanned role receives none of this stage's checks (no
    plan row to check it against), so it is rejected outright rather than
    silently skipped -- the converse case (a role the plan requires but the
    bundle never measured) remains a coverage concern the per-claim
    rejection stages (EVQ4/EVQ5) own, not this stage. ``reliability_repeat``
    and ``reliability_position`` are ordinary rows here too (see
    _measurement_role_rows), so 'every role the measurement set reports'
    is now literally true, not a rule with two silent exceptions.
    """
    _check_plan_direction_coupling(bundle)
    _check_sensitivity_pair_set_binding(bundle)
    rows = _measurement_role_rows(bundle)
    planned_roles = {
        planned["measurement_role"] for planned in bundle["declared_plan"]["planned_measurements"]
    }
    for role in rows:
        if role not in planned_roles:
            _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.planned_measurements")
    for planned in bundle["declared_plan"]["planned_measurements"]:
        row = rows.get(planned["measurement_role"])
        if row is None:
            continue
        if (
            row["estimator_id"] != planned["estimator_id"]
            or row["interval_params"]["interval_kind"]
            != planned["interval_params"]["interval_kind"]
            or row["nominal_coverage_ppm"] != planned["nominal_coverage_ppm"]
            or row["sample_unit"] != planned["sample_unit"]
            or row["value_unit"] != planned["value_unit"]
            or row["estimator_parameters"] != planned["estimator_parameters"]
        ):
            _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.planned_measurements")
        _check_measurement_registry_admissibility(row)
        _check_interval_well_formed(row)
        _check_resample_unit(row)
        if row["sample_size_n"] < planned["minimum_sample_size_n"]:
            _fail("SAMPLE_SIZE_INSUFFICIENT", "measurements.sample_size")
        _check_interval_width(row, planned)
        if planned["threshold_comparison"] == "interval_low_ge":
            if row["interval_low_value"] < planned["threshold_value"]:
                _fail("THRESHOLD_NOT_MET", "measurements.interval")
        elif planned["threshold_comparison"] == "interval_high_le":
            if row["interval_high_value"] > planned["threshold_value"]:
                _fail("THRESHOLD_NOT_MET", "measurements.interval")
        else:
            # Unreachable while the schema enum has exactly two members --
            # kept explicit so a future third member fails closed instead of
            # silently routing into the high-side branch.
            _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.planned_measurements")


def _check_sensitivity_claim_evidence(bundle: dict[str, Any]) -> None:
    """EVQ4's own coverage guard, distinct from S12's plan-containment sweep.

    S12 (`_check_plan_containment`) only rejects a role the bundle measured
    but the plan never authorised; it deliberately punts the converse --
    'a role the plan requires but the bundle never measured' -- to the
    per-claim rejection stages (see its own docstring). Nothing at the
    schema layer ties an EVQ4 support row's evidence_basis to the presence
    of `measurements.sensitivity`: EvaluatorMeasurementSetV1's `anyOf` only
    demands ONE of the four blocks, never sensitivity specifically. A
    non-abstained EVQ4 row asserted while the sensitivity block is entirely
    absent is exactly the one-sided sensitivity overclaim this claim's
    design text describes ('an evaluator ... is a random number generator,
    and a one-sided sensitivity claim is therefore not representable').

    SensitivityPairSetV1's own `known_equivalent_pair_count` already carries
    `minimum: 1` in the shipped schema (shared by both
    `declared_plan.sensitivity_pair_set` and
    `measurements.sensitivity.pair_set`), so a present pair_set with a zero
    equivalent-pair count is schema-unconstructible -- that half of this
    claim's rejection condition is a structural guarantee, not a live path.
    """
    row = _instrument_adequacy_rows(bundle).get("EVQ4")
    if row is None or row["evidence_basis"] == "abstained":
        return
    if bundle["measurements"].get("sensitivity") is None:
        _fail("SENSITIVITY_PAIR_SET_INCOMPLETE", "measurements.sensitivity")


def _check_probe_coverage(bundle: dict[str, Any]) -> None:
    """EVQ5's required-probe rule, stated unambiguously in the plan of
    record after sol F7: a required probe carrying a registered skip reason
    is `PROBE_COVERAGE_INSUFFICIENT`, not an accepted skip -- only a
    non-required probe may be skipped. ProbeResultV1's own if/then only
    couples `status` to `measurement`/`skip_reason` presence; nothing at the
    schema layer ties a probe's `required` flag (a package-data property,
    not a schema property) to whether `skipped` is an acceptable status for
    THAT probe_id, so this is a live cross-artifact gap the verifier must
    close.
    """
    reliability = bundle["measurements"].get("reliability")
    if reliability is None:
        return
    required = {
        probe["probe_id"]
        for probe in _load_evaluator_quality_document("perturbation_set")["probes"]
        if probe["required"]
    }
    for probe in reliability["probe_results"]:
        if probe["probe_id"] in required and probe["status"] != "measured":
            _fail("PROBE_COVERAGE_INSUFFICIENT", "measurements.reliability")


def _check_perturbation_set_registry_binding(bundle: dict[str, Any]) -> None:
    """PERTURBATION_SET_MISMATCH's live condition: a probe's `skip_reason`
    drawn from the CLOSED `ProbeSkipReasonV1` enum (four members, shared
    across all probes) but not from THAT probe_id's own narrower registered
    list in the shipped perturbation-set document -- e.g.
    `not_applicable_to_evaluator_kind` on `constant_output`, which the
    registry never lists for it. ProbeResultV1's own if/then only requires
    `skip_reason` be present and be A member of the closed enum when
    `status == skipped`; it cannot reach into the registry to narrow that
    enum per probe_id, which is exactly the vocabulary the registry
    document exists to pin (registry docstring: 'which perturbations were
    tried is a registry identity, not prose'). Probe array ORDER is already
    schema-pinned (`ReliabilityBlockV1.items` fixes each index's `probe_id`
    by `const`, in the registry's own order), so a reordered probe set is
    schema-unconstructible and not checked here.
    """
    reliability = bundle["measurements"].get("reliability")
    if reliability is None:
        return
    registry_index = {
        probe["probe_id"]: probe
        for probe in _load_evaluator_quality_document("perturbation_set")["probes"]
    }
    for probe in reliability["probe_results"]:
        if (
            probe["status"] == "skipped"
            and probe["skip_reason"] not in registry_index[probe["probe_id"]]["skip_reasons"]
        ):
            _fail("PERTURBATION_SET_MISMATCH", "measurements.reliability")


def _check_perturbation_set_digest_bindings(bundle: dict[str, Any]) -> None:
    """`measurements.reliability.perturbation_set_digest` and
    `declared_plan.perturbation_set_digest` are each schema-required
    perturbation-set claims in their own right, distinct from
    `_check_registry_digests`'s manifest-level binding (the manifest's own
    `perturbation_set_digest` field): both are required by their respective
    definitions (ReliabilityBlockV1, EvaluatorDeclaredPlanV1) but nothing
    binds either COPY to the shipped registry the manifest is checked
    against. Owned by PERTURBATION_SET_MISMATCH alongside the skip-reason
    guard above: both are "which perturbation set is this bundle actually
    about" claims. Probe-array reordering is already schema-unconstructible
    (see the guard above), so an unbound digest is the live remainder for
    both copies.
    """
    digest = _role_digest(
        _domain("perturbation_set"), _load_evaluator_quality_document("perturbation_set")
    )
    reliability = bundle["measurements"].get("reliability")
    if reliability is not None and reliability["perturbation_set_digest"] != digest:
        _fail("PERTURBATION_SET_MISMATCH", "measurements.reliability")
    if bundle["declared_plan"]["perturbation_set_digest"] != digest:
        _fail("PERTURBATION_SET_MISMATCH", "declared_plan")


def _check_reliability_determinism(bundle: dict[str, Any]) -> None:
    """ReliabilityBlockV1's own description: 'repeat_stability and
    repeat_count are present iff the descriptor's determinism is not
    deterministic. Both are verifier obligations across artifacts.' The
    schema's own `dependencies` clause only couples `repeat_stability` and
    `repeat_count` to EACH OTHER (both or neither); it cannot reach across
    to `descriptor.determinism` at draft-07. The `iff` has two directions,
    not one: a `deterministic` descriptor must not CARRY `repeat_stability`
    AT ALL -- not "carry one whose value disagrees with perfect
    self-agreement", which would miss a deterministic descriptor reporting a
    simulated-perfect (`point_value == 1000000`) repeat measurement it
    should never have reported in the first place -- and a non-deterministic
    descriptor must not OMIT `repeat_stability`.
    """
    reliability = bundle["measurements"].get("reliability")
    if reliability is None:
        return
    determinism = bundle["descriptor"]["determinism"]
    repeat_stability = reliability.get("repeat_stability")
    if determinism == "deterministic":
        if repeat_stability is not None:
            _fail("RELIABILITY_DETERMINISM_CONTRADICTION", "measurements.reliability")
    elif repeat_stability is None:
        _fail("RELIABILITY_DETERMINISM_CONTRADICTION", "measurements.reliability")


def _check_reliability_axis_required(bundle: dict[str, Any]) -> None:
    """ReliabilityBlockV1's own description: 'position_stability is
    required iff evaluator_kind is llm_judge_pairwise or ensemble_panel.'
    Nothing at the schema layer reaches across to `descriptor.evaluator_kind`
    to enforce this -- `position_stability` is schema-optional
    unconditionally.
    """
    reliability = bundle["measurements"].get("reliability")
    if reliability is None:
        return
    if (
        bundle["descriptor"]["evaluator_kind"] in ("llm_judge_pairwise", "ensemble_panel")
        and "position_stability" not in reliability
    ):
        _fail("RELIABILITY_AXIS_MISSING", "measurements.reliability")


def _check_selection_set_overlap(bundle: dict[str, Any]) -> None:
    """HeldOutStatusV1's own description, `held_out_disjoint`: 'the issuer
    DECLARES that the reported intervals were re-estimated on an estimation
    set disjoint from the selection set ... unequal digests are consistent
    with disjoint sets but do not by themselves establish it.' The converse
    is the live guard here: EQUAL digests are never consistent with a
    disjoint-sets declaration, so a `held_out_disjoint` scope whose
    `selection_set_digest` equals its `estimation_set_digest` is an
    internally contradictory attestation the schema's own `allOf` (which
    only forbids a null `selection_set_digest` on this branch) does not
    reach.
    """
    scope = bundle["evaluation_scope"]
    if (
        scope["held_out_status"] == "held_out_disjoint"
        and scope["selection_set_digest"] == scope["estimation_set_digest"]
    ):
        _fail("SELECTION_SET_OVERLAP", "evaluation_scope.held_out")


def _check_claim_support_row_binding_digests(bundle: dict[str, Any]) -> None:
    """CLAIM_SUPPORT_ROW_MISMATCH: each row's OWN copy of the artifact
    digests it presents must equal the bundle's actual, recomputed digests
    -- the same binding-obligation pattern A6
    (`_check_claim_material_row_digests`) already closes for
    `claim_material_digest`, extended here to the row's other digest
    fields. EvaluatorQualityClaimSupportRowV1's `allOf` only requires THAT
    these fields be present for a given `evidence_basis`; it never
    constrains their VALUE against the bundle's own descriptor,
    reference_standard, evaluation_scope, declared_plan or measurement_set
    -- a row could otherwise carry a syntactically valid but wrong digest
    copied from an unrelated bundle and pass every other stage.
    `claim_material_digest` is deliberately excluded here: A6 already owns
    it, and re-checking it here would create exactly the shadow-guard
    condition the plan's mutation discipline (sol F9) warns against.
    """
    bindings = (
        ("descriptor_digest", bundle["descriptor"]["descriptor_digest"]),
        ("reference_standard_digest", bundle["reference_standard"]["reference_standard_digest"]),
        ("evaluation_scope_digest", bundle["evaluation_scope"]["evaluation_scope_digest"]),
        ("declared_plan_digest", bundle["declared_plan"]["declared_plan_digest"]),
        ("measurement_set_digest", bundle["measurements"]["measurement_set_digest"]),
    )
    for row in bundle["claim_support_rows"]:
        for field, expected in bindings:
            if field in row and row[field] != expected:
                _fail("CLAIM_SUPPORT_ROW_MISMATCH", "claim_support_rows")


_AXIS_MEASUREMENT_BLOCK = frozenset({"calibration", "agreement", "sensitivity", "reliability"})


def _check_required_axis_measurement_block(bundle: dict[str, Any]) -> None:
    """A required axis's measurement block must be present.

    AggregationPolicyV1 pins exactly one weight entry per AggregationAxisV1
    member and forbids renormalizing over the axes that happen to have
    evidence: 'if any required_axis lacks a passed/directional claim the
    overall verdict MUST be abstain'. But EvaluatorMeasurementSetV1's own
    anyOf makes all four measurement blocks schema-optional -- nothing in
    the bundle schema forces a required axis's block to actually exist. A
    bundle that omits a required axis's block entirely is out of scope for
    this verifier the same way a level-shopped estimator is: reject it here
    with the same DECLARED_PLAN_SCOPE_VIOLATION family used elsewhere in
    this stage, rather than let it reach the aggregation layer as a
    quietly-missing axis. A NON-required axis that is absent is not this
    check's concern -- it is skipped here, and the aggregation weights
    themselves fail closed on it (see _axis_point_value) because
    AggregationPolicyV1's text is silent on what a missing non-required axis
    contributes to the weighted sum.
    """
    weights = {
        weight["axis"]: weight
        for weight in bundle["declared_plan"]["aggregation_policy"]["weights"]
    }
    measurements = bundle["measurements"]
    for axis in _AXIS_MEASUREMENT_BLOCK:
        weight = weights.get(axis)
        if weight is not None and weight["required_axis"] and axis not in measurements:
            _fail("DECLARED_PLAN_SCOPE_VIOLATION", "declared_plan.aggregation_policy")


_AXIS_INSTRUMENT_CLAIM = {
    "calibration": "EVQ3",
    "agreement": "EVQ2",
    "sensitivity": "EVQ4",
    "reliability": "EVQ5",
}
_INSTRUMENT_CLAIM_IDS = ("EVQ2", "EVQ3", "EVQ4", "EVQ5")
_VERDICT_RANK = {"failed": 0, "abstain": 1, "directional": 2, "passed": 3}
_CAPPED_REFERENCE_KINDS = frozenset({"proxy_evaluator", "human_single_rater"})
_NO_RATER_REFERENCE_KINDS = (
    "verifiable_execution",
    "unit_test_pass",
    "exact_match_gold",
    "partial_order",
    "proxy_evaluator",
)
_RATER_COUPLING_RULES: dict[str, Any] = {
    "human_panel_adjudicated": lambda rc, ap: (
        rc >= 2 and ap in ("majority", "unanimous", "expert_arbiter")
    ),
    "human_single_rater": lambda rc, ap: rc == 1 and ap == "none",
    **{
        kind: (lambda rc, ap: rc == 0 and ap == "not_applicable")
        for kind in _NO_RATER_REFERENCE_KINDS
    },
}


_REFERENCE_STANDARD_SCOPED_ROLES = frozenset(
    {
        "calibration_ece",
        "calibration_slope",
        "agreement_primary",
        "sensitivity_discriminating_power",
        "sensitivity_false_difference_rate",
    }
)
"""The decisive argument for this exclusion is internal, not textual:
ReferenceStandardV1's own description ('No calibration, agreement, or
sensitivity claim exists without one') is about the EXISTENCE of a
reference, not the SCOPE of the two directional limits below, which is
unrestricted on its face ('caps how high a higher_is_better estimate may
claim'). What actually forces the exclusion is
_check_reliability_determinism, which REQUIRES point_value == 1000000 for a
deterministic evaluator's repeat measurement, while every reliability probe
routinely sits near-but-not-at that ceiling -- a literal sweep of
agreement_ceiling_ppm (golden value 950000) over reliability roles would
make that guard and this one contradict each other on the same bundle.
Reliability roles (all higher_is_better) are therefore deliberately outside
both directional limits below.

Consequence recorded here because it is otherwise invisible in any artifact:
this ceiling now also sweeps calibration_slope, so a near-perfectly
calibrated evaluator (calibration_slope's interval climbing toward
1000000, above agreement_ceiling_ppm) is REJECTED as
REFERENCE_CEILING_EXCEEDED -- a rejection of a GOOD evaluator, defensible on
the schema's text but new, and undocumented anywhere a relying party would
see it.

This exclusion and AXIS_POINT_VALUE_ROLE below are the module's two verifier
conventions pending the Schema follow-up amendment (a point_value_role per
axis on AggregationWeightV1, and an explicit reliability/reference-limit
scoping rule) -- see AXIS_POINT_VALUE_ROLE's own docstring for the pending
ticket.
"""


def _check_reference_ceiling(bundle: dict[str, Any]) -> None:
    """ReferenceStandardV1's own limit, high side: agreement_ceiling_ppm caps
    how high EVERY higher_is_better reference-scoped estimate may claim
    (calibration_slope, agreement_primary, sensitivity_discriminating_power),
    not agreement_primary alone -- symmetric with _check_reference_floor's
    lower_is_better sweep below.
    """
    ceiling = bundle["reference_standard"]["agreement_ceiling_ppm"]
    for role, row in _measurement_role_rows(bundle).items():
        if role not in _REFERENCE_STANDARD_SCOPED_ROLES:
            continue
        if row["value_unit"] not in ("ppm_unsigned", "ppm_signed"):
            continue
        if row["estimator_parameters"]["direction"] != "higher_is_better":
            continue
        if row["interval_high_value"] > ceiling:
            _fail("REFERENCE_CEILING_EXCEEDED", "reference_standard.ceiling")


def _check_reference_floor(bundle: dict[str, Any]) -> None:
    """EVQ3's distinguishing stage: every lower_is_better reference-scoped
    ppm role (an error rate) is bounded below by the reference standard's own
    noise floor -- a single ceiling on both directions would let a
    perfect-calibration claim of zero through, below what the reference
    itself can resolve.
    """
    floor = bundle["reference_standard"]["error_floor_ppm"]
    for role, row in _measurement_role_rows(bundle).items():
        if role not in _REFERENCE_STANDARD_SCOPED_ROLES:
            continue
        if row["value_unit"] not in ("ppm_unsigned", "ppm_signed"):
            continue
        if row["estimator_parameters"]["direction"] != "lower_is_better":
            continue
        if row["interval_low_value"] < floor:
            _fail("REFERENCE_FLOOR_VIOLATED", "reference_standard")


def _check_reference_rater_coupling(bundle: dict[str, Any]) -> None:
    """Defense in depth over ReferenceStandardV1's own kind/rater/adjudication
    coupling (already schema-enforced via its allOf), plus the one
    cross-field bound draft-07 cannot express within that same object:
    rater_count may never exceed label_count.
    """
    reference = bundle["reference_standard"]
    rule = _RATER_COUPLING_RULES.get(reference["reference_kind"])
    if rule is not None and not rule(reference["rater_count"], reference["adjudication_policy"]):
        _fail("REFERENCE_RATER_COUPLING", "reference_standard.raters")
    if reference["rater_count"] > reference["label_count"]:
        _fail("REFERENCE_RATER_COUPLING", "reference_standard.raters")


def _check_reference_capping(bundle: dict[str, Any]) -> None:
    """A proxy or non-independent reference, or a single uncorroborated
    human rater, may never back a 'passed' instrument-adequacy claim --
    self-certification is exactly the failure this family exists to catch.
    """
    reference = bundle["reference_standard"]
    capped = (
        reference["reference_kind"] in _CAPPED_REFERENCE_KINDS
        or reference["reference_independence"] != "evaluator_independent"
    )
    if not capped:
        return
    for row in bundle["claim_support_rows"]:
        if row["claim_id"] in _INSTRUMENT_CLAIM_IDS and row["verdict"] == "passed":
            _fail("VERDICT_NOT_SUPPORTED", "claim_support_rows")


def _check_held_out_capping(bundle: dict[str, Any]) -> None:
    """Winner's-curse capping: intervals estimated on data whose relationship
    to selection is unknown, or that overlaps the selection set, may not
    back a 'passed' instrument-adequacy claim.
    """
    status = bundle["evaluation_scope"]["held_out_status"]
    if status in ("no_selection_performed", "held_out_disjoint"):
        return
    for row in bundle["claim_support_rows"]:
        if row["claim_id"] in _INSTRUMENT_CLAIM_IDS and row["verdict"] == "passed":
            _fail("VERDICT_NOT_SUPPORTED", "claim_support_rows")


def _check_measurement_basis(bundle: dict[str, Any]) -> None:
    """Defense in depth: EmittableMeasurementBasisV1 already pins every v1
    measurement's basis to 'issuer_attested_v1' at the schema layer, so
    there is no live v1 path to a different basis backing any row -- this
    guard exists for the day a future schema version widens the enum.
    """
    for row in _measurement_role_rows(bundle).values():
        if row["basis"] != "issuer_attested_v1":
            _fail("MEASUREMENT_BASIS_INSUFFICIENT", "measurements.basis")


def _check_transcript_digest(bundle: dict[str, Any]) -> None:
    """Defense in depth: MeasurementV1's own if/then already requires a
    non-null computation_transcript_digest exactly when basis is
    construction_recomputed_v1, and that basis is unconstructible in v1
    (EmittableMeasurementBasisV1) -- so no v1 measurement ever needs one.
    """
    for row in _measurement_role_rows(bundle).values():
        if (
            row["basis"] == "construction_recomputed_v1"
            and row["computation_transcript_digest"] is None
        ):
            _fail("TRANSCRIPT_DIGEST_MISSING", "measurements.basis")


def _check_claim_tier_bound(bundle: dict[str, Any]) -> None:
    """Defense in depth: EVQ1 can never be issuer_verified / tier 3 already
    (EvaluatorQualityClaimSupportRowV1 pins EVQ1's evidence_basis to
    client_declared/abstained, and both of those pin tier to 1) -- kept as
    an explicit guard rather than relying on that coupling silently.
    """
    for row in bundle["claim_support_rows"]:
        if row["claim_id"] == "EVQ1" and (
            row["tier"] != 1 or row["evidence_basis"] == "issuer_verified"
        ):
            _fail("CLAIM_TIER_MISMATCH", "claim_support_rows")


def _check_claim_material_row_digests(bundle: dict[str, Any]) -> None:
    """A6: each non-abstained support row carries its OWN copy of
    claim_material_digest, and it must equal the manifest's -- S5 only
    checks the manifest's own field against the recomputed claim_material
    digest, never each row's copy of it.

    Binding this verifier actually enforces: every row's claim_material_digest
    equals the single digest computed over the manifest's claim_material_digest
    field, i.e. the ARRAY-level digest over the whole claim_material list (S5's
    own binding), not a per-claim digest over just that row's one projection.
    EvaluatorQualityClaimMaterialV1's own description defines its digest over
    'this projection' (one item), so a row-level reading is also textually
    available; both readings reject the same negative (a row's digest copied
    from a different claim's material, which cannot equal either the
    array-level digest or that other claim's own item-level digest), so
    nothing observable breaks under either reading today. Which binding a
    relying party may rely on -- array-level (what this code checks) or
    row-level -- is a contract clarification this module does not resolve.
    """
    expected = bundle["unsigned_manifest"]["claim_material_digest"]
    for row in bundle["claim_support_rows"]:
        if row["evidence_basis"] == "abstained":
            continue
        if row.get("claim_material_digest") != expected:
            _fail("CLAIM_MATERIAL_MISMATCH", "claim_support_rows")


def _check_aggregation_policy_weights(bundle: dict[str, Any]) -> None:
    """A1: draft-07 cannot sum sibling array items, so weights summing to
    exactly 1_000_000 is a verifier obligation."""
    weights = bundle["declared_plan"]["aggregation_policy"]["weights"]
    if sum(w["weight_ppm"] for w in weights) != 1000000:
        _fail("AGGREGATION_POLICY_MISMATCH", "declared_plan.aggregation_policy")


def _instrument_adequacy_rows(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        row["claim_id"]: row
        for row in bundle["claim_support_rows"]
        if row["claim_id"] in _INSTRUMENT_CLAIM_IDS
    }


def _check_instrument_adequacy(bundle: dict[str, Any]) -> None:
    """A3: instrument_adequacy_verdict is DERIVED -- the worst verdict among
    the four instrument-adequacy rows -- never read from the issuer's own
    declared value. Duplicates a coupling EvaluatorQualityCertificateBundleV1
    already enforces structurally for the passed/directional rungs; kept
    anyway, deliberately, as the second independent mechanism over the one
    invariant an issuer most wants to escape.
    """
    rows = _instrument_adequacy_rows(bundle)
    worst_rank = min(
        (_VERDICT_RANK[row["verdict"]] for row in rows.values()), default=_VERDICT_RANK["passed"]
    )
    recomputed = next(k for k, v in _VERDICT_RANK.items() if v == worst_rank)
    if bundle["unsigned_manifest"]["overall"]["instrument_adequacy_verdict"] != recomputed:
        _fail("INSTRUMENT_ADEQUACY_MISMATCH", "overall")


def _check_required_axis_completeness(bundle: dict[str, Any]) -> None:
    """A2: weights are never renormalized over the axes that happen to have
    evidence -- if any required_axis lacks a passed/directional claim the
    overall verdict MUST be abstain (AggregationPolicyV1's own text). A
    required axis's claim reading 'failed' lacks a passed/directional
    verdict exactly as much as one reading 'abstain' does, so both trigger
    this guard -- checking only for 'abstain' would let a required axis that
    outright failed silently ride along under a non-abstain overall verdict.
    """
    rows = _instrument_adequacy_rows(bundle)
    overall = bundle["unsigned_manifest"]["overall"]
    for weight in bundle["declared_plan"]["aggregation_policy"]["weights"]:
        if not weight["required_axis"]:
            continue
        claim_id = _AXIS_INSTRUMENT_CLAIM.get(weight["axis"])
        if claim_id is None:
            continue
        row = rows.get(claim_id)
        if (
            row is not None
            and row["verdict"] not in ("passed", "directional")
            and overall["verdict"] != "abstain"
        ):
            _fail("AGGREGATION_RENORMALIZED", "overall")


def _check_overall_verdict_capped(bundle: dict[str, Any]) -> None:
    """A4: overall.verdict may never rank better than
    instrument_adequacy_verdict. EvaluatorQualityOverallV1 already enforces
    this structurally for the passed/directional rungs; this recomputation
    covers the remaining abstain/failed pairing the schema's own if/then
    does not reach.
    """
    overall = bundle["unsigned_manifest"]["overall"]
    if _VERDICT_RANK[overall["verdict"]] > _VERDICT_RANK[overall["instrument_adequacy_verdict"]]:
        _fail("OVERALL_VERDICT_UNSUPPORTED", "overall")


def _round_half_even(numerator: int, denominator: int) -> int:
    quotient, remainder = divmod(numerator, denominator)
    twice = 2 * remainder
    if twice < denominator:
        return quotient
    if twice > denominator:
        return quotient + 1
    return quotient if quotient % 2 == 0 else quotient + 1


AXIS_POINT_VALUE_ROLE: dict[str, str] = {
    "calibration": "calibration_slope",
    "agreement": "agreement_primary",
    "sensitivity": "sensitivity_discriminating_power",
    "reliability": "_reliability_mean_of_measured_probes",
}
"""Which measurement role is 'the axis's point value' for the A5 weighted
sum, per axis. THIS IS A VERIFIER CONVENTION, NOT A CONTRACT DERIVATION:
AggregationPolicyV1 and MeasurementV1 say overall_quality_ppm is the
weighted sum of 'each axis's point value', but no schema artifact says
which role that is for an axis that owns several (three of four do --
calibration also has expected_calibration_error, sensitivity also has
false_difference_rate). This pin is pending a contract amendment (Schema
follow-up: a point_value_role per axis on AggregationWeightV1); until then,
this constant IS the definition, and _axis_point_value below fails closed
rather than silently substituting 0 for anything not covered by it. The
reliability entry is a sentinel, not a real MeasurementRoleV1 value --
reliability's point value is the round-half-even mean of its measured
probes, not a single role's point_value.
"""


def _required_measurement_role_row(bundle: dict[str, Any], role: str) -> dict[str, Any]:
    """The measurement row for ``role``, or fail closed with
    ``AGGREGATION_DERIVATION_MISMATCH``.

    Same extraction rationale as :func:`_registered_estimator`: keeps the
    ``.get(...)``-then-``None``-check and the subsequent item access off the
    Optional value, so a static analyzer that does not follow ``_fail``'s
    ``-> NoReturn`` cannot mistake the row for possibly-``None`` at the
    caller. The code is hardcoded, not a parameter, so every ``_fail`` call
    site in this module stays a literal the S1 emission audit
    (``test_evaluator_quality_reserved_codes_match_source_emission_audit``)
    can see.
    """
    row = _measurement_role_rows(bundle).get(role)
    if row is None:
        _fail("AGGREGATION_DERIVATION_MISMATCH", "overall")
    return row


def _axis_point_value(bundle: dict[str, Any], axis: str) -> int:
    """The per-axis point value the A5 weighted sum is over. These values
    are themselves issuer-attested, never recomputed by this verifier
    (NC_EVQ_INTERVALS_NOT_RECOMPUTED) -- only the arithmetic over them is
    checked. Fails closed (AGGREGATION_DERIVATION_MISMATCH) rather than
    returning a silent 0 on an axis AXIS_POINT_VALUE_ROLE does not
    recognise, a role whose measurement is absent, or an empty reliability
    probe list -- a silent 0 would let a missing axis quietly zero out its
    own weighted contribution instead of rejecting the bundle.
    """
    role = AXIS_POINT_VALUE_ROLE.get(axis)
    if role is None:
        _fail("AGGREGATION_DERIVATION_MISMATCH", "overall")
    if axis == "reliability":
        reliability = bundle["measurements"].get("reliability")
        probes = (
            [
                probe["measurement"]["point_value"]
                for probe in reliability["probe_results"]
                if probe["status"] == "measured"
            ]
            if reliability is not None
            else []
        )
        if not probes:
            _fail("AGGREGATION_DERIVATION_MISMATCH", "overall")
        return _round_half_even(sum(probes), len(probes))
    row = _required_measurement_role_row(bundle, role)
    return cast(int, row["point_value"])


def _check_aggregation_derivation(bundle: dict[str, Any]) -> None:
    """A5: overall_quality_ppm is DERIVED -- the round-half-even weighted
    sum of each axis's own point value under the declared-plan weights,
    exact integer arithmetic throughout. Skipped when verdict is
    abstain/failed: EvaluatorQualityOverallV1 already forbids
    overall_quality_ppm from being present on those rows.
    """
    overall = bundle["unsigned_manifest"]["overall"]
    if overall["verdict"] in ("abstain", "failed"):
        return
    weights = bundle["declared_plan"]["aggregation_policy"]["weights"]
    numerator = sum(
        _axis_point_value(bundle, w["axis"]) * w["weight_ppm"]
        for w in weights
        if w["axis"] != "efficiency"
    )
    recomputed = _round_half_even(numerator, 1000000)
    if overall.get("overall_quality_ppm") != recomputed:
        _fail("AGGREGATION_DERIVATION_MISMATCH", "overall")


_NON_CLAIMS_CANONICAL: tuple[tuple[str, str], ...] = tuple(
    (
        item["allOf"][1]["properties"]["non_claim_id"]["const"],
        item["allOf"][1]["properties"]["reason_template_id"]["const"],
    )
    for item in _schema_definition("EvaluatorQualityNonClaimsFixedTupleV1")["items"]
)


def _check_non_claim_tuple(bundle: dict[str, Any]) -> None:
    """S8: ``non_claims`` is exactly the pinned, canonically-ordered
    18-member ``(non_claim_id, reason_template_id)`` tuple
    (``EvaluatorQualityNonClaimsFixedTupleV1``, eighteen at the shipped
    contract -- not the design's fifteen).

    ``EvaluatorQualityNonClaimsFixedTupleV1``'s own per-position ``allOf``/
    ``const`` pins already make any omission, addition, reorder, or
    id/template substitution schema-invalid, so no schema-valid bundle can
    reach this guard through :func:`_verify_evaluator_quality_private` (S2
    runs first) -- this is defense-in-depth, the same class as the
    ``DESCRIPTOR_DISCLOSURE_MODE_CONFLICT`` tripwire elsewhere in this
    module. Reachability is proven in the test module by calling this
    function directly against a hand-built, schema-bypassing tuple, not by
    a full-bundle runtime negative.
    """
    actual = tuple((row["non_claim_id"], row["reason_template_id"]) for row in bundle["non_claims"])
    if actual != _NON_CLAIMS_CANONICAL:
        _fail("NON_CLAIM_TUPLE_MISMATCH", "non_claims")


def _verify_evaluator_quality_private(bundle: object, *, context: object) -> None:
    """Run P3-V.2/P3-V.3/P3-V.4/P3-V.4d. The commitment pin must come from
    a VERIFIED process record."""
    shaped = _check_bundle_shape(bundle)
    _check_schema(shaped)
    _check_non_claim_tuple(shaped)
    _check_semantic_uniqueness(shaped)
    _check_scope_binding(shaped, context)
    _check_artifact_digests(shaped)
    _check_registry_digests(shaped)
    _check_manifest_signature(shaped)
    _check_commitment(shaped, context)
    _check_plan_containment(shaped)
    _check_sensitivity_claim_evidence(shaped)
    _check_probe_coverage(shaped)
    _check_perturbation_set_registry_binding(shaped)
    _check_perturbation_set_digest_bindings(shaped)
    _check_reliability_determinism(shaped)
    _check_reliability_axis_required(shaped)
    _check_selection_set_overlap(shaped)
    _check_claim_support_row_binding_digests(shaped)
    _check_required_axis_measurement_block(shaped)
    _check_reference_ceiling(shaped)
    _check_reference_floor(shaped)
    _check_reference_rater_coupling(shaped)
    _check_reference_capping(shaped)
    _check_held_out_capping(shaped)
    _check_measurement_basis(shaped)
    _check_transcript_digest(shaped)
    _check_claim_tier_bound(shaped)
    _check_claim_material_row_digests(shaped)
    _check_aggregation_policy_weights(shaped)
    _check_instrument_adequacy(shaped)
    _check_required_axis_completeness(shaped)
    _check_overall_verdict_capped(shaped)
    _check_aggregation_derivation(shaped)
    try:
        fp2.canonicalize(shaped)
    except Exception:
        _fail("EVALUATOR_CANONICALIZATION", "bundle")


# DECLARED_PLAN_BASIS_INSUFFICIENT and DECLARED_PLAN_ORDER are registered,
# closed vocabulary (EVALUATOR_QUALITY_ERROR_CODES above) with deliberately
# NO guard function and no call site in
# _verify_evaluator_quality_private -- unlike the three "unconstructible but
# defended anyway" codes above (MEASUREMENT_BASIS_INSUFFICIENT,
# TRANSCRIPT_DIGEST_MISSING, CLAIM_TIER_MISMATCH), there is no field on
# EvaluatorDeclaredPlanV1 for either guard to inspect: a Python guard
# checking a key that can never be present would be dead code checking
# nothing, not defense in depth. This mirrors the module's existing
# DESCRIPTOR_DISCLOSURE_MODE_CONFLICT / DESCRIPTOR_OPENING_INVALID
# precedent (P3-tl-review-1 P2-6: "unconstructibility tripwires ...
# correctly unreachable"). The schema's own text is the proof both ways:
#
#   EvaluatorDeclaredPlanV1 (top-level description): "this document carries
#   no basis, no ordering timestamp, and no verdict cap keyed to a plan
#   grade. It pins WHAT was planned ... it makes no representation about
#   WHEN it was authored relative to the results, and the verifier checks
#   containment only, never precedence."
#
#   The bundle schema's own top-level description: "Ordering evidence is
#   out of scope for v1: nothing here establishes when the declared plan
#   was authored relative to the measurements, and this certificate does
#   not verify it." -- printed unconditionally as
#   NC_EVQ_PLAN_ORDERING_OUT_OF_SCOPE.
#
# additionalProperties: false on EvaluatorDeclaredPlanV1, over a
# required/properties set naming neither "basis" nor any ordering/timestamp
# field, makes both codes structurally unconstructible through any
# schema-valid bundle. Reachability is proven by direct construction in
# tests/test_evaluator_quality_verifier.py (constructing
# EvaluatorQualityVerificationError with each code), not by a guard.


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


# ---------------------------------------------------------------------------
# P3-V.5 -- the public surface.
# ---------------------------------------------------------------------------

# S10 trust status. There is NO schema-shipped trust-status envelope for
# EvaluatorQualityCertificateBundleV1 -- unlike ProcessRecordCertificateBundleV1,
# the evaluator-quality contract at 7cb35d0 defines no TrustStatusEnvelopeV1
# counterpart and reserves no EvaluatorQualityFieldLocationV1 token for it.
# (process_record_verifier's own TrustStatusEnvelopeV1 cannot be reused
# as-is: its schema_version/max_age_seconds/certificate_status shape is
# pinned to the process-record family and requires a certificate_status
# entry this bundle has no certificate_ref to populate.) The constants and
# shape checks below are therefore a VERIFIER CONVENTION pending a Schema
# follow-up (an EvaluatorQualityTrustStatusEnvelopeV1 counterpart), mirroring
# AXIS_POINT_VALUE_ROLE's own pending-amendment status above. Until that
# amendment lands, this module owns the envelope shape in Python rather than
# via jsonschema, and only the issuer key's status is consulted -- there is
# no certificate concept in this bundle family to revoke separately from the
# key that signed it.
_EVALUATOR_TRUST_STATUS_ENVELOPE_VERSION = "traigent.evaluator_quality.trust_status_envelope.v1"
_EVALUATOR_TRUST_STATUS_VERSION = "traigent.evaluator_quality.trust_status.v1"
_EVALUATOR_TRUST_POLICY_ID = "traigent.trust_policy.evaluator_quality.v1"
_EVALUATOR_TRUST_MAX_AGE_SECONDS = 86400
_EVALUATOR_TRUST_SKEW_SECONDS = 0
_MAX_EVALUATOR_TRUST_STATUS_ENTRIES = 64


def _utc_microseconds(value: str) -> int:
    """Integer microseconds since the Unix epoch, or fail
    ``REVOCATION_STATUS_UNAVAILABLE`` -- see
    ``process_record_verifier._utc_microseconds`` for the parse rationale
    this mirrors (delegated to the shared, pure ``_parse_utc_timestamp``)."""
    parsed = _parse_utc_timestamp(value)
    if parsed is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE", "signature")
    year, month, day, hour, minute, second, frac_us = parsed
    days = date(year, month, day).toordinal() - _EPOCH_ORDINAL
    seconds = days * 86400 + hour * 3600 + minute * 60 + second
    return seconds * 1_000_000 + frac_us


def _evaluator_trust_status_shape(envelope: object) -> dict[str, Any] | None:
    """Structural check for the convention envelope shape; returns the
    snapshot body, or ``None`` on any shape defect (caller fails closed)."""
    if type(envelope) is not dict:
        return None
    if envelope.get("schema_version") != _EVALUATOR_TRUST_STATUS_ENVELOPE_VERSION:
        return None
    snapshot = envelope.get("snapshot")
    signature = envelope.get("signature")
    if type(snapshot) is not dict or type(signature) is not dict:
        return None
    if snapshot.get("schema_version") != _EVALUATOR_TRUST_STATUS_VERSION:
        return None
    if snapshot.get("trust_policy_id") != _EVALUATOR_TRUST_POLICY_ID:
        return None
    if snapshot.get("max_age_seconds") != _EVALUATOR_TRUST_MAX_AGE_SECONDS:
        return None
    if (
        type(snapshot.get("effective_time")) is not str
        or type(snapshot.get("trust_anchor_ref")) is not str
    ):
        return None
    key_status = snapshot.get("key_status")
    if not isinstance(key_status, list) or not (
        1 <= len(key_status) <= _MAX_EVALUATOR_TRUST_STATUS_ENTRIES
    ):
        return None
    seen: set[tuple[Any, Any]] = set()
    for entry in key_status:
        if not isinstance(entry, dict):
            return None
        if not {"key_ref", "trust_ring_ref", "status"} <= entry.keys():
            return None
        pair = (entry.get("key_ref"), entry.get("trust_ring_ref"))
        if pair in seen:
            return None
        seen.add(pair)
    for field_name in ("algorithm", "signature", "trust_anchor_ref", "snapshot_digest"):
        if type(signature.get(field_name)) is not str:
            return None
    return cast(dict[str, Any], snapshot)


def _verify_evaluator_trust_status(
    trust_status: object, context: EvaluatorQualityVerificationContext
) -> dict[str, Any]:
    """Authenticate and freshness-check a caller-supplied trust-status
    snapshot; return the verified snapshot body. Establishes non-revocation
    of the issuer key ONLY as of the snapshot's own ``effective_time`` --
    never current non-revocation."""
    if trust_status is None:
        _fail("REVOCATION_STATUS_UNAVAILABLE", "signature")
    snapshot = _evaluator_trust_status_shape(trust_status)
    if snapshot is None:
        _fail("TRUST_STATUS_SHAPE", "signature")
    signature = cast(dict[str, Any], cast(dict[str, Any], trust_status)["signature"])

    if signature["snapshot_digest"] != _role_digest(_EVALUATOR_TRUST_STATUS_VERSION, snapshot):
        _fail("TRUST_STATUS_DIGEST_MISMATCH", "signature")

    trust_anchor = context.trust_anchor
    if trust_anchor is None:
        _fail("CONTEXT", "context")
    if (
        snapshot["trust_anchor_ref"] != trust_anchor.key_ref
        or signature["trust_anchor_ref"] != trust_anchor.key_ref
    ):
        _fail("TRUST_ANCHOR_MISMATCH", "signature")

    try:
        anchor_key = _material_public_key(
            {
                "public_key_der_b64": trust_anchor.public_key_der_b64,
                "public_key_digest": trust_anchor.public_key_digest,
                "algorithm": trust_anchor.algorithm,
            },
            _ISSUER_SPKI_DOMAIN,
        )
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        _fail("CONTEXT", "context")
    try:
        canonical_snapshot = cast(str, fp2.canonicalize(snapshot)).encode("utf-8")
    except Exception:
        _fail("EVALUATOR_CANONICALIZATION", "bundle")
    material = _EVALUATOR_TRUST_STATUS_VERSION.encode() + b"\x00" + canonical_snapshot
    try:
        _verify_signature(anchor_key, signature["algorithm"], material, signature["signature"])
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        _fail("TRUST_STATUS_SIGNATURE_INVALID", "signature")

    effective_us = _utc_microseconds(snapshot["effective_time"])
    verification_us = _utc_microseconds(context.verification_time)
    if effective_us > verification_us + _EVALUATOR_TRUST_SKEW_SECONDS * 1_000_000:
        _fail("REVOCATION_STATUS_UNAVAILABLE", "signature")
    if verification_us - effective_us > _EVALUATOR_TRUST_MAX_AGE_SECONDS * 1_000_000:
        _fail("REVOCATION_STATUS_UNAVAILABLE", "signature")
    return snapshot


def _check_evaluator_trust_status_coverage(
    snapshot: dict[str, Any], *, issuer_key_ref: str, trust_ring_ref: str
) -> None:
    """Look up the issuer key's status; a missing entry fails closed with
    ``REVOCATION_STATUS_UNAVAILABLE`` (the snapshot does not speak to this
    key), never a pass. There is no certificate-status lookup: this bundle
    family carries no certificate_ref distinct from the key that signed it."""
    for entry in snapshot["key_status"]:
        if entry["key_ref"] == issuer_key_ref and entry["trust_ring_ref"] == trust_ring_ref:
            if entry["status"] != "active":
                _fail("KEY_REVOKED", "signature")
            return
    _fail("REVOCATION_STATUS_UNAVAILABLE", "signature")


_HELD_OUT_ACCEPTABLE = frozenset({"no_selection_performed", "held_out_disjoint"})


@dataclass(frozen=True, slots=True)
class EvaluatorQualityVerificationContext:
    """Fresh, caller-supplied bindings for one evaluator-quality verification.

    ``expected_project_ref`` is rebuilt into the scope-binding digest (S4).

    ``expected_evaluator_commitment_ref`` is the caller's pin of
    ``manifest.evaluator_commitment_ref`` (S9). **This pin must come from a
    VERIFIED process record** -- specifically, from the
    ``evaluator_commitment_ref`` field of a
    :class:`~traigent_schema.certification.process_record_verifier.ProcessRecordVerificationResult`
    returned by
    :func:`~traigent_schema.certification.process_record_verifier.verify_process_record_certificate`.
    The cross-bundle equality this pin makes possible is a RELYING-PARTY
    COMPOSITION, not a single-call check: this verifier takes exactly one
    bundle and never reaches into a second one. A pin copied from an
    *unverified* process-record bundle -- one the caller never ran through
    ``verify_process_record_certificate`` -- binds nothing: an adversary who
    controls the unverified bundle also controls the ref copied out of it.
    The caller is the party responsible for having verified the process
    record first; this context does not and cannot check that it did.

    ``allow_unchecked_trust_status`` is a required, explicit opt-in/opt-out
    for the S10 dynamic trust-status check, mirroring
    ``ProcessRecordVerificationContext.allow_unchecked_base_status``. There
    is no default, so every caller chooses deliberately. ``trust_anchor`` is
    required iff this is ``False`` and must be ``None`` iff it is ``True``.

    ``verification_time`` is the caller's own clock (this verifier is
    offline and owns none) and is required unconditionally, even when the
    caller opts out of the status check.
    """

    expected_project_ref: str
    expected_evaluator_commitment_ref: str
    allow_unchecked_trust_status: bool
    verification_time: str
    trust_anchor: TrustAnchorKeyV1 | None

    def __post_init__(self) -> None:
        if type(self.expected_project_ref) is not str or not self.expected_project_ref:
            _fail("CONTEXT", "context")
        if type(self.expected_evaluator_commitment_ref) is not str or not _SHA256_RE.fullmatch(
            self.expected_evaluator_commitment_ref
        ):
            _fail("CONTEXT", "context")
        if type(self.allow_unchecked_trust_status) is not bool:
            _fail("CONTEXT", "context")
        if (
            type(self.verification_time) is not str
            or _parse_utc_timestamp(self.verification_time) is None
        ):
            _fail("CONTEXT", "context")
        if (self.trust_anchor is None) != self.allow_unchecked_trust_status:
            _fail("CONTEXT", "context")
        if self.trust_anchor is not None and not isinstance(self.trust_anchor, TrustAnchorKeyV1):
            _fail("CONTEXT", "context")


@dataclass(frozen=True, slots=True)
class EvaluatorQualityVerificationResult:
    """Bounded, content-free success result. Only digest-free enum values,
    verdicts and one integer ever cross into this object.

    ``overall_quality_ppm`` is DEFINED as the round-half-even weighted sum,
    under exact integer arithmetic, of each declared-plan axis's own point
    value (the measurement role pinned per axis by ``AXIS_POINT_VALUE_ROLE``
    -- a verifier convention pending a ``point_value_role`` contract
    amendment) under the declared-plan's aggregation weights. It is
    recomputed, never read from the issuer's declaration (A5); it is
    ``None`` iff ``overall_verdict`` is ``abstain`` or ``failed``, per
    ``EvaluatorQualityOverallV1``. Recomputing the arithmetic over an
    axis's point value is NOT the same as recomputing that point value
    itself: the point values are issuer-attested and never recomputed by
    this offline verifier (``NC_EVQ_INTERVALS_NOT_RECOMPUTED``) -- only the
    weighted sum over them is checked.

    ``instrument_adequacy`` and the four per-axis verdicts
    (``calibration_verdict``, ``agreement_verdict``, ``sensitivity_verdict``,
    ``reliability_verdict``) are all recomputed by this verifier (A3),
    never read from the issuer's own declared value.

    ``code`` and ``instrument_adequacy`` are coupled ONE-DIRECTIONALLY by
    ``__post_init__`` (never the converse):

    * ``code == "EVALUATOR_QUALITY_VERIFIED"`` implies ``instrument_adequacy
      == "passed"`` AND ``reference_independence == "evaluator_independent"``
      AND ``held_out_status`` in ``{"no_selection_performed",
      "held_out_disjoint"}`` -- ALL THREE gate conditions, not just adequacy;
    * ``instrument_adequacy != "passed"`` implies ``code ==
      "EVALUATOR_QUALITY_CLAIMS_PARTIAL"``;
    * a ``"passed"`` ``instrument_adequacy`` together with
      ``"EVALUATOR_QUALITY_CLAIMS_PARTIAL"`` is FORBIDDEN by
      ``__post_init__`` (P3-V.5 sol milestone review finding S2): the
      verifier's own exhaustive sweep
      (``test_only_independent_disjoint_combination_reaches_verified``)
      proves ``instrument_adequacy == "passed"`` always implies both the
      reference-independence and held-out gates also pass, which forces
      ``code == "EVALUATOR_QUALITY_VERIFIED"``, so this pair can never arise
      from real verification. Encoding it as constructible anyway invited
      handlers for a state the verifier cannot produce; the dataclass now
      refuses to construct it.

    ``trust_status_evidence`` is ``"checked_active"`` iff a supplied
    ``trust_status`` snapshot verified as fresh, anchor-authentic, and the
    issuer key active; it is ``"not_checked"`` iff the caller opted out via
    ``context.allow_unchecked_trust_status=True``. This establishes
    non-revocation ONLY AS OF ``trust_status_effective_time`` -- never
    current non-revocation, and never "the key is valid" without that
    qualifier.
    """

    valid: bool = True
    code: str = EVALUATOR_QUALITY_VERIFIED
    instrument_adequacy: str = "passed"
    calibration_verdict: str = "passed"
    agreement_verdict: str = "passed"
    sensitivity_verdict: str = "passed"
    reliability_verdict: str = "passed"
    overall_verdict: str = "passed"
    reference_independence: str = "evaluator_independent"
    held_out_status: str = "no_selection_performed"
    overall_quality_ppm: int | None = None
    trust_status_evidence: str = "not_checked"
    trust_status_effective_time: str = ""

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")
        if self.code not in (EVALUATOR_QUALITY_VERIFIED, EVALUATOR_QUALITY_CLAIMS_PARTIAL):
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")
        if self.instrument_adequacy not in _VERDICT_RANK:
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")
        if self.trust_status_evidence not in ("checked_active", "not_checked"):
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")
        fully_supported = (
            self.instrument_adequacy == "passed"
            and self.reference_independence == "evaluator_independent"
            and self.held_out_status in _HELD_OUT_ACCEPTABLE
        )
        if self.code == EVALUATOR_QUALITY_VERIFIED and not fully_supported:
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")
        if self.code == EVALUATOR_QUALITY_CLAIMS_PARTIAL and self.instrument_adequacy == "passed":
            raise ValueError("EVALUATOR_QUALITY_VERIFICATION_RESULT")


def _verdict_for(rows: dict[str, dict[str, Any]], claim_id: str) -> str:
    row = rows.get(claim_id)
    return cast(str, row["verdict"]) if row is not None else "abstain"


def _verify_evaluator_quality_public(
    bundle: dict[str, Any],
    context: EvaluatorQualityVerificationContext,
    trust_status: object,
) -> EvaluatorQualityVerificationResult:
    _verify_evaluator_quality_private(bundle, context=context)
    manifest = bundle["unsigned_manifest"]
    overall = manifest["overall"]
    rows = _instrument_adequacy_rows(bundle)
    instrument_adequacy = cast(str, overall["instrument_adequacy_verdict"])
    reference_independence = cast(str, bundle["reference_standard"]["reference_independence"])
    held_out_status = cast(str, bundle["evaluation_scope"]["held_out_status"])
    fully_supported = (
        instrument_adequacy == "passed"
        and reference_independence == "evaluator_independent"
        and held_out_status in _HELD_OUT_ACCEPTABLE
    )
    code = EVALUATOR_QUALITY_VERIFIED if fully_supported else EVALUATOR_QUALITY_CLAIMS_PARTIAL

    if context.allow_unchecked_trust_status:
        trust_status_evidence = "not_checked"
        trust_status_effective_time = ""
    else:
        snapshot = _verify_evaluator_trust_status(trust_status, context)
        issuer = bundle["verification_materials_v0"]["issuer"]
        _check_evaluator_trust_status_coverage(
            snapshot, issuer_key_ref=issuer["key_ref"], trust_ring_ref=issuer["trust_ring_ref"]
        )
        trust_status_evidence = "checked_active"
        trust_status_effective_time = cast(str, snapshot["effective_time"])

    return EvaluatorQualityVerificationResult(
        code=code,
        instrument_adequacy=instrument_adequacy,
        calibration_verdict=_verdict_for(rows, "EVQ3"),
        agreement_verdict=_verdict_for(rows, "EVQ2"),
        sensitivity_verdict=_verdict_for(rows, "EVQ4"),
        reliability_verdict=_verdict_for(rows, "EVQ5"),
        overall_verdict=cast(str, overall["verdict"]),
        reference_independence=reference_independence,
        held_out_status=held_out_status,
        overall_quality_ppm=overall.get("overall_quality_ppm"),
        trust_status_evidence=trust_status_evidence,
        trust_status_effective_time=trust_status_effective_time,
    )


def verify_evaluator_quality_certificate(
    bundle: object,
    *,
    context: EvaluatorQualityVerificationContext,
    trust_status: object | None = None,
) -> EvaluatorQualityVerificationResult:
    """Verify an EvaluatorQualityCertificateBundleV1 entirely offline.

    Proves: the bundle is well-formed, internally digest-consistent, signed
    by a trusted issuer, bound to ``context.expected_project_ref`` and to one
    process record (via ``context.expected_evaluator_commitment_ref`` --
    see :class:`EvaluatorQualityVerificationContext` for the composition
    contract this pin requires of the caller), and that every verdict it
    prints is capped by the weakest evidence footing, reference standard,
    sample size and declared plan it rests on. It does NOT prove any
    statistic is the number that estimator would produce from the
    underlying data (``NC_EVQ_INTERVALS_NOT_RECOMPUTED``), that a held-out
    set is genuinely disjoint (``NC_EVQ_NO_SELECTION_UNBIASEDNESS``), or
    that the evaluator is good.

    ``trust_status`` is the fourth verification input (S10), a SEPARATE,
    unembedded artifact signed by the anchor pinned at
    ``context.trust_anchor`` -- see that context field and
    :class:`EvaluatorQualityVerificationResult` for the "as of
    ``effective_time`` only" freshness semantics this establishes. Passing
    ``trust_status`` together with ``allow_unchecked_trust_status=True`` is
    a caller contradiction and raises ``CONTEXT`` with no result
    constructed.

    Raises :class:`EvaluatorQualityVerificationError` on any failure, with a
    closed, content-free ``code``/``field`` pair. Any exception escaping the
    private pipeline that is not already an
    :class:`EvaluatorQualityVerificationError` is caught and re-raised as
    ``EVALUATOR_VERIFICATION_FAILED`` -- the catch-all never leaks the
    original exception's text, type, or traceback into the raised error.
    ``EVALUATOR_QUALITY_RESERVED_CODES`` names the codes declared in
    ``EVALUATOR_QUALITY_ERROR_CODES`` that this verifier never emits,
    classified as either ``tripwire`` (unreachable because the V1 schema
    makes the condition unrepresentable -- e.g. plan ordering is a declared
    non-claim and the descriptor has no field the code could report on --
    not merely reserved against a future stage reusing the string) or
    ``subsumed`` (superseded by another emitted code).

    Two verifier conventions here are pending amendment to the Schema
    contract: ``AXIS_POINT_VALUE_ROLE`` picks the per-axis point-value role
    behind ``overall_quality_ppm`` (e.g. ``calibration_slope`` for the
    calibration axis); and ``_REFERENCE_STANDARD_SCOPED_ROLES`` scopes the
    reference-standard directional limits to non-reliability roles, with the
    consequence that a calibration_slope above the agreement ceiling is
    rejected as ``REFERENCE_CEILING_EXCEEDED`` even for a well-calibrated
    evaluator. Both are verifier-side convention, not yet a schema-declared
    rule.
    """
    if not isinstance(context, EvaluatorQualityVerificationContext):
        _fail("CONTEXT", "context")
    if context.allow_unchecked_trust_status and trust_status is not None:
        _fail("CONTEXT", "context")
    if type(bundle) is not dict:
        _fail("EVALUATOR_BUNDLE_SHAPE", "bundle")
    try:
        return _verify_evaluator_quality_public(cast(dict[str, Any], bundle), context, trust_status)
    except EvaluatorQualityVerificationError:
        raise
    except Exception:
        failure = EvaluatorQualityVerificationError("EVALUATOR_VERIFICATION_FAILED", "bundle")
        try:
            raise failure from None
        except EvaluatorQualityVerificationError:
            # ``from None`` clears __cause__ and suppresses display, but while
            # still inside the ``except Exception`` block above the
            # interpreter has already linked the original exception as
            # __context__ -- and that object can carry caller content (see
            # process_record_verifier._load_registry_constant's docstring for
            # the full rationale this mirrors). Clearing it here, once this
            # handler has genuinely exited, is what makes it disappear.
            failure.__context__ = None
            raise


__all__ = [
    "EVALUATOR_QUALITY_ERROR_CODES",
    "EVALUATOR_QUALITY_FIELD_LOCATIONS",
    "EVALUATOR_QUALITY_VERIFIED",
    "EVALUATOR_QUALITY_CLAIMS_PARTIAL",
    "EvaluatorQualityVerificationContext",
    "EvaluatorQualityVerificationError",
    "EvaluatorQualityVerificationResult",
    "verify_evaluator_quality_certificate",
]
