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
    """The measurement-side role sweep S3 does not cover (see its docstring)."""
    measurements = bundle["measurements"]
    ordered = [
        measurements["calibration"]["expected_calibration_error"],
        measurements["calibration"]["calibration_slope"],
        measurements["agreement"]["agreement"],
        measurements["sensitivity"]["discriminating_power"],
        measurements["sensitivity"]["false_difference_rate"],
    ] + [
        probe["measurement"]
        for probe in measurements["reliability"]["probe_results"]
        if probe["status"] == "measured"
    ]
    rows: dict[str, dict[str, Any]] = {}
    for row in ordered:
        role = row["measurement_role"]
        if role in rows:
            _fail("MEASUREMENT_ROLE_DUPLICATE", "measurements")
        rows[role] = row
    return rows


def _check_measurement_registry_admissibility(row: dict[str, Any]) -> None:
    entry = _estimator_registry_index().get(row["estimator_id"])
    if entry is None:
        _fail("ESTIMATOR_NOT_REGISTERED", "measurements")
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


def _check_plan_containment(bundle: dict[str, Any]) -> None:
    """S12: per-role plan containment -- the post-hoc estimator/level-shopping guard.

    Every role the measurement set reports must have a matching plan entry:
    a measured-but-unplanned role receives none of this stage's checks (no
    plan row to check it against), so it is rejected outright rather than
    silently skipped -- the converse case (a role the plan requires but the
    bundle never measured) remains a coverage concern the per-claim
    rejection stages (EVQ4/EVQ5) own, not this stage.
    """
    _check_plan_direction_coupling(bundle)
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


def _check_reference_ceiling(bundle: dict[str, Any]) -> None:
    """EVQ2's own reference limit: the agreement measurement's conservative
    (high) bound must not exceed the reference standard's agreement ceiling.
    """
    row = _measurement_role_rows(bundle).get("agreement_primary")
    if row is None:
        return
    if row["interval_high_value"] > bundle["reference_standard"]["agreement_ceiling_ppm"]:
        _fail("REFERENCE_CEILING_EXCEEDED", "reference_standard.ceiling")


def _check_reference_floor(bundle: dict[str, Any]) -> None:
    """EVQ3's distinguishing stage: every lower_is_better ppm role (an error
    rate) is bounded below by the reference standard's own noise floor -- a
    single ceiling on both directions would let a perfect-calibration claim
    of zero through, below what the reference itself can resolve.
    """
    floor = bundle["reference_standard"]["error_floor_ppm"]
    for row in _measurement_role_rows(bundle).values():
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
    evidence -- a required axis that abstains forces the overall verdict to
    abstain too, never a narrower silent recomputation."""
    rows = _instrument_adequacy_rows(bundle)
    overall = bundle["unsigned_manifest"]["overall"]
    for weight in bundle["declared_plan"]["aggregation_policy"]["weights"]:
        if not weight["required_axis"]:
            continue
        claim_id = _AXIS_INSTRUMENT_CLAIM.get(weight["axis"])
        if claim_id is None:
            continue
        row = rows.get(claim_id)
        if row is not None and row["verdict"] == "abstain" and overall["verdict"] != "abstain":
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


def _axis_point_value(bundle: dict[str, Any], axis: str) -> int:
    """The per-axis point value the A5 weighted sum is over. These values
    are themselves issuer-attested, never recomputed by this verifier
    (NC_EVQ_INTERVALS_NOT_RECOMPUTED) -- only the arithmetic over them is
    checked.
    """
    measurements = bundle["measurements"]
    if axis == "calibration":
        return cast(int, measurements["calibration"]["calibration_slope"]["point_value"])
    if axis == "agreement":
        return cast(int, measurements["agreement"]["agreement"]["point_value"])
    if axis == "sensitivity":
        return cast(int, measurements["sensitivity"]["discriminating_power"]["point_value"])
    if axis == "reliability":
        probes = [
            probe["measurement"]["point_value"]
            for probe in measurements["reliability"]["probe_results"]
            if probe["status"] == "measured"
        ]
        return _round_half_even(sum(probes), len(probes)) if probes else 0
    return 0


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


def _verify_evaluator_quality_private(bundle: object, *, context: object) -> None:
    """Run P3-V.2/P3-V.3/P3-V.4. The commitment pin must come from a VERIFIED process record."""
    shaped = _check_bundle_shape(bundle)
    _check_schema(shaped)
    _check_semantic_uniqueness(shaped)
    _check_scope_binding(shaped, context)
    _check_artifact_digests(shaped)
    _check_registry_digests(shaped)
    _check_manifest_signature(shaped)
    _check_commitment(shaped, context)
    _check_plan_containment(shaped)
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
