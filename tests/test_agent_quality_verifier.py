"""Regression tests for the pillar-1 agent-quality V1 contract post-merge
audit findings on PR #459 and the round-2 tier-1 review of PR #461 (develop
8f8bb5882b0a04525a21888b190fc7fb04b7d430).

Each test below reproduces one of the reviewer's probes and failed before
the corresponding fix landed. They exist so the findings cannot silently
regress.
"""

from __future__ import annotations

import importlib
import importlib.resources
import json
import math
import re
import traceback
from fractions import Fraction
from pathlib import Path
from unittest.mock import patch

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

import traigent_schema.certification.agent_quality_verifier as v

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
SCHEMA_PATH = (
    ROOT / "traigent_schema" / "schemas" / "certification" / "agent_quality_v1_schema.json"
)
VERIFIER_PATH = ROOT / "traigent_schema" / "certification" / "agent_quality_verifier.py"
CATALOG_PATH = (
    ROOT / "traigent_schema" / "data" / "certification" / "agent_quality_non_claim_catalog.json"
)
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_TEXT = SCHEMA_PATH.read_text(encoding="utf-8")


def _schema_registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


_SCHEMA_REGISTRY = _schema_registry()


def _schema_validator(definition: str) -> Draft7Validator:
    document = {
        "$schema": SCHEMA["$schema"],
        "$id": f"{SCHEMA['$id']}#test-{definition}",
        "definitions": SCHEMA["definitions"],
        "allOf": [{"$ref": f"#/definitions/{definition}"}],
    }
    return Draft7Validator(document, registry=_SCHEMA_REGISTRY)


def _schema_emittable_levels() -> set[str]:
    """The schema's EmittableVerificationLevelV1, derived by validating each
    VerificationLevelV1 enum member -- never by transcribing the schema's
    ``not`` clause by hand, so this stays bound to the schema through
    executed behaviour rather than a second hard-coded copy."""
    validator = _schema_validator("EmittableVerificationLevelV1")
    return {
        level
        for level in SCHEMA["definitions"]["VerificationLevelV1"]["enum"]
        if validator.is_valid(level)
    }


def test_declared_plan_only_claims_the_digest_binding() -> None:
    """Finding 1: AgentQualityDeclaredPlanV1 no longer asserts ordering.

    Failed at 8f8bb5882 because the description said "declared before
    results were observed" -- an ordering claim this certificate family
    does not verify.
    """
    definition = SCHEMA["definitions"]["AgentQualityDeclaredPlanV1"]
    assert "before results were observed" not in definition["description"]


_STEM_SCAN_TARGETS = [
    ("schema", SCHEMA_PATH),
    ("verifier", VERIFIER_PATH),
    ("catalog", CATALOG_PATH),
]


@pytest.mark.parametrize("label,path", _STEM_SCAN_TARGETS, ids=[t[0] for t in _STEM_SCAN_TARGETS])
def test_literal_zero_preregistration_stem_hits(label: str, path: Path) -> None:
    """Finding 1 (extended): zero occurrences of the preregistration stem in
    any of the three artifacts this pillar ships -- the schema, the
    verifier module, and the non-claim catalog -- with no per-sentence or
    per-file exemption.

    Failed at 8f8bb5882 because the tripwire test scanned only the schema
    and exempted one sentence instead of requiring a literal zero
    everywhere this pillar's text lives.
    """
    text = path.read_text(encoding="utf-8")
    hit = re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", text, re.I)
    assert hit is None, f"preregistration stem hit in {label} ({path}): {hit}"


def test_catalog_reason_template_ids_match_the_wire() -> None:
    """Finding 2: the non-claim catalog's reason_template_id values agree
    with the schema's AgentQualityNonClaimsFixedTupleV1 wire tuple.

    Failed at 8f8bb5882 because the catalog used
    ``traigent.agent_quality.non_claim_reason.*`` ids while the schema's
    wire tuple required ``tmpl.aq.noncert.*``.
    """
    catalog = v._read_agent_quality_package_json("agent_quality_non_claim_catalog.json")
    items = SCHEMA["definitions"]["AgentQualityNonClaimsFixedTupleV1"]["items"]
    wire_ids = [item["allOf"][1]["properties"]["reason_template_id"]["const"] for item in items]
    assert [entry["reason_template_id"] for entry in catalog["entries"]] == wire_ids


_AGENT_QUALITY_CORRUPTIBLE_FILES = [
    f"agent_quality_{stem}.json" for stem in v._AGENT_QUALITY_REGISTRY_DOMAINS
] + [f"agent_quality_{stem}.digest.json" for stem in v._AGENT_QUALITY_REGISTRY_DOMAINS]


class _CorruptingTraversable:
    """Proxies a real ``importlib.resources`` Traversable, substituting
    corrupted text for exactly one filename and delegating everything else
    to the real filesystem-backed node.
    """

    def __init__(self, real: object, target_filename: str, corrupt_text: str) -> None:
        self._real = real
        self._target_filename = target_filename
        self._corrupt_text = corrupt_text

    def joinpath(self, name: str) -> _CorruptingTraversable:
        return _CorruptingTraversable(
            self._real.joinpath(name),
            self._target_filename,
            self._corrupt_text,  # type: ignore[attr-defined]
        )

    def read_text(self, encoding: str = "utf-8") -> str:
        if getattr(self._real, "name", None) == self._target_filename:
            return self._corrupt_text
        return self._real.read_text(encoding=encoding)  # type: ignore[attr-defined]


@pytest.mark.parametrize("target_filename", _AGENT_QUALITY_CORRUPTIBLE_FILES)
def test_import_time_package_data_validation(target_filename: str) -> None:
    """Finding 3 (extended): importing the module establishes the
    content-free package-data boundary unconditionally, and no sentinel
    from a corrupted document OR a corrupted digest sidecar ever reaches
    the raised error's message, cause, context, or a formatted traceback --
    for each of the four documents and each of the four sidecars,
    corrupted separately.

    Failed at 8f8bb5882 because ``_load_agent_quality_document`` was a lazy
    loader nothing called at import, so a corrupt package installation was
    only caught on whichever caller happened to touch it first; a prior
    permanent test only checked ``str(exc)`` for one global corruption,
    which does not prove per-file error-chain sanitization.
    """
    sentinel = "SENTINEL_" + re.sub(r"[^A-Za-z0-9]", "_", target_filename)
    corrupt_text = f"{{ not valid json -- {sentinel}"
    real_files = importlib.resources.files

    def fake_files(package: str) -> _CorruptingTraversable:
        return _CorruptingTraversable(real_files(package), target_filename, corrupt_text)

    try:
        with patch("importlib.resources.files", side_effect=fake_files):
            with pytest.raises(ValueError) as excinfo:
                importlib.reload(v)
        exc = excinfo.value
        assert str(exc) == "PACKAGE_DATA_INVALID"
        if isinstance(exc, v.AgentQualityVerificationError):
            assert exc.code == "PACKAGE_DATA_INVALID"
        assert sentinel not in str(exc)
        assert sentinel not in repr(exc.__cause__)
        assert sentinel not in repr(exc.__context__)
        formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        assert sentinel not in formatted
        assert target_filename not in formatted
    finally:
        importlib.reload(v)


def test_abstained_result_rejects_construction_recomputed_level() -> None:
    """Finding 4: an abstained result cannot carry
    construction_recomputed_v1, since an abstained bundle has no measured
    claims to recompute.

    Failed at 8f8bb5882 because __post_init__ required
    interval_verification_level == construction_recomputed_v1
    unconditionally, even for AGENT_QUALITY_CLAIM_ABSTAINED.
    """
    with pytest.raises(ValueError):
        v.AgentQualityVerificationResult(
            "AGENT_QUALITY_CLAIM_ABSTAINED",
            "AQ1",
            "abstained",
            "obj.accuracy.exact_match.v1",
            950000,
            200,
            "construction_recomputed_v1",
            "issuer_attested_v1",
            "dataset_certificate_not_verified",
            "evaluator_certificate_not_verified",
        )


def test_abstained_result_rejects_an_unregistered_level() -> None:
    """Round-2 BLOCKER: an abstained result's interval_verification_level
    must be drawn from a closed, registered vocabulary -- an unregistered
    string that is not ``construction_recomputed_v1`` must still be
    rejected, not merely the one forbidden literal.

    Failed before this fix because __post_init__ only forbade
    ``construction_recomputed_v1`` on an abstention, letting any other
    unregistered string (e.g. ``fully_recomputed_v9``) sail through.
    """
    with pytest.raises(ValueError):
        v.AgentQualityVerificationResult(
            "AGENT_QUALITY_CLAIM_ABSTAINED",
            "AQ1",
            "abstained",
            "obj.accuracy.exact_match.v1",
            950000,
            200,
            "fully_recomputed_v9",
            "issuer_attested_v1",
            "dataset_certificate_not_verified",
            "evaluator_certificate_not_verified",
        )


def test_valid_abstention_is_accepted() -> None:
    """Round-2 BLOCKER (positive case): the one interval_verification_level
    an abstained result CAN honestly carry -- issuer_attested_v1 -- is
    accepted, so the closed-vocabulary constraint cannot be satisfied by a
    __post_init__ that rejects every string.
    """
    result = v.AgentQualityVerificationResult(
        "AGENT_QUALITY_CLAIM_ABSTAINED",
        "AQ1",
        "abstained",
        "obj.accuracy.exact_match.v1",
        950000,
        200,
        "issuer_attested_v1",
        "issuer_attested_v1",
        "dataset_certificate_not_verified",
        "evaluator_certificate_not_verified",
    )
    assert result.interval_verification_level == "issuer_attested_v1"
    assert result.code == "AGENT_QUALITY_CLAIM_ABSTAINED"


def test_objective_duplicate_code_is_registered_and_field_located() -> None:
    """Finding 5: OBJECTIVE_DUPLICATE is a registered error code, so the
    duplicate guard can report its failure with a field location instead of
    degrading to a generic ValueError.

    Failed at 8f8bb5882 because AGENT_QUALITY_ERROR_CODES omitted
    OBJECTIVE_DUPLICATE, so constructing the error raised
    AGENT_QUALITY_VERIFICATION_ERROR_CODE instead.
    """
    assert "OBJECTIVE_DUPLICATE" in v.AGENT_QUALITY_ERROR_CODES
    assert "SELECTION_ESTIMATE_DUPLICATE" in v.AGENT_QUALITY_ERROR_CODES
    rows = [
        {"objective_id": "obj.accuracy.exact_match.v1"},
        {"objective_id": "obj.accuracy.exact_match.v1"},
    ]
    with pytest.raises(v.AgentQualityVerificationError) as excinfo:
        v._unique_by(rows, lambda r: r["objective_id"], "OBJECTIVE_DUPLICATE", "measured_claims")
    assert excinfo.value.field == "measured_claims"


def test_selection_estimate_duplicate_is_registered_and_field_located() -> None:
    """Round-2 evidence gap: SELECTION_ESTIMATE_DUPLICATE is registered and
    enforced by ``_unique_by`` -- this exercises that helper contract
    DIRECTLY, not a call site in the complete check sequence, since no
    verification path in this packet calls it yet (there is no public
    entry point here to call it from -- see the module docstring).
    """
    rows = [
        {"objective_id": "obj.accuracy.exact_match.v1", "point_estimate": 100000},
        {"objective_id": "obj.accuracy.exact_match.v1", "point_estimate": 200000},
    ]
    with pytest.raises(v.AgentQualityVerificationError) as excinfo:
        v._unique_by(
            rows,
            lambda r: r["objective_id"],
            "SELECTION_ESTIMATE_DUPLICATE",
            "non_certified_selection_estimates",
        )
    assert excinfo.value.code == "SELECTION_ESTIMATE_DUPLICATE"
    assert excinfo.value.field == "non_certified_selection_estimates"


def test_wilson_bounds_rounds_outward_for_a_sub_unit_interval() -> None:
    """Finding 6: Wilson bracketing uses the parabola's exact rational
    vertex, not the rounded point estimate, so outward rounding can only
    widen the interval.

    Failed at 8f8bb5882 for 1 success in 10**9 trials: the rounded point
    estimate rounded to 0, collapsing both the low- and high-endpoint
    bisection brackets to (0, 0) instead of the correctly outward-rounded
    (0, 1).
    """
    assert v._wilson_bounds(1, 10**9, 950000) == (0, 1)


def test_wilson_bounds_still_brackets_the_ordinary_spot_value() -> None:
    """Guard: the vertex-based bracketing fix does not regress the ordinary
    case -- 870/1000 at 95% coverage still brackets ~847000-889000 and
    contains the point estimate 870000.
    """
    low, high = v._wilson_bounds(870, 1000, 950000)
    assert 846000 <= low <= 870000 <= high <= 890000


def _exact_wilson_endpoints_ppm(k: int, n: int, coverage_ppm: int) -> tuple[Fraction, Fraction]:
    """Independent oracle: the true Wilson score endpoints, in ppm, as
    Fractions -- computed from the SAME pinned z (via the module's own
    quantile lookup) but via a completely separate arithmetic path from
    :func:`v._wilson_bounds`'s integer bisection.

    ``k == 0`` and ``k == n`` are handled analytically via Vieta's formulas
    on the defining quadratic (one root is exactly 0 or 1 by construction,
    so the other is the quadratic's exact rational product-of-roots) --
    no square root needed, and no risk of a conservative sqrt bound
    overshooting outside the unit interval at these extremes. The general
    case approximates the sole irrational quantity, sqrt(inside), by an
    exact-rational floor via ``math.isqrt`` at 10**40 precision -- an error
    orders of magnitude below one ppm, the module's own integer
    granularity, so it cannot flip the outward-rounding comparison.
    """
    z_scaled = v._lookup_t_scaled(coverage_ppm, v._INFINITY_DF_BUCKET)
    z = Fraction(z_scaled, v._T_SCALE)
    z2 = z * z
    if k == 0:
        low = Fraction(0)
        high = z2 / (n + z2)
    elif k == n:
        low = Fraction(n, 1) / (n + z2)
        high = Fraction(1)
    else:
        p = Fraction(k, n)
        denom = 1 + z2 / n
        center = p + z2 / (2 * n)
        inside = p * (1 - p) / n + z2 / (4 * n * n)
        precision = 10**40
        scaled = inside * precision * precision
        floor_val = scaled.numerator // scaled.denominator
        sqrt_floor = math.isqrt(floor_val)
        sqrt_approx = Fraction(sqrt_floor, precision)
        half = z * sqrt_approx
        low = (center - half) / denom
        high = (center + half) / denom
    return low * v._T_SCALE, high * v._T_SCALE


_WILSON_GRID = [
    (0, 30),
    (1, 30),
    (15, 30),
    (30, 30),
    (1, 10**9),
    (870, 1000),
    (999999, 10**6),
    (1, 100),
    (99, 100),
    (50, 201),
]


@pytest.mark.parametrize("k,n", _WILSON_GRID)
def test_wilson_bounds_never_narrow_across_a_grid(k: int, n: int) -> None:
    """Round-2 evidence gap: make the captain's hand-run exact-arithmetic
    grid probe permanent, with the oracle's k=0/k=n overshoot fixed by
    handling those two cases analytically instead of via the general
    conservative sqrt bound.

    For every (k, n) pair, the module's outward-rounded integer endpoints
    must never be narrower than the true (independently computed) Wilson
    endpoints: low <= exact_low and high >= exact_high.
    """
    coverage_ppm = 950000
    low, high = v._wilson_bounds(k, n, coverage_ppm)
    if k == 0:
        assert low == 0
    if k == n:
        assert high == 1_000_000
    exact_low, exact_high = _exact_wilson_endpoints_ppm(k, n, coverage_ppm)
    assert low <= exact_low
    assert high >= exact_high


def _verified_kwargs(**overrides: object) -> dict:
    kwargs: dict = dict(
        code="AGENT_QUALITY_VERIFIED",
        claim_id="AQ1",
        evidence_basis="issuer_verified",
        primary_objective_id="obj.accuracy.exact_match.v1",
        nominal_coverage_ppm=950000,
        holdout_item_count=200,
        interval_verification_level="construction_recomputed_v1",
        split_verification_level="issuer_attested_v1",
        dataset_condition_code="dataset_certificate_verified",
        evaluator_condition_code="evaluator_certificate_verified",
    )
    kwargs.update(overrides)
    return kwargs


def test_schema_emittable_verification_level_is_construction_recomputed_only() -> None:
    """N1: pins the schema side -- EmittableVerificationLevelV1 validates
    exactly {construction_recomputed_v1}, derived by validating (never by
    transcribing the schema's ``not`` clause)."""
    assert _schema_emittable_levels() == {"construction_recomputed_v1"}


def test_emittable_verification_levels_match_schema_contract() -> None:
    """N1: nothing in _EMITTABLE_VERIFICATION_LEVELS is unregistered by the
    schema's VerificationLevelV1, and the exact, named delta against the
    schema's EmittableVerificationLevelV1 is {issuer_attested_v1} -- fails if
    either side moves in either direction.

    See the comment above _EMITTABLE_VERIFICATION_LEVELS in
    agent_quality_verifier.py: the constant is the union of the result
    dataclass's two level fields, not a copy of EmittableVerificationLevelV1,
    and issuer_attested_v1 is a member by construction because
    __post_init__ pins split_verification_level to it.
    """
    registered = set(SCHEMA["definitions"]["VerificationLevelV1"]["enum"])
    schema_emittable = _schema_emittable_levels()

    assert v._EMITTABLE_VERIFICATION_LEVELS <= registered
    assert v._EMITTABLE_VERIFICATION_LEVELS - schema_emittable == {"issuer_attested_v1"}
    assert schema_emittable <= v._EMITTABLE_VERIFICATION_LEVELS


def test_abstained_interval_levels_disjoint_from_schema_emittable() -> None:
    """N1: an abstained result's only honest interval_verification_level is
    issuer_attested_v1, which is disjoint from the schema's emittable
    (recomputed) member -- an abstained result can never carry the
    recomputed level."""
    assert v._ABSTAINED_INTERVAL_VERIFICATION_LEVELS == {"issuer_attested_v1"}
    assert v._ABSTAINED_INTERVAL_VERIFICATION_LEVELS.isdisjoint(_schema_emittable_levels())


@pytest.mark.parametrize("level", sorted(SCHEMA["definitions"]["VerificationLevelV1"]["enum"]))
def test_verified_result_interval_level_guard_driven_by_schema_enum(level: str) -> None:
    """N1 (behaviour): a VERIFIED result accepts interval_verification_level
    only when it equals the schema's emittable member
    (construction_recomputed_v1); every other member of VerificationLevelV1's
    enum, including issuer_attested_v1 and opened_and_recomputed_v1, must be
    rejected. Driven from the schema enum, not a hand-written list."""
    kwargs = _verified_kwargs(interval_verification_level=level)
    if level == "construction_recomputed_v1":
        result = v.AgentQualityVerificationResult(**kwargs)
        assert result.interval_verification_level == "construction_recomputed_v1"
    else:
        with pytest.raises(ValueError):
            v.AgentQualityVerificationResult(**kwargs)


@pytest.mark.parametrize("level", sorted(SCHEMA["definitions"]["VerificationLevelV1"]["enum"]))
def test_split_verification_level_guard_driven_by_schema_enum(level: str) -> None:
    """N1 (behaviour): split_verification_level accepts only
    issuer_attested_v1 -- this verifier never recomputes the split
    derivation -- and rejects every other member of VerificationLevelV1's
    enum. Driven from the schema enum, not a hand-written list."""
    kwargs = _verified_kwargs(split_verification_level=level)
    if level == "issuer_attested_v1":
        result = v.AgentQualityVerificationResult(**kwargs)
        assert result.split_verification_level == "issuer_attested_v1"
    else:
        with pytest.raises(ValueError):
            v.AgentQualityVerificationResult(**kwargs)


def test_agent_quality_field_locations_match_schema_contract() -> None:
    """N2: AGENT_QUALITY_FIELD_LOCATIONS is exactly
    AgentQualityFieldLocationV1's enum in both directions -- replaces the
    comment's stale pointer to a nonexistent "check script" with the actual
    assertion that ties the two together."""
    schema_locations = set(SCHEMA["definitions"]["AgentQualityFieldLocationV1"]["enum"])
    symmetric_difference = v.AGENT_QUALITY_FIELD_LOCATIONS ^ schema_locations
    assert v.AGENT_QUALITY_FIELD_LOCATIONS == schema_locations, (
        f"AGENT_QUALITY_FIELD_LOCATIONS and AgentQualityFieldLocationV1 have "
        f"drifted apart; symmetric difference: {sorted(symmetric_difference)}"
    )


# --------------------------------------------------------------------------
# P1-V2.0 -- private stage runner, error-code partition, dead-helper
# inventory, no-public-entry-point sentinel.
# --------------------------------------------------------------------------

import ast  # noqa: E402
import importlib as _importlib  # noqa: E402

import tests.test_agent_quality_v1_schema as _schema_fixtures  # noqa: E402


def _context(**overrides: object) -> v.AgentQualityVerificationContext:
    sha = "sha256:" + "a" * 64
    kwargs: dict = dict(
        process_record_context=object(),
        expected_project_ref="proj-1",
        expected_build_session_ref="build_session:ssssssss",
        expected_agent_commitment_ref=sha,
        expected_dataset_commitment_ref=sha,
        expected_evaluator_commitment_ref=sha,
        expected_build_definition_commitment_ref=sha,
        expected_measurement_contract_ref="measurement:mmmmmmmm",
        expected_measurement_contract_record_digest=sha,
        accept_abstained_bundle=False,
    )
    kwargs.update(overrides)
    return v.AgentQualityVerificationContext(**kwargs)


_STAGE_FUNCTION_NAMES = (
    "_stage_s1_structural",
    "_stage_s2_context_binding",
    "_stage_s3_registry_identity",
    "_stage_s4_declared_plan_signatures",
    "_stage_s5_objective_measurement",
    "_stage_s6_splits_held_out",
    "_stage_s7_composition_abstention",
    "_stage_s8_manifest_digests_signature",
)


def test_no_public_entry_point_exists_yet() -> None:
    """Sol B1: this packet ships no public entry point. A half-checking
    verifier that reports success is worse than one that does not exist, so
    ``verify_agent_quality_certificate`` must be absent from both the module
    and its public surface until the complete check sequence lands. This
    test is deleted only in packet .6, once the real entry point ships."""
    assert not hasattr(v, "verify_agent_quality_certificate")
    module = _importlib.import_module("traigent_schema.certification")
    assert not any("agent_quality" in name.lower() for name in module.__all__)


def test_run_agent_quality_checks_rejects_every_bundle() -> None:
    """Every stage in this packet is an unconditional refusal, so the
    private runner rejects any bundle, valid or not, with the catch-all
    code -- proving the runner wraps the stage sequence rather than merely
    defining stages nobody calls."""
    context = _context()
    bundle = _schema_fixtures._bundle()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(bundle, context)
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"


@pytest.mark.parametrize("stage_name", _STAGE_FUNCTION_NAMES)
def test_each_stage_is_a_real_fail_closed_function(stage_name: str) -> None:
    """Every named stage exists, is independently callable, and refuses
    (rather than silently passing) when called directly."""
    stage = getattr(v, stage_name)
    assert callable(stage)
    context = _context()
    bundle = _schema_fixtures._bundle()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        if stage_name == "_stage_s2_context_binding":
            stage(bundle, context)
        else:
            stage(bundle)
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"


def test_abstained_bundle_carries_claims_is_schema_preempted() -> None:
    """ABSTAINED_BUNDLE_CARRIES_CLAIMS is in
    AGENT_QUALITY_SCHEMA_PREEMPTED_CODES: AgentQualityCertificateBundleV1's
    own ``allOf`` if/then/else abstention coupling already rejects a
    non-issuer_verified support row paired with a nonempty measured_claims
    array, before S1's schema check (design row 5) ever hands this module a
    schema-valid bundle to check."""
    bundle = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[_schema_fixtures._wilson_claim()],
        selection_estimates=[],
    )
    errors = _schema_fixtures._errors(bundle)
    assert errors, (
        "an abstained support row with a nonempty measured_claims array must "
        "be rejected by the schema itself (S1) -- ABSTAINED_BUNDLE_CARRIES_CLAIMS "
        "is unreachable through any schema-valid bundle"
    )


def test_selection_estimate_in_certified_set_is_schema_preempted() -> None:
    """SELECTION_ESTIMATE_IN_CERTIFIED_SET is in
    AGENT_QUALITY_SCHEMA_PREEMPTED_CODES for the same reason: the abstention
    coupling's ``else`` branch also caps
    non_certified_selection_estimates to maxItems 0 on a non-issuer_verified
    support row, so a schema-valid abstained bundle can never carry a
    selection estimate either -- rejected by S1's schema check before any
    per-claim guard would run."""
    bundle = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[],
        selection_estimates=[_schema_fixtures._selection_estimate()],
    )
    errors = _schema_fixtures._errors(bundle)
    assert errors, (
        "an abstained support row with a nonempty non_certified_selection_estimates "
        "array must be rejected by the schema itself (S1) -- "
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET is unreachable through any "
        "schema-valid bundle"
    )


def test_selection_estimate_duplicate_is_not_schema_preempted() -> None:
    """Counter-proof for sol N6's widened check: SELECTION_ESTIMATE_DUPLICATE
    was checked against the same preemption hypothesis and found NOT
    preempted -- NonCertifiedSelectionEstimatesV1's own description says
    uniqueItems cannot express "same objective_id, different point_estimate
    or sample_size", so two selection estimates for the same objective_id
    but different payloads must remain schema-valid, and the module's own
    guard (SELECTION_ESTIMATE_DUPLICATE, deferred to .4/.6) is the only thing
    that can ever reject it."""
    definition = SCHEMA["definitions"]["NonCertifiedSelectionEstimatesV1"]
    assert "SELECTION_ESTIMATE_DUPLICATE" in definition["description"]
    duplicate_estimates = [
        _schema_fixtures._selection_estimate(point_estimate=970000),
        _schema_fixtures._selection_estimate(point_estimate=960000),
    ]
    bundle = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_issuer_verified(),
        measured_claims=[_schema_fixtures._wilson_claim()],
        selection_estimates=duplicate_estimates,
    )
    errors = _schema_fixtures._errors(bundle)
    assert errors == [], (
        "two selection-estimate records sharing an objective_id but "
        "differing in point_estimate must be schema-VALID -- "
        "SELECTION_ESTIMATE_DUPLICATE stays a verifier-owned guard, not a "
        "schema-preempted one"
    )


def test_schema_preempted_codes_are_exactly_two_and_registered() -> None:
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES == {
        "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
    }
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES <= v.AGENT_QUALITY_ERROR_CODES


def test_pending_and_preempted_and_emitted_partition_is_disjoint_and_covers_all() -> None:
    """N6 widened: the three buckets -- schema-preempted, pending, and
    emitted-today -- are pairwise disjoint and their union is exactly
    AGENT_QUALITY_ERROR_CODES."""
    emitted_today = frozenset(
        {
            "CONTEXT",
            "PACKAGE_DATA_INVALID",
            "QUANTILE_TABLE_LOOKUP_FAILED",
            "AGENT_QUALITY_VERIFICATION_FAILED",
        }
    )
    preempted = v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    pending = v.AGENT_QUALITY_PENDING_CODES

    assert preempted.isdisjoint(pending)
    assert preempted.isdisjoint(emitted_today)
    assert pending.isdisjoint(emitted_today)
    assert preempted | pending | emitted_today == v.AGENT_QUALITY_ERROR_CODES


def test_pending_codes_are_not_yet_emitted() -> None:
    """No pending code has a literal call site in the module today, and
    every literal code actually raised is NOT pending -- source-scanned so a
    stage that starts emitting a pending code (or one that silently stops
    emitting a non-pending code) breaks this test instead of drifting past
    it. ``_unique_by`` is a second sanctioned pass-through, alongside
    ``_fail`` itself: it forwards a CALLER-supplied ``duplicate_code``
    parameter to ``_fail`` by design (see its docstring), so its own
    ``_fail(duplicate_code, field)`` call site is not a literal-code
    emission of anything and is excluded from the scan the same way ``_fail``
    excludes its own body."""
    source = Path(v.__file__).read_text()
    emitted = set(re.findall(r'_fail\(\s*"([A-Z_]+)"', source))
    emitted |= set(re.findall(r"AgentQualityVerificationError\(\s*\"([A-Z_]+)\"", source))
    assert emitted <= v.AGENT_QUALITY_ERROR_CODES, emitted - v.AGENT_QUALITY_ERROR_CODES
    assert emitted.isdisjoint(v.AGENT_QUALITY_PENDING_CODES), (
        emitted & v.AGENT_QUALITY_PENDING_CODES
    )
    assert v.AGENT_QUALITY_PENDING_CODES.isdisjoint(emitted)


def test_emission_audit_scans_only_literal_codes() -> None:
    """AST companion to the regex audit above: every ``_fail(...)`` /
    ``AgentQualityVerificationError(...)`` call site in the module must pass
    a string-literal first argument, except ``_fail``'s own body (which
    constructs the error from its parameters) and ``_unique_by`` (the one
    sanctioned pass-through of a caller-supplied code -- see its
    docstring)."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    offenders: list[str] = []

    class _Visitor(ast.NodeVisitor):
        function_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_stack.append(node.name)
            self.generic_visit(node)
            self.function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            if name in ("_fail", "AgentQualityVerificationError") and self.function_stack[
                -1:
            ] not in (["_fail"], ["_unique_by"]):
                if not node.args:
                    offenders.append(f"{name}() with no positional args at line {node.lineno}")
                else:
                    first = node.args[0]
                    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                        offenders.append(
                            f"{name}(...) with a non-literal code at line {node.lineno}"
                        )
            self.generic_visit(node)

    _Visitor().visit(tree)
    assert offenders == []
    assert v._run_agent_quality_checks.__module__ == v.__name__


def test_stage_codes_are_pairwise_disjoint_and_cover_all_non_preempted_codes() -> None:
    stage_sets = list(v._STAGE_CODES.values())
    union: set[str] = set()
    total = 0
    for codes in stage_sets:
        union |= codes
        total += len(codes)
    assert total == len(union), "two stages claim overlapping codes"
    assert union == v.AGENT_QUALITY_ERROR_CODES - v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    assert set(v._STAGE_CODES) == set(_STAGE_FUNCTION_NAMES)


_UNWIRED_HELPER_NAMES = frozenset(
    {
        # Pre-existing at base (#459/#461); packet .4 wires all four
        # arithmetic/dedup helpers, .2/.3 wires _strip_self_digest.
        "_strip_self_digest",
        "_wilson_point",
        "_student_t_half_width",
        "_wilson_bounds",
        "_unique_by",
        # New in P1-V2.0: the private runner has no in-module caller until
        # the public entry point exists (packet .6).
        "_run_agent_quality_checks",
    }
)


def test_unwired_helpers_inventory_is_exact() -> None:
    """The dead-helper comment block above ``_stage_s1_structural`` names
    exactly the MODULE-LEVEL (not class-method) private functions with zero
    in-module references today. Computed by AST rather than trusted by
    inspection, so a helper that becomes wired (or a previously-wired one
    that goes dead) breaks this test instead of letting the comment silently
    drift. Restricted to ``tree.body`` (top-level statements) so dataclass
    dunders (``__init__``, ``__post_init__``) -- which are never
    module-level defs and are always "referenced" by the language itself,
    not by any name lookup this scan could see -- never appear as false
    positives."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)

    top_level_private_functions = {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("_")
    }
    all_name_loads: list[str] = [
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    ]

    reference_counts: dict[str, int] = {}
    for name in all_name_loads:
        reference_counts[name] = reference_counts.get(name, 0) + 1

    unwired = {name for name in top_level_private_functions if reference_counts.get(name, 0) == 0}
    assert unwired == _UNWIRED_HELPER_NAMES, (
        f"unwired-helper inventory drifted: computed {sorted(unwired)}, "
        f"documented {sorted(_UNWIRED_HELPER_NAMES)}"
    )
