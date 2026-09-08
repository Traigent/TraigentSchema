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

import traigent_schema.certification.agent_quality_verifier as v

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "traigent_schema" / "schemas" / "certification" / "agent_quality_v1_schema.json"
)
VERIFIER_PATH = ROOT / "traigent_schema" / "certification" / "agent_quality_verifier.py"
CATALOG_PATH = (
    ROOT / "traigent_schema" / "data" / "certification" / "agent_quality_non_claim_catalog.json"
)
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_TEXT = SCHEMA_PATH.read_text(encoding="utf-8")


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
    wire_ids = [
        item["allOf"][1]["properties"]["reason_template_id"]["const"] for item in items
    ]
    assert [entry["reason_template_id"] for entry in catalog["entries"]] == wire_ids


_AGENT_QUALITY_CORRUPTIBLE_FILES = [
    f"agent_quality_{stem}.json" for stem in v._AGENT_QUALITY_REGISTRY_DOMAINS
] + [
    f"agent_quality_{stem}.digest.json" for stem in v._AGENT_QUALITY_REGISTRY_DOMAINS
]


class _CorruptingTraversable:
    """Proxies a real ``importlib.resources`` Traversable, substituting
    corrupted text for exactly one filename and delegating everything else
    to the real filesystem-backed node.
    """

    def __init__(self, real: object, target_filename: str, corrupt_text: str) -> None:
        self._real = real
        self._target_filename = target_filename
        self._corrupt_text = corrupt_text

    def joinpath(self, name: str) -> "_CorruptingTraversable":
        return _CorruptingTraversable(
            self._real.joinpath(name), self._target_filename, self._corrupt_text  # type: ignore[attr-defined]
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
        v._unique_by(
            rows, lambda r: r["objective_id"], "OBJECTIVE_DUPLICATE", "measured_claims"
        )
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
