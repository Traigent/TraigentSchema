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
import sys
import traceback
import types as _gv_types
from collections.abc import Callable
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
            self._real.joinpath(name),  # type: ignore[attr-defined]
            self._target_filename,
            self._corrupt_text,
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


def test_lookup_t_scaled_unregistered_coverage_fails_closed() -> None:
    """P1-V2.4 review P2-2: no test anywhere exercised
    ``QUANTILE_TABLE_LOOKUP_FAILED`` directly, even though the brief
    required one. An unregistered ``coverage_ppm`` has no bucket list at
    all."""
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._lookup_t_scaled(123456, 199)
    assert caught.value.code == "QUANTILE_TABLE_LOOKUP_FAILED"
    assert caught.value.field == "quantile_table"


def test_lookup_t_scaled_df_below_smallest_bucket_fails_closed() -> None:
    """A registered coverage with a ``df`` below the table's smallest
    ``df_bucket`` for that coverage -- unreachable for a schema-valid claim
    (``sample_count``'s schema minimum keeps ``df >= 1``), but this helper
    must still fail closed rather than assume that invariant."""
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._lookup_t_scaled(950000, 0)
    assert caught.value.code == "QUANTILE_TABLE_LOOKUP_FAILED"
    assert caught.value.field == "quantile_table"


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

# The catch-all, cross-cutting placeholder code every stage's unconditional
# refusal emits today (and that _run_agent_quality_checks' own wrapper also
# emits) -- see the module's "new in P1-V2.0: catch-all, emitted by every
# stage placeholder and by _run_agent_quality_checks' own wrapper" vocabulary
# comment. It is assigned SOLE ownership to S1 in _STAGE_CODES for
# partition-accounting purposes only; it is not subject to the
# per-stage-owns-what-it-emits invariant the way every other code is,
# because by design every stage's placeholder body emits it. Excluded, by
# name, from test_stage_only_emits_codes_it_owns below.
_UNIVERSAL_PLACEHOLDER_CODE = "AGENT_QUALITY_VERIFICATION_FAILED"


def _emission_sites(tree: ast.AST) -> list[tuple[str, str, int]]:
    """Return ``(enclosing_function_name, code, lineno)`` for every literal
    vocabulary-code emission site anywhere in the module: a
    ``_fail("CODE", ...)`` or ``AgentQualityVerificationError("CODE", ...)``
    call (excluding ``_fail``'s own body, which constructs the error from
    its parameters, not a literal), and a ``_unique_by(rows, key_fn,
    "CODE", field)`` call whose third positional argument (or
    ``duplicate_code=`` keyword) is a string literal -- ``_unique_by``
    forwards that argument straight into its own internal ``_fail`` call
    (see its docstring), so a CALL to ``_unique_by`` with a literal third
    argument really does emit that code at the call site, even though the
    emission is one level removed from a direct ``_fail(...)`` call
    (P1-V2.0 review finding P1-2: the original audit excluded ``_unique_by``
    call sites entirely as a "sanctioned pass-through", which let a stage
    raise a PENDING code through it with every scan green)."""
    sites: list[tuple[str, str, int]] = []

    class _Visitor(ast.NodeVisitor):
        function_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_stack.append(node.name)
            self.generic_visit(node)
            self.function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            enclosing = self.function_stack[-1] if self.function_stack else "<module>"
            if name in ("_fail", "AgentQualityVerificationError") and enclosing != "_fail":
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        sites.append((enclosing, first.value, node.lineno))
            elif name == "_unique_by" and enclosing != "_unique_by":
                literal_code: str | None = None
                if len(node.args) >= 3:
                    candidate = node.args[2]
                    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                        literal_code = candidate.value
                for kw in node.keywords:
                    if (
                        kw.arg == "duplicate_code"
                        and isinstance(kw.value, ast.Constant)
                        and isinstance(kw.value.value, str)
                    ):
                        literal_code = kw.value.value
                if literal_code is not None:
                    sites.append((enclosing, literal_code, node.lineno))
            self.generic_visit(node)

    _Visitor().visit(tree)
    return sites


def _parse_owns_docstring(doc: str) -> frozenset[str]:
    """Extract the vocabulary-code set from a stage docstring's ``Owns:``
    block: everything from ``Owns:`` up to the first blank line, with any
    parenthetical asides and RST ``:func:``/``:data:`` markup stripped, split
    on commas and periods."""
    match = re.search(r"Owns:\s*(.*?)\n\s*\n", doc, flags=re.DOTALL)
    assert match, f"docstring has no 'Owns:' block:\n{doc}"
    block = match.group(1)
    block = re.sub(r"\([^)]*\)", "", block)
    block = re.sub(r"``([^`]*)``", r"\1", block)
    codes = {token.strip().strip(".") for token in re.split(r"[,\n]", block)}
    return frozenset(code for code in codes if code and re.fullmatch(r"[A-Z_]+", code))


def test_stage_ownership_is_derived_from_owns_attribute() -> None:
    """P1-V2.0 review finding P1-1: ``_STAGE_CODES`` used to be a
    hand-written table independent of anything else in the module, so a
    code could be silently moved from one stage's entry to another's with
    every existing test still green (disjointness and total coverage are
    both invariant under a same-size permutation). ``_STAGE_CODES`` is now
    POPULATED by the ``@_owns(...)`` decorator on each stage function, from
    the exact same literal call that sets the function's own ``owns``
    attribute -- there is no second table left to drift out of sync. This
    test pins that mechanism directly: each stage's ``_STAGE_CODES`` entry
    must literally be the object referenced by ``fn.owns``, not merely an
    equal-by-value set assembled independently."""
    for stage_name in _STAGE_FUNCTION_NAMES:
        stage = getattr(v, stage_name)
        assert hasattr(stage, "owns"), f"{stage_name} has no .owns attribute"
        assert v._STAGE_CODES[stage_name] is stage.owns


def test_stage_docstrings_match_owns_attribute() -> None:
    """The prose ``Owns:`` block in each stage's docstring must name exactly
    the codes in its ``.owns`` attribute -- the mechanism (P1-1's fix) and
    the human-readable design intent (what P3-10 found had already drifted:
    S1's docstring omitted the catch-all its table entry carried) are two
    independent expressions of the same fact, and this test is what keeps
    them from drifting apart again."""
    for stage_name in _STAGE_FUNCTION_NAMES:
        stage = getattr(v, stage_name)
        doc = stage.__doc__ or ""
        documented = _parse_owns_docstring(doc)
        assert documented == stage.owns, (
            f"{stage_name}: docstring Owns: {sorted(documented)} != .owns {sorted(stage.owns)}"
        )


def test_stage_only_emits_codes_it_owns() -> None:
    """Every literal vocabulary-code emission site (``_fail``,
    ``AgentQualityVerificationError``, or a literal-forwarding
    ``_unique_by`` call -- see :func:`_emission_sites`) found lexically
    inside a ``_stage_sN`` function body must be a member of that stage's
    ``.owns`` set, with the sole exception of the universal placeholder
    catch-all (:data:`_UNIVERSAL_PLACEHOLDER_CODE`), which every stage's
    unconditional-refusal body emits today by design and which is owned
    only by S1 for partition-accounting purposes. This is the direct,
    call-site-level counterpart to the ownership-permutation mutation P1-1
    describes: even with ``_STAGE_CODES`` now derived from ``.owns``, a
    stage's guard body could still raise a code some OTHER stage owns; this
    test is what would catch that once real per-code guards land in
    packets .2-.5."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    sites = _emission_sites(tree)
    owns_by_stage = {name: getattr(v, name).owns for name in _STAGE_FUNCTION_NAMES}
    offenders = [
        (fn, code, line)
        for fn, code, line in sites
        if fn in owns_by_stage
        and code != _UNIVERSAL_PLACEHOLDER_CODE
        and code not in owns_by_stage[fn]
    ]
    assert offenders == [], offenders


# The module's public, module-owned callable surface as of packet .6, the
# packet that ships the real ``verify_agent_quality_certificate`` entry
# point -- exactly the three dataclass/exception types that predate P1-V2.0,
# plus the one new public function. Frozen here so any future packet that
# adds another public name has a single, explicit constant to update, rather
# than a test whose expectation is buried in assertion logic.
_AGENT_QUALITY_PUBLIC_SURFACE = frozenset(
    {
        "AgentQualityVerificationContext",
        "AgentQualityVerificationError",
        "AgentQualityVerificationResult",
        "verify_agent_quality_certificate",
    }
)


def test_public_entry_point_is_exactly_verify_agent_quality_certificate() -> None:
    """Sol B1: no public success path existed until the check sequence was
    complete (packets .0-.5); this packet is the one that ships it. A
    half-checking verifier that reports success is worse than one that does
    not exist, so this test -- the converted form of
    ``test_no_public_entry_point_exists_yet`` -- now pins the module's
    entire module-owned callable surface to EXACTLY the frozen set above,
    the one new name included, so any OTHER newly added public callable
    still breaks it, named however.

    P1-V2.0 review finding P1-3: the predecessor of this test only asserted
    the absence of one string, so a public entry point under any other name
    (``verify_agent_quality_bundle``, ``verify``, ``check``) would have
    shipped green. The ``__module__`` filter excludes the re-exported
    stdlib/typing names (``Any``, ``Callable``, ``dataclass``, ...) that are
    imported into this module's namespace but not defined by it."""
    module_owned_callables = {
        name
        for name in vars(v)
        if not name.startswith("_")
        and callable(getattr(v, name))
        and getattr(getattr(v, name), "__module__", None) == v.__name__
    }
    assert module_owned_callables == _AGENT_QUALITY_PUBLIC_SURFACE, (
        f"module-owned public callable surface drifted: {sorted(module_owned_callables)}"
    )
    assert hasattr(v, "verify_agent_quality_certificate")
    module = _importlib.import_module("traigent_schema.certification")
    assert "verify_agent_quality_certificate" in module.__all__
    assert "AgentQualityVerificationContext" in module.__all__
    assert "AgentQualityVerificationError" in module.__all__
    assert "AgentQualityVerificationResult" in module.__all__


def test_run_agent_quality_checks_returns_the_golden_verified_result() -> None:
    """P1-V2.4 commit 2 retarget (sanctioned by the packet brief): every
    stage is now real, so the golden bundle -- schema-valid,
    digest-consistent, genuinely signed, and internally consistent across
    all eight stages -- makes the private runner genuinely RETURN a
    :class:`v.AgentQualityVerificationResult` instead of raising. This is
    the converted form of the retired
    ``test_run_agent_quality_checks_rejects_every_bundle`` (P1-V2.0-.4:
    "S5-S7 are still unconditional refusals... rejects a bundle that
    reaches that far with the catch-all code"), which asserted the OPPOSITE
    of what a fully-wired verifier must do on a genuinely valid bundle --
    retained in spirit only by
    :func:`test_run_agent_quality_checks_propagates_process_record_error_unchanged`
    below, which still proves the runner wraps the stage sequence via a
    DIFFERENT (still-genuine) failure path."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()
    result = v._run_agent_quality_checks(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert result.code == "AGENT_QUALITY_VERIFIED"
    assert result.evidence_basis == "issuer_verified"
    assert result.claim_id == "AQ1"
    assert result.primary_objective_id == "obj.accuracy.exact_match.v1"
    assert result.nominal_coverage_ppm == 950000
    assert result.holdout_item_count == 200
    assert result.interval_verification_level == "construction_recomputed_v1"
    assert result.split_verification_level == "issuer_attested_v1"
    assert result.dataset_condition_code == "dataset_certificate_not_verified"
    assert result.evaluator_condition_code == "evaluator_certificate_not_verified"


def test_verify_agent_quality_certificate_golden_path() -> None:
    """The public entry point, on the golden bundle, returns exactly what
    the private runner returns -- the wrapper adds no transformation on the
    success path."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()
    direct = v._run_agent_quality_checks(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    public = v.verify_agent_quality_certificate(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert public == direct
    assert public.code == "AGENT_QUALITY_VERIFIED"


def test_verify_agent_quality_certificate_abstained_golden_path() -> None:
    context = build_agent_quality_context(accept_abstained_bundle=True)
    bundle = build_abstained_agent_quality_bundle()
    result = v.verify_agent_quality_certificate(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert result.code == "AGENT_QUALITY_CLAIM_ABSTAINED"
    assert result.evidence_basis == "abstained"


def test_verify_agent_quality_certificate_propagates_known_errors() -> None:
    """A genuine, closed-vocabulary failure (schema-invalid bundle) reaches
    the caller unchanged through the public wrapper, not relabeled as the
    catch-all."""
    context = build_agent_quality_context()
    bundle = {"schema_version": "wrong"}
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "BUNDLE_SHAPE"


def test_verify_agent_quality_certificate_split_opening_still_refused() -> None:
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
            split_opening={"anything": "at all"},
        )
    assert caught.value.code == "CONTEXT"
    assert caught.value.field == "split_opening_witness"


def test_verify_agent_quality_certificate_catches_stray_exceptions() -> None:
    """Content-free catch-all: any non-AgentQualityVerificationError,
    non-ProcessRecordVerificationError exception escaping the pipeline
    becomes AGENT_QUALITY_VERIFICATION_FAILED at field ``bundle``, with the
    original exception's identity scrubbed from ``__context__``."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("CANARY_STRAY_EXCEPTION_TEXT")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(v, "_stage_s1_structural", _boom)
        with pytest.raises(v.AgentQualityVerificationError) as caught:
            v.verify_agent_quality_certificate(
                bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
            )
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"
    assert caught.value.field == "bundle"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_verify_agent_quality_certificate_own_catch_all_is_exercised() -> None:
    """P1-V2.6 final-review closure P3-1: the test above patches
    ``_stage_s1_structural``, so ``_run_agent_quality_checks``'s OWN
    try/except already converts the stray exception into a well-formed
    :class:`v.AgentQualityVerificationError` -- the PUBLIC wrapper's own
    ``except Exception`` branch (:func:`v.verify_agent_quality_certificate`,
    which constructs the error directly rather than through :func:`_fail`)
    never actually runs in that test. This test patches
    ``_run_agent_quality_checks`` itself, so a stray exception escapes it
    unconverted and only the wrapper's own catch-all is left to handle it.
    The reviewer's probe: narrowing the wrapper's ``except Exception`` to
    e.g. ``except ZeroDivisionError`` makes this test fail (the stray
    ``RuntimeError`` propagates unconverted instead)."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("CANARY_STRAY_EXCEPTION_TEXT_WRAPPER")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(v, "_run_agent_quality_checks", _boom)
        with pytest.raises(v.AgentQualityVerificationError) as caught:
            v.verify_agent_quality_certificate(
                bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
            )
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"
    assert caught.value.field == "bundle"
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None


def test_verify_agent_quality_certificate_propagates_process_record_error_unchanged() -> None:
    """A failure verifying ``process_record_bundle`` itself reaches the
    caller as the process record's OWN error type/code, never relabeled
    into AgentQualityVerificationError -- through the PUBLIC wrapper, not
    just the private runner."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()
    broken_process_record = _gv_copy.deepcopy(_GV_PROCESS_RECORD_BUNDLE)
    broken_process_record["schema_version"] = "wrong"
    with pytest.raises(v.ProcessRecordVerificationError):
        v.verify_agent_quality_certificate(
            bundle, context=context, process_record_bundle=broken_process_record
        )


def test_public_function_sentinel_never_leaks() -> None:
    """Privacy canary at the public surface (mirrors
    evaluator_quality_verifier's test of the same name): a sentinel planted
    in the caller-controlled bundle must never appear in the raised error's
    message, args, code/field, or exception chain."""
    sentinel = "CANARY_PUBLIC_SURFACE_SENTINEL"
    bundle = build_agent_quality_bundle()
    bundle["assertion"]["rendered_text"] = sentinel
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    exc = caught.value
    rendered = "\n".join(
        (str(exc), repr(exc), repr(exc.args), repr(exc.__cause__), repr(exc.__context__))
    )
    assert sentinel not in rendered
    assert sentinel not in "".join(traceback.format_exception(exc))


# ==========================================================================
# P1-V2.6 commit 2 (G11) -- privacy canaries (design tests 74-79) and the
# non-vacuity meta-test that proves the canaries themselves would catch a
# genuinely leaking implementation, not merely pass vacuously on a
# content-free one.
# ==========================================================================


def _assert_no_leak(exc: BaseException, sentinel: str) -> None:
    """Shared canary body: ``sentinel`` must appear nowhere an exception
    could carry caller content -- message, repr, args, cause, context, or a
    fully formatted traceback."""
    rendered = "\n".join(
        (str(exc), repr(exc), repr(exc.args), repr(exc.__cause__), repr(exc.__context__))
    )
    assert sentinel not in rendered, f"sentinel leaked into exception rendering: {rendered!r}"
    formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert sentinel not in formatted, f"sentinel leaked into formatted traceback: {formatted!r}"


def test_privacy_canary_is_not_vacuous() -> None:
    """P1-V2.6 commit 2 (G11): the non-vacuity meta-test. Hand
    :func:`_assert_no_leak` a deliberately LEAKING stand-in -- a fake error
    whose message embeds the sentinel -- and prove the canary's own
    assertion FAILS on it. Without this, a canary that always passes
    (e.g. one that got its sentinel variable wrong) would be silently
    worthless."""
    sentinel = "CANARY_NON_VACUITY_SENTINEL"
    try:
        raise ValueError(f"leaking bundle content: {sentinel}")
    except ValueError as leaking_error:
        with pytest.raises(AssertionError):
            _assert_no_leak(leaking_error, sentinel)


def _gv_bundle_with_measurement_contract_ref_sentinel(sentinel_ref: str) -> dict:
    """A fully re-signed, schema-valid bundle carrying ``sentinel_ref`` as
    EVERY claim's and the manifest's own ``measurement_contract_ref`` (an
    OpaqueRef-shaped field -- ``measured_claims`` has no other free-text
    field that a schema-valid claim can carry; every other field is
    enum/const/integer). ``context.expected_measurement_contract_ref`` must
    be set to the SAME value by the caller for S2 to accept it -- this
    helper only builds the bundle side."""
    bundle = build_agent_quality_bundle()
    for claim in bundle["measured_claims"]:
        claim["measurement_contract_ref"] = sentinel_ref
    return _gv_reclose_after_manifest_field_mutation(
        bundle, lambda manifest: manifest.__setitem__("measurement_contract_ref", sentinel_ref)
    )


def test_privacy_canary_measured_claim_sentinel_never_leaks_at_s5() -> None:
    """Design test (P1-V2.6 commit 2, 74-79 series), P1-V2.6 final-review
    closure P2-3(a): a sentinel planted in a measured claim's own content,
    surviving S1-S4 in a genuinely re-signed, schema-valid bundle (the
    prior version of this test set ``objective_id`` to the raw sentinel,
    which is schema-invalid -- an enum member -- so the mutation never got
    past S1's SCHEMA check; the reviewer's probe found this). Reaches S5's
    own SAMPLE_SIZE_MISMATCH recomputation, through the PRIVATE runner
    directly (not just the public wrapper's own boundary, already covered
    by :func:`test_public_function_sentinel_never_leaks`), and the sentinel
    still never reaches the raised error."""
    sentinel = "CANARY_MEASURED_CLAIM_SENTINEL"
    sentinel_ref = f"sentinel:{sentinel}"
    closed = _gv_bundle_with_measurement_contract_ref_sentinel(sentinel_ref)
    closed["measured_claims"][0]["sample_size"] += 1
    context = build_agent_quality_context(expected_measurement_contract_ref=sentinel_ref)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SAMPLE_SIZE_MISMATCH"
    _assert_no_leak(caught.value, sentinel)


def test_privacy_canary_measured_claim_sentinel_never_leaks_at_s8() -> None:
    """P1-V2.6 final-review closure P2-3(a), second half: the SAME
    sentinel-carrying, otherwise fully valid and consistently re-signed
    bundle as the S5 canary above, but left content-correct all the way
    through S1-S7 -- only the top-level issuer signature is byte-flipped
    (one base64 character, not the padding, so the value stays schema-valid
    base64) after closing, so the failure is genuinely S8's
    ISSUER_SIGNATURE_INVALID, the LAST stage to run. Proves the sentinel
    survives the entire eight-stage pipeline, not just as far as S5."""
    sentinel = "CANARY_MEASURED_CLAIM_SENTINEL_S8"
    sentinel_ref = f"sentinel:{sentinel}"
    closed = _gv_copy.deepcopy(_gv_bundle_with_measurement_contract_ref_sentinel(sentinel_ref))
    signature = closed["signature"]["signature"]
    flipped_char = "A" if signature[10] != "A" else "B"
    closed["signature"]["signature"] = signature[:10] + flipped_char + signature[11:]
    context = build_agent_quality_context(expected_measurement_contract_ref=sentinel_ref)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "ISSUER_SIGNATURE_INVALID"
    _assert_no_leak(caught.value, sentinel)


def test_privacy_canary_project_ref_sentinel_never_reaches_signed_bundle() -> None:
    """Design test: a sentinel in ``context.expected_project_ref`` --
    caller-supplied, never copied into a bundle or a result (see
    :class:`v.AgentQualityVerificationContext`'s own docstring) -- causes
    SCOPE_MISMATCH (the golden bundle's own scope-binding digest was built
    from the REAL project ref, not this one) without ever reaching the
    raised error, and the golden bundle's own content is untouched.

    P1-V2.6 final-review closure P3-6: the OLD
    ``sentinel not in json.dumps(bundle)`` assert was vacuous -- ``bundle``
    is built by :func:`build_agent_quality_bundle`, which never reads
    ``context`` at all, so the sentinel could not have reached it
    regardless of build order or of whether this module leaks context
    content anywhere. The non-vacuous replacement: snapshot the bundle
    BEFORE verification and assert it is byte-for-byte unchanged AFTER --
    proof that the signed bundle handed to this failing call was never
    mutated in place, which is what would make a caller-context leak into
    it possible in the first place. A verifier that copied
    ``context.expected_project_ref`` onto the bundle before failing would
    break this assertion; the JSON-membership check alone would not have
    caught it, since the sentinel would still legitimately be a string
    inside ``bundle`` at that point -- this snapshot-equality check is
    strictly stronger."""
    sentinel = "CANARY_PROJECT_REF_SENTINEL"
    bundle = build_agent_quality_bundle()
    bundle_snapshot = _gv_copy.deepcopy(bundle)
    context = build_agent_quality_context(expected_project_ref=sentinel)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCOPE_MISMATCH"
    _assert_no_leak(caught.value, sentinel)
    assert sentinel not in json.dumps(bundle)
    assert bundle == bundle_snapshot


def test_no_content_carrying_raises_outside_sanctioned_sites() -> None:
    """P1-V2.6 final-review closure P2-3(b): an AST ban complementing the
    S5/S8 re-signed sentinel canaries above. Two rules, checked over the
    WHOLE module:

    1. No ``raise ... from <non-None>`` anywhere -- only ``raise ... from
       None`` is allowed. A real chained cause can carry caller content
       through ``__cause__``/``__context__``; ``from None`` is the one form
       that provably cannot.
    2. No direct ``AgentQualityVerificationError(...)`` construction
       outside three sanctioned sites: ``_fail`` (the sole constructor
       every stage actually calls), ``_load_agent_quality_document`` (the
       package-data loader's own fixed-vocabulary failure), and
       ``verify_agent_quality_certificate`` (the public wrapper's own
       catch-all, which immediately clears ``__context__`` -- see its
       inline comment). ``_run_agent_quality_checks``'s own catch-all goes
       through ``_fail`` and is not itself a construction site.

    Reproduces the reviewer's L2 mutation (S5's SAMPLE_SIZE_MISMATCH
    changed to raise ``from ValueError(repr(claim))``) as a collection-time
    failure instead of the runtime leak the reviewer found -- 287 tests
    passed with that mutation live and nothing caught it."""
    source = Path(v.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(v.__file__))

    sanctioned_construction_sites = frozenset(
        {"_fail", "_load_agent_quality_document", "verify_agent_quality_certificate"}
    )
    raise_from_violations: list[int] = []
    construction_violations: list[tuple[str, int]] = []

    class _Visitor(ast.NodeVisitor):
        function_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_stack.append(node.name)
            self.generic_visit(node)
            self.function_stack.pop()

        def visit_Raise(self, node: ast.Raise) -> None:
            cause = node.cause
            cause_is_none = isinstance(cause, ast.Constant) and cause.value is None
            if cause is not None and not cause_is_none:
                raise_from_violations.append(node.lineno)
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name) and node.func.id == "AgentQualityVerificationError":
                enclosing = self.function_stack[-1] if self.function_stack else "<module>"
                if enclosing not in sanctioned_construction_sites:
                    construction_violations.append((enclosing, node.lineno))
            self.generic_visit(node)

    _Visitor().visit(tree)
    assert raise_from_violations == [], (
        f"raise ... from <non-None> at line(s) {raise_from_violations} -- only "
        "'raise ... from None' is allowed"
    )
    assert construction_violations == [], (
        "AgentQualityVerificationError(...) constructed outside the sanctioned sites "
        f"{sorted(sanctioned_construction_sites)}: {construction_violations}"
    )


def test_privacy_canary_no_signed_bundle_field_is_caller_supplied() -> None:
    """Design test: no field of :class:`v.AgentQualityVerificationResult`
    is ever constructed from a ``context.`` attribute -- every result field
    comes from the verified bundle/manifest/row content alone, so a
    caller's context pins can never spoof what the result reports. Checked
    by AST: every keyword argument's value at each
    ``AgentQualityVerificationResult(...)`` call site inside
    ``_run_agent_quality_checks`` must not be, or contain, an attribute
    access on a name called ``context``."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    runner = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run_agent_quality_checks"
    )
    result_calls = [
        node
        for node in ast.walk(runner)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "AgentQualityVerificationResult"
    ]
    assert len(result_calls) >= 2, "expected a VERIFIED and an ABSTAINED construction site"
    for call in result_calls:
        for keyword in call.keywords:
            for attr_node in ast.walk(keyword.value):
                if (
                    isinstance(attr_node, ast.Attribute)
                    and isinstance(attr_node.value, ast.Name)
                    and attr_node.value.id == "context"
                ):
                    raise AssertionError(
                        f"AgentQualityVerificationResult field {keyword.arg!r} reads "
                        f"context.{attr_node.attr} directly -- result fields must come "
                        "from the verified bundle, never the caller's context"
                    )


def _literal_field_emission_sites(tree: ast.AST) -> list[tuple[str, str, int]]:
    """Return ``(enclosing_function_name, field, lineno)`` for every
    ``_fail(CODE, FIELD)`` / ``AgentQualityVerificationError(CODE, FIELD)``
    call site whose FIELD argument is itself a string literal, and every
    ``_unique_by(rows, key_fn, CODE, FIELD)`` call site whose 4th
    positional (or ``field=``) argument is a string literal. Mirrors
    :func:`_emission_sites`, scanning the FIELD position instead of the
    CODE position."""
    sites: list[tuple[str, str, int]] = []

    class _Visitor(ast.NodeVisitor):
        function_stack: list[str] = []

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_stack.append(node.name)
            self.generic_visit(node)
            self.function_stack.pop()

        def visit_Call(self, node: ast.Call) -> None:
            func = node.func
            name = func.id if isinstance(func, ast.Name) else None
            enclosing = self.function_stack[-1] if self.function_stack else "<module>"
            if name in ("_fail", "AgentQualityVerificationError") and enclosing != "_fail":
                if len(node.args) >= 2:
                    second = node.args[1]
                    if isinstance(second, ast.Constant) and isinstance(second.value, str):
                        sites.append((enclosing, second.value, node.lineno))
            elif name == "_unique_by" and enclosing != "_unique_by":
                literal_field: str | None = None
                if len(node.args) >= 4:
                    candidate = node.args[3]
                    if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                        literal_field = candidate.value
                for kw in node.keywords:
                    if kw.arg == "field" and isinstance(kw.value, ast.Constant):
                        if isinstance(kw.value.value, str):
                            literal_field = kw.value.value
                if literal_field is not None:
                    sites.append((enclosing, literal_field, node.lineno))
            self.generic_visit(node)

    _Visitor().visit(tree)
    return sites


def test_every_literal_fail_site_field_is_a_registered_field_location() -> None:
    """P1-V2.6 commit 2: an AST fuzz over every ``_fail(...)``/
    ``_unique_by(...)`` call site whose field argument is a string literal
    -- ``exc.field`` must always be a member of
    :data:`v.AGENT_QUALITY_FIELD_LOCATIONS`, the closed vocabulary a caller
    can pattern-match against. A typo'd or stray field string would
    otherwise ship silently -- this makes it a collection-time failure
    instead."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    sites = _literal_field_emission_sites(tree)
    assert len(sites) >= 60, f"expected the bulk of ~72 codes' call sites, got {len(sites)}"
    offenders = [
        (fn, field, line)
        for (fn, field, line) in sites
        if field not in v.AGENT_QUALITY_FIELD_LOCATIONS
    ]
    assert offenders == [], (
        f"call sites with a field not in AGENT_QUALITY_FIELD_LOCATIONS: {offenders}"
    )


def test_non_literal_fail_site_fields_are_also_registered() -> None:
    """The two remaining ``_fail`` call sites whose field argument is a
    variable, not a literal (``_stage_s7_composition_abstention``'s
    ``pillar_support`` loop, bound from the per-position tuple), checked
    behaviorally instead of by AST: both loop values are registered field
    locations, and BOTH are already independently reached by
    ``test_s7_pillar_support_shape_wrong_dataset_commitment_ref_full_runner``
    / ``..._wrong_evaluator_commitment_ref_full_runner`` above, which assert
    the exact field string on the raised error."""
    assert "pillar_support.dataset" in v.AGENT_QUALITY_FIELD_LOCATIONS
    assert "pillar_support.evaluator" in v.AGENT_QUALITY_FIELD_LOCATIONS


def test_run_agent_quality_checks_golden_path_is_deterministic() -> None:
    """Running the golden end-to-end path twice produces two EQUAL results
    -- the runner has no hidden state or nondeterminism."""
    context = build_agent_quality_context()
    bundle = build_agent_quality_bundle()
    first = v._run_agent_quality_checks(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    second = v._run_agent_quality_checks(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert first == second


def test_run_agent_quality_checks_propagates_process_record_error_unchanged() -> None:
    """P1-V2.3 (design Sec 3): S2 verifies ``process_record_bundle`` FIRST,
    in full, through the shipped public entry point
    (``verify_process_record_certificate``). A malformed process record
    must reach the caller as the process record's OWN
    ``ProcessRecordVerificationError`` -- never relabeled into this
    module's content-free ``AGENT_QUALITY_VERIFICATION_FAILED`` catch-all,
    which would hide the real reason from the caller."""
    context = build_agent_quality_context()
    bundle = _schema_fixtures._bundle()
    with pytest.raises(v.ProcessRecordVerificationError) as caught:
        v._run_agent_quality_checks(bundle, context=context, process_record_bundle={})
    assert caught.value.code != "AGENT_QUALITY_VERIFICATION_FAILED"


# P1-V2.5 commit 2: every stage is now a real check -- NONE are
# unconditional refusals any longer, so none of them can share the uniform
# "any schema-valid bundle is refused with the catch-all" assertion below.
# S2, S4 and S8 also don't share the uniform ``(bundle, context)``
# two-argument shape every other stage has (each additionally needs
# ``process_record_bundle``). Every stage now gets its own dedicated
# fail-closed coverage (test_stage_s{1..8}_..._is_a_real_fail_closed_function)
# instead.
_STILL_PLACEHOLDER_STAGE_FUNCTION_NAMES = tuple(
    name
    for name in _STAGE_FUNCTION_NAMES
    if name
    not in (
        "_stage_s1_structural",
        "_stage_s2_context_binding",
        "_stage_s3_registry_identity",
        "_stage_s4_declared_plan_signatures",
        "_stage_s5_objective_measurement",
        "_stage_s6_splits_held_out",
        "_stage_s7_composition_abstention",
        "_stage_s8_manifest_digests_signature",
    )
)


def test_no_placeholder_stage_remains() -> None:
    """P1-V2.5 review P3-5: the old version of this test parametrized over
    :data:`_STILL_PLACEHOLDER_STAGE_FUNCTION_NAMES` -- always empty since
    P1-V2.5 commit 2 made every stage real -- so it always collected zero
    cases and silently reported ``1 skipped`` forever, a permanent green
    that asserted nothing. This is the positive statement it should have
    been: all eight named stages are real, so the placeholder tuple is
    empty."""
    assert _STILL_PLACEHOLDER_STAGE_FUNCTION_NAMES == ()


def test_stage_s1_structural_is_a_real_fail_closed_function() -> None:
    """S1's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: unlike S2-S7, S1
    now PASSES a schema-valid bundle (the golden bundle passes every real
    stage, per each stage's own ``test_s{N}_passes_the_golden_bundle`` case
    elsewhere in this module), so its "still fail-closed when called
    directly" proof uses a structurally-invalid bundle instead, and checks
    S1's own real code rather than the catch-all."""
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural({"schema_version": "wrong"}, context)
    assert caught.value.code == "BUNDLE_SHAPE"
    assert caught.value.field == "bundle"


def test_stage_s2_context_binding_is_a_real_fail_closed_function() -> None:
    """S2's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: S2 now takes a
    third ``process_record_bundle`` argument and PASSES the golden bundle
    (the golden bundle passes every real stage, per each stage's own
    ``test_s{N}_passes_the_golden_bundle`` case elsewhere in this module),
    so its "still fail-closed when called directly" proof uses a bundle
    whose commitment refs disagree with the context/process-record pins."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context(expected_agent_commitment_ref="sha256:" + "9" * 64)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "COMMITMENT_REF_MISMATCH"
    assert caught.value.field == "commitment_refs"


def test_stage_s3_registry_identity_is_a_real_fail_closed_function() -> None:
    """S3's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: S3 PASSES the
    golden bundle, so its "still fail-closed when called directly" proof
    mutates the manifest's aggregation-policy identity instead."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["aggregation_policy"] = dict(
        bundle["unsigned_manifest"]["aggregation_policy"], policy_id="wrong"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "AGGREGATION_POLICY_MISMATCH"
    assert caught.value.field == "aggregation_policy"


def test_stage_s4_declared_plan_signatures_is_a_real_fail_closed_function() -> None:
    """S4's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: S4 now takes a
    third ``process_record_bundle`` argument and PASSES the golden bundle,
    so its "still fail-closed when called directly" proof mutates the
    declared plan's own digest field instead."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["primary_objective_id"] = (
        "obj.accuracy.evaluator_score_mean.v1"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_DIGEST_MISMATCH"
    assert caught.value.field == "declared_plan"


def test_stage_s6_splits_held_out_is_a_real_fail_closed_function() -> None:
    """S6's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: S6 PASSES the
    golden bundle, so its "still fail-closed when called directly" proof
    mutates the two split records' commitment digests to collide instead."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["split_commitment_digest"] = bundle["evaluation_splits"][0][
        "split_commitment_digest"
    ]
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "SPLIT_COMMITMENT_COLLISION"
    assert caught.value.field == "evaluation_splits"


def test_stage_s7_composition_abstention_is_a_real_fail_closed_function() -> None:
    """S7's real-check counterpart to
    :func:`test_no_placeholder_stage_remains`: S7 PASSES the
    golden bundle, so its "still fail-closed when called directly" proof
    mutates the assertion's own digest instead."""
    bundle = build_agent_quality_bundle()
    bundle["assertion"]["assertion_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s7_composition_abstention(bundle, context)
    assert caught.value.code == "ASSERTION_DIGEST_MISMATCH"
    assert caught.value.field == "assertion"


def test_rendered_text_carries_no_preregistration_timing_claim_wording() -> None:
    """Extends design test 35 (the literal-stem tripwire,
    :func:`test_literal_zero_preregistration_stem_hits`, which already
    scans the WHOLE schema/module/catalog text) with a targeted assertion
    on the ONE string S7 actually compares claims against: the shipped
    ``AgentQualityAssertionV1.rendered_text`` const must not merely be
    absent from a broad scan -- it must specifically carry no
    "pre-registered" (or any stem variant) timing-claim wording, since S7
    now mechanically pins every certified claim's rendered_text to exactly
    this string."""
    rendered_text = SCHEMA["definitions"]["AgentQualityAssertionV1"]["properties"]["rendered_text"][
        "const"
    ]
    assert re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", rendered_text, re.I) is None


def _all_string_leaves(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for v in value.values() for leaf in _all_string_leaves(v)]
    if isinstance(value, (list, tuple)):
        return [leaf for v in value for leaf in _all_string_leaves(v)]
    return []


def test_golden_fixture_text_fields_carry_no_preregistration_stem() -> None:
    """P1-V2.6 commit 2: the literal-stem tripwire extended to every new
    ARTIFACT this thread added -- not just the schema/module/catalog text
    (:func:`test_literal_zero_preregistration_stem_hits`) but the golden
    and abstained fixtures' own string content, recursively, since a hand-
    typed fixture string is exactly the kind of place stray "pre-
    registered" wording could reappear without any of the other three
    scans ever seeing it."""
    golden = build_agent_quality_bundle()
    abstained = build_abstained_agent_quality_bundle()
    for label, bundle in (("golden", golden), ("abstained", abstained)):
        for leaf in _all_string_leaves(bundle):
            hit = re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", leaf, re.I)
            assert hit is None, f"preregistration stem hit in {label} fixture: {leaf!r}"


# ==========================================================================
# P1-V2.2 -- S1 real checks, fixture family A: minimal/malformed/UNSIGNED
# dicts. NONE of these are signed -- a test below proves S1 rejects every
# one of them before any bundle could reach S8's signature check.
# ==========================================================================


def test_s1_rejects_non_mapping_bundle() -> None:
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(["not", "a", "mapping"], context)  # type: ignore[arg-type]
    assert caught.value.code == "BUNDLE_SHAPE"
    assert caught.value.field == "bundle"


def test_s1_rejects_wrong_schema_version() -> None:
    context = _context()
    bundle = dict(_schema_fixtures._bundle())
    bundle["schema_version"] = "traigent.agent_quality.certificate_bundle.v0"
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "BUNDLE_SHAPE"
    assert caught.value.field == "bundle"


def test_s1_rejects_bool_where_integer_required() -> None:
    """A ``bool`` anywhere in the tree is STRICT_INTEGER -- this module,
    unlike ``evaluator_quality_verifier``'s walk, does not let booleans
    through (see :func:`v._walk_strict_values`)."""
    context = _context()
    bundle = _gv_copy.deepcopy(_schema_fixtures._bundle())
    bundle["split_derivation"]["evaluated_universe_item_count"] = True
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "STRICT_INTEGER"
    assert caught.value.field == "bundle"


def test_s1_rejects_integer_outside_safe_range() -> None:
    context = _context()
    bundle = _gv_copy.deepcopy(_schema_fixtures._bundle())
    bundle["split_derivation"]["evaluated_universe_item_count"] = 2**53
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "UNSAFE_INTEGER"
    assert caught.value.field == "bundle"


def test_s1_rejects_schema_invalid_bundle() -> None:
    context = _context()
    bundle = dict(_schema_fixtures._bundle())
    del bundle["assertion"]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"


def test_s1_rejects_unresolvable_schema_dependency(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unresolvable ``$ref`` (simulated: the cached validator's
    ``iter_errors`` raises ``referencing.exceptions.Unresolvable``) is
    SCHEMA_DEPENDENCY, not SCHEMA -- a validator-construction/resolution
    failure is a package defect, not a finding about the bundle's content."""
    from referencing.exceptions import Unresolvable

    class _BrokenValidator:
        def iter_errors(self, _bundle: object) -> None:
            raise Unresolvable(ref="#/definitions/DoesNotExist")

    v._agent_quality_validator.cache_clear()
    monkeypatch.setattr(v, "_agent_quality_validator", lambda: _BrokenValidator())
    context = _context()
    bundle = _schema_fixtures._bundle()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "SCHEMA_DEPENDENCY"
    assert caught.value.field == "bundle"


def test_s1_rejects_canonicalization_failure_after_schema_valid() -> None:
    """A value the schema itself cannot see through jsonschema's type
    checking (a ``str`` SUBCLASS, deliberately let through
    :func:`v._walk_strict_values` -- see that function's docstring) but that
    ``fp2.canonicalize`` genuinely cannot represent is CANONICALIZATION,
    the last of S1's checks."""

    class _WeirdStr(str):
        pass

    context = _context()
    bundle = _gv_copy.deepcopy(_schema_fixtures._bundle())
    bundle["assertion"]["claim_id"] = _WeirdStr(bundle["assertion"]["claim_id"])
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural(bundle, context)
    assert caught.value.code == "CANONICALIZATION"
    assert caught.value.field == "bundle"


def test_s1_family_a_fixtures_never_reach_s8() -> None:
    """None of family A's fixtures are signed -- their ``signature.signature``
    is the schema-fixture placeholder, not a real ed25519 signature (see
    ``tests/test_agent_quality_v1_schema.py::_signature``). Proven directly
    through the FULL runner: every one of them fails at S1 (BUNDLE_SHAPE),
    which runs before S8, so no unsigned bundle can ever reach S8's
    signature check -- if S1 did not stop it, S8 would be the first stage
    capable of even attempting to verify a signature, and none of these
    fixtures carries one that could pass."""
    context = _context()
    bad_bundle_a = ["not", "a", "mapping"]
    bad_bundle_b = dict(_schema_fixtures._bundle())
    bad_bundle_b["schema_version"] = "traigent.agent_quality.certificate_bundle.v0"
    for bad_bundle in (bad_bundle_a, bad_bundle_b):
        with pytest.raises(v.AgentQualityVerificationError) as caught:
            v._run_agent_quality_checks(
                bad_bundle,  # type: ignore[arg-type]
                context=context,
                process_record_bundle={},
            )
        assert caught.value.code == "BUNDLE_SHAPE"
        assert caught.value.field == "bundle"


def test_abstained_bundle_carries_claims_is_schema_preempted() -> None:
    """ABSTAINED_BUNDLE_CARRIES_CLAIMS is in
    AGENT_QUALITY_SCHEMA_PREEMPTED_CODES: AgentQualityCertificateBundleV1's
    own ``allOf`` if/then/else abstention coupling already rejects a
    non-issuer_verified support row paired with a nonempty measured_claims
    array, before S1's schema check (design row 5) ever hands this module a
    schema-valid bundle to check.

    P1-V2.0 review finding P2-4: ``assert errors`` alone is vacuous -- ANY
    malformation anywhere in the bundle satisfies it, so this did not prove
    the rejection came from the abstention coupling specifically. The
    additional assertions below pin the rejection to exactly one error,
    rooted at the coupling's own ``else`` branch, and the two controls prove
    the SAME bundle validates clean the moment either half of the coupling
    is satisfied (the array emptied, or the support row flipped to
    issuer_verified) -- so the rejection is attributable to the coupling
    alone, not to some other malformation."""
    bundle = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[_schema_fixtures._wilson_claim()],
        selection_estimates=[],
    )
    errors = _schema_fixtures._errors(bundle)
    assert len(errors) == 1, (
        "an abstained support row with a nonempty measured_claims array must "
        "be rejected by the schema itself (S1) with exactly one error -- "
        f"got {len(errors)}"
    )
    assert list(errors[0].absolute_schema_path)[-4:] == [
        "else",
        "properties",
        "measured_claims",
        "maxItems",
    ]
    control_emptied = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[],
        selection_estimates=[],
    )
    assert _schema_fixtures._errors(control_emptied) == [], (
        "emptying measured_claims on the same abstained support row must "
        "validate clean -- the rejection above must be attributable to the "
        "coupling alone"
    )
    control_issuer_verified = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_issuer_verified(),
        measured_claims=[_schema_fixtures._wilson_claim()],
        selection_estimates=[],
    )
    assert _schema_fixtures._errors(control_issuer_verified) == [], (
        "the same measured_claims array on an issuer_verified support row "
        "must validate clean -- confirms the coupling, not the claim array "
        "itself, is what rejects the abstained bundle above"
    )
    # P1-V2.5 review P2-3 (astra's phase-gate constraint): agreement between
    # the schema and the module's own bucket alone is not proof -- push the
    # SAME mutated bundle through the REAL path
    # (:func:`v._run_agent_quality_checks`) and confirm it stops at SCHEMA,
    # at S1, before S7 (the stage that owns ABSTAINED_BUNDLE_CARRIES_CLAIMS
    # by design) ever runs. Named against the shipped schema's own version
    # const, not a hard-coded literal.
    assert (
        bundle["schema_version"]
        == SCHEMA["definitions"]["AgentQualityCertificateBundleV1"]["properties"]["schema_version"][
            "const"
        ]
    )
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"


def test_selection_estimate_in_certified_set_is_schema_preempted() -> None:
    """SELECTION_ESTIMATE_IN_CERTIFIED_SET is in
    AGENT_QUALITY_SCHEMA_PREEMPTED_CODES for the same reason: the abstention
    coupling's ``else`` branch also caps
    non_certified_selection_estimates to maxItems 0 on a non-issuer_verified
    support row, so a schema-valid abstained bundle can never carry a
    selection estimate either -- rejected by S1's schema check before any
    per-claim guard would run.

    Real controls per P1-V2.0 review finding P2-4 -- see
    :func:`test_abstained_bundle_carries_claims_is_schema_preempted` for the
    rationale."""
    bundle = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[],
        selection_estimates=[_schema_fixtures._selection_estimate()],
    )
    errors = _schema_fixtures._errors(bundle)
    assert len(errors) == 1, (
        "an abstained support row with a nonempty "
        "non_certified_selection_estimates array must be rejected by the "
        f"schema itself (S1) with exactly one error -- got {len(errors)}"
    )
    assert list(errors[0].absolute_schema_path)[-4:] == [
        "else",
        "properties",
        "non_certified_selection_estimates",
        "maxItems",
    ]
    control_emptied = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_abstained(),
        measured_claims=[],
        selection_estimates=[],
    )
    assert _schema_fixtures._errors(control_emptied) == [], (
        "emptying non_certified_selection_estimates on the same abstained "
        "support row must validate clean -- the rejection above must be "
        "attributable to the coupling alone"
    )
    control_issuer_verified = _schema_fixtures._bundle(
        support_row=_schema_fixtures._support_row_issuer_verified(),
        measured_claims=[_schema_fixtures._wilson_claim()],
        selection_estimates=[_schema_fixtures._selection_estimate()],
    )
    assert _schema_fixtures._errors(control_issuer_verified) == [], (
        "the same selection-estimate array on an issuer_verified support "
        "row must validate clean -- confirms the coupling, not the array "
        "itself, is what rejects the abstained bundle above"
    )
    # P1-V2.5 review P2-3: same real-path proof as
    # test_abstained_bundle_carries_claims_is_schema_preempted -- the
    # mutated bundle must stop at SCHEMA through the actual runner, before
    # S7 (this code's owning stage by design) ever runs.
    assert (
        bundle["schema_version"]
        == SCHEMA["definitions"]["AgentQualityCertificateBundleV1"]["properties"]["schema_version"][
            "const"
        ]
    )
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"


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


def test_schema_preempted_dead_codes_are_exactly_three_and_registered() -> None:
    """These schema-preempted codes have no guard anywhere in the module
    (dead vocabulary) -- see
    :func:`test_schema_preempted_backstop_codes_have_a_live_guard_each` for
    the other half of :data:`v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES`.
    PILLAR_BINDING_MISMATCH (P1-V2.5 commit 2, design row 55) joins the
    original two: ``EmittablePillarStatusV1`` excludes ``assessed_supported``
    entirely, so no schema-valid ``pillar_support`` entry can ever carry
    the sibling-verification binding this code would check, and v1 defines
    no sibling-bundle input mechanism to check one against."""
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES == {
        "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
        "PILLAR_BINDING_MISMATCH",
    }
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES <= v.AGENT_QUALITY_ERROR_CODES


def test_pillar_binding_mismatch_is_schema_preempted() -> None:
    """Validator proof: a ``pillar_support`` entry claiming
    ``assessed_supported`` fails SCHEMA validation at
    ``pillar_support[0].status`` (or whichever index/path the mutated entry
    occupies); the same entry with ``condition_declared_unverified`` (the
    control) validates fine."""
    bundle = _schema_fixtures._bundle()
    bundle["unsigned_manifest"]["pillar_support"][0]["status"] = "assessed_supported"
    errors = _schema_fixtures._errors(bundle)
    assert len(errors) >= 1, "assessed_supported must be schema-invalid"
    assert any(
        "status" in list(e.absolute_path) and "pillar_support" in str(list(e.absolute_path))
        for e in errors
    ), [(list(e.absolute_path), e.message) for e in errors]

    control = _schema_fixtures._bundle()
    control["unsigned_manifest"]["pillar_support"][0]["status"] = "condition_declared_unverified"
    assert _schema_fixtures._errors(control) == []

    # P1-V2.5 review P2-3: real-path proof through the runner, not just
    # schema/registry agreement -- the mutated bundle stops at SCHEMA, at
    # S1, before S7 (this code's owning stage by design) ever runs.
    assert (
        bundle["schema_version"]
        == SCHEMA["definitions"]["AgentQualityCertificateBundleV1"]["properties"]["schema_version"][
            "const"
        ]
    )
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"


def test_schema_preempted_backstop_codes_have_a_live_guard_each() -> None:
    """P1-V2.4 review P2-2 (S5) and its .5/commit-1 extension (S6): unlike
    the two dead codes above, each of these codes DOES have a real
    ``_fail(...)`` call site in :func:`v._stage_s5_objective_measurement` or
    :func:`v._stage_s6_splits_held_out` -- kept as a defensive backstop --
    even though no schema-valid bundle can ever reach it (see
    :data:`v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES`'s docstring for
    the per-code reachability argument, and
    :func:`test_schema_preempted_backstop_codes_are_proven_unreachable_by_schema`
    below for the empirical proof of each)."""
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES == {
        "OBJECTIVE_NOT_REGISTERED",
        "OBJECTIVE_MINIMUM_SAMPLE_NOT_MET",
        "DISTRIBUTION_ASSUMPTION_NOT_REGISTERED",
        "INTERVAL_METHOD_NOT_EMITTABLE",
        "INTERVAL_OUT_OF_UNIT_BOUNDS",
        "VERIFICATION_LEVEL_MISMATCH",
        "QUANTILE_TABLE_LOOKUP_FAILED",
        "HOLDOUT_NOT_USED",
        "HOLDOUT_MISSING",
        "HOLDOUT_TOO_SMALL",
        "HOLDOUT_REUSED",
    }
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    emitted = frozenset(code for (_fn, code, _line) in _emission_sites(tree))
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES <= emitted, (
        "every backstop code must have a real emission site -- "
        f"missing: {v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES - emitted}"
    )
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES.isdisjoint(emitted), (
        "a dead code must have NO emission site -- "
        f"unexpectedly emitted: {v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES & emitted}"
    )
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES == (
        v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES
        | v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES
    )
    assert v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES <= v.AGENT_QUALITY_ERROR_CODES


def test_schema_preempted_backstop_codes_are_proven_unreachable_by_schema() -> None:
    """The per-code reachability proof for each of the eleven backstop codes
    (P1-V2.5 review P3-8: seven from S5, plus S6's own four -- HOLDOUT_NOT_USED,
    HOLDOUT_MISSING, HOLDOUT_TOO_SMALL, HOLDOUT_REUSED -- proven below):
    either a re-signed mutation that a schema-valid bundle cannot represent
    (SCHEMA rejects it at S1, before S5's guard would ever run), or --
    where the guard concerns PACKAGE DATA rather than any bundle field
    (DISTRIBUTION_ASSUMPTION_NOT_REGISTERED, QUANTILE_TABLE_LOOKUP_FAILED)
    -- a direct assertion that the shipped package data always satisfies
    the guard, so no bundle content could ever make it fail.

    P1-V2.5 review P2-3 (astra's phase-gate constraint): equality between
    the schema and the registry alone is not proof by itself -- every
    equality assertion below is bound to the SHIPPED schema/registry
    document version it depends on, and the four S6 codes additionally get
    a re-signed mutation pushed through the REAL path
    (:func:`v._run_agent_quality_checks`), stopping at SCHEMA before S6 (the
    owning stage) ever runs."""
    assert (
        SCHEMA["definitions"]["AgentQualityCertificateBundleV1"]["properties"]["schema_version"][
            "const"
        ]
        == "traigent.agent_quality.certificate_bundle.v1"
    )
    _gv_assert_registry_versions_pinned_to_document()
    # OBJECTIVE_NOT_REGISTERED: EmittableObjectiveIdV1 (what a schema-valid
    # claim's objective_id is restricted to) is a SUBSET of the shipped
    # objective registry's own ids.
    emittable_ids = set(SCHEMA["definitions"]["EmittableObjectiveIdV1"]["allOf"][1]["enum"])
    registered_ids = set(v._objective_registry_entries_by_id())
    assert emittable_ids <= registered_ids

    # OBJECTIVE_MINIMUM_SAMPLE_NOT_MET / INTERVAL_OUT_OF_UNIT_BOUNDS:
    # MeasuredObjectiveClaimV1's own per-objective_kind if/then branches
    # already enforce the SAME sample_size floor / value bounds as the
    # shipped registry entry for every emittable objective_kind.
    kind_branches = {
        branch["if"]["properties"]["objective_kind"]["const"]: branch["then"]
        for branch in SCHEMA["definitions"]["MeasuredObjectiveClaimV1"]["allOf"]
    }
    for objective_id, entry in v._objective_registry_entries_by_id().items():
        if objective_id not in emittable_ids:
            continue
        branch = kind_branches[entry["objective_kind"]]
        schema_sample_min = (
            branch.get("properties", {})
            .get("sample_size", {})
            .get(
                "minimum",
                SCHEMA["definitions"]["MeasuredObjectiveClaimV1"]["properties"]["sample_size"][
                    "minimum"
                ],
            )
        )
        assert schema_sample_min == entry["minimum_sample_size"]
        schema_max = (
            branch.get("properties", {})
            .get("interval_high", {})
            .get(
                "maximum",
                SCHEMA["definitions"]["MeasuredObjectiveClaimV1"]["properties"]["interval_high"][
                    "maximum"
                ],
            )
        )
        assert schema_max == entry["maximum"]

    # DISTRIBUTION_ASSUMPTION_NOT_REGISTERED: every nonnegative_mean entry in
    # the shipped registry carries a registered distribution_assumption.
    for entry in v._objective_registry_entries_by_id().values():
        if entry["objective_kind"] == "nonnegative_mean":
            assert entry.get("distribution_assumption") in v._distribution_assumption_values()

    # INTERVAL_METHOD_NOT_EMITTABLE: EmittableObjectiveKindV1 excludes
    # nonnegative_quantile entirely (the only kind whose admissible method
    # is not emittable), and IntervalParamsV1 has no oneOf branch at all for
    # bootstrap_percentile_v1.
    emittable_kind_excludes = SCHEMA["definitions"]["EmittableObjectiveKindV1"]["allOf"][1]["not"][
        "const"
    ]
    assert emittable_kind_excludes == "nonnegative_quantile"
    interval_params_branches = {
        ref["$ref"].rsplit("/", 1)[-1] for ref in SCHEMA["definitions"]["IntervalParamsV1"]["oneOf"]
    }
    assert "IntervalParamsBootstrapV1" not in interval_params_branches

    # VERIFICATION_LEVEL_MISMATCH: EmittableVerificationLevelV1 is
    # VerificationLevelV1 minus its own excluded enum -- already narrowed to
    # the single member this stage would otherwise check for.
    all_levels = set(v._schema_definition("VerificationLevelV1")["enum"])
    excluded_levels = set(
        v._schema_definition("EmittableVerificationLevelV1")["allOf"][1]["not"]["enum"]
    )
    assert all_levels - excluded_levels == {"construction_recomputed_v1"}

    # QUANTILE_TABLE_LOOKUP_FAILED: NominalCoveragePpmV1's enum is exactly
    # the pinned table's coverage columns, and sample_count's schema minimum
    # keeps df >= the table's smallest bucket.
    table_coverages = set(v._quantile_buckets_by_coverage())
    assert set(SCHEMA["definitions"]["NominalCoveragePpmV1"]["enum"]) == table_coverages
    smallest_df_bucket = min(
        df for buckets in v._quantile_buckets_by_coverage().values() for df, _ in buckets
    )
    schema_min_sample_count = SCHEMA["definitions"]["SufficientStatisticsMeanVarianceV1"][
        "properties"
    ]["sample_count"]["minimum"]
    assert schema_min_sample_count - 1 >= smallest_df_bucket

    # HOLDOUT_NOT_USED: MeasuredObjectiveClaimV1.evaluated_split_id is a
    # hard schema const.
    assert SCHEMA["definitions"]["MeasuredObjectiveClaimV1"]["properties"][
        "evaluated_split_id"
    ] == {"const": "holdout"}

    # HOLDOUT_MISSING: EvaluationSplitSetV1's second tuple member is a hard
    # schema const "holdout", and the tuple is fixed-length (minItems ==
    # maxItems == 2, additionalItems false) -- a schema-valid bundle always
    # carries exactly one holdout record.
    split_set = SCHEMA["definitions"]["EvaluationSplitSetV1"]
    assert split_set["minItems"] == split_set["maxItems"] == 2
    assert split_set["additionalItems"] is False
    assert split_set["items"][1]["allOf"][1]["properties"]["split_id"] == {"const": "holdout"}

    # HOLDOUT_TOO_SMALL: the schema floor (30) on the tuple's own holdout
    # member, plus -- whenever a claim exists -- S5's SAMPLE_SIZE_MISMATCH
    # (which runs first) forcing holdout.item_count == claim.sample_size,
    # whose own schema minimum already meets the registry floor (see the
    # OBJECTIVE_MINIMUM_SAMPLE_NOT_MET proof above).
    assert split_set["items"][1]["allOf"][1]["properties"]["item_count"]["minimum"] == 30

    # HOLDOUT_REUSED: holdout_scored_arm_count is a hard schema const 1 on
    # BOTH the manifest and the declared plan.
    assert SCHEMA["definitions"]["AgentQualityUnsignedManifestV1"]["properties"][
        "holdout_scored_arm_count"
    ] == {"const": 1}
    assert SCHEMA["definitions"]["AgentQualityDeclaredPlanV1"]["properties"][
        "holdout_scored_arm_count"
    ] == {"const": 1}

    # Real-path proofs (P1-V2.5 review P2-3; P1-V2.5-fix review P2-B): a
    # mutation that violates each hard schema const above, RE-SIGNED
    # (:func:`resign_agent_quality_bundle` -- a caller submitting this would
    # have a genuinely, validly signed bundle; the signature is simply
    # irrelevant to whether SCHEMA fires first, since S1 runs before S8),
    # fed through :func:`v._run_agent_quality_checks`, stops at SCHEMA
    # before S6 -- the owning stage by design -- ever runs. Each case also
    # asserts the FIELD and the specific schema rule
    # (``absolute_schema_path``) that fired, via an independent direct call
    # to the validator -- not just the code.
    context = build_agent_quality_context()

    holdout_not_used_bundle = build_agent_quality_bundle()
    holdout_not_used_bundle["measured_claims"][0]["evaluated_split_id"] = "selection"
    holdout_not_used_resigned = resign_agent_quality_bundle(holdout_not_used_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(holdout_not_used_resigned))
    assert any("evaluated_split_id" in e.absolute_path for e in validator_errors), validator_errors
    with pytest.raises(v.AgentQualityVerificationError) as caught_not_used:
        v._run_agent_quality_checks(
            holdout_not_used_resigned,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
        )
    assert caught_not_used.value.code == "SCHEMA"
    assert caught_not_used.value.field == "bundle"

    holdout_missing_bundle = build_agent_quality_bundle()
    holdout_missing_bundle["evaluation_splits"][1]["split_id"] = "selection"
    holdout_missing_resigned = resign_agent_quality_bundle(holdout_missing_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(holdout_missing_resigned))
    assert any("split_id" in e.absolute_path for e in validator_errors), validator_errors
    with pytest.raises(v.AgentQualityVerificationError) as caught_missing:
        v._run_agent_quality_checks(
            holdout_missing_resigned,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
        )
    assert caught_missing.value.code == "SCHEMA"
    assert caught_missing.value.field == "bundle"

    holdout_reused_bundle = build_agent_quality_bundle()
    # _gv_close regenerates unsigned_manifest wholesale from the declared
    # plan's own holdout_scored_arm_count (see _gv_close) -- mutating the
    # manifest copy directly would be silently overwritten on resign, so
    # the source (the declared plan's copy) is what must be mutated.
    holdout_reused_bundle["declared_plan_envelope"]["declared_plan"]["holdout_scored_arm_count"] = 2
    holdout_reused_resigned = resign_agent_quality_bundle(holdout_reused_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(holdout_reused_resigned))
    assert any("holdout_scored_arm_count" in e.absolute_path for e in validator_errors), (
        validator_errors
    )
    with pytest.raises(v.AgentQualityVerificationError) as caught_reused:
        v._run_agent_quality_checks(
            holdout_reused_resigned,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
        )
    assert caught_reused.value.code == "SCHEMA"
    assert caught_reused.value.field == "bundle"

    verification_level_bundle = build_agent_quality_bundle()
    verification_level_bundle["measured_claims"][0]["verification_level"] = "self_reported_v1"
    verification_level_resigned = resign_agent_quality_bundle(verification_level_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(verification_level_resigned))
    assert any("verification_level" in e.absolute_path for e in validator_errors), validator_errors
    with pytest.raises(v.AgentQualityVerificationError) as caught_level:
        v._run_agent_quality_checks(
            verification_level_resigned,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
        )
    assert caught_level.value.code == "SCHEMA"
    assert caught_level.value.field == "bundle"


def test_p2_b_s5_backstop_codes_real_path_proofs() -> None:
    """P1-V2.5-fix review P2-B / .6 commit-0 addendum: the seven backstop
    codes the .5-fix review named as still missing a real-path proof. Six
    are genuinely bundle-shaped -- a re-signed mutation that a schema-valid
    bundle cannot represent, stopping at SCHEMA (with the field and the
    specific schema rule asserted) before S5/S6 -- the owning stage -- ever
    runs, exactly like the four proofs above. The seventh,
    DISTRIBUTION_ASSUMPTION_NOT_REGISTERED, is a PACKAGE-DATA invariant (see
    :data:`v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES`'s docstring): no
    bundle field controls it, so it has no SCHEMA-mutation proof to give --
    instead this pins the package-data equality to the registry's OWN
    ``registry_version`` field (not the schema's identity const), alongside
    the existing monkeypatch reachability test
    (:func:`test_s5_distribution_assumption_not_registered`)."""
    context = build_agent_quality_context()

    # OBJECTIVE_NOT_REGISTERED: an objective id outside EmittableObjectiveIdV1.
    objective_not_registered_bundle = build_agent_quality_bundle()
    objective_not_registered_bundle["measured_claims"][1]["objective_id"] = (
        "obj.unregistered.made_up.v1"
    )
    resigned = resign_agent_quality_bundle(objective_not_registered_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("objective_id" in e.absolute_path for e in validator_errors), validator_errors
    assert any("enum" in e.schema_path for e in validator_errors), [
        list(e.schema_path) for e in validator_errors
    ]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # OBJECTIVE_MINIMUM_SAMPLE_NOT_MET: below the per-kind schema minimum
    # (30, pinned to the shipped objective registry's own floor above).
    min_sample_bundle = build_agent_quality_bundle()
    min_sample_bundle["measured_claims"][0]["sample_size"] = 5
    resigned = resign_agent_quality_bundle(min_sample_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("sample_size" in e.absolute_path for e in validator_errors), validator_errors
    assert any("minimum" in e.schema_path for e in validator_errors), [
        list(e.schema_path) for e in validator_errors
    ]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # INTERVAL_METHOD_NOT_EMITTABLE: bootstrap_percentile_v1 has no
    # IntervalParamsV1 oneOf branch at all.
    interval_method_bundle = build_agent_quality_bundle()
    interval_method_bundle["measured_claims"][0]["interval_params"]["interval_method"] = (
        "bootstrap_percentile_v1"
    )
    resigned = resign_agent_quality_bundle(interval_method_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("interval_params" in e.absolute_path for e in validator_errors), validator_errors
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # INTERVAL_OUT_OF_UNIT_BOUNDS: the registry's own unit maximum (pinned
    # above, 1000000 ppm) is ALSO the schema's own per-kind maximum.
    out_of_bounds_bundle = build_agent_quality_bundle()
    out_of_bounds_bundle["measured_claims"][0]["interval_high"] = 1_500_000
    resigned = resign_agent_quality_bundle(out_of_bounds_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("interval_high" in e.absolute_path for e in validator_errors), validator_errors
    assert any("maximum" in e.schema_path for e in validator_errors), [
        list(e.schema_path) for e in validator_errors
    ]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # QUANTILE_TABLE_LOOKUP_FAILED: NominalCoveragePpmV1's closed enum
    # (pinned above to the pinned table's own coverage columns) means an
    # off-table coverage is unconstructible before _lookup_t_scaled ever runs.
    off_table_bundle = build_agent_quality_bundle()
    off_table_bundle["measured_claims"][0]["nominal_coverage_ppm"] = 123456
    resigned = resign_agent_quality_bundle(off_table_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("nominal_coverage_ppm" in e.absolute_path for e in validator_errors), (
        validator_errors
    )
    assert any("enum" in e.schema_path for e in validator_errors), [
        list(e.schema_path) for e in validator_errors
    ]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # HOLDOUT_TOO_SMALL (S6): below the schema floor (30, pinned above) on
    # the holdout tuple member's own item_count.
    holdout_small_bundle = build_agent_quality_bundle()
    holdout_small_bundle["evaluation_splits"][1]["item_count"] = 10
    resigned = resign_agent_quality_bundle(holdout_small_bundle)
    validator_errors = list(_gv_bundle_validator().iter_errors(resigned))
    assert any("item_count" in e.absolute_path for e in validator_errors), validator_errors
    assert any("minimum" in e.schema_path for e in validator_errors), [
        list(e.schema_path) for e in validator_errors
    ]
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SCHEMA"
    assert caught.value.field == "bundle"

    # DISTRIBUTION_ASSUMPTION_NOT_REGISTERED: package-data invariant, pinned
    # to the shipped registry's OWN identity, not the schema's.
    _gv_assert_registry_versions_pinned_to_document()
    for entry in v._objective_registry_entries_by_id().values():
        if entry["objective_kind"] == "nonnegative_mean":
            assert entry.get("distribution_assumption") in v._distribution_assumption_values()


def test_holdout_too_small_direct_call_guard_still_fires() -> None:
    """Behavioral half of the HOLDOUT_TOO_SMALL backstop proof: even though
    no schema-valid bundle can trip it, the guard itself is not dead code --
    calling S6 directly (bypassing schema) with an undersized holdout still
    raises it."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["item_count"] = 10
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "HOLDOUT_TOO_SMALL"
    assert caught.value.field == "evaluation_splits.holdout"


def test_holdout_not_used_direct_call_guard_still_fires() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["evaluated_split_id"] = "selection"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "HOLDOUT_NOT_USED"
    assert caught.value.field == "measured_claims"


def test_holdout_missing_direct_call_guard_still_fires() -> None:
    """HOLDOUT_MISSING has its OWN reachable-by-direct-call condition,
    distinct from SPLIT_SET_SHAPE: the "selection" slot is fine, but the
    second slot does not name split_id "holdout"."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["split_id"] = "selection"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "HOLDOUT_MISSING"
    assert caught.value.field == "evaluation_splits.holdout"


def test_split_set_shape_direct_call_guard_still_fires() -> None:
    """SPLIT_SET_SHAPE's own reachable-by-direct-call condition: the
    "selection" slot itself is wrong."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"] = list(reversed(bundle["evaluation_splits"]))
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "SPLIT_SET_SHAPE"
    assert caught.value.field == "evaluation_splits"


def test_holdout_reused_direct_call_guard_still_fires() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["holdout_scored_arm_count"] = 2
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "HOLDOUT_REUSED"
    assert caught.value.field == "unsigned_manifest"


def test_pending_and_preempted_and_emitted_partition_is_disjoint_and_covers_all() -> None:
    """N6 widened: the three buckets -- schema-preempted, pending, and
    emitted-today -- are pairwise disjoint and their union is exactly
    AGENT_QUALITY_ERROR_CODES.

    P1-V2.0 review finding P2-6: comparing ``preempted | pending |
    emitted_today == AGENT_QUALITY_ERROR_CODES`` against a hand-typed
    ``emitted_today`` literal is a tautology -- ``AGENT_QUALITY_PENDING_CODES``
    is DEFINED in the module as ``ERROR_CODES - PREEMPTED -
    <that same literal>``, so the identity holds for ANY content of
    ``ERROR_CODES``/``PREEMPTED`` as long as the test's literal matches the
    module's. This version derives ``emitted_today`` from the AST emission
    scan instead (a property of the actual code, not a mirror of the
    module's own subtraction), and separately recovers "the module's
    subtraction set" algebraically from the three public constants, so the
    two are compared rather than both being restated from the same
    source."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    emitted_today = frozenset(code for (_fn, code, _line) in _emission_sites(tree))

    preempted = v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES | v.AGENT_QUALITY_INPUT_PREEMPTED_CODES
    backstop = v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES
    dead = v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES | v.AGENT_QUALITY_INPUT_PREEMPTED_CODES
    pending = v.AGENT_QUALITY_PENDING_CODES
    # P1-V2.4 review P2-2: backstop codes are a NEW third case the original
    # two-way "preempted (no guard) xor emitted (real code)" split could not
    # express -- a backstop code is BOTH preempted (unreachable via any
    # schema-valid bundle) AND emitted (a real, defensive `_fail(...)` call
    # site still exists). `emitted_today` therefore legitimately overlaps
    # `preempted` on exactly the backstop subset, so the identity below
    # excludes that subset from `emitted_today` before comparing, and a
    # separate assertion pins the overlap to be EXACTLY that subset -- no
    # more, no less.
    module_subtraction_set = v.AGENT_QUALITY_ERROR_CODES - preempted - pending

    assert emitted_today - backstop == module_subtraction_set, (
        "a code started or stopped being emitted without "
        "AGENT_QUALITY_PENDING_CODES's subtraction being updated to match: "
        f"AST-derived={sorted(emitted_today - backstop)} "
        f"module-subtraction={sorted(module_subtraction_set)}"
    )
    assert preempted & emitted_today == backstop, (
        "the only preempted codes with a live emission site must be exactly "
        f"the backstop set: overlap={sorted(preempted & emitted_today)} "
        f"backstop={sorted(backstop)}"
    )
    assert dead.isdisjoint(emitted_today)
    # P1-V2.5 review P3-8's ``preempted.isdisjoint(pending)`` was a pure
    # algebraic tautology -- ``pending`` is DEFINED as ``ERROR_CODES -
    # preempted - <literal>``, so it is disjoint from ``preempted`` for ANY
    # content of ``ERROR_CODES``/the literal, proving nothing about the
    # actual code. P1-V2.5-fix review P3-F: its replacement,
    # ``backstop.isdisjoint(pending)``, was STILL a tautology for the same
    # underlying reason -- ``backstop`` (the module constant) is a subset of
    # ``preempted`` by construction (``AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    # = DEAD | BACKSTOP``), so anything derived as a subset of ``preempted``
    # is automatically disjoint from ``pending``, no matter how it was
    # derived; line 1805 above already independently pins
    # ``preempted & emitted_today == backstop``, so restating disjointness
    # from ``pending`` added no new information at all.
    #
    # The genuinely new, mutation-sensitive fact worth checking here is
    # LOCATION, not set membership: every backstop code's live emission
    # site must sit INSIDE one of the two stage functions that own it
    # (S5 or S6) -- not merely somewhere in the module. A code whose
    # ``_fail(...)`` call were moved into an unrelated function (or into
    # module scope) would still satisfy every set-algebra assertion above
    # but would no longer be a genuine per-stage backstop guard.
    emission_sites = _emission_sites(tree)
    # QUANTILE_TABLE_LOOKUP_FAILED is raised by _lookup_t_scaled, a helper
    # _stage_s5_objective_measurement calls rather than emitting directly
    # (see its own @_owns docstring, ":func:`v._lookup_t_scaled`") -- still
    # genuinely S5-owned, just one call frame removed.
    backstop_owning_functions = frozenset(
        {"_stage_s5_objective_measurement", "_stage_s6_splits_held_out", "_lookup_t_scaled"}
    )
    codes_emitted_in_owning_stages = frozenset(
        code for (fn, code, _line) in emission_sites if fn in backstop_owning_functions
    )
    assert backstop <= codes_emitted_in_owning_stages, (
        "every backstop code must be emitted from inside its owning S5/S6 "
        f"stage function: missing={sorted(backstop - codes_emitted_in_owning_stages)}"
    )
    assert pending.isdisjoint(emitted_today)
    assert preempted | pending | emitted_today == v.AGENT_QUALITY_ERROR_CODES


def test_four_way_code_vocabulary_partition_is_disjoint_and_covers_all() -> None:
    """P1-V2.4 review P2-2: ``AGENT_QUALITY_CONTEXT_PREEMPTED_CODES`` was
    never folded into any partition arithmetic -- this test is the fold.
    Every code in the closed vocabulary falls into EXACTLY one of four
    buckets: dead (no guard anywhere), preempted-with-a-live-backstop-guard
    (schema OR context preemption -- the guard exists but no valid input/
    context can ever reach it), pending (no guard yet -- empty as of
    P1-V2.5 commit 2, since every stage S1-S8 now runs a real check; see
    :func:`test_agent_quality_pending_codes_is_now_empty`), or reachable (a
    real guard that a schema-valid, correctly-constructed caller CAN
    trigger)."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    emitted_today = frozenset(code for (_fn, code, _line) in _emission_sites(tree))

    dead = v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES | v.AGENT_QUALITY_INPUT_PREEMPTED_CODES
    preempted_with_backstop = (
        v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES | v.AGENT_QUALITY_CONTEXT_PREEMPTED_CODES
    )
    pending = v.AGENT_QUALITY_PENDING_CODES
    reachable = emitted_today - preempted_with_backstop

    assert dead.isdisjoint(preempted_with_backstop)
    # P1-V2.5 review P3-8: ``dead.isdisjoint(pending)`` was a pure algebraic
    # tautology -- ``pending`` is DEFINED as ``ERROR_CODES -
    # AGENT_QUALITY_SCHEMA_PREEMPTED_CODES - AGENT_QUALITY_INPUT_PREEMPTED_CODES
    # - <literal>``, and ``dead`` is a SUBSET of exactly those two subtracted
    # sets, so the disjointness holds for ANY module content, proving
    # nothing about the actual code. Replaced with the genuine, code-derived
    # check: no dead code has a live emission site (asserted below, with a
    # failure message), which is what "dead" is actually supposed to mean.
    assert dead.isdisjoint(reachable)
    assert preempted_with_backstop.isdisjoint(pending)
    assert preempted_with_backstop.isdisjoint(reachable)
    assert pending.isdisjoint(reachable)
    assert preempted_with_backstop <= emitted_today, (
        "every preempted-with-backstop code must still have a live emission site: "
        f"missing={preempted_with_backstop - emitted_today}"
    )
    assert dead.isdisjoint(emitted_today), (
        f"a dead code must have NO emission site: unexpected={dead & emitted_today}"
    )
    assert dead | preempted_with_backstop | pending | reachable == v.AGENT_QUALITY_ERROR_CODES, (
        "the four buckets must exactly cover the closed code vocabulary"
    )


def test_agent_quality_preempted_total_matches_bucket_sum() -> None:
    """P1-V2.5 review P2-3: :data:`v.AGENT_QUALITY_PREEMPTED_TOTAL` must
    equal the sum of the four preemption buckets -- schema-preempted dead
    (3), schema-preempted backstop (11), context-preempted (1), and
    input-preempted (2) -- 17 codes total, none of which count toward
    reachable coverage. .6's PR body must cite this constant."""
    assert v.AGENT_QUALITY_PREEMPTED_TOTAL == (
        len(v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES)
        + len(v.AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES)
        + len(v.AGENT_QUALITY_CONTEXT_PREEMPTED_CODES)
        + len(v.AGENT_QUALITY_INPUT_PREEMPTED_CODES)
    )
    assert v.AGENT_QUALITY_PREEMPTED_TOTAL == 17


def test_agent_quality_pending_codes_is_now_empty() -> None:
    """P1-V2.5 commit 2: every stage (S1-S8) now runs a real check, so
    :data:`v.AGENT_QUALITY_PENDING_CODES` -- which the module's own
    long-lived comment has tracked shrinking release over release, and
    which was explicitly expected to hold only a future packet's own codes
    if any remained -- is exactly empty. No later packet owns any
    leftover code in this pillar's vocabulary."""
    assert v.AGENT_QUALITY_PENDING_CODES == frozenset()


def test_pending_codes_are_not_yet_emitted() -> None:
    """No pending code has a literal emission site in the module today, and
    every literal code actually raised is NOT pending -- source-scanned so a
    stage that starts emitting a pending code (or one that silently stops
    emitting a non-pending code) breaks this test instead of drifting past
    it.

    P1-V2.0 review finding P3-7: the regex half of the original audit
    matched docstrings and comments (three of four hits on
    ``AgentQualityVerificationError("PACKAGE_DATA_INVALID", ...)`` were
    prose, not code), so this version uses :func:`_emission_sites` (an AST
    walk, the same one :func:`test_stage_only_emits_codes_it_owns` and
    :func:`test_pending_and_preempted_and_emitted_partition_is_disjoint_and_covers_all`
    use) instead of a regex over the raw source. Finding P1-2: that scan
    ALSO counts a ``_unique_by(rows, key_fn, "CODE", field)`` call site as
    emitting ``"CODE"`` -- the previous version excluded ``_unique_by``
    call sites from the scan entirely, which let a stage raise a PENDING
    code (e.g. ``OBJECTIVE_DUPLICATE``) through it with the audit green."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    emitted = frozenset(code for (_fn, code, _line) in _emission_sites(tree))
    assert emitted <= v.AGENT_QUALITY_ERROR_CODES, emitted - v.AGENT_QUALITY_ERROR_CODES
    assert emitted.isdisjoint(v.AGENT_QUALITY_PENDING_CODES), (
        emitted & v.AGENT_QUALITY_PENDING_CODES
    )
    assert v.AGENT_QUALITY_PENDING_CODES.isdisjoint(emitted)


def test_emission_audit_scans_only_literal_codes() -> None:
    """Every ``_fail(...)`` / ``AgentQualityVerificationError(...)`` call
    site in the module must pass a string-literal first argument, and every
    ``_unique_by(...)`` call site's ``duplicate_code`` argument (3rd
    positional, or the ``duplicate_code=`` keyword) must also be a string
    literal when present -- except ``_fail``'s own body (which constructs
    the error from its parameters) and ``_unique_by``'s own body (which
    forwards its CALLER-supplied ``duplicate_code`` parameter, a variable,
    not a literal, by design -- see its docstring).

    P1-V2.0 review finding P3-8 (low realism, cheap to close): also asserts
    no module-level or nested ``Assign`` anywhere rebinds ``_fail`` or
    ``AgentQualityVerificationError`` to another name -- an alias
    (``_emit = _fail; _emit(...)``) would otherwise let a stage emit any
    code with every scan above still green, since they only recognize the
    literal names ``_fail`` / ``AgentQualityVerificationError`` /
    ``_unique_by`` as call targets."""
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
            enclosing = self.function_stack[-1] if self.function_stack else None
            if name in ("_fail", "AgentQualityVerificationError") and enclosing not in (
                "_fail",
                "_unique_by",
            ):
                if not node.args:
                    offenders.append(f"{name}() with no positional args at line {node.lineno}")
                else:
                    first = node.args[0]
                    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                        offenders.append(
                            f"{name}(...) with a non-literal code at line {node.lineno}"
                        )
            elif name == "_unique_by" and enclosing != "_unique_by":
                candidate: ast.expr | None = None
                if len(node.args) >= 3:
                    candidate = node.args[2]
                for kw in node.keywords:
                    if kw.arg == "duplicate_code":
                        candidate = kw.value
                if candidate is not None and not (
                    isinstance(candidate, ast.Constant) and isinstance(candidate.value, str)
                ):
                    offenders.append(
                        f"_unique_by(...) with a non-literal duplicate_code at line {node.lineno}"
                    )
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            if isinstance(node.value, ast.Name) and node.value.id in (
                "_fail",
                "AgentQualityVerificationError",
            ):
                offenders.append(f"alias of {node.value.id!r} created at line {node.lineno}")
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
    # Backstop codes (P1-V2.4 review P2-2, extended to S6 in P1-V2.5 commit 1) are
    # schema-preempted but still OWNED by S5/S6 -- their guard is what
    # raises them, even though no schema-valid bundle can trigger it. The
    # two DEAD schema-preempted codes and the two DEAD input-preempted
    # codes (row 48 -- no guard anywhere, since v1 has no opening path) are
    # excluded from every stage's owned set.
    assert union == v.AGENT_QUALITY_ERROR_CODES - (
        v.AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES | v.AGENT_QUALITY_INPUT_PREEMPTED_CODES
    )
    assert set(v._STAGE_CODES) == set(_STAGE_FUNCTION_NAMES)


# P1-V2.6 commit 1 (G12): _run_agent_quality_checks -- the last remaining
# unwired helper -- now has an in-module caller (the public entry point,
# verify_agent_quality_certificate), so this inventory is empty. _wilson_point,
# _wilson_bounds and _student_t_half_width were wired in .4 commit 2 (S5's
# point-estimate and interval recomputation); _unique_by was wired in commit
# 1's OBJECTIVE_DUPLICATE guard; _strip_self_digest is wired as of P1-V2.2
# (S8's unsigned-manifest reconstruction, design row 64).
_UNWIRED_HELPER_NAMES: frozenset[str] = frozenset()


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


# ==========================================================================
# P1-V2.1 -- golden vectors + re-signing harness. A test-side builder that
# mints a digest-consistent, schema-valid, fully signed agent-quality
# bundle; helpers that re-sign on demand after any mutation; the abstained
# counterpart. No verifier guard logic, no public entry point, no export --
# packets .2-.6 wire the guards these fixtures will exercise.
# ==========================================================================

import base64  # noqa: E402
import copy as _gv_copy  # noqa: E402

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import tests.test_process_record_verifier as _prv  # noqa: E402
from traigent_schema import fp2  # noqa: E402

# The schema's own digest-domain registry (AgentQualityDigestDomainRegistryV1)
# -- every domain string below is read from it, never retyped, so a domain
# rename in the schema breaks this file loudly instead of silently signing
# under a stale string.
_GV_DOMAINS: dict[str, str] = {
    role: spec["const"]
    for role, spec in SCHEMA["definitions"]["AgentQualityDigestDomainRegistryV1"][
        "properties"
    ].items()
}
# base_process_record_unsigned_manifest_digest's domain belongs to the
# PROCESS-RECORD family, not this schema's own digest-domain registry --
# read from the verifier module's own private constant (P1-V2.2 closure:
# no longer an ASSUMED, hand-copied string).
_GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN = v._PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN

# A REAL process-record certificate bundle (P1-V2.2 closure: replaces the
# .1 stub) -- built by test_process_record_verifier's own golden builder,
# signed under the SAME ed25519 test issuer key
# (``Ed25519PrivateKey.from_private_bytes(bytes(range(32)))``) that
# :data:`_GV_PRIVATE_KEY` below also uses, so a bundle this file signs with
# ``_GV_PRIVATE_KEY`` genuinely shares one key ring with this process
# record -- exactly what design row 66 (KEY_RING_MISMATCH) checks.
_GV_PROCESS_RECORD_BUNDLE, _GV_PROCESS_RECORD_CONTEXT, _GV_PROCESS_RECORD_STREAMS = (
    _prv._build_bundle()
)

_GV_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_GV_PUBLIC_KEY = _GV_PRIVATE_KEY.public_key()
# A second, independent key -- deliberately NOT in any key ring the private
# runner will trust -- for the "wrong key, valid shape" fixture (checkpoint
# b.3).
_GV_FOREIGN_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

# The golden bundle's issuer_key_ref/trust_ring_ref are read from the SAME
# process record's own verified issuer materials (rather than independent
# sentinels), so the two bundles agree on identity by construction, the way
# design row 66 requires -- not by two hand-typed strings that happen to
# match.
_GV_PROCESS_RECORD_ISSUER = _GV_PROCESS_RECORD_BUNDLE["verification_materials_v0"]["issuer"]
_GV_ISSUER_KEY_REF = _GV_PROCESS_RECORD_ISSUER["key_ref"]
_GV_TRUST_RING_REF = _GV_PROCESS_RECORD_ISSUER["trust_ring_ref"]
# P1-V2.3: project_ref/build_session_ref and the four commitment refs are
# now ALSO checked, by S2, against the verified process record's own
# result -- so they can no longer be independent sentinels chosen only for
# this file's own convenience. They are the SAME values
# tests.test_process_record_verifier's own golden builder pins
# (``_prv.PROJECT``/``_prv.BUILD``/``_prv.AGENT_COMMITMENT_REF`` etc.), so
# the golden agent-quality bundle's context genuinely agrees with
# :data:`_GV_PROCESS_RECORD_BUNDLE` about what project/build/commitments
# this verification is for -- not two independently-typed strings that
# happen to look alike.
_GV_PROJECT_REF = _prv.PROJECT
_GV_BUILD_SESSION_REF = _prv.BUILD
_GV_SHA = "sha256:" + "a" * 64
_GV_SHA_HOLDOUT = "sha256:" + "b" * 64

# Four independently-bound commitment refs in the unsigned manifest's
# `coverage`-const field set (review P2-3): each must be a DISTINCT sentinel
# so a golden-vector mutation/swap between any two of them is not a no-op --
# already true of the process-record suite's own four constants.
_GV_AGENT_COMMITMENT_REF = _prv.AGENT_COMMITMENT_REF
_GV_DATASET_COMMITMENT_REF = _prv.DATASET_COMMITMENT_REF
_GV_EVALUATOR_COMMITMENT_REF = _prv.EVALUATOR_COMMITMENT_REF
_GV_BUILD_DEFINITION_COMMITMENT_REF = _prv.BUILD_DEFINITION_COMMITMENT_REF
_GV_MEASUREMENT_CONTRACT_RECORD_DIGEST = "sha256:" + "a5" * 32
_GV_MEASUREMENT_CONTRACT_REF = "measurement:mmmmmmmm"


def build_agent_quality_context(**overrides: object) -> v.AgentQualityVerificationContext:
    """The context the golden bundle is bound to. A thin wrapper over
    :func:`_context` under the name this packet's brief specifies -- both
    names stay available and can never drift apart.

    P1-V2.3: pins ``process_record_context`` to
    :data:`_GV_PROCESS_RECORD_CONTEXT` (the SAME context
    :data:`_GV_PROCESS_RECORD_BUNDLE` verifies under) and the four
    commitment refs / project / build-session refs to the values that
    process record actually carries, so S2's real cross-artifact checks
    (COMMITMENT_REF_MISMATCH, SCOPE_MISMATCH) pass on the golden bundle by
    construction rather than by two independently-typed literals that
    happen to agree."""
    kwargs: dict = dict(
        process_record_context=_GV_PROCESS_RECORD_CONTEXT,
        expected_project_ref=_GV_PROJECT_REF,
        expected_build_session_ref=_GV_BUILD_SESSION_REF,
        expected_agent_commitment_ref=_GV_AGENT_COMMITMENT_REF,
        expected_dataset_commitment_ref=_GV_DATASET_COMMITMENT_REF,
        expected_evaluator_commitment_ref=_GV_EVALUATOR_COMMITMENT_REF,
        expected_build_definition_commitment_ref=_GV_BUILD_DEFINITION_COMMITMENT_REF,
        expected_measurement_contract_ref=_GV_MEASUREMENT_CONTRACT_REF,
        expected_measurement_contract_record_digest=_GV_MEASUREMENT_CONTRACT_RECORD_DIGEST,
    )
    kwargs.update(overrides)
    return _context(**kwargs)


def _gv_digest(role: str, payload: object) -> str:
    return v._role_digest(_GV_DOMAINS[role], payload)


def _gv_sign(role: str, payload: object, private_key: Ed25519PrivateKey = _GV_PRIVATE_KEY) -> str:
    """Sign ``UTF8(domain) || 0x00 || fp2.canonicalize(payload)`` and return
    base64 signature bytes -- the same construction
    ``AgentQualitySignaturePreimageV1`` names for the top-level issuer
    signature, reused here for the declared-plan signature under its own
    domain (ASSUMED: the schema does not spell out the declared-plan
    preimage explicitly; this mirrors the top-level signature's own
    construction, the only one the schema does spell out)."""
    material = (
        _GV_DOMAINS[role].encode("utf-8") + b"\x00" + fp2.canonicalize(payload).encode("utf-8")
    )
    return base64.b64encode(private_key.sign(material)).decode("ascii")


_GV_REGISTRY_IDENTITY_FIELDS = {
    "aggregation_policy": (
        "AggregationPolicyIdentityV1",
        "policy_id",
        "policy_version",
        "policy_digest",
    ),
    "objective_registry": (
        "ObjectiveRegistryIdentityV1",
        "registry_id",
        "registry_version",
        "registry_digest",
    ),
    "non_claim_catalog": (
        "NonClaimCatalogIdentityV1",
        "catalog_id",
        "catalog_version",
        "catalog_digest",
    ),
    "quantile_table": ("QuantileTableIdentityV1", "table_id", "table_version", "table_digest"),
}


def _gv_registry_identity(stem: str) -> dict:
    """A real registry-identity projection for one of the four shipped
    documents: id/version consts read straight from the schema, digest
    independently recomputed via the module's own
    :func:`_load_agent_quality_document` + :func:`_role_digest` under
    :data:`v._AGENT_QUALITY_REGISTRY_DOMAINS` -- never a sentinel (checkpoint
    a.6)."""
    definition_name, id_field, version_field, digest_field = _GV_REGISTRY_IDENTITY_FIELDS[stem]
    props = SCHEMA["definitions"][definition_name]["properties"]
    document = v._load_agent_quality_document(stem)
    digest = v._role_digest(v._AGENT_QUALITY_REGISTRY_DOMAINS[stem], document)
    return {
        id_field: props[id_field]["const"],
        version_field: props[version_field]["const"],
        digest_field: digest,
    }


def _gv_assert_registry_versions_pinned_to_document() -> None:
    """P1-V2.6 final-review closure P2-2: pin each of the four registries'
    version field to the SHIPPED DOCUMENT's own value, read via
    :func:`v._load_agent_quality_document`, not
    :func:`v._expected_registry_identity`'s schema-const copy -- the two
    happen to agree today, but only the document read is proof of that
    agreement rather than an assumption of it. The reviewer's probe (the
    document's ``registry_version`` set to ``"9.9.9"`` with its sidecar
    digest re-pinned to match) makes the document-side assertion below fail
    where the old schema-const-only assertion could not."""
    for stem, (_, _, version_field, _) in _GV_REGISTRY_IDENTITY_FIELDS.items():
        document_version = v._load_agent_quality_document(stem)[version_field]
        assert document_version == "1.0.0"
        assert document_version == v._expected_registry_identity(stem)[version_field]


AGGREGATION_POLICY_IDENTITY = _gv_registry_identity("aggregation_policy")
OBJECTIVE_REGISTRY_IDENTITY = _gv_registry_identity("objective_registry")
NON_CLAIM_CATALOG_IDENTITY = _gv_registry_identity("non_claim_catalog")
QUANTILE_TABLE_IDENTITY = _gv_registry_identity("quantile_table")


def _gv_merge(value: object, override: object) -> object:
    """Deep-merge ``override`` onto ``value``: dicts merge key-by-key
    (recursively), anything else (including a whole list) is replaced
    wholesale by the override. Mirrors
    ``test_evaluator_quality_verifier.py::_merge``."""
    if isinstance(value, dict) and isinstance(override, dict):
        result = _gv_copy.deepcopy(value)
        for key, child in override.items():
            result[key] = (
                _gv_merge(result[key], child) if key in result else _gv_copy.deepcopy(child)
            )
        return result
    return _gv_copy.deepcopy(override)


def _gv_split_derivation_raw() -> dict:
    return {
        "schema_version": _GV_DOMAINS["split_derivation"],
        "split_rule_id": "hmac_sha256_prefix_threshold_v1",
        "dataset_commitment_ref": _GV_SHA,
        "evaluated_universe_item_count": 1000,
        "holdout_fraction_ppm": 200000,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "canonicalization_profile": "jcs_v1",
        "split_key_commitment": _GV_SHA,
        "split_derivation_digest": _GV_SHA,
    }


def _gv_evaluation_split_record_raw(split_id: str, item_count: int) -> dict:
    # P1-V2.5 commit 1 (S6, row 46 SPLIT_COMMITMENT_COLLISION): the two
    # split records' own split_commitment_digest values must be DISTINCT --
    # a placeholder shared between selection and holdout would make the
    # golden bundle itself collide. split_derivation_digest, by contrast,
    # IS meant to be identical across both records (row 44); _gv_close
    # overwrites it from the shared split_derivation anyway.
    split_commitment_digest = _GV_SHA if split_id == "selection" else _GV_SHA_HOLDOUT
    return {
        "schema_version": _GV_DOMAINS["evaluation_split"],
        "split_id": split_id,
        "item_count": item_count,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "canonicalization_profile": "jcs_v1",
        "split_commitment_digest": split_commitment_digest,
        "split_derivation_digest": _GV_SHA,
    }


def _gv_measured_claims_raw() -> list[dict]:
    successes, trials, coverage_ppm = 190, 200, 950000
    wilson_low, wilson_high = v._wilson_bounds(successes, trials, coverage_ppm)
    wilson_claim = _schema_fixtures._wilson_claim(
        point_estimate=v._wilson_point(successes, trials),
        interval_low=wilson_low,
        interval_high=wilson_high,
        measurement_contract_ref=_GV_MEASUREMENT_CONTRACT_REF,
        measurement_contract_record_digest=_GV_MEASUREMENT_CONTRACT_RECORD_DIGEST,
    )
    mean_fixed, sample_stddev_fixed, sample_count, t_coverage_ppm = 800000, 50000, 200, 950000
    half_width = v._student_t_half_width(
        mean_fixed=mean_fixed,
        sample_stddev_fixed=sample_stddev_fixed,
        sample_count=sample_count,
        coverage_ppm=t_coverage_ppm,
        unit_scale="ppm",
    )
    student_t_claim = _schema_fixtures._student_t_claim(
        point_estimate=mean_fixed,
        interval_low=mean_fixed - half_width,
        interval_high=mean_fixed + half_width,
        interval_params={
            "interval_method": "student_t_normal_approx_v1",
            "degrees_of_freedom": sample_count - 1,
            "quantile_table": QUANTILE_TABLE_IDENTITY,
            "recomputation_profile": "exact_integer_rational_v1",
        },
        measurement_contract_ref=_GV_MEASUREMENT_CONTRACT_REF,
        measurement_contract_record_digest=_GV_MEASUREMENT_CONTRACT_RECORD_DIGEST,
    )
    return [wilson_claim, student_t_claim]


def _gv_assertion_raw() -> dict:
    definition = SCHEMA["definitions"]["AgentQualityAssertionV1"]
    return {
        "schema_version": definition["properties"]["schema_version"]["const"],
        "claim_id": definition["properties"]["claim_id"]["const"],
        "assertion_template_id": definition["properties"]["assertion_template_id"]["const"],
        "aggregation_policy": AGGREGATION_POLICY_IDENTITY,
        "objective_registry": OBJECTIVE_REGISTRY_IDENTITY,
        "rendered_text": definition["properties"]["rendered_text"]["const"],
        "assertion_digest": _GV_SHA,
    }


def _gv_declared_plan_raw(split_derivation_raw: dict) -> dict:
    return {
        "schema_version": _GV_DOMAINS["declared_plan"],
        "scope_binding_digest": _GV_SHA,
        "aggregation_policy": AGGREGATION_POLICY_IDENTITY,
        "objective_registry": OBJECTIVE_REGISTRY_IDENTITY,
        "objective_ids": ["obj.accuracy.exact_match.v1", "obj.accuracy.evaluator_score_mean.v1"],
        "primary_objective_id": "obj.accuracy.exact_match.v1",
        "split_derivation": split_derivation_raw,
        "selection_arm_count": 4,
        "holdout_scored_arm_count": 1,
        "declared_plan_digest": _GV_SHA,
    }


def _gv_base_bundle() -> dict:
    """The raw, un-closed skeleton: every digest/signature field present but
    set to a placeholder, so :func:`_gv_close` always recomputes every one
    of them fresh from the arrays actually present -- an override applied
    before closing changes what gets signed, never leaves a stale digest
    behind."""
    split_derivation_raw = _gv_split_derivation_raw()
    return {
        "schema_version": "traigent.agent_quality.certificate_bundle.v1",
        "split_derivation": split_derivation_raw,
        "evaluation_splits": [
            _gv_evaluation_split_record_raw("selection", 800),
            _gv_evaluation_split_record_raw("holdout", 200),
        ],
        "measured_claims": _gv_measured_claims_raw(),
        "non_certified_selection_estimates": [],
        "non_claims": _schema_fixtures._non_claims(),
        "assertion": _gv_assertion_raw(),
        "declared_plan_envelope": {
            "schema_version": "traigent.agent_quality.declared_plan_envelope.v1",
            "declared_plan": _gv_declared_plan_raw(split_derivation_raw),
            "signature": {
                "schema_version": _GV_DOMAINS["declared_plan_signature"],
                "algorithm": "ed25519",
                "issuer_key_ref": _GV_ISSUER_KEY_REF,
                "trust_ring_ref": _GV_TRUST_RING_REF,
                "signed_payload": "agent_quality_declared_plan",
                "declared_plan_digest": _GV_SHA,
                "signature": "A" * 85 + "A==",
            },
        },
        "claim_support_rows": [
            {
                "claim_id": "AQ1",
                "evidence_basis": "issuer_verified",
                "assertion_digest": _GV_SHA,
                "measured_claims_digest": _GV_SHA,
                "evaluation_splits_digest": _GV_SHA,
                "verifier_result": "pass",
                "claim_material_digest": _GV_SHA,
                "declared_plan_digest": _GV_SHA,
            }
        ],
        "unsigned_manifest": {"schema_version": "traigent.agent_quality.unsigned_manifest.v1"},
        "signature": {
            "schema_version": "traigent.agent_quality.signature.v1",
            "algorithm": "ed25519",
            "issuer_key_ref": _GV_ISSUER_KEY_REF,
            "trust_ring_ref": _GV_TRUST_RING_REF,
            "signed_payload": "unsigned_agent_quality_manifest",
            "unsigned_manifest_digest": _GV_SHA,
            "signature": "A" * 85 + "A==",
        },
    }


def _gv_close(bundle: dict, *, private_key: Ed25519PrivateKey = _GV_PRIVATE_KEY) -> dict:
    """Recompute EVERY digest and signature in ``bundle`` from its arrays,
    bottom-up, and return a new, fully consistent bundle. The one function
    every mutation-then-resign helper below is built from."""
    b = _gv_copy.deepcopy(bundle)

    split_derivation = b["split_derivation"]
    split_derivation["split_derivation_digest"] = _gv_digest(
        "split_derivation", v._strip_self_digest(split_derivation, "split_derivation_digest")
    )
    for record in b["evaluation_splits"]:
        record["split_derivation_digest"] = split_derivation["split_derivation_digest"]
    evaluation_splits_digest = _gv_digest("evaluation_splits", b["evaluation_splits"])
    measured_claims_digest = _gv_digest("measured_claims", b["measured_claims"])
    selection_estimates_digest = _gv_digest(
        "selection_estimates", b["non_certified_selection_estimates"]
    )
    non_claims_digest = _gv_digest("non_claims", b["non_claims"])

    assertion = b["assertion"]
    assertion["assertion_digest"] = _gv_digest(
        "assertion", v._strip_self_digest(assertion, "assertion_digest")
    )

    declared_plan = b["declared_plan_envelope"]["declared_plan"]
    declared_plan["split_derivation"] = split_derivation
    declared_plan["scope_binding_digest"] = _gv_digest(
        "scope_binding",
        {
            "schema_version": _GV_DOMAINS["scope_binding"],
            "project_ref": _GV_PROJECT_REF,
            "build_session_ref": _GV_BUILD_SESSION_REF,
        },
    )
    declared_plan["declared_plan_digest"] = _gv_digest(
        "declared_plan", v._strip_self_digest(declared_plan, "declared_plan_digest")
    )
    declared_plan_signature = b["declared_plan_envelope"]["signature"]
    declared_plan_signature["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    declared_plan_signature["signature"] = _gv_sign(
        "declared_plan_signature", declared_plan, private_key
    )
    declared_plan_signature_digest = _gv_digest("declared_plan_signature", declared_plan_signature)

    claim_material = {
        "claim_id": assertion["claim_id"],
        "tier": 3,
        "assertion_template_id": assertion["assertion_template_id"],
        "rendered_text": assertion["rendered_text"],
        "assertion_digest": assertion["assertion_digest"],
    }
    claim_material_digest = _gv_digest("claim_material", claim_material)

    for row in b["claim_support_rows"]:
        if row.get("evidence_basis") == "abstained":
            continue
        # verifier_result is CONTENT, not a derived digest -- _gv_close must
        # never assign it (review P1-1): the initial skeleton already sets it
        # to "pass", and a caller that mutated it (e.g. to "fail" for a
        # mutate-then-resign negative) must see it survive re-closing.
        row.update(
            {
                "assertion_digest": assertion["assertion_digest"],
                "measured_claims_digest": measured_claims_digest,
                "evaluation_splits_digest": evaluation_splits_digest,
                "claim_material_digest": claim_material_digest,
                "declared_plan_digest": declared_plan["declared_plan_digest"],
            }
        )
    claim_support_rows_digest = _gv_digest("claim_support_rows", b["claim_support_rows"])

    coverage = SCHEMA["definitions"]["AgentQualityUnsignedManifestV1"]["properties"]["coverage"][
        "const"
    ]
    manifest = {
        "schema_version": "traigent.agent_quality.unsigned_manifest.v1",
        "base_process_record_unsigned_manifest_digest": v._role_digest(
            _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN,
            _GV_PROCESS_RECORD_BUNDLE["unsigned_manifest"],
        ),
        "scope_binding_digest": declared_plan["scope_binding_digest"],
        "agent_commitment_ref": _GV_AGENT_COMMITMENT_REF,
        "dataset_commitment_ref": _GV_DATASET_COMMITMENT_REF,
        "evaluator_commitment_ref": _GV_EVALUATOR_COMMITMENT_REF,
        "build_definition_commitment_ref": _GV_BUILD_DEFINITION_COMMITMENT_REF,
        "measurement_contract_ref": _GV_MEASUREMENT_CONTRACT_REF,
        "measurement_contract_record_digest": _GV_MEASUREMENT_CONTRACT_RECORD_DIGEST,
        "aggregation_policy": AGGREGATION_POLICY_IDENTITY,
        "objective_registry": OBJECTIVE_REGISTRY_IDENTITY,
        "non_claim_catalog": NON_CLAIM_CATALOG_IDENTITY,
        "quantile_table": QUANTILE_TABLE_IDENTITY,
        "declared_plan_digest": declared_plan["declared_plan_digest"],
        "declared_plan_signature_digest": declared_plan_signature_digest,
        "split_derivation_digest": split_derivation["split_derivation_digest"],
        "evaluation_splits_digest": evaluation_splits_digest,
        "measured_claims_digest": measured_claims_digest,
        "non_certified_selection_estimates_digest": selection_estimates_digest,
        "primary_objective_id": declared_plan["primary_objective_id"],
        "selection_arm_count": declared_plan["selection_arm_count"],
        "holdout_scored_arm_count": declared_plan["holdout_scored_arm_count"],
        # P1-V2.5 commit 2 (S7, row 54): PILLAR_SUPPORT_SHAPE checks
        # bound_commitment_ref against the manifest's OWN real
        # dataset/evaluator commitment refs -- the schema fixture's generic
        # placeholder SHA would fail that real cross-field check, so the
        # golden manifest builds its own pillar_support with the real refs
        # instead of reusing _schema_fixtures._pillar_support() verbatim.
        "pillar_support": [
            dict(entry, bound_commitment_ref=ref)
            for entry, ref in zip(
                _schema_fixtures._pillar_support(),
                (_GV_DATASET_COMMITMENT_REF, _GV_EVALUATOR_COMMITMENT_REF),
                strict=True,
            )
        ],
        "assertion_digest": assertion["assertion_digest"],
        "non_claims_digest": non_claims_digest,
        "agent_quality_claim_support_rows_digest": claim_support_rows_digest,
        "trust_ring_ref": _GV_TRUST_RING_REF,
        "issuer_key_ref": _GV_ISSUER_KEY_REF,
        "issuer_signature_algorithm": "ed25519",
        "coverage": coverage,
    }
    b["unsigned_manifest"] = manifest
    b["signature"] = {
        "schema_version": "traigent.agent_quality.signature.v1",
        "algorithm": "ed25519",
        "issuer_key_ref": _GV_ISSUER_KEY_REF,
        "trust_ring_ref": _GV_TRUST_RING_REF,
        "signed_payload": "unsigned_agent_quality_manifest",
        "unsigned_manifest_digest": _gv_digest("unsigned_manifest", manifest),
        "signature": _gv_sign("issuer_signature", manifest, private_key),
    }
    return b


# Fields ``_gv_close`` regenerates wholesale from the bundle's OTHER content
# (never from these fields' own prior value) -- an override aimed at one of
# them would be silently discarded rather than taking effect (review P1-2).
_GV_REGENERATED_TOP_LEVEL_FIELDS = frozenset({"unsigned_manifest", "signature"})
_GV_REGENERATED_DECLARED_PLAN_FIELDS = frozenset(
    {"split_derivation", "scope_binding_digest", "declared_plan_digest"}
)


def _gv_assert_no_override_on_regenerated_fields(overrides: dict) -> None:
    for field in _GV_REGENERATED_TOP_LEVEL_FIELDS:
        if field in overrides:
            raise AssertionError(
                f"build_agent_quality_bundle(**overrides): {field!r} is regenerated wholesale "
                "by _gv_close and cannot be overridden"
            )
    envelope = overrides.get("declared_plan_envelope")
    if isinstance(envelope, dict):
        if "signature" in envelope:
            raise AssertionError(
                "build_agent_quality_bundle(**overrides): "
                "'declared_plan_envelope.signature' is regenerated wholesale by _gv_close "
                "and cannot be overridden"
            )
        declared_plan = envelope.get("declared_plan")
        if isinstance(declared_plan, dict):
            for field in _GV_REGENERATED_DECLARED_PLAN_FIELDS:
                if field in declared_plan:
                    raise AssertionError(
                        "build_agent_quality_bundle(**overrides): "
                        f"'declared_plan_envelope.declared_plan.{field}' is regenerated "
                        "wholesale by _gv_close and cannot be overridden"
                    )


def build_agent_quality_bundle(**overrides: object) -> dict:
    """Return a schema-valid, digest-consistent, genuinely ed25519-signed
    agent-quality bundle. ``**overrides`` deep-merge onto the raw skeleton
    BEFORE closing, so every digest/signature that depends on an overridden
    value is recomputed, never stale. An override that names a field
    ``_gv_close`` regenerates wholesale (``unsigned_manifest``, ``signature``,
    or the declared plan's ``split_derivation``/``scope_binding_digest``/
    ``declared_plan_digest``/``signature``) raises ``AssertionError`` naming
    the field, instead of being silently discarded (review P1-2)."""
    _gv_assert_no_override_on_regenerated_fields(overrides)
    merged = _gv_merge(_gv_base_bundle(), overrides)
    assert isinstance(merged, dict)
    return _gv_close(merged)


def _gv_bundle_validator() -> Draft7Validator:
    return _schema_validator("AgentQualityCertificateBundleV1")


def _gv_signature_verifies(bundle: dict, public_key: Ed25519PublicKey = _GV_PUBLIC_KEY) -> bool:
    manifest = bundle["unsigned_manifest"]
    if bundle["signature"]["unsigned_manifest_digest"] != _gv_digest("unsigned_manifest", manifest):
        return False
    material = (
        _GV_DOMAINS["issuer_signature"].encode("utf-8")
        + b"\x00"
        + fp2.canonicalize(manifest).encode("utf-8")
    )
    try:
        public_key.verify(base64.b64decode(bundle["signature"]["signature"]), material)
    except InvalidSignature:
        return False
    return True


# --------------------------------------------------------------------------
# Checkpoint (a) -- one deterministic, canonical, digest-consistent, signed
# bundle that reaches the private runner's fail-closed boundary.
# --------------------------------------------------------------------------


def test_golden_bundle_is_schema_valid() -> None:
    bundle = build_agent_quality_bundle()
    errors = list(_gv_bundle_validator().iter_errors(bundle))
    assert errors == [], [(list(e.absolute_path), e.message) for e in errors]


def test_golden_bundle_independently_bound_commitment_refs_are_pairwise_distinct() -> None:
    """review P2-3 -- the five independently-bound refs among the
    ``coverage``-const manifest fields (``agent_commitment_ref``,
    ``dataset_commitment_ref``, ``evaluator_commitment_ref``,
    ``build_definition_commitment_ref``, ``measurement_contract_record_digest``)
    must be pairwise distinct, so a verifier negative that swaps or binds two
    of them together is not a no-op on the golden vector."""
    manifest = build_agent_quality_bundle()["unsigned_manifest"]
    fields = [
        "agent_commitment_ref",
        "dataset_commitment_ref",
        "evaluator_commitment_ref",
        "build_definition_commitment_ref",
        "measurement_contract_record_digest",
    ]
    values = [manifest[f] for f in fields]
    assert len(set(values)) == len(values), dict(zip(fields, values, strict=True))


def test_build_agent_quality_bundle_rejects_overrides_on_regenerated_fields() -> None:
    """review P1-2 closure -- an override aimed at a field ``_gv_close``
    regenerates wholesale from the bundle's other content must fail loudly,
    one probe per regenerated block, instead of being silently discarded."""
    with pytest.raises(AssertionError, match="unsigned_manifest"):
        build_agent_quality_bundle(unsigned_manifest={"issuer_key_ref": "issuerkey:bbbbbbbb"})
    with pytest.raises(AssertionError, match="'signature'"):
        build_agent_quality_bundle(signature={"algorithm": "ed25519ph"})
    with pytest.raises(
        AssertionError, match=r"declared_plan_envelope\.declared_plan\.split_derivation"
    ):
        build_agent_quality_bundle(
            declared_plan_envelope={
                "declared_plan": {"split_derivation": {"evaluated_universe_item_count": 999}}
            }
        )
    with pytest.raises(
        AssertionError, match=r"declared_plan_envelope\.declared_plan\.scope_binding_digest"
    ):
        build_agent_quality_bundle(
            declared_plan_envelope={"declared_plan": {"scope_binding_digest": _GV_SHA}}
        )
    with pytest.raises(AssertionError, match=r"declared_plan_envelope\.signature"):
        build_agent_quality_bundle(
            declared_plan_envelope={"signature": {"signature": "A" * 85 + "A=="}}
        )


_GV_DIGEST_COVERAGE_CASES = [
    ("assertion", "assertion_digest", "assertion"),
    ("split_derivation", "split_derivation_digest", "split_derivation"),
    ("evaluation_splits", "evaluation_splits_digest", "evaluation_splits"),
    ("measured_claims", "measured_claims_digest", "measured_claims"),
    (
        "non_certified_selection_estimates",
        "non_certified_selection_estimates_digest",
        "selection_estimates",
    ),
    ("non_claims", "non_claims_digest", "non_claims"),
    ("claim_support_rows", "agent_quality_claim_support_rows_digest", "claim_support_rows"),
]


@pytest.mark.parametrize(
    "array_name,manifest_field,domain_role",
    _GV_DIGEST_COVERAGE_CASES,
    ids=[c[0] for c in _GV_DIGEST_COVERAGE_CASES],
)
def test_golden_bundle_digests_recompute(
    array_name: str, manifest_field: str, domain_role: str
) -> None:
    """Every ``*_digest`` field in ``unsigned_manifest`` that covers one of
    the seven signed arrays/projections (design rows 56-62) equals
    :func:`v._role_digest` recomputed from the bundle's own array under the
    domain the schema's own ``AgentQualityDigestDomainRegistryV1``
    registers for it -- one parametrized case per field, so a single
    mismatched field cannot hide behind seven others that still match."""
    bundle = build_agent_quality_bundle()
    projection = bundle[array_name]
    if array_name in ("assertion", "split_derivation"):
        self_field = manifest_field
        projection = v._strip_self_digest(projection, self_field)
    assert bundle["unsigned_manifest"][manifest_field] == v._role_digest(
        _GV_DOMAINS[domain_role], projection
    )


def test_golden_bundle_scope_binding_and_process_record_digests_recompute() -> None:
    """The two manifest digests that are NOT one of the seven signed
    arrays/projections: ``base_process_record_unsigned_manifest_digest``
    (over :data:`_GV_PROCESS_RECORD_BUNDLE`'s own real, schema-valid
    unsigned manifest) and ``scope_binding_digest`` (over
    ``ScopeBindingProjectionV1`` built from the same project/build-session
    refs :func:`build_agent_quality_context` uses)."""
    bundle = build_agent_quality_bundle()
    manifest = bundle["unsigned_manifest"]
    assert manifest["base_process_record_unsigned_manifest_digest"] == v._role_digest(
        _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN, _GV_PROCESS_RECORD_BUNDLE["unsigned_manifest"]
    )
    assert manifest["scope_binding_digest"] == _gv_digest(
        "scope_binding",
        {
            "schema_version": _GV_DOMAINS["scope_binding"],
            "project_ref": _GV_PROJECT_REF,
            "build_session_ref": _GV_BUILD_SESSION_REF,
        },
    )


def test_process_record_unsigned_manifest_domain_pinned_to_sibling_authority() -> None:
    """P1-V2.2 review P2-3 closure: the `.2` review found this constant a
    closed loop -- the module's own copy and this test file's mirror of it
    agreed with each other by construction, with nothing tying either to the
    actual authority. This is the missing tie: if
    ``process_record_verifier._UNSIGNED_MANIFEST_DOMAIN`` is ever renamed or
    re-versioned, this fails loudly instead of both sides silently drifting
    onto a stale preimage domain that still agrees with itself."""
    assert (
        v._PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN
        == _prv.pr_impl._UNSIGNED_MANIFEST_DOMAIN.decode()
    )


def test_golden_bundle_issuer_signature_verifies() -> None:
    bundle = build_agent_quality_bundle()
    assert _gv_signature_verifies(bundle)


def test_golden_bundle_issuer_signature_rejects_a_flipped_manifest_byte() -> None:
    """Negative counterpart -- proves the positive verification above is not
    vacuous: flipping one byte of the canonical manifest makes verification
    fail."""
    bundle = build_agent_quality_bundle()
    manifest = bundle["unsigned_manifest"]
    canonical = fp2.canonicalize(manifest)
    flipped = (canonical[:-2] + ("0" if canonical[-2] != "0" else "1") + canonical[-1:]).encode(
        "utf-8"
    )
    material = _GV_DOMAINS["issuer_signature"].encode("utf-8") + b"\x00" + flipped
    with pytest.raises(InvalidSignature):
        _GV_PUBLIC_KEY.verify(base64.b64decode(bundle["signature"]["signature"]), material)


def test_golden_declared_plan_digests_and_signature() -> None:
    bundle = build_agent_quality_bundle()
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    signature = bundle["declared_plan_envelope"]["signature"]
    assert declared_plan["declared_plan_digest"] == _gv_digest(
        "declared_plan", v._strip_self_digest(declared_plan, "declared_plan_digest")
    )
    assert signature["declared_plan_digest"] == declared_plan["declared_plan_digest"]
    assert (
        bundle["unsigned_manifest"]["declared_plan_digest"] == declared_plan["declared_plan_digest"]
    )
    assert bundle["unsigned_manifest"]["declared_plan_signature_digest"] == _gv_digest(
        "declared_plan_signature", signature
    )
    material = (
        _GV_DOMAINS["declared_plan_signature"].encode("utf-8")
        + b"\x00"
        + fp2.canonicalize(declared_plan).encode("utf-8")
    )
    _GV_PUBLIC_KEY.verify(base64.b64decode(signature["signature"]), material)


def test_golden_measured_claim_recomputes() -> None:
    """The golden ``measured_claims`` row's interval endpoints equal
    :func:`v._wilson_bounds` from the printed sufficient statistics, and the
    split arithmetic (holdout item count vs. the claim's own sample_size,
    selection+holdout summing to the declared universe) is internally
    consistent. A second, distinct interval-method vector
    (``student_t_normal_approx_v1``) is included because
    ``EmittableObjectiveIdV1``/the shipped ``ObjectiveRegistry`` package
    document register ``obj.accuracy.evaluator_score_mean.v1`` as a
    ``bounded_mean`` objective, a first-class vector distinct from the
    binary-rate/Wilson one -- so a golden vector with only Wilson coverage
    would never exercise :func:`v._student_t_half_width` at all."""
    bundle = build_agent_quality_bundle()
    wilson_claim, student_t_claim = bundle["measured_claims"]

    stats = wilson_claim["sufficient_statistics"]
    successes, trials = stats["success_count"], stats["trial_count"]
    coverage_ppm = wilson_claim["nominal_coverage_ppm"]
    assert wilson_claim["point_estimate"] == v._wilson_point(successes, trials)
    low, high = v._wilson_bounds(successes, trials, coverage_ppm)
    assert (wilson_claim["interval_low"], wilson_claim["interval_high"]) == (low, high)
    assert wilson_claim["sample_size"] == trials

    t_stats = student_t_claim["sufficient_statistics"]
    half_width = v._student_t_half_width(
        mean_fixed=t_stats["mean_fixed"],
        sample_stddev_fixed=t_stats["sample_stddev_fixed"],
        sample_count=t_stats["sample_count"],
        coverage_ppm=student_t_claim["nominal_coverage_ppm"],
        unit_scale=t_stats["unit_scale"],
    )
    assert student_t_claim["point_estimate"] == t_stats["mean_fixed"]
    assert student_t_claim["interval_low"] == t_stats["mean_fixed"] - half_width
    assert student_t_claim["interval_high"] == t_stats["mean_fixed"] + half_width
    assert student_t_claim["sample_size"] == t_stats["sample_count"]

    split_derivation = bundle["split_derivation"]
    selection_count, holdout_count = (
        record["item_count"] for record in bundle["evaluation_splits"]
    )
    assert selection_count + holdout_count == split_derivation["evaluated_universe_item_count"]
    assert wilson_claim["evaluated_split_id"] == "holdout"
    assert student_t_claim["evaluated_split_id"] == "holdout"
    assert wilson_claim["sample_size"] == holdout_count


def test_golden_registry_identities_match_package_data() -> None:
    """``aggregation_policy``/``objective_registry``/``non_claim_catalog``/
    ``quantile_table`` identities carry the SHIPPED package documents'
    ids/versions/digests, and ``non_claims`` is the shipped catalogue's
    fixed tuple in order."""
    bundle = build_agent_quality_bundle()
    manifest = bundle["unsigned_manifest"]
    for stem, field, identity in (
        ("aggregation_policy", "aggregation_policy", AGGREGATION_POLICY_IDENTITY),
        ("objective_registry", "objective_registry", OBJECTIVE_REGISTRY_IDENTITY),
        ("non_claim_catalog", "non_claim_catalog", NON_CLAIM_CATALOG_IDENTITY),
        ("quantile_table", "quantile_table", QUANTILE_TABLE_IDENTITY),
    ):
        document = v._load_agent_quality_document(stem)
        expected_digest = v._role_digest(v._AGENT_QUALITY_REGISTRY_DOMAINS[stem], document)
        assert manifest[field] == identity
        assert list(identity.values())[-1] == expected_digest
    assert bundle["non_claims"] == _schema_fixtures._non_claims()


def test_golden_bundle_passes_every_stage_directly() -> None:
    """P1-V2.4 commit 2 retarget (sanctioned by the packet brief) of the
    former ``test_golden_bundle_reaches_private_runner_fail_closed_boundary``:
    every stage is now real, so there is no placeholder boundary left for
    the golden bundle to "reach" -- it passes every one of the eight
    stages. This calls each stage directly, in order, so a failure here
    pinpoints exactly WHICH stage rejected the golden bundle, complementing
    :func:`test_run_agent_quality_checks_returns_the_golden_verified_result`'s
    single full-runner assertion."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s1_structural(bundle, context)
    v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    v._stage_s3_registry_identity(bundle, context)
    v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    v._stage_s5_objective_measurement(bundle, context)
    v._stage_s6_splits_held_out(bundle, context)
    v._stage_s7_composition_abstention(bundle, context)
    v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_golden_builders_are_deterministic() -> None:
    first = fp2.canonicalize(build_agent_quality_bundle())
    second = fp2.canonicalize(build_agent_quality_bundle())
    assert first == second


def build_abstained_agent_quality_bundle(**overrides: object) -> dict:
    """The abstained counterpart: ``claim_support_rows[0].evidence_basis`` is
    the abstained value with its required abstention code,
    ``measured_claims`` and ``non_certified_selection_estimates`` are EMPTY
    (the schema's ``else`` branch -- see
    ``test_abstained_bundle_carries_claims_is_schema_preempted``), and every
    digest is still recomputed and signed."""
    base_overrides: dict[str, object] = {
        "measured_claims": [],
        "non_certified_selection_estimates": [],
        "claim_support_rows": [
            {
                "claim_id": "AQ1",
                "evidence_basis": "abstained",
                "abstention_code": "verifier_not_run_or_not_pass",
            }
        ],
    }
    base_overrides.update(overrides)
    return build_agent_quality_bundle(**base_overrides)


def resign_declared_plan(bundle: dict, *, private_key: Ed25519PrivateKey = _GV_PRIVATE_KEY) -> dict:
    """Recompute the declared plan's own digest and re-sign it, in place on
    a deep copy, WITHOUT touching anything else (the caller is responsible
    for calling :func:`resign_agent_quality_bundle` afterward if the
    declared-plan digest feeding the top-level manifest must also move)."""
    b = _gv_copy.deepcopy(bundle)
    declared_plan = b["declared_plan_envelope"]["declared_plan"]
    declared_plan["declared_plan_digest"] = _gv_digest(
        "declared_plan", v._strip_self_digest(declared_plan, "declared_plan_digest")
    )
    signature = b["declared_plan_envelope"]["signature"]
    signature["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    signature["signature"] = _gv_sign("declared_plan_signature", declared_plan, private_key)
    return b


def resign_agent_quality_bundle(
    bundle: dict, *, private_key: Ed25519PrivateKey = _GV_PRIVATE_KEY
) -> dict:
    """Recompute EVERY manifest digest from ``bundle``'s own arrays, then
    the manifest digest, then the issuer signature -- restoring full
    consistency after ANY direct mutation to a signed array or projection.
    Implemented as ``_gv_close`` re-run over the bundle's current content
    (rather than a smaller patch), so it is correct regardless of WHICH of
    the seven signed arrays/projections was mutated."""
    return _gv_close(resign_declared_plan(bundle, private_key=private_key), private_key=private_key)


def resign_with_foreign_key(bundle: dict, key: Ed25519PrivateKey) -> dict:
    """Produce a structurally valid bundle whose top-level issuer signature
    verifies under ``key``'s public key and NOT under the golden
    :data:`_GV_PUBLIC_KEY` -- the fixture packets .2/.3 use to separate
    ``KEY_RING_MISMATCH`` (issuer_key_ref/trust_ring_ref/algorithm mismatch)
    from ``ISSUER_SIGNATURE_INVALID`` (right identity, wrong key). The
    declared-plan signature is left signed by the golden key -- only the
    TOP-LEVEL issuer signature is re-signed under the foreign key, since
    that is the one binding this fixture exercises."""
    return resign_agent_quality_bundle(bundle, private_key=key)


_GV_ALL_SPLIT_DERIVATION_SELF_DIGEST_TARGETS = frozenset(
    {"split_derivation", "selection", "holdout", "declared_plan"}
)


def _gv_reclose_after_free_split_derivation_self_digest(
    bundle: dict,
    foreign_digest: str,
    *,
    targets: frozenset[str] = _GV_ALL_SPLIT_DERIVATION_SELF_DIGEST_TARGETS,
) -> dict:
    """P1-V2.5 review P1-1: produce a fully re-signed, schema-valid bundle
    whose self-reported ``split_derivation_digest`` copies named in
    ``targets`` (any of ``"split_derivation"`` -- the top-level
    declaration's own field --, ``"selection"``/``"holdout"`` -- the two
    ``evaluation_splits`` records --, and ``"declared_plan"`` -- the
    declared plan's embedded copy) all report ``foreign_digest`` -- a value
    that does NOT match the role-digest recomputation over the split
    derivation's own (unchanged) content -- while every other manifest-bound
    digest and the issuer signature stay genuinely consistent. Unlike
    :func:`resign_agent_quality_bundle` (whose ``_gv_close`` unconditionally
    re-syncs every copy to the correct recomputation, which would silently
    repair exactly the defect this builds), this recomputes only the
    digests that depend on the mutated content -- ``evaluation_splits_digest``,
    the declared plan's own digest/signature, and everything chained from
    those -- leaving ``unsigned_manifest.split_derivation_digest`` at its
    correct value (computed over the split derivation's STRIPPED content,
    which a self-field mutation never touches)."""
    b = _gv_copy.deepcopy(resign_agent_quality_bundle(bundle))
    split_derivation = b["split_derivation"]
    correct_digest = split_derivation["split_derivation_digest"]
    if "split_derivation" in targets:
        split_derivation["split_derivation_digest"] = foreign_digest
    b["evaluation_splits"][0]["split_derivation_digest"] = (
        foreign_digest if "selection" in targets else correct_digest
    )
    b["evaluation_splits"][1]["split_derivation_digest"] = (
        foreign_digest if "holdout" in targets else correct_digest
    )
    declared_plan = b["declared_plan_envelope"]["declared_plan"]
    declared_plan["split_derivation"] = dict(
        v._strip_self_digest(bundle["split_derivation"], "split_derivation_digest"),
        split_derivation_digest=(foreign_digest if "declared_plan" in targets else correct_digest),
    )

    evaluation_splits_digest = _gv_digest("evaluation_splits", b["evaluation_splits"])
    declared_plan["declared_plan_digest"] = _gv_digest(
        "declared_plan", v._strip_self_digest(declared_plan, "declared_plan_digest")
    )
    plan_signature = b["declared_plan_envelope"]["signature"]
    plan_signature["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    plan_signature["signature"] = _gv_sign(
        "declared_plan_signature", declared_plan, _GV_PRIVATE_KEY
    )
    declared_plan_signature_digest = _gv_digest("declared_plan_signature", plan_signature)

    manifest = b["unsigned_manifest"]
    manifest["evaluation_splits_digest"] = evaluation_splits_digest
    manifest["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    manifest["declared_plan_signature_digest"] = declared_plan_signature_digest
    for row in b["claim_support_rows"]:
        if row.get("evidence_basis") == "abstained":
            continue
        row["evaluation_splits_digest"] = evaluation_splits_digest
        row["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    manifest["agent_quality_claim_support_rows_digest"] = _gv_digest(
        "claim_support_rows", b["claim_support_rows"]
    )
    b["signature"]["unsigned_manifest_digest"] = _gv_digest("unsigned_manifest", manifest)
    b["signature"]["signature"] = _gv_sign("issuer_signature", manifest, _GV_PRIVATE_KEY)
    return b


def _gv_reclose_declared_plan_split_derivation(
    bundle: dict, foreign_split_derivation: dict, *, digest: str | None = None
) -> dict:
    """P1-V2.5 review P1-1's second probe: re-close a bundle whose declared
    plan pre-registers a DIFFERENT split derivation from the one the bundle
    actually ships -- the shipped ``split_derivation``/``evaluation_splits``
    are left untouched, so ``unsigned_manifest.split_derivation_digest`` and
    everything chained from the SHIPPED derivation stay correct; only the
    declared plan's own digest/signature and the manifest fields chained
    from THAT are recomputed.

    ``digest`` controls what the declared plan's embedded
    ``split_derivation_digest`` reports: by default (``None``) it is a
    genuine recomputation over ``foreign_split_derivation``'s own content,
    so BOTH the digest-equality and content-equality halves of row 44's
    check disagree with the shipped derivation. P1-V2.5-fix review P2-A:
    passing the shipped digest Y explicitly isolates the content-equality
    clause alone -- the digest clause then agrees (declared_digest ==
    recomputed_split_derivation_digest == Y) and only
    ``declared_plan["split_derivation"] != split_derivation`` can fire."""
    b = _gv_copy.deepcopy(resign_agent_quality_bundle(bundle))
    declared_plan = b["declared_plan_envelope"]["declared_plan"]
    new_split_derivation = dict(foreign_split_derivation)
    new_split_derivation["split_derivation_digest"] = (
        digest
        if digest is not None
        else _gv_digest(
            "split_derivation",
            v._strip_self_digest(new_split_derivation, "split_derivation_digest"),
        )
    )
    declared_plan["split_derivation"] = new_split_derivation
    declared_plan["declared_plan_digest"] = _gv_digest(
        "declared_plan", v._strip_self_digest(declared_plan, "declared_plan_digest")
    )
    plan_signature = b["declared_plan_envelope"]["signature"]
    plan_signature["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    plan_signature["signature"] = _gv_sign(
        "declared_plan_signature", declared_plan, _GV_PRIVATE_KEY
    )
    declared_plan_signature_digest = _gv_digest("declared_plan_signature", plan_signature)

    manifest = b["unsigned_manifest"]
    manifest["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    manifest["declared_plan_signature_digest"] = declared_plan_signature_digest
    for row in b["claim_support_rows"]:
        if row.get("evidence_basis") == "abstained":
            continue
        row["declared_plan_digest"] = declared_plan["declared_plan_digest"]
    manifest["agent_quality_claim_support_rows_digest"] = _gv_digest(
        "claim_support_rows", b["claim_support_rows"]
    )
    b["signature"]["unsigned_manifest_digest"] = _gv_digest("unsigned_manifest", manifest)
    b["signature"]["signature"] = _gv_sign("issuer_signature", manifest, _GV_PRIVATE_KEY)
    return b


def _gv_reclose_after_manifest_field_mutation(
    bundle: dict, mutate_manifest: Callable[[dict], None]
) -> dict:
    """P1-V2.5 review P2-4: mutate a field that lives directly on
    ``unsigned_manifest`` (``pillar_support``, ``assertion_digest``, and
    similar top-level manifest fields that are not one of S8's six
    separately-digested arrays) and re-sign the ISSUER signature over the
    mutated manifest, so the resulting bundle is genuinely, validly signed
    -- unlike overwriting the field post-``build_agent_quality_bundle``
    with no re-sign at all, which leaves the top-level signature broken and
    only proves the target stage runs before S8, not that it catches a
    truly well-formed negative."""
    b = _gv_copy.deepcopy(resign_agent_quality_bundle(bundle))
    manifest = b["unsigned_manifest"]
    mutate_manifest(manifest)
    b["signature"]["unsigned_manifest_digest"] = _gv_digest("unsigned_manifest", manifest)
    b["signature"]["signature"] = _gv_sign("issuer_signature", manifest, _GV_PRIVATE_KEY)
    return b


# --------------------------------------------------------------------------
# Checkpoint (b) -- mutation-plus-re-sign harness, abstained counterpart,
# foreign-key signer.
# --------------------------------------------------------------------------


def _gv_mutate_last_hex_char(value: str) -> str:
    last = value[-1]
    replacement = "0" if last != "0" else "1"
    return value[:-1] + replacement


def _gv_mutate_assertion(bundle: dict) -> dict:
    bundle["assertion"]["aggregation_policy"]["policy_digest"] = _gv_mutate_last_hex_char(
        bundle["assertion"]["aggregation_policy"]["policy_digest"]
    )
    return bundle


def _gv_mutate_split_derivation(bundle: dict) -> dict:
    bundle["split_derivation"]["dataset_commitment_ref"] = _gv_mutate_last_hex_char(
        bundle["split_derivation"]["dataset_commitment_ref"]
    )
    return bundle


def _gv_mutate_evaluation_splits(bundle: dict) -> dict:
    bundle["evaluation_splits"][0]["split_commitment_digest"] = _gv_mutate_last_hex_char(
        bundle["evaluation_splits"][0]["split_commitment_digest"]
    )
    return bundle


def _gv_mutate_measured_claims(bundle: dict) -> dict:
    bundle["measured_claims"][0]["measurement_contract_record_digest"] = _gv_mutate_last_hex_char(
        bundle["measured_claims"][0]["measurement_contract_record_digest"]
    )
    return bundle


def _gv_mutate_selection_estimates(bundle: dict) -> dict:
    bundle["non_certified_selection_estimates"][0]["point_estimate"] += 1
    return bundle


def _gv_mutate_non_claims(bundle: dict) -> dict:
    # AgentQualityNonClaimV1 is entirely const (record_type, non_claim_id,
    # reason_template_id are all consts pinned per array index by
    # AgentQualityNonClaimsFixedTupleV1), so there is no freely-valued byte
    # to flip while staying schema-valid -- this mutation, unlike the other
    # six, is EXPECTED to leave the bundle schema-invalid even after
    # resigning. See test_resign_restores_consistency_after_each_signed_array_mutation's
    # per-case ``expect_schema_valid_after_resign=False`` for this array.
    # The replacement value is index 1's OWN valid non_claim_id -- a real
    # AgentQualityNonClaimV1.non_claim_id enum member -- so the mutation
    # trips ONLY index 0's fixed-tuple ``const`` (review P2-4); an
    # out-of-enum string would also trip the base definition's ``enum``
    # check and the resulting two-error shape can't be pinned to one path.
    bundle["non_claims"][0]["non_claim_id"] = "NCQ_NO_EXPANDED_EVALUATION"
    return bundle


def _gv_mutate_claim_support_rows(bundle: dict) -> dict:
    bundle["claim_support_rows"][0]["verifier_result"] = "fail"
    return bundle


def _gv_mutated_field_assertion(b: dict) -> object:
    return b["assertion"]["aggregation_policy"]["policy_digest"]


def _gv_mutated_field_split_derivation(b: dict) -> object:
    return b["split_derivation"]["dataset_commitment_ref"]


def _gv_mutated_field_evaluation_splits(b: dict) -> object:
    return b["evaluation_splits"][0]["split_commitment_digest"]


def _gv_mutated_field_measured_claims(b: dict) -> object:
    return b["measured_claims"][0]["measurement_contract_record_digest"]


def _gv_mutated_field_selection_estimates(b: dict) -> object:
    return b["non_certified_selection_estimates"][0]["point_estimate"]


def _gv_mutated_field_non_claims(b: dict) -> object:
    return b["non_claims"][0]["non_claim_id"]


def _gv_mutated_field_claim_support_rows(b: dict) -> object:
    return b["claim_support_rows"][0]["verifier_result"]


_GV_MUTATION_CASES = [
    (
        "assertion",
        "assertion_digest",
        "assertion",
        _gv_mutate_assertion,
        True,
        {},
        _gv_mutated_field_assertion,
        None,
    ),
    (
        "split_derivation",
        "split_derivation_digest",
        "split_derivation",
        _gv_mutate_split_derivation,
        True,
        {},
        _gv_mutated_field_split_derivation,
        None,
    ),
    (
        "evaluation_splits",
        "evaluation_splits_digest",
        "evaluation_splits",
        _gv_mutate_evaluation_splits,
        True,
        {},
        _gv_mutated_field_evaluation_splits,
        None,
    ),
    (
        "measured_claims",
        "measured_claims_digest",
        "measured_claims",
        _gv_mutate_measured_claims,
        True,
        {},
        _gv_mutated_field_measured_claims,
        None,
    ),
    (
        "non_certified_selection_estimates",
        "non_certified_selection_estimates_digest",
        "selection_estimates",
        _gv_mutate_selection_estimates,
        True,
        {"non_certified_selection_estimates": [_schema_fixtures._selection_estimate()]},
        _gv_mutated_field_selection_estimates,
        None,
    ),
    (
        "non_claims",
        "non_claims_digest",
        "non_claims",
        _gv_mutate_non_claims,
        False,
        {},
        _gv_mutated_field_non_claims,
        [1, "properties", "non_claim_id", "const"],
    ),
    (
        "claim_support_rows",
        "agent_quality_claim_support_rows_digest",
        "claim_support_rows",
        _gv_mutate_claim_support_rows,
        # verifier_result="fail" is itself schema-invalid (the schema pins
        # a non-abstained row's verifier_result to the const "pass") -- now
        # that resign preserves content instead of reverting it (review
        # P1-1), the honest post-resign state for THIS mutation is invalid,
        # same shape as non_claims.
        False,
        {},
        _gv_mutated_field_claim_support_rows,
        ["properties", "verifier_result", "const"],
    ),
]


@pytest.mark.parametrize(
    "array_name,manifest_field,domain_role,mutate,expect_schema_valid_after_resign,overrides,"
    "mutated_field,invalid_schema_path_suffix",
    _GV_MUTATION_CASES,
    ids=[c[0] for c in _GV_MUTATION_CASES],
)
def test_resign_restores_consistency_after_each_signed_array_mutation(
    array_name: str,
    manifest_field: str,
    domain_role: str,
    mutate,
    expect_schema_valid_after_resign: bool,
    overrides: dict,
    mutated_field,
    invalid_schema_path_suffix: list,
) -> None:
    """checkpoint (b).1 -- the harness every later negative test depends on.
    For EACH of the seven signed arrays/projections separately: mutate one
    byte, assert (i) the corresponding digest no longer recomputes, (ii) the
    signature no longer verifies against the mutated manifest, (iii) after
    :func:`resign_agent_quality_bundle` both hold again, (iv) the bundle is
    still schema-valid (except ``non_claims`` and ``claim_support_rows``,
    whose mutations are themselves schema-invalid regardless of resign --
    see :func:`_gv_mutate_non_claims` / :func:`_gv_mutate_claim_support_rows`),
    and (v) the resign is a genuine re-SIGN, not a re-CLOSE-by-reverting
    (review P1-1): the mutated field still holds its mutated value, and the
    resigned bundle is not byte-identical to the original golden bundle."""
    bundle = build_agent_quality_bundle(**overrides)
    mutated = mutate(_gv_copy.deepcopy(bundle))
    mutated_value = mutated_field(mutated)

    recomputed = (
        v._strip_self_digest(mutated[array_name], manifest_field)
        if array_name in ("assertion", "split_derivation")
        else mutated[array_name]
    )
    assert mutated["unsigned_manifest"][manifest_field] != v._role_digest(
        _GV_DOMAINS[domain_role], recomputed
    ), "(i) the digest must no longer recompute after the mutation"

    patched_manifest = dict(mutated["unsigned_manifest"])
    patched_manifest[manifest_field] = v._role_digest(_GV_DOMAINS[domain_role], recomputed)
    material = (
        _GV_DOMAINS["issuer_signature"].encode("utf-8")
        + b"\x00"
        + fp2.canonicalize(patched_manifest).encode("utf-8")
    )
    with pytest.raises(InvalidSignature):
        _GV_PUBLIC_KEY.verify(base64.b64decode(mutated["signature"]["signature"]), material)

    resigned = resign_agent_quality_bundle(mutated)
    assert resigned["unsigned_manifest"][manifest_field] == v._role_digest(
        _GV_DOMAINS[domain_role],
        v._strip_self_digest(resigned[array_name], manifest_field)
        if array_name in ("assertion", "split_derivation")
        else resigned[array_name],
    ), "(iii) the digest must recompute again after resigning"
    assert _gv_signature_verifies(resigned), "(iii) the signature must verify again after resigning"

    assert mutated_field(resigned) == mutated_value, (
        "(v) resign must recompute digests/signatures over the CURRENT content, "
        "not revert the mutated field back to the golden bundle's value"
    )
    assert fp2.canonicalize(resigned) != fp2.canonicalize(bundle), (
        "(v) a resigned, mutated bundle must not be byte-identical to the original golden bundle"
    )

    errors = list(_gv_bundle_validator().iter_errors(resigned))
    if expect_schema_valid_after_resign:
        assert errors == [], [(list(e.absolute_path), e.message) for e in errors]
    else:
        assert len(errors) == 1, [(list(e.absolute_path), e.message) for e in errors]
        suffix_len = len(invalid_schema_path_suffix)
        assert list(errors[0].absolute_schema_path)[-suffix_len:] == invalid_schema_path_suffix, (
            list(errors[0].absolute_schema_path)
        )
        assert errors[0].validator == "const"


def test_abstained_golden_bundle_is_schema_valid_and_signed() -> None:
    bundle = build_abstained_agent_quality_bundle()
    errors = list(_gv_bundle_validator().iter_errors(bundle))
    assert errors == [], [(list(e.absolute_path), e.message) for e in errors]
    assert _gv_signature_verifies(bundle)
    row = bundle["claim_support_rows"][0]
    assert row["evidence_basis"] == "abstained"
    assert row["abstention_code"] == "verifier_not_run_or_not_pass"
    assert bundle["measured_claims"] == []
    assert bundle["non_certified_selection_estimates"] == []


def test_abstained_golden_bundle_coupling_control() -> None:
    """The SAME abstained bundle, with one measured claim added, is
    schema-INVALID with the error path naming the coupling -- proving the
    abstained vector sits exactly on the ``if/then/else`` boundary (mirrors
    ``test_abstained_bundle_carries_claims_is_schema_preempted``'s
    control)."""
    coupled = build_abstained_agent_quality_bundle(
        measured_claims=[_schema_fixtures._wilson_claim()]
    )
    errors = list(_gv_bundle_validator().iter_errors(coupled))
    assert len(errors) == 1
    assert list(errors[0].absolute_schema_path)[-4:] == [
        "else",
        "properties",
        "measured_claims",
        "maxItems",
    ]


def test_abstained_golden_bundle_returns_the_abstained_result_when_accepted() -> None:
    """P1-V2.4 commit 2 retarget (sanctioned by the packet brief) of the
    former ``test_abstained_golden_bundle_reaches_private_runner_fail_closed_boundary``:
    the abstained golden bundle is schema-valid and genuinely bound to the
    real process record, passes S1-S4, vacuously passes S5/S6 (its
    ``measured_claims``/``non_certified_selection_estimates`` are both
    forced empty by the abstention coupling), and now S7 accepts it (row
    53: the caller's ``accept_abstained_bundle=True`` permits a non-
    ``issuer_verified`` row) -- so the runner returns a genuine ABSTAINED
    :class:`v.AgentQualityVerificationResult`, per row 53's second half."""
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    result = v._run_agent_quality_checks(
        bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert result.code == "AGENT_QUALITY_CLAIM_ABSTAINED"
    assert result.evidence_basis == "abstained"
    assert result.claim_id == "AQ1"
    assert result.interval_verification_level == "issuer_attested_v1"
    assert result.split_verification_level == "issuer_attested_v1"
    assert result.holdout_item_count == 200
    assert result.dataset_condition_code == "dataset_certificate_not_verified"
    assert result.evaluator_condition_code == "evaluator_certificate_not_verified"


def test_abstained_golden_bundle_claim_not_verified_when_not_accepted() -> None:
    """Row 53's first half: the SAME abstained bundle, with a caller that
    does NOT set ``accept_abstained_bundle`` -- S7 refuses it outright,
    never reaching a result at all."""
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=False)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "CLAIM_NOT_VERIFIED"
    assert caught.value.field == "claim_support_rows"


def test_resign_with_foreign_key_produces_a_mismatched_but_valid_signature() -> None:
    """checkpoint (b).3 -- a structurally valid signature by a key NOT in
    the key ring: verifies under the foreign public key, fails under the
    golden one. Packets .2/.3 use this to separate ``KEY_RING_MISMATCH``
    from ``ISSUER_SIGNATURE_INVALID``."""
    bundle = build_agent_quality_bundle()
    foreign = resign_with_foreign_key(bundle, _GV_FOREIGN_PRIVATE_KEY)
    assert _gv_signature_verifies(foreign, public_key=_GV_FOREIGN_PRIVATE_KEY.public_key())
    assert not _gv_signature_verifies(foreign, public_key=_GV_PUBLIC_KEY)
    errors = list(_gv_bundle_validator().iter_errors(foreign))
    assert errors == []


# ==========================================================================
# P1-V2.2 -- S8 real checks, fixture family B: golden, canonical, SIGNED,
# mutate-then-resign. Reuses build_agent_quality_bundle/
# build_abstained_agent_quality_bundle/resign_agent_quality_bundle/
# resign_with_foreign_key from checkpoint (a)/(b) above -- this is the
# harness those checkpoints exist to feed.
# ==========================================================================


def _gv_resign_manifest_and_signature_only(
    bundle: dict, *, private_key: Ed25519PrivateKey = _GV_PRIVATE_KEY
) -> dict:
    """Recompute ONLY ``signature.unsigned_manifest_digest`` and the top-level
    issuer signature from ``bundle["unsigned_manifest"]`` AS IT STANDS --
    unlike :func:`resign_agent_quality_bundle` (built on ``_gv_close``, which
    always overwrites every manifest field, including
    ``agent_quality_claim_support_rows_digest``, from the bundle's OTHER
    content), this lets a caller hand-patch one manifest field to a value
    that intentionally disagrees with the array it is supposed to cover, re-
    seal the envelope around that patched value, and prove S8's row-63/64
    check -- not row 57-62's digest recompute -- is what catches it."""
    b = _gv_copy.deepcopy(bundle)
    manifest = b["unsigned_manifest"]
    b["signature"]["unsigned_manifest_digest"] = _gv_digest("unsigned_manifest", manifest)
    material = (
        _GV_DOMAINS["issuer_signature"].encode("utf-8")
        + b"\x00"
        + fp2.canonicalize(manifest).encode("utf-8")
    )
    b["signature"]["signature"] = base64.b64encode(private_key.sign(material)).decode("ascii")
    return b


def test_golden_bundle_passes_s8_directly() -> None:
    """The golden, family-B bundle is exactly what S8's real checks are
    supposed to PASS -- called directly (bypassing S1-S7) with the real
    :data:`_GV_PROCESS_RECORD_BUNDLE`."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_abstained_golden_bundle_passes_s8_directly() -> None:
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_stage_s8_manifest_digests_signature_is_a_real_fail_closed_function() -> None:
    """S8's counterpart to
    :func:`test_stage_s1_structural_is_a_real_fail_closed_function`: called
    directly on a bundle whose ``split_derivation_digest`` no longer
    recomputes, it raises the real code, not the catch-all."""
    bundle = _gv_mutate_split_derivation(build_agent_quality_bundle())
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SPLIT_DERIVATION_DIGEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


def test_family_b_golden_bundle_result_is_independent_across_separately_built_bundles() -> None:
    """P1-V2.4 commit 2 retarget (sanctioned by the packet brief) of the
    former ``test_family_b_golden_bundle_reaches_s7_not_s8_through_full_runner``:
    there is no S7/S8 boundary left to reach -- every stage is real, and
    the family-B golden bundle now verifies end to end. Converted into a
    stronger determinism proof than
    :func:`test_run_agent_quality_checks_golden_path_is_deterministic`
    (which re-runs the SAME bundle object): two INDEPENDENTLY built golden
    bundles -- fresh dict trees from separate
    :func:`build_agent_quality_bundle` calls -- must verify to an EQUAL
    result, proving the runner carries no hidden shared mutable state
    across calls."""
    context = build_agent_quality_context()
    first_bundle = build_agent_quality_bundle()
    second_bundle = build_agent_quality_bundle()
    assert first_bundle is not second_bundle
    first_result = v._run_agent_quality_checks(
        first_bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    second_result = v._run_agent_quality_checks(
        second_bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
    )
    assert first_result == second_result


# Rows 57-62 -- one parametrized case per signed array/projection: mutate
# WITHOUT resigning, so the array's own manifest digest no longer recomputes
# and S8's dedicated code for that array fires. (`assertion` is excluded --
# it is S7's ASSERTION_DIGEST_MISMATCH, not one of S8's six.)
_S8_DIGEST_MISMATCH_CASES = [
    ("split_derivation", _gv_mutate_split_derivation, "SPLIT_DERIVATION_DIGEST_MISMATCH"),
    ("evaluation_splits", _gv_mutate_evaluation_splits, "EVALUATION_SPLITS_DIGEST_MISMATCH"),
    ("measured_claims", _gv_mutate_measured_claims, "MEASURED_CLAIMS_DIGEST_MISMATCH"),
    ("non_claims", _gv_mutate_non_claims, "NON_CLAIMS_DIGEST_MISMATCH"),
    ("claim_support_rows", _gv_mutate_claim_support_rows, "CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH"),
]


@pytest.mark.parametrize(
    "array_name,mutate,expected_code",
    _S8_DIGEST_MISMATCH_CASES,
    ids=[c[0] for c in _S8_DIGEST_MISMATCH_CASES],
)
def test_s8_rejects_unresigned_array_mutation_with_its_own_digest_code(
    array_name: str, mutate, expected_code: str
) -> None:
    bundle = mutate(build_agent_quality_bundle())
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == expected_code
    assert caught.value.field == "unsigned_manifest"


def test_s8_selection_estimates_digest_mismatch() -> None:
    """The seventh array-digest case: ``non_certified_selection_estimates``
    needs a nonempty array to mutate, so it is a schema-VALID
    issuer_verified override rather than one of the standard
    ``_gv_mutate_*`` helpers (mirrors
    :data:`_GV_MUTATION_CASES`'s own ``selection_estimates`` row)."""
    bundle = build_agent_quality_bundle(
        non_certified_selection_estimates=[_schema_fixtures._selection_estimate()]
    )
    bundle["non_certified_selection_estimates"][0]["point_estimate"] += 1
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SELECTION_ESTIMATES_DIGEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


@pytest.mark.parametrize("array_name,mutate,expected_code", _S8_DIGEST_MISMATCH_CASES)
def test_s8_resigned_array_mutation_passes_when_still_schema_valid(
    array_name: str, mutate, expected_code: str
) -> None:
    """The digest-mismatch negatives above have a positive counterpart: once
    :func:`resign_agent_quality_bundle` restores consistency, S8 passes --
    UNLESS the mutation is itself schema-invalid regardless of resign
    (``non_claims``/``claim_support_rows``, see
    :data:`_GV_MUTATION_CASES`), in which case S8's own row-63 check (for
    ``claim_support_rows``) or nothing schema-shaped is left to trip
    (``non_claims`` has no S8-owned counterpart at all, since S8 never reads
    ``non_claims`` content beyond its digest)."""
    mutated = mutate(build_agent_quality_bundle())
    resigned = resign_agent_quality_bundle(mutated)
    context = build_agent_quality_context()
    if array_name == "claim_support_rows":
        # verifier_result="fail" survives resign (review P1-1) and is caught
        # by S8's OWN row-63 binding check, not the digest recompute.
        with pytest.raises(v.AgentQualityVerificationError) as caught:
            v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
        assert caught.value.code == "CLAIM_SUPPORT_ROW_MISMATCH"
        return
    v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)


# Row 63 -- CLAIM_SUPPORT_ROW_MISMATCH: the single claim-support row's own
# digest bindings must be internally consistent with the SAME content S8
# independently recomputed, in both directions.


def test_s8_issuer_verified_row_missing_a_binding_is_row_mismatch() -> None:
    """An ``issuer_verified`` row whose ``declared_plan_digest`` binding
    disagrees with the declared plan's own digest -- resigned only at the
    manifest/signature layer (:func:`_gv_resign_manifest_and_signature_only`),
    so row 62's own digest recomputes and the failure is attributable to
    row 63 alone, not to the array-digest check above it."""
    bundle = build_agent_quality_bundle()
    bundle["claim_support_rows"][0]["declared_plan_digest"] = "sha256:" + "9" * 64
    bundle["unsigned_manifest"]["agent_quality_claim_support_rows_digest"] = _gv_digest(
        "claim_support_rows", bundle["claim_support_rows"]
    )
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "CLAIM_SUPPORT_ROW_MISMATCH"
    assert caught.value.field == "claim_support_rows"


def test_s8_abstained_row_carrying_a_binding_is_row_mismatch() -> None:
    """An ``abstained`` row that carries a ``verifier_result`` binding it
    must not -- schema-invalid on its own (the abstention coupling forbids
    it), so this calls S8 DIRECTLY (bypassing S1) to prove S8's own row-63
    check independently catches it too."""
    bundle = build_abstained_agent_quality_bundle()
    bundle["claim_support_rows"][0]["verifier_result"] = "pass"
    bundle["unsigned_manifest"]["agent_quality_claim_support_rows_digest"] = _gv_digest(
        "claim_support_rows", bundle["claim_support_rows"]
    )
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context(accept_abstained_bundle=True)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "CLAIM_SUPPORT_ROW_MISMATCH"
    assert caught.value.field == "claim_support_rows"


# Row 64 -- UNSIGNED_MANIFEST_MISMATCH: every manifest field this stage can
# reconstruct from the bundle + process_record_bundle alone.


def test_s8_unsigned_manifest_mismatch_wrong_coverage() -> None:
    bundle = build_agent_quality_bundle()
    manifest = dict(bundle["unsigned_manifest"])
    manifest["coverage"] = list(manifest["coverage"])[:-1]
    bundle["unsigned_manifest"] = manifest
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "UNSIGNED_MANIFEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


def test_s8_unsigned_manifest_mismatch_wrong_primary_objective_id() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["primary_objective_id"] = "obj.accuracy.evaluator_score_mean.v1"
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "UNSIGNED_MANIFEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


def test_s8_unsigned_manifest_mismatch_wrong_process_record_digest() -> None:
    """``base_process_record_unsigned_manifest_digest`` must equal the
    verifier's OWN recomputation over ``process_record_bundle``'s real
    unsigned manifest -- not merely echo whatever the agent-quality bundle
    happens to declare."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["base_process_record_unsigned_manifest_digest"] = (
        "sha256:" + "9" * 64
    )
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "UNSIGNED_MANIFEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


# Row 65 -- UNSIGNED_MANIFEST_DIGEST_MISMATCH


def test_s8_unsigned_manifest_digest_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["signature"]["unsigned_manifest_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "UNSIGNED_MANIFEST_DIGEST_MISMATCH"
    assert caught.value.field == "signature"


# Row 66 -- KEY_RING_MISMATCH: every key-resolution failure this stage can
# reach, never a forged-signature finding.


def test_s8_key_ring_mismatch_signature_refs_vs_manifest_refs() -> None:
    bundle = build_agent_quality_bundle()
    bundle["signature"]["issuer_key_ref"] = "issuerkey:bbbbbbbb"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "KEY_RING_MISMATCH"
    assert caught.value.field == "signature"


def test_s8_key_ring_mismatch_manifest_refs_vs_v0_issuer_materials() -> None:
    """The manifest's own ``issuer_key_ref``/``trust_ring_ref`` disagreeing
    with ``process_record_bundle``'s verified issuer materials -- re-signed
    only at the manifest/signature layer so the golden signature still
    verifies under the (unchanged) golden key, isolating this from row 67."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["issuer_key_ref"] = "issuerkey:bbbbbbbb"
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "KEY_RING_MISMATCH"
    assert caught.value.field == "signature"


def test_s8_key_ring_mismatch_algorithm_disagreement() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["issuer_signature_algorithm"] = "ecdsa_p256_sha256"
    resigned = _gv_resign_manifest_and_signature_only(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(resigned, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "KEY_RING_MISMATCH"
    assert caught.value.field == "signature"


def test_s8_key_ring_mismatch_malformed_issuer_key_material() -> None:
    """``process_record_bundle``'s own pinned issuer key material fails to
    parse -- a key-resolution failure this stage must fail closed on,
    without ever touching the agent-quality bundle it is verifying."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    broken_process_record = _gv_copy.deepcopy(_GV_PROCESS_RECORD_BUNDLE)
    broken_process_record["verification_materials_v0"]["issuer"]["public_key_der_b64"] = "not-b64!!"
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, broken_process_record)
    assert caught.value.code == "KEY_RING_MISMATCH"
    assert caught.value.field == "signature"


@pytest.mark.parametrize("degenerate_process_record", [None, {}])
def test_s8_fails_closed_on_degenerate_process_record_bundle(degenerate_process_record) -> None:
    """P1-V2.2 review P2-1 closure: ``None``/``{}`` used to escape S8's
    row-64 read as a raw ``TypeError``/``KeyError`` instead of an owned
    code, because only the row-66 read was guarded (see
    :func:`test_s8_key_ring_mismatch_malformed_issuer_key_material`). Both
    degenerate shapes must now fail closed with S8's own
    UNSIGNED_MANIFEST_MISMATCH, not escape uncaught."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, degenerate_process_record)
    assert caught.value.code == "UNSIGNED_MANIFEST_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


def test_wrong_key_valid_signature_shape_is_signature_invalid_not_key_ring_mismatch() -> None:
    """checkpoint (b).3's foreign-key harness, driven through S8 directly.

    Per CTO decision A: a signature produced by a key NOT in the key ring,
    with every declared ref (``issuer_key_ref``/``trust_ring_ref``/
    ``algorithm``) UNCHANGED and matching both the manifest and
    ``process_record_bundle``'s pinned issuer materials, is cryptographically
    INDISTINGUISHABLE, from the verifier's side, from a signature whose bytes
    were simply corrupted -- Ed25519 verification has no side channel that
    reveals "the wrong key signed this" versus "this signature is garbage"
    once the declared identity and the resolved public key both check out.
    Neither sibling verifier in this repository
    (``process_record_verifier``, ``evaluator_quality_verifier``) draws a
    KEY_RING_MISMATCH/ISSUER_SIGNATURE_INVALID line on that axis; both route
    every post-ref-check verification failure to their
    *_ISSUER_SIGNATURE_INVALID code, which is the ruling this test pins:
    case (a) of CTO decision A is ISSUER_SIGNATURE_INVALID, distinct from
    case (b)'s KEY_RING_MISMATCH (see
    :func:`test_s8_key_ring_mismatch_manifest_refs_vs_v0_issuer_materials`
    and :func:`test_s8_key_ring_mismatch_malformed_issuer_key_material`)."""
    bundle = build_agent_quality_bundle()
    foreign = resign_with_foreign_key(bundle, _GV_FOREIGN_PRIVATE_KEY)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(foreign, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "ISSUER_SIGNATURE_INVALID"
    assert caught.value.field == "signature"


# Row 67 -- ISSUER_SIGNATURE_INVALID: golden key, corrupted signature/preimage.


def test_s8_issuer_signature_invalid_flipped_signature_byte() -> None:
    bundle = build_agent_quality_bundle()
    raw = bundle["signature"]["signature"]
    bundle["signature"]["signature"] = ("A" if raw[0] != "A" else "B") + raw[1:]
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "ISSUER_SIGNATURE_INVALID"
    assert caught.value.field == "signature"


def test_s8_issuer_signature_invalid_wrong_preimage_domain() -> None:
    """Row 65 (the manifest-digest check) passes -- the digest is computed
    over the manifest bytes alone, not the signing domain -- but the
    signature itself was produced over the WRONG domain prefix with the
    golden key, so verification under the correct (``issuer_signature``)
    domain fails."""
    bundle = build_agent_quality_bundle()
    manifest = bundle["unsigned_manifest"]
    wrong_domain = _GV_DOMAINS["declared_plan_signature"]
    material = wrong_domain.encode("utf-8") + b"\x00" + fp2.canonicalize(manifest).encode("utf-8")
    bundle["signature"]["signature"] = base64.b64encode(_GV_PRIVATE_KEY.sign(material)).decode(
        "ascii"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s8_manifest_digests_signature(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "ISSUER_SIGNATURE_INVALID"
    assert caught.value.field == "signature"


# ==========================================================================
# P1-V2.3 -- S2 real checks (design rows 8-12): context and scope binding.
# ==========================================================================


def test_s2_passes_the_golden_bundle() -> None:
    """The golden bundle is exactly what S2's real checks are supposed to
    PASS -- called directly (bypassing S1, S3-S8) with the real
    :data:`_GV_PROCESS_RECORD_BUNDLE` and the context it is genuinely bound
    to."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_s2_process_record_binding_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["base_process_record_unsigned_manifest_digest"] = (
        "sha256:" + "9" * 64
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "PROCESS_RECORD_BINDING_MISMATCH"
    assert caught.value.field == "process_record_binding"


@pytest.mark.parametrize(
    "manifest_field,context_field",
    [
        ("agent_commitment_ref", "expected_agent_commitment_ref"),
        ("dataset_commitment_ref", "expected_dataset_commitment_ref"),
        ("evaluator_commitment_ref", "expected_evaluator_commitment_ref"),
        ("build_definition_commitment_ref", "expected_build_definition_commitment_ref"),
    ],
)
def test_s2_commitment_ref_mismatch_manifest_disagrees(
    manifest_field: str, context_field: str
) -> None:
    """The manifest's own commitment ref disagreeing with BOTH the verified
    process record's and the context's (which still agree with each other)
    is a mismatch."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"][manifest_field] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "COMMITMENT_REF_MISMATCH"
    assert caught.value.field == "commitment_refs"


@pytest.mark.parametrize(
    "manifest_field,context_field",
    [
        ("agent_commitment_ref", "expected_agent_commitment_ref"),
        ("dataset_commitment_ref", "expected_dataset_commitment_ref"),
        ("evaluator_commitment_ref", "expected_evaluator_commitment_ref"),
        ("build_definition_commitment_ref", "expected_build_definition_commitment_ref"),
    ],
)
def test_s2_commitment_ref_mismatch_context_disagrees_with_process_record(
    manifest_field: str, context_field: str
) -> None:
    """The manifest and the caller's context pin agree with EACH OTHER but
    disagree with what the verified process record actually proved -- a
    caller cannot simply assert its own pin and the manifest's matching
    value without the process record independently confirming it."""
    bundle = build_agent_quality_bundle()
    foreign_ref = "sha256:" + "8" * 64
    bundle["unsigned_manifest"][manifest_field] = foreign_ref
    context = build_agent_quality_context(**{context_field: foreign_ref})
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "COMMITMENT_REF_MISMATCH"
    assert caught.value.field == "commitment_refs"


def test_s2_scope_mismatch_manifest_scope_binding_digest() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["scope_binding_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SCOPE_MISMATCH"
    assert caught.value.field == "scope_binding"


def test_s2_scope_mismatch_declared_plan_scope_binding_digest() -> None:
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["scope_binding_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SCOPE_MISMATCH"
    assert caught.value.field == "scope_binding"


def test_s2_scope_mismatch_foreign_but_self_consistent_scope_digest() -> None:
    """Design test 81: a bundle whose manifest AND declared plan agree with
    EACH OTHER on a foreign scope-binding digest (i.e. self-consistent, but
    not derived from the caller's own pins) must still be rejected -- the
    projection is derived from ``context.expected_project_ref``/
    ``expected_build_session_ref`` alone, never copied from the bundle."""
    bundle = build_agent_quality_bundle()
    foreign_digest = v._role_digest(
        _GV_DOMAINS["scope_binding"],
        {
            "schema_version": _GV_DOMAINS["scope_binding"],
            "project_ref": "some-other-project",
            "build_session_ref": "build_session:zzzzzzzz",
        },
    )
    bundle["unsigned_manifest"]["scope_binding_digest"] = foreign_digest
    bundle["declared_plan_envelope"]["declared_plan"]["scope_binding_digest"] = foreign_digest
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SCOPE_MISMATCH"
    assert caught.value.field == "scope_binding"


def test_s2_scope_mismatch_context_disagrees_with_verified_process_record() -> None:
    """The caller's project/build-session pins disagree with what the
    process record actually proved, even though the manifest's own scope
    digest happens to be self-consistent under those (wrong) pins."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context(
        expected_project_ref="a-different-project",
        expected_build_session_ref="build_session:zzzzzzzz",
    )
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "SCOPE_MISMATCH"
    assert caught.value.field == "scope_binding"


def test_measurement_contract_pin_none_is_preempted_by_context_construction() -> None:
    """P1-V2.3 review finding P2-3: MEASUREMENT_CONTRACT_NOT_PINNED (design
    row 11) is preempted by ``AgentQualityVerificationContext.__post_init__``
    itself -- both measurement-contract pins are non-Optional ``str``
    fields, so constructing the context with either as ``None`` already
    raises CONTEXT before S2's stage body ever runs. See
    :data:`v.AGENT_QUALITY_CONTEXT_PREEMPTED_CODES`. (The previous version of
    this test forced the frozen dataclass open with ``object.__setattr__``
    to manufacture the state and prove only that the ``_fail`` line exists,
    which says nothing about whether it is ever reachable.)"""
    with pytest.raises(v.AgentQualityVerificationError) as caught_ref:
        build_agent_quality_context(expected_measurement_contract_ref=None)
    assert caught_ref.value.code == "CONTEXT"
    assert caught_ref.value.field == "context"

    with pytest.raises(v.AgentQualityVerificationError) as caught_digest:
        build_agent_quality_context(expected_measurement_contract_record_digest=None)
    assert caught_digest.value.code == "CONTEXT"
    assert caught_digest.value.field == "context"


def test_s2_measurement_contract_mismatch_manifest() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["measurement_contract_ref"] = "measurement:zzzzzzzz"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "MEASUREMENT_CONTRACT_MISMATCH"
    assert caught.value.field == "measurement_contract"


def test_s2_measurement_contract_mismatch_per_claim() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["measurement_contract_ref"] = "measurement:zzzzzzzz"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s2_context_binding(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "MEASUREMENT_CONTRACT_MISMATCH"
    assert caught.value.field == "measurement_contract"


# ==========================================================================
# P1-V2.3 -- S3 real checks (design rows 13-16): the four shipped
# registries' identity.
# ==========================================================================


def test_s3_passes_the_golden_bundle() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s3_registry_identity(bundle, context)


def test_s3_aggregation_policy_mismatch_declared_plan() -> None:
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["aggregation_policy"] = dict(
        bundle["declared_plan_envelope"]["declared_plan"]["aggregation_policy"], policy_id="wrong"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "AGGREGATION_POLICY_MISMATCH"
    assert caught.value.field == "aggregation_policy"


def test_s3_objective_registry_mismatch_manifest() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["objective_registry"] = dict(
        bundle["unsigned_manifest"]["objective_registry"], registry_digest="sha256:" + "9" * 64
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "OBJECTIVE_REGISTRY_MISMATCH"
    assert caught.value.field == "objective_registry"


def test_s3_objective_registry_mismatch_declared_plan() -> None:
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["objective_registry"] = dict(
        bundle["declared_plan_envelope"]["declared_plan"]["objective_registry"],
        registry_version="v9",
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "OBJECTIVE_REGISTRY_MISMATCH"
    assert caught.value.field == "objective_registry"


def test_s3_non_claim_set_mismatch_identity() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["non_claim_catalog"] = dict(
        bundle["unsigned_manifest"]["non_claim_catalog"], catalog_digest="sha256:" + "9" * 64
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "NON_CLAIM_SET_MISMATCH"
    assert caught.value.field == "non_claims"


def test_s3_non_claim_set_mismatch_swapped_order() -> None:
    """The identity digest is untouched, but the printed tuple's order no
    longer names the catalog's own order -- called directly (bypassing S1's
    schema check, which pins this tuple's order on a schema-valid bundle),
    so this stage's own order guard, not the schema, is what this test
    proves."""
    bundle = build_agent_quality_bundle()
    non_claims = bundle["non_claims"]
    non_claims[0], non_claims[1] = non_claims[1], non_claims[0]
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "NON_CLAIM_SET_MISMATCH"
    assert caught.value.field == "non_claims"


def test_s3_quantile_table_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["quantile_table"] = dict(
        bundle["unsigned_manifest"]["quantile_table"], table_digest="sha256:" + "9" * 64
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "QUANTILE_TABLE_MISMATCH"
    assert caught.value.field == "quantile_table"


def test_s3_quantile_table_mismatch_per_claim_direct() -> None:
    """P1-V2.4 review P2-1: row 16 only ever compared the MANIFEST's own
    quantile-table identity -- a Student-t claim's OWN
    ``interval_params.quantile_table`` copy went unchecked. Direct-call
    counterpart of :func:`test_s3_quantile_table_mismatch_per_claim_full_runner`
    below, isolating S3's own guard."""
    bundle = build_agent_quality_bundle()
    student_t_claim = bundle["measured_claims"][1]
    student_t_claim["interval_params"]["quantile_table"] = dict(
        student_t_claim["interval_params"]["quantile_table"], table_digest="sha256:" + "9" * 64
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s3_registry_identity(bundle, context)
    assert caught.value.code == "QUANTILE_TABLE_MISMATCH"
    assert caught.value.field == "quantile_table"


def test_s3_quantile_table_mismatch_per_claim_full_runner() -> None:
    """The re-signed, full-runner counterpart the P1-V2.4 review required:
    a Student-t claim citing a foreign quantile-table identity is rejected
    by the COMPLETE check sequence, not merely by calling S3 directly."""
    bundle = build_agent_quality_bundle()
    student_t_claim = bundle["measured_claims"][1]
    student_t_claim["interval_params"]["quantile_table"] = dict(
        student_t_claim["interval_params"]["quantile_table"], table_digest="sha256:" + "9" * 64
    )
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "QUANTILE_TABLE_MISMATCH"
    assert caught.value.field == "quantile_table"


# ==========================================================================
# P1-V2.3 -- S4 real checks (design rows 17-19, 21): declared-plan digest
# and signature.
# ==========================================================================


def test_s4_passes_the_golden_bundle() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_s4_declared_plan_digest_mismatch_manifest_only() -> None:
    """The declared plan's own digest is internally consistent with itself,
    but the manifest's copy of it disagrees."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["declared_plan_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_DIGEST_MISMATCH"
    assert caught.value.field == "declared_plan"


def test_s4_declared_plan_signature_digest_mismatch() -> None:
    """The declared plan's own digest is genuinely correct (row 17 passes),
    but the signature block's copy of it -- what the issuer actually
    signed over, per its own assertion -- disagrees."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["signature"]["declared_plan_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH"
    assert caught.value.field == "declared_plan_signature"


def test_s4_declared_plan_signature_invalid_foreign_key() -> None:
    """A structurally valid signature by a key NOT in the key ring: this
    stage owns no KEY_RING_MISMATCH code of its own, so -- consistent with
    CTO decision A's case (a) -- the outcome is DECLARED_PLAN_SIGNATURE_INVALID."""
    bundle = build_agent_quality_bundle()
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    material = (
        _GV_DOMAINS["declared_plan_signature"].encode("utf-8")
        + b"\x00"
        + fp2.canonicalize(declared_plan).encode("utf-8")
    )
    bundle["declared_plan_envelope"]["signature"]["signature"] = base64.b64encode(
        _GV_FOREIGN_PRIVATE_KEY.sign(material)
    ).decode("ascii")
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_SIGNATURE_INVALID"
    assert caught.value.field == "declared_plan_signature"


def test_s4_declared_plan_signature_invalid_malformed_process_record_key() -> None:
    """A malformed ``process_record_bundle`` key material: S4 owns no
    KEY_RING_MISMATCH, so a key-resolution failure also folds into
    DECLARED_PLAN_SIGNATURE_INVALID."""
    bundle = build_agent_quality_bundle()
    broken_process_record = _gv_copy.deepcopy(_GV_PROCESS_RECORD_BUNDLE)
    broken_process_record["verification_materials_v0"]["issuer"]["public_key_der_b64"] = "not-b64!!"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, broken_process_record)
    assert caught.value.code == "DECLARED_PLAN_SIGNATURE_INVALID"
    assert caught.value.field == "declared_plan_signature"


def test_s4_declared_plan_signature_invalid_foreign_but_self_consistent_key_ring() -> None:
    """P1-V2.3 review finding P2-2 (T7h): the declared-plan signature block
    asserts a FOREIGN issuer_key_ref/trust_ring_ref -- self-consistent with
    nothing else in the bundle checking those two fields except this
    stage -- while the manifest and every OTHER field stay genuinely signed
    by the real issuer. Before this closure, S4 never read the envelope's
    own key-ring fields at all (it resolved the verifying key straight from
    ``process_record_bundle``), so this bundle passed every stage in the
    packet. It must now fail DECLARED_PLAN_SIGNATURE_INVALID."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["signature"]["issuer_key_ref"] = "issuerkey:zzzzzzzz"
    bundle["declared_plan_envelope"]["signature"]["trust_ring_ref"] = "trustring:zzzzzzzz"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_SIGNATURE_INVALID"
    assert caught.value.field == "declared_plan_signature"


def test_s4_declared_plan_signature_invalid_wrong_algorithm_ref() -> None:
    """The third field P2-2 requires checked: a declared algorithm
    disagreement with the v0 issuer materials, everything else genuine."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["signature"]["algorithm"] = "ecdsa_p256_sha256"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_SIGNATURE_INVALID"
    assert caught.value.field == "declared_plan_signature"


def test_s4_declared_plan_pin_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context(expected_declared_plan_digest="sha256:" + "9" * 64)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)
    assert caught.value.code == "DECLARED_PLAN_PIN_MISMATCH"
    assert caught.value.field == "declared_plan"


def test_s4_declared_plan_pin_matches_when_supplied() -> None:
    bundle = build_agent_quality_bundle()
    declared_plan_digest = bundle["declared_plan_envelope"]["declared_plan"]["declared_plan_digest"]
    context = build_agent_quality_context(expected_declared_plan_digest=declared_plan_digest)
    v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


def test_s4_declared_plan_pin_skipped_when_none() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context(expected_declared_plan_digest=None)
    v._stage_s4_declared_plan_signatures(bundle, context, _GV_PROCESS_RECORD_BUNDLE)


# ==========================================================================
# P1-V2.4 commit 1 -- S5 real checks (design rows 22-31, 36-39): objective
# registration and per-claim structural shape. Rows 32-35 (the exact-integer
# recomputation and the order/degeneracy checks that must run before it) are
# added in commit 2, further below.
# ==========================================================================


def test_s5_passes_the_golden_bundle() -> None:
    """The golden bundle's two certified claims (Wilson for
    ``obj.accuracy.exact_match.v1``, Student-t for
    ``obj.accuracy.evaluator_score_mean.v1``) are exactly what S5's real
    checks are supposed to PASS -- called directly (bypassing S1-S4, S6-S8)."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s5_objective_measurement(bundle, context)


def test_s5_passes_the_abstained_golden_bundle() -> None:
    """An abstained bundle's ``measured_claims`` is empty by schema
    construction -- S5 has nothing to recompute and returns immediately,
    rather than reporting PRIMARY_OBJECTIVE_MISSING against an empty set."""
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    v._stage_s5_objective_measurement(bundle, context)


def test_s5_objective_not_in_declared_plan() -> None:
    """The claim's own ``objective_kind``/``unit``/statistics stay Wilson
    binary-rate/ppm so this fails at row 22 alone, not at a downstream
    kind/unit mismatch."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["objective_id"] = "obj.cost.mean_microusd_per_item.v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_NOT_IN_DECLARED_PLAN"
    assert caught.value.field == "measured_claims.objective"


def test_s5_primary_objective_missing_manifest_disagrees_with_declared_plan() -> None:
    """Both certified objective ids stay in the declared plan (row 22
    passes for every claim); only the manifest's own copy of
    ``primary_objective_id`` disagrees with the declared plan's."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["primary_objective_id"] = "obj.accuracy.evaluator_score_mean.v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "PRIMARY_OBJECTIVE_MISSING"
    assert caught.value.field == "measured_claims.objective"


def test_s5_primary_objective_missing_not_among_certified_claims() -> None:
    """Manifest and declared plan agree on the primary, but no certified
    claim actually names it."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["primary_objective_id"] = (
        "obj.cost.mean_microusd_per_item.v1"
    )
    bundle["declared_plan_envelope"]["declared_plan"]["objective_ids"] = [
        "obj.accuracy.exact_match.v1",
        "obj.accuracy.evaluator_score_mean.v1",
        "obj.cost.mean_microusd_per_item.v1",
    ]
    bundle["unsigned_manifest"]["primary_objective_id"] = "obj.cost.mean_microusd_per_item.v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "PRIMARY_OBJECTIVE_MISSING"
    assert caught.value.field == "measured_claims.objective"


def test_s5_objective_duplicate() -> None:
    """Two certified claims naming the SAME objective -- row 28's
    :func:`v._unique_by` guard, checked over the whole certified set before
    any per-claim shape check runs."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"].append(dict(bundle["measured_claims"][0]))
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_DUPLICATE"
    assert caught.value.field == "measured_claims"


def test_s5_objective_not_registered() -> None:
    """An objective id outside the shipped registry entirely -- schema
    would reject this (``ObjectiveIdV1``'s closed enum), so this stage's
    own defensive registry lookup, not the schema, is what this test
    proves, by calling S5 directly. Mutates the SECONDARY claim so the
    primary-objective check (row 23) still passes on the untouched primary
    claim."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["objective_ids"] = [
        "obj.accuracy.exact_match.v1",
        "obj.unregistered.made_up.v1",
    ]
    bundle["measured_claims"][1]["objective_id"] = "obj.unregistered.made_up.v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_NOT_REGISTERED"
    assert caught.value.field == "measured_claims.objective"


def test_s5_objective_kind_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["objective_kind"] = "bounded_mean"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_KIND_MISMATCH"
    assert caught.value.field == "measured_claims.objective"


def test_s5_objective_kind_mismatch_direction() -> None:
    """Direction folds into OBJECTIVE_KIND_MISMATCH (design row 25's own
    field, split only into kind+direction versus unit)."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["direction"] = "minimize"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_KIND_MISMATCH"
    assert caught.value.field == "measured_claims.objective"


def test_s5_objective_unit_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["unit"] = "microusd"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_UNIT_MISMATCH"
    assert caught.value.field == "measured_claims.objective"


def test_s5_objective_minimum_sample_not_met() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["sample_size"] = 5
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "OBJECTIVE_MINIMUM_SAMPLE_NOT_MET"
    assert caught.value.field == "measured_claims.sample_size"


def test_s5_distribution_assumption_not_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    """A ``nonnegative_mean`` objective whose SHIPPED registry entry lacks a
    registered ``distribution_assumption`` -- the shipped registry always
    carries one for its two ``nonnegative_mean`` entries, so this patches
    the cached registry-by-id lookup rather than mutating package data."""
    bundle = build_agent_quality_bundle()
    bundle["declared_plan_envelope"]["declared_plan"]["objective_ids"] = [
        "obj.accuracy.exact_match.v1",
        "obj.cost.mean_microusd_per_item.v1",
    ]
    student_t_claim = bundle["measured_claims"][1]
    student_t_claim.update(
        {
            "objective_id": "obj.cost.mean_microusd_per_item.v1",
            "objective_kind": "nonnegative_mean",
            "unit": "microusd",
            "direction": "minimize",
            "sample_size": 200,
        }
    )
    student_t_claim["sufficient_statistics"]["unit_scale"] = "microusd"

    real_entries = v._objective_registry_entries_by_id()
    broken_entry = dict(real_entries["obj.cost.mean_microusd_per_item.v1"])
    broken_entry.pop("distribution_assumption", None)
    patched = dict(real_entries)
    patched["obj.cost.mean_microusd_per_item.v1"] = broken_entry
    monkeypatch.setattr(v, "_objective_registry_entries_by_id", lambda: patched)

    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "DISTRIBUTION_ASSUMPTION_NOT_REGISTERED"
    assert caught.value.field == "objective_registry"


def test_s5_interval_method_not_emittable() -> None:
    """``bootstrap_percentile_v1`` is a registered ``IntervalMethodV1``
    member but excluded from ``EmittableIntervalMethodV1`` -- schema would
    already reject this shape, so this calls S5 directly to prove the
    stage's own defensive check."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["interval_params"]["interval_method"] = "bootstrap_percentile_v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_METHOD_NOT_EMITTABLE"
    assert caught.value.field == "measured_claims.interval_params"


def test_s5_interval_method_not_emittable_order_statistic() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["interval_params"]["interval_method"] = (
        "order_statistic_quantile_v1"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_METHOD_NOT_EMITTABLE"
    assert caught.value.field == "measured_claims.interval_params"


def test_s5_interval_method_not_admissible() -> None:
    """``student_t_normal_approx_v1`` IS emittable in v1, but it is not the
    method admissible for a ``binary_rate`` objective (Wilson is)."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["interval_params"]["interval_method"] = (
        "student_t_normal_approx_v1"
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_METHOD_NOT_ADMISSIBLE"
    assert caught.value.field == "measured_claims.interval_params"


def test_s5_sufficient_statistics_shape_wrong_stat_kind() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["sufficient_statistics"]["stat_kind"] = "mean_variance_v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "SUFFICIENT_STATISTICS_SHAPE"
    assert caught.value.field == "measured_claims.sufficient_statistics"


def test_s5_sufficient_statistics_shape_successes_exceed_trials() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["sufficient_statistics"]["success_count"] = 999
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "SUFFICIENT_STATISTICS_SHAPE"
    assert caught.value.field == "measured_claims.sufficient_statistics"


def test_s5_interval_out_of_unit_bounds() -> None:
    """``obj.accuracy.exact_match.v1``'s registry entry bounds ``ppm`` to
    ``[0, 1000000]``; the declared high endpoint exceeds it."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["interval_high"] = 1_500_000
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_OUT_OF_UNIT_BOUNDS"
    assert caught.value.field == "measured_claims.interval"


def test_s5_nominal_coverage_mismatch_unregistered_value() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["nominal_coverage_ppm"] = 123456
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "NOMINAL_COVERAGE_MISMATCH"
    assert caught.value.field == "measured_claims"


def test_s5_nominal_coverage_mismatch_not_uniform_across_claims() -> None:
    """Both coverages are individually registered members of
    ``NominalCoveragePpmV1`` -- the violation is that the two certified
    claims disagree with EACH OTHER.

    The student-t claim's own interval is re-recomputed at the new coverage
    (990000) so its OWN row 32-33 recomputation still passes -- otherwise
    changing a claim's ``nominal_coverage_ppm`` alone would trip
    INTERVAL_RECOMPUTATION_MISMATCH before the per-set uniformity check
    (row 37) is ever reached, which would test the wrong guard."""
    bundle = build_agent_quality_bundle()
    student_t_claim = bundle["measured_claims"][1]
    student_t_claim["nominal_coverage_ppm"] = 990000
    stats = student_t_claim["sufficient_statistics"]
    mean_fixed = stats["mean_fixed"]
    half_width = v._student_t_half_width(
        mean_fixed=mean_fixed,
        sample_stddev_fixed=stats["sample_stddev_fixed"],
        sample_count=stats["sample_count"],
        coverage_ppm=990000,
        unit_scale=stats["unit_scale"],
    )
    student_t_claim["interval_low"] = mean_fixed - half_width
    student_t_claim["interval_high"] = mean_fixed + half_width
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "NOMINAL_COVERAGE_MISMATCH"
    assert caught.value.field == "measured_claims"


def test_s5_sample_size_mismatch() -> None:
    """150 clears row 26's ``minimum_sample_size`` floor (30) but no longer
    equals either the holdout split's ``item_count`` (200) or the
    sufficient statistics' own ``trial_count`` (200)."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["sample_size"] = 150
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "SAMPLE_SIZE_MISMATCH"
    assert caught.value.field == "measured_claims.sample_size"


def test_s5_verification_level_mismatch() -> None:
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["verification_level"] = "issuer_attested_v1"
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "VERIFICATION_LEVEL_MISMATCH"
    assert caught.value.field == "measured_claims.verification_level"


# ==========================================================================
# P1-V2.4 commit 2 -- S5 arithmetic (design rows 32-35): exact-integer
# point-estimate and interval RECOMPUTATION, wired via the shipped
# _wilson_point/_wilson_bounds/_student_t_half_width helpers.
# ==========================================================================


@pytest.mark.parametrize(
    "endpoint,delta",
    [("interval_low", -1), ("interval_low", 1), ("interval_high", -1), ("interval_high", 1)],
)
def test_wrong_wilson_interval_is_rejected(endpoint: str, delta: int) -> None:
    """The headline P1-c negative: a Wilson claim's declared endpoint off by
    exactly ONE ppm from what :func:`v._wilson_bounds` recomputes from
    ``success_count``/``trial_count`` alone is rejected -- in EITHER
    direction, on EITHER endpoint -- with INTERVAL_RECOMPUTATION_MISMATCH,
    not merely a bounds or ordering complaint. This is the test rev 0 could
    not have written."""
    bundle = build_agent_quality_bundle()
    wilson_claim = bundle["measured_claims"][0]
    wilson_claim[endpoint] = wilson_claim[endpoint] + delta
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_RECOMPUTATION_MISMATCH"
    assert caught.value.field == "measured_claims.interval"


def test_wrong_point_estimate_for_declared_counts_is_rejected() -> None:
    """A Wilson claim's declared ``point_estimate`` disagreeing with
    ``round(success_count * 1e6 / trial_count)`` (:func:`v._wilson_point`)
    is rejected by row 32 BEFORE row 33's interval recomputation ever runs
    -- the declared endpoints are left untouched and still bracket the
    mutated point, so only POINT_ESTIMATE_RECOMPUTATION_MISMATCH can catch
    this."""
    bundle = build_agent_quality_bundle()
    wilson_claim = bundle["measured_claims"][0]
    wilson_claim["point_estimate"] = wilson_claim["point_estimate"] + 1
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "POINT_ESTIMATE_RECOMPUTATION_MISMATCH"
    assert caught.value.field == "measured_claims.interval"


def test_wrong_student_t_half_width_is_rejected() -> None:
    """A student-t claim's declared ``interval_high`` disagreeing with
    ``mean_fixed + _student_t_half_width(...)`` is rejected by row 33 --
    the Student-t branch of the same recomputation that
    ``test_wrong_wilson_interval_is_rejected`` exercises for the Wilson
    branch."""
    bundle = build_agent_quality_bundle()
    student_t_claim = bundle["measured_claims"][1]
    student_t_claim["interval_high"] = student_t_claim["interval_high"] + 1
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s5_objective_measurement(bundle, context)
    assert caught.value.code == "INTERVAL_RECOMPUTATION_MISMATCH"
    assert caught.value.field == "measured_claims.interval"


def test_wilson_recomputation_uses_no_floating_point(monkeypatch: pytest.MonkeyPatch) -> None:
    """S5's arithmetic profile is ``exact_integer_rational_v1``: no square
    root, no float, anywhere in verification. Patch ``math.sqrt`` and the
    module's own ``float`` name to raise on any call -- the golden bundle
    (both its Wilson and its Student-t claim) must still verify through S5
    without either ever being invoked."""

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("floating-point path used in S5 recomputation")

    monkeypatch.setattr(v.math, "sqrt", _boom)
    monkeypatch.setattr(v, "float", _boom, raising=False)
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s5_objective_measurement(bundle, context)


def test_outward_rounding_never_narrows_an_interval() -> None:
    """Design test 42, at the stage's own registry-admissible grid: over
    every registered ``nominal_coverage_ppm`` and a grid of ``(k, n)``
    pairs, :func:`v._wilson_bounds`'s outward-rounded integer endpoints
    never sit inside the true rational Wilson interval, computed by an
    independent :class:`fractions.Fraction` oracle
    (:func:`_exact_wilson_endpoints_ppm`) that shares only the pinned
    quantile table with the module under test, never its bisection."""
    grid = [
        (0, 30),
        (1, 30),
        (15, 30),
        (30, 30),
        (1, 10**6),
        (870, 1000),
        (999999, 10**6),
        (1, 100),
        (99, 100),
        (50, 201),
    ]
    for coverage_ppm in sorted(v._nominal_coverage_values()):
        for k, n in grid:
            low, high = v._wilson_bounds(k, n, coverage_ppm)
            exact_low, exact_high = _exact_wilson_endpoints_ppm(k, n, coverage_ppm)
            assert Fraction(low) <= exact_low, (coverage_ppm, k, n, low, exact_low)
            assert Fraction(high) >= exact_high, (coverage_ppm, k, n, high, exact_high)


def test_sum_of_squares_statistic_would_exceed_the_fp2_safe_integer_cap() -> None:
    """Documents why ``SufficientStatisticsMeanVarianceV1`` carries
    ``mean_fixed``/``sample_stddev_fixed`` -- each independently bounded by
    the objective's own unit maximum -- rather than a raw sum and
    sum-of-squares: a sum of squares of microsecond latencies (up to
    ``10**9`` microseconds each) over a million items is ``~10**24``, far
    past fp2's IEEE-754-safe-integer cap (``2**53 - 1``), so a certificate
    carrying that alternative statistic could not be canonicalized -- let
    alone signed -- at all."""
    per_item_max = 10**9
    item_count = 10**6
    sum_of_squares = item_count * per_item_max**2
    assert sum_of_squares > 2**53 - 1
    with pytest.raises(v.fp2.Fp2UnsupportedValue):
        v.fp2.canonicalize({"sum_of_squares": sum_of_squares})


# ==========================================================================
# P1-V2.4 review P2-1 closure -- four self-declared construction parameters
# S5 never checked: a Wilson claim's continuity_correction, a Student-t
# claim's degrees_of_freedom and unit_scale, and (see
# test_s3_quantile_table_mismatch_per_claim_full_runner above) each claim's
# own quantile_table identity. Each negative below mutates the GOLDEN
# bundle, re-signs it (:func:`resign_agent_quality_bundle`), and runs it
# through the COMPLETE check sequence -- not a direct stage call -- per the
# review's explicit requirement.
# ==========================================================================


def test_p2_1_wilson_continuity_correction_yates_is_not_admissible_full_runner() -> None:
    """The review's headline P2-1 case: a claim LABELLED Yates
    (``continuity_correction: "yates_v1"``) while still carrying the plain
    Wilson endpoints used to PASS -- this stage's recomputation never reads
    the field. Only ``"none"`` is an admissible construction until a
    Yates-corrected recomputation exists."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["interval_params"]["continuity_correction"] = "yates_v1"
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "INTERVAL_METHOD_NOT_ADMISSIBLE"
    assert caught.value.field == "measured_claims.interval_params"


def test_p2_1_student_t_degrees_of_freedom_mismatch_full_runner() -> None:
    """A Student-t claim's ``interval_params.degrees_of_freedom`` must equal
    ``sufficient_statistics.sample_count - 1`` -- the golden claim's
    sample_count is 200, so 199 is correct and 1 is not."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][1]["interval_params"]["degrees_of_freedom"] = 1
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SUFFICIENT_STATISTICS_SHAPE"
    assert caught.value.field == "measured_claims.sufficient_statistics"


def test_p2_1_student_t_degrees_of_freedom_far_mismatch_full_runner() -> None:
    """The same guard at the review's other probed value (10**9)."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][1]["interval_params"]["degrees_of_freedom"] = 10**9
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SUFFICIENT_STATISTICS_SHAPE"
    assert caught.value.field == "measured_claims.sufficient_statistics"


def test_p2_1_student_t_unit_scale_mismatch_full_runner() -> None:
    """A Student-t claim's ``sufficient_statistics.unit_scale`` must equal
    its own top-level ``unit`` -- both are ``"ppm"`` on the golden claim; a
    foreign ``unit_scale`` (``"microsecond"``) must be rejected even though
    every OTHER field of the claim stays internally consistent."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][1]["sufficient_statistics"]["unit_scale"] = "microsecond"
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SUFFICIENT_STATISTICS_SHAPE"
    assert caught.value.field == "measured_claims.sufficient_statistics"


# ==========================================================================
# P1-V2.4 review P2-3 closure -- rows 34/35 (INTERVAL_ORDER,
# INTERVAL_DEGENERATE) were entirely untested. Re-signed, full-runner
# negatives below, plus a guard-ORDER regression proof: temporarily running
# these two checks AFTER recomputation (rows 32-33) instead of before must
# be caught by dedicated tests, per the review's explicit requirement.
# ==========================================================================


@pytest.mark.parametrize(
    "claim_index,swap",
    [(0, True), (1, True)],
    ids=["wilson_swap", "student_t_swap"],
)
def test_p2_3_interval_order_swapped_endpoints_full_runner(claim_index: int, swap: bool) -> None:
    """Swapping a claim's ``interval_low``/``interval_high`` must be named
    INTERVAL_ORDER, checked on the DECLARED endpoints before any
    recomputation -- for both the Wilson and the Student-t claim."""
    bundle = build_agent_quality_bundle()
    claim = bundle["measured_claims"][claim_index]
    claim["interval_low"], claim["interval_high"] = claim["interval_high"], claim["interval_low"]
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "INTERVAL_ORDER"
    assert caught.value.field == "measured_claims.interval"


def test_p2_3_interval_order_point_below_low_full_runner() -> None:
    """``point_estimate`` set below ``interval_low`` -- a different way to
    violate ``interval_low <= point_estimate <= interval_high`` than
    swapping the two endpoints."""
    bundle = build_agent_quality_bundle()
    claim = bundle["measured_claims"][0]
    claim["point_estimate"] = claim["interval_low"] - 1
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "INTERVAL_ORDER"
    assert caught.value.field == "measured_claims.interval"


@pytest.mark.parametrize("claim_index", [0, 1], ids=["wilson", "student_t"])
def test_p2_3_interval_degenerate_full_runner(claim_index: int) -> None:
    """``interval_low == interval_high == point_estimate`` -- schema-valid
    (all three are independently bounded, ordinary integers) but a
    degenerate, zero-width interval, for both Wilson and Student-t."""
    bundle = build_agent_quality_bundle()
    claim = bundle["measured_claims"][claim_index]
    claim["interval_low"] = claim["point_estimate"]
    claim["interval_high"] = claim["point_estimate"]
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "INTERVAL_DEGENERATE"
    assert caught.value.field == "measured_claims.interval"


def test_p2_3_guard_order_regression_is_caught() -> None:
    """The review's own probe, turned into a permanent regression test:
    moving rows 34-35's order/degeneracy guards to run AFTER rows 32-33's
    recomputation (instead of before) must be caught -- because the two
    checks would then report a DIFFERENT code
    (INTERVAL_RECOMPUTATION_MISMATCH) for the same swapped/degenerate
    input, not INTERVAL_ORDER/INTERVAL_DEGENERATE. This test reimplements
    S5's guard sequencing against a source-level assertion: the module
    source must contain the INTERVAL_ORDER check strictly BEFORE the
    POINT_ESTIMATE_RECOMPUTATION_MISMATCH check, and INTERVAL_DEGENERATE
    strictly before it too -- verified by line number, not just by the
    modules's prose -- so a future edit that reorders them breaks this test
    instead of silently changing which code a caller sees."""
    source = Path(v.__file__).read_text()
    order_line = source.index('_fail("INTERVAL_ORDER"')
    degenerate_line = source.index('_fail("INTERVAL_DEGENERATE"')
    point_recomputation_line = source.index('_fail("POINT_ESTIMATE_RECOMPUTATION_MISMATCH"')
    interval_recomputation_line = source.index('_fail("INTERVAL_RECOMPUTATION_MISMATCH"')
    assert order_line < point_recomputation_line < interval_recomputation_line
    assert degenerate_line < point_recomputation_line < interval_recomputation_line

    # Behavioral half of the same proof: on the CURRENT (correctly-ordered)
    # source, a swapped-endpoint claim is named INTERVAL_ORDER, never
    # INTERVAL_RECOMPUTATION_MISMATCH -- the two codes a guard-order
    # regression would conflate.
    bundle = build_agent_quality_bundle()
    claim = bundle["measured_claims"][0]
    claim["interval_low"], claim["interval_high"] = claim["interval_high"], claim["interval_low"]
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "INTERVAL_ORDER"
    assert caught.value.code != "INTERVAL_RECOMPUTATION_MISMATCH"


# ==========================================================================
# P1-V2.5 commit 1 -- S6 real checks (design rows 40-51): evaluation
# splits, holdout usage, split derivation, arm counts, and the second G6
# wiring (SELECTION_ESTIMATE_DUPLICATE). Genuinely reachable codes get
# re-signed, full-runner negative tests; the four schema-preempted-backstop
# codes (HOLDOUT_NOT_USED, HOLDOUT_MISSING, HOLDOUT_TOO_SMALL,
# HOLDOUT_REUSED) already have their direct-call + validator proofs above.
# ==========================================================================


def test_s6_passes_the_golden_bundle() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s6_splits_held_out(bundle, context)


def test_s6_passes_the_abstained_golden_bundle() -> None:
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    v._stage_s6_splits_held_out(bundle, context)


def test_s6_split_derivation_mismatch_holdout_record_full_runner() -> None:
    """Row 44: BOTH split records agree with EACH OTHER (so row 40's
    SPLIT_SET_SHAPE does not fire first) but disagree with the top-level
    declaration's own ``split_derivation_digest`` AND with the role-digest
    recomputation (P1-V2.5 review P2-4: re-signed, not merely a bundle
    whose signature happens to be broken -- built with
    :func:`_gv_reclose_after_free_split_derivation_self_digest`, targeting
    only the two ``evaluation_splits`` records so the top-level declaration
    and the declared plan's own copy stay at the correct recomputation)."""
    bundle = build_agent_quality_bundle()
    foreign_digest = "sha256:" + "9" * 64
    closed = _gv_reclose_after_free_split_derivation_self_digest(
        bundle, foreign_digest, targets=frozenset({"selection", "holdout"})
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_DERIVATION_MISMATCH"
    assert caught.value.field == "split_derivation"


def test_s6_split_derivation_mismatch_declared_plan_copy_full_runner() -> None:
    """Row 44's other locus: the declared plan's OWN copy of
    ``split_derivation`` disagrees with the top-level declaration in
    CONTENT (a different ``split_key_commitment``, its own digest a
    genuine recomputation over that different content), even though both
    split records still agree with each other and with the top-level
    declaration. Re-signed end to end with
    :func:`_gv_reclose_declared_plan_split_derivation` (P1-V2.5 review
    P2-4), not merely the declared plan in isolation, so S4's own
    digest-binding check and the issuer signature both stay genuinely
    valid."""
    bundle = build_agent_quality_bundle()
    foreign_split_derivation = dict(
        v._strip_self_digest(bundle["split_derivation"], "split_derivation_digest"),
        split_key_commitment="sha256:" + "7" * 64,
    )
    closed = _gv_reclose_declared_plan_split_derivation(bundle, foreign_split_derivation)
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    assert (
        closed["declared_plan_envelope"]["declared_plan"]["split_derivation"][
            "split_key_commitment"
        ]
        != closed["split_derivation"]["split_key_commitment"]
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_DERIVATION_MISMATCH"
    assert caught.value.field == "split_derivation"


def test_s6_split_derivation_mismatch_all_copies_agree_but_not_recomputed_full_runner() -> None:
    """P1-V2.5 review P1-1: row 44's original check only compared the four
    self-reported ``split_derivation_digest`` copies to EACH OTHER, never to
    a recomputation -- so a validly signed, schema-valid bundle whose four
    copies all agree on a FOREIGN value (never the digest of the split
    derivation's own content) verified. Built with
    :func:`_gv_reclose_after_free_split_derivation_self_digest`, which keeps
    the bundle genuinely schema-valid and ed25519-signed."""
    bundle = build_agent_quality_bundle()
    foreign_digest = "sha256:" + "9" * 64
    closed = _gv_reclose_after_free_split_derivation_self_digest(bundle, foreign_digest)
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    assert closed["split_derivation"]["split_derivation_digest"] == foreign_digest
    assert closed["evaluation_splits"][0]["split_derivation_digest"] == foreign_digest
    assert closed["evaluation_splits"][1]["split_derivation_digest"] == foreign_digest
    assert (
        closed["declared_plan_envelope"]["declared_plan"]["split_derivation"][
            "split_derivation_digest"
        ]
        == foreign_digest
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_DERIVATION_MISMATCH"
    assert caught.value.field == "split_derivation"


def test_s6_split_derivation_mismatch_declared_plan_pins_different_holdout_full_runner() -> None:
    """P1-V2.5 review P1-1's second probe -- design row 44 ("one
    derivation") exists to refuse exactly this: a signed declared plan that
    pre-registers a 10% holdout under a DIFFERENT ``split_key_commitment``
    while the bundle ships a 20% holdout. P1-V2.5-fix review P2-A: the
    declared plan's embedded ``split_derivation_digest`` is pinned to the
    SHIPPED digest Y (``digest=...``), not recomputed over the foreign
    content -- so the digest-equality clause agrees (declared_digest ==
    recomputed_split_derivation_digest == Y) and ONLY the content-equality
    clause -- ``declared_plan["split_derivation"] == bundle["split_derivation"]``
    -- can be the one that fires. Without that clause this bundle verifies
    (see the mutation in W1 of the .5-fix review: dropping the content
    check alone fails no test)."""
    bundle = build_agent_quality_bundle()
    shipped_digest = bundle["split_derivation"]["split_derivation_digest"]
    foreign_split_derivation = dict(
        v._strip_self_digest(bundle["split_derivation"], "split_derivation_digest"),
        holdout_fraction_ppm=100000,
        split_key_commitment="sha256:" + "8" * 64,
    )
    closed = _gv_reclose_declared_plan_split_derivation(
        bundle, foreign_split_derivation, digest=shipped_digest
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    assert (
        closed["declared_plan_envelope"]["declared_plan"]["split_derivation"][
            "holdout_fraction_ppm"
        ]
        == 100000
    )
    assert closed["split_derivation"]["holdout_fraction_ppm"] == 200000
    # The digest clause, isolated: the declared plan's embedded digest
    # equals the shipped derivation's own digest, byte for byte.
    assert (
        closed["declared_plan_envelope"]["declared_plan"]["split_derivation"][
            "split_derivation_digest"
        ]
        == shipped_digest
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_DERIVATION_MISMATCH"
    assert caught.value.field == "split_derivation"


def test_s6_split_set_shape_digest_disagreement_full_runner() -> None:
    """Row 40: SPLIT_SET_SHAPE, re-signed. Direct-call coverage already
    exists (:func:`test_split_set_shape_direct_call_guard_still_fires`,
    reversed record order), but P1-V2.5 review P2-4 asks for a re-signed
    full-runner negative too. ``commitment_scheme``/``canonicalization_profile``
    and each record's own ``split_id`` are all schema-fixed single-enum
    consts, so the only branch a schema-valid bundle can still trip is the
    two records' ``split_derivation_digest`` disagreeing with EACH OTHER --
    built with :func:`_gv_reclose_after_free_split_derivation_self_digest`,
    targeting only the ``selection`` record so it alone carries a foreign
    value while the holdout record, the top-level declaration, and the
    declared plan's copy all stay at the correct recomputation (row 40 runs
    before row 44, so SPLIT_SET_SHAPE fires first)."""
    bundle = build_agent_quality_bundle()
    foreign_digest = "sha256:" + "9" * 64
    closed = _gv_reclose_after_free_split_derivation_self_digest(
        bundle, foreign_digest, targets=frozenset({"selection"})
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_SET_SHAPE"
    assert caught.value.field == "evaluation_splits"


def test_s6_split_commitment_collision_full_runner() -> None:
    """Row 46: SPLIT_COMMITMENT_COLLISION, re-signed. Direct-call coverage
    already exists (the mutate-the-guard representative case at
    ``_GUTTING_REPRESENTATIVE_CASES``), but P1-V2.5 review P2-4 asks for a
    dedicated re-signed full-runner negative: both split records'
    ``split_commitment_digest`` set to the SAME value before resigning --
    ``_gv_close`` never touches this field, so a plain
    :func:`resign_agent_quality_bundle` call (no free-close needed) produces
    a genuinely, validly signed collision."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["split_commitment_digest"] = bundle["evaluation_splits"][0][
        "split_commitment_digest"
    ]
    closed = resign_agent_quality_bundle(bundle)
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_COMMITMENT_COLLISION"
    assert caught.value.field == "evaluation_splits"


def test_s6_split_partition_incomplete_full_runner() -> None:
    """Row 45: the two split sizes no longer sum to the declared universe
    size. The SELECTION side is shrunk (800 -> 750), not the holdout side,
    so S5's SAMPLE_SIZE_MISMATCH (``sample_size == holdout.item_count``,
    which runs first and would otherwise mask this row) stays unaffected --
    750 + 200 = 950 != 1000."""
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][0]["item_count"] = 750
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_PARTITION_INCOMPLETE"
    assert caught.value.field == "evaluation_splits"


def test_s6_split_size_implausible_declared_50_percent_actual_20_percent_full_runner() -> None:
    """The design's own headline example, adapted to stay schema-valid and
    S5-compatible: mutate the DECLARED ``holdout_fraction_ppm`` (50%, the
    schema's own maximum) while leaving the two split records' actual item
    counts untouched (holdout stays 200 of 1000 = 20%) -- an issuer who
    declared a 50% holdout but shipped a 20% one is caught by the integer
    bound, exactly the same defect class as the design's literal "20%
    declared, 2% shipped" example, just with the roles of declared/actual
    swapped to stay within ``SplitDerivationDeclarationV1``'s own
    ``holdout_fraction_ppm`` bounds (``[50000, 500000]``, i.e. 5%-50%) and
    to leave holdout.item_count -- and therefore every certified claim's
    ``sample_size`` binding (S5's SAMPLE_SIZE_MISMATCH, which runs first)
    -- untouched."""
    bundle = build_agent_quality_bundle()
    bundle["split_derivation"]["holdout_fraction_ppm"] = 500000
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_SIZE_IMPLAUSIBLE"
    assert caught.value.field == "evaluation_splits.holdout"


def test_split_size_bound_matches_hand_computed_literal() -> None:
    """P1-V2.5 review P3-6: :func:`v._split_size_bound` must match the
    design's LITERAL ``|h - round(N*p)| <= 6*isqrt(N*p*(1-p)) + 1``, pinned
    to values computed BY HAND (not derived from the function under test):
    N=1000, p=20% -> round(N*p)=200, N*p*(1-p)=1000*0.2*0.8=160,
    isqrt(160)=12 (12**2=144 <= 160 < 169=13**2), tolerance=6*12+1=73."""
    round_val, tolerance = v._split_size_bound(1000, 200000)
    assert round_val == 200
    assert tolerance == 73


def test_s6_split_size_bound_boundary_value_passes_direct_call() -> None:
    """The plausibility bound's own boundary, pinned to a LITERAL computed
    by hand (P1-V2.5 review P3-6: the design's own N=1000, p=20% example --
    round(N*p)=200, tolerance=73 -- so h=273 is the exact boundary and must
    PASS). Direct-call (bypassing S1/S5, whose own item_count/sample_size
    couplings are orthogonal to this arithmetic) so the boundary is tested
    in isolation."""
    universe_count = 1000
    boundary_holdout = 273
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["item_count"] = boundary_holdout
    bundle["evaluation_splits"][0]["item_count"] = universe_count - boundary_holdout
    context = build_agent_quality_context()
    v._stage_s6_splits_held_out(bundle, context)


def test_s6_split_size_bound_one_past_boundary_fails_direct_call() -> None:
    """One unit past the same LITERAL boundary (h=274) must FAIL."""
    universe_count = 1000
    past_boundary_holdout = 274
    bundle = build_agent_quality_bundle()
    bundle["evaluation_splits"][1]["item_count"] = past_boundary_holdout
    bundle["evaluation_splits"][0]["item_count"] = universe_count - past_boundary_holdout
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "SPLIT_SIZE_IMPLAUSIBLE"
    assert caught.value.field == "evaluation_splits.holdout"


def test_split_size_bound_half_up_rounding_matches_hand_computed_literal() -> None:
    """P1-V2.5-fix review P3-D: the N=1000/p=20% literal above is exact
    (N*p=200, no fractional remainder), so it cannot distinguish half-up
    rounding from floor -- replacing ``round(N*p)`` with a floor failed no
    test. N=1001, p=50% has a genuine half: round(500.5), which half-up
    rounds to 501 and floor would round to 500 -- hand-computed:
    N*p*(1-p) = 1001*0.5*0.5 = 250.25 -> floor-divided integer form 250,
    isqrt(250)=15 (15**2=225 <= 250 < 256=16**2), tolerance=6*15+1=91."""
    round_val, tolerance = v._split_size_bound(1001, 500000)
    assert round_val == 501
    assert tolerance == 91


def _gv_bundle_with_split_derivation_shape(
    universe_count: int, holdout_fraction_ppm: int, holdout_count: int
) -> dict:
    """Build a bundle whose ``split_derivation`` (universe/fraction) and
    ``evaluation_splits`` (selection/holdout item counts) are set to the
    given shape, with every self-reported ``split_derivation_digest`` copy
    (the top-level declaration, both split records, and the declared plan's
    own copy) recomputed to match -- so S6's row-44 digest/content checks
    stay genuinely satisfied and only the split-size plausibility check
    (row 47) is exercised, exactly like a direct-call test that changes
    ``item_count`` alone, just extended to also vary the derivation
    parameters those tests hold fixed."""
    bundle = build_agent_quality_bundle()
    split_derivation = dict(
        v._strip_self_digest(bundle["split_derivation"], "split_derivation_digest"),
        evaluated_universe_item_count=universe_count,
        holdout_fraction_ppm=holdout_fraction_ppm,
    )
    digest = v._role_digest(v._AGENT_QUALITY_DIGEST_DOMAINS["split_derivation"], split_derivation)
    split_derivation["split_derivation_digest"] = digest
    bundle["split_derivation"] = split_derivation
    bundle["evaluation_splits"][0]["split_derivation_digest"] = digest
    bundle["evaluation_splits"][0]["item_count"] = universe_count - holdout_count
    bundle["evaluation_splits"][1]["split_derivation_digest"] = digest
    bundle["evaluation_splits"][1]["item_count"] = holdout_count
    bundle["declared_plan_envelope"]["declared_plan"]["split_derivation"] = dict(split_derivation)
    return bundle


def test_s6_split_size_bound_half_up_boundary_passes_direct_call() -> None:
    """The half-up boundary this rounding choice controls: at N=1001,
    p=50%, h=592 is exactly ``round_val(501) + tolerance(91)`` under
    half-up, so it PASSES here -- but under floor rounding (round_val=500)
    the SAME h=592 would be 92 away from round_val, one past a
    tolerance-91 bound, and FAIL. This test pins the half-up behavior; its
    neighbor below pins the boundary one unit further out, which fails
    under EITHER rounding rule."""
    bundle = _gv_bundle_with_split_derivation_shape(
        universe_count=1001, holdout_fraction_ppm=500000, holdout_count=592
    )
    context = build_agent_quality_context()
    v._stage_s6_splits_held_out(bundle, context)


def test_s6_split_size_bound_one_past_half_up_boundary_fails_direct_call() -> None:
    """One unit past the half-up boundary (h=593) must FAIL under either
    rounding rule -- the discriminating case is the boundary test above,
    not this one; this one guards against a regression in the tolerance
    arithmetic itself."""
    bundle = _gv_bundle_with_split_derivation_shape(
        universe_count=1001, holdout_fraction_ppm=500000, holdout_count=593
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s6_splits_held_out(bundle, context)
    assert caught.value.code == "SPLIT_SIZE_IMPLAUSIBLE"
    assert caught.value.field == "evaluation_splits.holdout"


def test_s6_split_size_implausible_declare_20_percent_ship_2_percent_full_runner() -> None:
    """The design's own literal headline example (P1-V2.5 review P3-6): a
    declared 20% holdout (``holdout_fraction_ppm=200000``) shipped as a 2%
    holdout at N=10000 (h=200) -- round(N*p)=2000, tolerance is tiny next to
    a delta of 1800, so this must be SPLIT_SIZE_IMPLAUSIBLE. Starts from the
    golden bundle (universe 1000) and scales BOTH the universe and the
    selection/holdout split by 10x, leaving holdout.item_count (and
    therefore every S5 sample-size binding, which stays pinned to 200)
    untouched, so only the plausibility bound itself is exercised."""
    bundle = build_agent_quality_bundle()
    bundle["split_derivation"]["evaluated_universe_item_count"] = 10000
    bundle["split_derivation"]["holdout_fraction_ppm"] = 200000
    bundle["evaluation_splits"][0]["item_count"] = 9800
    bundle["evaluation_splits"][1]["item_count"] = 200
    resigned = resign_agent_quality_bundle(bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            resigned, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SPLIT_SIZE_IMPLAUSIBLE"
    assert caught.value.field == "evaluation_splits.holdout"


def test_s6_arm_count_mismatch_full_runner() -> None:
    """Row 50: ``selection_arm_count`` disagrees between the manifest and
    the declared plan -- both independently-typed integers, not tied
    together by the schema. ``_gv_close`` sets the manifest's OWN copy from
    whatever the declared plan's copy is at close time, so mutating the
    declared plan's copy pre-resign would just make both sides agree on the
    mutated value instead of disagreeing; the manifest's copy is mutated
    directly instead, via :func:`_gv_reclose_after_manifest_field_mutation`
    (P1-V2.5-fix review P3-C), which re-signs the ISSUER signature over the
    mutated manifest afterward -- a genuinely, validly signed negative, not
    a bundle whose top-level signature is simply broken."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle, lambda manifest: manifest.__setitem__("selection_arm_count", 5)
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "ARM_COUNT_MISMATCH"
    assert caught.value.field == "unsigned_manifest"


def test_s6_selection_estimate_duplicate_full_runner() -> None:
    """The second G6 wiring: two ``non_certified_selection_estimates``
    records sharing an ``objective_id`` -- schema-valid (the schema's own
    description says uniqueItems cannot express this, see
    test_selection_estimate_duplicate_is_not_schema_preempted), rejected
    only by this stage's :func:`v._unique_by` call."""
    bundle = build_agent_quality_bundle(
        non_certified_selection_estimates=[
            _schema_fixtures._selection_estimate(point_estimate=970000),
            _schema_fixtures._selection_estimate(point_estimate=960000),
        ]
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SELECTION_ESTIMATE_DUPLICATE"
    assert caught.value.field == "non_certified_selection_estimates"


# ==========================================================================
# Row 48 (SPLIT_OPENING_MISMATCH / SPLIT_OPENING_RULE_VIOLATION): v1 ships
# no witness schema at all. The runner refuses fail-closed with CONTEXT
# whenever a caller supplies ``split_opening``, before any stage runs.
# ==========================================================================


def test_split_opening_none_is_the_only_accepted_value_golden_path_still_passes() -> None:
    """Passing ``split_opening=None`` explicitly must behave identically to
    omitting it -- the golden bundle still verifies end to end (P1-V2.4
    commit 2 retarget, sanctioned by the packet brief: every stage is now
    real, so there is no placeholder boundary left to "reach")."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    result = v._run_agent_quality_checks(
        bundle,
        context=context,
        process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
        split_opening=None,
    )
    assert result.code == "AGENT_QUALITY_VERIFIED"


def test_split_opening_non_none_is_refused_fail_closed() -> None:
    """Any non-``None`` ``split_opening`` -- even an empty mapping -- is
    refused BEFORE any stage runs, with the existing CONTEXT code at the
    existing ``split_opening_witness`` field location. Uses a bundle that
    would otherwise verify past every real stage, to prove the refusal
    happens unconditionally rather than merely surfacing sooner than some
    other failure would."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
            split_opening={},
        )
    assert caught.value.code == "CONTEXT"
    assert caught.value.field == "split_opening_witness"


def test_split_opening_sentinel_never_leaks_through_the_refusal() -> None:
    """P1-V2.5 review P3-7: a ``split_opening`` carrying a sentinel string
    is refused the same as any other non-``None`` value, and the sentinel
    itself never reaches the raised error's message, cause, context, or a
    formatted traceback -- the runner's refusal is content-free the same
    way :func:`test_import_time_package_data_validation` proves for
    package-data corruption."""
    sentinel = "SENTINEL_SPLIT_OPENING_" + "Q" * 32
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as excinfo:
        v._run_agent_quality_checks(
            bundle,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
            split_opening={"witness": sentinel},
        )
    exc = excinfo.value
    assert exc.code == "CONTEXT"
    assert exc.field == "split_opening_witness"
    assert sentinel not in str(exc)
    assert sentinel not in repr(exc.__cause__)
    assert sentinel not in repr(exc.__context__)
    formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert sentinel not in formatted


def test_split_opening_input_preempted_codes_are_never_emitted() -> None:
    """SPLIT_OPENING_MISMATCH/SPLIT_OPENING_RULE_VIOLATION have NO guard
    anywhere in the module -- there is nothing to check a witness against
    when v1 defines no witness schema at all."""
    source = Path(v.__file__).read_text()
    tree = ast.parse(source, filename=v.__file__)
    emitted = frozenset(code for (_fn, code, _line) in _emission_sites(tree))
    assert v.AGENT_QUALITY_INPUT_PREEMPTED_CODES.isdisjoint(emitted)
    assert v.AGENT_QUALITY_INPUT_PREEMPTED_CODES == {
        "SPLIT_OPENING_MISMATCH",
        "SPLIT_OPENING_RULE_VIOLATION",
    }
    assert v.AGENT_QUALITY_INPUT_PREEMPTED_CODES <= v.AGENT_QUALITY_ERROR_CODES
    assert v.AGENT_QUALITY_INPUT_PREEMPTED_CODES.isdisjoint(v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES)
    assert v.AGENT_QUALITY_INPUT_PREEMPTED_CODES.isdisjoint(v.AGENT_QUALITY_PENDING_CODES)
    assert set(v._STAGE_CODES.get("_stage_s6_splits_held_out", frozenset())).isdisjoint(
        v.AGENT_QUALITY_INPUT_PREEMPTED_CODES
    )


# ==========================================================================
# P1-V2.5 commit 2 -- S7 real checks (design rows 53-56): claim-support
# composition and abstention, pillar-support shape, and the assertion
# digest.
# ==========================================================================


def test_s7_passes_the_golden_bundle() -> None:
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    v._stage_s7_composition_abstention(bundle, context)


def test_s7_passes_the_abstained_golden_bundle_when_accepted() -> None:
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    v._stage_s7_composition_abstention(bundle, context)


def test_s7_pillar_support_shape_wrong_subject_order_direct_call() -> None:
    """Row 54: the two entries are swapped -- ``dataset`` shows up at index
    1 and ``evaluator`` at index 0. ``PillarSupportV1``'s own per-position
    ``support_subject``/``condition_code`` consts already make this
    schema-invalid, so this is a direct-stage-call proof of S7's own
    defensive check (mirroring how S5's tests distinguish schema-enforced
    shape from this stage's own guard). P1-V2.5 review P2-4: renamed from
    ``..._full_runner`` -- it calls the stage directly, not the runner, and
    the old name overclaimed."""
    bundle = build_agent_quality_bundle()
    bundle["unsigned_manifest"]["pillar_support"] = list(
        reversed(bundle["unsigned_manifest"]["pillar_support"])
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s7_composition_abstention(bundle, context)
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.dataset"


def test_s7_pillar_support_shape_wrong_dataset_commitment_ref_full_runner() -> None:
    """Row 54's real (non-schema-fixed) work: ``bound_commitment_ref`` must
    equal the manifest's OWN real ``dataset_commitment_ref`` -- a
    self-consistent but FOREIGN ref is schema-valid (both are just
    Sha256Digest-shaped strings) yet wrong. P1-V2.5 review P2-4: re-signed
    with :func:`_gv_reclose_after_manifest_field_mutation` (``_gv_close``
    itself would unconditionally rebuild ``pillar_support`` from the golden
    refs, silently repairing the defect -- the mutation happens AFTER
    closing, then only the issuer signature is redone over the mutated
    manifest)."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle,
        lambda manifest: manifest["pillar_support"][0].__setitem__(
            "bound_commitment_ref", "sha256:" + "9" * 64
        ),
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.dataset"


def test_s7_pillar_support_shape_wrong_evaluator_commitment_ref_full_runner() -> None:
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle,
        lambda manifest: manifest["pillar_support"][1].__setitem__(
            "bound_commitment_ref", "sha256:" + "9" * 64
        ),
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.evaluator"


def test_s7_pillar_support_shape_ref_nullity_bound_manifest_digest_full_runner() -> None:
    """P1-V2.5 review P2-2 (design row 54's ref-nullity clause): an entry
    whose ``status`` is ``condition_declared_unverified`` must carry NONE of
    ``bound_manifest_digest``/``evidence_ref``/``trust_anchor_ref`` -- a
    signed, schema-valid bundle carrying ``bound_manifest_digest`` on the
    ``pillar_support[0]`` (dataset) entry anyway must now be refused, not
    verified with the result still (correctly) reporting
    ``*_not_verified``."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle,
        lambda manifest: manifest["pillar_support"][0].__setitem__(
            "bound_manifest_digest", "sha256:" + "9" * 64
        ),
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.dataset"


def test_s7_pillar_support_shape_ref_nullity_trust_anchor_ref_full_runner() -> None:
    """P1-V2.5 review P2-2's second case: ``trust_anchor_ref`` on the
    ``pillar_support[1]`` (evaluator) entry."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle,
        lambda manifest: manifest["pillar_support"][1].__setitem__(
            "trust_anchor_ref", "trust-anchor:AAAAAAAA12345678"
        ),
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.evaluator"


def test_s7_pillar_support_shape_ref_nullity_evidence_ref_full_runner() -> None:
    """P1-V2.5-fix review P3-D: the ref-nullity clause's THIRD field,
    ``evidence_ref``, had no dedicated test -- only ``bound_manifest_digest``
    and ``trust_anchor_ref`` did (P2-2 above), so dropping the
    ``"evidence_ref" in entry`` arm of the guard failed nothing. Same shape
    as the other two, on the dataset entry."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle,
        lambda manifest: manifest["pillar_support"][0].__setitem__(
            "evidence_ref",
            {"evidence_kind": "verifier_report_digest", "evidence_digest": _GV_SHA},
        ),
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "PILLAR_SUPPORT_SHAPE"
    assert caught.value.field == "pillar_support.dataset"


def test_s7_assertion_digest_mismatch_manifest_copy_full_runner() -> None:
    """Row 56: the MANIFEST's own copy of ``assertion_digest`` disagrees,
    even though the assertion's own field is internally consistent with
    its content. P1-V2.5 review P2-4: re-signed with
    :func:`_gv_reclose_after_manifest_field_mutation` instead of a bundle
    whose top-level signature is left broken."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle, lambda manifest: manifest.__setitem__("assertion_digest", "sha256:" + "9" * 64)
    )
    assert _gv_bundle_validator().is_valid(closed)
    assert _gv_signature_verifies(closed)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "ASSERTION_DIGEST_MISMATCH"
    assert caught.value.field == "assertion"


def test_s7_assertion_digest_mismatch_wrong_rendered_text_direct_call() -> None:
    """Row 56's mechanical-rendering half: ``rendered_text`` no longer
    equals the schema's own fixed ``const``.
    ``AgentQualityAssertionV1.rendered_text`` is itself a hard schema
    ``const``, so no schema-valid bundle can carry any other string --
    this is a direct-stage-call proof of S7's own defensive check
    (the same backstop pattern as several S5/S6 codes), not a
    full-runner one."""
    bundle = build_agent_quality_bundle()
    bundle["assertion"]["rendered_text"] = "A materially different certified sentence."
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s7_composition_abstention(bundle, context)
    assert caught.value.code == "ASSERTION_DIGEST_MISMATCH"
    assert caught.value.field == "assertion"


# ==========================================================================
# P1-V2.3 -- mutate-the-guard: S2, S3, S4 negatives fail ONLY when that
# stage's own body is gutted, with zero leakage across stage boundaries.
# ==========================================================================


# P1-V2.3 review P2-1 closure: the previous version of this test asserted
# only that a gutted-stage bundle still raised *some*
# AgentQualityVerificationError -- true unconditionally while ANY later
# stage is an unconditional refusal, so it passed even with all of S2/S3/S4
# gutted simultaneously (a tautology, not a mutation-detection test). This
# version is REAL: per stage, a representative negative bundle (i) raises
# THAT STAGE's own owned code with the stage intact, and (ii) raises a
# DIFFERENT code once the stage is gutted, proving the gutted stage no
# longer catches the violation it owns. P1-V2.5 commit 2: every stage is
# now real, so there is no shared "later placeholder" left -- the code each
# gutted case (ii) actually produces is whichever real, later check
# happens to ALSO notice the same underlying inconsistency (typically one
# of S8's digest-mismatch codes, since these mutations are never
# re-signed); see :func:`test_gutting_s7_lets_a_wrong_assertion_digest_through`
# below for S7's OWN case, which is qualitatively different: NOTHING
# downstream catches it, so gutting S7 lets a genuinely bad bundle verify
# successfully -- proof that S7 is uniquely load-bearing for
# ASSERTION_DIGEST_MISMATCH, not merely first.
_GUTTING_REPRESENTATIVE_CASES: dict[str, tuple[Callable[[dict], None], str]] = {
    "_stage_s2_context_binding": (
        lambda bundle: bundle["unsigned_manifest"].__setitem__(
            "agent_commitment_ref", "sha256:" + "9" * 64
        ),
        "COMMITMENT_REF_MISMATCH",
    ),
    "_stage_s3_registry_identity": (
        lambda bundle: bundle["unsigned_manifest"].__setitem__(
            "quantile_table",
            dict(bundle["unsigned_manifest"]["quantile_table"], table_digest="sha256:" + "9" * 64),
        ),
        "QUANTILE_TABLE_MISMATCH",
    ),
    "_stage_s4_declared_plan_signatures": (
        lambda bundle: bundle["unsigned_manifest"].__setitem__(
            "declared_plan_digest", "sha256:" + "9" * 64
        ),
        "DECLARED_PLAN_DIGEST_MISMATCH",
    ),
    "_stage_s5_objective_measurement": (
        lambda bundle: bundle["measured_claims"][0].__setitem__(
            "objective_id", "obj.cost.mean_microusd_per_item.v1"
        ),
        "OBJECTIVE_NOT_IN_DECLARED_PLAN",
    ),
    "_stage_s6_splits_held_out": (
        lambda bundle: bundle["evaluation_splits"][1].__setitem__(
            "split_commitment_digest", bundle["evaluation_splits"][0]["split_commitment_digest"]
        ),
        "SPLIT_COMMITMENT_COLLISION",
    ),
}


@pytest.mark.parametrize("stage_name", sorted(_GUTTING_REPRESENTATIVE_CASES))
def test_gutting_one_stage_body_fails_only_its_own_negatives(stage_name: str) -> None:
    """Mutate-the-guard: replacing one stage's body with ``return None``
    must make ONLY that stage's own representative negative stop being
    caught -- proving each of S2, S3, S4, S5 and S6 is independently
    load-bearing, with no cross-stage leakage. This complements the
    P1-V2.2 review's own S1/S8 probes (reported by a human reviewer, not
    automated here) with an in-suite mechanical check for the stages this
    thread has wired real checks for."""
    mutate, owned_code = _GUTTING_REPRESENTATIVE_CASES[stage_name]

    intact_bundle = build_agent_quality_bundle()
    mutate(intact_bundle)
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            intact_bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == owned_code

    stage = getattr(v, stage_name)
    owned = stage.owns

    def _gutted(*args: object, **kwargs: object) -> None:
        return None

    _gutted.owns = owned  # type: ignore[attr-defined]
    with patch.object(v, stage_name, _gutted):
        gutted_bundle = build_agent_quality_bundle()
        mutate(gutted_bundle)
        with pytest.raises(v.AgentQualityVerificationError) as caught_gutted:
            v._run_agent_quality_checks(
                gutted_bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
            )
    # P1-V2.5 commit 2: every stage is now real, so there is no shared
    # "later placeholder" left to catch a gutted stage's own violation --
    # whichever LATER real check happens to also notice the same
    # underlying inconsistency (typically one of S8's digest-mismatch
    # codes, since none of these mutations are re-signed) fires instead,
    # and it varies by which stage/mutation this is. The invariant that
    # generalizes is simply: it is NOT the gutted stage's own code.
    assert caught_gutted.value.code != owned_code


def test_gutting_s7_lets_a_wrong_assertion_digest_through() -> None:
    """S7's own mutate-the-guard case, kept separate from
    :func:`test_gutting_one_stage_body_fails_only_its_own_negatives`'s
    uniform table because the shape of the proof is different: mutating
    ONLY ``assertion.assertion_digest`` (leaving the assertion's other
    content, the manifest's own ``assertion_digest`` copy, and
    ``claim_support_rows[0].assertion_digest`` all at their ORIGINAL
    correct values) is caught by S7 alone -- S8 never reads
    ``assertion["assertion_digest"]`` at all; it recomputes its own fresh
    digest from the assertion's OTHER content for the claim-material/
    claim-support-row checks, so a wrong value in that ONE field is
    invisible to S8's own guards.

    With S7 intact: ASSERTION_DIGEST_MISMATCH, as usual. With S7 gutted: NO
    exception at all -- the runner returns a "successful"
    :class:`v.AgentQualityVerificationResult` despite the bundle's own
    ``assertion.assertion_digest`` field being wrong. This is the
    documented asymmetry the packet brief calls out: a gutted real-check
    stage can let a genuinely bad bundle verify, which is a STRONGER
    failure mode than "a different code fires instead."""
    bundle = build_agent_quality_bundle()
    bundle["assertion"]["assertion_digest"] = "sha256:" + "9" * 64
    context = build_agent_quality_context()

    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "ASSERTION_DIGEST_MISMATCH"

    def _gutted(*args: object, **kwargs: object) -> None:
        return None

    _gutted.owns = v._stage_s7_composition_abstention.owns  # type: ignore[attr-defined]
    with patch.object(v, "_stage_s7_composition_abstention", _gutted):
        result = v._run_agent_quality_checks(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert result.code == "AGENT_QUALITY_VERIFIED"


# --- G9: wire-error code mapping and tripwire ---


def test_wire_error_code_mapping_covers_every_verifier_code() -> None:
    """G9 tripwire (a): AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE's keys are
    exactly AGENT_QUALITY_ERROR_CODES -- a verifier code added without also
    being sorted into a wire bucket would otherwise disappear from the
    mapping silently instead of raising here."""
    assert set(v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE) == v.AGENT_QUALITY_ERROR_CODES


def test_wire_error_code_mapping_values_are_schema_enum_members() -> None:
    """G9 tripwire (b): every mapped wire code is a member of the SHIPPED
    schema's AgentQualityErrorV1.code enum, read from the schema file
    itself (``SCHEMA``), not a literal copy of the enum retyped here."""
    schema_codes = set(SCHEMA["definitions"]["AgentQualityErrorV1"]["properties"]["code"]["enum"])
    offenders = {
        code: wire
        for code, wire in v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE.items()
        if wire not in schema_codes
    }
    assert offenders == {}


def test_wire_error_code_mapping_uses_every_schema_enum_member() -> None:
    """G9 tripwire (c): every one of the schema's wire codes is actually
    used by at least one verifier code -- no dead wire bucket that the
    schema advertises but this module never emits."""
    schema_codes = set(SCHEMA["definitions"]["AgentQualityErrorV1"]["properties"]["code"]["enum"])
    used = set(v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE.values())
    assert schema_codes <= used


# P1-V2.6 final-review closure P2-1: an explicit, per-code golden mapping,
# typed out independently of the module's own bucket frozensets, so a bug
# in the module's grouping (a bucket typo, or a code silently moved to the
# wrong bucket) is caught by plain equality against THIS dict -- not by a
# partition/coverage property that a wrong-but-still-total table can still
# satisfy. Grouped the same way the module's own buckets are documented.
_G9_EXPECTED_WIRE_BUCKET_BY_CODE: dict[str, str] = {
    **dict.fromkeys(
        (
            "OBJECTIVE_DUPLICATE",
            "QUANTILE_TABLE_LOOKUP_FAILED",
            "SELECTION_ESTIMATE_DUPLICATE",
            "OBJECTIVE_NOT_IN_DECLARED_PLAN",
            "PRIMARY_OBJECTIVE_MISSING",
            "OBJECTIVE_NOT_REGISTERED",
            "OBJECTIVE_KIND_MISMATCH",
            "OBJECTIVE_UNIT_MISMATCH",
            "OBJECTIVE_MINIMUM_SAMPLE_NOT_MET",
            "DISTRIBUTION_ASSUMPTION_NOT_REGISTERED",
            "INTERVAL_METHOD_NOT_EMITTABLE",
            "INTERVAL_METHOD_NOT_ADMISSIBLE",
            "SUFFICIENT_STATISTICS_SHAPE",
            "POINT_ESTIMATE_RECOMPUTATION_MISMATCH",
            "INTERVAL_RECOMPUTATION_MISMATCH",
            "INTERVAL_ORDER",
            "INTERVAL_DEGENERATE",
            "INTERVAL_OUT_OF_UNIT_BOUNDS",
            "NOMINAL_COVERAGE_MISMATCH",
            "SAMPLE_SIZE_MISMATCH",
            "VERIFICATION_LEVEL_MISMATCH",
            "HOLDOUT_NOT_USED",
        ),
        "agent_quality_invalid_measurement",
    ),
    **dict.fromkeys(
        (
            "SPLIT_SET_SHAPE",
            "HOLDOUT_MISSING",
            "HOLDOUT_TOO_SMALL",
            "SPLIT_DERIVATION_MISMATCH",
            "SPLIT_PARTITION_INCOMPLETE",
            "SPLIT_COMMITMENT_COLLISION",
            "SPLIT_SIZE_IMPLAUSIBLE",
            "SPLIT_OPENING_MISMATCH",
            "SPLIT_OPENING_RULE_VIOLATION",
            "HOLDOUT_REUSED",
            "ARM_COUNT_MISMATCH",
        ),
        "agent_quality_invalid_split",
    ),
    **dict.fromkeys(
        (
            "DECLARED_PLAN_DIGEST_MISMATCH",
            "DECLARED_PLAN_SIGNATURE_INVALID",
            "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
            "DECLARED_PLAN_PIN_MISMATCH",
        ),
        "agent_quality_invalid_declared_plan",
    ),
    **dict.fromkeys(
        (
            "CONTEXT",
            "PACKAGE_DATA_INVALID",
            "AGENT_QUALITY_VERIFICATION_FAILED",
            "BUNDLE_SHAPE",
            "STRICT_INTEGER",
            "UNSAFE_INTEGER",
            "SCHEMA",
            "SCHEMA_DEPENDENCY",
            "CANONICALIZATION",
            "PROCESS_RECORD_BINDING_MISMATCH",
            "COMMITMENT_REF_MISMATCH",
            "SCOPE_MISMATCH",
            "MEASUREMENT_CONTRACT_NOT_PINNED",
            "MEASUREMENT_CONTRACT_MISMATCH",
            "AGGREGATION_POLICY_MISMATCH",
            "OBJECTIVE_REGISTRY_MISMATCH",
            "NON_CLAIM_SET_MISMATCH",
            "QUANTILE_TABLE_MISMATCH",
            "CLAIM_NOT_VERIFIED",
            "PILLAR_SUPPORT_SHAPE",
            "PILLAR_BINDING_MISMATCH",
            "ASSERTION_DIGEST_MISMATCH",
            "SPLIT_DERIVATION_DIGEST_MISMATCH",
            "EVALUATION_SPLITS_DIGEST_MISMATCH",
            "MEASURED_CLAIMS_DIGEST_MISMATCH",
            "SELECTION_ESTIMATES_DIGEST_MISMATCH",
            "NON_CLAIMS_DIGEST_MISMATCH",
            "CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH",
            "CLAIM_SUPPORT_ROW_MISMATCH",
            "UNSIGNED_MANIFEST_MISMATCH",
            "UNSIGNED_MANIFEST_DIGEST_MISMATCH",
            "KEY_RING_MISMATCH",
            "ISSUER_SIGNATURE_INVALID",
            "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
            "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
        ),
        "agent_quality_verification_failed",
    ),
}


def test_wire_error_code_mapping_matches_golden_bucket_assignment() -> None:
    """G9 tripwire (d): plain equality between the module's REAL
    ``AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE`` and an independently
    typed-out golden dict (:data:`_G9_EXPECTED_WIRE_BUCKET_BY_CODE`). Unlike
    a partition/coverage property (which a total-but-wrong table can still
    satisfy), this catches a single code silently sorted into the wrong
    bucket, or a bucket-name typo -- both reproduced as real module
    mutations below."""
    assert dict(v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE) == _G9_EXPECTED_WIRE_BUCKET_BY_CODE
    assert set(_G9_EXPECTED_WIRE_BUCKET_BY_CODE) == v.AGENT_QUALITY_ERROR_CODES


def _gv_exec_mutated_agent_quality_module(mutate_source: Callable[[str], str]) -> dict:
    """Exec a mutated copy of ``agent_quality_verifier.py``'s OWN source
    text in a fresh namespace and return its globals. All of the module's
    imports are absolute (none relative to its package location), so this
    is safe outside the real package tree. Used so the G9 mutation tests
    below exercise the REAL module-level bucket/table construction -- not a
    scratch dict standing in for it, which is what made the prior version
    of these tests tautological (P1-V2.6 final review P2-1)."""
    source = Path(v.__file__).read_text(encoding="utf-8")
    mutated_source = mutate_source(source)
    assert mutated_source != source, "mutate_source must actually change the module text"
    module_name = f"agent_quality_verifier_mutant_{id(mutate_source)}"
    mutant_module = _gv_types.ModuleType(module_name)
    mutant_module.__file__ = str(v.__file__)
    sys.modules[module_name] = mutant_module
    try:
        exec(compile(mutated_source, str(v.__file__), "exec"), mutant_module.__dict__)
    finally:
        del sys.modules[module_name]
    return mutant_module.__dict__


def test_wire_error_code_mapping_missing_key_breaks_tripwire_a() -> None:
    """G9 tripwire (d), mutation 1: a verifier code added to
    AGENT_QUALITY_ERROR_CODES's own literal set without a matching entry in
    any of the four wire buckets -- against the REAL module source, exec'd
    fresh. The mutant's own AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE genuinely
    omits the new code, breaking tripwire (a)."""
    mutant = _gv_exec_mutated_agent_quality_module(
        lambda source: source.replace(
            '        "AGENT_QUALITY_VERIFICATION_FAILED",\n',
            '        "AGENT_QUALITY_VERIFICATION_FAILED",\n        "CANARY_NEW_VERIFIER_CODE",\n',
            1,
        )
    )
    assert (
        set(mutant["AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE"]) != mutant["AGENT_QUALITY_ERROR_CODES"]
    )


def test_wire_error_code_mapping_bucket_typo_breaks_a_named_test() -> None:
    """G9 tripwire (d), mutation 2 -- the reviewer's G9d: a bucket-entry
    typo (``"HOLDOUT_NOT_USEDX"`` instead of ``"HOLDOUT_NOT_USED"``) inside
    the measurement bucket, against the REAL module source. The real code
    HOLDOUT_NOT_USED is still in AGENT_QUALITY_ERROR_CODES but no longer in
    any wire bucket -- tripwire (a) (key-set equality) catches it, and so
    does the golden-dict equality in
    :func:`test_wire_error_code_mapping_matches_golden_bucket_assignment`,
    which the reviewer's probe found NOTHING caught against the old
    comprehension-based table."""
    mutant = _gv_exec_mutated_agent_quality_module(
        lambda source: source.replace(
            '        "VERIFICATION_LEVEL_MISMATCH",\n'
            '        "HOLDOUT_NOT_USED",\n'
            "    }\n"
            ")\n"
            "_AGENT_QUALITY_WIRE_SPLIT_CODES",
            '        "VERIFICATION_LEVEL_MISMATCH",\n'
            '        "HOLDOUT_NOT_USEDX",\n'
            "    }\n"
            ")\n"
            "_AGENT_QUALITY_WIRE_SPLIT_CODES",
            1,
        )
    )
    mutant_table = mutant["AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE"]
    assert set(mutant_table) != mutant["AGENT_QUALITY_ERROR_CODES"]
    assert dict(mutant_table) != _G9_EXPECTED_WIRE_BUCKET_BY_CODE


def test_wire_error_code_mapping_code_moved_between_buckets_breaks_a_named_test() -> None:
    """G9 tripwire (d), mutation 3 -- the reviewer's G9e: a code moved
    between buckets (INTERVAL_RECOMPUTATION_MISMATCH relocated from
    measurement into split), against the REAL module source. Both buckets
    stay internally well-formed (no typo, no dropped/duplicated key,
    partition and coverage both still hold) -- the reviewer's probe found
    NO test in the old suite caught this. The golden-dict equality in
    :func:`test_wire_error_code_mapping_matches_golden_bucket_assignment`
    does: it fails here because the mutant maps
    INTERVAL_RECOMPUTATION_MISMATCH to a different wire code than the
    golden dict does."""
    mutant = _gv_exec_mutated_agent_quality_module(
        lambda source: source.replace(
            '        "POINT_ESTIMATE_RECOMPUTATION_MISMATCH",\n'
            '        "INTERVAL_RECOMPUTATION_MISMATCH",\n'
            '        "INTERVAL_ORDER",\n'
            '        "INTERVAL_DEGENERATE",\n'
            '        "INTERVAL_OUT_OF_UNIT_BOUNDS",\n'
            '        "NOMINAL_COVERAGE_MISMATCH",\n'
            '        "SAMPLE_SIZE_MISMATCH",\n'
            '        "VERIFICATION_LEVEL_MISMATCH",\n'
            '        "HOLDOUT_NOT_USED",\n'
            "    }\n"
            ")\n"
            "_AGENT_QUALITY_WIRE_SPLIT_CODES: frozenset[str] = frozenset(\n"
            "    {\n"
            '        "SPLIT_SET_SHAPE",\n'
            '        "HOLDOUT_MISSING",\n'
            '        "HOLDOUT_TOO_SMALL",\n'
            '        "SPLIT_DERIVATION_MISMATCH",\n'
            '        "SPLIT_PARTITION_INCOMPLETE",\n'
            '        "SPLIT_COMMITMENT_COLLISION",\n'
            '        "SPLIT_SIZE_IMPLAUSIBLE",\n',
            '        "POINT_ESTIMATE_RECOMPUTATION_MISMATCH",\n'
            '        "INTERVAL_ORDER",\n'
            '        "INTERVAL_DEGENERATE",\n'
            '        "INTERVAL_OUT_OF_UNIT_BOUNDS",\n'
            '        "NOMINAL_COVERAGE_MISMATCH",\n'
            '        "SAMPLE_SIZE_MISMATCH",\n'
            '        "VERIFICATION_LEVEL_MISMATCH",\n'
            '        "HOLDOUT_NOT_USED",\n'
            "    }\n"
            ")\n"
            "_AGENT_QUALITY_WIRE_SPLIT_CODES: frozenset[str] = frozenset(\n"
            "    {\n"
            '        "SPLIT_SET_SHAPE",\n'
            '        "HOLDOUT_MISSING",\n'
            '        "HOLDOUT_TOO_SMALL",\n'
            '        "SPLIT_DERIVATION_MISMATCH",\n'
            '        "SPLIT_PARTITION_INCOMPLETE",\n'
            '        "SPLIT_COMMITMENT_COLLISION",\n'
            '        "SPLIT_SIZE_IMPLAUSIBLE",\n'
            '        "INTERVAL_RECOMPUTATION_MISMATCH",\n',
            1,
        )
    )
    mutant_table = mutant["AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE"]
    # Still total and still a genuine partition -- the property-based
    # tripwires (a)/(b)/(c) all still hold on the mutant.
    assert set(mutant_table) == mutant["AGENT_QUALITY_ERROR_CODES"]
    schema_codes = set(SCHEMA["definitions"]["AgentQualityErrorV1"]["properties"]["code"]["enum"])
    assert set(mutant_table.values()) <= schema_codes
    assert schema_codes <= set(mutant_table.values())
    # ... yet the golden per-code assignment now disagrees for the moved
    # code specifically.
    assert (
        mutant_table["INTERVAL_RECOMPUTATION_MISMATCH"]
        != _G9_EXPECTED_WIRE_BUCKET_BY_CODE["INTERVAL_RECOMPUTATION_MISMATCH"]
    )
    assert dict(mutant_table) != _G9_EXPECTED_WIRE_BUCKET_BY_CODE


def test_wire_code_property_for_measurement_error_via_public_function() -> None:
    """G9 tripwire (e), measurement bucket: 150 clears S5's own
    ``minimum_sample_size`` floor but disagrees with both the holdout
    split's ``item_count`` and the sufficient statistics' ``trial_count``
    (mirrors test_s5_sample_size_mismatch, but through the public entry
    point rather than the private stage function)."""
    bundle = build_agent_quality_bundle()
    bundle["measured_claims"][0]["sample_size"] = 150
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "SAMPLE_SIZE_MISMATCH"
    assert caught.value.wire_code == "agent_quality_invalid_measurement"
    assert caught.value.wire_code == v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE["SAMPLE_SIZE_MISMATCH"]


def test_wire_code_property_for_split_error_via_public_function() -> None:
    """G9 tripwire (e), split bucket: a re-signed manifest whose
    ``selection_arm_count`` disagrees with the declared plan's (mirrors
    the ARM_COUNT_MISMATCH full-runner test), through the public entry
    point."""
    bundle = build_agent_quality_bundle()
    closed = _gv_reclose_after_manifest_field_mutation(
        bundle, lambda manifest: manifest.__setitem__("selection_arm_count", 5)
    )
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            closed, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "ARM_COUNT_MISMATCH"
    assert caught.value.wire_code == "agent_quality_invalid_split"
    assert caught.value.wire_code == v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE["ARM_COUNT_MISMATCH"]


def test_wire_code_property_for_declared_plan_error_via_public_function() -> None:
    """G9 tripwire (e), declared-plan bucket: the relying party's own pin
    disagrees with the bundle's declared plan digest (mirrors
    test_s4_declared_plan_pin_mismatch), through the public entry point."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context(expected_declared_plan_digest="sha256:" + "9" * 64)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle, context=context, process_record_bundle=_GV_PROCESS_RECORD_BUNDLE
        )
    assert caught.value.code == "DECLARED_PLAN_PIN_MISMATCH"
    assert caught.value.wire_code == "agent_quality_invalid_declared_plan"
    assert (
        caught.value.wire_code
        == v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE["DECLARED_PLAN_PIN_MISMATCH"]
    )


def test_wire_code_property_for_catch_all_error_via_public_function() -> None:
    """G9 tripwire (e), catch-all bucket: a non-``None`` ``split_opening``
    is refused by CONTEXT itself (mirrors
    test_verify_agent_quality_certificate_split_opening_still_refused),
    through the public entry point."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v.verify_agent_quality_certificate(
            bundle,
            context=context,
            process_record_bundle=_GV_PROCESS_RECORD_BUNDLE,
            split_opening={"anything": "at all"},
        )
    assert caught.value.code == "CONTEXT"
    assert caught.value.wire_code == "agent_quality_verification_failed"
    assert caught.value.wire_code == v.AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE["CONTEXT"]
