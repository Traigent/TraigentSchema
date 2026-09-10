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


# The module's public, module-owned callable surface as of origin/develop
# 4b3373925cee6bd57071980285c58044165c90a4 (the base this packet built on) --
# exactly the three dataclass/exception types that predate P1-V2.0, verified
# by loading that ref's copy of the module and computing the same set the
# test below computes. Frozen here so packet .6 (which ships the real
# ``verify_agent_quality_certificate`` entry point) has a single, explicit
# constant to update, rather than a test whose expectation is buried in
# assertion logic.
_AGENT_QUALITY_PUBLIC_SURFACE_AT_DEVELOP_BASE = frozenset(
    {
        "AgentQualityVerificationContext",
        "AgentQualityVerificationError",
        "AgentQualityVerificationResult",
    }
)


def test_no_public_entry_point_exists_yet() -> None:
    """Sol B1: this packet ships no public entry point. A half-checking
    verifier that reports success is worse than one that does not exist, so
    no public function -- under ANY name -- may exist on this module until
    the complete check sequence lands.

    P1-V2.0 review finding P1-3: the original version of this test only
    asserted the ABSENCE of the one string
    ``verify_agent_quality_certificate``, so a public entry point under any
    other name (``verify_agent_quality_bundle``, ``verify``, ``check``)
    shipped green. This version pins the module's entire module-owned
    callable surface to a FROZEN set captured from origin/develop, not just
    one forbidden name -- so ANY newly added public callable breaks it,
    named however. The ``__module__`` filter excludes the re-exported
    stdlib/typing names (``Any``, ``Callable``, ``dataclass``, ...) that are
    imported into this module's namespace but not defined by it. This test
    is deleted only in packet .6, once the real entry point ships and this
    constant is updated to include it."""
    module_owned_callables = {
        name
        for name in vars(v)
        if not name.startswith("_")
        and callable(getattr(v, name))
        and getattr(getattr(v, name), "__module__", None) == v.__name__
    }
    assert module_owned_callables == _AGENT_QUALITY_PUBLIC_SURFACE_AT_DEVELOP_BASE, (
        f"module-owned public callable surface drifted: {sorted(module_owned_callables)}"
    )
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


# S1 (and, once P1-V2.2 wires it, S8) is no longer an unconditional
# refusal, so it cannot share the uniform "any schema-valid bundle is
# refused with the catch-all" assertion below -- a schema-valid bundle is
# exactly what S1's real checks are supposed to PASS. S2-S7 remain
# placeholders in this packet and keep the uniform assertion; S1 gets its
# own dedicated fail-closed coverage in
# test_stage_s1_structural_is_a_real_fail_closed_function below.
_STILL_PLACEHOLDER_STAGE_FUNCTION_NAMES = tuple(
    name for name in _STAGE_FUNCTION_NAMES if name != "_stage_s1_structural"
)


@pytest.mark.parametrize("stage_name", _STILL_PLACEHOLDER_STAGE_FUNCTION_NAMES)
def test_each_stage_is_a_real_fail_closed_function(stage_name: str) -> None:
    """Every named stage exists, is independently callable with the uniform
    ``(bundle, context)`` signature all eight stages now share (P1-V2.0
    review finding P3-11: S4's own docstring already needs
    ``context.expected_declared_plan_digest`` and S3's registry pins are the
    same shape, so giving every stage the context now is cheaper than
    packets .2-.5 each having to widen a stage's signature later), and
    refuses (rather than silently passing) when called directly."""
    stage = getattr(v, stage_name)
    assert callable(stage)
    context = _context()
    bundle = _schema_fixtures._bundle()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        stage(bundle, context)
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"


def test_stage_s1_structural_is_a_real_fail_closed_function() -> None:
    """S1's real-check counterpart to
    :func:`test_each_stage_is_a_real_fail_closed_function`: unlike S2-S7, S1
    now PASSES a schema-valid bundle (see
    :func:`test_golden_bundle_reaches_private_runner_fail_closed_boundary`),
    so its "still fail-closed when called directly" proof uses a
    structurally-invalid bundle instead, and checks S1's own real code
    rather than the catch-all."""
    context = _context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._stage_s1_structural({"schema_version": "wrong"}, context)
    assert caught.value.code == "BUNDLE_SHAPE"
    assert caught.value.field == "bundle"


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
            v._run_agent_quality_checks(bad_bundle, context)  # type: ignore[arg-type]
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

    preempted = v.AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    pending = v.AGENT_QUALITY_PENDING_CODES
    module_subtraction_set = v.AGENT_QUALITY_ERROR_CODES - preempted - pending

    assert emitted_today == module_subtraction_set, (
        "a code started or stopped being emitted without "
        "AGENT_QUALITY_PENDING_CODES's subtraction being updated to match: "
        f"AST-derived={sorted(emitted_today)} "
        f"module-subtraction={sorted(module_subtraction_set)}"
    )
    assert preempted.isdisjoint(pending)
    assert preempted.isdisjoint(emitted_today)
    assert pending.isdisjoint(emitted_today)
    assert preempted | pending | emitted_today == v.AGENT_QUALITY_ERROR_CODES


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
# copied verbatim from AgentQualityUnsignedManifestV1's
# base_process_record_unsigned_manifest_digest field description (ASSUMED:
# no shipped process-record constant is imported here; ProcessRecordVerifier
# is out of this packet's boundary).
_GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN = "traigent.process_record.unsigned_manifest.v1"
# A minimal stand-in for "a process record's unsigned manifest" -- this
# schema only requires base_process_record_unsigned_manifest_digest to be A
# Sha256Digest string; it does not validate the shape of the document that
# digest is over, so any object serves as long as its digest is what is
# declared here (ASSUMED, since real process-record construction is out of
# this packet's boundary).
_GV_PROCESS_RECORD_UNSIGNED_MANIFEST_STUB = {
    "schema_version": _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN,
    "golden_vector_placeholder": True,
}

_GV_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_GV_PUBLIC_KEY = _GV_PRIVATE_KEY.public_key()
# A second, independent key -- deliberately NOT in any key ring the private
# runner will trust -- for the "wrong key, valid shape" fixture (checkpoint
# b.3).
_GV_FOREIGN_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))

_GV_ISSUER_KEY_REF = "issuerkey:aaaaaaaa"
_GV_TRUST_RING_REF = "trustring:aaaaaaaa"
_GV_PROJECT_REF = "proj-1"
_GV_BUILD_SESSION_REF = "build_session:ssssssss"
_GV_SHA = "sha256:" + "a" * 64

# Five independently-bound commitment/digest refs in the unsigned manifest's
# `coverage`-const field set (review P2-3): each must be a DISTINCT sentinel
# so a golden-vector mutation/swap between any two of them is not a no-op.
_GV_AGENT_COMMITMENT_REF = "sha256:" + "a1" * 32
_GV_DATASET_COMMITMENT_REF = "sha256:" + "a2" * 32
_GV_EVALUATOR_COMMITMENT_REF = "sha256:" + "a3" * 32
_GV_BUILD_DEFINITION_COMMITMENT_REF = "sha256:" + "a4" * 32
_GV_MEASUREMENT_CONTRACT_RECORD_DIGEST = "sha256:" + "a5" * 32
_GV_MEASUREMENT_CONTRACT_REF = "measurement:mmmmmmmm"


def build_agent_quality_context(**overrides: object) -> v.AgentQualityVerificationContext:
    """The context the golden bundle is bound to. A thin wrapper over
    :func:`_context` under the name this packet's brief specifies -- both
    names stay available and can never drift apart."""
    return _context(**overrides)


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
    return {
        "schema_version": _GV_DOMAINS["evaluation_split"],
        "split_id": split_id,
        "item_count": item_count,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "canonicalization_profile": "jcs_v1",
        "split_commitment_digest": _GV_SHA,
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
        measurement_contract_record_digest=_GV_SHA,
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
        measurement_contract_record_digest=_GV_SHA,
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
            _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN, _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_STUB
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
        "pillar_support": _schema_fixtures._pillar_support(),
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
    (over a minimal process-record-unsigned-manifest stand-in -- see
    :data:`_GV_PROCESS_RECORD_UNSIGNED_MANIFEST_STUB`'s docstring for why
    any object suffices) and ``scope_binding_digest`` (over
    ``ScopeBindingProjectionV1`` built from the same project/build-session
    refs :func:`build_agent_quality_context` uses)."""
    bundle = build_agent_quality_bundle()
    manifest = bundle["unsigned_manifest"]
    assert manifest["base_process_record_unsigned_manifest_digest"] == v._role_digest(
        _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN, _GV_PROCESS_RECORD_UNSIGNED_MANIFEST_STUB
    )
    assert manifest["scope_binding_digest"] == _gv_digest(
        "scope_binding",
        {
            "schema_version": _GV_DOMAINS["scope_binding"],
            "project_ref": _GV_PROJECT_REF,
            "build_session_ref": _GV_BUILD_SESSION_REF,
        },
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


def test_golden_bundle_reaches_private_runner_fail_closed_boundary() -> None:
    """P1-V2.2 retarget (sanctioned by the packet brief): S1's real
    structural checks now PASS the golden bundle -- it is schema-valid,
    digest-consistent, and canonicalizable by construction -- so the runner
    advances past S1 and is rejected at S2's still-unconditional-refusal
    placeholder instead. Proves S1 does not silently swallow a bundle it
    should pass, without yet asserting anything about S2-S7 (still
    placeholders) or S8 (real, but never reached from this boundary)."""
    bundle = build_agent_quality_bundle()
    context = build_agent_quality_context()
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(bundle, context)
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"
    assert caught.value.field == "scope_binding"


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


def test_abstained_golden_bundle_reaches_private_runner_fail_closed_boundary() -> None:
    """P1-V2.2 retarget (sanctioned by the packet brief), same shape as
    :func:`test_golden_bundle_reaches_private_runner_fail_closed_boundary`:
    the abstained golden bundle is also schema-valid, so it now passes S1
    and is refused at S2's placeholder."""
    bundle = build_abstained_agent_quality_bundle()
    context = build_agent_quality_context(accept_abstained_bundle=True)
    with pytest.raises(v.AgentQualityVerificationError) as caught:
        v._run_agent_quality_checks(bundle, context)
    assert caught.value.code == "AGENT_QUALITY_VERIFICATION_FAILED"
    assert caught.value.field == "scope_binding"


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
