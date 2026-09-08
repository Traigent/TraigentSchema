"""Regression tests for the six post-merge audit findings on PR #459
(pillar-1 agent-quality V1 contract, develop 8f8bb5882b0a04525a21888b190fc7fb04b7d430).

Each test below reproduces one of the reviewer's seven probes and failed at
8f8bb5882 before the corresponding fix landed. They exist so the six
findings cannot silently regress.
"""

from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

import traigent_schema.certification.agent_quality_verifier as v

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = (
    ROOT / "traigent_schema" / "schemas" / "certification" / "agent_quality_v1_schema.json"
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


def test_literal_zero_preregistration_stem_hits() -> None:
    """Finding 1: zero occurrences of the preregistration stem anywhere in
    the schema text, with no per-sentence exemption.

    Failed at 8f8bb5882 because the tripwire test exempted one sentence
    instead of requiring a literal zero.
    """
    assert re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", SCHEMA_TEXT, re.I) is None


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


def test_import_time_package_data_validation() -> None:
    """Finding 3: importing the module establishes the content-free
    package-data boundary unconditionally, not only on first lazy use.

    Failed at 8f8bb5882 because ``_load_agent_quality_document`` was a lazy
    loader nothing called at import, so a corrupt package installation was
    only caught on whichever caller happened to touch it first.
    """
    with patch("importlib.resources.files", side_effect=ValueError("SENTINEL")):
        with pytest.raises(ValueError, match="^PACKAGE_DATA_INVALID$") as excinfo:
            importlib.reload(v)
        assert "SENTINEL" not in str(excinfo.value)
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
