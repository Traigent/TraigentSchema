# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline relying-party verifier for Agent Quality Record v1 (pillar 1).

This module decides whether a supplied certificate bundle's measured
objective claims are internally reconstructible: for each certified claim it
recomputes the claimed interval's CONSTRUCTION from the printed sufficient
statistics under the bundle's own declared interval method, and checks the
declared endpoints against that recomputation. It does not recompute the
sufficient statistics themselves (they remain issuer attestations), does not
establish which items belong to the selection split versus the holdout split
(split membership is also an issuer attestation in v1, since v1 defines no
opening path), and makes no claim about ordering evidence -- that the
declared plan was authored before the results -- which is out of scope for
this certificate family in v1.

The closed error and field-location vocabularies, the caller-facing context
and result shapes, the content-free package-data loading boundary for this
pillar's four registries (objective registry, aggregation policy, non-claim
catalog, quantile table), the role-digest helper, the exact-integer
estimator recomputation (Wilson score bounds and Student-t half-widths), and
a private, eight-stage bundle runner in which every stage now runs a real,
fail-closed check are all private building blocks of the public entry
point, :func:`verify_agent_quality_certificate`.

A ``VERIFIED`` result from that entry point entitles a relying party to
conclude ONLY: an issuer whose key is in the pinned trust ring signed a
manifest binding THIS process record, THESE commitment refs and THIS scope
binding built from the relying party's own pins; the interval endpoints are
exactly recomputable from the declared sufficient statistics under
``exact_integer_rational_v1`` and the pinned quantile table; and the claim
was scored on the split the issuer labelled ``holdout``, with plausible
split arithmetic.

It does NOT establish that the sufficient statistics summarise the holdout
observations (the statistics remain issuer attestations); that the committed
splits are the rule's partition (v1 defines no opening witness, so split
membership is an issuer attestation); that the declared plan was authored
before the results were computed (ordering evidence is issuer-asserted and
out of scope in v1); that the split key predates knowledge of the item ids;
or that the estimator implementation is correct. It also does NOT establish
that the dataset or evaluator this certificate depends on are themselves
valid (see ``pillar_support``'s ``condition_declared_unverified``
disposition). This paragraph is the canonical ceiling; the public entry
point's docstring repeats it verbatim.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any, NoReturn, TypeVar, cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable

import traigent_schema.fp2 as fp2
from traigent_schema.certification.process_record_verifier import (
    ProcessRecordVerificationContext,
    ProcessRecordVerificationError,
    verify_process_record_certificate,
)
from traigent_schema.certification.relying_party_verifier import (
    _ISSUER_SPKI_DOMAIN,
    _material_public_key,
    _verify_signature,
)

_SCHEMA_RESOURCE = (
    resources.files("traigent_schema")
    .joinpath("schemas")
    .joinpath("certification")
    .joinpath("agent_quality_v1_schema.json")
)

_SHA256_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9_-]{8,128}$")

# The four package-data registries this pillar ships, keyed by the same stem
# used in their filenames (``agent_quality_<stem>.json`` /
# ``agent_quality_<stem>.digest.json``) and in
# ``AgentQualityDigestDomainRegistryV1`` (agent_quality_v1_schema.json), whose
# ``const`` values are copied here verbatim as the role-digest domain for
# each document. Each stem doubles as a valid ``AgentQualityFieldLocationV1``
# token, so a package-data failure for one of these four can carry a real,
# schema-owned field location rather than a synthetic one.
_AGENT_QUALITY_REGISTRY_DOMAINS: dict[str, str] = {
    "objective_registry": "traigent.agent_quality.objective_registry.v1",
    "aggregation_policy": "traigent.agent_quality.aggregation_policy.v1",
    "non_claim_catalog": "traigent.agent_quality.non_claim_catalog.v1",
    "quantile_table": "traigent.agent_quality.quantile_table.v1",
}

# base_process_record_unsigned_manifest_digest's domain (design row 64):
# the PROCESS RECORD family's own unsigned-manifest domain, not one of this
# schema's own AgentQualityDigestDomainRegistryV1 entries -- copied verbatim
# from process_record_verifier's private ``_UNSIGNED_MANIFEST_DOMAIN``
# (decoded to str; that module's constant is bytes) rather than imported, to
# keep this module's digest construction self-contained the same way
# _role_digest's own docstring explains for the sibling verifiers.
_PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN = "traigent.process_record.unsigned_manifest.v1"


def _schema_definition(name: str) -> dict[str, Any]:
    document = json.loads(_SCHEMA_RESOURCE.read_text(encoding="utf-8"))
    return cast(dict[str, Any], document["definitions"][name])


# AgentQualityDigestDomainRegistryV1's full const-value map, read from the
# shipped schema by comprehension rather than retyped -- the same pattern
# ``evaluator_quality_verifier._const_registry`` uses for its own digest
# domain registry. S8 (design rows 57-67) is this module's first caller of
# roles other than the four package-data registries already named in
# :data:`_AGENT_QUALITY_REGISTRY_DOMAINS`.
_AGENT_QUALITY_DIGEST_DOMAINS: dict[str, str] = {
    key: cast(str, value["const"])
    for key, value in _schema_definition("AgentQualityDigestDomainRegistryV1")["properties"].items()
}

# ppm / fixed-point scale shared by NominalCoveragePpmV1, the point-estimate
# fields, and the pinned quantile table's ``quantile_x1e6`` column.
_T_SCALE = 1_000_000
# QuantileTableDocumentV1's own sentinel: the df_bucket row that carries the
# standard-normal (infinite-degrees-of-freedom) quantile. _wilson_bounds
# reads exactly this row -- Wilson has no "degrees of freedom" of its own;
# the pinned table's infinity rung IS the z-quantile it needs.
_INFINITY_DF_BUCKET = 1_000_000_000
# Internal precision scale for the exact, floored integer square root used
# by _student_t_half_width. Not part of any wire contract.
_ISQRT_SCALE = 1_000_000


# Public, closed, content-free failure vocabulary. AgentQualityVerificationError
# never raises a code outside this set. Packet P1-V2.0 widens this frozenset
# from the five codes shipped in #459/#461 to the full vocabulary implied by
# the design's 68 check rows (re-derived against the SHIPPED schema, not the
# design doc's field names -- see the module's divergence notes). It must
# never shrink or rename what is already here, since these codes are
# load-bearing. See AGENT_QUALITY_SCHEMA_PREEMPTED_CODES,
# AGENT_QUALITY_PENDING_CODES, and _STAGE_CODES below for how this set is
# partitioned and owned.
AGENT_QUALITY_ERROR_CODES = frozenset(
    {
        # --- shipped in #459/#461, already emitted ---
        "CONTEXT",
        "PACKAGE_DATA_INVALID",
        "QUANTILE_TABLE_LOOKUP_FAILED",
        "OBJECTIVE_DUPLICATE",
        # Registered and enforced by _unique_by; no verification path in
        # this packet calls it yet -- the public entry point that would
        # apply it to non_certified_selection_estimates does not exist here.
        # It exists so the code is not invented later ad hoc, not because
        # anything in this module currently raises it.
        "SELECTION_ESTIMATE_DUPLICATE",
        # --- new in P1-V2.0: catch-all, emitted by every stage placeholder
        # and by _run_agent_quality_checks' own wrapper ---
        "AGENT_QUALITY_VERIFICATION_FAILED",
        # --- new in P1-V2.0: S1 structural (design rows 2-7, 10b) ---
        "BUNDLE_SHAPE",
        "STRICT_INTEGER",
        "UNSAFE_INTEGER",
        "SCHEMA",
        "SCHEMA_DEPENDENCY",
        "CANONICALIZATION",
        # --- new in P1-V2.0: S2 context binding (design rows 8-12) ---
        "PROCESS_RECORD_BINDING_MISMATCH",
        "COMMITMENT_REF_MISMATCH",
        "SCOPE_MISMATCH",
        "MEASUREMENT_CONTRACT_NOT_PINNED",
        "MEASUREMENT_CONTRACT_MISMATCH",
        # --- new in P1-V2.0: S3 registry identity (design rows 13-16) ---
        "AGGREGATION_POLICY_MISMATCH",
        "OBJECTIVE_REGISTRY_MISMATCH",
        "NON_CLAIM_SET_MISMATCH",
        "QUANTILE_TABLE_MISMATCH",
        # --- new in P1-V2.0: S4 declared-plan + signature (design rows
        # 17-19, 21; design row 20's ordering check is dropped -- see the
        # divergence notes above _stage_s4_declared_plan_signatures) ---
        "DECLARED_PLAN_DIGEST_MISMATCH",
        "DECLARED_PLAN_SIGNATURE_INVALID",
        "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
        "DECLARED_PLAN_PIN_MISMATCH",
        # --- new in P1-V2.0: S5 objective + measurement (design rows
        # 22-27, 29-39) ---
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
        # --- new in P1-V2.0: S6 splits + holdout (design rows 40-51 minus
        # the preempted SELECTION_ESTIMATE_IN_CERTIFIED_SET below) ---
        "SPLIT_SET_SHAPE",
        "HOLDOUT_NOT_USED",
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
        # --- new in P1-V2.0: S7 composition + abstention (design rows
        # 53-56 minus the preempted ABSTAINED_BUNDLE_CARRIES_CLAIMS below) ---
        "CLAIM_NOT_VERIFIED",
        "PILLAR_SUPPORT_SHAPE",
        "PILLAR_BINDING_MISMATCH",
        "ASSERTION_DIGEST_MISMATCH",
        # --- new in P1-V2.0: S8 manifest digests + signature (design rows
        # 57-67) ---
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
        # --- new in P1-V2.0: schema-preempted (see
        # AGENT_QUALITY_SCHEMA_PREEMPTED_CODES) ---
        "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
    }
)

# P1-V2.6 final-review closure P3-5: the two success codes
# AgentQualityVerificationResult.code is validated against in
# __post_init__ below -- exported (see __init__.py) the same way
# evaluator_quality_verifier exports EVALUATOR_QUALITY_VERIFIED /
# EVALUATOR_QUALITY_CLAIMS_PARTIAL, right after its own error-code set.
AGENT_QUALITY_VERIFIED = "AGENT_QUALITY_VERIFIED"
AGENT_QUALITY_CLAIM_ABSTAINED = "AGENT_QUALITY_CLAIM_ABSTAINED"

# Codes a schema-valid AgentQualityCertificateBundleV1 can never reach,
# because AgentQualityCertificateBundleV1's own ``allOf`` if/then/else
# abstention coupling rejects the construction before this module's
# verification pipeline ever runs (S1's schema check, design row 5). Proven
# by direct schema validation in
# test_agent_quality_verifier.py::test_abstained_bundle_carries_claims_is_schema_preempted
# and
# test_agent_quality_verifier.py::test_selection_estimate_in_certified_set_is_schema_preempted.
# SELECTION_ESTIMATE_DUPLICATE was CHECKED against the same hypothesis and
# found NOT preempted -- NonCertifiedSelectionEstimatesV1's own description
# says "uniqueItems cannot express it because two records may differ only in
# point_estimate or sample_size" -- so it stays in
# AGENT_QUALITY_PENDING_CODES instead.
#
# .4 commit 2 (S7) adds a third: PILLAR_BINDING_MISMATCH (design row 55).
# ``EmittablePillarStatusV1`` excludes ``assessed_supported`` entirely --
# only ``condition_declared_unverified`` is emittable in v1 -- so no
# schema-valid ``pillar_support`` entry can ever carry the
# ``bound_manifest_digest``/sibling-verification binding this code would
# check. v1 defines no sibling-bundle input mechanism to check one against,
# so unlike the eleven S5/S6 backstop codes (seven from S5, four from S6 --
# see :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES` below), there is
# no guard for this one anywhere in the module at all.
#
# These three codes have NO guard anywhere in this module -- genuinely dead
# vocabulary, registered so the string exists but never a call-site target.
AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES: frozenset[str] = frozenset(
    {
        "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
        "PILLAR_BINDING_MISMATCH",
    }
)

# P1-V2.4 review finding P2-2: a SECOND, different preemption mechanism.
# These seven codes DO have a live guard in :func:`_stage_s5_objective_measurement`
# (unlike the dead codes above) -- but no AgentQualityCertificateBundleV1
# instance that is itself schema-valid can ever trip one, because the
# shipped schema and the shipped package-data registries already agree,
# row for row, on every fact these guards would otherwise catch:
#   - OBJECTIVE_NOT_REGISTERED: EmittableObjectiveIdV1 is exactly the three
#     objective ids that ARE also entries in the shipped objective registry.
#   - OBJECTIVE_MINIMUM_SAMPLE_NOT_MET: MeasuredObjectiveClaimV1's own
#     per-objective_kind ``if``/``then`` branches set ``sample_size``'s
#     schema minimum to the SAME value as that objective's registry entry
#     (30 for binary_rate/bounded_mean, 200 for nonnegative_mean).
#   - DISTRIBUTION_ASSUMPTION_NOT_REGISTERED: the shipped registry's own two
#     nonnegative_mean entries both carry a registered distribution_assumption
#     unconditionally -- this is a PACKAGE-DATA invariant, not a bundle-shaped
#     one, so no bundle field can ever make it fail (only monkeypatching the
#     cached registry lookup can, as the direct-call unit test does).
#   - INTERVAL_METHOD_NOT_EMITTABLE: EmittableObjectiveKindV1 excludes
#     nonnegative_quantile entirely (the only kind whose admissible method,
#     order_statistic_quantile_v1, is not emittable), and IntervalParamsV1's
#     oneOf has no branch at all for bootstrap_percentile_v1 -- so a claim
#     naming either excluded method cannot be schema-valid in the first
#     place.
#   - INTERVAL_OUT_OF_UNIT_BOUNDS: MeasuredObjectiveClaimV1's own per-kind
#     ``if``/``then`` branches already cap point_estimate/interval_low/
#     interval_high at the SAME bound as that objective's registry entry
#     (1000000 for the two ppm-bound kinds; the registry's own 10**15 unit
#     maximum for nonnegative_mean, which the base schema already carries).
#   - VERIFICATION_LEVEL_MISMATCH: EmittableVerificationLevelV1 (the schema
#     type MeasuredObjectiveClaimV1.verification_level actually uses) is
#     ALREADY narrowed to the single member "construction_recomputed_v1" --
#     see :data:`_EMITTABLE_VERIFICATION_LEVELS`'s docstring for the same
#     narrowing on this module's own result type.
#   - QUANTILE_TABLE_LOOKUP_FAILED: NominalCoveragePpmV1's enum is exactly
#     the pinned table's three coverage columns, and
#     SufficientStatisticsMeanVarianceV1.sample_count has schema minimum 2
#     (df = sample_count - 1 >= 1, the table's own smallest df_bucket) -- so
#     :func:`_lookup_t_scaled` can never miss a bucket for a schema-valid
#     claim.
# Each guard is KEPT as a defensive backstop -- belt-and-braces for a caller
# that bypasses schema validation, or a stage called directly, as every
# per-stage unit test in this module does -- but is not, and cannot be,
# exercised by any schema-valid, re-signed bundle through the full pipeline.
# See test_agent_quality_verifier.py::
# test_schema_preempted_backstop_codes_are_proven_unreachable_by_schema for
# the per-code validator proof (a re-signed mutation that hits SCHEMA first,
# or a direct schema/registry equality assertion where the guard concerns
# package data rather than the bundle).
#
# .5 (S6) adds four more of the same shape, found by the SAME audit applied
# to S6's own owned codes before wiring them, rather than after a review
# caught it a second time:
#   - HOLDOUT_NOT_USED: MeasuredObjectiveClaimV1.evaluated_split_id is a
#     hard schema ``const: "holdout"`` -- no certified claim can ever name
#     any other split.
#   - HOLDOUT_MISSING: EvaluationSplitSetV1 is a fixed 2-tuple whose second
#     member's ``split_id`` is a hard schema ``const: "holdout"`` -- a
#     schema-valid bundle always carries one.
#   - HOLDOUT_TOO_SMALL: EvaluationSplitSetV1's holdout member already
#     carries ``item_count.minimum: 30`` (the base floor), and whenever a
#     certified claim exists, S5's SAMPLE_SIZE_MISMATCH -- which runs
#     first -- already forces ``holdout.item_count == claim.sample_size``,
#     and MeasuredObjectiveClaimV1's own per-kind ``if``/``then`` branches
#     already set that claim's ``sample_size`` schema minimum to its
#     objective's registered floor (see OBJECTIVE_MINIMUM_SAMPLE_NOT_MET
#     above) -- so the holdout size a schema-valid, S5-passing bundle can
#     ever carry already meets both halves of this check.
#   - HOLDOUT_REUSED: ``holdout_scored_arm_count`` is a hard schema
#     ``const: 1`` on BOTH AgentQualityUnsignedManifestV1 and
#     AgentQualityDeclaredPlanV1.
AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES: frozenset[str] = frozenset(
    {
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
)

# The full schema-preempted vocabulary: dead codes (no guard at all) union
# backstop codes (a live guard that a schema-valid bundle can never trip).
# P1-V2.5 review P2-3: these two sub-buckets are kept distinct rather than
# merged, because they have a one-sentence distinct definition -- a dead
# code has NO ``_fail(...)`` call site anywhere in this module, while a
# backstop code has a REAL, defensive ``_fail(...)`` call site that no
# schema-valid bundle can ever reach -- and the module's own emission-audit
# tests (test_schema_preempted_backstop_codes_have_a_live_guard_each) rely
# on that distinction to verify each half independently.
# INTERVAL_METHOD_NOT_ADMISSIBLE is deliberately NOT a member of either
# sub-bucket: P1-V2.4 review P2-1 gave it a SECOND, genuinely reachable path
# (a Wilson claim's own ``continuity_correction`` set to ``yates_v1``, fully
# schema-valid), even though its ORIGINAL path (interval_method mismatched
# with objective_kind) remains schema-preempted the same way the seven
# backstop codes above are -- one reachable path is enough to keep a code
# out of this bucket.
AGENT_QUALITY_SCHEMA_PREEMPTED_CODES: frozenset[str] = frozenset(
    AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES | AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES
)

# P1-V2.3 review finding P2-3: MEASUREMENT_CONTRACT_NOT_PINNED (design row
# 11) is structurally preempted the same way the three schema-preempted dead
# codes above are, just by a DIFFERENT authority: AgentQualityVerificationContext
# declares both measurement-contract pins as non-Optional ``str`` fields, so
# ``__post_init__`` already rejects a ``None`` pin with CONTEXT before
# _stage_s2_context_binding ever runs (see
# test_agent_quality_verifier.py::
# test_measurement_contract_pin_none_is_preempted_by_context_construction).
# S2's own defensive ``_fail("MEASUREMENT_CONTRACT_NOT_PINNED", "context")``
# stays -- belt-and-braces for a caller that bypasses the dataclass entirely
# (e.g. a duck-typed context) -- but the code it guards is dead on every
# path that goes through the real dataclass, so it is bucketed here rather
# than counted as a live, reachable check.
AGENT_QUALITY_CONTEXT_PREEMPTED_CODES: frozenset[str] = frozenset(
    {
        "MEASUREMENT_CONTRACT_NOT_PINNED",
    }
)

# Design row 48's two codes: reachable only through an input v1 does not
# define. AgentQualityCertificateBundleV1 ships NO ``SplitOpeningWitnessV1``
# and NO ``split_opening_witness`` bundle field -- there is no opening path
# in v1 at all (see the module docstring and
# AgentQualityCertificateBundleV1's own description). ``split_opening`` is
# accepted on :func:`_run_agent_quality_checks`'s call signature only for
# forward compatibility (P1-V2.0 review finding P3-11: widening the shared
# stage signature later would ripple through every caller again), and the
# runner REFUSES it outright -- with the existing CONTEXT code, at the
# existing ``split_opening_witness`` field location -- whenever it is not
# ``None``, before any stage runs. Unlike the schema-preempted-backstop
# codes, these two have NO guard anywhere (there is nothing to check a
# witness against), so they are dead vocabulary exactly like
# :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES` -- just preempted by a
# DIFFERENT authority (the caller's own input, not the schema). Proven by
# test_agent_quality_verifier.py::
# test_split_opening_input_preempted_codes_are_never_emitted.
AGENT_QUALITY_INPUT_PREEMPTED_CODES: frozenset[str] = frozenset(
    {
        "SPLIT_OPENING_MISMATCH",
        "SPLIT_OPENING_RULE_VIOLATION",
    }
)

# Codes that would be reachable by design (not schema-preempted) but that no
# guard in this module raises -- empty as of P1-V2.5 commit 2: every stage
# S1-S8 now runs a real check, so this set is the closed vocabulary minus
# every preempted/emitted code (see :data:`AGENT_QUALITY_PENDING_CODES`'s
# assignment below, and
# test_agent_quality_verifier.py::test_agent_quality_pending_codes_is_now_empty).
# S1's six real-check codes (BUNDLE_SHAPE, STRICT_INTEGER, UNSAFE_INTEGER,
# SCHEMA, SCHEMA_DEPENDENCY, CANONICALIZATION) and S8's eleven
# (SPLIT_DERIVATION_DIGEST_MISMATCH, EVALUATION_SPLITS_DIGEST_MISMATCH,
# MEASURED_CLAIMS_DIGEST_MISMATCH, SELECTION_ESTIMATES_DIGEST_MISMATCH,
# NON_CLAIMS_DIGEST_MISMATCH, CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH,
# CLAIM_SUPPORT_ROW_MISMATCH, UNSIGNED_MANIFEST_MISMATCH,
# UNSIGNED_MANIFEST_DIGEST_MISMATCH, KEY_RING_MISMATCH,
# ISSUER_SIGNATURE_INVALID) were wired as of P1-V2.2. P1-V2.3 wires S2's six
# (PROCESS_RECORD_BINDING_MISMATCH, COMMITMENT_REF_MISMATCH, SCOPE_MISMATCH,
# MEASUREMENT_CONTRACT_NOT_PINNED, MEASUREMENT_CONTRACT_MISMATCH -- CONTEXT
# is raised outside the stage runner, by
# AgentQualityVerificationContext.__post_init__), S3's four
# (AGGREGATION_POLICY_MISMATCH, OBJECTIVE_REGISTRY_MISMATCH,
# NON_CLAIM_SET_MISMATCH, QUANTILE_TABLE_MISMATCH -- PACKAGE_DATA_INVALID is
# likewise raised outside the stage runner), S4's four
# (DECLARED_PLAN_DIGEST_MISMATCH, DECLARED_PLAN_SIGNATURE_INVALID,
# DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH, DECLARED_PLAN_PIN_MISMATCH), and
# P1-V2.4 wires all of S5's reachable codes (OBJECTIVE_NOT_IN_DECLARED_PLAN,
# PRIMARY_OBJECTIVE_MISSING, OBJECTIVE_KIND_MISMATCH, OBJECTIVE_UNIT_MISMATCH,
# OBJECTIVE_DUPLICATE, INTERVAL_METHOD_NOT_ADMISSIBLE,
# SUFFICIENT_STATISTICS_SHAPE, NOMINAL_COVERAGE_MISMATCH,
# SAMPLE_SIZE_MISMATCH -- commit 1 --, and
# POINT_ESTIMATE_RECOMPUTATION_MISMATCH, INTERVAL_RECOMPUTATION_MISMATCH,
# INTERVAL_ORDER, INTERVAL_DEGENERATE -- commit 2, the exact-integer
# arithmetic rows). Seven further S5 codes that were briefly treated as
# "live" in .4 commit 1 (OBJECTIVE_NOT_REGISTERED,
# OBJECTIVE_MINIMUM_SAMPLE_NOT_MET, DISTRIBUTION_ASSUMPTION_NOT_REGISTERED,
# INTERVAL_METHOD_NOT_EMITTABLE, INTERVAL_OUT_OF_UNIT_BOUNDS,
# VERIFICATION_LEVEL_MISMATCH, QUANTILE_TABLE_LOOKUP_FAILED) moved to
# :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES` in the .4 review
# closure (P2-2): each has a live guard, but no schema-valid bundle can ever
# trip it, so it is excluded from this set via the
# ``AGENT_QUALITY_SCHEMA_PREEMPTED_CODES`` subtraction below rather than by
# also naming it in this literal. .5 (commit 1) wires S6's reachable codes
# (SPLIT_SET_SHAPE, SPLIT_DERIVATION_MISMATCH, SPLIT_PARTITION_INCOMPLETE,
# SPLIT_COMMITMENT_COLLISION, SPLIT_SIZE_IMPLAUSIBLE, ARM_COUNT_MISMATCH,
# SELECTION_ESTIMATE_DUPLICATE); S6's four schema-preempted-with-backstop
# codes (HOLDOUT_NOT_USED, HOLDOUT_MISSING, HOLDOUT_TOO_SMALL,
# HOLDOUT_REUSED) and its two input-preempted codes
# (SPLIT_OPENING_MISMATCH, SPLIT_OPENING_RULE_VIOLATION) are excluded via
# the ``AGENT_QUALITY_SCHEMA_PREEMPTED_CODES`` /
# ``AGENT_QUALITY_INPUT_PREEMPTED_CODES`` subtractions instead, the same
# pattern as .4's seven. .4 commit 2 wires S7's three reachable codes
# (CLAIM_NOT_VERIFIED, PILLAR_SUPPORT_SHAPE, ASSERTION_DIGEST_MISMATCH);
# its fourth owned-by-design code, PILLAR_BINDING_MISMATCH, is dead
# vocabulary (see :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES`) with
# no guard anywhere, excluded via that subtraction instead. This set MUST
# be empty after this packet -- every stage now runs real checks.
AGENT_QUALITY_PENDING_CODES: frozenset[str] = frozenset(
    AGENT_QUALITY_ERROR_CODES
    - AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    - AGENT_QUALITY_INPUT_PREEMPTED_CODES
    - frozenset(
        {
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
            "DECLARED_PLAN_DIGEST_MISMATCH",
            "DECLARED_PLAN_SIGNATURE_INVALID",
            "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
            "DECLARED_PLAN_PIN_MISMATCH",
            "OBJECTIVE_NOT_IN_DECLARED_PLAN",
            "PRIMARY_OBJECTIVE_MISSING",
            "OBJECTIVE_KIND_MISMATCH",
            "OBJECTIVE_UNIT_MISMATCH",
            "OBJECTIVE_DUPLICATE",
            "INTERVAL_METHOD_NOT_ADMISSIBLE",
            "SUFFICIENT_STATISTICS_SHAPE",
            "POINT_ESTIMATE_RECOMPUTATION_MISMATCH",
            "INTERVAL_RECOMPUTATION_MISMATCH",
            "INTERVAL_ORDER",
            "INTERVAL_DEGENERATE",
            "NOMINAL_COVERAGE_MISMATCH",
            "SAMPLE_SIZE_MISMATCH",
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
            "SPLIT_SET_SHAPE",
            "SPLIT_DERIVATION_MISMATCH",
            "SPLIT_PARTITION_INCOMPLETE",
            "SPLIT_COMMITMENT_COLLISION",
            "SPLIT_SIZE_IMPLAUSIBLE",
            "ARM_COUNT_MISMATCH",
            "SELECTION_ESTIMATE_DUPLICATE",
            "CLAIM_NOT_VERIFIED",
            "PILLAR_SUPPORT_SHAPE",
            "ASSERTION_DIGEST_MISMATCH",
        }
    )
)

# P1-V2.5 review P2-3: the disclosed total of codes excluded from reachable
# coverage by ANY of the four preemption buckets -- schema-preempted dead
# (no guard anywhere), schema-preempted backstop (a live guard a
# schema-valid bundle can never trip), context-preempted (a live guard a
# real ``AgentQualityVerificationContext`` can never trip), and
# input-preempted (no guard anywhere, refused by the runner's own input
# check before any stage runs). The four buckets are pairwise disjoint (see
# test_four_way_code_vocabulary_partition_is_disjoint_and_covers_all), so
# this is a plain sum, not a union count -- test_agent_quality_preempted_total_matches_bucket_sum
# pins it to that sum, and .6's PR body must cite this constant rather than
# re-deriving the count by hand.
AGENT_QUALITY_PREEMPTED_TOTAL: int = (
    len(AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES)
    + len(AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES)
    + len(AGENT_QUALITY_CONTEXT_PREEMPTED_CODES)
    + len(AGENT_QUALITY_INPUT_PREEMPTED_CODES)
)

# Which of the eight private stages owns each code this table assigns an
# owner to (every code except the two input-preempted ones, which no stage
# owns). Ownership is a DESIGN mapping, re-checked against the shipped
# schema's field names, reflecting each stage's real, wired call sites.
# CONTEXT and PACKAGE_DATA_INVALID are raised outside the eight-stage runner
# (by AgentQualityVerificationContext.__post_init__ and the package-data
# loading boundary respectively) but are assigned here to the stage whose
# design concern they belong to. QUANTILE_TABLE_LOOKUP_FAILED is likewise
# raised outside its owning stage's own body -- by :func:`_lookup_t_scaled`,
# a helper S5 calls -- AND it is schema-preempted-backstop (see
# :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES` above): the helper's
# guard is real and live, but no schema-valid bundle can ever trip it. Its
# entry here records ownership (which stage's concern it is), not
# reachability (see the four-bucket partition tests for that).
#
# This table is POPULATED, not hand-written: each stage function below is
# decorated with ``@_owns(...)``, which is the one and only place that lists
# a stage's codes -- the decorator sets both the function's ``owns``
# attribute and this dict's entry from the same literal call. There is no
# second table to drift out of sync with the first (P1-V2.0 review finding
# P1-1: a permutation of a code between two stages here used to be
# invisible to every test because this dict was hand-written independently
# of the stage docstrings). See
# test_agent_quality_verifier.py::test_stage_ownership_is_derived_from_owns_attribute
# and ::test_stage_docstrings_match_owns_attribute.
_STAGE_CODES: dict[str, frozenset[str]] = {}

_StageFn = TypeVar("_StageFn", bound=Callable[..., None])


def _owns(*codes: str) -> Callable[[_StageFn], _StageFn]:
    """Register the exact set of vocabulary codes a stage function owns.

    Applied as ``@_owns("CODE_A", "CODE_B", ...)`` immediately above a
    ``_stage_sN`` definition. Sets the decorated function's ``owns``
    attribute AND inserts the same frozenset into module-level
    ``_STAGE_CODES`` keyed by the function's name, so both views come from
    this one literal call -- neither can be edited without the other
    changing too.
    """
    owned = frozenset(codes)

    def decorator(fn: _StageFn) -> _StageFn:
        fn.owns = owned  # type: ignore[attr-defined]
        _STAGE_CODES[fn.__name__] = owned
        return fn

    return decorator


# NOT a copy of the schema's EmittableVerificationLevelV1. This is the union
# of the level vocabularies of AgentQualityVerificationResult's two level
# fields (interval_verification_level and split_verification_level), each of
# which __post_init__ narrows independently. EmittableVerificationLevelV1 is
# VerificationLevelV1 minus {issuer_attested_v1, opened_and_recomputed_v1},
# i.e. {construction_recomputed_v1} alone, and it governs a bundle field --
# the per-claim interval's verification_level -- not this result.
# issuer_attested_v1 is a member of this constant by construction: this
# verifier never recomputes the split derivation, so __post_init__ pins
# split_verification_level to issuer_attested_v1 unconditionally; narrowing
# this constant to the schema's emittable set would make
# AgentQualityVerificationResult unconstructible. opened_and_recomputed_v1
# and anything outside VerificationLevelV1 are unregistered here and MUST be
# rejected regardless of which code or field they accompany.
# See test_agent_quality_verifier.py::test_emittable_verification_levels_match_schema_contract
# (and its neighboring tests) for the assertions that pin this relationship
# to the schema.
_EMITTABLE_VERIFICATION_LEVELS = frozenset({"construction_recomputed_v1", "issuer_attested_v1"})
# The only interval_verification_level an ABSTAINED result can honestly carry:
# an abstained bundle asserts no measured claim, so no recomputation ever ran,
# leaving issuer_attested_v1 (attested, not recomputed) as the sole truthful value.
_ABSTAINED_INTERVAL_VERIFICATION_LEVELS = frozenset({"issuer_attested_v1"})

# Closed field-location vocabulary, copied verbatim from
# AgentQualityFieldLocationV1 in agent_quality_v1_schema.json -- the schema
# is the authority for this set; see
# test_agent_quality_verifier.py::test_agent_quality_field_locations_match_schema_contract
# for the assertion that ties the two together. Never a JSON Pointer built
# from instance data.
AGENT_QUALITY_FIELD_LOCATIONS = frozenset(
    {
        "bundle",
        "scope_binding",
        "unsigned_manifest",
        "signature",
        "declared_plan",
        "declared_plan_signature",
        "split_derivation",
        "evaluation_splits",
        "evaluation_splits.selection",
        "evaluation_splits.holdout",
        "split_opening_witness",
        "measured_claims",
        "measured_claims.interval",
        "measured_claims.interval_params",
        "measured_claims.sufficient_statistics",
        "measured_claims.objective",
        "measured_claims.sample_size",
        "measured_claims.verification_level",
        "non_certified_selection_estimates",
        "assertion",
        "claim_support_rows",
        "non_claims",
        "pillar_support",
        "pillar_support.dataset",
        "pillar_support.evaluator",
        "aggregation_policy",
        "objective_registry",
        "non_claim_catalog",
        "quantile_table",
        "process_record_binding",
        "commitment_refs",
        "measurement_contract",
        "context",
    }
)

# G9: the wire-error code each of the 72 verifier codes maps to on
# AgentQualityErrorV1 (agent_quality_v1_schema.json). That schema's own
# description is the authority for the rule this mapping implements: "The
# code enum is deliberately coarser than the verifier's own [...]-code
# vocabulary, and that coarseness is the privacy property -- adding a
# verifier code must NOT widen this enum."
#
# P1-V2.6 final-review closure P2-1: this table is now an EXPLICIT, TOTAL
# literal -- every one of the 72 codes in AGENT_QUALITY_ERROR_CODES is
# listed by name below, with NO default/fall-through arm. The prior
# comprehension-over-AGENT_QUALITY_ERROR_CODES form silently swept any code
# not sorted into a named bucket into the catch-all, which let three S5
# measurement codes -- OBJECTIVE_DUPLICATE, QUANTILE_TABLE_LOOKUP_FAILED,
# SELECTION_ESTIMATE_DUPLICATE -- sit undocumented in
# agent_quality_verification_failed even though the docstring's own rule
# ("S5 ... all measurement") already covered them. CTO decision: all three
# are measurement-RECORD rules (duplicate-detection and quantile-table
# lookup over a measured claim), not split-topology rules, so all three
# join the measurement bucket below.
#
# The four buckets:
#   - agent_quality_invalid_measurement: S5 (design rows 22-39, all
#     measurement) plus HOLDOUT_NOT_USED (an S6 code whose own check is on
#     MeasuredObjectiveClaimV1.evaluated_split_id and whose ``_fail`` field
#     is "measured_claims", not a split field -- see
#     _stage_s6_splits_held_out) plus OBJECTIVE_DUPLICATE,
#     QUANTILE_TABLE_LOOKUP_FAILED and SELECTION_ESTIMATE_DUPLICATE (all
#     three per the CTO decision above).
#   - agent_quality_invalid_split: the remaining S6 split/holdout-structure
#     codes (SPLIT_* and the three holdout-arm codes
#     HOLDOUT_MISSING/_TOO_SMALL/_REUSED, plus ARM_COUNT_MISMATCH).
#   - agent_quality_invalid_declared_plan: S4's declared-plan codes (design
#     rows 17-19, 21), including the declared-plan pin
#     (DECLARED_PLAN_PIN_MISMATCH).
#   - agent_quality_verification_failed: everything else -- S1 structural,
#     S2 context binding, S3 registry identity, S7 composition/abstention,
#     S8 manifest digests/signature, the three DEAD schema-preempted S7
#     codes (:data:`AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES`),
#     MEASUREMENT_CONTRACT_NOT_PINNED (context-preempted -- see
#     :data:`AGENT_QUALITY_CONTEXT_PREEMPTED_CODES`), and the catch-all
#     code itself (AGENT_QUALITY_VERIFICATION_FAILED) -- the coarsest
#     bucket, matching a relying party's inability to act differently on
#     any of those distinctions anyway.
#
# Each bucket below is a plain frozenset, asserted disjoint from and unioned
# with the others by
# test_wire_error_code_mapping_buckets_partition_the_vocabulary; the table
# after them lists every code exactly once, by name.
_AGENT_QUALITY_WIRE_MEASUREMENT_CODES: frozenset[str] = frozenset(
    {
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
    }
)
_AGENT_QUALITY_WIRE_SPLIT_CODES: frozenset[str] = frozenset(
    {
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
    }
)
_AGENT_QUALITY_WIRE_DECLARED_PLAN_CODES: frozenset[str] = frozenset(
    {
        "DECLARED_PLAN_DIGEST_MISMATCH",
        "DECLARED_PLAN_SIGNATURE_INVALID",
        "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
        "DECLARED_PLAN_PIN_MISMATCH",
    }
)
_AGENT_QUALITY_WIRE_VERIFICATION_FAILED_CODES: frozenset[str] = frozenset(
    {
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
    }
)

# The explicit, total mapping: every code in AGENT_QUALITY_ERROR_CODES is
# named exactly once below -- NO comprehension, NO default arm. A verifier
# code added to AGENT_QUALITY_ERROR_CODES without a matching literal entry
# here raises KeyError at import time (the dict literal below has a fixed
# key set; AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE's own key-parity assertion
# in test_wire_error_code_mapping_covers_every_verifier_code is the second,
# independent proof).
AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE: Mapping[str, str] = MappingProxyType(
    {
        **dict.fromkeys(_AGENT_QUALITY_WIRE_MEASUREMENT_CODES, "agent_quality_invalid_measurement"),
        **dict.fromkeys(_AGENT_QUALITY_WIRE_SPLIT_CODES, "agent_quality_invalid_split"),
        **dict.fromkeys(
            _AGENT_QUALITY_WIRE_DECLARED_PLAN_CODES, "agent_quality_invalid_declared_plan"
        ),
        **dict.fromkeys(
            _AGENT_QUALITY_WIRE_VERIFICATION_FAILED_CODES, "agent_quality_verification_failed"
        ),
    }
)


class AgentQualityVerificationError(ValueError):
    """A fixed-code, fixed-field verification failure that never includes
    certificate data.

    Both ``code`` and ``field`` are validated against the module's two closed
    vocabularies at construction time, so an invalid pair can never be raised
    -- ``str(exc)`` returns the code alone, printing no field path and no
    instance data in a bare traceback.
    """

    def __init__(self, code: str, field: str) -> None:
        if code not in AGENT_QUALITY_ERROR_CODES:
            raise ValueError("AGENT_QUALITY_VERIFICATION_ERROR_CODE")
        if field not in AGENT_QUALITY_FIELD_LOCATIONS:
            raise ValueError("AGENT_QUALITY_VERIFICATION_ERROR_FIELD")
        self.code = code
        self.field = field
        super().__init__(code)

    @property
    def wire_code(self) -> str:
        """This error's ``AgentQualityErrorV1.code`` -- the coarse wire
        bucket ``self.code`` maps to under
        :data:`AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE`. Total lookup: every
        member of ``AGENT_QUALITY_ERROR_CODES`` (which ``self.code`` is
        already validated against in ``__init__``) is a key in that mapping."""
        return AGENT_QUALITY_WIRE_ERROR_CODE_BY_CODE[self.code]


def _fail(code: str, field: str) -> NoReturn:
    """Raise :class:`AgentQualityVerificationError` with a guaranteed-empty
    ``__context__``.

    Mirrors the raise/clear/re-raise discipline in
    ``traigent_schema/certification/dataset_record_verifier.py``'s ``_fail``:
    a plain ``raise ... from None`` inside an ``except`` block only suppresses
    *display* of the chained exception, it does not clear ``__context__``, so
    a caught exception built from caller-supplied content would still be
    reachable on the object that escapes. Raising, catching, clearing, and
    re-raising the SAME object -- outside any ``except`` block -- is what
    makes it genuinely unreachable.
    """
    failure = AgentQualityVerificationError(code, field)
    try:
        raise failure from None
    except AgentQualityVerificationError:
        failure.__context__ = None
        raise


@dataclass(frozen=True, slots=True)
class AgentQualityVerificationContext:
    """Fresh, caller-supplied bindings for one Agent Quality Record verification.

    Tenant identity is deliberately absent, exactly as in
    ``ProcessRecordVerificationContext``: this verifier enforces exact scope
    and commitment consistency, never tenant authorization, which remains a
    Backend/caller responsibility.

    ``process_record_context`` is forwarded, unexamined by this dataclass, to
    the already-shipped process-record verifier the complete check sequence
    calls; its shape is that verifier's concern, not this one's.

    The five ``expected_*_ref`` / ``expected_*_digest`` fields are the
    caller's pins for the build this verification is FOR: the project and
    build-session scope, the four commitment refs, and the measurement
    contract this record's claims must cite. Every one of them is a
    verification INPUT only -- none is ever copied into a bundle or a result;
    each enters only the digest preimage of the scope-binding/commitment
    checks the complete check sequence performs.

    ``accept_abstained_bundle`` has no default: whether an abstained
    (``AGENT_QUALITY_CLAIM_ABSTAINED``) bundle is an acceptable outcome for
    this caller, as opposed to a hard failure, is a deliberate choice every
    caller must make rather than inherit silently.

    ``expected_declared_plan_digest`` is a BINDING pin only: it establishes
    WHICH declared plan this verification expects the bundle to cite -- not
    ordering evidence that the plan was authored before the results, which
    is out of scope for this certificate family in v1 (see the module
    docstring).
    """

    process_record_context: object
    expected_project_ref: str
    expected_build_session_ref: str
    expected_agent_commitment_ref: str
    expected_dataset_commitment_ref: str
    expected_evaluator_commitment_ref: str
    expected_build_definition_commitment_ref: str
    expected_measurement_contract_ref: str
    expected_measurement_contract_record_digest: str
    accept_abstained_bundle: bool
    expected_declared_plan_digest: str | None = None
    trust_status: object | None = None

    def __post_init__(self) -> None:
        if type(self.expected_project_ref) is not str or not _PROJECT_REF_RE.fullmatch(
            self.expected_project_ref
        ):
            _fail("CONTEXT", "context")
        if type(self.expected_build_session_ref) is not str or not _REF_RE.fullmatch(
            self.expected_build_session_ref
        ):
            _fail("CONTEXT", "context")
        for commitment_ref in (
            self.expected_agent_commitment_ref,
            self.expected_dataset_commitment_ref,
            self.expected_evaluator_commitment_ref,
            self.expected_build_definition_commitment_ref,
        ):
            if type(commitment_ref) is not str or not _SHA256_RE.fullmatch(commitment_ref):
                _fail("CONTEXT", "context")
        if type(self.expected_measurement_contract_ref) is not str or not _REF_RE.fullmatch(
            self.expected_measurement_contract_ref
        ):
            _fail("CONTEXT", "context")
        if type(
            self.expected_measurement_contract_record_digest
        ) is not str or not _SHA256_RE.fullmatch(self.expected_measurement_contract_record_digest):
            _fail("CONTEXT", "context")
        if type(self.accept_abstained_bundle) is not bool:
            _fail("CONTEXT", "context")
        if self.expected_declared_plan_digest is not None and (
            type(self.expected_declared_plan_digest) is not str
            or not _SHA256_RE.fullmatch(self.expected_declared_plan_digest)
        ):
            _fail("CONTEXT", "context")


@dataclass(frozen=True, slots=True)
class AgentQualityVerificationResult:
    """Bounded, content-free success result.

    Every field is set from what THIS verifier computed -- nothing is ever
    copied from a signed bundle field into this object unexamined.

    ``plan_ordering_note`` is fixed: this certificate never establishes
    ordering evidence that the declared plan was authored before the
    results, so the note is not conditional on anything the bundle claims.

    ``__post_init__`` couples ``(code, evidence_basis)`` to exactly the two
    outcomes this family can reach -- an ``issuer_verified`` support row
    yields ``AGENT_QUALITY_VERIFIED``, an ``abstained`` one yields
    ``AGENT_QUALITY_CLAIM_ABSTAINED`` -- and additionally pins
    ``split_verification_level`` to ``issuer_attested_v1`` (v1 defines no
    opening path, so any other value would assert a recomputation this
    verifier never performs). Both ``interval_verification_level`` and
    ``split_verification_level`` MUST be one of the two levels registered in
    :data:`_EMITTABLE_VERIFICATION_LEVELS` -- any other string, for either
    code, is an unregistered level and is rejected outright, closing the
    vocabulary rather than merely forbidding one named value.
    ``interval_verification_level`` is further pinned to
    ``construction_recomputed_v1`` for a VERIFIED result (the one level this
    verifier's estimator recomputation actually establishes) and, for an
    ABSTAINED result, MUST be a member of
    :data:`_ABSTAINED_INTERVAL_VERIFICATION_LEVELS` (``issuer_attested_v1``
    only): an abstained bundle carries no measured claims, so no
    recomputation ever ran, and a result asserting otherwise -- whether
    ``construction_recomputed_v1`` or any unregistered string -- would
    overstate what this verifier checked.
    A violation of any of these invariants is a defect in THIS module, not a
    verification finding, so it raises a plain ``ValueError`` rather than
    :class:`AgentQualityVerificationError`.
    """

    code: str
    claim_id: str
    evidence_basis: str
    primary_objective_id: str
    nominal_coverage_ppm: int
    holdout_item_count: int
    interval_verification_level: str
    split_verification_level: str
    dataset_condition_code: str
    evaluator_condition_code: str
    plan_ordering_note: str = (
        "Ordering evidence — that the declared plan was authored "
        "before the results — is out of scope for v1 and is not "
        "verified by this certificate."
    )

    def __post_init__(self) -> None:
        if (self.code, self.evidence_basis) not in (
            ("AGENT_QUALITY_VERIFIED", "issuer_verified"),
            ("AGENT_QUALITY_CLAIM_ABSTAINED", "abstained"),
        ):
            raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        if self.split_verification_level not in _EMITTABLE_VERIFICATION_LEVELS:
            raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        if self.split_verification_level != "issuer_attested_v1":
            raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        if self.interval_verification_level not in _EMITTABLE_VERIFICATION_LEVELS:
            raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        if self.code == "AGENT_QUALITY_VERIFIED":
            if self.interval_verification_level != "construction_recomputed_v1":
                raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        else:
            if self.interval_verification_level not in _ABSTAINED_INTERVAL_VERIFICATION_LEVELS:
                raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")
        if self.plan_ordering_note != (
            "Ordering evidence — that the declared plan was authored "
            "before the results — is out of scope for v1 and is not "
            "verified by this certificate."
        ):
            raise ValueError("AGENT_QUALITY_VERIFICATION_RESULT")


def _role_digest(domain: str, payload: object) -> str:
    """``sha256:`` + hex over ``UTF8(domain) || 0x00 || jcs_v1(payload)``.

    A second implementation of the same construction used throughout this
    repo's certification verifiers (``process_record_verifier``,
    ``dataset_record_verifier``), not a shared import -- this is a separate
    contract family. Deliberately does NOT catch ``fp2.Fp2UnsupportedValue``:
    every caller in this module reaches this function from inside its own
    content-free boundary (see :func:`_load_agent_quality_document`), which
    already converts any exception into its own fixed error with the field
    location that call site knows and this function does not.
    """
    canonical = cast(str, fp2.canonicalize(payload)).encode("utf-8")
    return _SHA256_PREFIX + hashlib.sha256(domain.encode("utf-8") + b"\x00" + canonical).hexdigest()


def _strip_self_digest(payload: dict[str, Any], field_name: str) -> dict[str, Any]:
    """Return ``payload`` with ``field_name`` removed -- the digest preimage
    for a document that carries its own digest as a member and excludes it
    from what it signs over.
    """
    return {key: value for key, value in payload.items() if key != field_name}


def _read_agent_quality_package_json(filename: str) -> Any:
    """Read and JSON-decode one file from ``traigent_schema/data/certification``.

    No error handling of its own -- ``FileNotFoundError``, ``UnicodeError``
    and ``json.JSONDecodeError`` all carry content (a path or a text
    fragment) and MUST only be caught from inside
    :func:`_load_agent_quality_document`'s boundary.
    """
    package = resources.files("traigent_schema")
    node = package.joinpath("data").joinpath("certification").joinpath(filename)
    return json.loads(node.read_text(encoding="utf-8"))


@lru_cache(maxsize=4)
def _load_agent_quality_document(stem: str) -> dict[str, Any]:
    """Load, digest-check, and cache one of this pillar's four registries.

    ``stem`` is one of ``"objective_registry"``, ``"aggregation_policy"``,
    ``"non_claim_catalog"``, ``"quantile_table"`` -- the same token used in
    the shipped filenames and in ``AgentQualityDigestDomainRegistryV1``. The
    document is read from ``agent_quality_<stem>.json``, its pinned digest
    from the sidecar ``agent_quality_<stem>.digest.json``, and compared
    against a freshly computed :func:`_role_digest` under the domain named in
    the schema's own digest-domain registry.

    On ANY failure -- an unregistered stem, a missing file, undecodable or
    non-object JSON, a missing or non-string pinned digest, or a digest
    mismatch -- this raises the single fixed
    ``AgentQualityVerificationError("PACKAGE_DATA_INVALID", field)``, where
    ``field`` is ``stem`` itself when it names a real registry (every
    registered stem is also a valid ``AgentQualityFieldLocationV1`` token) or
    the generic ``"bundle"`` location for an unregistered one. No document
    text, filesystem path, or original exception ever reaches the raised
    error or its chain -- the raise happens OUTSIDE the ``except`` block that
    caught the underlying failure, and the object's ``__context__`` is
    explicitly cleared before re-raising, exactly as
    ``process_record_verifier._load_registry_constant`` documents.

    Cached per process: the four registries are read and validated at most
    once per interpreter, not once per verification call.
    """
    field = stem if stem in AGENT_QUALITY_FIELD_LOCATIONS else "bundle"
    loaded: dict[str, Any] | None
    try:
        domain = _AGENT_QUALITY_REGISTRY_DOMAINS[stem]
        document = _read_agent_quality_package_json(f"agent_quality_{stem}.json")
        pin = _read_agent_quality_package_json(f"agent_quality_{stem}.digest.json")
        if not isinstance(document, dict):
            raise ValueError("document is not an object")
        pinned_digest = pin["digest"] if isinstance(pin, dict) else None
        if type(pinned_digest) is not str:
            raise ValueError("pin file missing a string digest field")
        computed_digest = _role_digest(domain, document)
        if computed_digest != pinned_digest:
            raise ValueError("digest mismatch")
        loaded = document
    except Exception:
        loaded = None
    if loaded is None:
        failure = AgentQualityVerificationError("PACKAGE_DATA_INVALID", field)
        try:
            raise failure from None
        except AgentQualityVerificationError:
            # See _fail's docstring: this two-step raise/clear/re-raise is
            # what makes the caught exception above -- which may carry
            # document content -- genuinely unreachable, not merely
            # undisplayed.
            failure.__context__ = None
            raise
    return loaded


# Import-time package-data validation: this loads and digest-checks all four
# of this pillar's registries as soon as the module is imported, so a
# corrupt or tampered package installation is caught unconditionally rather
# than only on whichever caller happens to be first to touch one of the lazy
# loaders above. A failure here raises the same
# ``AgentQualityVerificationError("PACKAGE_DATA_INVALID", field)`` --
# str(exc) == "PACKAGE_DATA_INVALID", and its chain carries no document text
# -- straight out of module import / ``importlib.reload``.
for _agent_quality_registry_stem in _AGENT_QUALITY_REGISTRY_DOMAINS:
    _load_agent_quality_document(_agent_quality_registry_stem)
del _agent_quality_registry_stem


# Which schema definition, and which of its (id, version, digest)-shaped
# properties, each of the four shipped registries' own identity projection
# carries -- keyed by the same stem used throughout this module. Used by
# :func:`_expected_registry_identity` to build the identity S3 compares the
# bundle's manifest (and, for the first two, the declared plan) against.
_AGENT_QUALITY_REGISTRY_IDENTITY_FIELDS: dict[str, tuple[str, str, str, str]] = {
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


@lru_cache(maxsize=4)
def _expected_registry_identity(stem: str) -> dict[str, Any]:
    """The SHIPPED identity projection for one of this pillar's four
    registries: id/version consts read straight from the schema, digest
    independently recomputed via :func:`_load_agent_quality_document` and
    :func:`_role_digest` under :data:`_AGENT_QUALITY_REGISTRY_DOMAINS` --
    never a value trusted from the bundle being verified.
    """
    definition_name, id_field, version_field, digest_field = (
        _AGENT_QUALITY_REGISTRY_IDENTITY_FIELDS[stem]
    )
    props = _schema_definition(definition_name)["properties"]
    document = _load_agent_quality_document(stem)
    digest = _role_digest(_AGENT_QUALITY_REGISTRY_DOMAINS[stem], document)
    return {
        id_field: props[id_field]["const"],
        version_field: props[version_field]["const"],
        digest_field: digest,
    }


@lru_cache(maxsize=1)
def _quantile_buckets_by_coverage() -> dict[int, tuple[tuple[int, int], ...]]:
    """The pinned Student-t quantile table, grouped by nominal coverage and
    sorted by ``df_bucket`` ascending, ready for :func:`_lookup_t_scaled`'s
    bracket search.
    """
    document = _load_agent_quality_document("quantile_table")
    grouped: dict[int, list[tuple[int, int]]] = {}
    for row in document["rows"]:
        grouped.setdefault(row["nominal_coverage_ppm"], []).append(
            (row["df_bucket"], row["quantile_x1e6"])
        )
    return {coverage: tuple(sorted(rows)) for coverage, rows in grouped.items()}


@lru_cache(maxsize=1)
def _objective_registry_entries_by_id() -> dict[str, dict[str, Any]]:
    """The shipped objective registry's entries, keyed by ``objective_id``,
    read via :func:`_load_agent_quality_document` (cached, digest-checked) --
    never a value trusted from the bundle being verified."""
    document = _load_agent_quality_document("objective_registry")
    return {entry["objective_id"]: entry for entry in document["entries"]}


@lru_cache(maxsize=1)
def _emittable_interval_methods() -> frozenset[str]:
    """``IntervalMethodV1`` minus ``EmittableIntervalMethodV1``'s own
    exclusion list, derived from the shipped schema rather than retyped, so
    S5's admissibility check cannot drift from the schema's own vocabulary."""
    all_methods = frozenset(_schema_definition("IntervalMethodV1")["enum"])
    excluded = frozenset(_schema_definition("EmittableIntervalMethodV1")["allOf"][1]["not"]["enum"])
    return all_methods - excluded


@lru_cache(maxsize=1)
def _nominal_coverage_values() -> frozenset[int]:
    return frozenset(_schema_definition("NominalCoveragePpmV1")["enum"])


@lru_cache(maxsize=1)
def _distribution_assumption_values() -> frozenset[str]:
    return frozenset(_schema_definition("DistributionAssumptionV1")["enum"])


@lru_cache(maxsize=1)
def _emittable_pillar_statuses() -> frozenset[str]:
    """``PillarStatusV1`` minus ``EmittablePillarStatusV1``'s own exclusion
    (a single excluded const, unlike :func:`_emittable_interval_methods`'s
    excluded enum list) -- derived from the shipped schema so S7's shape
    check cannot drift from it. v1 excludes only ``assessed_supported``
    (see :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES`'s
    PILLAR_BINDING_MISMATCH entry for why)."""
    all_statuses = frozenset(_schema_definition("PillarStatusV1")["enum"])
    excluded = _schema_definition("EmittablePillarStatusV1")["allOf"][1]["not"]["const"]
    return all_statuses - {excluded}


def _holdout_item_count(evaluation_splits: object) -> object:
    """The ``item_count`` of the ``evaluation_splits`` entry whose
    ``split_id`` is ``"holdout"``, or ``None`` if absent/malformed --
    S5 fails closed on ``None`` (it can never equal a schema-valid
    ``sample_size``, which is a positive integer)."""
    if not isinstance(evaluation_splits, (list, tuple)):
        return None
    for record in evaluation_splits:
        if isinstance(record, Mapping) and record.get("split_id") == "holdout":
            return record.get("item_count")
    return None


# The one admissible interval-recomputation method per objective kind (design
# row 30), re-derived from MeasuredObjectiveClaimV1's own if/then branches in
# the shipped schema: binary_rate -> Wilson, bounded_mean/nonnegative_mean ->
# Student-t, nonnegative_quantile -> order-statistic (registered but never
# emittable in v1 -- see EmittableObjectiveKindV1 -- kept here only so the
# mapping is total over every ObjectiveKindV1 member).
_ADMISSIBLE_INTERVAL_METHOD_BY_OBJECTIVE_KIND: dict[str, str] = {
    "binary_rate": "wilson_score_v1",
    "bounded_mean": "student_t_normal_approx_v1",
    "nonnegative_mean": "student_t_normal_approx_v1",
    "nonnegative_quantile": "order_statistic_quantile_v1",
}

# The sufficient-statistics ``stat_kind`` each emittable interval method
# requires (design row 31).
_STAT_KIND_BY_INTERVAL_METHOD: dict[str, str] = {
    "wilson_score_v1": "binomial_v1",
    "student_t_normal_approx_v1": "mean_variance_v1",
}


def _lookup_t_scaled(coverage_ppm: int, df: int) -> int:
    """The pinned table's ``quantile_x1e6`` for ``coverage_ppm`` at ``df``,
    bucketed CONSERVATIVELY.

    ``df`` need not name a rung the table carries. The Student-t quantile
    strictly decreases as degrees of freedom increase, so borrowing the
    largest pinned ``df_bucket`` that is ``<= df`` always borrows a value
    from a bucket with EQUAL OR FEWER degrees of freedom than the true one --
    i.e. an equal-or-LARGER quantile -- so bucketing can only widen an
    interval, never narrow it. ``df`` at or above the table's infinity
    sentinel resolves to the standard-normal row; :func:`_wilson_bounds`
    reads exactly that row directly (Wilson has no degrees-of-freedom
    parameter of its own).

    Raises ``AgentQualityVerificationError("QUANTILE_TABLE_LOOKUP_FAILED",
    "quantile_table")`` for an unregistered ``coverage_ppm`` or a ``df``
    below the table's smallest bucket for that coverage (df < 1 cannot occur
    for a schema-valid claim, but this function does not assume that).
    """
    buckets = _quantile_buckets_by_coverage().get(coverage_ppm)
    if not buckets:
        _fail("QUANTILE_TABLE_LOOKUP_FAILED", "quantile_table")
    keys = [bucket for bucket, _ in buckets]
    index = bisect.bisect_right(keys, df) - 1
    if index < 0:
        _fail("QUANTILE_TABLE_LOOKUP_FAILED", "quantile_table")
    return buckets[index][1]


def _wilson_point(successes: int, trials: int) -> int:
    """The Wilson point estimate in ppm: ``round(successes * 1e6 / trials)``.

    Rounding rule is explicit HALF-UP (ties round away from zero), computed
    exactly via ``(2*successes*_T_SCALE + trials) // (2*trials)`` -- the
    standard integer identity for half-up rounding of a nonnegative ratio,
    with no intermediate float.
    """
    return (2 * successes * _T_SCALE + trials) // (2 * trials)


def _wilson_bounds(successes: int, trials: int, coverage_ppm: int) -> tuple[int, int]:
    """Recompute the Wilson score interval's endpoints, in ppm, from
    ``successes``/``trials`` alone -- no square root anywhere.

    The Wilson endpoints are the two roots, in the proportion ``p``, of

        n(n + z^2) p^2 - n(2k + z^2) p + k^2 = 0

    (``k`` = ``successes``, ``n`` = ``trials``, ``z`` the two-sided quantile
    for ``coverage_ppm`` read from the pinned table's infinity rung). This
    equation is irrational in ``z^2`` in general, so its roots cannot be
    represented exactly as a fixed-point integer even though every
    COEFFICIENT can. Substituting ``z = z_scaled / _T_SCALE`` and
    ``p = e / _T_SCALE`` (``e`` the ppm endpoint) and clearing every
    denominator yields a pure-integer quadratic ``Q(e) = A*e^2 + B*e + C``
    with integer ``A``, ``B``, ``C``; ``A > 0`` so ``Q`` is an upward
    parabola, negative strictly between the true roots and non-negative
    outside them (equal to zero exactly at a root).

    Each endpoint is then found by INTEGER BRACKETING rather than a closed
    form: the low endpoint is the largest integer ``e`` with ``Q(e) >= 0`` on
    the branch left of the parabola's vertex (the floor of the true lower
    root -- rounding the low bound DOWN, i.e. outward); the high endpoint is
    the smallest integer ``e`` with ``Q(e) >= 0`` on the branch right of the
    vertex (the ceiling of the true upper root -- rounding the high bound
    UP, i.e. outward).

    The split point for the two bisections is the parabola's own EXACT
    rational vertex ``e_v = -B / (2A)`` -- floored for the low-endpoint
    search, ceiled for the high-endpoint search -- computed by plain integer
    floor/ceil division, never the rounded point estimate
    (``_wilson_point``). ``Q`` is convex, so it is weakly decreasing on
    ``(-inf, e_v]`` and weakly increasing on ``[e_v, +inf)``; the true roots
    ``r1 <= e_v <= r2`` bracket the vertex exactly, so splitting there is
    always safe. Splitting at the HALF-UP-ROUNDED point estimate instead is
    NOT always safe: when the true interval is narrower than one ppm unit
    (e.g. 1 success in 10**9 trials), the rounded point estimate can round
    to an integer already OUTSIDE the true root interval, on the wrong side
    of the true upper root -- collapsing the high-endpoint bisection's
    search range to a single point below the true root and silently
    NARROWING the certified interval instead of widening it. ``Q(0) = k^2 *
    _T_SCALE**4 >= 0`` and ``Q(_T_SCALE) = (n-k)^2 >= 0`` always hold, so
    both bisections always have a valid bracket to search.
    """
    z_scaled = _lookup_t_scaled(coverage_ppm, _INFINITY_DF_BUCKET)
    n = trials
    k = successes
    scale = _T_SCALE
    scale_sq = scale * scale
    z_sq = z_scaled * z_scaled

    coeff_a = n * (n * scale_sq + z_sq)
    coeff_b = -n * (2 * k * scale_sq + z_sq) * scale
    coeff_c = k * k * scale_sq * scale_sq

    def q(e: int) -> int:
        return coeff_a * e * e + coeff_b * e + coeff_c

    vertex_numerator = -coeff_b
    vertex_denominator = 2 * coeff_a
    vertex_floor = vertex_numerator // vertex_denominator
    vertex_ceil = -(-vertex_numerator // vertex_denominator)
    vertex_floor = max(0, min(scale, vertex_floor))
    vertex_ceil = max(0, min(scale, vertex_ceil))

    low, high = 0, vertex_floor
    while low < high:
        mid = (low + high + 1) // 2
        if q(mid) >= 0:
            low = mid
        else:
            high = mid - 1
    low_endpoint = low

    low2, high2 = vertex_ceil, scale
    while low2 < high2:
        mid2 = (low2 + high2) // 2
        if q(mid2) >= 0:
            high2 = mid2
        else:
            low2 = mid2 + 1
    high_endpoint = low2

    return low_endpoint, high_endpoint


def _student_t_half_width(
    mean_fixed: int,
    sample_stddev_fixed: int,
    sample_count: int,
    coverage_ppm: int,
    unit_scale: str,
) -> int:
    """Outward-rounded Student-t half-width: ``ceil(t * sd / sqrt(n))``, in
    the objective's own fixed-point unit -- no square root, no float.

    ``t_scaled`` (``t * _T_SCALE``) is read from the pinned quantile table at
    ``df = sample_count - 1`` via :func:`_lookup_t_scaled`'s conservative
    bucket lookup. ``sqrt(sample_count)`` is approximated by
    ``math.isqrt(sample_count * _ISQRT_SCALE**2)`` -- an EXACT, FLOORED
    integer square root (``math.isqrt`` never touches a float), scaled by
    ``_ISQRT_SCALE`` for fixed-point precision. Flooring can only
    UNDERESTIMATE ``sqrt(sample_count)``, which makes the denominator here no
    larger than the true value, so this approximation can only WIDEN the
    result, never narrow it; the final division is then rounded up
    (ceiling), an independent second source of outward widening.

    ``mean_fixed`` and ``unit_scale`` are accepted, and deliberately unused
    here, so that every recomputation input for a bounded_mean /
    nonnegative_mean claim's interval travels through one function
    signature: the half-width itself depends only on the sample's spread and
    size, never its location, but the caller (the complete check sequence)
    needs ``mean_fixed`` alongside this return value to reconstruct
    ``mean_fixed - half_width`` / ``mean_fixed + half_width`` and needs
    ``unit_scale`` to know which bounded range the result must respect.
    """
    df = sample_count - 1
    t_scaled = _lookup_t_scaled(coverage_ppm, df)
    sqrt_n_scaled = math.isqrt(sample_count * _ISQRT_SCALE * _ISQRT_SCALE)
    numerator = t_scaled * sample_stddev_fixed * _ISQRT_SCALE
    denominator = _T_SCALE * sqrt_n_scaled
    return -(-numerator // denominator)


_RowT = TypeVar("_RowT")
_KeyT = TypeVar("_KeyT")


def _unique_by(
    rows: list[_RowT],
    key_fn: Callable[[_RowT], _KeyT],
    duplicate_code: str,
    field: str,
) -> dict[_KeyT, _RowT]:
    """Build a ``key -> row`` mapping over a SIGNED list, raising on any
    repeated key before any mapping is built.

    A ``{key_fn(row): row for row in rows}`` dict comprehension over a signed
    list silently keeps the LAST row for a repeated key -- exactly the shape
    that let a #458-class defect through: two rows sharing a key but
    disagreeing in payload would coalesce into whichever happened to be
    written last, with the disagreement never surfaced. This function instead
    makes a first pass over a plain ``set`` of keys ALONE and raises the
    moment a key repeats, before the second pass that builds the mapping ever
    runs -- so the failure is unconditional on whether the two rows' payloads
    happen to agree, not just on whether they differ.
    """
    seen_keys: set[_KeyT] = set()
    for row in rows:
        key = key_fn(row)
        if key in seen_keys:
            _fail(duplicate_code, field)
        seen_keys.add(key)
    by_key: dict[_KeyT, _RowT] = {}
    for row in rows:
        by_key[key_fn(row)] = row
    return by_key


# Dead-helper inventory. As of P1-V2.6, this inventory is EMPTY -- every
# top-level private function has an in-module call site -- verified by
# test_agent_quality_verifier.py::test_unwired_helpers_inventory_is_exact,
# which computes the set by AST rather than trusting this comment to stay
# accurate (see :data:`_UNWIRED_HELPER_NAMES` there). _wilson_point,
# _wilson_bounds and _student_t_half_width were wired in .4 commit 2 (S5's
# point-estimate and interval RECOMPUTATION, design rows 32-33). _unique_by
# is wired as of .4 commit 1 (S5's one-claim-per-objective guard) and again
# for S6's non_certified_selection_estimates de-duplication
# (SELECTION_ESTIMATE_DUPLICATE, design row 51's second G6 wiring --
# call site in :func:`_stage_s6_splits_held_out`). _strip_self_digest is
# wired as of P1-V2.2 (S8's unsigned-manifest reconstruction, design row
# 64). _run_agent_quality_checks is wired as of .6 commit 1, called by the
# public entry point, :func:`verify_agent_quality_certificate`.


_WALK_VALUE = 0
_WALK_CLOSE = 1


def _walk_strict_values(root: Any) -> None:
    """Reject values ``fp2.canonicalize`` must never be asked to handle,
    BEFORE canonicalization runs -- ported from
    ``evaluator_quality_verifier._walk_strict_values`` (lines 264-313 there),
    with this module's own two-way split of that sibling's single
    ``EVALUATOR_STRICT_INTEGER`` code: a ``bool`` (unlike the sibling, which
    explicitly lets booleans through) and any other non-``int``-safe scalar
    (``float``, a non-``str`` dict key, a string that fails strict UTF-8
    encoding) is :data:`STRICT_INTEGER`; an ``int`` whose magnitude exceeds
    the IEEE-754-safe range (``+-(2**53 - 1)``) is :data:`UNSAFE_INTEGER`.
    Uses an explicit work stack rather than recursion for the same reason the
    sibling does: recursion depth is a property of the caller's remaining
    interpreter stack, not of the data.
    """
    open_containers: set[int] = set()
    work: list[tuple[int, Any, int]] = [(_WALK_VALUE, root, 1)]
    while work:
        kind, value, depth = work.pop()
        if kind == _WALK_CLOSE:
            open_containers.discard(value)
            continue
        if isinstance(value, bool):
            _fail("STRICT_INTEGER", "bundle")
        if isinstance(value, int) and not -(2**53 - 1) <= value <= 2**53 - 1:
            _fail("UNSAFE_INTEGER", "bundle")
        if isinstance(value, float):
            _fail("STRICT_INTEGER", "bundle")
        if isinstance(value, str):
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                _fail("STRICT_INTEGER", "bundle")
        elif isinstance(value, (dict, list)):
            if depth > fp2.MAX_DEPTH:
                _fail("CANONICALIZATION", "bundle")
            identity = id(value)
            if identity in open_containers:
                _fail("CANONICALIZATION", "bundle")
            open_containers.add(identity)
            work.append((_WALK_CLOSE, identity, 0))
            if isinstance(value, dict):
                for key, child in value.items():
                    if not isinstance(key, str):
                        _fail("STRICT_INTEGER", "bundle")
                    work.append((_WALK_VALUE, key, depth + 1))
                    work.append((_WALK_VALUE, child, depth + 1))
            else:
                for child in value:
                    work.append((_WALK_VALUE, child, depth + 1))


@lru_cache(maxsize=1)
def _agent_quality_validator() -> Draft7Validator:
    """Cached :class:`Draft7Validator` for ``AgentQualityCertificateBundleV1``,
    built from the shipped ``agent_quality_v1_schema.json`` plus a
    ``referencing.Registry`` populated from every ``$id``-bearing document
    under ``traigent_schema/schemas`` -- mirrors
    ``evaluator_quality_verifier._evaluator_quality_validator``."""
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
        _fail("SCHEMA_DEPENDENCY", "bundle")


@_owns(
    "BUNDLE_SHAPE",
    "STRICT_INTEGER",
    "UNSAFE_INTEGER",
    "SCHEMA",
    "SCHEMA_DEPENDENCY",
    "CANONICALIZATION",
    "AGENT_QUALITY_VERIFICATION_FAILED",
)
def _stage_s1_structural(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S1 -- structural well-formedness (design rows 2-7, 10b).

    Owns: BUNDLE_SHAPE, STRICT_INTEGER, UNSAFE_INTEGER, SCHEMA,
    SCHEMA_DEPENDENCY, CANONICALIZATION, AGENT_QUALITY_VERIFICATION_FAILED
    (this stage's own unconditional-refusal placeholder catch-all).

    In order: (1) ``bundle`` must be a ``Mapping`` whose ``schema_version``
    is the one this module verifies, else BUNDLE_SHAPE; (2)
    :func:`_walk_strict_values` rejects any bool/float/oversized-int/
    non-str-key/non-UTF8-string/excessive-depth/self-referential value
    BEFORE canonicalization ever sees it (STRICT_INTEGER, UNSAFE_INTEGER,
    CANONICALIZATION); (3) :func:`_agent_quality_validator` runs
    ``AgentQualityCertificateBundleV1`` (SCHEMA for any validation error,
    SCHEMA_DEPENDENCY for an unresolvable ``$ref`` or any other validator
    construction/execution failure); (4) the ``fp2.canonicalize`` tail
    (CANONICALIZATION) -- belt-and-suspenders with step (2)'s depth/cycle
    guard, since a value step (2) cannot see (e.g. one fp2 rejects for a
    reason outside this walk's vocabulary) must still fail closed here
    rather than escape as a bare exception.
    """
    if not isinstance(bundle, Mapping) or bundle.get("schema_version") != (
        "traigent.agent_quality.certificate_bundle.v1"
    ):
        _fail("BUNDLE_SHAPE", "bundle")
    _walk_strict_values(bundle)
    try:
        errors = list(_agent_quality_validator().iter_errors(bundle))
    except Unresolvable:
        _fail("SCHEMA_DEPENDENCY", "bundle")
    except AgentQualityVerificationError:
        raise
    except Exception:
        _fail("SCHEMA_DEPENDENCY", "bundle")
    if errors:
        _fail("SCHEMA", "bundle")
    try:
        fp2.canonicalize(bundle)
    except fp2.Fp2UnsupportedValue:
        _fail("CANONICALIZATION", "bundle")


@_owns(
    "CONTEXT",
    "PROCESS_RECORD_BINDING_MISMATCH",
    "COMMITMENT_REF_MISMATCH",
    "SCOPE_MISMATCH",
    "MEASUREMENT_CONTRACT_NOT_PINNED",
    "MEASUREMENT_CONTRACT_MISMATCH",
)
def _stage_s2_context_binding(
    bundle: Mapping[str, Any],
    context: AgentQualityVerificationContext,
    process_record_bundle: Mapping[str, Any],
) -> None:
    """S2 -- context and scope binding (design rows 1, 8-12).

    Owns: CONTEXT (raised outside this stage, by
    ``AgentQualityVerificationContext.__post_init__``),
    PROCESS_RECORD_BINDING_MISMATCH, COMMITMENT_REF_MISMATCH, SCOPE_MISMATCH,
    MEASUREMENT_CONTRACT_NOT_PINNED, MEASUREMENT_CONTRACT_MISMATCH.

    Per the design (Sec 3), ``process_record_bundle`` is verified FIRST, in
    full, through the shipped public entry point
    (:func:`verify_process_record_certificate`); if that raises, the
    process record's own ``ProcessRecordVerificationError`` propagates
    UNCHANGED -- never wrapped into an agent-quality code -- so a caller
    always sees the real reason a process record failed, not this module's
    content-free catch-all. Nothing below this call runs if it raises. The
    verified result is then used, never the bundle's own unverified
    fields, for rows 9-10: the four commitment refs and the caller's scope
    pins are both checked against what the process record ACTUALLY proved,
    not merely what the agent-quality bundle claims about itself.

    In order: (row 8) the manifest's
    ``base_process_record_unsigned_manifest_digest`` must equal a fresh
    role digest over ``process_record_bundle``'s own real unsigned
    manifest; (row 9) all four commitment refs must agree, pairwise, across
    the manifest, the verified process record result, and the caller's
    context pins; (row 10) the verifier builds ``ScopeBindingProjectionV1``
    from ONLY the caller's own ``expected_project_ref``/
    ``expected_build_session_ref`` pins -- never copied from the bundle or
    the process record -- hashes it, and compares against both the
    manifest's and the declared plan's ``scope_binding_digest``; the
    verified process record's own ``project_ref``/``build_session_ref``
    must also agree with those same caller pins, so a process record that
    was itself issued for a different project/build cannot be substituted
    in; (rows 11-12) the caller must have pinned a measurement contract
    ref/digest, and the manifest and every measured claim must cite it
    exactly.
    """
    verified = verify_process_record_certificate(
        process_record_bundle,
        context=cast(ProcessRecordVerificationContext, context.process_record_context),
        trust_status=context.trust_status,
    )

    manifest = bundle["unsigned_manifest"]
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]

    if manifest.get("base_process_record_unsigned_manifest_digest") != _role_digest(
        _PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN, process_record_bundle["unsigned_manifest"]
    ):
        _fail("PROCESS_RECORD_BINDING_MISMATCH", "process_record_binding")

    for manifest_field, expected_ref in (
        ("agent_commitment_ref", context.expected_agent_commitment_ref),
        ("dataset_commitment_ref", context.expected_dataset_commitment_ref),
        ("evaluator_commitment_ref", context.expected_evaluator_commitment_ref),
        ("build_definition_commitment_ref", context.expected_build_definition_commitment_ref),
    ):
        if (
            manifest.get(manifest_field) != expected_ref
            or getattr(verified, manifest_field) != expected_ref
        ):
            _fail("COMMITMENT_REF_MISMATCH", "commitment_refs")

    if (
        verified.project_ref != context.expected_project_ref
        or verified.build_session_ref != context.expected_build_session_ref
    ):
        _fail("SCOPE_MISMATCH", "scope_binding")

    scope_binding_projection = {
        "schema_version": _schema_definition("ScopeBindingProjectionV1")["properties"][
            "schema_version"
        ]["const"],
        "project_ref": context.expected_project_ref,
        "build_session_ref": context.expected_build_session_ref,
    }
    expected_scope_binding_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["scope_binding"], scope_binding_projection
    )
    if (
        manifest.get("scope_binding_digest") != expected_scope_binding_digest
        or declared_plan.get("scope_binding_digest") != expected_scope_binding_digest
    ):
        _fail("SCOPE_MISMATCH", "scope_binding")

    if (
        context.expected_measurement_contract_ref is None
        or context.expected_measurement_contract_record_digest is None
    ):
        _fail("MEASUREMENT_CONTRACT_NOT_PINNED", "context")

    if (
        manifest.get("measurement_contract_ref") != context.expected_measurement_contract_ref
        or manifest.get("measurement_contract_record_digest")
        != context.expected_measurement_contract_record_digest
    ):
        _fail("MEASUREMENT_CONTRACT_MISMATCH", "measurement_contract")

    for claim in bundle.get("measured_claims", ()):
        if (
            claim.get("measurement_contract_ref") != context.expected_measurement_contract_ref
            or claim.get("measurement_contract_record_digest")
            != context.expected_measurement_contract_record_digest
        ):
            _fail("MEASUREMENT_CONTRACT_MISMATCH", "measurement_contract")


@_owns(
    "PACKAGE_DATA_INVALID",
    "AGGREGATION_POLICY_MISMATCH",
    "OBJECTIVE_REGISTRY_MISMATCH",
    "NON_CLAIM_SET_MISMATCH",
    "QUANTILE_TABLE_MISMATCH",
)
def _stage_s3_registry_identity(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S3 -- the four shipped registries' identity (design rows 13-16).

    Owns: PACKAGE_DATA_INVALID (raised outside this stage, by
    :func:`_load_agent_quality_document`), AGGREGATION_POLICY_MISMATCH,
    OBJECTIVE_REGISTRY_MISMATCH, NON_CLAIM_SET_MISMATCH,
    QUANTILE_TABLE_MISMATCH.

    For ``aggregation_policy`` and ``objective_registry`` (rows 13-14): the
    manifest's identity must equal BOTH the shipped package document's own
    (:func:`_expected_registry_identity`) AND the declared plan's --
    ``AgentQualityDeclaredPlanV1`` carries these two identities but not
    ``non_claim_catalog``/``quantile_table``, so those two (rows 15-16) are
    checked against the shipped document alone. Row 15 additionally checks
    that the bundle's printed ``non_claims`` tuple names the catalog's own
    entries, in the catalog's own order -- not merely the same count.
    """
    manifest = bundle["unsigned_manifest"]
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]

    if manifest.get("aggregation_policy") != _expected_registry_identity(
        "aggregation_policy"
    ) or declared_plan.get("aggregation_policy") != _expected_registry_identity(
        "aggregation_policy"
    ):
        _fail("AGGREGATION_POLICY_MISMATCH", "aggregation_policy")

    if manifest.get("objective_registry") != _expected_registry_identity(
        "objective_registry"
    ) or declared_plan.get("objective_registry") != _expected_registry_identity(
        "objective_registry"
    ):
        _fail("OBJECTIVE_REGISTRY_MISMATCH", "objective_registry")

    if manifest.get("non_claim_catalog") != _expected_registry_identity("non_claim_catalog"):
        _fail("NON_CLAIM_SET_MISMATCH", "non_claims")
    catalog_ids = tuple(
        entry["non_claim_id"]
        for entry in _load_agent_quality_document("non_claim_catalog")["entries"]
    )
    bundle_ids = tuple(entry.get("non_claim_id") for entry in bundle.get("non_claims", ()))
    if bundle_ids != catalog_ids:
        _fail("NON_CLAIM_SET_MISMATCH", "non_claims")

    if manifest.get("quantile_table") != _expected_registry_identity("quantile_table"):
        _fail("QUANTILE_TABLE_MISMATCH", "quantile_table")

    # P1-V2.4 review P2-1: row 16 only ever compared the MANIFEST's own
    # quantile-table identity. A Student-t claim carries its OWN copy in
    # ``interval_params.quantile_table`` (``IntervalParamsStudentTV1``,
    # required whenever this method is used) and nothing compared THAT copy
    # to the shipped table -- a claim could cite a foreign table identity
    # while the manifest's own copy still matched. A Wilson claim's
    # ``IntervalParamsWilsonV1`` carries no such field at all, so this loop
    # is a no-op for every Wilson claim by construction.
    for claim in bundle.get("measured_claims", ()):
        if not isinstance(claim, Mapping):
            continue
        interval_params = claim.get("interval_params")
        if not isinstance(interval_params, Mapping):
            continue
        quantile_table = interval_params.get("quantile_table")
        if quantile_table is not None and quantile_table != _expected_registry_identity(
            "quantile_table"
        ):
            _fail("QUANTILE_TABLE_MISMATCH", "quantile_table")


@_owns(
    "DECLARED_PLAN_DIGEST_MISMATCH",
    "DECLARED_PLAN_SIGNATURE_INVALID",
    "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
    "DECLARED_PLAN_PIN_MISMATCH",
)
def _stage_s4_declared_plan_signatures(
    bundle: Mapping[str, Any],
    context: AgentQualityVerificationContext,
    process_record_bundle: Mapping[str, Any],
) -> None:
    """S4 -- declared-plan digest and signature (design rows 17-19, 21).

    Owns: DECLARED_PLAN_DIGEST_MISMATCH, DECLARED_PLAN_SIGNATURE_INVALID,
    DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH, DECLARED_PLAN_PIN_MISMATCH.

    Design row 20 (ordering: ``declared_at`` before the earliest result
    timestamp) is NOT carried into this vocabulary: the shipped module
    docstring and ``AgentQualityDeclaredPlanV1`` both state plainly that
    ordering evidence is out of scope for this certificate family in v1 (see
    ``test_declared_plan_only_claims_the_digest_binding``), so a stage that
    checked it would assert something this certificate family does not
    verify. ``DECLARED_PLAN_PIN_MISMATCH`` (design row 21) survives as the
    one genuine binding check: whether ``context.expected_declared_plan_digest``,
    when the caller supplied it, equals the bundle's.

    In order: (row 17) a fresh role digest over the declared plan (its own
    ``declared_plan_digest`` stripped from the preimage) must equal both
    the declared plan's own ``declared_plan_digest`` and the manifest's;
    (row 19) the signature block's own ``declared_plan_digest`` field --
    what the issuer actually signed over -- must agree with that same
    value, checked BEFORE the cryptographic verification below so a
    signature that is bytewise valid but over a stale/foreign
    ``declared_plan_digest`` assertion cannot be mistaken for a genuine
    binding; (row 18) the issuer's ed25519 signature over
    ``UTF8(domain) || 0x00 || jcs_v1(declared_plan)`` is verified, with the
    issuer's public key resolved from ``process_record_bundle``'s verified
    ``verification_materials_v0.issuer`` -- the same resolution S8 performs
    for the top-level manifest signature (design row 66); this stage owns
    no KEY_RING_MISMATCH code, so ANY failure resolving or parsing that key
    material is folded into DECLARED_PLAN_SIGNATURE_INVALID rather than
    left to escape unguarded. P1-V2.3 review finding P2-2: before verifying
    the signature bytes, the envelope's OWN declared
    ``issuer_key_ref``/``trust_ring_ref``/``algorithm`` must also agree with
    ``process_record_bundle``'s verified issuer materials -- otherwise a
    fully self-consistent bundle could assert a foreign signing key/ring in
    its own signature block while still verifying under the authoritative
    issuer key, since Ed25519 verification success says nothing about which
    ref the caller printed. Any disagreement folds into the same
    DECLARED_PLAN_SIGNATURE_INVALID code, for the same reason as the key
    resolution failure above.
    """
    manifest = bundle["unsigned_manifest"]
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    declared_plan_signature = bundle["declared_plan_envelope"]["signature"]

    declared_plan_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["declared_plan"],
        _strip_self_digest(dict(declared_plan), "declared_plan_digest"),
    )
    if declared_plan_digest != declared_plan.get(
        "declared_plan_digest"
    ) or declared_plan_digest != manifest.get("declared_plan_digest"):
        _fail("DECLARED_PLAN_DIGEST_MISMATCH", "declared_plan")

    if declared_plan_signature.get("declared_plan_digest") != declared_plan.get(
        "declared_plan_digest"
    ):
        _fail("DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH", "declared_plan_signature")

    try:
        v0_issuer = process_record_bundle["verification_materials_v0"]["issuer"]
        issuer_public_key = _material_public_key(dict(v0_issuer), _ISSUER_SPKI_DOMAIN)
    except Exception:
        _fail("DECLARED_PLAN_SIGNATURE_INVALID", "declared_plan_signature")

    if not isinstance(v0_issuer, Mapping):
        _fail("DECLARED_PLAN_SIGNATURE_INVALID", "declared_plan_signature")
    if (
        declared_plan_signature.get("issuer_key_ref") != v0_issuer.get("key_ref")
        or declared_plan_signature.get("trust_ring_ref") != v0_issuer.get("trust_ring_ref")
        or declared_plan_signature.get("algorithm") != v0_issuer.get("algorithm")
    ):
        _fail("DECLARED_PLAN_SIGNATURE_INVALID", "declared_plan_signature")

    canonical_declared_plan = cast(str, fp2.canonicalize(declared_plan)).encode("utf-8")
    material = (
        _AGENT_QUALITY_DIGEST_DOMAINS["declared_plan_signature"].encode("utf-8")
        + b"\x00"
        + canonical_declared_plan
    )
    try:
        _verify_signature(
            issuer_public_key,
            declared_plan_signature.get("algorithm"),
            material,
            declared_plan_signature.get("signature"),
        )
    except Exception:
        _fail("DECLARED_PLAN_SIGNATURE_INVALID", "declared_plan_signature")

    if (
        context.expected_declared_plan_digest is not None
        and context.expected_declared_plan_digest != declared_plan.get("declared_plan_digest")
    ):
        _fail("DECLARED_PLAN_PIN_MISMATCH", "declared_plan")


@_owns(
    "QUANTILE_TABLE_LOOKUP_FAILED",
    "OBJECTIVE_DUPLICATE",
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
)
def _stage_s5_objective_measurement(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S5 -- objective registration and interval recomputation (design rows
    22-27, 29-39).

    Owns: QUANTILE_TABLE_LOOKUP_FAILED (raised outside this stage, by
    :func:`_lookup_t_scaled`, itself reached from :func:`_wilson_bounds`/
    :func:`_student_t_half_width` below), OBJECTIVE_DUPLICATE,
    OBJECTIVE_NOT_IN_DECLARED_PLAN, PRIMARY_OBJECTIVE_MISSING,
    OBJECTIVE_NOT_REGISTERED, OBJECTIVE_KIND_MISMATCH, OBJECTIVE_UNIT_MISMATCH,
    OBJECTIVE_MINIMUM_SAMPLE_NOT_MET, DISTRIBUTION_ASSUMPTION_NOT_REGISTERED,
    INTERVAL_METHOD_NOT_EMITTABLE, INTERVAL_METHOD_NOT_ADMISSIBLE,
    SUFFICIENT_STATISTICS_SHAPE, POINT_ESTIMATE_RECOMPUTATION_MISMATCH,
    INTERVAL_RECOMPUTATION_MISMATCH, INTERVAL_ORDER, INTERVAL_DEGENERATE,
    INTERVAL_OUT_OF_UNIT_BOUNDS, NOMINAL_COVERAGE_MISMATCH,
    SAMPLE_SIZE_MISMATCH, VERIFICATION_LEVEL_MISMATCH.

    A schema-valid bundle's ``measured_claims`` is empty if and only if its
    single claim-support row is ``abstained``
    (``AgentQualityCertificateBundleV1``'s own abstention coupling: an
    ``issuer_verified`` row requires ``minItems: 1``, an ``abstained`` row
    forces ``maxItems: 0``) -- with nothing certified, this stage has nothing
    to recompute, so it returns immediately rather than reporting
    PRIMARY_OBJECTIVE_MISSING against an empty set.

    Per certified claim, in order: (row 22) its ``objective_id`` must be one
    of the declared plan's own ``objective_ids``; (row 23, once, over the
    whole certified set) the manifest's ``primary_objective_id`` must equal
    the declared plan's, and that id must actually be among the certified
    claims; (row 28, once, over the whole certified set) no two claims may
    certify the same objective (:func:`_unique_by`); then per claim again:
    (row 24) the objective must be a member of the SHIPPED objective
    registry; (row 25) its ``objective_kind``/``direction`` and ``unit`` must
    equal that registry entry's (kind+direction fold into
    OBJECTIVE_KIND_MISMATCH, unit into its own OBJECTIVE_UNIT_MISMATCH); (row
    26) ``sample_size`` must meet the registry entry's
    ``minimum_sample_size``; (row 27) a ``nonnegative_mean`` objective's
    registry entry must carry a registered ``distribution_assumption``; (row
    29) the claim's ``interval_method`` must be emittable in v1; (row 30) it
    must be the one method admissible for the objective's kind
    (:data:`_ADMISSIBLE_INTERVAL_METHOD_BY_OBJECTIVE_KIND`); (row 31) the
    sufficient statistics' ``stat_kind`` must match that method, and a
    Wilson claim's ``success_count`` must not exceed its ``trial_count``;
    (row 37, per claim) ``nominal_coverage_ppm`` must be a member of the
    closed coverage vocabulary; (row 36) the declared point estimate and
    both endpoints must lie within the registry entry's own
    ``[minimum, maximum]``; (row 38) ``sample_size`` must equal both the
    holdout split's ``item_count`` and the sufficient statistics' own count
    (``trial_count``/``sample_count``); (row 39) ``verification_level`` must
    be ``construction_recomputed_v1``, the only level this stage's
    recomputation actually establishes. Finally (row 37, once, over the
    whole certified set) every claim must share the SAME nominal coverage.

    Rows 34-35 (per claim, immediately after row 36's unit-bounds check):
    the DECLARED ``interval_low <= point_estimate <= interval_high`` and
    ``interval_high > interval_low`` -- checked before any recomputation, so
    a nonsense declared interval is named INTERVAL_ORDER/INTERVAL_DEGENERATE
    rather than surfacing as a recomputation mismatch. Rows 32-33 (per
    claim, immediately after): the point estimate and both interval
    endpoints are recomputed in exact integer arithmetic from the
    sufficient statistics alone -- Wilson via :func:`_wilson_point` and
    :func:`_wilson_bounds` from ``success_count``/``trial_count``; Student-t
    via the claim's ``mean_fixed`` and :func:`_student_t_half_width` from
    ``sample_stddev_fixed``/``sample_count``/``unit_scale`` -- and compared
    to the declared values. A quantile point-estimate branch is unreachable
    by construction: row 29 already refuses INTERVAL_METHOD_NOT_EMITTABLE
    for every ``IntervalMethodV1`` member except the two handled here.
    """
    claims = list(bundle.get("measured_claims", ()))
    if not claims:
        return

    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    manifest = bundle["unsigned_manifest"]
    registry_by_id = _objective_registry_entries_by_id()

    declared_objective_ids = set(declared_plan.get("objective_ids", ()))
    for claim in claims:
        if claim.get("objective_id") not in declared_objective_ids:
            _fail("OBJECTIVE_NOT_IN_DECLARED_PLAN", "measured_claims.objective")

    claim_objective_ids = {claim.get("objective_id") for claim in claims}
    if (
        manifest.get("primary_objective_id") != declared_plan.get("primary_objective_id")
        or declared_plan.get("primary_objective_id") not in claim_objective_ids
    ):
        _fail("PRIMARY_OBJECTIVE_MISSING", "measured_claims.objective")

    _unique_by(
        claims, lambda claim: claim.get("objective_id"), "OBJECTIVE_DUPLICATE", "measured_claims"
    )

    holdout_item_count = _holdout_item_count(bundle.get("evaluation_splits"))
    coverages: set[object] = set()

    for claim in claims:
        entry = registry_by_id.get(claim.get("objective_id"))
        if entry is None:
            _fail("OBJECTIVE_NOT_REGISTERED", "measured_claims.objective")

        if (
            claim.get("objective_kind") != entry["objective_kind"]
            or claim.get("direction") != entry["direction"]
        ):
            _fail("OBJECTIVE_KIND_MISMATCH", "measured_claims.objective")
        if claim.get("unit") != entry["unit"]:
            _fail("OBJECTIVE_UNIT_MISMATCH", "measured_claims.objective")

        sample_size = claim.get("sample_size")
        if not isinstance(sample_size, int) or sample_size < entry["minimum_sample_size"]:
            _fail("OBJECTIVE_MINIMUM_SAMPLE_NOT_MET", "measured_claims.sample_size")

        if entry["objective_kind"] == "nonnegative_mean" and (
            entry.get("distribution_assumption") not in _distribution_assumption_values()
        ):
            _fail("DISTRIBUTION_ASSUMPTION_NOT_REGISTERED", "objective_registry")

        interval_params = claim.get("interval_params")
        interval_method = (
            interval_params.get("interval_method") if isinstance(interval_params, Mapping) else None
        )
        if interval_method not in _emittable_interval_methods():
            _fail("INTERVAL_METHOD_NOT_EMITTABLE", "measured_claims.interval_params")
        if interval_method != _ADMISSIBLE_INTERVAL_METHOD_BY_OBJECTIVE_KIND.get(
            entry["objective_kind"]
        ):
            _fail("INTERVAL_METHOD_NOT_ADMISSIBLE", "measured_claims.interval_params")

        stats = claim.get("sufficient_statistics")
        stats = stats if isinstance(stats, Mapping) else {}
        if stats.get("stat_kind") != _STAT_KIND_BY_INTERVAL_METHOD.get(interval_method):
            _fail("SUFFICIENT_STATISTICS_SHAPE", "measured_claims.sufficient_statistics")
        stat_own_count: object
        if interval_method == "wilson_score_v1":
            success_count = stats.get("success_count")
            trial_count = stats.get("trial_count")
            if (
                not isinstance(success_count, int)
                or not isinstance(trial_count, int)
                or success_count > trial_count
            ):
                _fail("SUFFICIENT_STATISTICS_SHAPE", "measured_claims.sufficient_statistics")
            stat_own_count = trial_count
            # P1-V2.4 review P2-1: a Wilson claim's own declared
            # ``continuity_correction`` must be ``none`` -- the only value
            # this stage's recomputation (:func:`_wilson_bounds`) actually
            # implements. A claim labelled ``yates_v1`` while carrying plain
            # Wilson endpoints used to PASS (the field was never read); an
            # honestly Yates-widened interval was REJECTED as a
            # recomputation mismatch -- backwards. Until a Yates-corrected
            # recomputation exists, ``yates_v1`` is not an admissible
            # construction for this verifier to certify.
            if interval_params.get("continuity_correction") != "none":
                _fail("INTERVAL_METHOD_NOT_ADMISSIBLE", "measured_claims.interval_params")
        else:
            stat_own_count = stats.get("sample_count")
            # P1-V2.4 review P2-1: a Student-t claim's own declared
            # ``degrees_of_freedom`` (in ``interval_params``, independent of
            # ``sufficient_statistics.sample_count``) and ``unit_scale``
            # (in ``sufficient_statistics``, independent of the claim's own
            # top-level ``unit``) were both accepted unchecked -- a claim
            # could assert a foreign df or a foreign unit_scale while its
            # printed interval was recomputed under DIFFERENT inputs.
            if (
                not isinstance(stat_own_count, int)
                or interval_params.get("degrees_of_freedom") != stat_own_count - 1
            ):
                _fail("SUFFICIENT_STATISTICS_SHAPE", "measured_claims.sufficient_statistics")
            if stats.get("unit_scale") != claim.get("unit"):
                _fail("SUFFICIENT_STATISTICS_SHAPE", "measured_claims.sufficient_statistics")

        coverage_ppm = claim.get("nominal_coverage_ppm")
        if coverage_ppm not in _nominal_coverage_values():
            _fail("NOMINAL_COVERAGE_MISMATCH", "measured_claims")
        coverages.add(coverage_ppm)

        low = claim.get("interval_low")
        point = claim.get("point_estimate")
        high = claim.get("interval_high")
        for endpoint in (low, point, high):
            if (
                not isinstance(endpoint, int)
                or endpoint < entry["minimum"]
                or endpoint > entry["maximum"]
            ):
                _fail("INTERVAL_OUT_OF_UNIT_BOUNDS", "measured_claims.interval")

        # Rows 34-35 run BEFORE rows 32-33's recomputation, on the DECLARED
        # endpoints alone: a declared interval that is out of order or
        # degenerate is named as such, never mistaken for a recomputation
        # disagreement.
        if not (low <= point <= high):
            _fail("INTERVAL_ORDER", "measured_claims.interval")
        if not (high > low):
            _fail("INTERVAL_DEGENERATE", "measured_claims.interval")

        # Rows 32-33: exact-integer recomputation of the point estimate and
        # both interval endpoints under `exact_integer_rational_v1`, from the
        # sufficient statistics alone -- never from the declared low/point/
        # high above. `interval_method` is guaranteed to be one of the two
        # emittable methods here: row 29 already refused
        # INTERVAL_METHOD_NOT_EMITTABLE for `order_statistic_quantile_v1` and
        # `bootstrap_percentile_v1`, and `IntervalMethodV1` has no other
        # member, so a quantile point-estimate branch is unreachable by
        # construction and is not implemented here.
        if interval_method == "wilson_score_v1":
            # success_count/trial_count were already narrowed to int by the
            # SUFFICIENT_STATISTICS_SHAPE guard above, in the same loop
            # iteration -- the cast documents that, since the narrowing does
            # not survive across the two separate `if` statements.
            wilson_successes = cast(int, success_count)
            wilson_trials = cast(int, trial_count)
            expected_point = _wilson_point(wilson_successes, wilson_trials)
            if point != expected_point:
                _fail("POINT_ESTIMATE_RECOMPUTATION_MISMATCH", "measured_claims.interval")
            expected_low, expected_high = _wilson_bounds(
                wilson_successes, wilson_trials, coverage_ppm
            )
        else:
            # mean_fixed/sample_stddev_fixed/unit_scale/sample_count are all
            # schema-required, schema-typed fields of
            # SufficientStatisticsMeanVarianceV1 -- guaranteed present and
            # correctly typed by S1's schema validation before S5 ever runs.
            mean_fixed = cast(int, stats.get("mean_fixed"))
            sample_stddev_fixed = cast(int, stats.get("sample_stddev_fixed"))
            unit_scale = cast(str, stats.get("unit_scale"))
            sample_count = cast(int, stat_own_count)
            if point != mean_fixed:
                _fail("POINT_ESTIMATE_RECOMPUTATION_MISMATCH", "measured_claims.interval")
            half_width = _student_t_half_width(
                mean_fixed=mean_fixed,
                sample_stddev_fixed=sample_stddev_fixed,
                sample_count=sample_count,
                coverage_ppm=coverage_ppm,
                unit_scale=unit_scale,
            )
            expected_low = mean_fixed - half_width
            expected_high = mean_fixed + half_width

        if low != expected_low or high != expected_high:
            _fail("INTERVAL_RECOMPUTATION_MISMATCH", "measured_claims.interval")

        if sample_size != holdout_item_count or sample_size != stat_own_count:
            _fail("SAMPLE_SIZE_MISMATCH", "measured_claims.sample_size")

        if claim.get("verification_level") != "construction_recomputed_v1":
            _fail("VERIFICATION_LEVEL_MISMATCH", "measured_claims.verification_level")

    if len(coverages) > 1:
        _fail("NOMINAL_COVERAGE_MISMATCH", "measured_claims")


def _split_size_bound(universe_count: int, holdout_fraction_ppm: int) -> tuple[int, int]:
    """The exact-integer form of design row 47's plausibility bound,
    LITERALLY: ``|holdout - round(N*p)| <= 6*isqrt(N*p*(1-p)) + 1``, with
    ``p = holdout_fraction_ppm / 10**6`` (CTO decision, P1-V2.5 review
    P3-6: the design's literal is normative -- ``isqrt`` here means the
    FLOORED integer square root, not a ceiling, even though that makes the
    bound up to 6 items stricter than a rounded-up reading).

    ``round(N*p)`` is computed half-up in item-count units directly:
    ``round_val = (N*ppm + scale//2) // scale`` (``scale`` =
    :data:`_T_SCALE`, ``ppm`` = ``holdout_fraction_ppm``).

    ``N*p*(1-p)`` is computed as the exact integer product ``N * ppm *
    (scale - ppm)``, floor-divided by ``scale**2`` -- ``npq`` -- then
    ``math.isqrt(npq)`` gives the design's own ``isqrt(N*p*(1-p))`` in
    item-count units, no separate scaling step needed since both ``round_val``
    and this square root are already unscaled integers.

    Returns ``(round_val, tolerance)`` in item-count units; the caller
    compares ``abs(holdout_count - round_val) <= tolerance`` directly.
    """
    scale = _T_SCALE
    round_val = (universe_count * holdout_fraction_ppm + scale // 2) // scale
    npq = (universe_count * holdout_fraction_ppm * (scale - holdout_fraction_ppm)) // (
        scale * scale
    )
    tolerance = 6 * math.isqrt(npq) + 1
    return round_val, tolerance


@_owns(
    "SELECTION_ESTIMATE_DUPLICATE",
    "SPLIT_SET_SHAPE",
    "HOLDOUT_NOT_USED",
    "HOLDOUT_MISSING",
    "HOLDOUT_TOO_SMALL",
    "SPLIT_DERIVATION_MISMATCH",
    "SPLIT_PARTITION_INCOMPLETE",
    "SPLIT_COMMITMENT_COLLISION",
    "SPLIT_SIZE_IMPLAUSIBLE",
    "HOLDOUT_REUSED",
    "ARM_COUNT_MISMATCH",
)
def _stage_s6_splits_held_out(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S6 -- evaluation splits and holdout usage (design rows 40-51, minus
    the schema-preempted SELECTION_ESTIMATE_IN_CERTIFIED_SET and the
    input-preempted SPLIT_OPENING_MISMATCH/SPLIT_OPENING_RULE_VIOLATION --
    see :data:`AGENT_QUALITY_INPUT_PREEMPTED_CODES`; the runner itself
    refuses a caller-supplied ``split_opening`` before any stage runs, since
    v1 defines no witness schema for this stage to check one against).

    Owns: SELECTION_ESTIMATE_DUPLICATE, SPLIT_SET_SHAPE, HOLDOUT_NOT_USED,
    HOLDOUT_MISSING, HOLDOUT_TOO_SMALL, SPLIT_DERIVATION_MISMATCH,
    SPLIT_PARTITION_INCOMPLETE, SPLIT_COMMITMENT_COLLISION,
    SPLIT_SIZE_IMPLAUSIBLE, HOLDOUT_REUSED, ARM_COUNT_MISMATCH.

    Four of these codes are schema-preempted-with-backstop, the same P2-2
    pattern as .4's seven S5 codes (see
    :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_BACKSTOP_CODES`): HOLDOUT_NOT_USED
    (``MeasuredObjectiveClaimV1.evaluated_split_id`` is a hard schema
    ``const: "holdout"``), HOLDOUT_MISSING (``EvaluationSplitSetV1`` is a
    fixed 2-tuple whose second member is ALWAYS ``split_id: "holdout"``),
    HOLDOUT_TOO_SMALL (the tuple's own ``item_count.minimum: 30`` already
    enforces the base floor, and whenever a certified claim exists, S5's
    SAMPLE_SIZE_MISMATCH -- which runs first -- already forces
    ``holdout.item_count == claim.sample_size``, and that claim's own
    schema-enforced minimum already meets its objective's registered
    floor), and HOLDOUT_REUSED (``holdout_scored_arm_count`` is a hard
    schema ``const: 1`` on BOTH the manifest and the declared plan). Each
    guard below is kept as a defensive backstop regardless.

    In order: (row 40) the two-record shape schema already fixes order and
    ``split_id``; what remains is checking, for a bundle that reaches this
    stage, that ``commitment_scheme``/``canonicalization_profile`` agree
    between the two records and that both cite the SAME
    ``split_derivation_digest`` (defensive shape guards also cover a
    direct-call malformed bundle, whose two-record shape is not
    schema-guaranteed); (row 41) every certified claim's
    ``evaluated_split_id`` is ``"holdout"``; (row 42) the holdout record
    exists; (row 43) the holdout's ``item_count`` meets both the schema
    floor and every certified objective's registered minimum; (row 44) the
    top-level declaration's own role digest is recomputed under its
    ``AgentQualityDigestDomainRegistryV1`` domain, all four self-reported
    ``split_derivation_digest`` copies (both records, the declaration's own
    field, and the declared plan's embedded copy) must equal that
    recomputation, and the declared plan's embedded ``split_derivation`` must
    equal the shipped one as CONTENT -- a validly signed bundle cannot ship a
    split derivation different from the one its declared plan already fixed,
    even if every self-reported digest field agrees with every other; (row 45)
    the two split sizes sum to the declared universe size; (row 46) the two
    ``split_commitment_digest`` values differ; (row 47)
    :func:`_split_size_bound`'s plausibility bound; (row 49)
    ``holdout_scored_arm_count`` is 1 in both the manifest and the declared
    plan; (row 50) ``selection_arm_count`` agrees between them; finally, the
    second G6 wiring: no two ``non_certified_selection_estimates`` records
    share an ``objective_id`` (:func:`_unique_by`).
    """
    manifest = bundle["unsigned_manifest"]
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    split_derivation = bundle["split_derivation"]
    splits = bundle.get("evaluation_splits")

    # Row 40 (SPLIT_SET_SHAPE) and row 42 (HOLDOUT_MISSING) both concern the
    # same two-record tuple's shape, so this stage separates them by WHICH
    # slot is wrong: a bad "selection" slot (missing/wrong split_id) or a
    # scheme/profile/derivation-digest disagreement between the two records
    # is SPLIT_SET_SHAPE; a "holdout" slot that is missing or names a
    # different split_id is HOLDOUT_MISSING alone -- otherwise, on a
    # schema-valid bundle where EvaluationSplitSetV1's own tuple shape
    # already guarantees both slots, the second check would be dead code
    # subsumed entirely by the first.
    if (
        not isinstance(splits, (list, tuple))
        or len(splits) != 2
        or not isinstance(splits[0], Mapping)
        or splits[0].get("split_id") != "selection"
    ):
        _fail("SPLIT_SET_SHAPE", "evaluation_splits")
    selection = splits[0]
    holdout_candidate = splits[1]
    if not isinstance(holdout_candidate, Mapping) or holdout_candidate.get("split_id") != "holdout":
        _fail("HOLDOUT_MISSING", "evaluation_splits.holdout")
    holdout = holdout_candidate
    if selection.get("commitment_scheme") != holdout.get("commitment_scheme") or selection.get(
        "canonicalization_profile"
    ) != holdout.get("canonicalization_profile"):
        _fail("SPLIT_SET_SHAPE", "evaluation_splits")
    if selection.get("split_derivation_digest") != holdout.get("split_derivation_digest"):
        _fail("SPLIT_SET_SHAPE", "evaluation_splits")

    for claim in bundle.get("measured_claims", ()):
        if not isinstance(claim, Mapping) or claim.get("evaluated_split_id") != "holdout":
            _fail("HOLDOUT_NOT_USED", "measured_claims")

    holdout_count = holdout.get("item_count")
    registry_by_id = _objective_registry_entries_by_id()
    minimum_required = 30
    for claim in bundle.get("measured_claims", ()):
        if not isinstance(claim, Mapping):
            continue
        objective_id = claim.get("objective_id")
        entry = registry_by_id.get(objective_id) if isinstance(objective_id, str) else None
        if entry is not None:
            minimum_required = max(minimum_required, entry["minimum_sample_size"])
    if not isinstance(holdout_count, int) or holdout_count < minimum_required:
        _fail("HOLDOUT_TOO_SMALL", "evaluation_splits.holdout")

    recomputed_split_derivation_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["split_derivation"],
        _strip_self_digest(split_derivation, "split_derivation_digest"),
    )
    declared_split_derivation = declared_plan.get("split_derivation")
    declared_digest = (
        declared_split_derivation.get("split_derivation_digest")
        if isinstance(declared_split_derivation, Mapping)
        else None
    )
    if (
        split_derivation.get("split_derivation_digest") != recomputed_split_derivation_digest
        or selection.get("split_derivation_digest") != recomputed_split_derivation_digest
        or holdout.get("split_derivation_digest") != recomputed_split_derivation_digest
        or declared_digest != recomputed_split_derivation_digest
        or declared_split_derivation != split_derivation
    ):
        _fail("SPLIT_DERIVATION_MISMATCH", "split_derivation")

    selection_count = selection.get("item_count")
    universe_count = split_derivation.get("evaluated_universe_item_count")
    if (
        not isinstance(selection_count, int)
        or not isinstance(holdout_count, int)
        or not isinstance(universe_count, int)
        or selection_count + holdout_count != universe_count
    ):
        _fail("SPLIT_PARTITION_INCOMPLETE", "evaluation_splits")

    if selection.get("split_commitment_digest") == holdout.get("split_commitment_digest"):
        _fail("SPLIT_COMMITMENT_COLLISION", "evaluation_splits")

    holdout_fraction_ppm = split_derivation.get("holdout_fraction_ppm")
    if not isinstance(holdout_fraction_ppm, int) or not isinstance(universe_count, int):
        _fail("SPLIT_SIZE_IMPLAUSIBLE", "evaluation_splits.holdout")
    round_val, tolerance = _split_size_bound(universe_count, holdout_fraction_ppm)
    if abs(holdout_count - round_val) > tolerance:
        _fail("SPLIT_SIZE_IMPLAUSIBLE", "evaluation_splits.holdout")

    if (
        manifest.get("holdout_scored_arm_count") != 1
        or declared_plan.get("holdout_scored_arm_count") != 1
    ):
        _fail("HOLDOUT_REUSED", "unsigned_manifest")

    if manifest.get("selection_arm_count") != declared_plan.get("selection_arm_count"):
        _fail("ARM_COUNT_MISMATCH", "unsigned_manifest")

    _unique_by(
        list(bundle.get("non_certified_selection_estimates", ())),
        lambda estimate: estimate.get("objective_id") if isinstance(estimate, Mapping) else None,
        "SELECTION_ESTIMATE_DUPLICATE",
        "non_certified_selection_estimates",
    )


@_owns(
    "CLAIM_NOT_VERIFIED",
    "PILLAR_SUPPORT_SHAPE",
    "ASSERTION_DIGEST_MISMATCH",
)
def _stage_s7_composition_abstention(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S7 -- claim-support composition and abstention (design rows 52-56,
    minus the schema-preempted ABSTAINED_BUNDLE_CARRIES_CLAIMS,
    SELECTION_ESTIMATE_IN_CERTIFIED_SET, and PILLAR_BINDING_MISMATCH).

    Owns: CLAIM_NOT_VERIFIED, PILLAR_SUPPORT_SHAPE, ASSERTION_DIGEST_MISMATCH.

    ABSTAINED_BUNDLE_CARRIES_CLAIMS (design row 52) is NOT carried into this
    stage's owned set: ``AgentQualityCertificateBundleV1``'s own ``allOf``
    if/then/else abstention coupling already forces ``measured_claims`` and
    ``non_certified_selection_estimates`` to ``maxItems 0`` on a non-
    ``issuer_verified`` support row, so no schema-valid bundle can ever reach
    this condition -- see AGENT_QUALITY_SCHEMA_PREEMPTED_CODES.

    PILLAR_BINDING_MISMATCH (design row 55) is likewise NOT owned: the
    shipped schema's ``EmittablePillarStatusV1`` excludes ``assessed_supported``
    entirely (only ``condition_declared_unverified`` is emittable in v1), so
    no schema-valid ``pillar_support`` entry can ever carry the
    ``bound_manifest_digest``/sibling-verification binding this code would
    check -- there is no guard for it anywhere in this module, matching
    :data:`AGENT_QUALITY_SCHEMA_PREEMPTED_DEAD_CODES`'s other two members.
    v1 defines no sibling-bundle input mechanism to check one against, and
    this packet does not invent one.

    In order: (row 53) the single claim-support row must be
    ``issuer_verified`` UNLESS the caller's ``context.accept_abstained_bundle``
    permits an ``abstained`` one -- the runner (not this stage) is what
    actually constructs an ABSTAINED :class:`AgentQualityVerificationResult`
    when this check passes on an abstained row; (row 54) ``pillar_support``
    is exactly the two-member ``[dataset, evaluator]`` tuple the schema
    fixes in order and per-position ``condition_code``, but the schema
    cannot tie ``bound_commitment_ref`` to any OTHER field, so this stage
    checks it against the manifest's own real commitment refs, ``status``
    against the emittable vocabulary, and -- since the schema also cannot
    tie an entry's optional refs to its OWN status -- that a
    ``condition_declared_unverified`` entry carries none of
    ``bound_manifest_digest``, ``evidence_ref``, or ``trust_anchor_ref``
    (an unverified condition asserts nothing bound, so a signed entry
    carrying one of these binding-shaped fields anyway is a shape
    violation even though nothing downstream reads it); (row 56) the assertion's
    own role digest is recomputed and compared to both its own
    ``assertion_digest`` field and the manifest's copy, and its
    ``rendered_text`` is compared to the schema's own fixed ``const`` --
    v1 ships no separate ``assertion_templates`` document for this pillar
    (unlike evaluator_quality's), so the schema's ``const`` IS the
    mechanical rendering to compare against.
    """
    manifest = bundle["unsigned_manifest"]
    row = bundle["claim_support_rows"][0]

    evidence_basis = row.get("evidence_basis")
    if evidence_basis != "issuer_verified" and not context.accept_abstained_bundle:
        _fail("CLAIM_NOT_VERIFIED", "claim_support_rows")

    pillar_support = manifest.get("pillar_support")
    if not isinstance(pillar_support, (list, tuple)) or len(pillar_support) != 2:
        _fail("PILLAR_SUPPORT_SHAPE", "pillar_support")
    emittable_statuses = _emittable_pillar_statuses()
    for entry, subject, condition_code, expected_ref, field in (
        (
            pillar_support[0],
            "dataset",
            "dataset_certificate_not_verified",
            manifest.get("dataset_commitment_ref"),
            "pillar_support.dataset",
        ),
        (
            pillar_support[1],
            "evaluator",
            "evaluator_certificate_not_verified",
            manifest.get("evaluator_commitment_ref"),
            "pillar_support.evaluator",
        ),
    ):
        if not isinstance(entry, Mapping):
            _fail("PILLAR_SUPPORT_SHAPE", field)
        if (
            entry.get("support_subject") != subject
            or entry.get("status") not in emittable_statuses
            or entry.get("condition_code") != condition_code
            or entry.get("bound_commitment_ref") != expected_ref
        ):
            _fail("PILLAR_SUPPORT_SHAPE", field)
        if entry.get("status") == "condition_declared_unverified" and (
            "bound_manifest_digest" in entry
            or "evidence_ref" in entry
            or "trust_anchor_ref" in entry
        ):
            _fail("PILLAR_SUPPORT_SHAPE", field)

    assertion = bundle["assertion"]
    recomputed_assertion_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["assertion"],
        _strip_self_digest(assertion, "assertion_digest"),
    )
    if recomputed_assertion_digest != assertion.get(
        "assertion_digest"
    ) or recomputed_assertion_digest != manifest.get("assertion_digest"):
        _fail("ASSERTION_DIGEST_MISMATCH", "assertion")
    expected_rendered_text = _schema_definition("AgentQualityAssertionV1")["properties"][
        "rendered_text"
    ]["const"]
    if assertion.get("rendered_text") != expected_rendered_text:
        _fail("ASSERTION_DIGEST_MISMATCH", "assertion")


@_owns(
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
)
def _stage_s8_manifest_digests_signature(
    bundle: Mapping[str, Any],
    context: AgentQualityVerificationContext,
    process_record_bundle: Mapping[str, Any],
) -> None:
    """S8 -- manifest-bound artifact digests and the issuer signature
    (design rows 57-67).

    Owns: SPLIT_DERIVATION_DIGEST_MISMATCH, EVALUATION_SPLITS_DIGEST_MISMATCH,
    MEASURED_CLAIMS_DIGEST_MISMATCH, SELECTION_ESTIMATES_DIGEST_MISMATCH,
    NON_CLAIMS_DIGEST_MISMATCH, CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH,
    CLAIM_SUPPORT_ROW_MISMATCH, UNSIGNED_MANIFEST_MISMATCH,
    UNSIGNED_MANIFEST_DIGEST_MISMATCH, KEY_RING_MISMATCH,
    ISSUER_SIGNATURE_INVALID.

    In order: (rows 57-62) each of the six signed arrays/projections' own
    manifest digest is recomputed under its own
    :data:`_AGENT_QUALITY_DIGEST_DOMAINS` role and compared -- one dedicated
    code per array, so a single mismatched field cannot hide behind five
    others that still match; (row 63) the single claim-support row's digest
    bindings are internally consistent with its own ``evidence_basis``: an
    ``issuer_verified`` row's five digest fields and ``verifier_result``
    must equal the values this stage independently recomputed, an
    ``abstained`` row must carry none of them; (row 64) every manifest field
    this stage can reconstruct from the bundle and the supplied
    ``process_record_bundle`` ALONE -- ``coverage`` (the schema's own fixed
    tuple), ``base_process_record_unsigned_manifest_digest``,
    ``declared_plan_digest``, ``declared_plan_signature_digest``,
    ``primary_objective_id``, ``selection_arm_count``,
    ``holdout_scored_arm_count`` -- equals the manifest's own value; fields
    that need a caller-supplied pin to reconstruct (the scope-binding
    digest, the four commitment refs, the measurement-contract ref/digest,
    the registry identities, ``pillar_support``, and ``assertion_digest``,
    which S7 owns) are reconstructed in S2/S3/S7 instead, never here; (row
    65) the manifest's own digest matches ``signature.unsigned_manifest_digest``;
    (row 66) the signature's issuer_key_ref/trust_ring_ref agree with the
    manifest's, the manifest's agree with ``process_record_bundle``'s own
    verified issuer materials (``verification_materials_v0.issuer``), and
    that projection's key material parses -- ALL key-resolution failures,
    never a forged-signature finding, mirroring
    ``process_record_verifier``'s own KEY_RING_MISMATCH/ISSUER_SIGNATURE_INVALID
    split for exactly this reason; (row 67) the issuer signature itself
    verifies against the reconstructed manifest under that resolved key.
    """
    manifest = bundle["unsigned_manifest"]
    signature = bundle["signature"]

    # P1-V2.2 review P2-1 closure: guard the row-64 read of
    # ``process_record_bundle["unsigned_manifest"]`` the same way row 66's
    # read of ``verification_materials_v0`` is already guarded below -- a
    # ``None``/``{}`` process_record_bundle must fail closed with an owned
    # code, never escape as a raw TypeError/KeyError. Today the runner masks
    # this because S2 (packet .3) refuses first on the same malformed
    # bundle, but S8 must not depend on that ordering to stay fail-closed
    # when called directly, as every stage in this module must be.
    if not isinstance(process_record_bundle, Mapping) or "unsigned_manifest" not in (
        process_record_bundle
    ):
        _fail("UNSIGNED_MANIFEST_MISMATCH", "unsigned_manifest")

    # Rows 57-62: one literal `_fail(...)` per signed array/projection --
    # deliberately NOT a data-driven loop over a (code, ...) table, so every
    # emission site here stays a string-literal `_fail` call that
    # test_emission_audit_scans_only_literal_codes and
    # test_stage_only_emits_codes_it_owns can verify statically.
    split_derivation_projection = _strip_self_digest(
        bundle["split_derivation"], "split_derivation_digest"
    )
    if manifest.get("split_derivation_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["split_derivation"], split_derivation_projection
    ):
        _fail("SPLIT_DERIVATION_DIGEST_MISMATCH", "unsigned_manifest")
    if manifest.get("evaluation_splits_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["evaluation_splits"], bundle["evaluation_splits"]
    ):
        _fail("EVALUATION_SPLITS_DIGEST_MISMATCH", "unsigned_manifest")
    if manifest.get("measured_claims_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["measured_claims"], bundle["measured_claims"]
    ):
        _fail("MEASURED_CLAIMS_DIGEST_MISMATCH", "unsigned_manifest")
    if manifest.get("non_certified_selection_estimates_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["selection_estimates"],
        bundle["non_certified_selection_estimates"],
    ):
        _fail("SELECTION_ESTIMATES_DIGEST_MISMATCH", "unsigned_manifest")
    if manifest.get("non_claims_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["non_claims"], bundle["non_claims"]
    ):
        _fail("NON_CLAIMS_DIGEST_MISMATCH", "unsigned_manifest")
    if manifest.get("agent_quality_claim_support_rows_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["claim_support_rows"], bundle["claim_support_rows"]
    ):
        _fail("CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH", "unsigned_manifest")

    assertion = bundle["assertion"]
    assertion_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["assertion"],
        _strip_self_digest(assertion, "assertion_digest"),
    )
    claim_material = {
        "claim_id": assertion["claim_id"],
        "tier": 3,
        "assertion_template_id": assertion["assertion_template_id"],
        "rendered_text": assertion["rendered_text"],
        "assertion_digest": assertion_digest,
    }
    claim_material_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["claim_material"], claim_material
    )
    declared_plan = bundle["declared_plan_envelope"]["declared_plan"]
    row = bundle["claim_support_rows"][0]
    if row.get("evidence_basis") == "issuer_verified":
        if (
            row.get("assertion_digest") != assertion_digest
            or row.get("measured_claims_digest") != manifest.get("measured_claims_digest")
            or row.get("evaluation_splits_digest") != manifest.get("evaluation_splits_digest")
            or row.get("declared_plan_digest") != declared_plan.get("declared_plan_digest")
            or row.get("claim_material_digest") != claim_material_digest
            or row.get("verifier_result") != "pass"
        ):
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", "claim_support_rows")
    elif row.get("evidence_basis") == "abstained":
        if any(
            key in row
            for key in (
                "assertion_digest",
                "measured_claims_digest",
                "evaluation_splits_digest",
                "declared_plan_digest",
                "verifier_result",
                "claim_material_digest",
            )
        ):
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", "claim_support_rows")
    else:
        _fail("CLAIM_SUPPORT_ROW_MISMATCH", "claim_support_rows")

    process_record_digest = _role_digest(
        _PROCESS_RECORD_UNSIGNED_MANIFEST_DOMAIN, process_record_bundle["unsigned_manifest"]
    )
    expected_coverage = tuple(
        _schema_definition("AgentQualityUnsignedManifestV1")["properties"]["coverage"]["const"]
    )
    expected_declared_plan_signature_digest = _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["declared_plan_signature"],
        bundle["declared_plan_envelope"]["signature"],
    )
    if (
        tuple(manifest.get("coverage", ())) != expected_coverage
        or manifest.get("base_process_record_unsigned_manifest_digest") != process_record_digest
        or manifest.get("declared_plan_digest") != declared_plan.get("declared_plan_digest")
        or manifest.get("declared_plan_signature_digest") != expected_declared_plan_signature_digest
        or manifest.get("primary_objective_id") != declared_plan.get("primary_objective_id")
        or manifest.get("selection_arm_count") != declared_plan.get("selection_arm_count")
        or manifest.get("holdout_scored_arm_count") != declared_plan.get("holdout_scored_arm_count")
    ):
        _fail("UNSIGNED_MANIFEST_MISMATCH", "unsigned_manifest")

    if signature.get("unsigned_manifest_digest") != _role_digest(
        _AGENT_QUALITY_DIGEST_DOMAINS["unsigned_manifest"], manifest
    ):
        _fail("UNSIGNED_MANIFEST_DIGEST_MISMATCH", "signature")

    if signature.get("issuer_key_ref") != manifest.get("issuer_key_ref") or signature.get(
        "trust_ring_ref"
    ) != manifest.get("trust_ring_ref"):
        _fail("KEY_RING_MISMATCH", "signature")

    try:
        v0_issuer = process_record_bundle["verification_materials_v0"]["issuer"]
    except Exception:
        _fail("KEY_RING_MISMATCH", "signature")
    if not isinstance(v0_issuer, Mapping):
        _fail("KEY_RING_MISMATCH", "signature")
    if (
        manifest.get("issuer_key_ref") != v0_issuer.get("key_ref")
        or manifest.get("trust_ring_ref") != v0_issuer.get("trust_ring_ref")
        or manifest.get("issuer_signature_algorithm") != v0_issuer.get("algorithm")
        or signature.get("algorithm") != v0_issuer.get("algorithm")
    ):
        _fail("KEY_RING_MISMATCH", "signature")
    try:
        issuer_public_key = _material_public_key(dict(v0_issuer), _ISSUER_SPKI_DOMAIN)
    except Exception:
        # Malformed/unparseable issuer key material is a key-resolution
        # failure, not a forged-signature finding -- keep it distinguishable
        # from ISSUER_SIGNATURE_INVALID (design row 66's own disposition).
        _fail("KEY_RING_MISMATCH", "signature")

    # fp2.canonicalize(manifest) cannot fail here: S1 already canonicalized
    # this same bundle, of which `manifest` is a member, before this stage
    # ever runs (see :func:`_stage_s1_structural`).
    canonical_manifest = cast(str, fp2.canonicalize(manifest)).encode("utf-8")
    material = (
        _AGENT_QUALITY_DIGEST_DOMAINS["issuer_signature"].encode("utf-8")
        + b"\x00"
        + canonical_manifest
    )
    try:
        _verify_signature(
            issuer_public_key, signature.get("algorithm"), material, signature.get("signature")
        )
    except Exception:
        _fail("ISSUER_SIGNATURE_INVALID", "signature")


def _run_agent_quality_checks(
    bundle: Mapping[str, Any],
    *,
    context: AgentQualityVerificationContext,
    process_record_bundle: Mapping[str, Any],
    split_opening: object | None = None,
) -> AgentQualityVerificationResult:
    """Run the eight private stages, in order, over ``bundle``.

    ``process_record_bundle`` is forwarded to S2, S4, and S8: S2 verifies it
    in full through the shipped public entry point
    (``verify_process_record_certificate``) before anything else in this
    packet's real stages runs (design Sec 3); S4 and S8 each resolve the
    issuer's key material from its verified ``verification_materials_v0``
    for their own signature checks. ``split_opening`` is accepted on this
    signature for forward compatibility only (P1-V2.0 review finding
    P3-11): v1 defines NO opening path and NO witness schema at all (see
    :data:`AGENT_QUALITY_INPUT_PREEMPTED_CODES`), so this function REFUSES
    outright -- with ``CONTEXT`` at the ``split_opening_witness`` field
    location, before any stage runs -- whenever a caller supplies one, the
    only accepted value being ``None``.

    Called by the public entry point, :func:`verify_agent_quality_certificate`
    (see ``test_public_entry_point_is_exactly_verify_agent_quality_certificate``
    in the test module). Every stage now runs real checks, so this function
    genuinely returns a
    :class:`AgentQualityVerificationResult` for a bundle that passes all
    eight -- built from what THIS function computed (the single support
    row's own ``evidence_basis``, which S7 already proved is either
    ``issuer_verified`` or an accepted ``abstained``), never copied from
    the bundle unexamined beyond that.

    Mirrors ``evaluator_quality_verifier``'s content-free catch-all: any
    exception escaping the stage sequence that is not already an
    :class:`AgentQualityVerificationError` -- including one raised while
    building the result below -- is caught and re-raised as
    ``AGENT_QUALITY_VERIFICATION_FAILED`` with no bundle content attached.
    The ONE exception to that catch-all is
    :class:`ProcessRecordVerificationError`: per the design, a failure
    verifying ``process_record_bundle`` itself must reach the caller as
    the process record's OWN code, not be relabeled into this module's
    vocabulary -- see :func:`_stage_s2_context_binding`.
    """
    if split_opening is not None:
        _fail("CONTEXT", "split_opening_witness")
    try:
        _stage_s1_structural(bundle, context)
        _stage_s2_context_binding(bundle, context, process_record_bundle)
        _stage_s3_registry_identity(bundle, context)
        _stage_s4_declared_plan_signatures(bundle, context, process_record_bundle)
        _stage_s5_objective_measurement(bundle, context)
        _stage_s6_splits_held_out(bundle, context)
        _stage_s7_composition_abstention(bundle, context)
        _stage_s8_manifest_digests_signature(bundle, context, process_record_bundle)

        manifest = bundle["unsigned_manifest"]
        row = bundle["claim_support_rows"][0]
        pillar_support = manifest["pillar_support"]
        dataset_condition_code = pillar_support[0]["condition_code"]
        evaluator_condition_code = pillar_support[1]["condition_code"]
        holdout_item_count = bundle["evaluation_splits"][1]["item_count"]

        if row.get("evidence_basis") == "issuer_verified":
            claim = bundle["measured_claims"][0]
            return AgentQualityVerificationResult(
                code="AGENT_QUALITY_VERIFIED",
                claim_id=row["claim_id"],
                evidence_basis="issuer_verified",
                primary_objective_id=manifest["primary_objective_id"],
                nominal_coverage_ppm=claim["nominal_coverage_ppm"],
                holdout_item_count=holdout_item_count,
                interval_verification_level="construction_recomputed_v1",
                split_verification_level="issuer_attested_v1",
                dataset_condition_code=dataset_condition_code,
                evaluator_condition_code=evaluator_condition_code,
            )
        # S7 already refused (CLAIM_NOT_VERIFIED) any non-issuer_verified
        # row the caller's context.accept_abstained_bundle does not permit,
        # so reaching here means an abstained row the caller explicitly
        # accepted. An abstained bundle asserts no measured claim, so no
        # recomputation ran and no certified nominal coverage exists to
        # report; 0 is a fixed sentinel for "not applicable", never a
        # value read from the bundle.
        #
        # P1-V2.5 review P3-10: primary_objective_id is read from the
        # MANIFEST here, the SAME source the verified branch above uses --
        # not from declared_plan, even though S8's row-64 check (and S5's
        # own OBJECTIVE_NOT_IN_DECLARED_PLAN binding) already forces
        # manifest["primary_objective_id"] == declared_plan["primary_objective_id"]
        # by the time either branch runs. A single source of truth for a
        # result field this module has already proven equal is simpler to
        # reason about than two branches quietly reading two different
        # (provably-equal) bundle locations.
        return AgentQualityVerificationResult(
            code="AGENT_QUALITY_CLAIM_ABSTAINED",
            claim_id=row["claim_id"],
            evidence_basis="abstained",
            primary_objective_id=manifest["primary_objective_id"],
            nominal_coverage_ppm=0,
            holdout_item_count=holdout_item_count,
            interval_verification_level="issuer_attested_v1",
            split_verification_level="issuer_attested_v1",
            dataset_condition_code=dataset_condition_code,
            evaluator_condition_code=evaluator_condition_code,
        )
    except AgentQualityVerificationError:
        raise
    except ProcessRecordVerificationError:
        raise
    except Exception:
        _fail("AGENT_QUALITY_VERIFICATION_FAILED", "bundle")


def verify_agent_quality_certificate(
    bundle: object,
    *,
    context: AgentQualityVerificationContext,
    process_record_bundle: object,
    split_opening: object | None = None,
) -> AgentQualityVerificationResult:
    """Verify an AgentQualityCertificateBundleV1 entirely offline (pillar 1).

    A ``VERIFIED`` result entitles a relying party to conclude: an issuer
    whose key is in the pinned trust ring signed a manifest binding THIS
    process record, THESE commitment refs and THIS scope binding built from
    the relying party's own pins; the interval endpoints are exactly
    recomputable from the declared sufficient statistics under
    ``exact_integer_rational_v1`` and the pinned quantile table; the claim
    was scored on the split the issuer labelled ``holdout``, and the split
    arithmetic is plausible.

    It does NOT establish that the sufficient statistics summarise the
    holdout observations; that the committed splits are the rule's partition
    (v1 ships no opening witness); that the declared plan was authored before
    the results were computed (ordering evidence is issuer-asserted); that
    the split key predates knowledge of the item ids; or that the estimator
    implementation is correct. It also does NOT establish that the dataset or
    evaluator this certificate depends on are themselves valid. This is the
    module docstring's canonical ceiling, repeated verbatim.

    ``process_record_bundle`` must verify in full through
    :func:`verify_process_record_certificate` before anything else runs; a
    failure there reaches the caller as the process record's OWN code
    (:class:`ProcessRecordVerificationError`), never relabeled into this
    module's vocabulary. ``split_opening`` accepts only ``None`` in v1 (see
    :data:`AGENT_QUALITY_INPUT_PREEMPTED_CODES`) -- forward-compatible
    signature room only, not a supported opening path.

    Raises :class:`AgentQualityVerificationError` on any failure, with a
    closed, content-free ``code``/``field`` pair. Any exception escaping the
    private eight-stage pipeline that is not already an
    :class:`AgentQualityVerificationError` or a
    :class:`ProcessRecordVerificationError` is caught and re-raised as
    ``AGENT_QUALITY_VERIFICATION_FAILED`` with no bundle content attached --
    the catch-all never leaks the original exception's text, type, or
    traceback into the raised error.
    """
    try:
        return _run_agent_quality_checks(
            cast(Mapping[str, Any], bundle),
            context=context,
            process_record_bundle=cast(Mapping[str, Any], process_record_bundle),
            split_opening=split_opening,
        )
    except AgentQualityVerificationError:
        raise
    except ProcessRecordVerificationError:
        raise
    except Exception:
        failure = AgentQualityVerificationError("AGENT_QUALITY_VERIFICATION_FAILED", "bundle")
        try:
            raise failure from None
        except AgentQualityVerificationError:
            # ``from None`` clears __cause__ and suppresses display, but while
            # still inside the ``except Exception`` block above the
            # interpreter has already linked the original exception as
            # __context__ -- and that object can carry caller content.
            # Clearing it here, once this handler has genuinely exited, is
            # what makes it disappear (mirrors
            # evaluator_quality_verifier.verify_evaluator_quality_certificate).
            failure.__context__ = None
            raise
