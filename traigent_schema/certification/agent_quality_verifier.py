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

This packet ships the module's private building blocks only: the closed
error and field-location vocabularies, the caller-facing context and result
shapes, the content-free package-data loading boundary for this pillar's
four registries (objective registry, aggregation policy, non-claim catalog,
quantile table), the role-digest helper, the exact-integer estimator
recomputation (Wilson score bounds and Student-t half-widths), and a private,
eight-stage bundle runner in which every stage is fail-closed by
construction -- each stage today ends in an unconditional refusal, so the
runner rejects every bundle it is given. It defines no public entry point:
``verify_agent_quality_certificate`` does not exist yet, because a verifier
that only half-checks a bundle and reports success is worse than one that
does not exist at all. It is deferred to the packet that finishes wiring the
real per-stage checks in place of today's unconditional refusals.
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
from typing import Any, NoReturn, TypeVar, cast

import traigent_schema.fp2 as fp2

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
AGENT_QUALITY_SCHEMA_PREEMPTED_CODES: frozenset[str] = frozenset(
    {
        "ABSTAINED_BUNDLE_CARRIES_CLAIMS",
        "SELECTION_ESTIMATE_IN_CERTIFIED_SET",
    }
)

# Codes that are reachable by design (not schema-preempted) but that no
# guard in this module raises yet. This packet's stage functions are all
# unconditional refusals, so every one of these is genuinely unraised today,
# not merely "not covered by a test" -- see
# test_agent_quality_verifier.py::test_pending_codes_are_not_yet_emitted.
# This set MUST shrink to empty by packet .6, as each later packet wires its
# stage's real checks and moves that stage's codes out of here.
AGENT_QUALITY_PENDING_CODES: frozenset[str] = frozenset(
    AGENT_QUALITY_ERROR_CODES
    - AGENT_QUALITY_SCHEMA_PREEMPTED_CODES
    - frozenset(
        {
            "CONTEXT",
            "PACKAGE_DATA_INVALID",
            "QUANTILE_TABLE_LOOKUP_FAILED",
            "AGENT_QUALITY_VERIFICATION_FAILED",
        }
    )
)

# Which of the eight private stages owns each non-preempted code, i.e. which
# stage's real (future) guard is the one that would raise it. Ownership is a
# DESIGN mapping, re-checked against the shipped schema's field names, not a
# claim about today's call sites -- every stage in this packet raises only
# the catch-all. CONTEXT, PACKAGE_DATA_INVALID and QUANTILE_TABLE_LOOKUP_FAILED
# are raised outside the eight-stage runner (by
# AgentQualityVerificationContext.__post_init__ and the package-data loading
# boundary respectively) but are assigned here to the stage whose design
# concern they belong to, so the coverage test below has one owner for every
# non-preempted code.
_STAGE_CODES: dict[str, frozenset[str]] = {
    "_stage_s1_structural": frozenset(
        {
            "BUNDLE_SHAPE",
            "STRICT_INTEGER",
            "UNSAFE_INTEGER",
            "SCHEMA",
            "SCHEMA_DEPENDENCY",
            "CANONICALIZATION",
            "AGENT_QUALITY_VERIFICATION_FAILED",
        }
    ),
    "_stage_s2_context_binding": frozenset(
        {
            "CONTEXT",
            "PROCESS_RECORD_BINDING_MISMATCH",
            "COMMITMENT_REF_MISMATCH",
            "SCOPE_MISMATCH",
            "MEASUREMENT_CONTRACT_NOT_PINNED",
            "MEASUREMENT_CONTRACT_MISMATCH",
        }
    ),
    "_stage_s3_registry_identity": frozenset(
        {
            "PACKAGE_DATA_INVALID",
            "AGGREGATION_POLICY_MISMATCH",
            "OBJECTIVE_REGISTRY_MISMATCH",
            "NON_CLAIM_SET_MISMATCH",
            "QUANTILE_TABLE_MISMATCH",
        }
    ),
    "_stage_s4_declared_plan_signatures": frozenset(
        {
            "DECLARED_PLAN_DIGEST_MISMATCH",
            "DECLARED_PLAN_SIGNATURE_INVALID",
            "DECLARED_PLAN_SIGNATURE_DIGEST_MISMATCH",
            "DECLARED_PLAN_PIN_MISMATCH",
        }
    ),
    "_stage_s5_objective_measurement": frozenset(
        {
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
        }
    ),
    "_stage_s6_splits_held_out": frozenset(
        {
            "SELECTION_ESTIMATE_DUPLICATE",
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
        }
    ),
    "_stage_s7_composition_abstention": frozenset(
        {
            "CLAIM_NOT_VERIFIED",
            "PILLAR_SUPPORT_SHAPE",
            "PILLAR_BINDING_MISMATCH",
            "ASSERTION_DIGEST_MISMATCH",
        }
    ),
    "_stage_s8_manifest_digests_signature": frozenset(
        {
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
        }
    ),
}

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


# Dead-helper inventory. Each of these top-level private functions has ZERO
# in-module call sites as of this packet -- verified by
# test_agent_quality_verifier.py::test_unwired_helpers_inventory_is_exact,
# which computes the set by AST rather than trusting this comment to stay
# accurate. Listed here, with the packet expected to wire each one, so an
# unwired helper reads as "not yet reached" rather than "forgotten":
#   _strip_self_digest  -- wired in .2/.3 (scope-binding and declared-plan/
#                           manifest digest recomputation strip their own
#                           digest member from the preimage)
#   _wilson_point        -- wired in .4 (S5's point-estimate recomputation)
#   _student_t_half_width -- wired in .4 (S5's interval recomputation)
#   _wilson_bounds        -- wired in .4 (S5's interval recomputation)
#   _unique_by            -- wired in .4 (S5's one-claim-per-objective guard)
#                             and in the deferred selection-estimate
#                             de-duplication (SELECTION_ESTIMATE_DUPLICATE)
# _run_agent_quality_checks itself is ALSO unwired in-module (no public entry
# point calls it yet) -- wired in .6, when verify_agent_quality_certificate
# ships and calls it.


def _stage_s1_structural(bundle: Mapping[str, Any]) -> None:
    """S1 -- structural well-formedness (design rows 2-7, 10b).

    Owns: BUNDLE_SHAPE, STRICT_INTEGER, UNSAFE_INTEGER, SCHEMA,
    SCHEMA_DEPENDENCY, CANONICALIZATION.

    This packet ships no real check: the stage unconditionally refuses, so
    that the runner rejects every bundle today rather than half-verifying
    one. The complete-check-sequence packet replaces this body with the
    bundle-type check, the pre-canonicalization strict/safe-integer walk,
    schema validation, $ref-resolution, and the ``fp2.canonicalize`` tail.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "bundle")


def _stage_s2_context_binding(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> None:
    """S2 -- context and scope binding (design rows 1, 8-12).

    Owns: CONTEXT (raised outside this stage, by
    ``AgentQualityVerificationContext.__post_init__``),
    PROCESS_RECORD_BINDING_MISMATCH, COMMITMENT_REF_MISMATCH, SCOPE_MISMATCH,
    MEASUREMENT_CONTRACT_NOT_PINNED, MEASUREMENT_CONTRACT_MISMATCH.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "scope_binding")


def _stage_s3_registry_identity(bundle: Mapping[str, Any]) -> None:
    """S3 -- the four shipped registries' identity (design rows 13-16).

    Owns: PACKAGE_DATA_INVALID (raised outside this stage, by
    :func:`_load_agent_quality_document`), AGGREGATION_POLICY_MISMATCH,
    OBJECTIVE_REGISTRY_MISMATCH, NON_CLAIM_SET_MISMATCH,
    QUANTILE_TABLE_MISMATCH.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "objective_registry")


def _stage_s4_declared_plan_signatures(bundle: Mapping[str, Any]) -> None:
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

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "declared_plan")


def _stage_s5_objective_measurement(bundle: Mapping[str, Any]) -> None:
    """S5 -- objective registration and interval recomputation (design rows
    22-27, 29-39).

    Owns: QUANTILE_TABLE_LOOKUP_FAILED (raised outside this stage, by
    :func:`_lookup_t_scaled`), OBJECTIVE_DUPLICATE,
    OBJECTIVE_NOT_IN_DECLARED_PLAN, PRIMARY_OBJECTIVE_MISSING,
    OBJECTIVE_NOT_REGISTERED, OBJECTIVE_KIND_MISMATCH, OBJECTIVE_UNIT_MISMATCH,
    OBJECTIVE_MINIMUM_SAMPLE_NOT_MET, DISTRIBUTION_ASSUMPTION_NOT_REGISTERED,
    INTERVAL_METHOD_NOT_EMITTABLE, INTERVAL_METHOD_NOT_ADMISSIBLE,
    SUFFICIENT_STATISTICS_SHAPE, POINT_ESTIMATE_RECOMPUTATION_MISMATCH,
    INTERVAL_RECOMPUTATION_MISMATCH, INTERVAL_ORDER, INTERVAL_DEGENERATE,
    INTERVAL_OUT_OF_UNIT_BOUNDS, NOMINAL_COVERAGE_MISMATCH,
    SAMPLE_SIZE_MISMATCH, VERIFICATION_LEVEL_MISMATCH.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "measured_claims.objective")


def _stage_s6_splits_held_out(bundle: Mapping[str, Any]) -> None:
    """S6 -- evaluation splits and holdout usage (design rows 40-51, minus
    the schema-preempted SELECTION_ESTIMATE_IN_CERTIFIED_SET).

    Owns: SELECTION_ESTIMATE_DUPLICATE (design row's own vocabulary; the
    guard is deferred, see :data:`AGENT_QUALITY_PENDING_CODES`),
    SPLIT_SET_SHAPE, HOLDOUT_NOT_USED, HOLDOUT_MISSING, HOLDOUT_TOO_SMALL,
    SPLIT_DERIVATION_MISMATCH, SPLIT_PARTITION_INCOMPLETE,
    SPLIT_COMMITMENT_COLLISION, SPLIT_SIZE_IMPLAUSIBLE, SPLIT_OPENING_MISMATCH,
    SPLIT_OPENING_RULE_VIOLATION, HOLDOUT_REUSED, ARM_COUNT_MISMATCH.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "evaluation_splits")


def _stage_s7_composition_abstention(bundle: Mapping[str, Any]) -> None:
    """S7 -- claim-support composition and abstention (design rows 52-56,
    minus the schema-preempted ABSTAINED_BUNDLE_CARRIES_CLAIMS and
    SELECTION_ESTIMATE_IN_CERTIFIED_SET).

    Owns: CLAIM_NOT_VERIFIED, PILLAR_SUPPORT_SHAPE, PILLAR_BINDING_MISMATCH,
    ASSERTION_DIGEST_MISMATCH.

    ABSTAINED_BUNDLE_CARRIES_CLAIMS (design row 52) is NOT carried into this
    stage's owned set: ``AgentQualityCertificateBundleV1``'s own ``allOf``
    if/then/else abstention coupling already forces ``measured_claims`` and
    ``non_certified_selection_estimates`` to ``maxItems 0`` on a non-
    ``issuer_verified`` support row, so no schema-valid bundle can ever reach
    this condition -- see AGENT_QUALITY_SCHEMA_PREEMPTED_CODES.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "claim_support_rows")


def _stage_s8_manifest_digests_signature(bundle: Mapping[str, Any]) -> None:
    """S8 -- manifest-bound artifact digests and the issuer signature
    (design rows 57-67).

    Owns: SPLIT_DERIVATION_DIGEST_MISMATCH, EVALUATION_SPLITS_DIGEST_MISMATCH,
    MEASURED_CLAIMS_DIGEST_MISMATCH, SELECTION_ESTIMATES_DIGEST_MISMATCH,
    NON_CLAIMS_DIGEST_MISMATCH, CLAIM_SUPPORT_ROWS_DIGEST_MISMATCH,
    CLAIM_SUPPORT_ROW_MISMATCH, UNSIGNED_MANIFEST_MISMATCH,
    UNSIGNED_MANIFEST_DIGEST_MISMATCH, KEY_RING_MISMATCH,
    ISSUER_SIGNATURE_INVALID.

    Unconditional refusal in this packet -- see :func:`_stage_s1_structural`.
    """
    _fail("AGENT_QUALITY_VERIFICATION_FAILED", "unsigned_manifest")


def _run_agent_quality_checks(
    bundle: Mapping[str, Any], context: AgentQualityVerificationContext
) -> AgentQualityVerificationResult:
    """Run the eight private stages, in order, over ``bundle``.

    No public entry point calls this yet (see the module docstring and
    ``test_no_public_entry_point_exists_yet``). Every stage in this packet is
    an unconditional refusal, so this function currently rejects every
    bundle it is given, and never returns a
    :class:`AgentQualityVerificationResult` in practice -- the return type is
    the one the complete check sequence will actually produce once each
    stage's real checks replace today's placeholders.

    Mirrors ``evaluator_quality_verifier``'s content-free catch-all: any
    exception escaping the stage sequence that is not already an
    :class:`AgentQualityVerificationError` -- including one raised by a
    stage's own placeholder body -- is caught and re-raised as
    ``AGENT_QUALITY_VERIFICATION_FAILED`` with no bundle content attached.
    """
    try:
        _stage_s1_structural(bundle)
        _stage_s2_context_binding(bundle, context)
        _stage_s3_registry_identity(bundle)
        _stage_s4_declared_plan_signatures(bundle)
        _stage_s5_objective_measurement(bundle)
        _stage_s6_splits_held_out(bundle)
        _stage_s7_composition_abstention(bundle)
        _stage_s8_manifest_digests_signature(bundle)
    except AgentQualityVerificationError:
        raise
    except Exception:
        _fail("AGENT_QUALITY_VERIFICATION_FAILED", "bundle")
    # Unreachable while every stage above is an unconditional refusal.
    raise AssertionError("unreachable: every stage above always raises")
