# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline relying-party verifier for Dataset Record v1 (pillar 2).

This module answers exactly one question for a supplied certificate bundle and
explicit relying-party context: for the identified build, does the declared
evaluation-dataset item set, its declared composition, its declared leakage
posture, its declared limitations, and its declared efficiency figures each
carry the evidence the record claims for them -- and does the whole record
bind, by digest, to the already-verified Process Record V1 bundle for the
same build.

``dataset_record_v1`` is a separate contract family: it does not add
identifiers or templates to the frozen Agent Certificate v0 vocabulary and it
modifies neither v0 nor Process Record V1. Direction of binding is
dataset-record to process-record, never the reverse -- the process record is
the only join key across the four pillars, so it is verified first, as a
SEPARATE verification input, never embedded in this bundle.

Only public certificate material is consumed. The caller supplies the
already-trusted process-record verification context, the four caller pins
this verification is FOR (project/build scope, the per-build dataset
commitment, the optional cross-build identity pin, and the leakage scope),
and, optionally, a fifth verification input: per-corpus leaf-commitment
lists a relying party holds locally. No Backend imports, callbacks, network
access, database access, or private-key signing are involved.

Leaf lists are supplied as ``leaf_lists: Mapping[str, Sequence[Mapping]]``,
keyed by the record's derived ``corpus_ref`` for a leakage corpus and by its
derived ``dataset_ref`` for the committed item set. Each entry carries the
pre-computed, client-side, HMAC-derived opaque leaf token (D3) --
``{"leaf": "sha256:..."}`` for a corpus, and additionally its cleartext
``category_id`` / ``difficulty_stratum`` tag for the item set. Both shapes are
now FIRST-CLASS artifacts of the contract rather than an implementer's
convention: :func:`_check_leaf_list_input` projects each supplied list onto
``DatasetLeafListV1`` / ``DatasetItemSetLeafListV1`` and validates it against
that definition before any digest, cell root or intersection is computed, so a
free-text tag, a non-digest leaf, an out-of-taxonomy category or a duplicated
leaf is rejected as input shape (``LEAF_LIST_SHAPE``) instead of surfacing
later as a confusing digest mismatch (sol round 1 P1).

The category/stratum tag never crosses the wire; it exists only in this
out-of-band, caller-supplied local input, where it is what lets this verifier
bucket leaves by (category, stratum) and recompute a composition cell's root
(D5) -- a grouping the opaque wire tokens alone cannot support, since each
token is a one-way HMAC over a preimage that embeds those values. Offline
nothing can bind a tag to its leaf's preimage (this module holds no blind, by
design), so the tags are never TRUSTED, only CHECKED: the grouping they induce
must reproduce every declared cell's issuer-SIGNED ``cell_leaf_root`` and the
issuer-SIGNED ``item_set_root``. A mis-tagged or fabricated list therefore
fails; it cannot manufacture a pass. That asymmetry, not the tags' own
trustworthiness, is what DS2's ``issuer_verified`` upgrade rests on.
Composition-cell reconstruction reads only the item-set entry, since the
schema carries no field binding a leakage corpus to the committed item set.

Verification failures expose only stable, content-free error codes plus a
bounded field location built from this schema's own key names and integer
indexes -- never from an instance value. Dataset content -- item text,
reference answers, category assignments outside the closed taxonomy -- is
never representable in the wire bundle at all (the schema is closed and
content-free by construction); this module additionally never echoes any
instance value into an exception message or its result object.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import lru_cache
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any, NoReturn, cast

from jsonschema import Draft7Validator
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
    RelyingPartyVerificationError,
    _material_public_key,
    _verify_signature,
)
from traigent_schema.validator import _FORMAT_CHECKER

_SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "schemas"
_CERT_DIR = _SCHEMAS_DIR / "certification"
_DATASET_RECORD_SCHEMA_PATH = _CERT_DIR / "dataset_record_v1_schema.json"

_SHA256_PREFIX = "sha256:"
_SHA256_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_PROJECT_REF_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_REF_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,63}:[A-Za-z0-9_-]{8,128}$")
_DATASET_REF_RE = re.compile(r"^dsr:[A-Za-z0-9_-]{43}$")
_CORPUS_REF_RE = re.compile(r"^cpr:[A-Za-z0-9_-]{43}$")
_LEAKAGE_SCOPE_REF_RE = re.compile(r"^lsr:[A-Za-z0-9_-]{43}$")
_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$")
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()

# Every role-digest domain this module uses, and NOTHING ELSE: each constant
# below must appear in DatasetRecordDigestDomainRegistryV1, which
# test_every_verifier_digest_domain_is_registered mechanises in both
# directions. The first draft used claim_support_rows without registering it
# and argued the omission was harmless (sol round 1 P2); the harm is that the
# registry then documents a partial list, so a second implementer reading the
# schema alone cannot reproduce this module's preimages.
_ITEM_LEAF_DOMAIN = b"traigent.dataset_record.item_leaf.v1"
_ITEM_SET_ROOT_DOMAIN = b"traigent.dataset_record.item_set_root.v1"
_CELL_ROOT_DOMAIN = b"traigent.dataset_record.cell_root.v1"
_IDENTITY_ROOT_DOMAIN = b"traigent.dataset_record.identity_root.v1"
_TAXONOMY_DOMAIN = b"traigent.dataset_record.taxonomy.v1"
_METHOD_REGISTRY_DOMAIN = b"traigent.dataset_record.method_registry.v1"
_PREREG_DOMAIN = b"traigent.dataset_record.prereg.v1"
_PREREG_SIGNATURE_DOMAIN = b"traigent.dataset_record.prereg_signature.v1"
_COMPOSITION_DOMAIN = b"traigent.dataset_record.composition.v1"
_LEAKAGE_REPORT_DOMAIN = b"traigent.dataset_record.leakage_report.v1"
_LEAF_GENERATION_ATTESTATION_DOMAIN = b"traigent.dataset_record.leaf_generation_attestation.v1"
_EFFICIENCY_REPORT_DOMAIN = b"traigent.dataset_record.efficiency_report.v1"
_LIMITATIONS_DOMAIN = b"traigent.dataset_record.limitations.v1"
_UNSIGNED_MANIFEST_DOMAIN = b"traigent.dataset_record.unsigned_manifest.v1"
_ISSUER_SIGNATURE_DOMAIN = b"traigent.dataset_record.issuer_signature.v1"
_LEAF_LIST_DOMAIN = b"traigent.dataset_record.leaf_list.v1"
_DATASET_REF_DOMAIN = b"traigent.dataset_record.dataset_ref.v1"
_DATASET_REF_ITEM_SET_DOMAIN = b"traigent.dataset_record.dataset_ref_item_set.v1"
_CORPUS_REF_DOMAIN = b"traigent.dataset_record.corpus_ref.v1"
_LEAKAGE_SCOPE_REF_DOMAIN = b"traigent.dataset_record.leakage_scope_ref.v1"
_SCOPE_BINDING_DOMAIN = b"traigent.dataset_record.scope_binding.v1"
_CLAIM_SUPPORT_ROWS_DOMAIN = b"traigent.dataset_record.claim_support_rows.v1"

_MAX_LEAF_LIST = 65536
_MAX_CELLS = 40
_MAX_LEAKAGE_FINDINGS = 32

_CLAIM_IDS = ("DS1", "DS2", "DS3", "DS4", "DS5")

_NON_CLAIMS_CANONICAL = (
    ("DS_NC_NO_CONTENT", "tmpl.dsnoncert.no_content.v1"),
    ("DS_NC_EVALUATED_SET_NOT_BOUND", "tmpl.dsnoncert.evaluated_set_not_bound.v1"),
    ("DS_NC_NO_REPRESENTATIVENESS", "tmpl.dsnoncert.no_representativeness.v1"),
    ("DS_NC_NO_SAMPLING_FRAME", "tmpl.dsnoncert.no_sampling_frame.v1"),
    (
        "DS_NC_COMPOSITION_IS_DECLARED_NOT_MEASURED",
        "tmpl.dsnoncert.composition_is_declared_not_measured.v1",
    ),
    ("DS_NC_NO_LABEL_CORRECTNESS", "tmpl.dsnoncert.no_label_correctness.v1"),
    ("DS_NC_NO_ANNOTATION_QUALITY", "tmpl.dsnoncert.no_annotation_quality.v1"),
    (
        "DS_NC_TOKEN_DISJOINTNESS_NOT_ITEM_DISJOINTNESS",
        "tmpl.dsnoncert.token_disjointness_not_item_disjointness.v1",
    ),
    ("DS_NC_LEAF_GENERATION_ATTESTED", "tmpl.dsnoncert.leaf_generation_attested.v1"),
    ("DS_NC_NO_TRAINING_CORPUS_ACCESS", "tmpl.dsnoncert.no_training_corpus_access.v1"),
    ("DS_NC_NEAR_DUPLICATE_METHOD_BOUND", "tmpl.dsnoncert.near_duplicate_method_bound.v1"),
    (
        "DS_NC_INERTNESS_IS_CANDIDATE_RELATIVE",
        "tmpl.dsnoncert.inertness_is_candidate_relative.v1",
    ),
    ("DS_NC_DECISIVE_SUBSET_IS_UPPER_BOUND", "tmpl.dsnoncert.decisive_subset_is_upper_bound.v1"),
    (
        "DS_NC_ITEM_INFORMATION_MODEL_DEPENDENT",
        "tmpl.dsnoncert.item_information_model_dependent.v1",
    ),
    ("DS_NC_EFFICIENCY_NOT_RECOMPUTABLE", "tmpl.dsnoncert.efficiency_not_recomputable.v1"),
    ("DS_NC_NO_FUTURE_VALIDITY", "tmpl.dsnoncert.no_future_validity.v1"),
    ("DS_NC_PREREG_ORDER_ISSUER_ASSERTED", "tmpl.dsnoncert.prereg_order_issuer_asserted.v1"),
)

_PREREG_COVERAGE = (
    "evidence_grade",
    "candidate_set_commitment",
    "candidate_count",
    "selection_rule",
    "inertness_criterion",
    "elimination_order",
    "information_method",
    "information_unit",
    "information_floor",
    "near_duplicate_method",
    "near_duplicate_threshold_milli",
    "interval_method",
    "interval_level_ppm",
    "score_metric",
    "per_item_weighting",
    "per_category_weighting",
    "missing_outcome_policy",
    "tie_break",
    "bootstrap_unit",
    "bootstrap_resamples",
    "random_seed",
    "minimum_sample_size_n",
)

_UNSIGNED_MANIFEST_COVERAGE = (
    "process_unsigned_manifest_digest",
    "dataset_commitment_ref",
    "commitment_scheme",
    "scope_binding_digest",
    "identity",
    "taxonomy",
    "method_registry",
    "composition_digest",
    "leakage_report_digest",
    "leaf_generation_attestation_digest",
    "efficiency_report_digest",
    "limitations_digest",
    "prereg_digest",
    "prereg_signature_digest",
    "prereg_evidence_grade",
    "prereg_registered_at",
    "claim_support_rows_digest",
    "non_claims",
    "trust_ring_ref",
    "issuer_key_ref",
    "issuer_signature_algorithm",
)

_ORDERING_STEP_IDS = frozenset({"evaluate", "aggregate", "select", "finalize"})

_TIER_C_FINDING_KINDS = frozenset({"training_corpus_contamination", "prior_output_contamination"})
_TIER_A_B_FINDING_KINDS = frozenset(
    {"declared_corpus_overlap", "split_disjointness", "near_duplicate_overlap"}
)

_DERIVABLE_LIMITATION_CODES = frozenset({"small_stratum", "unbalanced_strata"})

_EVIDENCE_GRADES = (
    "digest_bound_attestation",
    "caller_pinned_before_results",
    "log_inclusion_proof",
)

# The nine aggregation-policy fields the signed plan fixes and the efficiency
# report must echo, in the order DatasetAppliedPolicyProjectionV1.coverage
# pins. Equality is enforced field by field against the plan.
_APPLIED_POLICY_FIELDS = (
    "score_metric",
    "per_item_weighting",
    "per_category_weighting",
    "missing_outcome_policy",
    "tie_break",
    "bootstrap_unit",
    "bootstrap_resamples",
    "random_seed",
    "minimum_sample_size_n",
)

# The two leakage-finding kinds whose verification IS the DS3 claim: DS3
# asserts that the supplied token lists for two corpora are disjoint, so the
# corpora those findings name are exactly the corpora DS3 depends on.
_DS3_RELEVANT_FINDING_KINDS = frozenset({"declared_corpus_overlap", "split_disjointness"})

# The single verifier_version every issuer_verified row must carry (sol
# round 2 P2). This module ships one fixed release of the five DSn verifiers
# it implements, so one pinned constant covers every claim -- the same
# "1.0.0" convention already used for taxonomy_version/registry_version in
# this contract (see dataset_record_v1_schema.json's TaxonomyIdentityV1 /
# MethodRegistryIdentityV1). A row is free to satisfy the schema's
# BoundedSemver pattern with any syntactically-valid string; only comparing
# it against this constant proves the row names the verifier that actually
# ran.
_VERIFIER_VERSION = "1.0.0"

# The exact per-claim support-row profile (sol round 1 P2). For every claim,
# the verifier fixes which verifier id (and version) may appear beside it and
# which artifact its single evidence ref must commit to -- the artifact THIS
# module actually recomputed for that claim. ``evidence_source`` names the
# manifest field (or, for DS1, the identity field) holding that digest.
_CLAIM_ROW_PROFILE: dict[str, dict[str, str]] = {
    "DS1": {
        "verifier_id": "ver.dataset.identity_v1",
        "verifier_version": _VERIFIER_VERSION,
        "evidence_kind": "client_commitment_digest",
        "evidence_source": "identity.dataset_identity_root",
    },
    "DS2": {
        "verifier_id": "ver.dataset.composition_v1",
        "verifier_version": _VERIFIER_VERSION,
        "evidence_kind": "verifier_report_digest",
        "evidence_source": "composition_digest",
    },
    "DS3": {
        "verifier_id": "ver.dataset.token_disjointness_v1",
        "verifier_version": _VERIFIER_VERSION,
        "evidence_kind": "verifier_report_digest",
        "evidence_source": "leakage_report_digest",
    },
    "DS4": {
        "verifier_id": "ver.dataset.near_duplicate_v1",
        "verifier_version": _VERIFIER_VERSION,
        "evidence_kind": "verifier_report_digest",
        "evidence_source": "leakage_report_digest",
    },
    "DS5": {
        "verifier_id": "ver.dataset.efficiency_v1",
        "verifier_version": _VERIFIER_VERSION,
        "evidence_kind": "verifier_report_digest",
        "evidence_source": "efficiency_report_digest",
    },
}

# The only abstention code this contract's abstentions can carry. The frozen
# v0 vocabulary has five; the other four describe conditions this family
# cannot reach (an unregistered claim id, a versionless verifier, a verifier
# that ran and did not pass, a prohibited-register violation), so admitting
# them here would let a row explain its abstention with a reason the verifier
# never established.
_ABSTENTION_CODE = "missing_evidence_binding"

# The only attestation basis a client_declared row may carry (the closed
# DatasetAttestationBasisV1 vocabulary is a single value today; naming it here
# keeps the row profile complete rather than implicitly schema-delegated).
_ATTESTATION_BASIS = "client_signed_declaration_v1"


class DatasetRecordVerificationError(ValueError):
    """A fixed-code verification failure that never includes certificate data."""

    def __init__(self, code: str, location: str = "") -> None:
        self.code = code
        self.location = location
        super().__init__(code)


class DatasetRecordRegistryError(RuntimeError):
    """A shipped registry document failed its own v1 schema definition.

    Mirrors :class:`traigent_schema.certification.process_record_verifier.
    ProcessRecordRegistryError` structurally -- a second implementation, not a
    shared import, since this is a separate contract family. Raised only at
    import time, and only from :func:`_load_registry_constant`. The message
    is the fixed definition name; document content and filesystem paths never
    reach it.
    """

    def __init__(self, definition_name: str) -> None:
        self.definition_name = definition_name
        super().__init__(f"DATASET_RECORD_REGISTRY_DOCUMENT_INVALID:{definition_name}")


def _fail(code: str, location: str = "") -> NoReturn:
    """Raise the fixed-code failure with a guaranteed-empty ``__context__``.

    ``_fail`` is called from inside ``except`` blocks (canonicalization,
    schema-dependency resolution, signature primitives), and a plain ``raise``
    there implicitly chains the in-flight exception onto ``__context__``.
    ``raise ... from None`` does NOT clear it -- it only sets
    ``__suppress_context__``, so the suppressed object, which may have been
    built from caller-supplied content, is still reachable on the escaping
    error (sol round 1 P2 on the catch-all; the same defect class applies to
    every ``_fail`` reachable from a handler). Constructing the error, raising
    it under ``from None``, then clearing ``__context__`` and re-raising the
    same object is the discipline ``_load_registry_constant`` already uses:
    the bare ``raise`` re-raises the exception currently being handled, and
    Python never chains an exception onto itself, so ``__context__`` stays
    ``None``.
    """
    failure = DatasetRecordVerificationError(code, location)
    try:
        raise failure from None
    except DatasetRecordVerificationError:
        failure.__context__ = None
        raise


# Public, closed, content-free failure vocabulary. DatasetRecordVerificationError
# never raises a code outside this set. Deliberately disjoint from
# DatasetRecordErrorV1.code -- the wire enum stays coarser than this internal
# vocabulary, exactly as ProcessRecordErrorV1 is coarser than
# PROCESS_RECORD_ERROR_CODES (test_wire_error_enum_is_coarser_than_the_verifier_
# error_vocabulary).
DATASET_RECORD_ERROR_CODES = frozenset(
    {
        # Shape
        "CONTEXT",
        "BUNDLE_SHAPE",
        "SCHEMA",
        "SCHEMA_DEPENDENCY",
        "STRICT_INTEGER",
        "CANONICALIZATION",
        "VERIFICATION_FAILED",
        "LEAF_LIST_SHAPE",
        # Binding
        "PROCESS_RECORD_INVALID",
        "SCOPE_BINDING_MISMATCH",
        "PROCESS_MANIFEST_DIGEST_MISMATCH",
        "DATASET_COMMITMENT_REF_MISMATCH",
        "DATASET_IDENTITY_MISMATCH",
        "IDENTITY_EPOCH_INCONSISTENT",
        "REF_NOT_DERIVED",
        "KEY_RING_MISMATCH",
        "UNSIGNED_MANIFEST_DIGEST_MISMATCH",
        "ISSUER_SIGNATURE_INVALID",
        # Registry
        "TAXONOMY_DIGEST_MISMATCH",
        "METHOD_REGISTRY_DIGEST_MISMATCH",
        "TAXONOMY_TERM_UNREGISTERED",
        # Composition
        "COMPOSITION_DIGEST_MISMATCH",
        "STRATUM_PARTITION_MISMATCH",
        "COMPOSITION_CELL_ROOT_MISMATCH",
        "COMPOSITION_CELL_COUNT_MISMATCH",
        # Leakage
        "LEAKAGE_REPORT_DIGEST_MISMATCH",
        "LEAKAGE_BASIS_COUPLING",
        "LEAKAGE_SCOPE_MISMATCH",
        "LEAF_LIST_DIGEST_MISMATCH",
        "LEAKAGE_OVERLAP_MISMATCH",
        "SPLIT_DISJOINTNESS_VIOLATION",
        "LEAF_GENERATION_ATTESTATION_MISSING",
        "LEAF_SCOPE_BLIND_MISMATCH",
        "LEAF_COMPLETENESS_MISMATCH",
        # Limitations
        "LIMITATIONS_DIGEST_MISMATCH",
        "LIMITATION_OMITTED",
        "LIMITATION_BASIS_COUPLING",
        # Pre-registration -- shared names with pillars 1 and 3
        "PREREGISTRATION_DIGEST_MISMATCH",
        "PREREGISTRATION_SIGNATURE_INVALID",
        "PREREGISTRATION_SCOPE_VIOLATION",
        "PREREGISTRATION_ORDER",
        "PREREGISTRATION_GRADE_MISMATCH",
        "PREREGISTRATION_GRADE_UNSUPPORTED",
        # Efficiency
        "EFFICIENCY_REPORT_DIGEST_MISMATCH",
        "INTERVAL_ORDER",
        "INTERVAL_METHOD_COUPLING",
        "INTERVAL_METHOD_QUANTITY_MISMATCH",
        "SAMPLE_SIZE_INSUFFICIENT",
        "INFORMATION_UNIT_RANGE",
        "INERT_FRACTION_MISMATCH",
        "DECISIVE_SUBSET_BOUND",
        "COST_EFFICIENCY_MISMATCH",
        "LATENCY_EFFICIENCY_MISMATCH",
        # Record
        "NON_CLAIMS_MISMATCH",
        "CLAIM_SUPPORT_ROW_MISMATCH",
        "CLAIM_NOT_VERIFIED",
    }
)


@dataclass(frozen=True, slots=True)
class DatasetRecordVerificationContext:
    """Fresh, caller-supplied bindings for one Dataset Record verification.

    ``process_context`` is the exact context :func:`verify_process_record_
    certificate` requires to verify the bound process-record bundle offline;
    this verifier calls it with ``trust_status=None``, so
    ``process_context.allow_unchecked_base_status`` MUST be ``True`` or the
    process-record verification itself fails closed (surfaced here as
    ``PROCESS_RECORD_INVALID``) -- this contract does not thread a trust-status
    snapshot through, matching the Python signature sketch it implements.

    ``expected_project_ref`` / ``expected_build_session_ref`` MUST equal
    ``process_context``'s own scope pins: the two contexts describe the same
    build, so a caller passing disagreeing scopes is a caller contradiction,
    not a verification finding, and fails ``CONTEXT``.

    ``expected_dataset_commitment_ref`` is the per-build scope pin and MUST
    equal ``process_context.expected_dataset_commitment_ref`` -- the same
    contradiction rule.

    ``expected_dataset_identity_root`` is the caller's cross-build identity
    pin; ``None`` means the caller does not hold or does not want to check
    one, so DS1 abstains rather than being asserted. ``expected_identity_
    blind_epoch`` is always required (defaulting semantics live at the
    dataclass call site, not here) but is only consulted when a root is
    pinned.

    ``expected_prereg_digest`` is the caller's own early-held pin of the
    signed plan's digest; supplying it is what lets a caller-declared
    ``caller_pinned_before_results`` evidence grade actually verify. ``None``
    means the grade can never rise above ``digest_bound_attestation``.

    ``require_leaf_lists`` states, before the caller sees the record, whether
    it will accept a bundle whose DS3 row abstains for want of leaf lists.
    """

    process_context: ProcessRecordVerificationContext
    expected_project_ref: str
    expected_build_session_ref: str
    expected_dataset_commitment_ref: str
    expected_dataset_identity_root: str | None
    expected_identity_blind_epoch: int
    expected_leakage_scope_ref: str
    expected_prereg_digest: str | None
    require_leaf_lists: bool

    def __post_init__(self) -> None:
        if not isinstance(self.process_context, ProcessRecordVerificationContext):
            _fail("CONTEXT")
        if type(self.expected_project_ref) is not str or not _PROJECT_REF_RE.fullmatch(
            self.expected_project_ref
        ):
            _fail("CONTEXT")
        if type(self.expected_build_session_ref) is not str or not _REF_RE.fullmatch(
            self.expected_build_session_ref
        ):
            _fail("CONTEXT")
        if self.expected_project_ref != self.process_context.expected_project_ref:
            _fail("CONTEXT")
        if self.expected_build_session_ref != self.process_context.expected_build_session_ref:
            _fail("CONTEXT")
        if type(self.expected_dataset_commitment_ref) is not str or not _SHA256_RE.fullmatch(
            self.expected_dataset_commitment_ref
        ):
            _fail("CONTEXT")
        # NOT required to equal process_context.expected_dataset_commitment_ref
        # here: row 8 is a runtime THREE-way comparison (the record's own
        # field, the bound process record's field, and this pin), so a caller
        # whose pin disagrees with an otherwise-internally-consistent record
        # and process record is a verification finding
        # (DATASET_COMMITMENT_REF_MISMATCH), not a construction-time
        # contradiction.
        if self.expected_dataset_identity_root is not None and (
            type(self.expected_dataset_identity_root) is not str
            or not _SHA256_RE.fullmatch(self.expected_dataset_identity_root)
        ):
            _fail("CONTEXT")
        if (
            type(self.expected_identity_blind_epoch) is not int
            or isinstance(self.expected_identity_blind_epoch, bool)
            or not 0 <= self.expected_identity_blind_epoch <= 65535
        ):
            _fail("CONTEXT")
        if type(self.expected_leakage_scope_ref) is not str or not _LEAKAGE_SCOPE_REF_RE.fullmatch(
            self.expected_leakage_scope_ref
        ):
            _fail("CONTEXT")
        if self.expected_prereg_digest is not None and (
            type(self.expected_prereg_digest) is not str
            or not _SHA256_RE.fullmatch(self.expected_prereg_digest)
        ):
            _fail("CONTEXT")
        if type(self.require_leaf_lists) is not bool:
            _fail("CONTEXT")


@dataclass(frozen=True, slots=True)
class DatasetRecordVerificationResult:
    """Bounded, content-free success result. See the module docstring for the
    evidence-vs-verification distinctions ``composition_evidence``,
    ``disjointness_evidence``, ``efficiency_evidence`` and ``prereg_evidence_
    grade`` exist to preserve -- a reader of this object alone must not be
    able to mistake "the record is signed and internally consistent" for
    "the verifier reproduced these numbers".
    """

    valid: bool = True
    code: str = "DATASET_RECORD_VERIFIED"
    dataset_commitment_ref: str = ""
    dataset_identity_root: str = ""
    identity_blind_epoch: int = 0
    item_set_root: str = ""
    item_count: int = 0
    populated_cell_count: int = 0
    composition_evidence: str = "declared_counts_only"
    disjointness_evidence: str = "token_lists_only"
    leakage_findings_checked: int = 0
    leakage_findings_attested: int = 0
    limitation_count: int = 0
    max_limitation_severity: int = 0
    inert_fraction_ppm: int = 0
    decisive_subset_upper_bound: int = 0
    cost_efficiency_ppm: int = 0
    claims_verified: tuple[str, ...] = ()
    claims_declared: tuple[str, ...] = ()
    claims_abstained: tuple[str, ...] = ()
    prereg_digest: str = ""
    prereg_evidence_grade: str = "digest_bound_attestation"
    efficiency_evidence: str = "backend_observed_not_recomputed"

    def __post_init__(self) -> None:
        if self.valid is not True:
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if self.code not in ("DATASET_RECORD_VERIFIED", "DATASET_RECORD_VERIFIED_CLAIMS_PARTIAL"):
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if self.composition_evidence not in ("declared_counts_only", "cell_roots_recomputed"):
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if self.disjointness_evidence not in ("token_lists_only", "generation_attested"):
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if self.efficiency_evidence != "backend_observed_not_recomputed":
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if self.prereg_evidence_grade not in _EVIDENCE_GRADES:
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        full = tuple(_CLAIM_IDS)
        if self.code == "DATASET_RECORD_VERIFIED":
            if (
                self.claims_verified != full
                or self.claims_declared != ()
                or self.claims_abstained != ()
            ):
                raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        else:
            if (
                self.claims_verified == full
                and self.claims_declared == ()
                and self.claims_abstained == ()
            ):
                raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")
        if sorted(self.claims_verified + self.claims_declared + self.claims_abstained) != sorted(
            full
        ):
            raise ValueError("DATASET_RECORD_VERIFICATION_RESULT")


@lru_cache(maxsize=1)
def _dataset_record_schema() -> tuple[Registry, dict[str, Any]]:
    schema_resources: list[tuple[str, Resource]] = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            schema_resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(schema_resources)
    schema = cast(
        dict[str, Any],
        json.loads(_DATASET_RECORD_SCHEMA_PATH.read_text(encoding="utf-8")),
    )
    return registry, schema


@lru_cache(maxsize=1)
def _dataset_record_validator() -> Draft7Validator:
    registry, schema = _dataset_record_schema()
    return Draft7Validator(schema, registry=registry, format_checker=_FORMAT_CHECKER)


@lru_cache(maxsize=8)
def _definition_validator(definition_name: str) -> Draft7Validator:
    registry, schema = _dataset_record_schema()
    document = {
        "$schema": schema["$schema"],
        "$id": f"{schema['$id']}#definition-{definition_name}",
        "definitions": schema["definitions"],
        "allOf": [{"$ref": f"#/definitions/{definition_name}"}],
    }
    return Draft7Validator(document, registry=registry, format_checker=_FORMAT_CHECKER)


def _role_digest(domain: bytes, projection: Any) -> str:
    # A second implementation of process_record_verifier._role_digest's
    # SHA-256(domain || 0x00 || jcs(x)) construction, not a shared import --
    # separate contract families, per D1.
    try:
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    return _SHA256_PREFIX + hashlib.sha256(domain + b"\x00" + canonical).hexdigest()


def _length_prefixed(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">Q", len(part)) + part for part in parts)


def _derive_ref(prefix: str, domain: bytes, *parts: bytes) -> str:
    digest = hashlib.sha256(domain + _length_prefixed(*parts)).digest()
    return prefix + ":" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _derive_dataset_ref(identity_root: str, epoch: int) -> str:
    return _derive_ref(
        "dsr", _DATASET_REF_DOMAIN, identity_root.encode("utf-8"), struct.pack(">Q", epoch)
    )


def _derive_dataset_ref_from_item_set(item_set_root: str) -> str:
    """The null-identity derivation (sol round 1 P1).

    ``dataset_ref`` is required by the schema whether or not the customer
    holds a long-lived identity blind, and the first draft derived it only
    from ``dataset_identity_root`` -- so a record with a null root carried a
    SUPPLIED ``dsr:`` value, i.e. precisely the free string channel
    ``DatasetRefV1`` exists to close. With a null root the ref is derived
    instead from ``item_set_root``, a non-label value already public in the
    manifest, under its OWN domain so the two derivations can never be
    interchanged.
    """
    return _derive_ref(
        "dsr", _DATASET_REF_ITEM_SET_DOMAIN, item_set_root.encode("utf-8")
    )


def _expected_dataset_ref(identity: dict[str, Any]) -> str:
    root = identity["dataset_identity_root"]
    if root is None:
        return _derive_dataset_ref_from_item_set(identity["item_set_root"])
    return _derive_dataset_ref(root, identity["identity_blind_epoch"])


def _derive_corpus_ref(corpus_leaf_root: str, leakage_scope_ref: str) -> str:
    return _derive_ref(
        "cpr",
        _CORPUS_REF_DOMAIN,
        corpus_leaf_root.encode("utf-8"),
        leakage_scope_ref.encode("utf-8"),
    )


def _derive_leakage_scope_ref(scope_blind_commitment: str) -> str:
    return _derive_ref("lsr", _LEAKAGE_SCOPE_REF_DOMAIN, scope_blind_commitment.encode("utf-8"))


def _leaf_list_digest(leaves: list[str]) -> str:
    return _role_digest(_LEAF_LIST_DOMAIN, sorted(leaves))


def _validate_registry_document(
    document: dict[str, Any],
    definition_name: str,
    digest_field: str,
    domain: bytes,
) -> None:
    if digest_field in document:
        raise DatasetRecordRegistryError(definition_name) from None
    candidate = {**document, digest_field: _role_digest(domain, document)}
    try:
        error_count = sum(1 for _ in _definition_validator(definition_name).iter_errors(candidate))
    except (OSError, UnicodeError, KeyError, json.JSONDecodeError, Unresolvable):
        raise DatasetRecordRegistryError(definition_name) from None
    if error_count:
        raise DatasetRecordRegistryError(definition_name) from None


def _load_registry_document(filename: str, root: Traversable | None = None) -> dict[str, Any]:
    package = resources.files("traigent_schema") if root is None else root
    text = (
        package.joinpath("data")
        .joinpath("certification")
        .joinpath(filename)
        .read_text(encoding="utf-8")
    )
    return cast(dict[str, Any], json.loads(text))


def _load_registry_constant(
    filename: str,
    definition_name: str,
    digest_field: str,
    domain: bytes,
    root: Traversable | None = None,
) -> tuple[dict[str, Any], str]:
    """Read, validate and digest one shipped registry document.

    Mirrors ``process_record_verifier._load_registry_constant`` structurally
    (a second implementation, see the module docstring for why); the same
    ``from None`` / re-clear-``__context__`` discipline applies so a failure
    here never carries document content, a filesystem path, or an in-flight
    caller exception into ``DatasetRecordRegistryError``.
    """
    loaded: tuple[dict[str, Any], str] | None
    try:
        document = _load_registry_document(filename, root)
        _validate_registry_document(document, definition_name, digest_field, domain)
        loaded = (document, _role_digest(domain, document))
    except Exception:
        loaded = None
    if loaded is None:
        failure = DatasetRecordRegistryError(definition_name)
        try:
            raise failure from None
        except DatasetRecordRegistryError:
            failure.__context__ = None
            raise
    return loaded


_TAXONOMY_DOCUMENT, _TAXONOMY_DIGEST = _load_registry_constant(
    "dataset_taxonomy_document.json",
    "DatasetTaxonomyDocumentV1",
    "taxonomy_digest",
    _TAXONOMY_DOMAIN,
)
_METHOD_REGISTRY_DOCUMENT, _METHOD_REGISTRY_DIGEST = _load_registry_constant(
    "dataset_method_registry_document.json",
    "DatasetMethodRegistryDocumentV1",
    "registry_digest",
    _METHOD_REGISTRY_DOMAIN,
)

_TAXONOMY_IDENTITY: dict[str, Any] = {
    "taxonomy_id": "traigent.dataset_taxonomy.asap.v1",
    "taxonomy_version": "1.0.0",
    "taxonomy_digest": _TAXONOMY_DIGEST,
}
_METHOD_REGISTRY_IDENTITY: dict[str, Any] = {
    "registry_id": "traigent.dataset_method_registry.asap.v1",
    "registry_version": "1.0.0",
    "registry_digest": _METHOD_REGISTRY_DIGEST,
}
_REGISTERED_CATEGORY_IDS = frozenset(_TAXONOMY_DOCUMENT["category_ids"])
_REGISTERED_STRATA = frozenset(_TAXONOMY_DOCUMENT["difficulty_strata"])
_MIN_STRATUM_SIZE = _TAXONOMY_DOCUMENT["min_stratum_size"]
_IMBALANCE_RATIO_LIMIT = _TAXONOMY_DOCUMENT["imbalance_ratio_limit"]
_REGISTERED_NEAR_DUPLICATE_METHODS = frozenset(_METHOD_REGISTRY_DOCUMENT["near_duplicate_methods"])


def _require_int(value: object, location: str = "") -> None:
    if type(value) is not int:
        _fail("STRICT_INTEGER", location)


def _walk_strict_integers(value: Any, location: str) -> None:
    """Reject a decoded float sitting where schema validation already
    guarantees an integer-or-integral-float value.

    Rather than name every field path by hand (the schema has dozens of
    integer fields across nested optional objects), this walks the
    already schema-valid bundle and rejects every Python ``float`` --
    draft-07's own ``type: integer`` check (as ``jsonschema`` implements
    it) already accepts an integral float such as ``30.0``, which is
    exactly the JCS-signable-vs-unsignable gap this contract cannot
    admit (mirrors the per-field ``_require_int`` calls in
    ``process_record_verifier``, generically, since this schema's integer
    surface is far larger than V1's five ``RegisteredValuesV1`` members).
    Booleans are NOT flagged here: ``jsonschema``'s ``is_integer`` already
    excludes ``bool`` for a ``type: integer`` field, so a bool sitting
    where an integer is required is already rejected by schema validation
    (``SCHEMA``, not ``STRICT_INTEGER``) before this walk ever runs --
    the same division of labour ``process_record_verifier`` documents
    (``test_bool_seq_is_rejected_by_schema_before_strict_integer_check``).
    A field that is genuinely boolean-typed in the schema (e.g.
    ``disjointness_asserted``) must never be flagged here regardless of
    order, which a bool-sensitive walk cannot distinguish from an
    integer-typed field without re-deriving the schema; not flagging
    bool at all is what keeps that distinction correct.
    """
    if type(value) is float:
        _fail("STRICT_INTEGER", location)
    if type(value) is dict:
        for key, item in value.items():
            _walk_strict_integers(item, f"{location}/{key}" if location else f"/{key}")
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _walk_strict_integers(item, f"{location}/{index}")
        return


def _check_strict_integers(bundle: dict[str, Any]) -> None:
    _walk_strict_integers(bundle, "")


def _validate_schema(bundle: dict[str, Any]) -> None:
    try:
        validator = _dataset_record_validator()
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail("SCHEMA_DEPENDENCY")
    try:
        errors = list(validator.iter_errors(bundle))
    except Unresolvable:
        _fail("SCHEMA_DEPENDENCY")
    if errors:
        _fail("SCHEMA")


def _verify_process_record(
    process_record_bundle: object, context: DatasetRecordVerificationContext
) -> tuple[Any, dict[str, Any]]:
    try:
        result = verify_process_record_certificate(
            process_record_bundle, context=context.process_context, trust_status=None
        )
    except ProcessRecordVerificationError:
        _fail("PROCESS_RECORD_INVALID")
    if type(process_record_bundle) is not dict:
        _fail("PROCESS_RECORD_INVALID")
    pr_unsigned = cast(dict[str, Any], process_record_bundle)["unsigned_manifest"]
    return result, pr_unsigned


def _check_scope_binding(
    unsigned: dict[str, Any],
    pr_unsigned: dict[str, Any],
    context: DatasetRecordVerificationContext,
) -> None:
    if (
        pr_unsigned.get("project_ref") != context.expected_project_ref
        or pr_unsigned.get("build_session_ref") != context.expected_build_session_ref
    ):
        _fail("SCOPE_BINDING_MISMATCH", "/unsigned_manifest/scope_binding_digest")
    projection = {
        "schema_version": "traigent.dataset_record.scope_binding.v1",
        "project_ref": context.expected_project_ref,
        "build_session_ref": context.expected_build_session_ref,
    }
    expected_digest = _role_digest(_SCOPE_BINDING_DOMAIN, projection)
    if unsigned["scope_binding_digest"] != expected_digest:
        _fail("SCOPE_BINDING_MISMATCH", "/unsigned_manifest/scope_binding_digest")


def _check_process_binding(unsigned: dict[str, Any], pr_result: Any) -> None:
    if unsigned["process_unsigned_manifest_digest"] != pr_result.unsigned_manifest_digest:
        _fail(
            "PROCESS_MANIFEST_DIGEST_MISMATCH",
            "/unsigned_manifest/process_unsigned_manifest_digest",
        )


def _check_dataset_commitment(
    unsigned: dict[str, Any], pr_result: Any, context: DatasetRecordVerificationContext
) -> None:
    ref = unsigned["dataset_commitment_ref"]
    if ref != pr_result.dataset_commitment_ref or ref != context.expected_dataset_commitment_ref:
        _fail("DATASET_COMMITMENT_REF_MISMATCH", "/unsigned_manifest/dataset_commitment_ref")


def _check_identity(identity: dict[str, Any], context: DatasetRecordVerificationContext) -> str:
    """Returns the DS1 evidence basis: ``issuer_verified`` or ``abstained``."""
    root = identity["dataset_identity_root"]
    epoch = identity["identity_blind_epoch"]
    if root is None:
        return "abstained"
    if context.expected_dataset_identity_root is None:
        return "abstained"
    root_matches = root == context.expected_dataset_identity_root
    epoch_matches = epoch == context.expected_identity_blind_epoch
    if root_matches and epoch_matches:
        return "issuer_verified"
    if root_matches != epoch_matches:
        _fail("IDENTITY_EPOCH_INCONSISTENT", "/unsigned_manifest/identity/identity_blind_epoch")
    _fail("DATASET_IDENTITY_MISMATCH", "/unsigned_manifest/identity/dataset_identity_root")


def _check_derived_dataset_ref(identity: dict[str, Any]) -> None:
    """Row 9a, checked FIRST and on its own.

    Derived under BOTH identity branches (sol round 1 P1): with a null
    ``dataset_identity_root`` the ref is derived from ``item_set_root`` under
    the ``dataset_ref_item_set`` domain, so no record can carry a supplied
    ``dsr:`` value. It is checked before the fifth input is read because the
    committed item set's leaf list is keyed BY this ref -- an underived ref
    would otherwise make a correct list look like a malformed corpus list,
    blaming the relying party's input for the record's defect.
    """
    if identity["dataset_ref"] != _expected_dataset_ref(identity):
        _fail("REF_NOT_DERIVED", "/unsigned_manifest/identity/dataset_ref")


def _check_derived_refs(
    unsigned: dict[str, Any],
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    attestation: dict[str, Any] | None,
) -> None:
    identity = unsigned["identity"]
    leakage_scope_ref = identity["leakage_scope_ref"]
    if attestation is not None:
        expected_scope = _derive_leakage_scope_ref(attestation["scope_blind_commitment"])
        if leakage_scope_ref != expected_scope:
            _fail("REF_NOT_DERIVED", "/unsigned_manifest/identity/leakage_scope_ref")
        for corpus in attestation["corpora"]:
            expected_corpus = _derive_corpus_ref(corpus["leaf_root"], leakage_scope_ref)
            if corpus["corpus_ref"] != expected_corpus:
                _fail("REF_NOT_DERIVED", "/leaf_generation_attestation/corpora")

    if leaf_lists:
        dataset_ref = identity["dataset_ref"]
        for corpus_ref, entries in leaf_lists.items():
            if corpus_ref == dataset_ref:
                # The reserved item-set key (see _check_cell_roots) is never
                # itself a corpus_ref and carries no derivation of its own.
                continue
            leaves = [entry["leaf"] for entry in entries]
            corpus_leaf_root = _leaf_list_digest(leaves)
            expected_corpus = _derive_corpus_ref(corpus_leaf_root, leakage_scope_ref)
            if corpus_ref != expected_corpus:
                _fail("REF_NOT_DERIVED", "/leakage_report/leaf_list_digests")


def _leaf_list_projection_error(definition_name: str, projection: dict[str, Any]) -> bool:
    """``True`` iff ``projection`` violates its definition.

    The error objects are consumed and discarded inside the generator
    expression: a jsonschema error carries ``instance``, so binding one to a
    local would put caller-supplied material in this frame. Nothing but the
    boolean survives.
    """
    try:
        validator = _definition_validator(definition_name)
    except (OSError, UnicodeError, json.JSONDecodeError, Unresolvable):
        _fail("SCHEMA_DEPENDENCY")
    try:
        return any(True for _ in validator.iter_errors(projection))
    except Unresolvable:
        _fail("SCHEMA_DEPENDENCY")


def _check_leaf_list_input(
    identity: dict[str, Any],
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]] | None,
) -> None:
    """Validate the fifth verification input against its own definitions.

    The fifth input is caller-supplied and unsigned, so before ANY digest,
    cell root or intersection is computed from it, each supplied list is
    projected onto its contract artifact -- ``DatasetItemSetLeafListV1`` for
    the reserved ``dataset_ref`` key, ``DatasetLeafListV1`` for every corpus
    key -- and validated against that definition (sol round 1 P1: the tags
    were previously neither schema-validated nor named in the contract).

    Failures raise the fixed, content-free ``LEAF_LIST_SHAPE`` with NO
    location: the input is not part of the signed bundle, so there is no
    bundle path to name, and inventing one would point a reader at a
    certificate field that is not at fault.
    """
    if leaf_lists is None:
        return
    if not isinstance(leaf_lists, Mapping):
        _fail("LEAF_LIST_SHAPE")
    dataset_ref = identity["dataset_ref"]
    leakage_scope_ref = identity["leakage_scope_ref"]
    for key, entries in leaf_lists.items():
        if type(key) is not str:
            _fail("LEAF_LIST_SHAPE")
        if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
            _fail("LEAF_LIST_SHAPE")
        is_item_set = key == dataset_ref
        expected_keys = (
            ("leaf", "category_id", "difficulty_stratum") if is_item_set else ("leaf",)
        )
        rows: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                _fail("LEAF_LIST_SHAPE")
            row = {field: entry[field] for field in expected_keys if field in entry}
            if len(row) != len(expected_keys) or len(row) != len(entry):
                # Missing a required member, or carrying one this projection
                # does not define. A leakage corpus list carries the opaque
                # token ALONE: the category/stratum tag is meaningful only
                # for the committed item set, and accepting it on a corpus
                # would imply a per-corpus partition this contract does not
                # define.
                _fail("LEAF_LIST_SHAPE")
            if type(row["leaf"]) is not str or not _SHA256_RE.fullmatch(row["leaf"]):
                _fail("LEAF_LIST_SHAPE")
            rows.append(row)
        leaves = [cast(str, row["leaf"]) for row in rows]
        if len(set(leaves)) != len(leaves):
            _fail("LEAF_LIST_SHAPE")
        if len(rows) > _MAX_LEAF_LIST:
            # Above the cap the projection is deliberately NOT schema-checked:
            # both definitions bound their arrays at _MAX_LEAF_LIST, so
            # validating here would turn an oversized list -- which this
            # contract answers by ABSTAINING DS3 (row 20) -- into a hard
            # shape failure. The explicit checks above already guarantee
            # every downstream read is type-safe.
            continue
        if is_item_set:
            projection: dict[str, Any] = {
                "schema_version": "traigent.dataset_record.item_set_leaf_list.v1",
                "dataset_ref": key,
                "item_set_root": identity["item_set_root"],
                "entries": rows,
            }
            if _leaf_list_projection_error("DatasetItemSetLeafListV1", projection):
                _fail("LEAF_LIST_SHAPE")
            continue
        corpus_projection: dict[str, Any] = {
            "schema_version": "traigent.dataset_record.leaf_list.v1",
            "corpus_ref": key,
            "leakage_scope_ref": leakage_scope_ref,
            "leaves": sorted(leaves),
        }
        if _leaf_list_projection_error("DatasetLeafListV1", corpus_projection):
            _fail("LEAF_LIST_SHAPE")


def _check_taxonomy_and_registry_pins(unsigned: dict[str, Any]) -> None:
    """The manifest's registry identities are the INSTALLED identities.

    Astra P2 (report registry identities): the first draft compared only the
    two digest FIELDS, so the id and version members beside each digest were
    manifest-supplied values nothing in this module ever read -- a manifest
    could name registry ``x`` version ``9.9.9`` while carrying the digest of
    the document actually installed here, and every downstream check would
    then run against a registry the record does not claim. The comparison is
    now against the whole identity object (``_TAXONOMY_IDENTITY`` /
    ``_METHOD_REGISTRY_IDENTITY``), which is exactly the three-member
    projection the shipped documents produce.

    The schema independently pins ``taxonomy_id``/``taxonomy_version`` (and
    the registry pair) as ``const``, so a divergent id or version is
    schema-rejected before this function runs; that makes this comparison
    defence in depth against a schema that later widens those consts rather
    than a separately-reachable rejection through the wire bundle. It IS
    directly exercised as a unit
    (``test_manifest_registry_identity_is_compared_as_a_whole_object``).
    """
    if unsigned["taxonomy"] != _TAXONOMY_IDENTITY:
        _fail("TAXONOMY_DIGEST_MISMATCH", "/unsigned_manifest/taxonomy")
    if unsigned["method_registry"] != _METHOD_REGISTRY_IDENTITY:
        _fail(
            "METHOD_REGISTRY_DIGEST_MISMATCH",
            "/unsigned_manifest/method_registry",
        )


def _check_report_registry_identities(
    unsigned: dict[str, Any], composition: dict[str, Any], leakage_report: dict[str, Any]
) -> None:
    """The reports' own registry identities are the manifest's (astra P2).

    ``composition.taxonomy`` and ``leakage_report.method_registry`` are
    signed, report-side copies of the identities the manifest pins, and
    nothing compared them: a re-signed composition could name a different
    ``taxonomy_digest``, or a re-signed leakage report a different
    ``registry_digest``, while this module went on verifying every term
    against the INSTALLED documents. The record then reads as though its
    composition was classified under one taxonomy and its leakage findings
    computed under one method registry, when the checks were performed
    against others.

    Compared against the manifest's copies, which
    :func:`_check_taxonomy_and_registry_pins` has already required to equal
    the installed constants -- so equality here is equality with the
    installed documents too, established transitively rather than by
    repeating the constant.
    """
    if composition["taxonomy"] != unsigned["taxonomy"]:
        _fail("TAXONOMY_DIGEST_MISMATCH", "/composition/taxonomy")
    if leakage_report["method_registry"] != unsigned["method_registry"]:
        _fail("METHOD_REGISTRY_DIGEST_MISMATCH", "/leakage_report/method_registry")


def _check_composition_digest(unsigned: dict[str, Any], composition: dict[str, Any]) -> None:
    projection = {k: v for k, v in composition.items() if k != "composition_digest"}
    digest = _role_digest(_COMPOSITION_DOMAIN, projection)
    if digest != composition["composition_digest"]:
        _fail("COMPOSITION_DIGEST_MISMATCH", "/composition/composition_digest")
    if digest != unsigned["composition_digest"]:
        _fail("COMPOSITION_DIGEST_MISMATCH", "/unsigned_manifest/composition_digest")


def _check_declared_partition(identity: dict[str, Any], composition: dict[str, Any]) -> None:
    cells = composition["cells"]
    if len(cells) > _MAX_CELLS:
        _fail("STRATUM_PARTITION_MISMATCH", "/composition/cells")
    seen: set[tuple[str, str]] = set()
    total = 0
    for index, cell in enumerate(cells):
        key = (cell["category_id"], cell["difficulty_stratum"])
        if key in seen:
            _fail("STRATUM_PARTITION_MISMATCH", f"/composition/cells/{index}")
        seen.add(key)
        if cell["item_count"] < 1:
            _fail("STRATUM_PARTITION_MISMATCH", f"/composition/cells/{index}/item_count")
        total += cell["item_count"]
    if total != identity["item_count"]:
        _fail("STRATUM_PARTITION_MISMATCH", "/composition/cells")
    if composition["populated_cell_count"] != len(cells):
        _fail("STRATUM_PARTITION_MISMATCH", "/composition/populated_cell_count")


def _check_composition_vocabulary(composition: dict[str, Any]) -> None:
    for index, cell in enumerate(composition["cells"]):
        if cell["category_id"] not in _REGISTERED_CATEGORY_IDS:
            _fail("TAXONOMY_TERM_UNREGISTERED", f"/composition/cells/{index}/category_id")
        if cell["difficulty_stratum"] not in _REGISTERED_STRATA:
            _fail("TAXONOMY_TERM_UNREGISTERED", f"/composition/cells/{index}/difficulty_stratum")


def _check_cell_roots(
    identity: dict[str, Any],
    composition: dict[str, Any],
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]],
) -> bool:
    """Recompute per-cell roots and the item-set root from the committed
    item set's own leaves. Returns ``True`` iff DS2 upgrades to
    ``issuer_verified``, ``False`` if the caller supplied leaf lists but
    none of them is the item-set entry (composition simply stays declared,
    not a hard failure).

    The wire schema carries no field binding a leakage corpus to the
    committed item set (composition cells and leakage corpora are
    different partitions of the same dataset), so this reads the item
    set's own leaves from the RESERVED key ``identity["dataset_ref"]``
    inside ``leaf_lists`` -- a namespace (``dsr:...``) that can never
    collide with a real ``corpus_ref`` (``cpr:...``). This is an
    implementer's reading of an underspecified corner of the Python
    ``leaf_lists`` parameter shape (the design's signature sketch leaves
    it as a bare ``object``), documented in the packet report.
    """
    item_set_entries = leaf_lists.get(identity["dataset_ref"])
    if not item_set_entries:
        return False

    by_cell: dict[tuple[str, str], list[str]] = {}
    all_leaves: list[str] = []
    for entry in item_set_entries:
        leaf = entry["leaf"]
        all_leaves.append(leaf)
        key = (entry["category_id"], entry["difficulty_stratum"])
        by_cell.setdefault(key, []).append(leaf)

    for cell in composition["cells"]:
        key = (cell["category_id"], cell["difficulty_stratum"])
        leaves = by_cell.get(key, [])
        if len(leaves) != cell["item_count"]:
            _fail("COMPOSITION_CELL_COUNT_MISMATCH", "/composition/cells")
        recomputed = _role_digest(_CELL_ROOT_DOMAIN, sorted(leaves))
        if recomputed != cell["cell_leaf_root"]:
            _fail("COMPOSITION_CELL_ROOT_MISMATCH", "/composition/cells")

    declared_keys = {
        (cell["category_id"], cell["difficulty_stratum"]) for cell in composition["cells"]
    }
    if set(by_cell) - declared_keys:
        _fail("COMPOSITION_CELL_ROOT_MISMATCH", "/composition/cells")

    reconstructed_root = _role_digest(_ITEM_SET_ROOT_DOMAIN, sorted(all_leaves))
    if reconstructed_root != identity["item_set_root"]:
        _fail("COMPOSITION_CELL_ROOT_MISMATCH", "/unsigned_manifest/identity/item_set_root")
    return True


def _check_leakage_digest(unsigned: dict[str, Any], leakage_report: dict[str, Any]) -> None:
    projection = {k: v for k, v in leakage_report.items() if k != "leakage_report_digest"}
    digest = _role_digest(_LEAKAGE_REPORT_DOMAIN, projection)
    if digest != leakage_report["leakage_report_digest"]:
        _fail("LEAKAGE_REPORT_DIGEST_MISMATCH", "/leakage_report/leakage_report_digest")
    if digest != unsigned["leakage_report_digest"]:
        _fail("LEAKAGE_REPORT_DIGEST_MISMATCH", "/unsigned_manifest/leakage_report_digest")


def _check_leakage_basis_coupling(leakage_report: dict[str, Any]) -> None:
    for index, finding in enumerate(leakage_report["findings"]):
        kind = finding["finding_kind"]
        basis = finding["observation_basis"]
        if kind in _TIER_C_FINDING_KINDS and basis != "client_attested":
            _fail("LEAKAGE_BASIS_COUPLING", f"/leakage_report/findings/{index}/observation_basis")
        if kind in _TIER_A_B_FINDING_KINDS and basis != "backend_observed":
            _fail("LEAKAGE_BASIS_COUPLING", f"/leakage_report/findings/{index}/observation_basis")


def _check_leakage_scope_pin(
    identity: dict[str, Any], context: DatasetRecordVerificationContext
) -> None:
    """Row 8b: the record's leakage scope IS the scope the caller asked about.

    ``expected_leakage_scope_ref`` was a caller pin the first draft never
    compared to anything (sol round 1 P1), so a record could verify under a
    leakage scope the relying party had not asked for -- every downstream
    disjointness statement then describes a different comparison universe
    than the one the caller believes it read. Unlike the commitment-ref pin
    this is a two-way comparison (the record's field against the pin): the
    process record carries no leakage scope, so there is no third party to
    the comparison.
    """
    if identity["leakage_scope_ref"] != context.expected_leakage_scope_ref:
        _fail("LEAKAGE_SCOPE_MISMATCH", "/unsigned_manifest/identity/leakage_scope_ref")


def _ds3_relevant_corpus_refs(leakage_report: dict[str, Any]) -> set[str]:
    """The corpora DS3's claim is actually about: those named by a finding
    whose verification IS the token-list disjointness statement."""
    refs: set[str] = set()
    for finding in leakage_report["findings"]:
        if finding["finding_kind"] in _DS3_RELEVANT_FINDING_KINDS:
            refs.add(finding["corpus_a_ref"])
            refs.add(finding["corpus_b_ref"])
    return refs


def _check_leakage_scope(
    identity: dict[str, Any],
    leakage_report: dict[str, Any],
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]] | None,
) -> None:
    if leakage_report["leakage_scope_ref"] != identity["leakage_scope_ref"]:
        _fail("LEAKAGE_SCOPE_MISMATCH", "/leakage_report/leakage_scope_ref")
    if leaf_lists:
        supplied_corpora = {entry["corpus_ref"] for entry in leakage_report["leaf_list_digests"]}
        dataset_ref = identity["dataset_ref"]
        for corpus_ref in leaf_lists:
            if corpus_ref == dataset_ref:
                continue
            if corpus_ref not in supplied_corpora:
                _fail("LEAKAGE_SCOPE_MISMATCH", "/leakage_report/leaf_list_digests")


def _check_leaf_list_digests(
    identity: dict[str, Any],
    leakage_report: dict[str, Any],
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]],
) -> dict[str, list[str]]:
    """Recompute each supplied corpus's leaf-list digest and return, per
    corpus, the plain sorted leaf token list for use by the overlap/
    disjointness checks. The reserved item-set key
    (``identity["dataset_ref"]``, see ``_check_cell_roots``) is not a
    leakage corpus and is skipped here."""
    recomputed: dict[str, list[str]] = {}
    seen_refs: set[str] = set()
    for index, entry in enumerate(leakage_report["leaf_list_digests"]):
        corpus_ref = entry["corpus_ref"]
        if corpus_ref in seen_refs:
            _fail(
                "LEAF_LIST_DIGEST_MISMATCH",
                f"/leakage_report/leaf_list_digests/{index}/corpus_ref",
            )
        seen_refs.add(corpus_ref)
    declared_by_ref = {entry["corpus_ref"]: entry for entry in leakage_report["leaf_list_digests"]}
    dataset_ref = identity["dataset_ref"]
    for corpus_ref, entries in leaf_lists.items():
        if corpus_ref == dataset_ref:
            continue
        declared = declared_by_ref.get(corpus_ref)
        if declared is None:
            _fail("LEAF_LIST_DIGEST_MISMATCH", "/leakage_report/leaf_list_digests")
        leaves = sorted(entry["leaf"] for entry in entries)
        if len(leaves) != declared["leaf_count"]:
            _fail("LEAF_LIST_DIGEST_MISMATCH", "/leakage_report/leaf_list_digests")
        if _leaf_list_digest(leaves) != declared["leaf_list_digest"]:
            _fail("LEAF_LIST_DIGEST_MISMATCH", "/leakage_report/leaf_list_digests")
        recomputed[corpus_ref] = leaves
    return recomputed


def _check_overlap_and_disjointness(
    leakage_report: dict[str, Any], corpora_leaves: dict[str, list[str]]
) -> int:
    """Returns the number of Tier-A findings actually recomputed.

    Astra P1 (DS3 can certify overlapping lists as disjoint), second half:
    the ``overlap_count`` recomputation was guarded on
    ``declared_corpus_overlap``, so a ``split_disjointness`` finding's own
    ``overlap_count`` -- a required member of every finding, schema-capped
    but otherwise unconstrained -- was a number no check ever reproduced. A
    record could therefore report a truthful overlap on one finding kind and
    an arbitrary one on the other. Both kinds are now recomputed under the
    same rule.

    The disjointness assertion is evaluated BEFORE the count. Both defects
    can be present in one finding (an asserted-disjoint pair that intersects
    will also, usually, be miscounted), and the assertion is the stronger,
    more specific claim; checking it first keeps
    ``SPLIT_DISJOINTNESS_VIOLATION`` the code such a finding raises rather
    than making it depend on which comparison happens to run first.
    """
    checked = 0
    for index, finding in enumerate(leakage_report["findings"]):
        if finding["finding_kind"] not in _DS3_RELEVANT_FINDING_KINDS:
            continue
        a_ref = finding["corpus_a_ref"]
        b_ref = finding["corpus_b_ref"]
        if a_ref not in corpora_leaves or b_ref not in corpora_leaves:
            continue
        intersection = set(corpora_leaves[a_ref]) & set(corpora_leaves[b_ref])
        if finding.get("disjointness_asserted") and intersection:
            _fail(
                "SPLIT_DISJOINTNESS_VIOLATION",
                f"/leakage_report/findings/{index}/disjointness_asserted",
            )
        if len(intersection) != finding["overlap_count"]:
            _fail("LEAKAGE_OVERLAP_MISMATCH", f"/leakage_report/findings/{index}/overlap_count")
        checked += 1
    return checked


def _ds3_disjointness_established(
    leakage_report: dict[str, Any], corpora_leaves: dict[str, list[str]]
) -> bool:
    """Whether a POSITIVE, recomputed disjointness statement covers every
    corpus pair DS3's claim is about (astra P1).

    DS3 says the token lists for the corpora it names are disjoint. The
    first draft upgraded it on coverage alone -- every relevant corpus
    supplied, digest-checked and attested -- and coverage is not the claim:
    with the ``split_disjointness`` finding removed, or its
    ``disjointness_asserted`` set to ``false``, a record could report a
    truthful non-zero overlap on the sibling ``declared_corpus_overlap``
    finding and still reach ``issuer_verified`` for DS3. Nothing was
    dishonest in that record; the row was.

    The unit is the corpus PAIR, not the finding: the two DS3-relevant kinds
    describe the same pair from two angles, and only ``split_disjointness``
    may carry ``disjointness_asserted`` at all (the schema forbids the member
    on every other kind). So a pair is established only when SOME finding
    about it asserts disjointness AND both its lists were supplied AND their
    recomputed intersection is empty. A pair that is merely reported honestly
    as overlapping leaves DS3 at ``client_declared`` -- which is what such a
    record actually supports.

    Pair keys are order-normalised, so a pair stated as (b, a) by one finding
    and (a, b) by another is one pair, not two.
    """
    pairs: dict[tuple[str, str], bool] = {}
    for finding in leakage_report["findings"]:
        if finding["finding_kind"] not in _DS3_RELEVANT_FINDING_KINDS:
            continue
        key = cast(
            "tuple[str, str]",
            tuple(sorted((finding["corpus_a_ref"], finding["corpus_b_ref"]))),
        )
        asserted = finding.get("disjointness_asserted") is True
        pairs[key] = pairs.get(key, False) or asserted
    if not pairs:
        return False
    for (a_ref, b_ref), asserted in pairs.items():
        if not asserted:
            return False
        a_leaves = corpora_leaves.get(a_ref)
        b_leaves = corpora_leaves.get(b_ref)
        if a_leaves is None or b_leaves is None:
            return False
        if set(a_leaves) & set(b_leaves):
            return False
    return True


def _check_corpus_ref_descriptors(
    identity: dict[str, Any],
    leakage_report: dict[str, Any],
    attestation: dict[str, Any] | None,
) -> None:
    """Every finding ref resolves to a signed, re-derived corpus descriptor
    (astra P1: finding refs retain an arbitrary content channel).

    ``_check_derived_refs`` re-derives the attestation's corpus refs and the
    refs of any leaf list the caller happened to SUPPLY -- never the refs a
    finding names. A finding's ``corpus_a_ref``/``corpus_b_ref`` are
    43-character pattern-conformant strings inside the signed leakage report,
    so an issuer could point a near-duplicate finding at two ``cpr:`` values
    that describe no corpus in the record at all, re-digest, re-sign, and
    have DS4 verify over them: a free, signed, issuer-chosen channel in the
    exact field ``CorpusRefV1`` exists to close.

    Two things are established here. First, every entry in
    ``leaf_list_digests`` must have a ``corpus_ref`` re-derived from its OWN
    ``leaf_list_digest`` under this record's leakage scope -- a descriptor
    cannot name a ref unrelated to the digest it publishes. Second, both refs
    of every finding must land in the set of refs so derived, unioned with
    the attestation's own (already re-derived) corpus refs.

    This runs whether or not leaf lists were supplied: the derivation is over
    signed record material only, so the fifth input has no bearing on it.

    A ``training_corpus_contamination`` or ``prior_output_contamination``
    finding is NOT exempt. Those are the two kinds that carry no recomputable
    evidence, so exempting them would reopen the channel precisely where the
    record is weakest: a Tier-C finding must publish a ``leaf_list_digests``
    descriptor (or an attestation entry) for each corpus it names, exactly as
    every other kind must.
    """
    leakage_scope_ref = identity["leakage_scope_ref"]
    known: set[str] = set()
    for index, entry in enumerate(leakage_report["leaf_list_digests"]):
        expected = _derive_corpus_ref(entry["leaf_list_digest"], leakage_scope_ref)
        if entry["corpus_ref"] != expected:
            _fail("REF_NOT_DERIVED", f"/leakage_report/leaf_list_digests/{index}/corpus_ref")
        known.add(entry["corpus_ref"])
    if attestation is not None:
        for corpus in attestation["corpora"]:
            known.add(corpus["corpus_ref"])
    for index, finding in enumerate(leakage_report["findings"]):
        for field in ("corpus_a_ref", "corpus_b_ref"):
            if finding[field] not in known:
                _fail("REF_NOT_DERIVED", f"/leakage_report/findings/{index}/{field}")


def _check_leaf_generation_attestation(
    unsigned: dict[str, Any],
    leakage_report: dict[str, Any],
    attestation: dict[str, Any] | None,
    corpora_leaves: dict[str, list[str]],
) -> bool:
    """Returns ``True`` iff the attestation is present and internally
    consistent with the supplied leaf lists (i.e. DS3 may upgrade)."""
    if attestation is None:
        if unsigned["leaf_generation_attestation_digest"] is not None:
            _fail(
                "LEAF_GENERATION_ATTESTATION_MISSING",
                "/unsigned_manifest/leaf_generation_attestation_digest",
            )
        if leakage_report["leaf_generation_attestation_digest"] is not None:
            _fail(
                "LEAF_GENERATION_ATTESTATION_MISSING",
                "/leakage_report/leaf_generation_attestation_digest",
            )
        return False
    projection = {k: v for k, v in attestation.items() if k != "attestation_digest"}
    digest = _role_digest(_LEAF_GENERATION_ATTESTATION_DOMAIN, projection)
    if digest != attestation["attestation_digest"]:
        _fail("LEAF_GENERATION_ATTESTATION_MISSING", "/leaf_generation_attestation")
    if unsigned["leaf_generation_attestation_digest"] != digest:
        _fail(
            "LEAF_GENERATION_ATTESTATION_MISSING",
            "/unsigned_manifest/leaf_generation_attestation_digest",
        )
    if leakage_report["leaf_generation_attestation_digest"] != digest:
        _fail(
            "LEAF_GENERATION_ATTESTATION_MISSING",
            "/leakage_report/leaf_generation_attestation_digest",
        )
    if attestation["leakage_scope_ref"] != leakage_report["leakage_scope_ref"]:
        _fail("LEAF_SCOPE_BLIND_MISMATCH", "/leaf_generation_attestation/leakage_scope_ref")

    # The common-blind premise, checked rather than asserted (sol round 1
    # P2). The first draft built a one-element set from the single top-level
    # field and compared its length to 1 -- a condition that cannot fire.
    # Every corpus now carries its own commitment and every one must equal
    # the attestation's, so a corpus generated under a different blind is
    # representable and rejected.
    scope_blind_commitment = attestation["scope_blind_commitment"]
    for corpus in attestation["corpora"]:
        if corpus["scope_blind_commitment"] != scope_blind_commitment:
            _fail("LEAF_SCOPE_BLIND_MISMATCH", "/leaf_generation_attestation/corpora")

    for corpus in attestation["corpora"]:
        corpus_ref = corpus["corpus_ref"]
        leaves = corpora_leaves.get(corpus_ref)
        if leaves is None:
            continue
        if corpus["leaf_count"] != len(leaves):
            _fail("LEAF_COMPLETENESS_MISMATCH", "/leaf_generation_attestation/corpora")
        if corpus["leaf_root"] != _leaf_list_digest(leaves):
            _fail("LEAF_COMPLETENESS_MISMATCH", "/leaf_generation_attestation/corpora")
    return True


def _check_ds4_method(
    unsigned: dict[str, Any], leakage_report: dict[str, Any], prereg: dict[str, Any]
) -> None:
    for index, finding in enumerate(leakage_report["findings"]):
        if finding["finding_kind"] != "near_duplicate_overlap":
            continue
        if finding["method"] != prereg["near_duplicate_method"]:
            _fail(
                "PREREGISTRATION_SCOPE_VIOLATION",
                f"/leakage_report/findings/{index}/method",
            )
        if finding["threshold_milli"] != prereg["near_duplicate_threshold_milli"]:
            _fail(
                "PREREGISTRATION_SCOPE_VIOLATION",
                f"/leakage_report/findings/{index}/threshold_milli",
            )
        if finding["method"] not in _REGISTERED_NEAR_DUPLICATE_METHODS:
            _fail(
                "PREREGISTRATION_SCOPE_VIOLATION",
                f"/leakage_report/findings/{index}/method",
            )


def _check_limitations_digest(unsigned: dict[str, Any], limitations: dict[str, Any]) -> None:
    projection = {k: v for k, v in limitations.items() if k != "limitations_digest"}
    digest = _role_digest(_LIMITATIONS_DOMAIN, projection)
    if digest != limitations["limitations_digest"]:
        _fail("LIMITATIONS_DIGEST_MISMATCH", "/limitations/limitations_digest")
    if digest != unsigned["limitations_digest"]:
        _fail("LIMITATIONS_DIGEST_MISMATCH", "/unsigned_manifest/limitations_digest")


def _check_derivable_limitations(composition: dict[str, Any], limitations: dict[str, Any]) -> None:
    codes = {item["limitation_code"] for item in limitations["limitations"]}
    counts = [cell["item_count"] for cell in composition["cells"]]
    if any(0 < count < _MIN_STRATUM_SIZE for count in counts):
        if "small_stratum" not in codes:
            _fail("LIMITATION_OMITTED", "/limitations/limitations")
    if counts and max(counts) > _IMBALANCE_RATIO_LIMIT * min(counts):
        if "unbalanced_strata" not in codes:
            _fail("LIMITATION_OMITTED", "/limitations/limitations")


def _check_limitation_basis_coupling(limitations: dict[str, Any]) -> None:
    for index, item in enumerate(limitations["limitations"]):
        derivable = item["limitation_code"] in _DERIVABLE_LIMITATION_CODES
        expected = "backend_observed" if derivable else "client_attested"
        if item["observation_basis"] != expected:
            _fail(
                "LIMITATION_BASIS_COUPLING", f"/limitations/limitations/{index}/observation_basis"
            )


def _check_prereg_digest(unsigned: dict[str, Any], envelope: dict[str, Any]) -> dict[str, Any]:
    prereg = envelope["preregistration"]
    projection = {k: v for k, v in prereg.items() if k != "prereg_digest"}
    digest = _role_digest(_PREREG_DOMAIN, projection)
    if digest != prereg["prereg_digest"]:
        _fail(
            "PREREGISTRATION_DIGEST_MISMATCH",
            "/preregistration_envelope/preregistration/prereg_digest",
        )
    if digest != unsigned["prereg_digest"]:
        _fail("PREREGISTRATION_DIGEST_MISMATCH", "/unsigned_manifest/prereg_digest")
    return cast(dict[str, Any], prereg)


def _check_prereg_signature(
    unsigned: dict[str, Any],
    envelope: dict[str, Any],
    materials_issuer: dict[str, Any],
) -> None:
    signature = envelope["signature"]
    prereg = envelope["preregistration"]
    projection = {k: v for k, v in prereg.items() if k != "prereg_digest"}
    # signature["prereg_digest"] binds the PLAN's own self-digest as a
    # value (the pattern ProcessRecordSignatureV1.unsigned_manifest_digest
    # uses) -- it is the same value as prereg["prereg_digest"], not a
    # second digest under the signature domain.
    if signature["prereg_digest"] != prereg["prereg_digest"]:
        _fail(
            "PREREGISTRATION_SIGNATURE_INVALID",
            "/preregistration_envelope/signature/prereg_digest",
        )
    if signature["prereg_digest"] != unsigned["prereg_digest"]:
        _fail("PREREGISTRATION_SIGNATURE_INVALID", "/unsigned_manifest/prereg_digest")
    # prereg_signature_digest is the manifest's digest-as-value of the
    # DatasetPreRegistrationSignatureV1 block itself (the pattern
    # ProcessRecordUnsignedManifestV1 uses for process_report_digest /
    # receipt_bundle_digest: a digest of a SEPARATE artifact, bound as a
    # plain value -- the signature block carries no self-referential field
    # of its own to exclude).
    signature_block_digest = _role_digest(_PREREG_SIGNATURE_DOMAIN, signature)
    if unsigned["prereg_signature_digest"] != signature_block_digest:
        _fail("PREREGISTRATION_SIGNATURE_INVALID", "/unsigned_manifest/prereg_signature_digest")
    if (
        signature["issuer_key_ref"] != materials_issuer["key_ref"]
        or signature["trust_ring_ref"] != materials_issuer["trust_ring_ref"]
    ):
        _fail("PREREGISTRATION_SIGNATURE_INVALID", "/preregistration_envelope/signature")
    try:
        # Framing per D9 P2: UTF8(domain) || 0x00 || jcs_v1(preregistration
        # with prereg_digest excluded) -- the plan's own self-digest field
        # is never part of what it signs.
        canonical = cast(str, fp2.canonicalize(projection)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    material = _PREREG_SIGNATURE_DOMAIN + b"\x00" + canonical
    public_key = _material_public_key(materials_issuer, _ISSUER_SPKI_DOMAIN)
    try:
        _verify_signature(public_key, signature["algorithm"], material, signature["signature"])
    except RelyingPartyVerificationError:
        _fail("PREREGISTRATION_SIGNATURE_INVALID", "/preregistration_envelope/signature/signature")


def _check_prereg_coverage(prereg: dict[str, Any]) -> None:
    if tuple(prereg["coverage"]) != _PREREG_COVERAGE:
        _fail(
            "PREREGISTRATION_SCOPE_VIOLATION", "/preregistration_envelope/preregistration/coverage"
        )


def _check_applied_policy(prereg: dict[str, Any], efficiency_report: dict[str, Any]) -> None:
    """Row 28b: the nine aggregation-policy fields, compared not assumed.

    Sol round 1 P1: the plan pre-registers ``score_metric``, both weightings,
    ``missing_outcome_policy`` and ``tie_break``, but the first draft's report
    had no field carrying any of them, so containment could only compare the
    fields that happened to appear twice. A policy that nothing can contradict
    is not pre-registered in any sense a relying party can act on. The report
    now echoes all nine in a signed projection and each must equal the plan's.
    """
    applied = efficiency_report["applied_policy"]
    for field in _APPLIED_POLICY_FIELDS:
        if applied[field] != prereg[field]:
            _fail(
                "PREREGISTRATION_SCOPE_VIOLATION",
                f"/efficiency_report/applied_policy/{field}",
            )


def _check_containment(
    prereg: dict[str, Any], efficiency_report: dict[str, Any], leakage_report: dict[str, Any]
) -> None:
    """Astra P2 (the efficiency report's policy reference is never checked).

    ``efficiency_report.prereg_digest`` is the report's own statement of
    WHICH signed plan it was computed under, and the first draft compared it
    with nothing: an issuer could point it at another (even genuinely
    signed) plan, update the report and support-row digests, re-sign, and
    every containment comparison below would still run against the plan in
    the envelope -- so the record would read as "computed under plan X" while
    being checked against plan Y.

    Checked first, before any field-by-field comparison, because a report
    naming a different plan makes those comparisons meaningless rather than
    merely unequal. ``_check_prereg_digest`` has already established that the
    envelope's plan digest equals the manifest's, and F2's caller-pin check
    that it equals any pin the caller holds, so this single equality
    transitively binds report, envelope, manifest and caller pin to one plan.
    """
    if efficiency_report["prereg_digest"] != prereg["prereg_digest"]:
        _fail("PREREGISTRATION_DIGEST_MISMATCH", "/efficiency_report/prereg_digest")
    # information_method/information_unit are deliberately NOT checked here:
    # row 34's dedicated INFORMATION_UNIT_RANGE check (_check_information_
    # range) already covers "unit equals the plan's" under its own more
    # specific code, and checking it twice under two different codes would
    # make the raised code depend on function-call order rather than on the
    # nature of the defect.
    pairs = (
        (
            "candidate_set_commitment",
            efficiency_report["candidate_set_commitment"],
            "/efficiency_report/candidate_set_commitment",
        ),
        (
            "candidate_count",
            efficiency_report["candidate_count"],
            "/efficiency_report/candidate_count",
        ),
    )
    for key, value, location in pairs:
        if prereg[key] != value:
            _fail("PREREGISTRATION_SCOPE_VIOLATION", location)

    for estimate_name in ("mean_item_information", "decisive_subset_upper_bound"):
        estimate = efficiency_report[estimate_name]
        if estimate["interval_method"] != "none":
            if estimate["interval_method"] != prereg["interval_method"]:
                _fail(
                    "PREREGISTRATION_SCOPE_VIOLATION",
                    f"/efficiency_report/{estimate_name}/interval_method",
                )
            if estimate.get("interval_level_ppm") != prereg["interval_level_ppm"]:
                _fail(
                    "PREREGISTRATION_SCOPE_VIOLATION",
                    f"/efficiency_report/{estimate_name}/interval_level_ppm",
                )
            if estimate["interval_method"] == "bootstrap_percentile_v1":
                for field in ("resample_count", "bootstrap_unit", "random_seed"):
                    plan_field = "bootstrap_resamples" if field == "resample_count" else field
                    if estimate.get(field) != prereg[plan_field]:
                        _fail(
                            "PREREGISTRATION_SCOPE_VIOLATION",
                            f"/efficiency_report/{estimate_name}/{field}",
                        )
        if estimate["sample_size_n"] < prereg["minimum_sample_size_n"]:
            _fail("SAMPLE_SIZE_INSUFFICIENT", f"/efficiency_report/{estimate_name}/sample_size_n")

    for finding in leakage_report["findings"]:
        if finding["finding_kind"] == "near_duplicate_overlap":
            if finding["method"] != prereg["near_duplicate_method"]:
                _fail("PREREGISTRATION_SCOPE_VIOLATION", "/leakage_report/findings")
            if finding["threshold_milli"] != prereg["near_duplicate_threshold_milli"]:
                _fail("PREREGISTRATION_SCOPE_VIOLATION", "/leakage_report/findings")


def _utc_microseconds(value: str) -> int:
    if _UTC_RE.fullmatch(value) is None:
        _fail("PREREGISTRATION_ORDER")
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    dot_index = value.find(".")
    frac = value[dot_index + 1 : -1] if dot_index != -1 else ""
    frac_us = int((frac + "000000")[:6]) if frac else 0
    try:
        datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        _fail("PREREGISTRATION_ORDER")
    days = date(year, month, day).toordinal() - _EPOCH_ORDINAL
    seconds = days * 86400 + hour * 3600 + minute * 60 + second
    return seconds * 1_000_000 + frac_us


def _check_ordering(
    unsigned: dict[str, Any], prereg: dict[str, Any], process_record_bundle: dict[str, Any]
) -> None:
    if prereg["registered_at"] != unsigned["prereg_registered_at"]:
        _fail("PREREGISTRATION_ORDER", "/unsigned_manifest/prereg_registered_at")
    registered_us = _utc_microseconds(prereg["registered_at"])
    receipts = process_record_bundle["receipts"]
    observed_values = []
    for stream_name in ("decision_stream", "receipt_event_stream", "transition_stream"):
        for receipt in receipts[stream_name]:
            if receipt["step_id"] in _ORDERING_STEP_IDS:
                observed_values.append(_utc_microseconds(receipt["observed_at"]))
    if observed_values and registered_us >= min(observed_values):
        _fail("PREREGISTRATION_ORDER", "/preregistration_envelope/preregistration/registered_at")


def _check_evidence_grade(
    unsigned: dict[str, Any], prereg: dict[str, Any], context: DatasetRecordVerificationContext
) -> str:
    declared = prereg["evidence_grade"]
    if unsigned["prereg_evidence_grade"] != declared:
        _fail("PREREGISTRATION_GRADE_MISMATCH", "/unsigned_manifest/prereg_evidence_grade")
    if declared == "log_inclusion_proof":
        _fail(
            "PREREGISTRATION_GRADE_UNSUPPORTED",
            "/preregistration_envelope/preregistration/evidence_grade",
        )
    if declared == "caller_pinned_before_results":
        if (
            context.expected_prereg_digest is None
            or context.expected_prereg_digest != prereg["prereg_digest"]
        ):
            _fail(
                "PREREGISTRATION_GRADE_MISMATCH",
                "/preregistration_envelope/preregistration/evidence_grade",
            )
        return "caller_pinned_before_results"
    if declared != "digest_bound_attestation":
        _fail(
            "PREREGISTRATION_GRADE_MISMATCH",
            "/preregistration_envelope/preregistration/evidence_grade",
        )
    # Astra P1: the issuer could bypass the caller's registered-policy pin by
    # declaring a WEAKER grade. The pin was consulted only inside the
    # caller_pinned_before_results branch above, so an issuer holding a
    # different signed plan simply declared digest_bound_attestation and the
    # substituted plan verified with the caller's own pin sitting unused in
    # the context object. A supplied pin is the caller's statement about
    # WHICH plan this verification is for; it binds at every grade. Appended
    # at this tail rather than at the head of the function so the two
    # grade-specific branches above keep raising their own
    # PREREGISTRATION_GRADE_* codes for grade defects.
    if (
        context.expected_prereg_digest is not None
        and context.expected_prereg_digest != prereg["prereg_digest"]
    ):
        _fail(
            "PREREGISTRATION_DIGEST_MISMATCH",
            "/preregistration_envelope/preregistration/prereg_digest",
        )
    return "digest_bound_attestation"


def _check_efficiency_digest(unsigned: dict[str, Any], efficiency_report: dict[str, Any]) -> None:
    projection = {k: v for k, v in efficiency_report.items() if k != "efficiency_report_digest"}
    digest = _role_digest(_EFFICIENCY_REPORT_DOMAIN, projection)
    if digest != efficiency_report["efficiency_report_digest"]:
        _fail("EFFICIENCY_REPORT_DIGEST_MISMATCH", "/efficiency_report/efficiency_report_digest")
    if digest != unsigned["efficiency_report_digest"]:
        _fail("EFFICIENCY_REPORT_DIGEST_MISMATCH", "/unsigned_manifest/efficiency_report_digest")


def _check_estimate_shape(estimate: dict[str, Any], location: str) -> None:
    lo, point, hi = estimate["lo"], estimate["point"], estimate["hi"]
    if not (lo <= point <= hi):
        _fail("INTERVAL_ORDER", f"{location}")
    kind = estimate["estimator_kind"]
    if kind in ("exact", "upper_bound"):
        if estimate["interval_method"] != "none" or not (lo == point == hi):
            _fail("INTERVAL_METHOD_COUPLING", location)
    else:
        if estimate["interval_method"] == "none":
            _fail("INTERVAL_METHOD_COUPLING", location)
        if (
            estimate["interval_method"] == "wilson_score_v1"
            and estimate["quantity_kind"] != "proportion"
        ):
            _fail("INTERVAL_METHOD_QUANTITY_MISMATCH", location)
    if estimate["effective_sample_size_n"] > estimate["sample_size_n"]:
        _fail("SAMPLE_SIZE_INSUFFICIENT", f"{location}/effective_sample_size_n")


def _check_information_range(
    efficiency_report: dict[str, Any], prereg: dict[str, Any], identity: dict[str, Any]
) -> None:
    # Astra P2 (DS5 accepts an impossible item count): only inert_item_count
    # received the dataset-relative bound check, so a 60-item dataset could
    # report uninformative_item_count = 61 -- more uninformative items than
    # items -- and, with the efficiency/support digests and the signature
    # updated around it, verify. The schema's own 0..1_000_000 bound is
    # dataset-INDEPENDENT and cannot express this; it is the same defect the
    # second review reported at dataset_record_v1_schema.json:1477, closed
    # once, here.
    #
    # The code is E1's INFORMATION_UNIT_RANGE, not E2's
    # INERT_FRACTION_MISMATCH: this is a range violation on an
    # information-model quantity, and borrowing the inert-fraction code would
    # tell a relying party that a ratio it never computed disagreed.
    if efficiency_report["uninformative_item_count"] > identity["item_count"]:
        _fail("INFORMATION_UNIT_RANGE", "/efficiency_report/uninformative_item_count")
    method = efficiency_report["information_method"]
    unit = efficiency_report["information_unit"]
    expected_unit = {
        "irt_2pl_mml_v1": "fisher_micro",
        "point_biserial_v1": "point_biserial_milli",
        "score_variance_v1": "variance_micro",
    }[method]
    if unit != expected_unit:
        _fail("INFORMATION_UNIT_RANGE", "/efficiency_report/information_unit")
    if unit != prereg["information_unit"] or method != prereg["information_method"]:
        _fail("INFORMATION_UNIT_RANGE", "/efficiency_report/information_method")
    estimate = efficiency_report["mean_item_information"]
    if unit == "point_biserial_milli":
        if not (-1000 <= estimate["point"] <= 1000):
            _fail("INFORMATION_UNIT_RANGE", "/efficiency_report/mean_item_information/point")
    else:
        if estimate["point"] < 0:
            _fail("INFORMATION_UNIT_RANGE", "/efficiency_report/mean_item_information/point")


def _check_inert_fraction(identity: dict[str, Any], efficiency_report: dict[str, Any]) -> None:
    inert = efficiency_report["inert_item_count"]
    item_count = identity["item_count"]
    if inert > item_count:
        _fail("INERT_FRACTION_MISMATCH", "/efficiency_report/inert_item_count")
    expected_ppm = (inert * 1_000_000) // item_count if item_count else 0
    if efficiency_report["inert_fraction_ppm"] != expected_ppm:
        _fail("INERT_FRACTION_MISMATCH", "/efficiency_report/inert_fraction_ppm")


def _check_decisive_subset(identity: dict[str, Any], efficiency_report: dict[str, Any]) -> None:
    bound = efficiency_report["decisive_subset_upper_bound"]
    if bound["estimator_kind"] != "upper_bound" or bound["quantity_kind"] != "count":
        _fail("DECISIVE_SUBSET_BOUND", "/efficiency_report/decisive_subset_upper_bound")
    if not (1 <= bound["point"] <= identity["item_count"]):
        _fail("DECISIVE_SUBSET_BOUND", "/efficiency_report/decisive_subset_upper_bound/point")
    if efficiency_report["decisive_subset_estimator_kind"] != "upper_bound":
        _fail("DECISIVE_SUBSET_BOUND", "/efficiency_report/decisive_subset_estimator_kind")


def _check_cost_and_latency(efficiency_report: dict[str, Any]) -> None:
    full_cost = efficiency_report["full_pass_cost_microusd"]
    decisive_cost = efficiency_report["decisive_subset_cost_microusd"]
    if full_cost > 0:
        if decisive_cost > full_cost:
            _fail("COST_EFFICIENCY_MISMATCH", "/efficiency_report/decisive_subset_cost_microusd")
        expected = (decisive_cost * 1_000_000) // full_cost
        if efficiency_report["cost_efficiency_ppm"] != expected:
            _fail("COST_EFFICIENCY_MISMATCH", "/efficiency_report/cost_efficiency_ppm")
    elif efficiency_report["cost_efficiency_ppm"] != 0:
        _fail("COST_EFFICIENCY_MISMATCH", "/efficiency_report/cost_efficiency_ppm")

    full_latency = efficiency_report["full_pass_latency_us"]
    decisive_latency = efficiency_report["decisive_subset_latency_us"]
    if full_latency > 0:
        if decisive_latency > full_latency:
            _fail("LATENCY_EFFICIENCY_MISMATCH", "/efficiency_report/decisive_subset_latency_us")
        expected = (decisive_latency * 1_000_000) // full_latency
        if efficiency_report["latency_efficiency_ppm"] != expected:
            _fail("LATENCY_EFFICIENCY_MISMATCH", "/efficiency_report/latency_efficiency_ppm")
    elif efficiency_report["latency_efficiency_ppm"] != 0:
        _fail("LATENCY_EFFICIENCY_MISMATCH", "/efficiency_report/latency_efficiency_ppm")


def _check_non_claims(unsigned: dict[str, Any]) -> None:
    non_claims = unsigned["non_claims"]
    if len(non_claims) != len(_NON_CLAIMS_CANONICAL):
        _fail("NON_CLAIMS_MISMATCH", "/unsigned_manifest/non_claims")
    for index, (row, (expected_id, expected_template)) in enumerate(
        zip(non_claims, _NON_CLAIMS_CANONICAL, strict=True)
    ):
        if row["non_claim_id"] != expected_id or row["reason_template_id"] != expected_template:
            _fail("NON_CLAIMS_MISMATCH", f"/unsigned_manifest/non_claims/{index}")


def _expected_evidence_digest(
    unsigned: dict[str, Any], identity: dict[str, Any], claim_id: str
) -> str | None:
    source = _CLAIM_ROW_PROFILE[claim_id]["evidence_source"]
    if source == "identity.dataset_identity_root":
        return cast("str | None", identity["dataset_identity_root"])
    return cast(str, unsigned[source])


def _check_support_rows(
    unsigned: dict[str, Any],
    identity: dict[str, Any],
    claim_support_rows: list[dict[str, Any]],
    claim_bases: dict[str, str],
) -> tuple[str, dict[str, Any]]:
    """Rows 42/43: every row must be the row this verification produced.

    Sol round 1 P2: the first draft read ``evidence_basis`` and nothing else,
    so a row could name any verifier id and any evidence refs -- including
    refs to artifacts no check consumed -- and a ``client_declared`` row was
    accepted for a claim the verifier had ABSTAINED, because only the
    issuer_verified branch was compared at all. The row profile is now exact
    in three ways: the basis must EQUAL the basis this verification derived
    (not merely be no stronger); the verifier id must be the one registered
    for that claim; and ``evidence_refs`` must be exactly one ref, of the
    kind that claim's evidence actually is, committing to the artifact THIS
    module recomputed for it. Anything else is a row that reads as support
    for a check that did not happen.

    F9 tightened ``evidence_refs`` to ``maxItems: 1``, so the ``len(refs) !=
    1`` check below is now defence in depth, unreachable through the wire --
    a caller that reaches into this private helper directly, bypassing
    ``_validate_schema``, is the only path that still reaches it. It stays:
    requiring exactly one ref here remains deliberate on its own terms -- a
    second ref would be support this verifier did not establish -- with the
    locator, being operational rather than evidential, not compared.

    Sol round 2 P1: ``EvidenceRefV0`` also admits an OPTIONAL third key,
    ``evidence_ref`` -- an opaque linkability/content channel by that type's
    own description. Nothing upstream forbade a support row from carrying it
    alongside the checked kind/digest, so a signed manifest could smuggle an
    arbitrary opaque locator through this path. Pillars 1 and 3 close this by
    never admitting the field into their signed bundles at all; here the
    field is admitted by the shared v0 evidence-ref definition, so this
    function closes it structurally instead -- a support row's single ref may
    carry ``evidence_kind``/``evidence_digest`` and NOTHING else.

    Sol round 2 P2: the schema requires ``verifier_version`` on every
    issuer_verified row (a BoundedSemver token), but nothing compared it to
    anything -- any syntactically-valid string passed, including one naming a
    verifier release that never ran. ``_CLAIM_ROW_PROFILE`` now pins the one
    version this module implements, and an issuer_verified row must name it
    exactly, beside the verifier id.
    """
    digest = _role_digest(_CLAIM_SUPPORT_ROWS_DOMAIN, claim_support_rows)
    if digest != unsigned["claim_support_rows_digest"]:
        _fail("CLAIM_SUPPORT_ROW_MISMATCH", "/unsigned_manifest/claim_support_rows_digest")

    by_id = {row["claim_id"]: row for row in claim_support_rows}
    if set(by_id) != set(_CLAIM_IDS):
        _fail("CLAIM_SUPPORT_ROW_MISMATCH", "/claim_support_rows")

    tallies: dict[str, list[str]] = {
        "issuer_verified": [],
        "client_declared": [],
        "abstained": [],
    }
    for index, claim_id in enumerate(_CLAIM_IDS):
        row = by_id[claim_id]
        basis = row["evidence_basis"]
        expected_basis = claim_bases[claim_id]
        if basis != expected_basis:
            # A row claiming MORE than the verifier established is the
            # headline failure and keeps its own code; every other
            # disagreement (a declaration where the verifier abstained, an
            # abstention where it verified) is a row that does not describe
            # this verification.
            if basis == "issuer_verified":
                _fail("CLAIM_NOT_VERIFIED", f"/claim_support_rows/{index}")
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")

        profile = _CLAIM_ROW_PROFILE[claim_id]
        if basis == "abstained":
            if row["abstention_code"] != _ABSTENTION_CODE:
                _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")
            tallies[basis].append(claim_id)
            continue

        expected_digest = _expected_evidence_digest(unsigned, identity, claim_id)
        refs = row["evidence_refs"]
        if len(refs) != 1:
            # Defence in depth: the schema pins evidence_refs to maxItems: 1
            # (F9), so this is unreachable through the wire -- kept in case a
            # caller reaches into this private helper directly, bypassing
            # schema validation.
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")
        if (
            expected_digest is None
            or refs[0]["evidence_kind"] != profile["evidence_kind"]
            or refs[0]["evidence_digest"] != expected_digest
            or set(refs[0]) - {"evidence_kind", "evidence_digest"}
        ):
            # The last disjunct is sol round 2 P1: a support row's evidence
            # ref may name the checked kind/digest and nothing else --
            # EvidenceRefV0's optional third key (``evidence_ref``) is
            # structurally forbidden here even though the shared v0
            # definition permits it.
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")
        if basis == "issuer_verified":
            if (
                row["verifier_id"] != profile["verifier_id"]
                or row["verifier_version"] != profile["verifier_version"]
            ):
                # Sol round 2 P2: the verifier id AND the pinned version it
                # ran at must both match -- a row naming a different version
                # of the right verifier is a row for a check that did not
                # run under this module's implementation.
                _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")
        elif row["attestation_basis"] != _ATTESTATION_BASIS:
            _fail("CLAIM_SUPPORT_ROW_MISMATCH", f"/claim_support_rows/{index}")
        tallies[basis].append(claim_id)
    return digest, {
        "claims_verified": tuple(tallies["issuer_verified"]),
        "claims_declared": tuple(tallies["client_declared"]),
        "claims_abstained": tuple(tallies["abstained"]),
    }


def _check_manifest_digest_and_signature(
    unsigned: dict[str, Any], signature: dict[str, Any], materials_issuer: dict[str, Any]
) -> None:
    digest = _role_digest(_UNSIGNED_MANIFEST_DOMAIN, unsigned)
    if signature["unsigned_manifest_digest"] != digest:
        _fail("UNSIGNED_MANIFEST_DIGEST_MISMATCH", "/signature/unsigned_manifest_digest")
    # The algorithm is SIGNED metadata: issuer_signature_algorithm sits inside
    # the manifest's coverage tuple, so the issuer states which algorithm this
    # manifest is signed under. The first draft verified with
    # signature["algorithm"] and never compared the two (sol round 1 P2), so a
    # signature block could nominate a different primitive than the manifest
    # it accompanies -- the bytes then verify under an algorithm the signed
    # record does not claim.
    if signature["algorithm"] != unsigned["issuer_signature_algorithm"]:
        _fail("ISSUER_SIGNATURE_INVALID", "/signature/algorithm")
    if (
        signature["issuer_key_ref"] != unsigned["issuer_key_ref"]
        or signature["trust_ring_ref"] != unsigned["trust_ring_ref"]
        or signature["issuer_key_ref"] != materials_issuer["key_ref"]
        or signature["trust_ring_ref"] != materials_issuer["trust_ring_ref"]
    ):
        _fail("KEY_RING_MISMATCH", "/signature")
    try:
        canonical = cast(str, fp2.canonicalize(unsigned)).encode("utf-8")
    except Exception:
        _fail("CANONICALIZATION")
    material = _ISSUER_SIGNATURE_DOMAIN + b"\x00" + canonical
    public_key = _material_public_key(materials_issuer, _ISSUER_SPKI_DOMAIN)
    try:
        _verify_signature(public_key, signature["algorithm"], material, signature["signature"])
    except RelyingPartyVerificationError:
        _fail("ISSUER_SIGNATURE_INVALID", "/signature/signature")


def _verify(
    bundle: dict[str, Any],
    context: DatasetRecordVerificationContext,
    process_record_bundle: object,
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]] | None,
) -> DatasetRecordVerificationResult:
    _validate_schema(bundle)
    _check_strict_integers(bundle)

    if tuple(bundle["unsigned_manifest"]["coverage"]) != _UNSIGNED_MANIFEST_COVERAGE:
        _fail("SCHEMA", "/unsigned_manifest/coverage")

    pr_result, pr_unsigned = _verify_process_record(process_record_bundle, context)
    # The dataset record reuses the SAME issuer key material the bound
    # process record already establishes -- check 45 requires
    # issuer_key_ref/trust_ring_ref equality with the bound process record,
    # and this is the SOURCE of that trusted key material, not merely a
    # value it happens to equal. There is no separate materials parameter in
    # the Python signature sketch this module implements.
    materials_issuer = cast(dict[str, Any], process_record_bundle)["verification_materials_v0"][
        "issuer"
    ]
    unsigned = bundle["unsigned_manifest"]

    _check_scope_binding(unsigned, pr_unsigned, context)
    _check_process_binding(unsigned, pr_result)
    _check_dataset_commitment(unsigned, pr_result, context)

    identity = unsigned["identity"]
    ds1_basis = _check_identity(identity, context)

    attestation = bundle.get("leaf_generation_attestation")
    _check_derived_dataset_ref(identity)
    # The fifth input is validated against its own contract artifacts BEFORE
    # any value is read out of it.
    _check_leaf_list_input(identity, leaf_lists)
    _check_derived_refs(unsigned, leaf_lists, attestation)

    _check_taxonomy_and_registry_pins(unsigned)

    composition = bundle["composition"]
    _check_composition_digest(unsigned, composition)
    _check_declared_partition(identity, composition)
    _check_composition_vocabulary(composition)

    composition_evidence = "declared_counts_only"
    ds2_basis = "client_declared"
    if leaf_lists:
        # Sol round 2 P3(a): the item-set leaf list is the ONE input DS2's
        # upgrade reads (_check_cell_roots), and _check_leaf_list_input
        # deliberately never schema-validates a list above _MAX_LEAF_LIST
        # (it is answered instead by DS3's abstention). DS2 must not read an
        # unvalidated list as if it had been checked -- an oversized item-set
        # list keeps DS2 at client_declared rather than hard-failing the
        # whole verification, consistent with every other insufficient-
        # evidence outcome in this function.
        item_set_entries = leaf_lists.get(identity["dataset_ref"])
        item_set_oversized = item_set_entries is not None and len(item_set_entries) > _MAX_LEAF_LIST
        if not item_set_oversized and _check_cell_roots(identity, composition, leaf_lists):
            composition_evidence = "cell_roots_recomputed"
            ds2_basis = "issuer_verified"

    leakage_report = bundle["leakage_report"]
    # The caller's leakage-scope pin gates every leakage check below it.
    _check_leakage_scope_pin(identity, context)
    _check_leakage_digest(unsigned, leakage_report)
    _check_leakage_basis_coupling(leakage_report)
    _check_leakage_scope(identity, leakage_report, leaf_lists)
    # Signed-material-only checks: neither reads the fifth input, so both run
    # whether or not the caller holds any leaf list.
    _check_corpus_ref_descriptors(identity, leakage_report, attestation)
    _check_report_registry_identities(unsigned, composition, leakage_report)

    corpora_leaves: dict[str, list[str]] = {}
    if leaf_lists:
        corpora_leaves = _check_leaf_list_digests(identity, leakage_report, leaf_lists)
    # Astra P1: the attestation is authenticated UNCONDITIONALLY. Guarding
    # this call on ``bool(leaf_lists)`` meant that, with no leaf lists
    # supplied, an included attestation's own digest bindings were never
    # recomputed -- an attested leaf_count could be altered without updating
    # a single digest or signature and the bundle stayed acceptable -- and a
    # manifest could declare a non-null leaf_generation_attestation_digest
    # with no attestation present at all. Only the leaf-DEPENDENT comparisons
    # inside it are gated on supply, which they already self-gate
    # (``corpora_leaves.get(corpus_ref) is None`` skips).
    #
    # It is called BEFORE _check_overlap_and_disjointness because
    # _ds3_disjointness_established below reads the attestation-covered
    # corpora, and both feed the one DS3 decision.
    attestation_consistent = _check_leaf_generation_attestation(
        unsigned, leakage_report, attestation, corpora_leaves
    )
    leakage_findings_checked = _check_overlap_and_disjointness(leakage_report, corpora_leaves)
    leakage_findings_attested = sum(
        1 for f in leakage_report["findings"] if f["finding_kind"] in _TIER_C_FINDING_KINDS
    )

    disjointness_evidence = "token_lists_only"
    ds3_basis = "client_declared"
    # DS3 upgrades only when EVERY corpus its claim is about was supplied,
    # digest-checked AND attested (sol round 1 P1). The first draft skipped
    # findings whose corpora were not supplied and skipped attestation
    # corpora with no supplied list, then upgraded DS3 if any leaf list plus
    # an attestation existed -- so a record could reach issuer_verified with
    # the one disjointness check that mattered never recomputed. A relevant
    # set that is EMPTY does not upgrade either: with no disjointness finding
    # there is no token-list disjointness to verify, and a pass printed over
    # nothing is the vacuous-check failure this contract exists to prevent.
    ds3_relevant = _ds3_relevant_corpus_refs(leakage_report)
    attested_refs = (
        {corpus["corpus_ref"] for corpus in attestation["corpora"]}
        if attestation is not None
        else set()
    )
    ds3_fully_covered = bool(ds3_relevant) and ds3_relevant <= (
        set(corpora_leaves) & attested_refs
    )
    # ...and only when the disjointness DS3 asserts was actually recomputed
    # and came out empty for every pair the claim covers (astra P1). Coverage
    # answers "were the lists there"; this answers "did they say what DS3
    # says they say".
    if (
        attestation_consistent
        and ds3_fully_covered
        and _ds3_disjointness_established(leakage_report, corpora_leaves)
    ):
        disjointness_evidence = "generation_attested"
        ds3_basis = "issuer_verified"
    # Sol round 2 P3(b): abstention must inspect only the corpus lists DS3's
    # OWN claim depends on (``ds3_relevant``, derived above from the
    # disjointness/overlap findings), not every key in ``leaf_lists`` --
    # that included the reserved item-set key and any corpus irrelevant to
    # this claim, so an oversized list for a corpus DS3 never reads about
    # forced an abstention it had no bearing on.
    ds3_abstains = not leaf_lists or any(
        len(leaf_lists.get(corpus_ref, ())) > _MAX_LEAF_LIST for corpus_ref in ds3_relevant
    )
    if ds3_abstains and context.require_leaf_lists:
        _fail("CLAIM_SUPPORT_ROW_MISMATCH", "/claim_support_rows/2")
    if ds3_abstains:
        ds3_basis = "abstained"

    limitations = bundle["limitations"]
    _check_limitations_digest(unsigned, limitations)
    _check_derivable_limitations(composition, limitations)
    _check_limitation_basis_coupling(limitations)

    envelope = bundle["preregistration_envelope"]
    prereg = _check_prereg_digest(unsigned, envelope)
    _check_prereg_signature(unsigned, envelope, materials_issuer)
    _check_prereg_coverage(prereg)

    efficiency_report = bundle["efficiency_report"]
    _check_applied_policy(prereg, efficiency_report)
    _check_containment(prereg, efficiency_report, leakage_report)
    _check_ordering(unsigned, prereg, cast(dict[str, Any], process_record_bundle))
    evidence_grade = _check_evidence_grade(unsigned, prereg, context)

    _check_efficiency_digest(unsigned, efficiency_report)
    _check_estimate_shape(
        efficiency_report["mean_item_information"], "/efficiency_report/mean_item_information"
    )
    _check_estimate_shape(
        efficiency_report["decisive_subset_upper_bound"],
        "/efficiency_report/decisive_subset_upper_bound",
    )
    _check_information_range(efficiency_report, prereg, identity)
    _check_inert_fraction(identity, efficiency_report)
    _check_decisive_subset(identity, efficiency_report)
    _check_cost_and_latency(efficiency_report)
    _check_ds4_method(unsigned, leakage_report, prereg)
    ds4_available = any(
        f["finding_kind"] == "near_duplicate_overlap" for f in leakage_report["findings"]
    )
    # A zero denominator abstains DS5 (missing_evidence_binding) rather than
    # dividing -- the E3 rule from D8, applied to the whole DS5 row since a
    # cost/latency ratio that cannot be computed is not a figure DS5 can
    # cover.
    ds5_basis = (
        "abstained"
        if (
            efficiency_report["full_pass_cost_microusd"] == 0
            or efficiency_report["full_pass_latency_us"] == 0
        )
        else "issuer_verified"
    )

    _check_non_claims(unsigned)

    claim_bases = {
        "DS1": ds1_basis,
        "DS2": ds2_basis,
        "DS3": ds3_basis,
        "DS4": "issuer_verified" if ds4_available else "abstained",
        "DS5": ds5_basis,
    }
    _digest_unused, claim_tallies = _check_support_rows(
        unsigned, identity, bundle["claim_support_rows"], claim_bases
    )

    _check_manifest_digest_and_signature(unsigned, bundle["signature"], materials_issuer)

    full = tuple(_CLAIM_IDS)
    success_code = (
        "DATASET_RECORD_VERIFIED"
        if claim_tallies["claims_verified"] == full
        else "DATASET_RECORD_VERIFIED_CLAIMS_PARTIAL"
    )

    return DatasetRecordVerificationResult(
        code=success_code,
        dataset_commitment_ref=unsigned["dataset_commitment_ref"],
        dataset_identity_root=identity["dataset_identity_root"] or "",
        identity_blind_epoch=identity["identity_blind_epoch"],
        item_set_root=identity["item_set_root"],
        item_count=identity["item_count"],
        populated_cell_count=composition["populated_cell_count"],
        composition_evidence=composition_evidence,
        disjointness_evidence=disjointness_evidence,
        leakage_findings_checked=leakage_findings_checked,
        leakage_findings_attested=leakage_findings_attested,
        limitation_count=len(limitations["limitations"]),
        max_limitation_severity=max(
            (item["severity"] for item in limitations["limitations"]), default=0
        ),
        inert_fraction_ppm=efficiency_report["inert_fraction_ppm"],
        decisive_subset_upper_bound=efficiency_report["decisive_subset_upper_bound"]["point"],
        cost_efficiency_ppm=efficiency_report["cost_efficiency_ppm"],
        claims_verified=claim_tallies["claims_verified"],
        claims_declared=claim_tallies["claims_declared"],
        claims_abstained=claim_tallies["claims_abstained"],
        prereg_digest=unsigned["prereg_digest"],
        prereg_evidence_grade=evidence_grade,
        efficiency_evidence="backend_observed_not_recomputed",
    )


def verify_dataset_record_certificate(
    bundle: object,
    *,
    context: DatasetRecordVerificationContext,
    process_record_bundle: object,
    leaf_lists: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
) -> DatasetRecordVerificationResult:
    """Verify a Dataset Record v1 certificate bundle entirely offline.

    ``process_record_bundle`` is the SEPARATE, already-issued Process Record
    V1 bundle this dataset record binds by digest -- never embedded in
    ``bundle`` (revision 3). It is verified first, via
    :func:`traigent_schema.certification.process_record_verifier.
    verify_process_record_certificate`, so a ``PROCESS_RECORD_INVALID``
    failure precedes every dataset-specific check. The issuer public-key
    material used to verify this record's own manifest signature and its
    plan signature is read from that ALREADY-VERIFIED bundle's own
    ``verification_materials_v0.issuer`` -- the dataset record reuses the
    same issuer key the process record already establishes trust for
    (check 45's key-ring equality is not incidental: it is why no separate
    key-material parameter exists here, matching the four-parameter Python
    signature sketch this module implements).

    ``leaf_lists`` is the optional fifth verification input: a mapping from
    the record's derived ``corpus_ref`` to that corpus's sorted leaf entries
    (see the module docstring for the entry shape). Its absence forces DS3 to
    abstain and DS2 to stay ``client_declared``; DS4 and DS5 never depend on
    it (sol's over-abstention finding, D6).
    """
    if not isinstance(context, DatasetRecordVerificationContext):
        _fail("CONTEXT")
    if type(bundle) is not dict:
        _fail("BUNDLE_SHAPE")
    # The catch-all is CLASSIFIED inside the handler and RAISED outside it
    # (sol round 1 P2). ``raise ... from None`` sets __suppress_context__ but
    # leaves __context__ populated, so the suppressed exception -- which a
    # hostile fifth input could have filled with supplied material -- stays
    # reachable on the escaping error. Leaving the ``except`` block first
    # clears the in-flight exception, so the raise below chains nothing:
    # __context__ IS None, not merely suppressed.
    failure: DatasetRecordVerificationError | None = None
    try:
        return _verify(
            cast(dict[str, Any], bundle),
            context,
            process_record_bundle,
            leaf_lists,
        )
    except DatasetRecordVerificationError:
        raise
    except Exception:
        failure = DatasetRecordVerificationError("VERIFICATION_FAILED")
    raise failure


__all__ = [
    "DATASET_RECORD_ERROR_CODES",
    "DatasetRecordVerificationContext",
    "DatasetRecordVerificationError",
    "DatasetRecordVerificationResult",
    "verify_dataset_record_certificate",
]
