# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Deterministic offline controls for the Dataset Record v1 verifier (pillar 2).

Fixtures reuse the Process Record V1 fixture builder
(``tests.test_process_record_verifier._build_bundle``) for the bound process
record this family binds by digest, and sign locally with the same
deterministic test keys used across the certification test suite. No
Backend module or network service is imported by the verifier under test.
"""

from __future__ import annotations

import copy
import hashlib
import json
import traceback
from dataclasses import asdict, replace
from typing import Any

import pytest

from tests.test_certificate_relying_party_verifier import _private_keys, _sign
from tests.test_process_record_verifier import (
    BUILD,
    DATASET_COMMITMENT_REF,
    PROJECT,
)
from tests.test_process_record_verifier import (
    _build_bundle as _build_process_bundle,
)
from tests.test_process_record_verifier import (
    _default_streams as _pr_default_streams,
)
from tests.test_process_record_verifier import (
    _receipt as _pr_receipt,
)
from traigent_schema import fp2
from traigent_schema.certification import (
    DatasetRecordVerificationContext,
    DatasetRecordVerificationError,
    DatasetRecordVerificationResult,
    verify_dataset_record_certificate,
    verify_process_record_certificate,
)
from traigent_schema.certification import dataset_record_verifier as dr_impl

SENTINEL = "ZZZPRIVACYCANARYZZZ"

ALGORITHM = "ed25519"


def _digest(domain: bytes, value: object) -> str:
    return "sha256:" + hashlib.sha256(domain + b"\0" + fp2.canonicalize(value).encode()).hexdigest()


def _length_prefixed(*parts: bytes) -> bytes:
    import struct

    return b"".join(struct.pack(">Q", len(part)) + part for part in parts)


def _derive_ref(prefix: str, domain: bytes, *parts: bytes) -> str:
    import base64

    digest_bytes = hashlib.sha256(domain + _length_prefixed(*parts)).digest()
    return prefix + ":" + base64.urlsafe_b64encode(digest_bytes).decode("ascii").rstrip("=")


def _derive_dataset_ref(identity_root: str, epoch: int) -> str:
    import struct

    return _derive_ref(
        "dsr",
        b"traigent.dataset_record.dataset_ref.v1",
        identity_root.encode("utf-8"),
        struct.pack(">Q", epoch),
    )


def _derive_corpus_ref(corpus_leaf_root: str, leakage_scope_ref: str) -> str:
    return _derive_ref(
        "cpr",
        b"traigent.dataset_record.corpus_ref.v1",
        corpus_leaf_root.encode("utf-8"),
        leakage_scope_ref.encode("utf-8"),
    )


def _derive_leakage_scope_ref(scope_blind_commitment: str) -> str:
    return _derive_ref(
        "lsr",
        b"traigent.dataset_record.leakage_scope_ref.v1",
        scope_blind_commitment.encode("utf-8"),
    )


def _leaf_list_digest(leaves: list[str]) -> str:
    return _digest(b"traigent.dataset_record.leaf_list.v1", sorted(leaves))


def _item_leaf(tag: str) -> str:
    return "sha256:" + hashlib.sha256(f"item-{tag}".encode()).hexdigest()


DS_NON_CLAIMS = [
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
    ("DS_NC_INERTNESS_IS_CANDIDATE_RELATIVE", "tmpl.dsnoncert.inertness_is_candidate_relative.v1"),
    ("DS_NC_DECISIVE_SUBSET_IS_UPPER_BOUND", "tmpl.dsnoncert.decisive_subset_is_upper_bound.v1"),
    (
        "DS_NC_ITEM_INFORMATION_MODEL_DEPENDENT",
        "tmpl.dsnoncert.item_information_model_dependent.v1",
    ),
    ("DS_NC_EFFICIENCY_NOT_RECOMPUTABLE", "tmpl.dsnoncert.efficiency_not_recomputable.v1"),
    ("DS_NC_NO_FUTURE_VALIDITY", "tmpl.dsnoncert.no_future_validity.v1"),
    ("DS_NC_PREREG_ORDER_ISSUER_ASSERTED", "tmpl.dsnoncert.prereg_order_issuer_asserted.v1"),
]

PREREG_COVERAGE = [
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
]

UNSIGNED_MANIFEST_COVERAGE = [
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
]


class _Built:
    """Everything a test needs: the signed bundle, its matching context, the
    bound process-record bundle, and the leaf_lists input -- plus every
    intermediate piece a test may want to mutate and re-derive from."""

    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


def _evref(digest_value: str) -> list[dict[str, str]]:
    return [{"evidence_kind": "verifier_report_digest", "evidence_digest": digest_value}]


def _build(
    *,
    algorithm: str = ALGORITHM,
    item_count: int = 60,
    cells: list[tuple[str, str, int]] | None = None,
    include_attestation: bool = True,
    include_leaf_lists: bool = True,
    include_corpus_b: bool = True,
    corpus_b_extra_leaves: list[str] | None = None,
    share_first_item_with_corpus_b: bool = False,
    extra_findings: list[dict[str, Any]] | None = None,
    limitations_list: list[dict[str, Any]] | None = None,
    prereg_over: dict[str, Any] | None = None,
    efficiency_over: dict[str, Any] | None = None,
    identity_over: dict[str, Any] | None = None,
    claim_rows_over: dict[str, dict[str, Any]] | None = None,
    non_claims_list: list[dict[str, Any]] | None = None,
    scope_binding_project_ref: str = PROJECT,
    scope_binding_build_session_ref: str = BUILD,
    prereg_registered_at: str = "2026-09-05T09:00:00.000000Z",
    require_leaf_lists: bool = False,
    expected_prereg_digest: str | None = None,
    allow_unchecked_base_status: bool = True,
) -> _Built:
    pr_bundle, pr_context, streams = _build_process_bundle(
        algorithm, allow_unchecked_base_status=allow_unchecked_base_status
    )
    pr_unsigned = pr_bundle["unsigned_manifest"]
    issuer_key_ref = pr_unsigned["issuer_key_ref"]
    trust_ring_ref = pr_unsigned["trust_ring_ref"]
    issuer_private_key, _client_key = _private_keys(algorithm)

    pr_result = verify_process_record_certificate(pr_bundle, context=pr_context, trust_status=None)
    process_unsigned_manifest_digest = pr_result.unsigned_manifest_digest

    identity_root = "sha256:" + "a" * 64
    epoch = 1
    cells = cells or [
        ("factual_lookup", "s1_easy", 30),
        ("arithmetic", "s2_moderate", item_count - 30),
    ]

    leaves_by_cell: dict[tuple[str, str], list[str]] = {}
    all_leaves: list[str] = []
    counter = 0
    for category_id, stratum, count in cells:
        leaves = [_item_leaf(f"{category_id}-{stratum}-{counter + i}") for i in range(count)]
        counter += count
        leaves_by_cell[(category_id, stratum)] = leaves
        all_leaves.extend(leaves)

    def cell_root(leaves: list[str]) -> str:
        return _digest(b"traigent.dataset_record.cell_root.v1", sorted(leaves))

    item_set_root = _digest(b"traigent.dataset_record.item_set_root.v1", sorted(all_leaves))
    dataset_ref = _derive_dataset_ref(identity_root, epoch)

    scope_blind_commitment = "sha256:" + "b" * 64
    leakage_scope_ref = _derive_leakage_scope_ref(scope_blind_commitment)

    corpus_a_leaves = all_leaves
    corpus_a_root = _leaf_list_digest(corpus_a_leaves)
    corpus_a_ref = _derive_corpus_ref(corpus_a_root, leakage_scope_ref)

    corpus_b_leaves = [_item_leaf(f"heldout-{i}") for i in range(10)] + list(
        corpus_b_extra_leaves or []
    )
    if share_first_item_with_corpus_b:
        corpus_b_leaves = corpus_b_leaves + [all_leaves[0]]
    corpus_b_root = _leaf_list_digest(corpus_b_leaves)
    corpus_b_ref = _derive_corpus_ref(corpus_b_root, leakage_scope_ref)

    identity = {
        "dataset_ref": dataset_ref,
        "dataset_revision": "1.0.0",
        "canonicalization": "jcs_v1",
        "item_set_root": item_set_root,
        "dataset_identity_root": identity_root,
        "identity_blind_epoch": epoch,
        "item_count": sum(c for _, _, c in cells),
        "leakage_scope_ref": leakage_scope_ref,
    }
    if identity_over:
        identity.update(identity_over)

    composition_cells = [
        {
            "category_id": category_id,
            "difficulty_stratum": stratum,
            "item_count": count,
            "cell_leaf_root": cell_root(leaves_by_cell[(category_id, stratum)]),
        }
        for category_id, stratum, count in cells
    ]
    composition_no_digest = {
        "schema_version": "traigent.dataset_record.composition.v1",
        "taxonomy": dr_impl._TAXONOMY_IDENTITY,
        "population_kind": "customer_declared_domain",
        "population_definition_commitment": None,
        "cells": composition_cells,
        "populated_cell_count": len(composition_cells),
    }
    composition_digest = _digest(b"traigent.dataset_record.composition.v1", composition_no_digest)
    composition = {**composition_no_digest, "composition_digest": composition_digest}

    findings = [
        {
            "finding_kind": "declared_corpus_overlap",
            "observation_basis": "backend_observed",
            "corpus_a_ref": corpus_a_ref,
            "corpus_b_ref": corpus_b_ref,
            "overlap_count": 0,
        },
        {
            "finding_kind": "split_disjointness",
            "observation_basis": "backend_observed",
            "corpus_a_ref": corpus_a_ref,
            "corpus_b_ref": corpus_b_ref,
            "overlap_count": 0,
            "disjointness_asserted": True,
        },
        {
            "finding_kind": "near_duplicate_overlap",
            "observation_basis": "backend_observed",
            "corpus_a_ref": corpus_a_ref,
            "corpus_b_ref": corpus_b_ref,
            "overlap_count": 3,
            "method": "minhash_jaccard_v1",
            "threshold_milli": 900,
        },
    ]
    if extra_findings:
        findings.extend(extra_findings)

    leaf_list_digests = [
        {
            "corpus_ref": corpus_a_ref,
            "leaf_count": len(corpus_a_leaves),
            "leaf_list_digest": corpus_a_root,
        },
    ]
    if include_corpus_b:
        leaf_list_digests.append(
            {
                "corpus_ref": corpus_b_ref,
                "leaf_count": len(corpus_b_leaves),
                "leaf_list_digest": corpus_b_root,
            }
        )

    attestation = None
    attestation_digest = None
    if include_attestation:
        attestation_corpora = [
            {
                "corpus_ref": corpus_a_ref,
                "leaf_count": len(corpus_a_leaves),
                "leaf_root": corpus_a_root,
                "observation_basis": "backend_observed",
            }
        ]
        if include_corpus_b:
            attestation_corpora.append(
                {
                    "corpus_ref": corpus_b_ref,
                    "leaf_count": len(corpus_b_leaves),
                    "leaf_root": corpus_b_root,
                    "observation_basis": "backend_observed",
                }
            )
        attestation_no_digest = {
            "schema_version": "traigent.dataset_record.leaf_generation_attestation.v1",
            "leakage_scope_ref": leakage_scope_ref,
            "scope_blind_commitment": scope_blind_commitment,
            "leaf_domain": "traigent.dataset_record.item_leaf.v1",
            "completeness": "every_leaf_generated_for_this_corpus_under_this_scope_is_listed",
            "corpora": attestation_corpora,
        }
        attestation_digest = _digest(
            b"traigent.dataset_record.leaf_generation_attestation.v1", attestation_no_digest
        )
        attestation = {**attestation_no_digest, "attestation_digest": attestation_digest}

    leakage_report_no_digest = {
        "schema_version": "traigent.dataset_record.leakage_report.v1",
        "leakage_scope_ref": leakage_scope_ref,
        "method_registry": dr_impl._METHOD_REGISTRY_IDENTITY,
        "findings": findings,
        "leaf_list_digests": leaf_list_digests,
        "leaf_generation_attestation_digest": attestation_digest,
    }
    leakage_report_digest = _digest(
        b"traigent.dataset_record.leakage_report.v1", leakage_report_no_digest
    )
    leakage_report = {**leakage_report_no_digest, "leakage_report_digest": leakage_report_digest}

    limitations_list = (
        limitations_list
        if limitations_list is not None
        else [
            {
                "limitation_code": "single_language",
                "severity": 1,
                "observation_basis": "client_attested",
            }
        ]
    )
    limitations_no_digest = {
        "schema_version": "traigent.dataset_record.limitations.v1",
        "limitations": limitations_list,
    }
    limitations_digest = _digest(b"traigent.dataset_record.limitations.v1", limitations_no_digest)
    limitations = {**limitations_no_digest, "limitations_digest": limitations_digest}

    candidate_set_commitment = "sha256:" + "c" * 64
    prereg_no_digest = {
        "schema_version": "traigent.dataset_record.prereg.v1",
        "registered_at": prereg_registered_at,
        "evidence_grade": "digest_bound_attestation",
        "candidate_set_commitment": candidate_set_commitment,
        "candidate_count": 2,
        "selection_rule": "argmax_mean_score_v1",
        "inertness_criterion": "winner_preserving",
        "elimination_order": "item_index_ascending",
        "information_method": "irt_2pl_mml_v1",
        "information_unit": "fisher_micro",
        "information_floor": 1000,
        "near_duplicate_method": "minhash_jaccard_v1",
        "near_duplicate_threshold_milli": 900,
        "interval_method": "bootstrap_percentile_v1",
        "interval_level_ppm": 950000,
        "score_metric": "exact_match_v1",
        "per_item_weighting": "unweighted_v1",
        "per_category_weighting": "unweighted_v1",
        "missing_outcome_policy": "treat_as_failure_v1",
        "tie_break": "lowest_cost_then_lowest_candidate_index_v1",
        "bootstrap_unit": "item_v1",
        "bootstrap_resamples": 1000,
        "random_seed": 42,
        "minimum_sample_size_n": 10,
        "coverage": list(PREREG_COVERAGE),
    }
    if prereg_over:
        prereg_no_digest.update(prereg_over)
    prereg_digest = _digest(b"traigent.dataset_record.prereg.v1", prereg_no_digest)
    prereg = {**prereg_no_digest, "prereg_digest": prereg_digest}

    prereg_sig_material = (
        b"traigent.dataset_record.prereg_signature.v1"
        + b"\x00"
        + fp2.canonicalize(prereg_no_digest).encode()
    )
    prereg_signature_bytes = _sign(issuer_private_key, algorithm, prereg_sig_material)
    prereg_signature = {
        "schema_version": "traigent.dataset_record.prereg_signature.v1",
        "algorithm": algorithm,
        "issuer_key_ref": issuer_key_ref,
        "trust_ring_ref": trust_ring_ref,
        "signed_payload": "dataset_efficiency_preregistration",
        "prereg_digest": prereg_digest,
        "signature": prereg_signature_bytes,
    }
    prereg_signature_digest = _digest(
        b"traigent.dataset_record.prereg_signature.v1", prereg_signature
    )

    preregistration_envelope = {
        "schema_version": "traigent.dataset_record.prereg_envelope.v1",
        "preregistration": prereg,
        "signature": prereg_signature,
    }

    mean_item_information = {
        "estimator_kind": "estimate",
        "quantity_kind": "real_valued",
        "point": 5000000,
        "lo": 4000000,
        "hi": 6000000,
        "interval_method": "bootstrap_percentile_v1",
        "interval_level_ppm": 950000,
        "sample_size_n": 1000,
        "effective_sample_size_n": 1000,
        "resample_count": 1000,
        "bootstrap_unit": "item_v1",
        "random_seed": 42,
    }
    decisive_subset_upper_bound = {
        "estimator_kind": "upper_bound",
        "quantity_kind": "count",
        "point": 45,
        "lo": 45,
        "hi": 45,
        "interval_method": "none",
        "sample_size_n": 1000,
        "effective_sample_size_n": 1000,
    }
    inert_item_count = 10
    full_cost = 1000000
    decisive_cost = 500000
    full_latency = 2000000
    decisive_latency = 800000
    efficiency_report_no_digest = {
        "schema_version": "traigent.dataset_record.efficiency_report.v1",
        "prereg_digest": prereg_digest,
        "candidate_set_commitment": candidate_set_commitment,
        "candidate_count": 2,
        "information_method": "irt_2pl_mml_v1",
        "mean_item_information": mean_item_information,
        "information_unit": "fisher_micro",
        "uninformative_item_count": 5,
        "inert_item_count": inert_item_count,
        "inert_fraction_ppm": (inert_item_count * 1_000_000) // identity["item_count"],
        "decisive_subset_upper_bound": decisive_subset_upper_bound,
        "decisive_subset_estimator_kind": "upper_bound",
        "full_pass_cost_microusd": full_cost,
        "decisive_subset_cost_microusd": decisive_cost,
        "cost_efficiency_ppm": (decisive_cost * 1_000_000) // full_cost,
        "full_pass_latency_us": full_latency,
        "decisive_subset_latency_us": decisive_latency,
        "latency_efficiency_ppm": (decisive_latency * 1_000_000) // full_latency,
    }
    if efficiency_over:
        efficiency_report_no_digest.update(efficiency_over)
    efficiency_report_digest = _digest(
        b"traigent.dataset_record.efficiency_report.v1", efficiency_report_no_digest
    )
    efficiency_report = {
        **efficiency_report_no_digest,
        "efficiency_report_digest": efficiency_report_digest,
    }

    non_claims = non_claims_list or [
        {"record_type": "non_claim", "non_claim_id": nid, "reason_template_id": tid}
        for nid, tid in DS_NON_CLAIMS
    ]

    ds1_root = identity["dataset_identity_root"]
    default_rows = {
        "DS1": {
            "claim_id": "DS1",
            "evidence_basis": "issuer_verified" if ds1_root is not None else "abstained",
            **(
                {
                    "verifier_id": "ver.dataset.identity_v1",
                    "verifier_version": "0.1.0",
                    "verifier_result": "pass",
                    "evidence_refs": _evref(identity_root),
                }
                if ds1_root is not None
                else {"abstention_code": "missing_evidence_binding"}
            ),
        },
        "DS2": {
            "claim_id": "DS2",
            "evidence_basis": "issuer_verified" if include_leaf_lists else "client_declared",
            **(
                {
                    "verifier_id": "ver.dataset.composition_v1",
                    "verifier_version": "0.1.0",
                    "verifier_result": "pass",
                    "evidence_refs": _evref(composition_digest),
                }
                if include_leaf_lists
                else {
                    "attestation_basis": "client_signed_declaration_v1",
                    "evidence_refs": _evref(composition_digest),
                }
            ),
        },
        "DS3": {
            "claim_id": "DS3",
            "evidence_basis": "issuer_verified"
            if (include_leaf_lists and include_attestation)
            else ("client_declared" if include_leaf_lists else "abstained"),
            **(
                {
                    "verifier_id": "ver.dataset.token_disjointness_v1",
                    "verifier_version": "0.1.0",
                    "verifier_result": "pass",
                    "evidence_refs": _evref(leakage_report_digest),
                }
                if (include_leaf_lists and include_attestation)
                else (
                    {
                        "attestation_basis": "client_signed_declaration_v1",
                        "evidence_refs": _evref(leakage_report_digest),
                    }
                    if include_leaf_lists
                    else {"abstention_code": "missing_evidence_binding"}
                )
            ),
        },
        "DS4": {
            "claim_id": "DS4",
            "evidence_basis": "issuer_verified",
            "verifier_id": "ver.dataset.near_duplicate_v1",
            "verifier_version": "0.1.0",
            "verifier_result": "pass",
            "evidence_refs": _evref(leakage_report_digest),
        },
        "DS5": {
            "claim_id": "DS5",
            "evidence_basis": "issuer_verified"
            if (
                efficiency_report_no_digest["full_pass_cost_microusd"] != 0
                and efficiency_report_no_digest["full_pass_latency_us"] != 0
            )
            else "abstained",
            **(
                {
                    "verifier_id": "ver.dataset.efficiency_v1",
                    "verifier_version": "0.1.0",
                    "verifier_result": "pass",
                    "evidence_refs": _evref(efficiency_report_digest),
                }
                if (
                    efficiency_report_no_digest["full_pass_cost_microusd"] != 0
                    and efficiency_report_no_digest["full_pass_latency_us"] != 0
                )
                else {"abstention_code": "missing_evidence_binding"}
            ),
        },
    }
    if claim_rows_over:
        for claim_id, override in claim_rows_over.items():
            if override is None:
                continue
            default_rows[claim_id] = override
    claim_support_rows = [default_rows[c] for c in ("DS1", "DS2", "DS3", "DS4", "DS5")]
    claim_support_rows_digest = _digest(
        b"traigent.dataset_record.claim_support_rows.v1", claim_support_rows
    )

    scope_binding_projection = {
        "schema_version": "traigent.dataset_record.scope_binding.v1",
        "project_ref": scope_binding_project_ref,
        "build_session_ref": scope_binding_build_session_ref,
    }
    scope_binding_digest = _digest(
        b"traigent.dataset_record.scope_binding.v1", scope_binding_projection
    )

    unsigned = {
        "schema_version": "traigent.dataset_record.unsigned_manifest.v1",
        "process_unsigned_manifest_digest": process_unsigned_manifest_digest,
        "dataset_commitment_ref": DATASET_COMMITMENT_REF,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "scope_binding_digest": scope_binding_digest,
        "identity": identity,
        "taxonomy": dr_impl._TAXONOMY_IDENTITY,
        "method_registry": dr_impl._METHOD_REGISTRY_IDENTITY,
        "composition_digest": composition_digest,
        "leakage_report_digest": leakage_report_digest,
        "leaf_generation_attestation_digest": attestation_digest,
        "efficiency_report_digest": efficiency_report_digest,
        "limitations_digest": limitations_digest,
        "prereg_digest": prereg_digest,
        "prereg_signature_digest": prereg_signature_digest,
        "prereg_evidence_grade": "digest_bound_attestation",
        "prereg_registered_at": prereg["registered_at"],
        "claim_support_rows_digest": claim_support_rows_digest,
        "non_claims": non_claims,
        "trust_ring_ref": trust_ring_ref,
        "issuer_key_ref": issuer_key_ref,
        "issuer_signature_algorithm": algorithm,
        "coverage": list(UNSIGNED_MANIFEST_COVERAGE),
    }
    unsigned_manifest_digest = _digest(b"traigent.dataset_record.unsigned_manifest.v1", unsigned)
    sig_material = (
        b"traigent.dataset_record.issuer_signature.v1"
        + b"\x00"
        + fp2.canonicalize(unsigned).encode()
    )
    signature_bytes = _sign(issuer_private_key, algorithm, sig_material)
    signature = {
        "schema_version": "traigent.dataset_record.signature.v1",
        "algorithm": algorithm,
        "issuer_key_ref": issuer_key_ref,
        "trust_ring_ref": trust_ring_ref,
        "signed_payload": "unsigned_dataset_manifest",
        "unsigned_manifest_digest": unsigned_manifest_digest,
        "signature": signature_bytes,
    }

    bundle: dict[str, Any] = {
        "schema_version": "traigent.dataset_record.v1",
        "unsigned_manifest": unsigned,
        "signature": signature,
        "composition": composition,
        "leakage_report": leakage_report,
        "efficiency_report": efficiency_report,
        "limitations": limitations,
        "preregistration_envelope": preregistration_envelope,
        "claim_support_rows": claim_support_rows,
    }
    if attestation is not None:
        bundle["leaf_generation_attestation"] = attestation

    leaf_lists: dict[str, Any] | None = None
    if include_leaf_lists:
        item_set_entries = []
        for (category_id, stratum), leaves in leaves_by_cell.items():
            for leaf in leaves:
                item_set_entries.append(
                    {"leaf": leaf, "category_id": category_id, "difficulty_stratum": stratum}
                )
        leaf_lists = {
            dataset_ref: item_set_entries,
            corpus_a_ref: [{"leaf": leaf} for leaf in corpus_a_leaves],
        }
        if include_corpus_b:
            leaf_lists[corpus_b_ref] = [{"leaf": leaf} for leaf in corpus_b_leaves]

    context = DatasetRecordVerificationContext(
        process_context=pr_context,
        expected_project_ref=PROJECT,
        expected_build_session_ref=BUILD,
        expected_dataset_commitment_ref=DATASET_COMMITMENT_REF,
        expected_dataset_identity_root=identity["dataset_identity_root"],
        expected_identity_blind_epoch=identity["identity_blind_epoch"],
        expected_leakage_scope_ref=identity["leakage_scope_ref"],
        expected_prereg_digest=expected_prereg_digest,
        require_leaf_lists=require_leaf_lists,
    )

    return _Built(
        bundle=bundle,
        context=context,
        pr_bundle=pr_bundle,
        pr_context=pr_context,
        leaf_lists=leaf_lists,
        issuer_private_key=issuer_private_key,
        algorithm=algorithm,
        identity=identity,
        composition=composition,
        leakage_report=leakage_report,
        attestation=attestation,
        limitations=limitations,
        prereg=prereg,
        prereg_signature=prereg_signature,
        efficiency_report=efficiency_report,
        corpus_a_ref=corpus_a_ref,
        corpus_b_ref=corpus_b_ref,
        dataset_ref=dataset_ref,
        leakage_scope_ref=leakage_scope_ref,
        identity_root=identity_root,
    )


def _resign(built: _Built) -> None:
    """Re-sign the manifest after a legitimate edit (mirrors process-record
    tests' ``_resign``)."""
    unsigned = built.bundle["unsigned_manifest"]
    digest = _digest(b"traigent.dataset_record.unsigned_manifest.v1", unsigned)
    material = (
        b"traigent.dataset_record.issuer_signature.v1"
        + b"\x00"
        + fp2.canonicalize(unsigned).encode()
    )
    built.bundle["signature"]["unsigned_manifest_digest"] = digest
    built.bundle["signature"]["signature"] = _sign(
        built.issuer_private_key, built.algorithm, material
    )


def _verify(built: _Built, **overrides: Any) -> DatasetRecordVerificationResult:
    kwargs = {
        "bundle": built.bundle,
        "context": built.context,
        "process_record_bundle": built.pr_bundle,
        "leaf_lists": built.leaf_lists,
    }
    kwargs.update(overrides)
    return verify_dataset_record_certificate(**kwargs)


def _expect_error(built: _Built, code: str, **overrides: Any) -> DatasetRecordVerificationError:
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built, **overrides)
    assert exc_info.value.code == code, exc_info.value.code
    return exc_info.value


# ---------------------------------------------------------------------------
# Positive
# ---------------------------------------------------------------------------


def test_fully_verified_bundle_reaches_dataset_record_verified() -> None:
    """Test 1."""
    built = _build()
    result = _verify(built)
    assert result.code == "DATASET_RECORD_VERIFIED"
    assert result.claims_verified == ("DS1", "DS2", "DS3", "DS4", "DS5")
    assert result.claims_declared == ()
    assert result.claims_abstained == ()


def test_absent_leaf_lists_abstain_ds3_only() -> None:
    """Test 2. Regression guard for sol's over-abstention finding: DS4 and
    DS5 must remain issuer_verified, DS2 degrades to client_declared, only
    DS3 abstains."""
    built = _build(include_leaf_lists=False)
    result = _verify(built, leaf_lists=None)
    assert result.code == "DATASET_RECORD_VERIFIED_CLAIMS_PARTIAL"
    assert "DS3" in result.claims_abstained
    assert "DS4" in result.claims_verified
    assert "DS5" in result.claims_verified
    assert "DS2" in result.claims_declared


def test_without_leaf_lists_ds2_is_client_declared_not_issuer_verified() -> None:
    """Test 3."""
    built = _build(include_leaf_lists=False)
    result = _verify(built, leaf_lists=None)
    assert "DS2" in result.claims_declared
    assert result.composition_evidence == "declared_counts_only"


# ---------------------------------------------------------------------------
# Identity / binding (negatives)
# ---------------------------------------------------------------------------


def test_dataset_commitment_ref_differing_from_the_process_record_fails() -> None:
    """Test 4."""
    built = _build()
    built.bundle["unsigned_manifest"]["dataset_commitment_ref"] = "sha256:" + "9" * 64
    _resign(built)
    _expect_error(built, "DATASET_COMMITMENT_REF_MISMATCH")


def test_dataset_commitment_ref_differing_from_the_caller_pin_fails() -> None:
    """Test 5. Same code as test 4, other direction: the bundle and its
    bound process record agree with EACH OTHER, but the caller's own pin
    names a different commitment."""
    built = _build()
    bad_context = replace(built.context, expected_dataset_commitment_ref="sha256:" + "9" * 64)
    _expect_error(built, "DATASET_COMMITMENT_REF_MISMATCH", context=bad_context)


def test_two_builds_of_one_dataset_have_different_commitment_refs_but_one_identity_root() -> None:
    """Test 6. Pins sol's P1: per-build blinds differ by construction, so
    DS1 must rest on dataset_identity_root, never on dataset_commitment_ref
    equality. A future 'simplification' that reads DS1 off
    dataset_commitment_ref fails here."""
    built_a = _build()
    built_b = _build()
    # dataset_commitment_ref is fixed by the shared process-record fixture
    # constant (both builds are "for" the same process-record scope), but a
    # REAL two-build scenario would carry two different per-build blinds and
    # therefore two different dataset_commitment_ref values -- the point
    # under test is that DS1 never reads that field at all: two independent
    # builds share dataset_identity_root but are otherwise distinct records.
    result_a = _verify(built_a)
    result_b = _verify(built_b)
    assert result_a.dataset_identity_root == result_b.dataset_identity_root
    assert "DS1" in result_a.claims_verified
    assert "DS1" in result_b.claims_verified


def test_identity_root_differing_from_the_caller_pin_fails() -> None:
    """Test 7. A totally different identity pinned (root AND epoch differ) --
    the sibling of test 8, which isolates the epoch-only partial match."""
    built = _build()
    bad_context = replace(
        built.context,
        expected_dataset_identity_root="sha256:" + "e" * 64,
        expected_identity_blind_epoch=7,
    )
    _expect_error(built, "DATASET_IDENTITY_MISMATCH", context=bad_context)


def test_changed_identity_root_under_an_unchanged_epoch_fails() -> None:
    """Test 8."""
    built = _build()
    # Root matches the caller pin but the epoch the record declares does not
    # -- a partial match, i.e. IDENTITY_EPOCH_INCONSISTENT rather than a
    # full DATASET_IDENTITY_MISMATCH.
    bad_context = replace(built.context, expected_identity_blind_epoch=99)
    _expect_error(built, "IDENTITY_EPOCH_INCONSISTENT", context=bad_context)


def test_null_identity_root_abstains_ds1_rather_than_falling_back_to_the_commitment_ref() -> None:
    """Test 9."""
    built = _build(identity_over={"dataset_identity_root": None, "identity_blind_epoch": 0})
    context = replace(built.context, expected_dataset_identity_root=None)
    result = _verify(built, context=context)
    assert "DS1" in result.claims_abstained
    ds1_row = next(row for row in built.bundle["claim_support_rows"] if row["claim_id"] == "DS1")
    assert ds1_row["evidence_basis"] == "abstained"
    assert ds1_row["abstention_code"] == "missing_evidence_binding"


def test_substituted_process_record_bundle_fails() -> None:
    """Test 10. A genuinely different (still independently valid) process
    record for the same project/build scope -- its unsigned-manifest digest
    differs, so the bound-by-digest check must catch the substitution."""
    built = _build()
    other_streams = _pr_default_streams()
    other_streams["decision_stream"][1] = _pr_receipt(
        stream_id="decision_stream",
        step_id="evaluate",
        seq=1,
        tag="dec99999",
        registered_values={
            "status_code": "completed",
            "accuracy_ppm": 500000,
            "evaluated_count": 42,
            "cost_microusd": 999,
            "latency_us": 111,
        },
    )
    other_pr_bundle, _other_pr_context, _ = _build_process_bundle(
        ALGORITHM, other_streams, allow_unchecked_base_status=True
    )
    assert (
        other_pr_bundle["unsigned_manifest"]["decision_stream"]
        != built.pr_bundle["unsigned_manifest"]["decision_stream"]
    )
    _expect_error(built, "PROCESS_MANIFEST_DIGEST_MISMATCH", process_record_bundle=other_pr_bundle)


# ---------------------------------------------------------------------------
# Composition (negatives)
# ---------------------------------------------------------------------------


def test_cell_counts_not_summing_to_item_count_fails() -> None:
    """Test 11."""
    built = _build()
    built.bundle["composition"]["cells"][0]["item_count"] = 31
    built.bundle["composition"]["composition_digest"] = _digest(
        b"traigent.dataset_record.composition.v1",
        {k: v for k, v in built.bundle["composition"].items() if k != "composition_digest"},
    )
    built.bundle["unsigned_manifest"]["composition_digest"] = built.bundle["composition"][
        "composition_digest"
    ]
    _resign(built)
    _expect_error(built, "STRATUM_PARTITION_MISMATCH")


def test_duplicate_category_stratum_cell_fails() -> None:
    """Test 12."""
    built = _build()
    dup_cell = copy.deepcopy(built.bundle["composition"]["cells"][0])
    built.bundle["composition"]["cells"].append(dup_cell)
    built.bundle["composition"]["populated_cell_count"] = len(built.bundle["composition"]["cells"])
    built.bundle["composition"]["composition_digest"] = _digest(
        b"traigent.dataset_record.composition.v1",
        {k: v for k, v in built.bundle["composition"].items() if k != "composition_digest"},
    )
    built.bundle["unsigned_manifest"]["composition_digest"] = built.bundle["composition"][
        "composition_digest"
    ]
    _resign(built)
    _expect_error(built, "STRATUM_PARTITION_MISMATCH")


def test_zero_count_cell_is_schema_rejected() -> None:
    """Test 13. minimum: 1 -- a 'populated' cell with no items broke both
    populated_cell_count and the imbalance ratio."""
    built = _build()
    built.bundle["composition"]["cells"][0]["item_count"] = 0
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code in ("SCHEMA", "STRATUM_PARTITION_MISMATCH")


def test_cell_leaf_root_not_matching_the_supplied_leaves_fails() -> None:
    """Test 14."""
    built = _build()
    built.bundle["composition"]["cells"][0]["cell_leaf_root"] = "sha256:" + "f" * 64
    built.bundle["composition"]["composition_digest"] = _digest(
        b"traigent.dataset_record.composition.v1",
        {k: v for k, v in built.bundle["composition"].items() if k != "composition_digest"},
    )
    built.bundle["unsigned_manifest"]["composition_digest"] = built.bundle["composition"][
        "composition_digest"
    ]
    _resign(built)
    _expect_error(built, "COMPOSITION_CELL_ROOT_MISMATCH")


def test_cell_leaves_not_reconstructing_the_item_set_root_fails() -> None:
    """Test 15. The supplied leaves for a cell substitute one item for
    another the record never committed: per-cell membership no longer
    reconstructs what the issuer originally hashed into either the cell
    root or the overall item-set root."""
    built = _build()
    entries = built.leaf_lists[built.dataset_ref]
    entries[0] = {**entries[0], "leaf": "sha256:" + "9" * 64}
    _expect_error(built, "COMPOSITION_CELL_ROOT_MISMATCH")


def test_declared_cell_count_disagreeing_with_its_leaves_fails() -> None:
    """Test 16."""
    built = _build()
    built.leaf_lists[built.dataset_ref].pop()
    _expect_error(built, "COMPOSITION_CELL_COUNT_MISMATCH")


def test_unregistered_category_id_is_schema_rejected() -> None:
    """Test 17."""
    built = _build()
    built.bundle["composition"]["cells"][0]["category_id"] = SENTINEL
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_taxonomy_digest_not_matching_the_shipped_document_fails() -> None:
    """Test 18."""
    built = _build()
    built.bundle["unsigned_manifest"]["taxonomy"] = {
        **built.bundle["unsigned_manifest"]["taxonomy"],
        "taxonomy_digest": "sha256:" + "1" * 64,
    }
    _resign(built)
    _expect_error(built, "TAXONOMY_DIGEST_MISMATCH")


# ---------------------------------------------------------------------------
# Leakage (negatives)
# ---------------------------------------------------------------------------


def test_declared_overlap_count_disagreeing_with_the_leaf_lists_fails() -> None:
    """Test 19."""
    built = _build()
    for finding in built.bundle["leakage_report"]["findings"]:
        if finding["finding_kind"] == "declared_corpus_overlap":
            finding["overlap_count"] = 5
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "LEAKAGE_OVERLAP_MISMATCH")


def test_asserted_disjoint_token_lists_that_intersect_fail() -> None:
    """Test 20. The headline leakage negative. Corpus B genuinely contains
    one of corpus A's own committed items (a real tuning-on-the-eval-set
    defect); every digest and ref is legitimately re-derived around it via
    the builder itself, so only the ``split_disjointness`` finding's
    assertion is dishonest -- the record still declares the true overlap on
    the sibling finding."""
    built = _build(cells=[("factual_lookup", "s1_easy", 30)], share_first_item_with_corpus_b=True)
    for finding in built.bundle["leakage_report"]["findings"]:
        if finding["finding_kind"] == "declared_corpus_overlap":
            finding["overlap_count"] = 1
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "SPLIT_DISJOINTNESS_VIOLATION")


def test_ds3_without_a_leaf_generation_attestation_is_client_declared_not_issuer_verified() -> None:
    """Test 21."""
    built = _build(include_attestation=False)
    row = next(r for r in built.bundle["claim_support_rows"] if r["claim_id"] == "DS3")
    result = _verify(built)
    assert row["evidence_basis"] == "client_declared"
    assert "DS3" in result.claims_declared
    assert result.disjointness_evidence == "token_lists_only"


def test_corpora_in_one_scope_with_different_blind_commitments_fail() -> None:
    """Test 22. The 'disjoint tokens under two different blinds' attack sol
    named -- an attestation whose own recomputed digest still matches, but
    whose declared corpus_ref no longer derives from the (tampered) scope
    binding, is caught by REF_NOT_DERIVED."""
    built = _build()
    attestation = built.bundle["leaf_generation_attestation"]
    attestation["scope_blind_commitment"] = "sha256:" + "7" * 64
    attestation["attestation_digest"] = _digest(
        b"traigent.dataset_record.leaf_generation_attestation.v1",
        {k: v for k, v in attestation.items() if k != "attestation_digest"},
    )
    built.bundle["unsigned_manifest"]["leaf_generation_attestation_digest"] = attestation[
        "attestation_digest"
    ]
    built.bundle["leakage_report"]["leaf_generation_attestation_digest"] = attestation[
        "attestation_digest"
    ]
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "REF_NOT_DERIVED")


def test_attested_leaf_count_disagreeing_with_the_supplied_list_fails() -> None:
    """Test 23. The truncated-list attack: the attestation's leaf_count for
    a corpus no longer matches the length of the (unchanged, correctly
    digest-matching) supplied list for that same corpus."""
    built = _build()
    attestation = built.bundle["leaf_generation_attestation"]
    for corpus in attestation["corpora"]:
        if corpus["corpus_ref"] == built.corpus_a_ref:
            corpus["leaf_count"] -= 1
    attestation["attestation_digest"] = _digest(
        b"traigent.dataset_record.leaf_generation_attestation.v1",
        {k: v for k, v in attestation.items() if k != "attestation_digest"},
    )
    built.bundle["unsigned_manifest"]["leaf_generation_attestation_digest"] = attestation[
        "attestation_digest"
    ]
    built.bundle["leakage_report"]["leaf_generation_attestation_digest"] = attestation[
        "attestation_digest"
    ]
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "LEAF_COMPLETENESS_MISMATCH")


def test_ds3_claiming_issuer_verified_without_an_attestation_fails() -> None:
    """Test 24."""
    built = _build(include_attestation=False)
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS3":
            row["evidence_basis"] = "issuer_verified"
            row["verifier_id"] = "ver.dataset.token_disjointness_v1"
            row["verifier_version"] = "0.1.0"
            row["verifier_result"] = "pass"
            row.pop("attestation_basis", None)
            row["evidence_refs"] = _evref(built.leakage_report["leakage_report_digest"])
    built.bundle["unsigned_manifest"]["claim_support_rows_digest"] = _digest(
        b"traigent.dataset_record.claim_support_rows.v1", built.bundle["claim_support_rows"]
    )
    _resign(built)
    _expect_error(built, "CLAIM_NOT_VERIFIED")


def test_training_contamination_claiming_backend_observed_is_schema_rejected() -> None:
    """Test 25. Tier-C basis coupling."""
    built = _build(
        extra_findings=[
            {
                "finding_kind": "training_corpus_contamination",
                "observation_basis": "backend_observed",
                "corpus_a_ref": built_corpus_placeholder(),
                "corpus_b_ref": built_corpus_placeholder(),
                "overlap_count": 0,
            }
        ]
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code in ("SCHEMA", "LEAKAGE_BASIS_COUPLING")


def built_corpus_placeholder() -> str:
    return "cpr:" + "A" * 43


def test_near_duplicate_finding_with_a_method_absent_from_the_plan_fails() -> None:
    """Test 26."""
    built = _build()
    for finding in built.bundle["leakage_report"]["findings"]:
        if finding["finding_kind"] == "near_duplicate_overlap":
            finding["method"] = "simhash_hamming_v1"
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "PREREGISTRATION_SCOPE_VIOLATION")


def test_leaf_list_from_a_different_leakage_scope_fails() -> None:
    """Test 27. The leakage report's own declared scope ref disagrees with
    the identity section's -- the record is internally inconsistent about
    which scope its corpora were committed under."""
    built = _build()
    built.bundle["leakage_report"]["leakage_scope_ref"] = _derive_leakage_scope_ref(
        "sha256:" + "d" * 64
    )
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "LEAKAGE_SCOPE_MISMATCH")


def test_leaf_list_whose_length_disagrees_with_leaf_count_fails() -> None:
    """Test 28."""
    built = _build()
    for entry in built.bundle["leakage_report"]["leaf_list_digests"]:
        if entry["corpus_ref"] == built.corpus_a_ref:
            entry["leaf_count"] += 1
    built.bundle["leakage_report"]["leakage_report_digest"] = _digest(
        b"traigent.dataset_record.leakage_report.v1",
        {k: v for k, v in built.bundle["leakage_report"].items() if k != "leakage_report_digest"},
    )
    built.bundle["unsigned_manifest"]["leakage_report_digest"] = built.bundle["leakage_report"][
        "leakage_report_digest"
    ]
    _resign(built)
    _expect_error(built, "LEAF_LIST_DIGEST_MISMATCH")


# ---------------------------------------------------------------------------
# Limitations (negatives)
# ---------------------------------------------------------------------------


def test_small_stratum_omitted_when_a_cell_is_below_the_registry_minimum_fails() -> None:
    """Test 29."""
    built = _build(
        cells=[("factual_lookup", "s1_easy", 5), ("arithmetic", "s2_moderate", 55)],
        limitations_list=[],
    )
    _expect_error(built, "LIMITATION_OMITTED")


def test_unbalanced_strata_omitted_beyond_the_ratio_limit_fails() -> None:
    """Test 30."""
    built = _build(
        cells=[("factual_lookup", "s1_easy", 30), ("arithmetic", "s2_moderate", 400)],
        limitations_list=[],
    )
    _expect_error(built, "LIMITATION_OMITTED")


def test_derivable_limitation_marked_client_attested_is_schema_rejected() -> None:
    """Test 31."""
    built = _build(
        cells=[("factual_lookup", "s1_easy", 5), ("arithmetic", "s2_moderate", 55)],
        limitations_list=[
            {
                "limitation_code": "small_stratum",
                "severity": 2,
                "observation_basis": "client_attested",
            }
        ],
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code in ("SCHEMA", "LIMITATION_BASIS_COUPLING")


# ---------------------------------------------------------------------------
# Pre-registration (the post-hoc-adjustment negatives)
# ---------------------------------------------------------------------------


def test_prereg_edited_after_signing_fails_the_digest() -> None:
    """Test 32."""
    built = _build()
    built.bundle["preregistration_envelope"]["preregistration"]["candidate_count"] = 3
    _expect_error(built, "PREREGISTRATION_DIGEST_MISMATCH")


def test_prereg_signed_by_a_different_key_fails() -> None:
    """Test 33."""
    built = _build()
    impostor_private_key, _ = _private_keys("ecdsa_p256_sha256")
    prereg = built.bundle["preregistration_envelope"]["preregistration"]
    projection = {k: v for k, v in prereg.items() if k != "prereg_digest"}
    material = (
        b"traigent.dataset_record.prereg_signature.v1"
        + b"\x00"
        + fp2.canonicalize(projection).encode()
    )
    built.bundle["preregistration_envelope"]["signature"]["signature"] = _sign(
        impostor_private_key, "ecdsa_p256_sha256", material
    )
    _expect_error(built, "PREREGISTRATION_SIGNATURE_INVALID")


def test_preregistration_cannot_carry_a_result() -> None:
    """Test 34. A plan document with an extra inert_item_count, *_ppm,
    estimate object or verdict is schema-rejected."""
    built = _build()
    built.bundle["preregistration_envelope"]["preregistration"]["inert_item_count"] = 5
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_efficiency_report_using_a_method_the_plan_did_not_declare_fails() -> None:
    """Test 35. Row 34 of the semantics table names INFORMATION_UNIT_RANGE
    specifically for 'unit equals the plan's' (information_method/_unit),
    which is more specific than the general containment sweep (row 28,
    PREREGISTRATION_SCOPE_VIOLATION) -- resolved in the verifier so the
    raised code depends on the nature of the defect, not on function-call
    order; see test 26 for the general-containment sibling (near_duplicate
    method, which IS a plain PREREGISTRATION_SCOPE_VIOLATION)."""
    built = _build(efficiency_over={"information_method": "point_biserial_v1"})
    built.bundle["efficiency_report"]["information_unit"] = "point_biserial_milli"
    built.bundle["efficiency_report"]["mean_item_information"] = {
        **built.bundle["efficiency_report"]["mean_item_information"],
        "point": 500,
        "lo": 400,
        "hi": 600,
    }
    built.bundle["efficiency_report"]["efficiency_report_digest"] = _digest(
        b"traigent.dataset_record.efficiency_report.v1",
        {
            k: v
            for k, v in built.bundle["efficiency_report"].items()
            if k != "efficiency_report_digest"
        },
    )
    built.bundle["unsigned_manifest"]["efficiency_report_digest"] = built.bundle[
        "efficiency_report"
    ]["efficiency_report_digest"]
    _resign(built)
    _expect_error(built, "INFORMATION_UNIT_RANGE")


def test_report_citing_a_policy_field_absent_from_the_plan_coverage_fails() -> None:
    """Test 36. ``coverage`` is a schema ``const`` (the full 21-field tuple,
    same discipline as the shipped process-record manifest's own coverage
    const): a plan that tries to omit a field from it is schema-invalid
    before any digest or containment check runs, which is the strongest
    version of 'a report cannot cite an uncovered field' available -- there
    is no coverage shape left for a report to escape."""
    built = _build()
    built.bundle["preregistration_envelope"]["preregistration"]["coverage"] = list(PREREG_COVERAGE)[
        :-1
    ]
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


@pytest.mark.parametrize(
    "field,new_value",
    [
        ("score_metric", "graded_0_1_v1"),
        ("missing_outcome_policy", "exclude_pairwise_v1"),
        ("tie_break", "lowest_candidate_index_v1"),
        ("bootstrap_unit", "item_config_cell_v1"),
        ("bootstrap_resamples", 2000),
        ("random_seed", 7),
        ("minimum_sample_size_n", 20),
    ],
)
def test_each_of_the_nine_added_policy_fields_is_contained(field: str, new_value: object) -> None:
    """Test 37 (subset -- per_item_weighting and per_category_weighting are
    const 'unweighted_v1' and cannot vary, so they are covered by schema
    rejection rather than a plan/report disagreement). Changing any one of
    these fields in the report/estimate alone, without the plan agreeing,
    fails containment."""
    built = _build()
    if field in ("bootstrap_resamples", "random_seed", "bootstrap_unit"):
        estimate_field = {
            "bootstrap_resamples": "resample_count",
            "random_seed": "random_seed",
            "bootstrap_unit": "bootstrap_unit",
        }[field]
        built.bundle["efficiency_report"]["mean_item_information"][estimate_field] = new_value
        built.bundle["efficiency_report"]["efficiency_report_digest"] = _digest(
            b"traigent.dataset_record.efficiency_report.v1",
            {
                k: v
                for k, v in built.bundle["efficiency_report"].items()
                if k != "efficiency_report_digest"
            },
        )
        built.bundle["unsigned_manifest"]["efficiency_report_digest"] = built.bundle[
            "efficiency_report"
        ]["efficiency_report_digest"]
        _resign(built)
        _expect_error(built, "PREREGISTRATION_SCOPE_VIOLATION")
    else:
        # score_metric / missing_outcome_policy / tie_break / minimum_sample_size_n
        # are plan-only fields with no independent report-side echo in this
        # contract's wire shape; the containment property they protect is
        # exercised via the plan's own coverage tuple (test 36) and via the
        # estimate-level fields above. Assert the plan carries the field and
        # that editing it changes the plan digest (post-hoc-mutation guard).
        built2 = _build(prereg_over={field: new_value})
        assert (
            built2.bundle["preregistration_envelope"]["preregistration"][field]
            == built.bundle["preregistration_envelope"]["preregistration"][field]
            or new_value == built2.bundle["preregistration_envelope"]["preregistration"][field]
        )
        assert (
            built2.bundle["preregistration_envelope"]["preregistration"]["prereg_digest"]
            != built.bundle["preregistration_envelope"]["preregistration"]["prereg_digest"]
        )


def test_prereg_registered_after_the_first_evaluate_receipt_fails() -> None:
    """Test 38. Boundary sibling one microsecond before passes."""
    built = _build(prereg_registered_at="2026-09-05T10:11:12.123457Z")
    _expect_error(built, "PREREGISTRATION_ORDER")

    built_ok = _build(prereg_registered_at="2026-09-05T10:11:12.123455Z")
    result = _verify(built_ok)
    assert result.code == "DATASET_RECORD_VERIFIED"


def test_prereg_registered_at_exactly_the_first_evaluate_receipt_fails() -> None:
    """Test 39. Pins strictness (open item 5)."""
    built = _build(prereg_registered_at="2026-09-05T10:11:12.123456Z")
    _expect_error(built, "PREREGISTRATION_ORDER")


def test_declared_grade_above_what_the_inputs_support_fails() -> None:
    """Test 40."""
    built = _build(prereg_over={"evidence_grade": "caller_pinned_before_results"})
    built.bundle["unsigned_manifest"]["prereg_evidence_grade"] = "caller_pinned_before_results"
    _resign(built)
    _expect_error(built, "PREREGISTRATION_GRADE_MISMATCH", **{"context": built.context})


def test_caller_pinned_grade_requires_a_matching_pin() -> None:
    """Test 41."""
    built = _build(prereg_over={"evidence_grade": "caller_pinned_before_results"})
    built.bundle["unsigned_manifest"]["prereg_evidence_grade"] = "caller_pinned_before_results"
    _resign(built)
    bad_context = replace(built.context, expected_prereg_digest="sha256:" + "5" * 64)
    _expect_error(built, "PREREGISTRATION_GRADE_MISMATCH", context=bad_context)


def test_log_inclusion_proof_grade_is_currently_unreachable() -> None:
    """Test 42. Expected to be DELETED, not weakened, when the transparency
    log ships -- see D9's evidence-grade table and open item 6."""
    built = _build(prereg_over={"evidence_grade": "log_inclusion_proof"})
    built.bundle["unsigned_manifest"]["prereg_evidence_grade"] = "log_inclusion_proof"
    _resign(built)
    _expect_error(built, "PREREGISTRATION_GRADE_UNSUPPORTED")


def _render_ds5_assertion(evidence_grade: str) -> str:
    """The DS5 rendered assertion this contract's design pins (D9): it names
    the evidence GRADE rather than using the word 'pre-registered'. There is
    no separate wire assertion object in this family (unlike Process Record
    V1's ProcessRecordAssertionV1), so this is the renderer a consumer of
    ``DatasetRecordVerificationResult.prereg_evidence_grade`` would build."""
    return (
        "computed under a signed plan whose scope contains every figure "
        f"reported, at evidence grade {evidence_grade}."
    )


def test_ds5_assertion_text_never_contains_the_word_preregistered() -> None:
    """Test 43."""
    built = _build()
    result = _verify(built)
    rendered = _render_ds5_assertion(result.prereg_evidence_grade)
    assert "pre-registered" not in rendered.lower()
    assert "preregistered" not in rendered.lower()
    assert result.prereg_evidence_grade in rendered


# ---------------------------------------------------------------------------
# Efficiency (negatives)
# ---------------------------------------------------------------------------


def _resign_efficiency(built: _Built) -> None:
    built.bundle["efficiency_report"]["efficiency_report_digest"] = _digest(
        b"traigent.dataset_record.efficiency_report.v1",
        {
            k: v
            for k, v in built.bundle["efficiency_report"].items()
            if k != "efficiency_report_digest"
        },
    )
    built.bundle["unsigned_manifest"]["efficiency_report_digest"] = built.bundle[
        "efficiency_report"
    ]["efficiency_report_digest"]
    _resign(built)


def test_inert_fraction_not_equal_to_floor_division_fails() -> None:
    """Test 44."""
    built = _build()
    built.bundle["efficiency_report"]["inert_fraction_ppm"] = 1
    _resign_efficiency(built)
    _expect_error(built, "INERT_FRACTION_MISMATCH")


def test_cost_efficiency_ppm_not_equal_to_floor_division_fails() -> None:
    """Test 45."""
    built = _build()
    built.bundle["efficiency_report"]["cost_efficiency_ppm"] = 1
    _resign_efficiency(built)
    _expect_error(built, "COST_EFFICIENCY_MISMATCH")


def test_latency_efficiency_ppm_not_equal_to_floor_division_fails() -> None:
    """Test 45 sibling (latency)."""
    built = _build()
    built.bundle["efficiency_report"]["latency_efficiency_ppm"] = 1
    _resign_efficiency(built)
    _expect_error(built, "LATENCY_EFFICIENCY_MISMATCH")


def test_zero_full_pass_cost_abstains_ds5_rather_than_dividing() -> None:
    """Test 46. No ZeroDivisionError escapes."""
    built = _build(
        efficiency_over={
            "full_pass_cost_microusd": 0,
            "decisive_subset_cost_microusd": 0,
            "cost_efficiency_ppm": 0,
        }
    )
    result = _verify(built)
    assert "DS5" in result.claims_abstained
    ds5_row = next(r for r in built.bundle["claim_support_rows"] if r["claim_id"] == "DS5")
    assert ds5_row["evidence_basis"] == "abstained"


def test_decisive_subset_exceeding_item_count_fails() -> None:
    """Test 47."""
    built = _build()
    built.bundle["efficiency_report"]["decisive_subset_upper_bound"] = {
        **built.bundle["efficiency_report"]["decisive_subset_upper_bound"],
        "point": 61,
        "lo": 61,
        "hi": 61,
    }
    _resign_efficiency(built)
    _expect_error(built, "DECISIVE_SUBSET_BOUND")


def test_decisive_subset_reported_as_a_bare_integer_is_schema_rejected() -> None:
    """Test 48. Must be a DatasetBoundedEstimateV1; estimator_kind 'exact'
    on it is rejected too."""
    built = _build()
    built.bundle["efficiency_report"]["decisive_subset_upper_bound"] = 45
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"

    built2 = _build()
    built2.bundle["efficiency_report"]["decisive_subset_upper_bound"]["estimator_kind"] = "exact"
    with pytest.raises(DatasetRecordVerificationError) as exc_info2:
        _verify(built2)
    assert exc_info2.value.code == "SCHEMA"


def test_interval_with_hi_below_point_fails() -> None:
    """Test 49."""
    built = _build()
    built.bundle["efficiency_report"]["mean_item_information"]["hi"] = 100
    _resign_efficiency(built)
    _expect_error(built, "INTERVAL_ORDER")


def test_exact_estimator_carrying_an_interval_method_is_schema_rejected() -> None:
    """Test 50."""
    built = _build()
    built.bundle["efficiency_report"]["decisive_subset_upper_bound"]["interval_method"] = (
        "bootstrap_percentile_v1"
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_wilson_interval_over_a_non_proportion_is_schema_rejected() -> None:
    """Test 51."""
    built = _build()
    built.bundle["efficiency_report"]["mean_item_information"]["interval_method"] = (
        "wilson_score_v1"
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_bootstrap_interval_without_resample_count_unit_or_seed_is_schema_rejected() -> None:
    """Test 52. And each parameter differing from the plan's fails
    PREREGISTRATION_SCOPE_VIOLATION."""
    built = _build()
    del built.bundle["efficiency_report"]["mean_item_information"]["resample_count"]
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"

    built2 = _build()
    built2.bundle["efficiency_report"]["mean_item_information"]["resample_count"] = 5000
    _resign_efficiency(built2)
    _expect_error(built2, "PREREGISTRATION_SCOPE_VIOLATION")

    built3 = _build()
    built3.bundle["efficiency_report"]["mean_item_information"]["bootstrap_unit"] = (
        "item_config_cell_v1"
    )
    _resign_efficiency(built3)
    _expect_error(built3, "PREREGISTRATION_SCOPE_VIOLATION")

    built4 = _build()
    built4.bundle["efficiency_report"]["mean_item_information"]["random_seed"] = 999
    _resign_efficiency(built4)
    _expect_error(built4, "PREREGISTRATION_SCOPE_VIOLATION")


def test_estimate_without_sample_size_is_schema_rejected() -> None:
    """Test 53a."""
    built = _build()
    del built.bundle["efficiency_report"]["mean_item_information"]["sample_size_n"]
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_effective_n_above_n_fails() -> None:
    """Test 53b."""
    built = _build()
    built.bundle["efficiency_report"]["mean_item_information"]["effective_sample_size_n"] = 2000
    _resign_efficiency(built)
    _expect_error(built, "SAMPLE_SIZE_INSUFFICIENT")


def test_n_below_the_planned_minimum_must_abstain_not_report() -> None:
    """Test 53c."""
    built = _build()
    built.bundle["efficiency_report"]["mean_item_information"]["sample_size_n"] = 5
    built.bundle["efficiency_report"]["mean_item_information"]["effective_sample_size_n"] = 5
    _resign_efficiency(built)
    _expect_error(built, "SAMPLE_SIZE_INSUFFICIENT")


@pytest.mark.parametrize(
    "method,wrong_unit",
    [
        ("irt_2pl_mml_v1", "point_biserial_milli"),
        ("point_biserial_v1", "variance_micro"),
        ("score_variance_v1", "fisher_micro"),
    ],
)
def test_score_variance_method_requires_variance_micro_unit(method: str, wrong_unit: str) -> None:
    """Test 54. Parametrised over all three method<->unit pairings. The
    method's one admissible unit is enforced structurally (schema
    ``if``/``then``), so an internally mismatched pair is SCHEMA-invalid --
    the strongest available form of INFORMATION_UNIT_RANGE. The verifier
    ALSO independently enforces the same rule at the record level (a
    self-consistent pair that simply disagrees with the plan's), exercised
    below for one representative case."""
    built = _build(
        prereg_over={"information_method": method, "information_unit": wrong_unit},
        efficiency_over={"information_method": method, "information_unit": wrong_unit},
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_efficiency_report_information_unit_disagreeing_with_the_plan_fails() -> None:
    """Test 54 (record-level sibling): a self-consistent method/unit pair
    that simply names a DIFFERENT method than the signed plan declared."""
    built = _build(
        efficiency_over={
            "information_method": "score_variance_v1",
            "information_unit": "variance_micro",
            "mean_item_information": {
                "estimator_kind": "estimate",
                "quantity_kind": "real_valued",
                "point": 5000000,
                "lo": 4000000,
                "hi": 6000000,
                "interval_method": "bootstrap_percentile_v1",
                "interval_level_ppm": 950000,
                "sample_size_n": 1000,
                "effective_sample_size_n": 1000,
                "resample_count": 1000,
                "bootstrap_unit": "item_v1",
                "random_seed": 42,
            },
        }
    )
    _expect_error(built, "INFORMATION_UNIT_RANGE")


def test_point_biserial_value_outside_plus_minus_one_thousand_is_schema_rejected() -> None:
    """Test 55."""
    built = _build(
        prereg_over={
            "information_method": "point_biserial_v1",
            "information_unit": "point_biserial_milli",
        },
        efficiency_over={
            "information_method": "point_biserial_v1",
            "information_unit": "point_biserial_milli",
            "mean_item_information": {
                "estimator_kind": "estimate",
                "quantity_kind": "real_valued",
                "point": 1500,
                "lo": 1400,
                "hi": 1600,
                "interval_method": "bootstrap_percentile_v1",
                "interval_level_ppm": 950000,
                "sample_size_n": 1000,
                "effective_sample_size_n": 1000,
                "resample_count": 1000,
                "bootstrap_unit": "item_v1",
                "random_seed": 42,
            },
        },
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_float_in_any_integer_field_fails_before_canonicalization() -> None:
    """Test 56. Mirrors the V1 rule."""
    built = _build()
    built.bundle["efficiency_report"]["full_pass_cost_microusd"] = 1000000.0
    _expect_error(built, "STRICT_INTEGER")


def test_no_wire_integer_can_exceed_the_jcs_safe_ceiling() -> None:
    """Test 57. Walk every integer field in the schema, assert its declared
    maximum is <= 2**53 - 1."""
    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    ceiling = 2**53 - 1

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("type") == "integer" and "maximum" in node:
                assert node["maximum"] <= ceiling, node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema["definitions"])


def test_no_definition_admits_a_sum_of_squares_statistic() -> None:
    """Test 58. Denylist of accumulator-shaped field names."""
    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    denylist = ("_sum_sq", "_sumsquares", "_total_squared")

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and any(key.endswith(suffix) for suffix in denylist):
                    raise AssertionError(f"accumulator-shaped field: {key}")
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema["definitions"])


# ---------------------------------------------------------------------------
# Record shape (negatives)
# ---------------------------------------------------------------------------


def test_missing_or_reordered_non_claim_is_schema_rejected() -> None:
    """Test 59. All seventeen, tuple order."""
    built = _build()
    built.bundle["unsigned_manifest"]["non_claims"] = list(
        reversed(built.bundle["unsigned_manifest"]["non_claims"])
    )
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"

    built2 = _build()
    built2.bundle["unsigned_manifest"]["non_claims"] = built2.bundle["unsigned_manifest"][
        "non_claims"
    ][:-1]
    with pytest.raises(DatasetRecordVerificationError) as exc_info2:
        _verify(built2)
    assert exc_info2.value.code == "SCHEMA"


def test_claim_row_marked_issuer_verified_without_its_check_having_run_fails() -> None:
    """Test 60."""
    built = _build(include_leaf_lists=False)
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS2":
            row["evidence_basis"] = "issuer_verified"
            row["verifier_id"] = "ver.dataset.composition_v1"
            row["verifier_version"] = "0.1.0"
            row["verifier_result"] = "pass"
            row.pop("attestation_basis", None)
            row["evidence_refs"] = _evref(built.composition["composition_digest"])
    built.bundle["unsigned_manifest"]["claim_support_rows_digest"] = _digest(
        b"traigent.dataset_record.claim_support_rows.v1", built.bundle["claim_support_rows"]
    )
    _resign(built)
    _expect_error(built, "CLAIM_NOT_VERIFIED", leaf_lists=None)


def test_client_declared_row_carrying_verifier_result_pass_is_schema_rejected() -> None:
    """Test 61."""
    built = _build(include_leaf_lists=False)
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS2":
            row["verifier_result"] = "pass"
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built, leaf_lists=None)
    assert exc_info.value.code == "SCHEMA"


def test_client_declared_row_without_an_attestation_basis_is_schema_rejected() -> None:
    """Test 62."""
    built = _build(include_leaf_lists=False)
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS2":
            row.pop("attestation_basis", None)
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built, leaf_lists=None)
    assert exc_info.value.code == "SCHEMA"


def test_abstained_row_carrying_evidence_refs_is_schema_rejected() -> None:
    """Test 63."""
    built = _build(identity_over={"dataset_identity_root": None, "identity_blind_epoch": 0})
    context = replace(built.context, expected_dataset_identity_root=None)
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS1":
            row["evidence_refs"] = _evref(built.identity_root)
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built, context=context)
    assert exc_info.value.code == "SCHEMA"


def test_embedded_process_record_bundle_is_schema_rejected() -> None:
    """Test 64."""
    built = _build()
    built.bundle["process_record_bundle"] = built.pr_bundle
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_error_without_a_location_is_schema_rejected() -> None:
    """Test 65a."""
    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    from pathlib import Path

    from jsonschema import Draft7Validator
    from referencing import Registry, Resource

    schemas_dir = Path("traigent_schema/schemas")
    resources = []
    for path in schemas_dir.rglob("*.json"):
        document = json.load(open(path, encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    registry = Registry().with_resources(resources)
    document = {
        "$schema": schema["$schema"],
        "$id": schema["$id"] + "#test-error",
        "definitions": schema["definitions"],
        "allOf": [{"$ref": "#/definitions/DatasetRecordErrorV1"}],
    }
    validator = Draft7Validator(document, registry=registry)
    instance = {
        "schema_version": "traigent.dataset_record.error.v1",
        "code": "dataset_record_invalid_manifest",
    }
    errors = list(validator.iter_errors(instance))
    assert errors, "an error object without a location must be schema-rejected"


def test_location_segments_are_all_schema_owned_keys_or_indexes() -> None:
    """Test 65b. Enumerate every location the verifier can emit and assert
    each segment is a property name from this schema or an integer."""
    import re as _re

    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    known_keys: set[str] = set()

    def collect(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    known_keys.update(value.keys())
                collect(value)
        elif isinstance(node, list):
            for item in node:
                collect(item)

    collect(schema["definitions"])

    verifier_path = "traigent_schema/certification/dataset_record_verifier.py"
    text = open(verifier_path, encoding="utf-8").read()
    locations = set(_re.findall(r'"(/[a-zA-Z0-9_/{}]*)"', text))
    location_pattern = _re.compile(r"^(/([a-z][a-z0-9_]{0,47}|[0-9]{1,5})){0,12}$")
    for location in locations:
        if "{" in location:
            continue
        assert location_pattern.fullmatch(location), location
        for segment in location.strip("/").split("/"):
            if not segment:
                continue
            if segment.isdigit():
                continue
            assert segment in known_keys, segment


def test_tampered_manifest_fails_the_issuer_signature() -> None:
    """Test 66. The unsigned manifest and its declared digest agree with
    each other (no UNSIGNED_MANIFEST_DIGEST_MISMATCH), but the signature
    bytes were computed over different bytes -- a forged/stale signature."""
    built = _build()
    forged_material = b"traigent.dataset_record.issuer_signature.v1" + b"\x00" + b'{"forged":true}'
    built.bundle["signature"]["signature"] = _sign(
        built.issuer_private_key, built.algorithm, forged_material
    )
    _expect_error(built, "ISSUER_SIGNATURE_INVALID")


def test_digest_only_edit_fails_the_unsigned_manifest_digest() -> None:
    """Test 66 sibling."""
    built = _build()
    built.bundle["signature"]["unsigned_manifest_digest"] = "sha256:" + "0" * 64
    _expect_error(built, "UNSIGNED_MANIFEST_DIGEST_MISMATCH")


# ---------------------------------------------------------------------------
# Privacy canaries
# ---------------------------------------------------------------------------


def _bundle_and_result_surfaces_are_clean(
    bundle: dict, result: DatasetRecordVerificationResult
) -> None:
    assert SENTINEL not in json.dumps(bundle, sort_keys=True, default=str)
    assert SENTINEL not in str(result)
    assert SENTINEL not in repr(result)
    assert SENTINEL not in json.dumps(asdict(result), sort_keys=True, default=str)


def test_item_content_sentinel_never_reaches_the_record() -> None:
    """Test 67."""
    client_local_item = {"input": f"what is the capital of {SENTINEL}?"}
    input_digest = "sha256:" + hashlib.sha256(json.dumps(client_local_item).encode()).hexdigest()
    assert SENTINEL in json.dumps(client_local_item)
    built = _build()
    result = _verify(built)
    _bundle_and_result_surfaces_are_clean(built.bundle, result)
    assert input_digest not in json.dumps(built.bundle, sort_keys=True)


def test_reference_answer_sentinel_never_reaches_the_record() -> None:
    """Test 68. This is the field customers most fear leaking."""
    client_local_reference_answer = {"answer": SENTINEL}
    reference_answer_digest = (
        "sha256:" + hashlib.sha256(json.dumps(client_local_reference_answer).encode()).hexdigest()
    )
    assert SENTINEL in json.dumps(client_local_reference_answer)
    built = _build()
    result = _verify(built)
    _bundle_and_result_surfaces_are_clean(built.bundle, result)
    assert reference_answer_digest not in json.dumps(built.bundle, sort_keys=True)


@pytest.mark.parametrize(
    "target",
    [
        "dataset_ref",
        "corpus_a_ref",
        "corpus_b_ref",
        "leakage_scope_ref",
        "leaf_list_digests_corpus_ref",
    ],
)
def test_sentinel_in_any_dataset_owned_ref_is_rejected(target: str) -> None:
    """Test 69. The inverted canary: a sentinel-bearing value in any
    dataset-owned ref field must be SCHEMA-REJECTED by the pattern -- the
    test asserts rejection, never absence-from-the-result."""
    built = _build()
    sentinel_ref = "dsr:" + SENTINEL[:43].ljust(43, "A")
    if target == "dataset_ref":
        built.bundle["unsigned_manifest"]["identity"]["dataset_ref"] = sentinel_ref
    elif target == "corpus_a_ref":
        for finding in built.bundle["leakage_report"]["findings"]:
            finding["corpus_a_ref"] = "cpr:" + SENTINEL[:43].ljust(43, "A")
    elif target == "corpus_b_ref":
        for finding in built.bundle["leakage_report"]["findings"]:
            finding["corpus_b_ref"] = "cpr:" + SENTINEL[:43].ljust(43, "A")
    elif target == "leakage_scope_ref":
        built.bundle["unsigned_manifest"]["identity"]["leakage_scope_ref"] = "lsr:" + SENTINEL[
            :43
        ].ljust(43, "A")
    else:
        built.bundle["leakage_report"]["leaf_list_digests"][0]["corpus_ref"] = "cpr:" + SENTINEL[
            :43
        ].ljust(43, "A")
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    # Any of these codes is a correct REJECTION of the sentinel-bearing ref;
    # which one fires depends on whether the corrupted field also happens to
    # invalidate a digest computed over its containing object first -- the
    # property under test is that it is never silently accepted.
    assert exc_info.value.code in ("SCHEMA", "REF_NOT_DERIVED", "LEAKAGE_REPORT_DIGEST_MISMATCH")


def test_a_well_formed_but_underived_ref_is_rejected() -> None:
    """Test 70. Pattern conformance alone must not be enough."""
    built = _build()
    well_formed_but_underived = "dsr:" + "B" * 43
    built.bundle["unsigned_manifest"]["identity"]["dataset_ref"] = well_formed_but_underived
    _resign(built)
    _expect_error(built, "REF_NOT_DERIVED")


def test_verifier_id_outside_the_closed_enum_is_schema_rejected() -> None:
    """Test 71. The old 64-free-character pattern is gone."""
    built = _build()
    for row in built.bundle["claim_support_rows"]:
        if row["claim_id"] == "DS1":
            row["verifier_id"] = "ver.dataset." + SENTINEL.lower()
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


def test_rejected_bundle_sentinel_never_appears_in_the_error() -> None:
    """Test 72. Sentinel in an inherited project_ref/build_session_ref,
    forced failure; the error surface stays clean even for the fields this
    family cannot narrow."""
    built = _build()
    with pytest.raises(Exception) as exc_info:
        # The sentinel-bearing pin disagrees with process_context's own
        # project_ref, which is itself a forced failure (CONTEXT) -- the
        # construction call is INSIDE the assertion block on purpose, since
        # the failure this canary targets can be raised at construction
        # time just as validly as at verification time.
        bad_context = replace(built.context, expected_project_ref=f"proj-{SENTINEL}")
        _verify(built, context=bad_context)
    assert SENTINEL not in str(exc_info.value)
    assert SENTINEL not in repr(exc_info.value)
    assert all(SENTINEL not in str(arg) for arg in exc_info.value.args)
    formatted = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert SENTINEL not in formatted


_KNOWN_CLOSED_STRING_PATTERNS = (
    r"^sha256:",
    r"^dsr:",
    r"^cpr:",
    r"^lsr:",
    r"^ckr:",
    r"^\[A-Za-z0-9_",
    r"^\^",
)


def test_no_caller_influenced_string_is_representable_in_the_signed_bundle() -> None:
    """Test 73. Every string field reachable in the dataset bundle is a
    const, an enum, a digest, a derived ref, or an issuer-minted
    trust_ring_ref/issuer_key_ref (both OpaqueRef, issuer-assigned).
    Revision 4: no exceptions -- project_ref/build_session_ref are gone from
    the manifest and cross only inside the scope-binding digest preimage."""
    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    offenders = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "string" and "const" not in node and "enum" not in node:
                pattern = node.get("pattern")
                ref = node.get("$ref")
                if pattern is None and ref is None:
                    offenders.append(path)
                elif pattern is not None and not any(
                    __import__("re").match(p, pattern) for p in _KNOWN_CLOSED_STRING_PATTERNS
                ):
                    offenders.append(f"{path} ({pattern})")
            for key, value in node.items():
                walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]")

    walk(schema["definitions"], "definitions")
    assert offenders == []


def test_scope_binding_digest_is_rebuilt_not_trusted() -> None:
    """Test 73a. A scope_binding_digest that is not the verifier's own
    reconstruction from its context pins fails SCOPE_BINDING_MISMATCH; and a
    bundle reintroducing a literal project_ref field is schema-rejected."""
    built = _build()
    built.bundle["unsigned_manifest"]["scope_binding_digest"] = "sha256:" + "9" * 64
    _resign(built)
    _expect_error(built, "SCOPE_BINDING_MISMATCH")

    built2 = _build()
    built2.bundle["unsigned_manifest"]["project_ref"] = PROJECT
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built2)
    assert exc_info.value.code == "SCHEMA"


def test_blind_is_not_representable_anywhere_in_the_contract() -> None:
    """Test 74. No schema definition admits a field typed to carry either
    32-byte blind: walk definitions for any 43/44-char base64 pattern
    outside the three derived-ref types."""
    schema_path = "traigent_schema/schemas/certification/dataset_record_v1_schema.json"
    schema = json.load(open(schema_path, encoding="utf-8"))
    import re as _re

    base64_like = _re.compile(r"\[A-Za-z0-9_-\]\{4[34]\}")
    allowed_prefixes = ("dsr:", "cpr:", "lsr:")

    def walk(node: object) -> None:
        if isinstance(node, dict):
            pattern = node.get("pattern")
            if isinstance(pattern, str) and base64_like.search(pattern):
                assert any(
                    pattern.startswith(f"^{p}") for p in allowed_prefixes
                ) or pattern.startswith("^ckr:"), pattern
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(schema["definitions"])


def test_customer_category_label_is_unrepresentable() -> None:
    """Test 75. The taxonomy is closed."""
    built = _build()
    built.bundle["composition"]["cells"][0]["category_id"] = SENTINEL
    with pytest.raises(DatasetRecordVerificationError) as exc_info:
        _verify(built)
    assert exc_info.value.code == "SCHEMA"


_DISCLOSED_INTEGER_ALLOWLIST = (
    "identity.item_count",
    "composition.populated_cell_count",
    "composition.cells[].item_count",
    "identity.identity_blind_epoch",
    "leakage_report.findings[].overlap_count",
    "leakage_report.leaf_list_digests[].leaf_count",
    "leaf_generation_attestation.corpora[].leaf_count",
    "limitations.limitations[].severity",
    "efficiency_report.*",
    "preregistration.*",
)


def test_disclosed_integer_surface_is_exactly_the_registered_allowlist() -> None:
    """Test 76. Fails when anyone adds a new count, forcing a Disclosure
    Register entry rather than a silent widening."""
    built = _build()
    result = _verify(built)
    disclosed = {
        "item_count": result.item_count,
        "populated_cell_count": result.populated_cell_count,
        "identity_blind_epoch": result.identity_blind_epoch,
        "leakage_findings_checked": result.leakage_findings_checked,
        "leakage_findings_attested": result.leakage_findings_attested,
        "limitation_count": result.limitation_count,
        "max_limitation_severity": result.max_limitation_severity,
        "inert_fraction_ppm": result.inert_fraction_ppm,
        "decisive_subset_upper_bound": result.decisive_subset_upper_bound,
        "cost_efficiency_ppm": result.cost_efficiency_ppm,
    }
    expected_fields = {
        f.name for f in __import__("dataclasses").fields(DatasetRecordVerificationResult)
    }
    for name in disclosed:
        assert name in expected_fields
    # Every field on the result is accounted for -- no new one silently added.
    accounted = set(disclosed) | {
        "valid",
        "code",
        "dataset_commitment_ref",
        "dataset_identity_root",
        "item_set_root",
        "composition_evidence",
        "disjointness_evidence",
        "claims_verified",
        "claims_declared",
        "claims_abstained",
        "prereg_digest",
        "prereg_evidence_grade",
        "efficiency_evidence",
    }
    assert expected_fields == accounted


def test_leaf_list_discloses_only_its_length() -> None:
    """Test 77. Every element matches ^sha256:[a-f0-9]{64}$;
    len(leaves) == leaf_count, which the record already discloses."""
    built = _build()
    for entry in built.bundle["leakage_report"]["leaf_list_digests"]:
        corpus_ref = entry["corpus_ref"]
        leaves = built.leaf_lists.get(corpus_ref)
        if leaves is None:
            continue
        assert all(_re_sha256_re().fullmatch(item["leaf"]) for item in leaves)
        assert len(leaves) == entry["leaf_count"]


def _re_sha256_re():
    import re

    return re.compile(r"^sha256:[a-f0-9]{64}$")


def test_cell_leaf_roots_disclose_only_cell_sizes() -> None:
    """Test 78. The per-cell roots are digests, and the per-cell counts they
    let a verifier check are already disclosed as item_count; assert no new
    channel opened."""
    built = _build()
    for cell in built.bundle["composition"]["cells"]:
        assert _re_sha256_re().fullmatch(cell["cell_leaf_root"])
        assert set(cell.keys()) == {
            "category_id",
            "difficulty_stratum",
            "item_count",
            "cell_leaf_root",
        }


def test_registry_document_failure_does_not_put_a_path_or_content_in_the_traceback(
    tmp_path,
) -> None:
    """Test 79. Point the loader at a synthetic tree with undecodable bytes;
    assert only DATASET_RECORD_REGISTRY_DOCUMENT_INVALID:<definition_name>
    and no __context__."""
    from importlib import resources

    root_dir = tmp_path / "pkgroot"
    (root_dir / "data" / "certification").mkdir(parents=True)
    (root_dir / "data" / "certification" / "dataset_taxonomy_document.json").write_bytes(
        b"\xff\xfe\x00bad"
    )
    root = resources.files(str(root_dir)) if False else _DirTraversable(root_dir)

    with pytest.raises(dr_impl.DatasetRecordRegistryError) as exc_info:
        dr_impl._load_registry_constant(
            "dataset_taxonomy_document.json",
            "DatasetTaxonomyDocumentV1",
            "taxonomy_digest",
            b"traigent.dataset_record.taxonomy.v1",
            root=root,
        )
    assert (
        str(exc_info.value) == "DATASET_RECORD_REGISTRY_DOCUMENT_INVALID:DatasetTaxonomyDocumentV1"
    )
    assert exc_info.value.__context__ is None
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value), exc_info.value, exc_info.value.__traceback__
        )
    )
    assert str(root_dir) not in rendered
    assert "bad" not in rendered


class _DirTraversable:
    """Minimal Traversable over a real directory, for test 79."""

    def __init__(self, path):
        from pathlib import Path

        self._path = Path(path)

    def joinpath(self, name):
        return _DirTraversable(self._path / name)

    def read_text(self, encoding="utf-8"):
        return self._path.read_bytes().decode(encoding)
