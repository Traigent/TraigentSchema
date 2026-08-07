# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Executable Sprint-0 contracts for v2 certificates and EvidenceCase."""

from __future__ import annotations

from copy import deepcopy

import pytest

from traigent_schema import SchemaValidator

_VALIDATOR = SchemaValidator(contract="backend")
_DIGEST = "sha256:" + "a" * 64


def _v1_certificate() -> dict[str, object]:
    return {
        "schema_version": "traigent.guarantee_certificate.v1",
        "mode": "keep_accuracy_reduce_cost",
        "anchor_id": "baseline_B",
        "selected_id": "C1",
        "delta": 0.05,
        "epsilon": 0.10,
        "epsilon_acc": 0.05,
        "epsilon_cost": 0.05,
        "eta": 0.05,
        "eta_kind": "relative",
        "ci_method": "empirical_bernstein_fixed",
        "design": "paired",
        "multiplicity_scheme": "mode1_2K",
        "delta_prime_acc": 0.025,
        "delta_prime_cost": 0.0125,
        "per_candidate": {"baseline_B": "anchor", "C1": "selected"},
        "quality_ci": {"C1": [-0.0409809, 0.0409809]},
        "cost_ci": {"C1": [0.001, 0.001]},
        "sample_count": {"C1": 500},
        "cost_treated_as": "deterministic",
        "config_id": "C1",
        "spec_hash": _DIGEST,
        "config_hash": "sha256:" + "b" * 64,
        "scope_notes": ["covers paired evaluation evidence only"],
    }


def _v2_certificate() -> dict[str, object]:
    certificate = _v1_certificate()
    for binding_field in ("config_id", "config_hash", "spec_hash"):
        certificate.pop(binding_field)
    certificate.update(
        schema_version="traigent.guarantee_certificate.v2",
        subject={
            "hash_algorithm": "v1",
            "config_hash": "sha256:" + "b" * 64,
            "config_id": "C1",
            "function_ref": "app.routing:route",
            "environment": "production",
            "best_config_schema_version": "traigent.best_config.v2",
        },
    )
    return certificate


def _evidence_case(*, basis: str = "OBSERVED_ONLY") -> dict[str, object]:
    certified = basis == "SUPPORTED_RECOMMENDATION"
    return {
        "schema_version": "traigent.smartops.evidence_case.v1",
        "publication_basis": basis,
        "evidence": {
            "evidence_snapshot_hash": "ev_0123456789abcdefghijklmnopqrstuvwxyzAB",
            "certified": certified,
            "policy_eligible": certified,
            "certificate_ref": "certificate_0123456789abcdef" if certified else None,
        },
        "provenance": {
            "lifecycle_id": "lifecycle_0123456789abcdef",
            "lifecycle_revision": 7,
            "source_hash": "c" * 64,
            "lineage_hash": "d" * 64,
            "policy_version": "planner-v2-policy-2026.08",
            "policy_hash": "e" * 64,
        },
    }


def _errors(payload: dict[str, object], schema: str) -> list[str]:
    return _VALIDATOR.validate_json(payload, schema)


def test_complete_v2_certificate_accepts_the_statistical_body() -> None:
    assert _errors(_v2_certificate(), "guarantee_certificate_v2_schema") == []


@pytest.mark.parametrize("field", ["spec_hash", "config_hash", "config_id"])
def test_v2_rejects_top_level_v1_binding_members(field: str) -> None:
    hybrid = _v2_certificate()
    hybrid[field] = _DIGEST if field != "config_id" else "C1"
    assert _errors(hybrid, "guarantee_certificate_v2_schema"), field


def test_v2_rejects_hybrid_bindings_and_incomplete_or_unknown_subjects() -> None:
    hybrid = _v2_certificate()
    hybrid.update(spec_hash=_DIGEST, config_hash=_DIGEST, config_id="C1")
    assert _errors(hybrid, "guarantee_certificate_v2_schema")

    for member in tuple(_v2_certificate()["subject"]):
        missing = _v2_certificate()
        del missing["subject"][member]
        assert _errors(missing, "guarantee_certificate_v2_schema"), member

    unknown_algorithm = _v2_certificate()
    unknown_algorithm["subject"]["hash_algorithm"] = "v2"
    assert _errors(unknown_algorithm, "guarantee_certificate_v2_schema")


def test_v1_certificate_corpus_keeps_its_existing_valid_and_invalid_outcomes() -> None:
    corpus_valid = _v1_certificate()
    assert _errors(corpus_valid, "guarantee_certificate_schema") == []

    corpus_invalid = deepcopy(corpus_valid)
    del corpus_invalid["sample_count"]
    assert _errors(corpus_invalid, "guarantee_certificate_schema")


@pytest.mark.parametrize("basis", ["OBSERVED_ONLY", "SUPPORTED_RECOMMENDATION"])
def test_evidence_case_supports_both_publication_bases(basis: str) -> None:
    assert _errors(_evidence_case(basis=basis), "evidence_case_schema") == []


@pytest.mark.parametrize("field", ["certified", "policy_eligible"])
def test_supported_recommendation_requires_certified_and_policy_eligible(field: str) -> None:
    case = _evidence_case(basis="SUPPORTED_RECOMMENDATION")
    case["evidence"][field] = False
    assert _errors(case, "evidence_case_schema"), field


def test_evidence_case_is_closed_and_excludes_live_keys_and_wall_clock_fields() -> None:
    for container, field, value in (
        (None, "signature", "sig_live"),
        (None, "evaluated_at", "2026-08-07T10:00:00Z"),
        ("evidence", "live_key_id", "key_0123456789abcdef"),
        ("provenance", "observed_at", "2026-08-07T10:00:00Z"),
    ):
        case = _evidence_case()
        target = case if container is None else case[container]
        target[field] = value
        assert _errors(case, "evidence_case_schema"), field
