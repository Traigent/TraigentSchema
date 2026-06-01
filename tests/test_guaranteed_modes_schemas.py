# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the guaranteed optimizer-mode schemas.

Validates the three new optimization schemas (certificate, request, result), that the
result schema ENFORCES the fail-closed invariant (deployable iff CERTIFIED_SELECTION;
selected_config non-null only then), and the Mode-1 baseline_ref conditional.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
CERT_FILE = OPT_DIR / "guarantee_certificate_schema.json"
REQUEST_FILE = OPT_DIR / "guaranteed_selection_request_schema.json"
RESULT_FILE = OPT_DIR / "guaranteed_selection_result_schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in (CERT_FILE, REQUEST_FILE, RESULT_FILE):
        contents = _load(path)
        resources.append((contents["$id"], Resource.from_contents(contents)))
    return Registry().with_resources(resources)


def _validator(path: Path) -> Draft7Validator:
    return Draft7Validator(_load(path), registry=_registry())


def _errors(path: Path, instance: dict) -> list:
    return list(_validator(path).iter_errors(instance))


_CERT = {
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
    "spec_hash": "sha256:" + "a" * 64,
    "config_hash": "sha256:" + "b" * 64,
    "scope_notes": ["covers judged accuracy under the configured evaluator, not ground truth"],
}


def _result(**overrides) -> dict:
    base = {
        "schema_version": "traigent.guaranteed_selection_result.v1",
        "status": "CERTIFIED_SELECTION",
        "deployable": True,
        "selected_config": "C1",
        "fallback_config": "baseline_B",
        "certificate": _CERT,
    }
    base.update(overrides)
    return base


def test_schemas_are_valid_draft7() -> None:
    for path in (CERT_FILE, REQUEST_FILE, RESULT_FILE):
        Draft7Validator.check_schema(_load(path))


def test_valid_certified_result_passes() -> None:
    assert _errors(RESULT_FILE, _result()) == []


def test_valid_certificate_passes() -> None:
    assert _errors(CERT_FILE, _CERT) == []


def test_fail_closed_rejects_no_decision_marked_deployable() -> None:
    bad = _result(status="NO_DECISION_BASELINE_FALLBACK", deployable=True, selected_config=None)
    assert _errors(RESULT_FILE, bad), "NO_DECISION must not be deployable"


def test_fail_closed_rejects_certified_without_selected_config() -> None:
    bad = _result(status="CERTIFIED_SELECTION", deployable=True, selected_config=None)
    assert _errors(RESULT_FILE, bad), "CERTIFIED_SELECTION requires a selected_config"


def test_fail_closed_rejects_best_effort_with_selected_config() -> None:
    bad = _result(
        status="BEST_EFFORT_UNCERTIFIED", deployable=False, selected_config="C2"
    )
    assert _errors(RESULT_FILE, bad), "only CERTIFIED_SELECTION may carry a selected_config"


def test_no_decision_fallback_result_is_valid() -> None:
    ok = _result(status="NO_DECISION_BASELINE_FALLBACK", deployable=False, selected_config=None)
    assert _errors(RESULT_FILE, ok) == []


def test_request_mode1_requires_baseline_ref() -> None:
    req = {
        "schema_version": "traigent.guaranteed_selection_request.v1",
        "selection_mode": "keep_accuracy_reduce_cost",
        "delta": 0.02,
        "epsilon": 0.10,
    }
    assert _errors(REQUEST_FILE, req), "Mode 1 must require baseline_ref"
    req["baseline_ref"] = "baseline_B"
    assert _errors(REQUEST_FILE, req) == []


def test_request_mode2_does_not_require_baseline_ref() -> None:
    req = {
        "schema_version": "traigent.guaranteed_selection_request.v1",
        "selection_mode": "accuracy_then_cost",
        "delta": 0.02,
        "epsilon": 0.10,
    }
    assert _errors(REQUEST_FILE, req) == []


def test_certificate_rejects_unknown_mode() -> None:
    bad = dict(_CERT, mode="maximize_accuracy")
    assert _errors(CERT_FILE, bad), "unknown selection mode must be rejected"


def test_certificate_requires_evidence_fields() -> None:
    """The schema must require every field the GuaranteeCertificate dataclass always carries,
    so a 'certified' result cannot ship an evidence-thin certificate."""
    for field in (
        "selected_id", "eta", "eta_kind", "delta_prime_acc", "delta_prime_cost",
        "quality_ci", "cost_ci", "sample_count",
    ):
        thin = {k: v for k, v in _CERT.items() if k != field}
        assert _errors(CERT_FILE, thin), f"certificate must require {field}"


def test_design_must_be_paired() -> None:
    assert _errors(CERT_FILE, dict(_CERT, design="unpaired"))


_MODE2_CERT = dict(
    _CERT,
    mode="accuracy_then_cost",
    anchor_id="A",
    selected_id="Bm",
    multiplicity_scheme="mode2_pairwise_ordered",
    delta_prime_acc=0.0083333,
    per_candidate={"A": "peak", "Bm": "selected", "Cc": "infeasible"},
    quality_ci={"Bm": [-0.0460243, 0.0260243], "Cc": [-1.0, -0.1324987]},
    cost_ci={"Bm": [0.004, 0.004], "Cc": [0.001, 0.001]},
    sample_count={"Bm": 1000, "Cc": 1000},
    peak_gap_upper_bound=0.0260243,
    composite_gap_to_true_max=0.0760243,
)


def test_valid_mode2_certificate_passes() -> None:
    assert _errors(CERT_FILE, _MODE2_CERT) == []


def test_mode2_certificate_requires_peak_fields() -> None:
    for field in ("peak_gap_upper_bound", "composite_gap_to_true_max"):
        thin = {k: v for k, v in _MODE2_CERT.items() if k != field}
        assert _errors(CERT_FILE, thin), f"accuracy_then_cost must report {field}"


def test_runtime_hashes_must_be_sha256_when_present() -> None:
    bad = dict(_CERT, runtime_config_hash="not-a-hash")
    assert _errors(CERT_FILE, bad)
