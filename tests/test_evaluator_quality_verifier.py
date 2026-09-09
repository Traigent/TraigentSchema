"""P3-V.0: a real, re-signable evaluator-quality bundle and GV1."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from importlib import resources
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2
from traigent_schema.certification import evaluator_quality_verifier as evq
from traigent_schema.certification.process_record_verifier import _ISSUER_SPKI_DOMAIN

ROOT = resources.files("traigent_schema")
SCHEMA = json.loads(
    ROOT.joinpath("schemas")
    .joinpath("certification")
    .joinpath("evaluator_quality_v1_schema.json")
    .read_text(encoding="utf-8")
)
SHA = "sha256:" + "a" * 64
OPAQUE_REF = "trustring:aaaaaaaa"
KEY_REF = "issuerkey:aaaaaaaa"
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUBLIC_DER = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
PUBLIC_B64 = base64.b64encode(PUBLIC_DER).decode("ascii")
PUBLIC_KEY_DIGEST = (
    "sha256:" + hashlib.sha256(_ISSUER_SPKI_DOMAIN + b"\x00" + PUBLIC_DER).hexdigest()
)
PROJECT_REF = "demo_project"
COMMITMENT_REF = "sha256:" + "c" * 64
DEFAULT_CONTEXT = SimpleNamespace(
    expected_project_ref=PROJECT_REF, expected_evaluator_commitment_ref=COMMITMENT_REF
)


def _bootstrap_params(unit: str) -> dict[str, Any]:
    return {
        "interval_kind": "bootstrap_percentile",
        "replicate_count": 2000,
        "resample_unit": unit,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "canonicalization_profile": "jcs_v1",
        "resample_seed_commitment": SHA,
    }


def _analytic_params(kind: str) -> dict[str, Any]:
    return {"interval_kind": kind, "continuity_correction": "none"}


# Every role below is registry-admissible: (estimator_id, sample_unit,
# interval_kind, value_unit) is a real row of
# traigent_schema/data/certification/evaluator_measurement_registry.json, so
# a bundle built from these specs passes the P3-V.3 plan-containment stage
# without any guard needing to be relaxed.
ROLE_SPECS: dict[str, dict[str, Any]] = {
    "calibration_ece": {
        "estimator_id": "expected_calibration_error",
        "sample_unit": "evaluation_item",
        "value_unit": "ppm_unsigned",
        "interval_params": _bootstrap_params("evaluation_item"),
        "direction": "lower_is_better",
    },
    "calibration_slope": {
        "estimator_id": "calibration_slope",
        "sample_unit": "evaluation_item",
        "value_unit": "ppm_unsigned",
        "interval_params": _analytic_params("normal_approximation"),
        "direction": "higher_is_better",
    },
    "agreement_primary": {
        "estimator_id": "cohens_kappa",
        "sample_unit": "evaluation_item",
        "value_unit": "ppm_unsigned",
        "interval_params": _analytic_params("wilson_score"),
        "direction": "higher_is_better",
    },
    "sensitivity_discriminating_power": {
        "estimator_id": "discrimination_rate",
        "sample_unit": "item_pair",
        "value_unit": "ppm_unsigned",
        "interval_params": _analytic_params("wilson_score"),
        "direction": "higher_is_better",
    },
    "sensitivity_false_difference_rate": {
        "estimator_id": "false_difference_rate",
        "sample_unit": "item_pair",
        "value_unit": "ppm_unsigned",
        "interval_params": _analytic_params("wilson_score"),
        "direction": "lower_is_better",
    },
}
for _probe in ("constant_output", "verbosity", "position", "self_preference", "one_token_fool"):
    ROLE_SPECS["reliability_probe_" + _probe] = {
        "estimator_id": "perturbation_agreement_rate",
        "sample_unit": "perturbation_pair",
        "value_unit": "ppm_unsigned",
        "interval_params": _analytic_params("wilson_score"),
        "direction": "higher_is_better",
    }
del _probe

PLANNED_ROLE_ORDER = (
    "calibration_ece",
    "calibration_slope",
    "agreement_primary",
    "sensitivity_discriminating_power",
    "sensitivity_false_difference_rate",
    "reliability_probe_constant_output",
    "reliability_probe_verbosity",
    "reliability_probe_position",
    "reliability_probe_self_preference",
    "reliability_probe_one_token_fool",
)


def _digest(role: str, projection: Any) -> str:
    return evq._role_digest(role, projection)


def test_role_digest_known_answer_includes_domain_and_nul() -> None:
    projection = {"b": 2, "a": 1}
    # This vector is calculated independently from the implementation under
    # test, so either framing byte is load-bearing.
    expected = "sha256:d031fd8d7058aecf5a9c6aa2ce92b3dddd821055d8d8b5bfc2dc53e6c0f0a814"
    assert evq._role_digest("traigent.test.role.v1", projection) == expected


def _merge(value: Any, override: Any) -> Any:
    if isinstance(value, dict) and isinstance(override, dict):
        result = copy.deepcopy(value)
        for key, child in override.items():
            result[key] = _merge(result[key], child) if key in result else copy.deepcopy(child)
        return result
    return copy.deepcopy(override)


def _measurement(role: str, *, point: int = 900000) -> dict[str, Any]:
    spec = ROLE_SPECS[role]
    return {
        "measurement_role": role,
        "estimator_id": spec["estimator_id"],
        "estimator_parameters": {
            "interval_side": "two_sided",
            "direction": spec["direction"],
            "score_scale": "binary",
            "label_kind": "binary",
        },
        "value_unit": spec["value_unit"],
        "point_value": point,
        "interval_low_value": max(0, point - 10000),
        "interval_high_value": min(1000000, point + 10000),
        "interval_params": dict(spec["interval_params"]),
        "nominal_coverage_ppm": 950000,
        "sample_size_n": 100,
        "sample_unit": spec["sample_unit"],
        "basis": "issuer_attested_v1",
        "computation_transcript_digest": None,
    }


def _planned(role: str) -> dict[str, Any]:
    spec = ROLE_SPECS[role]
    direction = spec["direction"]
    return {
        "measurement_role": role,
        "estimator_id": spec["estimator_id"],
        "estimator_parameters": {
            "interval_side": "two_sided",
            "direction": direction,
            "score_scale": "binary",
            "label_kind": "binary",
        },
        "value_unit": spec["value_unit"],
        "interval_params": dict(spec["interval_params"]),
        "nominal_coverage_ppm": 950000,
        "sample_unit": spec["sample_unit"],
        "minimum_sample_size_n": 30,
        "maximum_interval_width_ppm": 200000,
        "threshold_value": 500000,
        "threshold_comparison": "interval_low_ge"
        if direction == "higher_is_better"
        else "interval_high_le",
    }


def _non_claims() -> list[dict[str, str]]:
    ids = [
        "NC_EVQ_NOT_GROUND_TRUTH",
        "NC_EVQ_REFERENCE_SCOPE",
        "NC_EVQ_EVALUATION_SET_SCOPE",
        "NC_EVQ_NO_DISTRIBUTION_SHIFT",
        "NC_EVQ_NO_ADAPTIVE_ADVERSARY",
        "NC_EVQ_PERTURBATION_SET_CLOSED",
        "NC_EVQ_DESCRIPTOR_UNOPENED",
        "NC_EVQ_NO_SELECTION_UNBIASEDNESS",
        "NC_EVQ_NOMINAL_COVERAGE_ONLY",
        "NC_EVQ_FRONTIER_NOT_CAUSAL",
        "NC_EVQ_COST_MEASURED_NOT_QUOTED",
        "NC_EVQ_PLAN_ORDERING_OUT_OF_SCOPE",
        "NC_EVQ_NO_SAFETY_CLAIM",
        "NC_EVQ_INTERVALS_NOT_RECOMPUTED",
        "NC_EVQ_EFFICIENCY_NOT_CLAIMED",
        "NC_EVQ_FRONTIER_NOT_CLAIMED",
        "NC_EVQ_REF_MINTING_IS_AN_ISSUER_OBLIGATION",
        "NC_EVQ_REFS_ARE_A_LINKABILITY_CHANNEL",
    ]
    reasons = [
        "tmpl.noncert.evq_agreement_is_not_correctness.v1",
        "tmpl.noncert.evq_relative_to_pinned_reference.v1",
        "tmpl.noncert.evq_pinned_evaluation_set_only.v1",
        "tmpl.noncert.evq_no_distribution_shift.v1",
        "tmpl.noncert.evq_no_adaptive_adversary.v1",
        "tmpl.noncert.evq_unprobed_failure_not_detectable.v1",
        "tmpl.noncert.evq_descriptor_commitment_unopened.v1",
        "tmpl.noncert.evq_no_selection_unbiasedness_claim.v1",
        "tmpl.noncert.evq_nominal_coverage_only.v1",
        "tmpl.noncert.evq_frontier_descriptive_only.v1",
        "tmpl.noncert.evq_cost_at_pinned_price_list.v1",
        "tmpl.noncert.evq_plan_ordering_out_of_scope.v1",
        "tmpl.noncert.evq_no_safety_claim.v1",
        "tmpl.noncert.evq_intervals_not_recomputed.v1",
        "tmpl.noncert.evq_efficiency_not_claimed.v1",
        "tmpl.noncert.evq_frontier_not_claimed.v1",
        "tmpl.noncert.evq_ref_minting_is_an_issuer_obligation.v1",
        "tmpl.noncert.evq_refs_are_a_linkability_channel.v1",
    ]
    return [
        {"record_type": "non_claim", "non_claim_id": i, "reason_template_id": r}
        for i, r in zip(ids, reasons, strict=True)
    ]


def _base_bundle() -> dict[str, Any]:
    descriptor = {
        "schema_version": "traigent.evaluator_quality.descriptor.v1",
        "disclosure_mode": "private_commitment",
        "evaluator_kind": "llm_judge_rubric",
        "evaluator_version": "1.0.0",
        "determinism": "deterministic",
        "component_commitments": [
            {
                "component": c,
                "commitment_scheme": "sha256_secret_blinded_v1",
                "canonicalization": "jcs_v1",
                "commitment_digest": SHA,
            }
            for c in ("implementation", "rubric", "model_identity", "parameters", "harness")
        ],
    }
    reference = {
        "schema_version": "traigent.evaluator_quality.reference_standard.v1",
        "reference_kind": "verifiable_execution",
        "reference_independence": "evaluator_independent",
        "reference_commitment_digest": SHA,
        "label_count": 1000,
        "rater_count": 0,
        "adjudication_policy": "not_applicable",
        "agreement_ceiling_ppm": 950000,
        "error_floor_ppm": 50000,
    }
    scope = {
        "schema_version": "traigent.evaluator_quality.evaluation_scope.v1",
        "evaluation_set_digest": SHA,
        "evaluation_item_count": 1000,
        "sampling_policy_digest": SHA,
        "sampling_frame": "full_declared_dataset",
        "held_out_status": "held_out_disjoint",
        "selection_set_digest": SHA,
        "estimation_set_digest": SHA,
    }
    pair_set = {
        "known_different_pair_count": 100,
        "known_equivalent_pair_count": 50,
        "equivalence_basis": "identical_configuration",
        "pair_set_digest": SHA,
    }
    policy = {
        "schema_version": "traigent.evaluator_quality.aggregation_policy.v1",
        "weights": [
            {
                "axis": a,
                "weight_ppm": 0 if a == "efficiency" else 250000,
                "required_axis": a != "efficiency",
                "minimum_sample_size_n": 30,
                "maximum_interval_width_ppm": 200000,
            }
            for a in ("calibration", "agreement", "sensitivity", "reliability", "efficiency")
        ],
        "rounding_mode": "round_half_even",
        "efficiency_offset_forbidden": True,
    }
    plan = {
        "schema_version": "traigent.evaluator_quality.declared_plan.v1",
        "evaluator_commitment_digest": SHA,
        "reference_standard_digest": SHA,
        "evaluation_scope_digest": SHA,
        "planned_measurements": [_planned(r) for r in PLANNED_ROLE_ORDER],
        "sensitivity_pair_set": pair_set,
        "perturbation_set_digest": SHA,
        "measurement_registry_digest": SHA,
        "binning_policy": "equal_width",
        "bin_count": 10,
        "aggregation_policy": policy,
    }
    measurements = {
        "schema_version": "traigent.evaluator_quality.measurement_set.v1",
        "evaluation_scope_digest": SHA,
        "measurement_window_start": "2026-09-05T10:11:12Z",
        "measurement_window_end": "2026-09-05T11:11:12Z",
        "calibration": {
            "expected_calibration_error": _measurement("calibration_ece", point=100000),
            "calibration_slope": _measurement("calibration_slope"),
            "binning_policy": "equal_width",
            "bin_count": 10,
        },
        "agreement": {"agreement": _measurement("agreement_primary", point=920000)},
        "sensitivity": {
            "discriminating_power": _measurement("sensitivity_discriminating_power", point=880000),
            "false_difference_rate": _measurement(
                "sensitivity_false_difference_rate", point=100000
            ),
            "pair_set": pair_set,
        },
        "reliability": {
            "probe_results": [
                {
                    "probe_id": p,
                    "status": "measured",
                    "measurement": _measurement("reliability_probe_" + p, point=960000),
                }
                for p in (
                    "constant_output",
                    "verbosity",
                    "position",
                    "self_preference",
                    "one_token_fool",
                )
            ],
            "perturbation_set_digest": SHA,
        },
    }
    claim_material = [
        {
            "claim_id": "EVQ1",
            "tier": 1,
            "verdict": "directional",
            "assertion_template_id": "tmpl.evq.identity_commitment.v1",
        }
    ]
    claim_material += [
        {"claim_id": c, "tier": 3, "verdict": "passed", "assertion_template_id": t}
        for c, t in (
            ("EVQ2", "tmpl.evq.agreement_with_reference.v1"),
            ("EVQ3", "tmpl.evq.calibration_against_reference.v1"),
            ("EVQ4", "tmpl.evq.sensitivity_two_sided.v1"),
            ("EVQ5", "tmpl.evq.reliability_declared_probe_set.v1"),
        )
    ]
    for row in claim_material:
        row.update(
            {
                "descriptor_digest": SHA,
                "reference_standard_digest": SHA,
                "evaluation_scope_digest": SHA,
                "declared_plan_digest": SHA,
            }
        )
    support = [
        {
            "claim_id": "EVQ1",
            "tier": 1,
            "evidence_basis": "client_declared",
            "verdict": "directional",
            "descriptor_digest": SHA,
            "declared_plan_digest": SHA,
            "claim_material_digest": SHA,
        }
    ]
    support += [
        {
            "claim_id": c,
            "tier": 3,
            "evidence_basis": "issuer_verified",
            "verdict": "passed",
            "descriptor_digest": SHA,
            "reference_standard_digest": SHA,
            "evaluation_scope_digest": SHA,
            "declared_plan_digest": SHA,
            "measurement_set_digest": SHA,
            "verifier_result": "pass",
            "claim_material_digest": SHA,
        }
        for c in ("EVQ2", "EVQ3", "EVQ4", "EVQ5")
    ]
    materials = {
        "schema_version": "traigent.certificate_verification_materials.v0",
        "distribution_role": "discovery_only",
        "requires_independent_pins": True,
        "certificate_ref": OPAQUE_REF,
        "issuer": {
            "key_ref": KEY_REF,
            "trust_ring_ref": OPAQUE_REF,
            "algorithm": "ed25519",
            "public_key_der_b64": PUBLIC_B64,
            "public_key_digest": PUBLIC_KEY_DIGEST,
        },
        "relying_party_policy": {
            "compiler_register_versions": {
                "compiler_version": "1.0.0",
                "semantics_manifest_digest": SHA,
                "claim_template_catalog_digest": SHA,
                "prohibited_register_digest": SHA,
                "verifier_catalog_digest": SHA,
                "non_claim_reason_catalog_digest": SHA,
            },
            "verifier_bindings": [
                {"verifier_id": "B1", "verifier_ref": "ver.cert.b1", "verifier_version": "1.0.0"},
                {"verifier_id": "G1", "verifier_ref": "ver.cert.g1", "verifier_version": "1.0.0"},
            ],
        },
        "materials_digest": SHA,
    }
    return {
        "schema_version": "traigent.evaluator_quality.certificate_bundle.v1",
        "descriptor": descriptor,
        "reference_standard": reference,
        "evaluation_scope": scope,
        "declared_plan": plan,
        "measurements": measurements,
        "claim_material": claim_material,
        "claim_support_rows": support,
        "non_claims": _non_claims(),
        "verification_materials_v0": materials,
    }


def _close(bundle: dict[str, Any]) -> dict[str, Any]:
    b = copy.deepcopy(bundle)
    d = evq._DIGEST_DOMAINS
    for name, field, role in (
        ("descriptor", "descriptor_digest", "descriptor"),
        ("reference_standard", "reference_standard_digest", "reference_standard"),
        ("evaluation_scope", "evaluation_scope_digest", "evaluation_scope"),
        ("declared_plan", "declared_plan_digest", "declared_plan"),
        ("measurements", "measurement_set_digest", "measurement_set"),
    ):
        b[name][field] = _digest(d[role], evq._strip_self_digest(b[name], field))
    for row in b["claim_material"]:
        row.update(
            {
                "descriptor_digest": b["descriptor"]["descriptor_digest"],
                "reference_standard_digest": b["reference_standard"]["reference_standard_digest"],
                "evaluation_scope_digest": b["evaluation_scope"]["evaluation_scope_digest"],
                "declared_plan_digest": b["declared_plan"]["declared_plan_digest"],
            }
        )
    claim_digest = _digest(d["claim_material"], b["claim_material"])
    for row in b["claim_support_rows"]:
        row["claim_material_digest"] = claim_digest
        if row["claim_id"] != "EVQ1":
            row.update(
                {
                    "descriptor_digest": b["descriptor"]["descriptor_digest"],
                    "reference_standard_digest": b["reference_standard"][
                        "reference_standard_digest"
                    ],
                    "evaluation_scope_digest": b["evaluation_scope"]["evaluation_scope_digest"],
                    "declared_plan_digest": b["declared_plan"]["declared_plan_digest"],
                    "measurement_set_digest": b["measurements"]["measurement_set_digest"],
                }
            )
    overall = {
        "verdict": "passed",
        "instrument_adequacy_verdict": "passed",
        "overall_quality_ppm": 915000,
        "aggregation_policy_digest": _digest(
            d["declared_plan"], b["declared_plan"]["aggregation_policy"]
        ),
    }
    scope_binding_digest = evq._role_digest(
        evq._EVALUATOR_SCOPE_BINDING_DOMAIN,
        {"schema_version": evq._EVALUATOR_SCOPE_BINDING_DOMAIN, "project_ref": PROJECT_REF},
    )
    registry_digests = {
        stem: evq._role_digest(evq._domain(stem), evq._load_evaluator_quality_document(stem))
        for stem in ("measurement_registry", "perturbation_set", "assertion_templates")
    }
    b["unsigned_manifest"] = {
        "schema_version": "traigent.evaluator_quality.unsigned_manifest.v1",
        "scope_binding_digest": scope_binding_digest,
        "evaluator_commitment_ref": COMMITMENT_REF,
        "evaluator_commitment": {
            "schema_version": "traigent.evaluator_quality.commitment.v1",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization": "jcs_v1",
            "artifact_kind": "evaluator",
            "commitment_digest": COMMITMENT_REF,
        },
        "descriptor_digest": b["descriptor"]["descriptor_digest"],
        "descriptor_opening_digest": None,
        "reference_standard_digest": b["reference_standard"]["reference_standard_digest"],
        "evaluation_scope_digest": b["evaluation_scope"]["evaluation_scope_digest"],
        "declared_plan_digest": b["declared_plan"]["declared_plan_digest"],
        "measurement_registry_digest": registry_digests["measurement_registry"],
        "perturbation_set_digest": registry_digests["perturbation_set"],
        "assertion_templates_digest": registry_digests["assertion_templates"],
        "measurement_set_digest": b["measurements"]["measurement_set_digest"],
        "frontier_digest": None,
        "claim_material_digest": claim_digest,
        "claim_support_rows_digest": _digest(d["claim_support_rows"], b["claim_support_rows"]),
        "non_claims_digest": _digest(d["non_claims"], b["non_claims"]),
        "overall": overall,
        "trust_ring_ref": OPAQUE_REF,
        "issuer_key_ref": KEY_REF,
        "issuer_signature_algorithm": "ed25519",
        "coverage": SCHEMA["definitions"]["EvaluatorQualityUnsignedManifestV1"]["properties"][
            "coverage"
        ]["const"],
    }
    b["signature"] = {
        "schema_version": "traigent.evaluator_quality.signature.v1",
        "algorithm": "ed25519",
        "issuer_key_ref": KEY_REF,
        "trust_ring_ref": OPAQUE_REF,
        "signed_payload": "unsigned_evaluator_quality_manifest",
        "unsigned_manifest_digest": _digest(d["unsigned_manifest"], b["unsigned_manifest"]),
        "signature": "",
    }
    material = (
        d["issuer_signature"].encode() + b"\0" + fp2.canonicalize(b["unsigned_manifest"]).encode()
    )
    b["signature"]["signature"] = base64.b64encode(PRIVATE_KEY.sign(material)).decode("ascii")
    return b


def build_bundle(**overrides: Any) -> dict[str, Any]:
    """Return a schema-valid, digest-closed, genuinely signed bundle."""
    return _close(_merge(_base_bundle(), overrides))


def break_(field: str, value: Any) -> dict[str, Any]:
    """Change one top-level field, then rebuild every dependent binding."""
    return build_bundle(**{field: value})


def _validator() -> Draft7Validator:
    registry = Registry()
    for path in ROOT.joinpath("schemas").rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return Draft7Validator(SCHEMA, registry=registry)


def _assert_digests(bundle: dict[str, Any]) -> None:
    d = evq._DIGEST_DOMAINS
    for name, field, role in (
        ("descriptor", "descriptor_digest", "descriptor"),
        ("reference_standard", "reference_standard_digest", "reference_standard"),
        ("evaluation_scope", "evaluation_scope_digest", "evaluation_scope"),
        ("declared_plan", "declared_plan_digest", "declared_plan"),
        ("measurements", "measurement_set_digest", "measurement_set"),
    ):
        assert bundle[name][field] == _digest(d[role], evq._strip_self_digest(bundle[name], field))
    m = bundle["unsigned_manifest"]
    assert m["claim_material_digest"] == _digest(d["claim_material"], bundle["claim_material"])
    assert m["claim_support_rows_digest"] == _digest(
        d["claim_support_rows"], bundle["claim_support_rows"]
    )
    assert m["non_claims_digest"] == _digest(d["non_claims"], bundle["non_claims"])
    assert bundle["signature"]["unsigned_manifest_digest"] == _digest(d["unsigned_manifest"], m)


def test_gv1_validates_digest_closes_and_signature_verifies() -> None:
    bundle = build_bundle()
    errors = list(_validator().iter_errors(bundle))
    assert not errors, errors
    _assert_digests(bundle)
    material = (
        evq._DIGEST_DOMAINS["issuer_signature"].encode()
        + b"\0"
        + fp2.canonicalize(bundle["unsigned_manifest"]).encode()
    )
    PRIVATE_KEY.public_key().verify(base64.b64decode(bundle["signature"]["signature"]), material)
    assert tuple(row["non_claim_id"] for row in bundle["non_claims"]) == tuple(
        row["non_claim_id"] for row in _non_claims()
    )
    assert (
        bundle["unsigned_manifest"]["overall"]["overall_quality_ppm"]
        == round(sum(v * 250000 / 1000000 for v in (900000, 920000, 880000, 960000)))
        == 915000
    )


def test_field_locations_are_schema_derived() -> None:
    assert evq.EVALUATOR_QUALITY_FIELD_LOCATIONS == frozenset(
        SCHEMA["definitions"]["EvaluatorQualityFieldLocationV1"]["enum"]
    )


def test_measurement_registry_matches_schema_enum_and_order() -> None:
    document = evq._load_evaluator_quality_document("measurement_registry")
    actual = [entry["estimator_id"] for entry in document["estimators"]]
    expected = SCHEMA["definitions"]["EstimatorIdV1"]["enum"]
    assert actual == expected


def test_perturbation_registry_matches_schema_enum_and_order() -> None:
    document = evq._load_evaluator_quality_document("perturbation_set")
    actual = [entry["probe_id"] for entry in document["probes"]]
    expected = SCHEMA["definitions"]["PerturbationProbeIdV1"]["enum"]
    assert actual == expected
    assert all(type(entry["required"]) is bool for entry in document["probes"])
    assert all(entry["skip_reasons"] for entry in document["probes"])


def test_assertion_template_registry_matches_schema_enum_and_emission() -> None:
    document = evq._load_evaluator_quality_document("assertion_templates")
    actual = [entry["template_id"] for entry in document["templates"]]
    expected = SCHEMA["definitions"]["EvaluatorAssertionTemplateIdV1"]["enum"]
    assert actual == expected
    assert [entry["emittable"] for entry in document["templates"][-2:]] == [False, False]


def test_patched_digest_without_closure_is_rejected() -> None:
    bundle = build_bundle()
    bundle["descriptor"]["descriptor_digest"] = SHA
    with pytest.raises(AssertionError):
        _assert_digests(bundle)


@pytest.mark.parametrize(
    ("stem", "filename"),
    [
        (stem, filename)
        for stem in ("measurement_registry", "perturbation_set", "assertion_templates")
        for filename in (
            f"evaluator_{stem}.json",
            f"evaluator_{stem}.digest.json",
        )
    ],
)
def test_package_data_corruption_is_content_free_and_reload_recovers(
    monkeypatch: pytest.MonkeyPatch, stem: str, filename: str
) -> None:
    original = evq._read_evaluator_quality_package_json
    sentinel = f"SENTINEL_{stem}_{filename}"

    def corrupted(name: str) -> Any:
        value = original(name)
        if name == filename:
            if isinstance(value, dict):
                value = copy.deepcopy(value)
                if name.endswith(".digest.json"):
                    value["digest"] = sentinel
                else:
                    value["sentinel"] = sentinel
            else:
                value = sentinel
        return value

    evq._load_evaluator_quality_document.cache_clear()
    monkeypatch.setattr(evq, "_read_evaluator_quality_package_json", corrupted)
    with pytest.raises(evq.EvaluatorQualityVerificationError) as caught:
        evq._load_evaluator_quality_document(stem)
    exc = caught.value
    rendered = "\n".join(
        (str(exc), repr(exc), repr(exc.args), repr(exc.__cause__), repr(exc.__context__))
    )
    assert exc.code == "REGISTRY_DIGEST_MISMATCH"
    assert sentinel not in rendered
    assert sentinel not in "".join(__import__("traceback").format_exception(exc))

    monkeypatch.setattr(evq, "_read_evaluator_quality_package_json", original)
    evq._load_evaluator_quality_document.cache_clear()
    assert isinstance(evq._load_evaluator_quality_document(stem), dict)


def test_p3v2_private_guard_rejection_codes_are_reachable() -> None:
    exact = {key: 0 for key in evq._EVALUATOR_BUNDLE_MEMBERS}
    cases = [
        ("EVALUATOR_BUNDLE_SHAPE", lambda: evq._check_bundle_shape({})),
        (
            "EVALUATOR_STRICT_INTEGER",
            lambda: evq._check_bundle_shape({**exact, "schema_version": 1.0}),
        ),
        ("EVALUATOR_SCHEMA", lambda: evq._check_schema({})),
        (
            "MEASUREMENT_ROLE_DUPLICATE",
            lambda: evq._check_semantic_uniqueness(
                build_bundle(
                    declared_plan={
                        "planned_measurements": [
                            {"measurement_role": "duplicate"},
                            {"measurement_role": "duplicate"},
                        ]
                    }
                )
            ),
        ),
        (
            "SCOPE_BINDING_MISMATCH",
            lambda: evq._check_scope_binding(
                build_bundle(), SimpleNamespace(expected_project_ref="wrong")
            ),
        ),
        (
            "EVALUATOR_ARTIFACT_DIGEST_MISMATCH",
            lambda: evq._check_artifact_digests(
                (lambda b: (b["descriptor"].update(evaluator_version="changed"), b)[1])(
                    build_bundle()
                )
            ),
        ),
        (
            "REGISTRY_DIGEST_MISMATCH",
            lambda: evq._check_registry_digests(
                (lambda b: (b["unsigned_manifest"].update(measurement_registry_digest=SHA), b)[1])(
                    build_bundle()
                )
            ),
        ),
        (
            "EVALUATOR_UNSIGNED_MANIFEST_MISMATCH",
            lambda: evq._check_manifest_signature(
                (lambda b: (b["unsigned_manifest"].update(coverage=[]), b)[1])(build_bundle())
            ),
        ),
        (
            "EVALUATOR_MANIFEST_DIGEST_MISMATCH",
            lambda: evq._check_manifest_signature(
                (lambda b: (b["signature"].update(unsigned_manifest_digest=SHA), b)[1])(
                    build_bundle()
                )
            ),
        ),
        (
            "EVALUATOR_KEY_RING_MISMATCH",
            lambda: evq._check_manifest_signature(
                (lambda b: (b["signature"].update(issuer_key_ref="issuerkey:bbbbbbbb"), b)[1])(
                    build_bundle()
                )
            ),
        ),
        (
            "EVALUATOR_KEY_RING_MISMATCH",
            lambda: evq._check_manifest_signature(
                (
                    lambda b: (
                        b["verification_materials_v0"]["issuer"].update(public_key_digest=SHA),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
        (
            "EVALUATOR_ISSUER_SIGNATURE_INVALID",
            lambda: evq._check_manifest_signature(
                (
                    lambda b: (
                        b["signature"].update(signature=base64.b64encode(b"\x00" * 64).decode()),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
        (
            "EVALUATOR_COMMITMENT_MISMATCH",
            lambda: evq._check_commitment(
                build_bundle(),
                SimpleNamespace(expected_evaluator_commitment_ref="sha256:" + "b" * 64),
            ),
        ),
        ("CONTEXT", lambda: evq._check_scope_binding(build_bundle(), None)),
        ("CONTEXT", lambda: evq._check_commitment(build_bundle(), None)),
        ("EVALUATOR_CANONICALIZATION", lambda: evq._role_digest("test", float("nan"))),
        (
            "DECLARED_PLAN_SCOPE_VIOLATION",
            lambda: evq._check_plan_containment(
                (
                    lambda b: (
                        b["measurements"]["agreement"]["agreement"].update(
                            estimator_id="fleiss_kappa"
                        ),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
        (
            "ESTIMATOR_NOT_REGISTERED",
            lambda: evq._check_measurement_registry_admissibility(
                {
                    "estimator_id": "not_a_real_estimator",
                    "value_unit": "ppm_unsigned",
                    "sample_unit": "evaluation_item",
                    "interval_params": {"interval_kind": "wilson_score"},
                }
            ),
        ),
        (
            "UNIT_NOT_ADMISSIBLE",
            lambda: evq._check_measurement_registry_admissibility(
                {
                    "estimator_id": "cohens_kappa",
                    "value_unit": "microusd",
                    "sample_unit": "evaluation_item",
                    "interval_params": {"interval_kind": "wilson_score"},
                }
            ),
        ),
        (
            "INTERVAL_MALFORMED",
            lambda: evq._check_interval_well_formed(
                {
                    "interval_low_value": 10,
                    "point_value": 5,
                    "interval_high_value": 20,
                    "value_unit": "ppm_unsigned",
                }
            ),
        ),
        (
            "RESAMPLE_UNIT_MISMATCH",
            lambda: evq._check_resample_unit(
                {
                    "interval_params": {
                        "interval_kind": "bootstrap_percentile",
                        "resample_unit": "item_pair",
                    },
                    "sample_unit": "evaluation_item",
                }
            ),
        ),
        (
            "SAMPLE_SIZE_INSUFFICIENT",
            lambda: evq._check_plan_containment(
                (
                    lambda b: (
                        b["measurements"]["agreement"]["agreement"].update(sample_size_n=2),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
        (
            "INTERVAL_WIDTH_EXCEEDED",
            lambda: evq._check_plan_containment(
                (
                    lambda b: (
                        b["measurements"]["agreement"]["agreement"].update(
                            interval_low_value=0, interval_high_value=1000000
                        ),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
        (
            "THRESHOLD_NOT_MET",
            lambda: evq._check_plan_containment(
                (
                    lambda b: (
                        b["measurements"]["agreement"]["agreement"].update(
                            point_value=100000, interval_low_value=90000, interval_high_value=110000
                        ),
                        b,
                    )[1]
                )(build_bundle())
            ),
        ),
    ]
    for code, action in cases:
        with pytest.raises(evq.EvaluatorQualityVerificationError, match=code):
            action()


def _expect(
    bundle: dict[str, Any], code: str, *, context: object = DEFAULT_CONTEXT
) -> evq.EvaluatorQualityVerificationError:
    with pytest.raises(evq.EvaluatorQualityVerificationError) as caught:
        evq._verify_evaluator_quality_private(bundle, context=context)
    assert caught.value.code == code, caught.value.code
    return caught.value


def test_private_pipeline_accepts_a_fully_closed_bundle() -> None:
    assert evq._verify_evaluator_quality_private(build_bundle(), context=DEFAULT_CONTEXT) is None


# --- Step-0 P1-1: the issuer signature check now has real coverage --------


def test_forged_signature_is_rejected_full_pipeline() -> None:
    bundle = build_bundle()
    bundle["signature"]["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    _expect(bundle, "EVALUATOR_ISSUER_SIGNATURE_INVALID")


def test_valid_signature_over_a_tampered_manifest_is_rejected_full_pipeline() -> None:
    bundle = build_bundle()
    original_signature = bundle["signature"]["signature"]
    bundle["unsigned_manifest"]["overall"]["overall_quality_ppm"] = 915001
    bundle["signature"]["unsigned_manifest_digest"] = evq._role_digest(
        evq._domain("unsigned_manifest"), bundle["unsigned_manifest"]
    )
    bundle["signature"]["signature"] = original_signature
    _expect(bundle, "EVALUATOR_ISSUER_SIGNATURE_INVALID")


# --- Step-0 P2-2: key-material failure is its own code, not the broad catch


def test_malformed_issuer_key_material_is_key_ring_mismatch_not_signature_invalid() -> None:
    bundle = build_bundle(verification_materials_v0={"issuer": {"public_key_digest": SHA}})
    _expect(bundle, "EVALUATOR_KEY_RING_MISMATCH")


def test_delete_signature_verification_guard_lets_forged_signature_through() -> None:
    """Mutate-the-guard probe for S7-sigverify (packet-2 review probe, template G).

    P3-tl-review-1 P1-3: the previous version of this test exec'd the
    mutated module into a namespace with no ``__file__``, so
    ``_evaluator_quality_validator()``'s ``Path(__file__)`` raised
    ``NameError`` on ANY input and the test's ``pytest.raises`` passed
    vacuously regardless of what the mutation did (probe V1). Passing
    ``__file__`` here (probe V2) exposes the true property: with
    ``_verify_signature`` deleted, nothing else in the pipeline rejects a
    forged signature, so the mutated verifier ACCEPTS both a valid bundle
    (the mutation is targeted, not a general break) and a forged one (the
    guard was the only thing standing between a forged signature and
    acceptance -- this is exactly why it is load-bearing). The converse --
    that a forged signature IS rejected with the guard present -- is
    covered separately by ``test_forged_signature_is_rejected_full_pipeline``
    against the real, unmutated module.
    """
    source = Path(evq.__file__).read_text()
    target = '        _verify_signature(key, issuer["algorithm"], material, signature["signature"])'
    assert target in source
    mutated = source.replace(target, "        pass", 1)
    namespace: dict[str, Any] = {"__name__": "evq_mutated", "__file__": evq.__file__}
    exec(compile(mutated, evq.__file__, "exec"), namespace)

    valid = build_bundle()
    assert namespace["_verify_evaluator_quality_private"](valid, context=DEFAULT_CONTEXT) is None

    forged = build_bundle()
    forged["signature"]["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    assert namespace["_verify_evaluator_quality_private"](forged, context=DEFAULT_CONTEXT) is None


# --- Step-0 P1-2: S5's manifest-side digests are covered, one per artifact -


def test_claim_material_manifest_side_digest_mismatch() -> None:
    bundle = build_bundle()
    bundle["claim_material"][1]["reference_standard_digest"] = SHA
    _expect(bundle, "EVALUATOR_ARTIFACT_DIGEST_MISMATCH")


def test_claim_support_rows_manifest_side_digest_mismatch() -> None:
    bundle = build_bundle()
    bundle["claim_support_rows"][1]["measurement_set_digest"] = SHA
    _expect(bundle, "EVALUATOR_ARTIFACT_DIGEST_MISMATCH")


def test_non_claims_manifest_side_digest_mismatch() -> None:
    """P3-tl-review-1 P2-4: no content mutation of non_claims is schema-valid
    (all 18 items are const-pinned), but the MANIFEST's own
    non_claims_digest field is an unconstrained digest string, so corrupting
    it needs no content mutation and models a tampered manifest directly."""
    bundle = build_bundle()
    bundle["unsigned_manifest"]["non_claims_digest"] = SHA
    _expect(bundle, "EVALUATOR_ARTIFACT_DIGEST_MISMATCH")


# --- Step-0 item 4: ordering, not just reachability ------------------------


def test_ordering_s3_duplicate_before_s4_scope_binding() -> None:
    duplicate_plan = [_planned(r) for r in PLANNED_ROLE_ORDER]
    extra = {**dict(duplicate_plan[0]), "minimum_sample_size_n": 999}
    bundle = build_bundle(declared_plan={"planned_measurements": [*duplicate_plan, extra]})
    _expect(
        bundle,
        "MEASUREMENT_ROLE_DUPLICATE",
        context=SimpleNamespace(
            expected_project_ref="wrong", expected_evaluator_commitment_ref=COMMITMENT_REF
        ),
    )


def test_ordering_s4_scope_binding_before_s5_artifact_digest() -> None:
    bundle = build_bundle()
    bundle["descriptor"]["evaluator_version"] = "9.9.9"
    _expect(
        bundle,
        "SCOPE_BINDING_MISMATCH",
        context=SimpleNamespace(
            expected_project_ref="wrong", expected_evaluator_commitment_ref=COMMITMENT_REF
        ),
    )


def test_ordering_s7_signature_before_s9_commitment() -> None:
    bundle = build_bundle()
    bundle["signature"]["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    _expect(
        bundle,
        "EVALUATOR_ISSUER_SIGNATURE_INVALID",
        context=SimpleNamespace(
            expected_project_ref=PROJECT_REF, expected_evaluator_commitment_ref="sha256:" + "b" * 64
        ),
    )


def test_ordering_s9_commitment_before_plan_containment() -> None:
    bundle = build_bundle(
        measurements={"agreement": {"agreement": {"estimator_id": "fleiss_kappa"}}}
    )
    _expect(
        bundle,
        "EVALUATOR_COMMITMENT_MISMATCH",
        context=SimpleNamespace(
            expected_project_ref=PROJECT_REF, expected_evaluator_commitment_ref="sha256:" + "b" * 64
        ),
    )


# --- P3-tl-review-1 answer (c): the load-bearing missing ordering pairs ----


def test_ordering_s1_bundle_shape_before_s2_schema() -> None:
    """A dict missing the fixed top-level member set must fail EVALUATOR_BUNDLE_SHAPE
    at S1, never fall through to the schema validator (or worse, to S3's
    unguarded bundle["declared_plan"]["planned_measurements"] indexing)."""
    _expect({"schema_version": 1}, "EVALUATOR_BUNDLE_SHAPE")


def test_ordering_s2_schema_before_s3_semantic_uniqueness() -> None:
    """A schema-invalid declared_plan.planned_measurements (None, not a list)
    must be rejected at S2; S3 indexes that field unguarded and would raise
    TypeError -- outside the closed vocabulary -- if it ran first."""
    bundle = build_bundle(declared_plan={"planned_measurements": None})
    _expect(bundle, "EVALUATOR_SCHEMA")


def test_ordering_s5_artifact_digest_before_s6_registry_digest() -> None:
    bundle = build_bundle()
    bundle["descriptor"]["evaluator_version"] = "9.9.9"
    bundle["unsigned_manifest"]["measurement_registry_digest"] = SHA
    _expect(bundle, "EVALUATOR_ARTIFACT_DIGEST_MISMATCH")


def test_ordering_s6_registry_digest_before_s7_manifest_signature() -> None:
    bundle = build_bundle()
    bundle["unsigned_manifest"]["measurement_registry_digest"] = SHA
    bundle["signature"]["unsigned_manifest_digest"] = SHA
    _expect(bundle, "REGISTRY_DIGEST_MISMATCH")


# --- Step-0 item 5: MEASUREMENT_ROLE_DUPLICATE through the full pipeline ---


def test_measurement_role_duplicate_same_role_different_payload_through_pipeline() -> None:
    """The #458 regression: two plan entries share a role with a different payload."""
    duplicate_plan = [_planned(r) for r in PLANNED_ROLE_ORDER]
    extra = {
        **dict(duplicate_plan[1]),
        "measurement_role": "calibration_ece",
        "minimum_sample_size_n": 999,
    }
    bundle = build_bundle(declared_plan={"planned_measurements": [*duplicate_plan, extra]})
    _expect(bundle, "MEASUREMENT_ROLE_DUPLICATE")


# --- Step-0 item 6: context pin is mandatory for S4/S9 ---------------------


def test_missing_context_fails_closed_at_scope_binding() -> None:
    _expect(build_bundle(), "CONTEXT", context=None)


def test_missing_context_fails_closed_at_commitment() -> None:
    _expect(build_bundle(), "CONTEXT", context=SimpleNamespace(expected_project_ref=PROJECT_REF))


# --- P3-1: genuine on-disk sidecar corruption, all three sidecars ----------


@pytest.mark.parametrize(
    "stem", ["measurement_registry", "perturbation_set", "assertion_templates"]
)
def test_sidecar_on_disk_corruption_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stem: str
) -> None:
    src = resources.files("traigent_schema").joinpath("data").joinpath("certification")
    data_dir = tmp_path / "data" / "certification"
    data_dir.mkdir(parents=True)
    for filename in (f"evaluator_{stem}.json", f"evaluator_{stem}.digest.json"):
        (data_dir / filename).write_bytes(src.joinpath(filename).read_bytes())

    sidecar_path = data_dir / f"evaluator_{stem}.digest.json"
    corrupted = json.loads(sidecar_path.read_text())
    corrupted["digest"] = "sha256:" + "0" * 64
    sidecar_path.write_text(json.dumps(corrupted))

    class _FakePackage:
        def joinpath(self, *parts: str) -> Path:
            return tmp_path.joinpath(*parts)

    monkeypatch.setattr(evq.resources, "files", lambda _name: _FakePackage())
    evq._load_evaluator_quality_document.cache_clear()
    try:
        with pytest.raises(evq.EvaluatorQualityVerificationError) as caught:
            evq._load_evaluator_quality_document(stem)
        assert caught.value.code == "REGISTRY_DIGEST_MISMATCH"
    finally:
        monkeypatch.undo()
        evq._load_evaluator_quality_document.cache_clear()
        assert isinstance(evq._load_evaluator_quality_document(stem), dict)


# --- P3-V.3: the semantic layer, each reached through the full pipeline ----


def test_declared_plan_scope_violation_estimator_shopping() -> None:
    """Headline post-hoc test: a claim-level (not role-level) key would pass this."""
    bundle = build_bundle(
        measurements={"agreement": {"agreement": {"estimator_id": "fleiss_kappa"}}}
    )
    _expect(bundle, "DECLARED_PLAN_SCOPE_VIOLATION")


def test_declared_plan_scope_violation_coverage_level_shopping() -> None:
    bundle = build_bundle(
        measurements={"agreement": {"agreement": {"nominal_coverage_ppm": 900000}}}
    )
    _expect(bundle, "DECLARED_PLAN_SCOPE_VIOLATION")


def test_declared_plan_scope_violation_estimator_parameters_diverge() -> None:
    """P3-tl-review-1 P2-1 / probe D2: estimator_parameters (direction,
    interval_side, score_scale, label_kind) was outside the containment
    tuple -- a measurement could flip direction against the plan and pass."""
    bundle = build_bundle(
        measurements={
            "calibration": {
                "calibration_slope": {
                    "estimator_parameters": {
                        "interval_side": "upper_one_sided",
                        "direction": "lower_is_better",
                        "score_scale": "binary",
                        "label_kind": "binary",
                    }
                }
            }
        }
    )
    _expect(bundle, "DECLARED_PLAN_SCOPE_VIOLATION")


def test_declared_plan_direction_threshold_comparison_coupling() -> None:
    """P3-tl-review-1 P1-1 / probe E4: a lower_is_better role declaring
    interval_low_ge (with a floor threshold) is direction-shopping -- the
    schema pins the coupling in prose only, so the verifier must enforce it."""
    shopped_plan = [
        {
            **_planned(r),
            **(
                {"threshold_comparison": "interval_low_ge", "threshold_value": -1000000}
                if r == "sensitivity_false_difference_rate"
                else {}
            ),
        }
        for r in PLANNED_ROLE_ORDER
    ]
    bundle = build_bundle(
        declared_plan={"planned_measurements": shopped_plan},
        measurements={
            "sensitivity": {
                "false_difference_rate": {
                    "point_value": 990000,
                    "interval_low_value": 980000,
                    "interval_high_value": 1000000,
                }
            }
        },
    )
    _expect(bundle, "DECLARED_PLAN_SCOPE_VIOLATION")


def test_registry_measurement_role_not_admissible_for_estimator() -> None:
    """P3-tl-review-1 P1-4 / probe D1: cohens_kappa is registry-admissible
    only for agreement_primary; using it for calibration_slope must be
    rejected even though estimator_id, unit and interval_kind all pass."""
    shopped_plan = [
        {
            **_planned(r),
            **(
                {
                    "estimator_id": "cohens_kappa",
                    "interval_params": _analytic_params("wilson_score"),
                }
                if r == "calibration_slope"
                else {}
            ),
        }
        for r in PLANNED_ROLE_ORDER
    ]
    bundle = build_bundle(
        declared_plan={"planned_measurements": shopped_plan},
        measurements={
            "calibration": {
                "calibration_slope": {
                    "estimator_id": "cohens_kappa",
                    "interval_params": _analytic_params("wilson_score"),
                }
            }
        },
    )
    _expect(bundle, "ESTIMATOR_PARAMS_NOT_ADMISSIBLE")


def test_measured_role_absent_from_plan_is_scope_violation() -> None:
    """P3-tl-review-1 P2-2 / probe F1: a measured-but-unplanned role received
    zero validation before (registry admissibility, interval well-formedness,
    threshold -- all skipped). Decision: it is a DECLARED_PLAN_SCOPE_VIOLATION,
    the converse of the plan-requires-but-never-measured case EVQ4/EVQ5 own."""
    bundle = build_bundle(
        declared_plan={
            "planned_measurements": [
                _planned(r) for r in PLANNED_ROLE_ORDER if r != "agreement_primary"
            ]
        }
    )
    _expect(bundle, "DECLARED_PLAN_SCOPE_VIOLATION")


def test_str_subclass_in_verification_materials_reaches_canonicalization_guard() -> None:
    """P3-tl-review-1 P2-3 / probe A1: S1's _walk_strict_values uses
    isinstance() (subclasses pass); fp2._encode dispatches on exact type by
    design. A str subclass placed in verification_materials_v0 -- a region
    no EARLIER stage canonicalizes -- survives S1 and jsonschema (both
    isinstance-based) and must still be rejected by the S11 canonicalization
    tail. Proves the tail is load-bearing, not dead code."""

    class SubStr(str):
        pass

    bundle = build_bundle()
    bundle["verification_materials_v0"]["issuer"]["algorithm"] = SubStr(
        bundle["verification_materials_v0"]["issuer"]["algorithm"]
    )
    _expect(bundle, "EVALUATOR_CANONICALIZATION")


def test_sample_size_insufficient_below_declared_plan_minimum() -> None:
    bundle = build_bundle(measurements={"agreement": {"agreement": {"sample_size_n": 2}}})
    _expect(bundle, "SAMPLE_SIZE_INSUFFICIENT")


def test_interval_width_exceeded_over_declared_plan_maximum() -> None:
    bundle = build_bundle(
        measurements={
            "agreement": {"agreement": {"interval_low_value": 0, "interval_high_value": 1000000}}
        }
    )
    _expect(bundle, "INTERVAL_WIDTH_EXCEEDED")


def test_threshold_not_met_at_the_conservative_bound() -> None:
    """Point PASSES the threshold (505000 >= 500000); only the conservative
    (low) bound fails (495000 < 500000). P3-tl-review-1 P1-2: the previous
    fixture (point 400000, low 300000, thr 500000) failed the point too, so
    mutation S12-thr-USE-POINT-low (compare point_value instead of
    interval_low_value) was GREEN -- this fixture isolates the bound."""
    bundle = build_bundle(
        measurements={
            "agreement": {
                "agreement": {
                    "point_value": 505000,
                    "interval_low_value": 495000,
                    "interval_high_value": 515000,
                }
            }
        }
    )
    _expect(bundle, "THRESHOLD_NOT_MET")


def test_threshold_conservative_bound_is_inverted_for_lower_is_better() -> None:
    bundle = build_bundle(
        measurements={
            "calibration": {
                "expected_calibration_error": {
                    "point_value": 500000,
                    "interval_low_value": 400000,
                    "interval_high_value": 600000,
                }
            }
        }
    )
    _expect(bundle, "THRESHOLD_NOT_MET")


def test_resample_unit_mismatch_pseudo_replication() -> None:
    bundle = build_bundle(
        measurements={
            "calibration": {
                "expected_calibration_error": {
                    "interval_params": {"resample_unit": "item_pair"},
                }
            }
        }
    )
    _expect(bundle, "RESAMPLE_UNIT_MISMATCH")


# --- P3-tl-review-1 P3: every S12 boundary comparison pinned off-by-one ----


def test_sample_size_boundary_29_rejected_30_accepted() -> None:
    minimum_sample_size_n = _planned("agreement_primary")["minimum_sample_size_n"]
    assert minimum_sample_size_n == 30
    rejected = build_bundle(measurements={"agreement": {"agreement": {"sample_size_n": 29}}})
    _expect(rejected, "SAMPLE_SIZE_INSUFFICIENT")
    accepted = build_bundle(measurements={"agreement": {"agreement": {"sample_size_n": 30}}})
    assert evq._verify_evaluator_quality_private(accepted, context=DEFAULT_CONTEXT) is None


def test_interval_width_boundary_200000_accepted_200001_rejected() -> None:
    maximum_interval_width_ppm = _planned("agreement_primary")["maximum_interval_width_ppm"]
    assert maximum_interval_width_ppm == 200000
    accepted = build_bundle(
        measurements={
            "agreement": {
                "agreement": {"interval_low_value": 800000, "interval_high_value": 1000000}
            }
        }
    )
    assert evq._verify_evaluator_quality_private(accepted, context=DEFAULT_CONTEXT) is None
    rejected = build_bundle(
        measurements={
            "agreement": {
                "agreement": {"interval_low_value": 799999, "interval_high_value": 1000000}
            }
        }
    )
    _expect(rejected, "INTERVAL_WIDTH_EXCEEDED")


def test_threshold_low_boundary_exact_500000_accepted_499999_rejected() -> None:
    threshold_value = _planned("agreement_primary")["threshold_value"]
    assert threshold_value == 500000
    accepted = build_bundle(
        measurements={
            "agreement": {
                "agreement": {
                    "point_value": 525000,
                    "interval_low_value": 500000,
                    "interval_high_value": 550000,
                }
            }
        }
    )
    assert evq._verify_evaluator_quality_private(accepted, context=DEFAULT_CONTEXT) is None
    rejected = build_bundle(
        measurements={
            "agreement": {
                "agreement": {
                    "point_value": 524999,
                    "interval_low_value": 499999,
                    "interval_high_value": 549999,
                }
            }
        }
    )
    _expect(rejected, "THRESHOLD_NOT_MET")


def test_threshold_high_boundary_exact_500000_accepted_500001_rejected() -> None:
    threshold_value = _planned("sensitivity_false_difference_rate")["threshold_value"]
    assert threshold_value == 500000
    accepted = build_bundle(
        measurements={
            "sensitivity": {
                "false_difference_rate": {
                    "point_value": 475000,
                    "interval_low_value": 450000,
                    "interval_high_value": 500000,
                }
            }
        }
    )
    assert evq._verify_evaluator_quality_private(accepted, context=DEFAULT_CONTEXT) is None
    rejected = build_bundle(
        measurements={
            "sensitivity": {
                "false_difference_rate": {
                    "point_value": 475001,
                    "interval_low_value": 450001,
                    "interval_high_value": 500001,
                }
            }
        }
    )
    _expect(rejected, "THRESHOLD_NOT_MET")


def test_measurement_side_role_duplicate_distinct_from_plan_side_duplicate() -> None:
    """P3-tl-review-1 P3: the measurement-side sweep (_measurement_role_rows,
    owned by S12) had zero coverage -- the existing #458-regression test
    duplicates a role in declared_plan.planned_measurements, which is S3,
    not this. Here the DUPLICATE is on the measurement side: two probe
    results carry the same measurement.measurement_role."""
    probes = [
        {
            "probe_id": p,
            "status": "measured",
            "measurement": _measurement(
                "reliability_probe_constant_output"
                if p == "verbosity"
                else "reliability_probe_" + p,
                point=960000,
            ),
        }
        for p in ("constant_output", "verbosity", "position", "self_preference", "one_token_fool")
    ]
    bundle = build_bundle(measurements={"reliability": {"probe_results": probes}})
    _expect(bundle, "MEASUREMENT_ROLE_DUPLICATE")


def test_circular_reference_yields_vocabulary_code_not_recursion_error() -> None:
    """P3-tl-review-1 P3 / probe A4: _walk_strict_values had no cycle guard,
    so a self-referential value built in Python (never JSON-parsed) escaped
    the closed vocabulary as a bare RecursionError."""
    bundle = build_bundle()
    cycle: dict[str, Any] = {}
    cycle["self"] = cycle
    bundle["verification_materials_v0"]["issuer"]["algorithm"] = cycle
    _expect(bundle, "EVALUATOR_CANONICALIZATION")


def test_overdeep_nesting_yields_vocabulary_code() -> None:
    """P3-tl-review-1 P3 / probe A3: mirrors fp2's own MAX_DEPTH rejection
    rather than relying on the interpreter's own recursion limit."""
    bundle = build_bundle()
    deep: Any = "x"
    for _ in range(fp2.MAX_DEPTH + 40):
        deep = [deep]
    bundle["verification_materials_v0"]["issuer"]["algorithm"] = deep
    _expect(bundle, "EVALUATOR_CANONICALIZATION")


def test_non_ppm_value_unit_rejected_at_width_guard_not_conflated() -> None:
    """P3-tl-review-1 P3: maximum_interval_width_ppm is ppm-of-[0,1000000];
    comparing a raw microusd/microsecond width against it would be a unit
    conflation. Latent in the fixtures (every planned role is ppm_unsigned),
    so this drives the extracted guard directly rather than through
    build_bundle (a non-ppm role cannot reach it through the full pipeline:
    the fixed AgreementBlockV1/etc. structural slots each const-pin their
    measurement_role, and every registry-admissible role reachable from
    PLANNED_ROLE_ORDER is ppm_unsigned)."""
    with pytest.raises(evq.EvaluatorQualityVerificationError) as caught:
        evq._check_interval_width(
            {"value_unit": "microusd", "interval_low_value": 0, "interval_high_value": 100},
            {"maximum_interval_width_ppm": 200000},
        )
    assert caught.value.code == "UNIT_NOT_ADMISSIBLE"


def test_ppm_value_unit_width_guard_still_enforces_the_maximum() -> None:
    with pytest.raises(evq.EvaluatorQualityVerificationError) as caught:
        evq._check_interval_width(
            {"value_unit": "ppm_unsigned", "interval_low_value": 0, "interval_high_value": 200001},
            {"maximum_interval_width_ppm": 200000},
        )
    assert caught.value.code == "INTERVAL_WIDTH_EXCEEDED"


@pytest.mark.parametrize(
    ("guard_name", "target", "replacement", "expect_code"),
    [
        (
            # NOTE: "DECLARED_PLAN_SCOPE_VIOLATION" is _fail()'d from four
            # call sites now (direction coupling, unplanned-role, the
            # containment tuple, and the unreachable dispatch fallback), all
            # byte-identical -- str.replace(..., 1) hits whichever occurs
            # FIRST in the file, so each target below includes the
            # preceding, guard-specific condition line to stay unique.
            "plan-direction-coupling",
            '        if planned["threshold_comparison"] != expected:\n'
            '            _fail("DECLARED_PLAN_SCOPE_VIOLATION", '
            '"declared_plan.planned_measurements")',
            '        if planned["threshold_comparison"] != expected:\n            pass',
            None,
        ),
        (
            "plan-unplanned-role-rejected",
            "        if role not in planned_roles:\n"
            '            _fail("DECLARED_PLAN_SCOPE_VIOLATION", '
            '"declared_plan.planned_measurements")',
            "        if role not in planned_roles:\n            pass",
            None,
        ),
        (
            "plan-containment-scope",
            '        ):\n            _fail("DECLARED_PLAN_SCOPE_VIOLATION", '
            '"declared_plan.planned_measurements")',
            "        ):\n            pass",
            None,
        ),
        (
            "sample-size-insufficient",
            '            _fail("SAMPLE_SIZE_INSUFFICIENT", "measurements.sample_size")',
            "            pass",
            None,
        ),
        (
            "interval-width-exceeded",
            '        _fail("INTERVAL_WIDTH_EXCEEDED", "measurements.interval")',
            "        pass",
            None,
        ),
    ],
)
def test_mutate_the_plan_containment_guard_is_caught(
    guard_name: str, target: str, replacement: str, expect_code: str | None
) -> None:
    """Delete only the named guard; the matching negative must go RED."""
    source = Path(evq.__file__).read_text()
    assert target in source, guard_name
    assert source.count(target) == 1, guard_name
    mutated = source.replace(target, replacement, 1)
    namespace: dict[str, Any] = {"__name__": "evq_mutated_plan"}
    exec(compile(mutated, "<mutated evq>", "exec"), namespace)
    negatives = {
        "plan-direction-coupling": build_bundle(
            declared_plan={
                "planned_measurements": [
                    {
                        **_planned(r),
                        **(
                            {"threshold_comparison": "interval_low_ge", "threshold_value": -1000000}
                            if r == "sensitivity_false_difference_rate"
                            else {}
                        ),
                    }
                    for r in PLANNED_ROLE_ORDER
                ]
            },
            measurements={
                "sensitivity": {
                    "false_difference_rate": {
                        "point_value": 990000,
                        "interval_low_value": 980000,
                        "interval_high_value": 1000000,
                    }
                }
            },
        ),
        "plan-unplanned-role-rejected": build_bundle(
            declared_plan={
                "planned_measurements": [
                    _planned(r) for r in PLANNED_ROLE_ORDER if r != "agreement_primary"
                ]
            }
        ),
        "plan-containment-scope": build_bundle(
            measurements={"agreement": {"agreement": {"estimator_id": "fleiss_kappa"}}}
        ),
        "sample-size-insufficient": build_bundle(
            measurements={"agreement": {"agreement": {"sample_size_n": 2}}}
        ),
        "interval-width-exceeded": build_bundle(
            measurements={
                "agreement": {
                    "agreement": {"interval_low_value": 0, "interval_high_value": 1000000}
                }
            }
        ),
    }
    bundle = negatives[guard_name]
    with pytest.raises(namespace["EvaluatorQualityVerificationError"]):
        namespace["_verify_evaluator_quality_private"](bundle, context=DEFAULT_CONTEXT)
