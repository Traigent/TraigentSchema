"""P3-V.0: a real, re-signable evaluator-quality bundle and GV1."""

from __future__ import annotations

import base64
import copy
import json
from importlib import resources
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2
from traigent_schema.certification import evaluator_quality_verifier as evq

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


def _measurement(
    role: str, *, point: int = 900000, direction: str = "higher_is_better"
) -> dict[str, Any]:
    return {
        "measurement_role": role,
        "estimator_id": "cohens_kappa",
        "estimator_parameters": {
            "interval_side": "two_sided",
            "direction": direction,
            "score_scale": "binary",
            "label_kind": "binary",
        },
        "value_unit": "ppm_unsigned",
        "point_value": point,
        "interval_low_value": max(0, point - 10000),
        "interval_high_value": min(1000000, point + 10000),
        "interval_params": {"interval_kind": "wilson_score", "continuity_correction": "none"},
        "nominal_coverage_ppm": 950000,
        "sample_size_n": 100,
        "sample_unit": "evaluation_item",
        "basis": "issuer_attested_v1",
        "computation_transcript_digest": None,
    }


def _planned(role: str, *, direction: str = "higher_is_better") -> dict[str, Any]:
    return {
        "measurement_role": role,
        "estimator_id": "cohens_kappa",
        "estimator_parameters": {
            "interval_side": "two_sided",
            "direction": direction,
            "score_scale": "binary",
            "label_kind": "binary",
        },
        "value_unit": "ppm_unsigned",
        "interval_params": {"interval_kind": "wilson_score", "continuity_correction": "none"},
        "nominal_coverage_ppm": 950000,
        "sample_unit": "evaluation_item",
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
    planned_roles = [
        ("calibration_ece", "lower_is_better"),
        ("calibration_slope", "higher_is_better"),
        ("agreement_primary", "higher_is_better"),
        ("sensitivity_discriminating_power", "higher_is_better"),
        ("sensitivity_false_difference_rate", "lower_is_better"),
        ("reliability_probe_constant_output", "higher_is_better"),
        ("reliability_probe_verbosity", "higher_is_better"),
        ("reliability_probe_position", "higher_is_better"),
        ("reliability_probe_self_preference", "higher_is_better"),
        ("reliability_probe_one_token_fool", "higher_is_better"),
    ]
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
        "planned_measurements": [_planned(r, direction=d) for r, d in planned_roles],
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
            "expected_calibration_error": _measurement(
                "calibration_ece", point=100000, direction="lower_is_better"
            ),
            "calibration_slope": _measurement("calibration_slope"),
            "binning_policy": "equal_width",
            "bin_count": 10,
        },
        "agreement": {"agreement": _measurement("agreement_primary", point=920000)},
        "sensitivity": {
            "discriminating_power": _measurement("sensitivity_discriminating_power", point=880000),
            "false_difference_rate": _measurement(
                "sensitivity_false_difference_rate", point=100000, direction="lower_is_better"
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
            "public_key_digest": SHA,
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
    b["unsigned_manifest"] = {
        "schema_version": "traigent.evaluator_quality.unsigned_manifest.v1",
        "scope_binding_digest": SHA,
        "evaluator_commitment_ref": SHA,
        "evaluator_commitment": {
            "schema_version": "traigent.evaluator_quality.commitment.v1",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization": "jcs_v1",
            "artifact_kind": "evaluator",
            "commitment_digest": SHA,
        },
        "descriptor_digest": b["descriptor"]["descriptor_digest"],
        "descriptor_opening_digest": None,
        "reference_standard_digest": b["reference_standard"]["reference_standard_digest"],
        "evaluation_scope_digest": b["evaluation_scope"]["evaluation_scope_digest"],
        "declared_plan_digest": b["declared_plan"]["declared_plan_digest"],
        "measurement_registry_digest": SHA,
        "perturbation_set_digest": SHA,
        "assertion_templates_digest": SHA,
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
