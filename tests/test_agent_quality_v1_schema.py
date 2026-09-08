"""Contract tests for the closed agent-quality v1 schema family (pillar 1)."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
CERTIFICATION = SCHEMAS / "certification"
SCHEMA_PATH = CERTIFICATION / "agent_quality_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_TEXT = SCHEMA_PATH.read_text(encoding="utf-8")

MERGE_BASE = "3f0529c1ba94a21afbcee749d6543dd0c4778229"

SHA = "sha256:" + "a" * 64
OPAQUE_REF = "measurement:" + "m" * 8
SIGNATURE_BYTES = "A" * 85 + "A" + "=="

AGGREGATION_POLICY = {
    "policy_id": "traigent.aggregation_policy.pillar1.v1",
    "policy_version": "1.0.0",
    "policy_digest": SHA,
}
OBJECTIVE_REGISTRY = {
    "registry_id": "traigent.objective_registry.pillar1.v1",
    "registry_version": "1.0.0",
    "registry_digest": SHA,
}
NON_CLAIM_CATALOG = {
    "catalog_id": "traigent.agent_quality.non_claim_catalog.v1",
    "catalog_version": "1.0.0",
    "catalog_digest": SHA,
}
QUANTILE_TABLE = {
    "table_id": "traigent.quantile_table.student_t.v1",
    "table_version": "1.0.0",
    "table_digest": SHA,
}

SPLIT_DERIVATION = {
    "schema_version": "traigent.agent_quality.split_derivation.v1",
    "split_rule_id": "hmac_sha256_prefix_threshold_v1",
    "dataset_commitment_ref": SHA,
    "evaluated_universe_item_count": 1000,
    "holdout_fraction_ppm": 200000,
    "commitment_scheme": "sha256_secret_blinded_v1",
    "canonicalization_profile": "jcs_v1",
    "split_key_commitment": SHA,
    "split_derivation_digest": SHA,
}


def _registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(definition: str | None = None) -> Draft7Validator:
    if definition is None:
        document = SCHEMA
    else:
        document = {
            "$schema": SCHEMA["$schema"],
            "$id": f"{SCHEMA['$id']}#test-{definition}",
            "definitions": SCHEMA["definitions"],
            "allOf": [{"$ref": f"#/definitions/{definition}"}],
        }
    return Draft7Validator(document, registry=REGISTRY)


def _errors(value: object, definition: str | None = None) -> list:
    return list(_validator(definition).iter_errors(value))


def _split_record(split_id: str, item_count: int) -> dict:
    return {
        "schema_version": "traigent.agent_quality.evaluation_split.v1",
        "split_id": split_id,
        "item_count": item_count,
        "commitment_scheme": "sha256_secret_blinded_v1",
        "canonicalization_profile": "jcs_v1",
        "split_commitment_digest": SHA,
        "split_derivation_digest": SHA,
    }


EVALUATION_SPLITS = [_split_record("selection", 800), _split_record("holdout", 200)]


def _wilson_claim(**overrides: object) -> dict:
    claim = {
        "schema_version": "traigent.agent_quality.measured_objective.v1",
        "objective_id": "obj.accuracy.exact_match.v1",
        "objective_kind": "binary_rate",
        "unit": "ppm",
        "direction": "maximize",
        "evaluated_split_id": "holdout",
        "sample_size": 200,
        "point_estimate": 950000,
        "interval_low": 900000,
        "interval_high": 980000,
        "interval_params": {
            "interval_method": "wilson_score_v1",
            "continuity_correction": "none",
            "recomputation_profile": "exact_integer_rational_v1",
        },
        "sufficient_statistics": {
            "stat_kind": "binomial_v1",
            "success_count": 190,
            "trial_count": 200,
        },
        "verification_level": "construction_recomputed_v1",
        "nominal_coverage_ppm": 950000,
        "measurement_contract_ref": OPAQUE_REF,
        "measurement_contract_record_digest": SHA,
    }
    claim.update(overrides)
    return claim


def _student_t_claim(**overrides: object) -> dict:
    claim = {
        "schema_version": "traigent.agent_quality.measured_objective.v1",
        "objective_id": "obj.accuracy.evaluator_score_mean.v1",
        "objective_kind": "bounded_mean",
        "unit": "ppm",
        "direction": "maximize",
        "evaluated_split_id": "holdout",
        "sample_size": 200,
        "point_estimate": 800000,
        "interval_low": 750000,
        "interval_high": 850000,
        "interval_params": {
            "interval_method": "student_t_normal_approx_v1",
            "degrees_of_freedom": 199,
            "quantile_table": QUANTILE_TABLE,
            "recomputation_profile": "exact_integer_rational_v1",
        },
        "sufficient_statistics": {
            "stat_kind": "mean_variance_v1",
            "sample_count": 200,
            "mean_fixed": 800000,
            "sample_stddev_fixed": 50000,
            "unit_scale": "ppm",
        },
        "verification_level": "construction_recomputed_v1",
        "nominal_coverage_ppm": 950000,
        "measurement_contract_ref": OPAQUE_REF,
        "measurement_contract_record_digest": SHA,
    }
    claim.update(overrides)
    return claim


def _selection_estimate(**overrides: object) -> dict:
    est = {
        "schema_version": "traigent.agent_quality.selection_estimate.v1",
        "record_kind": "non_certified_selection_estimate",
        "certifiable": "no",
        "objective_id": "obj.accuracy.exact_match.v1",
        "objective_kind": "binary_rate",
        "unit": "ppm",
        "evaluated_split_id": "selection",
        "sample_size": 800,
        "point_estimate": 970000,
    }
    est.update(overrides)
    return est


def _non_claims() -> list[dict]:
    items = SCHEMA["definitions"]["AgentQualityNonClaimsFixedTupleV1"]["items"]
    rows = []
    for item in items:
        consts = item["allOf"][1]["properties"]
        rows.append(
            {
                "record_type": "non_claim",
                "non_claim_id": consts["non_claim_id"]["const"],
                "reason_template_id": consts["reason_template_id"]["const"],
            }
        )
    return rows


def _assertion() -> dict:
    return {
        "schema_version": "traigent.agent_quality.assertion.v1",
        "claim_id": "AQ1",
        "assertion_template_id": "agent_quality_measured_interval_v1",
        "aggregation_policy": AGGREGATION_POLICY,
        "objective_registry": OBJECTIVE_REGISTRY,
        "rendered_text": SCHEMA["definitions"]["AgentQualityAssertionV1"]["properties"][
            "rendered_text"
        ]["const"],
        "assertion_digest": SHA,
    }


def _support_row_issuer_verified() -> dict:
    return {
        "claim_id": "AQ1",
        "evidence_basis": "issuer_verified",
        "assertion_digest": SHA,
        "measured_claims_digest": SHA,
        "evaluation_splits_digest": SHA,
        "verifier_result": "pass",
        "claim_material_digest": SHA,
        "declared_plan_digest": SHA,
    }


def _support_row_abstained() -> dict:
    return {
        "claim_id": "AQ1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }


def _declared_plan() -> dict:
    return {
        "schema_version": "traigent.agent_quality.declared_plan.v1",
        "scope_binding_digest": SHA,
        "aggregation_policy": AGGREGATION_POLICY,
        "objective_registry": OBJECTIVE_REGISTRY,
        "objective_ids": ["obj.accuracy.exact_match.v1"],
        "primary_objective_id": "obj.accuracy.exact_match.v1",
        "split_derivation": SPLIT_DERIVATION,
        "selection_arm_count": 4,
        "holdout_scored_arm_count": 1,
        "declared_plan_digest": SHA,
    }


def _declared_plan_signature() -> dict:
    return {
        "schema_version": "traigent.agent_quality.declared_plan_signature.v1",
        "algorithm": "ed25519",
        "issuer_key_ref": OPAQUE_REF,
        "trust_ring_ref": OPAQUE_REF,
        "signed_payload": "agent_quality_declared_plan",
        "declared_plan_digest": SHA,
        "signature": SIGNATURE_BYTES,
    }


def _declared_plan_envelope() -> dict:
    return {
        "schema_version": "traigent.agent_quality.declared_plan_envelope.v1",
        "declared_plan": _declared_plan(),
        "signature": _declared_plan_signature(),
    }


def _pillar_support() -> list[dict]:
    return [
        {
            "support_subject": "dataset",
            "status": "condition_declared_unverified",
            "bound_commitment_ref": SHA,
            "condition_code": "dataset_certificate_not_verified",
        },
        {
            "support_subject": "evaluator",
            "status": "condition_declared_unverified",
            "bound_commitment_ref": SHA,
            "condition_code": "evaluator_certificate_not_verified",
        },
    ]


def _unsigned_manifest() -> dict:
    coverage = SCHEMA["definitions"]["AgentQualityUnsignedManifestV1"]["properties"]["coverage"][
        "const"
    ]
    return {
        "schema_version": "traigent.agent_quality.unsigned_manifest.v1",
        "base_process_record_unsigned_manifest_digest": SHA,
        "scope_binding_digest": SHA,
        "agent_commitment_ref": SHA,
        "dataset_commitment_ref": SHA,
        "evaluator_commitment_ref": SHA,
        "build_definition_commitment_ref": SHA,
        "measurement_contract_ref": OPAQUE_REF,
        "measurement_contract_record_digest": SHA,
        "aggregation_policy": AGGREGATION_POLICY,
        "objective_registry": OBJECTIVE_REGISTRY,
        "non_claim_catalog": NON_CLAIM_CATALOG,
        "quantile_table": QUANTILE_TABLE,
        "declared_plan_digest": SHA,
        "declared_plan_signature_digest": SHA,
        "split_derivation_digest": SHA,
        "evaluation_splits_digest": SHA,
        "measured_claims_digest": SHA,
        "non_certified_selection_estimates_digest": SHA,
        "primary_objective_id": "obj.accuracy.exact_match.v1",
        "selection_arm_count": 4,
        "holdout_scored_arm_count": 1,
        "pillar_support": _pillar_support(),
        "assertion_digest": SHA,
        "non_claims_digest": SHA,
        "agent_quality_claim_support_rows_digest": SHA,
        "trust_ring_ref": OPAQUE_REF,
        "issuer_key_ref": OPAQUE_REF,
        "issuer_signature_algorithm": "ed25519",
        "coverage": coverage,
    }


def _signature() -> dict:
    return {
        "schema_version": "traigent.agent_quality.signature.v1",
        "algorithm": "ed25519",
        "issuer_key_ref": OPAQUE_REF,
        "trust_ring_ref": OPAQUE_REF,
        "signed_payload": "unsigned_agent_quality_manifest",
        "unsigned_manifest_digest": SHA,
        "signature": SIGNATURE_BYTES,
    }


def _bundle(
    *,
    support_row: dict | None = None,
    measured_claims: list[dict] | None = None,
    selection_estimates: list[dict] | None = None,
) -> dict:
    support_row = support_row or _support_row_issuer_verified()
    measured_claims = [_wilson_claim()] if measured_claims is None else measured_claims
    selection_estimates = [] if selection_estimates is None else selection_estimates
    return {
        "schema_version": "traigent.agent_quality.certificate_bundle.v1",
        "unsigned_manifest": _unsigned_manifest(),
        "signature": _signature(),
        "declared_plan_envelope": _declared_plan_envelope(),
        "assertion": _assertion(),
        "claim_support_rows": [support_row],
        "non_claims": _non_claims(),
        "evaluation_splits": EVALUATION_SPLITS,
        "measured_claims": measured_claims,
        "non_certified_selection_estimates": selection_estimates,
        "split_derivation": SPLIT_DERIVATION,
    }


# --------------------------------------------------------------------------
# Group 1 -- the file itself
# --------------------------------------------------------------------------


def test_schema_is_valid_draft7_and_every_ref_resolves() -> None:
    Draft7Validator.check_schema(SCHEMA)
    for definition in SCHEMA["definitions"]:
        Draft7Validator.check_schema(
            {
                "$schema": SCHEMA["$schema"],
                "$id": f"{SCHEMA['$id']}#check-{definition}",
                "definitions": SCHEMA["definitions"],
                "allOf": [{"$ref": f"#/definitions/{definition}"}],
            }
        )
    assert _errors(_bundle()) == []


def _iter_objects(node: object):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _iter_objects(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_objects(item)


def test_every_object_is_closed() -> None:
    for node in _iter_objects(SCHEMA):
        assert node.get("additionalProperties") is not True, node
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, node


def test_no_preregistration_vocabulary_survives() -> None:
    sentence = (
        "Pre-registration is not verified by this certificate; "
        "ordering evidence is out of scope for v1."
    )
    assert SCHEMA["description"].endswith(sentence)
    rest = SCHEMA_TEXT.replace(sentence, "", 1)
    assert re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", rest, re.I) is None


def test_aq1_does_not_widen_the_v0_claim_id_vocabulary() -> None:
    v0 = json.loads(
        (CERTIFICATION / "certificate_claims_v0_schema.json").read_text(encoding="utf-8")
    )
    claim_id_v0 = v0["definitions"]["ClaimIdV0"]
    assert "AQ1" not in claim_id_v0["enum"]
    assert "ClaimIdV0" not in SCHEMA_TEXT


def test_frozen_v0_files_are_byte_identical_to_the_merge_base() -> None:
    v0_files = sorted(CERTIFICATION.glob("*v0*.json"))
    assert v0_files
    for path in v0_files:
        rel = path.relative_to(ROOT).as_posix()
        result = subprocess.run(
            ["git", "show", f"{MERGE_BASE}:{rel}"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
        assert result.stdout == path.read_bytes(), rel


# --------------------------------------------------------------------------
# Group 2 -- the claim/evidence model
# --------------------------------------------------------------------------


def test_point_estimate_without_an_interval_is_schema_invalid() -> None:
    claim = _wilson_claim()
    del claim["interval_low"]
    del claim["interval_high"]
    assert _errors(claim, "MeasuredObjectiveClaimV1")


def test_interval_without_sufficient_statistics_is_schema_invalid() -> None:
    """Guard: the verifier's interval recomputation; an interval it cannot
    recompute must be unrepresentable."""
    claim = _wilson_claim()
    del claim["sufficient_statistics"]
    assert _errors(claim, "MeasuredObjectiveClaimV1")


def test_statistics_branch_is_coupled_to_the_interval_method() -> None:
    """Guard: SUFFICIENT_STATISTICS_SHAPE."""
    binomial_with_student_t_interval = _wilson_claim(
        interval_params=_student_t_claim()["interval_params"]
    )
    assert _errors(binomial_with_student_t_interval, "MeasuredObjectiveClaimV1")

    mean_variance_with_wilson_interval = _student_t_claim(
        interval_params=_wilson_claim()["interval_params"]
    )
    assert _errors(mean_variance_with_wilson_interval, "MeasuredObjectiveClaimV1")


def test_certified_claim_must_be_on_the_holdout_split() -> None:
    """Guard: HOLDOUT_NOT_USED."""
    claim = _wilson_claim(evaluated_split_id="selection")
    assert _errors(claim, "MeasuredObjectiveClaimV1")


def test_selection_estimate_is_a_structurally_different_record() -> None:
    """Guard: SELECTION_ESTIMATE_IN_CERTIFIED_SET."""
    assert _errors(_selection_estimate(), "NonCertifiedSelectionEstimateV1") == []
    assert _errors(_selection_estimate(), "MeasuredObjectiveClaimV1")


def test_nominal_coverage_is_a_closed_enum() -> None:
    assert _errors(940000, "NominalCoveragePpmV1")


def test_abstained_bundle_cannot_carry_measured_claims() -> None:
    """Guard: ABSTAINED_BUNDLE_CARRIES_CLAIMS."""
    bundle = _bundle(support_row=_support_row_abstained())
    assert _errors(bundle, "AgentQualityCertificateBundleV1")


def test_abstained_bundle_cannot_carry_selection_estimates() -> None:
    """Guard: ABSTAINED_BUNDLE_CARRIES_CLAIMS."""
    bundle = _bundle(
        support_row=_support_row_abstained(),
        measured_claims=[],
        selection_estimates=[_selection_estimate()],
    )
    assert _errors(bundle, "AgentQualityCertificateBundleV1")
    abstained_and_empty = _bundle(support_row=_support_row_abstained(), measured_claims=[])
    assert _errors(abstained_and_empty, "AgentQualityCertificateBundleV1") == []


def test_verification_level_cannot_be_issuer_attested() -> None:
    """Guard: no trust inflation -- a signed level is never a source."""
    assert _errors("issuer_attested_v1", "EmittableVerificationLevelV1")
    assert _errors("opened_and_recomputed_v1", "EmittableVerificationLevelV1")


# --------------------------------------------------------------------------
# Group 3 -- the tier-4 "registered but unconstructible" pattern
# --------------------------------------------------------------------------


def test_bootstrap_percentile_is_registered_but_unconstructible() -> None:
    assert _errors("bootstrap_percentile_v1", "IntervalMethodV1") == []
    assert _errors("bootstrap_percentile_v1", "EmittableIntervalMethodV1")


def test_order_statistic_quantile_is_registered_but_unconstructible() -> None:
    assert _errors("order_statistic_quantile_v1", "IntervalMethodV1") == []
    assert _errors("order_statistic_quantile_v1", "EmittableIntervalMethodV1")


def test_nonnegative_quantile_kind_is_registered_but_unconstructible() -> None:
    assert _errors("nonnegative_quantile", "ObjectiveKindV1") == []
    assert _errors("nonnegative_quantile", "EmittableObjectiveKindV1")


def test_the_two_non_emittable_objective_ids_are_registered_but_unconstructible() -> None:
    objective_ids = set(SCHEMA["definitions"]["ObjectiveIdV1"]["enum"])
    emittable_ids = set(SCHEMA["definitions"]["EmittableObjectiveIdV1"]["allOf"][1]["enum"])
    assert len(objective_ids) == 5
    assert emittable_ids == {
        "obj.accuracy.exact_match.v1",
        "obj.accuracy.evaluator_score_mean.v1",
        "obj.cost.mean_microusd_per_item.v1",
    }
    assert emittable_ids < objective_ids


def test_assessed_supported_is_registered_but_unconstructible() -> None:
    """Guard: dataset/evaluator validity is a declared CONDITION, never a support."""
    assert _errors("assessed_supported", "PillarStatusV1") == []
    assert _errors("assessed_supported", "EmittablePillarStatusV1")


def test_split_opening_witness_is_not_defined_anywhere() -> None:
    """Guard: v1 has no opening path, so split_verification_level can only be
    attested."""
    assert "SplitOpeningWitness" not in SCHEMA_TEXT


# --------------------------------------------------------------------------
# Group 4 -- pillar support (the #458-class defect surface)
# --------------------------------------------------------------------------


def test_pillar_support_is_exactly_two_entries_in_fixed_order() -> None:
    """Guard: PILLAR_SUPPORT_SHAPE / PILLAR_SUPPORT_SUBJECT_DUPLICATE."""
    good = _pillar_support()
    assert _errors(good, "PillarSupportV1") == []

    three_entries = good + [good[0]]
    assert _errors(three_entries, "PillarSupportV1")

    reversed_order = list(reversed(good))
    assert _errors(reversed_order, "PillarSupportV1")


def test_process_record_is_not_a_pillar_support_subject() -> None:
    """Guard: the process record is verified first and in full, not a support row."""
    assert _errors("process_record", "PillarSupportSubjectV1")


def test_condition_entry_requires_a_bound_commitment_ref_and_a_condition_code() -> None:
    """Guard: PILLAR_CONDITION_BINDING_MISMATCH; a nulled condition would delete
    the dependency binding a relying party needs."""
    entry = _pillar_support()[0]

    missing_commitment_ref = dict(entry)
    del missing_commitment_ref["bound_commitment_ref"]
    assert _errors(missing_commitment_ref, "PillarSupportEntryV1")

    missing_condition_code = dict(entry)
    del missing_condition_code["condition_code"]
    assert _errors(missing_condition_code, "PillarSupportEntryV1")


# --------------------------------------------------------------------------
# Group 5 -- non-claims and the printed surface
# --------------------------------------------------------------------------


def test_non_claims_tuple_is_exactly_twenty_eight_in_order() -> None:
    good = _non_claims()
    assert len(good) == 28
    assert _errors(good, "AgentQualityNonClaimsFixedTupleV1") == []

    twenty_seven = good[:-1]
    assert _errors(twenty_seven, "AgentQualityNonClaimsFixedTupleV1")

    twenty_nine = good + [good[-1]]
    assert _errors(twenty_nine, "AgentQualityNonClaimsFixedTupleV1")

    swapped = list(good)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert _errors(swapped, "AgentQualityNonClaimsFixedTupleV1")


def test_non_claim_record_carries_identifiers_only() -> None:
    record = _non_claims()[0]
    for field in ("sentence", "text", "verifier", "tier"):
        assert _errors({**record, field: "extra"}, "AgentQualityNonClaimV1")


def test_rendered_assertion_makes_no_forbidden_claim() -> None:
    """Guard: the certified sentence may name only recomputed facts."""
    rendered_text = SCHEMA["definitions"]["AgentQualityAssertionV1"]["properties"][
        "rendered_text"
    ]["const"]
    forbidden = (
        "pre-regist",
        "preregist",
        "not chosen on",
        "was not adjusted",
        "post-hoc",
        "guarantee",
        "proves",
    )
    lowered = rendered_text.lower()
    for phrase in forbidden:
        assert phrase not in lowered


def test_wire_error_requires_a_field_location() -> None:
    error = {
        "schema_version": "traigent.agent_quality.error.v1",
        "code": "agent_quality_invalid_measurement",
    }
    assert _errors(error, "AgentQualityErrorV1")


def test_field_location_tokens_carry_no_index_or_digest() -> None:
    """Guard: a failure location must not disclose which element failed."""
    pattern = re.compile(r"^[a-z][a-z_.]*$")
    tokens = SCHEMA["definitions"]["AgentQualityFieldLocationV1"]["enum"]
    assert tokens
    for token in tokens:
        assert pattern.match(token), token


def test_wire_error_code_enum_is_coarser_than_the_verifier_vocabulary() -> None:
    codes = SCHEMA["definitions"]["AgentQualityErrorV1"]["properties"]["code"]["enum"]
    assert len(codes) <= 6
