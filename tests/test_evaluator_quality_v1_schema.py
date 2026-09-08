"""Contract tests for the closed evaluator-quality v1 schema family (pillar 3)."""

from __future__ import annotations

import copy
import json
import re
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
CERT_DIR = SCHEMAS / "certification"
SCHEMA_PATH = CERT_DIR / "evaluator_quality_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
DEFS = SCHEMA["definitions"]
MERGE_BASE = "3f0529c1ba94a21afbcee749d6543dd0c4778229"
SHA = "sha256:" + "a" * 64
PREREG_SENTENCE = (
    "Pre-registration is not verified by this certificate; ordering evidence is "
    "out of scope for v1."
)


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
            "definitions": DEFS,
            "allOf": [{"$ref": f"#/definitions/{definition}"}],
        }
    return Draft7Validator(document, registry=REGISTRY)


def _errors(value: object, definition: str | None = None) -> list:
    return list(_validator(definition).iter_errors(value))


def _walk(node: object):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)


def _all_refs(node: object):
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            yield ref
        for value in node.values():
            yield from _all_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _all_refs(item)


# --------------------------------------------------------------------------
# Fixture builders
# --------------------------------------------------------------------------


def _measurement(
    role: str,
    *,
    estimator_id: str = "cohens_kappa",
    value_unit: str = "ppm_unsigned",
    point: int = 500000,
    low: int = 490000,
    high: int = 510000,
    sample_unit: str = "evaluation_item",
    basis: str = "issuer_attested_v1",
    direction: str = "higher_is_better",
) -> dict:
    return {
        "measurement_role": role,
        "estimator_id": estimator_id,
        "estimator_parameters": {
            "interval_side": "two_sided",
            "direction": direction,
            "score_scale": "binary",
            "label_kind": "binary",
        },
        "value_unit": value_unit,
        "point_value": point,
        "interval_low_value": low,
        "interval_high_value": high,
        "interval_params": {
            "interval_kind": "wilson_score",
            "continuity_correction": "none",
        },
        "nominal_coverage_ppm": 950000,
        "sample_size_n": 100,
        "sample_unit": sample_unit,
        "basis": basis,
        "computation_transcript_digest": None,
    }


def _reference_standard(
    *,
    reference_kind: str = "verifiable_execution",
    rater_count: int = 0,
    adjudication_policy: str = "not_applicable",
    agreement_ceiling_ppm: int = 950000,
    error_floor_ppm: int = 50000,
) -> dict:
    return {
        "schema_version": "traigent.evaluator_quality.reference_standard.v1",
        "reference_kind": reference_kind,
        "reference_independence": "evaluator_independent",
        "reference_commitment_digest": SHA,
        "label_count": 1000,
        "rater_count": rater_count,
        "adjudication_policy": adjudication_policy,
        "agreement_ceiling_ppm": agreement_ceiling_ppm,
        "error_floor_ppm": error_floor_ppm,
        "reference_standard_digest": SHA,
    }


def _measurement_set() -> dict:
    return {
        "schema_version": "traigent.evaluator_quality.measurement_set.v1",
        "evaluation_scope_digest": SHA,
        "measurement_window_start": "2026-09-05T10:11:12Z",
        "measurement_window_end": "2026-09-05T11:11:12Z",
        "measurement_set_digest": SHA,
    }


def _sensitivity_block() -> dict:
    return {
        "discriminating_power": _measurement("sensitivity_discriminating_power"),
        "false_difference_rate": _measurement(
            "sensitivity_false_difference_rate", direction="lower_is_better"
        ),
        "pair_set": {
            "known_different_pair_count": 100,
            "known_equivalent_pair_count": 50,
            "equivalence_basis": "identical_configuration",
            "pair_set_digest": SHA,
        },
    }


def _support_row(claim_id: str) -> dict:
    return {
        "claim_id": claim_id,
        "tier": 1,
        "evidence_basis": "abstained",
        "verdict": "abstain",
        "abstention_code": "verifier_not_run_or_not_pass",
    }


def _support_rows() -> list:
    return [_support_row(claim_id) for claim_id in ("EVQ1", "EVQ2", "EVQ3", "EVQ4", "EVQ5")]


def _overall(
    *,
    verdict: str = "passed",
    instrument_adequacy_verdict: str = "passed",
    overall_quality_ppm: int | None = 700000,
) -> dict:
    document = {
        "verdict": verdict,
        "instrument_adequacy_verdict": instrument_adequacy_verdict,
        "aggregation_policy_digest": SHA,
    }
    if overall_quality_ppm is not None:
        document["overall_quality_ppm"] = overall_quality_ppm
    return document


def _aggregation_policy(*, efficiency_offset_forbidden: object = True) -> dict:
    axes = ["calibration", "agreement", "sensitivity", "reliability", "efficiency"]
    return {
        "schema_version": "traigent.evaluator_quality.aggregation_policy.v1",
        "weights": [
            {
                "axis": axis,
                "weight_ppm": 0 if axis == "efficiency" else 250000,
                "required_axis": axis != "efficiency",
                "minimum_sample_size_n": 30,
                "maximum_interval_width_ppm": 200000,
            }
            for axis in axes
        ],
        "rounding_mode": "round_half_even",
        "efficiency_offset_forbidden": efficiency_offset_forbidden,
    }


def _wire_error(*, code: str = "evaluator_quality_invalid_measurement", field_location: str = "bundle") -> dict:
    return {
        "schema_version": "traigent.evaluator_quality.error.v1",
        "code": code,
        "field_location": field_location,
    }


def _non_claim_rows() -> list:
    rows = []
    for item in DEFS["EvaluatorQualityNonClaimsFixedTupleV1"]["items"]:
        overlay = item["allOf"][1]["properties"]
        rows.append(
            {
                "record_type": "non_claim",
                "non_claim_id": overlay["non_claim_id"]["const"],
                "reason_template_id": overlay["reason_template_id"]["const"],
            }
        )
    return rows


# --------------------------------------------------------------------------
# Group 1 -- the file
# --------------------------------------------------------------------------


def test_schema_is_valid_draft7_and_every_ref_resolves() -> None:
    Draft7Validator.check_schema(SCHEMA)
    for definition in DEFS:
        Draft7Validator.check_schema(
            {
                "$schema": SCHEMA["$schema"],
                "$id": f"{SCHEMA['$id']}#check-{definition}",
                "definitions": DEFS,
                "allOf": [{"$ref": f"#/definitions/{definition}"}],
            }
        )
    resolver = REGISTRY.resolver(base_uri=SCHEMA["$id"])
    unresolved = []
    for ref in _all_refs(SCHEMA):
        try:
            resolver.lookup(ref)
        except Exception:  # noqa: BLE001 -- collecting every failure for the assertion message
            unresolved.append(ref)
    assert unresolved == []


def test_every_object_is_closed() -> None:
    for node in _walk(SCHEMA):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, node
    for node in _walk(SCHEMA):
        assert node.get("additionalProperties") is not True, node


def test_no_preregistration_vocabulary_survives() -> None:
    text = SCHEMA_PATH.read_text(encoding="utf-8")
    assert PREREG_SENTENCE in text
    rest = text.replace(PREREG_SENTENCE, "", 1)
    assert re.search(r"pre[-_ ]?regist|preregist|PREREGISTR", rest, re.I) is None
    assert SCHEMA["description"][-len(PREREG_SENTENCE):] == PREREG_SENTENCE


def test_evq_ids_do_not_widen_the_v0_claim_id_vocabulary() -> None:
    claims_v0 = json.loads((CERT_DIR / "certificate_claims_v0_schema.json").read_text(encoding="utf-8"))
    v0_ids = set(claims_v0["definitions"]["ClaimIdV0"]["enum"])
    evq_ids = set(DEFS["EvaluatorQualityClaimIdV1"]["enum"])
    assert evq_ids.isdisjoint(v0_ids)


def test_frozen_v0_files_are_byte_identical_to_the_merge_base() -> None:
    v0_files = sorted(CERT_DIR.glob("*v0*.json"))
    assert v0_files
    for path in v0_files:
        rel = path.relative_to(ROOT).as_posix()
        base = subprocess.run(
            ["git", "show", f"{MERGE_BASE}:{rel}"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
        assert path.read_text(encoding="utf-8") == base, f"{rel} drifted from the merge base"


def test_shipped_v1_contracts_are_untouched() -> None:
    path = CERT_DIR / "process_record_v1_schema.json"
    rel = path.relative_to(ROOT).as_posix()
    base = subprocess.run(
        ["git", "show", f"{MERGE_BASE}:{rel}"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        text=True,
    ).stdout
    assert path.read_text(encoding="utf-8") == base


# --------------------------------------------------------------------------
# Group 2 -- the attestation ceiling
# --------------------------------------------------------------------------


def test_every_measurement_requires_a_basis() -> None:
    measurement = _measurement("agreement_primary")
    assert _errors(measurement, "MeasurementV1") == []
    del measurement["basis"]
    assert _errors(measurement, "MeasurementV1")


def test_construction_recomputed_basis_is_registered_but_unconstructible() -> None:
    assert set(DEFS["MeasurementBasisV1"]["enum"]) == {
        "issuer_attested_v1",
        "construction_recomputed_v1",
    }
    assert _errors("issuer_attested_v1", "EmittableMeasurementBasisV1") == []
    assert _errors("construction_recomputed_v1", "EmittableMeasurementBasisV1")


def test_public_descriptor_disclosure_mode_is_registered_but_unconstructible() -> None:
    assert set(DEFS["EvaluatorDisclosureModeV1"]["enum"]) == {
        "private_commitment",
        "public_descriptor",
    }
    assert _errors("private_commitment", "EmittableDisclosureModeV1") == []
    assert _errors("public_descriptor", "EmittableDisclosureModeV1")


def test_descriptor_opening_cannot_appear_in_the_bundle() -> None:
    assert "DescriptorOpeningV1" in DEFS
    bundle_def = DEFS["EvaluatorQualityCertificateBundleV1"]
    assert "descriptor_opening" not in bundle_def["properties"]
    assert "descriptor_opening" not in bundle_def["required"]
    assert bundle_def["additionalProperties"] is False


# --------------------------------------------------------------------------
# Group 3 -- EVQ6/EVQ7 are not claims
# --------------------------------------------------------------------------


def test_evq6_and_evq7_are_registered_but_not_emittable() -> None:
    assert {"EVQ6", "EVQ7"} <= set(DEFS["EvaluatorQualityClaimIdV1"]["enum"])
    for claim_id in ("EVQ6", "EVQ7"):
        assert _errors(claim_id, "EmittableEvaluatorQualityClaimIdV1")


def test_support_rows_are_exactly_five_in_order() -> None:
    rows = _support_rows()
    assert _errors(rows, "EvaluatorQualityClaimSupportRowsV1") == []

    too_many = rows + [_support_row("EVQ5")]
    assert _errors(too_many, "EvaluatorQualityClaimSupportRowsV1")

    too_few = rows[:-1]
    assert _errors(too_few, "EvaluatorQualityClaimSupportRowsV1")

    swapped = copy.deepcopy(rows)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert _errors(swapped, "EvaluatorQualityClaimSupportRowsV1")


def test_measurement_set_cannot_carry_efficiency_or_frontier() -> None:
    document = _measurement_set()
    assert _errors(document, "EvaluatorMeasurementSetV1") == []

    with_efficiency = {**document, "efficiency": {}}
    assert _errors(with_efficiency, "EvaluatorMeasurementSetV1")

    with_frontier = {**document, "frontier": {}}
    assert _errors(with_frontier, "EvaluatorMeasurementSetV1")

    assert "EfficiencyFrontierV1" in DEFS


def test_efficiency_and_frontier_roles_are_registered_but_not_emittable() -> None:
    assert len(DEFS["MeasurementRoleV1"]["enum"]) == 20
    excluded_roles = [
        role
        for role in DEFS["MeasurementRoleV1"]["enum"]
        if role.startswith("efficiency_") or role.startswith("frontier_")
    ]
    assert len(excluded_roles) == 8
    for role in excluded_roles:
        assert _errors(role, "EmittableMeasurementRoleV1")


# --------------------------------------------------------------------------
# Group 4 -- the instrument-adequacy floor and the reference limits
# --------------------------------------------------------------------------


def test_overall_requires_instrument_adequacy_verdict() -> None:
    document = _overall()
    assert _errors(document, "EvaluatorQualityOverallV1") == []
    del document["instrument_adequacy_verdict"]
    assert _errors(document, "EvaluatorQualityOverallV1")


def test_efficiency_offset_forbidden_is_a_const_true() -> None:
    assert DEFS["AggregationPolicyV1"]["properties"]["efficiency_offset_forbidden"]["const"] is True
    assert _errors(_aggregation_policy(), "AggregationPolicyV1") == []
    assert _errors(_aggregation_policy(efficiency_offset_forbidden=False), "AggregationPolicyV1")


def test_abstain_or_failed_overall_cannot_carry_a_quality_score() -> None:
    for verdict in ("abstain", "failed"):
        without_score = _overall(
            verdict=verdict, instrument_adequacy_verdict=verdict, overall_quality_ppm=None
        )
        assert _errors(without_score, "EvaluatorQualityOverallV1") == []

        with_score = _overall(
            verdict=verdict, instrument_adequacy_verdict=verdict, overall_quality_ppm=500000
        )
        assert _errors(with_score, "EvaluatorQualityOverallV1")

    for verdict in ("passed", "directional"):
        missing_score = _overall(
            verdict=verdict, instrument_adequacy_verdict=verdict, overall_quality_ppm=None
        )
        assert _errors(missing_score, "EvaluatorQualityOverallV1")


def test_reference_standard_carries_both_a_ceiling_and_a_floor() -> None:
    document = _reference_standard()
    assert _errors(document, "ReferenceStandardV1") == []

    no_ceiling = {k: v for k, v in document.items() if k != "agreement_ceiling_ppm"}
    assert _errors(no_ceiling, "ReferenceStandardV1")

    no_floor = {k: v for k, v in document.items() if k != "error_floor_ppm"}
    assert _errors(no_floor, "ReferenceStandardV1")


def test_human_single_rater_requires_exactly_one_rater_and_no_adjudication() -> None:
    document = _reference_standard(
        reference_kind="human_single_rater", rater_count=1, adjudication_policy="none"
    )
    assert _errors(document, "ReferenceStandardV1") == []

    two_raters = {**document, "rater_count": 2}
    assert _errors(two_raters, "ReferenceStandardV1")

    adjudicated = {**document, "adjudication_policy": "majority"}
    assert _errors(adjudicated, "ReferenceStandardV1")


def test_human_panel_adjudicated_requires_at_least_two_raters() -> None:
    document = _reference_standard(
        reference_kind="human_panel_adjudicated", rater_count=3, adjudication_policy="majority"
    )
    assert _errors(document, "ReferenceStandardV1") == []

    one_rater = {**document, "rater_count": 1}
    assert _errors(one_rater, "ReferenceStandardV1")

    no_adjudication = {**document, "adjudication_policy": "none"}
    assert _errors(no_adjudication, "ReferenceStandardV1")


def test_evq4_requires_both_sensitivity_measurements() -> None:
    block = _sensitivity_block()
    assert _errors(block, "SensitivityBlockV1") == []

    no_discriminating = {k: v for k, v in block.items() if k != "discriminating_power"}
    assert _errors(no_discriminating, "SensitivityBlockV1")

    no_false_difference = {k: v for k, v in block.items() if k != "false_difference_rate"}
    assert _errors(no_false_difference, "SensitivityBlockV1")


def test_evaluation_scope_is_required_on_the_measurement_set() -> None:
    document = _measurement_set()
    assert _errors(document, "EvaluatorMeasurementSetV1") == []
    del document["evaluation_scope_digest"]
    assert _errors(document, "EvaluatorMeasurementSetV1")


# --------------------------------------------------------------------------
# Group 5 -- the printed surface and the #458-class defect surface
# --------------------------------------------------------------------------


def test_non_claims_tuple_is_fixed_length_and_ordered() -> None:
    rows = _non_claim_rows()
    assert len(rows) == 20
    assert _errors(rows, "EvaluatorQualityNonClaimsFixedTupleV1") == []

    too_few = rows[:-1]
    assert _errors(too_few, "EvaluatorQualityNonClaimsFixedTupleV1")

    too_many = rows + [rows[-1]]
    assert _errors(too_many, "EvaluatorQualityNonClaimsFixedTupleV1")

    swapped = copy.deepcopy(rows)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert _errors(swapped, "EvaluatorQualityNonClaimsFixedTupleV1")


@pytest.mark.parametrize("field", ["sentence", "text", "verifier", "tier"])
def test_non_claim_record_carries_identifiers_only(field: str) -> None:
    row = _non_claim_rows()[0]
    assert _errors(row, "EvaluatorQualityNonClaimV1") == []
    row[field] = "unexpected"
    assert _errors(row, "EvaluatorQualityNonClaimV1")


def test_planned_measurements_are_keyed_by_claim_and_role() -> None:
    """Guard: keying containment by claim_id alone leaves post-hoc choice of
    estimator, interval, side and sample unit free inside a claim that
    carries several measurements -- see PlannedMeasurementV1's description
    and MeasurementRoleV1's."""
    definition = DEFS["PlannedMeasurementV1"]
    assert "claim_id" in definition["properties"], (
        "PlannedMeasurementV1 has no claim_id property: planned-measurement "
        "containment is keyed by measurement_role alone in the shipped schema, "
        "not by (claim_id, measurement_role) as the guard requires"
    )
    assert "claim_id" in definition["required"]


def test_wire_error_requires_a_field_location() -> None:
    document = _wire_error()
    assert _errors(document, "EvaluatorQualityErrorV1") == []
    del document["field_location"]
    assert _errors(document, "EvaluatorQualityErrorV1")


def test_field_location_tokens_carry_no_index_or_digest() -> None:
    for token in DEFS["EvaluatorQualityFieldLocationV1"]["enum"]:
        assert re.fullmatch(r"[a-z][a-z_.]*", token), token


def test_wire_error_code_enum_is_coarse() -> None:
    codes = DEFS["EvaluatorQualityErrorV1"]["properties"]["code"]["enum"]
    assert len(codes) <= 6


# One documented, bounded exception: a fixed-length base64-encoded blind is
# not free text (it is anchored and length-capped), but it is neither a
# const/enum nor a $ref to a named bounded primitive, so it is called out
# explicitly here rather than silently passed by a generic "has a pattern"
# allowance.
_ALLOWED_PATTERN_ONLY_STRINGS = {("ComponentOpeningV1", "blind_b64")}


def test_no_open_map_or_free_text_field_exists() -> None:
    for node in _walk(SCHEMA):
        assert node.get("additionalProperties") is not True, node

    exceptions = []
    for definition_name, definition in DEFS.items():
        properties = definition.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if not isinstance(prop_schema, dict):
                continue
            if prop_schema.get("type") != "string":
                continue
            bounded = "const" in prop_schema or "enum" in prop_schema or "$ref" in prop_schema
            if not bounded:
                exceptions.append((definition_name, prop_name))

    assert set(exceptions) == _ALLOWED_PATTERN_ONLY_STRINGS
