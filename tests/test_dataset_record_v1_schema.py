# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the closed dataset-record v1 schema family (pillar 2)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
SCHEMA_PATH = SCHEMAS / "certification" / "dataset_record_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

# The exact commit this design is anchored to (see the design document's
# header); an ancestor of this branch's HEAD.
_FROZEN_REF = "93030ccef7f50acbd205078b7da3e701f5b1dcf4"
_FROZEN_FILES = (
    "traigent_schema/schemas/certification/process_record_v1_schema.json",
    "traigent_schema/certification/process_record_verifier.py",
    "traigent_schema/schemas/certification/certification_common_v0_schema.json",
    "traigent_schema/schemas/certification/agent_certificate_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_claims_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_evidence_refs_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_audit_report_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_client_evidence_manifest_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_unsigned_manifest_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_signatures_v0_schema.json",
    "traigent_schema/schemas/certification/certificate_verification_materials_v0_schema.json",
    "traigent_schema/schemas/certification/certification_endpoints_v0.json",
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
            "definitions": SCHEMA["definitions"],
            "allOf": [{"$ref": f"#/definitions/{definition}"}],
        }
    return Draft7Validator(document, registry=REGISTRY)


def _errors(value: object, definition: str | None = None) -> list:
    return list(_validator(definition).iter_errors(value))


def test_every_ref_target_resolves() -> None:
    """Test 80. Every $ref in the new file resolves through the shipped
    registry."""
    Draft7Validator.check_schema(SCHEMA)
    for name in SCHEMA["definitions"]:
        # No Unresolvable/other exception escaping means every $ref chain
        # reachable from this definition resolved.
        _errors({}, name)


def test_all_definitions_are_closed_and_reject_free_text() -> None:
    """Test 81. additionalProperties: false everywhere; a 'note': 'free
    text' member is rejected in each object definition."""
    object_definitions = [
        name
        for name, definition in SCHEMA["definitions"].items()
        if isinstance(definition, dict) and definition.get("type") == "object"
    ]
    assert object_definitions, "expected at least one object definition"
    for name in object_definitions:
        definition = SCHEMA["definitions"][name]
        assert definition.get("additionalProperties") is False, name
        errors = _errors({"note": "free text"}, name)
        assert any(e.validator == "additionalProperties" for e in errors), name


def test_digest_domain_registry_pins_every_v1_preimage_role() -> None:
    """Test 82. All twenty domains required and const."""
    registry = SCHEMA["definitions"]["DatasetRecordDigestDomainRegistryV1"]
    required = set(registry["required"])
    properties = registry["properties"]
    assert required == set(properties)
    for name, definition in properties.items():
        assert set(definition.keys()) == {"const"}, name
        assert definition["const"] == f"traigent.dataset_record.{name}.v1"


def test_method_registry_document_matches_the_schema_enums() -> None:
    """Test 83. Set-equality both ways so package data and schema cannot
    drift."""
    document = json.loads(
        (
            ROOT
            / "traigent_schema"
            / "data"
            / "certification"
            / "dataset_method_registry_document.json"
        ).read_text(encoding="utf-8")
    )
    pairs = (
        ("information_methods", "DatasetInformationMethodV1"),
        ("selection_rules", "DatasetSelectionRuleV1"),
        ("inertness_criteria", "DatasetInertnessCriterionV1"),
        ("elimination_orders", "DatasetEliminationOrderV1"),
        ("near_duplicate_methods", "DatasetNearDuplicateMethodV1"),
        ("interval_methods", "DatasetIntervalMethodV1"),
    )
    for doc_key, definition_name in pairs:
        assert set(document[doc_key]) == set(SCHEMA["definitions"][definition_name]["enum"]), (
            doc_key
        )


def test_taxonomy_document_matches_the_schema_enums() -> None:
    """Companion to test 83 for the taxonomy registry document."""
    document = json.loads(
        (
            ROOT / "traigent_schema" / "data" / "certification" / "dataset_taxonomy_document.json"
        ).read_text(encoding="utf-8")
    )
    pairs = (
        ("category_ids", "DatasetCategoryIdV1"),
        ("difficulty_strata", "DatasetDifficultyStratumV1"),
        ("population_kinds", "DatasetPopulationKindV1"),
    )
    for doc_key, definition_name in pairs:
        assert set(document[doc_key]) == set(SCHEMA["definitions"][definition_name]["enum"]), (
            doc_key
        )


def test_wire_error_enum_is_coarser_than_the_verifier_error_vocabulary() -> None:
    """Test 84. The 4-member wire enum is disjoint from
    DATASET_RECORD_ERROR_CODES."""
    from traigent_schema.certification import DATASET_RECORD_ERROR_CODES

    wire_enum = set(SCHEMA["definitions"]["DatasetRecordErrorV1"]["properties"]["code"]["enum"])
    assert wire_enum & DATASET_RECORD_ERROR_CODES == set()
    assert len(wire_enum) == 4


def test_evidence_grade_enum_matches_pillars_one_and_three() -> None:
    """Test 85. The shared three-grade vocabulary is pinned to the exact
    literal value D9 specifies as common to pillars 1, 2 and 3. Pillar 1
    and pillar 3's own schemas are not yet present in this repo (they land
    in separate, parallel packets -- see the Schema PR path list's
    sequencing note), so this pins THIS family's copy exactly rather than
    cross-checking sibling files that do not exist yet; when they land,
    this assertion is the one to extend with a true set-equality against
    their schemas."""
    grade_enum = tuple(SCHEMA["definitions"]["PreRegistrationEvidenceGradeV1"]["enum"])
    assert grade_enum == (
        "digest_bound_attestation",
        "caller_pinned_before_results",
        "log_inclusion_proof",
    )


def test_every_verifier_digest_domain_is_registered() -> None:
    """Test 99 (sol round 1 P2). Set equality BOTH ways between the domain
    constants the verifier actually hashes under and
    DatasetRecordDigestDomainRegistryV1. The first draft used
    claim_support_rows without registering it and argued the omission was
    harmless; the harm is that the registry then documents a partial list,
    so a second implementer reading the schema alone cannot reproduce this
    module's preimages. This test is what stops the next one drifting."""
    from traigent_schema.certification import dataset_record_verifier as dr

    prefix = b"traigent.dataset_record."
    module_domains = {
        value.decode("utf-8")
        for name, value in vars(dr).items()
        if name.endswith("_DOMAIN") and isinstance(value, bytes) and value.startswith(prefix)
    }
    # The only *_DOMAIN constant in that namespace belonging to another
    # family is the v0 issuer-SPKI domain this module imports to reuse the
    # shipped signature primitives; naming it here keeps the filter above
    # from quietly hiding a mis-prefixed dataset-record domain.
    foreign = {
        value.decode("utf-8")
        for name, value in vars(dr).items()
        if name.endswith("_DOMAIN") and isinstance(value, bytes) and not value.startswith(prefix)
    }
    assert foreign == {"traigent.agent_certificate.issuer_spki_der.v0"}

    registry = SCHEMA["definitions"]["DatasetRecordDigestDomainRegistryV1"]
    registry_domains = {
        definition["const"] for definition in registry["properties"].values()
    }
    assert module_domains == registry_domains


def test_the_item_set_leaf_list_is_a_first_class_definition() -> None:
    """Test 100 (sol round 1 P1). The composition-cell tags the verifier
    groups by are a named, closed artifact of this contract -- not untyped
    caller input on an overloaded corpus map. Both tag fields resolve to the
    pinned taxonomy enums, so a free-text category is unrepresentable."""
    definition = SCHEMA["definitions"]["DatasetItemSetLeafListV1"]
    entry = definition["properties"]["entries"]["items"]
    assert definition["additionalProperties"] is False
    assert entry["additionalProperties"] is False
    assert set(entry["required"]) == {"leaf", "category_id", "difficulty_stratum"}
    assert entry["properties"]["category_id"]["$ref"] == "#/definitions/DatasetCategoryIdV1"
    assert (
        entry["properties"]["difficulty_stratum"]["$ref"]
        == "#/definitions/DatasetDifficultyStratumV1"
    )
    assert _errors(
        {
            "schema_version": "traigent.dataset_record.item_set_leaf_list.v1",
            "dataset_ref": "dsr:" + "A" * 43,
            "item_set_root": "sha256:" + "a" * 64,
            "entries": [
                {
                    "leaf": "sha256:" + "b" * 64,
                    "category_id": "customer_private_label",
                    "difficulty_stratum": "s1_easy",
                }
            ],
        },
        "DatasetItemSetLeafListV1",
    )


def test_the_applied_policy_projection_covers_every_planned_policy_field() -> None:
    """Test 101 (sol round 1 P1). The report-side echo is not a subset: the
    nine policy fields the plan fixes and the projection's own const coverage
    tuple are the same set, so no policy field can be pre-registered with
    nothing able to contradict it."""
    projection = SCHEMA["definitions"]["DatasetAppliedPolicyProjectionV1"]
    plan = SCHEMA["definitions"]["DatasetEfficiencyPreRegistrationV1"]
    coverage = tuple(projection["properties"]["coverage"]["const"])
    assert set(coverage) <= set(plan["properties"])
    assert set(coverage) == set(projection["properties"]) - {"schema_version", "coverage"}
    assert set(projection["required"]) == set(projection["properties"])
    for field in coverage:
        # Same TYPE on both sides (prose differs): an echo whose admissible
        # values were wider than the plan's could carry a policy the plan
        # cannot express, and equality against it would then be untestable.
        echoed = {k: v for k, v in projection["properties"][field].items() if k != "description"}
        planned = {k: v for k, v in plan["properties"][field].items() if k != "description"}
        assert echoed == planned, field
    assert "applied_policy" in SCHEMA["definitions"]["DatasetEfficiencyReportV1"]["required"]


def _git_show(ref: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=ROOT,
        capture_output=True,
        check=True,
    )
    return result.stdout


@pytest.mark.parametrize("relative_path", _FROZEN_FILES)
def test_process_record_v1_schema_is_byte_identical_to_the_shipped_ref(relative_path: str) -> None:
    """Test 86. Asserts this PR modified no existing schema file (the D1
    property, mechanised); same for every frozen v0 file and the shipped
    process-record verifier module."""
    frozen = _git_show(_FROZEN_REF, relative_path)
    current = (ROOT / relative_path).read_bytes()
    assert hashlib.sha256(current).hexdigest() == hashlib.sha256(frozen).hexdigest(), relative_path
    assert current == frozen, relative_path
