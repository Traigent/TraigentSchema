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
#: SHA-256 of each frozen artifact AS IT STANDS AT ``_FROZEN_REF``, pinned as
#: data rather than read out of git at test time.
#:
#: The first version of this test ran ``git show 93030cc:<path>`` and compared
#: bytes. That passes locally and CANNOT pass in CI: the checkout is shallow,
#: the anchor commit is not in it, and ``git show`` exits 128 -- so the test
#: was green on the one machine where nothing could go wrong and red on the
#: one machine that gates the merge.
#:
#: Pinning the digests is STRICTER, not weaker. It runs everywhere with no
#: history, it still fails the instant any frozen byte changes, and
#: ``test_the_pinned_frozen_digests_match_the_anchor_ref`` below re-derives
#: every one of these constants from ``_FROZEN_REF`` wherever the object IS
#: reachable, so a constant cannot drift away from the ref unnoticed.
#:
#: Regenerate only when the anchor ref is deliberately moved:
#:   git -C <schema checkout> show <ref>:<path> | sha256sum
_FROZEN_DIGESTS: dict[str, str] = {
    "traigent_schema/schemas/certification/process_record_v1_schema.json": (
        "1844ecf3e8e22110d5c8827e59c9219159fba3a05f0a60c3f681b534eca2b8ef"
    ),
    "traigent_schema/certification/process_record_verifier.py": (
        "b726bbf7065f4874b3e40a5de1668760336000a6f999dd2ff99e707a645a9eaa"
    ),
    "traigent_schema/schemas/certification/certification_common_v0_schema.json": (
        "069e488b794a35f4b85c66f796cd7278bbb4deb7b8b17c9483b21461c91f3c4f"
    ),
    "traigent_schema/schemas/certification/agent_certificate_v0_schema.json": (
        "df29e85888df6de1166f19b2f17ec4238864be5afa96421ed75e37059aceb390"
    ),
    "traigent_schema/schemas/certification/certificate_claims_v0_schema.json": (
        "cc9df368af739642b852dcf69da56b4eee803ee9d3c6ca720b56743132fc0d78"
    ),
    "traigent_schema/schemas/certification/certificate_evidence_refs_v0_schema.json": (
        "c8890632f16392e8df667def8090e89cb709bda0e4c583c1db2e3258f958e723"
    ),
    "traigent_schema/schemas/certification/certificate_audit_report_v0_schema.json": (
        "0ec8481e84c2aa894be869e13efc92ba3fd6d56ca6d8f6cde121866f1121f370"
    ),
    "traigent_schema/schemas/certification/certificate_client_evidence_manifest_v0_schema.json": (
        "2ea9ad3fa07cfdd006c44b2de7c65c63a0e6ef3d91b2e3bc1409776f00188aed"
    ),
    "traigent_schema/schemas/certification/certificate_unsigned_manifest_v0_schema.json": (
        "aaaa004541af79c9b5221f95dbdf15d9f5759edb78a9f0b53cd95e2f854bd9f8"
    ),
    "traigent_schema/schemas/certification/certificate_signatures_v0_schema.json": (
        "bf7d37ab402d509d7e8af087d0d12829b87b601808da9a7ec56ae13ba9df8b88"
    ),
    "traigent_schema/schemas/certification/certificate_verification_materials_v0_schema.json": (
        "232911c85d697d5793d5dd2a7f9aefbba53e5544159408d60134f457679f3a8e"
    ),
    "traigent_schema/schemas/certification/certification_endpoints_v0.json": (
        "da60d93ed3aa1c4a97f671972fecea967a756ffa15df1f884cb0105819a4542e"
    ),
}

_FROZEN_FILES = tuple(_FROZEN_DIGESTS)


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
    registry_domains = {definition["const"] for definition in registry["properties"].values()}
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


def _commit_is_reachable(ref: str) -> bool:
    """Whether ``ref`` resolves to a commit object THIS CLONE actually has.

    Checked independently of any path lookup: a shallow clone (the
    workspace's ``test`` CI job checks out with the default ``fetch-depth``,
    i.e. depth 1 -- no ``fetch-depth: 0``) has no object for a historical
    commit at all. In that state ``git show <ref>:<path>`` does NOT fail with
    "unknown revision" -- git resolves the working tree's HEAD fine and, on
    seeing that ``path`` exists in the current checkout, reports the
    unrelated-sounding "path '<path>' exists on disk, but not in '<ref>'".
    Matching on that specific stderr text (the previous version of this
    helper) is exactly backwards: it is the message a shallow checkout
    produces, not a message it never produces, so it was raising on the one
    condition the guard exists to tolerate.
    """

    result = subprocess.run(
        ["git", "cat-file", "-e", f"{ref}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def _git_show(ref: str, path: str) -> bytes | None:
    """The blob at ``ref``, or ``None`` when the commit is not in this clone.

    ``None`` is returned ONLY when the commit object itself is absent (a
    shallow CI checkout). Once the commit is confirmed present, any further
    git failure -- a corrupt object, a path that does not exist in that
    commit's tree -- is raised, because those are real findings and
    swallowing them is how a guard quietly stops guarding.
    """

    if not _commit_is_reachable(ref):
        return None
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout
    stderr = result.stderr.decode("utf-8", "replace")
    raise AssertionError(f"git show {ref}:{path} failed unexpectedly: {stderr}")


@pytest.mark.parametrize("relative_path", _FROZEN_FILES)
def test_process_record_v1_schema_is_byte_identical_to_the_shipped_ref(relative_path: str) -> None:
    """Test 86. Asserts this PR modified no existing schema file (the D1
    property, mechanised); same for every frozen v0 file and the shipped
    process-record verifier module.

    Unconditional and history-free: the working file's digest is compared to
    the constant pinned in ``_FROZEN_DIGESTS``, so it runs identically on a
    developer machine and in a shallow CI checkout. It is never skipped.
    """

    current = (ROOT / relative_path).read_bytes()
    assert hashlib.sha256(current).hexdigest() == _FROZEN_DIGESTS[relative_path], (
        f"{relative_path} is not byte-identical to the frozen artifact at {_FROZEN_REF}"
    )


@pytest.mark.parametrize("relative_path", _FROZEN_FILES)
def test_the_pinned_frozen_digests_match_the_anchor_ref(relative_path: str) -> None:
    """The guard on the guard: a pinned constant that had drifted from the ref
    would let a frozen file be edited and still pass test 86.

    Wherever the anchor object is reachable -- every developer machine, and
    any CI job with full history -- the constant is RE-DERIVED from the ref
    and compared. Where it is not, there is nothing to compare against; test
    86 above still holds unconditionally, so no property goes unchecked.
    """

    frozen = _git_show(_FROZEN_REF, relative_path)
    if frozen is None:
        pytest.skip(f"anchor {_FROZEN_REF} is not in this clone (shallow checkout)")
    assert hashlib.sha256(frozen).hexdigest() == _FROZEN_DIGESTS[relative_path], (
        f"_FROZEN_DIGESTS[{relative_path!r}] has drifted from {_FROZEN_REF}"
    )


def test_the_attestation_basis_restriction_is_not_a_sibling_of_a_ref() -> None:
    """Astra P2 (F7). Under draft-07 a keyword sitting BESIDE ``$ref`` is
    ignored, so the attestation corpus entry's ``const: backend_observed``
    restricted nothing and a ``client_attested`` entry validated. Asserted
    both structurally (the reference and the restriction are combined with
    ``allOf``) and behaviourally, against this repo's own validator."""
    entry = SCHEMA["definitions"]["DatasetLeafGenerationAttestationV1"]["properties"]["corpora"][
        "items"
    ]["properties"]["observation_basis"]
    assert "$ref" not in entry, "a $ref sibling would silence the restriction again"
    assert entry["allOf"] == [
        {"$ref": "process_record_v1_schema.json#/definitions/ObservationBasisV1"},
        {"const": "backend_observed"},
    ]

    def attestation(basis: str) -> dict:
        return {
            "schema_version": "traigent.dataset_record.leaf_generation_attestation.v1",
            "leakage_scope_ref": "lsr:" + "A" * 43,
            "scope_blind_commitment": "sha256:" + "b" * 64,
            "leaf_domain": "traigent.dataset_record.item_leaf.v1",
            "completeness": (
                "every_leaf_generated_for_this_corpus_under_this_scope_is_listed"
            ),
            "corpora": [
                {
                    "corpus_ref": "cpr:" + "A" * 43,
                    "leaf_count": 1,
                    "leaf_root": "sha256:" + "a" * 64,
                    "scope_blind_commitment": "sha256:" + "b" * 64,
                    "observation_basis": basis,
                }
            ],
            "attestation_digest": "sha256:" + "c" * 64,
        }

    assert _errors(attestation("backend_observed"), "DatasetLeafGenerationAttestationV1") == []
    rejected = _errors(attestation("client_attested"), "DatasetLeafGenerationAttestationV1")
    assert [error.message for error in rejected] == ["'backend_observed' was expected"]


def test_a_support_row_may_carry_exactly_one_evidence_ref() -> None:
    """Astra's second review (F9). The schema advertised ``maxItems: 4``
    while ``dataset_record_verifier._check_support_rows`` accepts exactly
    one, so a producer following the schema could emit a record no relying
    party could verify. The one-ref profile is the deliberate side (the same
    function separately forbids EvidenceRefV0's optional opaque locator), so
    the SCHEMA is what narrows."""
    refs = SCHEMA["definitions"]["DatasetRecordClaimSupportRowV1"]["properties"]["evidence_refs"]
    assert (refs["minItems"], refs["maxItems"]) == (1, 1)

    def row(count: int) -> dict:
        return {
            "claim_id": "DS4",
            "evidence_basis": "issuer_verified",
            "verifier_id": "ver.dataset.near_duplicate_v1",
            "verifier_version": "1.0.0",
            "verifier_result": "pass",
            "evidence_refs": [
                {
                    "evidence_kind": "verifier_report_digest",
                    "evidence_digest": "sha256:" + chr(ord("a") + index) * 64,
                }
                for index in range(count)
            ],
        }

    assert _errors(row(1), "DatasetRecordClaimSupportRowV1") == []
    assert [
        error.validator for error in _errors(row(2), "DatasetRecordClaimSupportRowV1")
    ] == ["maxItems"]


def test_schema_still_pins_the_wire_shape_two_unit_called_guards_rely_on() -> None:
    """Re-arm tripwire (sol round-3 P2-2).

    Two verifier guards are reachable through the wire bundle ONLY because
    the schema forecloses the shapes that would otherwise reach them, and
    each guard is exercised directly as a unit, not through a wire negative:

    - ``dataset_record_verifier._check_support_rows``'s ``len(refs) != 1``
      branch (astra F9) is schema-blocked by ``evidence_refs.maxItems: 1``
      on ``DatasetRecordClaimSupportRowV1`` -- see
      ``test_a_support_row_may_carry_exactly_one_evidence_ref`` above, which
      already re-derives this from ``SCHEMA``.
    - ``dataset_record_verifier._check_taxonomy_and_registry_pins`` and
      ``_check_report_registry_identities`` (astra F6a) are schema-blocked
      by ``const``-pinning ``taxonomy_id``/``taxonomy_version`` on
      ``DatasetTaxonomyIdentityV1`` and ``registry_id``/``registry_version``
      on ``DatasetMethodRegistryIdentityV1``.

    If a future schema change relaxes any of these -- widens ``maxItems``,
    or drops a ``const`` in favour of a plain ``type: string`` -- THIS test
    fails, and failing here is the signal that the guard it names just
    became reachable through the wire with no negative test proving it
    still rejects the widened shape.
    """
    support_row_refs = SCHEMA["definitions"]["DatasetRecordClaimSupportRowV1"]["properties"][
        "evidence_refs"
    ]
    assert support_row_refs["maxItems"] == 1, (
        "evidence_refs.maxItems widened past 1 -- "
        "dataset_record_verifier._check_support_rows's `len(refs) != 1` guard "
        "is now wire-reachable and needs a wire negative, not just a unit call"
    )

    taxonomy_identity = SCHEMA["definitions"]["DatasetTaxonomyIdentityV1"]["properties"]
    assert taxonomy_identity["taxonomy_id"] == {"const": "traigent.dataset_taxonomy.asap.v1"}, (
        "taxonomy_id is no longer const-pinned -- "
        "dataset_record_verifier._check_taxonomy_and_registry_pins's identity "
        "comparison is now wire-reachable and needs a wire negative"
    )
    assert taxonomy_identity["taxonomy_version"] == {"const": "1.0.0"}, (
        "taxonomy_version is no longer const-pinned -- "
        "dataset_record_verifier._check_taxonomy_and_registry_pins's identity "
        "comparison is now wire-reachable and needs a wire negative"
    )

    registry_identity = SCHEMA["definitions"]["DatasetMethodRegistryIdentityV1"]["properties"]
    assert registry_identity["registry_id"] == {
        "const": "traigent.dataset_method_registry.asap.v1"
    }, (
        "registry_id is no longer const-pinned -- "
        "dataset_record_verifier._check_taxonomy_and_registry_pins's identity "
        "comparison is now wire-reachable and needs a wire negative"
    )
    assert registry_identity["registry_version"] == {"const": "1.0.0"}, (
        "registry_version is no longer const-pinned -- "
        "dataset_record_verifier._check_taxonomy_and_registry_pins's identity "
        "comparison is now wire-reachable and needs a wire negative"
    )
