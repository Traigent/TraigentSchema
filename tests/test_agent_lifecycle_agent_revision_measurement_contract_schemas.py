# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""ALR-1106: Agent Lifecycle Record Part 1, Route 1 (agent revision register)
and Route 2 (measurement contract register) request/response schema
contracts.

These two routes had no owning story anywhere in the plan -- the captain
found this twice. `AgentRevisionRef` and `MeasurementContractRef` had no
producer, and mutation rows 1-17's Schema-owned half could never reach 5/5
without them. This module is the Schema-side proof that both producers now
exist, together with tests/test_agent_lifecycle_disclosure_register.py
(extended in the same packet to all nine PART1_CONTRACT_FREEZE_DRAFT.md:406-408
roots) and tests/data/agent_lifecycle_record/
agent_revision_measurement_contract_cases.json (the corpus this module
consumes).

Companion to tests/test_agent_lifecycle_receipt_schemas.py (ALR-1102's Route
3/4 module) -- same structure, same conventions.

Authoritative contract: runs/agent-lifecycle-contract-integration/
PART1_CONTRACT_FREEZE_DRAFT.md (Route 1: lines 535-577; Route 2: lines
579-624).

Binding owner constraint (runs/agent-lifecycle-contract-integration/
OWNER_DECISION_ACCOUNTING_20260809.md, Option A): neither field the
2026-08-09 owner accounting decision deleted from Part 1 may appear as a
property or as a literal string anywhere in this module (including
fixtures/case ids). Neither field exists on these two routes' schemas at all
(they are Route 3/4 concerns), but this module proves that negatively rather
than assuming it, using the same fragment-construction technique ALR-1102
established (see `_forbidden_field_names()` below) so neither literal
spelling sits in this file
as a static string.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from traigent_schema import SchemaValidator

DATA_PATH = (
    Path(__file__).parent
    / "data"
    / "agent_lifecycle_record"
    / "agent_revision_measurement_contract_cases.json"
)


def _load_corpus() -> dict[str, Any]:
    with open(DATA_PATH, encoding="utf-8") as handle:
        return json.load(handle)


_CORPUS = _load_corpus()
_SCHEMA_MAP: dict[str, str] = _CORPUS["target_schemas"]
_CASES: list[dict[str, Any]] = _CORPUS["cases"]
_VALID_CASES = [c for c in _CASES if c["kind"] == "valid"]
_INVALID_CASES = [c for c in _CASES if c["kind"] == "schema_invalid"]

_EXPECTED_VALID_IDS = [
    "agent_revision_register_unknown_omitted_declaration",
    "agent_revision_register_unknown_omitted_declaration_response",
    "agent_revision_register_reconstructed_declared_provenance",
    "agent_revision_register_reconstructed_declared_provenance_response",
    "typed_ref_stable_agent_ref_has_no_version_id",
    "measurement_contract_register_backend_sourced_dataset_and_evaluator",
    "measurement_contract_register_backend_sourced_dataset_and_evaluator_response",
    "measurement_contract_register_client_attested_universe",
    "measurement_contract_register_client_attested_universe_response",
    "measurement_contract_register_item_key_set_slice",
    "measurement_contract_register_item_key_set_slice_response",
    "measurement_contract_trust_levels_differ_universe_backend_evaluator_client",
    "measurement_contract_register_mixed_backend_dataset_client_evaluator",
]

_EXPECTED_INVALID_IDS = [
    "agent_revision_register_unknown_field",
    "agent_revision_register_wrong_schema_version",
    "agent_revision_register_wrong_agent_ref_kind",
    "agent_revision_register_stable_agent_ref_includes_version_id",
    "agent_revision_register_unknown_identity_source_or_mode",
    "agent_revision_register_identity_declaration_missing_identity_descriptor",
    "agent_revision_register_client_declared_local_identity_key_digest_shaped",
    "agent_revision_register_client_declared_local_identity_key_too_short",
    "agent_revision_register_response_unknown_field",
    "agent_revision_register_response_missing_record_ref",
    "agent_revision_register_response_wrong_schema_version",
    "measurement_contract_register_unknown_field",
    "measurement_contract_register_wrong_schema_version",
    "measurement_contract_register_client_supplied_denominator_rejected",
    "measurement_contract_register_dataset_source_shape_conflict",
    "measurement_contract_register_evaluator_source_shape_conflict",
    "measurement_contract_register_slice_definition_shape_conflict",
    "measurement_contract_register_item_keys_empty",
    "measurement_contract_register_item_key_set_with_backend_registered_dataset",
    "measurement_contract_register_client_local_version_key_digest_shaped",
    "measurement_contract_register_item_key_digest_shaped",
    "measurement_contract_register_dataset_source_ref_wrong_kind",
    "measurement_contract_register_evaluator_source_ref_wrong_kind",
    "measurement_contract_register_evaluator_source_item_keys_rejected",
    "measurement_contract_register_dataset_source_backend_registered_missing_source_ref",
    "measurement_contract_register_response_unknown_field",
    "measurement_contract_register_response_wrong_schema_version",
    "measurement_contract_register_response_missing_expected_count",
    "measurement_contract_register_zero_universe",
    "measurement_contract_register_response_expected_count_exceeds_beta_ceiling",
]

# service_invalid cases PART1_CONTRACT_FREEZE_DRAFT.md names for Routes 1/2
# that this corpus deliberately does NOT reproduce, because they require
# comparing this instance against live Backend/idempotency state (unresolvable
# source-ref scope, missing evaluator execution-semantic state, membership
# subset checks, header-layer idempotency behavior) -- not decidable by
# SchemaValidator alone (PART1_CONTRACT_FREEZE_DRAFT.md:971). Documentation,
# not an executable guard: it records what a future Backend successor's
# corpus must still prove.
_DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS = [
    "agent_revision_register_reconstructed_without_client_declaration",
    "agent_revision_register_emits_reserved_verified_without_producer",
    "agent_revision_register_idempotency_key_reuse_different_body_conflict",
    "agent_revision_register_missing_idempotency_key",
    "measurement_contract_register_backend_source_ref_unresolvable_or_wrong_scope",
    "measurement_contract_register_evaluator_source_missing_required_state",
    "measurement_contract_register_slice_item_keys_not_subset_of_dataset",
    "measurement_contract_register_missing_idempotency_key",
    "measurement_contract_register_backend_membership_exceeds_beta_ceiling",
]

# Contract-named valid cases that require a live Backend round trip (issue,
# then exact replay under the same Idempotency-Key) and so cannot be
# expressed as a single static JSON payload -- mirrors the pattern
# tests/test_agent_lifecycle_receipt_schemas.py established for Route 3's
# exact-replay case.
_DOCUMENTED_RUNTIME_VALID_IDS_NOT_IN_THIS_CORPUS = [
    "agent_revision_register_exact_replay_after_idempotency_key_rotation",
    "measurement_contract_register_exact_replay_after_idempotency_key_rotation",
    "agent_revision_identity_declaration_verifier_retained_key_after_rotation",
]


@pytest.fixture
def validator() -> SchemaValidator:
    return SchemaValidator()


class TestSchemaDiscoveryAndCrossFileRefs:
    def test_all_four_schemas_are_discovered(self, validator: SchemaValidator) -> None:
        for schema_name in _SCHEMA_MAP.values():
            assert schema_name in validator.available_schemas

    def test_ref_types_are_defined_once_and_reused_cross_file(
        self, validator: SchemaValidator
    ) -> None:
        """StableOpaqueRef/TypedOpaqueRef/StableSourceRef/AgentLifecycleRecordRef/
        ClientDeclaredIdentityDescriptor/ClientAttestedArtifactDescriptor/
        RequestOnlyRandomLabel all live only in agent_lifecycle_common_schema.json
        (ALR-1102 Terra review P2-2's reuse-not-duplicate precedent, extended by
        ALR-1106 to the new Route 1/2 request-only wire types and the
        record-handle ref both Route 1's and Route 5's responses share). None of
        this story's four schemas duplicates any of these shapes locally."""
        common_schema = validator._schemas["agent_lifecycle_common_schema"]
        for definition_name in (
            "StableOpaqueRef",
            "TypedOpaqueRef",
            "StableSourceRef",
            "AgentLifecycleRecordRef",
            "ClientDeclaredIdentityDescriptor",
            "ClientAttestedArtifactDescriptor",
            "RequestOnlyRandomLabel",
        ):
            assert definition_name in common_schema["definitions"]

        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            definitions = schema.get("definitions", {})
            for definition_name in (
                "StableOpaqueRef",
                "TypedOpaqueRef",
                "StableSourceRef",
                "AgentLifecycleRecordRef",
                "ClientDeclaredIdentityDescriptor",
                "ClientAttestedArtifactDescriptor",
                "RequestOnlyRandomLabel",
            ):
                assert definition_name not in definitions, (
                    f"{schema_name} must not duplicate {definition_name}"
                )

            refs = json.dumps(schema)
            assert "agent_lifecycle_common_schema.json#/definitions/" in refs, (
                f"{schema_name} is expected to cross-file $ref the shared ref types"
            )

    def test_route1_and_route5_responses_share_one_record_ref_definition(
        self, validator: SchemaValidator
    ) -> None:
        """The contract's exact-override manifest (PART1_CONTRACT_FREEZE_DRAFT.md:
        434-437) always named agent_lifecycle_common_schema.json as
        AgentLifecycleRecordRef's eventual home; ALR-1105 could not host it there
        yet (no Route 1 response schema existed on that branch). ALR-1106 moves
        it out of agent_lifecycle_record_response_schema.json's prior local
        definitions block into the shared common schema, and both response
        schemas now $ref that one copy."""
        record_response_schema = validator._schemas["agent_lifecycle_record_response_schema"]
        assert "AgentLifecycleRecordRef" not in record_response_schema.get("definitions", {})

        route1_response = validator._schemas[
            "agent_lifecycle_agent_revision_register_response_schema"
        ]
        assert "AgentLifecycleRecordRef" not in route1_response.get("definitions", {})

        for schema_name in (
            "agent_lifecycle_record_response_schema",
            "agent_lifecycle_agent_revision_register_response_schema",
        ):
            refs = json.dumps(validator._schemas[schema_name])
            assert "agent_lifecycle_common_schema.json#/definitions/AgentLifecycleRecordRef" in refs


class TestCorpusAntiVacuity:
    def test_corpus_matches_the_exact_expected_case_ids(self) -> None:
        actual_valid_ids = [case["id"] for case in _VALID_CASES]
        actual_invalid_ids = [case["id"] for case in _INVALID_CASES]

        assert sorted(actual_valid_ids) == sorted(_EXPECTED_VALID_IDS)
        assert sorted(actual_invalid_ids) == sorted(_EXPECTED_INVALID_IDS)
        assert len(actual_valid_ids) == len(_EXPECTED_VALID_IDS) == 13
        assert len(actual_invalid_ids) == len(_EXPECTED_INVALID_IDS) == 30
        assert len(set(actual_valid_ids)) == len(actual_valid_ids)
        assert len(set(actual_invalid_ids)) == len(actual_invalid_ids)
        assert set(actual_valid_ids).isdisjoint(actual_invalid_ids)

    def test_documented_service_invalid_ids_are_not_silently_duplicated_here(self) -> None:
        corpus_ids = {case["id"] for case in _CASES}
        overlap = corpus_ids.intersection(_DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS)
        assert overlap == set()

    def test_documented_runtime_valid_ids_are_not_silently_duplicated_here(self) -> None:
        corpus_ids = {case["id"] for case in _CASES}
        overlap = corpus_ids.intersection(_DOCUMENTED_RUNTIME_VALID_IDS_NOT_IN_THIS_CORPUS)
        assert overlap == set()

        cross_overlap = set(_DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS).intersection(
            _DOCUMENTED_RUNTIME_VALID_IDS_NOT_IN_THIS_CORPUS
        )
        assert cross_overlap == set()

    @pytest.mark.parametrize("case", _VALID_CASES, ids=[c["id"] for c in _VALID_CASES])
    def test_valid_cases_accept(self, validator: SchemaValidator, case: dict[str, Any]) -> None:
        schema_name = _SCHEMA_MAP[case["schema"]]
        errors = validator.validate_json(case["payload"], schema_name)
        assert errors == [], f"{case['id']}: unexpected errors against {schema_name}: {errors}"

    @pytest.mark.parametrize("case", _INVALID_CASES, ids=[c["id"] for c in _INVALID_CASES])
    def test_schema_invalid_cases_reject(
        self, validator: SchemaValidator, case: dict[str, Any]
    ) -> None:
        schema_name = _SCHEMA_MAP[case["schema"]]
        errors = validator.validate_json(case["payload"], schema_name)
        assert errors, (
            f"{case['id']}: expected rejection against {schema_name} but validated cleanly"
        )


def _valid_agent_revision_request() -> dict[str, Any]:
    return copy.deepcopy(
        next(
            c["payload"]
            for c in _CASES
            if c["id"] == "agent_revision_register_reconstructed_declared_provenance"
        )
    )


def _valid_measurement_contract_request() -> dict[str, Any]:
    return copy.deepcopy(
        next(
            c["payload"]
            for c in _CASES
            if c["id"] == "measurement_contract_register_backend_sourced_dataset_and_evaluator"
        )
    )


def _valid_measurement_contract_response() -> dict[str, Any]:
    return copy.deepcopy(
        next(
            c["payload"]
            for c in _CASES
            if c["id"]
            == "measurement_contract_register_backend_sourced_dataset_and_evaluator_response"
        )
    )


# Anti-vacuity by exact membership (mirrors
# TestRoute5ClosedResponseSchema::test_route5_schema_top_level_properties_are_exact
# in test_agent_lifecycle_contract.py). Both Route 1's and Route 2's response
# schema *descriptions* state a literal top-level property count in prose --
# these pin the real schema so the two can never silently diverge again the
# way Route 1's did (`record_ref` was added to the wire and the prose count
# was never bumped to match).
_EXPECTED_ROUTE1_RESPONSE_TOP_LEVEL_PROPERTIES = {
    "schema_version",
    "agent_revision_ref",
    "record_ref",
    "agent_ref",
    "identity_state",
    "created_at",
}

_EXPECTED_ROUTE2_RESPONSE_TOP_LEVEL_PROPERTIES = {
    "schema_version",
    "measurement_contract_ref",
    "dataset_version_ref",
    "evaluator_version_ref",
    "slice_definition_version_ref",
    "expected_count",
    "universe_trust_level",
    "evaluator_trust_level",
    "created_at",
}


class TestRoute1AgentRevisionRegisterProducer:
    """Closes the prior draft's open blocker 1: AgentRevisionRef had no
    producer. This class proves the Schema half exists and is shaped exactly
    per PART1_CONTRACT_FREEZE_DRAFT.md:535-577."""

    def test_request_has_exactly_agent_ref_and_identity_declaration_optional(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_agent_revision_register_request_schema"]
        assert set(schema["properties"]) == {"schema_version", "agent_ref", "identity_declaration"}
        assert schema["required"] == ["schema_version"]
        assert schema["additionalProperties"] is False

    def test_response_mints_both_agent_revision_ref_and_record_ref(
        self, validator: SchemaValidator
    ) -> None:
        """Closes Opus P1-1: record_ref is minted atomically with
        agent_revision_ref, one-to-one, in the same response."""
        schema = validator._schemas["agent_lifecycle_agent_revision_register_response_schema"]
        assert {"agent_revision_ref", "record_ref"} <= set(schema["required"])

    def test_route1_schema_top_level_properties_are_exact(self, validator: SchemaValidator) -> None:
        """Anti-vacuity by exact membership (mirrors the Route 5 precedent,
        test_agent_lifecycle_contract.py::TestRoute5ClosedResponseSchema::
        test_route5_schema_top_level_properties_are_exact): this response
        schema's own description states the literal property count in prose
        (PART1_CONTRACT_FREEZE_DRAFT.md:564-577). `record_ref` was added to
        the wire after that count was first written and the prose went
        stale without anyone noticing -- a mutation that adds or removes ANY
        top-level property must trip this test, not rely on the prose
        staying accurate."""
        schema = validator._schemas["agent_lifecycle_agent_revision_register_response_schema"]
        assert set(schema["properties"]) == _EXPECTED_ROUTE1_RESPONSE_TOP_LEVEL_PROPERTIES
        assert set(schema["required"]) == _EXPECTED_ROUTE1_RESPONSE_TOP_LEVEL_PROPERTIES
        assert schema["additionalProperties"] is False

    def test_identity_declaration_has_exactly_one_admitted_branch(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_agent_revision_register_request_schema"]
        branches = schema["properties"]["identity_declaration"]["oneOf"]
        assert len(branches) == 1
        assert branches[0]["properties"]["source"]["const"] == "client_declared"

    def test_no_backend_managed_selector_or_typed_ref_shaped_declaration_is_admitted(
        self, validator: SchemaValidator
    ) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:549: a Backend-managed selector,
        TypedOpaqueRef, identity-v2 snapshot id, Agent/Run id, ArtifactVersion
        id, raw fingerprint, database id, name, or path is schema-invalid.
        Structural proof: the closed one-branch oneOf's only property besides
        the source discriminator is identity_descriptor -- there is no ref-
        shaped alternative property anywhere on this field."""
        schema = validator._schemas["agent_lifecycle_agent_revision_register_request_schema"]
        branch = schema["properties"]["identity_declaration"]["oneOf"][0]
        assert set(branch["properties"]) == {"source", "identity_descriptor"}
        assert branch["additionalProperties"] is False


class TestRoute2MeasurementContractRegisterProducer:
    """Closes the prior draft's open blocker 1's Route 2 half: no existing
    Backend surface could mint kind=dataset_version/evaluator_version/
    slice_definition_version/measurement_contract. This class proves the
    composite mint's Schema half is shaped exactly per
    PART1_CONTRACT_FREEZE_DRAFT.md:579-624."""

    def test_request_has_no_expected_count_or_denominator_shaped_field(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_measurement_contract_register_request_schema"]
        assert set(schema["properties"]) == {
            "schema_version",
            "dataset_source",
            "evaluator_source",
            "slice_definition",
        }
        assert schema["additionalProperties"] is False

    def test_route2_schema_top_level_properties_are_exact(self, validator: SchemaValidator) -> None:
        """Anti-vacuity by exact membership (mirrors the Route 5 precedent,
        test_agent_lifecycle_contract.py::TestRoute5ClosedResponseSchema::
        test_route5_schema_top_level_properties_are_exact): this response
        schema's own description states the literal property count in prose
        (PART1_CONTRACT_FREEZE_DRAFT.md:598-612). A mutation that adds or
        removes ANY top-level property must trip this test, not rely on the
        prose staying accurate."""
        schema = validator._schemas["agent_lifecycle_measurement_contract_register_response_schema"]
        assert set(schema["properties"]) == _EXPECTED_ROUTE2_RESPONSE_TOP_LEVEL_PROPERTIES
        assert set(schema["required"]) == _EXPECTED_ROUTE2_RESPONSE_TOP_LEVEL_PROPERTIES
        assert schema["additionalProperties"] is False

    def test_real_schema_rejects_a_client_supplied_expected_count(
        self, validator: SchemaValidator
    ) -> None:
        """Isolates the guard: the real schema rejects a request carrying
        expected_count, and a schema mutated to explicitly PERMIT that field
        validates the identical payload cleanly -- proving additionalProperties:
        false is the load-bearing closure, not some unrelated malformation."""
        poisoned_payload = next(
            c["payload"]
            for c in _CASES
            if c["id"] == "measurement_contract_register_client_supplied_denominator_rejected"
        )
        real_errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_measurement_contract_register_request_schema"
        )
        assert real_errors, "the real schema must reject a client-supplied expected_count"

        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_measurement_contract_register_request_schema"]
        )
        mutated_schema["properties"]["expected_count"] = {"type": "integer", "minimum": 0}
        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            "mutation sanity check failed: widening the schema to permit "
            f"expected_count should have made the poisoned case validate, got: {mutated_errors}"
        )

    def test_response_computes_expected_count_only_from_accepted_membership(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_measurement_contract_register_response_schema"]
        expected_count = schema["properties"]["expected_count"]
        assert expected_count["minimum"] == 1
        assert expected_count["maximum"] == 10000

    def test_item_key_set_mode_admissible_only_over_client_attested_dataset(
        self, validator: SchemaValidator
    ) -> None:
        """MUTATION witness (closes Opus Final Contract Review P1-2). The
        real schema rejects the backend_registered+ITEM_KEY_SET combination;
        removing the root if/then guard admits it."""
        poisoned_payload = next(
            c["payload"]
            for c in _CASES
            if c["id"]
            == "measurement_contract_register_item_key_set_with_backend_registered_dataset"
        )
        real_errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_measurement_contract_register_request_schema"
        )
        assert real_errors

        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_measurement_contract_register_request_schema"]
        )
        del mutated_schema["allOf"]
        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            "mutation sanity check failed: removing the item-key-set/backend-"
            f"registered if/then should have admitted the poisoned case, got: {mutated_errors}"
        )

    def test_universe_and_evaluator_trust_level_can_never_claim_server_verified(
        self, validator: SchemaValidator
    ) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:198, :254: a client_attested source can
        support protocol completeness but never raises comparability,
        Qualification, Standing, or authority. Structural proof: both trust
        fields are a closed two-value enum that never includes server_verified
        -- there is no wire value through which either field could claim
        stronger authority than Backend actually accepted."""
        schema = validator._schemas["agent_lifecycle_measurement_contract_register_response_schema"]
        for field_name in ("universe_trust_level", "evaluator_trust_level"):
            enum_values = set(schema["properties"][field_name]["enum"])
            assert enum_values == {"client_attested", "backend_observed"}
            assert "server_verified" not in enum_values

    def test_evaluator_source_client_attested_branch_has_no_membership_dimension(
        self, validator: SchemaValidator
    ) -> None:
        """Evaluators have no version-pinning membership concept
        (PART1_CONTRACT_FREEZE_DRAFT.md:583): evaluator_source's client_attested
        branch has exactly source/artifact_descriptor, never item_keys."""
        schema = validator._schemas["agent_lifecycle_measurement_contract_register_request_schema"]
        branches = schema["properties"]["evaluator_source"]["oneOf"]
        client_attested_branch = next(
            b for b in branches if b["properties"]["source"]["const"] == "client_attested"
        )
        assert set(client_attested_branch["properties"]) == {"source", "artifact_descriptor"}


def _forbidden_field_names() -> tuple[str, str]:
    """The two field names the 2026-08-09 owner accounting decision deleted
    from Part 1 entirely (runs/agent-lifecycle-contract-integration/
    OWNER_DECISION_ACCOUNTING_20260809.md). Mirrors tests/test_agent_lifecycle_
    receipt_schemas.py::_deleted_field_names(): built from non-literal
    fragments so a repo-wide grep for either literal finds no hit in this
    file. Route 1/2 never had either field to begin with (they are Route 3/4
    concerns), but this module proves that negatively rather than assuming
    it."""
    first = "".join(("observed", "_", "unique"))
    second = "".join(("com", "mit", "ment"))
    return first, second


class TestOwnerAccountingConstraintDoesNotLeakIntoRoutes1And2:
    def test_neither_forbidden_field_name_appears_anywhere_in_these_four_schemas(
        self, validator: SchemaValidator
    ) -> None:
        first, second = _forbidden_field_names()
        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            text = json.dumps(schema).lower()
            assert first not in text, f"{schema_name} must not mention the deleted accounting field"
            assert second not in text, (
                f"{schema_name} must not mention the deleted possession field"
            )

    def test_neither_forbidden_field_name_appears_in_the_corpus_file(self) -> None:
        first, second = _forbidden_field_names()
        text = json.dumps(_CORPUS).lower()
        assert first not in text
        assert second not in text


# Number words a schema description might use to state a property count. Kept
# explicit rather than parsed with a library so an unrecognised word is a loud
# KeyError-shaped failure, not a silently skipped schema.
_NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}

# Matches "exactly six properties", "exactly three top-level properties",
# "exactly the fourteen top-level properties".
_PROSE_COUNT_RE = re.compile(
    r"exactly (?:the )?([a-z]+) (?:top-level )?propert(?:y|ies)", re.IGNORECASE
)

# Schemas known to state a top-level property count in prose today. This floor
# is the anti-vacuity guard: if a description is reworded so the regex stops
# matching, the loop below would silently check nothing and pass. Asserting the
# expected set means "the prose no longer states a count" fails loudly and gets
# a deliberate decision, instead of quietly retiring the check.
_SCHEMAS_STATING_A_PROSE_PROPERTY_COUNT = {
    "agent_lifecycle_agent_revision_register_response_schema",
    "agent_lifecycle_measurement_contract_register_response_schema",
    "agent_lifecycle_receipt_submit_request_schema",
    "agent_lifecycle_receipt_submit_response_schema",
    "agent_lifecycle_record_response_schema",
}


class TestProseStatedPropertyCountsMatchTheSchema:
    """A schema's prose must not drift from the schema it describes.

    The structural tests above pin `properties`/`required` to an exact set, so a
    change to the SCHEMA trips them. They do not, however, catch drift in the
    other direction -- prose silently disagreeing with a schema that never
    changed. That is precisely the defect this PR exists to fix: `record_ref`
    was added to Route 1's wire, and the description went on saying "exactly
    five properties" for as long as nobody read both halves at once. A guard
    that only covers one direction would not have caught the bug it was written
    in response to.
    """

    def test_every_prose_stated_count_matches_the_actual_property_count(
        self, validator: SchemaValidator
    ) -> None:
        checked: dict[str, tuple[int, int]] = {}
        for name, schema in validator._schemas.items():
            if not name.startswith("agent_lifecycle"):
                continue
            match = _PROSE_COUNT_RE.search(schema.get("description", ""))
            if match is None:
                continue
            word = match.group(1).lower()
            assert word in _NUMBER_WORDS, (
                f"{name}: description states a property count as {word!r}, which is not a "
                f"recognised number word -- extend _NUMBER_WORDS or reword the description"
            )
            checked[name] = (_NUMBER_WORDS[word], len(schema.get("properties", {})))

        assert set(checked) == _SCHEMAS_STATING_A_PROSE_PROPERTY_COUNT, (
            "the set of agent-lifecycle schemas stating a prose property count changed; "
            "update _SCHEMAS_STATING_A_PROSE_PROPERTY_COUNT deliberately rather than letting "
            f"this check silently cover less. got={sorted(checked)} "
            f"expected={sorted(_SCHEMAS_STATING_A_PROSE_PROPERTY_COUNT)}"
        )

        mismatches = {n: v for n, v in checked.items() if v[0] != v[1]}
        assert not mismatches, "prose property count disagrees with the schema: " + ", ".join(
            f"{n} says {stated} but has {actual}"
            for n, (stated, actual) in sorted(mismatches.items())
        )
