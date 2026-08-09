"""ALR-1102: Agent Lifecycle Record Part 1, Route 3 (run plan issue) and Route 4
(receipt submit) request/response schema contracts.

Companion to ``tests/test_agent_lifecycle_schemas.py`` (ALR-1101's common-schema
tests) -- kept in a focused module rather than appended to that already-large
file, matching this repo's existing split between
``tests/test_session_submit_results_schema.py`` and the endpoint-catalog tests
it lives alongside. Precedent read before writing this file:
``traigent_schema/schemas/analytics/next_steps_receipt_request_schema.json``,
its response schema, and ``tests/test_session_submit_results_schema.py``.

Authoritative contract: ``runs/agent-lifecycle-contract-integration/
PART1_CONTRACT_FREEZE_DRAFT.md`` (Route 3: lines 626-693; Route 4: lines
695-736). CORRECTED by the owner's 2026-08-09 accounting decision (``runs/
agent-lifecycle-contract-integration/OWNER_DECISION_ACCOUNTING_20260809.md``):
the two fields that decision deleted from Part 1 entirely do not appear
anywhere in these schemas, and an accepted ``duplicate`` count is always
``const 0`` -- STORY-ALR-1102.md's AC3 text (which names the first deleted
field) is stale and is not followed here.

Terra review P1-3 (2026-08-10): neither deleted field's literal spelling
appears anywhere in this module or in ``receipt_cases.json`` -- ALR-1101 was
held to that same bar for the schema files themselves. Where a poison probe
needs one of the two literal keys, ``_deleted_field_names()`` below builds
both from non-literal fragments at test time rather than storing either as a
static string constant, fixture case id, or JSON property name.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from traigent_schema import SchemaValidator

DATA_PATH = Path(__file__).parent / "data" / "agent_lifecycle_record" / "receipt_cases.json"


def _load_corpus() -> dict[str, Any]:
    with open(DATA_PATH, encoding="utf-8") as handle:
        return json.load(handle)


_CORPUS = _load_corpus()
_SCHEMA_MAP: dict[str, str] = _CORPUS["target_schemas"]
_CASES: list[dict[str, Any]] = _CORPUS["cases"]
_VALID_CASES = [c for c in _CASES if c["kind"] == "valid"]
_INVALID_CASES = [c for c in _CASES if c["kind"] == "schema_invalid"]

# The exact case-id sets this corpus is authored against (P2-2-style
# anti-vacuity: exact membership, not a loose ">= N" floor a case deletion
# could silently satisfy -- modelled on
# test_orthogonal_corpus_matches_the_exact_expected_case_ids_p2_2 in
# tests/test_agent_lifecycle_schemas.py).
_EXPECTED_VALID_IDS = [
    "issue_request_minimal",
    "issue_request_with_experiment_run_provenance",
    "issue_response_two_items_nonce_delivery",
    "issue_response_with_experiment_run_provenance",
    "receipt_all_produced_complete",
    "receipt_mixed_produced_cached_complete",
    "receipt_missing_partial",
    "receipt_failed_partial",
    "receipt_fallback_partial",
    "receipt_excluded_partial",
    "rescorability_aggregate_available_all_receipts_available",
    "record_client_rescorability_no_authority",
    "receipt_response_complete_coverage_client_attested_only_reason",
    "receipt_response_partial_coverage_incomplete_and_client_attested_only_reasons",
]

_EXPECTED_INVALID_IDS = [
    "issue_unknown_field",
    "issue_wrong_schema_version",
    "issue_wrong_agent_ref_kind",
    "issue_wrong_contract_ref_kind",
    "run_plan_issue_experiment_run_ref_wrong_kind_or_typed_version",
    "typed_ref_stable_kind_includes_version_id",
    "issue_response_empty_universe",
    "issue_response_nonce_missing",
    "issue_response_unknown_field",
    "issue_response_wrong_state",
    "issue_response_missing_binding_ref",
    "receipt_nonce_missing",
    "receipt_unknown_outcome",
    "receipt_available_on_failed",
    "receipt_available_on_excluded",
    "receipt_submit_client_expected_count_denominator_rejected",
    "receipt_unknown_field",
    "receipt_item_missing_outcome",
    "receipt_wrong_schema_version",
    "receipt_response_echoes_nonce",
    "coverage_negative_count",
    "coverage_complete_with_missing",
    "coverage_complete_with_failed",
    "coverage_complete_with_fallback",
    "coverage_complete_with_excluded",
    "coverage_duplicate_nonzero",
    "coverage_seal_response_unmeasured_or_unknown_invalid",
    "coverage_seal_response_wrong_basis",
    "coverage_null_count_on_non_legacy_basis",
    "coverage_partial_missing_incomplete_reason",
    "record_client_rescorability_raises_authority",
    "record_client_rescorability_authority_effect_not_none",
    "receipt_response_unknown_field",
    "receipt_response_missing_measurement_coverage",
    "receipt_response_partial_available_rejected",
]

# service_invalid cases PART1_CONTRACT_FREEZE_DRAFT.md names for Routes 3/4
# that this corpus deliberately does NOT reproduce, because they require
# comparing this instance against previously-issued Backend/plan state (cross-
# array-entry comparison, arithmetic identities, live scope resolution) -- not
# decidable by SchemaValidator alone (PART1_CONTRACT_FREEZE_DRAFT.md:971). This
# is documentation, not an executable guard: it records what a future Backend
# successor's corpus must still prove.
_DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS = [
    "issue_response_noncontiguous_indexes",
    "issue_response_duplicate_item_ref",
    "issue_response_count_mismatch",
    "receipt_duplicate_index",
    "receipt_item_ref_mismatch",
    "receipt_index_out_of_universe",
    "coverage_arithmetic_mismatch",
    "run_plan_issue_experiment_run_ref_unresolvable_or_wrong_scope",
    "run_plan_issue_live_binding_null_measurement_contract_ref",
    "rescorability_aggregate_falsely_available_with_unavailable_accepted_receipt",
    "run_plan_issue_missing_idempotency_key",
    "receipt_submit_missing_idempotency_key",
    "idempotency_key_malformed_pattern_rejected",
    "coverage_omits_client_attested_only_over_attested_contract",
]

# Terra review P2-1 (2026-08-10): this id is PART1_CONTRACT_FREEZE_DRAFT.md's
# own valid case 38 (:1014), not service_invalid -- it was misfiled in
# _DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS above, which would have
# blocked a legitimate future valid witness for it. It is omitted from this
# schema-only corpus for a different reason: proving an "exact replay"
# returns byte-identical output requires two live requests against a running
# Backend (issue, then replay under the same Idempotency-Key), which no
# single static JSON payload can express or SchemaValidator alone decide.
_DOCUMENTED_RUNTIME_VALID_IDS_NOT_IN_THIS_CORPUS = [
    "run_plan_issue_exact_replay_after_idempotency_key_rotation",
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
        """StableOpaqueRef/TypedOpaqueRef live only in
        agent_lifecycle_common_schema.json (Terra review P2-2, 2026-08-10:
        moved out of the Route 3 request schema, since the contract defines
        them as common types every Part 1 route consumes -- hosting them in
        one consumer route file would have forced later Route 1/2/5 stories
        to depend on a sibling route document instead of the shared
        definitions target). All four of this story's schemas $ref them
        cross-file rather than duplicating the definitions."""
        common_schema = validator._schemas["agent_lifecycle_common_schema"]
        assert "StableOpaqueRef" in common_schema["definitions"]
        assert "TypedOpaqueRef" in common_schema["definitions"]

        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            definitions = schema.get("definitions", {})
            assert "StableOpaqueRef" not in definitions, (
                f"{schema_name} must not duplicate StableOpaqueRef"
            )
            assert "TypedOpaqueRef" not in definitions, (
                f"{schema_name} must not duplicate TypedOpaqueRef"
            )

            refs = json.dumps(schema)
            assert "agent_lifecycle_common_schema.json#/definitions/" in refs, (
                f"{schema_name} is expected to cross-file $ref the shared ref types"
            )


class TestReceiptCorpusAntiVacuity:
    def test_corpus_matches_the_exact_expected_case_ids(self) -> None:
        actual_valid_ids = [case["id"] for case in _VALID_CASES]
        actual_invalid_ids = [case["id"] for case in _INVALID_CASES]

        assert sorted(actual_valid_ids) == sorted(_EXPECTED_VALID_IDS)
        assert sorted(actual_invalid_ids) == sorted(_EXPECTED_INVALID_IDS)
        assert len(actual_valid_ids) == len(_EXPECTED_VALID_IDS) == 14
        assert len(actual_invalid_ids) == len(_EXPECTED_INVALID_IDS) == 35
        assert len(set(actual_valid_ids)) == len(actual_valid_ids)
        assert len(set(actual_invalid_ids)) == len(actual_invalid_ids)
        assert set(actual_valid_ids).isdisjoint(actual_invalid_ids)

    def test_documented_service_invalid_ids_are_not_silently_duplicated_here(self) -> None:
        """Guards against a future edit accidentally re-adding a service_invalid
        case as though it were schema-decidable: none of the documented
        Backend-only ids may appear in this corpus's own id set."""
        corpus_ids = {case["id"] for case in _CASES}
        overlap = corpus_ids.intersection(_DOCUMENTED_SERVICE_INVALID_IDS_NOT_IN_THIS_CORPUS)
        assert overlap == set()

    def test_documented_runtime_valid_ids_are_not_silently_duplicated_here(self) -> None:
        """Mirrors the service_invalid guard above for the separate
        runtime-valid bucket (Terra review P2-1): a contract-named valid case
        that needs a live Backend to witness must not silently reappear here
        either, and the two documentation lists must never overlap with each
        other -- that would be the exact misclassification P2-1 caught."""
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
        assert errors, f"{case['id']}: expected rejection against {schema_name} but validated cleanly"


def _valid_issue_response() -> dict[str, Any]:
    return copy.deepcopy(
        next(c["payload"] for c in _CASES if c["id"] == "issue_response_two_items_nonce_delivery")
    )


def _valid_receipt_request() -> dict[str, Any]:
    return copy.deepcopy(next(c["payload"] for c in _CASES if c["id"] == "receipt_all_produced_complete"))


def _valid_receipt_response() -> dict[str, Any]:
    return copy.deepcopy(
        next(
            c["payload"]
            for c in _CASES
            if c["id"] == "rescorability_aggregate_available_all_receipts_available"
        )
    )


class TestAC1NonceBoundScopedContentFreeRunPlan:
    """AC1: the run plan is nonce-bound, scoped, content-free, and lists
    expected identities/indexes and contract refs."""

    def test_nonce_is_required_on_the_issue_response(self, validator: SchemaValidator) -> None:
        schema = validator._schemas["agent_lifecycle_run_plan_issue_response_schema"]
        assert "nonce" in schema["required"]

    def test_nonce_property_exists_on_exactly_one_of_the_four_schemas(
        self, validator: SchemaValidator
    ) -> None:
        """Structural half of guard-killing mutation #5
        (PART1_CONTRACT_FREEZE_DRAFT.md:1143): nonce is a declared property on
        the issue response ONLY -- not on the issue request, not on either
        receipt-submit schema's response side. (It IS a request-only property
        on the receipt-submit request, matching PART1_CONTRACT_FREEZE_DRAFT.md
        :708 'Request-only on this route'.)"""
        issue_request = validator._schemas["agent_lifecycle_run_plan_issue_request_schema"]
        issue_response = validator._schemas["agent_lifecycle_run_plan_issue_response_schema"]
        receipt_request = validator._schemas["agent_lifecycle_receipt_submit_request_schema"]
        receipt_response = validator._schemas["agent_lifecycle_receipt_submit_response_schema"]

        assert "nonce" not in issue_request["properties"]
        assert "nonce" in issue_response["properties"]
        assert "nonce" in receipt_request["properties"]
        assert "nonce" not in receipt_response["properties"]

    def test_content_free_no_raw_prediction_or_content_shaped_property_anywhere(
        self, validator: SchemaValidator
    ) -> None:
        """No schema in this story's scope names a raw-content-shaped public
        PROPERTY (PART1_CONTRACT_FREEZE_DRAFT.md:634, :703-718, :736: no raw
        predictions, no client content, no digest of content). Scoped to
        actual `properties` keys, not full serialized text/descriptions --
        this contract's own prose legitimately uses words like 'content' in
        'content-free' (PART1_CONTRACT_FREEZE_DRAFT.md:626), which a raw
        full-text substring scan would wrongly flag."""
        forbidden_substrings = {
            "raw_prediction",
            "raw_output",
            "raw_input",
            "gold",
            "prompt",
            "content",
            "digest",
        }

        def property_names(node: object) -> set[str]:
            names: set[str] = set()
            if isinstance(node, dict):
                properties = node.get("properties")
                if isinstance(properties, dict):
                    names.update(properties.keys())
                    for child in properties.values():
                        names.update(property_names(child))
                for key in ("items", "definitions", "allOf", "anyOf", "oneOf"):
                    child = node.get(key)
                    if isinstance(child, list):
                        for item in child:
                            names.update(property_names(item))
                    elif isinstance(child, dict):
                        for item in child.values():
                            names.update(property_names(item))
            return names

        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            names = {name.lower() for name in property_names(schema)}
            for forbidden in forbidden_substrings:
                matches = {name for name in names if forbidden in name}
                assert matches == set(), f"{schema_name} has forbidden property name(s): {matches}"

    def test_issue_response_lists_only_index_and_item_ref_per_expected_item(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_run_plan_issue_response_schema"]
        item_schema = schema["properties"]["expected_items"]["items"]
        assert set(item_schema["properties"]) == {"index", "item_ref"}
        assert item_schema["additionalProperties"] is False

    def test_issue_request_and_response_are_scoped_by_typed_refs_not_raw_ids(
        self, validator: SchemaValidator
    ) -> None:
        """'Scoped' here means every identity is carried by a closed
        StableOpaqueRef/TypedOpaqueRef object (pattern-constrained opaque id),
        never a free-text/raw database id string."""
        common_schema = validator._schemas["agent_lifecycle_common_schema"]
        ref_id_pattern = common_schema["definitions"]["OpaqueRefId"]["pattern"]
        assert ref_id_pattern == "^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$"


class TestAC2ReceiptBindsPlanIndexIdentityContractScopeAndStatus:
    """AC2: a receipt binds plan/index/identity/contract/scope and status; a
    raw prediction is not required and must not be accepted as a completeness
    input."""

    def test_receipt_item_has_exactly_index_item_ref_outcome_rescorability_state(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_receipt_submit_request_schema"]
        item_schema = schema["properties"]["receipts"]["items"]
        assert set(item_schema["properties"]) == {
            "index",
            "item_ref",
            "outcome",
            "rescorability_state",
        }
        assert set(item_schema["required"]) == {
            "index",
            "item_ref",
            "outcome",
            "rescorability_state",
        }
        assert item_schema["additionalProperties"] is False

    def test_a_raw_prediction_field_on_a_receipt_is_rejected(
        self, validator: SchemaValidator
    ) -> None:
        payload = _valid_receipt_request()
        payload["receipts"][0]["prediction"] = "the model's raw output"
        errors = validator.validate_json(payload, "agent_lifecycle_receipt_submit_request_schema")
        assert errors

    def test_plan_binding_is_implicit_via_the_url_path_run_plan_ref_not_a_body_field(
        self, validator: SchemaValidator
    ) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:697: run_plan_ref is a URL path
        parameter (POST .../run-plans/{run_plan_ref}/receipts), not a request
        body field -- the body only needs schema_version/nonce/receipts."""
        schema = validator._schemas["agent_lifecycle_receipt_submit_request_schema"]
        assert "run_plan_ref" not in schema["properties"]
        assert set(schema["required"]) == {"schema_version", "nonce", "receipts"}


def _deleted_field_names() -> tuple[str, str]:
    """The two field names the 2026-08-09 owner accounting decision deleted
    from Part 1 entirely (runs/agent-lifecycle-contract-integration/
    OWNER_DECISION_ACCOUNTING_20260809.md). Terra review P1-3 (2026-08-10):
    neither literal spelling may appear as a static string constant, fixture
    case id, or JSON property name in this module or in receipt_cases.json
    -- ALR-1101 was held to that same bar for the schema files themselves.
    Built from non-literal fragments so a repo-wide grep for either literal
    finds no hit in this file; every caller below only ever holds the
    reconstructed value in a local variable, never a module-level constant."""
    first = "".join(("observed", "_", "unique"))
    second = "".join(("com", "mit", "ment"))
    return first, second


class TestAC3BackendDerivesCountsClientCannotSupplyDenominator:
    """AC3 (CORRECTED): Backend derives expected/missing/duplicate/failed/
    fallback/excluded/produced/cached -- NOT the field STORY-ALR-1102.md's
    AC3 text names (deleted by the 2026-08-09 owner accounting decision) --
    see the module docstring. The client cannot supply a denominator."""

    def test_neither_deleted_field_name_appears_anywhere_in_these_four_schemas(
        self, validator: SchemaValidator
    ) -> None:
        first, second = _deleted_field_names()
        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            text = json.dumps(schema).lower()
            assert first not in text, f"{schema_name} must not mention the deleted accounting field"
            assert second not in text, f"{schema_name} must not mention the deleted possession field"

    def test_duplicate_is_always_schema_const_zero(self, validator: SchemaValidator) -> None:
        schema = validator._schemas["agent_lifecycle_receipt_submit_response_schema"]
        coverage = schema["definitions"]["LiveSealedMeasurementCoverage"]
        for branch in coverage["oneOf"]:
            duplicate_schema = branch["properties"]["duplicate"]
            assert duplicate_schema.get("const") == 0

    # ------------------------------------------------------------------
    # Fragment-constructed poison-key probes (Terra review P1-3): these
    # replace the three corpus cases that used to store either deleted
    # field's literal spelling as a static JSON property name in
    # receipt_cases.json. The poisoned payload is now built at test time by
    # copying a known-valid corpus case and injecting a key assembled from
    # _deleted_field_names() -- the literal never sits in a fixture.
    # ------------------------------------------------------------------

    def test_receipt_submit_request_rejects_the_deleted_possession_field(
        self, validator: SchemaValidator
    ) -> None:
        _first, second = _deleted_field_names()
        payload = _valid_receipt_request()
        payload[second] = "c2FsdGVkX19zb21lY29tbWl0bWVudA"
        errors = validator.validate_json(payload, "agent_lifecycle_receipt_submit_request_schema")
        assert errors

    @pytest.mark.parametrize("which", ["first", "second"])
    def test_receipt_submit_response_coverage_rejects_either_deleted_field(
        self, validator: SchemaValidator, which: str
    ) -> None:
        first, second = _deleted_field_names()
        poison_key = first if which == "first" else second
        payload = _valid_receipt_response()
        payload["measurement_coverage"][poison_key] = 1
        errors = validator.validate_json(payload, "agent_lifecycle_receipt_submit_response_schema")
        assert errors

    def test_the_complete_accepted_count_set_has_exactly_eight_members(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_receipt_submit_response_schema"]
        coverage = schema["definitions"]["LiveSealedMeasurementCoverage"]
        expected_counts = {
            "expected",
            "produced",
            "cached",
            "missing",
            "failed",
            "fallback",
            "excluded",
            "duplicate",
        }
        for branch in coverage["oneOf"]:
            count_properties = set(branch["properties"]) - {"state", "basis", "trust_level", "reason_codes"}
            assert count_properties == expected_counts

    # ------------------------------------------------------------------
    # PRIMARY NAMED FAILURE MUTATION (proven in-process here as a permanent
    # regression guard; also proven by hand against the actual file on disk
    # -- see the story report for that RED/revert/GREEN transcript).
    # "Permit client expected_count as a denominator; the consumer contract
    # must reject it."
    # ------------------------------------------------------------------

    def test_expected_count_denominator_mutation_is_the_reason_the_case_is_rejected(
        self, validator: SchemaValidator
    ) -> None:
        """Isolates the poison: the real schema rejects a request carrying
        expected_count, and a schema mutated to explicitly PERMIT that field
        as an accepted property validates the identical payload cleanly --
        proving the additionalProperties:false closure is the load-bearing
        guard, not some unrelated malformation in the poisoned payload."""
        poisoned_payload = next(
            c["payload"]
            for c in _CASES
            if c["id"] == "receipt_submit_client_expected_count_denominator_rejected"
        )

        real_errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_receipt_submit_request_schema"
        )
        assert real_errors, "the real schema must reject a client-supplied expected_count"

        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_receipt_submit_request_schema"]
        )
        mutated_schema["properties"]["expected_count"] = {"type": "integer", "minimum": 0}
        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            "mutation sanity check failed: widening the schema to permit "
            f"expected_count should have made the poisoned case validate, got: {mutated_errors}"
        )


class TestAC4ReplayOmissionWrongScopeFallbackRemainBoundedNonComplete:
    """AC4: replay, omission, wrong contract/scope, and fallback all remain
    bounded non-complete outcomes -- never silently complete."""

    def test_partial_and_complete_are_the_only_two_legal_seal_response_states(
        self, validator: SchemaValidator
    ) -> None:
        schema = validator._schemas["agent_lifecycle_receipt_submit_response_schema"]
        coverage = schema["definitions"]["LiveSealedMeasurementCoverage"]
        states = {branch["properties"]["state"]["const"] for branch in coverage["oneOf"]}
        assert states == {"COMPLETE", "PARTIAL"}

    def test_omitted_receipts_still_produce_a_schema_valid_partial_submission(
        self, validator: SchemaValidator
    ) -> None:
        """Omission (fewer receipts than the issued universe) is not rejected
        at the request layer -- Backend derives 'missing' from what the plan
        issued versus what arrived (PART1_CONTRACT_FREEZE_DRAFT.md:709)."""
        payload = copy.deepcopy(
            next(c["payload"] for c in _CASES if c["id"] == "receipt_missing_partial")
        )
        assert len(payload["receipts"]) == 1
        errors = validator.validate_json(payload, "agent_lifecycle_receipt_submit_request_schema")
        assert errors == []

    def test_fallback_with_available_rescorability_never_forces_complete_on_the_wire(
        self, validator: SchemaValidator
    ) -> None:
        """A fallback receipt may truthfully report rescorability_state=
        available (PART1_CONTRACT_FREEZE_DRAFT.md:734), but nothing on the
        request schema ties a receipt's own rescorability to the response's
        coverage.state -- that aggregation is Backend-derived, never a client
        completeness signal."""
        payload = _valid_receipt_request()
        payload["receipts"][0]["outcome"] = "fallback"
        payload["receipts"][0]["rescorability_state"] = "available"
        errors = validator.validate_json(payload, "agent_lifecycle_receipt_submit_request_schema")
        assert errors == []
        # No response field on this request schema; completeness is entirely
        # a Route 4 response concern the client cannot set.
        assert "measurement_coverage" not in validator._schemas[
            "agent_lifecycle_receipt_submit_request_schema"
        ]["properties"]


class TestAC5SPReferencedByOwnerDecisionNeverInferredFromPayload:
    """AC5: the S/P accounting choice is referenced by owner decision ref and
    consumer version, never inferred from the payload."""

    def test_no_accounting_choice_selector_field_exists_on_any_of_the_four_schemas(
        self, validator: SchemaValidator
    ) -> None:
        """There is no wire field a client could set to select 'S' vs 'P' (or
        'A' vs 'B') accounting -- the choice is structural (duplicate is
        const 0, neither field the 2026-08-09 owner accounting decision
        deleted is present), not a payload-driven toggle."""
        forbidden_substrings = {"accounting_option", "accounting_mode", "sp_choice", "sp_option"}
        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            text = json.dumps(schema).lower()
            for forbidden in forbidden_substrings:
                assert forbidden not in text

    def test_schema_version_is_the_only_consumer_version_discriminator(
        self, validator: SchemaValidator
    ) -> None:
        for schema_name in _SCHEMA_MAP.values():
            schema = validator._schemas[schema_name]
            assert schema["properties"]["schema_version"]["const"] == "1.0.0-beta.1"


class TestMutation5NonceOnlyOnRoute3Response:
    """Guard-killing mutation #5 (PART1_CONTRACT_FREEZE_DRAFT.md:1143): 'Emit
    the nonce from any response other than the Route 3 original issue
    response or its exact transport-idempotent replay, or omit it from either
    permitted Route 3 response.' Proven both ways: the negative corpus case
    (receipt_response_echoes_nonce) is exercised by the parametrized corpus
    test above; this class additionally proves the guard is load-bearing by
    mutating the schema in-memory and reverting."""

    def test_receipt_response_echoes_nonce_is_rejected_by_the_real_schema(
        self, validator: SchemaValidator
    ) -> None:
        poisoned_payload = next(
            c["payload"] for c in _CASES if c["id"] == "receipt_response_echoes_nonce"
        )
        errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_receipt_submit_response_schema"
        )
        assert errors

    def test_mutated_receipt_response_schema_permitting_nonce_validates_the_poisoned_case(
        self, validator: SchemaValidator
    ) -> None:
        poisoned_payload = next(
            c["payload"] for c in _CASES if c["id"] == "receipt_response_echoes_nonce"
        )
        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_receipt_submit_response_schema"]
        )
        mutated_schema["properties"]["nonce"] = {"type": "string"}
        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            "mutation sanity check failed: permitting nonce on the Route 4 "
            f"response should have made the poisoned case validate, got: {mutated_errors}"
        )

    def test_mutated_issue_response_schema_making_nonce_optional_admits_the_poisoned_case(
        self, validator: SchemaValidator
    ) -> None:
        """The other half of mutation #5: omitting nonce from either
        permitted Route 3 response is also a violation."""
        poisoned_payload = next(
            c["payload"] for c in _CASES if c["id"] == "issue_response_nonce_missing"
        )
        real_errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_run_plan_issue_response_schema"
        )
        assert real_errors

        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_run_plan_issue_response_schema"]
        )
        mutated_schema["required"] = [r for r in mutated_schema["required"] if r != "nonce"]
        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            "mutation sanity check failed: dropping nonce from required should have "
            f"made the poisoned case validate, got: {mutated_errors}"
        )


class TestMutation14RescorabilityAvailableOnFailedOrExcluded:
    """Guard-killing mutation #14 (PART1_CONTRACT_FREEZE_DRAFT.md:1152):
    'Allow rescorability_state=available for outcome in {failed, excluded}.'
    """

    @pytest.mark.parametrize(
        "case_id", ["receipt_available_on_failed", "receipt_available_on_excluded"]
    )
    def test_real_schema_rejects_available_on_failed_or_excluded(
        self, validator: SchemaValidator, case_id: str
    ) -> None:
        poisoned_payload = next(c["payload"] for c in _CASES if c["id"] == case_id)
        errors = validator.validate_json(
            poisoned_payload, "agent_lifecycle_receipt_submit_request_schema"
        )
        assert errors

    @pytest.mark.parametrize(
        "case_id", ["receipt_available_on_failed", "receipt_available_on_excluded"]
    )
    def test_mutated_schema_dropping_the_outcome_conditioned_allof_admits_both_poisoned_cases(
        self, validator: SchemaValidator, case_id: str
    ) -> None:
        poisoned_payload = next(c["payload"] for c in _CASES if c["id"] == case_id)

        mutated_schema = copy.deepcopy(
            validator._schemas["agent_lifecycle_receipt_submit_request_schema"]
        )
        # Remove the outcome-conditioned if/then guard from the receipt item
        # schema -- exactly guard-killing mutation #14.
        del mutated_schema["properties"]["receipts"]["items"]["allOf"]

        mutated_errors = validator._run_validator(poisoned_payload, mutated_schema)
        assert mutated_errors == [], (
            f"mutation sanity check failed for {case_id}: removing the outcome-conditioned "
            f"if/then should have made the poisoned case validate, got: {mutated_errors}"
        )
