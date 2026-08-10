# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""ALR-1105 (freeze-completion packet): the two Internal Contract Freeze
mutation-inventory rows the plan left with no owning story
(runs/agent-lifecycle-contract-integration/PART1_CONTRACT_FREEZE_DRAFT.md:1140,
:1146). Without these guards, neither mutation could ever be proven red, and
Internal Contract Freeze could never be recorded for the full 5/5 Schema-owned
set.

Row 2 -- identity-vocabulary separation
    Guard-killing mutation: alias ExperimentGroup's `identified` grouping
    vocabulary onto lifecycle `IdentityStateAxisValue.VERIFIED`.
    ``test_identity_vocabularies_are_structurally_separate`` is the exact
    test path/name the contract names at :1140.

Row 8 -- Route 5 closed response schema
    Guard-killing mutation: add a lifecycle `legacy_claims` projection, or
    map legacy `CERTIFIED_SELECTION` onto Qualification/Standing, in
    ``agent_lifecycle_record_response_schema.json`` (PART1_CONTRACT_FREEZE_DRAFT.md:1146).

Binding owner constraint (OWNER_DECISION_ACCOUNTING_20260809.md, Option A):
no `commitment`, no `observed_unique` -- not as properties, not as literal
strings, anywhere in this module (including fixtures/case ids).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

_SCHEMAS_DIR = get_schemas_dir()
_LIFECYCLE_SCHEMA_DIR = _SCHEMAS_DIR / "agent_lifecycle_record"
_COMMON_SCHEMA_RELATIVE_PATH = "agent_lifecycle_record/agent_lifecycle_common_schema.json"
_ROUTE5_SCHEMA_RELATIVE_PATH = "agent_lifecycle_record/agent_lifecycle_record_response_schema.json"
_ROUTE5_SCHEMA_NAME = "agent_lifecycle_record_response_schema"

# The vocabulary Schema #400 uses for ExperimentGroup grouping identity
# (PART1_CONTRACT_FREEZE_DRAFT.md:228) plus the two adjacent readings named
# explicitly in row 2's guard text (:1140) -- lifecycle's own
# IdentityStateAxisValue.value enum must never contain any of these four.
_FORBIDDEN_IDENTITY_VOCABULARY = {"identified", "unidentified", "partial", "unknown"}

_EXPERIMENT_GROUP_REF_TARGET = "execution/experiment_group_schema.json"


def _load_schema(relative_path: str) -> dict[str, Any]:
    with open(_SCHEMAS_DIR / relative_path, encoding="utf-8") as handle:
        result: dict[str, Any] = json.load(handle)
        return result


def _lifecycle_schema_paths() -> list[Path]:
    """Every schema file currently under agent_lifecycle_record/ on this
    branch. Scoped to the directory (not hardcoded to today's two files) so
    a later story's new lifecycle schema is automatically covered by row 2's
    $ref guard without editing this module."""
    return sorted(_LIFECYCLE_SCHEMA_DIR.glob("*.json"))


def _iter_ref_values(node: object) -> list[str]:
    refs: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "$ref" and isinstance(child, str):
                    refs.append(child)
                else:
                    visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return refs


def _iter_all_keys_and_string_values(node: object) -> list[str]:
    """Every dict key and every string value anywhere in ``node``, recursively."""
    strings: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                strings.append(key)
                visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            strings.append(value)

    visit(node)
    return strings


def _iter_dict_keys(node: object) -> list[str]:
    """Every dict key anywhere in ``node``, recursively -- i.e. every JSON
    Schema *property name* (a ``TypedOpaqueRef.kind`` reserved enum member
    like ``"qualification"`` is a string *value* inside a list, never a dict
    key, so it is correctly excluded here)."""
    keys: list[str] = []

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                keys.append(key)
                visit(child)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(node)
    return keys


def _identity_state_axis_value_consts(common_schema: dict[str, Any]) -> set[str]:
    """Every literal ``value`` const/enum member of
    ``#/definitions/IdentityStateAxisValue`` in the common schema."""
    axis = common_schema["definitions"]["IdentityStateAxisValue"]
    consts: set[str] = set()
    for branch in axis["oneOf"]:
        value_schema = branch["properties"]["value"]
        if "const" in value_schema:
            consts.add(value_schema["const"])
        consts.update(value_schema.get("enum", []))
    return consts


class TestIdentityVocabulariesAreStructurallySeparate:
    """Row 2 (PART1_CONTRACT_FREEZE_DRAFT.md:1140). The named guard-killing
    mutation is: alias ExperimentGroup `identified` to lifecycle `VERIFIED`.
    """

    def test_identity_vocabularies_are_structurally_separate(self) -> None:
        common_schema = _load_schema(_COMMON_SCHEMA_RELATIVE_PATH)

        identity_values = _identity_state_axis_value_consts(common_schema)
        leaked_vocabulary = identity_values & _FORBIDDEN_IDENTITY_VOCABULARY
        assert not leaked_vocabulary, (
            "lifecycle IdentityStateAxisValue.value enum leaked ExperimentGroup-"
            f"family vocabulary: {sorted(leaked_vocabulary)} "
            "(PART1_CONTRACT_FREEZE_DRAFT.md:1140)"
        )

        for path in _lifecycle_schema_paths():
            relative_path = path.relative_to(_SCHEMAS_DIR).as_posix()
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)

            offending_refs = [
                ref for ref in _iter_ref_values(document) if _EXPERIMENT_GROUP_REF_TARGET in ref
            ]
            assert not offending_refs, (
                f"{relative_path} $refs {_EXPERIMENT_GROUP_REF_TARGET}: {offending_refs} "
                "-- lifecycle identity must remain structurally separate from "
                "ExperimentGroup grouping identity (PART1_CONTRACT_FREEZE_DRAFT.md:1140)"
            )

    def test_forbidden_identity_vocabulary_canary(self) -> None:
        """Negative control: prove the extraction helper itself would catch
        the named mutation if it were applied. Directly exercises the same
        assertion shape as the guard above against a synthetic axis payload
        so a change to the extraction logic that silently stopped scanning
        `value` consts would be caught here, not only by (never) seeing a
        real leak in the checked-in common schema."""
        mutated_axis = {
            "oneOf": [
                {"properties": {"value": {"const": "identified"}}},
                {"properties": {"value": {"const": "RECONSTRUCTED"}}},
            ]
        }
        consts = _identity_state_axis_value_consts({"definitions": {"IdentityStateAxisValue": mutated_axis}})
        assert consts & _FORBIDDEN_IDENTITY_VOCABULARY == {"identified"}


# ---------------------------------------------------------------------------
# Row 8: Route 5 closed response schema
# ---------------------------------------------------------------------------

_EXPECTED_ROUTE5_TOP_LEVEL_PROPERTIES = {
    "schema_version",
    "record_ref",
    "agent_ref",
    "agent_revision_ref",
    "created_at",
    "as_of",
    "governance_profile",
    "identity_state",
    "measurement_coverage",
    "pending_episode",
    "comparability_verdict",
    "bindings",
    "evidence_episodes",
    "rescorability",
}

# PART1_CONTRACT_FREEZE_DRAFT.md:789: Route 5 deliberately has no
# qualification/standing/permit/invalidation/decision field, and :1465
# (Owner decision card 2, Option A): no release/release.state field either
# -- not merely defaulted or nulled. `legacy_claims` is row 8's own named
# corpus case (:1051).
_FORBIDDEN_ROUTE5_PROPERTY_NAMES = {
    "legacy_claims",
    "qualification",
    "standing",
    "permit",
    "decision",
    "invalidation",
    "release",
}


def _opaque_ref_id(seed: str) -> str:
    """A synthetic id matching OpaqueRefId's pattern (16-128 chars,
    ``^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$``); 20 characters is comfortably
    inside that range."""
    return (seed * 20)[:20]


def _minimal_valid_route5_payload() -> dict[str, Any]:
    """One minimal, fully closed-schema-valid Route 5 response: the
    marker-free UNMEASURED/no-live-activity branch (mirrors corpus case
    `record_reconstructed_unmeasured`/`record_no_sealed_evidence_episode...`
    shape, PART1_CONTRACT_FREEZE_DRAFT.md:982-983) -- empty bindings/
    evidence_episodes, no pending episode, marker-free UNMEASURED coverage,
    and the no-live-seal rescorability default."""
    return {
        "schema_version": "1.0.0-beta.1",
        "record_ref": {
            "kind": "agent_lifecycle_record",
            "id": _opaque_ref_id("r"),
            "version_id": _opaque_ref_id("r"),
        },
        "agent_ref": {"kind": "agent", "id": _opaque_ref_id("a")},
        "agent_revision_ref": {
            "kind": "agent_revision",
            "id": _opaque_ref_id("v"),
            "version_id": _opaque_ref_id("v"),
        },
        "created_at": "2026-08-01T00:00:00Z",
        "as_of": "2026-08-09T00:00:00Z",
        "governance_profile": {
            "value": "OBSERVED",
            "trust_level": "backend_observed",
            "reason_codes": [],
        },
        "identity_state": {
            "value": "UNKNOWN",
            "trust_level": "client_attested",
            "reason_codes": ["REQUIRED_IDENTITY_UNKNOWN"],
        },
        "measurement_coverage": {
            "state": "UNMEASURED",
            "basis": "NO_EVIDENCE_EPISODE",
            "trust_level": "backend_observed",
            "expected": 0,
            "produced": 0,
            "cached": 0,
            "missing": 0,
            "failed": 0,
            "fallback": 0,
            "excluded": 0,
            "duplicate": 0,
            "reason_codes": ["NO_EVIDENCE_EPISODE"],
        },
        "pending_episode": None,
        "comparability_verdict": {
            "value": "NOT_APPLICABLE",
            "trust_level": "backend_observed",
            "reason_codes": ["SINGLE_SUBJECT"],
        },
        "bindings": [],
        "evidence_episodes": [],
        "rescorability": {
            "state": "unknown",
            "trust_level": "client_attested",
            "authority_effect": "NONE",
        },
    }


class TestRoute5ClosedResponseSchema:
    """Row 8 (PART1_CONTRACT_FREEZE_DRAFT.md:1146). The named guard-killing
    mutation is: add a lifecycle `legacy_claims` projection, or map legacy
    `CERTIFIED_SELECTION` onto Qualification/Standing.

    The other half of row 8's required red guard -- "the unchanged
    legacy-schema compatibility assertion keeps the existing wire visibly
    legacy/client-attested/non-authorizing" -- is the pre-existing
    ``tests/test_certified_selection_schema.py`` suite (in particular
    ``TestCertifiedSelectionReport`` and
    ``TestFinalizeSelectionBasis::test_attestation_enum``, which already
    rejects a ``server_verified`` attestation). This packet does not touch
    ``certified_selection_schema.json`` or that test module; both are
    exercised unmodified by the full-suite run this packet's report cites.
    """

    @pytest.fixture
    def validator(self) -> SchemaValidator:
        return SchemaValidator()

    def test_minimal_valid_route5_payload_accepted(self, validator: SchemaValidator) -> None:
        errors = validator.validate_json(_minimal_valid_route5_payload(), _ROUTE5_SCHEMA_NAME)
        assert errors == [], f"unexpected errors: {errors}"

    def test_record_response_legacy_claims_property_rejected(
        self, validator: SchemaValidator
    ) -> None:
        """Corpus case `record_response_legacy_claims_property_rejected`
        (PART1_CONTRACT_FREEZE_DRAFT.md:1051): Route 5 is closed and has no
        `legacy_claims` property; injecting one must be rejected by
        `additionalProperties: false`."""
        payload = _minimal_valid_route5_payload()
        payload["legacy_claims"] = {"decision": "CERTIFIED_SELECTION"}

        errors = validator.validate_json(payload, _ROUTE5_SCHEMA_NAME)

        assert errors, "expected rejection but payload validated cleanly"
        assert any(
            "legacy_claims" in error or "Additional properties" in error for error in errors
        )

    def test_route5_schema_top_level_properties_are_exact(self) -> None:
        """Anti-vacuity by exact membership (mirrors the P2-2 pattern in
        test_agent_lifecycle_schemas.py): a mutation that adds ANY new
        top-level property -- legacy_claims, qualification, standing,
        permit, decision, invalidation, release -- must trip this, not only
        the specifically-named legacy_claims corpus case above."""
        schema = _load_schema(_ROUTE5_SCHEMA_RELATIVE_PATH)

        assert set(schema["properties"]) == _EXPECTED_ROUTE5_TOP_LEVEL_PROPERTIES
        assert set(schema["required"]) == _EXPECTED_ROUTE5_TOP_LEVEL_PROPERTIES
        assert schema["additionalProperties"] is False

    def test_route5_schema_never_names_a_forbidden_property_anywhere(self) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:789: Route 5 deliberately has no
        qualification, standing, permit, invalidation, or decision field
        anywhere, and :1465 that `release` (`release.state`) does not appear
        in the Route 5 response schema at all -- not merely defaulted or
        nulled. Checked recursively (every dict *key* at every depth, i.e.
        every JSON Schema property name -- not the ``TypedOpaqueRef.kind``
        reserved enum *values* ``qualification``/``standing``/``decision``/
        ``invalidation``, which are legitimate shared ref-kind vocabulary
        per PART1_CONTRACT_FREEZE_DRAFT.md:293 and never assigned to any
        actual property on this document), so a mutation cannot dodge the
        exact-membership check above by nesting the forbidden field one
        level down (e.g. inside a `bindings[]` item or the `rescorability`
        object)."""
        schema = _load_schema(_ROUTE5_SCHEMA_RELATIVE_PATH)
        keys = {key for key in _iter_dict_keys(schema) if key in _FORBIDDEN_ROUTE5_PROPERTY_NAMES}
        assert not keys, f"forbidden property name(s) present in Route 5 schema: {sorted(keys)}"

    def test_route5_schema_never_references_legacy_certified_selection(self) -> None:
        """PART1_CONTRACT_FREEZE_DRAFT.md:116/898/965: the existing legacy
        `CERTIFIED_SELECTION` wire is untouched by Part 1, and Route 5
        performs no legacy-claim join -- the literal value must not appear
        anywhere in this schema (catches a mapping introduced through a
        nested enum/const rather than a top-level property name)."""
        schema = _load_schema(_ROUTE5_SCHEMA_RELATIVE_PATH)
        values = set(_iter_all_keys_and_string_values(schema))
        assert "CERTIFIED_SELECTION" not in values

    def test_route5_forbidden_property_scan_canary(self) -> None:
        """Negative control: prove the recursive key scan actually catches a
        forbidden name nested below the top level, not only at the root
        (where the exact-membership test above would already catch it)."""
        mutated_schema = {
            "properties": {
                "rescorability": {
                    "properties": {
                        "standing": {"const": "QUALIFIED"},
                    }
                }
            }
        }
        keys = {key for key in _iter_dict_keys(mutated_schema) if key in _FORBIDDEN_ROUTE5_PROPERTY_NAMES}
        assert keys == {"standing"}

    def test_forbidden_property_scan_ignores_reserved_ref_kind_enum_values(self) -> None:
        """Negative control for the dict-keys-only design: a
        ``TypedOpaqueRef.kind``-shaped enum listing the reserved
        ``qualification``/``standing``/``decision``/``invalidation`` values
        (legitimate per PART1_CONTRACT_FREEZE_DRAFT.md:293) must NOT trip
        the forbidden-property-name guard merely because those strings
        appear as enum *values* -- only as dict *keys* (actual property
        names) is it a real leak."""
        reserved_kind_enum_document = {
            "properties": {
                "some_ref": {
                    "properties": {
                        "kind": {
                            "enum": [
                                "decision",
                                "claim",
                                "qualification",
                                "standing",
                                "dependency",
                                "invalidation",
                            ]
                        }
                    }
                }
            }
        }
        keys = {
            key
            for key in _iter_dict_keys(reserved_kind_enum_document)
            if key in _FORBIDDEN_ROUTE5_PROPERTY_NAMES
        }
        assert not keys, f"reserved enum values incorrectly treated as property names: {keys}"
