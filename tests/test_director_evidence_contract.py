# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Director evidence v2 schema (G1 contracts §2-§4).

Each test group below is named after the acceptance item it proves (T-S brief /
instruction, "Acceptance mapping"). Reject cases assert a specific structural
reason (branch mismatch, envelope shape, grant invariant), never a tautology.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir, load_schema
from traigent_schema.validator import _FORMAT_CHECKER

SCHEMAS_DIR = get_schemas_dir()
ANALYTICS_DIR = SCHEMAS_DIR / "analytics"
DATA_DIR = Path(__file__).parent / "test_data" / "analytics"

DTO = json.loads((ANALYTICS_DIR / "director_evidence_schema.json").read_text(encoding="utf-8"))
ENVELOPE = json.loads(
    (ANALYTICS_DIR / "director_evidence_response_schema.json").read_text(encoding="utf-8")
)

REGISTRY = Registry().with_resources(
    [
        (DTO["$id"], Resource.from_contents(DTO)),
        (ENVELOPE["$id"], Resource.from_contents(ENVELOPE)),
    ]
)

A = json.loads((DATA_DIR / "director_evidence_available_valid.json").read_text(encoding="utf-8"))
B = json.loads((DATA_DIR / "director_evidence_abstain_valid.json").read_text(encoding="utf-8"))
C = json.loads(
    (DATA_DIR / "director_evidence_privacy_abstain_valid.json").read_text(encoding="utf-8")
)

SUPPRESSED = ["completed_trials", "recorded_observations", "mean_quality", "nonzero_cost", "age"]
ORDINARY_REASONS = DTO["definitions"]["ordinary_abstain_reason"]["enum"]


def dto_errors(payload: dict) -> list:
    return list(Draft7Validator(DTO, registry=REGISTRY).iter_errors(payload))


def envelope_errors(payload: dict) -> list:
    return list(Draft7Validator(ENVELOPE, registry=REGISTRY).iter_errors(payload))


def matching_branches(payload: dict) -> list[str]:
    names = ["branch_available", "branch_abstain", "branch_privacy_abstain"]
    out = []
    for name in names:
        sub = {"$ref": f"{DTO['$id']}#/definitions/{name}"}
        if not list(Draft7Validator(sub, registry=REGISTRY).iter_errors(payload)):
            out.append(name)
    return out


# ---------------------------------------------------------------------------
# Item 1 — each canonical fixture validates and matches exactly one branch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture,branch",
    [(A, "branch_available"), (B, "branch_abstain"), (C, "branch_privacy_abstain")],
    ids=["available", "ordinary_abstain", "privacy_abstain"],
)
def test_item1_canonical_fixture_matches_exactly_one_branch(fixture, branch) -> None:
    assert dto_errors(fixture) == []
    assert matching_branches(fixture) == [branch]


@pytest.mark.parametrize("reason", ORDINARY_REASONS)
def test_item1_every_ordinary_reason_selects_branch_b_only(reason: str) -> None:
    payload = {**B, "abstain_reason": reason}
    assert matching_branches(payload) == ["branch_abstain"]


# ---------------------------------------------------------------------------
# Item 2 — suppressed-field rejection, null != absent, privacy forbids provenance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", SUPPRESSED)
def test_item2_ordinary_abstain_rejects_present_suppressed_field(field: str) -> None:
    assert dto_errors({**B, field: A[field]})


@pytest.mark.parametrize("field", SUPPRESSED)
def test_item2_ordinary_abstain_rejects_null_suppressed_field(field: str) -> None:
    assert dto_errors({**B, field: None})


@pytest.mark.parametrize("field", SUPPRESSED)
def test_item2_privacy_abstain_rejects_present_suppressed_field(field: str) -> None:
    assert dto_errors({**C, field: A[field]})


@pytest.mark.parametrize("field", SUPPRESSED)
def test_item2_privacy_abstain_rejects_null_suppressed_field(field: str) -> None:
    assert dto_errors({**C, field: None})


def test_item2_privacy_abstain_rejects_present_provenance() -> None:
    assert dto_errors({**C, "provenance": "unknown"})


def test_item2_privacy_abstain_rejects_null_provenance() -> None:
    assert dto_errors({**C, "provenance": None})


def test_item2_available_rejects_abstain_reason() -> None:
    assert dto_errors({**A, "abstain_reason": "too_few_trials"})


def test_item2_ordinary_abstain_rejects_privacy_mode_reason() -> None:
    assert dto_errors({**B, "abstain_reason": "privacy_mode"})


# ---------------------------------------------------------------------------
# Item 3 — evidence_available <=> mean_quality; completed_trials/pct_bucket enums
# ---------------------------------------------------------------------------


def test_item3_evidence_available_true_without_mean_quality_rejected() -> None:
    payload = copy.deepcopy(A)
    del payload["mean_quality"]
    assert dto_errors(payload)


def test_item3_evidence_available_false_with_mean_quality_rejected() -> None:
    assert dto_errors({**B, "mean_quality": A["mean_quality"]})


@pytest.mark.parametrize(
    "value,ok",
    [("3-9", True), ("10+", True), ("0", False), ("1-2", False), (3, False), ("3-10", False)],
)
def test_item3_completed_trials_enum_is_exactly_3_9_and_10_plus(value, ok: bool) -> None:
    errors = dto_errors({**A, "completed_trials": value})
    assert (errors == []) is ok


@pytest.mark.parametrize(
    "value,ok",
    [
        (0, True),
        (5, True),
        (85, True),
        (100, True),
        (83, False),
        (-5, False),
        (105, False),
        ("85.0", False),
        (None, False),
    ],
)
def test_item3_pct_bucket_is_multiple_of_five_in_0_to_100(value, ok: bool) -> None:
    errors = dto_errors({**A, "mean_quality": {"pct_bucket": value}})
    assert (errors == []) is ok


# ---------------------------------------------------------------------------
# Item 4 — envelope shape: {success, message?, data, meta?, warnings?}
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", [A, B, C], ids=["available", "ordinary_abstain", "privacy_abstain"])
def test_item4_envelope_accepts_bare_success_and_data(fixture) -> None:
    assert envelope_errors({"success": True, "data": fixture}) == []


@pytest.mark.parametrize("fixture", [A, B, C], ids=["available", "ordinary_abstain", "privacy_abstain"])
def test_item4_envelope_accepts_message_meta_and_warnings(fixture) -> None:
    payload = {"success": True, "message": "ok", "data": fixture, "meta": {}, "warnings": []}
    assert envelope_errors(payload) == []


def test_item4_envelope_rejects_success_false() -> None:
    assert envelope_errors({"success": False, "data": A})


def test_item4_envelope_rejects_missing_success() -> None:
    assert envelope_errors({"data": A})


def test_item4_envelope_rejects_missing_data() -> None:
    assert envelope_errors({"success": True})


def test_item4_envelope_rejects_extra_top_level_metadata_key() -> None:
    assert envelope_errors({"success": True, "data": A, "metadata": {}})


# ---------------------------------------------------------------------------
# Item 5 — authorization vocabulary: scope -> permission, restricted, never
# user-requestable, scope pattern still equals x-scope-convention pattern
# ---------------------------------------------------------------------------

VOCAB_SCHEMA_NAME = "api_key_authorization_vocabulary_schema"


def test_item5_scope_maps_to_permission() -> None:
    schema = load_schema(VOCAB_SCHEMA_NAME)
    assert schema["x-scope-permission-map"]["director_evidence:read"]["permissions"] == [
        "director_evidence.read"
    ]


def test_item5_scope_listed_in_restricted_scopes() -> None:
    schema = load_schema(VOCAB_SCHEMA_NAME)
    assert "director_evidence:read" in schema["x-restricted-scopes"]


def test_item5_restricted_scopes_declared_in_x_extensions_meta_schema() -> None:
    meta_schema = load_schema("x_extensions_meta_schema")
    assert "x-restricted-scopes" in meta_schema["properties"]


def test_item5_scope_not_user_requestable() -> None:
    schema = load_schema(VOCAB_SCHEMA_NAME)
    assert "director_evidence:read" not in schema["x-user-requestable-scopes"]
    assert (
        "director_evidence:read"
        not in schema["definitions"]["UserRequestableApiKeyScopeToken"]["enum"]
    )


def test_item5_scope_token_pattern_still_equals_convention_pattern() -> None:
    schema = load_schema(VOCAB_SCHEMA_NAME)
    assert schema["definitions"]["ApiKeyScopeToken"]["pattern"] == schema["x-scope-convention"][
        "pattern"
    ]


# ---------------------------------------------------------------------------
# Item 6 — create/update/rotate request schemas: Director key invariants
# ---------------------------------------------------------------------------

CREATE_SCHEMA_NAME = "api_key_create_request_schema"
UPDATE_SCHEMA_NAME = "api_key_update_request_schema"
ROTATE_SCHEMA_NAME = "api_key_rotate_request_schema"


def create_errors(payload: dict) -> list:
    schema = load_schema(CREATE_SCHEMA_NAME)
    return [str(e) for e in Draft7Validator(schema, format_checker=_FORMAT_CHECKER).iter_errors(payload)]


def update_errors(payload: dict) -> list:
    schema = load_schema(UPDATE_SCHEMA_NAME)
    return [str(e) for e in Draft7Validator(schema, format_checker=_FORMAT_CHECKER).iter_errors(payload)]


def rotate_errors(payload: dict) -> list:
    schema = load_schema(ROTATE_SCHEMA_NAME)
    return [str(e) for e in Draft7Validator(schema, format_checker=_FORMAT_CHECKER).iter_errors(payload)]


def _valid_grant(**overrides) -> dict:
    grant = {
        "resource_type": "experiment",
        "resource_id": "exp-1",
        "permissions": ["read"],
        "expires_at": "2026-10-01T00:00:00Z",
    }
    grant.update(overrides)
    return grant


def _base_director_create() -> dict:
    return {
        "key_name": "d",
        "key_type": "director",
        "scopes": ["director_evidence:read"],
        "permissions": [],
        "resource_grants": [_valid_grant()],
    }


def test_item6_create_valid_director_request_validates() -> None:
    assert create_errors(_base_director_create()) == []


DIRECTOR_CREATE_MUTATIONS = [
    ("scopes_missing", lambda p: p.pop("scopes")),
    ("scopes_not_director_evidence_read", lambda p: p.__setitem__("scopes", ["experiments:read"])),
    (
        "scopes_has_extra_token",
        lambda p: p.__setitem__("scopes", ["director_evidence:read", "experiments:read"]),
    ),
    ("permissions_missing", lambda p: p.pop("permissions")),
    ("permissions_nonempty", lambda p: p.__setitem__("permissions", ["read"])),
    ("resource_grants_missing", lambda p: p.pop("resource_grants")),
    ("resource_grants_empty", lambda p: p.__setitem__("resource_grants", [])),
    ("grant_permission_write", lambda p: p["resource_grants"][0].__setitem__("permissions", ["write"])),
    (
        "grant_permission_duplicate_read",
        lambda p: p["resource_grants"][0].__setitem__("permissions", ["read", "read"]),
    ),
    ("grant_resource_type_project", lambda p: p["resource_grants"][0].__setitem__("resource_type", "project")),
    ("grant_missing_expires_at", lambda p: p["resource_grants"][0].pop("expires_at")),
    ("grant_expires_at_not_a_date", lambda p: p["resource_grants"][0].__setitem__("expires_at", "not-a-date")),
    ("grant_extra_property", lambda p: p["resource_grants"][0].__setitem__("extra", "x")),
    ("scope_preset_present", lambda p: p.__setitem__("scope_preset", "minimal")),
]


@pytest.mark.parametrize(
    "case_id,mutate", DIRECTOR_CREATE_MUTATIONS, ids=[c[0] for c in DIRECTOR_CREATE_MUTATIONS]
)
def test_item6_create_director_request_rejects(case_id: str, mutate) -> None:
    payload = _base_director_create()
    mutate(payload)
    assert create_errors(payload), case_id


NON_DIRECTOR_KEY_TYPES = ["user", "service", "admin", "temporary", "readonly", "system", None]


@pytest.mark.parametrize("key_type", NON_DIRECTOR_KEY_TYPES, ids=lambda kt: kt or "omitted")
def test_item6f4_non_director_empty_scopes_rejected(key_type) -> None:
    payload = {"key_name": "k", "scopes": []}
    if key_type is not None:
        payload["key_type"] = key_type
    assert create_errors(payload)


@pytest.mark.parametrize("key_type", NON_DIRECTOR_KEY_TYPES, ids=lambda kt: kt or "omitted")
def test_item6f4_non_director_empty_permissions_rejected(key_type) -> None:
    payload = {"key_name": "k", "permissions": []}
    if key_type is not None:
        payload["key_type"] = key_type
    assert create_errors(payload)


@pytest.mark.parametrize("key_type", NON_DIRECTOR_KEY_TYPES, ids=lambda kt: kt or "omitted")
def test_item6f4_non_director_valid_scopes_and_permissions_accepted(key_type) -> None:
    payload = {"key_name": "k", "scopes": ["experiments:read"], "permissions": ["read"]}
    if key_type is not None:
        payload["key_type"] = key_type
    assert create_errors(payload) == []


@pytest.mark.parametrize("key_type", NON_DIRECTOR_KEY_TYPES, ids=lambda kt: kt or "omitted")
def test_item6f4_non_director_omitted_scopes_and_permissions_accepted(key_type) -> None:
    payload = {"key_name": "k"}
    if key_type is not None:
        payload["key_type"] = key_type
    assert create_errors(payload) == []


@pytest.mark.parametrize("key_type", NON_DIRECTOR_KEY_TYPES, ids=lambda kt: kt or "omitted")
def test_item6f4_non_director_resource_grants_rejected(key_type) -> None:
    payload = {"key_name": "k", "resource_grants": [_valid_grant()]}
    if key_type is not None:
        payload["key_type"] = key_type
    assert create_errors(payload)


def test_item6_create_backend_obligations_mention_30_day_grant_bound() -> None:
    schema = load_schema(CREATE_SCHEMA_NAME)
    assert any("30 days" in obligation for obligation in schema["x-backend-obligations"])


def test_item6_update_key_name_only_validates() -> None:
    assert update_errors({"key_name": "x"}) == []


def test_item6_update_key_type_rejected() -> None:
    assert update_errors({"key_type": "director"})


def test_item6_update_resource_grants_rejected() -> None:
    assert update_errors({"resource_grants": [_valid_grant()]})


def test_item6_update_has_backend_obligations() -> None:
    schema = load_schema(UPDATE_SCHEMA_NAME)
    assert schema.get("x-backend-obligations")


def test_item6_rotate_strategy_immediate_validates() -> None:
    assert rotate_errors({"strategy": "immediate"}) == []


def test_item6_rotate_key_type_rejected() -> None:
    assert rotate_errors({"key_type": "director"})


def test_item6_rotate_has_backend_obligations() -> None:
    schema = load_schema(ROTATE_SCHEMA_NAME)
    assert schema.get("x-backend-obligations")


# ---------------------------------------------------------------------------
# Item 7 — advertised route is contract-first (backend does not serve it yet)
# ---------------------------------------------------------------------------


def test_item7_director_evidence_route_is_contract_first() -> None:
    endpoints = json.loads((ANALYTICS_DIR / "analytics_endpoints.json").read_text(encoding="utf-8"))
    operation = endpoints["paths"]["/api/v1/analytics/runs/{run_id}/director-evidence"]["get"]
    assert operation.get("x-asserted-against-backend") is False


# ---------------------------------------------------------------------------
# Item 8 — envelope compatibility: repo (relative $ref) vs Director-vendored
# (absolute $ref) variants both validate the canonical fixtures, and the two
# variants are structurally identical apart from $ref/$id/description.
# ---------------------------------------------------------------------------

# Inlined, not a file in the packet's edit boundary: the Director-vendored
# envelope variant from ~/.claude/plans/2026-09-15-director-G1-artifacts/
# director_evidence_response_schema.json, with an absolute $ref to the DTO.
VENDORED_ENVELOPE = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "$id": "https://schemas.traigent.ai/analytics/director_evidence_response_schema.json",
    "title": "Director Evidence Success Response",
    "description": "Director-vendored envelope variant (G1 artifact), inlined here for the F8 compatibility test.",
    "type": "object",
    "additionalProperties": False,
    "required": ["success", "data"],
    "properties": {
        "success": {"type": "boolean", "const": True},
        "message": {"type": "string", "maxLength": 240},
        "data": {"$ref": "https://schemas.traigent.ai/analytics/director_evidence_schema.json"},
        "meta": {"type": "object", "additionalProperties": True},
        "warnings": {"type": "array", "items": {"type": "object"}},
    },
}


def vendored_envelope_errors(payload: dict) -> list:
    return list(Draft7Validator(VENDORED_ENVELOPE, registry=REGISTRY).iter_errors(payload))


@pytest.mark.parametrize("fixture", [A, B, C], ids=["available", "ordinary_abstain", "privacy_abstain"])
def test_item8_fixture_validates_against_repo_envelope(fixture) -> None:
    assert envelope_errors({"success": True, "data": fixture}) == []


@pytest.mark.parametrize("fixture", [A, B, C], ids=["available", "ordinary_abstain", "privacy_abstain"])
def test_item8_fixture_validates_against_vendored_envelope(fixture) -> None:
    assert vendored_envelope_errors({"success": True, "data": fixture}) == []


def _normalize_envelope_for_comparison(schema: dict) -> dict:
    normalized = copy.deepcopy(schema)
    normalized.pop("$id", None)
    normalized.pop("description", None)
    normalized["properties"]["data"].pop("$ref", None)
    return normalized


def test_item8_repo_and_vendored_envelope_equal_apart_from_ref_id_description() -> None:
    assert _normalize_envelope_for_comparison(ENVELOPE) == _normalize_envelope_for_comparison(
        VENDORED_ENVELOPE
    )
