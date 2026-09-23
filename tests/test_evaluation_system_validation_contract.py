"""Contract tests for the E3 evaluation-system-validation family
(traigent_schema/schemas/evaluation_system_validation/): the append-only expert
sign-off record for one pillar of a project's evaluation system, and the
evaluation_system_reviewer capability grant that authorizes signing.

See business/product-personas/e3-validation-record-design.md (v0.2) for the
design this implements.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
FAMILY = SCHEMAS / "evaluation_system_validation"
VALIDATION_SCHEMA_PATH = FAMILY / "evaluation_system_validation_schema.json"
GRANT_SCHEMA_PATH = FAMILY / "evaluation_system_reviewer_grant_schema.json"
ENDPOINTS_PATH = FAMILY / "evaluation_system_validation_endpoints.json"
COMMON_SCHEMA_PATH = SCHEMAS / "agent_readiness" / "agent_readiness_common_schema.json"


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        if "_endpoints" in path.name:
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()


def _validator(path: Path, definition: str) -> Draft7Validator:
    document = json.loads(path.read_text(encoding="utf-8"))
    return Draft7Validator(
        {"$ref": f"{document['$id']}#/definitions/{definition}"}, registry=_REGISTRY
    )


CREATE_REQUEST = _validator(VALIDATION_SCHEMA_PATH, "ValidationCreateRequest")
RECORD = _validator(VALIDATION_SCHEMA_PATH, "ValidationRecord")
LIST_RESPONSE = _validator(VALIDATION_SCHEMA_PATH, "ValidationListResponse")
GRANT_CREATE_REQUEST = _validator(GRANT_SCHEMA_PATH, "ReviewerGrantCreateRequest")
GRANT_RECORD = _validator(GRANT_SCHEMA_PATH, "ReviewerGrantRecord")
GRANT_LIST_RESPONSE = _validator(GRANT_SCHEMA_PATH, "ReviewerGrantListResponse")
CAN_SIGN_RESPONSE = _validator(GRANT_SCHEMA_PATH, "ReviewerCanSignResponse")
EVALUATION_SYSTEM_VALIDITY = _validator(COMMON_SCHEMA_PATH, "EvaluationSystemValidity")
PILLAR_VALIDITY = _validator(COMMON_SCHEMA_PATH, "PillarValidity")


def _errors(validator: Draft7Validator, payload: Any) -> list[str]:
    return [e.message for e in validator.iter_errors(payload)]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _evaluator_create_request() -> dict[str, Any]:
    return {
        "record_kind": "validation",
        "pillar": "evaluator",
        "source_run_id": "run-1",
        "method": "expert_review",
        "outcome": "valid",
        "sample_size": 120,
        "agreement": {"kind": "percent_agreement", "value": "0.91", "compared_items": 120},
        "notes": "Reviewed by a senior domain expert.",
        "revokes": None,
    }


def _dataset_create_request() -> dict[str, Any]:
    req = _evaluator_create_request()
    req["pillar"] = "evaluation_dataset"
    req["agreement"] = {"kind": "label_accuracy", "value": "1.0", "compared_items": 50}
    return req


def _revocation_create_request() -> dict[str, Any]:
    return {
        "record_kind": "revocation",
        "pillar": "evaluator",
        "source_run_id": "run-1",
        "method": "expert_review",
        "outcome": None,
        "sample_size": None,
        "agreement": None,
        "notes": "The reviewed configuration was superseded.",
        "revokes": "esv_original",
    }


def _evaluator_subject_ref() -> dict[str, Any]:
    return {
        "kind": "evaluator_version",
        "evaluator_version_id": "ev-1",
        "evaluator_id": "evaluator-1",
        "version": 3,
        "config_fingerprint": "sha256:" + "a" * 64,
        "fingerprint_basis": "backend_observed",
    }


def _dataset_subject_ref(verified: bool = True) -> dict[str, Any]:
    return {
        "kind": "evaluation_dataset",
        "dataset_id": "dataset-1",
        "dataset_id_source": "registered",
        "content_fingerprint": "sha256:" + "b" * 64 if verified else None,
        "fingerprint_state": "verified" if verified else "unknown",
        "fingerprint_basis": "server_recorded_client_declaration",
        "hosted_updated_at": None,
    }


def _validation_record(pillar: str = "evaluator") -> dict[str, Any]:
    return {
        "validation_id": "esv_1",
        "record_kind": "validation",
        "pillar": pillar,
        "subject_ref": (
            _evaluator_subject_ref() if pillar == "evaluator" else _dataset_subject_ref()
        ),
        "source_run_id": "run-1",
        "method": "expert_review",
        "outcome": "valid",
        "sample_size": 120,
        "agreement": {"kind": "percent_agreement", "value": "0.91", "compared_items": 120}
        if pillar == "evaluator"
        else {"kind": "label_accuracy", "value": "1.0", "compared_items": 50},
        "notes": "Reviewed by a senior domain expert.",
        "reviewer": {"principal_kind": "USER", "principal_ref": "user-1"},
        "signed_under_grant_id": "rvg_1",
        "signed_under_self_grant": False,
        "signed_at": "2026-09-20T00:00:00Z",
        "revokes": None,
        "revoked_by": None,
        "observation_basis": "server_recorded_client_declaration",
    }


def _revocation_record() -> dict[str, Any]:
    record = _validation_record()
    record.update(
        {
            "validation_id": "esv_2",
            "record_kind": "revocation",
            "outcome": None,
            "sample_size": None,
            "agreement": None,
            "notes": "Superseded.",
            "revokes": "esv_1",
            "revoked_by": None,
        }
    )
    return record


def _grant_create_request() -> dict[str, Any]:
    return {
        "record_kind": "grant",
        "grantee_user_id": "user-2",
        "revokes": None,
        "reason": "Domain expert for the billing evaluator.",
    }


def _grant_revocation_create_request() -> dict[str, Any]:
    return {
        "record_kind": "revocation",
        "grantee_user_id": None,
        "revokes": "rvg_1",
        "reason": "No longer an active reviewer.",
    }


def _grant_record(self_granted: bool = False) -> dict[str, Any]:
    return {
        "grant_id": "rvg_1",
        "record_kind": "grant",
        "capability": "evaluation_system_reviewer",
        "grantee": {"principal_kind": "USER", "principal_ref": "user-2"},
        "granted_by": {
            "principal_kind": "USER",
            "principal_ref": "user-2" if self_granted else "admin-1",
        },
        "self_granted": self_granted,
        "reason": "Domain expert for the billing evaluator.",
        "recorded_at": "2026-09-20T00:00:00Z",
        "revokes": None,
        "revoked_by": None,
        "observation_basis": "backend_observed",
    }


# ---------------------------------------------------------------------------
# Meta / discoverability
# ---------------------------------------------------------------------------


def test_schema_files_are_valid_draft7() -> None:
    for path in (VALIDATION_SCHEMA_PATH, GRANT_SCHEMA_PATH):
        Draft7Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_endpoints_file_is_registered_in_the_catalog() -> None:
    root = json.loads((SCHEMAS / "mep_endpoints.json").read_text(encoding="utf-8"))
    modules = [
        m
        for m in root["x-endpoint-modules"]
        if m.get("paths_file")
        == "./evaluation_system_validation/evaluation_system_validation_endpoints.json"
    ]
    assert len(modules) == 1


def test_endpoint_inventory_declares_the_six_routes() -> None:
    inventory = json.loads(ENDPOINTS_PATH.read_text(encoding="utf-8"))
    assert set(inventory["paths"]) == {
        "/api/v1beta/projects/{project_id}/evaluation-system-validations",
        "/api/v1beta/projects/{project_id}/evaluation-system-validations/{validation_id}",
        "/api/v1beta/projects/{project_id}/evaluation-system-reviewer-grants",
        "/api/v1beta/projects/{project_id}/evaluation-system-reviewer-grants/me",
    }
    validations = inventory["paths"][
        "/api/v1beta/projects/{project_id}/evaluation-system-validations"
    ]
    assert set(validations) == {"post", "get"}
    grants = inventory["paths"][
        "/api/v1beta/projects/{project_id}/evaluation-system-reviewer-grants"
    ]
    assert set(grants) == {"post", "get"}
    for path in inventory["paths"].values():
        for operation in path.values():
            assert operation["x-asserted-against-backend"] is False


def test_agent_readiness_endpoint_path_set_is_unchanged() -> None:
    """This family is separate from Agent Readiness precisely so that
    test_agent_readiness_contract.py's pinned path set never has to move for E3."""
    inventory = json.loads(
        (SCHEMAS / "agent_readiness" / "agent_readiness_endpoints.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(inventory["paths"]) == {
        "/api/v1beta/projects/{project_id}/agent-readiness",
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}",
        "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/target-revisions",
    }


# ---------------------------------------------------------------------------
# ValidationCreateRequest
# ---------------------------------------------------------------------------


def test_evaluator_and_dataset_create_requests_are_valid() -> None:
    assert _errors(CREATE_REQUEST, _evaluator_create_request()) == []
    assert _errors(CREATE_REQUEST, _dataset_create_request()) == []
    assert _errors(CREATE_REQUEST, _revocation_create_request()) == []


def test_create_request_rejects_unknown_and_server_derived_fields() -> None:
    req = _evaluator_create_request()
    req["extra_field"] = "nope"
    assert _errors(CREATE_REQUEST, req)

    for field in ("reviewer", "signed_at", "validation_id", "subject_ref"):
        req = _evaluator_create_request()
        req[field] = "nope"
        assert _errors(CREATE_REQUEST, req), field


def test_revocation_requires_revokes_and_notes_validation_forbids_revokes() -> None:
    invalid = _revocation_create_request()
    invalid["revokes"] = None
    assert _errors(CREATE_REQUEST, invalid)

    invalid = _revocation_create_request()
    invalid["notes"] = None
    assert _errors(CREATE_REQUEST, invalid)

    invalid = _evaluator_create_request()
    invalid["revokes"] = "esv_x"
    assert _errors(CREATE_REQUEST, invalid)


def test_agreement_kind_must_match_pillar() -> None:
    wrong = _evaluator_create_request()
    wrong["agreement"] = {"kind": "label_accuracy", "value": "1.0", "compared_items": 10}
    assert _errors(CREATE_REQUEST, wrong)

    wrong = _dataset_create_request()
    wrong["agreement"] = {"kind": "cohens_kappa", "value": "0.5", "compared_items": 10}
    assert _errors(CREATE_REQUEST, wrong)

    ok = _evaluator_create_request()
    ok["agreement"] = {"kind": "cohens_kappa", "value": "0.5", "compared_items": 10}
    assert _errors(CREATE_REQUEST, ok) == []

    no_agreement = _evaluator_create_request()
    no_agreement["outcome"] = "not_valid"
    no_agreement["agreement"] = None
    assert _errors(CREATE_REQUEST, no_agreement) == []


def test_agreement_value_pattern_and_sample_size_bounds() -> None:
    bad_value = _evaluator_create_request()
    bad_value["agreement"]["value"] = "1.5.0"
    assert _errors(CREATE_REQUEST, bad_value)

    bad_size = _evaluator_create_request()
    bad_size["sample_size"] = 0
    assert _errors(CREATE_REQUEST, bad_size)

    bad_notes = _evaluator_create_request()
    bad_notes["notes"] = "x" * 2001
    assert _errors(CREATE_REQUEST, bad_notes)


# ---------------------------------------------------------------------------
# ValidationRecord / ValidationListResponse
# ---------------------------------------------------------------------------


def test_validation_records_for_both_pillars_are_valid() -> None:
    assert _errors(RECORD, _validation_record("evaluator")) == []
    assert _errors(RECORD, _validation_record("evaluation_dataset")) == []
    assert _errors(RECORD, _revocation_record()) == []


def test_subject_ref_kind_must_match_pillar() -> None:
    mismatched = _validation_record("evaluator")
    mismatched["subject_ref"] = _dataset_subject_ref()
    assert _errors(RECORD, mismatched)

    mismatched = _validation_record("evaluation_dataset")
    mismatched["subject_ref"] = _evaluator_subject_ref()
    assert _errors(RECORD, mismatched)


def test_dataset_subject_ref_fingerprint_state_gates_content_fingerprint() -> None:
    ref = _dataset_subject_ref(verified=False)
    ref["content_fingerprint"] = "sha256:" + "c" * 64
    record = _validation_record("evaluation_dataset")
    record["subject_ref"] = ref
    assert _errors(RECORD, record)

    ref = _dataset_subject_ref(verified=True)
    ref["content_fingerprint"] = None
    record = _validation_record("evaluation_dataset")
    record["subject_ref"] = ref
    assert _errors(RECORD, record)


def test_record_rejects_client_supplied_digest_named_field() -> None:
    """Naming discipline from the design: *_fingerprint, never digest."""
    schema = json.loads(VALIDATION_SCHEMA_PATH.read_text(encoding="utf-8"))

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "properties" in node:
                assert "digest" not in node["properties"], node["properties"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)


def test_list_response_is_valid_and_bounds_page_size() -> None:
    payload = {
        "schema_version": "1.0.0",
        "items": [_validation_record()],
        "pagination": {
            "page": 1,
            "per_page": 25,
            "total": 1,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        },
    }
    assert _errors(LIST_RESPONSE, payload) == []

    too_large_page = deepcopy(payload)
    too_large_page["pagination"]["per_page"] = 101
    assert _errors(LIST_RESPONSE, too_large_page)


# ---------------------------------------------------------------------------
# Reviewer grants (§3.5) + owner ruling on self-grant
# ---------------------------------------------------------------------------


def test_grant_and_revocation_create_requests_are_valid() -> None:
    assert _errors(GRANT_CREATE_REQUEST, _grant_create_request()) == []
    assert _errors(GRANT_CREATE_REQUEST, _grant_revocation_create_request()) == []


def test_grant_create_request_closes_the_off_axis_field() -> None:
    invalid = _grant_create_request()
    invalid["revokes"] = "rvg_x"
    assert _errors(GRANT_CREATE_REQUEST, invalid)

    invalid = _grant_revocation_create_request()
    invalid["grantee_user_id"] = "user-2"
    assert _errors(GRANT_CREATE_REQUEST, invalid)


def test_grant_record_discloses_self_granted() -> None:
    assert _errors(GRANT_RECORD, _grant_record(self_granted=False)) == []
    assert _errors(GRANT_RECORD, _grant_record(self_granted=True)) == []

    missing = _grant_record()
    del missing["self_granted"]
    assert _errors(GRANT_RECORD, missing)


def test_grant_record_revocation_shape() -> None:
    revocation = _grant_record()
    revocation.update(
        {
            "grant_id": "rvg_2",
            "record_kind": "revocation",
            "revokes": "rvg_1",
            "revoked_by": None,
        }
    )
    assert _errors(GRANT_RECORD, revocation) == []

    invalid = deepcopy(revocation)
    invalid["revokes"] = None
    assert _errors(GRANT_RECORD, invalid)


def test_grant_list_response_is_valid() -> None:
    payload = {
        "schema_version": "1.0.0",
        "items": [_grant_record()],
        "pagination": {
            "page": 1,
            "per_page": 25,
            "total": 1,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        },
    }
    assert _errors(GRANT_LIST_RESPONSE, payload) == []


def test_can_sign_response_shapes() -> None:
    signable = {"can_sign": True, "cannot_sign_reason": None, "grant_id": "rvg_1"}
    assert _errors(CAN_SIGN_RESPONSE, signable) == []

    not_signable = {"can_sign": False, "cannot_sign_reason": "NO_ACTIVE_GRANT", "grant_id": None}
    assert _errors(CAN_SIGN_RESPONSE, not_signable) == []

    inconsistent = {"can_sign": True, "cannot_sign_reason": "NO_ACTIVE_GRANT", "grant_id": "rvg_1"}
    assert _errors(CAN_SIGN_RESPONSE, inconsistent)

    inconsistent = {"can_sign": False, "cannot_sign_reason": None, "grant_id": None}
    assert _errors(CAN_SIGN_RESPONSE, inconsistent)


def test_validation_record_discloses_self_granted_signing() -> None:
    record = _validation_record()
    record["signed_under_self_grant"] = True
    assert _errors(RECORD, record) == []

    missing = _validation_record()
    del missing["signed_under_self_grant"]
    assert _errors(RECORD, missing)

    missing_grant_id = _validation_record()
    del missing_grant_id["signed_under_grant_id"]
    assert _errors(RECORD, missing_grant_id)


# ---------------------------------------------------------------------------
# 409 const-bodied conflict responses (mirrors agent_readiness_endpoints.json's
# revision_conflict pattern rather than the shared error envelope)
# ---------------------------------------------------------------------------


def test_validation_post_409_is_a_const_body_not_the_shared_error_envelope() -> None:
    inventory = json.loads(ENDPOINTS_PATH.read_text(encoding="utf-8"))
    schema = inventory["paths"][
        "/api/v1beta/projects/{project_id}/evaluation-system-validations"
    ]["post"]["responses"]["409"]["content"]["application/json"]["schema"]
    assert schema["properties"]["error_code"]["const"] == "already_revoked"


def test_grant_post_409_offers_already_granted_and_already_revoked() -> None:
    inventory = json.loads(ENDPOINTS_PATH.read_text(encoding="utf-8"))
    schema = inventory["paths"][
        "/api/v1beta/projects/{project_id}/evaluation-system-reviewer-grants"
    ]["post"]["responses"]["409"]["content"]["application/json"]["schema"]
    codes = {branch["properties"]["error_code"]["const"] for branch in schema["oneOf"]}
    assert codes == {"already_granted", "already_revoked"}


# ---------------------------------------------------------------------------
# Property-name deny-list walk over EvaluationSystemValidity / PillarValidity
# (captain review item 1: proves a stray "notes"/"reason"/"reviewer"/
# "principal_ref" field, or any unconstrained free-text string, cannot be
# smuggled onto the derived, content-free readiness block.)
# ---------------------------------------------------------------------------

DENIED_PROPERTY_NAMES = {"notes", "reason", "reviewer", "reviewer_notes", "principal_ref"}


def _walk_property_names(node: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(properties.keys())
        for value in node.values():
            names.update(_walk_property_names(value))
    elif isinstance(node, list):
        for item in node:
            names.update(_walk_property_names(item))
    return names


def _walk_unconstrained_string_properties(node: Any, path: str = "") -> list[str]:
    """A property literal-typed `string` with none of enum/const/pattern/format is
    free text with no bound -- content that could carry the customer's own words. A
    $ref'd property is out of scope here (it is bounded wherever it is defined)."""
    findings: list[str] = []
    if isinstance(node, dict):
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, prop_schema in properties.items():
                if not isinstance(prop_schema, dict) or "$ref" in prop_schema:
                    continue
                candidates = prop_schema.get("oneOf") or [prop_schema]
                for candidate in candidates:
                    if not isinstance(candidate, dict) or "$ref" in candidate:
                        continue
                    if candidate.get("type") == "string" and not (
                        "enum" in candidate
                        or "const" in candidate
                        or "pattern" in candidate
                        or "format" in candidate
                    ):
                        findings.append(f"{path}/{name}")
        for key, value in node.items():
            findings.extend(_walk_unconstrained_string_properties(value, f"{path}/{key}"))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            findings.extend(_walk_unconstrained_string_properties(item, f"{path}[{index}]"))
    return findings


def test_evaluation_system_validity_and_pillar_validity_deny_free_text_property_names() -> None:
    common = json.loads(COMMON_SCHEMA_PATH.read_text(encoding="utf-8"))
    for definition in ("EvaluationSystemValidity", "PillarValidity"):
        names = _walk_property_names(common["definitions"][definition])
        hit = names & DENIED_PROPERTY_NAMES
        assert not hit, f"{definition} carries a denied property name: {hit}"


def test_evaluation_system_validity_and_pillar_validity_have_no_unbounded_string_fields() -> None:
    common = json.loads(COMMON_SCHEMA_PATH.read_text(encoding="utf-8"))
    for definition in ("EvaluationSystemValidity", "PillarValidity"):
        findings = _walk_unconstrained_string_properties(common["definitions"][definition])
        assert not findings, f"{definition} carries unbounded free-text string field(s): {findings}"


# ---------------------------------------------------------------------------
# EvaluationSystemValidity / PillarValidity fixtures (captain review items 2, 5, 6)
# ---------------------------------------------------------------------------


def _no_subject_pillar() -> dict[str, Any]:
    return {
        "status": "NO_SUBJECT",
        "status_reason": None,
        "validation_id": None,
        "signed_at": None,
        "expires_at": None,
    }


def _subject_not_fingerprinted_pillar() -> dict[str, Any]:
    return {**_no_subject_pillar(), "status": "SUBJECT_NOT_FINGERPRINTED"}


def _not_validated_pillar(revoked: bool = False) -> dict[str, Any]:
    return {
        "status": "NOT_VALIDATED",
        "status_reason": "REVOKED" if revoked else None,
        "validation_id": None,
        "signed_at": None,
        "expires_at": None,
    }


def _validated_pillar(validation_id: str, expires_at: str | None = None) -> dict[str, Any]:
    return {
        "status": "VALIDATED",
        "status_reason": None,
        "validation_id": validation_id,
        "signed_at": "2026-09-19T00:00:00Z",
        "expires_at": expires_at,
    }


def _reviewer_rejected_pillar(validation_id: str) -> dict[str, Any]:
    return {
        "status": "REVIEWER_REJECTED",
        "status_reason": None,
        "validation_id": validation_id,
        "signed_at": "2026-09-19T00:00:00Z",
        "expires_at": None,
    }


def _decayed_pillar(
    validation_id: str, reason: str, expires_at: str | None = None
) -> dict[str, Any]:
    return {
        "status": "DECAYED",
        "status_reason": reason,
        "validation_id": validation_id,
        "signed_at": "2026-08-01T00:00:00Z",
        "expires_at": expires_at,
    }


def _validity(
    *,
    level: str,
    evaluator: dict[str, Any],
    evaluation_dataset: dict[str, Any],
    decayed_reason: str | None,
    evidence_ids: list[str],
    observation_basis: str,
) -> dict[str, Any]:
    return {
        "level": level,
        "pillars": {"evaluator": evaluator, "evaluation_dataset": evaluation_dataset},
        "decayed_reason": decayed_reason,
        "evidence_ids": evidence_ids,
        "observation_basis": observation_basis,
        "evaluated_at": "2026-09-20T00:00:00Z",
    }


# ---------------------------------------------------------------------------
# PillarValidity per-status branches (captain review item 1: proves
# PillarValidity.allOf)
# ---------------------------------------------------------------------------


def test_pillar_validity_no_subject_and_not_fingerprinted_are_valid() -> None:
    assert _errors(PILLAR_VALIDITY, _no_subject_pillar()) == []
    assert _errors(PILLAR_VALIDITY, _subject_not_fingerprinted_pillar()) == []


def test_pillar_validity_no_subject_rejects_a_dangling_validation_id() -> None:
    invalid = {**_no_subject_pillar(), "validation_id": "esv_1"}
    assert _errors(PILLAR_VALIDITY, invalid)


def test_pillar_validity_not_validated_allows_only_null_or_revoked_reason() -> None:
    assert _errors(PILLAR_VALIDITY, _not_validated_pillar(revoked=False)) == []
    assert _errors(PILLAR_VALIDITY, _not_validated_pillar(revoked=True)) == []

    invalid = {**_not_validated_pillar(), "status_reason": "BACKSTOP_ELAPSED"}
    assert _errors(PILLAR_VALIDITY, invalid)


def test_pillar_validity_validated_requires_validation_id_and_signed_at() -> None:
    assert _errors(PILLAR_VALIDITY, _validated_pillar("esv_1")) == []

    missing_id = {**_validated_pillar("esv_1"), "validation_id": None}
    assert _errors(PILLAR_VALIDITY, missing_id)

    missing_signed_at = {**_validated_pillar("esv_1"), "signed_at": None}
    assert _errors(PILLAR_VALIDITY, missing_signed_at)


def test_pillar_validity_reviewer_rejected_never_carries_an_expiry() -> None:
    assert _errors(PILLAR_VALIDITY, _reviewer_rejected_pillar("esv_1")) == []
    invalid = {**_reviewer_rejected_pillar("esv_1"), "expires_at": "2026-10-19T00:00:00Z"}
    assert _errors(PILLAR_VALIDITY, invalid)


def test_pillar_validity_decayed_rejects_revoked_as_its_reason() -> None:
    """DECAYED's reason is a DecayReasonCode (no REVOKED); NOT_VALIDATED is the
    only status that reports REVOKED."""
    invalid = _decayed_pillar("esv_1", "REVOKED")
    assert _errors(PILLAR_VALIDITY, invalid)

    valid = _decayed_pillar("esv_1", "SUBJECT_CHANGED_AFTER_SIGNING")
    assert _errors(PILLAR_VALIDITY, valid) == []


def test_pillar_validity_decayed_backstop_elapsed_requires_an_expiry_others_forbid_it() -> None:
    assert (
        _errors(
            PILLAR_VALIDITY,
            _decayed_pillar("esv_1", "BACKSTOP_ELAPSED", expires_at="2026-10-19T00:00:00Z"),
        )
        == []
    )
    missing_expiry = _decayed_pillar("esv_1", "BACKSTOP_ELAPSED", expires_at=None)
    assert _errors(PILLAR_VALIDITY, missing_expiry)

    stray_expiry = _decayed_pillar(
        "esv_1", "SUBJECT_CHANGED_AFTER_SIGNING", expires_at="2026-10-19T00:00:00Z"
    )
    assert _errors(PILLAR_VALIDITY, stray_expiry)


# ---------------------------------------------------------------------------
# EvaluationSystemValidity: level, observation_basis, decayed_reason, evidence_ids
# (captain review items 2, 5, 6: proves EvaluationSystemValidity.allOf)
# ---------------------------------------------------------------------------


def test_v1_requires_both_pillars_validated() -> None:
    both_validated = _validity(
        level="V1",
        evaluator=_validated_pillar("esv_1"),
        evaluation_dataset=_validated_pillar("esv_2"),
        decayed_reason=None,
        evidence_ids=["esv_1", "esv_2"],
        observation_basis="server_recorded_client_declaration",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, both_validated) == []

    one_not_validated = deepcopy(both_validated)
    one_not_validated["level"] = "V1"
    one_not_validated["pillars"]["evaluation_dataset"] = _not_validated_pillar()
    one_not_validated["evidence_ids"] = ["esv_1"]
    assert _errors(EVALUATION_SYSTEM_VALIDITY, one_not_validated)


def test_v1_requires_exactly_two_evidence_ids() -> None:
    validity = _validity(
        level="V1",
        evaluator=_validated_pillar("esv_1"),
        evaluation_dataset=_validated_pillar("esv_2"),
        decayed_reason=None,
        evidence_ids=["esv_1"],
        observation_basis="server_recorded_client_declaration",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, validity)

    fixed = deepcopy(validity)
    fixed["evidence_ids"] = ["esv_1", "esv_2"]
    assert _errors(EVALUATION_SYSTEM_VALIDITY, fixed) == []


def test_observation_basis_tracks_whether_any_validation_is_referenced() -> None:
    no_evidence = _validity(
        level="V0",
        evaluator=_no_subject_pillar(),
        evaluation_dataset=_no_subject_pillar(),
        decayed_reason=None,
        evidence_ids=[],
        observation_basis="not_assessed",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, no_evidence) == []

    wrong_basis_when_empty = deepcopy(no_evidence)
    wrong_basis_when_empty["observation_basis"] = "server_recorded_client_declaration"
    assert _errors(EVALUATION_SYSTEM_VALIDITY, wrong_basis_when_empty)

    # One pillar NO_SUBJECT, the other has a matched (even non-VALIDATED) record:
    # basis must still be server_recorded_client_declaration because a record WAS
    # referenced -- this is the case the old NO_SUBJECT-only rule got wrong.
    one_sided_evidence = _validity(
        level="V0",
        evaluator=_no_subject_pillar(),
        evaluation_dataset=_not_validated_pillar(),
        decayed_reason=None,
        evidence_ids=[],
        observation_basis="not_assessed",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, one_sided_evidence) == []  # NOT_VALIDATED carries no validation_id either

    referenced = _validity(
        level="V0",
        evaluator=_no_subject_pillar(),
        evaluation_dataset=_reviewer_rejected_pillar("esv_9"),
        decayed_reason=None,
        evidence_ids=["esv_9"],
        observation_basis="server_recorded_client_declaration",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, referenced) == []
    wrong_basis_when_referenced = deepcopy(referenced)
    wrong_basis_when_referenced["observation_basis"] = "not_assessed"
    assert _errors(EVALUATION_SYSTEM_VALIDITY, wrong_basis_when_referenced)


def test_decayed_reason_is_tied_to_an_actually_decayed_pillar() -> None:
    decayed = _validity(
        level="V0",
        evaluator=_decayed_pillar("esv_1", "SUBJECT_CHANGED_AFTER_SIGNING"),
        evaluation_dataset=_not_validated_pillar(),
        decayed_reason="SUBJECT_CHANGED_AFTER_SIGNING",
        evidence_ids=["esv_1"],
        observation_basis="server_recorded_client_declaration",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, decayed) == []

    reason_without_a_decayed_pillar = deepcopy(decayed)
    reason_without_a_decayed_pillar["pillars"]["evaluator"] = _not_validated_pillar()
    assert _errors(EVALUATION_SYSTEM_VALIDITY, reason_without_a_decayed_pillar)

    decayed_pillar_without_a_reason = deepcopy(decayed)
    decayed_pillar_without_a_reason["decayed_reason"] = None
    assert _errors(EVALUATION_SYSTEM_VALIDITY, decayed_pillar_without_a_reason)


def test_evaluator_pillar_never_carries_a_backstop_expiry_even_when_validated() -> None:
    validity = _validity(
        level="V1",
        evaluator=_validated_pillar("esv_1", expires_at=None),
        evaluation_dataset=_validated_pillar("esv_2", expires_at="2026-10-19T00:00:00Z"),
        decayed_reason=None,
        evidence_ids=["esv_1", "esv_2"],
        observation_basis="server_recorded_client_declaration",
    )
    assert _errors(EVALUATION_SYSTEM_VALIDITY, validity) == []

    evaluator_with_expiry = deepcopy(validity)
    evaluator_with_expiry["pillars"]["evaluator"]["expires_at"] = "2026-10-19T00:00:00Z"
    assert _errors(EVALUATION_SYSTEM_VALIDITY, evaluator_with_expiry)


# ---------------------------------------------------------------------------
# ValidationRecord: validation/revocation branches, agreement pairing, method
# and observation_basis closedness (captain review items 3, 4, 11)
# ---------------------------------------------------------------------------


def test_validation_record_validation_kind_requires_outcome_and_sample_size() -> None:
    record = _validation_record()
    assert _errors(RECORD, record) == []

    missing_outcome = deepcopy(record)
    missing_outcome["outcome"] = None
    assert _errors(RECORD, missing_outcome)

    missing_sample_size = deepcopy(record)
    missing_sample_size["sample_size"] = None
    assert _errors(RECORD, missing_sample_size)


def test_validation_record_revocation_kind_forces_outcome_sample_size_agreement_null() -> None:
    revocation = _revocation_record()
    assert _errors(RECORD, revocation) == []

    for field in ("outcome", "sample_size", "agreement"):
        invalid = deepcopy(revocation)
        invalid[field] = "valid" if field == "outcome" else (10 if field == "sample_size" else {})
        assert _errors(RECORD, invalid), field


def test_validation_record_agreement_kind_must_match_pillar() -> None:
    record = _validation_record("evaluator")
    assert _errors(RECORD, record) == []

    mismatched = deepcopy(record)
    mismatched["agreement"] = {"kind": "label_accuracy", "value": "1.0", "compared_items": 10}
    assert _errors(RECORD, mismatched)


def test_validation_record_rejects_a_widened_observation_basis() -> None:
    record = _validation_record()
    assert record["observation_basis"] == "server_recorded_client_declaration"
    widened = deepcopy(record)
    widened["observation_basis"] = "backend_observed"
    assert _errors(RECORD, widened)


def test_method_is_closed_to_expert_review_on_both_request_and_record() -> None:
    request = _evaluator_create_request()
    request["method"] = "acet"
    assert _errors(CREATE_REQUEST, request)

    record = _validation_record()
    record["method"] = "acet"
    assert _errors(RECORD, record)


def test_revocation_create_request_forces_outcome_and_sample_size_null() -> None:
    valid = _revocation_create_request()
    assert _errors(CREATE_REQUEST, valid) == []

    outcome_set = deepcopy(valid)
    outcome_set["outcome"] = "valid"
    assert _errors(CREATE_REQUEST, outcome_set)

    sample_size_set = deepcopy(valid)
    sample_size_set["sample_size"] = 10
    assert _errors(CREATE_REQUEST, sample_size_set)


def test_validation_create_request_requires_outcome_and_sample_size() -> None:
    valid = _evaluator_create_request()
    assert _errors(CREATE_REQUEST, valid) == []

    missing_outcome = deepcopy(valid)
    missing_outcome["outcome"] = None
    assert _errors(CREATE_REQUEST, missing_outcome)

    missing_sample_size = deepcopy(valid)
    missing_sample_size["sample_size"] = None
    assert _errors(CREATE_REQUEST, missing_sample_size)


# ---------------------------------------------------------------------------
# Agreement value ranges and compared_items cap (captain review item 9)
# ---------------------------------------------------------------------------


def test_agreement_value_range_is_bound_per_kind() -> None:
    percent_out_of_range = _evaluator_create_request()
    percent_out_of_range["agreement"] = {
        "kind": "percent_agreement",
        "value": "-0.1",
        "compared_items": 10,
    }
    assert _errors(CREATE_REQUEST, percent_out_of_range)

    percent_over_one = _evaluator_create_request()
    percent_over_one["agreement"] = {
        "kind": "percent_agreement",
        "value": "1.5",
        "compared_items": 10,
    }
    assert _errors(CREATE_REQUEST, percent_over_one)

    kappa_negative_ok = _evaluator_create_request()
    kappa_negative_ok["agreement"] = {"kind": "cohens_kappa", "value": "-0.5", "compared_items": 10}
    assert _errors(CREATE_REQUEST, kappa_negative_ok) == []

    kappa_over_one = _evaluator_create_request()
    kappa_over_one["agreement"] = {"kind": "cohens_kappa", "value": "1.5", "compared_items": 10}
    assert _errors(CREATE_REQUEST, kappa_over_one)

    label_out_of_range = _dataset_create_request()
    label_out_of_range["agreement"] = {
        "kind": "label_accuracy",
        "value": "-0.5",
        "compared_items": 10,
    }
    assert _errors(CREATE_REQUEST, label_out_of_range)


def test_agreement_compared_items_caps_at_one_million() -> None:
    at_cap = _evaluator_create_request()
    at_cap["agreement"]["compared_items"] = 1_000_000
    assert _errors(CREATE_REQUEST, at_cap) == []

    over_cap = _evaluator_create_request()
    over_cap["agreement"]["compared_items"] = 1_000_001
    assert _errors(CREATE_REQUEST, over_cap)


# ---------------------------------------------------------------------------
# DatasetSubjectRef.hosted_updated_at (captain review item 12)
# ---------------------------------------------------------------------------


def test_declared_dataset_subject_ref_forces_hosted_updated_at_null() -> None:
    registered = _dataset_subject_ref()
    registered["dataset_id_source"] = "registered"
    registered["hosted_updated_at"] = "2026-09-19T00:00:00Z"
    record = _validation_record("evaluation_dataset")
    record["subject_ref"] = registered
    assert _errors(RECORD, record) == []

    declared = _dataset_subject_ref()
    declared["dataset_id_source"] = "declared"
    declared["hosted_updated_at"] = "2026-09-19T00:00:00Z"
    invalid = _validation_record("evaluation_dataset")
    invalid["subject_ref"] = declared
    assert _errors(RECORD, invalid)

    declared_null = _dataset_subject_ref()
    declared_null["dataset_id_source"] = "declared"
    declared_null["hosted_updated_at"] = None
    valid = _validation_record("evaluation_dataset")
    valid["subject_ref"] = declared_null
    assert _errors(RECORD, valid) == []


# ---------------------------------------------------------------------------
# ReviewerCapabilityReasonCode: NO_PROJECT_ACCESS dropped (captain review item 8)
# ---------------------------------------------------------------------------


def test_cannot_sign_reason_no_longer_offers_no_project_access() -> None:
    grant_schema = json.loads(GRANT_SCHEMA_PATH.read_text(encoding="utf-8"))
    enum = grant_schema["definitions"]["ReviewerCapabilityReasonCode"]["enum"]
    assert "NO_PROJECT_ACCESS" not in enum
    assert set(enum) == {"NO_ACTIVE_GRANT", "API_KEY_PRINCIPAL"}


# ---------------------------------------------------------------------------
# Owner ruling (this round): outcome=valid requires agreement; not_valid may
# omit it. Enforced on both the create request and the record.
# ---------------------------------------------------------------------------


def test_create_request_outcome_valid_requires_agreement() -> None:
    valid_outcome_no_agreement = _evaluator_create_request()
    valid_outcome_no_agreement["agreement"] = None
    assert _errors(CREATE_REQUEST, valid_outcome_no_agreement)

    not_valid_outcome_no_agreement = _evaluator_create_request()
    not_valid_outcome_no_agreement["outcome"] = "not_valid"
    not_valid_outcome_no_agreement["agreement"] = None
    assert _errors(CREATE_REQUEST, not_valid_outcome_no_agreement) == []

    valid_outcome_with_agreement = _evaluator_create_request()
    assert valid_outcome_with_agreement["outcome"] == "valid"
    assert _errors(CREATE_REQUEST, valid_outcome_with_agreement) == []


def test_validation_record_outcome_valid_requires_agreement() -> None:
    record = _validation_record()
    assert record["outcome"] == "valid"
    assert _errors(RECORD, record) == []

    missing_agreement = deepcopy(record)
    missing_agreement["agreement"] = None
    assert _errors(RECORD, missing_agreement)

    not_valid_without_agreement = deepcopy(record)
    not_valid_without_agreement["outcome"] = "not_valid"
    not_valid_without_agreement["agreement"] = None
    assert _errors(RECORD, not_valid_without_agreement) == []
