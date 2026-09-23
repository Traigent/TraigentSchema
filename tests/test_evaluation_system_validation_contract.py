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
        "outcome": "valid",
        "sample_size": 120,
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
