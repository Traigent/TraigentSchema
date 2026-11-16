"""Contract tests for AGB-74 slice 2: attester grants and authenticated attestations.

New schema: agent_readiness/compliance_attestation_schema.json
New endpoints module: agent_readiness/compliance_attestation_endpoints.json (registered in
mep_endpoints.json). Additive change to compliance_evidence_response_schema.json: an optional
``attestation`` summary on an ingredient row and one more ``producer_ref`` value.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READINESS = SCHEMAS / "agent_readiness"
SCHEMA_PATH = READINESS / "compliance_attestation_schema.json"
ENDPOINTS_PATH = READINESS / "compliance_attestation_endpoints.json"
EVIDENCE_PATH = READINESS / "compliance_evidence_response_schema.json"
_REGISTRY = build_registry(SCHEMAS)
_SCHEMA = load_json(SCHEMA_PATH)
_ID = _SCHEMA["$id"]
_DIGEST = "a" * 64
_NOW = "2026-11-08T12:00:00Z"


def _errors(definition: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, f"{_ID}#/definitions/{definition}", instance)


def _principal(ref: str = "user-1") -> dict[str, str]:
    return {"principal_kind": "USER", "principal_ref": ref}


def _grant() -> dict[str, Any]:
    return {
        "grant_id": "cag_1",
        "kind": "grant",
        "statement_id": "A1",
        "grantee": _principal(),
        "granted_by": _principal("admin-1"),
        "self_grant": False,
        "recorded_at": _NOW,
        "revokes": None,
        "withdrawn_by": None,
    }


def _record() -> dict[str, Any]:
    return {
        "attestation_id": "cat_1",
        "kind": "attestation",
        "ingredient_id": "A1",
        "statement_version": "1",
        "statement_digest": _DIGEST,
        "outcome": "affirmed",
        "dependency_fingerprints": [
            {
                "kind": "agent_configuration",
                "value": "sha256:" + "a" * 64,
                "basis": "backend_observed",
            }
        ],
        "signer": _principal(),
        "grant_id": "cag_1",
        "revoker_basis": None,
        "can_revoke": True,
        "recorded_at": _NOW,
        "review_due_at": "2027-11-08T12:00:00Z",
        "revokes": None,
        "revoked_by": None,
        "currency_reason": "CURRENT",
        "note": None,
        "document_ref_ids": ["cdr_1"],
    }


def _grant_request() -> dict[str, Any]:
    return {"grantee_user_id": "u", "statement_id": "A1"}


def _request() -> dict[str, Any]:
    return {
        "agent_id": "agent-1",
        "ingredient_id": "A1",
        "statement_digest": _DIGEST,
        "outcome": "affirmed",
        "review_period_days": 90,
    }


def _walk_closed(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object":
            assert node.get("additionalProperties") is False, node
        for value in node.values():
            _walk_closed(value)
    elif isinstance(node, list):
        for value in node:
            _walk_closed(value)


def test_schema_is_valid_draft7_and_discoverable() -> None:
    assert "compliance_attestation_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_SCHEMA)


def test_schema_is_closed_everywhere() -> None:
    _walk_closed(_SCHEMA)
    _walk_closed(load_json(ENDPOINTS_PATH)["paths"])


@pytest.mark.parametrize(
    ("definition", "factory"),
    [
        ("AttesterGrantRecord", _grant),
        ("AttestationRecord", _record),
        ("AttestationCreateRequest", _request),
        ("AttestationRevokeRequest", dict),
        (
            "AttesterGrantCreateRequest",
            lambda: {"grantee_user_id": "user-1", "statement_id": "A4"},
        ),
        (
            "AttestationSummary",
            lambda: {
                "attestation_id": "cat_1",
                "can_revoke": False,
                "signer": _principal("erased"),
                "recorded_at": _NOW,
                "review_due_at": _NOW,
                "statement_version": "1",
                "currency_reason": "REVIEW_DATE_PASSED",
                "document_ref_ids": [],
                "self_grant": False,
            },
        ),
    ],
)
def test_valid_examples_conform(definition: str, factory: Any) -> None:
    assert _errors(definition, factory()) == []


@pytest.mark.parametrize(
    ("definition", "factory", "mutate"),
    [
        # Server-derived fields are never accepted from the client.
        ("AttestationCreateRequest", _request, lambda r: r.update(signer_user_id="u")),
        ("AttestationCreateRequest", _request, lambda r: r.update(recorded_at=_NOW)),
        ("AttestationCreateRequest", _request, lambda r: r.update(tenant_id="t")),
        ("AttestationCreateRequest", _request, lambda r: r.update(project_id="p")),
        ("AttestationCreateRequest", _request, lambda r: r.update(review_due_at=_NOW)),
        ("AttestationCreateRequest", _request, lambda r: r.update(outcome="not_affirmed")),
        ("AttestationCreateRequest", _request, lambda r: r.update(ingredient_id="M1")),
        ("AttestationCreateRequest", _request, lambda r: r.update(review_period_days=0)),
        ("AttestationCreateRequest", _request, lambda r: r.update(review_period_days=367)),
        ("AttestationCreateRequest", _request, lambda r: r.update(statement_digest="short")),
        ("AttestationCreateRequest", _request, lambda r: r.update(note="")),
        ("AttestationCreateRequest", _request, lambda r: r.update(note="x" * 2001)),
        (
            "AttestationCreateRequest",
            _request,
            lambda r: r.update(
                dependency_fingerprints=[
                    {"kind": "evaluator", "value": "v", "basis": "backend_observed"}
                ]
            ),
        ),
        (
            "AttestationCreateRequest",
            _request,
            lambda r: r.update(dependency_fingerprints=[{"kind": "prompt", "value": "v"}]),
        ),
        ("AttestationRevokeRequest", dict, lambda r: r.update(signer_user_id="u")),
        (
            "AttesterGrantCreateRequest",
            lambda: {"grantee_user_id": "u", "statement_id": "A1"},
            lambda r: r.update(reason="why"),
        ),
        (
            "AttesterGrantCreateRequest",
            lambda: {"grantee_user_id": "u", "statement_id": "A1"},
            lambda r: r.update(statement_id="A9"),
        ),
        ("AttesterGrantRecord", _grant, lambda r: r.update(kind="withdrawn")),
        ("AttesterGrantRecord", _grant, lambda r: r.pop("self_grant")),
        ("AttestationRecord", _record, lambda r: r.update(outcome="compliant")),
        ("AttestationRecord", _record, lambda r: r.update(currency_reason="FINE")),
        ("AttestationRecord", _record, lambda r: r.update(signature="MEUCIQ")),
        ("AttestationRecord", _record, lambda r: r.pop("note")),
        ("AttestationRecord", _record, lambda r: r.pop("revoker_basis")),
        ("AttestationRecord", _record, lambda r: r.pop("can_revoke")),
        ("AttestationRecord", _record, lambda r: r.update(can_revoke="yes")),
        ("AttestationRecord", _record, lambda r: r.update(revoker_basis="tenant_admin")),
        (
            "AttestationRecord",
            _record,
            lambda r: r["dependency_fingerprints"][0].update(value="raw-dataset-id"),
        ),
        (
            "AttestationRecord",
            _record,
            lambda r: r["dependency_fingerprints"][0].update(basis="guess"),
        ),
    ],
)
def test_invalid_shapes_are_rejected(definition: str, factory: Any, mutate: Any) -> None:
    instance = copy.deepcopy(factory())
    mutate(instance)
    assert _errors(definition, instance) != []


def test_capabilities_response_is_closed_booleans() -> None:
    ok = {
        "schema_version": "1.0.0-beta.1",
        "can_manage_grants": False,
        "statements": [
            {
                "ingredient_id": "A1",
                "statement_version": "1",
                "statement_digest": _DIGEST,
                "statement_text": "I state that the example holds.",
                "can_sign": False,
            }
        ],
    }
    assert _errors("AttestationCapabilitiesResponse", ok) == []
    missing = copy.deepcopy(ok)
    del missing["can_manage_grants"]
    assert _errors("AttestationCapabilitiesResponse", missing) != []
    bad = copy.deepcopy(ok)
    bad["can_manage_grants"] = "yes"
    assert _errors("AttestationCapabilitiesResponse", bad) != []
    bad = copy.deepcopy(ok)
    bad["statements"][0]["can_sign"] = "no"
    assert _errors("AttestationCapabilitiesResponse", bad) != []
    bad = copy.deepcopy(ok)
    bad["statements"][0]["cannot_sign_reason"] = "NO_ACTIVE_GRANT"
    assert _errors("AttestationCapabilitiesResponse", bad) != []


_PAGINATION = {
    "page": 1,
    "per_page": 25,
    "total": 1,
    "total_pages": 1,
    "has_next": False,
    "has_prev": False,
}


@pytest.mark.parametrize(
    ("definition", "item"),
    [("AttestationListResponse", _record), ("AttesterGrantListResponse", _grant)],
)
def test_list_responses_declare_real_pagination(definition: str, item: Any) -> None:
    ok = {"schema_version": "1.0.0-beta.1", "items": [item()], "pagination": dict(_PAGINATION)}
    assert _errors(definition, ok) == []
    for field in ("page", "per_page", "total", "total_pages", "has_next", "has_prev"):
        broken = copy.deepcopy(ok)
        del broken["pagination"][field]
        assert _errors(definition, broken) != [], field
    too_big = copy.deepcopy(ok)
    too_big["pagination"]["per_page"] = 101
    assert _errors(definition, too_big) != []
    no_pagination = copy.deepcopy(ok)
    del no_pagination["pagination"]
    assert _errors(definition, no_pagination) != []
    paths = load_json(ENDPOINTS_PATH)["paths"]
    base = "/api/v1beta/projects/{project_id}/"
    for path in (
        base + "compliance-attester-grants",
        base + "compliance-attestations/agents/{agent_id}",
    ):
        names = {p["name"] for p in paths[path]["get"]["parameters"]}
        assert {"page", "per_page"} <= names


def test_note_is_the_only_free_text_and_is_marked_customer_content() -> None:
    definitions = _SCHEMA["definitions"]
    for name in ("AttestationCreateRequest", "AttestationRevokeRequest"):
        assert "CUSTOMER CONTENT" in definitions[name]["properties"]["note"]["description"]
    assert (
        "CUSTOMER CONTENT" in definitions["AttestationRecord"]["properties"]["note"]["description"]
    )
    # The evidence-summary shape has no note at all.
    assert "note" not in definitions["AttestationSummary"]["properties"]


def test_evidence_response_accepts_an_attestation_summary_but_no_note() -> None:
    evidence = load_json(EVIDENCE_PATH)
    summary = {
        "attestation_id": "cat_1",
        "can_revoke": False,
        "signer": _principal(),
        "recorded_at": _NOW,
        "review_due_at": "2027-11-08T12:00:00Z",
        "statement_version": "1",
        "currency_reason": "CURRENT",
        "document_ref_ids": [],
        "self_grant": False,
    }
    row = {
        "id": "A1",
        "kind": "A",
        "group": "Accountability",
        "title": "Example",
        "state": "SUPPORTED",
        "producer_ref": "ATTESTATION_RECORDS_V1",
        "attestation": summary,
        "links": [],
    }
    ref = f"{evidence['$id']}#/definitions/Ingredient"
    assert ref_errors(_REGISTRY, ref, row) == []
    row["attestation"] = {**summary, "note": "customer text"}
    assert ref_errors(_REGISTRY, ref, row) != []


def test_schema_text_has_no_determination_or_cryptographic_wording() -> None:
    for path in (SCHEMA_PATH, ENDPOINTS_PATH):
        text = path.read_text(encoding="utf-8").lower()
        for word in ("compliant", "certified", "satisfies", "cryptographically signed"):
            assert word not in text, (path.name, word)


def test_endpoints_are_registered_and_wired() -> None:
    assert "./agent_readiness/compliance_attestation_endpoints.json" in (
        SCHEMAS / "mep_endpoints.json"
    ).read_text(encoding="utf-8")
    paths = load_json(ENDPOINTS_PATH)["paths"]
    base = "/api/v1beta/projects/{project_id}/"
    assert set(paths) == {
        base + "compliance-attester-grants",
        base + "compliance-attester-grants/{grant_id}/withdrawals",
        base + "compliance-attestations",
        base + "compliance-attestations/capabilities",
        base + "compliance-attestations/{attestation_id}/revocations",
        base + "compliance-attestations/agents/{agent_id}",
    }
    for item in paths.values():
        for operation in item.values():
            assert operation["responses"]
            assert "404" in operation["responses"]
            assert operation["x-asserted-against-backend"] is False
            for key in ("signer", "signer_user_id", "recorded_at", "tenant_id", "project_id"):
                body = operation.get("requestBody")
                if body:
                    ref = body["content"]["application/json"]["schema"]["$ref"]
                    definition = _SCHEMA["definitions"][ref.rsplit("/", 1)[-1]]
                    assert key not in definition["properties"]


def test_fingerprints_are_server_derived_only_and_dataset_is_not_a_kind() -> None:
    definitions = _SCHEMA["definitions"]
    assert definitions["FingerprintKind"]["enum"] == ["agent_configuration", "evaluator", "posture"]
    assert definitions["FingerprintBasis"]["enum"] == ["backend_observed"]
    for name in ("DependencyFingerprint", "FingerprintEcho"):
        assert "server-generated" in definitions[name]["properties"]["value"]["description"]
        assert "agb74-fp-v1" in definitions[name]["properties"]["value"]["description"]
    fingerprint = _record()["dependency_fingerprints"][0]
    assert _errors("DependencyFingerprint", fingerprint) == []
    assert _errors("DependencyFingerprint", {**fingerprint, "kind": "dataset"}) != []
    assert (
        _errors(
            "DependencyFingerprint", {**fingerprint, "basis": "server_recorded_client_declaration"}
        )
        != []
    )


def test_a_grant_withdrawal_declares_an_empty_object_body() -> None:
    assert _errors("AttesterGrantWithdrawRequest", {}) == []
    assert _errors("AttesterGrantWithdrawRequest", {"reason": "why"}) != []
    path = "/api/v1beta/projects/{project_id}/compliance-attester-grants/{grant_id}/withdrawals"
    post = load_json(ENDPOINTS_PATH)["paths"][path]["post"]
    ref = post["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("#/definitions/AttesterGrantWithdrawRequest")


def test_the_evidence_summary_carries_the_standing_attestation_id_and_can_revoke() -> None:
    summary = {
        "attestation_id": "cat_1",
        "can_revoke": True,
        "signer": _principal(),
        "recorded_at": _NOW,
        "review_due_at": _NOW,
        "statement_version": "1",
        "currency_reason": "CURRENT",
        "document_ref_ids": [],
        "self_grant": False,
    }
    assert _errors("AttestationSummary", summary) == []
    for field in ("attestation_id", "can_revoke", "document_ref_ids", "self_grant"):
        broken = {k: v for k, v in summary.items() if k != field}
        assert _errors("AttestationSummary", broken) != [], field
    assert _errors("AttestationSummary", {**summary, "can_revoke": "yes"}) != []
    assert _errors("AttestationSummary", {**summary, "note": "customer text"}) != []


def test_linked_statements_carry_document_ref_ids_and_two_new_currency_reasons() -> None:
    assert _errors("AttestationCreateRequest", {**_request(), "document_ref_ids": ["cdr_1"]}) == []
    for bad in ("cdr_1", [1], ["a", "a"], ["x"] * 21):
        assert _errors("AttestationCreateRequest", {**_request(), "document_ref_ids": bad}) != []
    reasons = load_json(SCHEMA_PATH)["definitions"]["CurrencyReason"]["enum"]
    assert {"LINKED_REFERENCE_WITHDRAWN", "SIGNER_ERASED"} <= set(reasons)
    assert _errors("AttestationRecord", {**_record(), "currency_reason": "SIGNER_ERASED"}) == []
    broken = {k: v for k, v in _record().items() if k != "document_ref_ids"}
    assert _errors("AttestationRecord", broken) != []


def test_the_sign_route_declares_the_linked_reference_conflicts() -> None:
    text = ENDPOINTS_PATH.read_text()
    assert "linked_reference_required" in text and "linked_reference_invalid" in text


def test_the_statement_text_status_marker_is_a_closed_enum() -> None:
    for value in ("current", "superseded_version", "statement_unavailable"):
        assert _errors("StatementTextStatus", value) == []
    for bad in ("CURRENT", "unknown", "", None, 1):
        assert _errors("StatementTextStatus", bad) != []
    description = load_json(SCHEMA_PATH)["definitions"]["CurrencyReason"]["description"]
    assert "takes precedence" in description


def _exported(status: str, text: str | None) -> dict[str, Any]:
    record = _record()
    record.pop("can_revoke")
    record.update(
        signer_erased=False,
        self_grant=False,
        statement_text=text,
        statement_text_status=status,
    )
    return record


def test_the_exported_record_references_the_statement_text_status_enum() -> None:
    props = _SCHEMA["definitions"]["ExportedAttestationRecord"]["properties"]
    assert props["statement_text_status"] == {"$ref": "#/definitions/StatementTextStatus"}


@pytest.mark.parametrize(
    ("status", "text"),
    [
        ("current", "I state that the example holds."),
        ("superseded_version", None),
        ("statement_unavailable", None),
    ],
)
def test_an_exported_record_is_valid_for_each_status(status: str, text: str | None) -> None:
    assert _errors("ExportedAttestationRecord", _exported(status, text)) == []


def test_an_exported_record_with_no_grant_may_have_a_null_self_grant() -> None:
    record = _exported("current", "wording")
    record["self_grant"] = None
    assert _errors("ExportedAttestationRecord", record) == []


@pytest.mark.parametrize(
    "record",
    [
        _exported("current", None),  # current without text
        _exported("current", 5),  # current with a non-string text
        _exported("superseded_version", "old wording"),  # superseded with text
        _exported("statement_unavailable", "wording"),  # unavailable with text
        _exported("unknown", None),  # outside the closed enum
    ],
)
def test_an_exported_record_rejects_text_that_disagrees_with_its_status(
    record: dict[str, Any],
) -> None:
    assert _errors("ExportedAttestationRecord", record) != []


@pytest.mark.parametrize("missing", ["statement_text", "statement_text_status", "signer_erased"])
def test_an_exported_record_requires_the_marker_fields(missing: str) -> None:
    record = _exported("current", "wording")
    del record[missing]
    assert _errors("ExportedAttestationRecord", record) != []
