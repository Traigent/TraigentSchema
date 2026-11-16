"""Contract tests for AGB-74 slice 3: customer-declared document references.

New schema: agent_readiness/compliance_document_ref_schema.json
New endpoints module: agent_readiness/compliance_document_ref_endpoints.json (registered in
mep_endpoints.json). Additive change to compliance_evidence_response_schema.json: an optional
``document_reference`` summary on an ingredient row and one more ``producer_ref`` value.
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
SCHEMA_PATH = READINESS / "compliance_document_ref_schema.json"
ENDPOINTS_PATH = READINESS / "compliance_document_ref_endpoints.json"
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


def _record() -> dict[str, Any]:
    return {
        "reference_id": "cdr_1",
        "kind": "reference",
        "ingredient_id": "D2",
        "document_kind": "technical_documentation",
        "url": "https://docs.example.test/technical-file",
        "sha256": _DIGEST,
        "hash_basis": "customer_declared",
        "verification": "unverified_external_reference",
        "actor": _principal(),
        "recorded_at": _NOW,
        "withdraws": None,
        "withdrawn_by": None,
        "can_withdraw": True,
    }


def _withdrawal() -> dict[str, Any]:
    return {
        **_record(),
        "reference_id": "cdr_2",
        "kind": "withdrawal",
        "url": None,
        "sha256": None,
        "hash_basis": None,
        "verification": None,
        "withdraws": "cdr_1",
        "can_withdraw": False,
    }


def _request() -> dict[str, Any]:
    return {
        "agent_id": "agent-1",
        "ingredient_id": "D2",
        "url": "https://docs.example.test/technical-file",
        "sha256": _DIGEST,
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
    assert "compliance_document_ref_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_SCHEMA)


def test_schema_is_closed_everywhere() -> None:
    _walk_closed(_SCHEMA)
    _walk_closed(load_json(ENDPOINTS_PATH)["paths"])


@pytest.mark.parametrize(
    ("definition", "factory"),
    [
        ("DocumentReferenceRecord", _record),
        ("DocumentReferenceRecord", _withdrawal),
        ("DocumentReferenceCreateRequest", _request),
        ("DocumentReferenceWithdrawRequest", dict),
        (
            "DocumentReferenceSummary",
            lambda: {
                "hash_basis": "customer_declared",
                "recorded_at": _NOW,
                "verification": "unverified_external_reference",
            },
        ),
    ],
)
def test_valid_examples_conform(definition: str, factory: Any) -> None:
    assert _errors(definition, factory()) == []


@pytest.mark.parametrize(
    ("definition", "factory", "mutate"),
    [
        # Server-derived fields and every free-text sibling are refused.
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(actor_user_id="u")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(recorded_at=_NOW)),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(tenant_id="t")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(hash_basis="verified")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(document_kind="x")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(title="Tech file")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(filename="a.pdf")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(note="n")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(supplier="s")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(ingredient_id="A1")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(ingredient_id="M1")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(url="http://x.test/a")),
        (
            "DocumentReferenceCreateRequest",
            _request,
            lambda r: r.update(url="https://" + "a" * 2050),
        ),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(sha256="short")),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.update(sha256="g" * 64)),
        ("DocumentReferenceCreateRequest", _request, lambda r: r.pop("url")),
        ("DocumentReferenceWithdrawRequest", dict, lambda r: r.update(reason="why")),
        (
            "DocumentReferenceRecord",
            _record,
            lambda r: r.update(hash_basis="independently_verified"),
        ),
        ("DocumentReferenceRecord", _record, lambda r: r.update(verification="verified")),
        ("DocumentReferenceRecord", _record, lambda r: r.update(document_kind="other")),
        ("DocumentReferenceRecord", _record, lambda r: r.update(title="Tech file")),
        ("DocumentReferenceRecord", _record, lambda r: r.pop("can_withdraw")),
        ("DocumentReferenceRecord", _record, lambda r: r.pop("url")),
        ("DocumentReferenceRecord", _record, lambda r: r.update(sha256="A" * 64)),
        (
            "DocumentReferenceSummary",
            lambda: {
                "hash_basis": "customer_declared",
                "recorded_at": _NOW,
                "verification": "unverified_external_reference",
            },
            lambda r: r.update(url="https://docs.example.test/x"),
        ),
        (
            "DocumentReferenceSummary",
            lambda: {
                "hash_basis": "customer_declared",
                "recorded_at": _NOW,
                "verification": "unverified_external_reference",
            },
            lambda r: r.update(sha256=_DIGEST),
        ),
    ],
)
def test_invalid_shapes_are_rejected(definition: str, factory: Any, mutate: Any) -> None:
    instance = copy.deepcopy(factory())
    mutate(instance)
    assert _errors(definition, instance) != []


def test_list_response_declares_real_pagination() -> None:
    ok = {
        "schema_version": "1.0.0-beta.1",
        "items": [_record()],
        "pagination": {
            "page": 1,
            "per_page": 25,
            "total": 1,
            "total_pages": 1,
            "has_next": False,
            "has_prev": False,
        },
    }
    assert _errors("DocumentReferenceListResponse", ok) == []
    for field in ("page", "per_page", "total", "total_pages", "has_next", "has_prev"):
        broken = copy.deepcopy(ok)
        del broken["pagination"][field]
        assert _errors("DocumentReferenceListResponse", broken) != [], field
    too_big = copy.deepcopy(ok)
    too_big["pagination"]["per_page"] = 101
    assert _errors("DocumentReferenceListResponse", too_big) != []
    paths = load_json(ENDPOINTS_PATH)["paths"]
    listing = paths["/api/v1beta/projects/{project_id}/compliance-document-refs/agents/{agent_id}"]
    names = {p["name"] for p in listing["get"]["parameters"]}
    assert {"page", "per_page"} <= names


def test_the_url_is_in_bodies_only_never_a_path_or_query_parameter() -> None:
    paths = load_json(ENDPOINTS_PATH)["paths"]
    for path, item in paths.items():
        assert "url" not in path
        for operation in item.values():
            for parameter in operation["parameters"]:
                assert parameter["name"] not in {"url", "sha256", "document_url"}
    post = paths["/api/v1beta/projects/{project_id}/compliance-document-refs"]["post"]
    assert "requestBody" in post


def test_url_is_marked_customer_content_and_there_is_no_free_text_sibling() -> None:
    definitions = _SCHEMA["definitions"]
    assert (
        "CUSTOMER CONTENT"
        in definitions["DocumentReferenceCreateRequest"]["properties"]["url"]["description"]
    )
    assert (
        "CUSTOMER CONTENT"
        in definitions["DocumentReferenceRecord"]["properties"]["url"]["description"]
    )
    for name in ("DocumentReferenceCreateRequest", "DocumentReferenceRecord"):
        assert not {"title", "filename", "note", "supplier"} & set(definitions[name]["properties"])
    # The evidence-summary shape has neither the URL nor the digest.
    assert not {"url", "sha256"} & set(definitions["DocumentReferenceSummary"]["properties"])


def test_evidence_response_accepts_a_document_reference_summary_but_no_url() -> None:
    evidence = load_json(EVIDENCE_PATH)
    summary = {
        "hash_basis": "customer_declared",
        "recorded_at": _NOW,
        "verification": "unverified_external_reference",
    }
    row = {
        "id": "D2",
        "kind": "D",
        "group": "Transparency",
        "title": "Example",
        "state": "SUPPORTED",
        "producer_ref": "DOCUMENT_REFERENCES_V1",
        "document_reference": summary,
        "links": [],
    }
    ref = f"{evidence['$id']}#/definitions/Ingredient"
    assert ref_errors(_REGISTRY, ref, row) == []
    row["document_reference"] = {**summary, "url": "https://docs.example.test/x"}
    assert ref_errors(_REGISTRY, ref, row) != []


def test_schema_text_has_no_determination_or_verification_wording() -> None:
    for path in (SCHEMA_PATH, ENDPOINTS_PATH):
        text = path.read_text(encoding="utf-8").lower()
        for word in ("compliant", "certified", "satisfies", "verified document"):
            assert word not in text, (path.name, word)


def test_endpoints_are_registered_and_wired() -> None:
    assert "./agent_readiness/compliance_document_ref_endpoints.json" in (
        SCHEMAS / "mep_endpoints.json"
    ).read_text(encoding="utf-8")
    paths = load_json(ENDPOINTS_PATH)["paths"]
    base = "/api/v1beta/projects/{project_id}/compliance-document-refs"
    assert set(paths) == {
        base,
        base + "/{reference_id}/withdrawals",
        base + "/agents/{agent_id}",
    }
    for item in paths.values():
        for operation in item.values():
            assert operation["x-asserted-against-backend"] is False
            assert "429" in operation["responses"]
