"""Contract tests for AGB-74 slice 4: the applicability screen.

New schema: agent_readiness/compliance_applicability_schema.json
New endpoints module: agent_readiness/compliance_applicability_endpoints.json (registered in
mep_endpoints.json). Additive change to compliance_evidence_response_schema.json: an optional
per-pack ``applicability`` summary.
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
SCHEMA_PATH = READINESS / "compliance_applicability_schema.json"
ENDPOINTS_PATH = READINESS / "compliance_applicability_endpoints.json"
EVIDENCE_PATH = READINESS / "compliance_evidence_response_schema.json"
_REGISTRY = build_registry(SCHEMAS)
_SCHEMA = load_json(SCHEMA_PATH)
_ID = _SCHEMA["$id"]
_DIGEST = "a" * 64
_NOW = "2026-11-08T12:00:00Z"
_OBL = "OBL-EU-AI-ACT-ART10"
_FW = "FW-EU-AI-ACT"


def _errors(definition: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, f"{_ID}#/definitions/{definition}", instance)


def _principal(ref: str = "user-1") -> dict[str, str]:
    return {"principal_kind": "USER", "principal_ref": ref}


def _screening() -> dict[str, Any]:
    return {
        "role": "provider",
        "jurisdictions": ["EU"],
        "domain": "high_risk",
        "interacts_with_people": True,
    }


def _request() -> dict[str, Any]:
    return {
        "agent_id": "agent-1",
        "expected_current_id": None,
        "review_period_days": 90,
        "screening": _screening(),
        "decisions": [{"obligation_id": _OBL, "decision": "applicable", "rationale": "text"}],
    }


def _record() -> dict[str, Any]:
    return {
        "revision_id": "car_1",
        "predecessor_id": None,
        "posture_revision_id": None,
        "catalogue_version": "be4267a0360742f4133f610d84d30c8b2583b3b4",
        "catalogue_digest": _DIGEST,
        "screening": _screening(),
        "decisions": [{"obligation_id": _OBL, "decision": "applicable", "rationale": None}],
        "reviewer": _principal(),
        "recorded_at": _NOW,
        "review_due_at": "2027-02-06T12:00:00Z",
    }


def _current() -> dict[str, Any]:
    return {
        "revision": _record(),
        "catalogue_changed": False,
        "review_overdue": False,
        "obligations": [
            {
                "framework_id": _FW,
                "obligation_id": _OBL,
                "suggestion": "applicable",
                "decision": "applicable",
                "effective_decision": "unresolved",
                "invalidation": "facts_changed",
            }
        ],
    }


_PAGINATION = {
    "page": 1,
    "per_page": 25,
    "total": 1,
    "total_pages": 1,
    "has_next": False,
    "has_prev": False,
}


def _response() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0-beta.1",
        "catalogue": {"version": "be4267a", "manifest_sha256": _DIGEST},
        "can_write": False,
        "current": _current(),
        "items": [_record()],
        "pagination": dict(_PAGINATION),
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
    assert "compliance_applicability_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_SCHEMA)


def test_schema_is_closed_everywhere() -> None:
    _walk_closed(_SCHEMA)
    _walk_closed(load_json(ENDPOINTS_PATH)["paths"])


@pytest.mark.parametrize(
    ("definition", "factory"),
    [
        ("ApplicabilityRevisionCreateRequest", _request),
        ("ApplicabilityRevisionRecord", _record),
        ("ApplicabilityCurrent", _current),
        ("ApplicabilityResponse", _response),
        ("ApplicabilityResponse", lambda: {**_response(), "current": None, "items": []}),
        ("ScreeningAnswers", _screening),
        (
            "ScreeningAnswers",
            lambda: {
                "role": None,
                "jurisdictions": None,
                "domain": None,
                "interacts_with_people": None,
            },
        ),
        ("SuggestionsRequest", _screening),
        (
            "SuggestionsResponse",
            lambda: {
                "schema_version": "1.0.0-beta.1",
                "catalogue": {"version": "be4267a", "manifest_sha256": _DIGEST},
                "suggestions": [
                    {"framework_id": _FW, "obligation_id": _OBL, "suggestion": "unresolved"}
                ],
            },
        ),
        (
            "ApplicabilitySummary",
            lambda: {"decided": 3, "unresolved": 12, "not_applicable": 2, "reviewed_at": _NOW},
        ),
        (
            "ApplicabilitySummary",
            lambda: {"decided": 0, "unresolved": 17, "not_applicable": 0, "reviewed_at": None},
        ),
    ],
)
def test_valid_examples_conform(definition: str, factory: Any) -> None:
    assert _errors(definition, factory()) == []


@pytest.mark.parametrize(
    ("definition", "factory", "mutate"),
    [
        # Server-derived fields are never accepted from the client.
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(reviewer_user_id="u")),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(recorded_at=_NOW)),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(tenant_id="t")),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(review_due_at=_NOW)),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(catalogue_digest="a")),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r.update(posture_revision_id="postrev_1"),
        ),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.pop("expected_current_id")),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.pop("screening")),
        ("ApplicabilityRevisionCreateRequest", _request, lambda r: r.update(review_period_days=0)),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r.update(review_period_days=367),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["decisions"][0].update(decision="compliant"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["decisions"][0].update(rationale=""),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["decisions"][0].update(rationale="x" * 2001),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["decisions"][0].update(obligation_id="art10"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["decisions"][0].update(suggestion="applicable"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(role="regulator"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(jurisdictions=["Mars"]),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(jurisdictions=["EU", "EU"]),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(domain="healthcare_free_text"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(interacts_with_people="yes"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].update(company_name="Acme"),
        ),
        (
            "ApplicabilityRevisionCreateRequest",
            _request,
            lambda r: r["screening"].pop("interacts_with_people"),
        ),
        ("ApplicabilityRevisionRecord", _record, lambda r: r.update(signature="x")),
        ("ApplicabilityRevisionRecord", _record, lambda r: r.update(catalogue_digest="short")),
        ("ApplicabilityRevisionRecord", _record, lambda r: r.pop("review_due_at")),
        ("ApplicabilityRevisionRecord", _record, lambda r: r["decisions"][0].pop("rationale")),
        ("ApplicabilityCurrent", _current, lambda r: r.pop("review_overdue")),
        (
            "ApplicabilityCurrent",
            _current,
            lambda r: r["obligations"][0].update(invalidation="guess"),
        ),
        (
            "ApplicabilityCurrent",
            _current,
            lambda r: r["obligations"][0].update(effective_decision="compliant"),
        ),
        ("ApplicabilityCurrent", _current, lambda r: r["obligations"][0].pop("suggestion")),
        ("ApplicabilityResponse", _response, lambda r: r.pop("can_write")),
        ("ApplicabilityResponse", _response, lambda r: r.pop("pagination")),
        ("ApplicabilityResponse", _response, lambda r: r["pagination"].update(per_page=101)),
        (
            "ApplicabilitySummary",
            lambda: {"decided": 1, "unresolved": 1, "not_applicable": 1, "reviewed_at": _NOW},
            lambda r: r.update(rationale="text"),
        ),
        (
            "ApplicabilitySummary",
            lambda: {"decided": 1, "unresolved": 1, "not_applicable": 1, "reviewed_at": _NOW},
            lambda r: r.update(unresolved=-1),
        ),
        (
            "ApplicabilitySummary",
            lambda: {"decided": 1, "unresolved": 1, "not_applicable": 1, "reviewed_at": _NOW},
            lambda r: r.pop("reviewed_at"),
        ),
        ("SuggestionsRequest", _screening, lambda r: r.update(decision="applicable")),
    ],
)
def test_invalid_shapes_are_rejected(definition: str, factory: Any, mutate: Any) -> None:
    instance = copy.deepcopy(factory())
    mutate(instance)
    assert _errors(definition, instance) != []


def test_list_response_declares_real_pagination() -> None:
    for field in ("page", "per_page", "total", "total_pages", "has_next", "has_prev"):
        broken = _response()
        del broken["pagination"][field]
        assert _errors("ApplicabilityResponse", broken) != [], field
    paths = load_json(ENDPOINTS_PATH)["paths"]
    key = "/api/v1beta/projects/{project_id}/compliance-applicability/agents/{agent_id}"
    names = {p["name"] for p in paths[key]["get"]["parameters"]}
    assert {"page", "per_page"} <= names


def test_customer_content_is_marked_and_the_facts_never_travel_in_a_path_or_query() -> None:
    definitions = _SCHEMA["definitions"]
    assert "CUSTOMER CONTENT" in definitions["ScreeningAnswers"]["description"]
    assert (
        "CUSTOMER CONTENT" in definitions["DecisionInput"]["properties"]["rationale"]["description"]
    )
    assert (
        "CUSTOMER CONTENT"
        in definitions["DecisionRecord"]["properties"]["rationale"]["description"]
    )
    # The summary shape carries neither the screening answers nor a rationale.
    assert set(definitions["ApplicabilitySummary"]["properties"]) == {
        "decided",
        "unresolved",
        "not_applicable",
        "reviewed_at",
    }
    for path, item in load_json(ENDPOINTS_PATH)["paths"].items():
        for operation in item.values():
            for parameter in operation["parameters"]:
                assert parameter["name"] in {"project_id", "agent_id", "page", "per_page"}, path


def test_stale_revision_is_the_only_conflict_and_it_is_declared_on_the_write() -> None:
    paths = load_json(ENDPOINTS_PATH)["paths"]
    base = "/api/v1beta/projects/{project_id}/compliance-applicability"
    conflict = paths[base]["post"]["responses"]["409"]["content"]["application/json"]["schema"]
    assert conflict["properties"]["error_code"]["enum"] == ["stale_revision"]
    for path, method in ((base + "/suggestions", "post"), (base + "/agents/{agent_id}", "get")):
        assert "409" not in paths[path][method]["responses"]


def test_evidence_response_accepts_the_pack_applicability_summary_and_nothing_more() -> None:
    evidence = load_json(EVIDENCE_PATH)
    pack = {
        "framework_id": _FW,
        "semver": "0.1.0",
        "title": "EU AI Act",
        "draft": True,
        "coverage": {
            "supported": 0,
            "gap": 0,
            "not_assessed": 3,
            "expired": 0,
            "applicability_unresolved": 17,
        },
        "applicability": {"decided": 0, "unresolved": 17, "not_applicable": 0, "reviewed_at": None},
    }
    ref = f"{evidence['$id']}#/definitions/PackSummary"
    assert ref_errors(_REGISTRY, ref, pack) == []
    without = {k: v for k, v in pack.items() if k != "applicability"}
    assert ref_errors(_REGISTRY, ref, without) == []
    pack["applicability"] = {**pack["applicability"], "rationale": "customer text"}
    assert ref_errors(_REGISTRY, ref, pack) != []


def test_schema_text_has_no_determination_wording() -> None:
    for path in (SCHEMA_PATH, ENDPOINTS_PATH):
        text = path.read_text(encoding="utf-8").lower()
        for word in ("compliant", "certified", "satisfies", "verified document"):
            assert word not in text, (path.name, word)


def test_endpoints_are_registered_and_wired() -> None:
    assert "./agent_readiness/compliance_applicability_endpoints.json" in (
        SCHEMAS / "mep_endpoints.json"
    ).read_text(encoding="utf-8")
    paths = load_json(ENDPOINTS_PATH)["paths"]
    base = "/api/v1beta/projects/{project_id}/compliance-applicability"
    assert set(paths) == {base, base + "/suggestions", base + "/agents/{agent_id}"}
    for item in paths.values():
        for operation in item.values():
            assert operation["x-asserted-against-backend"] is False
            assert "429" in operation["responses"]
