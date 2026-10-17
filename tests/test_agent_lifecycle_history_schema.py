"""Contract tests for Lane 3's fleet-agent lifecycle-history bridge.

New route: GET /api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/lifecycle-history
New schema: agent_readiness/agent_lifecycle_history_response_schema.json
Operation added to the existing agent_readiness/agent_readiness_endpoints.json module
(already registered in mep_endpoints.json; no new endpoints module needed).

The route bridges fleet Agent.id onto agent-lifecycle-record revisions through an
experiment-run link (association_basis is always the single closed value
EXPERIMENT_RUN_LINK -- a derived association, never a causal claim, and the response
carries no attribution, actor identity, or record content).
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, load_json, ref_errors
from tests.test_agent_lifecycle_schemas import (
    LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS,
    LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS,
    OPTIMIZATION_TRACE_IP_FORBIDDEN_SUBSTRINGS,
    PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS,
)
from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READINESS = SCHEMAS / "agent_readiness"
RESPONSE_SCHEMA_PATH = READINESS / "agent_lifecycle_history_response_schema.json"
ENDPOINTS_PATH = READINESS / "agent_readiness_endpoints.json"
ERROR_SCHEMA_PATH = READINESS / "agent_readiness_error_schema.json"
ROUTE = "/api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/lifecycle-history"

_load = load_json
_REGISTRY = build_registry(SCHEMAS)
_RESPONSE_SCHEMA = _load(RESPONSE_SCHEMA_PATH)
_RESPONSE_ID = _RESPONSE_SCHEMA["$id"]


def _errors(ref: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, ref, instance)


def _item(
    *,
    agent_revision_id: str = "agent-revision-000000000001",
    record_id: str = "lifecycle-record-000000001",
    created_at: str = "2026-09-27T00:00:00Z",
    association_basis: str = "EXPERIMENT_RUN_LINK",
) -> dict[str, Any]:
    return {
        "agent_revision_ref": {
            "kind": "agent_revision",
            "id": agent_revision_id,
            "version_id": agent_revision_id,
        },
        "record_ref": {
            "kind": "agent_lifecycle_record",
            "id": record_id,
            "version_id": record_id,
        },
        "created_at": created_at,
        "association_basis": association_basis,
    }


def _response(*, items: list[dict[str, Any]], page: int = 1, per_page: int = 25) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0-beta.1",
        "items": items,
        "pagination": {"page": page, "per_page": per_page, "total": len(items)},
    }


# ---------------------------------------------------------------------------
# Schema self-validity
# ---------------------------------------------------------------------------


def test_schema_is_valid_draft7_and_discoverable() -> None:
    assert "agent_lifecycle_history_response_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_RESPONSE_SCHEMA)


def test_schema_is_closed_everywhere() -> None:
    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(_RESPONSE_SCHEMA)


# ---------------------------------------------------------------------------
# Valid fixtures
# ---------------------------------------------------------------------------


def test_valid_empty_page() -> None:
    errors = _errors(_RESPONSE_ID, _response(items=[]))
    assert errors == []


def test_valid_populated_page() -> None:
    errors = _errors(_RESPONSE_ID, _response(items=[_item()]))
    assert errors == []


def test_valid_page_with_multiple_items() -> None:
    instance = _response(
        items=[
            _item(
                agent_revision_id="agent-revision-000000000001",
                record_id="lifecycle-record-000000001",
            ),
            _item(
                agent_revision_id="agent-revision-000000000002",
                record_id="lifecycle-record-000000002",
            ),
        ]
    )
    assert _errors(_RESPONSE_ID, instance) == []


# ---------------------------------------------------------------------------
# Closed-shape rejections
# ---------------------------------------------------------------------------


def test_rejects_extra_top_level_field() -> None:
    instance = _response(items=[])
    instance["attribution"] = "unknown"
    assert _errors(_RESPONSE_ID, instance)


def test_rejects_extra_item_field() -> None:
    instance = _response(items=[_item()])
    instance["items"][0]["extra_field"] = "surprise"
    assert _errors(_RESPONSE_ID, instance)


def test_rejects_extra_pagination_field() -> None:
    instance = _response(items=[])
    instance["pagination"]["total_pages"] = 0
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("field", ["actor", "actor_id", "created_by", "user_id", "attributed_to"])
def test_rejects_an_actor_or_user_field_on_the_item(field: str) -> None:
    """No attribution/actor identity is representable anywhere on an item --
    additionalProperties:false on the closed item shape must reject it."""
    instance = _response(items=[_item()])
    instance["items"][0][field] = "someone"
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("field", ["actor", "actor_id", "created_by", "user_id"])
def test_rejects_an_actor_or_user_field_at_top_level(field: str) -> None:
    instance = _response(items=[])
    instance[field] = "someone"
    assert _errors(_RESPONSE_ID, instance)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def _numbered_item(i: int) -> dict[str, Any]:
    return _item(
        agent_revision_id=f"agent-revision-{i:024d}",
        record_id=f"lifecycle-record-{i:022d}",
    )


def test_items_maxitems_50_accepted() -> None:
    instance = _response(items=[_numbered_item(i) for i in range(50)])
    assert _errors(_RESPONSE_ID, instance) == []


def test_items_maxitems_51_rejected() -> None:
    instance = _response(items=[_numbered_item(i) for i in range(51)])
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("per_page", [0, 51])
def test_rejects_per_page_out_of_bounds(per_page: int) -> None:
    instance = _response(items=[], per_page=per_page)
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("per_page", [1, 25, 50])
def test_accepts_per_page_in_bounds(per_page: int) -> None:
    instance = _response(items=[], per_page=per_page)
    assert _errors(_RESPONSE_ID, instance) == []


def test_rejects_page_below_one() -> None:
    instance = _response(items=[], page=0)
    assert _errors(_RESPONSE_ID, instance)


def test_rejects_page_above_int32_max() -> None:
    instance = _response(items=[], page=2147483648)
    assert _errors(_RESPONSE_ID, instance)


def test_accepts_page_at_int32_max() -> None:
    instance = _response(items=[], page=2147483647)
    assert _errors(_RESPONSE_ID, instance) == []


def test_rejects_negative_total() -> None:
    instance = _response(items=[])
    instance["pagination"]["total"] = -1
    assert _errors(_RESPONSE_ID, instance)


# ---------------------------------------------------------------------------
# Closed vocab / const rejections
# ---------------------------------------------------------------------------


def test_rejects_wrong_schema_version() -> None:
    instance = _response(items=[])
    instance["schema_version"] = "2.0.0"
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize(
    "value",
    ["EXPERIMENT_LINK", "AGENT_REF_MATCH", "CAUSED_BY", "experiment_run_link", ""],
)
def test_rejects_association_basis_other_values(value: str) -> None:
    instance = _response(items=[_item(association_basis=value)])
    assert _errors(_RESPONSE_ID, instance)


def test_rejects_wrong_agent_revision_ref_kind() -> None:
    instance = _response(items=[_item()])
    instance["items"][0]["agent_revision_ref"]["kind"] = "agent_lifecycle_record"
    assert _errors(_RESPONSE_ID, instance)


def test_rejects_wrong_record_ref_kind() -> None:
    instance = _response(items=[_item()])
    instance["items"][0]["record_ref"]["kind"] = "agent_revision"
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize(
    "missing", ["agent_revision_ref", "record_ref", "created_at", "association_basis"]
)
def test_rejects_item_missing_a_required_field(missing: str) -> None:
    instance = _response(items=[_item()])
    del instance["items"][0][missing]
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("missing", ["schema_version", "items", "pagination"])
def test_rejects_response_missing_a_required_top_level_field(missing: str) -> None:
    instance = _response(items=[])
    del instance[missing]
    assert _errors(_RESPONSE_ID, instance)


@pytest.mark.parametrize("missing", ["page", "per_page", "total"])
def test_rejects_pagination_missing_a_required_field(missing: str) -> None:
    instance = _response(items=[])
    del instance["pagination"][missing]
    assert _errors(_RESPONSE_ID, instance)


# ---------------------------------------------------------------------------
# Endpoint registration
# ---------------------------------------------------------------------------


def test_endpoint_registered_with_expected_params_and_responses() -> None:
    inventory = _load(ENDPOINTS_PATH)
    assert ROUTE in inventory["paths"]
    op = inventory["paths"][ROUTE]["get"]
    assert op["x-asserted-against-backend"] is False
    assert op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "agent_lifecycle_history_response_schema.json"
    )
    for status in ("400", "401", "403", "404"):
        assert (
            op["responses"][status]["content"]["application/json"]["schema"]["$ref"]
            == "./agent_readiness_error_schema.json"
        )

    params = {p["name"]: p for p in op["parameters"]}
    assert params["project_id"]["in"] == "path"
    assert params["project_id"]["required"] is True
    assert params["agent_id"]["in"] == "path"
    assert params["agent_id"]["required"] is True

    page = params["page"]
    assert page["in"] == "query"
    assert page["required"] is False
    assert page["schema"]["minimum"] == 1
    assert page["schema"]["maximum"] == 2147483647
    assert page["schema"]["default"] == 1

    per_page = params["per_page"]
    assert per_page["in"] == "query"
    assert per_page["required"] is False
    assert per_page["schema"]["minimum"] == 1
    assert per_page["schema"]["maximum"] == 50
    assert per_page["schema"]["default"] == 25


def test_error_responses_validate_against_the_shared_error_schema() -> None:
    error_id = _load(ERROR_SCHEMA_PATH)["$id"]
    not_found = {
        "success": False,
        "message": "Not found",
        "error": "not_found",
        "error_code": "not_found",
    }
    assert _errors(error_id, not_found) == []


# ---------------------------------------------------------------------------
# Privacy / no-content denylists shared with the rest of the ALR corpus
# ---------------------------------------------------------------------------


def test_schema_contains_no_forbidden_lifecycle_ip_or_content_substrings() -> None:
    text = json.dumps(_RESPONSE_SCHEMA).lower()
    forbidden = (
        LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS
        | LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS
        | PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS
        | OPTIMIZATION_TRACE_IP_FORBIDDEN_SUBSTRINGS
    )
    hits = {token for token in forbidden if token.lower() in text}
    assert hits == set()


def test_endpoints_file_contains_no_forbidden_lifecycle_ip_or_content_substrings() -> None:
    text = json.dumps(_load(ENDPOINTS_PATH)).lower()
    forbidden = (
        LIFECYCLE_IP_FORBIDDEN_SUBSTRINGS
        | LIFECYCLE_STATE_SURFACE_TIER_1_RAW_FORBIDDEN_SUBSTRINGS
        | PHASE4_ROLLUP_REGISTRY_FORBIDDEN_SUBSTRINGS
        | OPTIMIZATION_TRACE_IP_FORBIDDEN_SUBSTRINGS
    )
    hits = {token for token in forbidden if token.lower() in text}
    assert hits == set()


def test_no_attribution_or_actor_property_name_anywhere_in_the_schema() -> None:
    """Belt-and-suspenders on top of the closed-shape rejection tests above:
    walk every declared property name in the response schema and assert none
    of the disallowed attribution/actor/content vocabulary appears."""
    forbidden_property_names = {
        "actor",
        "actor_id",
        "created_by",
        "updated_by",
        "user_id",
        "author",
        "attributed_to",
        "attribution",
        "content",
        "prompt",
        "output",
    }

    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "properties" in node and isinstance(node["properties"], dict):
                found.update(forbidden_property_names & set(node["properties"]))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(_RESPONSE_SCHEMA)
    assert found == set()


# ---------------------------------------------------------------------------
# Neutral wording: no causal/outcome-claiming language in description strings
# ---------------------------------------------------------------------------

_CAUSAL_WORDING_PATTERN = re.compile(
    r"\b(caused|cause|produced|improved|because|led to|resulted)\b", re.IGNORECASE
)


def _find_description_strings(node: Any) -> list[str]:
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "description" and isinstance(value, str):
                found.append(value)
            found.extend(_find_description_strings(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_find_description_strings(value))
    return found


def test_schema_descriptions_contain_no_causal_or_outcome_wording() -> None:
    """Even negated ("never caused", "not because") is disallowed -- these
    handles must stay neutral (association, not outcome/origin) everywhere."""
    hits = {
        (text, match)
        for text in _find_description_strings(_RESPONSE_SCHEMA)
        for match in _CAUSAL_WORDING_PATTERN.findall(text)
    }
    assert hits == set()


def test_endpoint_op_descriptions_contain_no_causal_or_outcome_wording() -> None:
    inventory = _load(ENDPOINTS_PATH)
    op = inventory["paths"][ROUTE]["get"]
    hits = {
        (text, match)
        for text in _find_description_strings(op)
        for match in _CAUSAL_WORDING_PATTERN.findall(text)
    }
    # "summary" is not named "description" but carries the same prose risk.
    summary = op.get("summary", "")
    hits |= {(summary, match) for match in _CAUSAL_WORDING_PATTERN.findall(summary)}
    assert hits == set()
