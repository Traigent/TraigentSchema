"""Contract tests for AGB-74 slice 1: the Agent compliance-evidence response.

New route: GET /api/v1beta/projects/{project_id}/agent-compliance-evidence/{agent_id}
New schema: agent_readiness/compliance_evidence_response_schema.json
New endpoints module: agent_readiness/compliance_evidence_endpoints.json (registered in
mep_endpoints.json).

The schema fixes the SHAPE only. No regulation text (requirement wording, obligations,
citations) is part of this public repository; the Backend serves catalogue content at runtime.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READINESS = SCHEMAS / "agent_readiness"
RESPONSE_PATH = READINESS / "compliance_evidence_response_schema.json"
ENDPOINTS_PATH = READINESS / "compliance_evidence_endpoints.json"
ROUTE = "/api/v1beta/projects/{project_id}/agent-compliance-evidence/{agent_id}"
BANNER = "Evidence coverage, not a compliance determination."

_REGISTRY = build_registry(SCHEMAS)
_SCHEMA = load_json(RESPONSE_PATH)
_ID = _SCHEMA["$id"]


def _errors(instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, _ID, instance)


def _link() -> dict[str, Any]:
    return {
        "framework_id": "FW-EXAMPLE",
        "obligation_id": "OBL-EXAMPLE-1",
        "requirement_id": "REQ-0001",
        "relation": "partial",
        "criterion_addressed": "Example criterion",
        "limitations": ["Example limit"],
    }


def _measurement() -> dict[str, Any]:
    return {
        "metric": "ACCURACY",
        "value": 0.91,
        "interval_low": 0.88,
        "interval_high": 0.94,
        "confidence": 0.95,
        "target": 0.85,
        "method": "wilson_score_binary",
        "observation_basis": "client_reported",
    }


def _response() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0-beta.1",
        "generated_at": "2026-11-08T12:00:00Z",
        "catalogue": {
            "version": "fb9cd62",
            "manifest_sha256": "a" * 64,
            "draft": True,
            "visible_obligations": 5,
        },
        "packs": [
            {
                "framework_id": "FW-EXAMPLE",
                "semver": "0.1.0",
                "title": "Example pack",
                "draft": True,
                "coverage": {
                    "supported": 1,
                    "gap": 0,
                    "not_assessed": 2,
                    "expired": 0,
                    "applicability_unresolved": 5,
                },
            }
        ],
        "ingredients": [
            {
                "id": "M1",
                "kind": "M",
                "group": "Performance",
                "title": "Example ingredient",
                "state": "SUPPORTED",
                "measurements": [_measurement()],
                "producer_ref": "ACCURACY_INTERVAL_V1",
                "links": [_link()],
            },
            {
                "id": "A3b",
                "kind": "A",
                "group": "Transparency",
                "title": "Example attestation",
                "state": "NOT_ASSESSED",
                "links": [],
            },
        ],
        "banner": BANNER,
    }


def test_schema_is_valid_draft7_and_discoverable() -> None:
    assert "compliance_evidence_response_schema" in SchemaValidator().available_schemas
    Draft7Validator.check_schema(_SCHEMA)


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

    walk(_SCHEMA)


def test_valid_populated_and_empty_packs() -> None:
    assert _errors(_response()) == []
    empty = _response()
    empty["packs"] = []
    empty["catalogue"]["visible_obligations"] = 0
    for ingredient in empty["ingredients"]:
        ingredient["links"] = []
    assert _errors(empty) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(banner="Fully compliant."),
        lambda r: r.update(extra="x"),
        lambda r: r["catalogue"].update(draft="yes"),
        lambda r: r["catalogue"].update(manifest_sha256="abc"),
        lambda r: r["packs"][0]["coverage"].update(percent=80),
        lambda r: r["packs"][0]["coverage"].pop("expired"),
        lambda r: r["packs"][0].update(semver="v1"),
        lambda r: r["ingredients"][0].update(state="COMPLIANT"),
        lambda r: r["ingredients"][0].update(state="supported"),
        lambda r: r["ingredients"][0].update(kind="X"),
        lambda r: r["ingredients"][0].update(group="Legal"),
        lambda r: r["ingredients"][0].update(producer_ref="free text"),
        lambda r: r["ingredients"][0].update(note="customer text"),
        lambda r: r["ingredients"][0]["links"][0].update(relation="equal"),
        lambda r: r["ingredients"][0]["links"][0].update(relation="exact-ish"),
        lambda r: r["ingredients"][0]["links"][0].pop("limitations"),
        lambda r: r["ingredients"][0]["measurements"][0].update(metric="PROMPT"),
        lambda r: r["ingredients"][0]["measurements"][0].update(method="manual"),
        lambda r: r["ingredients"][0]["measurements"][0].update(confidence=1.5),
        lambda r: r["ingredients"][0]["measurements"][0].pop("target"),
        lambda r: r["ingredients"][0]["measurements"][0].pop("observation_basis"),
        lambda r: r["ingredients"][0]["measurements"][0].update(
            observation_basis="backend_observed"
        ),
        lambda r: r.update(agent_id="customer-chosen-id"),  # the requested id is never echoed
        lambda r: r["catalogue"].pop("visible_obligations"),
        lambda r: r["catalogue"].update(visible_obligations=-1),
    ],
)
def test_invalid_shapes_are_rejected(mutate: Any) -> None:
    instance = copy.deepcopy(_response())
    mutate(instance)
    assert _errors(instance) != []


def test_response_does_not_carry_the_requested_agent_id() -> None:
    assert "agent_id" not in _SCHEMA["properties"]
    assert "agent_id" not in _SCHEMA["required"]


def test_draft_wording_matches_per_pack_filtering() -> None:
    text = json.dumps(_SCHEMA["properties"]["catalogue"]["properties"]["draft"])
    assert "`packs` is empty" not in text
    assert "published packs remain visible" in text


def test_banner_is_a_single_member_enum() -> None:
    assert _SCHEMA["properties"]["banner"]["enum"] == [BANNER]


def test_null_measurement_members_are_allowed() -> None:
    instance = _response()
    instance["ingredients"][0]["measurements"] = [
        {
            "metric": "COST_USD",
            "value": 0.4,
            "interval_low": None,
            "interval_high": None,
            "confidence": None,
            "target": None,
            "method": "point_mean",
            "observation_basis": "client_reported",
        }
    ]
    assert _errors(instance) == []


def test_schema_text_has_no_determination_wording_and_no_catalogue_content() -> None:
    text = RESPONSE_PATH.read_text(encoding="utf-8").lower()
    for word in ("compliant", "certified", "satisfies"):
        assert word not in text
    # Shape only: the contract names no framework, obligation or requirement from the catalogue.
    for token in ("eu-ai-act", "nist", "sb26", "art13", "art15"):
        assert token not in text


def test_endpoint_is_registered_and_wired() -> None:
    assert "./agent_readiness/compliance_evidence_endpoints.json" in (
        SCHEMAS / "mep_endpoints.json"
    ).read_text(encoding="utf-8")
    endpoints = load_json(ENDPOINTS_PATH)
    operation = endpoints["paths"][ROUTE]["get"]
    assert operation["operationId"] == "getProjectAgentComplianceEvidence"
    ok = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ok == "./compliance_evidence_response_schema.json"
    for status in ("401", "403", "404"):
        err = operation["responses"][status]["content"]["application/json"]["schema"]["$ref"]
        assert err == "./agent_readiness_error_schema.json"
    param_names = {p["name"] for p in operation["parameters"]}
    assert param_names == {"project_id", "agent_id"}  # tenant never travels as a parameter
