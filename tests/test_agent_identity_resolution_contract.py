"""Agent identity resolution contract on POST /api/v1/sessions (TraigentSchema#616).

Pins: legacy requests stay valid; the code locator is optional, typed and code-identifier
only; a content-less request carries no customer-chosen agent label; the 409 / 400 refusal
bodies match the Backend wire shapes exactly (fixed text, ids only); the duplicate-candidates
report shape (not yet served) validates and carries no names.
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OPT = get_schemas_dir() / "optimization"
RESOLUTION = json.loads((OPT / "agent_identity_resolution_schema.json").read_text())

AMBIGUOUS_TEXT = (
    "More than one existing agent in this project matches this function. "
    "No agent was created; resolve the duplicates and retry."
)
CONFLICT_TEXT = (
    "An existing agent already uses this identity for a different function. "
    "No agent was created."
)
CAPABILITY_TEXT = (
    "A requested capability is not supported by this server; no session was created"
)
A1 = "11111111-1111-4111-8111-111111111111"
A2 = "22222222-2222-4222-8222-222222222222"
A3 = "33333333-3333-4333-8333-333333333333"
A4 = "44444444-4444-4444-8444-444444444444"
AGENT_REF = "agentref_" + "0" * 32


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _errors(payload: dict[str, Any]) -> list[Any]:
    return SchemaValidator(contract="sdk_tuning").validate_request(
        "/api/v1/sessions", "POST", payload
    )


def _definition(name: str) -> dict[str, Any]:
    return {**RESOLUTION["definitions"][name], "definitions": RESOLUTION["definitions"]}


def _valid(name: str, body: dict[str, Any]) -> bool:
    return not list(jsonschema.Draft7Validator(_definition(name)).iter_errors(body))


LOCATOR = {
    "function_module": "app.agents.router",
    "function_qualname": "Router.route",
    "function_relative_path": "app/agents/router.py",
}


def test_legacy_request_without_any_new_field_is_valid() -> None:
    assert _errors(_payload()) == []
    assert _errors(_payload(agent_key="support-router", metadata={"owner": "x"})) == []


def test_code_locator_is_optional_and_accepted_in_metadata() -> None:
    assert _errors(_payload(metadata=dict(LOCATOR))) == []
    assert _errors(_payload(metadata={"function_module": "app.agents.router"})) == []
    assert _errors(_payload(capabilities=CONTENT_LESS, metadata=dict(LOCATOR))) == []


@pytest.mark.parametrize(
    "legacy_metadata",
    [
        {"function_module": "app/agents/router"},
        {"function_module": "Alice has diabetes"},
        {"function_module": 7},
        {"function_qualname": "Router route"},
        {"function_qualname": ["x"]},
        {"function_relative_path": "/abs/path.txt"},
        {"function_relative_path": None},
        {"function_module": None, "other": {"nested": True}},
    ],
)
def test_legacy_metadata_keeps_its_old_open_shape(legacy_metadata: dict[str, Any]) -> None:
    """Base-vs-branch regression: the base schema accepted any metadata object (open,
    additionalProperties true) and so does this one outside a content-less session."""
    assert _errors(_payload(metadata=legacy_metadata)) == []


@pytest.mark.parametrize(
    "bad",
    [
        {"function_module": "Alice has diabetes"},
        {"function_module": "app/agents/router"},
        {"function_qualname": "Router route"},
        {"function_qualname": "a" * 513},
        {"function_relative_path": "/etc/passwd.py"},
        {"function_relative_path": "../secret.py"},
        {"function_relative_path": "Alice has diabetes.py"},
    ],
)
def test_content_less_locator_fields_reject_free_text_and_unsafe_paths(
    bad: dict[str, str],
) -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, metadata=bad)), bad


def test_content_less_function_name_must_be_a_code_identifier() -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, function_name="Alice has diabetes"))
    assert _errors(_payload(capabilities=CONTENT_LESS, function_name="a, b"))
    ok = "app/agents/router.py_app.agents.router_Router_route"
    assert _errors(_payload(capabilities=CONTENT_LESS, function_name=ok)) == []
    # legacy: a free-text function_name is unchanged
    assert _errors(_payload(function_name="Alice has diabetes")) == []


@pytest.mark.parametrize("field", ["run_title", "run_description"])
def test_content_less_run_labels_must_be_null(field: str) -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, **{field: "Alice has diabetes"}))
    assert _errors(_payload(capabilities=CONTENT_LESS, **{field: None})) == []
    assert _errors(_payload(**{field: "nightly sweep"})) == []


def test_unknown_capability_value_is_a_schema_violation() -> None:
    assert _errors(_payload(capabilities=["no_such_capability"]))


def test_exact_key_and_flattened_input_shapes_are_documented() -> None:
    text = RESOLUTION["description"]
    # exact legacy lookup first, then locator; flattened fallback reads metadata.function_name
    assert "exact legacy lookup" in text and "step 1" not in text.lower() or "(1)" in text
    assert "metadata.function_name" in text and "NOT the top-level" in text
    assert "never compared" in text
    assert "agent_ref" in text and "RESERVED" in text
    # a flattened-only request (no function_qualname) is a valid request
    meta = {"function_module": "app.agents.router", "function_name": "app_agents_router_R_route"}
    assert _errors(_payload(metadata=meta)) == []
    assert _errors(_payload(agent_key="support-router", metadata=dict(LOCATOR))) == []


def test_legacy_content_less_with_declared_agent_id_is_now_invalid() -> None:
    """Compatibility record: this content-less shape (identity v2, declared agent_id) was
    valid before TraigentSchema#616 and is deliberately refused now (GNFR-PRIV-003)."""
    payload = _payload(
        capabilities=CONTENT_LESS,
        identity_version=2,
        agent_id="ticket-classifier",
        agent_id_source="declared",
        dataset_id="refunds-golden",
        dataset_id_source="declared",
        artifact_versions={
            k: {"schema": "fp1", "digest": "sha256:" + str(i) * 64, "state": "verified"}
            for i, k in enumerate(("agent", "dataset", "evaluator", "config_space"), 1)
        },
    )
    errors = _errors(payload)
    assert errors and any("agent_id" in str(e) for e in errors)
    assert _errors({**payload, "agent_id": None, "agent_id_source": "unknown"}) == []


def test_declared_identity_stays_distinct_from_resolved_identity() -> None:
    """A request has no `resolved_agent_id`-style field; the resolved id is response-only."""
    request = json.loads((OPT / "optimization_endpoints.json").read_text())
    body = request["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert "resolved_agent_id" not in body["properties"]
    response = json.loads((OPT / "session_create_response_schema.json").read_text())
    meta_agent_id = response["properties"]["metadata"]["properties"]["agent_id"]
    assert meta_agent_id["type"] == ["string", "null"]
    assert "JWT" in meta_agent_id["description"]
    assert "metadata.agent_id" in RESOLUTION["description"]
    assert "JWT" in RESOLUTION["description"]


CONTENT_LESS = ["content_less_v1"]


def test_agent_ref_description_says_reserved() -> None:
    doc = json.loads((OPT / "optimization_endpoints.json").read_text())
    body = doc["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    assert "RESERVED" in body["properties"]["agent_ref"]["description"]


def test_content_less_with_only_agent_ref_is_valid() -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, agent_ref=AGENT_REF)) == []


def test_content_less_with_only_the_code_locator_is_valid() -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, metadata=dict(LOCATOR))) == []


@pytest.mark.parametrize("field", ["agent_key", "agent_id"])
def test_content_less_with_a_customer_chosen_name_is_rejected(field: str) -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, **{field: "Alice_has_diabetes"}))


@pytest.mark.parametrize("field", ["agent_key", "agent_id"])
def test_content_less_with_null_name_is_valid_and_legacy_keeps_its_name(field: str) -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, **{field: None})) == []
    assert _errors(_payload(**{field: "support-router"})) == []


def test_agent_ref_must_be_a_server_issued_ref_and_is_reserved() -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, agent_ref="Alice_has_diabetes"))


def _ambiguous(ids: list[str]) -> dict[str, Any]:
    return {
        "success": False,
        "message": AMBIGUOUS_TEXT,
        "error": AMBIGUOUS_TEXT,
        "error_code": "agent_identity_ambiguous",
        "details": {"candidate_agent_ids": ids},
    }


def test_ambiguous_409_validates_and_is_closed() -> None:
    assert _valid("AgentIdentityAmbiguousResponse", _ambiguous([A1, A2]))
    # the Backend caps nothing: a long candidate list must validate
    many = [f"{i:08x}-0000-4000-8000-000000000000" for i in range(150)]
    assert _valid("AgentIdentityAmbiguousResponse", _ambiguous(many))
    # one candidate is not an ambiguity
    assert not _valid("AgentIdentityAmbiguousResponse", _ambiguous([A1]))
    # ids are server-issued UUIDs, never names
    assert not _valid("AgentIdentityAmbiguousResponse", _ambiguous(["Alice_has_diabetes", A2]))
    # fixed text only: an echoed client value is rejected
    echoed = {**_ambiguous([A1, A2]), "message": "agent Alice_has_diabetes matches"}
    assert not _valid("AgentIdentityAmbiguousResponse", echoed)
    extra = _ambiguous([A1, A2])
    extra["details"]["name"] = "Alice_has_diabetes"
    assert not _valid("AgentIdentityAmbiguousResponse", extra)


def test_conflict_409_validates_and_is_closed() -> None:
    body = {
        "success": False,
        "message": CONFLICT_TEXT,
        "error": CONFLICT_TEXT,
        "error_code": "agent_identity_conflict",
        "details": {"conflicting_agent_id": A1},
    }
    assert _valid("AgentIdentityConflictResponse", body)
    assert not _valid("AgentIdentityConflictResponse", {**body, "details": {}})
    assert not _valid("AgentIdentityConflictResponse", {**body, "error_code": "other"})


def test_capability_not_supported_400_validates_without_details() -> None:
    body = {
        "success": False,
        "message": CAPABILITY_TEXT,
        "error": CAPABILITY_TEXT,
        "error_code": "CAPABILITY_NOT_SUPPORTED",
    }
    assert _valid("CapabilityNotSupportedResponse", body)
    assert not _valid("CapabilityNotSupportedResponse", {**body, "details": {"c": "x"}})


def test_endpoint_declares_the_409_as_the_canonical_envelope() -> None:
    doc = json.loads((OPT / "optimization_endpoints.json").read_text())
    responses = doc["paths"]["/api/v1/sessions"]["post"]["responses"]
    schema = responses["409"]["content"]["application/json"]["schema"]
    assert schema == {"$ref": "../error_envelope_schema.json"}
    text = responses["409"]["description"]
    for name in ("AgentIdentityAmbiguousResponse", "AgentIdentityConflictResponse"):
        assert name in text


def test_refusal_bodies_are_valid_canonical_envelopes() -> None:
    envelope = json.loads((get_schemas_dir() / "error_envelope_schema.json").read_text())
    for body in (
        _ambiguous([A1, A2]),
        {
            "success": False,
            "message": CAPABILITY_TEXT,
            "error": CAPABILITY_TEXT,
            "error_code": "CAPABILITY_NOT_SUPPORTED",
        },
    ):
        assert not list(jsonschema.Draft7Validator(envelope).iter_errors(body))


def test_duplicate_candidates_report_shape_and_not_yet_served() -> None:
    report = {
        "project_id": "project_" + "0" * 32,
        "agents_examined": 3,
        "read_only": True,
        "notes": ["The relative file path is a hint and is not compared."],
        "groups": [
            {
                "match_reasons": ["same_module_and_qualname"],
                "locator_precision": "mixed",
                "uncertainty": "medium",
                "decisive": False,
                "candidates": [
                    {"agent_id": A1, "created_at": "2026-10-01T00:00:00+00:00", "run_count": 4},
                    {"agent_id": A2, "created_at": None, "run_count": 0},
                ],
            },
            {
                "match_reasons": ["shared_hash_suffix_only"],
                "uncertainty": "high",
                "decisive": False,
                "candidates": [
                    {"agent_id": A3, "created_at": None, "run_count": 1},
                    {"agent_id": A4, "created_at": None, "run_count": 2},
                ],
            },
        ],
    }
    assert _valid("DuplicateAgentCandidatesReport", report)
    assert not _valid("DuplicateAgentCandidatesReport", {**report, "read_only": False})
    named = json.loads(json.dumps(report))
    named["groups"][0]["candidates"][0]["name"] = "Alice_has_diabetes"
    assert not _valid("DuplicateAgentCandidatesReport", named)
    # no route serves it yet
    endpoints = "".join(p.read_text() for p in OPT.glob("*_endpoints.json"))
    assert "DuplicateAgentCandidatesReport" not in endpoints
    assert "not yet served" in RESOLUTION["definitions"][
        "DuplicateAgentCandidatesReport"
    ]["description"].lower()
