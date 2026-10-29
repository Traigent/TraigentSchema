"""Schema-only checks for agent identity resolution on POST /api/v1/sessions (TraigentSchema#616).

These validate hand-built requests and bodies against the schemas; they do not prove Backend
resolution behaviour. Legacy requests stay valid; the 409 / 400 refusal bodies and the
duplicate-candidates report (not yet served) validate with no names. Typing of the locator
fields in request metadata and the content-less request shape are deferred to a later slice.
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema

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
CONTENT_LESS = ["content_less_v1"]


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
    resolver = jsonschema.RefResolver(base_uri=OPT.as_uri() + "/", referrer=_definition(name))
    validator = jsonschema.Draft7Validator(_definition(name), resolver=resolver)
    return not list(validator.iter_errors(body))


LOCATOR = {
    "function_module": "app.agents.router",
    "function_qualname": "Router.route",
    "function_relative_path": "app/agents/router.py",
}


def test_every_legacy_request_stays_valid() -> None:
    assert _errors(_payload()) == []
    assert _errors(_payload(agent_key="support-router", metadata={"owner": "x"})) == []
    assert _errors(_payload(metadata=dict(LOCATOR))) == []
    # metadata is an open object: odd locator values are accepted exactly as before
    for odd in (
        {"function_module": "app/agents/router"},
        {"function_module": 7},
        {"function_qualname": ["x"]},
        {"function_relative_path": None},
    ):
        assert _errors(_payload(metadata=odd)) == [], odd


def test_no_identity_field_is_added_to_the_request() -> None:
    doc = json.loads((OPT / "optimization_endpoints.json").read_text())
    body = doc["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    metadata_props = body["properties"]["metadata"]["properties"]
    assert not {"function_module", "function_qualname", "function_relative_path"} & set(
        metadata_props
    )
    assert "resolved_agent_id" not in body["properties"]
    assert not any(
        "agent_identity_resolution" in json.dumps(branch) for branch in body.get("allOf", [])
    )


def test_content_less_requests_are_unchanged_and_deferred() -> None:
    """The content-less identity shape is deferred; the schema neither adds nor removes
    anything for it. The Backend refuses the capability before any write (400)."""
    assert _errors(_payload(capabilities=CONTENT_LESS, agent_ref=AGENT_REF)) == []
    assert _errors(_payload(capabilities=["no_such_capability"]))
    doc = json.loads((OPT / "optimization_endpoints.json").read_text())
    post = doc["paths"]["/api/v1/sessions"]["post"]
    assert "content_less_v1" in post["responses"]["400"]["description"]
    assert "deferred" in post["responses"]["400"]["description"].lower()
    ref = post["requestBody"]["content"]["application/json"]["schema"]["properties"]["agent_ref"]
    assert "RESERVED" in ref["description"]


def test_agent_ref_must_still_be_a_server_issued_ref() -> None:
    assert _errors(_payload(capabilities=CONTENT_LESS, agent_ref="Alice_has_diabetes"))


def test_resolved_id_is_returned_in_response_metadata() -> None:
    response = json.loads((OPT / "session_create_response_schema.json").read_text())
    meta_agent_id = response["properties"]["metadata"]["properties"]["agent_id"]
    assert meta_agent_id["type"] == ["string", "null"]
    assert "JWT" in meta_agent_id["description"]


# Schema-only checks: each request validates against the request schema and each hand-built
# body against the refusal definitions. They do not prove Backend resolution behaviour.
def _envelope(code: str, text: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"success": False, "message": text, "error": text, "error_code": code}
    if details is not None:
        body["details"] = details
    return body


def test_ambiguous_body_validates_for_flattened_only_request() -> None:
    request = _payload(
        function_name="app/agents/router.py_app.agents.router_Router_route",
        metadata={
            "function_module": "app.agents.router",
            "function_relative_path": "app/agents/router.py",
            "function_name": "app/agents/router.py_app.agents.router_Router_route",
        },
    )
    assert _errors(request) == []
    refusal = _envelope(
        "agent_identity_ambiguous", AMBIGUOUS_TEXT, {"candidate_agent_ids": [A1, A2]}
    )
    assert _valid("AgentIdentityAmbiguousResponse", refusal)


def test_conflict_body_validates_against_schema() -> None:
    # Schema-only check: the body shape validates. It does not prove when the Backend sends it;
    # per the schema description an explicit agent_key hit is returned without a locator
    # comparison, so a conflict arises only from a name hit with a differing locator.
    request = _payload(metadata=dict(LOCATOR))
    assert _errors(request) == []
    refusal = _envelope("agent_identity_conflict", CONFLICT_TEXT, {"conflicting_agent_id": A1})
    assert _valid("AgentIdentityConflictResponse", refusal)


def test_refusal_bodies_carry_no_path_field() -> None:
    # Schema-only check: neither refusal body can carry function_relative_path.
    moved = dict(LOCATOR, function_relative_path="app/agents/moved/router.py")
    assert _errors(_payload(metadata=moved)) == []
    for name in ("AgentIdentityAmbiguousResponse", "AgentIdentityConflictResponse"):
        props = RESOLUTION["definitions"][name]["properties"]["details"]["properties"]
        assert "function_relative_path" not in props


def test_content_less_request_and_400_body_validate_against_schema() -> None:
    request = _payload(capabilities=CONTENT_LESS, metadata=dict(LOCATOR))
    assert _errors(request) == []  # the schema allows it; the Backend refuses it
    refusal = _envelope("CAPABILITY_NOT_SUPPORTED", CAPABILITY_TEXT)
    assert _valid("CapabilityNotSupportedResponse", refusal)
    assert not _valid("CapabilityNotSupportedResponse", {**refusal, "details": {"c": "x"}})


def test_ambiguous_409_is_closed_and_uncapped() -> None:
    assert _valid(
        "AgentIdentityAmbiguousResponse",
        _envelope("agent_identity_ambiguous", AMBIGUOUS_TEXT, {"candidate_agent_ids": [A1, A2]}),
    )
    many = [f"{i:08x}-0000-4000-8000-000000000000" for i in range(150)]
    assert _valid(
        "AgentIdentityAmbiguousResponse",
        _envelope("agent_identity_ambiguous", AMBIGUOUS_TEXT, {"candidate_agent_ids": many}),
    )
    one = _envelope("agent_identity_ambiguous", AMBIGUOUS_TEXT, {"candidate_agent_ids": [A1]})
    assert not _valid("AgentIdentityAmbiguousResponse", one)
    echoed = _envelope(
        "agent_identity_ambiguous",
        "agent Alice_has_diabetes matches",
        {"candidate_agent_ids": [A1, A2]},
    )
    assert not _valid("AgentIdentityAmbiguousResponse", echoed)
    extra = _envelope(
        "agent_identity_ambiguous",
        AMBIGUOUS_TEXT,
        {"candidate_agent_ids": [A1, A2], "name": "Alice_has_diabetes"},
    )
    assert not _valid("AgentIdentityAmbiguousResponse", extra)


def test_agent_ids_reuse_the_create_response_definition() -> None:
    ref = RESOLUTION["definitions"]["AgentId"]["$ref"]
    assert ref == "./session_create_response_schema.json#/properties/agent_id"
    # legacy non-UUID ids validate: the type is exactly the one the Backend already returns
    legacy = _envelope(
        "agent_identity_conflict", CONFLICT_TEXT, {"conflicting_agent_id": "legacy-agent"}
    )
    assert _valid("AgentIdentityConflictResponse", legacy)


def test_conflict_409_requires_its_detail() -> None:
    base = _envelope("agent_identity_conflict", CONFLICT_TEXT, {})
    assert not _valid("AgentIdentityConflictResponse", base)
    wrong = _envelope("other", CONFLICT_TEXT, {"conflicting_agent_id": A1})
    assert not _valid("AgentIdentityConflictResponse", wrong)


def test_endpoint_declares_the_409_as_the_canonical_envelope() -> None:
    doc = json.loads((OPT / "optimization_endpoints.json").read_text())
    responses = doc["paths"]["/api/v1/sessions"]["post"]["responses"]
    schema = responses["409"]["content"]["application/json"]["schema"]
    assert schema == {"$ref": "../error_envelope_schema.json"}


def test_refusal_bodies_are_valid_canonical_envelopes() -> None:
    envelope = json.loads((get_schemas_dir() / "error_envelope_schema.json").read_text())
    for body in (
        _envelope("agent_identity_ambiguous", AMBIGUOUS_TEXT, {"candidate_agent_ids": [A1, A2]}),
        _envelope("CAPABILITY_NOT_SUPPORTED", CAPABILITY_TEXT),
    ):
        assert not list(jsonschema.Draft7Validator(envelope).iter_errors(body))


def test_duplicate_candidates_report_shape_and_not_yet_served() -> None:
    report = {
        "project_id": "proj_other",
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
                    {"agent_id": A1, "created_at": "2026-10-01T00:00:00", "run_count": 4},
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
    # format checking enabled: legacy project id and a timezone-naive timestamp still validate
    resolver = jsonschema.RefResolver(
        base_uri=OPT.as_uri() + "/", referrer=_definition("DuplicateAgentCandidatesReport")
    )
    strict = jsonschema.Draft7Validator(
        _definition("DuplicateAgentCandidatesReport"),
        resolver=resolver,
        format_checker=jsonschema.FormatChecker(),
    )
    assert not list(strict.iter_errors(report))
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


def test_description_does_not_make_request_agent_id_a_resolution_input() -> None:
    # Schema-only wording check, aligned with the Backend deriving its lookup from
    # agent_key / function_name only.
    text = RESOLUTION["description"]
    assert "(agent_key, function_name) is a resolution input" in text
    assert "agent_key, agent_id, function_name" not in text
    assert "`agent_id` field is accepted but NOT used to select an agent" in text
