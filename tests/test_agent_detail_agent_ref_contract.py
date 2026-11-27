"""Contract for the optional agent_ref on the agent detail response.

GET /api/v1/projects/{project_id}/agents/{agent_ref} returns the success envelope; its
``data`` is ``agent_detail_schema.json``: the shared agent schema plus the optional
server-issued ``agent_ref``. The shared ``agent_schema.json`` must stay unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
AGENTS = S / "agents"
VALID_REF = "agentref_" + "0" * 32
PLAIN_AGENT_ID = "agent_9f2c4e1a"


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    registry = Registry()
    for path in S.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = "https://schemas.traigent.ai/" + path.relative_to(S).as_posix()
        registry = registry.with_resource(uri, Resource.from_contents(doc, default_specification=DRAFT7))
    return registry


def _validator(schema: dict[str, Any]) -> jsonschema.Draft7Validator:
    return jsonschema.Draft7Validator(schema, registry=_registry())


DETAIL = _validator(_load(AGENTS / "agent_detail_schema.json"))


def _agent(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"id": PLAIN_AGENT_ID, "name": "Support bot", "agent_type": "chat"}
    body.update(extra)
    return body


def _errors(validator, body):
    return list(validator.iter_errors(body))


def test_detail_accepts_a_valid_server_issued_reference():
    assert not _errors(DETAIL, _agent(agent_ref=VALID_REF))


def test_detail_rejects_a_plain_agent_id_in_the_reference_slot():
    assert _errors(DETAIL, _agent(agent_ref=PLAIN_AGENT_ID))


def test_detail_rejects_a_reference_with_uppercase_hex():
    assert _errors(DETAIL, _agent(agent_ref="agentref_" + "A" * 32))


def test_detail_allows_absence_of_agent_ref():
    assert "agent_ref" not in _load(AGENTS / "agent_detail_schema.json").get("required", [])
    assert not _errors(DETAIL, _agent())


def test_detail_stays_closed_to_unknown_keys():
    assert _errors(DETAIL, _agent(agent_id=PLAIN_AGENT_ID))


def test_detail_agent_ref_is_the_shared_opaque_reference_definition():
    prop = _load(AGENTS / "agent_detail_schema.json")["properties"]["agent_ref"]
    assert "$ref" not in prop
    assert prop["allOf"] == [{"$ref": "../labels/label_common_schema.json#/definitions/AgentRef"}]
    assert prop["x-content-class"] == "opaque_ref"
    assert prop["description"] == (
        "Server-issued release reference of this agent (an `agentref_` digest), scoped to the "
        "tenant and project and derived one-way from the agent id. It is not the agent id used in "
        "this request's path: the release-acceptance and release routes take this reference in "
        "their `{agent_ref}` path segment."
    )


def test_detail_property_set_tracks_shared_agent_schema_plus_agent_ref():
    shared = set(_load(AGENTS / "agent_schema.json")["properties"])
    detail = set(_load(AGENTS / "agent_detail_schema.json")["properties"])
    assert detail == shared | {"agent_ref"}


def test_shared_agent_schema_is_unchanged_and_still_rejects_agent_ref():
    shared = _load(AGENTS / "agent_schema.json")
    assert "agent_ref" not in shared["properties"]
    assert shared["additionalProperties"] is False
    assert _errors(_validator(shared), _agent(agent_ref=VALID_REF))


def test_get_agent_200_data_is_wired_to_the_detail_schema():
    get_200_pointer = (
        "/paths/~1api~1v1~1projects~1{project_id}~1agents~1{agent_ref}"
        "/get/responses/200/content/application~1json/schema"
    )
    envelope_ref = {"$ref": "https://schemas.traigent.ai/agents/agents_endpoints.json#" + get_200_pointer}
    envelope = _validator(envelope_ref)
    ok = {"success": True, "message": "ok", "data": _agent(agent_ref=VALID_REF)}
    assert not _errors(envelope, ok)
    assert _errors(envelope, {"success": True, "message": "ok", "data": _agent(agent_ref=PLAIN_AGENT_ID)})
    assert not _errors(envelope, {"success": True, "message": "ok", "data": _agent()})
