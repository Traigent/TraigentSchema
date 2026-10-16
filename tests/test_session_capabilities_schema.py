"""P3 group 1: additive identity refs, closed environment, capability negotiation."""
import json

from traigent_schema.utils import get_schemas_dir

OPT = get_schemas_dir() / "optimization"


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


def _request_props():
    doc = _load("optimization_endpoints.json")
    body = doc["paths"]["/api/v1/sessions"]["post"]["requestBody"]
    schema = body["content"]["application/json"]["schema"]
    return schema, schema["properties"]


def test_closed_vocabularies():
    defs = _load("session_capabilities_schema.json")["definitions"]
    assert defs["SessionCapability"]["enum"] == ["content_less_v1"]
    assert defs["SessionEnvironment"]["enum"] == [
        "production", "staging", "development", "test", "default",
    ]
    assert defs["OptimizationRefusalCode"]["enum"] == [
        "client_upgrade_required", "backend_upgrade_required", "session_shape_legacy",
    ]
    assert defs["SessionCapabilityList"]["uniqueItems"] is True


def test_request_members_are_optional_and_reference_closed_definitions():
    schema, props = _request_props()
    names = ("agent_ref", "dataset_ref", "evaluation_set_ref", "evaluator_ref")
    for name in names + ("environment", "capabilities"):
        assert name in props
        assert name not in schema["required"]
    assert props["environment"]["$ref"].endswith("#/definitions/SessionEnvironment")
    assert props["capabilities"]["$ref"].endswith("#/definitions/SessionCapabilityList")


def test_response_advertises_capabilities_in_both_contracts():
    doc = _load("optimization_endpoints.json")
    created = doc["paths"]["/api/v1/sessions"]["post"]["responses"]["201"]
    inline = created["content"]["application/json"]["schema"]
    standalone = _load("session_create_response_schema.json")
    for props in (inline["properties"], standalone["properties"]):
        assert props["capabilities"]["$ref"].endswith("#/definitions/SessionCapabilityList")
