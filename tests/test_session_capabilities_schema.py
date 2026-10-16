"""P3 group 1: additive identity refs, closed environment, capability negotiation."""
import json
from pathlib import Path

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


def test_refusal_envelope_is_closed_and_wired():
    refusal = _load("optimization_refusal_schema.json")
    assert refusal["additionalProperties"] is False
    assert refusal["properties"]["error_code"]["enum"] == [
        "client_upgrade_required", "session_shape_legacy",
    ]  # backend_upgrade_required is client-local, never on the wire
    codes = _load("session_capabilities_schema.json")["definitions"]["OptimizationRefusalCode"]
    assert set(refusal["properties"]["error_code"]["enum"]) < set(codes["enum"])
    paths = _load("optimization_endpoints.json")["paths"]
    ref = "./optimization_refusal_schema.json"

    def schema_ref(path, code):
        resp = paths[path]["post"]["responses"][code]
        return resp["content"]["application/json"]["schema"]["$ref"]

    assert schema_ref("/api/v1/sessions", "426") == ref
    for sub in ("next-trial", "intermediate-report", "results"):
        assert schema_ref(f"/api/v1/sessions/{{session_id}}/{sub}", "409") == ref


def test_negotiation_by_membership_is_documented():
    doc = Path(__file__).resolve().parents[1] / "docs" / "content-classes.md"
    text = doc.read_text(encoding="utf-8")
    assert "absent or `[]` means the legacy shape" in text
    assert "never falls back to plaintext" in text
    assert "client-local" in text


def _registry():
    """Map every local schema $id to its file so relative $refs resolve offline."""
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in get_schemas_dir().rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and isinstance(doc.get("$id"), str):
            registry = registry.with_resource(doc["$id"], Resource.from_contents(doc, default_specification=DRAFT7))
    return registry


def _ref_validator(schema):
    from jsonschema import Draft7Validator

    return Draft7Validator(schema, registry=_registry())


def _created_201_payload(**refs):
    payload = {
        "session_id": "11111111-1111-1111-1111-111111111111",
        "status": "created",
        "capabilities": ["content_less_v1"],
        "agent_ref": "agentref_0123456789abcdef0123456789abcdef",
        "dataset_ref": "datasetref_0123456789abcdef0123456789abcdef",
        "evaluator_ref": "evaluatorref_0123456789abcdef0123456789abcdef",
    }
    payload.update(refs)
    return payload


def _inline_201_schema():
    doc = _load("optimization_endpoints.json")
    schema = dict(doc["paths"]["/api/v1/sessions"]["post"]["responses"]["201"]["content"]["application/json"]["schema"])
    # Give the inline schema a base URI so its relative $refs resolve like the standalone file's.
    schema["$id"] = "https://schemas.traigent.ai/optimization/optimization_endpoints.json"
    return schema


def test_201_with_opaque_refs_validates_in_both_contracts():
    standalone = _load("session_create_response_schema.json")
    for schema in (standalone, _inline_201_schema()):
        validator = _ref_validator(schema)
        assert list(validator.iter_errors(_created_201_payload())) == []
        # Refs are optional: a 201 without them still validates.
        bare = {k: v for k, v in _created_201_payload().items() if not k.endswith("_ref")}
        assert list(validator.iter_errors(bare)) == []


def test_201_rejects_malformed_refs_in_both_contracts():
    standalone = _load("session_create_response_schema.json")
    bad_values = {
        "agent_ref": ["agent-42", "agentref_XYZ", "Alice_has_diabetes", "agentref_0123456789ABCDEF0123456789ABCDEF"],
        "dataset_ref": ["my-dataset", "datasetref_short"],
        "evaluator_ref": ["evaluator_1", "evaluatorref_0123456789abcdef0123456789abcdef0"],
    }
    for schema in (standalone, _inline_201_schema()):
        validator = _ref_validator(schema)
        for field, values in bad_values.items():
            for value in values:
                errors = list(validator.iter_errors(_created_201_payload(**{field: value})))
                assert errors, f"{field}={value!r} should be rejected"
