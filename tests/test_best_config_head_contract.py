"""Plan v2.1 phase 0b: ref-addressed agent head read and the protected-publish refusals."""
import json
import re
from pathlib import Path

from traigent_schema.utils import get_schemas_dir

OPT = Path(get_schemas_dir()) / "optimization"


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


def test_head_response_is_closed_and_has_no_raw_ids():
    schema = _load("agent_head_by_ref_response_schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"agent_ref", "environment", "generation", "exists"}
    assert set(schema["required"]) == set(schema["properties"])
    gen = schema["properties"]["generation"]
    assert gen["type"] == "integer" and gen["minimum"] == 0
    assert schema["properties"]["agent_ref"]["$ref"].endswith("#/definitions/AgentRef")
    assert schema["properties"]["environment"]["$ref"].endswith("#/definitions/SessionEnvironment")


def test_refusal_envelope_is_closed_with_one_fixed_branch_per_code():
    schema = _load("best_config_head_refusal_schema.json")
    assert schema["additionalProperties"] is False
    codes = schema["properties"]["error_code"]["enum"]
    assert codes == [
        "reference_not_found",
        "head_capture_invalid",
        "head_environment_mismatch",
        "head_agent_mismatch",
        "head_generation_stale",
        "head_write_unauthorized",
    ]
    branches = {b["properties"]["error_code"]["const"]: b["properties"] for b in schema["oneOf"]}
    assert list(branches) == codes
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches.values()] == messages
    for props in branches.values():
        assert props["error"]["const"] in schema["properties"]["error"]["enum"]
    # nothing of a request can appear in a refusal
    assert all("{" not in m and "%" not in m for m in messages)


def test_endpoints_declare_path_headers_and_closed_refusals():
    doc = _load("best_config_head_endpoints.json")
    get = doc["paths"]["/api/v1/best-configs/agent-heads/by-ref/{agent_ref}"]["get"]
    names = {p["name"]: p for p in get["parameters"]}
    assert names["agent_ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert names["environment"]["schema"]["$ref"].endswith("#/definitions/SessionEnvironment")
    assert get["responses"]["404"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "best_config_head_refusal_schema.json"
    )


def test_protected_publish_headers_rule_and_refusals_on_the_publish_route():
    doc = json.loads(
        (Path(get_schemas_dir()) / "execution" / "best_config_endpoints.json").read_text()
    )
    post = doc["paths"]["/api/v1/best-configs"]["post"]
    headers = {p["name"]: p for p in post["parameters"] if p["in"] == "header"}
    assert {"X-Traigent-Agent-Ref", "X-Traigent-Expected-Head-Generation"} <= set(headers)
    assert headers["X-Traigent-Agent-Ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert headers["X-Traigent-Expected-Head-Generation"]["schema"]["minimum"] == 0
    for status in ("400", "403", "404"):
        schema = post["responses"][status]["content"]["application/json"]["schema"]
        assert schema["$ref"].endswith("best_config_head_refusal_schema.json")
    rule = post["description"]
    for needle in ("PROTECTED PATH", "authoritative session binding", "WRITE", "ONE transaction"):
        assert needle in rule
    assert "LEGACY PATH" in rule


def test_existing_publish_inventory_mentions_the_headers():
    doc = json.loads(
        (Path(get_schemas_dir()) / "execution" / "best_config_endpoints.json").read_text()
    )
    names = {p["name"] for p in doc["paths"]["/api/v1/best-configs"]["post"]["parameters"]}
    assert {"X-Traigent-Agent-Ref", "X-Traigent-Expected-Head-Generation"} <= names
