"""Plan v2.1 phase 0b: ref-addressed agent head read and the protected-publish contract."""
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
OPT = SCHEMAS / "optimization"
BASE = "https://schemas.traigent.ai/"
CODES = [
    "reference_not_found",
    "head_capture_invalid",
    "head_environment_mismatch",
    "head_agent_mismatch",
    "head_generation_stale",
    "head_write_unauthorized",
    "unauthenticated",
    "forbidden",
    "internal_error",
]


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


def _validator(name):
    registry = Registry()
    for rel in ("optimization/session_capabilities_schema.json", "labels/label_common_schema.json"):
        doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
        registry = registry.with_resource(BASE + rel, Resource.from_contents(doc))
    return Draft7Validator(_load(name), registry=registry)


REF = "agentref_" + "a" * 32


def test_head_response_is_closed_and_has_no_raw_ids():
    schema = _load("agent_head_by_ref_response_schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"agent_ref", "environment", "generation", "exists"}
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["agent_ref"]["$ref"].endswith("#/definitions/AgentRef")
    assert schema["properties"]["environment"]["$ref"].endswith("#/definitions/SessionEnvironment")


@pytest.mark.parametrize(
    ("generation", "exists", "valid"),
    [(0, False, True), (1, True, True), (7, True, True), (0, True, False), (1, False, False),
     (5, False, False), (-1, False, False)],
)
def test_exists_is_false_iff_generation_is_zero(generation, exists, valid):
    body = {"agent_ref": REF, "environment": "default", "generation": generation, "exists": exists}
    assert (not list(_validator("agent_head_by_ref_response_schema.json").iter_errors(body))) is valid


def test_response_rejects_raw_ids_and_extra_members():
    body = {"agent_ref": REF, "environment": "default", "generation": 0, "exists": False}
    validator = _validator("agent_head_by_ref_response_schema.json")
    assert not list(validator.iter_errors(body))
    assert list(validator.iter_errors({**body, "agent_id": "pk"}))
    assert list(validator.iter_errors({**body, "agent_ref": "pk-1"}))


def test_refusal_envelope_is_closed_with_one_fixed_branch_per_code():
    schema = _load("best_config_head_refusal_schema.json")
    assert schema["additionalProperties"] is False
    assert schema["properties"]["error_code"]["enum"] == CODES
    branches = {b["properties"]["error_code"]["const"]: b["properties"] for b in schema["oneOf"]}
    assert list(branches) == CODES
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches.values()] == messages
    for props in branches.values():
        assert props["error"]["const"] in schema["properties"]["error"]["enum"]
    assert all("{" not in m and "%" not in m for m in messages)
    validator = _validator("best_config_head_refusal_schema.json")
    for code, props in branches.items():
        body = {
            "success": False,
            "error": props["error"]["const"],
            "error_code": code,
            "message": props["message"]["const"],
        }
        assert not list(validator.iter_errors(body)), code
        # a code with another code's text is not a valid envelope
        other = {**body, "message": messages[(CODES.index(code) + 1) % len(CODES)]}
        assert list(validator.iter_errors(other)), code


def test_stale_guidance_is_normative_and_never_says_reread_and_resubmit():
    text = (OPT / "best_config_head_refusal_schema.json").read_text(encoding="utf-8")
    assert "MUST NOT refresh the generation and resubmit the same result" in text
    assert "MUST NEVER auto-retry" in text
    for forbidden in ("re-read the head and re-run", "re-run the promotion"):
        assert forbidden not in text
        for path in (
            OPT / "best_config_head_endpoints.json",
            OPT / "agent_head_by_ref_response_schema.json",
            SCHEMAS / "execution" / "best_config_endpoints.json",
        ):
            assert forbidden not in path.read_text(encoding="utf-8")


def test_read_route_has_closed_errors_for_every_status_but_rate_limit():
    doc = _load("best_config_head_endpoints.json")
    get = doc["paths"]["/api/v1/best-configs/agent-heads/by-ref/{agent_ref}"]["get"]
    names = {p["name"]: p for p in get["parameters"]}
    assert names["agent_ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert names["environment"]["schema"]["$ref"].endswith("#/definitions/SessionEnvironment")
    for status in ("400", "401", "403", "404", "500"):
        schema = get["responses"][status]["content"]["application/json"]["schema"]
        assert schema["$ref"].endswith("best_config_head_refusal_schema.json"), status
    assert get["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "rate_limit_info_schema.json"
    )
    assert "ORDER OF REFUSALS" in get["description"]


def _publish():
    doc = json.loads((SCHEMAS / "execution" / "best_config_endpoints.json").read_text())
    return doc["paths"]["/api/v1/best-configs"]["post"]


def test_publish_headers_and_applicability_decision_table():
    post = _publish()
    headers = {p["name"]: p for p in post["parameters"] if p["in"] == "header"}
    assert {"X-Traigent-Agent-Ref", "X-Traigent-Expected-Head-Generation"} <= set(headers)
    assert headers["X-Traigent-Agent-Ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert headers["X-Traigent-Expected-Head-Generation"]["schema"]["minimum"] == 0
    rule = post["description"]
    assert "if and only if" in rule and "content_less_v1" in rule and "content_less_v2" in rule
    rows = [f"[{n}]" for n in range(1, 9)]
    assert all(row in rule for row in rows)
    for needle in (
        "Agent-Ref and Agent-Id both present -> 400 head_capture_invalid",
        "Agent-Ref present, Expected-Head-Generation missing",
        "LEGACY, unchanged",
        "authoritative session binding",
        "ONE transaction",
        "exactly one wins",
    ):
        assert needle in rule, needle


def test_refusal_precedence_is_written_down():
    rule = _publish()["description"]
    order = [
        "400 head_capture_invalid",
        "404 reference_not_found",
        "403 head_write_unauthorized",
        "409 head_agent_mismatch",
        "409 head_environment_mismatch",
        "409 head_generation_stale",
    ]
    positions = [rule.index(item, rule.index("ORDER OF REFUSALS")) for item in order]
    assert positions == sorted(positions)


def test_protected_409_has_a_schema_and_the_legacy_body_is_kept():
    post = _publish()
    schema = post["responses"]["409"]["content"]["application/json"]["schema"]
    protected, legacy = schema["oneOf"]
    assert protected["allOf"][0]["$ref"].endswith("best_config_head_refusal_schema.json")
    assert protected["allOf"][1]["properties"]["error_code"]["enum"] == [
        "head_environment_mismatch",
        "head_agent_mismatch",
        "head_generation_stale",
    ]
    assert "STALE_HEAD_GENERATION" in legacy["description"]
    for status in ("400", "403", "404"):
        assert post["responses"][status]["content"]["application/json"]["schema"]["$ref"].endswith(
            "best_config_head_refusal_schema.json"
        )
