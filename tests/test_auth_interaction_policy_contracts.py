"""Contract tests for persona interaction policy auth surfaces.

Assumed resolve route for the schema-first contract leg:
  GET /api/v1/auth/me/interaction-policy

Persistence continues through PUT /api/v1/auth/me via the top-level
interaction_policy field on update_profile_request_schema.json.
"""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator, load_schema
from traigent_schema.utils import get_schemas_dir

INTERACTION_POLICY = "interaction_policy_schema"
REQUEST = "agent_interaction_policy_request_schema"
RESPONSE = "agent_interaction_policy_response_schema"
RESOLVE_PATH = "/api/v1/auth/me/interaction-policy"


def _policy(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "control": "guided",
        "expertise": "se",
        "pace": "balanced",
    }
    payload.update(overrides)
    return payload


def test_interaction_policy_contracts_are_valid_draft7() -> None:
    for schema_name in (INTERACTION_POLICY, REQUEST, RESPONSE):
        Draft7Validator.check_schema(load_schema(schema_name))


def test_interaction_policy_contracts_are_registered_by_runtime_discovery() -> None:
    available = set(SchemaValidator().available_schemas)
    assert INTERACTION_POLICY in available
    assert REQUEST in available
    assert RESPONSE in available


def test_interaction_policy_accepts_minimal_profile() -> None:
    assert SchemaValidator().validate_json(_policy(), INTERACTION_POLICY) == []


def test_interaction_policy_rejects_unknown_fields_and_bad_confidence() -> None:
    validator = SchemaValidator()
    assert validator.validate_json(
        _policy(confidence=1.1),
        INTERACTION_POLICY,
    )
    assert validator.validate_json(
        _policy(source="stored", extra_mode="fast"),
        INTERACTION_POLICY,
    )


def test_update_profile_request_wires_top_level_interaction_policy() -> None:
    update_profile = load_schema("update_profile_request_schema")
    assert update_profile["properties"]["interaction_policy"]["$ref"].endswith(
        "interaction_policy_schema.json"
    )
    payload = {
        "name": "Alice",
        "interaction_policy": _policy(
            source="stored",
            confidence=0.82,
            schema_version="traigent.interaction_policy.v1",
        ),
    }
    assert SchemaValidator().validate_json(payload, "update_profile_request_schema") == []


def test_resolve_request_accepts_minimal_and_full_payloads() -> None:
    validator = SchemaValidator(contract="backend")
    minimal = {"schema_version": "traigent.agent_interaction.request.v1"}
    assert validator.validate_json(minimal, REQUEST) == []
    assert validator.validate_request(RESOLVE_PATH, "GET", minimal) == []

    full = {
        "schema_version": "traigent.agent_interaction.request.v1",
        "harness": "codex",
        "skill": "traigent-spine:feature",
        "task_intent": "plan",
        "observed_signals": {
            "explicit_profile": {"control": "inspect", "expertise": "ds"},
            "pace_cues": ["needs walkthrough", "wants checkpoints"],
            "confidence": 0.6,
        },
        "privacy": {"allow_persist": True, "allow_telemetry": False},
    }
    assert validator.validate_json(full, REQUEST) == []


def test_resolve_request_rejects_missing_version_and_nested_unknowns() -> None:
    validator = SchemaValidator(contract="backend")
    assert validator.validate_request(RESOLVE_PATH, "GET", {})
    invalid = {
        "schema_version": "traigent.agent_interaction.request.v1",
        "observed_signals": {
            "explicit_profile": {"control": "guided", "expertise": "se", "pace": "execute"},
        },
        "privacy": {"allow_persist": True},
    }
    errors = validator.validate_json(invalid, REQUEST)
    assert errors


def test_resolve_response_accepts_resolved_profile_payload() -> None:
    payload = {
        "schema_version": "traigent.agent_interaction.response.v1",
        "profile": _policy(
            source="session",
            confidence=0.91,
            schema_version="traigent.interaction_policy.v1",
        ),
        "policy_text": "Ask at most one clarifying question, then execute with brief technical commentary.",
        "question_budget": 1,
        "options_max": 2,
        "jargon_level": "technical",
        "next_skill_hint": "traigent-spine:feature",
        "fallback_policy": "static_v1",
    }
    assert SchemaValidator().validate_json(payload, RESPONSE) == []


def test_resolve_response_requires_profile_and_static_fallback() -> None:
    validator = SchemaValidator()
    payload = {
        "schema_version": "traigent.agent_interaction.response.v1",
        "profile": _policy(),
        "policy_text": "Proceed carefully.",
        "fallback_policy": "dynamic_v2",
    }
    assert validator.validate_json(payload, RESPONSE)
    missing_profile = {
        "schema_version": "traigent.agent_interaction.response.v1",
        "policy_text": "Proceed carefully.",
        "fallback_policy": "static_v1",
    }
    assert validator.validate_json(missing_profile, RESPONSE)


def test_auth_endpoints_wire_interaction_policy_contracts() -> None:
    with open(get_schemas_dir() / "auth" / "auth_endpoints.json", encoding="utf-8") as fh:
        spec = json.load(fh)

    route = spec["paths"][RESOLVE_PATH]["get"]
    request_ref = route["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert request_ref.endswith("agent_interaction_policy_request_schema.json")

    response_ref = route["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert response_ref.endswith("agent_interaction_policy_response_schema.json")

    for code in ("400", "401", "404", "500"):
        assert route["responses"][code]["content"]["application/json"]["schema"]["$ref"].endswith(
            "error_envelope_schema.json"
        )
