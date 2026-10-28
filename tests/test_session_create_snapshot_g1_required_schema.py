"""Closed G1 intent boolean on session create (`snapshot_g1_required`).

An online run with an opt-in snapshot store declares, at registration, that it will be
co-signed (G1) so the server defers B1 issuance. Only this boolean crosses.
"""

from __future__ import annotations

from typing import Any

import pytest

from traigent_schema import SchemaValidator


def _payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "support_router",
        "configuration_space": {"temperature": [0.1, 0.9]},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def _errors(payload: dict[str, Any]) -> list[Any]:
    validator = SchemaValidator(contract="sdk_tuning")
    return validator.validate_request("/api/v1/sessions", "POST", payload)


def test_absent_is_valid() -> None:
    assert _errors(_payload()) == []


@pytest.mark.parametrize("value", [True, False])
def test_boolean_is_valid(value: bool) -> None:
    assert _errors(_payload(snapshot_g1_required=value)) == []


@pytest.mark.parametrize("value", ["true", 1, 0, None, {}, []])
def test_non_boolean_is_rejected(value: Any) -> None:
    assert _errors(_payload(snapshot_g1_required=value)), repr(value)


def test_property_is_optional_and_declares_its_semantics() -> None:
    import json

    from traigent_schema.utils import get_schemas_dir

    path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(path.read_text())
    body = document["paths"]["/api/v1/sessions"]["post"]["requestBody"]
    schema = body["content"]["application/json"]["schema"]
    assert "snapshot_g1_required" not in schema["required"]
    prop = schema["properties"]["snapshot_g1_required"]
    assert prop["type"] == "boolean"
    assert "G1" in prop["description"] and "B1" in prop["description"]
