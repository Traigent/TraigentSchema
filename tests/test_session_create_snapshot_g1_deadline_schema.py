"""Closed G1 co-sign deadline on session create (`snapshot_g1_deadline_days`).

An integer from 1 to 30 days, meaningful only together with ``snapshot_g1_required: true``.
Absent means the server default (7 days).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


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


def _property() -> dict[str, Any]:
    path = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
    document = json.loads(path.read_text())
    body = document["paths"]["/api/v1/sessions"]["post"]["requestBody"]
    schema = body["content"]["application/json"]["schema"]
    assert "snapshot_g1_deadline_days" not in schema["required"]
    return schema["properties"]["snapshot_g1_deadline_days"]


def test_absent_is_valid() -> None:
    assert _errors(_payload(snapshot_g1_required=True)) == []


@pytest.mark.parametrize("days", [1, 7, 30])
def test_in_range_integer_is_valid(days: int) -> None:
    payload = _payload(snapshot_g1_required=True, snapshot_g1_deadline_days=days)
    assert _errors(payload) == []


@pytest.mark.parametrize("value", [0, 31, -1, 7.5, "7", None, True, {}, []])
def test_out_of_range_or_non_integer_is_rejected(value: Any) -> None:
    payload = _payload(snapshot_g1_required=True, snapshot_g1_deadline_days=value)
    assert _errors(payload), repr(value)


def test_property_is_closed_optional_and_documents_the_pairing() -> None:
    prop = _property()
    assert prop["type"] == "integer"
    assert (prop["minimum"], prop["maximum"]) == (1, 30)
    assert prop["x-content-class"] == "number"
    assert "snapshot_g1_required" in prop["description"]
    assert "7" in prop["description"]


@pytest.mark.parametrize("flag", ["absent", False, None])
def test_deadline_without_a_true_required_flag_is_rejected(flag: Any) -> None:
    payload = _payload(snapshot_g1_deadline_days=12)
    if flag != "absent":
        payload["snapshot_g1_required"] = flag
    assert _errors(payload), repr(flag)


def test_deadline_with_required_true_is_valid() -> None:
    payload = _payload(snapshot_g1_required=True, snapshot_g1_deadline_days=12)
    assert _errors(payload) == []


@pytest.mark.parametrize("flag", ["absent", True, False])
def test_neither_deadline_nor_a_required_flag_constraint_is_valid(flag: Any) -> None:
    payload = _payload()
    if flag != "absent":
        payload["snapshot_g1_required"] = flag
    assert _errors(payload) == []
