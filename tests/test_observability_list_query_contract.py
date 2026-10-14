# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Trace-list and session-list query parameters match what the backend accepts (#550).

The backend reads both list endpoints through one query model (the trace list adds numeric
ranges, a sort choice and content search). The expected sets below are a copy of those model
fields, kept here because this repository cannot import the backend. ``tags`` stays one
comma-separated string, the shape every client sends; its description now says so, and says
that repeated ``tags=`` keys are also accepted.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

SCHEMAS = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas"
OBS = SCHEMAS / "observability"
BASE = "/api/v1beta/projects/{project_id}/observability"
TRACES = f"{BASE}/traces"
SESSIONS = f"{BASE}/sessions"

SHARED_PARAMS = {
    "page",
    "per_page",
    "search",
    "environment",
    "user_id",
    "session_id",
    "status",
    "release",
    "model",
    "tags",
    "start_time_from",
    "start_time_to",
    "outcome_kind",
    "has_outcome",
}
TRACE_ONLY_PARAMS = {
    "min_cost_usd",
    "max_cost_usd",
    "min_tokens",
    "max_tokens",
    "min_latency_ms",
    "max_latency_ms",
    "sort_by",
    "order",
    "q",
}
EXPECTED_PARAMS = {TRACES: SHARED_PARAMS | TRACE_ONLY_PARAMS, SESSIONS: SHARED_PARAMS}


def _load(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _operation(path: str) -> dict:
    return _load(OBS / "observability_endpoints.json")["paths"][path]["get"]


def _params(path: str) -> dict[str, dict]:
    return {p["name"]: p for p in _operation(path)["parameters"] if p.get("in") == "query"}


def _resolve(schema: dict) -> dict:
    """Follow one file-relative ``$ref`` (``../file.json#/definitions/Name``)."""
    ref = schema.get("$ref")
    if ref is None:
        return schema
    file_part, _, pointer = ref.partition("#")
    target = _load((OBS / file_part).resolve())
    for key in pointer.strip("/").split("/"):
        target = target[key]
    return target


@pytest.mark.parametrize("path", [TRACES, SESSIONS])
def test_list_query_parameters_match_the_backend_query_model(path: str) -> None:
    assert set(_params(path)) == EXPECTED_PARAMS[path]


@pytest.mark.parametrize("path", [TRACES, SESSIONS])
def test_tags_is_a_comma_separated_string_with_its_encoding_described(path: str) -> None:
    tags = _params(path)["tags"]
    assert tags["schema"] == {"type": "string", "maxLength": 4096}
    assert "style" not in tags and "explode" not in tags
    validator = Draft7Validator(tags["schema"])
    assert validator.is_valid("vip,beta")
    assert not validator.is_valid(["vip", "beta"])
    description = tags["description"]
    assert "comma-separated" in description
    assert "?tags=vip,beta" in description
    assert "?tags=vip&tags=beta" in description
    assert "not split on commas" in description
    assert "cannot be filtered with the comma form" in description


@pytest.mark.parametrize("path", [TRACES, SESSIONS])
def test_outcome_filters_use_the_canonical_outcome_kind_enum(path: str) -> None:
    params = _params(path)
    kind = params["outcome_kind"]["schema"]
    assert kind == {"$ref": "./session_schema.json#/definitions/ObservabilityOutcomeKind"}
    resolved = _resolve(kind)
    assert resolved["type"] == "string"
    assert resolved["enum"] == ["conversion", "resolution", "csat", "custom"]
    assert params["has_outcome"]["schema"] == {"type": "boolean"}


@pytest.mark.parametrize("path", [TRACES, SESSIONS])
def test_status_filter_uses_the_trace_status_enum(path: str) -> None:
    status = _params(path)["status"]["schema"]
    assert status == {"$ref": "../status_schema.json#/definitions/ObservabilityTraceStatus"}
    assert _resolve(status)["enum"] == ["running", "completed", "failed", "rejected"]


def test_session_list_model_and_session_id_bounds_are_consistent_with_the_trace_list() -> None:
    sessions, traces = _params(SESSIONS), _params(TRACES)
    for name in ("model", "session_id"):
        assert sessions[name]["schema"] == traces[name]["schema"]


def test_trace_list_ranges_sort_and_content_search() -> None:
    params = _params(TRACES)
    assert params["min_cost_usd"]["schema"] == {"type": "number", "minimum": 0}
    assert params["max_cost_usd"]["schema"] == {"type": "number", "minimum": 0}
    for name in ("min_tokens", "max_tokens", "min_latency_ms", "max_latency_ms"):
        assert params[name]["schema"] == {"type": "integer", "minimum": 0}, name
    assert params["sort_by"]["schema"] == {
        "type": "string",
        "enum": ["started_at", "cost", "tokens", "latency"],
        "default": "started_at",
    }
    assert params["order"]["schema"] == {
        "type": "string",
        "enum": ["asc", "desc"],
        "default": "desc",
    }
    assert params["q"]["schema"] == {"type": "string", "maxLength": 200}
