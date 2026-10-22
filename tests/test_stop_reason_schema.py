# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Closed stop_reason enum shared by the finalize request and response (Traigent#2508)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator

OPT_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas" / "optimization"
STOP_REASON_URL = "https://schemas.traigent.ai/optimization/stop_reason_schema.json"
FINALIZE_PATH = "/api/v1/sessions/00000000-0000-4000-8000-000000000000/finalize"

# Mirror of the SDK StopReason literal (Traigent traigent/api/types.py).
SDK_STOP_REASONS = {
    "max_trials_reached",
    "max_samples_reached",
    "timeout",
    "cost_limit",
    "execution_budget",
    "metric_limit",
    "optimizer",
    "plateau",
    "convergence",
    "semantic_saturation",
    "safety_constraint",
    "safety_constraint_insufficient_evidence",
    "no_usage_captured",
    "user_cancelled",
    "condition",
    "error",
    "vendor_error",
    "network_error",
}


def _load(name: str) -> dict:
    return json.loads((OPT_DIR / name).read_text(encoding="utf-8"))


def test_enum_matches_sdk_set_and_is_closed_enum_class() -> None:
    schema = _load("stop_reason_schema.json")
    assert set(schema["enum"]) == SDK_STOP_REASONS
    assert len(schema["enum"]) == len(set(schema["enum"]))
    assert schema["x-content-class"] == "closed_enum"


def test_request_refs_shared_enum_and_response_stays_open() -> None:
    endpoints = _load("optimization_endpoints.json")
    req = endpoints["paths"]["/api/v1/sessions/{session_id}/finalize"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]["properties"]["stop_reason"]
    resp = _load("session_finalize_response_schema.json")["properties"]["stop_reason"]
    assert req["$ref"] == STOP_REASON_URL
    # Backend still emits its own reasons (finalized, search_complete, ...): stays open.
    assert resp["type"] == ["string", "null"]


@pytest.mark.parametrize("reason", sorted(SDK_STOP_REASONS))
def test_finalize_request_accepts_every_closed_reason(reason: str) -> None:
    errors = SchemaValidator(contract="sdk_tuning").validate_request(
        FINALIZE_PATH, "POST", {"stop_reason": reason}
    )
    assert errors == []


def test_finalize_request_stop_reason_is_optional() -> None:
    assert SchemaValidator(contract="sdk_tuning").validate_request(FINALIZE_PATH, "POST", {}) == []


@pytest.mark.parametrize("bad", ["Alice_has_diabetes", "", "MAX_TRIALS_REACHED", 3])
def test_finalize_request_rejects_non_enum_stop_reason(bad: object) -> None:
    assert SchemaValidator(contract="sdk_tuning").validate_request(
        FINALIZE_PATH, "POST", {"stop_reason": bad}
    )


def test_finalize_response_stop_reason_accepts_backend_reasons_and_null() -> None:
    base = {
        "session_id": "s1",
        "best_config": {"model": "a"},
        "selection_basis": "objective_best",
        "total_trials": 1,
    }
    for ok in ("plateau", "finalized", "search_complete", "smart_prune", None):
        assert (
            SchemaValidator().validate_json(
                {**base, "stop_reason": ok}, "session_finalize_response_schema"
            )
            == []
        )
