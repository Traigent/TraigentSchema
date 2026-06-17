# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract-completeness docs: timing-metric vocabulary (#118), session next-trial
response (#145), and the RBAC privilege vocabulary (#144).

These assert the documented contract metadata/shape, not backend/frontend runtime.
"""

from __future__ import annotations

import json

from jsonschema import Draft7Validator

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _load(rel: str) -> dict:
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# #118 — timing-metric vocabulary
# --------------------------------------------------------------------------- #
def test_timing_metric_vocabulary_is_advisory_and_self_consistent() -> None:
    voc = _load("measures/timing_metric_vocabulary_schema.json")
    Draft7Validator.check_schema(voc)

    assert voc["x-source-of-truth"] == "timing_metric_vocabulary"
    assert voc["x-canonical-unit"] == "millisecond"

    canonical = set(voc["definitions"]["CanonicalTimingMetricName"]["enum"])
    # legacy _s aliases removed after compatibility window; no LegacySecondTimingMetricName
    assert "LegacySecondTimingMetricName" not in voc["definitions"]
    assert "x-legacy-timing-aliases" not in voc
    # the x-* canonical map must exactly cover the canonical enum
    assert set(voc["x-canonical-timing-metrics"]) == canonical

    # decision: function wall-time folds into execution_time_ms (no function_duration_ms)
    pending = voc["x-non-canonical-pending-migration"]
    assert pending["function_duration"]["should_become"] == "execution_time_ms"
    assert pending["model_response_time"]["should_become"] == "response_time_ms"
    assert "function_duration_ms" not in canonical


def test_metric_submission_points_at_timing_vocabulary() -> None:
    """The open MetricResults map carries a non-constraining discoverability pointer."""
    sub = _load("execution/metric_submission_schema.json")
    assert (
        sub["properties"]["metrics"]["x-timing-metric-vocabulary"]
        == "../measures/timing_metric_vocabulary_schema.json"
    )
    # still advisory: MetricResults stays an open patternProperties map (no timing enum)
    assert "enum" not in json.dumps(sub["definitions"]["MetricResults"])


# --------------------------------------------------------------------------- #
# #145 — session next-trial response
# --------------------------------------------------------------------------- #
def test_next_trial_response_schema_validates_both_states() -> None:
    schema = _load("optimization/session_next_trial_response_schema.json")
    Draft7Validator.check_schema(schema)
    v = Draft7Validator(schema)

    with_trial = {
        "has_next": True,
        "trial": {
            "trial_id": "t-1",
            "agent_specification": {
                "agent_platform": "openai",
                "prompt_template": "x",
                "model_parameters": {"model": "gpt-4o", "temperature": 0.7, "max_tokens": 1000},
            },
            "dataset_subset_indices": {"indices": [0, 1, 2], "strategy": "random"},
            "metadata": {},
        },
        "remaining_trials": 8,
        "session_status": "active",
    }
    exhausted = {"has_next": False, "trial": None, "remaining_trials": 0, "session_status": "active"}
    assert list(v.iter_errors(with_trial)) == []
    assert list(v.iter_errors(exhausted)) == []
    # has_next is required
    assert list(v.iter_errors({"trial": None}))


def test_next_trial_endpoint_references_the_response_schema() -> None:
    eps = _load("optimization/optimization_endpoints.json")
    op = eps["paths"]["/api/v1/sessions/{session_id}/next-trial"]["post"]
    ref = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("optimization/session_next_trial_response_schema.json")


# --------------------------------------------------------------------------- #
# #144 — RBAC privilege vocabulary
# --------------------------------------------------------------------------- #
def test_rbac_vocabulary_documents_admin_bypass_surfaces() -> None:
    voc = _load("auth/rbac_privilege_vocabulary_schema.json")
    Draft7Validator.check_schema(voc)

    assert voc["x-source-of-truth"] == "rbac_privilege_vocabulary"
    roles = voc["x-privilege-roles"]
    assert roles["member"]["is_privileged"] is False
    assert roles["admin"]["is_privileged"] is True

    rules = voc["x-scoping-rules"]
    # exactly the three documented relaxations, each admin-only
    assert set(rules) == {"owner_filter", "tenant_scope", "project_membership"}
    for name, rule in rules.items():
        assert rule["admin_bypass"] is True, name
        assert rule["applies_to"] == ["member"], name
    # tenant override is an admin-only header, never trusted for members
    assert rules["tenant_scope"]["admin_override_header"] == "X-Tenant-Id"
