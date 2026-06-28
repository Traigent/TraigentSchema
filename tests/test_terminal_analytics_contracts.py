# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the terminal-first run-analytics DTOs.

Covers the v0 analytics contracts that move optimization-results analysis out of
the web portal and into the terminal (Claude Code skill -> traigent-analytics-mcp
-> backend analytics endpoints):

  * decision_payload_schema      (keystone)
  * decision_payload_response_schema
  * run_pareto_schema
  * run_pareto_response_schema
  * run_correlations_schema
  * run_correlations_response_schema
  * run_leaderboard_schema
  * run_leaderboard_response_schema
  * run_parameter_insights_schema
  * run_parameter_insights_response_schema
  * run_example_insights_schema  (privacy-bounded)
  * run_example_insights_response_schema
  * run_report_response_schema
  * privacy_mode_schema          (shared PrivacyMode enum primitive)

These tests validate the canonical happy-path fixtures, exercise the IP/privacy
allowlist discipline (no proprietary signals leak through these client-safe
contracts), and lock the structural constraints (enums, required fields, closed
objects, canonical ForeignKeyId reuse). They also keep the schema files reachable
for the orphan-schema ratchet in test_schemas.py by referencing each by name.
"""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir, load_schema

# Schema names under test (also documents the reachability surface).
DECISION_PAYLOAD_SCHEMA = "decision_payload_schema"
DECISION_PAYLOAD_RESPONSE_SCHEMA = "decision_payload_response_schema"
RUN_PARETO_SCHEMA = "run_pareto_schema"
RUN_PARETO_RESPONSE_SCHEMA = "run_pareto_response_schema"
RUN_CORRELATIONS_SCHEMA = "run_correlations_schema"
RUN_CORRELATIONS_RESPONSE_SCHEMA = "run_correlations_response_schema"
RUN_LEADERBOARD_SCHEMA = "run_leaderboard_schema"
RUN_LEADERBOARD_RESPONSE_SCHEMA = "run_leaderboard_response_schema"
RUN_PARAMETER_INSIGHTS_SCHEMA = "run_parameter_insights_schema"
RUN_PARAMETER_INSIGHTS_RESPONSE_SCHEMA = "run_parameter_insights_response_schema"
RUN_EXAMPLE_INSIGHTS_SCHEMA = "run_example_insights_schema"
RUN_EXAMPLE_INSIGHTS_RESPONSE_SCHEMA = "run_example_insights_response_schema"
RUN_REPORT_RESPONSE_SCHEMA = "run_report_response_schema"
PRIVACY_MODE_SCHEMA = "privacy_mode_schema"

ALL_CONTRACT_SCHEMAS = [
    DECISION_PAYLOAD_SCHEMA,
    DECISION_PAYLOAD_RESPONSE_SCHEMA,
    RUN_PARETO_SCHEMA,
    RUN_PARETO_RESPONSE_SCHEMA,
    RUN_CORRELATIONS_SCHEMA,
    RUN_CORRELATIONS_RESPONSE_SCHEMA,
    RUN_LEADERBOARD_SCHEMA,
    RUN_LEADERBOARD_RESPONSE_SCHEMA,
    RUN_PARAMETER_INSIGHTS_SCHEMA,
    RUN_PARAMETER_INSIGHTS_RESPONSE_SCHEMA,
    RUN_EXAMPLE_INSIGHTS_SCHEMA,
    RUN_EXAMPLE_INSIGHTS_RESPONSE_SCHEMA,
    RUN_REPORT_RESPONSE_SCHEMA,
]

RESPONSE_CONTRACT_FIXTURES = [
    ("decision_payload_valid.json", DECISION_PAYLOAD_RESPONSE_SCHEMA),
    ("run_pareto_valid.json", RUN_PARETO_RESPONSE_SCHEMA),
    ("run_correlations_valid.json", RUN_CORRELATIONS_RESPONSE_SCHEMA),
    ("run_leaderboard_valid.json", RUN_LEADERBOARD_RESPONSE_SCHEMA),
    ("run_parameter_insights_valid.json", RUN_PARAMETER_INSIGHTS_RESPONSE_SCHEMA),
    ("run_example_insights_valid.json", RUN_EXAMPLE_INSIGHTS_RESPONSE_SCHEMA),
]


@pytest.fixture
def validator() -> SchemaValidator:
    return SchemaValidator()


@pytest.fixture
def data_dir() -> Path:
    return Path(__file__).parent / "test_data" / "analytics"


def _load_fixture(data_dir: Path, name: str) -> dict:
    with open(data_dir / name, encoding="utf-8") as fh:
        return json.load(fh)


def _success_envelope(data: dict) -> dict:
    return {"success": True, "message": "ok", "data": data}


def _load_analytics_endpoints() -> dict:
    with open(get_schemas_dir() / "analytics" / "analytics_endpoints.json", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Discovery / reachability
# ---------------------------------------------------------------------------


class TestDiscovery:
    def test_all_contract_schemas_discovered(self, validator: SchemaValidator) -> None:
        available = validator.available_schemas
        for name in ALL_CONTRACT_SCHEMAS:
            assert name in available, f"{name} not discovered by SchemaValidator"

    def test_privacy_mode_primitive_loadable(self) -> None:
        schema = load_schema(PRIVACY_MODE_SCHEMA)
        privacy_mode = schema["definitions"]["PrivacyMode"]
        assert privacy_mode["enum"] == ["safe_agent_projection", "elevated"]
        assert privacy_mode["default"] == "safe_agent_projection"


# ---------------------------------------------------------------------------
# Happy-path fixtures
# ---------------------------------------------------------------------------


class TestValidFixtures:
    @pytest.mark.parametrize(
        ("fixture", "schema"),
        [
            ("decision_payload_valid.json", DECISION_PAYLOAD_SCHEMA),
            ("run_pareto_valid.json", RUN_PARETO_SCHEMA),
            ("run_correlations_valid.json", RUN_CORRELATIONS_SCHEMA),
            ("run_leaderboard_valid.json", RUN_LEADERBOARD_SCHEMA),
            ("run_parameter_insights_valid.json", RUN_PARAMETER_INSIGHTS_SCHEMA),
            ("run_example_insights_valid.json", RUN_EXAMPLE_INSIGHTS_SCHEMA),
        ],
    )
    def test_valid_fixture_passes(
        self, validator: SchemaValidator, data_dir: Path, fixture: str, schema: str
    ) -> None:
        data = _load_fixture(data_dir, fixture)
        errors = validator.validate_json(data, schema)
        assert errors == [], f"Unexpected errors for {fixture}: {errors}"

    @pytest.mark.parametrize(("fixture", "schema"), RESPONSE_CONTRACT_FIXTURES)
    def test_valid_fixture_passes_inside_success_envelope(
        self, validator: SchemaValidator, data_dir: Path, fixture: str, schema: str
    ) -> None:
        data = _success_envelope(_load_fixture(data_dir, fixture))
        errors = validator.validate_json(data, schema)
        assert errors == [], f"Unexpected response-envelope errors for {fixture}: {errors}"

    def test_run_report_response_wraps_report_payload(self, validator: SchemaValidator) -> None:
        data = _success_envelope(
            {
                "report_id": "report_123",
                "schema_version": "1.0",
                "provenance": {"run_id": "run_123", "data_hash": "sha256:abc"},
            }
        )
        errors = validator.validate_json(data, RUN_REPORT_RESPONSE_SCHEMA)
        assert errors == [], f"Unexpected report response-envelope errors: {errors}"

    def test_bare_decision_payload_fails_response_schema(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        errors = validator.validate_json(data, DECISION_PAYLOAD_RESPONSE_SCHEMA)
        assert errors


class TestAnalyticsEndpoints:
    def test_decision_endpoint_uses_decision_payload_path(self) -> None:
        paths = _load_analytics_endpoints()["paths"]
        assert "/api/v1/analytics/runs/{run_id}/decision" not in paths
        assert "/api/v1/analytics/runs/{run_id}/decision-payload" in paths

    @pytest.mark.parametrize(
        ("path", "stem"),
        [
            (
                "/api/v1/analytics/runs/{run_id}/decision-payload",
                "decision_payload_response_schema.json",
            ),
            ("/api/v1/analytics/runs/{run_id}/report", "run_report_response_schema.json"),
            ("/api/v1/analytics/runs/{run_id}/pareto", "run_pareto_response_schema.json"),
            (
                "/api/v1/analytics/runs/{run_id}/correlations",
                "run_correlations_response_schema.json",
            ),
            (
                "/api/v1/analytics/runs/{run_id}/leaderboard",
                "run_leaderboard_response_schema.json",
            ),
            (
                "/api/v1/analytics/runs/{run_id}/parameter-insights",
                "run_parameter_insights_response_schema.json",
            ),
            (
                "/api/v1/analytics/runs/{run_id}/example-insights",
                "run_example_insights_response_schema.json",
            ),
        ],
    )
    def test_run_analytics_200s_reference_success_envelope_responses(
        self, path: str, stem: str
    ) -> None:
        spec = _load_analytics_endpoints()
        ref = (
            spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"][
                "schema"
            ]["$ref"]
        )
        assert ref.endswith(stem), f"{path}: expected {stem}, got {ref}"


# ---------------------------------------------------------------------------
# decision_payload (keystone)
# ---------------------------------------------------------------------------


class TestDecisionPayload:
    def test_invalid_intent_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        data["intent"] = "ship_it"  # not in enum
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert any("intent" in e or "enum" in e for e in errors)

    def test_invalid_confidence_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        data["confidence"] = "0.97"  # buckets only, no numeric strings
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert any("confidence" in e or "enum" in e for e in errors)

    def test_missing_required_recommended_action_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        del data["recommended_action"]
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert len(errors) > 0

    def test_recommended_action_requires_why(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        del data["recommended_action"]["why"]
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert len(errors) > 0

    def test_additional_properties_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        data["raw_signal"] = 0.873  # proprietary signal must not ride along
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert any("raw_signal" in e or "Additional properties" in e for e in errors)

    def test_empty_evidence_and_warnings_allowed(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        data["evidence"] = []
        data["warnings"] = []
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_sdk_trial_id_accepted_as_run_id(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        # ForeignKeyId reuse: SDK-generated trial_<hex> ids must validate (not format:uuid).
        data = _load_fixture(data_dir, "decision_payload_valid.json")
        data["run_id"] = "trial_deadbeef00"
        errors = validator.validate_json(data, DECISION_PAYLOAD_SCHEMA)
        assert errors == [], f"Unexpected errors: {errors}"


# ---------------------------------------------------------------------------
# run_pareto
# ---------------------------------------------------------------------------


class TestRunPareto:
    def test_invalid_shape_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_pareto_valid.json")
        data["shape"] = "banana"
        errors = validator.validate_json(data, RUN_PARETO_SCHEMA)
        assert any("shape" in e or "enum" in e for e in errors)

    def test_measures_axes_required(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_pareto_valid.json")
        del data["measures"]["latency"]
        errors = validator.validate_json(data, RUN_PARETO_SCHEMA)
        assert len(errors) > 0

    def test_frontier_metric_key_pattern_enforced(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_pareto_valid.json")
        # Non-identifier metric key violates patternProperties + additionalProperties:false.
        data["frontier"][0]["metrics"] = {"9bad-key": 1.0}
        errors = validator.validate_json(data, RUN_PARETO_SCHEMA)
        assert len(errors) > 0

    def test_rank_must_be_positive(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_pareto_valid.json")
        data["frontier"][0]["rank_on_frontier"] = 0
        errors = validator.validate_json(data, RUN_PARETO_SCHEMA)
        assert any("rank_on_frontier" in e or "minimum" in e for e in errors)


# ---------------------------------------------------------------------------
# run_correlations
# ---------------------------------------------------------------------------


class TestRunCorrelations:
    def test_invalid_method_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_correlations_valid.json")
        data["method"] = "kendall"
        errors = validator.validate_json(data, RUN_CORRELATIONS_SCHEMA)
        assert any("method" in e or "enum" in e for e in errors)

    def test_r_out_of_range_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_correlations_valid.json")
        data["measure_correlations"][0]["r"] = 1.5
        errors = validator.validate_json(data, RUN_CORRELATIONS_SCHEMA)
        assert any("maximum" in e or "r" in e for e in errors)

    def test_p_value_out_of_range_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_correlations_valid.json")
        data["measure_correlations"][0]["p_value"] = -0.1
        errors = validator.validate_json(data, RUN_CORRELATIONS_SCHEMA)
        assert any("minimum" in e or "p_value" in e for e in errors)

    def test_invalid_strength_rejected(self, validator: SchemaValidator, data_dir: Path) -> None:
        data = _load_fixture(data_dir, "run_correlations_valid.json")
        data["measure_correlations"][0]["strength"] = "huge"
        errors = validator.validate_json(data, RUN_CORRELATIONS_SCHEMA)
        assert any("strength" in e or "enum" in e for e in errors)


# ---------------------------------------------------------------------------
# run_leaderboard
# ---------------------------------------------------------------------------


class TestRunLeaderboard:
    def test_invalid_recommendation_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_leaderboard_valid.json")
        data["configs"][0]["recommendation"] = "maybe"
        errors = validator.validate_json(data, RUN_LEADERBOARD_SCHEMA)
        assert any("recommendation" in e or "enum" in e for e in errors)

    def test_ranking_basis_required_fields(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_leaderboard_valid.json")
        del data["ranking_basis"]["weights"]
        errors = validator.validate_json(data, RUN_LEADERBOARD_SCHEMA)
        assert len(errors) > 0

    def test_weights_values_must_be_numeric(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_leaderboard_valid.json")
        data["ranking_basis"]["weights"]["accuracy"] = "heavy"
        errors = validator.validate_json(data, RUN_LEADERBOARD_SCHEMA)
        assert len(errors) > 0


# ---------------------------------------------------------------------------
# run_parameter_insights
# ---------------------------------------------------------------------------


class TestRunParameterInsights:
    def test_invalid_suggested_action_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_parameter_insights_valid.json")
        data["drivers"][0]["suggested_action"] = "delete"
        errors = validator.validate_json(data, RUN_PARAMETER_INSIGHTS_SCHEMA)
        assert any("suggested_action" in e or "enum" in e for e in errors)

    def test_confidence_interval_must_be_pair(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_parameter_insights_valid.json")
        data["drivers"][0]["confidence_interval"] = [0.1]  # not a 2-tuple
        errors = validator.validate_json(data, RUN_PARAMETER_INSIGHTS_SCHEMA)
        assert len(errors) > 0

    def test_best_value_accepts_mixed_domains(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        # best_value may be string, number, boolean, or null (parameter domain varies).
        data = _load_fixture(data_dir, "run_parameter_insights_valid.json")
        for value in ("gpt-4o", 7, True, None):
            data["drivers"][0]["best_value"] = value
            errors = validator.validate_json(data, RUN_PARAMETER_INSIGHTS_SCHEMA)
            assert errors == [], f"Unexpected errors for best_value={value!r}: {errors}"

    def test_interaction_parameters_must_be_pair(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_parameter_insights_valid.json")
        data["interactions"][0]["parameters"] = ["model", "few_shot_k", "temperature"]
        errors = validator.validate_json(data, RUN_PARAMETER_INSIGHTS_SCHEMA)
        assert len(errors) > 0


# ---------------------------------------------------------------------------
# run_example_insights (privacy-bounded)
# ---------------------------------------------------------------------------


class TestRunExampleInsights:
    def test_examples_to_review_projection_present(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert errors == [], f"Unexpected errors: {errors}"

        summary = data["summary"]
        for key in (
            "suspicious_example_count",
            "notable_example_count",
            "stable_example_count",
        ):
            assert isinstance(summary[key], int)
            assert summary[key] >= 0

        quality_posture = data["quality_posture"]
        assert quality_posture["summary_text"]
        datetime.fromisoformat(quality_posture["generated_at"].replace("Z", "+00:00"))

        assert 1 <= len(data["example_rows"]) <= 100
        for row in data["example_rows"]:
            assert row["safe_example_ref"].startswith("ex_")
            assert row["review_priority"] in {"critical", "high", "medium", "low"}
            assert row["difficulty_bucket"] in {"low", "medium", "high", "unknown"}
            assert len(row["suspicious_flags"]) == len(set(row["suspicious_flags"]))
            assert row["possible_cause"]
            assert row["recommended_action"]

    def test_privacy_mode_defaults_to_safe_projection(self) -> None:
        # The shared PrivacyMode primitive declares the safe default.
        schema = load_schema(RUN_EXAMPLE_INSIGHTS_SCHEMA)
        ref = schema["properties"]["privacy_mode"]["$ref"]
        assert ref == (
            "https://schemas.traigent.ai/analytics/privacy_mode_schema.json"
            "#/definitions/PrivacyMode"
        )
        primitive = load_schema(PRIVACY_MODE_SCHEMA)
        assert primitive["definitions"]["PrivacyMode"]["default"] == "safe_agent_projection"

    def test_elevated_privacy_mode_accepted(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["privacy_mode"] = "elevated"
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_invalid_privacy_mode_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["privacy_mode"] = "raw"  # not a permitted projection level
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert len(errors) > 0

    def test_invalid_dataset_quality_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["summary"]["dataset_quality"] = 0.42  # bucket only, not numeric
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert any("dataset_quality" in e or "enum" in e for e in errors)

    def test_redactions_required(self, validator: SchemaValidator, data_dir: Path) -> None:
        # The redactions declaration is mandatory: omitted detail must be flagged as
        # redacted, never silently absent.
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        del data["redactions"]
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert len(errors) > 0

    def test_cohort_additional_properties_rejected(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        # A cohort must not smuggle raw signal fields beyond the allowlisted shape.
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["cohorts"][0]["raw_score"] = 0.91
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert any("raw_score" in e or "Additional properties" in e for e in errors)

    @pytest.mark.parametrize(
        ("raw_field", "value"),
        [
            ("composite_score", 0.91),
            ("informativeness", 0.8),
            ("uniqueness", 0.72),
            ("difficulty", 0.63),
            ("exact_rank", 1),
            ("score_metadata", {"source": "internal"}),
        ],
    )
    def test_rejects_raw_signal_fields(
        self, validator: SchemaValidator, data_dir: Path, raw_field: str, value: object
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["example_rows"][0][raw_field] = value
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert any(raw_field in e or "Additional properties" in e for e in errors)

    def test_rejects_unknown_top_level_key(
        self, validator: SchemaValidator, data_dir: Path
    ) -> None:
        data = _load_fixture(data_dir, "run_example_insights_valid.json")
        data["raw_signal_debug"] = {"composite_score": 0.91}
        errors = validator.validate_json(data, RUN_EXAMPLE_INSIGHTS_SCHEMA)
        assert any("raw_signal_debug" in e or "Additional properties" in e for e in errors)
