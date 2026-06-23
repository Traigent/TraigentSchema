# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the terminal-first run-analytics DTOs.

Covers the v0 analytics contracts that move optimization-results analysis out of
the web portal and into the terminal (Claude Code skill -> traigent-analytics-mcp
-> backend analytics endpoints):

  * decision_payload_schema      (keystone)
  * run_pareto_schema
  * run_correlations_schema
  * run_leaderboard_schema
  * run_parameter_insights_schema
  * run_example_insights_schema  (privacy-bounded)
  * privacy_mode_schema          (shared PrivacyMode enum primitive)

These tests validate the canonical happy-path fixtures, exercise the IP/privacy
allowlist discipline (no proprietary signals leak through these client-safe
contracts), and lock the structural constraints (enums, required fields, closed
objects, canonical ForeignKeyId reuse). They also keep the schema files reachable
for the orphan-schema ratchet in test_schemas.py by referencing each by name.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import load_schema

# Schema names under test (also documents the reachability surface).
DECISION_PAYLOAD_SCHEMA = "decision_payload_schema"
RUN_PARETO_SCHEMA = "run_pareto_schema"
RUN_CORRELATIONS_SCHEMA = "run_correlations_schema"
RUN_LEADERBOARD_SCHEMA = "run_leaderboard_schema"
RUN_PARAMETER_INSIGHTS_SCHEMA = "run_parameter_insights_schema"
RUN_EXAMPLE_INSIGHTS_SCHEMA = "run_example_insights_schema"
PRIVACY_MODE_SCHEMA = "privacy_mode_schema"

ALL_CONTRACT_SCHEMAS = [
    DECISION_PAYLOAD_SCHEMA,
    RUN_PARETO_SCHEMA,
    RUN_CORRELATIONS_SCHEMA,
    RUN_LEADERBOARD_SCHEMA,
    RUN_PARAMETER_INSIGHTS_SCHEMA,
    RUN_EXAMPLE_INSIGHTS_SCHEMA,
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
