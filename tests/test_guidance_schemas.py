"""Tests for the GuidancePlan contract schemas.

The GuidancePlan is the opaque guidance primitive: it conveys selection (seed,
action, coarse priority) but must never carry proprietary tuning signals. These
tests assert both the happy-path structure and the privacy guarantees:

* ``additionalProperties: false`` everywhere structurally blocks any smuggled
  signal field (e.g. ``informativeness``) or numeric ``score``.
* plan items carry NO per-seed count (a per-seed count is a leakage channel).
* result submissions are content-free (no prompt text / example content).
* no schema text discloses the proprietary signal taxonomy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator

_GUIDANCE_DIR = (
    Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas" / "guidance"
)
_TEST_DATA_DIR = Path(__file__).parent / "test_data" / "guidance"

# Proprietary signal taxonomy — must never appear in any client-facing guidance
# schema (field name or description). Mirrors the SDK/backend redaction denylist.
_FORBIDDEN_SIGNAL_TERMS = [
    "informativeness",
    "statistical_uniqueness",
    "discriminative_power",
    "content_uniqueness",
    "content_novelty",
    "cost_efficiency",
    "error_sensitivity",
    "predictive_value",
    "composite_score",
    "difficulty",
    "ambiguity",
    "consistency",
]


@pytest.fixture
def validator() -> SchemaValidator:
    return SchemaValidator()


def _load(name: str) -> dict:
    return json.loads((_TEST_DATA_DIR / name).read_text())


class TestGuidanceHappyPath:
    def test_valid_plan(self, validator: SchemaValidator) -> None:
        errors = validator.validate_json(_load("guidance_plan_valid.json"), "guidance_plan_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_plan_request(self, validator: SchemaValidator) -> None:
        errors = validator.validate_json(
            _load("guidance_plan_request_valid.json"), "guidance_plan_request_schema"
        )
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_result_submission(self, validator: SchemaValidator) -> None:
        errors = validator.validate_json(
            _load("guidance_result_submission_valid.json"), "guidance_result_submission_schema"
        )
        assert errors == [], f"Unexpected errors: {errors}"

    def test_empty_items_plan_is_valid(self, validator: SchemaValidator) -> None:
        """A degenerate/too-small run yields an empty plan, not an isolated signal."""
        plan = _load("guidance_plan_valid.json")
        plan["items"] = []
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors == [], f"Unexpected errors: {errors}"


class TestGuidancePrivacyStructure:
    def test_plan_rejects_smuggled_signal_field(self, validator: SchemaValidator) -> None:
        plan = _load("guidance_plan_valid.json")
        plan["informativeness"] = 0.87
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "additionalProperties:false must reject a smuggled signal field on the plan"

    def test_plan_item_rejects_numeric_score(self, validator: SchemaValidator) -> None:
        plan = _load("guidance_plan_valid.json")
        plan["items"][0]["score"] = 0.91
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "plan items must not accept a numeric score field"

    def test_plan_item_rejects_per_seed_count(self, validator: SchemaValidator) -> None:
        """A per-seed count is a near-continuous leakage channel; it must not exist."""
        plan = _load("guidance_plan_valid.json")
        plan["items"][0]["target_count"] = 7
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "plan items must not accept a per-seed target_count"

    def test_plan_item_rejects_unknown_action(self, validator: SchemaValidator) -> None:
        plan = _load("guidance_plan_valid.json")
        plan["items"][0]["action"] = "reveal_difficulty"
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "action enum must reject unknown verbs"

    def test_plan_item_rejects_unknown_priority(self, validator: SchemaValidator) -> None:
        plan = _load("guidance_plan_valid.json")
        plan["items"][0]["coarse_priority"] = 0.42
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "coarse_priority must be one of the three ordinal buckets"

    def test_request_rejects_unknown_field(self, validator: SchemaValidator) -> None:
        req = _load("guidance_plan_request_valid.json")
        req["min_difficulty"] = 0.5
        errors = validator.validate_json(req, "guidance_plan_request_schema")
        assert errors, "request must not let the client ask for a specific signal threshold"

    def test_result_submission_is_content_free(self, validator: SchemaValidator) -> None:
        sub = _load("guidance_result_submission_valid.json")
        sub["results"][0]["content"] = "the synthesized example text"
        errors = validator.validate_json(sub, "guidance_result_submission_schema")
        assert errors, "result submission must reject content fields (content-free contract)"


class TestGuidanceTaxonomyCanary:
    """No guidance schema text may disclose the proprietary signal taxonomy."""

    def test_no_signal_terms_in_guidance_schemas(self) -> None:
        leaked: dict[str, list[str]] = {}
        for path in sorted(_GUIDANCE_DIR.glob("*.json")):
            text = path.read_text().lower()
            hits = [term for term in _FORBIDDEN_SIGNAL_TERMS if term in text]
            if hits:
                leaked[path.name] = hits
        assert not leaked, f"signal taxonomy term(s) leaked into guidance schemas: {leaked}"
