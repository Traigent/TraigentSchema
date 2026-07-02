"""Tests for the GuidancePlan contract schemas.

The GuidancePlan is the opaque guidance primitive: it conveys selection (seed,
action, coarse priority) but must never carry proprietary tuning signals. These
tests assert the happy-path structure, required-field failures, and privacy
guarantees against the Backend/SDK wire shapes that shipped on develop.
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

# Proprietary signal taxonomy must never appear in any client-facing guidance
# schema field or description.
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
    return SchemaValidator(contract="backend")


def _load(name: str) -> dict:
    return json.loads((_TEST_DATA_DIR / name).read_text(encoding="utf-8"))


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
        plan = _load("guidance_plan_valid.json")
        plan["items"] = []
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_result_submission_may_omit_results(self, validator: SchemaValidator) -> None:
        submission = _load("guidance_result_submission_valid.json")
        submission.pop("results")
        errors = validator.validate_json(submission, "guidance_result_submission_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_new_example_ref_matches_backend_regex(self, validator: SchemaValidator) -> None:
        submission = _load("guidance_result_submission_valid.json")
        submission["results"][0]["new_example_refs"] = ["ex_A1-b_2"]
        errors = validator.validate_json(submission, "guidance_result_submission_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_plan_request_accepts_null_budget_fields(self, validator: SchemaValidator) -> None:
        req = _load("guidance_plan_request_valid.json")
        req["budget"] = {
            "max_items": None,
            "max_total_generations": None,
        }
        errors = validator.validate_json(req, "guidance_plan_request_schema")
        assert errors == [], f"Unexpected errors: {errors}"

    def test_plan_request_accepts_null_budget(self, validator: SchemaValidator) -> None:
        req = _load("guidance_plan_request_valid.json")
        req["budget"] = None
        errors = validator.validate_json(req, "guidance_plan_request_schema")
        assert errors == [], f"Unexpected errors: {errors}"


class TestGuidanceRequiredFields:
    @pytest.mark.parametrize(
        ("schema_name", "payload_name", "required_field"),
        [
            ("guidance_plan_request_schema", "guidance_plan_request_valid.json", "plan_kind"),
            ("guidance_plan_schema", "guidance_plan_valid.json", "plan_id"),
            ("guidance_plan_schema", "guidance_plan_valid.json", "plan_budget"),
            ("guidance_result_submission_schema", "guidance_result_submission_valid.json", "plan_id"),
            (
                "guidance_result_submission_schema",
                "guidance_result_submission_valid.json",
                "plan_token",
            ),
        ],
    )
    def test_rejects_required_missing(
        self,
        validator: SchemaValidator,
        schema_name: str,
        payload_name: str,
        required_field: str,
    ) -> None:
        payload = _load(payload_name)
        payload.pop(required_field)
        errors = validator.validate_json(payload, schema_name)
        assert errors, f"{schema_name} must reject missing {required_field}"

    def test_plan_item_rejects_missing_action(self, validator: SchemaValidator) -> None:
        plan = _load("guidance_plan_valid.json")
        plan["items"][0].pop("action")
        errors = validator.validate_json(plan, "guidance_plan_schema")
        assert errors, "plan item must require action"

    def test_result_item_rejects_missing_generated_count(self, validator: SchemaValidator) -> None:
        submission = _load("guidance_result_submission_valid.json")
        submission["results"][0].pop("generated_count")
        errors = validator.validate_json(submission, "guidance_result_submission_schema")
        assert errors, "result item must require generated_count"


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
        plan["items"][0]["coarse_priority"] = "urgent"
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
        assert errors, "result submission must reject content fields"

    def test_new_example_ref_rejects_prompt_text(self, validator: SchemaValidator) -> None:
        sub = _load("guidance_result_submission_valid.json")
        sub["results"][0]["new_example_refs"] = ["write a prompt containing private content"]
        errors = validator.validate_json(sub, "guidance_result_submission_schema")
        assert errors, "new_example_refs must remain deterministic ids, not content"


class TestGuidanceEndpointWiring:
    @staticmethod
    def _responses(path: str) -> dict:
        endpoints = json.loads(
            (_GUIDANCE_DIR / "guidance_endpoints.json").read_text(encoding="utf-8")
        )
        return endpoints["paths"][path]["post"]["responses"]

    def test_backend_contract_validates_guidance_plan_request(self, validator: SchemaValidator) -> None:
        errors = validator.validate_request(
            "/api/v1/sessions/{session_id}/guidance-plan",
            "POST",
            _load("guidance_plan_request_valid.json"),
        )
        assert errors == [], f"Unexpected errors: {errors}"

    @pytest.mark.parametrize(
        "path",
        [
            "/api/v1/sessions/{session_id}/guidance-plan",
            "/api/v1/sessions/{session_id}/guidance-results",
        ],
    )
    def test_feature_gate_and_global_rate_limit_responses_are_documented(self, path: str) -> None:
        responses = self._responses(path)

        assert responses["401"]["description"] == "Authentication required."
        assert responses["403"]["description"] == "Insufficient permissions."
        assert responses["429"]["description"] == "Too many requests \u2014 rate limit exceeded."
        assert responses["501"]["description"] == "Guided generation feature is disabled."

    def test_guidance_results_not_found_and_conflict_responses_match_backend(self) -> None:
        responses = self._responses("/api/v1/sessions/{session_id}/guidance-results")

        assert responses["404"]["description"] == "Session not found for the canonical tenant context."
        assert "plan_token invalid" in responses["409"]["description"]
        assert "does not match the session" in responses["409"]["description"]

    def test_backend_contract_validates_guidance_results_request(
        self, validator: SchemaValidator
    ) -> None:
        errors = validator.validate_request(
            "/api/v1/sessions/{session_id}/guidance-results",
            "POST",
            _load("guidance_result_submission_valid.json"),
        )
        assert errors == [], f"Unexpected errors: {errors}"


class TestGuidanceTaxonomyCanary:
    """No guidance schema text may disclose the proprietary signal taxonomy."""

    def test_no_signal_terms_in_guidance_schemas(self) -> None:
        leaked: dict[str, list[str]] = {}
        for path in sorted(_GUIDANCE_DIR.glob("*.json")):
            text = path.read_text(encoding="utf-8").lower()
            hits = [term for term in _FORBIDDEN_SIGNAL_TERMS if term in text]
            if hits:
                leaked[path.name] = hits
        assert not leaked, f"signal taxonomy term(s) leaked into guidance schemas: {leaked}"
