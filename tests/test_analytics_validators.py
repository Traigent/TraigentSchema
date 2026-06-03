"""Focused tests for analytics validators and schema utility helpers."""

from __future__ import annotations

import pytest

from traigent_schema.analytics_validators import AnalyticsValidator
from traigent_schema.utils import (
    get_all_schema_files,
    get_contract_path,
    get_openapi_path,
    get_schema_path,
    get_schemas_dir,
    load_schema,
)


class TestAnalyticsValidatorHelpers:
    @pytest.fixture
    def validator(self) -> AnalyticsValidator:
        return AnalyticsValidator()

    def test_validate_example_score_delegates_to_schema_validator(
        self, validator: AnalyticsValidator
    ) -> None:
        payload = {
            "example_id": "ex_a3f4b2c8d1_0",
            "experiment_run_id": "run_123",
            "algorithm_version": "1.0.0",
            "composite_score": 0.9,
        }

        assert validator.validate_example_score(payload) == []

        invalid_payload = {**payload, "example_id": "EX_a3f4b2c8d1_0"}
        assert validator.validate_example_score(invalid_payload)

    def test_validate_dataset_quality_delegates_to_schema_validator(
        self, validator: AnalyticsValidator
    ) -> None:
        payload = {
            "experiment_run_id": "run_123",
            "dataset_quality": 0.82,
            "algorithm_version": "1.0.0",
            "recommendations": [],
        }

        assert validator.validate_dataset_quality(payload) == []

        invalid_payload = {**payload, "dataset_quality": 1.1}
        assert validator.validate_dataset_quality(invalid_payload)

    def test_validate_scoring_job_status_delegates_to_schema_validator(
        self, validator: AnalyticsValidator
    ) -> None:
        payload = {
            "job_id": "score_dataset_eval_1705320600",
            "status": "completed",
            "result": {
                "experiment_run_id": "run_123",
                "num_examples": 12,
                "dataset_quality": 0.91,
                "algorithm_version": "1.0.0",
            },
        }

        assert validator.validate_scoring_job_status(payload) == []

        invalid_payload = {key: value for key, value in payload.items() if key != "result"}
        assert validator.validate_scoring_job_status(invalid_payload)

    @pytest.mark.parametrize(
        ("example_id", "expected"),
        [
            ("ex_a3f4b2c8_0", True),
            ("ex_abcdef123456_99", True),
            ("ex_ABCDEF12_0", False),
            ("example_abcdef12_0", False),
        ],
    )
    def test_validate_example_id_format(
        self, validator: AnalyticsValidator, example_id: str, expected: bool
    ) -> None:
        assert validator.validate_example_id_format(example_id) is expected

    @pytest.mark.parametrize(
        ("job_id", "expected"),
        [
            ("score_run_abc123_1705320600", True),
            ("score-demo_job_1", False),
            ("invalid_job", False),
        ],
    )
    def test_validate_job_id_format(
        self, validator: AnalyticsValidator, job_id: str, expected: bool
    ) -> None:
        assert validator.validate_job_id_format(job_id) is expected

    @pytest.mark.parametrize(
        ("score", "expected"),
        [(0.0, True), (0.5, True), (1.0, True), (-0.1, False), (1.1, False)],
    )
    def test_validate_score_range(
        self, validator: AnalyticsValidator, score: float, expected: bool
    ) -> None:
        assert validator.validate_score_range(score) is expected

    @pytest.mark.parametrize(
        ("version", "expected"),
        [("1.0.0", True), ("2.10.3", True), ("v1.0.0", False), ("1.0", False)],
    )
    def test_validate_algorithm_version(
        self, validator: AnalyticsValidator, version: str, expected: bool
    ) -> None:
        assert validator.validate_algorithm_version(version) is expected

    @pytest.mark.parametrize(
        ("recommendation_type", "expected"),
        [("info", True), ("warning", True), ("critical", True), ("debug", False)],
    )
    def test_validate_recommendation_type(
        self,
        validator: AnalyticsValidator,
        recommendation_type: str,
        expected: bool,
    ) -> None:
        assert validator.validate_recommendation_type(recommendation_type) is expected

    @pytest.mark.parametrize(
        ("action", "expected"),
        [
            ("remove", True),
            ("add_similar", True),
            ("review", True),
            (None, True),
            ("notify", False),
        ],
    )
    def test_validate_recommendation_action(
        self, validator: AnalyticsValidator, action: str | None, expected: bool
    ) -> None:
        assert validator.validate_recommendation_action(action) is expected

    def test_available_schemas_lists_expected_contracts(
        self, validator: AnalyticsValidator
    ) -> None:
        assert validator.available_schemas == [
            "example_score_schema",
            "dataset_quality_schema",
            "scoring_job_status_schema",
        ]


class TestSchemaUtils:
    def test_get_schemas_dir_points_to_real_directory(self) -> None:
        schemas_dir = get_schemas_dir()
        assert schemas_dir.exists()
        assert schemas_dir.is_dir()

    def test_get_schema_path_supports_direct_lookup(self) -> None:
        path = get_schema_path("project_schema")
        assert path.name == "project_schema.json"
        assert path.parent.name == "projects"

    def test_get_schema_path_finds_file_in_subdirectories(self) -> None:
        path = get_schema_path("project_scoped_analytics_summary_schema")
        assert path.name == "project_scoped_analytics_summary_schema.json"
        assert path.parent.name == "projects"

    def test_get_schema_path_tries_schema_suffix(self) -> None:
        path = get_schema_path("agent")
        assert path.name == "agent_schema.json"
        assert path.parent.name == "agents"

    def test_get_schema_path_raises_for_missing_schema(self) -> None:
        with pytest.raises(FileNotFoundError):
            get_schema_path("definitely_missing_schema_name")

    def test_get_all_schema_files_returns_json_paths(self) -> None:
        files = get_all_schema_files()
        assert files
        assert all(path.suffix == ".json" for path in files)

    def test_get_openapi_path_points_to_endpoint_catalog(self) -> None:
        path = get_openapi_path()
        assert path.name == "mep_endpoints.json"
        assert path.exists()

    def test_get_contract_path_points_to_additional_contract_catalogs(self) -> None:
        sdk_path = get_contract_path("sdk_tuning")
        planned_path = get_contract_path("planned_projects")
        assert sdk_path.name == "sdk_tuning_endpoints.json"
        assert planned_path.name == "planned_projects_endpoints.json"
        assert sdk_path.exists()
        assert planned_path.exists()

    def test_load_schema_returns_dict(self) -> None:
        schema = load_schema("project_schema")
        assert isinstance(schema, dict)
        assert schema.get("title") == "Project Schema"

    def test_load_dataset_schema_returns_canonical_dataset_contract(self) -> None:
        schema = load_schema("dataset_schema")
        assert isinstance(schema, dict)
        assert schema.get("title") == "Dataset Schema"
