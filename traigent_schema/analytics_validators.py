"""Validation utilities for analytics schemas.

Provides helper functions and a validator class for validating
example scores, dataset quality, and scoring job status data
against their respective JSON schemas.
"""

import re
from typing import Any

from traigent_schema.validator import SchemaValidator


class AnalyticsValidator:
    """Validator for analytics-related schemas.

    Provides convenience methods for validating ExampleScore, DatasetQuality,
    and ScoringJobStatus data against their JSON schemas.

    Example:
        validator = AnalyticsValidator()
        errors = validator.validate_example_score(score_data)
        if not errors:
            print("Score data is valid")
    """

    # Pre-compiled regex patterns for validation
    _EXAMPLE_ID_PATTERN = re.compile(r'^ex_[a-f0-9]{8,12}_\d+$')
    _JOB_ID_PATTERN = re.compile(r'^score_[a-zA-Z0-9_-]+_\d+$')
    _ALGORITHM_VERSION_PATTERN = re.compile(r'^\d+\.\d+\.\d+$')

    def __init__(self) -> None:
        """Initialize the validator with schema validator."""
        self._validator = SchemaValidator()

    def validate_example_score(self, score_data: dict[str, Any]) -> list[str]:
        """Validate ExampleScore data against schema.

        Args:
            score_data: Dictionary containing example score data

        Returns:
            List of validation error messages. Empty if valid.
        """
        return self._validator.validate_json(
            score_data,
            "example_score_schema"
        )

    def validate_dataset_quality(self, quality_data: dict[str, Any]) -> list[str]:
        """Validate DatasetQuality data against schema.

        Args:
            quality_data: Dictionary containing dataset quality data

        Returns:
            List of validation error messages. Empty if valid.
        """
        return self._validator.validate_json(
            quality_data,
            "dataset_quality_schema"
        )

    def validate_scoring_job_status(self, status_data: dict[str, Any]) -> list[str]:
        """Validate ScoringJobStatus data against schema.

        Args:
            status_data: Dictionary containing job status data

        Returns:
            List of validation error messages. Empty if valid.
        """
        return self._validator.validate_json(
            status_data,
            "scoring_job_status_schema"
        )

    def validate_example_metrics(self, data: dict[str, Any]) -> list[str]:
        """Validate ExampleMetrics structure (nested example format).

        Validates the nested structure used for per-example metrics where
        example_id is separated from the numeric metrics.

        Args:
            data: Dictionary containing example metrics data with structure:
                  {"example_id": "ex_...", "metrics": {"score": 0.85, ...}}

        Returns:
            List of validation error messages. Empty if valid.

        Example:
            >>> validator.validate_example_metrics({
            ...     "example_id": "ex_abc12345_0",
            ...     "metrics": {"score": 0.85, "cost": 0.05}
            ... })
            []
        """
        errors = []

        # Check required field: example_id
        if "example_id" not in data:
            errors.append("Missing required field: example_id")
        elif not isinstance(data["example_id"], str):
            errors.append("example_id must be a string")
        elif not self.validate_example_id_format(data["example_id"]):
            errors.append(f"Invalid example_id format: {data['example_id']}")

        # Check required field: metrics
        if "metrics" not in data:
            errors.append("Missing required field: metrics")
        elif not isinstance(data["metrics"], dict):
            errors.append("metrics must be a dict")
        elif len(data["metrics"]) > 50:
            errors.append(f"Too many metrics ({len(data['metrics'])}): max 50 allowed")
        else:
            # Validate each metric value is numeric or null
            for key, value in data["metrics"].items():
                if value is not None and not isinstance(value, (int, float)):
                    errors.append(f"Metric '{key}' must be numeric or null, got {type(value).__name__}")

        return errors

    def validate_example_id_format(self, example_id: str) -> bool:
        """Validate example ID follows the required pattern.

        The pattern is: ex_{hash}_{index} where hash is 8-12 hex characters
        and index is a non-negative integer.

        Args:
            example_id: Example ID string to validate

        Returns:
            True if valid format, False otherwise

        Example:
            >>> validator.validate_example_id_format("ex_abc12345_0")
            True
            >>> validator.validate_example_id_format("invalid")
            False
        """
        return bool(self._EXAMPLE_ID_PATTERN.match(example_id))

    def validate_job_id_format(self, job_id: str) -> bool:
        """Validate job ID follows the required pattern.

        The pattern is: score_{identifier}_{timestamp} where identifier
        can contain alphanumeric characters, underscores, and hyphens.

        Args:
            job_id: Job ID string to validate

        Returns:
            True if valid format, False otherwise

        Example:
            >>> validator.validate_job_id_format("score_exp_run_abc123_1705320600")
            True
            >>> validator.validate_job_id_format("invalid_job")
            False
        """
        return bool(self._JOB_ID_PATTERN.match(job_id))

    def validate_score_range(self, score: float) -> bool:
        """Validate score is in valid range [0, 1].

        Args:
            score: Score value to validate

        Returns:
            True if in range [0, 1], False otherwise
        """
        return 0.0 <= score <= 1.0

    def validate_algorithm_version(self, version: str) -> bool:
        """Validate algorithm version follows semver pattern.

        Args:
            version: Version string (e.g., '1.0.0')

        Returns:
            True if valid semver (MAJOR.MINOR.PATCH), False otherwise

        Example:
            >>> validator.validate_algorithm_version("1.0.0")
            True
            >>> validator.validate_algorithm_version("v1.0.0")
            False
        """
        return bool(self._ALGORITHM_VERSION_PATTERN.match(version))

    def validate_recommendation_type(self, rec_type: str) -> bool:
        """Validate recommendation type is valid.

        Args:
            rec_type: Recommendation type string

        Returns:
            True if valid type (info, warning, critical), False otherwise
        """
        return rec_type in ("info", "warning", "critical")

    def validate_recommendation_action(self, action: str | None) -> bool:
        """Validate recommendation action is valid.

        Args:
            action: Action string or None

        Returns:
            True if valid action (remove, add_similar, review, None), False otherwise
        """
        return action in ("remove", "add_similar", "review", None)

    @property
    def available_schemas(self) -> list[str]:
        """Get list of analytics schema names."""
        return [
            "example_score_schema",
            "dataset_quality_schema",
            "scoring_job_status_schema",
        ]
