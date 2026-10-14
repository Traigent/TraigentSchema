# Exact method from e344708 analytics_validators.py.
# Full original source SHA256: d399caa52ae9d5bd8dc218a24c5898d92788d1f710c02067da38712ac9a17399
from typing import Any


class FrozenOriginal:
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
                if value is not None and (
                    isinstance(value, bool) or not isinstance(value, (int, float))
                ):
                    errors.append(
                        f"Metric '{key}' must be numeric or null, got {type(value).__name__}"
                    )

        return errors


validate_example_metrics = FrozenOriginal.validate_example_metrics
