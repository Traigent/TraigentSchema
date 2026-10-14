"""Characterize existing example-metric behavior before extracting its branches."""

from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
from typing import Any

import pytest

from traigent_schema.analytics_validators import AnalyticsValidator

VALID_ID = "ex_abc12345_0"


@pytest.fixture(scope="module")
def validator() -> AnalyticsValidator:
    return AnalyticsValidator()


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({}, ["Missing required field: example_id", "Missing required field: metrics"]),
        ({"metrics": {}}, ["Missing required field: example_id"]),
        ({"example_id": VALID_ID}, ["Missing required field: metrics"]),
        (
            {"example_id": None, "metrics": None},
            ["example_id must be a string", "metrics must be a dict"],
        ),
        (
            {"example_id": 12, "metrics": []},
            ["example_id must be a string", "metrics must be a dict"],
        ),
        (
            {"example_id": "INVALID", "metrics": {"first": True, "second": "bad"}},
            [
                "Invalid example_id format: INVALID",
                "Metric 'first' must be numeric or null, got bool",
                "Metric 'second' must be numeric or null, got str",
            ],
        ),
        ({"example_id": "", "metrics": {}}, ["Invalid example_id format: "]),
        ({"example_id": VALID_ID, "metrics": {}}, []),
        ({"example_id": VALID_ID, "metrics": {"pending": None}}, []),
        ({"example_id": VALID_ID, "metrics": {"count": 1, "score": -1.25}}, []),
        (
            {
                "example_id": VALID_ID,
                "metrics": {"nan": float("nan"), "inf": float("inf")},
            },
            [],
        ),
        (
            {"example_id": VALID_ID, "metrics": {"negative_inf": float("-inf")}},
            [],
        ),
        (
            {"example_id": VALID_ID, "metrics": {"a": False, "b": True}},
            [
                "Metric 'a' must be numeric or null, got bool",
                "Metric 'b' must be numeric or null, got bool",
            ],
        ),
        (
            {"example_id": VALID_ID, "metrics": {"decimal": Decimal("0.5")}},
            ["Metric 'decimal' must be numeric or null, got Decimal"],
        ),
        (
            {"example_id": VALID_ID, "metrics": {"fraction": Fraction(1, 2)}},
            ["Metric 'fraction' must be numeric or null, got Fraction"],
        ),
        (
            {"example_id": VALID_ID, "metrics": {"nested": {}, "items": []}},
            [
                "Metric 'nested' must be numeric or null, got dict",
                "Metric 'items' must be numeric or null, got list",
            ],
        ),
        ({"example_id": VALID_ID, "metrics": {7: 0.5}, "extra": {"ignored": True}}, []),
        (
            {"example_id": VALID_ID, "metrics": {7: "bad"}},
            ["Metric '7' must be numeric or null, got str"],
        ),
        ({"example_id": "ex_abc12345_0\n", "metrics": {}}, []),
        ({"example_id": "ex_abc12345_١", "metrics": {}}, []),
    ],
)
def test_exact_results_and_payload_unchanged(
    validator: AnalyticsValidator, payload: dict[str, Any], expected: list[str]
) -> None:
    original = deepcopy(payload)
    assert validator.validate_example_metrics(payload) == expected
    # repr also preserves the observed spelling/order of nonfinite floats.
    assert repr(payload) == repr(original)


@pytest.mark.parametrize("count", [49, 50, 51])
def test_metric_limit_and_error_precedence(
    validator: AnalyticsValidator, count: int
) -> None:
    metrics = {f"metric_{index}": "bad" for index in range(count)}
    payload = {"example_id": "bad", "metrics": metrics}
    original = deepcopy(payload)
    expected = ["Invalid example_id format: bad"]
    if count > 50:
        expected.append(f"Too many metrics ({count}): max 50 allowed")
    else:
        expected.extend(
            f"Metric 'metric_{index}' must be numeric or null, got str"
            for index in range(count)
        )
    assert validator.validate_example_metrics(payload) == expected
    assert payload == original


def test_fifty_valid_metrics_are_accepted(validator: AnalyticsValidator) -> None:
    payload = {
        "example_id": VALID_ID,
        "metrics": {str(index): index for index in range(50)},
    }
    original = deepcopy(payload)
    assert validator.validate_example_metrics(payload) == []
    assert payload == original


def test_builtin_subclasses_are_accepted(validator: AnalyticsValidator) -> None:
    class Metrics(dict[str, Any]):
        pass

    class Score(float):
        pass

    class Count(int):
        pass

    payload = {
        "example_id": VALID_ID,
        "metrics": Metrics(score=Score(0.5), count=Count(1)),
    }
    original = deepcopy(payload)
    assert validator.validate_example_metrics(payload) == []
    assert payload == original
    assert isinstance(payload["metrics"], Metrics)


def test_example_id_override_dispatch_and_call_order() -> None:
    class Override(AnalyticsValidator):
        def validate_example_id_format(self, example_id: str) -> bool:
            calls.append(example_id)
            return example_id == "custom-id"

    calls: list[str] = []
    validator = Override()
    assert (
        validator.validate_example_metrics({"example_id": "custom-id", "metrics": {}})
        == []
    )
    assert calls == ["custom-id"]
    assert validator.validate_example_metrics({"example_id": None, "metrics": {}}) == [
        "example_id must be a string"
    ]
    assert validator.validate_example_metrics({"metrics": {}}) == [
        "Missing required field: example_id"
    ]
    assert calls == ["custom-id"]


def test_example_id_override_exception_propagates_without_mutating_payload() -> None:
    failure = RuntimeError("custom identifier failure")

    class Override(AnalyticsValidator):
        def validate_example_id_format(self, example_id: str) -> bool:
            raise failure

    payload = {"example_id": VALID_ID, "metrics": {"invalid": True}}
    original = deepcopy(payload)
    validator = Override()
    with pytest.raises(RuntimeError) as caught:
        validator.validate_example_metrics(payload)
    assert caught.value is failure
    assert payload == original
