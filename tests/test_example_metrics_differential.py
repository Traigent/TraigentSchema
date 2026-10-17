"""Compare the extracted implementation with its exact pinned original method."""

from copy import deepcopy
from decimal import Decimal
from fractions import Fraction
from hashlib import sha256
from itertools import product
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.analytics_validators import AnalyticsValidator

# This is immutable historical test data, not a second live implementation.
# Verify the bundled reference before executing its exact pinned baseline bytes.
_REFERENCE = Path(__file__).parent / "data" / "example_metrics_e344708.py.txt"
_REFERENCE_BYTES = _REFERENCE.read_bytes()
if sha256(_REFERENCE_BYTES).hexdigest() != (
    "c636c7b380f1b932da1b293838ffe83fabcef97ddd31fb41cbc3076104a7f690"
):
    raise RuntimeError("Historical example metrics reference integrity failure")
_REFERENCE_NAMESPACE: dict[str, Any] = {"__name__": "historical_example_metrics"}
exec(compile(_REFERENCE_BYTES, str(_REFERENCE), "exec"), _REFERENCE_NAMESPACE)
original = _REFERENCE_NAMESPACE["validate_example_metrics"]


def observe(validator: AnalyticsValidator, payload: Any, legacy: bool) -> tuple:
    before = repr(payload)
    try:
        result = (
            original(validator, payload)
            if legacy
            else validator.validate_example_metrics(payload)
        )
        outcome = ("returned", result)
    except Exception as exc:
        outcome = ("raised", type(exc), str(exc))
    return outcome, before, repr(payload)


VALUES = [
    None,
    False,
    True,
    0,
    -1,
    0.25,
    float("nan"),
    float("inf"),
    float("-inf"),
    "bad",
    [],
    {},
    Decimal("0.5"),
    Fraction(1, 2),
]
PAYLOADS = [{}, None, [], "metrics", 1]
PAYLOADS += [
    dict(example_id=identifier, metrics=metrics)
    for identifier, metrics in product(
        [None, 0, "", "invalid", "ex_abc12345_0", "ex_abc12345_0\n", "ex_abc12345_١"],
        [None, [], "bad", {}, *[{"value": value} for value in VALUES]],
    )
]
PAYLOADS += [
    {"example_id": "bad", "metrics": {i: "bad" for i in range(n)}}
    for n in [0, 1, 49, 50, 51, 52]
]
PAYLOADS += [
    {"metrics": {str(i): value for i, value in enumerate(VALUES)}},
    {"example_id": "ex_abc12345_0"},
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_frozen_original_differential(payload: Any) -> None:
    assert observe(AnalyticsValidator(), deepcopy(payload), False) == observe(
        AnalyticsValidator(), deepcopy(payload), True
    )


@pytest.mark.parametrize("mode", ["accept", "reject", "raise"])
def test_subclass_lookup_and_exception_differential(mode: str) -> None:
    class Override(AnalyticsValidator):
        def validate_example_id_format(self, example_id: str) -> bool:
            self.calls.append(example_id)
            if mode == "raise":
                raise LookupError("identifier formatter")
            return mode == "accept"

    validators = [Override(), Override()]
    for validator in validators:
        validator.calls = []
    payload = {"example_id": "custom", "metrics": {"v": True}}
    assert observe(validators[0], deepcopy(payload), False) == observe(
        validators[1], deepcopy(payload), True
    )
    assert validators[0].calls == validators[1].calls


@pytest.mark.parametrize("raise_on", [None, 1, 2, 3, 4, 5, 6])
def test_observable_dict_access_differential(raise_on: int | None) -> None:
    class Observed(dict):
        def __init__(self, *args: Any) -> None:
            super().__init__(*args)
            self.calls = []

        def __contains__(self, key: Any) -> bool:
            self.calls.append(("contains", key))
            return super().__contains__(key)

        def __getitem__(self, key: Any) -> Any:
            self.calls.append(("getitem", key))
            if sum(call[0] == "getitem" for call in self.calls) == raise_on:
                raise RuntimeError("observed access failure")
            return super().__getitem__(key)

    inputs = [
        Observed({"example_id": "bad", "metrics": {"v": False}}) for _ in range(2)
    ]
    assert observe(AnalyticsValidator(), inputs[0], False) == observe(
        AnalyticsValidator(), inputs[1], True
    )
    assert inputs[0].calls == inputs[1].calls


@pytest.mark.parametrize("mode", ["ordinary", "len-raise", "items-raise", "oversize"])
def test_observable_metrics_dictionary_differential(mode: str) -> None:
    class Metrics(dict):
        def __len__(self) -> int:
            calls.append("len")
            if mode == "len-raise":
                raise OverflowError("metric length failure")
            return 51 if mode == "oversize" else super().__len__()

        def items(self) -> Any:
            calls.append("items")
            if mode == "items-raise":
                raise LookupError("metric iteration failure")
            return super().items()

    calls: list[str] = []
    payload = {"example_id": "ex_abc12345_0", "metrics": Metrics(v=True)}
    actual = observe(AnalyticsValidator(), payload, False)
    actual_calls = calls[:]
    calls.clear()
    expected = observe(AnalyticsValidator(), payload, True)
    assert actual == expected
    assert actual_calls == calls
