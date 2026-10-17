"""Characterization tests for the iterative encoder ``fp2._encode``.

Pins the canonical text returned for every admissible value kind, member ordering, depth
and cycle handling, and the exception type and message for every rejected value. The
expected values in tests/data/fp2_encode_characterization.json were recorded from the
implementation before the encoder loop was split into smaller helpers. The cases reach
every branch of ``_encode``.
"""

from __future__ import annotations

import enum
from typing import Any

import pytest

from tests._characterization import Case, load_golden, observe
from traigent_schema import fp2

GOLDEN_FILE = "fp2_encode_characterization.json"
TARGET = fp2


class _Str(str):
    pass


class _Int(int):
    pass


class _Float(float):
    pass


class _List(list):
    pass


class _Dict(dict):
    pass


class _Color(enum.IntEnum):
    RED = 1


class _Marker:
    pass


def _nested_lists(depth: int) -> Any:
    node: Any = []
    for _ in range(depth - 1):
        node = [node]
    return node


def _nested_dicts(depth: int) -> Any:
    node: Any = {}
    for _ in range(depth - 1):
        node = {"k": node}
    return node


def _self_list() -> Any:
    node: list[Any] = [1]
    node.append(node)
    return node


def _self_dict() -> Any:
    node: dict[str, Any] = {"a": 1}
    node["self"] = {"inner": [node]}
    return node


def _dag() -> Any:
    shared = {"x": [1, 2]}
    return {"a": shared, "b": [shared, shared]}


def _enc(value_factory: Any) -> Case:
    return lambda m: m._encode(value_factory())


VALUES: dict[str, Any] = {
    "none": lambda: None,
    "true": lambda: True,
    "false": lambda: False,
    "zero": lambda: 0,
    "negative_int": lambda: -42,
    "max_safe_int": lambda: 2**53 - 1,
    "min_safe_int": lambda: -(2**53 - 1),
    "unsafe_int": lambda: 2**53,
    "unsafe_negative_int": lambda: -(2**53),
    "float_zero": lambda: 0.0,
    "float_negative_zero": lambda: -0.0,
    "float_fraction": lambda: 1.5,
    "float_large": lambda: 1e21,
    "float_small": lambda: 1e-7,
    "float_integral": lambda: 3.0,
    "float_nan": lambda: float("nan"),
    "float_inf": lambda: float("inf"),
    "string_plain": lambda: "hello",
    "string_escapes": lambda: 'q"\\\n\t\x01\x7f',
    "string_unicode": lambda: "café \U0001f600  ",
    "string_lone_surrogate": lambda: "\ud800",
    "empty_list": lambda: [],
    "empty_dict": lambda: {},
    "list_mixed": lambda: [1, "a", None, True, 2.5, [], {}],
    "dict_sorted_members": lambda: {"b": 1, "a": 2, "A": 3, "": 4},
    "dict_utf16_order": lambda: {"￿": 1, "\U0001f600": 2, "z": 3},
    "nested_mixed": lambda: {"list": [{"y": [1, {"z": None}]}, "s"], "n": {"m": {}}},
    "dag_shared_child": _dag,
    "lists_at_depth_limit": lambda: _nested_lists(fp2.MAX_DEPTH),
    "lists_over_depth_limit": lambda: _nested_lists(fp2.MAX_DEPTH + 1),
    "dicts_at_depth_limit": lambda: _nested_dicts(fp2.MAX_DEPTH),
    "dicts_over_depth_limit": lambda: _nested_dicts(fp2.MAX_DEPTH + 1),
    "self_referencing_list": _self_list,
    "self_referencing_dict": _self_dict,
    "int_key": lambda: {1: "a"},
    "str_subclass_key": lambda: {_Str("a"): 1},
    "str_subclass_value": lambda: ["ok", _Str("a")],
    "int_subclass_value": lambda: [_Int(1)],
    "int_enum_value": lambda: {"c": _Color.RED},
    "float_subclass_value": lambda: [_Float(1.0)],
    "list_subclass_value": lambda: [_List([1])],
    "dict_subclass_root": lambda: _Dict(a=1),
    "tuple_value": lambda: (1, 2),
    "set_value": lambda: [{1}],
    "bytes_value": lambda: {"b": b"x"},
    "object_value": lambda: [object.__new__(_Marker)],
    "bad_value_after_good_members": lambda: {"a": [1, 2], "b": [3, (4,)]},
    "bad_key_after_good_members": lambda: {"a": 1, "b": {"c": 1, 2: 3}},
    "unsafe_int_nested": lambda: {"a": [[2**60]]},
}


ALL_CASES: dict[str, Case] = {f"encode/{k}": _enc(v) for k, v in VALUES.items()}
ALL_CASES.update(
    {
        "canonicalize/unhashable_foreign": lambda m: m.canonicalize([1, _Marker()]),
        "canonicalize/mixed": lambda m: m.canonicalize({"z": [1.25, "x"], "a": None}),
    }
)


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], fp2) == _golden()[case_id]
