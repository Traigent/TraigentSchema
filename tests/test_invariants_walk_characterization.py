"""Characterization tests for the pointer resolver and canonical prevalidation in invariants.

Pins ``_resolve_pointer`` (the value found, or the missing sentinel, for every segment
kind) and ``_prevalidate_canonical`` (acceptance, and the exception type and message for
every rejection: non-canonical types, non-finite floats, depth, cycles and the node
budget). The expected values in tests/data/invariants_walk_characterization.json were
recorded from the implementation before these functions were split into smaller
helpers. The cases reach every branch of both functions.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any

import pytest

from tests._characterization import Case, load_golden, observe
from traigent_schema import invariants

GOLDEN_FILE = "invariants_walk_characterization.json"
TARGET = invariants

MISSING = "<missing sentinel>"


class _Str(str):
    pass


class _EqualsEverything(str):
    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


class _Int(int):
    pass


DOC: dict[Any, Any] = {
    "a": {"b": [10, {"c": "deep"}, [True, None]]},
    "a/b": "slash key",
    "m~n": "tilde key",
    "~1": "literal tilde-one key",
    "": {"": "empty keys"},
    7: "int key",
    "list": list(range(12)),
    "scalar": 5,
    "null": None,
}


def _resolve(payload_factory: Any, pointer: Any) -> Case:
    def run(m: ModuleType) -> Any:
        result = m._resolve_pointer(payload_factory(), pointer)
        return MISSING if result is m._MISSING else result

    return run


def _doc() -> Any:
    return DOC


RESOLVE_CASES: dict[str, Case] = {
    "empty_pointer_returns_root": _resolve(_doc, ""),
    "relative_pointer_rejected": _resolve(_doc, "a/b"),
    "relative_pointer_on_scalar": _resolve(lambda: 3, "x"),
    "member": _resolve(_doc, "/a"),
    "nested_member_index_member": _resolve(_doc, "/a/b/1/c"),
    "escaped_slash_key": _resolve(_doc, "/a~1b"),
    "escaped_tilde_key": _resolve(_doc, "/m~0n"),
    "escaped_tilde_one_literal": _resolve(_doc, "/~01"),
    "empty_segment_key": _resolve(_doc, "//"),
    "missing_member": _resolve(_doc, "/nope"),
    "int_key_not_matched": _resolve(_doc, "/7"),
    "index_zero": _resolve(_doc, "/list/0"),
    "index_eleven": _resolve(_doc, "/list/11"),
    "index_out_of_range": _resolve(_doc, "/list/12"),
    "index_leading_zero": _resolve(_doc, "/list/01"),
    "index_negative": _resolve(_doc, "/list/-1"),
    "index_plus_sign": _resolve(_doc, "/list/+1"),
    "index_decimal": _resolve(_doc, "/list/1.0"),
    "index_dash_append": _resolve(_doc, "/list/-"),
    "index_non_ascii_digit": _resolve(_doc, "/list/١"),
    "index_huge_digits": _resolve(_doc, "/list/" + "9" * 5000),
    "index_on_nested_list": _resolve(_doc, "/a/b/2/0"),
    "through_scalar": _resolve(_doc, "/scalar/x"),
    "through_null": _resolve(_doc, "/null/x"),
    "value_is_null": _resolve(_doc, "/null"),
    "str_subclass_key_skipped": _resolve(lambda: {_Str("k"): 1}, "/k"),
    "eq_override_key_never_compared": _resolve(lambda: {_EqualsEverything("z"): 1}, "/k"),
    "first_plain_key_wins": _resolve(lambda: {_Str("k"): 1, "k": 2}, "/k"),
    "tuple_container_not_followed": _resolve(lambda: {"t": (1, 2)}, "/t/0"),
    "dict_subclass_not_followed": _resolve(lambda: {"d": type("D", (dict,), {})(x=1)}, "/d/x"),
    "list_subclass_not_followed": _resolve(lambda: {"l": type("L", (list,), {})([1])}, "/l/0"),
}


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
    node: list[Any] = []
    node.append([node])
    return node


def _self_dict() -> Any:
    node: dict[str, Any] = {}
    node["k"] = node
    return node


def _dag() -> Any:
    shared = [1, {"x": 2}]
    return {"a": shared, "b": shared, "c": [shared]}


def _wide(width: int) -> Any:
    return list(range(width))


def _prevalidate(value_factory: Any) -> Case:
    return lambda m: m._prevalidate_canonical(value_factory())


NODES = invariants._MAX_COMPARISON_NODES
DEPTH = invariants._MAX_COMPARISON_DEPTH

PREVALIDATE_CASES: dict[str, Case] = {
    "none": _prevalidate(lambda: None),
    "true": _prevalidate(lambda: True),
    "false": _prevalidate(lambda: False),
    "str": _prevalidate(lambda: "s"),
    "int": _prevalidate(lambda: 2**80),
    "float": _prevalidate(lambda: 1.5),
    "float_nan": _prevalidate(lambda: float("nan")),
    "float_inf_nested": _prevalidate(lambda: {"a": [1, float("-inf")]}),
    "int_subclass": _prevalidate(lambda: [_Int(1)]),
    "str_subclass_value": _prevalidate(lambda: {"a": _Str("x")}),
    "tuple": _prevalidate(lambda: (1,)),
    "set_nested": _prevalidate(lambda: [[{1}]]),
    "bytes": _prevalidate(lambda: b""),
    "dict_subclass": _prevalidate(type("D", (dict,), {})),
    "empty_containers": _prevalidate(lambda: {"a": [], "b": {}}),
    "mixed_document": _prevalidate(lambda: DOC | {7: None}),
    "plain_document": _prevalidate(lambda: {"a": [1, 2.5, "x", None, True, {"b": []}]}),
    "int_key": _prevalidate(lambda: {"a": {1: "x"}}),
    "str_subclass_key": _prevalidate(lambda: {_Str("a"): 1}),
    "lists_at_depth_limit": _prevalidate(lambda: _nested_lists(DEPTH)),
    "lists_over_depth_limit": _prevalidate(lambda: _nested_lists(DEPTH + 1)),
    "dicts_at_depth_limit": _prevalidate(lambda: _nested_dicts(DEPTH)),
    "dicts_over_depth_limit": _prevalidate(lambda: _nested_dicts(DEPTH + 1)),
    "scalar_below_depth_limit_container": _prevalidate(lambda: [_nested_lists(DEPTH - 1) + [1]]),
    "self_referencing_list": _prevalidate(_self_list),
    "self_referencing_dict": _prevalidate(_self_dict),
    "dag_shared_child": _prevalidate(_dag),
    "width_at_node_budget": _prevalidate(lambda: _wide(NODES - 1)),
    "width_over_node_budget": _prevalidate(lambda: _wide(NODES)),
    "nested_over_node_budget": _prevalidate(
        lambda: [_wide(NODES // 2), _wide(NODES // 2)]
    ),
    "nested_at_node_budget": _prevalidate(
        lambda: [_wide(NODES // 2 - 1), _wide(NODES // 2 - 2)]
    ),
    "bad_type_after_good_siblings": _prevalidate(lambda: {"a": [1, 2], "b": [3, object()]}),
}

ALL_CASES: dict[str, Case] = {
    **{f"resolve_pointer/{k}": v for k, v in RESOLVE_CASES.items()},
    **{f"prevalidate_canonical/{k}": v for k, v in PREVALIDATE_CASES.items()},
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], invariants) == _golden()[case_id]
