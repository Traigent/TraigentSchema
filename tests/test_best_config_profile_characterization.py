"""Characterization tests for the contract loader and prevalidation in best_config_profile.

Pins ``_load_contract`` (the constants derived from the packaged contract, and the
exception message for each way the contract file can be missing or malformed) and
``_prevalidate`` (acceptance, and the exception type and positional location message
for every rejection). The expected values in
tests/data/best_config_profile_characterization.json were recorded from the
implementation before these functions were split into smaller helpers. The cases reach
every branch of both functions.
"""

from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests._characterization import Case, load_golden, observe
from traigent_schema import best_config_profile
from traigent_schema.utils import get_schemas_dir

GOLDEN_FILE = "best_config_profile_characterization.json"
TARGET = best_config_profile

CONTRACT_FILENAME = "best_config_hash_contract_schema.json"
REAL_CONTRACT = json.loads(
    (get_schemas_dir() / "optimization" / CONTRACT_FILENAME).read_text(encoding="utf-8")
)
TMP_TOKEN = "<tmp>"


def _contract_case(text: str | bytes | None) -> Case:
    """Run ``_load_contract`` against a temporary schemas dir holding ``text``.

    ``None`` leaves the contract file absent. The temporary directory path is replaced by
    a fixed token in any raised message so the recorded output does not depend on it.
    """

    def run(m: ModuleType) -> Any:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "optimization").mkdir()
            target = root / "optimization" / CONTRACT_FILENAME
            if isinstance(text, bytes):
                target.write_bytes(text)
            elif text is not None:
                target.write_text(text, encoding="utf-8")
            original = m.get_schemas_dir
            m.get_schemas_dir = lambda: root
            try:
                return m._load_contract()
            except m.BestConfigProfileError as exc:
                raise type(exc)(str(exc).replace(tmp, TMP_TOKEN)) from None
            finally:
                m.get_schemas_dir = original

    return run


def _edited(edit: Any) -> str:
    contract = copy.deepcopy(REAL_CONTRACT)
    edit(contract)
    return json.dumps(contract)


def _set_canon(field: str, value: Any) -> Any:
    def edit(c: dict[str, Any]) -> None:
        c["definitions"]["canonicalization"]["properties"][field]["const"] = value

    return edit


def _set_tags(value: Any) -> Any:
    def edit(c: dict[str, Any]) -> None:
        c["definitions"]["domain_tag"]["enum"] = value

    return edit


def _drop(*path: str) -> Any:
    def edit(c: dict[str, Any]) -> None:
        node = c
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]

    return edit


CONTRACT_CASES: dict[str, Case] = {
    "packaged_contract": lambda m: m._load_contract(),
    "real_contract_copy": _contract_case(json.dumps(REAL_CONTRACT)),
    "file_missing": _contract_case(None),
    "not_json": _contract_case("{not json"),
    "not_utf8": _contract_case(b"\xff{}"),
    "no_definitions": _contract_case(_edited(_drop("definitions"))),
    "definitions_is_list": _contract_case(
        _edited(lambda c: c.__setitem__("definitions", ["canonicalization"]))
    ),
    "no_max_bytes_const": _contract_case(
        _edited(
            _drop(
                "definitions",
                "canonicalization",
                "properties",
                "max_canonical_spec_bytes",
                "const",
            )
        )
    ),
    "no_max_depth": _contract_case(
        _edited(_drop("definitions", "canonicalization", "properties", "max_depth"))
    ),
    "no_domain_tag": _contract_case(_edited(_drop("definitions", "domain_tag"))),
    "max_bytes_bool": _contract_case(_edited(_set_canon("max_canonical_spec_bytes", True))),
    "max_bytes_zero": _contract_case(_edited(_set_canon("max_canonical_spec_bytes", 0))),
    "max_bytes_str": _contract_case(_edited(_set_canon("max_canonical_spec_bytes", "10"))),
    "max_bytes_float": _contract_case(_edited(_set_canon("max_canonical_spec_bytes", 10.0))),
    "max_depth_bool": _contract_case(_edited(_set_canon("max_depth", True))),
    "max_depth_negative": _contract_case(_edited(_set_canon("max_depth", -1))),
    "max_depth_null": _contract_case(_edited(_set_canon("max_depth", None))),
    "max_depth_other_value": _contract_case(_edited(_set_canon("max_depth", 7))),
    "tags_not_list": _contract_case(_edited(_set_tags("traigent.best_config.config.v1"))),
    "tags_non_string": _contract_case(_edited(_set_tags(["a.config.v1", 3]))),
    "tags_empty": _contract_case(_edited(_set_tags([]))),
    "tags_no_spec": _contract_case(_edited(_set_tags(["a.config.v1"]))),
    "tags_two_config": _contract_case(
        _edited(_set_tags(["a.config.v1", "b.config.v1", "a.spec.v1"]))
    ),
    "tags_two_spec": _contract_case(_edited(_set_tags(["a.config.v1", "a.spec.v1", "b.spec.v1"]))),
    "tags_with_extra": _contract_case(
        _edited(_set_tags(["x.other", "a.spec.v1", "a.config.v1"]))
    ),
}


class _Str(str):
    pass


class _Int(int):
    pass


class _Float(float):
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
    node: list[Any] = [0]
    node.append({"x": node})
    return node


def _dag() -> Any:
    shared = {"x": [1]}
    return [shared, {"y": shared}]


def _pre(value_factory: Any) -> Case:
    return lambda m: m._prevalidate(value_factory())


MAX_DEPTH = best_config_profile.MAX_DEPTH
SAFE = 2**53 - 1

PREVALIDATE_CASES: dict[str, Case] = {
    "none": _pre(lambda: None),
    "true": _pre(lambda: True),
    "str": _pre(lambda: "s"),
    "int_safe": _pre(lambda: SAFE),
    "int_unsafe": _pre(lambda: SAFE + 1),
    "int_unsafe_negative": _pre(lambda: [-(SAFE + 1)]),
    "float_fraction_large": _pre(lambda: 1e300 + 0.5),
    "float_integral_safe": _pre(lambda: 2.0**52),
    "float_integral_unsafe": _pre(lambda: {"a": [1, 2.0**60]}),
    "float_nan": _pre(lambda: float("nan")),
    "float_inf": _pre(lambda: [float("inf")]),
    "int_subclass": _pre(lambda: {"a": _Int(1)}),
    "float_subclass": _pre(lambda: [_Float(1.0)]),
    "str_subclass_value": _pre(lambda: [0, [1, _Str("x")]]),
    "tuple": _pre(lambda: {"a": (1,)}),
    "bytes_root": _pre(lambda: b"x"),
    "empty_containers": _pre(lambda: {"a": [], "b": {}}),
    "document": _pre(lambda: {"a": [1, 2.5, "x", None, False, {"b": [{}]}]}),
    "int_key": _pre(lambda: {"a": 1, "b": {"c": 1, 5: 2}}),
    "str_subclass_key": _pre(lambda: [{_Str("k"): 1}]),
    "lists_at_depth_limit": _pre(lambda: _nested_lists(MAX_DEPTH)),
    "lists_over_depth_limit": _pre(lambda: _nested_lists(MAX_DEPTH + 1)),
    "dicts_over_depth_limit": _pre(lambda: _nested_dicts(MAX_DEPTH + 1)),
    "self_reference": _pre(_self_list),
    "dag_shared_child": _pre(_dag),
    "error_location_order": _pre(lambda: [{"a": 1, "b": [None, None, {1: 2}]}, (1,)]),
}

ALL_CASES: dict[str, Case] = {
    **{f"load_contract/{k}": v for k, v in CONTRACT_CASES.items()},
    **{f"prevalidate/{k}": v for k, v in PREVALIDATE_CASES.items()},
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], best_config_profile) == _golden()[case_id]
