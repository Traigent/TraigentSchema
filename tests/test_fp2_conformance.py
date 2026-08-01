"""fp2 conformance corpus — the executable definition of cross-SDK parity.

Both SDKs run this same corpus. A case that disagrees means two clients
compute different versions for identical data, which splits cohorts by
language invisibly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.fp2 import Fp2UnsupportedValue, canonicalize, digest

CORPUS = Path(__file__).resolve().parent / "data" / "fp2_conformance.json"

_MARKERS: dict[str, Any] = {
    "@@NAN@@": float("nan"),
    "@@INF@@": float("inf"),
    "@@UNDEFINED@@": ...,
    "@@BIGINT@@": 2**70,
    "@@DATE@@": object(),
}


def _cases() -> list[dict[str, Any]]:
    return json.loads(CORPUS.read_text(encoding="utf-8"))["cases"]


def _substitute(value: Any) -> Any:
    if isinstance(value, str) and value in _MARKERS:
        return _MARKERS[value]
    if isinstance(value, list):
        return [_substitute(item) for item in value]
    if isinstance(value, dict):
        return {key: _substitute(item) for key, item in value.items()}
    return value


def _python_cases() -> list[dict[str, Any]]:
    return [case for case in _cases() if case["expect"] != "language_specific"]


def test_corpus_exists_and_is_non_trivial() -> None:
    cases = _cases()

    assert len(cases) >= 12, "A corpus this small cannot pin cross-SDK behavior"


@pytest.mark.parametrize("case", _python_cases(), ids=lambda c: c["name"])
def test_canonicalization_matches_the_corpus(case: dict[str, Any]) -> None:
    value = _substitute(case["value"])
    if case["expect"] == "unsupported":
        with pytest.raises(Fp2UnsupportedValue):
            canonicalize(value)
        return

    assert canonicalize(value) == case["canonical"]


@pytest.mark.parametrize(
    "case",
    [case for case in _python_cases() if case["expect"] == "ok"],
    ids=lambda c: c["name"],
)
def test_digest_matches_the_corpus(case: dict[str, Any]) -> None:
    assert digest(_substitute(case["value"])) == case["digest"]


def test_key_ordering_is_code_point_not_locale() -> None:
    """localeCompare would order these differently from code-point order."""
    assert canonicalize({"Z": 1, "a": 2}) == '{"Z":1,"a":2}'


def test_negative_zero_normalizes_to_zero() -> None:
    assert canonicalize({"n": -0.0}) == '{"n":0}'


def test_undefined_like_absence_is_omitted_not_nulled() -> None:
    assert canonicalize({"a": 1, "b": None}) == '{"a":1,"b":null}'


def test_nan_is_unsupported_not_null() -> None:
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"n": float("nan")})


def test_infinity_is_unsupported_not_null() -> None:
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"n": float("inf")})


def test_non_plain_objects_are_unsupported_not_stringified() -> None:
    """The default=str trap: this must raise, not produce a repr-based digest."""

    class Thing:
        def __repr__(self) -> str:
            return "<thing>"

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"o": Thing()})


def test_circular_reference_is_unsupported() -> None:
    node: dict[str, Any] = {"name": "a"}
    node["self"] = node

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize(node)


def test_non_ascii_is_emitted_literally() -> None:
    assert canonicalize({"k": "héllo"}) == '{"k":"héllo"}'


def test_digest_carries_its_algorithm_prefix() -> None:
    assert digest({"a": 1}).startswith("sha256:")
