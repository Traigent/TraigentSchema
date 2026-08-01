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
    "@@LONE_SURROGATE@@": "a\ud800b",
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


def test_no_case_is_allowed_to_be_language_specific() -> None:
    """A value one SDK digests and another rejects is the divergence we hunt.

    'language_specific' was an escape hatch that let Python skip the oversized
    integer while asserting nothing about JavaScript. Skipping a disagreement
    is still a disagreement; every case must resolve the same way everywhere.
    """
    offenders = [case["name"] for case in _cases() if case["expect"] == "language_specific"]

    assert not offenders, f"cases that let the SDKs disagree: {offenders}"


def test_key_ordering_is_code_unit_not_locale() -> None:
    """localeCompare would order these differently from code-unit order."""
    assert canonicalize({"Z": 1, "a": 2}) == '{"Z":1,"a":2}'


def test_key_ordering_is_utf16_code_unit_not_code_point() -> None:
    """The one ordering case where the two candidate rules give opposite answers.

    U+1F600 is UTF-16 D83D DE00; U+FF21 is FF21. By code point the astral key
    is larger (0x1F600 > 0xFF21) and sorts last, which is what Python's bare
    sorted() does. By code unit its lead surrogate is smaller (0xD83D < 0xFF21)
    and it sorts first, which is what JavaScript's `<` does and what RFC 8785
    requires. Every ASCII or BMP-only fixture agrees under both rules and so
    cannot catch this; without this case a Python implementation using sorted()
    passes the whole corpus and still splits cohorts by client language.
    """
    astral = "\U0001F600"
    bmp = "Ａ"

    assert astral.encode("utf-16-be").hex() == "d83dde00"
    assert ord(astral) > ord(bmp)  # code point says astral is larger...
    assert astral.encode("utf-16-be") < bmp.encode("utf-16-be")  # ...code unit says smaller

    assert canonicalize({astral: 1, bmp: 2}) == f'{{"{astral}":1,"{bmp}":2}}'
    # ...and the same inversion after a shared prefix, not just at position 0.
    assert canonicalize({"a" + astral: 1, "a" + bmp: 2}) == f'{{"a{astral}":1,"a{bmp}":2}}'


def test_numbers_use_ecmascript_notation_thresholds_not_python_repr() -> None:
    """Python repr round-trips but picks different notation from JavaScript.

    Round-tripping is not enough: the digest is over the *text*. These are the
    exact values where repr and ECMAScript Number::toString disagree.
    """
    assert repr(1e16) == "1e+16"  # what a naive implementation would emit...
    assert canonicalize({"n": 1e16}) == '{"n":10000000000000000}'  # ...vs required

    assert canonicalize({"n": 1e20}) == '{"n":100000000000000000000}'
    assert canonicalize({"n": 1e21}) == '{"n":1e+21}'
    assert canonicalize({"n": 1e-5}) == '{"n":0.00001}'
    assert canonicalize({"n": 1e-6}) == '{"n":0.000001}'
    assert canonicalize({"n": 1e-7}) == '{"n":1e-7}'  # not repr's zero-padded 1e-07
    assert canonicalize({"n": 5e-324}) == '{"n":5e-324}'
    assert canonicalize({"n": 123.456}) == '{"n":123.456}'
    assert canonicalize({"n": -2.5}) == '{"n":-2.5}'


def test_integer_beyond_the_safe_range_is_unsupported() -> None:
    """A JavaScript Number cannot hold it, so no digest can be cross-SDK true."""
    assert canonicalize({"n": 9007199254740991}) == '{"n":9007199254740991}'

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"n": 2**53})
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"n": -(2**70)})

    # The float of the same magnitude round-trips through a Number exactly and
    # stays supported: the limit is Python's arbitrary precision, not the size.
    assert canonicalize({"n": float(2**70)}) == '{"n":1.1805916207174113e+21}'


def test_numeric_subclass_cannot_reach_the_digest_through_repr() -> None:
    """The default=str trap one level down: repr on a float subclass is caller-owned.

    numpy.float64 renders as 'np.float64(0.1)'. Formatting via repr would put
    that straight into the canonical bytes -- invalid JSON, and a digest that
    silently depends on a library's display choice.
    """

    class Sneaky(float):
        def __repr__(self) -> str:
            return "PWNED"

    assert canonicalize({"n": Sneaky(1.5)}) == '{"n":1.5}'


def test_negative_zero_normalizes_to_zero() -> None:
    assert canonicalize({"n": -0.0}) == '{"n":0}'


def test_explicit_null_is_emitted_not_omitted() -> None:
    """null is a value and survives; only JS `undefined` is an omission."""
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


def test_lone_surrogate_degrades_to_unknown_rather_than_crashing() -> None:
    """Callers catch Fp2UnsupportedValue to record state='unknown'.

    An un-encodable string used to escape as UnicodeEncodeError from digest(),
    which no caller is told to catch: the run dies instead of honestly
    reporting an incomplete manifest.
    """
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"k": "a\ud800b"})
    with pytest.raises(Fp2UnsupportedValue):
        digest({"k": "a\ud800b"})
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"a\ud800b": 1})  # as a key, too


def test_circular_reference_is_unsupported() -> None:
    node: dict[str, Any] = {"name": "a"}
    node["self"] = node

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize(node)


def test_non_ascii_is_emitted_literally() -> None:
    assert canonicalize({"k": "héllo"}) == '{"k":"héllo"}'


def test_digest_carries_its_algorithm_prefix() -> None:
    assert digest({"a": 1}).startswith("sha256:")
