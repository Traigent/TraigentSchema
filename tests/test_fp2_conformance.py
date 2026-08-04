"""fp2 conformance corpus — the executable definition of cross-SDK parity.

Both SDKs run this same corpus. A case that disagrees means two clients
compute different versions for identical data, which splits cohorts by
language invisibly.
"""

from __future__ import annotations

import collections
import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.fp2 import MAX_DEPTH, Fp2UnsupportedValue, canonicalize, digest

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
    astral = "\U0001f600"
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


def test_subclasses_cannot_choose_the_canonical_bytes() -> None:
    """Exact types only: a subclass owns its own iteration and conversion.

    isinstance() let user code decide the digest through an overridden items(),
    __iter__ or __int__ -- the repr trap through a different door. Each of
    these produced attacker-chosen canonical bytes before the fix.
    """

    class SneakyDict(dict):
        def items(self) -> Any:
            return [("evil", "injected")]

        def __iter__(self) -> Any:
            return iter(["evil"])

    class SneakyList(list):
        def __iter__(self) -> Any:
            return iter(["injected"])

    class SneakyStr(str):
        def __iter__(self) -> Any:
            return iter("HACKED")

    class SneakyInt(int):
        def __int__(self) -> int:
            return 999

    for label, value in (
        ("dict subclass", SneakyDict(a=1)),
        ("list subclass", SneakyList([1, 2])),
        ("str subclass", SneakyStr("safe")),
        ("int subclass", SneakyInt(1)),
    ):
        with pytest.raises(Fp2UnsupportedValue):
            canonicalize({"k": value})
            pytest.fail(f"{label} chose its own bytes")


def test_a_hostile_key_cannot_choose_the_object_ordering() -> None:
    """Keys, not just values: encode() produces the UTF-16 sort key.

    A str subclass overriding encode() picked the sort key for the whole
    object and got a VERIFIED digest for a reordering of the caller's choosing.
    The subclass must be used AS A KEY -- in value position this was already
    closed, so a value-position test passes and proves nothing.
    """

    class HostileKey(str):
        def encode(self, *args: Any, **kwargs: Any) -> bytes:
            return b"\x00\x00"  # sorts before everything

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({HostileKey("z"): 1, "a": 2})
    with pytest.raises(Fp2UnsupportedValue):
        digest({HostileKey("z"): 1, "a": 2})

    # The honest ordering, for contrast.
    assert canonicalize({"z": 1, "a": 2}) == '{"a":2,"z":1}'


def test_tuples_are_rejected_rather_than_flattened_into_arrays() -> None:
    """Reversed on review, and the reasoning matters more than the rule.

    Accepting tuples converged the SDKs, but it made {"mode": ["safe"]} and
    {"mode": ("safe",)} hash EQUAL while a closure branching on
    isinstance(mode, tuple) behaves differently -- a version asserting an
    equality that does not exist. The two failure modes are not symmetric:
    rejecting loses a comparison that was available (recoverable, and visible
    as unknown), accepting asserts comparability that is not there (silent,
    and the exact failure this feature exists to stop).

    The convergence belongs one level up: a genuinely positional dataset row is
    normalized to an array by the manifest builder, where the positional intent
    is known.
    """
    for value in ((1, 2), ("safe",), ()):
        with pytest.raises(Fp2UnsupportedValue):
            canonicalize({"k": value})

    Row = collections.namedtuple("Row", ["input", "expected"])
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"k": Row(1, 2)})

    # The builder's normalization is what produces a digest, and it is explicit.
    assert canonicalize({"k": list(("safe",))}) == '{"k":["safe"]}'


def test_error_messages_never_echo_caller_content() -> None:
    """fp2 runs over dataset rows; an exception message is logged everywhere.

    The same disclosure rule that covers telemetry and exports covers this.
    Report the type, the index, or the limit -- never the value.
    """
    secret = "customer SSN 123-45-6789"

    probes = (
        {"row": secret + "\ud800"},  # lone surrogate carrying user content
        {secret + "\ud800": 1, "a": 2},  # ...in key position
    )
    for payload in probes:
        with pytest.raises(Fp2UnsupportedValue) as caught:
            canonicalize(payload)  # type: ignore[arg-type]
        assert secret not in str(caught.value), f"leaked content: {caught.value}"

    class Hostile(dict):
        def __iter__(self) -> Any:
            raise ValueError(secret)  # a foreign error whose message is content

    with pytest.raises(Fp2UnsupportedValue) as caught:
        canonicalize({"outer": Hostile()})
    assert secret not in str(caught.value), f"leaked a chained message: {caught.value}"


def test_numeric_subclass_cannot_reach_the_digest_through_repr() -> None:
    """The default=str trap one level down: repr on a float subclass is caller-owned.

    numpy.float64 renders as 'np.float64(0.1)'. Formatting via repr would put
    that straight into the canonical bytes -- invalid JSON, and a digest that
    silently depends on a library's display choice. Now rejected outright by
    exact-type dispatch rather than coerced, so the caller gets an honest
    unknown instead of a digest nobody else can reproduce.
    """

    class Sneaky(float):
        def __repr__(self) -> str:
            return "PWNED"

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"n": Sneaky(1.5)})


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


def _nest(depth: int) -> dict[str, Any]:
    """Build ``depth`` nested objects: depth 1 is ``{"a": {}}``'s outer level."""
    value: Any = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


def test_nesting_at_the_depth_limit_is_accepted() -> None:
    assert canonicalize(_nest(MAX_DEPTH)).count("{") == MAX_DEPTH


def test_nesting_beyond_the_depth_limit_degrades_to_unknown() -> None:
    """Deep nesting used to escape as RecursionError, which no caller catches.

    A configuration space can genuinely nest, and the old encoder burned about
    three interpreter frames per level, so it died at depth 332 on a default
    recursion limit -- as an exception type the contract never mentions, so the
    run crashed instead of recording state="unknown".
    """
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize(_nest(MAX_DEPTH + 1))
    with pytest.raises(Fp2UnsupportedValue):
        digest(_nest(MAX_DEPTH + 1))
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"rows": [_nest(MAX_DEPTH)]})  # limit counts from the root


def _stack_depth() -> int:
    depth = 0
    frame: Any = sys._getframe()
    while frame is not None:
        depth += 1
        frame = frame.f_back
    return depth


def _call_with_headroom(headroom: int, action: Any) -> Any:
    """Invoke ``action`` with only ``headroom`` interpreter frames left."""
    if sys.getrecursionlimit() - _stack_depth() > headroom:
        return _call_with_headroom(headroom, action)
    return action()


def test_depth_limit_is_a_property_of_the_data_not_of_the_call_site() -> None:
    """The same manifest must resolve the same way from any stack depth.

    A recursive encoder spends the CALLER's stack, so identical data
    canonicalized fine from main() and raised RecursionError 400 frames down:
    the digest depended on where in the program it was computed, which is not a
    property any manifest should have.

    The headroom is deliberately smaller than a recursive encoder would need
    for a legal manifest (~3 frames per level, so ~300 at the limit) and far
    more than the iterative one does. Calling at a fixed shallow depth instead
    would pass under both encoders and prove nothing.
    """
    payload = _nest(MAX_DEPTH)
    expected = canonicalize(payload)
    headroom = 150

    assert headroom < 3 * MAX_DEPTH, "headroom must be too small for a recursive encoder"

    assert _call_with_headroom(headroom, lambda: canonicalize(payload)) == expected


def test_entry_points_raise_only_the_documented_type() -> None:
    """The class rule: no foreign exception may escape, whatever the cause.

    Enumerating known offenders is exactly what left RecursionError uncovered
    after the lone-surrogate fix, so this asserts the guarantee itself.
    """

    class Hostile(dict):  # a mapping whose iteration blows up mid-encode
        def __iter__(self) -> Any:
            raise ZeroDivisionError("not a TypeError, not anticipated")

    for entry_point in (canonicalize, digest):
        with pytest.raises(Fp2UnsupportedValue):
            entry_point({"outer": Hostile()})


def test_circular_reference_is_unsupported() -> None:
    node: dict[str, Any] = {"name": "a"}
    node["self"] = node

    with pytest.raises(Fp2UnsupportedValue):
        canonicalize(node)


def test_non_ascii_is_emitted_literally() -> None:
    assert canonicalize({"k": "héllo"}) == '{"k":"héllo"}'


def test_digest_carries_its_algorithm_prefix() -> None:
    assert digest({"a": 1}).startswith("sha256:")


def test_nfc_and_nfd_are_distinct_and_never_collapsed() -> None:
    """fp2 preserves code points; it must NOT normalize.

    This is load-bearing for the best-config hash contract: a prompt is customer
    content, and NFC-normalizing it changes the bytes that reach a model, so the
    canonicalizer has to leave both forms alone and let them hash differently.
    An implementation that quietly normalized would still satisfy every other
    case in the corpus -- the precomposed and decomposed spellings are visually
    identical, so nothing else here would notice.
    """
    cases = {case["name"]: case for case in _cases()}

    precomposed = cases["non_ascii_literal"]  # {"k": "h\u00e9llo"}, NFC
    decomposed = cases["unicode_value_nfd_decomposed"]  # same text, NFD

    assert precomposed["value"] != decomposed["value"], "fixtures must differ"
    assert unicodedata.normalize("NFC", decomposed["value"]["k"]) == (precomposed["value"]["k"]), (
        "the two fixtures must be the same text in different forms"
    )

    assert precomposed["digest"] != decomposed["digest"]
    assert digest(decomposed["value"]) == decomposed["digest"]

    # Keys too: a normalizing implementation would collapse these into one member.
    key_case = cases["unicode_key_nfd_decomposed"]
    assert digest(key_case["value"]) == key_case["digest"]
    assert key_case["digest"] != precomposed["digest"]
