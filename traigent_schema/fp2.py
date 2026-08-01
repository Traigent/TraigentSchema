"""Reference implementation of the fp2 canonicalization spec.

Normative document: docs/fingerprints/fp2.md

This is the reference both SDKs are checked against. It deliberately
FAILS on values it cannot represent rather than coercing them: coercion
is what produces a digest that looks verified but silently depends on an
object's repr.

Two rules exist purely so Python and JavaScript agree byte-for-byte, and
both are easy to get wrong in the obvious way:

* Object keys are ordered by **UTF-16 code unit**, not by code point.
  Python's bare ``sorted()`` compares code points, which inverts against
  JavaScript for any key containing an astral character.
* Numbers are serialized with the **ECMAScript ``Number::toString``**
  algorithm, not with Python's ``repr``. ``repr(1e16)`` is ``'1e+16'``
  where JavaScript emits ``10000000000000000``.

Both rules follow RFC 8785 (JSON Canonicalization Scheme).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = ["Fp2UnsupportedValue", "canonicalize", "digest"]

# IEEE-754 doubles represent every integer up to this magnitude exactly.
# A Python int beyond it cannot round-trip through a JavaScript Number, so it
# is unsupported rather than silently divergent (see docs/fingerprints/fp2.md).
_MAX_SAFE_INTEGER = 2**53 - 1


class Fp2UnsupportedValue(TypeError):
    """A value that fp2 cannot represent; the manifest is incomplete."""


_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\b": "\\b",
    "\f": "\\f",
}


def _utf16_sort_key(value: str) -> bytes:
    """Return the UTF-16 code-unit sort key for ``value``.

    Comparing UTF-16 big-endian bytes lexicographically is exactly comparing
    UTF-16 code-unit sequences numerically, which is what JavaScript's ``<``
    does. Python's own string comparison uses code points and disagrees for
    astral characters, so the sort key cannot be the string itself.

    Raises:
        Fp2UnsupportedValue: ``value`` is not encodable text (a lone
            surrogate), so no two implementations could agree on its bytes.
    """
    try:
        return value.encode("utf-16-be")
    except UnicodeEncodeError as error:
        raise Fp2UnsupportedValue(f"string is not encodable text: {value!r}") from error


def _encode_string(value: str) -> str:
    # Reject un-encodable text (lone surrogates) here rather than letting a
    # UnicodeEncodeError escape from digest(): callers catch Fp2UnsupportedValue
    # to record state="unknown", and an unexpected exception type would crash
    # the run instead of degrading to unknown.
    _utf16_sort_key(value)
    out = ['"']
    for character in value:
        if character in _ESCAPES:
            out.append(_ESCAPES[character])
        elif character < " ":
            out.append(f"\\u{ord(character):04x}")
        else:
            out.append(character)
    out.append('"')
    return "".join(out)


def _shortest_digits(value: float) -> tuple[str, int]:
    """Decompose a positive finite float into ECMAScript's ``(s, n)``.

    Returns the shortest round-trip significant digits ``s`` and the exponent
    ``n`` such that ``0.s * 10**n == value``, matching the variables named in
    ECMA-262 Number::toString.
    """
    text = repr(value)
    mantissa, _, exponent_text = text.partition("e")
    exponent = int(exponent_text) if exponent_text else 0
    integer_part, _, fraction_part = mantissa.partition(".")

    digits = integer_part + fraction_part
    n = len(integer_part) + exponent

    stripped = digits.lstrip("0")
    n -= len(digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    return digits, n


def _ecmascript_number_to_string(value: float) -> str:
    """Serialize a finite float exactly as ECMAScript ``Number::toString``.

    ECMA-262 section 6.1.6.1.20, which RFC 8785 adopts as the canonical JSON
    number format. Python's ``repr`` round-trips but picks different notation
    thresholds and pads exponents, so it cannot be used directly.
    """
    if value == 0:  # covers -0.0, which canonicalizes to 0
        return "0"
    if value < 0:
        return "-" + _ecmascript_number_to_string(-value)

    digits, n = _shortest_digits(value)
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    exponent = n - 1
    sign = "+" if exponent >= 0 else "-"
    significand = digits if k == 1 else digits[0] + "." + digits[1:]
    return f"{significand}e{sign}{abs(exponent)}"


def _encode_float(value: float) -> str:
    if math.isnan(value) or math.isinf(value):
        raise Fp2UnsupportedValue(f"non-finite number: {value!r}")
    # float() strips any subclass: repr() on a float subclass is caller-defined
    # (numpy.float64 renders as "np.float64(0.1)"), which is precisely the
    # repr-dependent digest fp2 exists to prevent.
    return _ecmascript_number_to_string(float(value))


def _encode_int(value: int) -> str:
    exact = int(value)  # strip int subclasses (IntEnum, numpy integers)
    if abs(exact) > _MAX_SAFE_INTEGER:
        raise Fp2UnsupportedValue(
            f"integer outside the IEEE-754 safe range, not representable as a "
            f"JavaScript Number: {exact}"
        )
    return str(exact)


def _encode(value: Any, seen: set[int]) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return _encode_int(value)
    if isinstance(value, float):
        return _encode_float(value)
    if isinstance(value, (list, tuple)):
        if id(value) in seen:
            raise Fp2UnsupportedValue("circular reference")
        seen.add(id(value))
        try:
            return "[" + ",".join(_encode(item, seen) for item in value) + "]"
        finally:
            seen.discard(id(value))
    if isinstance(value, dict):
        if id(value) in seen:
            raise Fp2UnsupportedValue("circular reference")
        seen.add(id(value))
        try:
            for key in value:
                if not isinstance(key, str):
                    raise Fp2UnsupportedValue(f"non-string object key: {key!r}")
            items = sorted(value.items(), key=lambda item: _utf16_sort_key(item[0]))
            body = ",".join(
                f"{_encode_string(key)}:{_encode(item, seen)}" for key, item in items
            )
            return "{" + body + "}"
        finally:
            seen.discard(id(value))
    raise Fp2UnsupportedValue(f"unsupported type: {type(value).__name__}")


def canonicalize(value: Any) -> str:
    """Return the fp2 canonical JSON text for ``value``.

    Raises:
        Fp2UnsupportedValue: the manifest is incomplete and the caller must
            record ``state="unknown"`` with no digest.
    """
    return _encode(value, set())


def digest(value: Any) -> str:
    """Return the algorithm-prefixed fp2 digest for ``value``."""
    canonical = canonicalize(value)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
