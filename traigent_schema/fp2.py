"""Reference implementation of the fp2 canonicalization spec.

Normative document: docs/fingerprints/fp2.md

This is the reference both SDKs are checked against. It deliberately
FAILS on values it cannot represent rather than coercing them: coercion
is what produces a digest that looks verified but silently depends on an
object's repr.
"""

from __future__ import annotations

import hashlib
import math
from typing import Any

__all__ = ["Fp2UnsupportedValue", "canonicalize", "digest"]


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


def _encode_string(value: str) -> str:
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


def _encode_number(value: float | int) -> str:
    if isinstance(value, bool):  # bool is a subclass of int; handled by caller
        raise Fp2UnsupportedValue("bool must be encoded as a literal")
    if isinstance(value, int):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise Fp2UnsupportedValue(f"non-finite number: {value!r}")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 2**53:
        return str(int(value))
    return repr(value)


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
        return str(value)
    if isinstance(value, float):
        return _encode_number(value)
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
            items = sorted(value.items(), key=lambda item: item[0])
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
