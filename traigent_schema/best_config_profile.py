# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Reference implementation of the best-config integrity digest profile.

Normative document: traigent_schema/schemas/optimization/best_config_hash_contract_schema.json

This profile composes four steps, in order, none of which change fp2 itself:

1. An iterative prevalidation pass over the parsed value, admitting only the
   exact JSON built-in types (dict/list/str/int/float/bool/None -- never a
   subclass) and rejecting, before fp2 ever runs: an unsafe integral VALUE
   (abs(n) > 2**53-1 when the value is integral, whether it arrived as a
   Python ``int`` or a ``float`` -- fp2 rejects the unsafe ``int`` TYPE but,
   by design, canonicalizes an equal-magnitude ``float``, because an
   ordinary finite float is otherwise valid fp2 input); a circular
   reference; nesting deeper than the shared ``max_depth`` bound; a
   non-string object key; and any other unsupported type. Every one of
   these mirrors a rule fp2 itself would eventually enforce, but catching it
   here means a rejected value never reaches ``fp2.canonicalize`` at all
   (zero fp2 calls on any prevalidation rejection).
2. Unchanged fp2 canonicalization (``fp2.canonicalize``), for values that
   pass step 1. Any rejection fp2 still raises here (a non-finite number or
   a lone surrogate -- the two rules that can only be evaluated inside fp2's
   own float/string handling) is wrapped into a profile-typed error rather
   than allowed to escape as a raw ``fp2.Fp2UnsupportedValue``.
3. A post-canonicalization UTF-8 byte bound: fp2 performs no byte-length
   check at all, because the bound is on canonical text that does not exist
   until fp2 has already run.
4. A domain-separated SHA-256 digest: ``sha256(domain_tag + b"\\x00" + canonical_bytes)``.

Every normative constant here (the byte bound, the depth bound, the domain
tags) is read from the packaged ``best_config_hash_contract_schema.json``
rather than hardcoded, so a contract change cannot silently diverge from
this implementation. If that schema is missing or malformed, importing this
module fails closed - there is no fallback literal for a normative value.

A separate concern this module also closes: ``config_digest``/``spec_digest``
operate on an already-parsed Python value, so a duplicate object key in the
original JSON text has already been silently collapsed by the time either
function ever sees it -- no parsed-value function can detect that. A caller
reading raw JSON text (from a file or an HTTP body) that wants
``duplicate_property_name`` rejection MUST decode through :func:`loads_strict`
(or an equivalent duplicate-aware decoder) rather than plain ``json.loads``.
This module is the reference implementation of that parse-boundary decoder;
other runtimes MUST implement equivalent duplicate-key and non-finite-constant
rejection at their own parse boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from . import fp2
from .utils import get_schemas_dir

__all__ = [
    "BestConfigProfileError",
    "UnsafeIntegralValueError",
    "CanonicalSpecTooLargeError",
    "CircularReferenceError",
    "ExceedsMaxDepthError",
    "NonStringKeyError",
    "UnsupportedProfileTypeError",
    "Fp2CanonicalizationError",
    "DuplicatePropertyNameError",
    "MalformedJsonError",
    "MAX_CANONICAL_SPEC_BYTES",
    "MAX_DEPTH",
    "DOMAIN_TAG_CONFIG",
    "DOMAIN_TAG_SPEC",
    "config_digest",
    "spec_digest",
    "loads_strict",
]

_MAX_SAFE_INTEGER = 2**53 - 1

_CONTRACT_FILENAME = "best_config_hash_contract_schema.json"


class BestConfigProfileError(Exception):
    """Base class for every best-config hash profile failure.

    No digest is ever returned when one of these is raised: rejection
    happens before ``fp2.canonicalize`` (prevalidation), inside fp2 itself
    (wrapped rather than left as a raw ``fp2.Fp2UnsupportedValue``), or
    before hashing (the byte bound) -- never after a digest has already
    been computed. Every exception this module raises, including fp2's own
    rejections once they reach ``config_digest``/``spec_digest``, is an
    instance of this class.
    """

    code = "best_config_profile_error"


class UnsafeIntegralValueError(BestConfigProfileError):
    """A numeric VALUE is an integral magnitude outside the IEEE-754 safe range.

    Raised for the Python VALUE, independent of ``int``/``float`` type - see
    the ``rejected_values`` entry ``unsafe_integral_number`` in
    best_config_hash_contract_schema.json.
    """

    code = "unsafe_integral_number"


class CanonicalSpecTooLargeError(BestConfigProfileError):
    """The fp2-canonical UTF-8 encoding exceeds MAX_CANONICAL_SPEC_BYTES.

    See the ``rejected_values`` entry ``exceeds_max_canonical_spec_bytes``.
    """

    code = "exceeds_max_canonical_spec_bytes"


class CircularReferenceError(BestConfigProfileError):
    """A container reaches itself. See the ``rejected_values`` entry ``cycle``."""

    code = "cycle"


class ExceedsMaxDepthError(BestConfigProfileError):
    """Nesting exceeds MAX_DEPTH containers from the root.

    See the ``rejected_values`` entry ``exceeds_max_depth``.
    """

    code = "exceeds_max_depth"


class NonStringKeyError(BestConfigProfileError):
    """An object key is not a plain ``str``.

    See the ``rejected_values`` entry ``non_string_key``.
    """

    code = "non_string_key"


class UnsupportedProfileTypeError(BestConfigProfileError):
    """A value is not one of the admissible exact JSON built-in types.

    See the ``rejected_values`` entry ``unsupported_type``.
    """

    code = "unsupported_type"


class Fp2CanonicalizationError(BestConfigProfileError):
    """fp2 itself rejected a value that passed prevalidation.

    Wraps ``fp2.Fp2UnsupportedValue`` so every failure path out of
    ``config_digest``/``spec_digest`` is a ``BestConfigProfileError``. The
    underlying fp2 reason (a non-finite number or a lone surrogate -- the
    only two rejections fp2 can still raise once prevalidation has already
    ruled out every structural-shape rule) is preserved on ``__cause__`` for
    a developer holding the traceback, but this class intentionally carries
    one generic code rather than re-deriving a specific one from fp2's
    message text: fp2.canonicalize's own docstring documents that it
    reports only the exception TYPE, by design, because a foreign message
    can embed caller data. Parsing that message here to recover a
    finer-grained code would undo that discipline.
    """

    code = "fp2_canonicalization_failure"


class DuplicatePropertyNameError(BestConfigProfileError):
    """A JSON object literal repeated a key. See :func:`loads_strict`."""

    code = "duplicate_property_name"


class MalformedJsonError(BestConfigProfileError):
    """The text is not well-formed JSON. See :func:`loads_strict`."""

    code = "malformed_json"


def _load_contract() -> dict[str, Any]:
    """Read the normative constants from the packaged contract schema.

    Raises BestConfigProfileError rather than falling back to a literal:
    a normative value that this module cannot verify against the shipped
    schema must not be guessed.
    """
    contract_path = get_schemas_dir() / "optimization" / _CONTRACT_FILENAME
    try:
        raw = contract_path.read_text(encoding="utf-8")
        contract = json.loads(raw)
        definitions = contract["definitions"]
        canonicalization = definitions["canonicalization"]["properties"]
        max_bytes = canonicalization["max_canonical_spec_bytes"]["const"]
        max_depth = canonicalization["max_depth"]["const"]
        domain_tags = definitions["domain_tag"]["enum"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise BestConfigProfileError(
            f"{_CONTRACT_FILENAME} is missing or malformed; cannot derive "
            f"normative best-config hash profile constants: {error}"
        ) from error

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise BestConfigProfileError(
            "canonicalization.max_canonical_spec_bytes must be a positive integer"
        )

    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth <= 0:
        raise BestConfigProfileError("canonicalization.max_depth must be a positive integer")

    if not isinstance(domain_tags, list) or not all(isinstance(t, str) for t in domain_tags):
        raise BestConfigProfileError("domain_tag.enum must be a list of strings")

    config_tags = [tag for tag in domain_tags if tag.endswith(".config.v1")]
    spec_tags = [tag for tag in domain_tags if tag.endswith(".spec.v1")]
    if len(config_tags) != 1 or len(spec_tags) != 1:
        raise BestConfigProfileError(
            "domain_tag.enum must declare exactly one *.config.v1 tag and exactly one *.spec.v1 tag"
        )

    return {
        "max_canonical_spec_bytes": max_bytes,
        "max_depth": max_depth,
        "config_tag": config_tags[0],
        "spec_tag": spec_tags[0],
    }


_CONTRACT = _load_contract()

#: Upper bound, in UTF-8 bytes, on the fp2-canonical text of a preimage.
#: Sourced from best_config_hash_contract_schema.json - see _load_contract.
MAX_CANONICAL_SPEC_BYTES: int = _CONTRACT["max_canonical_spec_bytes"]

#: Upper bound on container nesting, from the same packaged contract as
#: MAX_CANONICAL_SPEC_BYTES. Asserted below to equal fp2.MAX_DEPTH exactly:
#: the prevalidation pass must reject at the identical boundary fp2 itself
#: would, or "zero fp2 calls on rejection" would not hold at the boundary.
MAX_DEPTH: int = _CONTRACT["max_depth"]

if MAX_DEPTH != fp2.MAX_DEPTH:
    raise BestConfigProfileError(
        "canonicalization.max_depth in the packaged contract "
        f"({MAX_DEPTH}) diverges from fp2.MAX_DEPTH ({fp2.MAX_DEPTH}); the "
        "best-config hash profile's prevalidation depth bound must exactly "
        "match fp2's own limit"
    )

#: Domain separator for config_hash preimages.
DOMAIN_TAG_CONFIG: str = _CONTRACT["config_tag"]

#: Domain separator for spec_hash preimages.
DOMAIN_TAG_SPEC: str = _CONTRACT["spec_tag"]


def _is_unsafe_integral(value: int | float) -> bool:
    """True if value (a confirmed exact, non-bool int or float) is an unsafe integral magnitude.

    Only ever called by ``_prevalidate`` after the caller has already
    confirmed ``type(value) is int`` or ``type(value) is float`` and ruled
    out ``bool`` separately, so no bool-exclusion branch is needed here.
    """
    if type(value) is int:
        return abs(value) > _MAX_SAFE_INTEGER
    if not math.isfinite(value):
        # Non-finite values are fp2's rejection to raise, not this rule's.
        return False
    if value != int(value):
        # Non-integral floats are ordinary fp2 input.
        return False
    return abs(value) > _MAX_SAFE_INTEGER


# Work-stack entry tags for the iterative prevalidation walk.
_VALUE = 0  # visit and validate this node
_CLOSE = 1  # leave a container: drop its identity from the open-path set


def _location(path: tuple[int, ...]) -> str:
    """Return a structural, content-free location for an error message.

    Every segment is a positional index -- an object member's ordinal
    position or an array index -- never the key or value found there. This
    is deliberately NOT a full RFC 6901 JSON Pointer rendering of object
    keys: echoing a key would echo customer content, which none of this
    module's exceptions may ever do.
    """
    return "$" + "".join(f"[{segment}]" for segment in path)


def _prevalidate(root: Any) -> None:
    """Iteratively walk ``root``, admitting only the exact JSON built-in types.

    Raises the first violation found; callers must not reach
    ``fp2.canonicalize`` if this raises. An explicit work stack is used
    rather than recursion for the same reason ``fp2._encode`` uses one (see
    fp2.py): the result must be a property of the data alone, not of how
    much interpreter stack the caller happened to have left, so identical
    data cannot canonicalize from one call site and raise ``RecursionError``
    from a deeper one.

    Cycle detection is path-local, not global: a container's identity is
    tracked only while a still-open ancestor frame owns it (added when
    first visited, discarded via a ``_CLOSE`` marker once every descendant
    has been visited), mirroring fp2's own ``open_containers`` set exactly.
    This means the same acyclic sub-object reachable from two different
    siblings validates -- it is visited, closed, and revisited fresh -- while
    a container that reaches itself through its own descendants is rejected,
    because its identity is still open when the self-reference is reached.

    Raises:
        UnsafeIntegralValueError: an integral value's magnitude exceeds the
            IEEE-754 safe integer range.
        UnsupportedProfileTypeError: a value is not exactly one of
            dict/list/str/int/float/bool/None (a subclass of any of these
            is also rejected here, before any subclass override -- __iter__,
            items(), __int__, __float__ -- could run).
        ExceedsMaxDepthError: nesting exceeds MAX_DEPTH containers from the
            root.
        CircularReferenceError: a container reaches itself.
        NonStringKeyError: an object key is not exactly ``str`` (a ``str``
            subclass is also rejected here, before its own ``encode``
            override could choose the object's sort key).
    """
    open_ids: set[int] = set()
    work: list[tuple[int, Any, int, tuple[int, ...]]] = [(_VALUE, root, 1, ())]

    while work:
        kind, node, depth, path = work.pop()

        if kind == _CLOSE:
            open_ids.discard(node)
            continue

        if node is None:
            continue

        # Exact types only. isinstance() would admit a subclass, and a
        # subclass decides its own __iter__/items()/__int__/__float__ -- so
        # user code, not this function, would choose what gets hashed. This
        # mirrors fp2._encode's own exact-type dispatch (see fp2.py) for
        # exactly the same reason.
        node_type = type(node)

        if node_type is bool:
            continue
        if node_type is int or node_type is float:
            if _is_unsafe_integral(node):
                raise UnsafeIntegralValueError(
                    f"{_location(path)}: integral value outside the IEEE-754 "
                    f"safe integer range (limit {_MAX_SAFE_INTEGER})"
                )
            continue
        if node_type is str:
            continue

        if node_type is not dict and node_type is not list:
            raise UnsupportedProfileTypeError(
                f"{_location(path)}: unsupported type ({node_type.__name__})"
            )

        if depth > MAX_DEPTH:
            raise ExceedsMaxDepthError(
                f"{_location(path)}: nests deeper than the profile limit of {MAX_DEPTH}"
            )

        identity = id(node)
        if identity in open_ids:
            raise CircularReferenceError(f"{_location(path)}: circular reference")
        open_ids.add(identity)
        # Pushed before the children: LIFO means it pops only after every
        # child (and its full subtree) has already been popped and validated.
        work.append((_CLOSE, identity, 0, ()))

        if node_type is dict:
            for index, (key, item) in enumerate(node.items()):
                if type(key) is not str:
                    raise NonStringKeyError(
                        f"{_location(path + (index,))}: object key is not a "
                        f"plain string (type: {type(key).__name__})"
                    )
                work.append((_VALUE, item, depth + 1, path + (index,)))
        else:
            for index, item in enumerate(node):
                work.append((_VALUE, item, depth + 1, path + (index,)))


def _canonical_bytes(value: Any) -> bytes:
    """Prevalidate, canonicalize with fp2 unchanged, then enforce the byte bound.

    Raises:
        UnsafeIntegralValueError, UnsupportedProfileTypeError,
        ExceedsMaxDepthError, CircularReferenceError, NonStringKeyError:
            prevalidation rejected the value before fp2 ever ran (see
            :func:`_prevalidate`).
        Fp2CanonicalizationError: fp2 canonicalization itself rejected the
            value (non-finite number or lone surrogate -- the two rules
            prevalidation cannot evaluate ahead of fp2's own float/string
            handling).
        CanonicalSpecTooLargeError: the canonical UTF-8 encoding exceeds
            MAX_CANONICAL_SPEC_BYTES.
    """
    _prevalidate(value)
    try:
        canonical = fp2.canonicalize(value)
    except fp2.Fp2UnsupportedValue as error:
        raise Fp2CanonicalizationError("$: fp2 canonicalization rejected the value") from error
    encoded = canonical.encode("utf-8")
    if len(encoded) > MAX_CANONICAL_SPEC_BYTES:
        raise CanonicalSpecTooLargeError(
            f"canonical spec is {len(encoded)} bytes, exceeds the limit of "
            f"{MAX_CANONICAL_SPEC_BYTES}"
        )
    return encoded


def _domain_digest(value: Any, domain_tag: str) -> str:
    encoded = _canonical_bytes(value)
    preimage = domain_tag.encode("ascii") + b"\x00" + encoded
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def config_digest(config: Any) -> str:
    """Return the config_hash digest for a raw, as-published best-config config.

    See digest_roles.config_hash in best_config_hash_contract_schema.json:
    computed over the exact raw spec.config, before any allowlist filtering
    or default merging.
    """
    return _domain_digest(config, DOMAIN_TAG_CONFIG)


def spec_digest(spec: Any) -> str:
    """Return the spec_hash digest for a complete best-config spec object.

    See digest_roles.spec_hash in best_config_hash_contract_schema.json:
    computed over the complete spec, with no exclusion list.
    """
    return _domain_digest(spec, DOMAIN_TAG_SPEC)


def _reject_non_finite_constant(constant: str) -> float:
    # Reject rather than accept json.loads' non-standard NaN/Infinity/-Infinity
    # constants at the parse boundary: letting one through would hand
    # config_digest/spec_digest an already-parsed non-finite float, which fp2
    # rejects anyway, but with a parse-time cause instead of a value-time one.
    raise MalformedJsonError(f"$: non-finite JSON constant ({constant})")


def _parse_float_rejecting_overflow(literal: str) -> float:
    # A syntactically ordinary number literal (e.g. 1e9999) can still parse
    # to a non-finite float: float() silently rounds an out-of-range
    # magnitude to +-inf rather than raising. That is a different gap than
    # _reject_non_finite_constant closes (which only catches the separate
    # NaN/Infinity/-Infinity *keyword* tokens) -- here the source text is a
    # normal digit-exponent literal, not a special constant, so only
    # checking the parsed result's finiteness can catch it. Rejected here
    # rather than left for fp2, for the same parse-time-cause reason as the
    # constant case above. The literal itself is not included in the error:
    # only the fact that some number in the document overflowed to +-inf.
    value = float(literal)
    if not math.isfinite(value):
        raise MalformedJsonError("$: JSON number literal overflows to a non-finite float")
    return value


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    # object_pairs_hook sees every key exactly as parsed, before json.loads'
    # own dict construction silently keeps only the last value for a repeated
    # key -- the point in the pipeline where duplication can still be seen at
    # all. No key or value is included in the error: only the fact that some
    # object in the document repeated a member.
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise DuplicatePropertyNameError("$: duplicate object key in a parsed object")
        seen.add(key)
    return dict(pairs)


def loads_strict(text: str) -> Any:
    """Parse JSON text with duplicate-key and non-finite-constant rejection.

    The reference parse-boundary decoder for this profile. ``json.loads``
    alone silently keeps the LAST value for a duplicate object key, so by
    the time a caller holds a parsed Python value the duplicate is already
    gone -- no parsed-value function (``config_digest``, ``spec_digest``,
    ``_prevalidate``) can ever detect it again from an already-materialized
    dict. A file or HTTP reader that wants ``duplicate_property_name``
    rejection MUST decode through this function (or an equivalent
    duplicate-aware decoder) rather than handing plain ``json.loads``
    output to this module.

    ``json.loads`` also accepts the non-standard ``NaN``/``Infinity``/
    ``-Infinity`` constants by default, and silently rounds an ordinary
    numeric literal whose magnitude overflows a float (e.g. ``1e9999``) to
    ``inf``/``-inf`` rather than raising; this rejects both here rather than
    letting a non-finite float reach fp2 as an already-parsed value.

    A JSON document whose container nesting exceeds the interpreter's own
    recursion limit raises a raw ``RecursionError`` from CPython's decoder
    -- a foreign, undocumented exception type this function must not leak,
    for the same reason ``config_digest``/``spec_digest`` never leak one.
    That is mapped to ``MalformedJsonError`` here too.

    Returns:
        The parsed Python value. The caller still invokes
        ``config_digest``/``spec_digest`` on it; this function does not
        digest anything itself.

    Raises:
        DuplicatePropertyNameError: an object literal repeats a key.
        MalformedJsonError: the text is not well-formed JSON, nests deeper
            than the interpreter can parse, or contains a non-finite
            constant or numeric literal (NaN/Infinity/-Infinity, or a
            magnitude that overflows to +-inf).
    """
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object_keys,
            parse_constant=_reject_non_finite_constant,
            parse_float=_parse_float_rejecting_overflow,
        )
    except (DuplicatePropertyNameError, MalformedJsonError):
        raise
    except RecursionError as error:
        raise MalformedJsonError("$: JSON text nests too deeply to parse") from error
    except json.JSONDecodeError as error:
        raise MalformedJsonError(
            f"$: malformed JSON at line {error.lineno} column {error.colno}"
        ) from error
