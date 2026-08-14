# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Generic interpreter for a schema's declared ``x-traigent-invariants``.

Normative document: traigent_schema/schemas/x_extensions_meta_schema.json
(the ``x-traigent-invariants`` entry).

Draft-07 JSON Schema has no keyword for asserting that two fields -- often
siblings in independently-validated subtrees, or fields composed in from
different ``allOf`` branches -- must hold equal values, must diverge under a
condition, or that one field's value selects a dynamic key into another. A
payload can be fully schema-valid while such a relationship silently fails
to hold. Rather than leave that gap undocumented, a schema declares each
such invariant as data (``x-traigent-invariants``), and this module
evaluates those declarations against an already structurally-valid parsed
instance.

Three relations are interpreted, each documented (with its own closed
per-relation shape) on the ``x-traigent-invariants`` property in
x_extensions_meta_schema.json: ``present_and_equal``,
``selector_lookup_equals_literal``, and ``condition_implies_unequal``.

Boundary, stated so it is not over-read: this checks structural consistency
between named locations in a payload only. It is not a cryptographic
certificate validity check, not an eligibility or optimality claim, and not
an authorization decision. A payload with zero violations has not thereby
been certified, made eligible, or authorized for anything -- it has only
been shown internally consistent on the specific relations its schema
declares.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError

from .utils import load_schema

__all__ = [
    "InvariantComparisonBoundError",
    "InvariantDeclarationError",
    "InvariantNoncanonicalPayloadError",
    "InvariantViolation",
    "validate_declared_invariants",
]

_MISSING = object()

_META_SCHEMA_NAME = "x_extensions_meta_schema"

# Shared with fp2/best_config_profile's own nesting bound: a comparison walk
# must reject at the same magnitude those modules already do, not invent an
# unrelated number. See fp2.py's MAX_DEPTH docstring for why 100 specifically.
_MAX_COMPARISON_DEPTH = 100

# A generous bound on how many nodes ONE SIDE of a comparison may contain.
# Applied independently to each compared subtree by _prevalidate_canonical,
# before the two are ever paired up -- so a pathologically wide (not
# necessarily deep) hostile subtree on either side is refused on its own,
# rather than only once paired against the other side. Real declared-
# invariant targets are small schema-bounded subtrees; this exists only to
# bound a hostile one.
_MAX_COMPARISON_NODES = 100_000

# RFC 6901 array-index segments this module resolves: "0", or a nonzero digit
# followed by any digits -- ASCII only ("[0-9]" in a Python str pattern
# matches only the ASCII digits, never a Unicode decimal digit like U+0660
# ARABIC-INDIC DIGIT ZERO). A leading zero ("01"), a sign ("-1", "+1"), a
# decimal point ("1.0"), interior whitespace, or any non-ASCII digit is
# deliberately NOT a canonical index segment -- it is unresolvable, the same
# outcome as any other missing pointer segment, not a distinct error. This
# is narrower, by design, than the RFC 6901 *syntax* the meta-schema's own
# pointer pattern accepts for a POINTER (which allows any non-"/"/"~"
# characters, since an object member name can legitimately look like a
# non-canonical number) -- this regex only decides which *array* index
# segments this function will follow.
_ARRAY_INDEX_SEGMENT = re.compile(r"(?:0|[1-9][0-9]*)")


class InvariantDeclarationError(Exception):
    """A schema's x-traigent-invariants declarations are missing or malformed.

    Raised for a call-site/schema-authoring error, never for a payload that
    fails an invariant -- that outcome is an InvariantViolation, not an
    exception. There is no fallback to "no invariants declared": a schema
    named here MUST declare valid x-traigent-invariants, or this module
    fails closed rather than silently reporting zero violations. Every
    message here is content-free: it names a structural position (a
    declaration's index) or a fixed reason, never an echoed declaration
    value, schema fragment, or jsonschema-library message (which can itself
    embed the offending value).
    """

    code = "invariant_declaration_error"


class InvariantComparisonBoundError(Exception):
    """A compared subtree could not be safely walked: too deep, too wide, or cyclic.

    Raised by the structural comparator itself while walking the two
    subtrees a declaration names, independent of InvariantDeclarationError
    (a schema-authoring problem) and independent of InvariantViolation (an
    ordinary, expected relation failure). A subtree that trips this bound is
    neither validated nor invalidated against the declared relation --
    evaluation is refused outright, content-free (no compared value is ever
    included), rather than silently truncated or left to exhaust the
    interpreter's own call stack.
    """

    code = "invariant_comparison_bound_exceeded"


class InvariantNoncanonicalPayloadError(Exception):
    """A compared subtree is not built purely from canonical JSON built-ins.

    Raised by the same prevalidation pass that enforces
    InvariantComparisonBoundError's depth/width/cycle bounds, for a
    different reason: somewhere in a compared subtree (not necessarily at
    the pointer's own target -- anywhere beneath it) a value is not exactly
    one of dict/list/str/int/float/bool/None, an object key is not exactly
    ``str``, or a float is not finite. A ``dict``/``list``/``str`` SUBCLASS
    is rejected here too, before any of its own ``__eq__``/``__ne__``/
    ``__hash__`` override -- or its metaclass's own
    ``__instancecheck__``/``__subclasscheck__`` -- could run and decide the
    comparison itself; this module only ever calls ``type(x) is ...``, never
    ``isinstance``, and never invokes ``==``/``!=``/membership against a
    value whose exact type has not already been confirmed canonical.

    Every message here is fixed, content-free wording: it never names the
    offending type (not even via ``__name__``, which a hostile class can set
    to embed payload content) and never echoes the offending value or key.
    A payload rejected here is neither validated nor invalidated against the
    declared relation -- evaluation is refused outright, the same posture
    InvariantComparisonBoundError takes for a too-deep/-wide/cyclic subtree.
    """

    code = "invariant_noncanonical_payload"


@dataclass(frozen=True)
class InvariantViolation:
    """One declared invariant that did not hold for a given payload.

    Carries only the invariant's own identity (code, relation, the pointers
    compared) -- never the values found at those pointers, so a violation
    report can be logged or returned to a caller without leaking payload
    content. ``condition_pointer`` is set only for a ``condition_implies_unequal``
    violation (the only relation with a third pointer); it is ``None`` for
    every other relation.
    """

    code: str
    relation: str
    left_pointer: str
    right_pointer: str
    condition_pointer: str | None = None


def _unescape_segment(segment: str) -> str:
    # RFC 6901 escapes, applied in this order: ~1 -> / must be undone before
    # ~0 -> ~ or a literal "~1" in a key would incorrectly become "/".
    return segment.replace("~1", "/").replace("~0", "~")


def _resolve_pointer(payload: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 absolute JSON Pointer against payload.

    Returns the ``_MISSING`` sentinel if any segment along the path is
    absent or the wrong container kind, rather than raising: for a
    presence-requiring relation, a missing pointer is itself a violation,
    not an error the caller must separately guard against.

    Object-member lookup never uses ``in``/``[]`` against the traversed
    dict directly: those operators hash- and equality-compare the segment
    against every STORED key, and if a stored key is a ``str`` subclass
    with an overridden ``__eq__``, Python's comparison protocol runs the
    subclass's method first (its type is the more specific one), even
    though the probe segment itself is a plain ``str``. Instead, every
    candidate key is type-checked (``type(key) is str``) before it is ever
    compared to the segment at all, so a non-``str`` key -- subclass or
    otherwise -- is skipped, never compared, and its ``__eq__`` is never
    invoked, regardless of whether it happens to match by content.

    Array-index lookup accepts only a canonical ASCII index segment
    (``_ARRAY_INDEX_SEGMENT``: ``0`` or ``[1-9][0-9]*``); a segment with a
    leading zero, a sign, a decimal point, interior whitespace, or a
    non-ASCII digit resolves to ``_MISSING`` like any other unresolvable
    segment, not a distinct outcome. ``int()`` is only ever called on a
    segment this regex has already accepted, and even then is guarded: an
    astronomically long (but canonical-looking) digit segment can still trip
    CPython's own separate, version-dependent integer-string-conversion
    digit limit, which raises a raw ``ValueError`` this module must not
    leak -- caught here and treated the same as any other unresolvable
    segment.
    """
    if pointer == "":
        return payload
    if not pointer.startswith("/"):
        raise InvariantDeclarationError("a declared pointer is not an RFC 6901 absolute pointer")

    current = payload
    for raw_segment in pointer.split("/")[1:]:
        segment = _unescape_segment(raw_segment)
        if type(current) is dict:
            match = _MISSING
            for key, value in current.items():
                if type(key) is not str:
                    continue
                if key == segment:
                    match = value
                    break
            if match is _MISSING:
                return _MISSING
            current = match
        elif type(current) is list:
            if not _ARRAY_INDEX_SEGMENT.fullmatch(segment):
                return _MISSING
            try:
                index = int(segment)
            except ValueError:
                return _MISSING
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


# Work-stack entry tags for the iterative prevalidation walk.
_VALIDATE = 0  # visit and canonically validate this node
_LEAVE = 1  # leave a container: drop its identity from the open-path set


def _prevalidate_canonical(root: Any) -> None:
    """Iteratively confirm ``root`` is built purely from canonical JSON built-ins.

    Walks the WHOLE subtree -- not just its root -- admitting only
    dict/list/str/int/float/bool/None, each checked by exact type
    (``type(x) is ...``, never ``isinstance``) so a subclass is rejected
    before any of its own ``__eq__``/``__iter__``/``items()`` override could
    run, mirroring best_config_profile._prevalidate and fp2._encode's own
    exact-type dispatch for exactly the same reason (see those modules).
    Type dispatch happens first for every scalar kind; the depth check is
    reached only after scalars have already been ruled out, exactly as in
    best_config_profile._prevalidate.

    Iterative (explicit work stack), not recursive, for the same
    stack-independence reason fp2._encode and best_config_profile's own
    walk are iterative.

    Cycle detection is path-local (mirroring best_config_profile's
    ``open_ids``): a container's identity is tracked only while its own
    frame is still open, so a DAG -- the same acyclic sub-object reachable
    from two different siblings -- validates cleanly, while a true
    self-reference is rejected rather than looped on.

    Node budget is charged (reserved) for an entire container's children
    BEFORE any of them is pushed onto the work stack: ``len(node)`` (O(1)
    for an exact dict/list -- both track their own length, so this never
    iterates or copies the container just to size it) is checked against
    the remaining budget once per container, strictly before the loop that
    would otherwise enqueue every child. This is what stops a single
    pathologically wide container from first allocating an unbounded
    amount of pending work -- or even touching a single one of its
    children -- before the bound is ever checked.

    Raises:
        InvariantNoncanonicalPayloadError: some value in the subtree is not
            an exact JSON built-in type, an object key is not exactly
            ``str``, or a float is not finite.
        InvariantComparisonBoundError: the subtree nests deeper than
            _MAX_COMPARISON_DEPTH, contains more than _MAX_COMPARISON_NODES
            nodes, or a container reaches itself.
    """
    open_ids: set[int] = set()
    remaining = _MAX_COMPARISON_NODES - 1  # the root itself counts as one node
    work: list[tuple[int, Any, int]] = [(_VALIDATE, root, 1)]

    while work:
        kind, node, depth = work.pop()

        if kind == _LEAVE:
            open_ids.discard(node)
            continue

        if node is None or node is True or node is False:
            continue
        node_type = type(node)
        if node_type is str or node_type is int:
            continue
        if node_type is float:
            if not math.isfinite(node):
                raise InvariantNoncanonicalPayloadError(
                    "a compared subtree contains a non-finite float"
                )
            continue

        if node_type is not dict and node_type is not list:
            raise InvariantNoncanonicalPayloadError(
                "a compared subtree contains a value that is not an exact JSON built-in type"
            )

        if depth > _MAX_COMPARISON_DEPTH:
            raise InvariantComparisonBoundError(
                "invariant comparison exceeded the maximum nesting depth"
            )

        identity = id(node)
        if identity in open_ids:
            raise InvariantComparisonBoundError("invariant comparison found a circular reference")

        size = len(node)
        if size > remaining:
            raise InvariantComparisonBoundError(
                "invariant comparison exceeded the maximum number of discovered nodes"
            )
        remaining -= size
        open_ids.add(identity)
        work.append((_LEAVE, identity, 0))

        if node_type is dict:
            for key, item in node.items():
                if type(key) is not str:
                    raise InvariantNoncanonicalPayloadError(
                        "a compared subtree contains an object key that is not a plain string"
                    )
                work.append((_VALIDATE, item, depth + 1))
        else:
            for item in node:
                work.append((_VALIDATE, item, depth + 1))


def _compare_validated(left: Any, right: Any) -> bool:
    """Deep structural equality between two subtrees already confirmed canonical.

    Callers MUST have already run ``_prevalidate_canonical`` on both
    ``left`` and ``right`` -- this function trusts, and does not re-check,
    that every node on both sides is an exact JSON built-in, every object
    key is an exact ``str``, every float is finite, and neither side is
    cyclic or exceeds the shared depth/node bounds. Because of that
    guarantee, this walk needs no bound bookkeeping of its own: it is
    exactly as deep and as wide as the (already-bounded) left subtree it
    follows.

    ``type(node_left) is not type(node_right)`` is checked before every
    comparison and rejects a type mismatch immediately: an ``int`` must
    never compare equal to an equal-magnitude ``float``, and a ``bool``
    must never compare equal to the ``int`` ``1``. Ordinary Python ``==``
    is used only once both sides are confirmed the same exact canonical
    type, so ``-0.0 == 0.0`` is ``True`` (both exact ``float``) with no
    special-casing needed.
    """
    work: list[tuple[Any, Any]] = [(left, right)]

    while work:
        node_left, node_right = work.pop()

        if type(node_left) is not type(node_right):
            return False
        node_type = type(node_left)

        if node_type is dict:
            if node_left.keys() != node_right.keys():
                return False
            for key in node_left:
                work.append((node_left[key], node_right[key]))
        elif node_type is list:
            if len(node_left) != len(node_right):
                return False
            work.extend(zip(node_left, node_right, strict=True))
        elif node_left != node_right:
            return False

    return True


def _exact_structural_equal(left: Any, right: Any) -> bool:
    """Validate-then-compare exact-type deep structural equality.

    Both ``left`` and ``right`` are FULLY, INDEPENDENTLY confirmed
    canonical (see ``_prevalidate_canonical``) before any comparison
    shortcut -- a key-set mismatch, a length mismatch, a top-level type
    mismatch -- is ever taken. This ordering matters: without it, a
    cyclic/oversized/noncanonical LEFT compared against a trivially empty
    RIGHT could return an ordinary ``False`` (via an early key/length
    mismatch) before the walk ever reached the part of ``left`` that would
    have raised -- silently treating a subtree this module cannot safely
    evaluate as merely "unequal", which is wrong for a relation like
    ``condition_implies_unequal`` (an unequal outcome there is a PASS, not
    a violation). Validating first, unconditionally, before any shortcut
    means a subtree this module cannot safely evaluate is refused outright
    instead.

    Raises:
        InvariantNoncanonicalPayloadError: either subtree contains a value
            that is not an exact JSON built-in type, a non-``str`` object
            key, or a non-finite float.
        InvariantComparisonBoundError: either subtree nests deeper than
            _MAX_COMPARISON_DEPTH, contains more than _MAX_COMPARISON_NODES
            nodes, or a container reaches itself.
    """
    _prevalidate_canonical(left)
    _prevalidate_canonical(right)
    return _compare_validated(left, right)


def _present_and_equal(payload: Any, declaration: dict[str, Any]) -> bool:
    left = _resolve_pointer(payload, declaration["left_pointer"])
    right = _resolve_pointer(payload, declaration["right_pointer"])
    if left is _MISSING or right is _MISSING:
        return False
    return _exact_structural_equal(left, right)


def _selector_lookup_equals_literal(payload: Any, declaration: dict[str, Any]) -> bool:
    selector = _resolve_pointer(payload, declaration["selector_pointer"])
    if type(selector) is not str:
        return False
    mapping = _resolve_pointer(payload, declaration["map_pointer"])
    if type(mapping) is not dict:
        return False
    # Manual scan, not `selector not in mapping` / `mapping[selector]`: those
    # operators hash- and equality-compare selector against every STORED
    # key, and a str-subclass key with an overridden __eq__ would run its
    # own method first (see _resolve_pointer's docstring for the same
    # reasoning). Every candidate key is type-checked before it is ever
    # compared to selector, so a non-str key is skipped, never compared.
    looked_up = _MISSING
    for key, value in mapping.items():
        if type(key) is not str:
            continue
        if key == selector:
            looked_up = value
            break
    if looked_up is _MISSING:
        return False
    return _exact_structural_equal(looked_up, declaration["literal"])


def _condition_implies_unequal(payload: Any, declaration: dict[str, Any]) -> bool:
    condition = _resolve_pointer(payload, declaration["condition_pointer"])
    if condition is not True:
        # One-way: only an exact boolean true triggers the assertion. A
        # missing pointer, false, or any non-boolean value asserts nothing
        # -- there is deliberately no converse rule for the "false" case.
        return True
    left = _resolve_pointer(payload, declaration["left_pointer"])
    right = _resolve_pointer(payload, declaration["right_pointer"])
    if left is _MISSING or right is _MISSING:
        return False
    return not _exact_structural_equal(left, right)


_RELATION_CHECKS = {
    "present_and_equal": _present_and_equal,
    "selector_lookup_equals_literal": _selector_lookup_equals_literal,
    "condition_implies_unequal": _condition_implies_unequal,
}


def _invariants_item_schema() -> dict[str, Any]:
    """Load the closed per-relation ``x-traigent-invariants`` item schema.

    This is the actual governed schema from x_extensions_meta_schema.json,
    not a hand-maintained duplicate of its constraints: a declaration is
    valid here if and only if it is valid there.
    """
    meta_schema = load_schema(_META_SCHEMA_NAME)
    try:
        item_schema: dict[str, Any] = meta_schema["properties"]["x-traigent-invariants"]["items"]
    except (KeyError, TypeError) as error:
        raise InvariantDeclarationError(
            "the x-traigent-invariants meta-schema is missing or malformed"
        ) from error
    return item_schema


def _validate_declaration_shape(
    declaration: Any, index: int, item_schema: dict[str, Any]
) -> None:
    """Validate one declaration against the closed per-relation item schema.

    Raises InvariantDeclarationError, content-free, for every way this can
    fail: the declaration does not match any relation's closed shape, the
    item schema itself is not a valid JSON Schema, or jsonschema raises
    anything else while checking it. jsonschema's own ValidationError
    message can embed the offending declaration value, so it is never
    included here -- only the declaration's structural position (index).
    """
    try:
        validator = Draft7Validator(item_schema)
        is_valid = validator.is_valid(declaration)
    except SchemaError as error:
        raise InvariantDeclarationError(
            "the x-traigent-invariants meta-schema itself is not a valid JSON Schema"
        ) from error
    except Exception as error:  # noqa: BLE001 - must not leak a raw/foreign exception
        raise InvariantDeclarationError(
            f"x-traigent-invariants declaration at index {index} could not be validated"
        ) from error
    if not is_valid:
        raise InvariantDeclarationError(
            f"x-traigent-invariants declaration at index {index} does not match "
            "any closed x-traigent-invariants relation shape"
        )


def _declarations(schema_name: str) -> list[dict[str, Any]]:
    schema = load_schema(schema_name)
    declarations = schema.get("x-traigent-invariants")
    if not isinstance(declarations, list) or not declarations:
        raise InvariantDeclarationError(
            "the named schema declares no x-traigent-invariants; this is a "
            "call-site error (check the schema name), not a payload failure"
        )

    item_schema = _invariants_item_schema()
    for index, declaration in enumerate(declarations):
        _validate_declaration_shape(declaration, index, item_schema)
        if declaration["relation"] not in _RELATION_CHECKS:
            # Unreachable if the meta-schema and _RELATION_CHECKS are kept
            # in sync (every relation's shape fixes "relation" to a const
            # this module also implements) -- kept as a fail-closed
            # backstop rather than trusted silently.
            raise InvariantDeclarationError(
                f"x-traigent-invariants declaration at index {index} names a relation "
                "with no registered interpreter"
            )
    return declarations


def validate_declared_invariants(payload: Any, schema_name: str) -> list[InvariantViolation]:
    """Evaluate ``schema_name``'s declared ``x-traigent-invariants`` against ``payload``.

    ``payload`` must already be a structurally-valid instance of
    ``schema_name``; this function does not itself perform JSON Schema
    validation and treats a pointer that resolves to nothing as a
    violation (for a presence-requiring relation), not a validation error.

    Args:
        payload: An already-parsed value (dict/list/str/int/float/bool/None).
        schema_name: The packaged schema name to load declarations from, in
            the form accepted by :func:`traigent_schema.utils.load_schema`.

    Returns:
        One :class:`InvariantViolation` per declared invariant that did not
        hold. An empty list means every declared invariant held for this
        payload -- see the module docstring for what that does and does not
        imply.

    Raises:
        InvariantDeclarationError: ``schema_name`` declares no
            ``x-traigent-invariants``, or a declaration does not match its
            relation's closed shape. Fails closed rather than silently
            returning no violations for a schema that was never wired up to
            declare any.
        InvariantComparisonBoundError: a compared subtree nests too deep,
            contains too many nodes, or is circular.
        InvariantNoncanonicalPayloadError: a compared subtree contains a
            value that is not an exact JSON built-in type, a non-``str``
            object key, or a non-finite float.
    """
    violations: list[InvariantViolation] = []
    for declaration in _declarations(schema_name):
        check = _RELATION_CHECKS[declaration["relation"]]
        if not check(payload, declaration):
            violations.append(
                InvariantViolation(
                    code=declaration["code"],
                    relation=declaration["relation"],
                    left_pointer=declaration.get(
                        "left_pointer", declaration.get("selector_pointer", "")
                    ),
                    right_pointer=declaration.get(
                        "right_pointer", declaration.get("map_pointer", "")
                    ),
                    condition_pointer=declaration.get("condition_pointer"),
                )
            )
    return violations
