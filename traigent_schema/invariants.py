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

from dataclasses import dataclass
from typing import Any

from jsonschema import Draft7Validator
from jsonschema.exceptions import SchemaError

from .utils import load_schema

__all__ = ["InvariantViolation", "validate_declared_invariants"]

_MISSING = object()

_META_SCHEMA_NAME = "x_extensions_meta_schema"

# Shared with fp2/best_config_profile's own nesting bound: a comparison walk
# must reject at the same magnitude those modules already do, not invent an
# unrelated number. See fp2.py's MAX_DEPTH docstring for why 100 specifically.
_MAX_COMPARISON_DEPTH = 100

# A generous bound on how many (left, right) node pairs one comparison may
# visit. Real declared-invariant targets are small schema-bounded subtrees;
# this exists only so a pathologically wide (not necessarily deep) hostile
# subtree cannot make a single comparison do unbounded work.
_MAX_COMPARISON_NODES = 100_000


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


def _unescape_token(token: str) -> str:
    # RFC 6901 escapes, applied in this order: ~1 -> / must be undone before
    # ~0 -> ~ or a literal "~1" in a key would incorrectly become "/".
    return token.replace("~1", "/").replace("~0", "~")


def _resolve_pointer(payload: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 absolute JSON Pointer against payload.

    Returns the ``_MISSING`` sentinel if any segment along the path is
    absent or the wrong container kind, rather than raising: for a
    presence-requiring relation, a missing pointer is itself a violation,
    not an error the caller must separately guard against.
    """
    if pointer == "":
        return payload
    if not pointer.startswith("/"):
        raise InvariantDeclarationError("a declared pointer is not an RFC 6901 absolute pointer")

    current = payload
    for raw_token in pointer.split("/")[1:]:
        token = _unescape_token(raw_token)
        if type(current) is dict:
            if token not in current:
                return _MISSING
            current = current[token]
        elif type(current) is list:
            if not token.isdigit():
                return _MISSING
            index = int(token)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


# Work-stack entry tags for the iterative comparison walk.
_VALUE = 0  # visit and compare this (left, right) pair
_CLOSE = 1  # leave a container pair: drop its identity from the open-path sets


def _exact_structural_equal(left: Any, right: Any) -> bool:
    """Exact-type, deep structural equality over parsed-JSON exact built-ins.

    Iterative (explicit work stack), not recursive: the result must be a
    property of the two subtrees alone, not of how much interpreter stack
    the caller happened to have left, mirroring fp2._encode and
    best_config_profile._prevalidate's own iterative walks for exactly the
    same reason (see fp2.py, best_config_profile.py).

    ``type(left) is type(right)`` is checked before every comparison, at
    every depth, and rejects a mismatch immediately: a bool must never
    compare equal to the int 1, and a dict/list/str subclass with an
    overridden ``__eq__`` must never decide the answer -- the same
    exact-type discipline fp2 and best_config_profile both use.

    Cycle detection is path-local per side (mirroring
    best_config_profile._prevalidate's ``open_ids``): a container's
    identity is tracked only while its own frame, on its own side, is
    still open, so the same acyclic sub-object reachable from two
    siblings on one side compares cleanly against the other side, while a
    true self-reference on either side is rejected rather than looped on.

    Raises:
        InvariantComparisonBoundError: either subtree nests deeper than
            _MAX_COMPARISON_DEPTH, the walk visits more than
            _MAX_COMPARISON_NODES pairs, or a container on either side
            reaches itself.
    """
    work: list[tuple[int, Any, Any, int]] = [(_VALUE, left, right, 1)]
    open_left_ids: set[int] = set()
    open_right_ids: set[int] = set()
    visited = 0

    while work:
        kind, node_left, node_right, depth = work.pop()

        if kind == _CLOSE:
            open_left_ids.discard(node_left)
            open_right_ids.discard(node_right)
            continue

        visited += 1
        if visited > _MAX_COMPARISON_NODES:
            raise InvariantComparisonBoundError(
                "invariant comparison exceeded the maximum number of compared node pairs"
            )
        if depth > _MAX_COMPARISON_DEPTH:
            raise InvariantComparisonBoundError(
                "invariant comparison exceeded the maximum nesting depth"
            )

        if type(node_left) is not type(node_right):
            return False

        node_type = type(node_left)

        if node_type is dict:
            if node_left.keys() != node_right.keys():
                return False
            left_id, right_id = id(node_left), id(node_right)
            if left_id in open_left_ids or right_id in open_right_ids:
                raise InvariantComparisonBoundError(
                    "invariant comparison found a circular reference"
                )
            open_left_ids.add(left_id)
            open_right_ids.add(right_id)
            work.append((_CLOSE, left_id, right_id, 0))
            for key in node_left:
                work.append((_VALUE, node_left[key], node_right[key], depth + 1))
        elif node_type is list:
            if len(node_left) != len(node_right):
                return False
            left_id, right_id = id(node_left), id(node_right)
            if left_id in open_left_ids or right_id in open_right_ids:
                raise InvariantComparisonBoundError(
                    "invariant comparison found a circular reference"
                )
            open_left_ids.add(left_id)
            open_right_ids.add(right_id)
            work.append((_CLOSE, left_id, right_id, 0))
            for item_left, item_right in zip(node_left, node_right):
                work.append((_VALUE, item_left, item_right, depth + 1))
        elif node_left != node_right:
            return False

    return True


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
    if type(mapping) is not dict or selector not in mapping:
        return False
    return _exact_structural_equal(mapping[selector], declaration["literal"])


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
            visits too many node pairs, or is circular.
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
