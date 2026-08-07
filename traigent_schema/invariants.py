# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Generic interpreter for a schema's declared ``x-traigent-invariants``.

Normative document: traigent_schema/schemas/x_extensions_meta_schema.json
(the ``x-traigent-invariants`` entry).

Draft-07 JSON Schema has no keyword for asserting that two fields -- often
siblings in independently-validated subtrees, or fields composed in from
different ``allOf`` branches -- must hold equal values. A payload can be
fully schema-valid while two fields that are supposed to always agree have
silently diverged. Rather than leave that gap undocumented, a schema
declares each such invariant as data (``x-traigent-invariants``), and this
module evaluates those declarations against an already structurally-valid
parsed instance.

Boundary, stated so it is not over-read: this checks structural consistency
between two named locations in a payload only. It is not a cryptographic
certificate validity check, not an eligibility or optimality claim, and not
an authorization decision. A payload with zero violations has not thereby
been certified, made eligible, or authorized for anything -- it has only
been shown internally consistent on the specific pairs its schema declares.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import load_schema

__all__ = ["InvariantViolation", "validate_declared_invariants"]

_MISSING = object()

_DECLARATION_KEYS = ("code", "relation", "left_pointer", "right_pointer")


class InvariantDeclarationError(Exception):
    """A schema's x-traigent-invariants declarations are missing or malformed.

    Raised for a call-site/schema-authoring error, never for a payload that
    fails an invariant -- that outcome is an InvariantViolation, not an
    exception. There is no fallback to "no invariants declared": a schema
    named here MUST declare valid x-traigent-invariants, or this module
    fails closed rather than silently reporting zero violations.
    """


@dataclass(frozen=True)
class InvariantViolation:
    """One declared invariant that did not hold for a given payload.

    Carries only the invariant's own identity (code, relation, the two
    pointers compared) -- never the values found at those pointers, so a
    violation report can be logged or returned to a caller without leaking
    payload content.
    """

    code: str
    relation: str
    left_pointer: str
    right_pointer: str


def _unescape_token(token: str) -> str:
    # RFC 6901 escapes, applied in this order: ~1 -> / must be undone before
    # ~0 -> ~ or a literal "~1" in a key would incorrectly become "/".
    return token.replace("~1", "/").replace("~0", "~")


def _resolve_pointer(payload: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 absolute JSON Pointer against payload.

    Returns the ``_MISSING`` sentinel if any segment along the path is
    absent or the wrong container kind, rather than raising: for
    ``present_and_equal``, a missing pointer is itself a violation, not an
    error the caller must separately guard against.
    """
    if pointer == "":
        return payload
    if not pointer.startswith("/"):
        raise InvariantDeclarationError(f"not an RFC 6901 absolute JSON pointer: {pointer!r}")

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


def _exact_structural_equal(left: Any, right: Any) -> bool:
    """Exact-type, deep structural equality over parsed-JSON exact built-ins.

    type(left) is type(right) is checked first and rejects mismatches
    immediately: a bool must never compare equal to the int 1, and a
    dict/list/str subclass with an overridden __eq__ must never decide the
    answer, mirroring the exact-type discipline fp2 and best_config_profile
    both use for the same reason (see fp2.py, best_config_profile.py).
    """
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        if left.keys() != right.keys():
            return False
        return all(_exact_structural_equal(left[key], right[key]) for key in left)
    if type(left) is list:
        if len(left) != len(right):
            return False
        return all(_exact_structural_equal(a, b) for a, b in zip(left, right))
    return left == right


def _present_and_equal(payload: Any, left_pointer: str, right_pointer: str) -> bool:
    left = _resolve_pointer(payload, left_pointer)
    right = _resolve_pointer(payload, right_pointer)
    if left is _MISSING or right is _MISSING:
        return False
    return _exact_structural_equal(left, right)


_RELATION_CHECKS = {
    "present_and_equal": _present_and_equal,
}


def _declarations(schema_name: str) -> list[dict[str, Any]]:
    schema = load_schema(schema_name)
    declarations = schema.get("x-traigent-invariants")
    if not isinstance(declarations, list) or not declarations:
        raise InvariantDeclarationError(
            f"{schema_name!r} declares no x-traigent-invariants; this is a "
            "call-site error (check the schema name), not a payload failure"
        )
    for declaration in declarations:
        if not isinstance(declaration, dict):
            raise InvariantDeclarationError(
                f"{schema_name!r}: x-traigent-invariants entry is not an object: {declaration!r}"
            )
        missing_keys = [key for key in _DECLARATION_KEYS if key not in declaration]
        if missing_keys:
            raise InvariantDeclarationError(
                f"{schema_name!r}: x-traigent-invariants entry missing key(s) {missing_keys}"
            )
        if declaration["relation"] not in _RELATION_CHECKS:
            raise InvariantDeclarationError(
                f"{schema_name!r}: unknown invariant relation {declaration['relation']!r}"
            )
    return declarations


def validate_declared_invariants(payload: Any, schema_name: str) -> list[InvariantViolation]:
    """Evaluate ``schema_name``'s declared ``x-traigent-invariants`` against ``payload``.

    ``payload`` must already be a structurally-valid instance of
    ``schema_name``; this function does not itself perform JSON Schema
    validation and treats a pointer that resolves to nothing as a
    violation, not a validation error.

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
            ``x-traigent-invariants``, or a declaration is malformed
            (missing key, unknown relation). Fails closed rather than
            silently returning no violations for a schema that was never
            wired up to declare any.
    """
    violations: list[InvariantViolation] = []
    for declaration in _declarations(schema_name):
        check = _RELATION_CHECKS[declaration["relation"]]
        if not check(payload, declaration["left_pointer"], declaration["right_pointer"]):
            violations.append(
                InvariantViolation(
                    code=declaration["code"],
                    relation=declaration["relation"],
                    left_pointer=declaration["left_pointer"],
                    right_pointer=declaration["right_pointer"],
                )
            )
    return violations
