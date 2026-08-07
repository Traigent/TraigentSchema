# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Tests for traigent_schema/invariants.py, the x-traigent-invariants interpreter.

Separate from any one schema's own contract tests: this file proves the
GENERIC interpreter's own pointer-resolution, equality, and fail-closed
declaration handling, using small synthetic schemas/payloads rather than
the real shadow_evaluate_response/guarantee_certificate_v2 declarations
(those are covered where they are declared, in
tests/test_smartops_v2_contracts.py and tests/test_evidence_case_contract.py).
"""

from __future__ import annotations

from typing import Any

import pytest

import traigent_schema as public_schema
import traigent_schema.invariants as invariants_module
from traigent_schema import (
    InvariantComparisonBoundError,
    InvariantDeclarationError,
    InvariantNoncanonicalPayloadError,
    InvariantViolation,
    validate_declared_invariants,
)
from traigent_schema.invariants import (
    _ARRAY_INDEX_TOKEN,
    _MAX_COMPARISON_NODES,
    _META_SCHEMA_NAME,
    _MISSING,
    _exact_structural_equal,
    _prevalidate_canonical,
    _resolve_pointer,
)
from traigent_schema.utils import load_schema as _real_load_schema


def test_public_invariant_exceptions_are_the_submodule_classes() -> None:
    expected_exports = {
        "InvariantComparisonBoundError",
        "InvariantDeclarationError",
        "InvariantNoncanonicalPayloadError",
    }
    assert expected_exports <= set(public_schema.__all__)
    assert expected_exports <= set(invariants_module.__all__)
    assert InvariantComparisonBoundError is invariants_module.InvariantComparisonBoundError
    assert InvariantDeclarationError is invariants_module.InvariantDeclarationError
    assert InvariantNoncanonicalPayloadError is invariants_module.InvariantNoncanonicalPayloadError

# --- pointer resolution -------------------------------------------------------


def test_resolves_a_nested_pointer() -> None:
    payload = {"a": {"b": [10, 20, {"c": "value"}]}}
    assert _resolve_pointer(payload, "/a/b/2/c") == "value"


def test_empty_pointer_resolves_to_the_root() -> None:
    payload = {"a": 1}
    assert _resolve_pointer(payload, "") is payload


def test_missing_object_member_resolves_to_missing_sentinel() -> None:
    assert _resolve_pointer({"a": 1}, "/b") is _MISSING


def test_out_of_range_array_index_resolves_to_missing_sentinel() -> None:
    assert _resolve_pointer({"a": [1, 2]}, "/a/5") is _MISSING


def test_pointer_through_a_scalar_resolves_to_missing_sentinel() -> None:
    assert _resolve_pointer({"a": 1}, "/a/b") is _MISSING


def test_pointer_unescapes_rfc6901_tilde_and_slash() -> None:
    payload = {"a/b": 1, "c~d": 2}
    assert _resolve_pointer(payload, "/a~1b") == 1
    assert _resolve_pointer(payload, "/c~0d") == 2


def test_relative_pointer_is_rejected() -> None:
    with pytest.raises(InvariantDeclarationError):
        _resolve_pointer({"a": 1}, "a")


# --- array-index pointer tokens: canonical ASCII only --------------------------


@pytest.mark.parametrize(
    "token, is_canonical",
    [
        ("0", True),
        ("1", True),
        ("10", True),
        ("9" * 40, True),  # canonical syntax; magnitude is a separate, out-of-range question
        ("01", False),  # leading zero
        ("-", False),
        ("-1", False),  # sign
        ("+1", False),  # sign
        ("1.0", False),  # decimal point
        (" 1", False),  # interior whitespace
        ("1 ", False),  # interior whitespace
        ("٠", False),  # ARABIC-INDIC DIGIT ZERO: str.isdigit() is True, not ASCII
        ("²", False),  # SUPERSCRIPT TWO: str.isdigit() is True, int() raises ValueError
    ],
)
def test_array_index_token_canonicality_table(token: str, is_canonical: bool) -> None:
    assert (_ARRAY_INDEX_TOKEN.fullmatch(token) is not None) is is_canonical


def test_leading_zero_array_index_does_not_resolve_despite_being_int_parseable() -> None:
    """int("01") == 1, an in-range index -- but "01" is not a canonical token."""
    payload = {"items": ["first", "second"]}
    assert _resolve_pointer(payload, "/items/01") is _MISSING


def test_unicode_digit_array_index_does_not_resolve_despite_str_isdigit_true() -> None:
    assert "٠".isdigit()  # sanity: this is exactly the trap str.isdigit() sets
    payload = {"items": ["first", "second"]}
    assert _resolve_pointer(payload, "/items/٠") is _MISSING


def test_superscript_digit_array_index_does_not_raise_a_raw_value_error() -> None:
    assert "²".isdigit()  # sanity: str.isdigit() is True but int() raises ValueError
    payload = {"items": ["first", "second"]}
    assert _resolve_pointer(payload, "/items/²") is _MISSING


def test_unicode_digit_token_is_a_valid_object_key_pointer_unlike_an_array_index() -> None:
    """The array-index regex narrows only LIST traversal.

    An OBJECT member literally named with the same-looking Unicode digit is
    an ordinary string key and resolves normally -- this is the asymmetry
    the meta-schema's own pointer syntax regex (unchanged, unnarrowed by
    this fix) already allows for object member names, which may legitimately
    look like a non-canonical number.
    """
    payload = {"٠": "value-for-unicode-key"}
    assert _resolve_pointer(payload, "/٠") == "value-for-unicode-key"


def test_pointer_through_a_huge_digit_token_does_not_raise_a_raw_value_error() -> None:
    """CPython's own (separate, version-dependent) int-string conversion
    digit limit must never leak as a raw ValueError through this module."""
    payload = {"items": ["first", "second"]}
    huge_token = "9" * 5000
    assert _resolve_pointer(payload, f"/items/{huge_token}") is _MISSING


# --- declaration loading: fail closed -----------------------------------------


def _patch_declarations(
    monkeypatch: pytest.MonkeyPatch, declarations: list[dict[str, Any]] | object
) -> None:
    """Patch ``load_schema`` so ``schema_name`` gets a fake schema while the
    real x-traigent-invariants meta-schema is still loaded from disk.

    ``validate_declared_invariants`` loads two different schemas by name
    -- the caller's ``schema_name`` and, internally, the governing
    x_extensions_meta_schema.json -- so a single unconditional monkeypatch
    would also replace the meta-schema and make every declaration look
    malformed against a payload-shaped dict. This dispatches by name
    instead, matching what the real module does at runtime.
    """
    import traigent_schema.invariants as invariants_module

    def fake_load_schema(name: str) -> dict[str, Any]:
        if name == _META_SCHEMA_NAME:
            return _real_load_schema(name)
        return {"x-traigent-invariants": declarations}

    monkeypatch.setattr(invariants_module, "load_schema", fake_load_schema)


def test_unknown_schema_name_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Exception):  # noqa: B017 - load_schema's own FileNotFoundError
        validate_declared_invariants({}, "definitely_not_a_real_schema")


def test_schema_without_declared_invariants_fails_closed() -> None:
    """A real, existing schema that happens to declare none must not silently pass."""
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "best_config_v2_schema")


def test_malformed_declaration_missing_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, [{"code": "X", "relation": "present_and_equal"}])
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_malformed_declaration_unknown_relation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(
        monkeypatch,
        [
            {
                "code": "X",
                "relation": "greater_than",
                "left_pointer": "/a",
                "right_pointer": "/b",
                "description": "unsupported relation",
            }
        ],
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_malformed_declaration_extra_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The closed per-relation shape rejects additional properties too."""
    _patch_declarations(
        monkeypatch,
        [
            {
                "code": "X",
                "relation": "present_and_equal",
                "left_pointer": "/a",
                "right_pointer": "/b",
                "description": "d",
                "unexpected": "nope",
            }
        ],
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_malformed_declaration_wrong_relation_fields_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A selector_lookup_equals_literal declaration missing its own required keys."""
    _patch_declarations(
        monkeypatch,
        [
            {
                "code": "X",
                "relation": "selector_lookup_equals_literal",
                "left_pointer": "/a",
                "right_pointer": "/b",
                "description": "wrong shape for this relation",
            }
        ],
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_malformed_declaration_error_is_content_free(monkeypatch: pytest.MonkeyPatch) -> None:
    """The raised error never echoes the declaration's own values."""
    _patch_declarations(
        monkeypatch,
        [
            {
                "code": "X",
                "relation": "present_and_equal",
                "left_pointer": "/a",
                "right_pointer": "/b",
                "description": "SECRET_CANARY_VALUE_ZZZ",
                "extra": "SECRET_CANARY_VALUE_ZZZ",
            }
        ],
    )
    with pytest.raises(InvariantDeclarationError) as excinfo:
        validate_declared_invariants({}, "irrelevant")
    assert "SECRET_CANARY_VALUE_ZZZ" not in str(excinfo.value)


def test_malformed_meta_schema_itself_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """If x_extensions_meta_schema.json itself is unusable, fail closed, not open."""
    import traigent_schema.invariants as invariants_module

    def fake_load_schema(name: str) -> dict[str, Any]:
        if name == _META_SCHEMA_NAME:
            return {"not": "the expected shape"}
        return {"x-traigent-invariants": _ONE_DECLARATION}

    monkeypatch.setattr(invariants_module, "load_schema", fake_load_schema)
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({"a": 1, "b": 1}, "irrelevant")


def test_declarations_that_are_not_a_list_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, "not-a-list")  # type: ignore[arg-type]
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


# --- present_and_equal: satisfied, violated, missing --------------------------


_ONE_DECLARATION = [
    {
        "code": "A_MATCHES_B",
        "relation": "present_and_equal",
        "left_pointer": "/a",
        "right_pointer": "/b",
        "description": "a and b must agree",
    }
]


def test_present_and_equal_holds_when_values_match(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    assert validate_declared_invariants({"a": "x", "b": "x"}, "irrelevant") == []


def test_present_and_equal_violated_when_values_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    violations = validate_declared_invariants({"a": "x", "b": "y"}, "irrelevant")
    assert violations == [
        InvariantViolation(
            code="A_MATCHES_B",
            relation="present_and_equal",
            left_pointer="/a",
            right_pointer="/b",
        )
    ]


def test_present_and_equal_violated_when_one_side_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    violations = validate_declared_invariants({"a": "x"}, "irrelevant")
    assert len(violations) == 1
    assert violations[0].code == "A_MATCHES_B"


def test_present_and_equal_violated_when_both_sides_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing/missing is a violation, not a vacuous pass."""
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    violations = validate_declared_invariants({}, "irrelevant")
    assert len(violations) == 1


def test_present_and_equal_uses_exact_type_equality(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bool must never compare equal to the int 1 -- exact-type discipline."""
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    violations = validate_declared_invariants({"a": True, "b": 1}, "irrelevant")
    assert len(violations) == 1


def test_present_and_equal_deep_structural_equality_for_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    equal_nested = {"a": {"x": [1, 2, {"y": "z"}]}, "b": {"x": [1, 2, {"y": "z"}]}}
    assert validate_declared_invariants(equal_nested, "irrelevant") == []

    unequal_nested = {"a": {"x": [1, 2, {"y": "z"}]}, "b": {"x": [1, 2, {"y": "different"}]}}
    assert len(validate_declared_invariants(unequal_nested, "irrelevant")) == 1


def test_violation_never_carries_the_actual_values() -> None:
    violation = InvariantViolation(
        code="X", relation="present_and_equal", left_pointer="/a", right_pointer="/b"
    )
    assert not hasattr(violation, "left_value")
    assert not hasattr(violation, "right_value")
    assert "SECRET" not in repr(violation)


def test_violation_condition_pointer_defaults_to_none() -> None:
    violation = InvariantViolation(
        code="X", relation="present_and_equal", left_pointer="/a", right_pointer="/b"
    )
    assert violation.condition_pointer is None


def test_multiple_declarations_each_evaluated_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declarations = [
        {
            "code": "FIRST",
            "relation": "present_and_equal",
            "left_pointer": "/a",
            "right_pointer": "/b",
            "description": "first",
        },
        {
            "code": "SECOND",
            "relation": "present_and_equal",
            "left_pointer": "/c",
            "right_pointer": "/d",
            "description": "second",
        },
    ]
    _patch_declarations(monkeypatch, declarations)
    violations = validate_declared_invariants({"a": 1, "b": 1, "c": 1, "d": 2}, "irrelevant")
    assert [v.code for v in violations] == ["SECOND"]


# --- selector_lookup_equals_literal: satisfied, violated, missing -------------


_LOOKUP_DECLARATION = [
    {
        "code": "SELECTED_MAPS_TO_SELECTED",
        "relation": "selector_lookup_equals_literal",
        "selector_pointer": "/selected_id",
        "map_pointer": "/per_candidate",
        "literal": "selected",
        "description": "per_candidate[selected_id] must read 'selected'",
    }
]


def test_selector_lookup_holds_when_the_looked_up_value_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    payload = {"selected_id": "C1", "per_candidate": {"C1": "selected", "C2": "feasible"}}
    assert validate_declared_invariants(payload, "irrelevant") == []


def test_selector_lookup_violated_when_the_looked_up_value_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    payload = {"selected_id": "C1", "per_candidate": {"C1": "feasible"}}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert [v.code for v in violations] == ["SELECTED_MAPS_TO_SELECTED"]


def test_selector_lookup_violated_when_selector_key_is_absent_from_the_map(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    payload = {"selected_id": "C1", "per_candidate": {"C2": "selected"}}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert len(violations) == 1


def test_selector_lookup_violated_when_selector_pointer_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    violations = validate_declared_invariants({"per_candidate": {"C1": "selected"}}, "irrelevant")
    assert len(violations) == 1


def test_selector_lookup_violated_when_selector_is_not_a_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dynamic key must itself be an exact str -- an int/bool selector is never usable."""
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    payload = {"selected_id": 1, "per_candidate": {"1": "selected"}}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert len(violations) == 1


def test_selector_lookup_violated_when_map_pointer_is_not_a_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    payload = {"selected_id": "C1", "per_candidate": ["not", "a", "dict"]}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert len(violations) == 1


# --- pointer traversal / selector lookup: stored-key hooks never fire ---------


class _FlaggedStr(str):
    """A str subclass whose __eq__ sets a class-level flag when invoked.

    Unlike a plain assertion inside __eq__, a flag lets a test make a
    positive assertion ("this hook stayed unset") rather than only proving
    absence of a crash.
    """

    eq_called = False

    def __eq__(self, other: object) -> bool:
        type(self).eq_called = True
        return str.__eq__(self, other)

    def __hash__(self) -> int:
        return str.__hash__(self)


def test_pointer_traversal_never_invokes_a_stored_subclass_keys_eq() -> None:
    _FlaggedStr.eq_called = False
    decoy = _FlaggedStr("b")
    payload = {"a": 1, decoy: "decoy-value"}

    assert _resolve_pointer(payload, "/a") == 1
    # The decoy key is skipped by type before ever being compared to "b" --
    # if it were compared, __eq__ would have set the flag regardless of
    # whether the comparison happened to match.
    assert _resolve_pointer(payload, "/b") is _MISSING
    assert _FlaggedStr.eq_called is False


def test_selector_lookup_never_invokes_a_stored_subclass_keys_eq(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FlaggedStr.eq_called = False
    _patch_declarations(monkeypatch, _LOOKUP_DECLARATION)
    decoy = _FlaggedStr("C2")
    payload = {"selected_id": "C1", "per_candidate": {"C1": "selected", decoy: "decoy-value"}}

    assert validate_declared_invariants(payload, "irrelevant") == []
    assert _FlaggedStr.eq_called is False


# --- condition_implies_unequal: one-way, no converse ---------------------------


_CONDITIONAL_DECLARATION = [
    {
        "code": "DISAGREES_IMPLIES_DIVERGE",
        "relation": "condition_implies_unequal",
        "condition_pointer": "/disagrees",
        "left_pointer": "/rules",
        "right_pointer": "/policy",
        "description": "disagrees=true implies rules and policy structurally diverge",
    }
]


def test_condition_true_and_values_differ_has_no_violation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"disagrees": True, "rules": {"a": 1}, "policy": {"a": 2}}
    assert validate_declared_invariants(payload, "irrelevant") == []


def test_condition_true_and_values_equal_is_violated(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"disagrees": True, "rules": {"a": 1}, "policy": {"a": 1}}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert [v.code for v in violations] == ["DISAGREES_IMPLIES_DIVERGE"]
    assert violations[0].condition_pointer == "/disagrees"
    assert violations[0].left_pointer == "/rules"
    assert violations[0].right_pointer == "/policy"


def test_condition_false_asserts_nothing_even_when_values_are_equal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One-way: the false branch has no converse rule."""
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"disagrees": False, "rules": {"a": 1}, "policy": {"a": 1}}
    assert validate_declared_invariants(payload, "irrelevant") == []


def test_condition_missing_asserts_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"rules": {"a": 1}, "policy": {"a": 1}}
    assert validate_declared_invariants(payload, "irrelevant") == []


def test_condition_truthy_but_not_exactly_bool_true_asserts_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exact-type discipline: the int 1 is not the condition boolean True."""
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"disagrees": 1, "rules": {"a": 1}, "policy": {"a": 1}}
    assert validate_declared_invariants(payload, "irrelevant") == []


def test_condition_true_but_one_side_missing_is_violated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    payload = {"disagrees": True, "rules": {"a": 1}}
    violations = validate_declared_invariants(payload, "irrelevant")
    assert len(violations) == 1


def test_condition_true_with_cyclic_left_and_empty_right_raises_typed_not_a_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: cyclic-vs-empty must raise, not silently satisfy the relation.

    Before validate-then-compare, a naive comparator could take a
    key-count/length mismatch shortcut ("cyclic dict has 2 keys, {} has 0")
    and return an ordinary False (unequal) before ever walking far enough
    into ``left`` to notice it is cyclic. For condition_implies_unequal,
    "unequal" is a PASS -- so that bug would have silently reported this
    payload as satisfying the invariant, when the correct outcome is that
    the payload could not be safely evaluated at all.
    """
    _patch_declarations(monkeypatch, _CONDITIONAL_DECLARATION)
    cyclic: dict[str, Any] = {"x": 1}
    cyclic["self"] = cyclic
    payload = {"disagrees": True, "rules": cyclic, "policy": {}}
    with pytest.raises(InvariantComparisonBoundError):
        validate_declared_invariants(payload, "irrelevant")


# --- hostile payloads: deep, cyclic, wide, subclassed --------------------------


def test_deeply_nested_equal_containers_are_bounded_not_stack_exhausted() -> None:
    nested: Any = "leaf"
    for _ in range(5000):
        nested = [nested]
    with pytest.raises(InvariantComparisonBoundError):
        _exact_structural_equal(nested, nested)


def _nest(n: int) -> Any:
    value: Any = "leaf"
    for _ in range(n):
        value = [value]
    return value


def test_nesting_at_99_containers_is_accepted() -> None:
    assert _exact_structural_equal(_nest(99), _nest(99)) is True


def test_nesting_at_100_containers_is_accepted() -> None:
    assert _exact_structural_equal(_nest(100), _nest(100)) is True


def test_nesting_at_101_containers_is_rejected() -> None:
    with pytest.raises(InvariantComparisonBoundError):
        _exact_structural_equal(_nest(101), _nest(101))


def test_huge_first_level_container_is_refused_before_children_are_inspected() -> None:
    """The node-count bound is charged before any child is individually visited.

    Every element is a "poison" value (a bare ``set()``) that would raise
    InvariantNoncanonicalPayloadError -- the per-child TYPE check -- if it
    were ever individually type-checked. Getting
    InvariantComparisonBoundError (the SIZE check) instead proves the
    oversized container was refused on its length before a single one of
    its children was pushed onto the work stack or inspected.
    """
    poison: Any = set()
    huge = [poison] * (_MAX_COMPARISON_NODES + 1)
    with pytest.raises(InvariantComparisonBoundError):
        _prevalidate_canonical(huge)


def test_hostile_subtree_at_a_declared_pointer_raises_through_the_public_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bound applies through validate_declared_invariants too, not just
    to direct callers of the internal comparator."""
    _patch_declarations(monkeypatch, _ONE_DECLARATION)
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    with pytest.raises(InvariantComparisonBoundError):
        validate_declared_invariants({"a": cyclic, "b": cyclic}, "irrelevant")


def test_self_referential_container_is_rejected_not_looped_on() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    with pytest.raises(InvariantComparisonBoundError):
        _exact_structural_equal(cyclic, cyclic)


def test_mutual_cycle_between_two_containers_is_rejected() -> None:
    left: dict[str, Any] = {}
    right: dict[str, Any] = {}
    left["self"] = left
    right["self"] = right
    with pytest.raises(InvariantComparisonBoundError):
        _exact_structural_equal(left, right)


def test_shared_acyclic_substructure_is_not_flagged_as_a_cycle() -> None:
    """The same acyclic sub-object reachable from two siblings must still compare cleanly."""
    shared = {"x": 1}
    left = {"a": shared, "b": shared}
    right = {"a": {"x": 1}, "b": {"x": 1}}
    assert _exact_structural_equal(left, right) is True


def test_wide_payload_within_the_node_bound_still_compares() -> None:
    wide = {str(i): i for i in range(1000)}
    assert _exact_structural_equal(wide, dict(wide)) is True


def test_comparison_bound_error_is_content_free() -> None:
    cyclic: list[Any] = ["SECRET_CANARY_VALUE_ZZZ"]
    cyclic.append(cyclic)
    with pytest.raises(InvariantComparisonBoundError) as excinfo:
        _exact_structural_equal(cyclic, cyclic)
    assert "SECRET_CANARY_VALUE_ZZZ" not in str(excinfo.value)


class _SneakyDict(dict):
    def keys(self) -> Any:  # type: ignore[override]
        raise AssertionError("subclass override must never be invoked")


class _SneakyList(list):
    def __iter__(self) -> Any:  # type: ignore[override]
        raise AssertionError("subclass override must never be invoked")


class _SneakyStr(str):
    def __eq__(self, other: object) -> bool:
        raise AssertionError("subclass override must never be invoked")

    def __hash__(self) -> int:
        return super().__hash__()


def test_dict_subclass_is_rejected_as_noncanonical_never_via_its_own_overrides() -> None:
    sneaky = _SneakyDict(a=1)
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(sneaky, {"a": 1})
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal({"a": 1}, sneaky)


def test_list_subclass_is_rejected_as_noncanonical_never_via_its_own_overrides() -> None:
    sneaky = _SneakyList([1, 2])
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(sneaky, [1, 2])
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal([1, 2], sneaky)


def test_str_subclass_is_rejected_as_noncanonical_never_via_its_own_overrides() -> None:
    sneaky = _SneakyStr("x")
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(sneaky, "x")
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal("x", sneaky)


def test_same_subclass_leaves_still_raise_noncanonical_not_compared_via_eq() -> None:
    """Two leaves of the exact SAME subclass must not slip through equal.

    ``type(left) is type(right)`` would be True here (both _SneakyStr), so
    a comparator that validated only AFTER a type-match shortcut could fall
    through to comparing them with ``==`` -- which is exactly the
    subclass's own overridden, hook-triggering __eq__ (it raises
    AssertionError if invoked). Getting InvariantNoncanonicalPayloadError,
    not AssertionError, proves prevalidation ran first and __eq__ was never
    reached at all.
    """
    left = _SneakyStr("x")
    right = _SneakyStr("x")
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(left, right)


def test_same_subclass_dict_leaves_still_raise_noncanonical_not_compared_via_keys() -> None:
    left = _SneakyDict(a=1)
    right = _SneakyDict(a=1)
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(left, right)


def test_dict_with_a_subclass_key_is_rejected_as_noncanonical() -> None:
    """The container is an exact dict; only one KEY inside it is a subclass."""
    with_bad_key = {_SneakyStr("k"): 1}
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(with_bad_key, {"k": 1})


def test_bool_never_equals_the_int_one() -> None:
    assert _exact_structural_equal(True, 1) is False
    assert _exact_structural_equal(False, 0) is False


def test_int_never_equals_an_equal_magnitude_float() -> None:
    assert _exact_structural_equal(1, 1.0) is False


def test_negative_zero_float_equals_positive_zero_float() -> None:
    assert _exact_structural_equal(-0.0, 0.0) is True


def test_non_finite_float_is_rejected_as_noncanonical() -> None:
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(float("nan"), float("nan"))
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(float("inf"), float("inf"))


def test_noncanonical_payload_error_is_content_free() -> None:
    class _Odd:
        pass

    with pytest.raises(InvariantNoncanonicalPayloadError) as excinfo:
        _exact_structural_equal({"k": _Odd()}, {"k": 1})
    assert "_Odd" not in str(excinfo.value)
    assert "Odd" not in str(excinfo.value)


class _SECRET_CANARY_CLASS_NAME:  # noqa: N801 - the unusual name IS the test
    pass


def test_noncanonical_type_error_never_names_the_offending_class() -> None:
    with pytest.raises(InvariantNoncanonicalPayloadError) as excinfo:
        _exact_structural_equal(_SECRET_CANARY_CLASS_NAME(), 1)
    assert "SECRET_CANARY_CLASS_NAME" not in str(excinfo.value)


class _InstanceCheckMeta(type):
    """A metaclass whose __instancecheck__ raises if isinstance() ever runs it."""

    def __instancecheck__(cls, instance: object) -> bool:
        raise AssertionError("isinstance() must never be used for canonical type checks")


class _InstanceCheckDict(dict, metaclass=_InstanceCheckMeta):
    pass


def test_prevalidation_never_triggers_a_hostile_metaclass_instancecheck() -> None:
    """Only ``type(x) is dict`` is ever used, never ``isinstance(x, dict)``.

    isinstance() would admit this subclass (it IS a dict) and, along the
    way, invoke the metaclass's own __instancecheck__ -- which raises.
    Getting InvariantNoncanonicalPayloadError, not AssertionError, proves
    isinstance() was never called.
    """
    sneaky = _InstanceCheckDict(a=1)
    with pytest.raises(InvariantNoncanonicalPayloadError):
        _exact_structural_equal(sneaky, {"a": 1})


# --- bidirectional drift: every emitted violation code is declared somewhere -

_DECLARING_SCHEMAS = ["shadow_evaluate_response_schema", "guarantee_certificate_v2_schema"]


def test_every_declared_invariant_is_exercised_positive_and_negative() -> None:
    """Cross-checked against each real schema's own positive/negative tests.

    This file itself only proves the generic interpreter mechanics with
    synthetic schemas; the concrete declarations on
    shadow_evaluate_response_schema.json and guarantee_certificate_v2_schema.json
    are exercised end-to-end in test_smartops_v2_contracts.py and
    test_evidence_case_contract.py. This test is the drift guard: it fails
    the moment a new x-traigent-invariants entry is declared without a
    corresponding schema-name/code pair being added to the expectation
    table below, so a newly declared invariant cannot silently ship
    unexercised.
    """
    from traigent_schema.invariants import _declarations

    expected_codes = {
        "shadow_evaluate_response_schema": {
            "EVIDENCE_SNAPSHOT_HASH_MATCHES_EVIDENCE_CASE",
            "DIAGNOSTICS_CERTIFIED_MATCHES_EVIDENCE_CASE",
            "DIAGNOSTICS_CERTIFICATE_REF_MATCHES_EVIDENCE_CASE",
            "PINS_ARTIFACT_VERSION_MATCHES_EVIDENCE_CASE_POLICY_VERSION",
            "PINS_ARTIFACT_HASH_MATCHES_EVIDENCE_CASE_POLICY_HASH",
            "DISAGREES_IMPLIES_RULES_POLICY_DIVERGE",
        },
        "guarantee_certificate_v2_schema": {
            "SELECTED_ID_MATCHES_SUBJECT_CONFIG_ID",
            "SELECTED_ID_MAPS_TO_SELECTED_DISPOSITION",
        },
    }

    for schema_name in _DECLARING_SCHEMAS:
        declared_codes = {declaration["code"] for declaration in _declarations(schema_name)}
        assert declared_codes == expected_codes[schema_name], schema_name


def test_declared_invariants_mechanical_fields_are_snapshotted_not_only_codes() -> None:
    """Snapshot every MECHANICAL field of all 8 declared invariants, not codes alone.

    A codes-only check (test_every_declared_invariant_is_exercised_positive_and_negative,
    above) would miss a declaration whose CODE stayed the same while its
    RELATION or POINTERS silently changed underneath it -- exactly the kind
    of drift that would make a positive fixture's "zero violations" or a
    negative fixture's "exactly these codes" stop meaning what the test
    believes it means. ``description`` is deliberately NOT snapshotted here
    (prose changes are not mechanical drift); it is only checked for
    presence and non-emptiness, i.e. that it is meta-schema-valid.
    """
    from traigent_schema.invariants import _declarations

    expected: dict[str, list[dict[str, Any]]] = {
        "shadow_evaluate_response_schema": [
            {
                "code": "EVIDENCE_SNAPSHOT_HASH_MATCHES_EVIDENCE_CASE",
                "relation": "present_and_equal",
                "left_pointer": "/evidence_snapshot_hash",
                "right_pointer": "/evidence_case/evidence/evidence_snapshot_hash",
            },
            {
                "code": "DIAGNOSTICS_CERTIFIED_MATCHES_EVIDENCE_CASE",
                "relation": "present_and_equal",
                "left_pointer": "/diagnostics/certified",
                "right_pointer": "/evidence_case/evidence/certified",
            },
            {
                "code": "DIAGNOSTICS_CERTIFICATE_REF_MATCHES_EVIDENCE_CASE",
                "relation": "present_and_equal",
                "left_pointer": "/diagnostics/certificate_ref",
                "right_pointer": "/evidence_case/evidence/certificate_ref",
            },
            {
                "code": "PINS_ARTIFACT_VERSION_MATCHES_EVIDENCE_CASE_POLICY_VERSION",
                "relation": "present_and_equal",
                "left_pointer": "/pins/artifact_version",
                "right_pointer": "/evidence_case/provenance/policy_version",
            },
            {
                "code": "PINS_ARTIFACT_HASH_MATCHES_EVIDENCE_CASE_POLICY_HASH",
                "relation": "present_and_equal",
                "left_pointer": "/pins/artifact_hash",
                "right_pointer": "/evidence_case/provenance/policy_hash",
            },
            {
                "code": "DISAGREES_IMPLIES_RULES_POLICY_DIVERGE",
                "relation": "condition_implies_unequal",
                "condition_pointer": "/disagrees",
                "left_pointer": "/rules",
                "right_pointer": "/policy",
            },
        ],
        "guarantee_certificate_v2_schema": [
            {
                "code": "SELECTED_ID_MATCHES_SUBJECT_CONFIG_ID",
                "relation": "present_and_equal",
                "left_pointer": "/selected_id",
                "right_pointer": "/subject/config_id",
            },
            {
                "code": "SELECTED_ID_MAPS_TO_SELECTED_DISPOSITION",
                "relation": "selector_lookup_equals_literal",
                "selector_pointer": "/selected_id",
                "map_pointer": "/per_candidate",
                "literal": "selected",
            },
        ],
    }

    total = 0
    for schema_name, expected_declarations in expected.items():
        actual = _declarations(schema_name)
        mechanical = [
            {key: value for key, value in declaration.items() if key != "description"}
            for declaration in actual
        ]
        assert mechanical == expected_declarations, schema_name
        for declaration in actual:
            assert isinstance(declaration.get("description"), str)
            assert declaration["description"].strip() != ""
        total += len(actual)

    assert total == 8
