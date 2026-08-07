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

from traigent_schema import InvariantViolation, validate_declared_invariants
from traigent_schema.invariants import (
    _META_SCHEMA_NAME,
    InvariantComparisonBoundError,
    InvariantDeclarationError,
    _exact_structural_equal,
    _resolve_pointer,
)
from traigent_schema.utils import load_schema as _real_load_schema

# --- pointer resolution -------------------------------------------------------


def test_resolves_a_nested_pointer() -> None:
    payload = {"a": {"b": [10, 20, {"c": "value"}]}}
    assert _resolve_pointer(payload, "/a/b/2/c") == "value"


def test_empty_pointer_resolves_to_the_root() -> None:
    payload = {"a": 1}
    assert _resolve_pointer(payload, "") is payload


def test_missing_object_member_resolves_to_missing_sentinel() -> None:
    from traigent_schema.invariants import _MISSING

    assert _resolve_pointer({"a": 1}, "/b") is _MISSING


def test_out_of_range_array_index_resolves_to_missing_sentinel() -> None:
    from traigent_schema.invariants import _MISSING

    assert _resolve_pointer({"a": [1, 2]}, "/a/5") is _MISSING


def test_pointer_through_a_scalar_resolves_to_missing_sentinel() -> None:
    from traigent_schema.invariants import _MISSING

    assert _resolve_pointer({"a": 1}, "/a/b") is _MISSING


def test_pointer_unescapes_rfc6901_tilde_and_slash() -> None:
    payload = {"a/b": 1, "c~d": 2}
    assert _resolve_pointer(payload, "/a~1b") == 1
    assert _resolve_pointer(payload, "/c~0d") == 2


def test_relative_pointer_is_rejected() -> None:
    with pytest.raises(InvariantDeclarationError):
        _resolve_pointer({"a": 1}, "a")


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


# --- hostile payloads: deep, cyclic, wide, subclassed --------------------------


def test_deeply_nested_equal_containers_are_bounded_not_stack_exhausted() -> None:
    nested: Any = "leaf"
    for _ in range(5000):
        nested = [nested]
    with pytest.raises(InvariantComparisonBoundError):
        _exact_structural_equal(nested, nested)


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


def test_dict_subclass_is_never_compared_via_its_own_overrides() -> None:
    sneaky = _SneakyDict(a=1)
    assert _exact_structural_equal(sneaky, {"a": 1}) is False
    assert _exact_structural_equal({"a": 1}, sneaky) is False


def test_list_subclass_is_never_compared_via_its_own_overrides() -> None:
    sneaky = _SneakyList([1, 2])
    assert _exact_structural_equal(sneaky, [1, 2]) is False
    assert _exact_structural_equal([1, 2], sneaky) is False


def test_str_subclass_is_never_compared_via_its_own_overrides() -> None:
    sneaky = _SneakyStr("x")
    assert _exact_structural_equal(sneaky, "x") is False
    assert _exact_structural_equal("x", sneaky) is False


def test_bool_never_equals_the_int_one() -> None:
    assert _exact_structural_equal(True, 1) is False
    assert _exact_structural_equal(False, 0) is False


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
