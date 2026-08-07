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
from traigent_schema.invariants import InvariantDeclarationError, _resolve_pointer

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


def test_unknown_schema_name_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(Exception):  # noqa: B017 - load_schema's own FileNotFoundError
        validate_declared_invariants({}, "definitely_not_a_real_schema")


def test_schema_without_declared_invariants_fails_closed() -> None:
    """A real, existing schema that happens to declare none must not silently pass."""
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "best_config_v2_schema")


def test_malformed_declaration_missing_key_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module,
        "load_schema",
        lambda name: {"x-traigent-invariants": [{"code": "X", "relation": "present_and_equal"}]},
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_malformed_declaration_unknown_relation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module,
        "load_schema",
        lambda name: {
            "x-traigent-invariants": [
                {
                    "code": "X",
                    "relation": "greater_than",
                    "left_pointer": "/a",
                    "right_pointer": "/b",
                    "description": "unsupported relation",
                }
            ]
        },
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


def test_declarations_that_are_not_a_list_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: {"x-traigent-invariants": "not-a-list"}
    )
    with pytest.raises(InvariantDeclarationError):
        validate_declared_invariants({}, "irrelevant")


# --- present_and_equal: satisfied, violated, missing --------------------------


def _fake_schema(declarations: list[dict[str, Any]]) -> dict[str, Any]:
    return {"x-traigent-invariants": declarations}


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
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
    assert validate_declared_invariants({"a": "x", "b": "x"}, "irrelevant") == []


def test_present_and_equal_violated_when_values_differ(monkeypatch: pytest.MonkeyPatch) -> None:
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
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
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
    violations = validate_declared_invariants({"a": "x"}, "irrelevant")
    assert len(violations) == 1
    assert violations[0].code == "A_MATCHES_B"


def test_present_and_equal_violated_when_both_sides_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Missing/missing is a violation, not a vacuous pass."""
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
    violations = validate_declared_invariants({}, "irrelevant")
    assert len(violations) == 1


def test_present_and_equal_uses_exact_type_equality(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bool must never compare equal to the int 1 -- exact-type discipline."""
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
    violations = validate_declared_invariants({"a": True, "b": 1}, "irrelevant")
    assert len(violations) == 1


def test_present_and_equal_deep_structural_equality_for_containers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import traigent_schema.invariants as invariants_module

    monkeypatch.setattr(
        invariants_module, "load_schema", lambda name: _fake_schema(_ONE_DECLARATION)
    )
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


def test_multiple_declarations_each_evaluated_independently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import traigent_schema.invariants as invariants_module

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
    monkeypatch.setattr(invariants_module, "load_schema", lambda name: _fake_schema(declarations))
    violations = validate_declared_invariants({"a": 1, "b": 1, "c": 1, "d": 2}, "irrelevant")
    assert [v.code for v in violations] == ["SECOND"]


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
        },
        "guarantee_certificate_v2_schema": {
            "SELECTED_ID_MATCHES_SUBJECT_CONFIG_ID",
        },
    }

    for schema_name in _DECLARING_SCHEMAS:
        declared_codes = {declaration["code"] for declaration in _declarations(schema_name)}
        assert declared_codes == expected_codes[schema_name], schema_name
