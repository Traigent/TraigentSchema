# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for optional evaluation dataset split assignments."""

from __future__ import annotations

import copy

from traigent_schema import SchemaValidator

SCHEMA = "evaluation_set_schema"


def _validator() -> SchemaValidator:
    return SchemaValidator()


def _valid_evaluation_set() -> dict:
    return {
        "id": "eval_set_support_v1",
        "name": "support_eval_v1",
        "label": "Support Evaluation v1",
        "description": "Support answer quality evaluation dataset.",
        "type": "input-output",
        "examples_count": 3,
        "examples": [
            {
                "example_id": "ex_train_1",
                "input_text": "How do I reset my password?",
                "expected_output": "Use the password reset link.",
            },
            {
                "example_id": "ex_selection_1",
                "input_text": "Can I change billing owners?",
                "expected_output": "Tenant admins can change billing owners.",
            },
            {
                "example_id": "ex_test_1",
                "input_text": "Where can I find invoices?",
                "expected_output": "Invoices are available in billing settings.",
            },
        ],
    }


def _with_splits(payload: dict) -> dict:
    result = copy.deepcopy(payload)
    result["splits"] = {
        "policy": {
            "strategy": "explicit",
            "locked_test": True,
        },
        "assignments": {
            "ex_train_1": "train",
            "ex_selection_1": "selection",
            "ex_test_1": "test",
        },
    }
    return result


def test_evaluation_set_without_splits_still_validates() -> None:
    assert _validator().validate_json(_valid_evaluation_set(), SCHEMA) == []


def test_evaluation_set_with_splits_validates() -> None:
    assert _validator().validate_json(_with_splits(_valid_evaluation_set()), SCHEMA) == []


def test_evaluation_set_rejects_invalid_split_value() -> None:
    payload = _with_splits(_valid_evaluation_set())
    payload["splits"]["assignments"]["ex_selection_1"] = "validation"

    errors = _validator().validate_json(payload, SCHEMA)

    assert errors
    assert any("splits.assignments.ex_selection_1" in error for error in errors)


def test_evaluation_set_split_policy_requires_locked_test() -> None:
    payload = _with_splits(_valid_evaluation_set())
    del payload["splits"]["policy"]["locked_test"]

    errors = _validator().validate_json(payload, SCHEMA)

    assert errors
    assert any("locked_test" in error for error in errors)


def test_evaluation_set_splits_rejects_unknown_property() -> None:
    payload = _with_splits(_valid_evaluation_set())
    payload["splits"]["notes"] = "selection split is used for candidate acceptance"

    errors = _validator().validate_json(payload, SCHEMA)

    assert errors
    assert any("splits" in error and "notes" in error for error in errors)

def test_evaluation_set_splits_locked_test_false_validates() -> None:
    payload = _with_splits(_valid_evaluation_set())
    payload["splits"]["policy"]["locked_test"] = False

    assert _validator().validate_json(payload, SCHEMA) == []


def test_evaluation_set_splits_empty_assignments_validates() -> None:
    # An empty assignments map is contractually valid (e.g. hash-strategy
    # datasets assign lazily). Referential integrity between assignment keys
    # and the examples list is runtime/backend-enforced, not expressible in
    # JSON Schema.
    payload = _with_splits(_valid_evaluation_set())
    payload["splits"]["assignments"] = {}

    assert _validator().validate_json(payload, SCHEMA) == []


def test_evaluation_set_splits_policy_rejects_unknown_strategy() -> None:
    payload = _with_splits(_valid_evaluation_set())
    payload["splits"]["policy"]["strategy"] = "random"

    errors = _validator().validate_json(payload, SCHEMA)

    assert errors
    assert any("strategy" in error for error in errors)
