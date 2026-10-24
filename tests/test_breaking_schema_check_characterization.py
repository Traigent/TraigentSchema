# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Characterization tests for the structural comparator in scripts/breaking_schema_check.py.

These pin the exact observable output of ``compare_node`` (the recursive JSON Schema differ)
and ``_compare_operation`` (the OpenAPI operation differ): every emitted finding, every field
of it (file, pointer, rule, severity, role, message, subject, old, new), and the ORDER in which
findings are emitted. A raised exception is pinned by type and message.

The expected values live in tests/data/breaking_schema_check_characterization.json. They were
recorded from the implementation as it stood before those two functions were decomposed into
smaller helpers, so any change in classification, wording or emission order shows up here as a
diff against the recorded output. Do not regenerate that file to make a failing test pass: a
difference is a behaviour change and has to be justified on its own.

Each comparator case runs under all three file roles (request / response / conservative),
because the role decides the severity of every keyword-level finding. A final end-to-end case
drives the real CLI against a throwaway git repository and pins the printed report, the exit
code and the machine-readable JSON summary.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "breaking_schema_check.py"
GOLDEN = REPO_ROOT / "tests" / "data" / "breaking_schema_check_characterization.json"
ROLES = ("request", "response", "conservative")
BASE_URI = "https://schemas.traigent.ai/main/main_schema.json"
ENDPOINTS_URI = "https://schemas.traigent.ai/main/main_endpoints.json"


def _load_gate_module():
    spec = importlib.util.spec_from_file_location("breaking_schema_check", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load_gate_module()


# ---------------------------------------------------------------------------
# $ref fixtures: an OLD and a NEW registry that differ inside a shared definition
# ---------------------------------------------------------------------------


def _shared_lib(name_max_length: int) -> dict[str, Any]:
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://schemas.traigent.ai/lib/shared.json",
        "definitions": {
            "Name": {"type": "string", "maxLength": name_max_length},
            "Loop": {"$ref": "#/definitions/Loop"},
            "Node": {
                "type": "object",
                "properties": {"next": {"$ref": "#/definitions/Node"}},
            },
        },
    }


OLD_REG, _ = gate._build_registry({"lib/shared.json": _shared_lib(10)})
NEW_REG, _ = gate._build_registry({"lib/shared.json": _shared_lib(5)})


def _nested(depth: int, leaf: dict[str, Any]) -> dict[str, Any]:
    node = leaf
    for _ in range(depth):
        node = {"type": "object", "properties": {"x": node}}
    return node


# ---------------------------------------------------------------------------
# compare_node cases: (case id, old schema, new schema)
# ---------------------------------------------------------------------------

NODE_CASES: list[tuple[str, Any, Any]] = [
    ("identical_object", {"type": "object", "properties": {"a": {"type": "string"}}}, None),
    ("depth_limit", _nested(62, {"type": "string"}), _nested(62, {"type": "integer"})),
    ("unresolved_base", {"$ref": "../missing.json"}, {"type": "string"}),
    ("unresolved_head", {"type": "string"}, {"$ref": "#/definitions/absent"}),
    ("unresolved_both", {"$ref": "../missing.json"}, {"$ref": "../missing.json"}),
    ("leaf_equal_bool", True, True),
    ("leaf_bool_changed", True, False),
    ("leaf_dict_to_bool", {"type": "string"}, True),
    ("leaf_list_vs_dict", [1, 2], {"type": "string"}),
    (
        "cyclic_self_ref",
        {"$ref": "../lib/shared.json#/definitions/Loop"},
        {"$ref": "../lib/shared.json#/definitions/Loop"},
    ),
    (
        "cyclic_recursive_object",
        {"$ref": "../lib/shared.json#/definitions/Node"},
        {"$ref": "../lib/shared.json#/definitions/Node"},
    ),
    (
        "cross_file_ref_changed",
        {"$ref": "../lib/shared.json#/definitions/Name"},
        {"$ref": "../lib/shared.json#/definitions/Name"},
    ),
    ("type_unchanged", {"type": "string"}, {"type": "string"}),
    ("type_constrained", {}, {"type": "string"}),
    ("type_unconstrained", {"type": ["string", "null"]}, {}),
    ("type_removed_member", {"type": ["string", "null"]}, {"type": "string"}),
    ("type_added_member", {"type": "string"}, {"type": ["string", "null"]}),
    ("type_swapped", {"type": ["string", "integer"]}, {"type": ["integer", "boolean"]}),
    ("type_invalid_shape", {"type": 5}, {"type": "string"}),
    ("enum_unchanged", {"enum": ["a", "b"]}, {"enum": ["b", "a"]}),
    ("enum_member_removed", {"enum": ["a", "b", 1]}, {"enum": ["a"]}),
    ("enum_member_added", {"enum": ["a"]}, {"enum": ["a", {"k": 1}, None]}),
    ("enum_swapped", {"enum": ["a", "b"]}, {"enum": ["b", "c"]}),
    ("enum_added_entirely", {}, {"enum": ["a"]}),
    ("enum_removed_entirely", {"enum": ["a"]}, {}),
    ("ap_open_to_closed", {}, {"additionalProperties": False}),
    ("ap_open_to_constrained", {"additionalProperties": True}, {"additionalProperties": {}}),
    (
        "ap_constrained_to_closed",
        {"additionalProperties": {"type": "string"}},
        {"additionalProperties": False},
    ),
    ("ap_closed_to_open", {"additionalProperties": False}, {}),
    (
        "ap_map_value_changed",
        {"additionalProperties": {"type": "string", "maxLength": 5}},
        {"additionalProperties": {"type": "integer", "maxLength": 9}},
    ),
    ("pattern_added", {}, {"pattern": "^a$"}),
    ("pattern_removed", {"pattern": "^a$"}, {}),
    ("pattern_changed", {"pattern": "^a$"}, {"pattern": "^b$"}),
    ("pattern_unchanged", {"pattern": "^a$"}, {"pattern": "^a$"}),
    (
        "max_bounds_lowered",
        {"maxLength": 10, "maximum": 10, "maxItems": 10, "maxProperties": 10},
        {"maxLength": 5, "maximum": 5.5, "maxItems": 0, "maxProperties": 9},
    ),
    (
        "max_bounds_raised",
        {"maxLength": 5, "maximum": 5, "maxItems": 5, "maxProperties": 5},
        {"maxLength": 6, "maximum": 50, "maxItems": 7, "maxProperties": 8},
    ),
    ("max_bound_added", {}, {"maxLength": 3}),
    ("max_bound_removed", {"maximum": 3}, {}),
    ("max_bound_int_vs_float_equal", {"maximum": 3}, {"maximum": 3.0}),
    (
        "min_bounds_raised",
        {"minLength": 1, "minimum": 1, "minItems": 1, "minProperties": 1},
        {"minLength": 2, "minimum": 1.5, "minItems": 3, "minProperties": 4},
    ),
    (
        "min_bounds_lowered",
        {"minLength": 5, "minimum": 5, "minItems": 5, "minProperties": 5},
        {"minLength": 0, "minimum": -1, "minItems": 4, "minProperties": 3},
    ),
    ("min_bound_added", {}, {"minimum": 0}),
    ("min_bound_removed", {"minItems": 2}, {}),
    ("bound_type_error", {"maxLength": "5"}, {"maxLength": 3}),
    # NaN differs from itself but is neither lower nor higher: no finding either way.
    (
        "bound_unordered_nan",
        {"maximum": float("nan"), "minimum": float("nan")},
        {"maximum": float("nan"), "minimum": float("nan")},
    ),
    ("required_added", {"required": ["a"]}, {"required": ["c", "a", "b"]}),
    ("required_removed", {"required": ["a", "b", "c"]}, {"required": ["b"]}),
    ("required_swapped", {"required": ["a"]}, {"required": ["b"]}),
    ("required_null_vs_empty", {"required": None}, {"required": []}),
    (
        "property_removed_closed",
        {"properties": {"a": {}, "b": {}}, "additionalProperties": False},
        {"properties": {"a": {}}, "additionalProperties": False},
    ),
    (
        "property_removed_constrained",
        {"properties": {"a": {}, "b": {}}},
        {"properties": {"a": {}}, "additionalProperties": {"type": "string"}},
    ),
    (
        "property_removed_open",
        {"properties": {"a": {}, "b": {}}},
        {"properties": {"a": {}}},
    ),
    (
        "property_added_old_closed",
        {"properties": {"a": {}}, "additionalProperties": False},
        {"properties": {"a": {}, "z": {}}, "additionalProperties": False},
    ),
    (
        "property_added_old_constrained",
        {"properties": {}, "additionalProperties": {"type": "integer"}},
        {"properties": {"z": {"type": "string"}}, "additionalProperties": {"type": "integer"}},
    ),
    (
        "property_added_old_open",
        {"properties": {"a": {}}},
        {"properties": {"a": {}, "z": {}}},
    ),
    (
        "property_recursed",
        {"properties": {"a": {"type": "string", "maxLength": 9}, "b": {"enum": [1]}}},
        {"properties": {"a": {"type": "integer", "maxLength": 3}, "b": {"enum": [2]}}},
    ),
    ("properties_not_a_dict", {"properties": ["a"]}, {"properties": {"a": {}}}),
    (
        "pattern_properties_removed_closed",
        {"patternProperties": {"^x": {}}, "additionalProperties": False},
        {"additionalProperties": False},
    ),
    (
        "pattern_properties_removed_open",
        {"patternProperties": {"^x": {}, "^y": {}}},
        {"patternProperties": {"^y": {}}},
    ),
    (
        "pattern_properties_added_old_closed",
        {"additionalProperties": False},
        {"patternProperties": {"^x": {}}, "additionalProperties": False},
    ),
    (
        "pattern_properties_added_old_open",
        {},
        {"patternProperties": {"^x": {}}},
    ),
    (
        "pattern_properties_recursed",
        {"patternProperties": {"^x": {"type": "string"}}},
        {"patternProperties": {"^x": {"type": "number"}}},
    ),
    ("pattern_properties_not_a_dict", {"patternProperties": 3}, {"patternProperties": {}}),
    (
        "items_recursed",
        {"type": "array", "items": {"type": "string", "minLength": 1}},
        {"type": "array", "items": {"type": "string", "minLength": 2}},
    ),
    ("items_added", {"type": "array"}, {"type": "array", "items": {"type": "string"}}),
    ("items_removed", {"type": "array", "items": {"type": "string"}}, {"type": "array"}),
    (
        "items_tuple_changed",
        {"items": [{"type": "string"}]},
        {"items": [{"type": "integer"}]},
    ),
    ("items_tuple_unchanged", {"items": [{"type": "string"}]}, {"items": [{"type": "string"}]}),
    ("items_dict_to_tuple", {"items": {"type": "string"}}, {"items": [{"type": "string"}]}),
    ("items_bool_added", {}, {"items": False}),
    ("items_tuple_removed", {"items": [{}]}, {}),
    ("oneof_added", {}, {"oneOf": [{"type": "string"}, {"type": "integer"}]}),
    ("anyof_added_empty", {}, {"anyOf": []}),
    ("allof_added_empty", {}, {"allOf": []}),
    ("allof_added_nonempty", {}, {"allOf": [{"type": "string"}]}),
    ("oneof_removed", {"oneOf": [{"type": "string"}]}, {}),
    ("allof_removed_empty", {"allOf": []}, {}),
    ("allof_removed_nonempty", {"allOf": [{}, {}]}, {}),
    ("anyof_shape_changed", {"anyOf": {"type": "string"}}, {"anyOf": [{"type": "string"}]}),
    ("oneof_added_non_list", {}, {"oneOf": "x"}),
    ("allof_removed_to_non_list", {"allOf": [{}]}, {"allOf": 7}),
    (
        "anyof_branch_count_changed",
        {"anyOf": [{"type": "string"}]},
        {"anyOf": [{"type": "string"}, {"type": "null"}]},
    ),
    (
        "combinators_positional",
        {
            "oneOf": [{"type": "string"}, {"maximum": 9}],
            "anyOf": [{"enum": ["a"]}],
            "allOf": [{"required": ["x"]}],
        },
        {
            "oneOf": [{"type": "integer"}, {"maximum": 3}],
            "anyOf": [{"enum": ["a", "b"]}],
            "allOf": [{"required": ["x", "y"]}],
        },
    ),
    (
        "everything_at_once",
        {
            "type": "object",
            "enum": [{"a": 1}],
            "pattern": "p",
            "maxLength": 4,
            "minLength": 2,
            "required": ["a", "gone"],
            "properties": {
                "a": {"type": "string", "items": {"type": "integer"}},
                "gone": {},
                "same": {"$ref": "../lib/shared.json#/definitions/Name"},
            },
            "patternProperties": {"^old": {}},
            "items": {"type": "string"},
            "oneOf": [{}],
            "allOf": [],
        },
        {
            "type": ["object", "null"],
            "enum": [{"a": 2}],
            "maxLength": 2,
            "minLength": 1,
            "required": ["a", "new"],
            "additionalProperties": False,
            "properties": {
                "a": {"type": "string"},
                "new": {},
                "same": {"$ref": "../lib/shared.json#/definitions/Name"},
            },
            "patternProperties": {"^new": {}},
            "anyOf": [{}],
        },
    ),
]


def _finding_dict(finding: Any) -> dict[str, Any]:
    return {
        "file": finding.file,
        "pointer": finding.pointer,
        "rule": finding.rule,
        "severity": finding.severity,
        "role": finding.role,
        "message": finding.message,
        "subject": finding.subject,
        "old": finding.old,
        "new": finding.new,
    }


def _run(callable_: Any) -> dict[str, Any]:
    findings: list[Any] = []
    try:
        callable_(findings)
    except Exception as exc:  # noqa: BLE001 - the raised exception IS the pinned behaviour
        return {
            "raises": type(exc).__name__,
            "message": str(exc),
            "findings_before_raise": [_finding_dict(f) for f in findings],
        }
    return {"findings": [_finding_dict(f) for f in findings]}


def run_node_case(old: Any, new: Any, role: str) -> dict[str, Any]:
    if new is None:
        new = old

    def call(findings: list[Any]) -> None:
        gate.compare_node(
            old,
            new,
            old_base=BASE_URI,
            new_base=BASE_URI,
            old_reg=OLD_REG,
            new_reg=NEW_REG,
            old_visited=frozenset(),
            new_visited=frozenset(),
            pointer="#",
            role=role,
            file="main/main_schema.json",
            findings=findings,
        )

    return _run(call)


# ---------------------------------------------------------------------------
# _compare_operation cases: (case id, old operation, new operation)
# ---------------------------------------------------------------------------


def _media(schema: Any) -> dict[str, Any]:
    return {"application/json": {"schema": schema}}


_LOCAL_DEFS_OLD = {
    "definitions": {"Item": {"type": "string", "maxLength": 8}},
    "type": "object",
    "properties": {"item": {"$ref": "#/definitions/Item"}},
}
_LOCAL_DEFS_NEW = {
    "definitions": {"Item": {"type": "string", "maxLength": 4}},
    "type": "object",
    "properties": {"item": {"$ref": "#/definitions/Item"}},
}

OPERATION_CASES: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
    ("empty_operations", {}, {}),
    (
        "request_body_became_required",
        {"requestBody": {"content": _media({"type": "object"})}},
        {"requestBody": {"required": True, "content": _media({"type": "object"})}},
    ),
    (
        "request_body_became_optional",
        {"requestBody": {"required": True}},
        {"requestBody": {"required": False}},
    ),
    (
        "request_body_required_unchanged",
        {"requestBody": {"required": True, "content": _media({"type": "string"})}},
        {"requestBody": {"required": 1, "content": _media({"type": "string"})}},
    ),
    (
        "request_body_schema_narrowed",
        {"requestBody": {"content": _media({"type": "object", "properties": {"a": {}}})}},
        {
            "requestBody": {
                "content": _media({"type": "object", "properties": {"a": {}}, "required": ["a"]})
            }
        },
    ),
    (
        "request_body_media_added_and_removed",
        {"requestBody": {"content": {"text/plain": {"schema": {"type": "string"}}}}},
        {"requestBody": {"content": _media({"type": "object"})}},
    ),
    (
        "request_body_media_without_schema",
        {"requestBody": {"content": {"application/json": None, "text/csv": {}}}},
        {"requestBody": {"content": {"application/json": {}, "text/csv": None}}},
    ),
    (
        "request_body_local_definitions",
        {"requestBody": {"content": _media(_LOCAL_DEFS_OLD)}},
        {"requestBody": {"content": _media(_LOCAL_DEFS_NEW)}},
    ),
    (
        "request_body_content_not_a_dict",
        {"requestBody": {"content": "x"}},
        {"requestBody": {"content": _media({"type": "object"})}},
    ),
    (
        "request_body_added_optional",
        {},
        {"requestBody": {"content": _media({"type": "object"})}},
    ),
    ("request_body_added_required", {}, {"requestBody": {"required": True}}),
    ("request_body_removed", {"requestBody": {"required": True}}, {}),
    ("request_body_not_a_dict", {"requestBody": "x"}, {"requestBody": {"required": True}}),
    (
        "parameters_added_removed",
        {
            "parameters": [
                {"name": "gone_req", "required": True},
                {"name": "gone_opt"},
            ]
        },
        {
            "parameters": [
                {"name": "new_req", "required": True},
                {"name": "new_opt", "required": False},
            ]
        },
    ),
    (
        "parameters_required_flip",
        {"parameters": [{"name": "a"}, {"name": "b", "required": True}, {"name": "c"}]},
        {
            "parameters": [
                {"name": "a", "required": True},
                {"name": "b"},
                {"name": "c", "required": False},
            ]
        },
    ),
    (
        "parameters_schema_compared",
        {
            "parameters": [
                {"name": "q", "schema": {"type": "string", "maxLength": 10}},
                {"name": "r", "schema": {"type": "string"}},
                {"name": "s"},
            ]
        },
        {
            "parameters": [
                {"name": "q", "schema": {"type": "integer", "maxLength": 20}},
                {"name": "r", "schema": True},
                {"name": "s", "schema": {"type": "string"}},
            ]
        },
    ),
    (
        "parameters_malformed_entries_ignored",
        {"parameters": ["x", {"in": "query"}, {"name": "keep"}]},
        {"parameters": [None, {"name": "keep"}, 5]},
    ),
    ("parameters_null", {"parameters": None}, {"parameters": [{"name": "p"}]}),
    (
        "responses_added_removed",
        {"responses": {"200": {}, "404": {}}},
        {"responses": {"200": {}, "201": {}}},
    ),
    (
        "responses_schema_loosened",
        {
            "responses": {
                "200": {
                    "content": _media(
                        {"type": "object", "required": ["id"], "additionalProperties": False}
                    )
                }
            }
        },
        {"responses": {"200": {"content": _media({"type": "object"})}}},
    ),
    (
        "responses_schema_removed_and_added",
        {"responses": {"200": {"content": _media({"type": "object"})}, "400": {}}},
        {"responses": {"200": {}, "400": {"content": _media({"type": "object"})}}},
    ),
    (
        "responses_status_not_a_dict",
        {"responses": {"200": "x"}},
        {"responses": {"200": {"content": _media({})}}},
    ),
    ("responses_not_a_dict", {"responses": []}, {"responses": {"200": {}}}),
    (
        "everything_at_once",
        {
            "requestBody": {"content": _media({"type": "object", "maxProperties": 3})},
            "parameters": [{"name": "page", "schema": {"type": "integer", "minimum": 1}}],
            "responses": {"200": {"content": _media({"enum": ["a", "b"]})}, "500": {}},
        },
        {
            "requestBody": {
                "required": True,
                "content": _media({"type": "object", "maxProperties": 2}),
            },
            "parameters": [
                {"name": "page", "required": True, "schema": {"type": "integer", "minimum": 0}},
                {"name": "size", "required": True},
            ],
            "responses": {"200": {"content": _media({"enum": ["a", "b", "c"]})}},
        },
    ),
]


def run_operation_case(old_op: dict[str, Any], new_op: dict[str, Any]) -> dict[str, Any]:
    empty_reg, _ = gate._build_registry({})

    def call(findings: list[Any]) -> None:
        gate._compare_operation(
            old_op,
            new_op,
            file="main/main_endpoints.json",
            pointer="#/paths//things/post",
            old_base=ENDPOINTS_URI,
            new_base=ENDPOINTS_URI,
            old_reg=empty_reg,
            new_reg=empty_reg,
            findings=findings,
        )

    return _run(call)


# ---------------------------------------------------------------------------
# End-to-end CLI case: a throwaway repo with one plain schema and one endpoints file
# ---------------------------------------------------------------------------

_E2E_BASE = {
    "widgets/widget_schema.json": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://schemas.traigent.ai/widgets/widget_schema.json",
        "type": "object",
        "properties": {
            "name": {"type": "string", "maxLength": 100},
            "color": {"enum": ["red", "blue"]},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["name"],
        "additionalProperties": False,
    },
    "widgets/widget_endpoints.json": {
        "openapi": "3.0.0",
        "paths": {
            "/widgets": {
                "post": {
                    "parameters": [{"name": "dry_run", "in": "query"}],
                    "requestBody": {
                        "content": _media({"$ref": "widget_schema.json"}),
                    },
                    "responses": {
                        "200": {"content": _media({"$ref": "widget_schema.json"})},
                        "404": {},
                    },
                },
                "delete": {"responses": {"204": {}}},
            }
        },
    },
}

_E2E_HEAD = {
    "widgets/widget_schema.json": {
        **_E2E_BASE["widgets/widget_schema.json"],
        "properties": {
            "name": {"type": "string", "maxLength": 50},
            "color": {"enum": ["red", "blue", "green"]},
            "tags": {"type": "array", "items": {"type": ["string", "null"]}},
            "size": {"type": "integer"},
        },
        "required": ["name", "size"],
    },
    "widgets/widget_endpoints.json": {
        "openapi": "3.0.0",
        "paths": {
            "/widgets": {
                "post": {
                    "parameters": [
                        {"name": "dry_run", "in": "query", "required": True},
                        {"name": "trace", "in": "header"},
                    ],
                    "requestBody": {
                        "required": True,
                        "content": _media({"$ref": "widget_schema.json"}),
                    },
                    "responses": {
                        "200": {"content": _media({"$ref": "widget_schema.json"})},
                        "201": {},
                    },
                },
                "get": {"responses": {"200": {}}},
            }
        },
    },
}


def _git_env() -> dict[str, str]:
    local_vars = subprocess.run(
        ["git", "rev-parse", "--local-env-vars"], capture_output=True, text=True, check=True
    ).stdout.split()
    env = {k: v for k, v in os.environ.items() if k not in set(local_vars)}
    env.update(
        {
            "GIT_AUTHOR_NAME": "Characterization",
            "GIT_AUTHOR_EMAIL": "characterization@example.com",
            "GIT_COMMITTER_NAME": "Characterization",
            "GIT_COMMITTER_EMAIL": "characterization@example.com",
        }
    )
    return env


def _write_tree(repo: Path, files: dict[str, Any]) -> None:
    for rel, doc in files.items():
        path = repo / "traigent_schema" / "schemas" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def run_cli_case(tmp_path: Path) -> dict[str, Any]:
    repo = tmp_path / "repo"
    repo.mkdir()
    env = _git_env()

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, env=env
        ).stdout.strip()

    git("init", "-q")
    _write_tree(repo, _E2E_BASE)
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    base = git("rev-parse", "HEAD")
    _write_tree(repo, _E2E_HEAD)
    git("add", "-A")
    git("commit", "-q", "-m", "head")
    head = git("rev-parse", "HEAD")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--check",
            "--repo-root",
            str(repo),
            "--base-ref",
            base,
            "--head-ref",
            head,
            "--allowlist",
            str(repo / "no-such-allowlist.json"),
            "--json",
            str(repo / "report.json"),
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    summary = json.loads((repo / "report.json").read_text(encoding="utf-8"))

    def normalize(text: str) -> str:
        text = text.replace(base, "<BASE>").replace(head, "<HEAD>")
        return re.sub(r"@[0-9a-f]{12}", "@<SHA>", text)

    return {
        "returncode": result.returncode,
        "stdout": normalize(result.stdout),
        "stderr": normalize(result.stderr),
        "json": json.loads(normalize(json.dumps(summary))),
    }


# ---------------------------------------------------------------------------
# Golden comparison
# ---------------------------------------------------------------------------


def _canonical(value: Any) -> str:
    # Compare canonical JSON text, not Python values, so True/1 and 1/1.0 stay distinct.
    return json.dumps(value, sort_keys=True, indent=1)


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


def test_golden_covers_exactly_the_declared_cases(golden: dict[str, Any]) -> None:
    node_keys = {f"{case_id}/{role}" for case_id, _, _ in NODE_CASES for role in ROLES}
    op_keys = {case_id for case_id, _, _ in OPERATION_CASES}
    assert len(node_keys) == len(NODE_CASES) * len(ROLES)
    assert set(golden["compare_node"]) == node_keys
    assert set(golden["compare_operation"]) == op_keys


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    ("case_id", "old", "new"), NODE_CASES, ids=[case[0] for case in NODE_CASES]
)
def test_compare_node_matches_recorded_output(
    golden: dict[str, Any], case_id: str, old: Any, new: Any, role: str
) -> None:
    actual = run_node_case(old, new, role)
    assert _canonical(actual) == _canonical(golden["compare_node"][f"{case_id}/{role}"])


@pytest.mark.parametrize(
    ("case_id", "old_op", "new_op"), OPERATION_CASES, ids=[case[0] for case in OPERATION_CASES]
)
def test_compare_operation_matches_recorded_output(
    golden: dict[str, Any], case_id: str, old_op: dict[str, Any], new_op: dict[str, Any]
) -> None:
    actual = run_operation_case(old_op, new_op)
    assert _canonical(actual) == _canonical(golden["compare_operation"][case_id])


def test_cli_end_to_end_matches_recorded_output(golden: dict[str, Any], tmp_path: Path) -> None:
    actual = run_cli_case(tmp_path)
    assert _canonical(actual) == _canonical(golden["cli"])


def run_repository_self_compare() -> list[dict[str, Any]]:
    tree = gate.load_tree_from_dir(REPO_ROOT / "traigent_schema" / "schemas", label="repo")
    assert tree.files, "no repository schemas were loaded"
    findings: list[Any] = []
    for relpath, doc in sorted(tree.files.items()):
        base_uri = tree.file_base_uri.get(relpath, gate.SCHEMA_ID_BASE + relpath)
        if "_endpoints" in Path(relpath).name:
            gate.compare_endpoints_file(
                doc,
                doc,
                file=relpath,
                old_base=base_uri,
                new_base=base_uri,
                old_reg=tree.registry,
                new_reg=tree.registry,
                findings=findings,
            )
        else:
            gate.compare_node(
                doc,
                doc,
                old_base=base_uri,
                new_base=base_uri,
                old_reg=tree.registry,
                new_reg=tree.registry,
                old_visited=frozenset(),
                new_visited=frozenset(),
                pointer="#",
                role="conservative",
                file=relpath,
                findings=findings,
            )
    return [_finding_dict(f) for f in findings]


def test_every_repository_schema_compared_against_itself_matches_recorded_output(
    golden: dict[str, Any],
) -> None:
    actual = run_repository_self_compare()
    # A self-comparison may only ever report the informational "could not descend" kinds.
    assert {f["rule"] for f in actual} <= {"cyclic_ref", "depth_limit"}
    assert all(f["severity"] == "INFO" for f in actual)
    assert _canonical(actual) == _canonical(golden["repository_self_compare"])
