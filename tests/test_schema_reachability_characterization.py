"""Characterization tests for ``compute_graph_reachable_schemas`` in schema_reachability.

Each case writes a crafted schema tree into a temporary directory, points the script's
schema directory and catalog roots at it, and pins the reachable set: module catalogs,
relative, absolute-URL and fragment-only references, references that escape the tree or
name missing files, unreadable documents, and cycles. The expected values in
tests/data/schema_reachability_characterization.json were recorded from the
implementation before the function was split into smaller helpers. The cases reach every
branch of it.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from tests._characterization import REPO_ROOT, Case, load_golden, load_script, observe

GOLDEN_FILE = "schema_reachability_characterization.json"
TARGET = load_script(
    "schema_reachability_characterization_target",
    REPO_ROOT / "scripts" / "schema_reachability.py",
)

# ---------------------------------------------------------------------------
# compute_graph_reachable_schemas
# ---------------------------------------------------------------------------

HTTP = "https://schemas.traigent.ai/"


def _reach(files: dict[str, Any], roots: tuple[str, ...] = ("root_endpoints.json",)) -> Case:
    """Write ``files`` (dict/list -> JSON, str -> raw text) and walk from ``roots``."""

    def run(m: Any) -> Any:
        with tempfile.TemporaryDirectory() as tmp:
            schemas = Path(tmp) / "schemas"
            schemas.mkdir()
            for rel, content in files.items():
                path = schemas / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                text = content if isinstance(content, str) else json.dumps(content)
                path.write_text(text, encoding="utf-8")
            saved = (m._SCHEMAS_DIR, m._MASTER_ENDPOINT_ROOTS)
            m._SCHEMAS_DIR, m._MASTER_ENDPOINT_ROOTS = schemas, roots
            try:
                return m.compute_graph_reachable_schemas()
            finally:
                m._SCHEMAS_DIR, m._MASTER_ENDPOINT_ROOTS = saved

    return run


GRAPH = {
    "root_endpoints.json": {
        "x-endpoint-modules": [
            {"paths_file": "mod/a_endpoints.json"},
            {"paths_file": 5},
            "not-a-module",
            {"other": "x"},
        ],
        "paths": {"/x": {"post": {"$ref": "schemas/req.json#/definitions/R"}}},
    },
    "mod/a_endpoints.json": {
        "paths": {
            "/a": {"$ref": "../shared/common.json"},
            "/b": {"$ref": f"{HTTP}shared/http_target.json#/x"},
            "/c": {"$ref": "#/local"},
            "/d": {"$ref": "../../outside.json"},
            "/e": {"$ref": "missing.json"},
        }
    },
    "schemas/req.json": {"definitions": {"R": {"$ref": "../shared/common.json#/defs/c"}}},
    "shared/common.json": {"allOf": [{"$ref": "deep/leaf.json"}], "$ref": 7},
    "shared/deep/leaf.json": {"$ref": "../common.json"},
    "shared/http_target.json": [{"$ref": f"{HTTP}lists/item.json"}],
    "lists/item.json": True,
    "unreached.json": {"$ref": "shared/common.json"},
}

REACH_CASES: dict[str, Case] = {
    "graph": _reach(GRAPH),
    "graph_two_roots_one_missing": _reach(
        GRAPH, roots=("absent_endpoints.json", "unreached.json", "root_endpoints.json")
    ),
    "no_roots_exist": _reach(GRAPH, roots=("nope.json",)),
    "root_not_json": _reach({"root_endpoints.json": "{oops"}),
    "child_not_json": _reach(
        {"root_endpoints.json": {"$ref": "bad.json"}, "bad.json": "not json at all"}
    ),
    "root_is_list": _reach({"root_endpoints.json": [{"$ref": "a.json"}], "a.json": {}}),
    "modules_null": _reach({"root_endpoints.json": {"x-endpoint-modules": None}}),
    "modules_empty_string": _reach({"root_endpoints.json": {"x-endpoint-modules": ""}}),
    "module_paths_file_escapes": _reach(
        {"root_endpoints.json": {"x-endpoint-modules": [{"paths_file": "../../x.json"}]}}
    ),
    "self_reference": _reach({"root_endpoints.json": {"$ref": "root_endpoints.json#/a"}}),
    "ref_to_directory": _reach(
        {"root_endpoints.json": {"$ref": "dir"}, "dir/inner.json": {}}
    ),
}

ALL_CASES: dict[str, Case] = REACH_CASES


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], TARGET) == _golden()[case_id]
