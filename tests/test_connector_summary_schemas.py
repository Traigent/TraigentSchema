"""Contract tests for the closed connector summary schemas."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
schemas_dir = ROOT / "traigent_schema" / "schemas"
CONNECTORS = schemas_dir / "connectors"

# Literal path forms (schemas_dir / "connectors" / "<file>") are how
# tests/test_schemas.py's orphan ratchet recognises a schema as referenced.
RUN_PATH = schemas_dir / "connectors" / "connector_run_summary.json"
DATASET_PATH = schemas_dir / "connectors" / "dataset_revision_summary.json"
CORRELATION_PATH = schemas_dir / "connectors" / "correlation_summary.json"

RUN = RUN_PATH.name
DATASET = DATASET_PATH.name
CORRELATION = CORRELATION_PATH.name


def _validator(name: str) -> Draft7Validator:
    schema = json.loads((CONNECTORS / name).read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, format_checker=Draft7Validator.FORMAT_CHECKER)


GOLDEN: dict[str, dict[str, Any]] = {
    RUN: {
        "schema_version": "1",
        "run_token": "run_a1b2c3d4",
        "connector_kind": "langfuse",
        "connection_token": "conn-9f8e7d6c",
        "command": "bootstrap_dataset",
        "status": "partial",
        "started_at": "2026-10-08T10:00:00Z",
        "finished_at": "2026-10-08T10:00:42Z",
        "counts": {
            "observations_read": 120,
            "scores_read": 80,
            "rows_dropped_invalid": 3,
            "pages": 4,
            "items_written": 0,
        },
        "guarantees": [
            {"operation": "read_scores", "support": "emulated", "reason": "emulated_client_side"}
        ],
        "error_code": "rate_limited",
    },
    DATASET: {
        "schema_version": "1",
        "dataset_token": "ds_0a1b2c3d",
        "revision": 2,
        "source_connector_kind": "langfuse",
        "item_count": 200,
        "holdout_count": 40,
        "approved": True,
        "approval_at": "2026-10-08T11:00:00Z",
        "sampling_policy": {"kind": "random", "fraction": 0.25, "seed": 7},
        "score_semantics": [
            {"score_token": "score_11223344", "type": "numeric", "direction": "higher_better"}
        ],
    },
    CORRELATION: {
        "schema_version": "1",
        "run_token": "run_a1b2c3d4",
        "trials_total": 10,
        "trials_linked": 8,
        "trials_unknown": 2,
        "tier_counts": {
            "exact": 5,
            "commit_name": 2,
            "name_only": 1,
            "deployment": 0,
            "ambiguous": 0,
        },
        "agent_function_ref": "my_pkg.agents:answer_question",
        "agent_file_path": "src/my_pkg/agents.py",
    },
}


def _mutated(name: str, path: tuple[str, ...], value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(GOLDEN[name])
    cur = doc
    for key in path[:-1]:
        cur = cur[key]
    cur[path[-1]] = value
    return doc


@pytest.mark.parametrize("name", [RUN, DATASET, CORRELATION])
def test_golden_example_validates(name: str) -> None:
    assert list(_validator(name).iter_errors(GOLDEN[name])) == []


@pytest.mark.parametrize("name", [RUN, DATASET, CORRELATION])
def test_extra_top_level_field_rejected(name: str) -> None:
    doc = copy.deepcopy(GOLDEN[name])
    doc["note"] = "free text"
    assert not _validator(name).is_valid(doc)


def test_extra_nested_field_rejected() -> None:
    assert not _validator(RUN).is_valid(_mutated(RUN, ("counts", "extra"), 1))
    assert not _validator(CORRELATION).is_valid(_mutated(CORRELATION, ("tier_counts", "extra"), 1))


@pytest.mark.parametrize("value", ["Authentication failed for user bob", "AUTH_FAILED", ""])
def test_free_text_error_code_rejected(value: str) -> None:
    assert not _validator(RUN).is_valid(_mutated(RUN, ("error_code",), value))


@pytest.mark.parametrize("value", ["running_fast", "SUCCEEDED", "ok"])
def test_non_enum_status_rejected(value: str) -> None:
    assert not _validator(RUN).is_valid(_mutated(RUN, ("status",), value))


def test_non_enum_connector_kind_and_command_rejected() -> None:
    assert not _validator(RUN).is_valid(_mutated(RUN, ("connector_kind",), "datadog"))
    assert not _validator(RUN).is_valid(_mutated(RUN, ("command",), "delete_everything"))


@pytest.mark.parametrize(
    "value",
    [
        "/home/user/proj/agents.py",
        "../agents.py",
        "src/../../etc/passwd",
        "src/..",
        "..",
        "https://github.com/acme/repo/agents.py",
        "file:///etc/passwd",
        "C:\\proj\\agents.py",
        "src\\agents.py",
        "x" * 513,
    ],
)
def test_bad_file_path_rejected(value: str) -> None:
    assert not _validator(CORRELATION).is_valid(_mutated(CORRELATION, ("agent_file_path",), value))


@pytest.mark.parametrize("value", ["src/a..b/agents.py", "agents.py", "./src/agents.py"])
def test_benign_relative_paths_accepted(value: str) -> None:
    assert _validator(CORRELATION).is_valid(_mutated(CORRELATION, ("agent_file_path",), value))


@pytest.mark.parametrize(
    "path,name",
    [
        (("run_token",), RUN),
        (("connection_token",), RUN),
        (("dataset_token",), DATASET),
        (("run_token",), CORRELATION),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        "https://langfuse.example.com/project/abc",
        "Alice_has_diabetes",
        "short",
        "a" * 65,
        "has space in it",
    ],
)
def test_non_token_in_token_field_rejected(path: tuple[str, ...], name: str, value: str) -> None:
    assert not _validator(name).is_valid(_mutated(name, path, value))


def test_score_token_must_be_opaque() -> None:
    doc = copy.deepcopy(GOLDEN[DATASET])
    doc["score_semantics"][0]["score_token"] = "https://x.example/score"
    assert not _validator(DATASET).is_valid(doc)


def test_too_long_or_malformed_function_ref_rejected() -> None:
    v = _validator(CORRELATION)
    assert not v.is_valid(_mutated(CORRELATION, ("agent_function_ref",), "a" * 513))
    assert not v.is_valid(_mutated(CORRELATION, ("agent_function_ref",), "mod:" + "q" * 520))
    assert not v.is_valid(_mutated(CORRELATION, ("agent_function_ref",), "1bad.ref"))
    assert not v.is_valid(_mutated(CORRELATION, ("agent_function_ref",), "has space"))
    assert v.is_valid(_mutated(CORRELATION, ("agent_function_ref",), "pkg.mod:Cls.<locals>.fn"))


def test_dataset_enums_and_approval_null() -> None:
    v = _validator(DATASET)
    assert v.is_valid(_mutated(DATASET, ("approval_at",), None))
    assert not v.is_valid(_mutated(DATASET, ("sampling_policy", "kind"), "vibes"))
    doc = copy.deepcopy(GOLDEN[DATASET])
    doc["score_semantics"][0]["direction"] = "sideways"
    assert not v.is_valid(doc)
    doc["score_semantics"][0]["direction"] = "none"
    doc["score_semantics"][0]["type"] = "text"
    assert not v.is_valid(doc)


def test_negative_counts_and_wrong_schema_version_rejected() -> None:
    assert not _validator(RUN).is_valid(_mutated(RUN, ("counts", "pages"), -1))
    assert not _validator(RUN).is_valid(_mutated(RUN, ("schema_version",), "2"))
    assert not _validator(CORRELATION).is_valid(_mutated(CORRELATION, ("trials_total",), -1))


@pytest.mark.parametrize("name", [RUN, DATASET, CORRELATION])
def test_every_object_is_closed(name: str) -> None:
    schema = json.loads((CONNECTORS / name).read_text(encoding="utf-8"))

    def walk(node: Any, where: str) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False, where
            for key, child in node.items():
                walk(child, f"{where}/{key}")
        elif isinstance(node, list):
            for i, child in enumerate(node):
                walk(child, f"{where}/{i}")

    walk(schema, name)
