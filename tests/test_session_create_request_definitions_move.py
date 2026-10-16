"""The embedded definitions of POST /api/v1/sessions moved to their own schema file.

The move must not change what any request body validates to: the pre-move embedded schema is
frozen in ``tests/fixtures/session_create_request_embedded_before_move.json`` and both shapes
are run over the same representative bodies, valid and invalid, with identical results.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from traigent_schema.validator import SchemaValidator

FIXTURE = Path(__file__).parent / "fixtures" / "session_create_request_embedded_before_move.json"

BASE: dict[str, Any] = {
    "function_name": "f",
    "configuration_space": {"model": ["a", "b"]},
    "objectives": ["accuracy"],
}
TYPED = [{"metric": "accuracy", "orientation": "maximize"}]
LEGACY_OBJ = [{"name": "accuracy", "orientation": "maximize", "weight": 1.0}]


def _bodies() -> dict[str, dict[str, Any]]:
    b = lambda **kw: {**copy.deepcopy(BASE), **kw}  # noqa: E731
    bodies = {
        "minimal": b(),
        "empty": {},
        "missing_objectives": {k: v for k, v in BASE.items() if k != "objectives"},
        "objectives_wrong_type": b(objectives=5),
        "objectives_empty_list": b(objectives=[]),
        "objectives_typed": b(objectives=TYPED),
        "objectives_typed_bad": b(objectives=[{"metric": 3}]),
        "objectives_legacy_objects": b(objectives=LEGACY_OBJ),
        "objectives_legacy_object_bad_band": b(
            objectives=[{"name": "x", "orientation": "maximize", "band": {"low": "a"}}]
        ),
        "objectives_mixed": b(objectives=["accuracy", {"name": "x"}]),
        "objectives_string_not_list": b(objectives="accuracy"),
        "artifact_versions_empty": b(artifact_versions={}),
        "artifact_versions_bad": b(artifact_versions={"agent": 3}),
        "artifact_versions_unknown": b(
            artifact_versions={"agent": {"state": "unknown", "version": "x"}}
        ),
        "artifact_versions_full": b(
            identity_version=2,
            artifact_versions={
                s: {"schema": "fp1", "state": "known", "digest": "0" * 64}
                for s in ("agent", "config_space", "dataset", "evaluator")
            },
        ),
        "max_trials_str": b(max_trials="ten"),
        "function_name_empty": b(function_name=""),
        "extra_property": b(unexpected_key=1),
    }
    return bodies


ENDPOINTS = (
    Path(__file__).parent.parent
    / "traigent_schema"
    / "schemas"
    / "optimization"
    / "optimization_endpoints.json"
)
BASE_URI = "https://schemas.traigent.ai/optimization/optimization_endpoints.json"


def _current_schema() -> dict[str, Any]:
    doc = json.loads(ENDPOINTS.read_text(encoding="utf-8"))
    return doc["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]


def _validate(sv: SchemaValidator, schema: dict[str, Any], data: Any) -> list[str]:
    return sv._validate_inline_schema(data, schema, BASE_URI)


def test_moved_definitions_validate_exactly_as_the_embedded_ones_did() -> None:
    sv = SchemaValidator()
    new_schema = _current_schema()
    assert "definitions" not in new_schema, "definitions must live in their own schema file"
    old_schema = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert set(old_schema["definitions"]) == {
        "CanonicalTypedObjectiveDefinition",
        "LegacyObjectObjectiveDefinition",
        "LegacyObjectiveBand",
        "TypedObjectiveArray",
        "LegacyStringObjectiveArray",
        "ArtifactVersion",
    }
    results = {}
    for name, body in _bodies().items():
        old = _validate(sv, old_schema, copy.deepcopy(body))
        new = _validate(sv, new_schema, copy.deepcopy(body))
        assert bool(old) == bool(new), (name, old, new)
        assert sorted(old) == sorted(new), (name, old, new)
        results[name] = bool(new)
    assert results["minimal"] is False  # at least one valid body ...
    assert any(results.values())  # ... and at least one invalid body were compared


def test_the_moved_definitions_file_holds_the_same_definitions() -> None:
    old = json.loads(FIXTURE.read_text(encoding="utf-8"))["definitions"]
    moved = SchemaValidator()._schemas["session_create_definitions_schema"]["definitions"]
    assert moved == old
