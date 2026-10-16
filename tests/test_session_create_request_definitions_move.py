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


def _over_length_bodies() -> dict[str, dict[str, Any]]:
    """Accepted before the bounds (#138) and refused now: the only intended difference.

    The digest bound (71 = len("sha256:") + 64) is not a pure restatement of the pattern: Python's
    regex "$" also matches before a final newline, so the old pattern admitted a 72-character
    digest ending in "\\n". That case is covered by its own regression test below.
    """
    b = lambda **kw: {**copy.deepcopy(BASE), **kw}  # noqa: E731
    long_name = "m" * 256
    return {
        "legacy_string_objective_over_255": b(objectives=[long_name]),
        "legacy_object_metric_over_255": b(
            objectives=[{"metric": long_name, "direction": "maximize"}]
        ),
    }


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
    moved = SchemaValidator()._schemas["session_create_request_definitions_schema"]["definitions"]
    moved = copy.deepcopy(moved)
    # the only difference is the four length bounds added afterwards (#138)
    moved["LegacyObjectObjectiveDefinition"]["properties"]["metric"].pop("maxLength")
    moved["LegacyStringObjectiveArray"]["items"].pop("maxLength")
    moved["ArtifactVersion"]["properties"]["digest"].pop("maxLength")
    for branch in moved["ArtifactVersion"]["allOf"]:
        branch.get("then", {}).get("properties", {}).get("digest", {}).pop("maxLength", None)
    assert moved == old


def test_the_length_bounds_are_the_only_tightening() -> None:
    sv = SchemaValidator()
    new_schema = _current_schema()
    old_schema = json.loads(FIXTURE.read_text(encoding="utf-8"))
    at_limit = {
        "string_objective_255": {**BASE, "objectives": ["m" * 255]},
        "object_metric_255": {
            **BASE,
            "objectives": [{"metric": "m" * 255, "direction": "maximize"}],
        },
    }
    for name, body in at_limit.items():
        assert _validate(sv, old_schema, body) == _validate(sv, new_schema, body) == [], name
    for name, body in _over_length_bodies().items():
        assert _validate(sv, old_schema, copy.deepcopy(body)) == [], name  # old accepted it
        refused = _validate(sv, new_schema, copy.deepcopy(body))
        assert refused, name


def test_digest_with_trailing_newline_is_refused_by_the_bound_only() -> None:
    """The 71-char digest bound is an intentional tightening over the frozen pre-move schema.

    ``pattern`` is ``^sha256:[0-9a-f]{64}$`` and Python's ``$`` also matches before a final
    newline, so the old schema admitted ``"sha256:" + 64 hex + "\\n"`` (72 chars). The new
    maxLength refuses it. A digest without the newline stays valid under both.
    """
    sv = SchemaValidator()
    new_schema = _current_schema()
    old_schema = json.loads(FIXTURE.read_text(encoding="utf-8"))
    digest = "sha256:" + "0" * 64
    with_newline = {
        **copy.deepcopy(BASE),
        "artifact_versions": {
            "agent": {"schema": "afp2", "state": "verified", "digest": digest + "\n"}
        },
    }
    without_newline = copy.deepcopy(with_newline)
    without_newline["artifact_versions"]["agent"]["digest"] = digest
    assert _validate(sv, old_schema, copy.deepcopy(with_newline)) == []
    assert _validate(sv, new_schema, copy.deepcopy(with_newline)) != []
    assert _validate(sv, old_schema, copy.deepcopy(without_newline)) == []
    assert _validate(sv, new_schema, copy.deepcopy(without_newline)) == []
