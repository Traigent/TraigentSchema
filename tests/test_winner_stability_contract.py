# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the optional ``winner_stability`` block on best-config validation.

The block records a post-selection rerun of the winning configuration on the same
evaluation set — measured evidence only; it carries no stability guarantee and this
revision attaches no gating semantics. These tests pin:

* the block is OPTIONAL on both envelopes (v1 and v2) — payloads without it are untouched;
* a well-formed block validates on both envelopes and through the publish-request closure;
* the block itself is CLOSED (``additionalProperties: false``) and each member's type
  constraint holds (reps >= 1, std >= 0, scores numeric and bounded);
* ``validation`` remains an OPEN object — foreign evidence keys still pass;
* the v1 envelope ``$ref``s the single normative definition in the v2 file, so the
  shape cannot drift between envelopes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator, RefResolver

from traigent_schema.utils import get_schemas_dir


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _schema_store(root: Path) -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*.json"):
        schema = _load(path)
        store[path.as_uri()] = schema
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            store[schema_id] = schema
    return store


def _validator(schema_path: str) -> Draft7Validator:
    schemas_dir = get_schemas_dir()
    schema = _load(schemas_dir / schema_path)

    def _deny_remote(uri: str) -> None:
        raise AssertionError(f"schema ref escaped packaged closure: {uri}")

    resolver = RefResolver.from_schema(
        schema,
        store=_schema_store(schemas_dir),
        handlers={"http": _deny_remote, "https": _deny_remote},
    )
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, resolver=resolver)


def _winner_stability() -> dict[str, Any]:
    return {
        "reps": 3,
        "mean": 0.842,
        "std": 0.031,
        "scores": [0.81, 0.85, 0.866],
        "config_hash": "sha256:" + "a" * 64,
        "evaluated_at": "2026-08-11T00:00:00Z",
    }


_V1 = "optimization/best_config_schema.json"
_V2 = "optimization/best_config_v2_schema.json"


def _best_config(schema_path: str, validation: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "traigent.best_config.v1"
        if schema_path == _V1
        else "traigent.best_config.v2",
        "config_id": "support-answerer",
        "function_ref": "tests.best_config:answer",
        "environment": "default",
        "config": {"model": "gpt-4o-mini", "temperature": 0.2},
        "provenance": {"algorithm": "tpe", "optimization_id": "opt_cloud_123"},
    }
    if validation is not None:
        payload["validation"] = validation
    return payload


# --- the block is optional ----------------------------------------------------


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_payload_without_winner_stability_still_validates(schema_path: str) -> None:
    assert list(_validator(schema_path).iter_errors(_best_config(schema_path))) == []
    assert list(_validator(schema_path).iter_errors(_best_config(schema_path, validation={}))) == []


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_validation_remains_open_for_foreign_evidence_keys(schema_path: str) -> None:
    payload = _best_config(
        schema_path, validation={"guaranteed_selection": {"certificate_id": "cert_1"}}
    )
    assert list(_validator(schema_path).iter_errors(payload)) == []


# --- a well-formed block validates on both envelopes --------------------------


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_well_formed_winner_stability_validates(schema_path: str) -> None:
    payload = _best_config(schema_path, validation={"winner_stability": _winner_stability()})
    assert list(_validator(schema_path).iter_errors(payload)) == []


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_every_winner_stability_member_is_optional(schema_path: str) -> None:
    full = _winner_stability()
    for member in full:
        partial = {k: v for k, v in full.items() if k != member}
        payload = _best_config(schema_path, validation={"winner_stability": partial})
        errors = list(_validator(schema_path).iter_errors(payload))
        assert errors == [], f"dropping optional member {member!r} must not fail"
    empty = _best_config(schema_path, validation={"winner_stability": {}})
    assert list(_validator(schema_path).iter_errors(empty)) == []


def test_publish_request_closure_resolves_winner_stability_refs_locally() -> None:
    payload = {
        "spec": _best_config(_V1, validation={"winner_stability": _winner_stability()}),
        "environment": "default",
    }
    errors = list(
        _validator("execution/best_config_publish_request_schema.json").iter_errors(payload)
    )
    assert errors == []


# --- malformed blocks are rejected --------------------------------------------


@pytest.mark.parametrize(
    "mutation",
    [
        {"reps": 0},
        {"reps": 1001},
        {"reps": 2.5},
        {"std": -0.001},
        {"scores": "not-a-list"},
        {"scores": [0.8, "high", 0.9]},
        {"config_hash": ""},
        {"config_hash": 123},
        {"evaluated_at": 1754870400},
    ],
)
@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_malformed_winner_stability_is_rejected(schema_path: str, mutation: dict[str, Any]) -> None:
    block = {**_winner_stability(), **mutation}
    payload = _best_config(schema_path, validation={"winner_stability": block})
    errors = list(_validator(schema_path).iter_errors(payload))
    assert errors != [], f"mutation {mutation!r} must be rejected"


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_scores_over_the_bound_are_rejected(schema_path: str) -> None:
    block = {**_winner_stability(), "scores": [0.5] * 1001}
    payload = _best_config(schema_path, validation={"winner_stability": block})
    assert list(_validator(schema_path).iter_errors(payload)) != []


@pytest.mark.parametrize("schema_path", [_V1, _V2])
def test_winner_stability_block_is_closed(schema_path: str) -> None:
    block = {**_winner_stability(), "guaranteed": True}
    payload = _best_config(schema_path, validation={"winner_stability": block})
    assert list(_validator(schema_path).iter_errors(payload)) != []


# --- single normative definition ----------------------------------------------


def test_v1_refs_the_v2_normative_definition_rather_than_repeating_it() -> None:
    schemas_dir = get_schemas_dir()
    v1 = _load(schemas_dir / _V1)
    v2 = _load(schemas_dir / _V2)

    v1_ref = v1["properties"]["validation"]["properties"]["winner_stability"]
    assert v1_ref == {"$ref": "./best_config_v2_schema.json#/definitions/winner_stability"}, (
        "v1 must $ref the single normative definition, not repeat the shape"
    )

    definition = v2["definitions"]["winner_stability"]
    assert definition["additionalProperties"] is False
    assert set(definition["properties"]) == {
        "reps",
        "mean",
        "std",
        "scores",
        "config_hash",
        "evaluated_at",
    }
    assert definition.get("required") is None, (
        "every winner_stability member is optional in this revision"
    )
    assert definition["properties"]["scores"]["maxItems"] == 1000
