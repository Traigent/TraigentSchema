"""Unidentified runs are singletons, never a shared bucket."""

from __future__ import annotations

import json
from typing import Any

from jsonschema import Draft7Validator

from traigent_schema.utils import get_schemas_dir


def _document() -> dict[str, Any]:
    path = get_schemas_dir() / "execution" / "experiment_group_schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _validator() -> Draft7Validator:
    """Validate a bare group item against ExperimentGroupOverview."""
    document = _document()
    return Draft7Validator({**document, "$ref": "#/definitions/ExperimentGroupOverview"})


def _identified_group(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "group_id": "grp_1234",
        "agent_id": "agt_123",
        "dataset_id": "dset_456",
        "identity_state": "identified",
        "experiment_count": 3,
        "experiment_run_count": 7,
        "configuration_run_count": 42,
        "created_at": "2026-06-30T08:00:00Z",
        "updated_at": "2026-06-30T09:00:00Z",
        "first_experiment_created_at": "2026-06-30T08:00:00Z",
        "last_experiment_updated_at": "2026-06-30T09:00:00Z",
        "first_experiment_run_created_at": "2026-06-30T08:05:00Z",
        "last_experiment_run_updated_at": "2026-06-30T08:55:00Z",
        "status_summary": {
            "experiment_run_status_counts": {"RUNNING": 1, "COMPLETED": 2},
            "configuration_run_status_counts": {"RUNNING": 1, "COMPLETED": 41},
        },
    }
    item.update(overrides)
    return item


def test_identified_group_validates() -> None:
    assert list(_validator().iter_errors(_identified_group())) == []


def test_unidentified_singleton_validates() -> None:
    item = _identified_group(
        agent_id=None,
        dataset_id=None,
        identity_state="unidentified",
        run_id="run_789",
    )

    assert list(_validator().iter_errors(item)) == []


def test_identity_state_rejects_unknown_values() -> None:
    errors = list(_validator().iter_errors(_identified_group(identity_state="maybe")))

    assert errors, "identity_state is a closed vocabulary"


def test_unidentified_item_requires_a_run_id() -> None:
    item = _identified_group(agent_id=None, dataset_id=None, identity_state="unidentified")

    errors = list(_validator().iter_errors(item))

    assert errors, "An unidentified item must carry the run_id it is a singleton for"


def test_identified_item_must_not_carry_a_run_id() -> None:
    errors = list(_validator().iter_errors(_identified_group(run_id="run_789")))

    assert errors, "run_id is meaningful only for unidentified singletons"
