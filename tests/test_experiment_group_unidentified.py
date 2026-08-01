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


def test_group_identity_invariant_admits_the_singleton_run_id() -> None:
    """run_id is a new identity field on the group object; the contract must say so.

    The document-level invariant used to read 'group identity is exactly
    agent_id plus canonical dataset_id'. Adding run_id without amending that
    sentence leaves a contract whose own summary contradicts its properties -
    the kind of drift a Backend or Frontend reader resolves by guessing.
    """
    description = _document()["description"]

    assert "run_id" in description, "the identity invariant never mentions run_id"
    assert "singleton" in description.lower()
    # ...and the invariant still forbids identity by content, which is the point.
    for forbidden in ("tuned variables", "fingerprints", "config hashes"):
        assert forbidden in description


def test_group_list_tie_break_includes_run_id_so_singletons_stay_orderable() -> None:
    """Every unidentified singleton has a null agent_id.

    The group-list tie-break was (agent_id, canonical dataset_id). Once several
    singletons exist they all share the key (null, null), so that pair is no
    longer a total order and the contract's promise of non-overlapping,
    non-skipping cursor windows cannot hold. run_id restores uniqueness.
    """
    document = _document()
    sort_field_description = document["definitions"]["ExperimentGroupSortField"]["description"]

    for haystack in (sort_field_description, document["description"]):
        lowered = haystack.lower()
        assert "agent_id ascending" in lowered
        assert "canonical dataset_id ascending" in lowered
        assert "run_id ascending" in lowered, "the tie-break is not a total order"
        assert "nulls ordered first" in lowered

    # The OpenAPI inline mirror must not drift from the authoritative field.
    spec_path = get_schemas_dir() / "execution" / "execution_endpoints.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    inline_sort_by = next(
        parameter
        for parameter in spec["paths"]["/api/v1/experiment-groups"]["get"]["parameters"]
        if parameter["name"] == "sort_by"
    )

    assert inline_sort_by["description"] == sort_field_description


def test_identified_group_may_still_have_no_dataset() -> None:
    """Pinned deliberately: the dataset half of the symmetry is NOT enforced.

    identity_state keys on agent identity only. dataset_id null on an
    identified group is the pre-existing explicit no-dataset group that
    dataset_scope='without_dataset' selects, and it stays valid. Whether a
    missing dataset identity should also force a singleton is an open owner
    decision; this test records the current, enforced answer so a future
    change is a visible decision rather than an accident.
    """
    errors = list(_validator().iter_errors(_identified_group(dataset_id=None)))

    assert errors == [], f"identified + no dataset must remain valid: {errors}"
