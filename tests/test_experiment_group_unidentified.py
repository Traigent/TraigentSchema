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


def _provenance_validator() -> Draft7Validator:
    """Validate a bare browse-row provenance object."""
    document = _document()
    return Draft7Validator(
        {**document, "$ref": "#/definitions/GroupedConfigurationRunProvenance"}
    )


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


def _identified_provenance(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "agent_id": "agt_123",
        "dataset_id": "dset_456",
        "identity_state": "identified",
        "experiment_name": "Prompt strategy sweep",
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


def test_unidentified_provenance_is_a_singleton_not_a_cohort() -> None:
    """The row-level identity must agree with the group-level discriminator."""
    singleton = _identified_provenance(
        agent_id=None,
        dataset_id=None,
        identity_state="unidentified",
    )

    assert list(_provenance_validator().iter_errors(singleton)) == []
    for field, invalid_value in (
        ("agent_id", "agt_123"),
        ("dataset_id", "dset_456"),
    ):
        invalid = dict(singleton)
        invalid[field] = invalid_value
        assert list(_provenance_validator().iter_errors(invalid)), field

    assert list(_provenance_validator().iter_errors(_identified_provenance(run_id="run_789")))


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
        assert "agent_id ascending with nulls ordered last" in lowered
        assert "canonical dataset_id ascending with nulls ordered first" in lowered
        assert "run_id ascending with nulls ordered first" in lowered
        assert "portable case null-rank terms" in lowered
        assert "agent_id nulls-last term" in lowered
        assert "run_id nulls-first does not establish" in lowered

    # The OpenAPI inline mirror must not drift from the authoritative field.
    spec_path = get_schemas_dir() / "execution" / "execution_endpoints.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    inline_sort_by = next(
        parameter
        for parameter in spec["paths"]["/api/v1/experiment-groups"]["get"]["parameters"]
        if parameter["name"] == "sort_by"
    )

    assert inline_sort_by["description"] == sort_field_description


def test_a_singleton_run_id_is_never_empty() -> None:
    """run_id is the singleton's entire identity AND the final tie-break term.

    An empty run_id makes two singletons collide twice over: on the cohort key
    and on the group-list ordering, restoring the non-total order that makes a
    cursor walk return a run twice or skip it.
    """
    singleton = dict(identity_state="unidentified", agent_id=None, dataset_id=None)

    assert list(_validator().iter_errors(_identified_group(run_id="", **singleton)))
    assert list(_validator().iter_errors(_identified_group(run_id="run_1", **singleton))) == []


def test_the_contract_defines_unidentified_symmetrically() -> None:
    """Either missing identity makes a singleton, and the summary must say so.

    The document-level description still defined an unidentified run as one
    whose AGENT was undeclared, contradicting the enforced rule and telling a
    Backend reader that a declared agent with an undeclared dataset is a group.
    """
    description = _document()["description"]

    assert "EITHER the agent or the dataset" in description
    assert "symmetric" in description


def test_explicit_none_dataset_stays_a_group() -> None:
    """null under 'identified' means the caller explicitly ran without a dataset.

    That is a real cohort and dataset_scope='without_dataset' still selects it.
    Losing this would break an already-shipped query surface.
    """
    errors = list(_validator().iter_errors(_identified_group(dataset_id=None)))

    assert errors == [], f"an explicit no-dataset group must stay valid: {errors}"


def test_a_singleton_carries_no_cohort_key() -> None:
    """The false merge, closed structurally.

    Two different undeclared inline datasets under one declared agent used to
    validate as (agent_id, null) twice and merge into a single cohort -- one
    agent's history showing runs that never shared a dataset. A singleton has
    no cohort, so it carries no cohort key: both agent_id and dataset_id are
    null and identity lives entirely in run_id.
    """
    for label, overrides in (
        ("agent_id on a singleton", {"agent_id": "agt_123"}),
        ("dataset_id on a singleton", {"dataset_id": "dset_456"}),
    ):
        item = _identified_group(
            **{
                "agent_id": None,
                "dataset_id": None,
                "identity_state": "unidentified",
                "run_id": "run_789",
                **overrides,
            }
        )
        assert list(_validator().iter_errors(item)), label


def test_null_dataset_means_two_different_things_and_the_state_says_which() -> None:
    """The distinction the whole B3 fix rests on, asserted directly.

    Same dataset_id (null), opposite meanings: explicit none under
    'identified', not-known under 'unidentified'. Overloading one null for
    both is what produced the false merge.
    """
    explicit_none = _identified_group(dataset_id=None)
    unknown = _identified_group(
        agent_id=None, dataset_id=None, identity_state="unidentified", run_id="run_789"
    )

    assert explicit_none["dataset_id"] == unknown["dataset_id"] is None
    assert list(_validator().iter_errors(explicit_none)) == []
    assert list(_validator().iter_errors(unknown)) == []
    assert explicit_none["identity_state"] != unknown["identity_state"]

    # And the contract says which is which, for the reader who has only the schema.
    dataset_description = _document()["definitions"]["CanonicalDatasetId"]["description"]
    assert "EXPLICITLY no dataset" in dataset_description
    scope_description = _document()["definitions"]["ExperimentGroupDatasetScope"]["description"]
    assert "does NOT select unidentified singletons" in scope_description


# ---- Expand-contract: identity_state is optional; absence means legacy ----


def test_identity_state_is_optional_at_the_top_level() -> None:
    """The active Backend does not yet emit identity_state on every item, so it
    must not be declared required — a required field the producer can't yet
    guarantee would make every legacy response invalid."""
    document = _document()
    overview_required = document["definitions"]["ExperimentGroupOverview"]["required"]
    provenance_required = document["definitions"]["GroupedConfigurationRunProvenance"][
        "required"
    ]

    assert "identity_state" not in overview_required
    assert "identity_state" not in provenance_required
    # agent_id / dataset_id remain required in both places.
    assert {"agent_id", "dataset_id"} <= set(overview_required)
    assert {"agent_id", "dataset_id"} <= set(provenance_required)


def test_identity_state_absence_is_not_a_third_enum_member() -> None:
    """The enum stays closed to identified/unidentified; there is no 'legacy'
    value. Legacy is expressed only by omitting the key entirely, never by a
    new enum member."""
    document = _document()
    identity_state = document["definitions"]["ExperimentGroupOverview"]["properties"][
        "identity_state"
    ]
    assert set(identity_state["enum"]) == {"identified", "unidentified"}

    errors = list(_validator().iter_errors(_identified_group(identity_state="legacy")))
    assert errors, "an explicit 'legacy' identity_state value must still be rejected"


def test_legacy_group_without_identity_state_accepts_string_agent_and_dataset() -> None:
    """Absence of identity_state is the live legacy cohort shape: a declared
    string agent_id and a string-or-null dataset_id, with no run_id."""
    legacy = _identified_group()
    legacy.pop("identity_state")
    assert list(_validator().iter_errors(legacy)) == []

    legacy_no_dataset = _identified_group(dataset_id=None)
    legacy_no_dataset.pop("identity_state")
    assert list(_validator().iter_errors(legacy_no_dataset)) == []


def test_legacy_group_without_identity_state_rejects_null_agent() -> None:
    """Absence means identity-unqualified legacy, never identified or
    unidentified: a legacy item never asserts that its agent is unknown."""
    legacy = _identified_group(agent_id=None)
    legacy.pop("identity_state")

    assert list(_validator().iter_errors(legacy))


def test_legacy_group_without_identity_state_accepts_explicit_null_run_id() -> None:
    """A legacy item may carry run_id as an explicit null, not only an absent
    key: run_id must stay null-or-absent, exactly like an identified cohort."""
    legacy = _identified_group(run_id=None)
    legacy.pop("identity_state")

    assert list(_validator().iter_errors(legacy)) == []


def test_legacy_group_without_identity_state_rejects_populated_run_id() -> None:
    """A legacy item is never a singleton: run_id must stay null or absent,
    exactly like an identified cohort."""
    legacy = _identified_group(run_id="run_789")
    legacy.pop("identity_state")

    assert list(_validator().iter_errors(legacy))


def test_legacy_provenance_without_identity_state_accepts_string_agent_and_dataset() -> None:
    legacy = _identified_provenance()
    legacy.pop("identity_state")
    assert list(_provenance_validator().iter_errors(legacy)) == []

    legacy_no_dataset = _identified_provenance(dataset_id=None)
    legacy_no_dataset.pop("identity_state")
    assert list(_provenance_validator().iter_errors(legacy_no_dataset)) == []


def test_legacy_provenance_without_identity_state_rejects_null_agent() -> None:
    legacy = _identified_provenance(agent_id=None)
    legacy.pop("identity_state")

    assert list(_provenance_validator().iter_errors(legacy))


def test_explicit_identified_rejects_null_agent_and_string_run_id() -> None:
    """An explicit identified item keeps its strict branch: agent_id must stay
    a string and run_id must stay null, even though identity_state itself is
    now optional at the top level."""
    assert list(_validator().iter_errors(_identified_group(agent_id=None)))
    assert list(_validator().iter_errors(_identified_group(run_id="run_789")))


def test_provenance_rejects_copied_run_id_in_every_state() -> None:
    """Provenance never carries run_id, in the identified, unidentified, or
    absence-only legacy branch alike — the enclosing row's experiment_run_id
    stays the single canonical source-execution identity."""
    identified_with_run_id = _identified_provenance(run_id="run_789")
    assert list(_provenance_validator().iter_errors(identified_with_run_id))

    unidentified_with_run_id = _identified_provenance(
        agent_id=None,
        dataset_id=None,
        identity_state="unidentified",
        run_id="run_789",
    )
    assert list(_provenance_validator().iter_errors(unidentified_with_run_id))

    legacy_with_run_id = _identified_provenance(run_id="run_789")
    legacy_with_run_id.pop("identity_state")
    assert list(_provenance_validator().iter_errors(legacy_with_run_id))
