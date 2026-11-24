"""Schema-first contract for additive experiment groups/cohorts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


SCHEMA_NAME = "experiment_group_schema"


def _load_schema(relative_path: str) -> dict[str, Any]:
    with (get_schemas_dir() / relative_path).open(encoding="utf-8") as handle:
        return json.load(handle)


def _pagination() -> dict[str, Any]:
    return {
        "page": 1,
        "per_page": 25,
        "total": 1,
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    }


def _success_envelope(data: dict[str, Any]) -> dict[str, Any]:
    return {"success": True, "message": "ok", "data": data}


def _group(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "group_id": "grp_agentA_dataset1",
        "agent_id": "agent_123",
        "dataset_id": "dataset_456",
        "identity_state": "identified",
        "experiment_count": 2,
        "experiment_run_count": 3,
        "configuration_run_count": 7,
        "created_at": "2026-06-30T08:00:00Z",
        "updated_at": "2026-06-30T09:00:00Z",
        "first_experiment_created_at": "2026-06-30T08:00:00Z",
        "last_experiment_updated_at": "2026-06-30T09:00:00Z",
        "first_experiment_run_created_at": "2026-06-30T08:05:00Z",
        "last_experiment_run_updated_at": "2026-06-30T08:55:00Z",
        "status_summary": {
            "experiment_run_status_counts": {
                "RUNNING": 1,
                "COMPLETED": 2,
            },
            "configuration_run_status_counts": {
                "RUNNING": 1,
                "COMPLETED": 6,
            },
        },
    }
    payload.update(overrides)
    return payload


def _source_experiment(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "experiment_id": "experiment_1",
        "name": "Prompt strategy sweep",
        "status": "COMPLETED",
        "experiment_run_count": 2,
        "configuration_run_count": 7,
        "created_at": "2026-06-30T08:00:00Z",
        "updated_at": "2026-06-30T09:00:00Z",
    }
    payload.update(overrides)
    return payload


def _configuration_run(**overrides: Any) -> dict[str, Any]:
    """A GroupedConfigurationRun carrying only the pre-existing (Wave-0) fields."""
    payload: dict[str, Any] = {
        "configuration_run_id": "config_run_1",
        "experiment_run_id": "experiment_run_1",
        "experiment_id": "experiment_1",
        "run_label": "morning batch",
        "run_name": None,
        "status": "COMPLETED",
        "created_at": "2026-06-30T08:10:00Z",
        "started_at": "2026-06-30T08:11:00Z",
        "completed_at": "2026-06-30T08:20:00Z",
        "updated_at": "2026-06-30T08:20:00Z",
        "configuration": {"model": "bedrock/nova", "temperature": 0.2},
        "parameters": {"model": "bedrock/nova", "temperature": 0.2},
    }
    payload.update(overrides)
    return payload


def _provenance(**overrides: Any) -> dict[str, Any]:
    # Provenance carries only group identity + display context. The canonical
    # source-execution ids live once at the row top level (see _configuration_run),
    # never duplicated here, because Draft 7 cannot assert sibling equality.
    payload: dict[str, Any] = {
        "agent_id": "agent_123",
        "dataset_id": "dataset_456",
        "identity_state": "identified",
        "experiment_name": "Prompt strategy sweep",
    }
    payload.update(overrides)
    return payload


def _browse_row(**overrides: Any) -> dict[str, Any]:
    """A row complete for browsing: every additive Wave-A field populated."""
    payload = _configuration_run(
        measures={"accuracy": 0.91, "latency_ms": 812.0, "unrecorded": None},
        summary_stats={"weighted_score": 0.88, "metrics": {"accuracy": 0.91}},
        error_state={
            "has_error": False,
            "error_code": None,
            "error_message_available": False,
        },
        provenance=_provenance(),
        comparison_state=None,
    )
    payload.update(overrides)
    return payload


def _column(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "kind": "parameter",
        "key": "temperature",
        "value_type": "number",
        "occurrence_count": 7,
        "filterable": True,
        "sortable": True,
    }
    payload.update(overrides)
    return payload


def _manifest(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scope": "full_group",
        "parameters": [_column()],
        "measures": [_column(kind="measure", key="accuracy")],
        "summary_stats": [_column(kind="summary_stat", key="weighted_score")],
    }
    payload.update(overrides)
    return payload


def _cursor_page(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {"next_cursor": "b3BhcXVl-cursor.1~", "has_more": True}
    payload.update(overrides)
    return payload


def _validator_for(definition: str) -> Draft7Validator:
    schema = _load_schema("execution/experiment_group_schema.json")
    subschema = dict(schema)
    subschema["properties"] = {"payload": {"$ref": f"#/definitions/{definition}"}}
    subschema["required"] = ["payload"]
    subschema["additionalProperties"] = False
    return Draft7Validator(
        subschema,
        registry=SchemaValidator()._registry,
        format_checker=FormatChecker(),
    )


def _errors(definition: str, payload: dict[str, Any]) -> list[Any]:
    return list(_validator_for(definition).iter_errors({"payload": payload}))


def test_group_list_response_uses_canonical_dataset_and_pagination() -> None:
    data = {
        "items": [_group()],
        "pagination": _pagination(),
    }

    assert _errors("ExperimentGroupListPayload", data) == []
    assert _errors("ExperimentGroupListResponse", _success_envelope(data)) == []
    assert _errors("ExperimentGroupListResponse", data)


def test_group_detail_envelope_carries_group_and_manifest_without_source_experiments() -> None:
    data = {"group": _group(), "column_manifest": _manifest()}

    assert _errors("ExperimentGroupDetailEnvelope", _success_envelope(data)) == []
    # source_experiments moved to experiment_group.list_group_experiments.
    assert _errors(
        "ExperimentGroupDetailEnvelope",
        _success_envelope({**data, "source_experiments": [_source_experiment()]}),
    )
    for field in ("group", "column_manifest"):
        incomplete = dict(data)
        incomplete.pop(field)
        assert _errors("ExperimentGroupDetailEnvelope", _success_envelope(incomplete)), field


def test_null_dataset_is_explicit_and_empty_dataset_is_rejected() -> None:
    no_dataset = _group(
        group_id="grp_agentA_no_dataset",
        dataset_id=None,
        first_experiment_run_created_at=None,
        last_experiment_run_updated_at=None,
    )
    empty_dataset = _group(dataset_id="")

    assert _errors("ExperimentGroupOverview", no_dataset) == []
    assert _errors("ExperimentGroupOverview", empty_dataset)


def test_dataset_label_is_optional_display_only_and_nullable() -> None:
    with_label = _group(dataset_label="Support Tickets v2")
    with_null_label = _group(dataset_label=None)
    without_label = _group()
    empty_label = _group(dataset_label="")

    assert _errors("ExperimentGroupOverview", with_label) == []
    assert _errors("ExperimentGroupOverview", with_null_label) == []
    assert "dataset_label" not in without_label
    assert _errors("ExperimentGroupOverview", without_label) == []
    assert _errors("ExperimentGroupOverview", empty_label)


def test_dataset_label_is_never_required_or_identity_constrained() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    overview = schema["definitions"]["ExperimentGroupOverview"]

    assert "dataset_label" not in overview["required"]

    # dataset_label must not be pinned or referenced by the identity_state
    # discriminator branches (identified / unidentified / absent-legacy):
    # it is display-only and orthogonal to group identity.
    for branch in overview["allOf"]:
        for clause in ("if", "then"):
            assert "dataset_label" not in branch.get(clause, {}).get("properties", {})

    # Sort/tie-break vocabulary must never gain a dataset_label member either.
    sort_field = schema["definitions"]["ExperimentGroupSortField"]
    assert "dataset_label" not in sort_field["enum"]


def test_agent_name_is_optional_display_only_and_nullable() -> None:
    with_name = _group(agent_name="Support Triage Agent")
    with_null_name = _group(agent_name=None)
    without_name = _group()
    empty_name = _group(agent_name="")

    assert _errors("ExperimentGroupOverview", with_name) == []
    assert _errors("ExperimentGroupOverview", with_null_name) == []
    assert "agent_name" not in without_name
    assert _errors("ExperimentGroupOverview", without_name) == []
    assert _errors("ExperimentGroupOverview", empty_name)


def test_agent_name_is_never_required_or_identity_constrained() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    overview = schema["definitions"]["ExperimentGroupOverview"]

    assert "agent_name" not in overview["required"]

    # agent_name is display-only and orthogonal to group identity: it must not
    # be pinned by any identity_state discriminator branch.
    for branch in overview["allOf"]:
        for clause in ("if", "then"):
            assert "agent_name" not in branch.get(clause, {}).get("properties", {})

    sort_field = schema["definitions"]["ExperimentGroupSortField"]
    assert "agent_name" not in sort_field["enum"]


def test_group_id_is_opaque_url_safe_lookup_token_only() -> None:
    assert _errors("ExperimentGroupOverview", _group(group_id="group_AbC-123")) == []
    assert _errors("ExperimentGroupOverview", _group(group_id="../tenant-a"))


def test_status_summary_uses_existing_status_vocabulary() -> None:
    unknown_status = _group(
        status_summary={
            "experiment_run_status_counts": {"succeeded": 1},
            "configuration_run_status_counts": {"COMPLETED": 1},
        }
    )

    assert _errors("ExperimentGroupOverview", unknown_status)


def test_grouped_configuration_rows_keep_source_identity_and_parameters() -> None:
    row = {
        "configuration_run_id": "config_run_1",
        "experiment_run_id": "experiment_run_1",
        "experiment_id": "experiment_1",
        "run_label": "morning batch",
        "run_name": None,
        "status": "COMPLETED",
        "created_at": "2026-06-30T08:10:00Z",
        "started_at": "2026-06-30T08:11:00Z",
        "completed_at": "2026-06-30T08:20:00Z",
        "updated_at": "2026-06-30T08:20:00Z",
        "configuration": {
            "model": "bedrock/nova",
            "temperature": 0.2,
        },
        "parameters": {
            "model": "bedrock/nova",
            "temperature": 0.2,
        },
    }

    assert _errors("GroupedConfigurationRun", row) == []
    without_source = dict(row)
    without_source.pop("configuration_run_id")
    assert _errors("GroupedConfigurationRun", without_source)


def test_grouped_configuration_run_trial_number_is_optional_nullable_positive() -> None:
    row = {
        "configuration_run_id": "config_run_1",
        "experiment_run_id": "experiment_run_1",
        "experiment_id": "experiment_1",
        "run_label": None,
        "run_name": None,
        "status": "COMPLETED",
        "created_at": "2026-06-30T08:10:00Z",
        "started_at": None,
        "completed_at": None,
        "updated_at": "2026-06-30T08:20:00Z",
        "configuration": {},
        "parameters": {},
    }
    schema = _load_schema("execution/experiment_group_schema.json")
    run = schema["definitions"]["GroupedConfigurationRun"]

    assert "trial_number" not in run["required"]
    assert _errors("GroupedConfigurationRun", row) == []
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": 1}) == []
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": None}) == []
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": 0})
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": -3})
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": 1.5})
    assert _errors("GroupedConfigurationRun", {**row, "trial_number": "2"})


def test_grouped_configuration_run_list_is_paginated() -> None:
    data = {
        "items": [
            {
                "configuration_run_id": "config_run_1",
                "experiment_run_id": "experiment_run_1",
                "experiment_id": "experiment_1",
                "run_label": None,
                "run_name": None,
                "status": "RUNNING",
                "created_at": "2026-06-30T08:10:00Z",
                "started_at": None,
                "completed_at": None,
                "updated_at": "2026-06-30T08:20:00Z",
                "configuration": {},
                "parameters": {},
            }
        ],
        "pagination": _pagination(),
    }

    assert _errors("GroupedConfigurationRunListPayload", data) == []
    assert _errors("GroupedConfigurationRunListResponse", _success_envelope(data)) == []
    assert _errors("GroupedConfigurationRunListResponse", data)


PROJECT_GROUPS = "/api/v1/projects/{project_id}/experiment-groups"
GROUP_OPERATIONS = {
    ("post", f"{PROJECT_GROUPS}/search"): (
        "experiment_group.list_groups",
        "ExperimentGroupsPageEnvelope",
    ),
    ("get", f"{PROJECT_GROUPS}/{{group_ref}}"): (
        "experiment_group.get_group",
        "ExperimentGroupDetailEnvelope",
    ),
    ("get", f"{PROJECT_GROUPS}/{{group_ref}}/configuration-runs"): (
        "experiment_group.list_group_runs",
        "GroupConfigurationRunsPageEnvelope",
    ),
    ("post", f"{PROJECT_GROUPS}/{{group_ref}}/configuration-runs/query"): (
        "experiment_group.query_group_runs",
        "GroupConfigurationRunsPageEnvelope",
    ),
    ("get", f"{PROJECT_GROUPS}/{{group_ref}}/experiments"): (
        "experiment_group.list_group_experiments",
        "GroupExperimentsPageEnvelope",
    ),
}


def test_openapi_wires_experiment_group_routes_to_response_schemas() -> None:
    spec = _load_schema("execution/execution_endpoints.json")

    for (method, path), (operation_id, definition) in GROUP_OPERATIONS.items():
        operation = spec["paths"][path][method]
        assert operation["operationId"] == operation_id
        ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        assert ref == f"./experiment_group_schema.json#/definitions/{definition}"

    # The retired unscoped /api/v1/experiment-groups paths are gone.
    assert not [p for p in spec["paths"] if p.startswith("/api/v1/experiment-groups")]


def test_schema_validator_loads_group_schema_and_no_request_body_routes_fail_open() -> None:
    validator = SchemaValidator(contract="backend")

    assert SCHEMA_NAME in validator.available_schemas
    assert validator.validate_json({"group": _group()}, SCHEMA_NAME) == []
    for path in (
        "/api/v1/projects/proj_123/experiment-groups/group_123",
        "/api/v1/projects/proj_123/experiment-groups/group_123/configuration-runs",
        "/api/v1/projects/proj_123/experiment-groups/group_123/experiments",
    ):
        assert validator.validate_request(path, "GET", {}) == []


def test_new_contract_file_is_under_execution_scope() -> None:
    path = Path(get_schemas_dir()) / "execution" / "experiment_group_schema.json"
    assert path.is_file()


# ---- Wave A: browse-row enrichment (measures / summary_stats / error / provenance) ----


def test_wave_a_row_fields_are_optional_so_existing_producers_stay_valid() -> None:
    """Back-compat: a pre-Wave-A row (no measures/provenance/...) must still validate."""
    assert _errors("GroupedConfigurationRun", _configuration_run()) == []
    assert _errors("GroupedConfigurationRun", _browse_row()) == []


def test_browse_row_requires_the_full_additive_field_set() -> None:
    """The query surface returns complete rows: each additive field is required there."""
    assert _errors("GroupedConfigurationRunBrowseRow", _browse_row()) == []

    for field in (
        "measures",
        "summary_stats",
        "error_state",
        "provenance",
        "comparison_state",
    ):
        incomplete = _browse_row()
        incomplete.pop(field)
        assert _errors("GroupedConfigurationRunBrowseRow", incomplete), field


def test_row_measures_follow_the_canonical_measuresdict_contract() -> None:
    assert _errors("GroupedConfigurationRun", _browse_row(measures=None)) == []
    assert _errors("GroupedConfigurationRun", _browse_row(measures={})) == []
    # null is "not recorded" — a legal value, distinct from 0.
    assert _errors("GroupedConfigurationRun", _browse_row(measures={"acc": None})) == []
    # non-numeric values, non-identifier keys, and >50 keys are rejected.
    assert _errors("GroupedConfigurationRun", _browse_row(measures={"acc": "high"}))
    assert _errors("GroupedConfigurationRun", _browse_row(measures={"9bad": 1}))
    assert _errors(
        "GroupedConfigurationRun",
        _browse_row(measures={f"m{i}": 1.0 for i in range(51)}),
    )


def test_row_summary_stats_reuse_canonical_definition_and_are_nullable() -> None:
    assert _errors("GroupedConfigurationRun", _browse_row(summary_stats=None)) == []
    assert (
        _errors("GroupedConfigurationRun", _browse_row(summary_stats={"weighted_score": None}))
        == []
    )
    assert _errors("GroupedConfigurationRun", _browse_row(summary_stats="0.9"))


def test_error_state_is_safe_and_carries_no_raw_error_text() -> None:
    failed = _browse_row(
        status="FAILED",
        error_state={
            "has_error": True,
            "error_code": "provider.timeout",
            "error_message_available": True,
        },
    )
    assert _errors("GroupedConfigurationRun", failed) == []

    # Unclassified failure: code null is legal.
    assert (
        _errors(
            "GroupedConfigurationRun",
            _browse_row(error_state={"has_error": True, "error_code": None}),
        )
        == []
    )
    # has_error/error_code are required; raw message text is NOT part of the contract.
    assert _errors("GroupedConfigurationRun", _browse_row(error_state={"has_error": True}))
    assert _errors(
        "GroupedConfigurationRun",
        _browse_row(
            error_state={
                "has_error": True,
                "error_code": "x.y",
                "error_message": "prompt 'my secret' failed",
            }
        ),
    )
    # error_code stays a bounded machine token, never free-form text.
    assert _errors(
        "GroupedConfigurationRun",
        _browse_row(error_state={"has_error": True, "error_code": "timed out: 'secret prompt'"}),
    )
    assert _errors(
        "GroupedConfigurationRun",
        _browse_row(error_state={"has_error": True, "error_code": "e" * 129}),
    )


def test_error_state_is_classified_aggregate_safe() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    error_state = schema["definitions"]["GroupedConfigurationRunErrorState"]
    assert error_state["x-privacy-classification"] == "aggregate_safe"
    assert error_state["properties"]["error_code"]["x-privacy-classification"] == "aggregate_safe"
    assert "error_message" not in error_state["properties"]


def test_provenance_carries_truthful_identity_not_duplicated_source_ids() -> None:
    assert _errors("GroupedConfigurationRunProvenance", _provenance()) == []
    # The no-dataset group is explicit; empty string still rejected.
    assert _errors("GroupedConfigurationRunProvenance", _provenance(dataset_id=None)) == []
    assert _errors("GroupedConfigurationRunProvenance", _provenance(dataset_id=""))
    assert _errors("GroupedConfigurationRunProvenance", _provenance(experiment_name=None)) == []

    # agent_id and dataset_id remain required in every row.
    for field in ("agent_id", "dataset_id"):
        incomplete = _provenance()
        incomplete.pop(field)
        assert _errors("GroupedConfigurationRunProvenance", incomplete), field

    # identity_state is optional (expand-contract): its absence is the legacy
    # branch, not a validation error, as long as the legacy shape holds.
    legacy = _provenance()
    legacy.pop("identity_state")
    assert _errors("GroupedConfigurationRunProvenance", legacy) == []


def test_unidentified_browse_row_carries_singleton_provenance() -> None:
    """A complete browse row must represent an unidentified singleton truthfully."""
    singleton_provenance = _provenance(
        agent_id=None,
        dataset_id=None,
        identity_state="unidentified",
    )

    assert _errors(
        "GroupedConfigurationRunBrowseRow", _browse_row(provenance=singleton_provenance)
    ) == []

    for field, invalid_value in (
        ("agent_id", "agent_123"),
        ("dataset_id", "dataset_456"),
    ):
        invalid = dict(singleton_provenance)
        invalid[field] = invalid_value
        assert _errors("GroupedConfigurationRunBrowseRow", _browse_row(provenance=invalid)), field

    # Singleton source identity remains at the browse-row top level, where it
    # is already required as experiment_run_id; provenance must not duplicate
    # an alias Draft 7 cannot prove equal.
    assert _browse_row(provenance=singleton_provenance)["experiment_run_id"] == "experiment_run_1"
    assert _errors("GroupedConfigurationRunProvenance", _provenance(run_id="run_123"))


def test_provenance_never_duplicates_the_canonical_source_execution_ids() -> None:
    """Draft 7 cannot compare siblings, so the source ids are NOT copied into
    provenance where a prose-only 'must equal' claim would silently drift. They
    stay canonical at the browse-row top level; provenance rejects them outright."""
    schema = _load_schema("execution/experiment_group_schema.json")
    provenance = schema["definitions"]["GroupedConfigurationRunProvenance"]
    disallowed_provenance_ids = {
        "experiment_id",
        "experiment_run_id",
        "configuration_run_id",
        "run_id",
    }

    # The redundant ids are absent from the provenance object entirely...
    assert not (set(provenance["properties"]) & disallowed_provenance_ids)
    # ...and additionalProperties:false makes re-introducing them a hard error.
    assert provenance["additionalProperties"] is False
    for source_id in disallowed_provenance_ids:
        assert _errors(
            "GroupedConfigurationRunProvenance", _provenance(**{source_id: "x"})
        ), source_id

    # The canonical ids remain required at the browse-row top level.
    row_required = set(
        schema["definitions"]["GroupedConfigurationRun"]["required"]
    )
    row_source_ids = {"experiment_id", "experiment_run_id", "configuration_run_id"}
    assert row_source_ids <= row_required
    for source_id in row_source_ids:
        incomplete = _browse_row()
        incomplete.pop(source_id)
        assert _errors("GroupedConfigurationRunBrowseRow", incomplete), source_id


def test_comparison_state_admits_only_unknown_or_null_in_wave_a() -> None:
    """Wave A makes no comparability claim; compare/rank is Wave B."""
    assert _errors("GroupedConfigurationRun", _browse_row(comparison_state=None)) == []
    assert _errors("GroupedConfigurationRun", _browse_row(comparison_state="unknown")) == []
    for claim in ("comparable", "better", "winner", "best"):
        assert _errors("GroupedConfigurationRun", _browse_row(comparison_state=claim)), claim


def test_rows_carry_no_ranking_or_winner_claim() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    row_properties = set(schema["definitions"]["GroupedConfigurationRun"]["properties"])
    forbidden = {"rank", "ranking", "winner", "is_winner", "is_best", "best", "score_rank"}
    assert not (row_properties & forbidden)


def test_group_identity_never_leaks_tvars_kpis_or_fingerprints() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    identity_properties = set(schema["definitions"]["ExperimentGroupOverview"]["properties"])
    forbidden = {
        "tvars",
        "tuned_variables",
        "kpis",
        "objectives",
        "config_hash",
        "configuration_hash",
        "fingerprint",
        "name",
    }
    assert not (identity_properties & forbidden)
    # Identity is agent_id + canonical dataset_id for a cohort, or run_id for an
    # unidentified singleton, discriminated by identity_state.
    assert {"agent_id", "dataset_id", "run_id", "identity_state"} <= identity_properties
    # Pinned as an exact set, not a subset: a subset check silently tolerates a
    # new identity field, which is how run_id itself landed here without the
    # contract's own identity invariant being updated to mention it.
    assert {name for name in identity_properties if name.endswith("_id")} == {
        "group_id",
        "agent_id",
        "dataset_id",
        "run_id",
    }


# ---- Wave A: full-group column manifest ----


def test_column_manifest_describes_the_full_group_not_the_current_page() -> None:
    assert _errors("GroupColumnManifest", _manifest()) == []
    # scope is pinned: a page-scoped manifest is not representable.
    assert _errors("GroupColumnManifest", _manifest(scope="page"))
    for field in ("scope", "parameters", "measures", "summary_stats"):
        incomplete = _manifest()
        incomplete.pop(field)
        assert _errors("GroupColumnManifest", incomplete), field


def test_column_manifest_is_complete_with_no_truncation_escape_hatch() -> None:
    """A truncated=true flag with no continuation is a dishonest completeness
    claim; the manifest has no such field and additionalProperties:false rejects
    it. The manifest is complete by construction or the response is invalid."""
    schema = _load_schema("execution/experiment_group_schema.json")
    manifest = schema["definitions"]["GroupColumnManifest"]
    assert "truncated" not in manifest["properties"]
    assert manifest["additionalProperties"] is False
    assert _errors("GroupColumnManifest", _manifest(truncated=True))


def test_column_manifest_namespaces_only_accept_their_own_kind() -> None:
    """Each namespace array accepts only descriptors of its own kind: a measure
    descriptor cannot masquerade as a parameter column, and vice versa."""
    assert _errors(
        "GroupColumnManifest", _manifest(parameters=[_column(kind="measure", key="accuracy")])
    )
    assert _errors(
        "GroupColumnManifest", _manifest(measures=[_column(kind="parameter", key="temperature")])
    )
    assert _errors(
        "GroupColumnManifest",
        _manifest(summary_stats=[_column(kind="measure", key="accuracy")]),
    )


def test_column_manifest_covers_columns_beyond_the_first_row_or_page() -> None:
    """The manifest is full-group: it legitimately lists a column whose
    occurrence_count spans rows far beyond the first page, and a column that
    appears on no early row at all - completeness is page-independent."""
    late_only = _manifest(
        parameters=[
            _column(key="temperature", occurrence_count=7),
            _column(key="top_p", occurrence_count=5000),
        ]
    )
    assert _errors("GroupColumnManifest", late_only) == []


def test_column_descriptor_occurrence_count_treats_missing_as_absence_never_zero() -> None:
    assert _errors("ColumnDescriptor", _column(occurrence_count=1)) == []
    # A descriptor exists only because the column occurs: 0 (and negatives) unrepresentable.
    assert _errors("ColumnDescriptor", _column(occurrence_count=0))
    assert _errors("ColumnDescriptor", _column(occurrence_count=-1))


def test_column_descriptor_bounds_key_and_pins_value_type_vocabulary() -> None:
    assert _errors("ColumnDescriptor", _column(key="k" * 128)) == []
    assert _errors("ColumnDescriptor", _column(key="k" * 129))
    assert _errors("ColumnDescriptor", _column(key=""))
    assert _errors("ColumnDescriptor", _column(value_type="mixed")) == []
    # "null" is not a value type — absence is absence, not a typed column.
    assert _errors("ColumnDescriptor", _column(value_type="null"))
    assert _errors("ColumnDescriptor", _column(kind="tvar"))


def test_column_descriptor_declares_filterability_and_sortability() -> None:
    for field in ("filterable", "sortable", "kind", "key", "value_type", "occurrence_count"):
        incomplete = _column()
        incomplete.pop(field)
        assert _errors("ColumnDescriptor", incomplete), field
    assert _errors("ColumnDescriptor", _column(filterable="yes"))


# ---- Wave A: cursor mode alongside page/per_page ----


def test_cursor_is_opaque_and_bounded() -> None:
    assert _errors("OpaqueCursor", "abcDEF-123_x.~") == []
    assert _errors("OpaqueCursor", "a" * 512) == []
    assert _errors("OpaqueCursor", "a" * 513)
    assert _errors("OpaqueCursor", "")
    # Structured / traversal-shaped cursors are not accepted.
    assert _errors("OpaqueCursor", '{"page":2}')
    assert _errors("OpaqueCursor", "../tenant-a")


def test_cursor_page_requires_next_cursor_and_has_more() -> None:
    assert _errors("CursorPage", _cursor_page()) == []
    assert _errors("CursorPage", _cursor_page(next_cursor=None, has_more=False)) == []
    assert _errors("CursorPage", {"has_more": False})
    assert _errors("CursorPage", {"next_cursor": None})
    assert _errors("CursorPage", _cursor_page(next_cursor='{"page":2}'))


def test_cursor_page_couples_has_more_with_cursor_nullness() -> None:
    """has_more true REQUIRES a non-null cursor; has_more false REQUIRES null.
    Neither ambiguous combination is representable."""
    # Valid, coupled combinations.
    assert _errors("CursorPage", {"has_more": True, "next_cursor": "cur.1~"}) == []
    assert _errors("CursorPage", {"has_more": False, "next_cursor": None}) == []
    # "More rows but no cursor to continue with" is rejected.
    assert _errors("CursorPage", {"has_more": True, "next_cursor": None})
    # "Walk complete yet here is a cursor" is rejected.
    assert _errors("CursorPage", {"has_more": False, "next_cursor": "cur.1~"})


def test_list_payloads_accept_cursor_mode_while_page_mode_stays_valid() -> None:
    """Back-compat: page/per_page payloads unchanged; cursor payloads newly allowed."""
    for definition, item in (
        ("ExperimentGroupListPayload", _group()),
        ("GroupedConfigurationRunListPayload", _configuration_run()),
    ):
        assert _errors(definition, {"items": [item], "pagination": _pagination()}) == []
        assert _errors(definition, {"items": [item], "cursor": _cursor_page()}) == []
        # Exactly one mode must drive the response: neither is invalid...
        assert _errors(definition, {"items": [item]})
        # ...and carrying BOTH pagination and cursor is equally invalid.
        assert _errors(
            definition,
            {"items": [item], "pagination": _pagination(), "cursor": _cursor_page()},
        )


def test_configuration_run_list_payload_may_carry_the_full_group_manifest() -> None:
    data = {
        "items": [_configuration_run()],
        "pagination": _pagination(),
        "column_manifest": _manifest(),
    }
    assert _errors("GroupedConfigurationRunListPayload", data) == []
    # Optional on this legacy surface, so existing producers stay valid.
    assert _errors("GroupedConfigurationRunListPayload", {
        "items": [_configuration_run()],
        "pagination": _pagination(),
    }) == []
    assert _errors("GroupedConfigurationRunListPayload", {**data, "column_manifest": {}})


# ---- Wave A: read-only configuration-run query surface ----


def test_query_request_is_valid_when_empty_and_bounds_every_filter() -> None:
    assert _errors("GroupedConfigurationRunQueryRequest", {}) == []

    full = {
        "source_experiment_ids": ["experiment_1", "experiment_2"],
        "source_experiment_run_ids": ["experiment_run_1"],
        "statuses": ["COMPLETED", "FAILED"],
        "created_at_from": "2026-06-01T00:00:00Z",
        "created_at_to": "2026-06-30T00:00:00Z",
        "updated_at_from": "2026-06-01T00:00:00Z",
        "updated_at_to": "2026-06-30T00:00:00Z",
        "predicates": [
            {"kind": "parameter", "key": "temperature", "op": "gte", "value": 0.5},
            {"kind": "measure", "key": "accuracy", "op": "is_not_null"},
            {"kind": "parameter", "key": "model", "op": "in", "value": ["a", "b"]},
        ],
        "sort": [{"kind": "measure", "key": "accuracy", "direction": "desc"}],
        "cursor": "b3BhcXVl-1",
        "limit": 50,
    }
    assert _errors("GroupedConfigurationRunQueryRequest", full) == []


def test_query_request_rejects_unbounded_id_status_and_date_filters() -> None:
    too_many = [f"experiment_{i}" for i in range(101)]
    assert _errors(
        "GroupedConfigurationRunQueryRequest", {"source_experiment_ids": too_many}
    )
    assert _errors(
        "GroupedConfigurationRunQueryRequest", {"source_experiment_run_ids": too_many}
    )
    assert _errors(
        "GroupedConfigurationRunQueryRequest", {"source_experiment_ids": ["a", "a"]}
    )
    assert _errors("GroupedConfigurationRunQueryRequest", {"source_experiment_ids": []})
    assert _errors("GroupedConfigurationRunQueryRequest", {"statuses": ["succeeded"]})
    assert _errors("GroupedConfigurationRunQueryRequest", {"limit": 0})
    assert _errors("GroupedConfigurationRunQueryRequest", {"limit": 201})


def test_query_request_cannot_mix_cursor_with_page_or_per_page() -> None:
    """The query surface is cursor-only by construction."""
    assert _errors("GroupedConfigurationRunQueryRequest", {"cursor": "c1", "page": 2})
    assert _errors("GroupedConfigurationRunQueryRequest", {"page": 1})
    assert _errors("GroupedConfigurationRunQueryRequest", {"per_page": 25})

    schema = _load_schema("execution/experiment_group_schema.json")
    request = schema["definitions"]["GroupedConfigurationRunQueryRequest"]
    assert request["additionalProperties"] is False
    assert "page" not in request["properties"]
    assert "per_page" not in request["properties"]


def test_query_predicates_and_sort_are_bounded_and_manifest_shaped() -> None:
    predicate = {"kind": "parameter", "key": "temperature", "op": "eq", "value": 0.2}
    assert _errors("ColumnPredicate", predicate) == []
    assert _errors("ColumnPredicate", {"kind": "measure", "key": "acc", "op": "is_null"}) == []
    assert _errors("ColumnPredicate", {**predicate, "op": "matches"})
    assert _errors("ColumnPredicate", {**predicate, "kind": "tvar"})
    assert _errors("ColumnPredicate", {**predicate, "key": "k" * 129})
    assert _errors("ColumnPredicate", {**predicate, "value": [1] * 101})
    assert _errors("ColumnPredicate", {**predicate, "value": {"nested": 1}})
    assert _errors("ColumnPredicate", {"kind": "parameter", "key": "t"})

    sort = {"kind": "measure", "key": "accuracy", "direction": "desc"}
    assert _errors("ColumnSort", sort) == []
    assert _errors("ColumnSort", {**sort, "direction": "ascending"})
    assert _errors("ColumnSort", {"kind": "measure", "key": "accuracy"})

    assert _errors(
        "GroupedConfigurationRunQueryRequest", {"predicates": [predicate] * 21}
    )
    assert _errors("GroupedConfigurationRunQueryRequest", {"sort": [sort] * 6})


def test_predicate_operator_and_operand_are_exclusive_variants() -> None:
    """Scalar operators take a scalar operand; in/not_in take a bounded non-empty
    scalar array; is_null/is_not_null take no operand at all."""
    base = {"kind": "parameter", "key": "temperature"}

    # Scalar operators: exactly one scalar operand.
    for op in ("eq", "ne", "gt", "gte", "lt", "lte"):
        assert _errors("ColumnPredicate", {**base, "op": op, "value": 0.2}) == [], op
        # A scalar operator with an ARRAY operand is rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": [0.2, 0.3]}), op
        # A scalar operator with a MISSING operand is rejected (value required).
        assert _errors("ColumnPredicate", {**base, "op": op}), op

    # in/not_in: a bounded, non-empty scalar array.
    for op in ("in", "not_in"):
        assert _errors("ColumnPredicate", {**base, "op": op, "value": ["a", "b"]}) == [], op
        # A scalar operand where a set is required is rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": "a"}), op
        # An empty set is rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": []}), op
        # A missing operand is rejected.
        assert _errors("ColumnPredicate", {**base, "op": op}), op

    # is_null/is_not_null: no operand permitted.
    for op in ("is_null", "is_not_null"):
        assert _errors("ColumnPredicate", {**base, "op": op}) == [], op
        # A null-check operator carrying a value is rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": 5}), op
        assert _errors("ColumnPredicate", {**base, "op": op, "value": None}), op


def test_predicate_operator_operand_coupling_is_enforced_on_the_validator_path() -> None:
    """The same op/operand coupling holds through the authoritative request
    validator, not only against the bare ColumnPredicate definition."""
    validator = SchemaValidator(contract="backend")
    path = "/api/v1/projects/proj_123/experiment-groups/group_123/configuration-runs/query"

    def _predicate(**over: Any) -> dict[str, Any]:
        pred = {"kind": "parameter", "key": "temperature", "op": "eq", "value": 0.2}
        pred.update(over)
        return pred

    # Well-formed predicates pass the route validator.
    assert validator.validate_request(path, "POST", {"predicates": [_predicate()]}) == []
    assert (
        validator.validate_request(
            path, "POST", {"predicates": [_predicate(op="in", value=["a", "b"])]}
        )
        == []
    )
    assert (
        validator.validate_request(
            path, "POST", {"predicates": [{"kind": "measure", "key": "acc", "op": "is_null"}]}
        )
        == []
    )
    # Scalar operator with an array operand is rejected on the validator path.
    assert validator.validate_request(
        path, "POST", {"predicates": [_predicate(value=[0.2, 0.3])]}
    )
    # Null-check operator carrying a value is rejected on the validator path.
    assert validator.validate_request(
        path,
        "POST",
        {"predicates": [{"kind": "measure", "key": "acc", "op": "is_null", "value": 1}]},
    )
    # Value-required operator with no operand is rejected on the validator path.
    assert validator.validate_request(
        path, "POST", {"predicates": [{"kind": "parameter", "key": "temperature", "op": "eq"}]}
    )
    # in with a scalar (non-array) operand is rejected on the validator path.
    assert validator.validate_request(
        path, "POST", {"predicates": [_predicate(op="in", value="a")]}
    )


def test_query_payload_returns_complete_rows_manifest_and_cursor() -> None:
    data = {
        "items": [_browse_row()],
        "column_manifest": _manifest(),
        "cursor": _cursor_page(),
    }
    assert _errors("GroupedConfigurationRunQueryPayload", data) == []
    assert _errors("GroupedConfigurationRunQueryResponse", _success_envelope(data)) == []
    assert _errors("GroupedConfigurationRunQueryResponse", data)

    for field in ("items", "column_manifest", "cursor"):
        incomplete = dict(data)
        incomplete.pop(field)
        assert _errors("GroupedConfigurationRunQueryPayload", incomplete), field

    # Rows on this surface must be complete browse rows.
    assert _errors(
        "GroupedConfigurationRunQueryPayload", {**data, "items": [_configuration_run()]}
    )
    # Window size stays bounded.
    assert _errors(
        "GroupedConfigurationRunQueryPayload", {**data, "items": [_browse_row()] * 201}
    )


def test_query_payload_stays_complete_when_comparison_semantics_are_unknown() -> None:
    """Browse rows must be fully usable before any Wave-B comparison signature exists."""
    data = {
        "items": [_browse_row(comparison_state="unknown"), _browse_row(comparison_state=None)],
        "column_manifest": _manifest(),
        "cursor": _cursor_page(next_cursor=None, has_more=False),
    }
    assert _errors("GroupedConfigurationRunQueryPayload", data) == []


def test_openapi_wires_the_read_only_query_route() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    path = f"{PROJECT_GROUPS}/{{group_ref}}/configuration-runs/query"
    operation = spec["paths"][path]["post"]

    assert operation["operationId"] == "experiment_group.query_group_runs"
    ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref == (
        "./experiment_group_schema.json#/definitions/GroupConfigurationRunsPageEnvelope"
    )
    body_ref = operation["requestBody"]["content"]["application/json"]["schema"]["allOf"][0]["$ref"]
    assert body_ref.endswith("experiment_group_schema.json#/definitions/GroupConfigurationRunQuery")
    # POST is a read carrier: the route must say so.
    description = operation["description"].lower()
    assert "a read, served as post" in description
    assert "query" in operation["summary"].lower()


def test_query_route_binds_its_request_schema_through_the_validator() -> None:
    validator = SchemaValidator(contract="backend")
    path = "/api/v1/projects/proj_123/experiment-groups/group_123/configuration-runs/query"

    # An empty body is a valid unfiltered first window...
    assert validator.validate_request(path, "POST", {}) == []
    assert validator.validate_request(path, "POST", {"cursor": "c1", "limit": 25}) == []
    # ...and the route no longer fails open on malformed queries.
    assert validator.validate_request(path, "POST", {"limit": 500})
    assert validator.validate_request(path, "POST", {"statuses": ["succeeded"]})
    assert validator.validate_request(path, "POST", {"page": 2})
    # Date bounds are enforced as RFC-3339 date-times on the authoritative
    # validator path (SchemaValidator installs the repo's format checker).
    assert validator.validate_request(path, "POST", {"created_at_from": "yesterday"})
    assert validator.validate_request(path, "POST", {"updated_at_to": "2026-06-01 00:00:00"})
    assert validator.validate_request(
        path, "POST", {"created_at_from": "2026-06-01T00:00:00Z"}
    ) == []


def _resolve_pointer(document: dict[str, Any], pointer: str) -> Any:
    node: Any = document
    for token in pointer.lstrip("#/").split("/"):
        node = node[token]
    return node


def _request_schema(spec: dict[str, Any], method: str, path: str) -> dict[str, Any]:
    """Resolve an operation's requestBody schema through the allOf wrapper."""
    body = spec["paths"][path][method]["requestBody"]["content"]["application/json"]["schema"]
    ref = body["allOf"][0]["$ref"]
    file_part, _, pointer = ref.partition("#")
    assert file_part == "./experiment_group_schema.json", ref
    return _resolve_pointer(_load_schema("execution/experiment_group_schema.json"), pointer)


def _response_schema(spec: dict[str, Any], method: str, path: str) -> dict[str, Any]:
    ref = spec["paths"][path][method]["responses"]["200"]["content"]["application/json"][
        "schema"
    ]["$ref"]
    file_part, _, pointer = ref.partition("#")
    assert file_part == "./experiment_group_schema.json", ref
    return _resolve_pointer(_load_schema("execution/experiment_group_schema.json"), pointer)


def _operation_validator(schema: dict[str, Any]) -> Draft7Validator:
    root = dict(_load_schema("execution/experiment_group_schema.json"))
    root.pop("properties", None)
    root.pop("required", None)
    root.pop("additionalProperties", None)
    root.update(schema)
    return Draft7Validator(
        root, registry=SchemaValidator()._registry, format_checker=FormatChecker()
    )


def test_group_search_route_is_a_cursor_only_post_with_the_filters_in_the_body() -> None:
    """Asserted against the OPERATION: POST .../search must carry the request body."""
    spec = _load_schema("execution/execution_endpoints.json")
    path = f"{PROJECT_GROUPS}/search"
    operation = spec["paths"][path]["post"]

    # Filters and search text are in the body, never query parameters.
    assert [p["name"] for p in operation["parameters"]] == ["project_id"]
    request = _request_schema(spec, "post", path)
    assert request["additionalProperties"] is False
    assert {
        "search",
        "agent_id",
        "dataset_id",
        "dataset_scope",
        "sort_by",
        "sort_order",
        "limit",
        "cursor",
    } == set(request["properties"])
    assert request["properties"]["search"]["maxLength"] == 200
    assert request["properties"]["dataset_scope"]["enum"] == [
        "all",
        "with_dataset",
        "without_dataset",
    ]
    assert request["properties"]["sort_by"]["enum"] == (
        _load_schema("execution/experiment_group_schema.json")["definitions"][
            "ExperimentGroupSortField"
        ]["enum"]
    )
    assert request["properties"]["limit"]["maximum"] == 100
    assert request["properties"]["limit"]["default"] == 20
    assert request["properties"]["cursor"]["maxLength"] == 4096

    validator = _operation_validator(request)
    assert list(validator.iter_errors({})) == []
    assert list(validator.iter_errors({"search": "x" * 200, "limit": 100})) == []
    for bad in (
        {"search": "x" * 201},
        {"limit": 101},
        {"limit": 0},
        {"cursor": "c" * 4097},
        {"dataset_scope": "none"},
        {"sort_by": "group_id"},
        {"page": 1},
        {"per_page": 10},
        {"offset": 0},
    ):
        assert list(validator.iter_errors(bad)), bad


def test_paged_get_routes_take_limit_and_cursor_only() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    for suffix in ("configuration-runs", "experiments"):
        operation = spec["paths"][f"{PROJECT_GROUPS}/{{group_ref}}/{suffix}"]["get"]
        by_name = {p["name"]: p for p in operation["parameters"]}
        assert set(by_name) == {"project_id", "group_ref", "limit", "cursor"}, suffix
        assert by_name["limit"]["schema"]["maximum"] == 100
        assert by_name["limit"]["schema"]["default"] == 20
        assert by_name["cursor"]["schema"]["maxLength"] == 4096


def test_no_dataset_filtering_is_explicit_rather_than_an_empty_string() -> None:
    assert _errors("ExperimentGroupDatasetScope", "without_dataset") == []
    assert _errors("ExperimentGroupDatasetScope", "with_dataset") == []
    assert _errors("ExperimentGroupDatasetScope", "all") == []
    assert _errors("ExperimentGroupDatasetScope", "")
    assert _errors("ExperimentGroupDatasetScope", "none")


def test_dataset_scope_defaults_to_all() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    dataset_scope = schema["definitions"]["ExperimentGroupDatasetScope"]
    assert dataset_scope["default"] == "all"
    assert "all" in dataset_scope["enum"]


STRICT_ERROR_REF = "#/definitions/ExperimentGroupErrorEnvelope"
SERVICE_UNAVAILABLE_ERROR_REF = (
    "#/definitions/ExperimentGroupServiceUnavailableErrorEnvelope"
)


GROUPS_PROBLEM_CODES = {
    "bad_request",
    "invalid_cursor",
    "invalid_page_size",
    "not_found",
    "payload_too_large",
    "service_unavailable",
    "unauthenticated",
    "validation_failed",
}
POST_OPERATIONS = {key for key in GROUP_OPERATIONS if key[0] == "post"}


def _problem_response_names(spec: dict[str, Any], path: str, method: str) -> dict[str, str]:
    responses = spec["paths"][path][method]["responses"]
    return {
        code: response["$ref"].rsplit("/", 1)[-1]
        for code, response in responses.items()
        if code.startswith(("4", "5"))
    }


EXPECTED_PROBLEM_RESPONSES = {
    "400": "GroupsBadRequest",
    "401": "GroupsUnauthenticated",
    "403": "GroupsForbidden",
    "404": "GroupsNotFound",
    "413": "GroupsPayloadTooLarge",
    "429": "GroupsRateLimited",
    "500": "GroupsInternalError",
    "503": "GroupsServiceUnavailable",
}


def test_read_surfaces_expose_closed_problem_responses_for_every_declared_status() -> None:
    """Every operation declares the same closed problem set (422 on all but the experiments listing),
    and each status resolves to its own Groups* response component."""
    spec = _load_schema("execution/execution_endpoints.json")

    for method, path in GROUP_OPERATIONS:
        names = _problem_response_names(spec, path, method)
        expected = dict(EXPECTED_PROBLEM_RESPONSES)
        # 422 is declared everywhere except the experiments listing.
        if not path.endswith("/experiments"):
            expected["422"] = "GroupsValidationFailed"
        assert names == expected, (path, method)

    not_found = spec["components"]["responses"]["GroupsNotFound"]
    assert "identical for absent, hidden and foreign groups" in not_found["description"]


def _problem_validator(spec: dict[str, Any]) -> Draft7Validator:
    return Draft7Validator(
        spec["components"]["schemas"]["GroupsProblem"], format_checker=FormatChecker()
    )


_PROBLEM_FIXED_TEXT = {
    "bad_request": (400, "Bad Request"),
    "forbidden": (403, "Forbidden"),
    "internal_error": (500, "Internal Server Error"),
    "invalid_cursor": (400, "Bad Request"),
    "invalid_page_size": (400, "Bad Request"),
    "not_found": (404, "Not Found"),
    "payload_too_large": (413, "Content Too Large"),
    "rate_limited": (429, "Too Many Requests"),
    "service_unavailable": (503, "Service Unavailable"),
    "unauthenticated": (401, "Unauthorized"),
    "validation_failed": (422, "Unprocessable Content"),
}


def _problem_body(branch: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    body = {
        name: spec["const"]
        for name, spec in branch["properties"].items()
        if "const" in spec
    }
    body["problem_id"] = "0123456789abcdef0123456789abcdef"
    body.update(overrides)
    return body


def test_group_problem_bodies_are_application_problem_json_with_a_closed_code() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    responses = spec["components"]["responses"]
    assert set(responses) == {
        "GroupsBadRequest",
        "GroupsUnauthenticated",
        "GroupsNotFound",
        "GroupsValidationFailed",
        "GroupsServiceUnavailable",
        "GroupsPayloadTooLarge",
        "GroupsForbidden",
        "GroupsRateLimited",
        "GroupsInternalError",
    }
    for name, response in responses.items():
        assert list(response["content"]) == ["application/problem+json"], name
        assert response["content"]["application/problem+json"]["schema"] == {
            "$ref": "#/components/schemas/GroupsProblem"
        }, name

    problem = spec["components"]["schemas"]["GroupsProblem"]
    branches = problem["oneOf"]
    assert {b["properties"]["code"]["const"] for b in branches} == set(_PROBLEM_FIXED_TEXT)
    assert len(branches) == len(_PROBLEM_FIXED_TEXT)
    for branch in branches:
        code = branch["properties"]["code"]["const"]
        status, title = _PROBLEM_FIXED_TEXT[code]
        assert branch["additionalProperties"] is False, code
        assert set(branch["required"]) == {
            "type",
            "title",
            "status",
            "code",
            "detail",
            "problem_id",
        }, code
        assert branch["properties"]["status"]["const"] == status, code
        assert branch["properties"]["title"]["const"] == title, code
        assert branch["properties"]["problem_id"] == {
            "type": "string",
            "pattern": "^[0-9a-f]{32}$",
            "minLength": 32,
            "maxLength": 32,
        }, code


def test_group_problem_bodies_reject_request_derived_text_and_extra_fields() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    validator = _problem_validator(spec)
    for branch in spec["components"]["schemas"]["GroupsProblem"]["oneOf"]:
        code = branch["properties"]["code"]["const"]
        good = _problem_body(branch)
        assert list(validator.iter_errors(good)) == [], code
        # Request-derived detail text is rejected: detail is a fixed constant.
        assert list(validator.iter_errors({**good, "detail": "project grp_secretvalue"})), code
        # An extra (possibly request-derived) field is rejected.
        assert list(validator.iter_errors({**good, "echo": "grp_secretvalue"})), code
        # problem_id must be 32 lowercase hex.
        assert list(validator.iter_errors({**good, "problem_id": "GRP_secretvalue"})), code
        # A trailing newline is rejected (a bare pattern would accept it).
        assert list(
            validator.iter_errors({**good, "problem_id": "0123456789abcdef0123456789abcdef\n"})
        ), code
        # A missing field is rejected.
        assert list(validator.iter_errors({k: v for k, v in good.items() if k != "detail"})), code
    # An unknown code is rejected.
    assert list(
        validator.iter_errors(
            {
                "type": "urn:traigent:problem:other",
                "title": "Other",
                "status": 400,
                "code": "other",
                "detail": "x",
                "problem_id": "0123456789abcdef0123456789abcdef",
            }
        )
    )


def test_every_operation_error_response_resolves_to_the_closed_problem() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    problem = spec["components"]["schemas"]["GroupsProblem"]
    codes_by_status: dict[int, set[str]] = {}
    for branch in problem["oneOf"]:
        status = branch["properties"]["status"]["const"]
        codes_by_status.setdefault(status, set()).add(branch["properties"]["code"]["const"])
    for method, path in GROUP_OPERATIONS:
        for code, response in spec["paths"][path][method]["responses"].items():
            if not code.startswith(("4", "5")):
                continue
            target = _resolve_pointer(spec, response["$ref"])
            schema_ref = target["content"]["application/problem+json"]["schema"]["$ref"]
            assert schema_ref == "#/components/schemas/GroupsProblem", (path, method, code)
            # The declared status has a matching closed branch in GroupsProblem.
            assert int(code) in codes_by_status, (path, method, code)


def test_active_success_envelopes_are_closed_over_success_message_and_data() -> None:
    """Every ACTIVE W9 operation's 200 is an envelope that requires success (const true),
    a non-empty message and data."""
    spec = _load_schema("execution/execution_endpoints.json")
    page = {"limit": 20, "next_cursor": None, "has_more": False}
    samples = {
        "experiment_group.list_groups": {"items": [_group()], "pagination": page},
        "experiment_group.get_group": {"group": _group(), "column_manifest": _manifest()},
        "experiment_group.list_group_runs": {
            "items": [_browse_row()],
            "column_manifest": _manifest(),
            "pagination": page,
        },
        "experiment_group.query_group_runs": {
            "items": [_browse_row()],
            "column_manifest": _manifest(),
            "pagination": page,
        },
        "experiment_group.list_group_experiments": {
            "items": [_source_experiment()],
            "pagination": page,
        },
    }
    for (method, path), (operation_id, _definition) in GROUP_OPERATIONS.items():
        envelope = _response_schema(spec, method, path)
        assert set(envelope["required"]) == {"success", "message", "data"}, operation_id
        assert envelope["properties"]["success"]["const"] is True, operation_id
        assert envelope["properties"]["message"]["minLength"] == 1, operation_id
        validator = _operation_validator(envelope)
        good = {"success": True, "message": "ok", "data": samples[operation_id]}
        assert list(validator.iter_errors(good)) == [], operation_id
        assert list(validator.iter_errors({**good, "success": False})), operation_id
        assert list(validator.iter_errors({**good, "message": ""})), operation_id
        assert list(
            validator.iter_errors({k: v for k, v in good.items() if k != "message"})
        ), operation_id
        assert list(
            validator.iter_errors({k: v for k, v in good.items() if k != "data"})
        ), operation_id


def _strict_error(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "success": False,
        "message": "The experiment group could not be found.",
        "error": "not_found",
    }
    payload.update(overrides)
    return payload


def _generic_error_validator() -> Draft7Validator:
    schema = _load_schema("error_envelope_schema.json")
    return Draft7Validator(schema, format_checker=FormatChecker())


def test_strict_error_subtype_is_shape_compatible_with_the_generic_envelope() -> None:
    """Every value the strict subtype accepts is also valid under the canonical
    generic error envelope, so existing generic-error consumers keep working."""
    generic = _generic_error_validator()
    for payload in (
        _strict_error(),
        _strict_error(error="bad_request", error_code="validation.limit_out_of_range"),
        _strict_error(error="unauthorized", message="Authentication is required."),
        _strict_error(error="internal_error", message="An unexpected error occurred."),
    ):
        assert _errors("ExperimentGroupErrorEnvelope", payload) == [], payload
        assert list(generic.iter_errors(payload)) == [], payload


def test_strict_error_subtype_forbids_details_and_open_error_vocabulary() -> None:
    """The generic envelope's free-form 'details' sink and open 'error' string are
    both removed: details is rejected outright and 'error' is a closed vocabulary,
    even though the generic envelope accepts both."""
    generic = _generic_error_validator()

    # A details object is valid under the generic envelope...
    with_details = _strict_error(details={"query": "SELECT * FROM experiment_groups"})
    assert list(generic.iter_errors(with_details)) == []
    # ...but the strict subtype forbids it structurally (no property + no additionalProperties).
    assert _errors("ExperimentGroupErrorEnvelope", with_details)

    schema = _load_schema("execution/experiment_group_schema.json")
    strict = schema["definitions"]["ExperimentGroupErrorEnvelope"]
    assert strict["additionalProperties"] is False
    assert "details" not in strict["properties"]

    # 'error' is a closed server-controlled vocabulary; an open string is rejected.
    assert _errors("ExperimentGroupErrorEnvelope", _strict_error(error="something_new"))
    assert set(strict["properties"]["error"]["enum"]) == {
        "bad_request",
        "unauthorized",
        "not_found",
        "internal_error",
    }
    # No 'forbidden' token exists — forbidden-vs-not-found never leaks.
    assert "forbidden" not in strict["properties"]["error"]["enum"]


def test_strict_error_subtype_rejects_raw_query_group_sql_and_secret_content() -> None:
    """No raw query text, group id, SQL, or secret can validate: message is
    display-safe/bounded, error is a closed enum, error_code is a server token,
    and there is no details sink."""
    # Sentinel raw/SQL/secret content dumped into 'error' (open string) — rejected.
    for sentinel in (
        "SELECT * FROM experiment_groups WHERE agent_id='a'",
        "'; DROP TABLE experiment_groups; --",
        "api_key=sk-live-SECRET",
    ):
        assert _errors("ExperimentGroupErrorEnvelope", _strict_error(error=sentinel)), sentinel

    # The same content in 'error_code' fails the server-token grammar.
    for sentinel in (
        "SELECT * FROM t",
        "'; DROP TABLE x; --",
        "sk-live-SECRET value",
        "UPPER_CASE",
    ):
        assert _errors(
            "ExperimentGroupErrorEnvelope", _strict_error(error_code=sentinel)
        ), sentinel

    # The same content in 'message' fails the display-safe pattern (quotes,
    # semicolons, angle brackets, braces, backticks, backslashes are forbidden).
    for sentinel in (
        "query was: SELECT * FROM t WHERE name='bob'",
        "'; DROP TABLE experiment_groups; --",
        "<script>steal()</script>",
        "leaked {\"secret\": \"value\"}",
    ):
        assert _errors(
            "ExperimentGroupErrorEnvelope", _strict_error(message=sentinel)
        ), sentinel

    # A raw details object is rejected regardless of its (redacted-looking) content.
    assert _errors(
        "ExperimentGroupErrorEnvelope",
        _strict_error(details={"offending_value": "grp_../../etc/passwd"}),
    )

    # message and error_code stay bounded.
    assert _errors("ExperimentGroupErrorEnvelope", _strict_error(message="x" * 201))
    assert _errors(
        "ExperimentGroupErrorEnvelope", _strict_error(error_code="a" + "b" * 64)
    )
    # success must be the false discriminator.
    assert _errors("ExperimentGroupErrorEnvelope", _strict_error(success=True))


# The opaque-token sentinel: a benign-looking lowercase token that is a legal
# group id, and that the PRIOR draft (character-set 'message' + lowercase-token
# 'error_code') wrongly accepted in every public string field. Every public
# field of the strict envelope must now reject it.
OPAQUE_ID_SENTINEL = "grp_secretvalue"


def _strict_error_public_enums() -> dict[str, list[str]]:
    schema = _load_schema("execution/experiment_group_schema.json")
    props = schema["definitions"]["ExperimentGroupErrorEnvelope"]["properties"]
    return {field: props[field]["enum"] for field in ("message", "error", "error_code")}


def test_strict_error_public_fields_are_finite_fixed_enums() -> None:
    """Redaction is structural: message, error, and error_code are each a finite,
    fixed enum. No length/pattern escape hatch survives on any public string, so a
    field can only carry a value the server itself enumerated."""
    schema = _load_schema("execution/experiment_group_schema.json")
    props = schema["definitions"]["ExperimentGroupErrorEnvelope"]["properties"]

    for field in ("message", "error", "error_code"):
        spec = props[field]
        assert isinstance(spec.get("enum"), list), field
        assert spec["enum"], field
        # A closed enum leaves no character-set / token-grammar escape hatch.
        assert "pattern" not in spec, field
        # Every enumerated value is a non-empty string (generic-envelope minLength 1).
        for value in spec["enum"]:
            assert isinstance(value, str), (field, value)
            assert value, (field, value)

    # The enums are exactly the intended closed vocabularies.
    assert set(props["error"]["enum"]) == {
        "bad_request",
        "unauthorized",
        "not_found",
        "internal_error",
    }
    assert set(props["message"]["enum"]) == {
        "The request could not be processed.",
        "Authentication is required.",
        "The experiment group could not be found.",
        "An unexpected error occurred.",
    }
    assert set(props["error_code"]["enum"]) == {
        "validation.malformed_request",
        "validation.malformed_group_id",
        "validation.limit_out_of_range",
        "auth.required",
        "group.not_found",
        "internal.unexpected",
    }


def test_strict_error_rejects_the_opaque_id_sentinel_in_every_public_field() -> None:
    """Decisive regression for the redaction finding: the SAME opaque token
    'grp_secretvalue' that is a legal group id must NOT validate as message,
    error, or error_code. The prior character-set/token-grammar draft accepted it
    in message and error_code; the finite enums now reject it everywhere."""
    generic = _generic_error_validator()

    for field in ("message", "error", "error_code"):
        payload = _strict_error(**{field: OPAQUE_ID_SENTINEL})
        assert _errors("ExperimentGroupErrorEnvelope", payload), field

    # The sentinel is genuinely group-id-shaped: it validates as an
    # OpaqueExperimentGroupId, proving the envelope is not just rejecting
    # malformed junk but a real, benign-looking identifier.
    assert _errors("OpaqueExperimentGroupId", OPAQUE_ID_SENTINEL) == []

    # A raw group id, a raw query, and a secret-shaped token are all rejected in
    # both free-text-capable fields (message and error_code).
    for sentinel in (
        OPAQUE_ID_SENTINEL,
        "grp_agentA_dataset1",
        "select_star_from_experiment_groups",
        "sk_live_secretvalue",
    ):
        assert _errors("ExperimentGroupErrorEnvelope", _strict_error(message=sentinel)), sentinel
        assert _errors(
            "ExperimentGroupErrorEnvelope", _strict_error(error_code=sentinel)
        ), sentinel
        # The same token in 'error' is likewise rejected (closed vocabulary)...
        assert _errors("ExperimentGroupErrorEnvelope", _strict_error(error=sentinel)), sentinel
        # ...even though the GENERIC envelope (open strings) would have accepted it,
        # which is exactly the leak the strict subtype closes.
        assert list(generic.iter_errors(_strict_error(message=sentinel, error="not_found"))) == []


def test_strict_error_positive_covers_every_backend_error_and_code_combination() -> None:
    """Positive coverage: every allowed error, every allowed display message, and
    every allowed error_code that Backend can emit validates against the strict
    subtype AND stays shape-compatible with the canonical generic envelope. This
    is the retained white-list the negative sentinel tests are the complement of."""
    enums = _strict_error_public_enums()
    generic = _generic_error_validator()

    # Every closed error value, paired with every fixed display message, validates
    # (message and error are intentionally decoupled: both are server-controlled).
    for error in enums["error"]:
        for message in enums["message"]:
            payload = _strict_error(error=error, message=message)
            assert _errors("ExperimentGroupErrorEnvelope", payload) == [], payload
            assert list(generic.iter_errors(payload)) == [], payload

    # Every fixed error_code is accepted (optional field) and shape-compatible.
    for error_code in enums["error_code"]:
        payload = _strict_error(error="bad_request", error_code=error_code)
        assert _errors("ExperimentGroupErrorEnvelope", payload) == [], payload
        assert list(generic.iter_errors(payload)) == [], payload

    # error_code is optional: omitting it entirely stays valid.
    minimal = _strict_error()
    assert "error_code" not in minimal
    assert _errors("ExperimentGroupErrorEnvelope", minimal) == []


def test_group_scoped_error_routes_point_at_the_problem_components_not_the_generic() -> None:
    """Every experiment-group 4xx/5xx references a Groups* problem component, never
    the generic envelope directly."""
    spec = _load_schema("execution/execution_endpoints.json")
    for method, path in GROUP_OPERATIONS:
        responses = spec["paths"][path][method]["responses"]
        for code, response in responses.items():
            if not code.startswith(("4", "5")):
                continue
            assert set(response) == {"$ref"}, (path, method, code)
            assert response["$ref"].startswith("#/components/responses/Groups"), (
                path,
                method,
                code,
            )


def test_auth_backend_unavailable_503_shapes_stay_finite_and_redacted() -> None:
    """The ExperimentGroupServiceUnavailableErrorEnvelope definition keeps both
    supported middleware shapes as exact server-controlled constants."""
    public_shapes = (
        {
            "success": False,
            "message": "Authentication temporarily unavailable",
            "error": "AUTH_BACKEND_UNAVAILABLE",
            "error_code": "AUTH_BACKEND_UNAVAILABLE",
        },
        {
            "success": False,
            "message": "Internal server error",
            "error": "Internal server error",
            "error_code": "AUTH_BACKEND_UNAVAILABLE",
        },
    )
    generic = _generic_error_validator()
    for payload in public_shapes:
        assert _errors("ExperimentGroupServiceUnavailableErrorEnvelope", payload) == []
        assert list(generic.iter_errors(payload)) == []

        with_details = {**payload, "details": {"database": "secret-host"}}
        assert _errors("ExperimentGroupServiceUnavailableErrorEnvelope", with_details)

        for field in ("message", "error", "error_code"):
            leaked = {**payload, field: "request-derived-sensitive-value"}
            assert _errors("ExperimentGroupServiceUnavailableErrorEnvelope", leaked), field


def test_every_group_ref_route_declares_a_bounded_group_ref_and_a_safe_400() -> None:
    """Routes addressed by group_ref carry a bounded opaque path parameter and a closed
    400 for a malformed reference."""
    spec = _load_schema("execution/execution_endpoints.json")
    for method, path in GROUP_OPERATIONS:
        if "{group_ref}" not in path:
            continue
        operation = spec["paths"][path][method]
        group_param = next(p for p in operation["parameters"] if p["name"] == "group_ref")
        assert group_param["in"] == "path" and group_param["required"] is True
        assert group_param["schema"] == {"type": "string", "minLength": 1, "maxLength": 128}
        assert operation["responses"]["400"] == {"$ref": "#/components/responses/GroupsBadRequest"}


def test_group_routes_are_cursor_only_and_project_scoped() -> None:
    """Cursor-only paging: no page, per_page or offset anywhere (query parameters or
    request bodies), and every operation is scoped by a bounded project_id."""
    spec = _load_schema("execution/execution_endpoints.json")
    schema = _load_schema("execution/experiment_group_schema.json")["definitions"]
    for method, path in GROUP_OPERATIONS:
        operation = spec["paths"][path][method]
        names = {p["name"] for p in operation["parameters"]}
        assert not names & {"page", "per_page", "offset"}, (path, method)
        project = next(p for p in operation["parameters"] if p["name"] == "project_id")
        assert project["schema"] == {"type": "string", "minLength": 1, "maxLength": 128}
    for body in ("ExperimentGroupSearchRequest", "GroupConfigurationRunQuery"):
        properties = schema[body]["properties"]
        assert schema[body]["additionalProperties"] is False
        assert not set(properties) & {"page", "per_page", "offset"}, body
    for envelope in (
        "ExperimentGroupsPageEnvelope",
        "GroupConfigurationRunsPageEnvelope",
        "GroupExperimentsPageEnvelope",
    ):
        data = schema[envelope]["properties"]["data"]
        assert data["properties"]["pagination"] == {"$ref": "#/definitions/GroupPageBlock"}


def test_group_list_sort_vocabulary_is_closed_and_identity_scoped() -> None:
    for field in ("created_at", "updated_at", "agent_id", "experiment_count"):
        assert _errors("ExperimentGroupSortField", field) == [], field
    # Never sortable by comparison-flavoured or tuned-variable fields.
    for field in ("weighted_score", "tvars", "config_hash", "rank", "name"):
        assert _errors("ExperimentGroupSortField", field), field


def test_group_list_tie_break_is_canonical_identity_not_opaque_group_id() -> None:
    """The group-list deterministic tie-break is the group's canonical visible
    identity - agent_id ascending nulls last, canonical dataset_id ascending nulls
    first, then run_id ascending nulls first - applied after the requested primary
    sort and fixed independent of the primary field and direction. The opaque group_id is
    NOT the mandated sort/tie-break key: it is a non-reversible SHA-derived token
    that cannot back exact SQL-bounded cursor pagination. This regression pins the
    amended contract so a reversion to 'group_id ascending' fails."""
    schema = _load_schema("execution/experiment_group_schema.json")

    # (1) group_id is not, and never becomes, a sortable group-list field.
    assert _errors("ExperimentGroupSortField", "group_id")
    assert "group_id" not in schema["definitions"]["ExperimentGroupSortField"]["enum"]

    sort_field_desc = schema["definitions"]["ExperimentGroupSortField"]["description"].lower()
    top_desc = schema["description"].lower()

    for haystack in (sort_field_desc, top_desc):
        # (2) The canonical-identity tie-break is spelled out for Backend/Frontend.
        assert "agent_id ascending" in haystack
        assert "canonical dataset_id ascending" in haystack
        # (3) Explicit, cross-dialect null placement for every identity term.
        assert "agent_id ascending with nulls ordered last" in haystack
        assert "canonical dataset_id ascending with nulls ordered first" in haystack
        assert "run_id ascending with nulls ordered first" in haystack
        assert "portable case null-rank terms" in haystack
        assert "agent_id nulls-last term" in haystack
        assert "run_id nulls-first does not establish" in haystack
        # (4) The tie-break is a secondary tie after the primary sort, and is
        #     fixed independent of the requested primary direction.
        assert "independent of" in haystack
        assert "direction" in haystack
        # (5) group_id is explicitly rejected as the tie-break key, with the
        #     load-bearing reason (non-reversible / not range-bounded).
        assert "group_id is" in haystack
        assert "not the" in haystack
        assert "range-bounded" in haystack or "range-orderable" in haystack

    # (6) The old mandate 'group_id ascending' as the tie-break must be gone.
    assert "group_id ascending" not in sort_field_desc
    assert "group_id ascending for groups" not in top_desc

    # (6b) The search request's sort_by carries exactly the authoritative field enum.
    search_request = schema["definitions"]["ExperimentGroupSearchRequest"]
    assert search_request["properties"]["sort_by"]["enum"] == (
        schema["definitions"]["ExperimentGroupSortField"]["enum"]
    )

    # (7) The row-level configuration-run tie-break is untouched: still
    #     configuration_run_id ascending, and the group amendment did not bleed
    #     into it.
    query_sort_desc = (
        schema["definitions"]["GroupedConfigurationRunQueryRequest"]["properties"]["sort"][
            "description"
        ].lower()
    )
    assert "configuration_run_id ascending" in query_sort_desc

    # (8) Identity is scope + agent_id + canonical dataset_id for a cohort, or
    #     run_id for an unidentified singleton. run_id also joins the tie-break:
    #     singletons all carry a null agent_id, so (agent_id, dataset_id) alone
    #     stopped being a total order the moment they were introduced.
    identity_properties = set(schema["definitions"]["ExperimentGroupOverview"]["properties"])
    assert {"agent_id", "dataset_id", "run_id"} <= identity_properties
    for haystack in (sort_field_desc, top_desc):
        assert "run_id ascending" in haystack


def test_contract_documents_auth_non_disclosure_and_pagination_invariants() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    description = schema["description"].lower()

    # Tokens are lookup/continuation only — never an authorization boundary.
    assert "tokens are not an authorization boundary" in description
    assert "never derive scope or identity from a token" in description
    # Non-disclosure: forbidden must be indistinguishable from not-found.
    assert "indistinguishable" in description
    # Deterministic ordering.
    assert "deterministic" in description
    assert "tie-breaker" in description
    # No auto cross-page column discovery.
    assert "never by walking pages" in description

    cursor_description = schema["definitions"]["OpaqueCursor"]["description"].lower()
    assert "never an authorization boundary" in cursor_description
    assert "insert-stable snapshot" in cursor_description
    assert "eventually consistent" in cursor_description

    manifest_description = schema["definitions"]["GroupColumnManifest"]["description"].lower()
    assert "independent of the current page" in manifest_description
    assert "never discover columns by walking pages" in manifest_description


# ---- Fix 4: predicate operands exclude null; sets are non-empty, bounded, unique ----


PREDICATE_STRING_MAX_LENGTH = 255


def test_predicate_string_operands_are_consistently_bounded() -> None:
    """Scalar strings and every in/not_in string member share one finite cap.

    The duplicated value schemas are intentional Draft 7 operator coupling, so
    assert all four locations to prevent an outer/variant branch from drifting.
    """
    schema = _load_schema("execution/experiment_group_schema.json")
    predicate = schema["definitions"]["ColumnPredicate"]

    outer_scalar = predicate["properties"]["value"]["oneOf"][0]
    outer_set_member = predicate["properties"]["value"]["oneOf"][1]["items"]
    scalar_variant = predicate["oneOf"][0]["properties"]["value"]
    set_variant_member = predicate["oneOf"][1]["properties"]["value"]["items"]

    for branch in (outer_scalar, outer_set_member, scalar_variant, set_variant_member):
        assert branch["maxLength"] == PREDICATE_STRING_MAX_LENGTH

    base = {"kind": "parameter", "key": "prompt"}
    at_cap = "x" * PREDICATE_STRING_MAX_LENGTH
    over_cap = "x" * (PREDICATE_STRING_MAX_LENGTH + 1)

    assert _errors("ColumnPredicate", {**base, "op": "eq", "value": at_cap}) == []
    assert _errors("ColumnPredicate", {**base, "op": "eq", "value": over_cap})
    for op in ("in", "not_in"):
        assert _errors("ColumnPredicate", {**base, "op": op, "value": [at_cap]}) == [], op
        assert _errors("ColumnPredicate", {**base, "op": op, "value": [over_cap]}), op


def test_predicate_string_operand_cap_is_enforced_on_the_validator_path() -> None:
    """The authoritative request validator rejects over-cap scalar and set strings."""
    validator = SchemaValidator(contract="backend")
    path = "/api/v1/projects/proj_123/experiment-groups/group_123/configuration-runs/query"
    base = {"kind": "parameter", "key": "prompt"}
    at_cap = "x" * PREDICATE_STRING_MAX_LENGTH
    over_cap = "x" * (PREDICATE_STRING_MAX_LENGTH + 1)

    assert (
        validator.validate_request(
            path, "POST", {"predicates": [{**base, "op": "eq", "value": at_cap}]}
        )
        == []
    )
    assert validator.validate_request(
        path, "POST", {"predicates": [{**base, "op": "eq", "value": over_cap}]}
    )
    for op in ("in", "not_in"):
        assert (
            validator.validate_request(
                path, "POST", {"predicates": [{**base, "op": op, "value": [at_cap]}]}
            )
            == []
        )
        assert validator.validate_request(
            path, "POST", {"predicates": [{**base, "op": op, "value": [over_cap]}]}
        )


def test_predicate_operands_exclude_null_for_scalar_and_set_operators() -> None:
    """Null is not a scalar operand and not a set member. Absent-or-null matching
    is reserved for is_null/is_not_null, so eq/gt/in/not_in with null are rejected."""
    base = {"kind": "parameter", "key": "temperature"}

    # Scalar operators reject a null operand.
    for op in ("eq", "ne", "gt", "gte", "lt", "lte"):
        assert _errors("ColumnPredicate", {**base, "op": op, "value": None}), op
        # A real scalar operand still validates.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": 0.5}) == [], op

    # Set operators reject null anywhere in the set.
    for op in ("in", "not_in"):
        assert _errors("ColumnPredicate", {**base, "op": op, "value": [None]}), op
        assert _errors("ColumnPredicate", {**base, "op": op, "value": ["a", None]}), op
        assert _errors("ColumnPredicate", {**base, "op": op, "value": [1, 2]}) == [], op

    # Absent-or-null matching remains available only through the null operators.
    assert _errors("ColumnPredicate", {**base, "op": "is_null"}) == []
    assert _errors("ColumnPredicate", {**base, "op": "is_not_null"}) == []


def test_predicate_set_operands_must_be_unique_nonempty_and_bounded() -> None:
    base = {"kind": "measure", "key": "accuracy"}
    for op in ("in", "not_in"):
        # Duplicate members are rejected (uniqueItems).
        assert _errors("ColumnPredicate", {**base, "op": op, "value": ["a", "a"]}), op
        # Empty set rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": []}), op
        # Over-bound set rejected.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": list(range(101))}), op
        # A bounded, unique, non-empty set validates.
        assert _errors("ColumnPredicate", {**base, "op": op, "value": ["a", "b", "c"]}) == [], op


def test_predicate_null_operand_is_rejected_on_the_validator_path() -> None:
    """The null-operand exclusion holds through the authoritative request
    validator, not only against the bare ColumnPredicate definition."""
    validator = SchemaValidator(contract="backend")
    path = "/api/v1/projects/proj_123/experiment-groups/group_123/configuration-runs/query"

    def _pred(**over: Any) -> dict[str, Any]:
        pred = {"kind": "parameter", "key": "temperature", "op": "eq", "value": 0.2}
        pred.update(over)
        return pred

    # Scalar eq/gt with a null operand are rejected on the validator path.
    assert validator.validate_request(path, "POST", {"predicates": [_pred(op="eq", value=None)]})
    assert validator.validate_request(path, "POST", {"predicates": [_pred(op="gt", value=None)]})
    # in/not_in carrying null in the set are rejected on the validator path.
    assert validator.validate_request(
        path, "POST", {"predicates": [_pred(op="in", value=["a", None])]}
    )
    assert validator.validate_request(
        path, "POST", {"predicates": [_pred(op="not_in", value=[None])]}
    )
    # A well-formed non-null predicate still passes.
    assert (
        validator.validate_request(path, "POST", {"predicates": [_pred(op="in", value=["a", "b"])]})
        == []
    )


# ---- Fix 5: error-state has_error / error_code coupling ----


def test_error_state_couples_has_error_false_with_null_error_code() -> None:
    """has_error false REQUIRES error_code null; has_error true may carry a stable
    non-null code or null for an unclassified failure."""
    # No error, no code — valid.
    assert (
        _errors("GroupedConfigurationRun", _browse_row(
            error_state={"has_error": False, "error_code": None})) == []
    )
    # has_error false with a non-null code is contradictory — rejected.
    assert _errors(
        "GroupedConfigurationRun",
        _browse_row(error_state={"has_error": False, "error_code": "provider.timeout"}),
    )
    # has_error true with a stable code — valid.
    assert (
        _errors("GroupedConfigurationRun", _browse_row(
            error_state={"has_error": True, "error_code": "provider.timeout"})) == []
    )
    # has_error true with a null (unclassified) code — valid.
    assert (
        _errors("GroupedConfigurationRun", _browse_row(
            error_state={"has_error": True, "error_code": None})) == []
    )


# ---- Fix 6: manifest rejects exact-duplicate descriptors ----


def test_manifest_rejects_exact_duplicate_descriptors() -> None:
    """uniqueItems catches exact-duplicate descriptors in each namespace. Draft 7
    cannot express uniqueness by the (kind, key) subtuple, so conflicting-metadata
    duplicates are a documented backend acceptance criterion (see manifest prose)."""
    dup = _column(key="temperature")
    assert _errors("GroupColumnManifest", _manifest(parameters=[dup, dict(dup)]))
    dup_measure = _column(kind="measure", key="accuracy")
    assert _errors("GroupColumnManifest", _manifest(measures=[dup_measure, dict(dup_measure)]))
    dup_stat = _column(kind="summary_stat", key="weighted_score")
    assert _errors(
        "GroupColumnManifest", _manifest(summary_stats=[dup_stat, dict(dup_stat)])
    )

    # Distinct descriptors in the same namespace still validate.
    assert (
        _errors("GroupColumnManifest", _manifest(
            parameters=[_column(key="temperature"), _column(key="top_p")])) == []
    )

    # The prose records the backend handoff for subproperty-uniqueness.
    schema = _load_schema("execution/experiment_group_schema.json")
    manifest_desc = schema["definitions"]["GroupColumnManifest"]["description"].lower()
    assert "uniqueitems" in manifest_desc
    assert "backend" in manifest_desc
    for array_name in ("parameters", "measures", "summary_stats"):
        assert (
            schema["definitions"]["GroupColumnManifest"]["properties"][array_name][
                "uniqueItems"
            ]
            is True
        ), array_name
