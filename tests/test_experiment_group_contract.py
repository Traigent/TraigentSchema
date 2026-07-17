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


def test_group_detail_response_wraps_group_payload_under_data() -> None:
    data = {
        "group": _group(),
        "source_experiments": [_source_experiment()],
    }

    assert _errors("ExperimentGroupDetailPayload", data) == []
    assert _errors("ExperimentGroupDetailResponse", _success_envelope(data)) == []
    assert _errors("ExperimentGroupDetailResponse", data)


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


def test_openapi_wires_experiment_group_routes_to_response_schemas() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    expected = {
        "/api/v1/experiment-groups": "ExperimentGroupListResponse",
        "/api/v1/experiment-groups/{group_id}": "ExperimentGroupDetailResponse",
        "/api/v1/experiment-groups/{group_id}/configuration-runs": (
            "GroupedConfigurationRunListResponse"
        ),
    }

    for path, definition in expected.items():
        ref = (
            spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"][
                "schema"
            ]["$ref"]
        )
        assert ref == f"./experiment_group_schema.json#/definitions/{definition}"


def test_schema_validator_loads_group_schema_and_no_request_body_routes_fail_open() -> None:
    validator = SchemaValidator(contract="backend")

    assert SCHEMA_NAME in validator.available_schemas
    assert validator.validate_json({"group": _group()}, SCHEMA_NAME) == []
    for path in (
        "/api/v1/experiment-groups",
        "/api/v1/experiment-groups/group_123",
        "/api/v1/experiment-groups/group_123/configuration-runs",
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


def test_provenance_carries_group_context_not_duplicated_source_ids() -> None:
    assert _errors("GroupedConfigurationRunProvenance", _provenance()) == []
    # The no-dataset group is explicit; empty string still rejected.
    assert _errors("GroupedConfigurationRunProvenance", _provenance(dataset_id=None)) == []
    assert _errors("GroupedConfigurationRunProvenance", _provenance(dataset_id=""))
    assert _errors("GroupedConfigurationRunProvenance", _provenance(experiment_name=None)) == []

    # Only the group's own identity is required here.
    for field in ("agent_id", "dataset_id"):
        incomplete = _provenance()
        incomplete.pop(field)
        assert _errors("GroupedConfigurationRunProvenance", incomplete), field


def test_provenance_never_duplicates_the_canonical_source_execution_ids() -> None:
    """Draft 7 cannot compare siblings, so the source ids are NOT copied into
    provenance where a prose-only 'must equal' claim would silently drift. They
    stay canonical at the browse-row top level; provenance rejects them outright."""
    schema = _load_schema("execution/experiment_group_schema.json")
    provenance = schema["definitions"]["GroupedConfigurationRunProvenance"]
    source_ids = {"experiment_id", "experiment_run_id", "configuration_run_id"}

    # The redundant ids are absent from the provenance object entirely...
    assert not (set(provenance["properties"]) & source_ids)
    # ...and additionalProperties:false makes re-introducing them a hard error.
    assert provenance["additionalProperties"] is False
    for source_id in source_ids:
        assert _errors(
            "GroupedConfigurationRunProvenance", _provenance(**{source_id: "x"})
        ), source_id

    # The canonical ids remain required at the browse-row top level.
    row_required = set(
        schema["definitions"]["GroupedConfigurationRun"]["required"]
    )
    assert source_ids <= row_required
    for source_id in source_ids:
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
    # Identity remains exactly agent_id + canonical dataset_id.
    assert {"agent_id", "dataset_id"} <= identity_properties


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
    path = "/api/v1/experiment-groups/group_123/configuration-runs/query"

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
    path = "/api/v1/experiment-groups/{group_id}/configuration-runs/query"
    operation = spec["paths"][path]["post"]

    ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref == (
        "./experiment_group_schema.json#/definitions/GroupedConfigurationRunQueryResponse"
    )
    body_ref = operation["requestBody"]["content"]["application/json"]["schema"]["allOf"][0]["$ref"]
    assert body_ref.endswith(
        "experiment_group_schema.json#/definitions/GroupedConfigurationRunQueryRequest"
    )
    # POST is a read-only query carrier: the route must document no side effects.
    description = operation["description"].lower()
    assert "read-only" in description
    assert "no side effects" in description
    # Wave B stays out of this surface.
    assert "query" in spec["paths"][path]["post"]["summary"].lower()


def test_query_route_binds_its_request_schema_through_the_validator() -> None:
    validator = SchemaValidator(contract="backend")
    path = "/api/v1/experiment-groups/group_123/configuration-runs/query"

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


def test_group_list_route_keeps_page_params_and_adds_search_filter_sort_cursor() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    parameters = spec["paths"]["/api/v1/experiment-groups"]["get"]["parameters"]
    by_name = {parameter["name"]: parameter for parameter in parameters}

    # Pre-existing params are preserved.
    assert {"page", "per_page", "agent_id", "dataset_id"} <= set(by_name)
    # Fixed search/filter/sort/cursor surface is added.
    assert {"search", "dataset_scope", "sort_by", "sort_order", "cursor", "limit"} <= set(by_name)

    assert by_name["sort_by"]["schema"]["$ref"].endswith(
        "#/definitions/ExperimentGroupSortField"
    )
    assert by_name["sort_order"]["schema"]["$ref"].endswith("#/definitions/SortDirection")
    assert by_name["cursor"]["schema"]["$ref"].endswith("#/definitions/OpaqueCursor")
    assert by_name["dataset_scope"]["schema"]["$ref"].endswith(
        "#/definitions/ExperimentGroupDatasetScope"
    )
    assert by_name["search"]["schema"]["maxLength"] == 200
    # cursor/page mutual exclusion is documented on the cursor param.
    assert "mutually exclusive with page" in by_name["cursor"]["description"].lower()


def test_configuration_runs_route_keeps_page_params_and_adds_cursor_mode() -> None:
    spec = _load_schema("execution/execution_endpoints.json")
    path = "/api/v1/experiment-groups/{group_id}/configuration-runs"
    parameters = spec["paths"][path]["get"]["parameters"]
    by_name = {parameter["name"]: parameter for parameter in parameters}

    assert {"group_id", "page", "per_page"} <= set(by_name)
    assert {"cursor", "limit"} <= set(by_name)
    assert "mutually exclusive with page" in by_name["cursor"]["description"].lower()


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


def test_read_surfaces_expose_redacted_error_envelopes_without_forbidden_leakage() -> None:
    """Safe errors: malformed input and the single indistinguishable hidden/
    not-found condition emit the STRICT redacted error subtype (not the generic
    envelope directly). Group-scoped resources expose 404 but never 403, so
    'forbidden' is never distinguishable from 'not found'. Every constrained
    group_id route also carries a safe 400 for a malformed id. Tests inspect the
    actual response schemas, not prose."""
    spec = _load_schema("execution/execution_endpoints.json")

    def _responses(path: str, method: str) -> dict[str, Any]:
        return spec["paths"][path][method]["responses"]

    def _error_ref(response: dict[str, Any]) -> str:
        return response["content"]["application/json"]["schema"]["$ref"]

    group_scoped = {
        ("/api/v1/experiment-groups/{group_id}", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs/query", "post"),
    }
    for path, method in group_scoped:
        responses = _responses(path, method)
        # The single indistinguishable hidden/not-found condition is 404...
        assert "404" in responses, (path, method)
        # ...and there is deliberately NO 403 that would leak forbidden-vs-missing.
        assert "403" not in responses, (path, method)
        # 404 carries the strict redacted subtype, and the prose says the two
        # conditions are indistinguishable.
        assert _error_ref(responses["404"]).endswith(STRICT_ERROR_REF), (path, method)
        assert "indistinguishable" in responses["404"]["description"].lower()
        # Ordinary auth/server errors are present and also strict-redacted.
        assert _error_ref(responses["401"]).endswith(STRICT_ERROR_REF), (path, method)
        assert _error_ref(responses["500"]).endswith(STRICT_ERROR_REF), (path, method)
        # Every constrained-group_id route has a safe malformed-id 400.
        assert "400" in responses, (path, method)
        assert _error_ref(responses["400"]).endswith(STRICT_ERROR_REF), (path, method)

    # The detail GET specifically gained its previously-missing malformed-id 400.
    detail_400 = _responses("/api/v1/experiment-groups/{group_id}", "get")["400"]
    assert "group_id" in detail_400["description"]

    # Malformed query returns the strict subtype on the query surface.
    query_responses = _responses(
        "/api/v1/experiment-groups/{group_id}/configuration-runs/query", "post"
    )
    assert _error_ref(query_responses["400"]).endswith(STRICT_ERROR_REF)
    malformed_desc = query_responses["400"]["description"].lower()
    assert "malformed query" in malformed_desc
    # The malformed-query envelope must not promise to echo raw query text.
    assert "never" in malformed_desc

    # The bare list surface has no group to hide, so it carries no 404/403 but
    # still redacts malformed-input and server errors via the strict subtype.
    list_responses = _responses("/api/v1/experiment-groups", "get")
    assert "403" not in list_responses
    assert "404" not in list_responses
    assert _error_ref(list_responses["400"]).endswith(STRICT_ERROR_REF)
    assert _error_ref(list_responses["500"]).endswith(STRICT_ERROR_REF)


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
        assert isinstance(spec.get("enum"), list) and spec["enum"], field
        # A closed enum leaves no character-set / token-grammar escape hatch.
        assert "pattern" not in spec, field
        # Every enumerated value is a non-empty string (generic-envelope minLength 1).
        for value in spec["enum"]:
            assert isinstance(value, str) and value, (field, value)

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


def test_group_scoped_error_routes_point_at_the_strict_subtype_not_the_generic() -> None:
    """Fix 1/2: every experiment-group 400/401/404/500 references the strict
    subtype, never the generic envelope directly."""
    spec = _load_schema("execution/execution_endpoints.json")
    group_routes = (
        ("/api/v1/experiment-groups", "get"),
        ("/api/v1/experiment-groups/{group_id}", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs/query", "post"),
    )
    for path, method in group_routes:
        responses = spec["paths"][path][method]["responses"]
        for code, response in responses.items():
            if not code.startswith(("4", "5")):
                continue
            ref = response["content"]["application/json"]["schema"]["$ref"]
            assert ref.endswith(STRICT_ERROR_REF), (path, method, code, ref)
            # The strict subtype lives in the group schema, not the generic file.
            assert not ref.endswith("../error_envelope_schema.json"), (path, method, code)


def test_every_constrained_group_id_route_has_a_safe_malformed_id_400() -> None:
    """Fix 2: routes whose group_id is the constrained OpaqueExperimentGroupId all
    carry a redacted 400 for a malformed id."""
    spec = _load_schema("execution/execution_endpoints.json")
    constrained = (
        ("/api/v1/experiment-groups/{group_id}", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs", "get"),
        ("/api/v1/experiment-groups/{group_id}/configuration-runs/query", "post"),
    )
    for path, method in constrained:
        operation = spec["paths"][path][method]
        group_param = next(
            p for p in operation["parameters"] if p["name"] == "group_id"
        )
        assert group_param["schema"]["$ref"].endswith("#/definitions/OpaqueExperimentGroupId")
        assert "400" in operation["responses"], (path, method)


def test_legacy_and_cursor_modes_are_mutually_exclusive_and_matrix_complete() -> None:
    """Fix 3: both paginated GET routes make legacy page mode (page/per_page) and
    cursor mode (cursor/limit) mutually exclusive via the repository's established
    machine-readable x-excludes extension on each parameter. The exclusion is
    symmetric and its induced rejected-pair set is the COMPLETE cross-product of the
    two mode sets, so every cross-mix - cursor+page, cursor+per_page, limit+page,
    limit+per_page - is covered and no ambiguous mixed state is left undocumented."""
    spec = _load_schema("execution/execution_endpoints.json")
    legacy_set = {"page", "per_page"}
    cursor_set = {"cursor", "limit"}
    paginated = (
        "/api/v1/experiment-groups",
        "/api/v1/experiment-groups/{group_id}/configuration-runs",
    )
    for path in paginated:
        operation = spec["paths"][path]["get"]
        by_name = {p["name"]: p for p in operation["parameters"]}

        # All four mode parameters exist and each declares its x-excludes set.
        assert (legacy_set | cursor_set) <= set(by_name), path
        excludes = {name: set(by_name[name]["x-excludes"]) for name in legacy_set | cursor_set}

        # Each legacy param excludes exactly the cursor set, and vice versa.
        for name in legacy_set:
            assert excludes[name] == cursor_set, (path, name, excludes[name])
        for name in cursor_set:
            assert excludes[name] == legacy_set, (path, name, excludes[name])

        # The exclusion relation is symmetric: A excludes B <=> B excludes A.
        for name, others in excludes.items():
            for other in others:
                assert name in excludes[other], (path, name, other)

        # The induced set of rejected unordered pairs is the COMPLETE cross-product
        # of the two modes (the full 2x2 matrix), with no legacy/legacy or
        # cursor/cursor pair wrongly excluded.
        induced = {
            frozenset((name, other)) for name, others in excludes.items() for other in others
        }
        expected = {frozenset((legacy, cur)) for legacy in legacy_set for cur in cursor_set}
        assert induced == expected, (path, induced, expected)
        assert len(induced) == 4, path

        # Ordinary omitted defaults are documented as legacy page mode.
        assert "defaults to legacy page mode" in by_name["page"]["description"].lower()


def test_group_list_sort_vocabulary_is_closed_and_identity_scoped() -> None:
    for field in ("created_at", "updated_at", "agent_id", "experiment_count"):
        assert _errors("ExperimentGroupSortField", field) == [], field
    # Never sortable by comparison-flavoured or tuned-variable fields.
    for field in ("weighted_score", "tvars", "config_hash", "rank", "name"):
        assert _errors("ExperimentGroupSortField", field), field


def test_group_list_tie_break_is_canonical_identity_not_opaque_group_id() -> None:
    """The group-list deterministic tie-break is the group's canonical visible
    identity - agent_id ascending, then canonical dataset_id ascending with nulls
    first - applied after the requested primary sort and fixed independent of the
    primary field, its direction, and dataset_id nullness. The opaque group_id is
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
        # (3) Explicit, deterministic null placement (NULLS FIRST).
        assert "nulls ordered first" in haystack
        # (4) The tie-break is a secondary tie after the primary sort, and is
        #     fixed independent of the requested primary direction.
        assert "independent of" in haystack and "direction" in haystack
        # (5) group_id is explicitly rejected as the tie-break key, with the
        #     load-bearing reason (non-reversible / not range-bounded).
        assert "group_id is" in haystack and "not the" in haystack
        assert "range-bounded" in haystack or "range-orderable" in haystack

    # (6) The old mandate 'group_id ascending' as the tie-break must be gone.
    assert "group_id ascending" not in sort_field_desc
    assert "group_id ascending for groups" not in top_desc

    # (6b) The OpenAPI endpoint's inline sort_by mirror must not drift from the
    #     authoritative field: it carries the exact authoritative language and no
    #     residual 'group_id ascending' tie-break mandate. This closes the inline
    #     contradiction where the endpoint parameter still said the tie-break was
    #     group_id ascending while the field schema had moved to canonical identity.
    spec = _load_schema("execution/execution_endpoints.json")
    inline_sort_by = next(
        parameter
        for parameter in spec["paths"]["/api/v1/experiment-groups"]["get"]["parameters"]
        if parameter["name"] == "sort_by"
    )
    inline_desc = inline_sort_by["description"]
    # The inline mirror is byte-identical to the authoritative field description...
    assert inline_desc == schema["definitions"]["ExperimentGroupSortField"]["description"]
    # ...and therefore carries the canonical-identity tie-break, not group_id ascending.
    assert "agent_id ascending" in inline_desc.lower()
    assert "canonical dataset_id ascending" in inline_desc.lower()
    assert "nulls ordered first" in inline_desc.lower()
    assert "group_id ascending" not in inline_desc.lower()

    # (7) The row-level configuration-run tie-break is untouched: still
    #     configuration_run_id ascending, and the group amendment did not bleed
    #     into it.
    query_sort_desc = (
        schema["definitions"]["GroupedConfigurationRunQueryRequest"]["properties"]["sort"][
            "description"
        ].lower()
    )
    assert "configuration_run_id ascending" in query_sort_desc

    # (8) Identity remains exactly scope + agent_id + canonical dataset_id: the
    #     tie-break change added no new identity field and dropped none.
    identity_properties = set(schema["definitions"]["ExperimentGroupOverview"]["properties"])
    assert {"agent_id", "dataset_id"} <= identity_properties


def test_contract_documents_auth_non_disclosure_and_pagination_invariants() -> None:
    schema = _load_schema("execution/experiment_group_schema.json")
    description = schema["description"].lower()

    # Tokens are lookup/continuation only — never an authorization boundary.
    assert "tokens are not an authorization boundary" in description
    assert "never derive scope or identity from a token" in description
    # Non-disclosure: forbidden must be indistinguishable from not-found.
    assert "indistinguishable" in description
    # Deterministic ordering.
    assert "deterministic" in description and "tie-breaker" in description
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
    path = "/api/v1/experiment-groups/group_123/configuration-runs/query"

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
