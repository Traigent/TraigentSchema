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
