"""Contract tests for the window-1b experiment read operations (API revision Phase 3 slice 3.3).

Canonical operations at their new paths, operationId equal to the backend operation id:
search, detail, export, graphs, trend, the context resolver, and the agent experiments page.
Also pins the retained legacy siblings, the reference provenance pattern, the closed
request body, cursor pagination bounds, numeric budgets and the closed error shapes.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READS = SCHEMAS / "evaluation" / "experiment_reads_schema.json"
_REGISTRY = build_registry(SCHEMAS)
_ID = load_json(READS)["$id"]
P = "/api/v1/projects/{project_id}"
REF = "experiment_" + "0123456789abcdef" * 2

EXEC = load_json(SCHEMAS / "execution" / "execution_endpoints.json")["paths"]
PLANNED = load_json(SCHEMAS / "planned_projects_endpoints.json")["paths"]
AGENTS = load_json(SCHEMAS / "agents" / "agents_endpoints.json")


def _errors(fragment: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, f"{_ID}#/definitions/{fragment}", instance)


CANONICAL = [
    (EXEC, "post", P + "/experiments/search", "experiment.get_experiments"),
    (EXEC, "get", P + "/experiments/{experiment_ref}", "experiment.get_experiment"),
    (EXEC, "get", P + "/experiments/{experiment_ref}/export", "experiment.export_experiment"),
    (EXEC, "get", P + "/experiments/{experiment_ref}/graphs", "trace.get_experiment_graphs"),
    (EXEC, "post", "/api/v1/experiment-context/resolve", "experiment_context.get_experiment_context"),
    (PLANNED, "get", P + "/experiments/{experiment_ref}/trend", "project_core_metrics.get_experiment_trend"),
]

RETAINED = [
    (EXEC, "post", "/api/v1/experiments", "experiment.create_experiment"),
    (EXEC, "put", "/api/v1/experiments/{experiment_id}", "experiment.update_experiment"),
    (EXEC, "patch", "/api/v1/experiments/{experiment_id}", "experiment.rename_experiment"),
    (EXEC, "delete", "/api/v1/experiments/{experiment_id}", "experiment.delete_experiment"),
    (EXEC, "post", "/api/v1/experiments/bulk-update-status", "experiment.bulk_update_experiment_status"),
    (EXEC, "post", "/api/v1beta/projects/{project_id}/experiments", "project_experiments.create_experiment"),
    (EXEC, "put", "/api/v1beta/projects/{project_id}/experiments/{experiment_id}", "project_experiments.update_experiment"),
    (EXEC, "patch", "/api/v1beta/projects/{project_id}/experiments/{experiment_id}", "project_experiments.rename_experiment"),
    (EXEC, "delete", "/api/v1beta/projects/{project_id}/experiments/{experiment_id}", "project_experiments.delete_experiment"),
    (EXEC, "post", "/api/v1beta/projects/{project_id}/experiments/bulk-update-status", "project_experiments.bulk_update_experiment_status"),
    (EXEC, "get", "/api/v1/traces/{trace_id}", "trace.get_trace"),
    (EXEC, "get", "/api/v1/traces/graphs/{graph_id}", "trace.get_graph"),
    (EXEC, "post", "/api/v1/traces/ingest", "trace.ingest_traces"),
    (PLANNED, "get", "/api/v1beta/projects/{project_id}/core-metrics/overview", "project_core_metrics.get_core_metrics_overview"),
    (PLANNED, "get", "/api/v1beta/core-metrics/overview", "legacy_core_metrics.get_core_metrics_overview"),
]


@pytest.mark.parametrize("paths,method,path,op_id", CANONICAL + RETAINED)
def test_operation_id_equals_the_backend_op_id(paths, method, path, op_id) -> None:
    assert paths[path][method]["operationId"] == op_id


def test_moved_and_retired_paths_are_gone() -> None:
    assert "get" not in EXEC["/api/v1/experiments"]
    assert "get" not in EXEC["/api/v1/experiments/{experiment_id}"]
    assert "/api/v1beta/experiments/{experiment_id}/context" not in EXEC
    assert "/api/v1/traces/experiments/{experiment_id}/graphs" not in EXEC
    assert "/api/v1beta/projects/{project_id}/core-metrics/experiments/{experiment_id}/trend" not in PLANNED
    # retired duplicates are not re-declared
    ids = {o.get("operationId") for item in {**EXEC, **PLANNED}.values() for o in item.values() if isinstance(o, dict)}
    assert not {"project_experiments.get_experiments", "project_experiments.get_experiment",
                "project_experiments.export_experiment", "legacy_core_metrics.get_experiment_trend"} & ids


def test_operation_ids_are_unique_across_the_catalogs() -> None:
    seen: dict[str, str] = {}
    for paths in (EXEC, PLANNED):
        for path, item in paths.items():
            for method, o in item.items():
                oid = o.get("operationId") if isinstance(o, dict) else None
                if oid:
                    assert oid not in seen, (oid, path, seen.get(oid))
                    seen[oid] = path


def test_private_admin_stats_stays_out_of_the_public_fragments() -> None:
    text = json.dumps([EXEC, PLANNED])
    private_op = "get_experiment" + "_admin" + "_stats"
    assert "admin/stats" not in text and private_op not in text


def test_reference_has_exact_length_43_and_experiment_prefix() -> None:
    ref = load_json(READS)["definitions"]["ExperimentRef"]
    assert ref["pattern"] == "^experiment_[0-9a-f]{32}$"
    assert ref["minLength"] == ref["maxLength"] == len("experiment_") + 32 == 43
    assert _errors("ExperimentRef", "exs_" + "a" * 32)


def test_canonical_read_rejects_retired_has_hybrid_session() -> None:
    resource = {"experiment_ref": REF, "has_hybrid_session": False}
    assert any("has_hybrid_session" in e or "not" in e for e in _errors("ExperimentRead", resource))
    shared = load_json(SCHEMAS / "evaluation" / "experiment_schema.json")
    assert "has_hybrid_session" in shared["properties"]


@pytest.mark.parametrize("value", [REF, "experiment_" + "0" * 32, "experiment_" + "f" * 32])
def test_reference_accepts_experiment_plus_32_lowercase_hex(value: str) -> None:
    assert _errors("ExperimentRef", value) == []


@pytest.mark.parametrize("value", ["", "experiment_", "experiment_" + "A" * 32, "experiment_" + "a" * 31, "experiment_" + "a" * 33,
                                   "exp_" + "a" * 32, "0123456789abcdef" * 2, "experiment_" + "g" * 32,
                                   "11111111-1111-1111-1111-111111111111", 5, None])
def test_reference_rejects_ids_uuids_and_bad_shapes(value: Any) -> None:
    assert _errors("ExperimentRef", value)


def test_path_parameters_use_the_reference_schema() -> None:
    for paths, method, path, _ in CANONICAL:
        if "{experiment_ref}" in path:
            params = {p["name"]: p for p in paths[path][method]["parameters"]}
            assert params["experiment_ref"]["schema"]["$ref"].endswith("#/definitions/ExperimentRef")
            assert "experiment_id" not in params


def test_search_request_is_closed_and_bounded() -> None:
    assert _errors("ExperimentSearchRequest", {}) == []
    assert _errors("ExperimentSearchRequest", {"limit": 100, "cursor": "x" * 4096, "search": "q", "sort_by": "name",
                                              "sort_order": "asc", "status": "RUNNING", "agent_ref": "a", "is_active": True}) == []
    for bad in ({"limit": 101}, {"limit": 0}, {"limit": "20"}, {"cursor": "x" * 4097}, {"cursor": ""},
                {"search": "x" * 201}, {"search": ""}, {"sort_by": "id"}, {"sort_by": "dataset_id"},
                {"sort_order": "up"}, {"status": "bogus"}, {"page": 1}, {"per_page": 5}, {"offset": 0},
                {"total": 1}, {"experiment_id": "exp_1"}, {"unknown": 1}):
        assert _errors("ExperimentSearchRequest", bad), bad
    req = load_json(READS)["definitions"]["ExperimentSearchRequest"]
    assert req["properties"]["limit"]["default"] == 20 and req["x-max-request-bytes"] == 8192


def _page(items: list[Any], **p: Any) -> dict[str, Any]:
    pag = {"limit": 20, "next_cursor": None, "has_more": False}
    pag.update(p)
    return {"success": True, "message": "ok", "data": {"items": items, "pagination": pag}}


def test_cursor_envelope_shape_and_bounds() -> None:
    assert _errors("ExperimentSearchResponse", _page([])) == []
    assert _errors("ExperimentSearchResponse", _page([], next_cursor="c", has_more=True)) == []
    for bad in (_page([], limit=101), _page([], limit=0), _page([], next_cursor="x" * 4097)):
        assert _errors("ExperimentSearchResponse", bad)
    legacy = _page([])
    legacy["data"]["pagination"] = {"page": 1, "per_page": 20, "total": 0, "total_pages": 0, "has_next": False, "has_prev": False}
    assert _errors("ExperimentSearchResponse", legacy)
    assert _errors("ExperimentSearchResponse", {**_page([]), "extra": 1})
    too_many = _page([{"experiment_ref": REF, "name": "n"}] * 101)
    assert any("maxItems" in e or "too long" in e for e in _errors("ExperimentSearchResponse", too_many))


def test_experiment_resource_carries_a_read_only_reference() -> None:
    exp = load_json(SCHEMAS / "evaluation" / "experiment_schema.json")
    prop = exp["properties"]["experiment_ref"]
    assert prop["$ref"].endswith("experiment_reads_schema.json#/definitions/ExperimentRef")
    assert prop["readOnly"] is True


def test_agent_experiments_page_is_closed_with_references() -> None:
    item = {"experiment_ref": REF, "name": "n", "description": None, "status": "RUNNING",
            "total_runs": 2, "active_runs": 1, "created_at": "2026-11-20T10:00:00Z"}
    assert _errors("AgentExperimentItem", item) == []
    assert _errors("AgentExperimentItem", {**item, "id": "exp_1"})
    legacy = {k: v for k, v in item.items() if k != "experiment_ref"}
    legacy["id"] = "exp_1"
    assert _errors("AgentExperimentItem", legacy)
    op = AGENTS["paths"][P + "/agents/{agent_ref}/experiments"]["get"]
    assert op["operationId"] == "agent.get_agent_experiments"
    resp = AGENTS["components"]["schemas"]["AgentExperimentsResponse"]
    items = resp["properties"]["data"]["properties"]["items"]
    assert items["maxItems"] == 100 and items["items"]["$ref"].endswith("#/definitions/AgentExperimentItem")
    assert resp["properties"]["data"]["properties"]["pagination"]["properties"]["next_cursor"]["type"] == ["string", "null"]


def test_graphs_page_is_bounded_and_hides_the_historical_id() -> None:
    g = {"id": "g1", "graph_hash": "h", "sdk_version": None, "node_count": 500, "edge_count": 1000,
         "loop_count": 100, "created_at": "2026-11-20T10:00:00Z", "updated_at": None}
    assert _errors("ExperimentGraphSummary", g) == []
    assert _errors("ExperimentGraphSummary", {**g, "sdk_version": "1.2"}) == []
    assert _errors("ExperimentGraphSummary", {**g, "experiment_id": "exp_1"})
    # Keys the backend _graph_summary (TraigentBackend src/routes/trace_routes.py:540) emits today.
    # experiment_id is removed from that route by the window-1b backend cutover, so it is excluded here.
    backend_keys = {"id", "graph_hash", "sdk_version", "node_count", "edge_count",
                    "loop_count", "created_at", "updated_at"}
    exp_reads = load_json(SCHEMAS / "evaluation" / "experiment_reads_schema.json")
    assert set(exp_reads["definitions"]["ExperimentGraphSummary"]["required"]) == backend_keys
    assert _errors("ExperimentGraphSummary", {**g, "nodes": []})
    assert _errors("ExperimentGraphSummary", {**g, "node_count": 501})
    assert _errors("ExperimentGraphSummary", {**g, "edge_count": 1001})
    assert _errors("ExperimentGraphSummary", {**g, "loop_count": 101})
    assert _errors("ExperimentGraphsResponse", _page([g])) == []
    op = EXEC[P + "/experiments/{experiment_ref}/graphs"]["get"]
    assert {p["name"] for p in op["parameters"]} == {"project_id", "experiment_ref", "limit", "cursor"}
    assert op["x-max-response-bytes"] == 8388608


def test_canonical_experiment_reads_require_the_reference() -> None:
    base = load_json(SCHEMAS / "evaluation" / "experiment_schema.json")
    assert "experiment_ref" not in base["required"]  # retained legacy mutations reuse the resource
    resource = {"name": "n", "description": "d", "configurations": {}, "agent_ref": "agent_ref_1", "metrics": [], "evaluation_set": None}
    assert any("experiment_ref" in e for e in _errors("ExperimentRead", resource))
    assert not any("experiment_ref" in e for e in _errors("ExperimentRead", {**resource, "experiment_ref": REF}))
    assert _errors("ExperimentSearchResponse", _page([resource]))


def test_bulk_mutations_declare_no_id_count_limit() -> None:
    for path in ("/api/v1/experiments/bulk-update-status", "/api/v1beta/projects/{project_id}/experiments/bulk-update-status"):
        ids = EXEC[path]["post"]["requestBody"]["content"]["application/json"]["schema"]["properties"]["ids"]
        assert "maxItems" not in ids and "uniqueItems" not in ids


def test_export_budgets_are_numeric_and_413_is_closed() -> None:
    op = EXEC[P + "/experiments/{experiment_ref}/export"]["get"]
    assert op["x-max-response-bytes"] == 33554432
    fmt = next(p for p in op["parameters"] if p["name"] == "format")
    assert fmt["schema"]["enum"] == ["csv", "xlsx"]
    body = {"success": False, "message": "Experiment export exceeds the maximum row limit.",
            "error": "EXPORT_TOO_LARGE", "error_code": "EXPERIMENT_EXPORT_ROW_LIMIT_EXCEEDED", "details": {"max_rows": 50000}}
    assert _errors("ExperimentReadPayloadTooLargeError", body) == []
    assert _errors("ExperimentReadPayloadTooLargeError", {**body, "details": {"max_rows": 5, "observed_rows": 9}})


def test_trend_is_bounded_and_returns_the_reference() -> None:
    trend = load_json(SCHEMAS / "projects" / "project_scoped_experiment_trend_schema.json")
    assert "experiment_id" not in trend["properties"] and "experiment_ref" in trend["required"]
    assert trend["properties"]["daily_runs"]["maxItems"] == 366
    assert trend["properties"]["measure_summary"]["maxProperties"] == 200
    assert trend["x-max-response-bytes"] == 1048576


@pytest.mark.parametrize("definition", ["ExperimentReadBadRequestError", "ExperimentReadAuthenticationRequiredError",
                                        "ExperimentReadForbiddenError", "ExperimentReadNotFoundError"])
def test_errors_are_closed_and_never_echo_inputs(definition: str) -> None:
    spec = load_json(READS)["definitions"][definition]
    assert spec["additionalProperties"] is False and "details" not in spec["properties"]
    assert all("enum" in spec["properties"][k] or "const" in spec["properties"][k] for k in ("message", "error", "error_code"))
    msg = spec["properties"]["message"]["enum"][0]
    code = spec["properties"]["error_code"]["enum"][0]
    err = spec["properties"]["error"]["enum"][0]
    ok = {"success": False, "message": msg, "error": err, "error_code": code}
    assert _errors(definition, ok) == []
    assert _errors(definition, {**ok, "message": f"{msg} {REF}"})
    assert _errors(definition, {**ok, "details": {"experiment_ref": REF}})
    for text in spec["properties"]["message"]["enum"]:
        assert not re.search(r"experiment_[0-9a-f]{4}|exp_|\{", text)


def test_replay_class_read_is_documented_for_pure_read_posts() -> None:
    for path in (P + "/experiments/search", "/api/v1/experiment-context/resolve"):
        assert "replay class read" in EXEC[path]["post"]["description"]


RUN_REF = "experiment_run_" + "0123456789abcdef" * 2
_RAW_ID_KEYS = {"run_id", "experiment_run_id", "agent_id"}
_REMOVED_EXPERIMENT_READ_KEYS = ("id", "model_parameters_id", "dataset_id", "eval_dataset_id", "evaluation_set_id",
                                 "benchmark_id", "dataset", "eval_dataset", "benchmark",
                                 "model_parameters")


def _canonical_read_definitions() -> dict[str, Any]:
    return load_json(READS)["definitions"]


def _keys(node: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(node, dict):
        for k, v in node.items():
            found.add(k)
            found |= _keys(v)
    elif isinstance(node, list):
        for v in node:
            found |= _keys(v)
    return found


def test_canonical_reads_expose_no_raw_run_or_agent_ids() -> None:
    defs = _canonical_read_definitions()
    for name in ("ExperimentRead", "ExperimentGraphSummary", "AgentExperimentItem"):
        props = defs[name].get("properties", {})
        assert not (_RAW_ID_KEYS & set(props)), name
        assert "agent" not in props and "experiment_run" not in props, name
    trend = load_json(SCHEMAS / "projects" / "project_scoped_experiment_trend_schema.json")
    assert not (_RAW_ID_KEYS & _keys(trend["properties"]))
    assert "agent_id" not in defs["ExperimentRead"]["required"]


def test_canonical_read_run_reference_is_opaque_and_exact() -> None:
    prop = _canonical_read_definitions()["ExperimentRead"]["properties"]["experiment_run_ref"]
    assert prop["pattern"] == "^experiment_run_[0-9a-f]{32}$"
    assert prop["minLength"] == prop["maxLength"] == len("experiment_run_") + 32 == 47
    resource = {"experiment_ref": REF, "name": "n", "description": "d", "configurations": {},
                "agent_ref": "agent_ref_1", "metrics": [], "evaluation_set": None}
    # The nested shared sub-schemas have their own required members; compare against a baseline
    # so only the errors the changed field introduces are asserted.
    baseline = set(_errors("ExperimentRead", resource))
    assert not any("agent_ref" in e or "experiment_run" in e for e in baseline)
    assert set(_errors("ExperimentRead", {**resource, "experiment_run_ref": RUN_REF})) == baseline
    assert set(_errors("ExperimentRead", {**resource, "experiment_run_ref": None})) == baseline
    assert set(_errors("ExperimentRead", {**resource, "experiment_run_ref": "experiment_run_" + "A" * 32})) - baseline
    assert set(_errors("ExperimentRead", {**resource, "agent_id": "a"})) - baseline
    assert set(_errors("ExperimentRead", {**resource, "experiment_run": {"run_id": "r"}})) - baseline
    assert set(_errors("ExperimentRead", {k: v for k, v in resource.items() if k != "agent_ref"})) - baseline


def _read_errors(fragment: str, instance: Any) -> list[str]:
    """Errors other than the unrelated required Configurations.infrastructure of the shared resource."""
    return [e for e in _errors(fragment, instance) if "infrastructure" not in e]


def test_experiment_read_is_reference_only_and_rejects_raw_and_hydrated_identifiers() -> None:
    resource = {"experiment_ref": REF, "name": "n", "description": "d", "configurations": {},
                "agent_ref": "agent_ref_1", "metrics": [], "evaluation_set": None}
    assert _read_errors("ExperimentRead", resource) == []
    defs = _canonical_read_definitions()["ExperimentRead"]
    assert not (set(_REMOVED_EXPERIMENT_READ_KEYS) & set(defs["properties"]))
    assert not (set(_REMOVED_EXPERIMENT_READ_KEYS) & set(defs["required"]))
    assert "anyOf" not in defs
    for key in _REMOVED_EXPERIMENT_READ_KEYS:
        value: Any = {"id": "x", "name": "n"} if key in ("dataset", "eval_dataset", "benchmark", "model_parameters") else "x"
        assert _read_errors("ExperimentRead", {**resource, key: value}), key


_METRIC = "metric_" + "a" * 32
_DS = "ds_" + "b" * 32


def test_experiment_read_metrics_and_evaluation_set_are_opaque_references() -> None:
    base = {"experiment_ref": REF, "name": "n", "description": "d", "configurations": {},
            "agent_ref": "agent_ref_1", "metrics": [_METRIC], "evaluation_set": None}
    assert _read_errors("ExperimentRead", base) == []
    assert _read_errors("ExperimentRead", {**base, "evaluation_set": {"ref": _DS}}) == []
    assert _read_errors("ExperimentRead", {**base, "measures": []})
    assert _read_errors("ExperimentRead", {**base, "metrics": ["m_1"]})
    assert _read_errors("ExperimentRead", {**base, "metrics": ["exs_" + "a" * 32]})
    assert _read_errors("ExperimentRead", {**base, "metrics": [_METRIC.upper()]})
    assert _read_errors("ExperimentRead", {**base, "evaluation_set": {"ref": _DS, "version": 1}})
    assert _read_errors("ExperimentRead", {**base, "evaluation_set": {"ref": "exs_" + "b" * 32}})
    assert _read_errors("ExperimentRead", {**base, "evaluation_set": {"ref": "ds_1"}})
    assert _read_errors("ExperimentRead", {**base, "evaluation_set": {}})
    assert _read_errors("ExperimentRead", {k: v for k, v in base.items() if k != "evaluation_set"})
    assert _read_errors("ExperimentRead", {k: v for k, v in base.items() if k != "metrics"})


def test_experiment_read_counts_experiment_runs_and_has_no_free_form_fields() -> None:
    base = {"experiment_ref": REF, "name": "n", "description": "d", "configurations": {},
            "agent_ref": "agent_ref_1", "metrics": [], "evaluation_set": None}
    assert _read_errors("ExperimentRead", {**base, "experiment_runs_count": 3}) == []
    assert _read_errors("ExperimentRead", {**base, "experiment_runs_count": -1})
    assert _read_errors("ExperimentRead", {**base, "experiment_runs_count": "3"})
    for key, value in (("optimization_runs_count", 3), ("metadata", {"tags": ["t"]}), ("experiment_parameters", {"a": 1})):
        assert _read_errors("ExperimentRead", {**base, key: value}), key
