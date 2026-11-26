"""Metric endpoints: canonical paths, ref pattern, closed write bodies, measure deprecations."""

import json
import re

import jsonschema
import pytest

from traigent_schema.utils import get_schemas_dir

M = get_schemas_dir() / "measures"
PATHS = json.loads((M / "measures_endpoints.json").read_text(encoding="utf-8"))["paths"]
PROJECT = "/api/v1/projects/{project_id}/metrics"
REF = "/api/v1/metrics/{metric_ref}"
EVALUATOR_FIELDS = ("evaluation_method", "criteria", "python_packages", "measure_parameters")


def _schema(name):
    return json.loads((M / name).read_text(encoding="utf-8"))


def test_metric_operations_and_ids():
    got = {
        (path, method): op["operationId"]
        for path, item in PATHS.items()
        if "metrics" in path
        for method, op in item.items()
    }
    assert got == {
        (PROJECT, "get"): "metric.list_project_metrics",
        (PROJECT, "post"): "metric.create_project_metric",
        ("/api/v1/metrics", "get"): "metric.list_library_metrics",
        ("/api/v1/metrics", "post"): "metric.create_library_metric",
        (REF, "get"): "metric.get_metric",
        (REF, "patch"): "metric.update_metric",
        (REF, "delete"): "metric.delete_metric",
    }
    assert "put" not in PATHS[REF]
    assert all(op["x-asserted-against-backend"] is False for p in PATHS if "metrics" in p for op in PATHS[p].values())


def test_metric_ref_pattern_matches_the_resolver():
    for op in PATHS[REF].values():
        (param,) = op["parameters"]
        assert param["schema"]["pattern"] == "^metric_[0-9a-f]{32}$"
    pattern = _schema("metric_schema.json")["properties"]["metric_ref"]["pattern"]
    assert re.match(pattern, "metric_" + "a1" * 16)
    assert not re.match(pattern, "metric_" + "A1" * 16)
    assert not re.match(pattern, "accuracy")


@pytest.mark.parametrize("name", ["metric_write_request_schema.json", "metric_update_request_schema.json"])
@pytest.mark.parametrize("field", EVALUATOR_FIELDS)
def test_write_bodies_reject_evaluator_fields(name, field):
    schema = _schema(name)
    assert schema["additionalProperties"] is False
    assert not set(EVALUATOR_FIELDS) & set(schema["properties"])
    body = {"label": "L", "measure_type": "accuracy", field: []}
    errors = list(jsonschema.Draft7Validator({k: v for k, v in schema.items() if k != "$schema"}).iter_errors(body))
    assert [e.validator for e in errors] == ["additionalProperties"], field
    assert field in errors[0].message
    # The refusal the server renders for it is the one closed 422, bound on all three writes.
    for path, method in [(PROJECT, "post"), ("/api/v1/metrics", "post"), (REF, "patch")]:
        assert PATHS[path][method]["responses"]["422"]["content"]["application/json"]["schema"]["$ref"] == (
            "./metric_validation_failed_error_schema.json"
        )


def test_write_bodies_require_what_they_must():
    assert _schema("metric_write_request_schema.json")["required"] == ["label", "measure_type"]
    assert _schema("metric_update_request_schema.json")["minProperties"] == 1


def test_every_metric_write_declares_a_422_and_reads_carry_no_evaluator_fields():
    for path, method in [(PROJECT, "post"), ("/api/v1/metrics", "post"), (REF, "patch")]:
        assert "422" in PATHS[path][method]["responses"]
    assert not set(EVALUATOR_FIELDS) & set(_schema("metric_schema.json")["properties"])


def test_measure_deprecations():
    dep = {
        (p, m): op["x-deprecated"]
        for p, item in PATHS.items()
        if "measures" in p
        for m, op in item.items()
        if op.get("deprecated") is True
    }
    assert set(dep) == {
        ("/api/v1/measures/default", "post"),
        ("/api/v1/measures", "get"),
        ("/api/v1/measures/{measure_id}", "get"),
        ("/api/v1/measures/{measure_id}", "delete"),
    }
    # The evaluator-capable legacy writes are kept until the evaluator cutover.
    assert "deprecated" not in PATHS["/api/v1/measures"]["post"]
    assert "deprecated" not in PATHS["/api/v1/measures/{measure_id}"]["put"]


def _validator(name):
    schema = _schema(name)
    resolver_store = {s["$id"]: s for s in (_schema(n) for n in M_FILES)}
    resolver_store["https://schemas.traigent.ai/pagination_schema.json"] = json.loads(
        (get_schemas_dir() / "pagination_schema.json").read_text(encoding="utf-8")
    )
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry().with_resources(
        [(uri, Resource.from_contents(doc, default_specification=DRAFT7)) for uri, doc in resolver_store.items()]
    )
    return jsonschema.Draft7Validator(schema, registry=registry)


M_FILES = [
    "metric_schema.json",
    "metric_list_response_schema.json",
    "metric_validation_failed_error_schema.json",
    "metric_not_found_error_schema.json",
]
VALIDATION_FAILED = {
    "success": False,
    "message": "Validation failed",
    "error": "validation_failed",
    "error_code": "validation_failed",
}
NOT_FOUND = {
    "success": False,
    "message": "Metric not found",
    "error": "not_found",
    "error_code": "not_found",
}


def _metric(**over):
    row = {
        "metric_ref": "metric_" + "ab" * 16,
        "scope": "project",
        "project_id": "p-1",
        "label": "Accuracy",
        "measure_type": "accuracy",
        "unit": None,
        "version": "1.0.0",
        "domain": [0, 1],
        "agent_types": [{"agent_type_id": "a1", "name": "qa", "description": None}],
        "is_custom": True,
    }
    row.update(over)
    return row


def _errors(name, body):
    return list(_validator(name).iter_errors(body))


@pytest.mark.parametrize(
    "row",
    [
        _metric(),
        _metric(scope="shared", project_id=None),
        _metric(scope="builtin", project_id=None, unit="ms", agent_types=[], domain=[None, 1e308]),
    ],
)
def test_metric_projection_accepts_the_three_scopes(row):
    assert not _errors("metric_schema.json", row)


@pytest.mark.parametrize(
    "row",
    [
        _metric(scope="tenant", project_id=None),
        _metric(scope="built_in", project_id=None),
        _metric(project_id=None),
        _metric(scope="shared", project_id="p-1"),
        _metric(scope="builtin", project_id="p-1"),
        _metric(metric_ref="accuracy"),
    ],
)
def test_metric_projection_rejects_bad_scope_project_pairs_and_refs(row):
    assert _errors("metric_schema.json", row)
    missing = {k: v for k, v in _metric().items() if k != "project_id"}
    assert _errors("metric_schema.json", missing)


def test_list_bodies_are_bound_and_items_use_the_metric_schema():
    for path, method in [(PROJECT, "get"), ("/api/v1/metrics", "get")]:
        ref = PATHS[path][method]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        assert ref == "./metric_list_response_schema.json"
    page = {"page": 1, "per_page": 20, "total": 1, "total_pages": 1, "has_next": False, "has_prev": False}
    body = {"success": True, "message": "ok", "data": {"items": [_metric()], "pagination": page}}
    assert not _errors("metric_list_response_schema.json", body)
    body["data"]["items"][0]["scope"] = "tenant"
    assert _errors("metric_list_response_schema.json", body)


def test_write_bodies_carry_unit_and_version_but_not_is_custom():
    for name in ("metric_write_request_schema.json", "metric_update_request_schema.json"):
        props = _schema(name)["properties"]
        assert {"unit", "version"} <= set(props)
        assert "is_custom" not in props
        assert _errors(name, {"label": "L", "measure_type": "accuracy", "is_custom": True})
        assert not _errors(name, {"label": "L", "measure_type": "accuracy", "unit": "ms", "version": "1.2.0"})


def _closed_ref(path, method, status):
    return PATHS[path][method]["responses"][status]["content"]["application/json"]["schema"]["$ref"]


def test_422_on_every_write_is_bound_to_the_closed_validation_error():
    for path, method in [(PROJECT, "post"), ("/api/v1/metrics", "post"), (REF, "patch")]:
        assert _closed_ref(path, method, "422") == "./metric_validation_failed_error_schema.json"
    name = "metric_validation_failed_error_schema.json"
    assert not _errors(name, VALIDATION_FAILED)
    assert _errors(name, {**VALIDATION_FAILED, "details": {"label": "secret text"}})
    assert _errors(name, {**VALIDATION_FAILED, "message": "label 'secret' is invalid"})
    assert _errors(name, {**VALIDATION_FAILED, "error_code": "other"})
    assert _errors(name, NOT_FOUND)


def test_404_on_every_item_op_is_bound_to_the_closed_not_found_error():
    for method in PATHS[REF]:
        assert _closed_ref(REF, method, "404") == "./metric_not_found_error_schema.json"
    name = "metric_not_found_error_schema.json"
    assert not _errors(name, NOT_FOUND)
    assert _errors(name, {**NOT_FOUND, "details": {"metric_ref": "metric_x"}})
    assert _errors(name, {**NOT_FOUND, "message": "Metric metric_x not found"})
    assert _errors(name, VALIDATION_FAILED)
