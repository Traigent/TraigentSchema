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
    assert errors, field


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
