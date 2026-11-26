# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""experiment_run.get_run_correlations on the experiment-run reference URL."""

from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/correlations"
OLD_PATH = "/api/v1/analytics/runs/{run_id}/correlations"
OP_ID = "experiment_run.get_run_correlations"
PROBLEMS = {
    "400": ("bad_request", "Bad Request", "The request could not be processed."),
    "401": ("unauthenticated", "Unauthorized", "Authentication is required."),
    "403": ("forbidden", "Forbidden", "The credential is not allowed to perform this operation."),
    "404": ("not_found", "Not Found", "The requested resource was not found."),
    "429": ("rate_limited", "Too Many Requests", "Too many requests. Retry later."),
    "500": ("internal_error", "Internal Server Error", "The request could not be completed."),
    "503": (
        "service_unavailable",
        "Service Unavailable",
        "The service is temporarily unavailable. Retry later.",
    ),
}
MAX_BYTES = 1048576
MAX_DIMENSIONS = 128
MAX_ROWS = 10000
NAME_MAX = 256


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")
OP = CATALOG["paths"][PATH]["get"]
PROBLEM_FILE = "analytics/correlations_problem_schema.json"
RESP_FILE = "analytics/experiment_run_correlations_response_schema.json"


def _validator(stem: str) -> Draft7Validator:
    v = SchemaValidator(contract="backend")
    return Draft7Validator(v._schemas[stem], registry=v._registry, format_checker=FormatChecker())


def _problem(status: str) -> dict:
    code, title, detail = PROBLEMS[status]
    urn = f"urn:traigent:problem:{code}"
    return {
        "type": urn,
        "title": title,
        "status": int(status),
        "code": code,
        "detail": detail,
        "problem_id": hashlib.sha256(urn.encode()).hexdigest()[:32],
    }


def test_operation_id_is_unique_and_reachable():
    master = _load("mep_endpoints.json")
    found = []
    for module in master["x-endpoint-modules"]:
        doc = _load(module["paths_file"].removeprefix("./"))
        for path, item in doc["paths"].items():
            for method, op in item.items():
                if isinstance(op, dict) and op.get("operationId") == OP_ID:
                    found.append((method, path))
    assert found == [("get", PATH)]
    assert f"GET:{PATH}" in SchemaValidator(contract="backend")._known_endpoints


def test_path_parameters_and_ref_pattern():
    names = [(p["name"], p["in"], p["required"]) for p in OP["parameters"]]
    assert names[:2] == [("project_id", "path", True), ("experiment_run_ref", "path", True)]
    ref = Draft7Validator(OP["parameters"][1]["schema"])
    assert ref.is_valid("experiment_run_" + "a1b2c3d4" * 4)
    assert not ref.is_valid("12345")  # raw integer id
    assert not ref.is_valid("experiment_run_" + "A" * 32)  # uppercase hex
    assert not ref.is_valid("experiment_run_abc")  # short
    assert not ref.is_valid("experiment_run_" + "a" * 33)  # long
    assert not ref.is_valid("experiment_" + "a" * 32)  # wrong prefix
    assert not ref.is_valid("experiment_bad_" + "a" * 32)  # same length, wrong prefix
    assert not ref.is_valid("")
    assert "(?!" not in OP["parameters"][1]["schema"]["pattern"]


def test_query_parameters_follow_the_backend_query_model():
    # backend RunCorrelationsQuery: src/shared_infrastructure/schemas/run_analytics.py:79-84
    # (method enum default pearson, min_sample int ge=2 le=10_000 default 3, extra="forbid").
    query = {p["name"]: p for p in OP["parameters"] if p["in"] == "query"}
    assert set(query) == {"method", "min_sample"}
    assert all(not p["required"] for p in query.values())
    method = Draft7Validator(query["method"]["schema"])
    assert query["method"]["schema"]["default"] == "pearson"
    assert method.is_valid("pearson") and method.is_valid("spearman")
    for bad in ("kendall", "PEARSON", "", None, 1):
        assert not method.is_valid(bad), bad
    sample = Draft7Validator(query["min_sample"]["schema"])
    assert query["min_sample"]["schema"]["default"] == 3
    assert sample.is_valid(2) and sample.is_valid(10000)
    for bad in (1, 0, -1, 10001, 2.5, "3"):
        assert not sample.is_valid(bad), bad


def test_declared_statuses_and_media_types():
    assert set(OP["responses"]) == {"200", *PROBLEMS}
    for status, resp in OP["responses"].items():
        media = "application/json" if status == "200" else "application/problem+json"
        assert set(resp["content"]) == {media}, status
    for status in ("429", "503"):
        assert "Retry-After" in OP["responses"][status]["headers"]
    assert "never a partial success" in OP["responses"]["503"]["description"]
    assert "echoes no value" in OP["responses"]["400"]["description"]
    for phrase in ("128 numeric measure dimensions", "10000 scoped configuration rows", "over 256 characters"):
        assert phrase in OP["responses"]["503"]["description"], phrase


@pytest.mark.parametrize("status", sorted(PROBLEMS))
def test_each_problem_is_closed_and_matches_its_status(status):
    ref = OP["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"]
    assert ref.startswith("./correlations_problem_schema.json#/definitions/")
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    assert one.is_valid(_problem(status))
    assert not one.is_valid({**_problem(status), "extra": 1})
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))
    assert not list(_validator("correlations_problem_schema").iter_errors(_problem(status)))


def test_bad_query_problem_names_and_echoes_nothing():
    bad = _load(PROBLEM_FILE)["definitions"]["BadRequestProblem"]
    assert set(bad["properties"]) == {"type", "title", "status", "code", "detail", "problem_id"}
    assert bad["properties"]["detail"] == {
        "const": "The request could not be processed.",
        "x-content-class": "closed_enum",
    }
    assert "echoes no value" in _load(PROBLEM_FILE)["description"]
    v = _validator("correlations_problem_schema")
    echoed = {**_problem("400"), "errors": [{"loc": ["min_sample"], "input": "abc"}]}
    assert list(v.iter_errors(echoed))
    assert list(v.iter_errors({**_problem("400"), "detail": "min_sample must be >= 2"}))


# builder field set: RunAnalyticsService.correlations (backend
# src/services/analytics/run_analytics_service.py:803-832) returns run_id, method, sample_size,
# measure_correlations, parameter_correlations, warnings. Measure rows x/y/r/p_value/strength are
# built at :874-882, parameter rows parameter/measure/effect/confidence at :919-930.
DATA_FIELDS = {"method", "sample_size", "measure_correlations", "parameter_correlations", "warnings"}
BUILDER_FIELDS = DATA_FIELDS | {"run_id"}


def _measure(i: int = 0) -> dict:
    return {"x": f"m{i}", "y": f"m{i + 1}", "r": 0.5, "p_value": 0.01, "strength": "moderate"}


def _param(i: int = 0) -> dict:
    return {"parameter": f"p{i}", "measure": f"m{i}", "effect": -0.25, "confidence": "low"}


def _data() -> dict:
    return {
        "method": "pearson",
        "sample_size": 12,
        "measure_correlations": [_measure()],
        "parameter_correlations": [_param()],
        "warnings": ["insufficient_samples:a~b"],
    }


def _envelope(data: dict | None = None, measures: int = 2, params: int = 1) -> dict:
    return {
        "success": True,
        "message": "ok",
        "data": data if data is not None else _data(),
        "meta": {"measure_dimensions_total": measures, "parameter_dimensions_total": params},
    }


def test_field_set_matches_the_builder_minus_the_internal_run_id():
    new = _load(RESP_FILE)
    bounded = new["definitions"]["BoundedCorrelations"]
    assert set(bounded["properties"]) == DATA_FIELDS == BUILDER_FIELDS - {"run_id"}
    assert set(bounded["required"]) == DATA_FIELDS
    assert bounded["additionalProperties"] is False
    old = _load("analytics/run_correlations_schema.json")
    assert set(old["properties"]) == BUILDER_FIELDS  # the unchanged historical DTO agrees
    for name, keys in (
        ("MeasureCorrelation", {"x", "y", "r", "p_value", "strength"}),
        ("ParameterCorrelation", {"parameter", "measure", "effect", "confidence"}),
    ):
        d = new["definitions"][name]
        assert set(d["properties"]) == set(d["required"]) == keys
        assert d["additionalProperties"] is False
    assert "omits data.run_id" in new["description"]


def test_response_validates_and_is_closed():
    v = _validator("experiment_run_correlations_response_schema")
    d = _data()
    ok = _envelope(d)
    assert not list(v.iter_errors(ok))
    assert list(v.iter_errors(d))  # not enveloped
    assert list(v.iter_errors({**ok, "extra": 1}))
    assert list(v.iter_errors({**ok, "data": {**d, "extra": 1}}))
    assert list(v.iter_errors({**ok, "meta": {**ok["meta"], "extra": 1}}))
    assert list(v.iter_errors({k: x for k, x in ok.items() if k != "meta"}))
    for bad in (
        {**d, "method": "kendall"},
        {**d, "sample_size": -1},
        {**d, "sample_size": 10001},
        {**d, "measure_correlations": [{**_measure(), "extra": 1}]},
        {**d, "measure_correlations": [{**_measure(), "r": 1.5}]},
        {**d, "measure_correlations": [{**_measure(), "r": -1.5}]},
        {**d, "measure_correlations": [{**_measure(), "p_value": 1.5}]},
        {**d, "measure_correlations": [{**_measure(), "strength": "huge"}]},
        {**d, "measure_correlations": [{**_measure(), "x": ""}]},
        {**d, "measure_correlations": [{**_measure(), "x": "x" * 257}]},
        {**d, "parameter_correlations": [{**_param(), "extra": 1}]},
        {**d, "parameter_correlations": [{**_param(), "effect": 1.5}]},
        {**d, "parameter_correlations": [{**_param(), "confidence": "certain"}]},
        {**d, "parameter_correlations": [{**_param(), "parameter": "p" * 257}]},
        {**d, "warnings": [""]},
        {**d, "warnings": ["w"]},  # not one of the builder's three formats
        {**d, "warnings": ["insufficient_samples:a"]},
        {**d, "warnings": ["insufficient_samples:a~"]},
        {**d, "warnings": ["zero_variance:"]},
        {**d, "warnings": ["zero_variance:" + "x" * 257]},
        {**d, "warnings": ["insufficient_samples:" + "x" * 257 + "~y"]},
        {**d, "warnings": ["zero_variance:a\nb"]},  # control character
        {**d, "warnings": ["categorical_parameters_omitted:other"]},
        {**d, "measure_correlations": [{**_measure(), "x": "a\x00b"}]},
        {**d, "measure_correlations": [{**_measure(), "y": "a\x1fb"}]},
        {**d, "measure_correlations": [{**_measure(), "y": "a\x7fb"}]},
        {**d, "parameter_correlations": [{**_param(), "parameter": "a\nb"}]},
        {**d, "parameter_correlations": [{**_param(), "parameter": "a\tb"}]},  # tab: stored name -> closed 503
        {**d, "parameter_correlations": [{**_param(), "measure": "a\tb"}]},
    ):
        assert list(v.iter_errors(_envelope(bad))), bad
    assert not list(v.iter_errors({**ok, "metadata": {"k": "v"}}))
    assert list(v.iter_errors({**ok, "metadata": {str(i): 1 for i in range(9)}}))


def test_internal_run_id_is_rejected():
    v = _validator("experiment_run_correlations_response_schema")
    for rid in ("12345", "experiment_run_" + "a" * 32, None):
        assert list(v.iter_errors(_envelope({**_data(), "run_id": rid}))), rid
    # the historical DTO still carries it (deprecated path)
    legacy = _validator("run_correlations_response_schema")
    assert not list(legacy.iter_errors({"success": True, "message": "ok", "data": {**_data(), "run_id": "12345"}}))


def test_dimension_cap_and_required_totals():
    v = _validator("experiment_run_correlations_response_schema")
    pairs = MAX_DIMENSIONS * (MAX_DIMENSIONS - 1) // 2
    rows = MAX_DIMENSIONS * MAX_DIMENSIONS
    assert (pairs, rows) == (8128, 16384)
    d = _data()
    longest = "x" * NAME_MAX
    full = {
        **d,
        "sample_size": MAX_ROWS,
        "measure_correlations": [{**_measure(), "x": longest, "y": longest}] * pairs,
        "parameter_correlations": [{**_param(), "parameter": longest, "measure": longest}] * rows,
        "warnings": [f"insufficient_samples:{longest}~{longest}"] * (pairs + 1),
    }
    assert len(full["warnings"][0]) == 534
    assert not list(v.iter_errors(_envelope(full, measures=128, params=128)))  # declared maximum
    assert list(v.iter_errors(_envelope({**full, "measure_correlations": full["measure_correlations"] + [_measure()]}, 128, 128)))
    assert list(v.iter_errors(_envelope({**full, "parameter_correlations": full["parameter_correlations"] + [_param()]}, 128, 128)))
    assert list(v.iter_errors(_envelope({**full, "warnings": full["warnings"] + ["zero_variance:a"]}, 128, 128)))
    assert list(v.iter_errors(_envelope({**full, "sample_size": MAX_ROWS + 1}, 128, 128)))
    # a run with 65..128 parameters is an ordinary run, not rejected
    assert not list(v.iter_errors(_envelope(d, measures=2, params=100)))
    for bad_meta in (
        {"measure_dimensions_total": 129, "parameter_dimensions_total": 1},
        {"measure_dimensions_total": 1, "parameter_dimensions_total": 129},
        {"measure_dimensions_total": -1, "parameter_dimensions_total": 1},
        {"measure_dimensions_total": 1.5, "parameter_dimensions_total": 1},
        {"measure_dimensions_total": 1},
        {"parameter_dimensions_total": 1},
        {},
    ):
        assert list(v.iter_errors({**_envelope(), "meta": bad_meta})), bad_meta
    # the three builder warning formats, with the longest allowed names
    for ok in (
        f"zero_variance:{longest}",
        "categorical_parameters_omitted:unordered_levels_have_no_signed_effect",
        "insufficient_samples:a~b",
    ):
        assert not list(v.iter_errors(_envelope({**d, "warnings": [ok]}))), ok
    text = _load(RESP_FILE)["description"]
    assert "at most 128 numeric measure dimensions" in text
    assert "refused with the closed 503, never truncated" in text
    assert "could merge two names" in text
    assert "before either analysis loop" in text
    assert "128 numeric parameter dimensions" in OP["description"]
    assert "never truncated or partially analyzed" in OP["description"]
    assert "before either analysis loop" in OP["description"].lower()
    assert "work cap of 10000 scoped configuration rows" in OP["description"]
    assert "src/schemas/traigent.py:54-63" in OP["description"]
    assert "parses the query strictly" in OP["description"]
    assert "query_params.py:64-97" in OP["description"]
    assert "tenant-selector" in OP["responses"]["400"]["description"]


def test_size_limit_is_enforced_on_the_serialized_envelope_not_statically():
    resp = _load(RESP_FILE)
    assert resp["x-max-response-bytes"] == MAX_BYTES == OP["x-max-response-bytes"]
    assert OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == (
        "./experiment_run_correlations_response_schema.json"
    )
    for text in (resp["description"], OP["description"]):
        low = text.lower()
        assert "enforced on the serialized envelope" in low
        assert "the closed 503" in low
    assert "no static byte bound" in resp["description"].lower()
    assert "the schema gives no static byte bound" in OP["description"].lower()


def test_deprecated_path_points_at_the_successor():
    old = CATALOG["paths"][OLD_PATH]["get"]
    assert old["deprecated"] is True
    assert old["operationId"] == "analytics_runs.get_run_correlations"
    assert OP_ID in old["description"]
    assert "{experiment_run_ref}/correlations" in old["description"]
    assert "beta" in old["description"] and "api_v1beta.py:111" in old["description"]
    assert not OP.get("deprecated")


def test_historical_correlations_schemas_are_untouched():
    old = _load("analytics/run_correlations_schema.json")
    assert old["properties"]["measure_correlations"]["maxItems"] == 200
    assert old["properties"]["parameter_correlations"]["maxItems"] == 500
    assert "run_id" in old["required"]


def test_stored_name_failing_the_pattern_is_the_closed_503_not_sanitized():
    for text in (
        OP["responses"]["503"]["description"],
        OP["description"],
        _load(RESP_FILE)["description"],
        _load(PROBLEM_FILE)["description"],
    ):
        assert "fails the name pattern" in text
        assert "tab" in text
    assert "never truncated and never sanitized" in OP["description"]
    assert "(?!" not in _load(RESP_FILE)["description"]


def test_no_name_or_warning_pattern_uses_a_lookahead():
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pattern":
                    yield value
                else:
                    yield from walk(value)
        elif isinstance(node, list):
            for item in node:
                yield from walk(item)

    patterns = list(walk(_load(RESP_FILE)))
    assert len(patterns) == 7  # 4 names + 3 warning formats
    for pattern in patterns:
        assert pattern.endswith("$"), pattern  # no lookahead: Pydantic v2 rust-regex refuses it
        assert "(?!" not in pattern, pattern


def test_parameter_scan_exclusion_and_key_cap_are_stated():
    for text in (OP["description"], _load(RESP_FILE)["description"]):
        assert "excluded BEFORE the importance loop" in text
        assert "DISTINCT stored parameter keys" in text
        assert "capped at 256" in text
        assert "closed 503 above it (never truncated)" in text
        assert "before any analysis loop" in text
        assert "run_analytics_service.py:909-919, :3506-3529" in text
    assert "256 distinct stored parameter keys" in OP["responses"]["503"]["description"]
    assert "256 distinct stored parameter keys" in _load(PROBLEM_FILE)["description"]
