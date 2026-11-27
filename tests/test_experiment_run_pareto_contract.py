# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""experiment_run.get_run_pareto on the experiment-run reference URL."""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

# Generic path-shape guards (file ref, file:line ref, source-tree prefix, line range); split so the repository's own leak scan stays clean.
_PRIVATE = re.compile(r"\.py\b|s[r]c/|\.p" + r"y:\d|:\d+-\d+")

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/pareto"
OLD_PATH = "/api/v1/analytics/runs/{run_id}/pareto"
OP_ID = "experiment_run.get_run_pareto"
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


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")
OP = CATALOG["paths"][PATH]["get"]
RESP = _load("analytics/experiment_run_pareto_response_schema.json")
PROBLEM_FILE = "analytics/pareto_problem_schema.json"
QUERY = {p["name"]: p for p in OP["parameters"] if p["in"] == "query"}


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
    path_params = [(p["name"], p["required"]) for p in OP["parameters"] if p["in"] == "path"]
    assert path_params == [("project_id", True), ("experiment_run_ref", True)]
    ref = Draft7Validator(OP["parameters"][1]["schema"])
    assert ref.is_valid("experiment_run_" + "a1b2c3d4" * 4)
    assert not ref.is_valid("12345")  # raw integer id
    assert not ref.is_valid("experiment_run_" + "A" * 32)  # uppercase hex
    assert not ref.is_valid("experiment_run_abc")  # short
    assert not ref.is_valid("experiment_run_" + "a" * 33)  # long
    assert not ref.is_valid("experiment_" + "a" * 32)  # wrong prefix


def test_query_vocabulary_is_closed_and_matches_the_backend_query_model():
    # the backend Pareto query model
    # plus the collection pair limit/cursor; extra="forbid" in the backend, so any other name is the 400
    assert set(QUERY) == {"limit", "cursor", "x_measure", "y_measure", "request_count"}
    assert all(not p["required"] for p in QUERY.values())
    xs = QUERY["x_measure"]["schema"]
    assert (xs["type"], xs["minLength"], xs["maxLength"], xs["default"]) == ("string", 1, 100, "cost")
    assert QUERY["y_measure"]["schema"]["default"] == "quality"
    rc = QUERY["request_count"]["schema"]
    assert (rc["minimum"], rc["maximum"], rc["default"]) == (1, 1_000_000, 1)
    for text in (OP["description"], OP["responses"]["400"]["description"]):
        assert "page" in text and "offset" in text
    assert "any other query parameter" in OP["description"]


def test_limit_bounds_and_default():
    schema = QUERY["limit"]["schema"]
    assert schema["default"] == 20
    v = Draft7Validator(schema)
    for ok in (1, 20, 100):
        assert v.is_valid(ok), ok
    for bad in (0, -1, 101, 1.5, "20", None):
        assert not v.is_valid(bad), bad
    assert RESP["definitions"]["Pagination"]["properties"]["limit"]["maximum"] == 100
    assert RESP["definitions"]["ParetoPage"]["properties"]["items"]["maxItems"] == 100


def test_cursor_is_bounded_and_opaque():
    schema = QUERY["cursor"]["schema"]
    v = Draft7Validator(schema)
    assert schema["maxLength"] == 512
    assert v.is_valid("eyJhIjoxfQ")
    assert v.is_valid("A" * 512)
    assert not v.is_valid("A" * 513)
    assert not v.is_valid("")
    assert not v.is_valid("not base64url!")
    assert not v.is_valid("a/b+c=")  # standard base64 alphabet and padding are not accepted
    assert RESP["definitions"]["Cursor"]["pattern"] == schema["pattern"]
    text = QUERY["cursor"]["description"]
    assert "Opaque" in text and "sealed" in text and "Never a raw primary key" in text
    assert "never a raw historical primary key" in RESP["description"]


def test_declared_statuses_and_media_types():
    assert set(OP["responses"]) == {"200", *PROBLEMS}
    for status, resp in OP["responses"].items():
        media = "application/json" if status == "200" else "application/problem+json"
        assert set(resp["content"]) == {media}, status
    for status in ("429", "503"):
        assert "Retry-After" in OP["responses"][status]["headers"]
    assert "never a partial success" in OP["responses"]["503"]["description"]
    # the 400 echoes no client value
    assert "no value is echoed" in OP["responses"]["400"]["description"]
    assert "never echoes the offending value" in _load(PROBLEM_FILE)["description"]


@pytest.mark.parametrize("status", sorted(PROBLEMS))
def test_each_problem_is_closed_and_matches_its_status(status):
    schema = OP["responses"][status]["content"]["application/problem+json"]["schema"]
    ref = schema["oneOf"][0]["$ref"] if status == "400" else schema["$ref"]
    assert ref.startswith("./pareto_problem_schema.json#/definitions/")
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    assert one.is_valid(_problem(status))
    assert not one.is_valid({**_problem(status), "extra": 1})
    assert not one.is_valid({**_problem(status), "detail": "limit=101 is invalid"})  # no echo
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))
    assert not list(_validator("pareto_problem_schema").iter_errors(_problem(status)))


def test_problem_schema_root_oneof_enforces_the_vocabulary():
    v = _validator("pareto_problem_schema")
    assert not list(v.iter_errors(_problem("404")))
    assert list(v.iter_errors({**_problem("404"), "status": 418}))
    assert list(v.iter_errors({**_problem("404"), "extra": 1}))
    assert list(v.iter_errors({"type": "urn:traigent:problem:not_found"}))


REF = "experiment_run_" + "0f" * 16


def _frontier(pos: int, rank: int, knee: bool = False) -> dict:
    return {
        "kind": "frontier",
        "trial_ref": f"trial_{pos + 1:016x}",
        "rank_on_frontier": rank,
        "metrics": {"cost": 0.01, "quality": 0.9, "latency": 120.0},
        "is_knee": knee,
        "tradeoff_summary": "Balanced trade-off between cost and quality.",
    }


def _dominated(pos: int, by: int) -> dict:
    return {
        "kind": "dominated",
        "trial_ref": f"trial_{pos + 1:016x}",
        "dominated_by": f"trial_{by + 1:016x}",
        "reason": "Another configuration matches or beats it on both axes.",
    }


def _page() -> dict:
    return {
        "run_id": REF,
        "measures": {"quality": "accuracy", "cost": "total_cost", "latency": "latency_ms"},
        "shape": "clear_knee",
        "knee_ref": "trial_%016x" % 2,
        "frontier_total": 3,
        "dominated_total": 1,
        "warnings": ["non_finite_filtered:1"],
        "items": [_frontier(0, 1), _frontier(1, 2, True), _frontier(2, 3), _dominated(3, 1)],
        "pagination": {"limit": 20, "next_cursor": None, "has_more": False, "total": 4},
    }


def _env(data: dict) -> dict:
    return {"success": True, "message": "ok", "data": data}


def test_response_validates_and_pagination_is_required():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    assert not list(v.iter_errors(_env(d)))
    more = {**d["pagination"], "next_cursor": "c2Vh", "has_more": True}
    assert not list(v.iter_errors(_env({**d, "pagination": more})))
    page = RESP["definitions"]["ParetoPage"]
    assert {"items", "pagination"} <= set(page["required"])
    assert set(RESP["definitions"]["Pagination"]["required"]) == {"limit", "next_cursor", "has_more", "total"}
    for missing in ("items", "pagination", "knee_ref", "frontier_total", "dominated_total", "run_id"):
        assert list(v.iter_errors(_env({k: x for k, x in d.items() if k != missing}))), missing
    for missing in ("limit", "next_cursor", "has_more", "total"):
        bad = {k: x for k, x in d["pagination"].items() if k != missing}
        assert list(v.iter_errors(_env({**d, "pagination": bad}))), missing
    for bad_total in (-1, 10001, 1.5, "4", None):
        assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "total": bad_total}}))), bad_total
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "a/b"}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "A" * 513}})))
    assert list(v.iter_errors(d))  # not enveloped


def test_knee_and_frontier_semantics_are_preserved_across_pages():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    assert not list(v.iter_errors(_env({**d, "knee_ref": None, "shape": "linear"})))
    for shape in ("clear_knee", "flat", "linear", "scattered"):
        assert not list(v.iter_errors(_env({**d, "shape": shape})))
    assert list(v.iter_errors(_env({**d, "shape": "wiggly"})))
    # a frontier item always carries rank, knee flag and trade-off; a dominated item its dominator
    bad_frontier = {k: x for k, x in _frontier(0, 1).items() if k != "is_knee"}
    assert list(v.iter_errors(_env({**d, "items": [bad_frontier]})))
    assert list(v.iter_errors(_env({**d, "items": [_frontier(0, 0)]})))  # rank is 1-based
    assert list(v.iter_errors(_env({**d, "items": [{**_dominated(3, 1), "kind": "frontier"}]})))
    text = RESP["description"]
    assert "computed over the FULL eligible population" in text
    assert "ascending trial_ref (lexicographic)" in text
    assert "knee_ref names the knee whatever page it is on" in text


def test_field_set_matches_the_backend_builder():
    # the backend Pareto payload, frontier entry and dominated entry key sets
    page = RESP["definitions"]["ParetoPage"]["properties"]
    assert {"measures", "shape", "warnings"} <= set(page)
    assert set(RESP["definitions"]["FrontierItem"]["properties"]) == {
        "kind", "trial_ref", "rank_on_frontier", "metrics", "is_knee", "tradeoff_summary",
    }  # config_id -> trial_ref
    assert set(RESP["definitions"]["DominatedItem"]["properties"]) == {
        "kind", "trial_ref", "dominated_by", "reason",
    }  # config_id -> trial_ref
    assert RESP["definitions"]["ParetoPage"]["properties"]["measures"]["required"] == ["quality", "cost", "latency"]
    assert RESP["definitions"]["Metrics"]["maxProperties"] == 5  # x, y and three axes
    assert "The analysis mirrors the backend's Pareto analysis" in RESP["description"]
    assert not re.search(r"\.py\b|\.p" + r"y:\d|s[r]c/|:\d{3,}-\d{3,}", RESP["description"])
    # the historical DTO is unchanged and still serves the deprecated path
    old = _load("analytics/run_pareto_schema.json")
    assert set(old["required"]) == {"run_id", "project_id", "measures", "frontier", "dominated", "shape", "warnings"}


def test_internal_ids_are_rejected():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    assert list(v.iter_errors(_env({**d, "project_id": "12345"})))
    assert list(v.iter_errors(_env({**d, "run_id": "12345"})))  # historical run id
    assert list(v.iter_errors(_env({**d, "run_id": "experiment_run_" + "A" * 32})))
    f = _frontier(0, 1)
    assert list(v.iter_errors(_env({**d, "items": [{**f, "config_id": "12345"}]})))
    assert list(v.iter_errors(_env({**d, "items": [{**f, "trial_ref": "12345"}]})))
    dom = _dominated(3, 1)
    assert list(v.iter_errors(_env({**d, "items": [{**dom, "config_id": "12345"}]})))
    assert list(v.iter_errors(_env({**d, "items": [{**dom, "dominated_by": "12345"}]})))
    for bad in ("0", "trial_", "trial_1", "trial_10000", "trial_" + "a" * 15, "trial_" + "a" * 17, "trial_" + "A" * 16, "Trial_" + "a" * 16, "trial_" + "g" * 16, "trial_-" + "a" * 15):
        assert list(v.iter_errors(_env({**d, "items": [{**f, "trial_ref": bad}]}))), bad
    for ok in ("trial_0123456789abcdef", "trial_ffffffffffffffff"):
        assert not list(v.iter_errors(_env({**d, "items": [{**f, "trial_ref": ok}]}))), ok
    desc = RESP["description"]
    for omitted in ("config_id", "project_id"):
        assert f"omits {omitted}" in desc, omitted
    assert "populated from the resolved reference, never the historical run id" in desc
    assert "omits config_id" in OP["description"] or "omits config_id and project_id" in OP["description"]


def test_response_is_closed_and_bounded():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    f = _frontier(0, 1)
    assert list(v.iter_errors({**_env(d), "extra": 1}))
    assert list(v.iter_errors({**_env(d), "meta": {}}))
    for bad in (
        {**d, "extra": 1},
        {**d, "items": [{**f, "extra": 1}]},
        {**d, "items": [f] * 101},
        {**d, "warnings": ["w"] * 51},
        {**d, "warnings": ["x" * 501]},
        {**d, "warnings": [""]},
        {**d, "measures": {**d["measures"], "extra": "x"}},
        {**d, "measures": {**d["measures"], "cost": "x" * 101}},
        {**d, "measures": {**d["measures"], "cost": ""}},
        {**d, "frontier_total": 10001},
        {**d, "items": [{**f, "metrics": {}}]},
        {**d, "items": [{**f, "metrics": {str(i): 1.0 for i in range(6)}}]},
        {**d, "items": [{**f, "metrics": {"bad\tname": 1.0}}]},
        {**d, "items": [{**f, "metrics": {"cost": "high"}}]},
        {**d, "items": [{**f, "tradeoff_summary": "x" * 501}]},
        {**d, "items": [{**_dominated(3, 1), "reason": "x" * 501}]},
        {**d, "items": [{"kind": "other"}]},
    ):
        assert list(v.iter_errors(_env(bad))), bad
    edge = {
        **d,
        "warnings": ["measure_unavailable:" + "x" * 100] * 50,
        "items": [{**f, "trial_ref": f"trial_{i + 1:016x}", "tradeoff_summary": "x" * 500} for i in range(100)],
        "pagination": {"limit": 100, "next_cursor": "A" * 512, "has_more": True, "total": 10000},
        "frontier_total": 10000,
        "dominated_total": 0,
    }
    assert not list(v.iter_errors(_env(edge)))


def test_size_limit_is_enforced_on_the_serialized_envelope_not_statically():
    assert RESP["x-max-response-bytes"] == MAX_BYTES == OP["x-max-response-bytes"]
    assert (
        OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "./experiment_run_pareto_response_schema.json"
    )
    for text in (RESP["description"], OP["description"]):
        low = text.lower()
        assert "enforced on the serialized envelope" in low
        assert "the closed 503" in low
        assert "no static byte bound" in low
    assert "1 MiB" in OP["responses"]["503"]["description"]
    assert "never a partial" in _load(PROBLEM_FILE)["description"]


def test_deprecated_path_points_at_the_successor():
    old = CATALOG["paths"][OLD_PATH]["get"]
    assert old["deprecated"] is True
    assert old["operationId"] == "analytics_runs.get_run_pareto"
    assert OP_ID in old["description"]
    assert "{experiment_run_ref}/pareto" in old["description"]
    assert "beta" in old["description"]
    assert not OP.get("deprecated")
    # the historical schema files are left untouched
    assert old["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == "./run_pareto_response_schema.json"


def test_trial_ref_is_the_shared_run_scoped_definition():
    ref = "https://schemas.traigent.ai/analytics/experiment_run_trial_ref_schema.json"
    assert RESP["definitions"]["TrialRef"] == {"$ref": ref}
    shared = _load("analytics/experiment_run_trial_ref_schema.json")
    assert shared["$id"] == ref
    assert shared["pattern"] == "^(trial_[0-9a-f]{16}|configuration_run_[0-9a-f]{32})$"
    assert (shared["minLength"], shared["maxLength"]) == (22, 50)
    assert Draft7Validator(shared).is_valid("trial_0123456789abcdef")
    assert Draft7Validator(shared).is_valid("configuration_run_" + "0f" * 16)
    assert not Draft7Validator(shared).is_valid("trial_10000")
    assert "run-scoped" in OP["description"]
    # persisted reference: no private migration file is cited
    assert not _PRIVATE.search(RESP["description"])
    assert "1-based" not in RESP["description"] and "1-based" not in OP["description"]
    assert "not yet issued is the closed 503" in RESP["description"]
    assert "not yet issued is the closed 503" in OP["description"]
    for name in ("FrontierItem", "DominatedItem"):
        assert RESP["definitions"][name]["properties"]["trial_ref"] == {"$ref": "#/definitions/TrialRef"}
    assert RESP["definitions"]["DominatedItem"]["properties"]["dominated_by"]["$ref"] == "#/definitions/TrialRef"
    assert RESP["definitions"]["ParetoPage"]["properties"]["knee_ref"]["anyOf"][0] == {"$ref": "#/definitions/TrialRef"}


REVISION_RULE = (
    "a per-run monotonic counter the backend increments in the same transaction as any insert or delete "
    "of the run's configuration rows, and any update that changes a configuration row's analysis content "
    "(its status, measures, summary_stats, experiment_parameters or metadata); writes that change none of "
    "these (timestamps, workflow metadata, public-reference backfill, identical rewrites) do not change it"
)


def test_cursor_seals_the_analysis_revision_and_a_stale_cursor_is_invalid_cursor():
    for text in (RESP["description"], OP["description"]):
        assert "analysis_revision" in text
        assert "per-run monotonic counter" in text
        assert REVISION_RULE in text
        assert "maximum configuration updated_at" not in text and "digest" not in text
        assert "invalid_cursor" in text
    assert "analysis_revision" in QUERY["cursor"]["description"]
    refs = [x["$ref"] for x in OP["responses"]["400"]["content"]["application/problem+json"]["schema"]["oneOf"]]
    assert refs == [
        "./pareto_problem_schema.json#/definitions/BadRequestProblem",
        "./pareto_problem_schema.json#/definitions/InvalidCursorProblem",
    ]
    bad = _load(PROBLEM_FILE)["definitions"]["InvalidCursorProblem"]
    one = Draft7Validator(bad)
    urn = "urn:traigent:problem:invalid_cursor"
    doc = {
        "type": urn,
        "title": "Bad Request",
        "status": 400,
        "code": "invalid_cursor",
        "detail": "The cursor is not valid for this request.",
        "problem_id": hashlib.sha256(urn.encode()).hexdigest()[:32],
    }
    assert one.is_valid(doc)
    assert not one.is_valid({**doc, "extra": 1})
    assert not one.is_valid({**doc, "detail": "cursor abc is stale"})  # echoes nothing
    assert not list(_validator("pareto_problem_schema").iter_errors(doc))
    assert not Draft7Validator(_load(PROBLEM_FILE)["definitions"]["BadRequestProblem"]).is_valid(doc)


def test_ordering_is_stated():
    for text in (RESP["description"], OP["description"]):
        assert "ascending trial_ref (lexicographic)" in text
        assert "before ranks are assigned" in text or "BEFORE ranks are assigned" in text
    assert "dominated entries are ordered by ascending trial_ref" in RESP["description"]


def test_cap_counts_all_scoped_configuration_rows_before_metric_processing():
    for text in (RESP["description"], OP["description"]):
        assert "counts ALL the run's scoped configuration rows before any metric processing" in text
    assert "10000 scoped configuration rows" in OP["responses"]["503"]["description"]


def test_metrics_accept_any_finite_number():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    for value in (1e16, -1e300, 0, 3.5):
        item = {**_frontier(0, 1), "metrics": {"cost": value}}
        assert not list(v.iter_errors(_env({**d, "items": [item]}))), value
    assert "maximum" not in RESP["definitions"]["Metrics"]["additionalProperties"]
    assert "Any finite JSON number" in RESP["definitions"]["Metrics"]["description"]


def test_has_more_is_true_if_and_only_if_next_cursor_is_non_null():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    pg = d["pagination"]
    assert not list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": True, "next_cursor": "c2Vh"}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": True, "next_cursor": None}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": False, "next_cursor": "c2Vh"}})))


def test_warnings_are_the_three_builder_tag_forms():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    for ok in ("measure_unavailable:cost", "measure_unavailable:" + "x" * 100, "non_finite_filtered:3", "single_configuration"):
        assert not list(v.iter_errors(_env({**d, "warnings": [ok]}))), ok
    for bad in ("frontier_truncated:600", "anything", "measure_unavailable:", "non_finite_filtered:x", "single_configuration:1"):
        assert list(v.iter_errors(_env({**d, "warnings": [bad]}))), bad


def test_deprecation_names_the_full_beta_route():
    old = CATALOG["paths"][OLD_PATH]["get"]["description"]
    assert "/api/v1beta/projects/{project_id}/analytics/runs/{run_id}/pareto" in old


def test_measure_names_reject_control_characters_and_warnings_use_the_same_class():
    for name in ("x_measure", "y_measure"):
        schema = QUERY[name]["schema"]
        assert schema["pattern"] == "^[^\\x00-\\x1f\\x7f]{1,100}$"
        v = Draft7Validator(schema)
        assert v.is_valid("total_cost")
        assert v.is_valid("a b.c-d")
        assert v.is_valid("x" * 100)
        for bad in ("", "x" * 101, "a\nb", "a\x00b", "a\x1fb", "a\x7fb", "a\tb"):
            assert not v.is_valid(bad), repr(bad)
    assert "control characters" in OP["responses"]["400"]["description"]
    warn = RESP["definitions"]["ParetoPage"]["properties"]["warnings"]["items"]["anyOf"][0]["pattern"]
    assert "[^\\x00-\\x1f\\x7f]" in warn and "." not in warn.replace("\\.", "")
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    assert not list(v.iter_errors(_env({**d, "warnings": ["measure_unavailable:name with spaces"]})))
    assert list(v.iter_errors(_env({**d, "warnings": ["measure_unavailable:a\nb"]})))


def _all_patterns(node, out):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                out.append(value)
            else:
                _all_patterns(value, out)
    elif isinstance(node, list):
        for item in node:
            _all_patterns(item, out)
    return out


def test_no_w10_pattern_uses_a_lookahead():
    # Patterns end in "$" (Pydantic v2's rust-regex engine refuses lookahead).
    pats = _all_patterns(RESP, []) + _all_patterns(_load("analytics/experiment_run_trial_ref_schema.json"), [])
    pats += _all_patterns(OP, []) + _all_patterns(_load("analytics/experiment_run_report_response_schema.json"), [])
    pats += _all_patterns(CATALOG["paths"]["/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/report"], [])
    assert len(pats) >= 10
    for pat in pats:
        assert "(?!" not in pat, pat
        assert pat.endswith("$"), pat


def test_every_pareto_ref_rejects_empty_and_malformed_ids_and_accepts_valid_ones():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    path_ref = Draft7Validator(OP["parameters"][1]["schema"])
    cursor = Draft7Validator(QUERY["cursor"]["schema"])
    assert path_ref.is_valid(REF) and cursor.is_valid("c2Vh")
    for bad in ("", "12345", REF[:-1], REF + "0", REF.upper(), "experiment_" + "0f" * 16,
                "experiment_bad_" + "0f" * 16):
        assert not path_ref.is_valid(bad), bad
    for bad in ("", "a b", "a" * 513):
        assert not cursor.is_valid(bad), bad
    assert not list(v.iter_errors(_env({**d, "run_id": REF})))
    for bad in ("", "12345", REF[:-1], REF.upper()):
        assert list(v.iter_errors(_env({**d, "run_id": bad}))), bad
    f = _frontier(0, 1)
    bad_trials = ("", "trial_" + "a" * 15, "trial_" + "A" * 16, "configuration_run_" + "a" * 31, "configuration_run_" + "A" * 32,
                "trial_bad_" + "a" * 16, "configuration_bad_" + "a" * 32, "configuration_run_" + "a" * 33)
    for bad in bad_trials:
        assert list(v.iter_errors(_env({**d, "knee_ref": bad}))), bad
        assert list(v.iter_errors(_env({**d, "items": [{**f, "trial_ref": bad}]}))), bad
        assert list(v.iter_errors(_env({**d, "items": [{**_dominated(3, 1), "dominated_by": bad}]}))), bad
        assert list(v.iter_errors(_env({**d, "items": [{**_dominated(3, 1), "trial_ref": bad}]}))), bad
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "", "has_more": True}})))
    assert list(v.iter_errors(_env({**d, "warnings": ["measure_unavailable:a\nb"]})))
    assert not list(v.iter_errors(_env({**d, "warnings": ["measure_unavailable:cost"]})))


def test_both_issued_reference_formats_are_accepted_on_every_ref_field():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    for ref in ("trial_" + "0f" * 8, "configuration_run_" + "0f" * 16):
        items = [{**_frontier(0, 1), "trial_ref": ref}, {**_dominated(3, 1), "trial_ref": ref, "dominated_by": ref}]
        assert not list(v.iter_errors(_env({**d, "knee_ref": ref, "items": items}))), ref
    desc = _load("analytics/experiment_run_trial_ref_schema.json")["description"]
    assert not re.search(r"\.py\b|s[r]c/|\.p" + r"y:\d|:\d+-\d+", desc)
    assert "(issued by sessions)" in desc and "(minted by the backend)" in desc


def test_metric_keys_use_the_shared_name_class_and_a_stored_bad_name_is_the_503():
    v = _validator("experiment_run_pareto_response_schema")
    d = _page()
    f = _frontier(0, 1)
    pn = RESP["definitions"]["Metrics"]["propertyNames"]["pattern"]
    assert pn == QUERY["x_measure"]["schema"]["pattern"] == "^[^\\x00-\\x1f\\x7f]{1,100}$"
    for ok in ("review score", "cost", "1st", "a.b-c", "\u00e9t\u00e9", "x" * 100):
        item = {**f, "metrics": {ok: 1.0}}
        assert not list(v.iter_errors(_env({**d, "items": [item]}))), ok
    for bad in ("a\tb", "a\x00b", "a\x7fb", "", "x" * 101):
        item = {**f, "metrics": {bad: 1.0}}
        assert list(v.iter_errors(_env({**d, "items": [item]}))), repr(bad)
    needle = "A stored metric name outside the shared name class"
    for text in (RESP["description"], OP["responses"]["503"]["description"], OP["description"]):
        assert needle in text
        assert "never truncated or sanitized" in text
    assert needle in RESP["definitions"]["Metrics"]["description"]
    assert "stored metric name" in _load(PROBLEM_FILE)["description"]


def test_pareto_cursor_wording_drift_guard():
    """Drift guard: passes on the previous wording by design; the Pareto text was already correct. It fails if a future edit lists a cursor case under BadRequestProblem or drops "any invalid or stale cursor" from InvalidCursorProblem."""
    desc = _load(PROBLEM_FILE)["description"]
    bad_sentence = desc.partition("BadRequestProblem is")[2].split("ServiceUnavailableProblem is", 1)[0]
    assert "cursor" not in bad_sentence
    assert "any invalid or stale cursor" in desc.split("InvalidCursorProblem", 1)[1]
