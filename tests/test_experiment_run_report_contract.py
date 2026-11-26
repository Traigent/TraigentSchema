# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""experiment_run.get_run_report on the experiment-run reference URL."""

from __future__ import annotations

import hashlib
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/report"
OLD_PATH = "/api/v1/analytics/runs/{run_id}/report"
OP_ID = "experiment_run.get_run_report"
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
MAX_BYTES = 8388608


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")
OP = CATALOG["paths"][PATH]["get"]
PROBLEM_FILE = "analytics/report_problem_schema.json"


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


def test_parameters_and_ref_pattern():
    assert [(p["name"], p["in"], p["required"]) for p in OP["parameters"]] == [
        ("project_id", "path", True),
        ("experiment_run_ref", "path", True),
    ]
    ref = Draft7Validator(OP["parameters"][1]["schema"])
    assert ref.is_valid("experiment_run_" + "a1b2c3d4" * 4)
    assert not ref.is_valid("12345")  # raw integer id
    assert not ref.is_valid("experiment_run_" + "A" * 32)  # uppercase hex
    assert not ref.is_valid("experiment_run_abc")  # short
    assert not ref.is_valid("experiment_run_" + "a" * 33)  # long
    assert not ref.is_valid("experiment_" + "a" * 32)  # wrong prefix


def test_declared_statuses_and_media_types():
    assert set(OP["responses"]) == {"200", *PROBLEMS}
    for status, resp in OP["responses"].items():
        media = "application/json" if status == "200" else "application/problem+json"
        assert set(resp["content"]) == {media}, status
    for status in ("429", "503"):
        assert "Retry-After" in OP["responses"][status]["headers"]
    assert "never a partial success" in OP["responses"]["503"]["description"]


@pytest.mark.parametrize("status", sorted(PROBLEMS))
def test_each_problem_is_closed_and_matches_its_status(status):
    ref = OP["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"]
    assert ref.startswith("./report_problem_schema.json#/definitions/")
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    assert one.is_valid(_problem(status))
    assert not one.is_valid({**_problem(status), "extra": 1})
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))
    assert not list(_validator("report_problem_schema").iter_errors(_problem(status)))


REF = "experiment_run_" + "0f" * 16
OMITTED = {
    "experiment_context": {"experiment_id", "run_id"},
    "provenance": {"source_endpoints"},
    "data": {"report_id"},
}


def test_response_envelope_and_field_set_against_the_dto_and_the_builder():
    old = _load("analytics/run_report_response_schema.json")
    new = _load("analytics/experiment_run_report_response_schema.json")
    assert set(new["properties"]) == set(old["properties"])
    # the canonical envelope also requires meta (the two untruncated totals)
    assert new["required"] == [*old["required"], "meta"]
    assert new["properties"]["data"] == {"$ref": "#/definitions/BoundedReport"}
    dto = _load("results/report_payload_response_schema.json")
    bounded = new["definitions"]["BoundedReport"]
    # DTO fields are kept, minus the internal-id carrier report_id, plus the builder-always fields
    assert set(bounded["properties"]) == (set(dto["properties"]) - OMITTED["data"]) | {
        "generated_at",
        "experiment_context",
        "methodology",
        "example_index_map",
    }
    assert set(dto["required"]) <= set(bounded["required"])
    assert {"generated_at", "experiment_context", "methodology", "example_index_map"} <= set(
        bounded["required"]
    )
    defs = dto["definitions"]
    for name, key in (
        ("AggregatedResultRow", "aggregated_result_row"),
        ("RawExampleResultRow", "raw_example_result_row"),
        ("ReportInsight", "report_insight"),
    ):
        # the field set is the DTO's, with the internal trial_id replaced by the opaque trial_ref
        swap = {"trial_ref" if k == "trial_id" else k for k in defs[key]["properties"]}
        assert set(new["definitions"][name]["properties"]) == swap, name
        assert {"trial_ref" if k == "trial_id" else k for k in defs[key]["required"]} == set(
            new["definitions"][name]["required"]
        ), name
    prov = new["definitions"]["Provenance"]
    assert set(prov["properties"]) >= set(dto["properties"]["provenance"]["properties"])
    assert "run_id" in prov["required"]  # the experiment_run_ref is required
    assert "source_endpoints" not in prov["properties"]
    ctx = new["definitions"]["ExperimentContext"]
    assert not OMITTED["experiment_context"] & set(ctx["properties"])
    desc = new["description"]
    for omitted in (
        "experiment_context.experiment_id",
        "experiment_context.run_id",
        "provenance.source_endpoints",
        "report_id",
    ):
        assert f"omits {omitted}" in desc, omitted
    assert "populates it from the resolved reference" in desc


def _report() -> dict:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-11-26T10:00:00+00:00",
        "experiment_context": {
            "status": "completed",
            "created_at": "2026-11-26T09:00:00+00:00",
            "updated_at": "2026-11-26T09:30:00+00:00",
            "completed_at": None,
        },
        "methodology": {
            "accuracy_formula": "accuracy = accuracy | overall_accuracy",
            "score_formula": "score = score | accuracy",
            "fe_cost_formula": "fe_cost_usd = sdk_total_cost_usd / total_examples",
        },
        "provenance": {
            "data_hash": "ab" * 32,
            "run_id": REF,
            "source_counts": {
                "configuration_runs": 1,
                "raw_example_rows": 1,
                "example_scores": 0,
                "dataset_quality_records": 0,
            },
            "max_source_timestamp": None,
            "generator_versions": {"backend": "unknown", "report_service": "1.0.0", "schema_version": "1.0"},
        },
        "aggregated_results": [
            {
                "trial_ref": "trial_00000000000000a1",
                "config_label": "gpt",
                "config_hash": "deadbeef",
                "config_params": {
                    "temperature": 0.2,
                    "model": "m",
                    "flag": True,
                    "safe_nested": {"temperature": 0.2},
                    "stops": ["a", "b"],
                    "long": "x" * 128,
                },
                "accuracy": 0.9,
                "score": None,
            }
        ],
        "raw_example_results": [
            {"trial_ref": "trial_00000000000000a1", "example_id": "e1", "example_num": 0, "config_label": "gpt", "config_hash": "deadbeef", "cost_usd": 0.01}
        ],
        "example_index_map": [{"example_num": 0, "example_id": "e1"}],
        "insights": [{"rule_id": "x", "severity": "info", "statement": "s", "evidence": "e"}],
        "warnings": ["w"],
    }


def _meta(raw: int = 1, agg: int = 1) -> dict:
    return {"raw_example_results_total": raw, "aggregated_results_total": agg}


def _envelope(data: dict, total: int = 1, agg: int = 1) -> dict:
    return {"success": True, "message": "ok", "data": data, "meta": _meta(total, agg)}


def test_response_validates_and_is_closed_and_bounded():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    ok = _envelope(d)
    assert not list(v.iter_errors(ok))  # includes the backend case safe_nested {"temperature": 0.2}
    assert list(v.iter_errors(d))  # not enveloped
    assert list(v.iter_errors({**ok, "extra": 1}))
    assert list(v.iter_errors({**ok, "meta": {**_meta(), **{str(i): 1 for i in range(8)}}}))
    assert list(v.iter_errors({**ok, "meta": {**_meta(), "a": 1.5}}))
    agg = d["aggregated_results"][0]
    prov = d["provenance"]
    for bad in (
        {**d, "extra": 1},
        {**d, "provenance": {**prov, "extra": 1}},
        {**d, "provenance": {**prov, "run_id": "12345"}},
        {**d, "provenance": {**prov, "run_id": "experiment_run_" + "A" * 32}},
        {**d, "warnings": ["w"] * 1001},
        {**d, "warnings": ["x" * 513]},
        {**d, "insights": d["insights"] * 51},
        {**d, "aggregated_results": d["aggregated_results"] * 1001},
        {**d, "raw_example_results": d["raw_example_results"] * 5001},
        {**d, "example_index_map": d["example_index_map"] * 5001},
        {**d, "aggregated_results": [{**agg, "trial_id": "12345"}]},  # internal id, rejected
        {**d, "aggregated_results": [{**agg, "trial_ref": "12345"}]},
        {**d, "aggregated_results": [{**agg, "trial_ref": "trial_" + "a" * 17}]},
        {**d, "raw_example_results": [{**d["raw_example_results"][0], "trial_id": "12345"}]},
        {**d, "aggregated_results": [{**agg, "extra": 1}]},
        {**d, "aggregated_results": [{**agg, "config_params": {"a": {"b": {"c": {"d": {"e": 1}}}}}}]},  # depth 4
        {**d, "aggregated_results": [{**agg, "config_params": {"a": "x" * 129}}]},
        {**d, "aggregated_results": [{**agg, "config_params": {"a": [1] * 13}}]},
        {**d, "aggregated_results": [{**agg, "config_params": {str(i): 1 for i in range(65)}}]},
        {**d, "aggregated_results": [{**agg, "accuracy": 1e16}]},
        {**d, "aggregated_results": [{**agg, "config_label": "x" * 513}]},
        {**d, "insights": [{**d["insights"][0], "severity": "fatal"}]},
    ):
        assert list(v.iter_errors(_envelope(bad))), bad
    # boundary values are accepted
    edge = {
        **d,
        "warnings": ["x" * 512] * 1000,
        "aggregated_results": [{**agg, "config_label": "x" * 512}] * 1000,
        "raw_example_results": d["raw_example_results"] * 5000,
        "example_index_map": d["example_index_map"] * 5000,
    }
    assert not list(v.iter_errors(_envelope(edge, total=100000, agg=3000)))
    # legacy envelope still serves the deprecated path with historical ids
    legacy = _validator("run_report_response_schema")
    historical = {
        **d,
        "provenance": {**prov, "run_id": "12345"},
        "aggregated_results": [{**agg, "trial_ref": None, "trial_id": "12345"}],
        "raw_example_results": [{**d["raw_example_results"][0], "trial_id": "12345"}],
    }
    for row in historical["aggregated_results"]:
        row.pop("trial_ref")
    assert not list(legacy.iter_errors({"success": True, "message": "ok", "data": historical}))


def test_provenance_run_id_is_required():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    no_ref = {**d, "provenance": {k: x for k, x in d["provenance"].items() if k != "run_id"}}
    assert list(v.iter_errors(_envelope(no_ref)))


def test_canonical_projection_rejects_internal_id_fields():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    internal = {"experiment_id": "exp_1", "run_id": "12345"}
    for k, val in internal.items():
        bad = {**d, "experiment_context": {**d["experiment_context"], k: val}}
        assert list(v.iter_errors(_envelope(bad))), k
    bad = {**d, "provenance": {**d["provenance"], "source_endpoints": ["/api/v1/experiment-runs/runs/12345/configurations"]}}
    assert list(v.iter_errors(_envelope(bad)))
    assert list(v.iter_errors(_envelope({**d, "report_id": "report_12345_abc"})))


def test_truncation_is_declared_through_the_required_meta_totals():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    assert list(v.iter_errors({"success": True, "message": "ok", "data": d}))  # meta missing
    assert list(v.iter_errors({"success": True, "message": "ok", "data": d, "meta": {}}))
    for missing in ("raw_example_results_total", "aggregated_results_total"):
        assert list(v.iter_errors({**_envelope(d), "meta": {k: 1 for k in _meta() if k != missing}}))
    assert list(v.iter_errors(_envelope(d, total=-1)))
    assert list(v.iter_errors(_envelope(d, agg=-1)))
    assert list(v.iter_errors({**_envelope(d), "meta": {**_meta(), "raw_example_results_total": 1.5}}))
    assert not list(v.iter_errors(_envelope(d, total=50000, agg=2000)))
    text = _load("analytics/experiment_run_report_response_schema.json")["description"]
    assert "truncated server-side" in text
    assert "aggregated_results_total" in text


def test_config_params_follow_the_sanitizer_shapes():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    agg = d["aggregated_results"][0]

    def with_params(params: dict) -> dict:
        return _envelope({**d, "aggregated_results": [{**agg, "config_params": params}]})

    # depth 3: top key -> object -> object -> object -> scalar leaf
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": {"d": 1}}}})))
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": ["x", 2, None, True]}}})))
    assert not list(v.iter_errors(with_params({"safe_nested": {"temperature": 0.2}})))
    # the sanitizer emits {} and [] at its depth limit (config_redaction.py:157,172)
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": []}}})))
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": {}}}})))
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": {"d": []}}}})))
    assert not list(v.iter_errors(with_params({"a": {"b": {"c": {"d": {}}}}})))
    assert not list(v.iter_errors(with_params({"a": [[[[]]]]})))
    # a non-empty container one level deeper than the limit is dropped by the sanitizer
    assert list(v.iter_errors(with_params({"a": {"b": {"c": {"d": [1]}}}})))
    assert list(v.iter_errors(with_params({"a": {"b": {"c": {"d": {"e": 1}}}}})))
    assert list(v.iter_errors(with_params({"a": [[[[1]]]]})))
    assert not list(v.iter_errors(with_params({"a": list(range(12))})))  # 12 list items
    assert not list(v.iter_errors(with_params({"a": ["x" * 128] * 12})))
    assert not list(v.iter_errors(with_params({str(i): i for i in range(64)})))  # 64 keys
    assert not list(v.iter_errors(with_params({"a": {str(i): i for i in range(64)}})))


def test_trial_ref_replaces_the_internal_trial_id():
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    for ok in ("trial_0123456789abcdef", "trial_ffffffffffffffff", "trial_0000000000000000"):
        row = {**d["aggregated_results"][0], "trial_ref": ok}
        assert not list(v.iter_errors(_envelope({**d, "aggregated_results": [row]}))), ok
    for bad in ("0", "trial_", "trial_1", "trial_0", "trial_" + "a" * 15, "trial_" + "a" * 17, "trial_" + "A" * 16, "Trial_" + "a" * 16, "trial_" + "g" * 16):
        row = {**d["aggregated_results"][0], "trial_ref": bad}
        assert list(v.iter_errors(_envelope({**d, "aggregated_results": [row]}))), bad
    desc = _load("analytics/experiment_run_report_response_schema.json")["description"]
    assert "scrub internal ids embedded in warnings, insight evidence and fallback config labels" in desc


def test_size_limit_is_enforced_on_the_serialized_envelope_not_statically():
    resp = _load("analytics/experiment_run_report_response_schema.json")
    assert resp["x-max-response-bytes"] == MAX_BYTES == OP["x-max-response-bytes"]
    assert (
        OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "./experiment_run_report_response_schema.json"
    )
    for text in (resp["description"], OP["description"]):
        low = text.lower()
        assert "enforced on the serialized envelope" in low
        assert "the closed 503" in low
        assert "no static byte bound" in low
    assert "allOf" not in resp["properties"]["data"]
    assert "trial_id and example_id remain" not in resp["description"]
    assert "trial_id is omitted (internal configuration-run id)" in resp["description"]


def test_deprecated_path_points_at_the_successor():
    old = CATALOG["paths"][OLD_PATH]["get"]
    assert old["deprecated"] is True
    assert old["operationId"] == "analytics.get_run_report"
    assert OP_ID in old["description"]
    assert "{experiment_run_ref}/report" in old["description"]
    assert "beta" in old["description"]  # the two beta mounts of the same handler retire with it
    assert not OP.get("deprecated")


def test_problem_schema_root_oneof_enforces_the_vocabulary():
    v = _validator("report_problem_schema")
    assert not list(v.iter_errors(_problem("404")))
    assert list(v.iter_errors({**_problem("404"), "status": 418}))
    assert list(v.iter_errors({**_problem("404"), "extra": 1}))
    assert list(v.iter_errors({"type": "urn:traigent:problem:not_found"}))


def test_trial_ref_is_the_shared_run_scoped_definition():
    new = _load("analytics/experiment_run_report_response_schema.json")
    shared = _load("analytics/experiment_run_trial_ref_schema.json")
    ref = "https://schemas.traigent.ai/analytics/experiment_run_trial_ref_schema.json"
    for name in ("AggregatedResultRow", "RawExampleResultRow"):
        assert new["definitions"][name]["properties"]["trial_ref"] == {"$ref": ref}, name
    assert shared["$id"] == ref
    assert shared["pattern"] == "^(trial_[0-9a-f]{16}|configuration_run_[0-9a-f]{32})$"
    assert "(?!" not in shared["pattern"]
    assert (shared["minLength"], shared["maxLength"]) == (22, 50)
    one = Draft7Validator(shared)
    assert one.is_valid("trial_0123456789abcdef")
    assert one.is_valid("configuration_run_" + "0f" * 16)
    for bad in ("trial_1", "trial_" + "a" * 15, "trial_" + "a" * 17, "trial_10000", "configuration_run_" + "a" * 31, "configuration_run_" + "a" * 33, "configuration_run_" + "A" * 32, "configuration_run_1", "Configuration_run_" + "a" * 32, "", "trial_" + "A" * 16):
        assert not one.is_valid(bad), bad
    assert "report-scoped" not in new["description"]
    assert "1-based" not in new["description"] and "1-based" not in shared["description"]
    desc = shared["description"]
    assert "configuration_runs.configuration_run_ref" in desc
    assert "20261122_0001_configuration_run_ref_role_v1.py:1-24" in desc
    assert "Issued once, never re-minted" in desc
    assert "never a positional or synthetic stand-in" in desc
    assert "the closed 503" in desc


def test_report_refs_reject_malformed_ids_and_both_trial_formats_are_accepted():
    # Patterns end in "$" with no lookahead; trailing-newline hardening is Python-side.
    v = _validator("experiment_run_report_response_schema")
    d = _report()
    agg = d["aggregated_results"][0]
    for ref in ("trial_" + "0f" * 8, "configuration_run_" + "0f" * 16):
        row = {**agg, "trial_ref": ref}
        assert not list(v.iter_errors(_envelope({**d, "aggregated_results": [row]}))), ref
    for bad in ("", "trial_" + "0f" * 7, "configuration_run_" + "0F" * 16, "run_" + "0f" * 16):
        assert list(v.iter_errors(_envelope({**d, "aggregated_results": [{**agg, "trial_ref": bad}]}))), bad
    path_ref = Draft7Validator(OP["parameters"][1]["schema"])
    assert path_ref.is_valid(REF)
    for bad in ("", "12345", REF[:-1], REF + "0", REF.upper(), "experiment_" + REF[len("experiment_run_"):], "experiment_bad_" + "0f" * 16):
        assert not path_ref.is_valid(bad), bad
    raw = d["raw_example_results"][0]
    for ref in ("trial_" + "0f" * 8, "configuration_run_" + "0f" * 16):
        assert not list(v.iter_errors(_envelope({**d, "raw_example_results": [{**raw, "trial_ref": ref}]}))), ref
    for bad in ("", "trial_" + "0f" * 7, "trial_" + "0F" * 8, "configuration_run_" + "0f" * 15,
                "configuration_run_" + "0F" * 16, "run_" + "0f" * 16):
        assert list(v.iter_errors(_envelope({**d, "raw_example_results": [{**raw, "trial_ref": bad}]}))), bad
    assert not list(v.iter_errors(_envelope({**d, "provenance": {**d["provenance"], "run_id": REF}})))
    for bad in ("", "experiment_bad_" + "0f" * 16, REF[:-1], REF + "0"):  # correct prefix, wrong length too
        assert list(v.iter_errors(_envelope({**d, "provenance": {**d["provenance"], "run_id": bad}}))), bad
    assert list(v.iter_errors(_envelope({**d, "provenance": {**d["provenance"], "run_id": "12345"}})))


def test_no_report_pattern_uses_a_lookahead():
    def walk(n):
        if isinstance(n, dict):
            for k, val in n.items():
                if k == "pattern" and isinstance(val, str):
                    yield val
                else:
                    yield from walk(val)
        elif isinstance(n, list):
            for it in n:
                yield from walk(it)

    pats = [*walk(OP), *walk(_load("analytics/experiment_run_report_response_schema.json")),
            *walk(_load("analytics/report_problem_schema.json")),
            *walk(_load("analytics/experiment_run_trial_ref_schema.json"))]
    assert pats
    assert not [p for p in pats if "(?!" in p]
