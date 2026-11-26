# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""experiment_run.get_run_leaderboard on the experiment-run reference URL."""

from __future__ import annotations

import hashlib
import json
import re

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

_PRIVATE = re.compile(r"\.py\b|src/|_dal\b|_service\b|_bp\b|mint_|migrations?/|\d{8}_\d{4}_|[a-z_]+s\.[a-z_]+_id")

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/leaderboard"
OLD_PATH = "/api/v1/analytics/runs/{run_id}/leaderboard"
OP_ID = "experiment_run.get_run_leaderboard"
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
PROBLEM_FILE = "analytics/leaderboard_problem_schema.json"
REF = "experiment_run_" + "0f" * 16
TRIAL_REF_REF = "https://schemas.traigent.ai/analytics/experiment_run_trial_ref_schema.json"
NAME_POLICY = "^[^\\x00-\\x1f\\x7f]{1,128}$"


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")
OP = CATALOG["paths"][PATH]["get"]
RESP = _load("analytics/experiment_run_leaderboard_response_schema.json")
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


def _item(rank: int, rec: str = "candidate", flags: list | None = None) -> dict:
    return {
        "rank": rank,
        "trial_ref": f"trial_{rank:016x}",
        "composite_score": 0.9 - rank / 100,
        "measures": {"accuracy": 0.9, "total_cost": 0.01},
        "confidence": "high",
        "risk_flags": flags or [],
        "recommendation": rec,
    }


def _page() -> dict:
    return {
        "run_id": REF,
        "ranking_basis": {
            "objective": "weighted",
            "weights": {"accuracy": 0.7, "total_cost": 0.3},
            "constraints": {"total_cost": 1.0},
        },
        "items": [_item(1, "winner"), _item(2), _item(3, "reject", ["disqualified_by_constraint:total_cost"])],
        "warnings": [],
        "pagination": {"limit": 20, "next_cursor": None, "has_more": False, "total": 3},
    }


def _env(data: dict) -> dict:
    return {"success": True, "message": "ok", "data": data}


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
    assert not ref.is_valid("12345")
    assert not ref.is_valid("experiment_run_" + "A" * 32)
    assert not ref.is_valid("experiment_run_abc")
    assert not ref.is_valid("experiment_run_" + "a" * 33)
    assert not ref.is_valid("experiment_" + "a" * 32)


def test_query_vocabulary_matches_the_backend_query_model():
    # the backend leaderboard query model: objective,
    # weights, constraints, request_count, limit; page/offset are replaced by the cursor
    assert set(QUERY) == {"limit", "cursor", "objective", "weights", "constraints", "request_count"}
    assert all(not p["required"] for p in QUERY.values())
    obj = Draft7Validator(QUERY["objective"]["schema"])
    assert QUERY["objective"]["schema"]["default"] == "weighted"
    for ok in ("weighted", "quality", "cost", "latency"):
        assert obj.is_valid(ok)
    assert not obj.is_valid("accuracy")
    rc = QUERY["request_count"]["schema"]
    assert (rc["minimum"], rc["maximum"], rc["default"]) == (1, 1_000_000, 1)
    for name in ("weights", "constraints"):
        assert QUERY[name]["schema"]["maxLength"] == 8192  # bounded, backend caps 50 keys
        assert "50 keys" in QUERY["weights"]["description"]
    for text in (OP["description"], OP["responses"]["400"]["description"]):
        assert "page" in text and "offset" in text
    assert "any other query parameter" in OP["description"]
    assert "of the legacy leaderboard query" in OP["description"] and ".py" not in OP["description"]


def test_limit_bounds_and_default_replace_the_backend_50_200():
    schema = QUERY["limit"]["schema"]
    assert schema["default"] == 20
    v = Draft7Validator(schema)
    for ok in (1, 20, 100):
        assert v.is_valid(ok), ok
    for bad in (0, -1, 101, 200, 1.5, "20", None):
        assert not v.is_valid(bad), bad
    assert RESP["definitions"]["Pagination"]["properties"]["limit"]["maximum"] == 100
    assert RESP["definitions"]["LeaderboardPage"]["properties"]["items"]["maxItems"] == 100
    assert "historical default 50 and maximum 200" in OP["description"]
    assert "replaced by cursor pagination with limit default 20, maximum 100" in RESP["description"]


def test_cursor_is_bounded_and_opaque():
    schema = QUERY["cursor"]["schema"]
    v = Draft7Validator(schema)
    assert schema["maxLength"] == 512
    assert v.is_valid("eyJhIjoxfQ")
    assert v.is_valid("A" * 512)
    assert not v.is_valid("A" * 513)
    assert not v.is_valid("")
    assert not v.is_valid("a/b+c=")
    assert RESP["definitions"]["Cursor"]["pattern"] == schema["pattern"]
    text = QUERY["cursor"]["description"]
    assert "Opaque" in text and "sealed" in text and "Never a raw primary key" in text
    assert "analysis_revision" in text
    assert "never a raw historical primary key" in RESP["description"]


def test_declared_statuses_and_media_types():
    assert set(OP["responses"]) == {"200", *PROBLEMS}
    for status, resp in OP["responses"].items():
        media = "application/json" if status == "200" else "application/problem+json"
        assert set(resp["content"]) == {media}, status
    for status in ("429", "503"):
        assert "Retry-After" in OP["responses"][status]["headers"]
    assert "never a partial success" in OP["responses"]["503"]["description"]
    assert "no value is echoed" in OP["responses"]["400"]["description"]
    assert "never echoes the offending value" in _load(PROBLEM_FILE)["description"]


@pytest.mark.parametrize("status", sorted(PROBLEMS))
def test_each_problem_is_closed_and_matches_its_status(status):
    schema = OP["responses"][status]["content"]["application/problem+json"]["schema"]
    ref = schema["oneOf"][0]["$ref"] if status == "400" else schema["$ref"]
    assert ref.startswith("./leaderboard_problem_schema.json#/definitions/")
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    assert one.is_valid(_problem(status))
    assert not one.is_valid({**_problem(status), "extra": 1})
    assert not one.is_valid({**_problem(status), "detail": "limit=101 is invalid"})
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))
    assert not list(_validator("leaderboard_problem_schema").iter_errors(_problem(status)))


def test_problem_schema_root_oneof_enforces_the_vocabulary():
    v = _validator("leaderboard_problem_schema")
    assert not list(v.iter_errors(_problem("404")))
    assert list(v.iter_errors({**_problem("404"), "status": 418}))
    assert list(v.iter_errors({**_problem("404"), "extra": 1}))


def test_response_validates_and_pagination_is_required():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    assert not list(v.iter_errors(_env(d)))
    more = {**d["pagination"], "next_cursor": "c2Vh", "has_more": True}
    assert not list(v.iter_errors(_env({**d, "pagination": more})))
    assert set(RESP["definitions"]["Pagination"]["required"]) == {"limit", "next_cursor", "has_more", "total"}
    for missing in ("items", "pagination", "ranking_basis", "warnings", "run_id"):
        assert list(v.iter_errors(_env({k: x for k, x in d.items() if k != missing}))), missing
    for missing in ("limit", "next_cursor", "has_more", "total"):
        bad = {k: x for k, x in d["pagination"].items() if k != missing}
        assert list(v.iter_errors(_env({**d, "pagination": bad}))), missing
    for bad_total in (-1, 10001, 1.5, "3", None):
        assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "total": bad_total}}))), bad_total
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "a/b"}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "A" * 513}})))
    assert list(v.iter_errors(d))  # not enveloped


def test_has_more_is_true_if_and_only_if_next_cursor_is_non_null():
    v = _validator("experiment_run_leaderboard_response_schema")
    pg = _page()["pagination"]
    d = _page()
    assert not list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": True, "next_cursor": "c2Vh"}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": True, "next_cursor": None}})))
    assert list(v.iter_errors(_env({**d, "pagination": {**pg, "has_more": False, "next_cursor": "c2Vh"}})))


def test_field_set_matches_the_backend_builder():
    # backend payload keys: run_id, ranking_basis, configs, warnings; config entry keys: rank,
    # config_id, label, composite_score, measures, confidence, risk_flags, recommendation
    page = RESP["definitions"]["LeaderboardPage"]
    assert set(page["properties"]) == {"run_id", "ranking_basis", "items", "warnings", "pagination"}
    basis = page["properties"]["ranking_basis"]
    assert basis["required"] == ["objective", "weights", "constraints"]
    assert set(basis["properties"]) == {"objective", "weights", "constraints"}
    assert set(RESP["definitions"]["LeaderboardItem"]["properties"]) == {
        "rank", "trial_ref", "composite_score", "measures", "confidence", "risk_flags", "recommendation",
    }  # config_id -> trial_ref; label omitted
    assert set(RESP["definitions"]["LeaderboardItem"]["required"]) == set(
        RESP["definitions"]["LeaderboardItem"]["properties"]
    )
    assert "The fields mirror the backend's leaderboard analysis" in RESP["description"]
    assert not re.search(r"\.py\b|\.py:\d|src/|:\d{3,}-\d{3,}", json.dumps(RESP))
    old = _load("analytics/run_leaderboard_schema.json")
    assert set(old["required"]) == {"run_id", "ranking_basis", "configs", "warnings"}  # untouched


def test_enums_and_flags_follow_the_builder():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    for rec in ("winner", "candidate", "reject"):
        assert not list(v.iter_errors(_env({**d, "items": [_item(1, rec)]}))), rec
    assert list(v.iter_errors(_env({**d, "items": [_item(1, "maybe")]})))
    assert list(v.iter_errors(_env({**d, "items": [{**_item(1), "confidence": "certain"}]})))
    for ok in ("low_sample", "disqualified_by_constraint:cost", "missing_constrained_measure:x", "missing_weighted_measure:y"):
        assert not list(v.iter_errors(_env({**d, "items": [_item(1, flags=[ok])]}))), ok
    for bad in ("few_samples", "low_sample:1", "disqualified_by_constraint:"):
        assert list(v.iter_errors(_env({**d, "items": [_item(1, flags=[bad])]}))), bad
    bad_obj = {**d["ranking_basis"], "objective": "accuracy"}
    assert list(v.iter_errors(_env({**d, "ranking_basis": bad_obj})))


def test_warnings_are_the_builder_forms():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    for ok in (
        "No successful configuration is available to rank.",
        "objective='weighted' requested with no weights; ranked by quality only",
        "objective_unavailable:cost; no numeric measure to rank by",
        "objective_unavailable:latency; ranked by fallback measure accuracy",
    ):
        assert not list(v.iter_errors(_env({**d, "warnings": [ok]}))), ok
    for bad in ("anything", "objective_unavailable:weighted; no numeric measure to rank by", "objective_unavailable:cost"):
        assert list(v.iter_errors(_env({**d, "warnings": [bad]}))), bad
    assert list(v.iter_errors(_env({**d, "warnings": ["No successful configuration is available to rank."] * 9})))


def test_internal_ids_are_rejected():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    it = _item(1)
    assert list(v.iter_errors(_env({**d, "run_id": "12345"})))
    assert list(v.iter_errors(_env({**d, "run_id": "experiment_run_" + "A" * 32})))
    assert list(v.iter_errors(_env({**d, "project_id": "12345"})))
    assert list(v.iter_errors(_env({**d, "items": [{**it, "config_id": "12345"}]})))
    assert list(v.iter_errors(_env({**d, "items": [{**it, "label": "Trial 12345"}]})))
    assert list(v.iter_errors(_env({**d, "items": [{**it, "trial_ref": "12345"}]})))
    for bad in ("0", "trial_", "trial_1", "trial_" + "A" * 16, "trial_" + "a" * 15, "trial_" + "a" * 17, "Trial_" + "a" * 16):
        assert list(v.iter_errors(_env({**d, "items": [{**it, "trial_ref": bad}]}))), bad
    for ok in ("trial_" + "0" * 16, "trial_0123456789abcdef", "configuration_run_" + "ab" * 16):
        assert not list(v.iter_errors(_env({**d, "items": [{**it, "trial_ref": ok}]}))), ok
    desc = RESP["description"]
    assert "omits config_id" in desc and "omits label" in desc
    assert "populated from the resolved reference, never the historical run id" in desc
    assert "omits config_id and label" in OP["description"]


def test_trial_ref_is_the_shared_persisted_reference():
    assert RESP["definitions"]["TrialRef"] == {"$ref": TRIAL_REF_REF}
    shared = _load("analytics/experiment_run_trial_ref_schema.json")
    assert shared["$id"] == TRIAL_REF_REF
    assert shared["pattern"] == "^(trial_[0-9a-f]{16}|configuration_run_[0-9a-f]{32})$"
    assert RESP["definitions"]["LeaderboardItem"]["properties"]["trial_ref"] == {"$ref": "#/definitions/TrialRef"}
    assert "configuration_run_ref" in RESP["description"]
    assert "not yet issued is the closed 503" in RESP["description"]
    assert "not yet issued is the closed 503" in OP["description"]


def test_response_is_closed_and_bounded():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    it = _item(1)
    assert list(v.iter_errors({**_env(d), "extra": 1}))
    for bad in (
        {**d, "extra": 1},
        {**d, "items": [{**it, "extra": 1}]},
        {**d, "items": [it] * 101},
        {**d, "items": [{**it, "rank": 0}]},
        {**d, "items": [{**it, "measures": {}}]},
        {**d, "items": [{**it, "measures": {"bad\x01": 1.0}}]},
        {**d, "items": [{**it, "measures": {"a": "high"}}]},
        {**d, "items": [{**it, "measures": {f"m{i}": 1.0 for i in range(65)}}]},
        {**d, "items": [{**it, "risk_flags": ["low_sample"] * 129}]},
        {**d, "ranking_basis": {**d["ranking_basis"], "extra": 1}},
        {**d, "ranking_basis": {**d["ranking_basis"], "constraints": {f"m{i}": 1.0 for i in range(51)}}},
    ):
        assert list(v.iter_errors(_env(bad))), bad
    edge = {**d, "items": [{**_item(i + 1), "risk_flags": ["low_sample"] * 128} for i in range(100)],
            "pagination": {"limit": 100, "next_cursor": "A" * 512, "has_more": True, "total": 10000}}
    assert not list(v.iter_errors(_env(edge)))


def test_metrics_accept_any_finite_number():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    for value in (1e16, -1e300, 0, 3.5):
        item = {**_item(1), "measures": {"cost": value}, "composite_score": value}
        assert not list(v.iter_errors(_env({**d, "items": [item]}))), value
    assert "maximum" not in RESP["definitions"]["MeasureMap"]["additionalProperties"]
    assert "any finite JSON number" in RESP["definitions"]["LeaderboardItem"]["properties"]["composite_score"]["description"]


def test_ordering_and_full_population_ranking_are_stated():
    for text in (RESP["description"], OP["description"]):
        assert "ascending trial_ref" in text
        assert "ranks are assigned after" in text or "ranks assigned after" in text
    assert "computed over the FULL eligible population and only then paginated" in RESP["description"]
    assert "computed over the full eligible population and then paginated" in OP["description"]


def test_cap_counts_all_scoped_configuration_rows_before_metric_processing():
    for text in (RESP["description"], OP["description"]):
        assert "counts ALL the run's scoped configuration rows before any metric processing" in text
    assert "10000 scoped configuration rows" in OP["responses"]["503"]["description"]
    assert "10000 scoped configuration rows" in _load(PROBLEM_FILE)["description"] or "10000 scoped configuration rows" in json.dumps(_load(PROBLEM_FILE))


def test_cursor_seals_the_analysis_revision_and_a_stale_cursor_is_invalid_cursor():
    for text in (RESP["description"], OP["description"]):
        assert "analysis_revision" in text
        assert "invalid_cursor" in text
    refs = [x["$ref"] for x in OP["responses"]["400"]["content"]["application/problem+json"]["schema"]["oneOf"]]
    assert refs == [
        "./leaderboard_problem_schema.json#/definitions/BadRequestProblem",
        "./leaderboard_problem_schema.json#/definitions/InvalidCursorProblem",
    ]
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"]["InvalidCursorProblem"])
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
    assert not one.is_valid({**doc, "detail": "cursor abc is stale"})
    assert not list(_validator("leaderboard_problem_schema").iter_errors(doc))


def test_size_limit_is_enforced_on_the_serialized_envelope_not_statically():
    assert RESP["x-max-response-bytes"] == MAX_BYTES == OP["x-max-response-bytes"]
    assert (
        OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "./experiment_run_leaderboard_response_schema.json"
    )
    for text in (RESP["description"], OP["description"]):
        low = text.lower()
        assert "enforced on the serialized envelope" in low
        assert "the closed 503" in low
        assert "no static byte bound" in low
    assert "1 MiB" in OP["responses"]["503"]["description"]
    assert "never a partial" in _load(PROBLEM_FILE)["description"]


def test_deprecated_path_points_at_the_successor_and_the_full_beta_route():
    old = CATALOG["paths"][OLD_PATH]["get"]
    assert old["deprecated"] is True
    assert old["operationId"] == "analytics_runs.get_run_leaderboard"
    assert OP_ID in old["description"]
    assert "{experiment_run_ref}/leaderboard" in old["description"]
    assert "/api/v1beta/projects/{project_id}/analytics/runs/{run_id}/leaderboard" in old["description"]
    assert not _PRIVATE.search(old["description"])
    assert not OP.get("deprecated")
    assert old["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == "./run_leaderboard_response_schema.json"


def test_one_name_policy_everywhere_names_are_echoed():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    long_ok = "m" * 128
    spaced = "Total Cost (USD)"
    for name in (long_ok, spaced, "a.b-c"):
        page = {
            **d,
            "ranking_basis": {"objective": "weighted", "weights": {name: 1}, "constraints": {name: 2}},
            "items": [{**_item(1), "measures": {name: 1.0}, "risk_flags": [f"disqualified_by_constraint:{name}", f"missing_weighted_measure:{name}"]}],
            "warnings": [f"objective_unavailable:cost; ranked by fallback measure {name}"],
        }
        assert not list(v.iter_errors(_env(page))), name
    for bad in ("m" * 129, "tab\there", "nul\x00", "del\x7f", ""):
        page = {**d, "ranking_basis": {**d["ranking_basis"], "weights": {bad: 1}}}
        assert list(v.iter_errors(_env(page))), repr(bad)
        assert list(v.iter_errors(_env({**d, "items": [{**_item(1), "measures": {bad: 1.0}}]}))), repr(bad)
        assert list(v.iter_errors(_env({**d, "items": [_item(1, flags=[f"disqualified_by_constraint:{bad}"])]}))), repr(bad)
        assert list(v.iter_errors(_env({**d, "warnings": [f"objective_unavailable:cost; ranked by fallback measure {bad}"]}))), repr(bad)
    props = RESP["definitions"]["LeaderboardPage"]["properties"]
    assert RESP["definitions"]["MeasureMap"]["propertyNames"]["pattern"] == NAME_POLICY
    assert props["ranking_basis"]["properties"]["weights"]["propertyNames"]["pattern"] == NAME_POLICY
    assert props["ranking_basis"]["properties"]["constraints"]["propertyNames"]["pattern"] == NAME_POLICY
    flags = RESP["definitions"]["LeaderboardItem"]["properties"]["risk_flags"]["items"]
    assert flags["maxLength"] == len("missing_constrained_measure:") + 128
    assert props["warnings"]["items"]["maxLength"] == len("objective_unavailable:quality; ranked by fallback measure ") + 128
    for text in (RESP["description"], OP["description"]):
        assert NAME_POLICY in text
        assert "the closed 400" in text and "the closed 503" in text
    assert NAME_POLICY in QUERY["weights"]["description"] and NAME_POLICY in QUERY["constraints"]["description"]


def test_weights_are_bounded_normalized_and_the_score_sorts_unrounded():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    for ok in (0, 1, 1000, 0.5):
        basis = {**d["ranking_basis"], "weights": {"accuracy": ok}}
        assert not list(v.iter_errors(_env({**d, "ranking_basis": basis}))), ok
    for bad in (-0.1, 1000.1, 1e308, "1"):
        basis = {**d["ranking_basis"], "weights": {"accuracy": bad}}
        assert list(v.iter_errors(_env({**d, "ranking_basis": basis}))), bad
    for text in (RESP["description"], OP["description"], QUERY["weights"]["description"]):
        assert "[0, 1000]" in text
        assert "normalized to sum to 1" in text
        assert "silent exclusion of negative weights" in text
    for text in (RESP["description"], OP["description"]):
        assert "unrounded" in text.lower()
    assert "UNROUNDED" in RESP["definitions"]["LeaderboardItem"]["properties"]["composite_score"]["description"]


REVISION_RULE = (
    "a per-run monotonic counter the backend increments in the same transaction as any insert or delete "
    "of the run's configuration rows, and any update that changes a configuration row's analysis content "
    "(its status, measures, summary_stats, experiment_parameters or metadata); writes that change none of "
    "these (timestamps, workflow metadata, public-reference backfill, identical rewrites) do not change it"
)


def test_analysis_revision_is_a_monotonic_counter_from_the_same_snapshot():
    for text in (RESP["description"], OP["description"]):
        assert "per-run monotonic counter" in text
        assert "same transaction" in text
        assert "SAME snapshot as the ranked rows" in text
        assert "maximum configuration updated_at" not in text
        assert REVISION_RULE in text


def _patterns(node, out=None):
    out = [] if out is None else out
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                out.append(v)
            else:
                _patterns(v, out)
    elif isinstance(node, list):
        for x in node:
            _patterns(x, out)
    return out


ALL_PATTERNS = (
    _patterns(RESP) + _patterns(_load(PROBLEM_FILE)) + _patterns(OP)
)


def test_no_leaderboard_pattern_uses_a_lookahead():
    # Patterns end in "$" (Pydantic v2's rust-regex engine refuses lookahead).
    assert len(ALL_PATTERNS) >= 10
    for pat in ALL_PATTERNS:
        assert "(?!" not in pat, pat
        assert pat.endswith("$"), pat


def test_every_leaderboard_ref_rejects_empty_and_malformed_ids_and_accepts_valid_ones():
    path_ref = Draft7Validator(OP["parameters"][1]["schema"])
    cursor = Draft7Validator(QUERY["cursor"]["schema"])
    trial = Draft7Validator(_load("analytics/experiment_run_trial_ref_schema.json"))
    assert path_ref.is_valid(REF) and cursor.is_valid("abc") and trial.is_valid("trial_" + "a" * 16)
    assert trial.is_valid("configuration_run_" + "b" * 32)
    for bad in ("", "12345", REF[:-1], REF + "0", REF.upper(), "experiment_" + "0f" * 16,
                "experiment_bad_" + "0f" * 16):
        assert not path_ref.is_valid(bad), bad
    for bad in ("", "a b", "a" * 513):
        assert not cursor.is_valid(bad), bad
    for bad in ("", "trial_" + "a" * 15, "trial_" + "a" * 17, "trial_" + "A" * 16,
                "configuration_run_" + "b" * 31, "configuration_run_" + "B" * 32, "run_" + "a" * 16):
        assert not trial.is_valid(bad), bad
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    assert not list(v.iter_errors(_env({**d, "run_id": REF})))
    for bad in ("", "12345", REF[:-1], REF.upper()):
        assert list(v.iter_errors(_env({**d, "run_id": bad}))), bad
    assert list(v.iter_errors(_env({**d, "items": [{**_item(1), "trial_ref": ""}]})))
    assert list(v.iter_errors(_env({**d, "pagination": {**d["pagination"], "next_cursor": "", "has_more": True}})))
    assert list(v.iter_errors(_env({**d, "items": [{**_item(1), "measures": {"a\x00": 1.0}}]})))


def test_description_names_both_issued_trial_ref_formats():
    for text in (RESP["description"],):
        assert "trial_ plus 16 lowercase hex or configuration_run_ plus 32 lowercase hex" in text
        assert "minted by the backend" in text and not _PRIVATE.search(text)
    shared = _load("analytics/experiment_run_trial_ref_schema.json")
    assert "Two issued formats exist" in shared["description"]


def test_all_zero_weights_are_the_closed_400_and_omitting_weights_keeps_the_default():
    for text in (OP["description"], QUERY["weights"]["description"], OP["responses"]["400"]["description"]):
        assert "all-zero" in text or "all weights zero" in text
    for text in (OP["description"], QUERY["weights"]["description"]):
        assert "greater than 0" in text
    # the rule is request-side only: the response description does not impose it
    assert "all-zero" not in RESP["description"]
    assert "applies only to a weights map supplied in the request" in RESP["description"]
    assert "omitting weights keeps the default objective path" in OP["description"]
    assert "no echo" in OP["description"]


def test_normalization_is_overflow_safe_and_a_convex_combination():
    for text in (RESP["description"], OP["description"]):
        assert "without overflow" in text
        assert "largest absolute finite value" in text
        assert "distinct finite values keep their order" not in text
        assert "equal values score equal" in text
        assert "convex combination" in text
    assert "replacing the builder's range arithmetic" in RESP["description"] and ".py" not in RESP["description"]
    cs = RESP["definitions"]["LeaderboardItem"]["properties"]["composite_score"]["description"]
    assert "overflow-safe" in cs and "unrounded binary64 composite" in cs
    assert "distinct finite" not in cs
    assert "distinct finite values keep their order" not in json.dumps(CATALOG["paths"][PATH])


def test_an_empty_effective_weights_map_validates_in_the_response():
    v = _validator("experiment_run_leaderboard_response_schema")
    d = _page()
    page = {**d, "ranking_basis": {"objective": "cost", "weights": {}, "constraints": {}}, "items": [],
            "warnings": ["No successful configuration is available to rank."],
            "pagination": {"limit": 20, "next_cursor": None, "has_more": False, "total": 0}}
    assert not list(v.iter_errors(_env(page)))


TIE_RULE = (
    "The ranking sorts by the unrounded binary64 composite; equal composites are ordered by the raw values "
    "of the weighted measures in descending weight order, ties between equal weights broken by measure name "
    "ascending (lexicographic), each compared in that measure's better direction, with a missing raw value ordered after any present value at that step; any remaining tie is broken "
    "by ascending trial_ref (lexicographic)."
)


def test_one_tie_rule_identical_in_all_four_places_and_no_other_tie_wording():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    # The entry is in CHANGELOG.md once released, or in a changelog.d/ fragment before that.
    sources = [root / "CHANGELOG.md", *sorted((root / "changelog.d").glob("*.md"))]
    entry = next(
        line
        for source in sources
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.startswith("- **`experiment_run.get_run_leaderboard`")
    )
    composite = RESP["definitions"]["LeaderboardItem"]["properties"]["composite_score"]["description"]
    for text in (OP["description"], RESP["description"], composite, entry):
        assert text.count(TIE_RULE) == 1
        assert "when two composites are equal" not in text
    # no other tie-break wording anywhere in the leaderboard descriptions
    texts = [OP["description"], RESP["description"], composite, entry]
    for text in texts:
        rest = text.replace(TIE_RULE, "")
        assert not re.search(r"\btie[- ]?break|\bties\b|\btie\b", rest, re.IGNORECASE), rest[:0] or re.findall(r".{40}\btie.{40}", rest)
        assert "as the tie-break" not in rest


def test_cursor_failures_are_invalid_cursor_never_bad_request_in_the_wording():
    desc = _load(PROBLEM_FILE)["description"]
    bad, _, rest = desc.partition("BadRequestProblem is")
    bad_sentence = rest.split("ServiceUnavailableProblem is", 1)[0]
    assert "cursor" not in bad_sentence
    assert "any invalid or stale cursor" in desc.split("InvalidCursorProblem", 1)[1]
    text400 = OP["responses"]["400"]["description"]
    head, _, tail = text400.partition("Any invalid or stale cursor")
    assert "cursor" not in head and "is the closed invalid_cursor 400" in tail
