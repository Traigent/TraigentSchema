# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Evaluator promotion and IRT fit operations are declared at their current paths.

Fixtures are built key-for-key from what the server emits: the decision projection (plus the
`audit_status` the POST adds), the platform success envelope, and the bare body of the IRT
fit acceptance.
"""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
CATALOG = json.loads((S / "analytics" / "analytics_endpoints.json").read_text(encoding="utf-8"))

EVALUATE = "/api/v1/analytics/runs/{run_id}/evaluator-promotion/evaluate"
LIST = "/api/v1/analytics/runs/{run_id}/evaluator-promotion"
FIT = "/api/v1/analytics/experiments/{experiment_run_id}/fit-irt"

OPS = [
    ("post", EVALUATE, "evaluator_promotion.evaluate_evaluator_promotion"),
    ("get", LIST, "evaluator_promotion.list_evaluator_promotion_decisions"),
    ("post", FIT, "next_steps.fit_irt_model"),
]


def _responses(method: str, path: str) -> dict:
    """The operation's responses with shared component references resolved."""
    out = {}
    for status, resp in CATALOG["paths"][path][method]["responses"].items():
        if "$ref" in resp:
            resp = CATALOG["components"]["responses"][resp["$ref"].rsplit("/", 1)[1]]
        out[status] = resp
    return out


def _refs(resp: dict, media: str = "application/json") -> list[str]:
    schema = resp["content"][media]["schema"]
    return [b["$ref"] for b in schema["anyOf"]] if "anyOf" in schema else [schema["$ref"]]


def _validator(stem: str) -> Draft7Validator:
    v = SchemaValidator(contract="backend")
    return Draft7Validator(v._schemas[stem], registry=v._registry, format_checker=FormatChecker())


def _decision(**over) -> dict:
    row = {
        "decision_id": "6f1c2a52-3b6e-4c1e-9d0e-0a5f2f5b7c11",
        "decision": "promote",
        "lcb": 0.021,
        "point_diff": 0.12,
        "n_pairs": 48,
        "delta": 0.05,
        "anchor_type": "verifiable",
        "incumbent_fingerprint": "a" * 64,
        "challenger_fingerprint": "b" * 64,
        "challenger_only_wins": 9,
        "incumbent_only_wins": 2,
        "created_at": "2026-11-23T10:15:00+00:00",
    }
    row.update(over)
    return row


def _env(data, message="ok") -> dict:
    return {"success": True, "message": message, "data": data}


@pytest.mark.parametrize(("method", "path", "op_id"), OPS)
def test_operation_declared_with_backend_id_at_current_template(method, path, op_id):
    assert CATALOG["paths"][path][method]["operationId"] == op_id


def test_operation_ids_are_unique_and_reachable_through_master_catalog():
    master = json.loads((S / "mep_endpoints.json").read_text(encoding="utf-8"))
    ids: list[str] = []
    for module in master["x-endpoint-modules"]:
        doc = json.loads((S / module["paths_file"].removeprefix("./")).read_text(encoding="utf-8"))
        ids += [
            op["operationId"]
            for item in doc["paths"].values()
            for op in item.values()
            if isinstance(op, dict) and "operationId" in op
        ]
    validator = SchemaValidator(contract="backend")
    for method, path, op_id in OPS:
        assert ids.count(op_id) == 1
        assert f"{method.upper()}:{path}" in validator._known_endpoints


def test_statuses_match_the_handlers():
    r = lambda m, p: set(CATALOG["paths"][p][m]["responses"])  # noqa: E731
    assert r("post", EVALUATE) == {
        "201", "400", "401", "403", "404", "409", "413", "422", "429", "500", "503"
    }
    assert r("get", LIST) == {"200", "400", "401", "403", "404", "413", "422", "429", "500", "503"}
    assert r("post", FIT) == {
        "202", "400", "401", "403", "404", "409", "413", "422", "429", "500", "501", "503"
    }


def test_list_limit_query_matches_backend_model():
    params = {p["name"]: p for p in CATALOG["paths"][LIST]["get"]["parameters"]}
    assert params["run_id"]["in"] == "path"
    assert params["run_id"]["required"] is True
    assert params["limit"]["schema"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 100,
        "default": 20,
    }
    assert params["limit"]["required"] is False
    assert "requestBody" not in CATALOG["paths"][LIST]["get"]
    assert "requestBody" not in CATALOG["paths"][FIT]["post"]


# ---- request body -----------------------------------------------------------------


def test_request_accepts_valid_examples_and_rejects_unknown_field():
    v = _validator("evaluator_promotion_evaluate_request_schema")
    assert not list(v.iter_errors({"challenger_fingerprint": "c" * 64}))
    full = {
        "challenger_fingerprint": "c" * 64,
        "incumbent_fingerprint": "d" * 64,
        "delta": 0.01,
        "min_pairs": 25,
    }
    assert not list(v.iter_errors(full))
    assert not list(v.iter_errors({**full, "incumbent_fingerprint": None}))
    assert list(v.iter_errors({**full, "extra": 1}))


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"challenger_fingerprint": "C" * 64},
        {"challenger_fingerprint": "c" * 63},
        {"challenger_fingerprint": "c" * 64, "delta": 0},
        {"challenger_fingerprint": "c" * 64, "delta": 1},
        {"challenger_fingerprint": "c" * 64, "min_pairs": 1},
        {"challenger_fingerprint": "c" * 64, "min_pairs": 100001},
        {"challenger_fingerprint": "c" * 64, "incumbent_fingerprint": "xyz"},
    ],
)
def test_request_rejects_values_the_server_rejects(bad):
    assert list(_validator("evaluator_promotion_evaluate_request_schema").iter_errors(bad))


# ---- responses --------------------------------------------------------------------


def test_evaluate_response_validates_projection_and_is_closed():
    v = _validator("evaluator_promotion_evaluate_response_schema")
    ok = _env({**_decision(), "audit_status": "missing"}, "Evaluator promotion decision computed successfully")
    assert not list(v.iter_errors(ok))
    # insufficient / abstain branches emit null bounds and an empty incumbent
    nothing = _decision(
        decision="insufficient_evidence",
        lcb=None,
        point_diff=None,
        n_pairs=0,
        anchor_type="none",
        incumbent_fingerprint="",
        challenger_only_wins=0,
        incumbent_only_wins=0,
    )
    for audit in ("passed", "directional", "abstain", "failed", "missing", None):
        assert not list(v.iter_errors(_env({**nothing, "audit_status": audit})))
    # audit_status is required on the POST data, and nothing else may appear
    assert list(v.iter_errors(_env(_decision())))
    assert list(v.iter_errors(_env({**_decision(), "audit_status": "missing", "method": "x"})))
    assert list(v.iter_errors(_env({**_decision(), "audit_status": "bogus"})))
    assert list(v.iter_errors(_env({**_decision(), "audit_status": "missing", "decision": "maybe"})))


def test_list_response_validates_and_rejects_audit_status_entries():
    v = _validator("evaluator_promotion_decisions_response_schema")
    ok = _env({"decisions": [_decision(), _decision(decision="hold", lcb=-0.01)]})
    assert not list(v.iter_errors(ok))
    assert not list(v.iter_errors(_env({"decisions": []})))
    assert list(v.iter_errors(_env({"decisions": [{**_decision(), "audit_status": "missing"}]})))
    broken = copy.deepcopy(ok)
    del broken["data"]["decisions"][0]["created_at"]
    assert list(v.iter_errors(broken))
    assert list(v.iter_errors(_env({"decisions": [], "extra": 1})))


def test_irt_fit_response_is_the_bare_accepted_body():
    v = _validator("irt_fit_accepted_response_schema")
    body = {"job_id": "score_run-1_1763892900_ab12cd34", "status": "accepted", "submitted": True}
    assert not list(v.iter_errors(body))
    assert not list(v.iter_errors({**body, "submitted": False}))
    assert list(v.iter_errors({**body, "status": "running"}))
    assert list(v.iter_errors({**body, "extra": 1}))
    assert list(v.iter_errors({"job_id": body["job_id"], "status": "accepted"}))


# ---- error bodies -------------------------------------------------------------------


def test_dedicated_limiter_429_body_and_anyof():
    schema = CATALOG["paths"][EVALUATE]["post"]["responses"]["429"]["content"]["application/json"][
        "schema"
    ]
    assert [b["$ref"] for b in schema["anyOf"]] == [
        "../rate_limit_info_schema.json",
        "./evaluator_promotion_rate_limit_schema.json",
    ]
    v = _validator("evaluator_promotion_rate_limit_schema")
    body = {
        "success": False,
        "message": "Too many requests for this operation. Please retry later.",
        "error": "Too many requests",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "details": {"scope": "expensive_provider", "retry_after": 12, "limit": 10, "remaining": 0},
    }
    assert not list(v.iter_errors(body))
    assert list(v.iter_errors({**body, "details": {**body["details"], "limit": "10 per minute"}}))
    shared = _validator("rate_limit_info_schema")
    assert list(shared.iter_errors(body))


def test_feature_disabled_body():
    v = _validator("feature_disabled_response_schema")
    body = {
        "success": False,
        "error": "Empirical Intelligence feature not implemented",
        "message": "The 'empirical_intelligence' feature is disabled in local mode",
        "error_code": "FEATURE_DISABLED",
        "feature": "empirical_intelligence",
        "local_mode": True,
        "upgrade_message": "This feature is available in our cloud platform. Contact us to upgrade.",
    }
    assert not list(v.iter_errors(body))
    assert list(v.iter_errors({**body, "extra": 1}))
    ref = CATALOG["paths"][FIT]["post"]["responses"]["501"]["content"]["application/json"]["schema"]
    assert ref == {"$ref": "./feature_disabled_response_schema.json"}


def test_middleware_bodies():
    big = _validator("payload_too_large_schema")
    assert not list(
        big.iter_errors(
            {
                "error": "Request Too Large",
                "message": "Request size exceeds maximum allowed size of 1048576 bytes",
                "max_size": 1048576,
            }
        )
    )
    ct = _validator("unsupported_content_type_schema")
    assert not list(
        ct.iter_errors(
            {
                "error": "Bad Request",
                "message": "Invalid request format or content type",
                "allowed_content_types": ["application/json"],
            }
        )
    )
    assert list(ct.iter_errors({"error": "Bad Request"}))


def test_500_accepts_envelope_or_catch_all_and_fit_403_has_no_optimization_only_text():
    for method, path in (("post", EVALUATE), ("get", LIST), ("post", FIT)):
        assert set(_refs(_responses(method, path)["500"])) == {
            "../error_envelope_schema.json",
            "../global_error_schema.json",
            "./middleware_message_error_schema.json",
        }
    assert "optimization" not in _responses("post", FIT)["403"]["description"]


def test_audit_status_enum_includes_stale_and_unavailable():
    v = _validator("evaluator_promotion_evaluate_response_schema")
    for status in ("audit_stale", "audit_unavailable"):
        assert not list(v.iter_errors(_env({**_decision(), "audit_status": status})))


def test_middleware_responses_are_shared_and_applicable_per_method():
    for path in (EVALUATE, FIT):
        responses = _responses("post", path)
        assert _refs(responses["413"]) == [
            "./body_too_large_schema.json",
            "./payload_too_large_schema.json",
            "../global_error_schema.json",
        ]
        assert set(responses["400"]["content"]) == {"application/json", "application/problem+json"}
        assert "./idempotency_middleware_error_schema.json" in _refs(responses["400"])
        assert _refs(responses["400"], "application/problem+json") == [
            "../agents/agent_import_credential_error_schema.json"
        ]
        assert "./idempotency_middleware_error_schema.json" in _refs(responses["409"])
        assert "./idempotency_middleware_error_schema.json" in _refs(responses["503"])
    # the GET has no body, no content-type check and no Idempotency-Key
    get = _responses("get", LIST)
    assert set(get["400"]["content"]) == {"application/problem+json"}
    assert "409" not in get
    assert "./idempotency_middleware_error_schema.json" not in _refs(get["503"])
    assert "../global_error_schema.json" in _refs(get["413"])
    refs = [
        resp["$ref"]
        for method, path in (("post", EVALUATE), ("get", LIST), ("post", FIT))
        for resp in CATALOG["paths"][path][method]["responses"].values()
        if "$ref" in resp
    ]
    assert refs.count("#/components/responses/AnalyticsMwInternal") == 3


def test_idempotency_error_body():
    v = _validator("idempotency_middleware_error_schema")
    assert not list(v.iter_errors({"error": "Invalid Idempotency-Key", "message": "Key too long"}))
    assert not list(
        v.iter_errors({"error": "Idempotency unavailable", "message": "Operation is not registered"})
    )
    assert list(v.iter_errors({"error": "Key too long"}))
    assert list(v.iter_errors({"error": "Invalid Idempotency-Key", "message": "x", "success": False}))


def test_dedicated_429_retry_after_is_not_capped_at_a_day():
    v = _validator("evaluator_promotion_rate_limit_schema")
    body = {
        "success": False,
        "message": "Too many requests for this operation. Please retry later.",
        "error": "Too many requests",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "details": {"scope": "expensive_provider", "retry_after": 87840, "limit": 500, "remaining": 0},
    }
    assert not list(v.iter_errors(body))


def test_503_descriptions_name_the_auth_backend_case():
    for method, path in (("post", EVALUATE), ("get", LIST), ("post", FIT)):
        desc = _responses(method, path)["503"]["description"]
        assert "AUTH_BACKEND_UNAVAILABLE" in desc
        assert "RATE_LIMIT_UNAVAILABLE" in desc

def test_point_difference_is_unbounded_and_db_bodies_are_declared():
    v = _validator("evaluator_promotion_evaluate_response_schema")
    assert not list(v.iter_errors(_env({**_decision(point_diff=2.0, n_pairs=3), "audit_status": "missing"})))
    lv = _validator("evaluator_promotion_decisions_response_schema")
    assert not list(lv.iter_errors(_env({"decisions": [_decision(point_diff=-2.5)]})))
    msg = _validator("middleware_message_error_schema")
    assert not list(
        msg.iter_errors(
            {
                "error": "Database transaction error",
                "message": "The previous operation failed. Please retry.",
                "recovery": "automatic",
            }
        )
    )
    assert list(
        msg.iter_errors(
            {
                "error": "Security middleware error",
                "message": "Failed to apply CORS response headers",
                "request_id": "r1",
            }
        )
    )
    assert list(msg.iter_errors({"error": "x", "message": "y", "_dev_error_class": "z"}))
    dup = _validator("db_duplicate_entry_error_schema")
    assert not list(dup.iter_errors({"error": "Duplicate entry", "message": "This record already exists."}))
    assert list(dup.iter_errors({"error": "Duplicate entry", "message": "free text"}))
    integ = _validator("db_integrity_error_schema")
    assert not list(
        integ.iter_errors(
            {
                "error": "Reference not found",
                "message": "A referenced record does not exist. Please create it first.",
            }
        )
    )
    assert not list(
        integ.iter_errors(
            {"error": "Data integrity error", "message": "The operation violates data constraints."}
        )
    )
    # no mismatched pair, and the duplicate body is not a 400 integrity body
    assert list(
        integ.iter_errors({"error": "Reference not found", "message": "This record already exists."})
    )
    assert list(
        integ.iter_errors({"error": "Duplicate entry", "message": "This record already exists."})
    )
    post = _responses("post", EVALUATE)
    assert "./db_duplicate_entry_error_schema.json" in _refs(post["409"])
    assert "./db_integrity_error_schema.json" not in _refs(post["409"])
    assert "./db_integrity_error_schema.json" in _refs(post["400"])
    assert "./db_duplicate_entry_error_schema.json" not in _refs(post["400"])
    for path in (EVALUATE, FIT):
        assert "../global_error_schema.json" in _refs(_responses("post", path)["400"])
    assert "./db_integrity_error_schema.json" not in _refs(_responses("post", FIT)["400"])


def test_wording_of_reuse_and_not_found():
    desc = CATALOG["paths"][FIT]["post"]["description"]
    assert "fit-only" not in desc
    assert "active scoring job already running" in desc
    nf = _responses("post", EVALUATE)["404"]["description"]
    assert "NOT_FOUND or RESOURCE_NOT_FOUND" in nf
    assert "same body" not in nf
