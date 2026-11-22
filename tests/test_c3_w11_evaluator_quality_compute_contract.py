# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""C3 W11: experiment_run.compute_evaluator_quality on the canonical experiment-run URL."""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/evaluator-quality/compute"
OP_ID = "experiment_run.compute_evaluator_quality"
PROBLEM_FILE = "analytics/evaluator_quality_compute_problem_schema.json"
IN_PROGRESS = "urn:traigent:problem:evaluator_audit_in_progress"

PROBLEMS = {
    "401": ("unauthenticated", "Unauthorized", "Authentication is required."),
    "403": (
        "forbidden",
        "Forbidden",
        "The credential is not allowed to perform this operation.",
    ),
    "404": ("not_found", "Not Found", "The requested resource was not found."),
    "409": (
        "evaluator_audit_in_progress",
        "Conflict",
        "The evaluator-quality audit for this run is being computed by another request. "
        "Retry later.",
    ),
    "422": ("validation_failed", "Unprocessable Content", "The request is not valid."),
    "429": ("rate_limited", "Too Many Requests", "Too many requests. Retry later."),
    "500": ("internal_error", "Internal Server Error", "The request could not be completed."),
    "503": (
        "service_unavailable",
        "Service Unavailable",
        "The service is temporarily unavailable. Retry later.",
    ),
}


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")
OP = CATALOG["paths"][PATH]["post"]


def _validator(stem: str) -> Draft7Validator:
    v = SchemaValidator(contract="backend")
    return Draft7Validator(v._schemas[stem], registry=v._registry, format_checker=FormatChecker())


def _problem(status: str) -> dict:
    import hashlib

    code, title, detail = PROBLEMS[status]
    return {
        "type": f"urn:traigent:problem:{code}",
        "title": title,
        "status": int(status),
        "code": code,
        "detail": detail,
        "problem_id": hashlib.sha256(f"urn:traigent:problem:{code}".encode()).hexdigest()[:32],
    }


PAYLOAD = {
    "run_id": "run_1",
    "project_id": "project_1",
    "status": "directional",
    "reason": None,
    "anchor": {"anchor_type": "reference_labels", "confidence_ceiling": 0.8, "policy_version": "v1"},
    "evaluators": [
        {
            "evaluator_fingerprint": "ab" * 16,
            "rank": 0,
            "eligible": True,
            "quality": {"lower_bound": 0.5, "point": 0.7, "ci_low": 0.5, "ci_high": 0.8},
        }
    ],
    "panel": {"effective_votes": 2.5, "redundancy_ratio": 0.1, "n_informative": 2},
    "computed_at": "2026-11-22T10:00:00+00:00",
    "payload_version": "run_evaluator_quality.v1",
}


def _wrap(payload):
    return {"success": True, "message": "ok", "data": payload}


def test_operation_is_unique_and_reachable():
    master = _load("mep_endpoints.json")
    found = []
    for module in master["x-endpoint-modules"]:
        doc = _load(module["paths_file"].removeprefix("./"))
        for path, item in doc["paths"].items():
            for method, op in item.items():
                if isinstance(op, dict) and op.get("operationId") == OP_ID:
                    found.append((method, path))
    assert found == [("post", PATH)]
    assert f"POST:{PATH}" in SchemaValidator(contract="backend")._known_endpoints


def test_no_body_and_only_the_two_path_parameters():
    assert "requestBody" not in OP
    assert [(p["name"], p["in"], p["required"]) for p in OP["parameters"]] == [
        ("project_id", "path", True),
        ("experiment_run_ref", "path", True),
    ]
    ref = Draft7Validator(OP["parameters"][1]["schema"])
    assert ref.is_valid("experiment_run_" + "a" * 32)
    assert not ref.is_valid("experiment_" + "a" * 32)
    assert not ref.is_valid("run_1")


def test_every_ref_resolves():
    for stem in (
        "run_evaluator_quality_schema",
        "run_evaluator_quality_response_schema",
        "evaluator_quality_compute_problem_schema",
    ):
        assert _validator(stem) is not None
    for status, resp in OP["responses"].items():
        media = "application/json" if status == "200" else "application/problem+json"
        assert set(resp["content"]) == {media}, status


def test_declared_statuses_are_the_closed_set():
    assert set(OP["responses"]) == {"200", *PROBLEMS}
    for status in ("409", "429", "503"):
        assert "Retry-After" in OP["responses"][status]["headers"]


def test_valid_200_validates_and_envelope_is_enforced():
    v = _validator("run_evaluator_quality_response_schema")
    assert not list(v.iter_errors(_wrap(PAYLOAD)))
    assert list(v.iter_errors(PAYLOAD))
    minimal = {
        "run_id": "r",
        "project_id": "p",
        "status": "abstain",
        "reason": "insufficient_data",
        "anchor": {"anchor_type": "none"},
        "evaluators": [],
        "panel": {},
        "computed_at": None,
        "payload_version": "run_evaluator_quality.v1",
    }
    assert not list(v.iter_errors(_wrap(minimal)))


@pytest.mark.parametrize("sentinel", ["report_json", "axes", "acet"])
def test_internal_report_fields_are_rejected_at_every_level(sentinel):
    v = _validator("run_evaluator_quality_response_schema")
    top = {**PAYLOAD, sentinel: {}}
    assert list(v.iter_errors(_wrap(top)))
    for where in ("anchor", "panel"):
        bad = copy.deepcopy(PAYLOAD)
        bad[where][sentinel] = 1
        assert list(v.iter_errors(_wrap(bad))), where
    bad = copy.deepcopy(PAYLOAD)
    bad["evaluators"][0][sentinel] = 1
    assert list(v.iter_errors(_wrap(bad)))
    bad = copy.deepcopy(PAYLOAD)
    bad["evaluators"][0]["quality"][sentinel] = 1
    assert list(v.iter_errors(_wrap(bad)))


def test_closed_vocabularies_are_enforced():
    v = _validator("run_evaluator_quality_response_schema")
    for field, value in (
        ("status", "unknown"),
        ("reason", "free text"),
        ("payload_version", "v2"),
    ):
        assert list(v.iter_errors(_wrap({**PAYLOAD, field: value}))), field
    for field in ("run_id", "project_id", "status", "anchor", "panel", "payload_version"):
        broken = {k: x for k, x in PAYLOAD.items() if k != field}
        assert list(v.iter_errors(_wrap(broken))), field


def test_every_payload_property_is_privacy_classified():
    doc = _load("analytics/run_evaluator_quality_schema.json")

    def walk(node, where):
        for name, prop in node.get("properties", {}).items():
            if "$ref" not in prop:
                assert "x-privacy-classification" in prop, f"{where}.{name}"
        if node.get("x-content"):
            assert "x-privacy-classification" in node

    walk(doc, "root")
    for name, d in doc["definitions"].items():
        walk(d, name)


def test_caller_controlled_ids_are_content_classified_not_system():
    # The backend preserves caller-supplied run ids, so run_id (and project_id,
    # which declares no server-minted shape) is not provably content-free: the
    # repo convention is legacy_content + user_content + x-content, never system.
    doc = _load("analytics/run_evaluator_quality_schema.json")
    for name in ("run_id", "project_id"):
        prop = doc["properties"][name]
        assert prop["x-privacy-classification"] == "user_content", name
        assert prop["x-content"] is True, name
        assert prop["x-content-class"] == "legacy_content", name
        assert "x-content-note" in prop, name
        assert prop["minLength"] == 1 and "pattern" not in prop, name

    def system_ids(node, where):
        for name, prop in node.get("properties", {}).items():
            if name.endswith("_id") or name.endswith("_ref"):
                assert prop.get("x-privacy-classification") != "system", f"{where}.{name}"

    system_ids(doc, "root")
    for name, d in doc["definitions"].items():
        system_ids(d, name)


GET_PATH = "/api/v1beta/projects/{project_id}/analytics/runs/{run_id}/evaluator-quality"
GET_OP_ID = "project_analytics_runs.get_run_evaluator_quality"


def test_existing_get_shares_the_response_schema_with_the_post():
    get = CATALOG["paths"][GET_PATH]["get"]
    shared = "./run_evaluator_quality_response_schema.json"
    assert get["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == shared
    assert OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] == shared
    assert [(p["name"], p["in"], p["required"]) for p in get["parameters"]] == [
        ("project_id", "path", True),
        ("run_id", "path", True),
    ]
    assert "requestBody" not in get
    assert sorted(get["responses"]) == ["200", "401", "403", "404", "429", "500"]


def test_existing_get_is_unique_and_reachable():
    master = _load("mep_endpoints.json")
    found = []
    for module in master["x-endpoint-modules"]:
        doc = _load(module["paths_file"].removeprefix("./"))
        for path, item in doc["paths"].items():
            for method, op in item.items():
                if isinstance(op, dict) and op.get("operationId") == GET_OP_ID:
                    found.append((method, path))
    assert found == [("get", GET_PATH)]
    assert f"GET:{GET_PATH}" in SchemaValidator(contract="backend")._known_endpoints


@pytest.mark.parametrize("status", sorted(PROBLEMS))
def test_each_problem_validates_and_matches_its_status(status):
    v = _validator("evaluator_quality_compute_problem_schema")
    assert not list(v.iter_errors(_problem(status)))
    ref = OP["responses"][status]["content"]["application/problem+json"]["schema"]["$ref"]
    code = PROBLEMS[status][0]
    assert ref.startswith("./evaluator_quality_compute_problem_schema.json#/definitions/")
    definition = _load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]]
    one = Draft7Validator(definition)
    assert one.is_valid(_problem(status))
    assert definition["properties"]["code"]["const"] == code
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))


def test_409_accepts_only_the_in_progress_type():
    ref = OP["responses"]["409"]["content"]["application/problem+json"]["schema"]["$ref"]
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    ok = _problem("409")
    assert ok["type"] == IN_PROGRESS and one.is_valid(ok)
    for bad_type in (
        "urn:traigent:problem:idempotency_in_progress",
        "urn:traigent:problem:idempotency_conflict",
        "urn:traigent:problem:not_found",
    ):
        assert not one.is_valid({**ok, "type": bad_type})
    assert not one.is_valid({**ok, "extra": 1})
