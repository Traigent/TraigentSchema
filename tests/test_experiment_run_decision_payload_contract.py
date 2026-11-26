# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""experiment_run.get_run_decision_payload on the experiment-run reference URL."""

from __future__ import annotations

import hashlib
import json
import posixpath

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
PATH = "/api/v1/projects/{project_id}/experiment-runs/{experiment_run_ref}/decision-payload"
OLD_PATH = "/api/v1/analytics/runs/{run_id}/decision-payload"
OP_ID = "experiment_run.get_run_decision_payload"
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
PROBLEM_FILE = "analytics/decision_payload_problem_schema.json"


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
    assert ref.startswith("./decision_payload_problem_schema.json#/definitions/")
    one = Draft7Validator(_load(PROBLEM_FILE)["definitions"][ref.rsplit("/", 1)[1]])
    assert one.is_valid(_problem(status))
    assert not one.is_valid({**_problem(status), "extra": 1})
    for other in PROBLEMS:
        if other != status:
            assert not one.is_valid(_problem(other))
    assert not list(_validator("decision_payload_problem_schema").iter_errors(_problem(status)))


def _resolve(ref: str, doc_rel: str, doc: dict) -> tuple[dict, str, dict]:
    """Return (target node, its document path, its document) for a $ref."""
    file_part, _, fragment = ref.partition("#")
    if file_part.startswith("https://schemas.traigent.ai/"):
        rel = file_part.removeprefix("https://schemas.traigent.ai/")
    elif file_part:
        rel = posixpath.normpath(posixpath.join(posixpath.dirname(doc_rel), file_part))
    else:
        rel = doc_rel
    target_doc = doc if rel == doc_rel else _load(rel)
    node = target_doc
    for part in [x for x in fragment.split("/") if x]:
        node = node[part]
    return node, rel, target_doc


def _max_chars(node: dict, doc_rel: str, doc: dict) -> int:
    """Upper bound of encoded characters of an instance of `node`; fails on any unbounded part."""
    if "$ref" in node:
        target, rel, tdoc = _resolve(node["$ref"], doc_rel, doc)
        return _max_chars(target, rel, tdoc)
    if "allOf" in node:
        # a branch without additionalProperties only tightens a property of the closed DTO branch
        return max(
            _max_chars(n, doc_rel, doc)
            for n in node["allOf"]
            if "$ref" in n or n.get("type") != "object" or "additionalProperties" in n
        )
    if "const" in node:
        return len(json.dumps(node["const"]))
    if "enum" in node:
        return max(len(json.dumps(v)) for v in node["enum"])
    if "anyOf" in node:
        return max(_max_chars(n, doc_rel, doc) for n in node["anyOf"])
    t = node["type"]
    if isinstance(t, list):
        t = "string" if "string" in t else t[0]
    if t == "string":
        assert "maxLength" in node, node
        return node["maxLength"] + 2
    if t == "array":
        assert "maxItems" in node, node
        return node["maxItems"] * (_max_chars(node["items"], doc_rel, doc) + 1) + 2
    if t == "object":
        total = 2
        for name, prop in node.get("properties", {}).items():
            total += len(name) + 4 + _max_chars(prop, doc_rel, doc)
        extra = node.get("additionalProperties")
        if isinstance(extra, dict):
            assert "maxProperties" in node, node
            total += node["maxProperties"] * (
                node["propertyNames"]["maxLength"] + 4 + _max_chars(extra, doc_rel, doc)
            )
        else:
            assert extra is False, node
        return total
    if t == "integer":
        assert node["minimum"] >= -(2**53 - 1) and node["maximum"] <= 2**53 - 1, node
        return len(str(node["minimum"]))  # sign plus 16 digits
    assert t in ("boolean", "null"), f"unbounded numeric arm: {node}"  # no free `number`
    return 5


def test_response_schema_is_bounded_within_one_mib():
    resp = _load("analytics/run_decision_payload_response_schema.json")
    assert resp["additionalProperties"] is False
    assert resp["x-max-response-bytes"] == MAX_BYTES == OP["x-max-response-bytes"]
    assert (
        OP["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        == "./run_decision_payload_response_schema.json"
    )
    # worst case: every character escaped to a 12-byte astral surrogate pair
    rel = "analytics/run_decision_payload_response_schema.json"
    assert _max_chars(resp, rel, resp) * 12 <= MAX_BYTES


def test_response_data_field_set_is_unchanged_and_enveloped():
    old = _load("analytics/decision_payload_response_schema.json")
    new = _load("analytics/run_decision_payload_response_schema.json")
    assert set(new["properties"]) == set(old["properties"])
    # same DTO, with only run_id overridden (allOf) in the canonical schema
    assert new["properties"]["data"]["allOf"][0] == old["properties"]["data"]
    dto = _load("analytics/decision_payload_schema.json")
    assert set(dto["properties"]) >= set(new["properties"]["data"]["allOf"][1]["properties"])
    assert new["required"] == old["required"]
    v = _validator("run_decision_payload_response_schema")
    body = {
        "run_id": "experiment_run_" + "0f" * 16,
        "project_id": "p",
        "intent": "iterate",
        "headline": "h",
        "confidence": "high",
        "recommended_action": {"kind": "k", "why": "w"},
        "evidence": [],
        "drilldowns": [],
        "warnings": [],
    }
    ok = {"success": True, "message": "ok", "data": body}
    assert not list(v.iter_errors(ok))
    assert list(v.iter_errors(body))
    assert list(v.iter_errors({**ok, "extra": 1}))
    assert list(v.iter_errors({**ok, "meta": {str(i): 1 for i in range(9)}}))
    assert list(v.iter_errors({**ok, "meta": {"a": {"nested": 1}}}))
    assert list(v.iter_errors({**ok, "data": {**body, "evidence": [{"type": "t", "summary": "s"}] * 51}}))


def test_deprecated_path_points_at_the_successor():
    old = CATALOG["paths"][OLD_PATH]["get"]
    assert old["deprecated"] is True
    assert old["operationId"] == "analytics.get_run_decision_payload"
    assert OP_ID in old["description"]
    assert "{experiment_run_ref}/decision-payload" in old["description"]
    assert not OP.get("deprecated")


def test_canonical_data_run_id_is_the_experiment_run_ref_and_legacy_is_unchanged():
    v = _validator("run_decision_payload_response_schema")
    base = {
        "run_id": "experiment_run_" + "0f" * 16,
        "project_id": "p",
        "intent": "iterate",
        "headline": "h",
        "confidence": "high",
        "recommended_action": {"kind": "k", "why": "w"},
        "evidence": [],
        "drilldowns": [],
        "warnings": [],
    }
    ok = {"success": True, "message": "ok", "data": base}
    assert not list(v.iter_errors(ok))
    for bad in ("12345", "experiment_run_" + "A" * 32, "experiment_run_abc", "run_1"):
        assert list(v.iter_errors({**ok, "data": {**base, "run_id": bad}})), bad
    assert list(v.iter_errors({**ok, "data": {**base, "extra": 1}}))
    legacy = _validator("decision_payload_response_schema")
    assert not list(legacy.iter_errors({**ok, "data": {**base, "run_id": "12345"}}))


def test_meta_numeric_arm_is_integers_in_the_safe_range_only():
    v = _validator("run_decision_payload_response_schema")
    base = {
        "run_id": "experiment_run_" + "0f" * 16,
        "project_id": "p",
        "intent": "iterate",
        "headline": "h",
        "confidence": "high",
        "recommended_action": {"kind": "k", "why": "w"},
        "evidence": [],
        "drilldowns": [],
        "warnings": [],
    }
    env = {"success": True, "message": "ok", "data": base}
    for good in (0, -(2**53 - 1), 2**53 - 1, True, None, "x" * 128):
        assert not list(v.iter_errors({**env, "meta": {"k": good}})), good
    for bad in (1.5, 2**53, -(2**53), "x" * 129):
        assert list(v.iter_errors({**env, "meta": {"k": bad}})), bad


def test_problem_schema_root_oneof_enforces_the_vocabulary():
    v = _validator("decision_payload_problem_schema")
    assert not list(v.iter_errors(_problem("404")))
    assert list(v.iter_errors({**_problem("404"), "status": 418}))
    assert list(v.iter_errors({**_problem("404"), "extra": 1}))
    assert list(v.iter_errors({"type": "urn:traigent:problem:not_found"}))


def _all_patterns(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                yield v
            else:
                yield from _all_patterns(v)
    elif isinstance(node, list):
        for v in node:
            yield from _all_patterns(v)


def test_no_pattern_uses_a_lookahead_and_refs_reject_malformed_ids():
    # Patterns end in "$" (Pydantic v2's rust-regex engine refuses lookahead); the
    # trailing-newline hardening is applied by the Python-side validators, not by the schema.
    ref = "experiment_run_" + "0f" * 16
    resp = _load("analytics/run_decision_payload_response_schema.json")
    patterns = [*_all_patterns(OP), *_all_patterns(resp), *_all_patterns(_load(PROBLEM_FILE))]
    assert patterns
    assert not [p for p in patterns if "(?!" in p]
    path_ref = Draft7Validator(OP["parameters"][1]["schema"])
    run_id = Draft7Validator(resp["properties"]["data"]["allOf"][1]["properties"]["run_id"])
    for field in (path_ref, run_id):
        assert field.is_valid(ref)
        for bad in ("", "12345", "experiment_" + "0f" * 16, "experiment_run_" + "0f" * 15,
                    "experiment_run_" + "0f" * 17, "experiment_run_" + "0F" * 16,
                    "experiment_bad_" + "0f" * 16):  # same length as a valid ref: prefix rule alone
            assert not field.is_valid(bad), bad
