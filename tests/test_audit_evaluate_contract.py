"""Audit evaluate contract (audit_evaluate domain): closed summary in, findings and one next step out.

Contract-only and additive. The documents are referenced by path so the orphan ratchet stays unchanged.
"""

import copy
import json

import jsonschema
import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
ENDPOINTS = "audit_evaluate/audit_evaluate_endpoints.json"
REQUEST = "audit_evaluate/audit_evaluate_request_schema.json"
RESPONSE = "audit_evaluate/audit_evaluate_response_schema.json"
ERROR = "audit_evaluate/audit_evaluate_error_schema.json"
PROBLEM = "audit_evaluate/audit_evaluate_problem_schema.json"
BODIES = [REQUEST, RESPONSE, ERROR, PROBLEM]
PATH = "/api/v1/projects/{project_id}/audit/evaluate"


def _load(rel):
    return json.loads((S / rel).read_text(encoding="utf-8"))


def _walk(node):
    yield node
    if isinstance(node, dict):
        for v in node.values():
            yield from _walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk(v)


def _validator(rel):
    schema = _load(rel)
    jsonschema.Draft7Validator.check_schema(schema)
    return jsonschema.Draft7Validator(schema)


def _minimal(schema, defs):
    """The smallest instance of a closed schema: required members only, zero or first enum value."""
    if "$ref" in schema:
        return _minimal(defs[schema["$ref"].rsplit("/", 1)[1]], defs)
    if "anyOf" in schema:
        return _minimal(schema["anyOf"][0], defs)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema["type"]
    if kind == "object":
        return {k: _minimal(schema["properties"][k], defs) for k in schema.get("required", [])}
    if kind == "array":
        return []
    if kind == "boolean":
        return False
    if kind == "integer":
        return schema.get("minimum", 0)
    return "1.2.3"


_REQ = _load(REQUEST)
REQUEST_OK = _minimal(_REQ, _REQ["definitions"])


def test_the_endpoint_is_declared_once_and_wired_into_the_master_catalog():
    doc = _load(ENDPOINTS)
    assert list(doc["paths"]) == [PATH]
    assert list(doc["paths"][PATH]) == ["post"]
    mep = _load("mep_endpoints.json")
    assert any(m["paths_file"] == "./" + ENDPOINTS for m in mep["x-endpoint-modules"])
    assert doc["paths"][PATH]["post"]["operationId"] == "audit_evaluate.evaluate_audit_summary"


def test_every_response_status_points_at_a_body_schema_that_exists():
    responses = _load(ENDPOINTS)["paths"][PATH]["post"]["responses"]
    assert sorted(responses) == [
        "200",
        "400",
        "401",
        "404",
        "413",
        "415",
        "422",
        "429",
        "500",
        "503",
    ]
    for code, resp in responses.items():
        ((media, body),) = resp["content"].items()
        assert media == ("application/problem+json" if code == "404" else "application/json")
        assert (S / "audit_evaluate" / body["schema"]["$ref"][2:]).exists()


def test_body_schemas_are_closed_draft7_documents():
    for rel in BODIES:
        schema = _load(rel)
        _validator(rel)
        assert schema["$id"].endswith(rel)
        for node in _walk(schema):
            if isinstance(node, dict) and node.get("type") == "object" and "properties" in node:
                assert node.get("additionalProperties") is False, rel


def test_the_request_accepts_a_minimal_summary_and_rejects_extras_and_bad_versions():
    v = _validator(REQUEST)
    assert not list(v.iter_errors(REQUEST_OK))
    extra = copy.deepcopy(REQUEST_OK)
    extra["note"] = "free text"
    assert list(v.iter_errors(extra))
    for bad in ("1.2", "1.2.3-x", "v1.2.3", "Alice has diabetes", "1000.1.1"):
        broken = copy.deepcopy(REQUEST_OK)
        broken["collector_version"] = bad
        assert list(v.iter_errors(broken)), bad


def test_the_three_fields_that_needed_a_vocabulary_decision():
    request = _load(REQUEST)
    cv = request["properties"]["collector_version"]
    assert cv["x-content-class"] == "version"
    assert cv["maxLength"] == 11
    result = _load(RESPONSE)["definitions"]["Result"]
    text = result["properties"]["instructions"]["items"]["properties"]["text"]
    assert text["x-content-class"] == "server_text"
    assert text["maxLength"] == 400
    assert text["x-content-note"]
    pid = _load(PROBLEM)["properties"]["problem_id"]
    assert pid["x-content-class"] == "opaque_ref"
    assert pid["pattern"] == "^[0-9a-f]{32}$"
    uses = {
        (rel, node["x-content-class"])
        for rel in BODIES
        for node in _walk(_load(rel))
        if isinstance(node, dict) and node.get("x-content-class") in ("version", "server_text")
    }
    assert uses == {(REQUEST, "version"), (RESPONSE, "server_text")}


def test_the_finding_and_template_vocabularies_are_closed_lists():
    result = _load(RESPONSE)["definitions"]["Result"]
    finding_ids = result["properties"]["findings"]["items"]["properties"]["finding_id"]["enum"]
    template_ids = result["properties"]["instructions"]["items"]["properties"]["template_id"][
        "enum"
    ]
    assert len(finding_ids) == 44
    assert len(set(finding_ids)) == 44
    assert len(template_ids) == 25
    assert len(set(template_ids)) == 25


def test_no_schema_carries_a_description_beyond_the_field_meaning():
    for rel in [ENDPOINTS, *BODIES]:
        for node in _walk(_load(rel)):
            if isinstance(node, dict) and isinstance(node.get("description"), str):
                assert len(node["description"]) <= 80, (rel, node["description"])


def test_the_response_and_error_bodies_validate_real_shapes():
    ok = {
        "success": True,
        "message": "Audit summary evaluated",
        "data": {
            "protocol_version": 2,
            "ruleset_version": "audit-ruleset-1",
            "status": "evaluated",
            "findings": [],
            "next_step": None,
            "instructions": [],
        },
    }
    assert not list(_validator(RESPONSE).iter_errors(ok))
    problem = {
        "type": "urn:traigent:problem:not_found",
        "title": "Not Found",
        "status": 404,
        "code": "not_found",
        "detail": "The requested resource was not found.",
        "problem_id": "0" * 32,
    }
    assert not list(_validator(PROBLEM).iter_errors(problem))
    problem["problem_id"] = "request failed for acme"
    assert list(_validator(PROBLEM).iter_errors(problem))
    err = {"success": False, "error": "Too many requests", "error_code": "RATE_LIMIT_EXCEEDED"}
    assert not list(_validator(ERROR).iter_errors(err))
    err["error"] = "project acme is missing"
    assert list(_validator(ERROR).iter_errors(err))


def test_the_validator_binds_the_endpoint():
    validator = SchemaValidator(contract="backend")
    assert f"POST:{PATH}" in validator._endpoint_schemas


@pytest.mark.parametrize("rel", BODIES)
def test_each_body_schema_is_a_content_class_lint_root(rel):
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "content_class_lint.py"
    spec = importlib.util.spec_from_file_location("content_class_lint_audit", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert rel in module.EXTRA_ROOT_FILES
