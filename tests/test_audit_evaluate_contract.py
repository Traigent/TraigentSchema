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


# The identities (not only the counts) of the two closed vocabularies, pinned to the server's lists.
FINDING_IDS = (
    "AGT_NO_ENTRY_POINT",
    "AGT_BLANK_SPACE",
    "AGT_ALL_KNOBS_UNREAD",
    "AGT_SOME_KNOBS_UNREAD",
    "AGT_SPACE_NOT_INVENTORIED",
    "AGT_KNOBS_MAYBE_READ",
    "INV_PARSE_GAP",
    "INV_TRUNCATED",
    "SCR_NONE_FOUND",
    "SCR_NOT_MEASURED",
    "SCR_PROBE_UNSTABLE",
    "SCR_PROBE_MISORDERED",
    "SCR_PROBE_ERRORS",
    "SCR_PROBE_NONFINITE",
    "SCR_PROBE_FAILED",
    "SCR_PROBE_BLOCKED",
    "SCR_PROBE_SYNTHETIC",
    "DS_NONE_FOUND",
    "DS_UNREADABLE",
    "DS_ROWS_NO_SDK_INPUT",
    "DS_GOLD_ABSENT",
    "DS_GOLD_UNUSABLE",
    "DS_BELOW_SMOKE",
    "DS_BELOW_TUNING",
    "DS_NO_HOLDOUT",
    "DS_HOLDOUT_SHORT",
    "DS_HOLDOUT_OVERLAP",
    "DS_EXACT_DUPES",
    "DS_NEAR_DUPES",
    "DS_NEAR_DUPES_UNCHECKED",
    "DS_CROSS_SPLIT_NEAR",
    "DS_CROSS_SPLIT_UNCHECKED",
    "DS_LABEL_DOMINANT",
    "DS_LABEL_FIELD_MISSING",
    "DS_LABEL_FIELD_SINGLE_VALUE",
    "DS_LABEL_MINORITY_SHORT",
    "DS_STRUCTURED_GOLD_UNCHECKED",
    "DS_JSON_CONSTANTS",
    "DS_LINES_SKIPPED",
    "DS_ROWS_TRUNCATED",
    "DS_FILES_TRUNCATED",
    "DS_SPLIT_MARKER_CONFLICT",
    "EVAL_INCOMPLETE",
    "ALL_CLEAR",
)

TEMPLATE_IDS = (
    "step.a.no_entry_point",
    "step.b.all_unread",
    "step.b.blank",
    "step.c.no_scorer",
    "step.d.probe_not_ready",
    "step.e.not_measured",
    "step.e.placeholder_probe",
    "step.f.fact",
    "step.f.holdout_overlap",
    "step.f.missing_gold",
    "step.f.no_dataset",
    "step.f.only_unread_facts",
    "step.f.scan_truncated",
    "step.f.short",
    "step.f.short_holdout_named",
    "step.f.unloadable",
    "step.f.unread_beside_analysed",
    "step.f.unread_none_analysed",
    "step.g.all_clear",
    "step.h.not_inventoried",
    "step.h.partly_unread",
    "step.h.possibly_read",
    "step.i.incomplete",
    "step.i.parse_gap",
    "step.i.truncated",
)


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
    for bad in ("1.2", "1.2.3-x", "v1.2.3", "Alice has diabetes", "1000.1.1", "1.2.3\n", "1.2.3\r\n"):
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
    assert pid["pattern"] == "^[0-9a-f]{32}(?![\\s\\S])"
    assert cv["pattern"] == "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(?![\\s\\S])"
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
    assert sorted(finding_ids) == sorted(FINDING_IDS)
    assert sorted(template_ids) == sorted(TEMPLATE_IDS)
    assert len(set(FINDING_IDS)) == 44
    assert len(set(TEMPLATE_IDS)) == 25


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
    for bad in ("request failed for acme", "0" * 32 + "\n"):
        problem["problem_id"] = bad
        assert list(_validator(PROBLEM).iter_errors(problem)), bad
    err = {"success": False, "error": "Too many requests", "error_code": "RATE_LIMIT_EXCEEDED"}
    assert not list(_validator(ERROR).iter_errors(err))
    err["error"] = "project acme is missing"
    assert list(_validator(ERROR).iter_errors(err))


def test_the_validator_binds_the_endpoint():
    validator = SchemaValidator(contract="backend")
    assert f"POST:{PATH}" in validator._endpoint_schemas


PROJECT_ID_FORMS = (
    "project_" + "0123456789abcdef" * 2,
    "project_default_" + "0123456789abcdef",
    "project_personal_" + "0123456789abcdef" * 2,
)


def test_the_project_id_path_parameter_is_a_fixed_pattern_opaque_ref():
    (param,) = _load(ENDPOINTS)["paths"][PATH]["post"]["parameters"]
    schema = param["schema"]
    assert schema["x-content-class"] == "opaque_ref"
    assert schema["maxLength"] == 49
    assert schema["pattern"] == (
        "^project_(default_[0-9a-f]{16}|personal_[0-9a-f]{32}|[0-9a-f]{32})(?![\\s\\S])"
    )
    v = jsonschema.Draft7Validator(schema)
    for ok in PROJECT_ID_FORMS:
        assert not list(v.iter_errors(ok)), ok
    for bad in (
        "Alice has diabetes",
        "project_" + "0" * 31,
        "project_" + "0" * 33,
        "project_" + "A" * 32,
        PROJECT_ID_FORMS[0] + "\n",
        PROJECT_ID_FORMS[1] + "\n",
        PROJECT_ID_FORMS[2] + "\n",
        "project_default_" + "0" * 32,
        "",
    ):
        assert list(v.iter_errors(bad)), bad


def test_the_endpoints_document_is_a_content_class_lint_root():
    import importlib.util
    import sys
    from pathlib import Path

    path = Path(__file__).resolve().parent.parent / "scripts" / "content_class_lint.py"
    spec = importlib.util.spec_from_file_location("content_class_lint_audit_ep", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert ENDPOINTS in module.EXTRA_ROOT_FILES
    assert module.PROJECT_ID_PATTERN in module._FIXED_REF_PATTERNS


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
