"""Release candidate routes, reports and read models."""

import json
import runpy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir
from traigent_schema.validator import _FORMAT_CHECKER

SCHEMAS = Path(get_schemas_dir())
SCHEMA_BASE = "https://schemas.traigent.ai/"
CANDIDATE_SCHEMA = "optimization/release_candidate_schema.json"
ACCEPTANCE_SCHEMA = "optimization/release_acceptance_schema.json"
ENDPOINTS = "optimization/release_endpoints.json"
COLLECTION = "/api/v1/projects/{project_id}/agents/{agent_ref}/release-candidates"
ITEM = COLLECTION + "/{candidate_ref}"
ACCEPTANCE_COLLECTION = "/api/v1/projects/{project_id}/agents/{agent_ref}/release-acceptances"
VERDICTS = ("promote", "reject", "no_decision")
CANDIDATE_ROUTES = ((COLLECTION, "post"), (COLLECTION, "get"), (ITEM, "get"))


def _document(path):
    return json.loads((SCHEMAS / path).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry():
    paths = (
        CANDIDATE_SCHEMA,
        ACCEPTANCE_SCHEMA,
        "optimization/session_capabilities_schema.json",
        "optimization/tvl_reactive_common_schema.json",
        "error_envelope_schema.json",
        "fleet_observe/fleet_observe_responses_schema.json",
        "rate_limit_info_schema.json",
    )
    return Registry().with_resources(
        (SCHEMA_BASE + path, Resource.from_contents(_document(path))) for path in paths
    )


def _validator(registry, name):
    ref = f"{SCHEMA_BASE}{CANDIDATE_SCHEMA}#/definitions/{name}"
    return Draft7Validator({"$ref": ref}, registry=registry)


def _response_validator(registry, path, method, status):
    response = _document(ENDPOINTS)["paths"][path][method]["responses"][status]
    schema = response["content"]["application/json"]["schema"]
    return Draft7Validator(
        {"$id": SCHEMA_BASE + ENDPOINTS, "allOf": [schema]},
        registry=registry,
        format_checker=_FORMAT_CHECKER,
    )


@pytest.fixture
def report():
    return {
        "environment": "production",
        "best_config_id": "bc_1",
        "best_config_version": 3,
        "candidate_fingerprint": "a" * 64,
        "gate_result_digest": "b" * 64,
        "configuration_space_digest": "c" * 64,
        "agent_code_version": "d" * 40,
        "gate_verdict": "promote",
    }


@pytest.fixture
def record(report):
    return {
        **report,
        "candidate_ref": "release_candidate_" + "e" * 32,
        "recorded_at": "2026-11-20T10:00:00Z",
        "recorded_by_kind": "api_key",
        "state": "open",
    }


@pytest.mark.parametrize(
    ("path", "method", "operation_id", "status", "response"),
    [
        (COLLECTION, "post", "create_release_candidate", "201", "ReleaseCandidateResponse"),
        (COLLECTION, "get", "list_release_candidates", "200", "ReleaseCandidateListResponse"),
        (
            ITEM,
            "get",
            "get_release_candidate",
            "200",
            "ReleaseCandidateResponse",
        ),
    ],
)
def test_release_candidate_routes(path, method, operation_id, status, response):
    paths = _document(ENDPOINTS)["paths"]
    operation = paths[path][method]
    assert operation["operationId"] == f"best_configs.{operation_id}"
    responses = operation["responses"]
    body_schema = responses[status]["content"]["application/json"]["schema"]
    assert body_schema["$ref"] == f"./release_candidate_schema.json#/definitions/{response}"
    assert "reference_not_found" in responses["404"]["description"]
    acceptance = paths[ACCEPTANCE_COLLECTION][method]
    for code in ("401", "403"):
        assert responses[code]["content"] == acceptance["responses"][code]["content"]
    parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
    for parameter in acceptance["parameters"]:
        if parameter["in"] == "path":
            assert parameters[parameter["name"]] == parameter
    if path.endswith("/{candidate_ref}"):
        candidate_ref = parameters["candidate_ref"]
        assert candidate_ref["in"] == "path"
        assert candidate_ref["required"] is True
        assert candidate_ref["schema"]["$ref"] == (
            "./release_candidate_schema.json#/definitions/ReleaseCandidateRef"
        )
    if operation_id == "list_release_candidates":
        assert parameters["limit"]["schema"]["maximum"] == 100


def test_create_route_requires_report_and_documents_replay_and_conflict():
    operation = _document(ENDPOINTS)["paths"][COLLECTION]["post"]
    body = operation["requestBody"]
    assert body["required"] is True
    description = operation["description"]
    assert (
        "A replay of the same body returns 201 with the same candidate_ref "
        "and original recording metadata."
    ) in description
    assert (
        "A different body for the same (agent, environment, best_config_id, "
        "best_config_version) returns 409 candidate_conflict; a fingerprint that does not match "
        "the stored version is the masked 404 instead, never a conflict."
    ) in description
    assert (
        "A candidate_fingerprint that does not match the stored version is refused the same way."
    ) in description
    responses = operation["responses"]
    assert "invalid_request" in responses["400"]["description"]
    assert "candidate_conflict" in responses["409"]["description"]
    assert responses["409"]["content"]["application/json"]["schema"]["$ref"] == (
        "./release_candidate_schema.json#/definitions/ReleaseCandidateConflict"
    )
    conflict = _document(CANDIDATE_SCHEMA)["definitions"]["ReleaseCandidateConflict"]
    assert conflict["properties"]["error_code"]["const"] == "candidate_conflict"


def test_create_report_through_public_request_validator(report):
    validator = SchemaValidator(unknown_endpoint_policy="strict")
    path = COLLECTION.format(project_id="project_1", agent_ref="agentref_" + "f" * 32)
    assert validator.validate_request(path, "POST", report) == []
    errors = validator.validate_request(path, "POST", {**report, "gate_verdict": "pending"})
    assert any("gate_verdict" in error and "pending" in error for error in errors), errors


def test_report_requires_every_field_and_rejects_extras(registry, report):
    definition = _document(CANDIDATE_SCHEMA)["definitions"]["ReleaseCandidateRequest"]
    validator = _validator(registry, "ReleaseCandidateRequest")
    assert definition["additionalProperties"] is False
    assert set(definition["required"]) == set(report)
    assert validator.is_valid(report)
    for field in report:
        missing = report.copy()
        del missing[field]
        assert not validator.is_valid(missing), field
    assert not validator.is_valid({**report, "note": "unexpected text"})


def test_report_gate_verdict_is_a_closed_enum(registry, report):
    definition = _document(CANDIDATE_SCHEMA)["definitions"]["ReleaseCandidateRequest"]
    assert set(definition["properties"]["gate_verdict"]["enum"]) == set(VERDICTS)
    validator = _validator(registry, "ReleaseCandidateRequest")
    for verdict in VERDICTS:
        assert validator.is_valid({**report, "gate_verdict": verdict})
    assert not validator.is_valid({**report, "gate_verdict": "pending"})


@pytest.mark.parametrize("verdict", VERDICTS)
@pytest.mark.parametrize("digest", ["b" * 64, "no_gate_run"], ids=["digest", "no-gate-run"])
def test_gate_digest_matches_verdict(registry, report, record, verdict, digest):
    expected = digest != "no_gate_run" or verdict == "no_decision"
    for name, body in (("ReleaseCandidateRequest", report), ("ReleaseCandidate", record)):
        validator = _validator(registry, name)
        payload = {**body, "gate_verdict": verdict, "gate_result_digest": digest}
        assert validator.is_valid(payload) == expected, name


def test_report_reuses_acceptance_digest_definitions():
    candidate = _document(CANDIDATE_SCHEMA)["definitions"]["ReleaseCandidateRequest"]["properties"]
    definitions = _document(ACCEPTANCE_SCHEMA)["definitions"]
    acceptance = definitions["CreateReleaseAcceptanceRequest"]["properties"]
    assert "candidate_ref" not in acceptance
    for field in (
        "candidate_fingerprint",
        "gate_result_digest",
        "configuration_space_digest",
        "agent_code_version",
    ):
        assert candidate[field]["$ref"] == acceptance[field]["$ref"]
        assert {"type", "pattern", "enum", "anyOf"}.isdisjoint(candidate[field])


def test_candidate_record_requires_all_fields_and_rejects_extras(registry, record):
    validator = _validator(registry, "ReleaseCandidate")
    assert validator.is_valid(record)
    for field in record:
        missing = record.copy()
        del missing[field]
        assert not validator.is_valid(missing), field
    assert not validator.is_valid({**record, "note": "unexpected text"})


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("candidate_ref", "release_candidate_" + "E" * 32),
        ("candidate_ref", "release_candidate_" + "e" * 32 + "\n"),
        ("recorded_at", 1763632800),
        ("recorded_by_kind", "unknown"),
        ("state", "pending"),
    ],
)
def test_candidate_record_rejects_invalid_metadata(registry, record, field, invalid):
    validator = _validator(registry, "ReleaseCandidate")
    assert not validator.is_valid({**record, field: invalid})


def test_candidate_record_uses_shared_timestamp():
    properties = _document(CANDIDATE_SCHEMA)["definitions"]["ReleaseCandidate"]["properties"]
    assert properties["recorded_at"]["$ref"] == (
        "./tvl_reactive_common_schema.json#/definitions/Timestamp"
    )
    definitions = _document("optimization/tvl_reactive_common_schema.json")["definitions"]
    assert definitions["Timestamp"]["format"] == "date-time"


def test_candidate_read_envelopes_are_closed_and_list_is_bounded(registry, record):
    validator = _validator(registry, "ReleaseCandidateResponse")
    assert validator.is_valid({"success": True, "data": record})
    assert not validator.is_valid({"success": False, "data": record})
    assert not validator.is_valid({"success": True, "data": record, "extra": 1})

    validator = _validator(registry, "ReleaseCandidateListResponse")
    assert validator.is_valid({"success": True, "data": []})
    assert validator.is_valid({"success": True, "data": [record] * 100})
    assert not validator.is_valid({"success": True, "data": [record] * 101})
    assert not validator.is_valid({"success": True, "data": [{}]})
    assert not validator.is_valid({"success": True, "data": [], "extra": 1})


@pytest.mark.parametrize("path", [COLLECTION, ITEM])
def test_get_candidate_responses_through_catalog(registry, record, path):
    validator = _response_validator(registry, path, "get", "200")
    invalid = {**record, "gate_verdict": "reject", "gate_result_digest": "no_gate_run"}
    data, invalid_data = ([record], [invalid]) if path == COLLECTION else (record, invalid)
    assert validator.is_valid({"success": True, "data": data})
    errors = list(validator.iter_errors({"success": True, "data": invalid_data}))
    assert [error.path[-1] for error in errors] == ["gate_result_digest"]


@pytest.mark.parametrize(("path", "method"), CANDIDATE_ROUTES)
def test_candidate_not_found_accepts_only_the_masked_refusal(registry, path, method):
    validator = _response_validator(registry, path, method, "404")
    assert validator.is_valid(
        {
            "success": False,
            "error": "reference_not_found",
            "error_code": "reference_not_found",
            "message": "Reference not found.",
        }
    )
    assert not validator.is_valid(
        {
            "success": False,
            "error": "forbidden",
            "error_code": "forbidden",
            "message": "Forbidden.",
        }
    )


@pytest.mark.parametrize(("path", "method"), CANDIDATE_ROUTES)
def test_candidate_rate_limit_uses_shared_headers_and_closed_values(registry, path, method):
    validator = _response_validator(registry, path, method, "429")
    details = {"scope": "global", "retry_after": 60}
    body = {
        "success": False,
        "message": "Rate limit exceeded",
        "error": "Too many requests",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "details": details,
    }
    assert validator.is_valid(body)
    for scope in ("api", "tenant"):
        assert validator.is_valid({**body, "details": {**details, "scope": scope}}), scope

    assert validator.is_valid(
        {
            **body,
            "details": {
                **details,
                "limit": "1 per 1 hour",
                "reset_time": "2026-11-20T10:00:00.123456+00:00",
            },
        }
    )
    for field in ("message", "error"):
        assert not validator.is_valid({**body, field: "unexpected text"}), field
    for field in ("scope", "limit", "reset_time"):
        invalid = {**body, "details": {**details, field: "unexpected text"}}
        assert not validator.is_valid(invalid), field
    # The limiter renders any configured window, e.g. RATE_LIMIT_GLOBAL="1 per 10000000000 seconds".
    for limit in ("1 per 10000000000 second", "10000000000 per 1 hour", "5 per 1 days"):
        assert validator.is_valid({**body, "details": {**details, "limit": limit}}), limit
    too_wide = "1" * 21
    for limit in ("1 per 1 hour\n", "100 per minute", f"{too_wide} per 1 hour", "1 per 1 week"):
        assert not validator.is_valid({**body, "details": {**details, "limit": limit}}), limit

    response = _document(ENDPOINTS)["paths"][path][method]["responses"]["429"]
    shared_headers = _document("rate_limit_info_schema.json")["x-response-headers"]
    assert response["headers"] == {
        header: {"$ref": f"../rate_limit_info_schema.json#/x-response-headers/{header}"}
        for header in shared_headers
    }


def test_candidate_conflict_has_a_fixed_closed_envelope(registry):
    validator = _validator(registry, "ReleaseCandidateConflict")
    refusal = {
        "success": False,
        "error": "release_precondition_refused",
        "error_code": "candidate_conflict",
        "message": "A different release candidate already exists for this best-config version.",
    }
    assert validator.is_valid(refusal)
    assert not validator.is_valid({**refusal, "message": "unexpected text"})
    assert not validator.is_valid({**refusal, "extra": 1})


def test_release_candidate_content_classes_pass_lint():
    script = Path(__file__).resolve().parents[1] / "scripts" / "content_class_lint.py"
    result = runpy.run_path(str(script))["run_lint"](SCHEMAS)
    assert result.ok, (result.missing, result.invalid, result.unresolved)
    assert any(
        finding.loc == f"{CANDIDATE_SCHEMA}#/definitions/ReleaseCandidateRef"
        and finding.cls == "opaque_ref"
        for finding in result.findings
    )
