"""Contracts for the agent head read and best-config publish."""

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
OPT = SCHEMAS / "optimization"
BASE = "https://schemas.traigent.ai/"
CODES = [
    "reference_not_found",
    "head_capture_invalid",
    "head_environment_mismatch",
    "head_agent_mismatch",
    "head_generation_stale",
    "head_write_unauthorized",
    "head_body_invalid",
    "head_publish_conflict",
    "unauthenticated",
    "forbidden",
    "internal_error",
]


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


def _registry():
    registry = Registry()
    for rel in (
        "optimization/session_capabilities_schema.json",
        "labels/label_common_schema.json",
        "optimization/best_config_head_refusal_schema.json",
        "optimization/best_config_publish_401_schema.json",
        "optimization/best_config_publish_403_schema.json",
        "optimization/best_config_publish_409_schema.json",
        "optimization/best_config_publish_500_schema.json",
        "optimization/release_acceptance_schema.json",
        "error_envelope_schema.json",
    ):
        doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
        registry = registry.with_resource(BASE + rel, Resource.from_contents(doc))
    return registry


def _validator(name):
    return Draft7Validator(_load(name), registry=_registry())


def test_refusal_envelope_is_closed_with_one_fixed_branch_per_code():
    schema = _load("best_config_head_refusal_schema.json")
    assert schema["additionalProperties"] is False
    assert schema["properties"]["error_code"]["enum"] == CODES
    branches = {b["properties"]["error_code"]["const"]: b["properties"] for b in schema["oneOf"]}
    assert list(branches) == CODES
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches.values()] == messages
    for props in branches.values():
        assert props["error"]["const"] in schema["properties"]["error"]["enum"]
    assert all("{" not in m and "%" not in m for m in messages)
    validator = _validator("best_config_head_refusal_schema.json")
    for code, props in branches.items():
        body = {
            "success": False,
            "error": props["error"]["const"],
            "error_code": code,
            "message": props["message"]["const"],
        }
        assert not list(validator.iter_errors(body)), code
        # a code with another code's text is not a valid envelope
        other = {**body, "message": messages[(CODES.index(code) + 1) % len(CODES)]}
        assert list(validator.iter_errors(other)), code


def test_stale_guidance_is_normative_and_never_says_reread_and_resubmit():
    text = (OPT / "best_config_head_refusal_schema.json").read_text(encoding="utf-8")
    assert "MUST NOT refresh the generation and resubmit the same result" in text
    assert "MUST NEVER auto-retry" in text
    for forbidden in ("re-read the head and re-run", "re-run the promotion"):
        assert forbidden not in text
        for path in (
            OPT / "best_config_head_endpoints.json",
            SCHEMAS / "execution" / "best_config_endpoints.json",
        ):
            assert forbidden not in path.read_text(encoding="utf-8")


def test_read_route_is_project_scoped_and_declares_every_error_status():
    doc = _load("best_config_head_endpoints.json")
    assert list(doc["paths"]) == [
        "/api/v1/projects/{project_id}/agents/{agent_ref}/best-config-head"
    ]
    get = doc["paths"]["/api/v1/projects/{project_id}/agents/{agent_ref}/best-config-head"]["get"]
    assert get["operationId"] == "best_configs.get_agent_head"
    names = {p["name"]: p for p in get["parameters"]}
    assert set(names) == {"project_id", "agent_ref", "environment"}
    assert names["environment"]["schema"]["$ref"].endswith("#/definitions/SessionEnvironment")
    for status in ("200", "400", "401", "403", "404", "500"):
        assert get["responses"][status]["content"]["application/json"]["schema"], status
    assert get["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "rate_limit_info_schema.json"
    )
    ok = get["responses"]["200"]["content"]["application/json"]["schema"]
    assert ok["$ref"].endswith("agent_head_response_schema.json")
    data = _load("agent_head_response_schema.json")["properties"]["data"]
    assert data["additionalProperties"] is False
    assert data["properties"]["generation"]["minimum"] == 0
    assert set(data["required"]) == set(data["properties"])


def _publish():
    doc = json.loads((SCHEMAS / "execution" / "best_config_endpoints.json").read_text())
    return doc["paths"]["/api/v1/best-configs"]["post"]


def _publish_request_validator():
    name = "execution/best_config_publish_request_schema.json"
    registry = Registry()
    for rel in ("optimization/best_config_schema.json",):
        doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
        registry = registry.with_resource(BASE + rel, Resource.from_contents(doc))
    schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
    return Draft7Validator(schema, registry=registry)


def _publish_body(provenance=None):
    spec = {"schema_version": "traigent.best_config.v1", "config_id": "c1", "config": {}}
    if provenance is not None:
        spec["provenance"] = provenance
    return {"spec": spec}


@pytest.mark.parametrize(
    "provenance",
    [
        None,
        {},
        {"source_session_id": "sess_1"},
        {"source_session_id": "  sess_1  "},
        {"source_session_id": ""},
        {"source_session_id": "s" * 512},
    ],
)
def test_publish_request_schema_accepts_valid_source_session_ids(provenance):
    assert _publish_request_validator().is_valid(_publish_body(provenance))


@pytest.mark.parametrize(
    "provenance",
    [
        {"source_session_id": None},
        {"source_session_id": 7},
        {"source_session_id": ["sess_1"]},
        {"session_id": "sess_1"},
        {"source_session_id": "s" * 513},
    ],
)
def test_publish_request_schema_rejects_invalid_source_session_ids(provenance):
    """null, non-strings, a `session_id` fallback and >512 characters are not valid bodies."""
    assert not _publish_request_validator().is_valid(_publish_body(provenance))


PUBLISH_SCHEMA_ID = BASE + "execution/best_config_endpoints.json"
RELEASE_REFUSAL_REF = "../optimization/release_acceptance_schema.json#/definitions/ReleaseRefusal"
ACCEPTANCE_REQUIRED = {
    "success": False,
    "error": "release_precondition_refused",
    "error_code": "acceptance_required",
    "message": "A release acceptance is required.",
}
REFERENCE_NOT_FOUND = {
    "success": False,
    "error": "reference_not_found",
    "error_code": "reference_not_found",
    "message": "Reference not found.",
}


def _publish_prose():
    docs_path = Path(__file__).resolve().parents[1] / "docs" / "content-classes.md"
    docs = docs_path.read_text(encoding="utf-8")
    section = docs.split("## Ref-addressed agent head and best-config publish", 1)[1]
    section = section.split("\n## ", 1)[0]
    return tuple(
        " ".join(text.replace("`", "").split()) for text in (_publish()["description"], section)
    )


def _response_schema(status, media="application/json"):
    return _publish()["responses"][status]["content"][media]["schema"]


def _response_definition(status):
    schema = _response_schema(status)
    if "$ref" in schema:
        return _load(Path(schema["$ref"]).name)
    return schema


def _response_validator(status, media="application/json", *, branch=None):
    base_id = PUBLISH_SCHEMA_ID
    if branch is None:
        schema = _response_schema(status, media)
    else:
        assert media == "application/json"
        definition = _response_definition(status)
        base_id = definition.get("$id", PUBLISH_SCHEMA_ID)
        schema = definition["oneOf"][branch]
    return Draft7Validator({"$id": base_id, "allOf": [schema]}, registry=_registry())


def _assert_single_response_branch(status, body, expected_branch):
    assert _response_validator(status).is_valid(body)
    matches = [
        index
        for index, _ in enumerate(_response_definition(status)["oneOf"])
        if _response_validator(status, branch=index).is_valid(body)
    ]
    assert matches == [expected_branch]


def test_publish_head_headers_document_format_and_are_optional():
    parameters = {param["name"]: param for param in _publish()["parameters"]}
    assert set(parameters) == {
        "If-Match",
        "X-Traigent-Agent-Ref",
        "X-Traigent-Expected-Head-Generation",
    }
    assert all(
        param["in"] == "header" and param["required"] is False for param in parameters.values()
    )
    assert parameters["X-Traigent-Agent-Ref"]["schema"]["$ref"] == (
        "../labels/label_common_schema.json#/definitions/AgentRef"
    )
    assert parameters["X-Traigent-Expected-Head-Generation"]["schema"] == {
        "x-content-class": "number",
        "type": "integer",
        "minimum": 0,
        "maximum": 9007199254740991,
    }


@pytest.mark.parametrize(
    "clause",
    [
        "Publish never moves the head.",
        "When X-Traigent-Agent-Id, X-Traigent-Agent-Ref and "
        "X-Traigent-Expected-Head-Generation are all absent, this is an ordinary publish.",
        "For a new configuration, omit If-Match.",
        "For a changed existing configuration, send the current ETag as If-Match.",
        "An identical spec returns the current version even with a stale If-Match.",
        "The presence of any of the three head headers, including an empty value, "
        "requests a head move.",
        "Send exactly one of X-Traigent-Agent-Id or X-Traigent-Agent-Ref together with "
        "X-Traigent-Expected-Head-Generation for a syntactically valid head-move request.",
        "The agent ID must be non-empty and at most 512 characters after trimming.",
        "The agent ref must be agentref_ followed by 32 lowercase hex digits.",
        "The expected generation must be 1 to 16 decimal digits "
        "with a value from 0 through 9007199254740991.",
        "Neither refusal publishes a configuration or version or changes the head or head history.",
        "Both refusals set Cache-Control: private, no-store and Vary: Authorization, and omit "
        "ETag and X-Traigent-Head-Generation.",
        "A retry of a refused request with the same Idempotency-Key may return an idempotency 409 "
        "instead of the refusal. It never returns a success.",
    ],
)
def test_publish_rules_are_stated_in_the_contract_and_docs(clause):
    for prose in _publish_prose():
        assert prose.count(clause) == 1


def test_publish_precedence_in_the_contract_and_docs():
    stages = (
        "malformed JSON and some unsafe strings can be refused with 400.",
        "The idempotency check runs before the separate unsafe-JSON-string guard that can return "
        "422, and before the route checks head headers.",
        "it can return 409 before those later checks.",
        "Authentication, experiment.write permission, editor role "
        "and an explicit tenant and project write scope",
        "incomplete, conflicting or malformed head headers return 400 AGENT_HEAD_VALIDATION_ERROR "
        "before agent authorization.",
        "after header validation and before the agent decision.",
        "same 404 reference_not_found. Where per-owner access applies, an agent whose creator is "
        "missing or differs from the caller also receives that 404.",
        "Per-owner access applies to non-platform-admin callers in the shared default tenant "
        "on an unpinned deployment.",
        "In an explicitly scoped collaboration project, an editor with agent write access can "
        "receive 409 acceptance_required for an agent created by another member.",
        "An agent the caller is authorized to write returns 409 acceptance_required",
        "The agent decision precedes configuration validation.",
    )
    for prose in _publish_prose():
        positions = [prose.index(stage) for stage in stages]
        assert positions == sorted(positions)


def test_release_migration_names_the_registered_operations_in_order():
    release_paths = _load("release_endpoints.json")["paths"]
    base = "/api/v1/projects/{project_id}/agents/{agent_ref}"
    acceptance = release_paths[f"{base}/release-acceptances"]["post"]["operationId"]
    release = release_paths[f"{base}/best-config-head/release"]["post"]["operationId"]
    assert acceptance == "best_configs.create_release_acceptance"
    assert release == "best_configs.release_agent_head"
    for prose in _publish_prose():
        assert (
            "publish without the head headers, record a person's release acceptance "
            f"with {acceptance}, then call {release}."
        ) in prose


@pytest.mark.parametrize(
    "obsolete",
    [
        "ORDER OF REFUSALS",
        "decision table",
        "content_less_v1",
        "content_less_v2",
        "content-less identity layer",
        "LEGACY promotion",
        "g -> g+1",
        "STALE_HEAD_GENERATION",
        "canonical session id",
        "session binding resolution",
    ],
)
def test_publish_never_documents_removed_behavior(obsolete):
    post = json.dumps(_publish())
    _, docs = _publish_prose()
    assert obsolete.lower() not in post.lower()
    assert obsolete.lower() not in docs.lower()


_CAPTURED_GENERATION = (
    r"\b(?:captured (?:head )?generation|(?:head )?generation captured "
    r"(?:at|when) optimization start(?:ed)?)\b"
)
_BEST_CONFIG_PUBLISH = (
    r"(?:\bpublish(?:es|ing)?\b|\bPOST /api/v1/best-configs(?![\w/-])|\bbest_config_endpoints\.json\b)"
)
_OBSOLETE_PUBLISH_GUIDANCE = re.compile(
    r"\b(?:protected[- ]publish precondition|closed head_body_invalid 400)\b"
    r"|\bpublish(?:es|ing)? [^.]{0,80}(?:returns?|emits?) (?:400 |403 )?"
    r"(?:head_capture_invalid|head_write_unauthorized)\b"
    r"|\b(?:sent|sends?)\b[^.]{0,120}\b(?:when|to) (?:it )?publish(?:es|ing)?\b"
    r"|\bpublish(?:ing|es)? (?:the winner |(?:an?|the) (?:best[- ]config(?:uration)?|candidate|result) )?"
    r"(?:promotes?|moves?|advances?|updates?) (?:an? |the )?(?:agent(?:'s|[- ]) )?head\b"
    rf"|{_CAPTURED_GENERATION}[^.?!]{{0,120}}{_BEST_CONFIG_PUBLISH}"
    rf"|{_BEST_CONFIG_PUBLISH}[^.?!]{{0,120}}{_CAPTURED_GENERATION}",
    flags=re.IGNORECASE,
)


@pytest.mark.parametrize(
    "stale_text",
    [
        "A run captures generation and sends it back as X-Traigent-Expected-Head-Generation "
        "when it publishes its own result.",
        "Captured by an SDK and sent back as X-Traigent-Expected-Head-Generation when it publishes.",
        "Protected path: every refusal is the closed head_body_invalid 400.",
        "Publishing a best config advances the head.",
        "Publish promotes the head.",
        "Use the captured head generation on publish.",
        "POST /api/v1/best-configs uses the generation captured at optimization start.",
        "best_config_endpoints.json requires the generation captured at optimization start.",
    ],
)
def test_schema_wide_guard_recognizes_obsolete_publish_guidance(stale_text):
    assert _OBSOLETE_PUBLISH_GUIDANCE.search(stale_text)


def test_no_schema_describes_publish_time_promotion():
    violations = [
        (path.relative_to(SCHEMAS), line, match.group())
        for path in sorted(SCHEMAS.rglob("*.json"))
        for line, prose in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if (match := _OBSOLETE_PUBLISH_GUIDANCE.search(prose))
    ]
    assert not violations


@pytest.mark.parametrize(
    ("status", "body"),
    [("404", REFERENCE_NOT_FOUND), ("409", ACCEPTANCE_REQUIRED)],
)
def test_head_move_refusal_matches_exactly_one_release_branch(status, body):
    branch = _response_definition(status)["oneOf"][0]
    expected_ref = (
        RELEASE_REFUSAL_REF
        if status == "404"
        else "./release_acceptance_schema.json#/definitions/ReleaseRefusal"
    )
    assert branch["allOf"][0] == {"$ref": expected_ref}
    assert branch["allOf"][1]["properties"]["error_code"]["const"] == body["error_code"]
    _assert_single_response_branch(status, body, 0)
    _, docs = _publish_prose()
    assert json.dumps(body, separators=(",", ":")) in docs


@pytest.mark.parametrize("status", ["404", "409"])
def test_head_move_refusal_declares_private_cache_headers(status):
    headers = _publish()["responses"][status]["headers"]
    expected = (
        {"Cache-Control", "Vary", "Retry-After"} if status == "409" else {"Cache-Control", "Vary"}
    )
    assert set(headers) == expected
    assert headers["Cache-Control"]["schema"]["const"] == "private, no-store"
    vary = Draft7Validator(headers["Vary"]["schema"])
    assert vary.is_valid("Authorization")
    assert vary.is_valid("Authorization, Origin")
    assert vary.is_valid("Origin")
    assert not vary.is_valid("*")
    assert "Head-move refusals vary by Authorization" in headers["Vary"]["description"]


def test_in_progress_idempotency_409_can_include_retry_after():
    header = _publish()["responses"]["409"]["headers"]["Retry-After"]
    assert "in-progress request" in header["description"]
    validator = Draft7Validator(header["schema"])
    assert validator.is_valid(1)
    assert not validator.is_valid(0)
    assert not validator.is_valid(1.5)


@pytest.mark.parametrize(
    ("status", "body", "other"),
    [
        ("404", REFERENCE_NOT_FOUND, ACCEPTANCE_REQUIRED),
        ("409", ACCEPTANCE_REQUIRED, REFERENCE_NOT_FOUND),
    ],
)
def test_head_move_refusal_rejects_wrong_values_and_wrong_shape(status, body, other):
    validator = _response_validator(status)
    for key, value in body.items():
        assert not validator.is_valid({k: v for k, v in body.items() if k != key}), key
        wrong = True if value is False else "request value"
        assert not validator.is_valid({**body, key: wrong}), key
    for bad in (
        {**body, "generation": 0},
        {**body, "agent_id": "agent"},
        other,
        {
            **body,
            "error_code": "head_generation_stale",
            "message": "Agent head moved since the acceptance.",
        },
    ):
        assert not validator.is_valid(bad), bad


def test_masked_404_does_not_replace_ordinary_publish_not_found():
    _assert_single_response_branch(
        "404",
        {
            "success": False,
            "error": "best config not found",
            "error_code": "BEST_CONFIG_NOT_FOUND",
            "message": "best config not found",
        },
        1,
    )


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("RESOURCE_NOT_FOUND", "Resource not found"),
        ("TENANT_NOT_FOUND", "Tenant context is invalid for this request"),
        ("PROJECT_NOT_FOUND", "project not found"),
    ],
)
def test_scope_404s_are_disjoint_from_the_agent_mask(code, message):
    body = {"success": False, "error": code, "error_code": code, "message": message}
    _assert_single_response_branch("404", body, 1)
    assert not _response_validator("404").is_valid({**body, "error_code": "reference_not_found"})


@pytest.mark.parametrize(
    "message",
    [
        "X-Traigent-Agent-Id and X-Traigent-Agent-Ref must not be sent together",
        "X-Traigent-Expected-Head-Generation and one of X-Traigent-Agent-Id or "
        "X-Traigent-Agent-Ref must be sent together",
        "X-Traigent-Expected-Head-Generation must be a non-negative integer",
        "X-Traigent-Expected-Head-Generation must be at most 9007199254740991",
        "agent id must be a non-empty string",
        "agent id is too long",
        "X-Traigent-Agent-Ref is malformed",
    ],
)
def test_head_header_validation_400_is_closed_and_matches_exactly_one_branch(message):
    body = {
        "success": False,
        "error": message,
        "error_code": "AGENT_HEAD_VALIDATION_ERROR",
        "message": message,
    }
    _assert_single_response_branch("400", body, 0)
    validator = _response_validator("400")
    for removed in body:
        assert not validator.is_valid({key: value for key, value in body.items() if key != removed})
    for bad in (
        {**body, "success": True},
        {**body, "details": {}},
        {**body, "message": "agent not found"},
        {**body, "error": "head_capture_invalid"},
        {**body, "error_code": "head_capture_invalid"},
    ):
        assert not validator.is_valid(bad), bad


@pytest.mark.parametrize(
    "message",
    [
        "request body must contain JSON",
        "request body must be a JSON object",
        "config_id must be a non-empty string",
    ],
)
def test_normal_best_config_validation_400_is_retained(message):
    body = {
        "success": False,
        "error": message,
        "error_code": "BEST_CONFIG_VALIDATION_ERROR",
        "message": message,
    }
    _assert_single_response_branch("400", body, 1)
    validator = _response_validator("400")
    for removed in body:
        assert not validator.is_valid({key: value for key, value in body.items() if key != removed})


def test_documented_best_config_validation_error_repeats_the_same_text():
    media = _publish()["responses"]["400"]["content"]["application/json"]
    body = media["examples"]["emptyHeadMoveBody"]["value"]
    _assert_single_response_branch("400", body, 1)
    # Draft 7 cannot compare two arbitrary sibling strings.
    assert body["error"] == body["message"] == "request body must contain JSON"


@pytest.mark.parametrize(
    ("error", "message"),
    [
        ("Invalid Idempotency-Key", "Key too long"),
        ("Invalid idempotent request", "Unable to fingerprint request body"),
    ],
)
def test_keyed_publish_keeps_pre_route_400_errors(error, message):
    body = {"error": error, "message": message}
    _assert_single_response_branch("400", body, 2)
    validator = _response_validator("400")
    assert not validator.is_valid({"error": error})
    assert not validator.is_valid({"message": message})
    assert not validator.is_valid({**body, "success": False})
    assert not validator.is_valid({**body, "error_code": "BEST_CONFIG_VALIDATION_ERROR"})


def test_unsupported_content_type_400_is_a_separate_request_guard_body():
    body = {
        "error": "Bad Request",
        "message": "Invalid request format or content type",
        "allowed_content_types": [
            "application/json",
            "application/x-protobuf",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ],
    }
    _assert_single_response_branch("400", body, 2)
    validator = _response_validator("400")
    for removed in body:
        assert not validator.is_valid({key: value for key, value in body.items() if key != removed})
    assert not validator.is_valid({**body, "allowed_content_types": []})
    assert not validator.is_valid({**body, "success": False})
    assert not validator.is_valid({**body, "error_code": "BEST_CONFIG_VALIDATION_ERROR"})


def test_provider_guard_400_is_a_closed_problem_document():
    code = "provider_credential_not_accepted"
    message = (
        "Provider credentials are not accepted by the API. Configure them in the deployment "
        "environment or secret storage."
    )
    body = {
        "type": f"urn:traigent:problem:{code}",
        "title": "Provider credentials are not accepted",
        "status": 400,
        "code": code,
        "detail": message,
        "success": False,
        "error": code,
        "error_code": code,
        "message": message,
    }
    validator = _response_validator("400", "application/problem+json")
    assert validator.is_valid(body)
    for removed in body:
        assert not validator.is_valid({key: value for key, value in body.items() if key != removed})
    assert not validator.is_valid({**body, "detail": "request value"})
    assert not validator.is_valid({**body, "extra": "request value"})
    assert not _response_validator("400").is_valid(body)


@pytest.mark.parametrize(
    "message",
    [
        "If-Match cannot be used for a new best config",
        "If-Match is required to update an existing best config",
        "If-Match does not match the current ETag",
        "config_id/environment already belongs to a different function_ref",
        "best config publish conflicted",
    ],
)
def test_ordinary_publish_409_conflicts_are_retained(message):
    body = {
        "success": False,
        "error": message,
        "error_code": "BEST_CONFIG_CONFLICT",
        "message": message,
    }
    _assert_single_response_branch("409", body, 1)
    assert not _response_validator("409").is_valid({**body, "error_code": "STALE_HEAD_GENERATION"})


@pytest.mark.parametrize(
    ("error", "message"),
    [
        ("Idempotency conflict", "Idempotency-Key already used with different payload"),
        ("Idempotency conflict", "Idempotency record is in an unknown state"),
        ("Idempotency conflict", "Idempotency key already used"),
        ("Request in progress", "A request with this Idempotency-Key is currently processing"),
    ],
)
def test_keyed_409_errors_are_disjoint_from_release_refusal(error, message):
    body = {"error": error, "message": message}
    _assert_single_response_branch("409", body, 2)
    assert not _response_validator("409").is_valid({**body, "success": True})


def test_publish_500_keeps_the_handler_error_and_rejects_removed_protected_refusal():
    validator = _response_validator("500")
    body = {
        "success": False,
        "error": "Internal server error",
        "error_code": "BEST_CONFIG_ERROR",
        "message": "Internal server error",
    }
    assert validator.is_valid(body)
    for bad in (
        {**body, "error_code": "internal_error"},
        {**body, "message": "Internal error."},
        {**body, "extra": "member"},
        {key: value for key, value in body.items() if key != "message"},
    ):
        assert not validator.is_valid(bad), bad


@pytest.mark.parametrize(
    ("status", "error", "code", "message"),
    [
        ("401", "AUTHENTICATION_REQUIRED", "AUTHENTICATION_REQUIRED", "Authentication required"),
        (
            "401",
            "Authentication required",
            "AUTHENTICATION_REQUIRED",
            "Valid authentication is required to access this endpoint",
        ),
        ("401", "INVALID_TOKEN", "INVALID_TOKEN", "Authentication failed"),
        ("403", "PERMISSION_DENIED", "PERMISSION_DENIED", "Permission denied"),
    ],
)
def test_ordinary_publish_auth_statuses_keep_their_error_bodies(status, error, code, message):
    validator = _response_validator(status)
    body = {"success": False, "error": error, "error_code": code, "message": message}
    assert validator.is_valid(body)
    for field in body:
        assert not validator.is_valid({k: v for k, v in body.items() if k != field})
    assert not validator.is_valid({**body, "success": True})
    assert not validator.is_valid({**body, "extra": "member"})


@pytest.mark.parametrize(
    ("status", "retired_codes"),
    [
        ("401", {"unauthenticated"}),
        ("403", {"forbidden", "head_write_unauthorized"}),
        (
            "409",
            {
                "head_environment_mismatch",
                "head_agent_mismatch",
                "head_generation_stale",
                "head_publish_conflict",
            },
        ),
        ("500", {"internal_error"}),
    ],
)
def test_publish_rejects_retired_protected_refusals(status, retired_codes):
    schema_name = f"best_config_publish_{status}_schema.json"
    assert _response_schema(status) == {"$ref": f"../optimization/{schema_name}"}
    assert (OPT / schema_name).exists()
    legacy = _validator("best_config_head_refusal_schema.json")
    current = _response_validator(status)
    checked = set()
    for branch in legacy.schema["oneOf"]:
        props = branch["properties"]
        code = props["error_code"]["const"]
        if code not in retired_codes:
            continue
        body = {
            "success": False,
            "error": props["error"]["const"],
            "error_code": code,
            "message": props["message"]["const"],
        }
        assert legacy.is_valid(body)
        assert not current.is_valid(body), body
        checked.add(code)
    assert checked == retired_codes


@pytest.mark.parametrize(
    "message",
    ["Failed to apply security response headers", "Failed to apply CORS response headers"],
)
def test_publish_500_accepts_two_field_response_hardening_failure(message):
    validator = _response_validator("500")
    body = {"error": "Security middleware error", "message": message}
    assert validator.is_valid(body)
    assert not validator.is_valid({"error": body["error"]})
    assert not validator.is_valid({**body, "message": "arbitrary text"})
    assert not validator.is_valid({**body, "success": False})


def test_publish_500_accepts_fixed_transaction_commit_failure():
    validator = _response_validator("500")
    body = {
        "error": "Transaction commit failed",
        "message": "A database error occurred. Please retry.",
    }
    assert validator.is_valid(body)
    development_body = {
        **body,
        "_dev_error_class": "RuntimeError",
        "_dev_error_detail": "commit failed",
    }
    assert validator.is_valid(development_body)
    assert not validator.is_valid({**development_body, "_dev_error_detail": "database detail"})
    assert not validator.is_valid({**body, "message": "database detail"})


@pytest.mark.parametrize(
    "body",
    [
        {"error": "Request body too large", "code": "REQUEST_BODY_TOO_LARGE"},
        {
            "error": "Request Too Large",
            "message": "Request size exceeds maximum allowed size of 1024 bytes",
            "max_size": 1024,
        },
        {"success": False, "error": "Request Entity Too Large", "code": "REQUEST_ENTITY_TOO_LARGE"},
        {"success": False, "error": "Content Too Large", "code": "REQUEST_ENTITY_TOO_LARGE"},
    ],
)
def test_publish_413_accepts_body_limit_errors(body):
    validator = _response_validator("413")
    assert validator.is_valid(body)
    for field in body:
        assert not validator.is_valid({k: v for k, v in body.items() if k != field})
    assert not validator.is_valid({**body, "extra": "member"})
    if "max_size" in body:
        assert not validator.is_valid({**body, "message": "arbitrary text"})
        assert not validator.is_valid({**body, "message": body["message"] + "\n"})
        assert not validator.is_valid({**body, "max_size": 0})


def test_publish_501_accepts_the_feature_disabled_response():
    validator = _response_validator("501")
    body = {
        "success": False,
        "error": "Traigent Integration feature not implemented",
        "error_code": "FEATURE_DISABLED",
        "message": "The 'traigent_integration' feature is disabled in local mode",
        "feature": "traigent_integration",
        "local_mode": True,
        "upgrade_message": "This feature is available in our cloud platform. Contact us to upgrade.",
    }
    assert validator.is_valid(body)
    assert validator.is_valid({**body, "local_mode": False})
    assert not validator.is_valid({**body, "feature": "another_feature"})
    for field in body:
        assert not validator.is_valid({k: v for k, v in body.items() if k != field})


@pytest.mark.parametrize("code", ["BEST_CONFIG_AUDIT_ERROR", "AUTH_BACKEND_UNAVAILABLE"])
def test_publish_503_accepts_redacted_audit_and_auth_errors(code):
    validator = _response_validator("503")
    body = {
        "success": False,
        "error": "Internal server error",
        "error_code": code,
        "message": "Internal server error",
    }
    assert validator.is_valid(body)
    assert not validator.is_valid({**body, "message": "best config audit logging failed"})
    for field in body:
        assert not validator.is_valid({k: v for k, v in body.items() if k != field})
