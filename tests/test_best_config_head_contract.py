"""Plan v2.1 phase 0b: ref-addressed agent head read and the protected-publish contract."""
import json
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
    ):
        doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
        registry = registry.with_resource(BASE + rel, Resource.from_contents(doc))
    return registry


def _validator(name):
    return Draft7Validator(_load(name), registry=_registry())


REF = "agentref_" + "a" * 32


def test_head_response_is_closed_and_has_no_raw_ids():
    schema = _load("agent_head_by_ref_response_schema.json")
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"agent_ref", "environment", "generation", "exists"}
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["properties"]["agent_ref"]["$ref"].endswith("#/definitions/AgentRef")
    assert schema["properties"]["environment"]["$ref"].endswith("#/definitions/SessionEnvironment")


@pytest.mark.parametrize(
    ("generation", "exists", "valid"),
    [(0, False, True), (1, True, True), (7, True, True), (0, True, False), (1, False, False),
     (5, False, False), (-1, False, False)],
)
def test_exists_is_false_iff_generation_is_zero(generation, exists, valid):
    body = {"agent_ref": REF, "environment": "default", "generation": generation, "exists": exists}
    assert (not list(_validator("agent_head_by_ref_response_schema.json").iter_errors(body))) is valid


def test_response_rejects_raw_ids_and_extra_members():
    body = {"agent_ref": REF, "environment": "default", "generation": 0, "exists": False}
    validator = _validator("agent_head_by_ref_response_schema.json")
    assert not list(validator.iter_errors(body))
    assert list(validator.iter_errors({**body, "agent_id": "pk"}))
    assert list(validator.iter_errors({**body, "agent_ref": "pk-1"}))


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
            OPT / "agent_head_by_ref_response_schema.json",
            SCHEMAS / "execution" / "best_config_endpoints.json",
        ):
            assert forbidden not in path.read_text(encoding="utf-8")


def test_read_route_has_closed_errors_for_every_status_but_rate_limit():
    doc = _load("best_config_head_endpoints.json")
    get = doc["paths"]["/api/v1/best-configs/agent-heads/by-ref/{agent_ref}"]["get"]
    names = {p["name"]: p for p in get["parameters"]}
    assert names["agent_ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert names["environment"]["schema"]["$ref"].endswith("#/definitions/SessionEnvironment")
    for status in ("400", "401", "403", "404", "500"):
        schema = get["responses"][status]["content"]["application/json"]["schema"]
        assert schema["$ref"].endswith("best_config_head_refusal_schema.json"), status
    assert get["responses"]["429"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "rate_limit_info_schema.json"
    )
    assert "ORDER OF REFUSALS" in get["description"]


def _publish():
    doc = json.loads((SCHEMAS / "execution" / "best_config_endpoints.json").read_text())
    return doc["paths"]["/api/v1/best-configs"]["post"]


def test_publish_headers_and_applicability_decision_table():
    post = _publish()
    headers = {p["name"]: p for p in post["parameters"] if p["in"] == "header"}
    assert {"X-Traigent-Agent-Ref", "X-Traigent-Expected-Head-Generation"} <= set(headers)
    assert headers["X-Traigent-Agent-Ref"]["schema"]["$ref"].endswith("#/definitions/AgentRef")
    assert headers["X-Traigent-Expected-Head-Generation"]["schema"]["minimum"] == 0
    rule = post["description"]
    assert "if and only if" in rule and "content_less_v1" in rule and "content_less_v2" in rule
    rows = [f"[{n}]" for n in range(1, 9)]
    assert all(row in rule for row in rows)
    for needle in (
        "Agent-Ref and Agent-Id both present -> 400 head_capture_invalid",
        "Agent-Ref present, Expected-Head-Generation missing",
        "LEGACY, unchanged",
        "authoritative session binding",
        "ONE transaction",
        "exactly one wins",
    ):
        assert needle in rule, needle


def test_refusal_precedence_is_written_down():
    rule = _publish()["description"]
    order = [
        "400 head_capture_invalid",
        "404 reference_not_found",
        "403 head_write_unauthorized",
        "409 head_agent_mismatch",
        "409 head_environment_mismatch",
        "400 head_body_invalid",
        "409 head_generation_stale",
        "409 head_publish_conflict",
    ]
    positions = [rule.index(item, rule.index("ORDER OF REFUSALS")) for item in order]
    assert positions == sorted(positions)


PROTECTED_409 = ["head_environment_mismatch", "head_agent_mismatch", "head_generation_stale",
                 "head_publish_conflict"]


def _envelope_body(code):
    schema = _load("best_config_head_refusal_schema.json")
    branch = next(b for b in schema["oneOf"] if b["properties"]["error_code"]["const"] == code)
    props = branch["properties"]
    return {
        "success": False,
        "error": props["error"]["const"],
        "error_code": code,
        "message": props["message"]["const"],
    }


def _publish_409_validator():
    """The 409 schema of the execution endpoint, resolved as it is served (relative refs)."""
    registry = _registry().with_resource(
        BASE + "optimization/best_config_publish_409_schema.json",
        Resource.from_contents(_load("best_config_publish_409_schema.json")),
    )
    schema = _publish()["responses"]["409"]["content"]["application/json"]["schema"]
    base = BASE + "execution/best_config_endpoints.json"
    return Draft7Validator({"$id": base, **schema}, registry=registry)


def test_publish_409_has_two_disjoint_branches_and_other_statuses_are_closed():
    post = _publish()
    schema = post["responses"]["409"]["content"]["application/json"]["schema"]
    protected, legacy = schema["oneOf"]
    assert protected["$ref"].endswith("optimization/best_config_publish_409_schema.json")
    assert legacy["not"]["properties"]["error_code"]["enum"] == PROTECTED_409
    assert legacy["x-content-class"] == "legacy_content"
    for status in ("400", "404"):
        got = post["responses"][status]["content"]["application/json"]["schema"]
        assert got["$ref"].endswith("best_config_head_refusal_schema.json"), status


@pytest.mark.parametrize("code", PROTECTED_409)
def test_every_complete_protected_409_body_matches_exactly_one_branch(code):
    validator = _publish_409_validator()
    body = _envelope_body(code)
    assert not list(validator.iter_errors(body)), code  # oneOf: exactly one branch
    assert _validator("best_config_publish_409_schema.json").is_valid(body)  # the closed branch
    legacy = _publish()["responses"]["409"]["content"]["application/json"]["schema"]["oneOf"][1]
    assert not Draft7Validator(legacy).is_valid(body)  # and not the legacy branch


@pytest.mark.parametrize(
    "body",
    [
        {"success": False, "error": "If-Match is required to update an existing best config",
         "error_code": "BEST_CONFIG_CONFLICT",
         "message": "If-Match is required to update an existing best config"},
        {"success": False, "code": "STALE_HEAD_GENERATION", "error_code": "STALE_HEAD_GENERATION",
         "current_generation": 3, "expected_generation": 1, "error": "x", "message": "x"},
    ],
)
def test_legacy_409_bodies_are_still_valid(body):
    assert _publish_409_validator().is_valid(body)


@pytest.mark.parametrize("code", PROTECTED_409)
def test_a_malformed_protected_body_is_rejected(code):
    validator = _publish_409_validator()
    good = _envelope_body(code)
    for bad in (
        {**good, "message": "CANARY free text"},
        {**good, "extra": "member"},
        {**good, "error": "upgrade_required"},
        {k: v for k, v in good.items() if k != "message"},
    ):
        assert not validator.is_valid(bad), bad


def _publish_500_validator():
    registry = _registry().with_resource(
        BASE + "optimization/best_config_publish_500_schema.json",
        Resource.from_contents(_load("best_config_publish_500_schema.json")),
    )
    schema = _publish()["responses"]["500"]["content"]["application/json"]["schema"]
    base = BASE + "execution/best_config_endpoints.json"
    return Draft7Validator({"$id": base, **schema}, registry=registry)


# The body the Backend emits for an unchanged legacy publish that fails unexpectedly
# (src/routes/best_config_routes.py error_response(..., status=500, error_code="BEST_CONFIG_ERROR")
# through the 5xx branch of src/utils/response_handler.py).
LEGACY_500 = {"success": False, "message": "Internal server error", "error": "Internal server error",
              "error_code": "BEST_CONFIG_ERROR"}


def test_publish_500_has_two_disjoint_branches():
    schema = _publish()["responses"]["500"]["content"]["application/json"]["schema"]
    protected, legacy = schema["oneOf"]
    assert protected["$ref"].endswith("optimization/best_config_publish_500_schema.json")
    assert legacy["not"]["properties"]["error_code"]["enum"] == ["internal_error"]
    assert legacy["x-content-class"] == "legacy_content"


def test_protected_500_internal_error_matches_exactly_one_branch():
    body = _envelope_body("internal_error")
    assert _publish_500_validator().is_valid(body)  # oneOf: exactly one branch
    assert _validator("best_config_publish_500_schema.json").is_valid(body)  # the closed branch
    legacy = _publish()["responses"]["500"]["content"]["application/json"]["schema"]["oneOf"][1]
    assert not Draft7Validator(legacy).is_valid(body)  # and not the legacy branch


def test_legacy_500_body_validates_and_matches_exactly_one_branch():
    assert _publish_500_validator().is_valid(LEGACY_500)
    assert not _validator("best_config_publish_500_schema.json").is_valid(LEGACY_500)
    legacy = _publish()["responses"]["500"]["content"]["application/json"]["schema"]["oneOf"][1]
    assert Draft7Validator(legacy).is_valid(LEGACY_500)


def test_a_malformed_protected_500_is_rejected():
    validator = _publish_500_validator()
    good = _envelope_body("internal_error")
    for bad in (
        {**good, "message": "CANARY free text"},
        {**good, "extra": "member"},
        {**good, "error": "upgrade_required"},
        {k: v for k, v in good.items() if k != "message"},
    ):
        assert not validator.is_valid(bad), bad


# --- 401 / 403 of the protected publish: closed `unauthenticated` / `forbidden`, disjoint from legacy ---

LEGACY_401 = {"success": False, "message": "Authentication required",
              "error": "AUTHENTICATION_REQUIRED", "error_code": "AUTHENTICATION_REQUIRED"}
LEGACY_403 = {"success": False, "message": "Permission denied", "error": "PERMISSION_DENIED",
              "error_code": "PERMISSION_DENIED"}


def _auth_status_validator(status):
    registry = _registry().with_resource(
        BASE + f"optimization/best_config_publish_{status}_schema.json",
        Resource.from_contents(_load(f"best_config_publish_{status}_schema.json")),
    )
    schema = _publish()["responses"][status]["content"]["application/json"]["schema"]
    return Draft7Validator({"$id": BASE + "execution/best_config_endpoints.json", **schema},
                           registry=registry)


@pytest.mark.parametrize(
    ("status", "closed", "legacy_body"),
    [("401", ["unauthenticated"], LEGACY_401),
     ("403", ["forbidden", "head_write_unauthorized"], LEGACY_403)],
)
def test_publish_auth_statuses_have_two_disjoint_branches(status, closed, legacy_body):
    schema = _publish()["responses"][status]["content"]["application/json"]["schema"]
    protected, legacy = schema["oneOf"]
    assert protected["$ref"].endswith(f"optimization/best_config_publish_{status}_schema.json")
    assert legacy["not"]["properties"]["error_code"]["enum"] == CODES  # every closed code
    assert legacy["x-content-class"] == "legacy_content"
    validator = _auth_status_validator(status)
    for code in closed:
        body = _envelope_body(code)
        assert validator.is_valid(body)  # oneOf: exactly one branch
        assert not Draft7Validator(legacy).is_valid(body)
    assert validator.is_valid(legacy_body)
    assert not _validator(f"best_config_publish_{status}_schema.json").is_valid(legacy_body)


@pytest.mark.parametrize(
    ("status", "code", "other"),
    [("401", "unauthenticated", "forbidden"), ("403", "forbidden", "unauthenticated"),
     ("403", "head_write_unauthorized", "head_body_invalid")],
)
def test_publish_auth_statuses_reject_malformed_and_foreign_codes(status, code, other):
    validator = _auth_status_validator(status)
    good = _envelope_body(code)
    assert validator.is_valid(good)
    for bad in (
        {**good, "message": "CANARY free text"},
        {**good, "extra": "member"},
        {k: v for k, v in good.items() if k != "message"},
        _envelope_body(other),
    ):
        assert not validator.is_valid(bad), bad


# --- the authentication stage, the decision table and the refusal order agree (sol r5 P2) ---

def _post_description():
    return _publish()["description"]


def test_auth_envelope_predicate_is_the_agent_ref_header_alone():
    text = _post_description()
    stage = text[text.index("AUTHENTICATION STAGE"): text.index("DECISION TABLE")]
    assert "iff" not in stage and "if and only if the content-less identity layer is enabled and the request carries X-Traigent-Agent-Ref" in stage
    assert "before any session is resolved" in stage
    assert "Expected-Head-Generation and Agent-Id play no part" in stage
    # the response descriptions and the vendored envelopes state the same predicate, no other
    for status in ("401", "403"):
        desc = _publish()["responses"][status]["description"]
        assert "carries X-Traigent-Agent-Ref" in desc and "Expected-Head-Generation" not in desc
        assert "Expected-Head-Generation" not in _load(f"best_config_publish_{status}_schema.json")["description"]


def test_row_7_is_legacy_for_the_auth_stage_too():
    text = _post_description()
    assert "[7] No Agent-Ref, non-content-less or no session, Agent-Id and/or Expected-Head-Generation -> LEGACY, unchanged" in text
    stage = text[text.index("AUTHENTICATION STAGE"): text.index("DECISION TABLE")]
    assert "decision-table row [7]" in stage and "legacy generic 401/403" in stage
    assert "everything AFTER authentication" in stage


def test_known_content_less_session_without_header_gap_is_documented():
    text = _post_description()
    stage = text[text.index("AUTHENTICATION STAGE"): text.index("DECISION TABLE")]
    assert "KNOWN, ACCEPTED GAP" in stage and "row [6]" in stage
    assert "refused 400 head_capture_invalid" in stage
    assert "[6] No Agent-Ref, content-less session" in text and "-> 400 head_capture_invalid" in text


ORDER = ["401 unauthenticated", "403 forbidden", "400 head_capture_invalid", "404 reference_not_found",
         "403 head_write_unauthorized", "409 head_agent_mismatch", "409 head_environment_mismatch",
         "400 head_body_invalid", "409 head_generation_stale", "409 head_publish_conflict"]


def test_refusal_order_starts_with_auth_then_permission_then_capture():
    text = _post_description()
    order = text[text.index("ORDER OF REFUSALS"):]
    positions = [order.index(item) for item in ORDER]
    assert positions == sorted(positions), positions
    docs = (Path(__file__).resolve().parents[1] / "docs" / "content-classes.md").read_text()
    section = docs[docs.index("**Refusal precedence.**"):docs.index("## Scope and commands")]
    flat = " ".join(section.split()).replace("`", "")
    codes = ["401 unauthenticated", "403 forbidden", "400 head_capture_invalid", "404 reference_not_found",
             "403 head_write_unauthorized", "409 head_agent_mismatch", "409 head_environment_mismatch",
             "400 head_body_invalid", "409 head_generation_stale", "409 head_publish_conflict"]
    pos = [flat.index(c) for c in codes]
    assert pos == sorted(pos), pos
