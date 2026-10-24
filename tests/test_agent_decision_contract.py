"""Host-prompt decision request contract (agent_decision domain, TRAIG-109)."""

import copy
import json

import jsonschema
import pytest

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
DOMAIN = S / "agent_decision"


def _load(rel):
    return json.loads((S / rel).read_text(encoding="utf-8"))


def _validator(rel):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in S.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = "https://schemas.traigent.ai/" + path.relative_to(S).as_posix()
        registry = registry.with_resource(
            uri, Resource.from_contents(doc, default_specification=DRAFT7)
        )
    return jsonschema.Draft7Validator(_load(rel), registry=registry)


def _ok(rel, body):
    errors = list(_validator(rel).iter_errors(body))
    assert not errors, [e.message for e in errors]


def _bad(rel, body):
    assert list(_validator(rel).iter_errors(body))


DECISION = "agent_decision/agent_decision_schema.json"
ENSURE = "agent_decision/agent_decision_ensure_request_schema.json"
ANSWER = "agent_decision/agent_decision_answer_request_schema.json"
ENSURE_RESP = "agent_decision/agent_decision_ensure_response_schema.json"
ANSWER_RESP = "agent_decision/agent_decision_answer_response_schema.json"
LATEST_RESP = "agent_decision/agent_decision_latest_response_schema.json"
ERROR = "agent_decision/agent_decision_error_schema.json"

DIGEST = "sha256:" + "a" * 64


def _decision():
    return {
        "decision_id": "dr_" + "0" * 32,
        "kind": "PREPARE_BASELINE_EVALUATION",
        "prompt": {
            "question": "Prepare the baseline evaluation for this agent now?",
            "options": [
                {"code": "YES", "label": "Yes, prepare it"},
                {"code": "NOT_NOW", "label": "Not now"},
            ],
        },
        "options_version": "1",
        "policy_version": "1",
        "basis_digest": DIGEST,
        "status": "ANSWERED",
        "answer": "YES",
        "answered_at": "2026-10-25T10:00:00Z",
        "answered_via": "AGENT_HOST_PROMPT",
        "answered_principal_type": "API_KEY",
        "human_responder": "UNKNOWN",
        "execution_status": "AWAITING_PREFLIGHT",
        "execution_ref": "xr_" + "1" * 32,
        "next_action": "RUN_PREFLIGHT",
        "issued_at": "2026-10-25T09:00:00Z",
        "expires_at": "2026-10-26T09:00:00Z",
    }


def _open_decision():
    d = _decision()
    d.update(
        status="OPEN", answer=None, answered_at=None, answered_via=None,
        answered_principal_type=None, human_responder=None,
        execution_status="NOT_APPLICABLE", execution_ref=None, next_action="ASK_BUILDER",
    )
    return d


def test_full_valid_decision():
    _ok(DECISION, _decision())
    _ok(DECISION, _open_decision())


def test_unknown_keys_rejected_top_and_nested():
    d = _decision()
    d["extra"] = 1
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["extra"] = "x"
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["options"][0]["extra"] = "x"
    _bad(DECISION, d)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__("kind", "OTHER"),
        lambda d: d.__setitem__("answer", "MAYBE"),
        lambda d: d.__setitem__("status", "DONE"),
        lambda d: d["prompt"]["options"][0].__setitem__("code", "MAYBE"),
        lambda d: d.__setitem__("next_action", "GO"),
        lambda d: d.__setitem__("execution_status", "RUNNING"),
        lambda d: d.__setitem__("human_responder", "VERIFIED_SESSION_USER"),
        lambda d: d.__setitem__("answered_via", "EMAIL"),
        lambda d: d.__setitem__("answered_principal_type", "ADMIN"),
    ],
)
def test_out_of_domain_enums_rejected(mutate):
    d = _decision()
    mutate(d)
    _bad(DECISION, d)


@pytest.mark.parametrize(
    "field,value",
    [
        ("decision_id", "dr_xyz"),
        ("decision_id", "DR_" + "0" * 32),
        ("execution_ref", "xr_" + "g" * 32),
        ("basis_digest", "sha256:" + "a" * 63),
        ("basis_digest", "md5:" + "a" * 64),
        ("options_version", "12345"),
        ("policy_version", "v1"),
    ],
)
def test_bad_patterns_rejected(field, value):
    d = _decision()
    d[field] = value
    _bad(DECISION, d)


def test_prompt_option_bounds():
    d = _decision()
    d["prompt"]["options"] = d["prompt"]["options"][:1]
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["question"] = "q" * 201
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["options"][0]["label"] = "l" * 41
    _bad(DECISION, d)


def test_ensure_request():
    _ok(ENSURE, {"kind": "PREPARE_BASELINE_EVALUATION"})
    _bad(ENSURE, {"kind": "PREPARE_BASELINE_EVALUATION", "extra": 1})
    _bad(ENSURE, {"kind": "OTHER"})
    _bad(ENSURE, {})


def test_answer_request():
    good = {
        "answer": "NOT_NOW", "options_version": "1", "policy_version": "1",
        "basis_digest": DIGEST, "retry_nonce": "rn_" + "2" * 32,
    }
    _ok(ANSWER, good)
    _bad(ANSWER, {**good, "extra": "free text"})
    for k in good:
        missing = copy.deepcopy(good)
        del missing[k]
        _bad(ANSWER, missing)
    _bad(ANSWER, {**good, "answer": "MAYBE"})


def test_response_envelopes():
    for rel in (ENSURE_RESP, ANSWER_RESP, LATEST_RESP):
        _bad(rel, {})
        _bad(rel, {"decision": _decision(), "extra": 1})
        _bad(rel, {"decision": {**_decision(), "extra": 1}})
    _ok(ENSURE_RESP, {"decision": _open_decision()})
    _ok(ENSURE_RESP, {"decision": None})
    _bad(ENSURE_RESP, {"decision": _decision()})
    _ok(ANSWER_RESP, {"decision": _decision()})
    _bad(ANSWER_RESP, {"decision": _open_decision()})
    _bad(ANSWER_RESP, {"decision": None})
    for d in (_decision(), _open_decision(), None):
        _ok(LATEST_RESP, {"decision": d})


def test_error_body():
    _ok(ERROR, {"error": {"reason": "STALE_BASIS"}})
    for r in ("UNAUTHENTICATED", "FORBIDDEN"):
        _ok(ERROR, {"error": {"reason": r}})
    _ok(ERROR, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": 30}})
    _bad(ERROR, {"error": {"reason": "FORBIDDEN", "retry_after_seconds": 30}})
    _bad(ERROR, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": 86401}})
    _bad(ERROR, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": -1}})
    _bad(ERROR, {"error": {"reason": "RATE_LIMITED"}})
    _bad(ERROR, {"error": {"reason": "SOMETHING_ELSE"}})
    _bad(ERROR, {"error": {"reason": "STALE_BASIS", "detail": "echo"}})
    _bad(ERROR, {"error": {"reason": "STALE_BASIS"}, "extra": 1})


RATE_LIMITED = "agent_decision/agent_decision_rate_limited_error_schema.json"


def test_rate_limited_body_is_closed_and_requires_retry_after():
    _ok(RATE_LIMITED, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": 5}})
    _bad(RATE_LIMITED, {"error": {"reason": "RATE_LIMITED"}})
    _bad(RATE_LIMITED, {"error": {"reason": "FORBIDDEN", "retry_after_seconds": 5}})
    _bad(RATE_LIMITED, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": 86401}})
    _bad(RATE_LIMITED, {"error": {"reason": "RATE_LIMITED", "retry_after_seconds": 1, "x": 1}})


def _state(status, **kw):
    d = _open_decision()
    d["status"] = status
    d.update(kw)
    return d


def _not_now():
    return _decision() | {
        "answer": "NOT_NOW", "execution_status": "NOT_APPLICABLE",
        "execution_ref": None, "next_action": "NONE",
    }


def test_valid_lifecycle_states():
    _ok(DECISION, _open_decision())
    _ok(DECISION, _state("EXPIRED", next_action="NONE"))
    _ok(DECISION, _state("SUPERSEDED", next_action="NONE"))
    _ok(DECISION, _not_now())
    _ok(DECISION, _decision())
    for es in ("STARTED", "COMPLETED", "FAILED"):
        _ok(DECISION, _decision() | {"execution_status": es, "next_action": "NONE"})
    _ok(DECISION, _decision() | {"answered_principal_type": "USER_SESSION",
                                 "answered_via": "AGENT_HOST_PROMPT"})


@pytest.mark.parametrize(
    "mutate",
    [
        lambda: _open_decision() | {"answer": "YES"},
        lambda: _open_decision() | {"execution_ref": "xr_" + "1" * 32},
        lambda: _open_decision() | {"next_action": "NONE"},
        lambda: _state("EXPIRED", next_action="NONE") | {"answer": "YES"},
        lambda: _state("SUPERSEDED", next_action="NONE") | {"answered_at": "2026-10-25T10:00:00Z"},
        lambda: _state("EXPIRED"),  # next_action must be NONE
        lambda: _not_now() | {"next_action": "RUN_PREFLIGHT"},
        lambda: _not_now() | {"execution_ref": "xr_" + "1" * 32},
        lambda: _not_now() | {"execution_status": "STARTED"},
        lambda: _decision() | {"execution_ref": None},
        lambda: _decision() | {"execution_status": "NOT_APPLICABLE"},
        lambda: _decision() | {"next_action": "NONE"},
        lambda: _decision() | {"execution_status": "STARTED"},  # RUN_PREFLIGHT only awaiting
        lambda: _decision() | {"answer": None},
        lambda: _decision() | {"answered_at": None},
        lambda: _decision() | {"human_responder": None},
        lambda: _decision() | {"human_responder": "VERIFIED_SESSION_USER"},
        lambda: _decision() | {"retry_nonce": "rn_" + "2" * 32},
        lambda: _decision() | {"issued_at": "Alice_has_diabetes"},
        lambda: _decision() | {"expires_at": "2026-10-25 10:00:00"},
        lambda: _decision() | {"expires_at": "2026-10-25T10:00:00+02:00"},
        lambda: _decision() | {"answered_at": "Alice_has_diabetes"},
    ],
)
def test_lifecycle_invariants_rejected(mutate):
    _bad(DECISION, mutate())


def test_prompt_and_versions_are_pinned():
    d = _decision()
    d["prompt"]["options"][1] = {"code": "YES", "label": "Not now"}
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["options"][1] = {"code": "YES", "label": "Yes, prepare it"}
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["question"] = "Prepare the baseline evaluation for Alice's agent?"
    _bad(DECISION, d)
    d = _decision()
    d["prompt"]["options"].reverse()
    _bad(DECISION, d)
    _bad(DECISION, _decision() | {"options_version": "2"})
    _bad(DECISION, _decision() | {"policy_version": "2"})


def _walk(node, path=""):
    if isinstance(node, dict):
        if node.get("type") == "object" or (
            isinstance(node.get("type"), list) and "object" in node["type"]
        ):
            yield path, node
        for k, v in node.items():
            yield from _walk(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}/{i}")


def test_every_object_in_domain_is_closed():
    files = sorted(DOMAIN.glob("*_schema.json"))
    assert len(files) == 8
    for f in files:
        for path, node in _walk(json.loads(f.read_text(encoding="utf-8"))):
            assert node.get("additionalProperties") is False, f"{f.name}{path}"


def test_endpoints_wire_schemas():
    cat = _load("agent_decision/agent_decision_endpoints.json")
    base = "/api/v1beta/agent-decisions/"
    ens = cat["paths"][base + "{agent_id}/ensure"]["post"]
    assert ens["requestBody"]["content"]["application/json"]["schema"]["$ref"] == (
        "./agent_decision_ensure_request_schema.json"
    )
    assert "get" in cat["paths"][base + "{agent_id}/latest"]
    ans = cat["paths"][base + "{decision_id}/answer"]["post"]
    assert set(ans["responses"]) == {"200", "401", "403", "404", "409", "410", "422", "429", "503"}
    for op in (ens, ans):
        assert op["x-required-permission"] == "experiment.write"
        for code, resp in op["responses"].items():
            ref = resp["content"]["application/json"]["schema"]["$ref"]
            assert ref.endswith(
                "response_schema.json" if code == "200" else "error_schema.json"
            )
        assert {"401", "403", "429"} <= set(op["responses"])
        assert op["responses"]["429"]["content"]["application/json"]["schema"]["$ref"] == (
            "./agent_decision_rate_limited_error_schema.json"
        )


def test_session_create_carries_optional_execution_ref():
    cat = _load("optimization/optimization_endpoints.json")
    schema = cat["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    prop = schema["properties"]["decision_execution_ref"]
    assert "decision_execution_ref" not in schema["required"]
    assert prop["pattern"] == "^xr_[0-9a-f]{32}$"
    assert "null" in prop["type"]


def test_answer_nonce_pattern_and_bounds():
    good = {
        "answer": "YES", "options_version": "1", "policy_version": "1",
        "basis_digest": DIGEST, "retry_nonce": "rn_" + "2" * 32,
    }
    _ok(ANSWER, good)
    for bad in ("rn_" + "2" * 31, "rn_" + "G" * 32, "xx_" + "2" * 32, "rn_" + "2" * 33):
        _bad(ANSWER, {**good, "retry_nonce": bad})
    assert _load(ANSWER)["properties"]["retry_nonce"]["maxLength"] == 35
    assert "CLIENT-generated" in _load(ANSWER)["properties"]["retry_nonce"]["description"]


def test_timestamps_accept_rfc3339_utc():
    _ok(DECISION, _decision() | {"issued_at": "2026-10-25T09:00:00.123456Z"})


def test_error_reasons_include_agent_not_found():
    _ok(ERROR, {"error": {"reason": "AGENT_NOT_FOUND"}})


def test_endpoint_semantics_text_and_params():
    cat = _load("agent_decision/agent_decision_endpoints.json")
    base = "/api/v1beta/agent-decisions/"
    ens = cat["paths"][base + "{agent_id}/ensure"]["post"]
    lat = cat["paths"][base + "{agent_id}/latest"]["get"]
    ans = cat["paths"][base + "{decision_id}/answer"]["post"]
    assert "AGENT_NOT_FOUND" in ens["responses"]["404"]["description"]
    assert "AGENT_NOT_FOUND" in lat["responses"]["404"]["description"]
    assert ans["responses"]["404"]["description"] == "DECISION_NOT_FOUND."
    assert "STALE_BASIS" not in ens["description"]
    assert "STALE_BASIS" not in ens["responses"]["409"]["description"]
    assert "call latest" in ens["description"]
    assert "FAILED" in ens["description"]
    for text in (
        "same principal AND same nonce AND same body",
        "keyed digest",
        "DECISION_ALREADY_ANSWERED",
    ):
        assert text in ans["description"]
    pid = ans["parameters"][0]["schema"]
    assert pid["pattern"] == "^dr_[0-9a-f]{32}$"


def test_session_ref_description_states_linking_rules():
    cat = _load("optimization/optimization_endpoints.json")
    schema = cat["paths"]["/api/v1/sessions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    desc = schema["properties"]["decision_execution_ref"]["description"]
    for text in ("never blocked", "same tenant, project and agent", "never echoed"):
        assert text in desc


def test_decision_domain_is_a_content_class_lint_root():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    text = (root / "scripts" / "content_class_lint.py").read_text(encoding="utf-8")
    for f in sorted(DOMAIN.glob("*.json")):
        assert f'"agent_decision/{f.name}"' in text
