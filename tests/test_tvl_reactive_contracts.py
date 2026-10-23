"""TRAIG-101 S1: closed wire contracts of the TVL 1.4 reactive layer.

GNFR-PRIV-002(f) expansion.
"""

import copy
import json
import re
from pathlib import Path

import pytest

from tests._schema_refs import build_registry, ref_errors
from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
OPT = SCHEMAS / "optimization"
EXE = SCHEMAS / "execution"
REGISTRY = build_registry()
B = "https://schemas.traigent.ai/"
REACTIVE_DOCS = sorted(OPT.glob("tvl_reactive_*_schema.json")) + [
    EXE / "best_config_deploy_schema.json"
]
POLICY_CATALOG = SCHEMAS / "production_requirements" / "tvl_reactive_policy_endpoints.json"
CATALOGS = [
    OPT / "tvl_reactive_endpoints.json",
    POLICY_CATALOG,
    EXE / "best_config_deploy_endpoints.json",
    EXE / "best_config_agent_head_config_endpoints.json",
]

TOK = "t" + "A1_-" * 4
TOK2 = "t" + "b2c3" * 4
H64 = "a" * 64
H64B = "b" * 64
KEY = "0123456789abcdef0123456789abcdef"


def ref(name, **parts):
    return lambda inst: ref_errors(REGISTRY, f"{B}{name}", inst)


def v(doc, definition):
    return lambda inst: ref_errors(
        REGISTRY, f"{B}optimization/{doc}.json#/definitions/{definition}", inst
    )


def vx(doc, definition):
    return lambda inst: ref_errors(
        REGISTRY, f"{B}execution/{doc}.json#/definitions/{definition}", inst
    )


def r(kind):
    return f"{kind}ref_" + "0123456789abcdef" * 2


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ structural closure
def _walk(node, path=""):
    yield path, node
    if isinstance(node, dict):
        for k, val in node.items():
            if k in ("description", "enum", "const", "required", "default"):
                continue
            yield from _walk(val, f"{path}/{k}")
    elif isinstance(node, list):
        for i, val in enumerate(node):
            yield from _walk(val, f"{path}/{i}")


def _value_nodes(doc):
    """Property / item schemas: every node reached through properties, items or definitions."""
    for path, node in _walk(doc):
        if not isinstance(node, dict):
            continue
        parent = path.rsplit("/", 2)
        if len(parent) >= 2 and (
            path.rsplit("/", 2)[-2] in ("properties", "definitions") or path.endswith("/items")
        ):
            yield path, node


@pytest.mark.parametrize("path", REACTIVE_DOCS, ids=lambda p: p.name)
def test_every_value_is_bounded_and_closed(path):
    doc = load(path)
    problems = []
    for p, node in _walk(doc):
        if not isinstance(node, dict):
            continue
        t = node.get("type")
        if (
            node.get("type") == "object"
            or "properties" in node
            and "oneOf" not in node
            and "type" in node
        ):
            if node.get("additionalProperties") is not False:
                problems.append(f"{p}: object not closed")
        if t == "array" and "maxItems" not in node:
            problems.append(f"{p}: array without maxItems")
        types = t if isinstance(t, list) else [t]
        if "integer" in types and "const" not in node and "enum" not in node:
            if "minimum" not in node or "maximum" not in node:
                problems.append(f"{p}: integer without bounds")
        if "string" in types and not any(k in node for k in ("enum", "const")):
            if "pattern" not in node and node.get("format") != "date-time":
                problems.append(f"{p}: free string")
            if "maxLength" not in node:
                problems.append(f"{p}: string without maxLength")
        if "number" in types:
            problems.append(f"{p}: floating number (use bounded integers)")
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("path", REACTIVE_DOCS[:-1], ids=lambda p: p.name)
def test_every_value_carries_a_content_class(path):
    doc = load(path)
    missing = []
    for p, node in _walk(doc):
        if not isinstance(node, dict) or "$ref" in node:
            continue
        t = node.get("type")
        types = t if isinstance(t, list) else [t]
        leaf = (
            any(x in ("string", "integer", "boolean") for x in types)
            or "enum" in node
            or "const" in node
        )
        if (
            leaf
            and "x-content-class" not in node
            and not p.endswith("/allOf/0")
            and "/not/" not in p + "/"
            and "/if/" not in p + "/"
        ):
            missing.append(p)
    # branch re-constraints (oneOf/if/else) legitimately repeat a class; the lint walks those too
    assert not missing, "\n".join(missing)


def test_no_customer_chosen_name_fields():
    banned = re.compile(
        r"(^|_)(name|label|title|message_text|prompt|description_text|config_id|function_ref)$"
    )
    for path in REACTIVE_DOCS[:-1]:
        for p, node in _walk(load(path)):
            if "/properties/" in p and p.rsplit("/", 1)[-1] and isinstance(node, dict):
                assert not banned.search(p.rsplit("/", 1)[-1]), f"{path.name}{p}"


# ------------------------------------------------------------------ common
def test_hosted_token_is_the_minted_shape_only():
    tok = v("tvl_reactive_common_schema", "HostedToken")
    assert not tok(TOK)
    for bad in (
        "",
        "x" * 17,
        "Alice_has_diabetes",
        "t" + "a" * 15,
        "t" + "a" * 17,
        "t" + "a" * 15 + "!",
        "T" + "a" * 16,
    ):
        assert tok(bad), bad


def test_digest_key_and_ref_shapes():
    assert not v("tvl_reactive_common_schema", "Digest")(H64)
    assert v("tvl_reactive_common_schema", "Digest")("sha256:" + H64)
    assert not v("tvl_reactive_common_schema", "IdempotencyKey")(KEY)
    for bad in (KEY.upper(), KEY[:-1], "Alice_has_diabetes_" + "0" * 13):
        assert v("tvl_reactive_common_schema", "IdempotencyKey")(bad)
    for d, kind in (
        ("PolicyRevisionRef", "policyrevision"),
        ("AttemptRef", "attempt"),
        ("GrantRef", "grant"),
        ("ReservationRef", "reservation"),
        ("NotificationRef", "notification"),
    ):
        f = v("tvl_reactive_common_schema", d)
        assert not f(r(kind))
        assert f(r("other")) and f(kind + "ref_" + "g" * 32) and f("x")


def test_instants_are_bounded_integers():
    h = v("tvl_reactive_common_schema", "Hours")
    assert not h(0) and not h(1000000000)
    for bad in (-1, 1000000001, 1.5, "1", True, None):
        assert h(bad), bad


# ------------------------------------------------------------------ refusals
def test_refusal_is_one_fixed_branch_per_code_and_never_echoes():
    schema = load(OPT / "tvl_reactive_common_schema.json")["definitions"]["Refusal"]
    codes = schema["properties"]["error_code"]["enum"]
    msgs = schema["properties"]["message"]["enum"]
    assert len(codes) == len(set(codes)) == len(msgs) == len(schema["oneOf"])
    for code, msg, br in zip(codes, msgs, schema["oneOf"], strict=True):
        assert (
            br["properties"]["error_code"]["const"] == code
            and br["properties"]["message"]["const"] == msg
        )
        assert "{" not in msg and "%" not in msg
    f = v("tvl_reactive_common_schema", "Refusal")
    ok = {
        "success": False,
        "error": "instant_sealed",
        "error_code": "instant_sealed",
        "message": "Instant is sealed.",
    }
    assert not f(ok)
    assert (
        f({**ok, "message": "Internal error."})
        and f({**ok, "details": "x"})
        and f({**ok, "success": True})
    )
    for needed in (
        "batch_out_of_order",
        "instant_not_increasing",
        "evaluation_inputs_frozen",
        "instant_sealed",
        "fact_contradicts_record",
        "fact_source_not_permitted",
        "head_generation_stale",
        "publication_cancelled",
    ):
        assert needed in codes


# ------------------------------------------------------------------ facts
def window(**o):
    return {"monitor": TOK, "start": 0, "end": 24, "verdict": "MET", "usable": True, **o}


def test_window_unknown_reason_only_with_unknown():
    f = v("tvl_reactive_facts_schema", "WindowFact")
    assert not f(window()) and not f(window(verdict="BREACHED"))
    assert not f(window(verdict="UNKNOWN")) and not f(
        window(verdict="UNKNOWN", unknown_reason="insufficient")
    )
    assert f(window(unknown_reason="insufficient")) and f(
        window(verdict="UNKNOWN", unknown_reason="free text")
    )
    assert f(window(verdict="met")) and f(window(extra=1)) and f(window(start=-1))


def test_episode_reason_only_on_close():
    f = v("tvl_reactive_facts_schema", "EpisodeFact")
    base = {"monitor": TOK, "scope": TOK2}
    assert not f({**base, "event": "opened"}) and not f({**base, "event": "continued"})
    assert not f({**base, "event": "closed", "reason": "resolved"}) and not f(
        {**base, "event": "closed", "reason": "withdrawn"}
    )
    assert f({**base, "event": "closed"}) and f({**base, "event": "opened", "reason": "resolved"})
    assert f({**base, "event": "closed", "reason": "timeout"})


def opt(fact, **o):
    base = {
        "response": TOK,
        "revision": H64,
        "rule": TOK2,
        "scope": TOK,
        "occurrence": 0,
        "fact": fact,
    }
    return {**base, **o}


VALID_OPT = {
    "fired": opt("fired"),
    "started": opt("started"),
    "finished": opt("finished", completion="normal", candidates=[]),
    "approval": opt("approval", effect="optimize", state="granted"),
    "authority": opt("authority", state="unreachable"),
    "deploy_started": opt("deploy_started"),
    "deploy_result": opt(
        "deploy_result", checks="passed", write="succeeded", retries_exhausted=False
    ),
}


@pytest.mark.parametrize("kind", sorted(VALID_OPT))
def test_each_optimization_fact_has_exactly_its_fields(kind):
    f = v("tvl_reactive_facts_schema", "OptimizationFact")
    assert not f(VALID_OPT[kind])
    assert f({**VALID_OPT[kind], "free": "x"})
    for other, inst in VALID_OPT.items():
        if other == kind:
            continue
        extras = {k: val for k, val in inst.items() if k not in VALID_OPT["fired"]}
        if extras and not set(extras) <= set(VALID_OPT[kind]):
            assert f({**VALID_OPT[kind], **extras}), f"{kind} accepted {other}'s fields"


def test_optimization_fact_field_rules():
    f = v("tvl_reactive_facts_schema", "OptimizationFact")
    assert f(opt("finished", completion="normal"))  # candidates required
    assert f(opt("finished", completion="other", candidates=[]))
    assert f(opt("approval", effect="optimize", state="reachable"))
    assert f(opt("authority", state="granted"))
    assert f(opt("deploy_result", checks="refused", write="succeeded", retries_exhausted=False))
    assert not f(
        opt("deploy_result", checks="refused", write="not_attempted", retries_exhausted=False)
    )
    assert f(opt("deploy_result", checks="passed", write="succeeded", retries_exhausted="no"))
    assert (
        f(opt("fired", occurrence=-1))
        and f(opt("fired", revision="rev-1"))
        and f(opt("fired", scope="Alice has diabetes"))
    )


def test_candidates_valid_and_invalid_evidence():
    c = v("tvl_reactive_facts_schema", "Candidate")
    assert not c(
        {
            "evidence_valid": True,
            "legacy_decision": "Promote",
            "monitor_verdicts": ["MET", "UNKNOWN(insufficient)"],
            "fingerprint": H64,
            "gate_result_digest": H64B,
        }
    )
    assert not c({"evidence_valid": False})
    assert c({"evidence_valid": True}) and c(
        {"evidence_valid": False, "legacy_decision": "Promote"}
    )
    assert c(
        {
            "evidence_valid": True,
            "legacy_decision": "Promote",
            "monitor_verdicts": ["UNKNOWN(because I said so)"],
        }
    )
    assert c(
        {"evidence_valid": True, "legacy_decision": "Promote", "monitor_verdicts": ["MET"] * 33}
    )


# ------------------------------------------------------------------ stage / complete
def stage(**o):
    return {
        "schema_version": 1,
        "stage_key": KEY,
        "policy_revision_ref": r("policyrevision"),
        "environment": TOK,
        "producer_kind": "customer_monitor",
        **o,
    }


def test_stage_request_is_closed_and_bounded():
    f = v("tvl_reactive_stage_schema", "EvaluationStageRequest")
    assert not f(stage())
    assert not f(
        stage(
            windows=[window()],
            episodes=[{"monitor": TOK, "scope": TOK2, "event": "opened"}],
            revisions=[{"kind": "monitor", "target": TOK, "value": H64}],
            liveness=[{"monitor": TOK, "event": "stale", "scope": TOK2}],
            optimizations=[VALID_OPT["fired"]],
        )
    )
    assert (
        f(stage(extra=1))
        and f(stage(producer_kind="backend_native"))
        and f(stage(environment="production"))
    )
    assert not f(stage(windows=[window()] * 256)) and f(stage(windows=[window()] * 257))
    assert f(stage(optimizations=[VALID_OPT["fired"]] * 257)) and f(
        stage(windows=[{**window(), "note": "x"}])
    )


def test_complete_request_rules():
    f = v("tvl_reactive_stage_schema", "EvaluationCompleteRequest")
    base = {
        "schema_version": 1,
        "complete_key": KEY,
        "policy_revision_ref": r("policyrevision"),
        "environment": TOK,
    }
    assert not f(
        {
            **base,
            "producer_kind": "customer_monitor",
            "monitor": TOK,
            "completed_through_end": 24,
            "disposition": "complete",
        }
    )
    assert not f({**base, "producer_kind": "optimization_reporter", "disposition": "defer"})
    assert not f({**base, "producer_kind": "optimization_reporter", "disposition": "complete"})
    assert f({**base, "producer_kind": "customer_monitor", "disposition": "complete"})
    assert f(
        {
            **base,
            "producer_kind": "customer_monitor",
            "monitor": TOK,
            "completed_through_end": 24,
            "disposition": "defer",
        }
    )
    assert f(
        {
            **base,
            "producer_kind": "optimization_reporter",
            "disposition": "complete",
            "monitor": TOK,
        }
    )
    assert f({**base, "producer_kind": "native", "disposition": "complete"})


# ------------------------------------------------------------------ authority
def grant(**o):
    return {
        "schema_version": 1,
        "grant_key": KEY,
        "attempt_ref": r("attempt"),
        "contract_digest": H64,
        **o,
    }


OPTIMIZE = dict(
    effect="optimize",
    decision="granted",
    duration_hours=1,
    ceiling={"max_trials": 10, "max_cost_micro_usd": 5000000},
)
DEPLOY = dict(
    effect="deploy",
    decision="granted",
    duration_hours=4,
    deploy={
        "candidate_fingerprint": H64,
        "gate_result_digest": H64B,
        "expected_head_generation": 3,
    },
)


def test_grant_create_shapes():
    f = v("tvl_reactive_authority_schema", "GrantCreateRequest")
    assert not f(grant(**OPTIMIZE)) and not f(grant(**DEPLOY))
    assert not f(grant(effect="optimize", decision="declined")) and not f(
        grant(effect="deploy", decision="declined")
    )
    assert f(grant(**{**OPTIMIZE, "duration_hours": 2})) and f(
        grant(**{**OPTIMIZE, "duration_hours": 0})
    )
    assert f(grant(**{**OPTIMIZE, "deploy": DEPLOY["deploy"]})) and f(
        grant(**{**DEPLOY, "ceiling": OPTIMIZE["ceiling"]})
    )
    assert f(grant(effect="optimize", decision="granted")) and f(
        grant(effect="optimize", decision="declined", duration_hours=1)
    )
    assert f(grant(**{**OPTIMIZE, "standing": True})) and f(
        grant(**{**OPTIMIZE, "approval": "standing"})
    )


def test_reservation_start_results_cancel():
    assert not v("tvl_reactive_authority_schema", "ReservationRequest")(
        {"schema_version": 1, "reservation_key": KEY, "grant_ref": r("grant")}
    )
    s = v("tvl_reactive_authority_schema", "StartRequest")
    assert not s(
        {
            "schema_version": 1,
            "start_key": KEY,
            "reservation_ref": r("reservation"),
            "reservation_generation": 1,
        }
    )
    assert s({"schema_version": 1, "start_key": KEY, "reservation_ref": r("reservation")})
    o = v("tvl_reactive_authority_schema", "EffectOutcomeRequest")
    base = {
        "schema_version": 1,
        "result_key": KEY,
        "reservation_ref": r("reservation"),
        "reservation_generation": 1,
    }
    assert not o({**base, "fact": "finished", "completion": "cost_limit", "candidates": []})
    assert not o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "refused",
            "write": "not_attempted",
            "retries_exhausted": False,
        }
    )
    assert not o({**base, "fact": "authority", "state": "reachable"})
    pk = KEY_D
    ok_s = {
        **base,
        "fact": "deploy_result",
        "checks": "passed",
        "write": "succeeded",
        "retries_exhausted": False,
        "publish_result_key": pk,
    }
    ok_f = {
        **base,
        "fact": "deploy_result",
        "checks": "passed",
        "write": "failed",
        "retries_exhausted": True,
        "publish_result_key": pk,
    }
    ok_r = {
        **base,
        "fact": "deploy_result",
        "checks": "refused",
        "write": "not_attempted",
        "retries_exhausted": False,
    }
    assert not o(ok_s) and not o(ok_f) and not o(ok_r)
    assert not o({**ok_r, "checks": "unreachable"})
    assert o({**ok_f, "retries_exhausted": False})  # failed needs the retry bound reached
    assert o({**ok_s, "retries_exhausted": True})
    assert o({**ok_f, "checks": "refused"}) and o({**ok_s, "checks": "unreachable"})
    assert o(
        {**ok_r, "checks": "passed"}
    )  # passed with no write attempted is not a valid terminal result
    assert o({**ok_r, "write": "failed"}) and o({**ok_r, "retries_exhausted": True})
    assert not o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "passed",
            "write": "succeeded",
            "retries_exhausted": False,
            "publish_result_key": pk,
        }
    )
    assert not o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "passed",
            "write": "failed",
            "retries_exhausted": True,
            "publish_result_key": pk,
        }
    )
    assert o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "passed",
            "write": "succeeded",
            "retries_exhausted": False,
        }
    )
    assert o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "passed",
            "write": "failed",
            "retries_exhausted": True,
        }
    )
    assert not o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "refused",
            "write": "not_attempted",
            "retries_exhausted": False,
        }
    )
    assert o(
        {
            **base,
            "fact": "deploy_result",
            "checks": "refused",
            "write": "not_attempted",
            "retries_exhausted": False,
            "publish_result_key": pk,
        }
    )
    assert o(
        {
            **base,
            "fact": "finished",
            "completion": "normal",
            "candidates": [],
            "publish_result_key": pk,
        }
    )
    assert o({**base, "fact": "started"}) and o(
        {**base, "fact": "finished", "completion": "normal"}
    )
    assert o({**base, "fact": "authority", "state": "reachable", "completion": "normal"})
    c = v("tvl_reactive_authority_schema", "CancelRequest")
    assert not c(
        {
            "schema_version": 1,
            "cancel_key": KEY,
            "effect": "optimize",
            "confirmation": "process_gone",
        }
    )
    assert c(
        {"schema_version": 1, "cancel_key": KEY, "effect": "deploy", "confirmation": "process_gone"}
    )
    assert c({"schema_version": 1, "cancel_key": KEY, "confirmation": "process_gone"})
    assert c({"schema_version": 1, "cancel_key": KEY, "effect": "optimize", "confirmation": "yes"})


def test_read_models_are_closed():
    notif = {
        "schema_version": 1,
        "notification_ref": r("notification"),
        "policy_revision_ref": r("policyrevision"),
        "response": TOK,
        "rule": TOK2,
        "event": "unknown_for",
        "scope": TOK,
        "occurrence_index": 0,
        "repeat_index": 0,
        "evaluation_instant": 24,
        "decision": "suppressed",
        "guards": [
            {"kind": "monitor_episode_open", "monitor": TOK, "list": "unless", "value": "TRUE"},
            {"kind": "rule_attempt_open", "rule": TOK2, "list": "only_while", "value": "UNDECIDED"},
        ],
        "evidence_source": "recorded_by_customer",
        "producers_missing": False,
        "recorded_at": "2026-10-22T10:00:00Z",
    }
    f = v("tvl_reactive_notification_schema", "Notification")
    assert not f(notif)
    assert (
        f({**notif, "title": "x"})
        and f({**notif, "event": "deploy_held"})
        and f({**notif, "decision": "sent"})
    )
    g = copy.deepcopy(notif)
    g["guards"][0]["rule"] = TOK
    assert f(g)
    page = v("tvl_reactive_notification_schema", "NotificationPage")
    assert not page({"schema_version": 1, "items": [notif], "next_after": None}) and page(
        {"schema_version": 1, "items": [notif] * 101, "next_after": 1}
    )
    attempt = {
        "schema_version": 1,
        "attempt_ref": r("attempt"),
        "policy_revision_ref": r("policyrevision"),
        "response": TOK,
        "rule": TOK2,
        "scope": TOK,
        "occurrence": 0,
        "effect": "deploy",
        "state": "lapsed",
        "optimize_outcome": "promoted",
        "deploy_outcome": "none",
        "lapsed": True,
        "opened_at": "2026-10-22T10:00:00Z",
    }
    a = v("tvl_reactive_authority_schema", "Attempt")
    assert (
        not a(attempt)
        and a({**attempt, "deploy_outcome": "deploy_held"})
        and a({**attempt, "state": "hold"})
    )
    gr = {
        "schema_version": 1,
        "grant_ref": r("grant"),
        "attempt_ref": r("attempt"),
        "policy_revision_ref": r("policyrevision"),
        "effect": "optimize",
        "state": "granted",
        "contract_digest": H64,
        "decided_by": "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f",
        "decided_at": "2026-10-22T10:00:00Z",
        "expires_at": "2026-10-22T11:00:00Z",
    }
    assert not v("tvl_reactive_authority_schema", "Grant")(gr) and v(
        "tvl_reactive_authority_schema", "Grant"
    )({**gr, "decided_by": "Nimrod"})


# ------------------------------------------------------------------ deploy
KEY_D = f"deploy:{r('attempt')}:{H64}:{H64B}"


def test_deploy_key_result_and_finalize():
    k = vx("best_config_deploy_schema", "DeployIdempotencyKey")
    assert (
        not k(KEY_D)
        and k("deploy:x:y:z")
        and k(KEY_D + "0")
        and k(KEY_D.replace("attemptref_", "grantref_"))
    )
    res = vx("best_config_deploy_schema", "DeployPublishResult")
    ok = {
        "schema_version": 1,
        "idempotency_key": KEY_D,
        "state": "succeeded",
        "head_generation": 4,
        "pinned_version": 2,
        "decided_at": "2026-10-22T10:00:00Z",
    }
    assert not res(ok)
    assert not res({**ok, "state": "cancelled", "head_generation": None, "pinned_version": None})
    assert not res(
        {
            **ok,
            "state": "pending",
            "head_generation": None,
            "pinned_version": None,
            "decided_at": None,
        }
    )
    assert res({**ok, "state": "cancelled"}) and res(
        {**ok, "state": "succeeded", "head_generation": None}
    )
    assert res({**ok, "state": "failed"}) and res({**ok, "config": {}})
    assert not vx("best_config_deploy_schema", "DeployFinalizeRequest")({"schema_version": 1})
    assert vx("best_config_deploy_schema", "DeployFinalizeRequest")(
        {"schema_version": 1, "force": True}
    )


def test_pinned_read_response_declares_content_and_generation():
    doc = load(EXE / "best_config_agent_head_config_schema.json")
    resp = doc["definitions"]["AgentHeadConfigResponse"]
    assert resp["additionalProperties"] is False and set(resp["required"]) == {
        "schema_version",
        "generation",
        "version",
        "spec",
    }
    assert "customer content" in resp["properties"]["spec"]["description"].lower()
    assert "customer content" in doc["description"].lower()


# ------------------------------------------------------------------ catalogs
def _entries(node):
    if isinstance(node, dict):
        if "paths_file" in node:
            yield node
        for val in node.values():
            yield from _entries(val)
    elif isinstance(node, list):
        for val in node:
            yield from _entries(val)


def test_catalogs_are_registered_and_every_error_is_the_closed_envelope():
    mep = json.loads((SCHEMAS / "mep_endpoints.json").read_text())
    registered = {e["paths_file"] for e in _entries(mep)}
    for cat in CATALOGS:
        assert "./" + cat.relative_to(SCHEMAS).as_posix() in registered
        for route, item in load(cat)["paths"].items():
            assert route.startswith(
                (
                    "/api/v1/production-reactive/agents/{agent_ref}",
                    "/api/v1/best-configs/agent-heads/{agent_ref}",
                    "/api/v1/projects/{project_id}/agents/{agent_id}/production-reactive-policy",
                )
            )
            for _method, o in item.items():
                assert o["x-asserted-against-backend"] is False and o["operationId"]
                for status, resp in o["responses"].items():
                    ref_ = resp["content"]["application/json"]["schema"]["$ref"]
                    if int(status) >= 400:
                        assert ref_.endswith(
                            "tvl_reactive_common_schema.json#/definitions/Refusal"
                        ), (route, status)


def test_principal_split_is_stated_on_authority_routes():
    ops = {
        o["operationId"]: o
        for item in load(OPT / "tvl_reactive_endpoints.json")["paths"].values()
        for o in item.values()
    }
    assert "P-human only" in ops["createTvlReactiveGrant"]["description"]
    assert "P-human only" in ops["cancelTvlReactiveAttempt"]["description"]
    assert "P-ingest" in ops["reserveTvlReactiveAttempt"]["description"]
    assert "fact_source_not_permitted" in ops["stageTvlReactiveEvaluation"]["description"]
    assert "201" in ops["startTvlReactiveAttempt"]["description"]


def test_every_ref_resolves():
    for path in REACTIVE_DOCS:
        doc = load(path)
        for _p, node in _walk(doc):
            if (
                isinstance(node, dict)
                and isinstance(node.get("$ref"), str)
                and not node["$ref"].startswith("#")
            ):
                target = (path.parent / node["$ref"].split("#")[0]).resolve()
                assert target.exists(), (path.name, node["$ref"])


# ----------------------------------------------------------- trace shape, projection, lint roots
import hashlib  # noqa: E402
import importlib.util  # noqa: E402
import sys  # noqa: E402

import yaml  # noqa: E402
from jsonschema import Draft7Validator  # noqa: E402

from traigent_schema.tvl_reactive import project_evaluation, project_fact  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "tvl" / "semantic_traces"
TRACE_SHAPE = Draft7Validator(
    load(ROOT / "traigent_schema" / "data" / "tvl" / "trace-history-shape.json")
)
FACTS_V = v("tvl_reactive_facts_schema", "OptimizationFact")
CASES = sorted(FIXTURES.glob("*.yml"))


def test_fixture_copies_are_pinned_and_complete():
    src = load(FIXTURES / "SOURCE.json")
    assert len(CASES) == 13 == len(src["files"])
    for c in CASES:
        assert hashlib.sha256(c.read_bytes()).hexdigest() == src["files"][c.name]


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.stem)
def test_fixture_histories_match_trace_shape(case):
    history = yaml.safe_load(case.read_text(encoding="utf-8"))["input"]["history"]
    assert not list(TRACE_SHAPE.iter_errors(history))


def test_trace_shape_rejects_transport_only_fields():
    hist = {
        "agent": "a",
        "environment": "e",
        "evaluations": [
            {
                "instant": 6,
                "windows": [
                    {
                        **window(),
                        "monitor": "m",
                        "unknown_reason": "insufficient",
                        "verdict": "UNKNOWN",
                    }
                ],
            }
        ],
    }
    assert list(TRACE_SHAPE.iter_errors(hist))
    cand = {
        "evidence_valid": True,
        "legacy_decision": "Promote",
        "monitor_verdicts": ["MET"],
        "fingerprint": H64,
    }
    fact = {
        "response": "r",
        "revision": "1",
        "rule": "x",
        "scope": "s",
        "occurrence": 0,
        "fact": "finished",
        "completion": "normal",
        "candidates": [cand],
    }
    assert list(
        TRACE_SHAPE.iter_errors(
            {
                "agent": "a",
                "environment": "e",
                "evaluations": [{"instant": 1, "optimizations": [fact]}],
            }
        )
    )


class _Tokens:
    def __init__(self):
        self.fwd, self.back = {}, {}

    def tok(self, name):
        if name not in self.fwd:
            t = "t" + hashlib.sha256(name.encode()).hexdigest()[:16].translate(
                str.maketrans("abcdef", "ABCDEF")
            )
            self.fwd[name], self.back[t] = t, name
        return self.fwd[name]

    def dig(self, value):
        d = hashlib.sha256(("rev:" + value).encode()).hexdigest()
        self.back[d] = value
        return d


def _to_transport(ev, tk):
    out = {"instant": ev["instant"]}
    for cat in ev:
        if cat == "instant":
            continue
        facts = []
        for f in ev[cat]:
            g = dict(f)
            for k in ("monitor", "scope", "response", "rule"):
                if k in g:
                    g[k] = tk.tok(g[k])
            if cat == "revisions":
                g = {"kind": g["kind"], "target": tk.tok(f["name"]), "value": tk.dig(f["value"])}
            if "revision" in g:
                g["revision"] = tk.dig(g["revision"])
            if cat == "windows" and g["verdict"] == "UNKNOWN":
                g["unknown_reason"] = "insufficient"  # transport-only metadata
            if cat == "optimizations" and "candidates" in g:
                g["candidates"] = [
                    (
                        {**c, "fingerprint": H64, "gate_result_digest": H64B}
                        if c["evidence_valid"]
                        else c
                    )
                    for c in g["candidates"]
                ]
            facts.append(g)
        out[cat] = facts
    return out


def _detranslate(node, tk, key=None):
    if isinstance(node, dict):
        return {k: _detranslate(x, tk, k) for k, x in node.items()}
    if isinstance(node, list):
        return [_detranslate(x, tk, key) for x in node]
    if key in ("monitor", "scope", "response", "rule", "name", "revision", "value") and isinstance(
        node, str
    ):
        return tk.back.get(node, node)
    return node


@pytest.mark.parametrize("case", CASES, ids=lambda p: p.stem)
def test_transport_facts_validate_and_project_to_the_trace_fact(case):
    history = yaml.safe_load(case.read_text(encoding="utf-8"))["input"]["history"]
    tk = _Tokens()
    stage_v = v("tvl_reactive_stage_schema", "EvaluationStageRequest")
    for ev in history["evaluations"]:
        transport = _to_transport(ev, tk)
        body = stage(**{k: x for k, x in transport.items() if k != "instant"})
        assert not stage_v(body), (case.name, stage_v(body))
        projected = _detranslate(project_evaluation(transport), tk)
        assert projected == ev, case.name


def test_projection_drops_exactly_the_documented_fields():
    w = window(verdict="UNKNOWN", unknown_reason="insufficient")
    assert project_fact("windows", w) == {k: x for k, x in w.items() if k != "unknown_reason"}
    cand = {
        "evidence_valid": True,
        "legacy_decision": "Promote",
        "monitor_verdicts": ["MET"],
        "fingerprint": H64,
        "gate_result_digest": H64B,
    }
    f = opt("finished", completion="normal", candidates=[cand, {"evidence_valid": False}])
    pf = project_fact("optimizations", f)
    assert pf["candidates"] == [
        {"evidence_valid": True, "legacy_decision": "Promote", "monitor_verdicts": ["MET"]},
        {"evidence_valid": False},
    ]
    assert project_fact("revisions", {"kind": "monitor", "target": TOK, "value": H64}) == {
        "kind": "monitor",
        "name": TOK,
        "value": H64,
    }
    assert f["candidates"][0]["fingerprint"] == H64  # input not mutated
    with pytest.raises(ValueError):
        project_fact("other", {})


def _lint():
    spec = importlib.util.spec_from_file_location(
        "content_class_lint_t", ROOT / "scripts" / "content_class_lint.py"
    )
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def test_deploy_contracts_are_lint_roots_and_the_content_read_is_an_explicit_exception():
    m = _lint()
    assert "execution/best_config_deploy_schema.json" in m.EXTRA_ROOT_FILES
    assert "execution/best_config_deploy_endpoints.json" in m.EXTRA_ROOT_FILES
    assert set(m.EXPLICIT_CONTENT_EXCEPTIONS) == {
        "execution/best_config_agent_head_config_schema.json",
        "execution/best_config_agent_head_config_endpoints.json",
    }
    assert not set(m.EXPLICIT_CONTENT_EXCEPTIONS) & set(m.EXTRA_ROOT_FILES)
    manifest = load(ROOT / "docs" / "content-class-manifest.json")["classes"]
    assert any(k.startswith("execution/best_config_deploy_schema.json#") for k in manifest)
    assert not any(k.startswith("execution/best_config_agent_head_config") for k in manifest)
    for name in m.EXPLICIT_CONTENT_EXCEPTIONS:
        assert "customer content" in (SCHEMAS / name).read_text(encoding="utf-8").lower()


# ------------------------------------------------------------------ review round 3
def test_rate_limit_is_a_closed_envelope_on_every_endpoint():
    f = v("tvl_reactive_common_schema", "Refusal")
    ok = {
        "success": False,
        "error": "rate_limited",
        "error_code": "rate_limited",
        "message": "Too many requests.",
    }
    assert not f(ok)
    assert f({**ok, "message": "slow down alice"}) and f({**ok, "details": {"scope": "x"}})
    for cat in CATALOGS:
        for route, item in load(cat)["paths"].items():
            for o in item.values():
                if "429" in o["responses"]:
                    r429 = o["responses"]["429"]
                    assert r429["content"]["application/json"]["schema"]["$ref"].endswith(
                        "#/definitions/Refusal"
                    )
                    assert r429["headers"]["Retry-After"]["schema"]["maximum"] == 86400
                else:
                    pytest.fail(f"{route} declares no 429")
    assert "rate_limit_info" not in json.dumps([load(c) for c in CATALOGS])


def test_approval_context_is_closed_and_human_only():
    f = v("tvl_reactive_authority_schema", "ApprovalContext")
    base = {
        "schema_version": 1,
        "attempt_ref": r("attempt"),
        "policy_revision_ref": r("policyrevision"),
        "state": "approved",
        "contract_digest": H64,
    }
    dep = {
        "candidate_fingerprint": H64,
        "gate_result_digest": H64B,
        "optimization_start_generation": 3,
        "current_head_generation": 4,
        "head_moved_since_optimization_start": True,
    }
    assert not f({**base, "effect": "optimize"}) and not f({**base, "effect": "deploy", **dep})
    assert f({**base, "effect": "deploy"}) and f({**base, "effect": "optimize", **dep})
    assert f({**base, "effect": "deploy", **dep, "note": "x"})
    ops = {
        o["operationId"]: o
        for item in load(OPT / "tvl_reactive_endpoints.json")["paths"].values()
        for o in item.values()
    }
    assert "P-human only" in ops["getTvlReactiveApprovalContext"]["description"]
    assert "both shown" in ops["getTvlReactiveApprovalContext"]["description"]


def test_lease_renewal_is_bound_to_the_existing_reservation():
    f = v("tvl_reactive_authority_schema", "HeartbeatRequest")
    ok = {
        "schema_version": 1,
        "heartbeat_key": KEY,
        "reservation_ref": r("reservation"),
        "reservation_generation": 2,
    }
    assert (
        not f(ok)
        and f({k: x for k, x in ok.items() if k != "reservation_generation"})
        and f({**ok, "attempt": "x"})
    )
    assert not v("tvl_reactive_authority_schema", "HeartbeatReceipt")(
        {
            "schema_version": 1,
            "attempt_ref": r("attempt"),
            "lease_expires_at": "2026-10-22T10:00:00Z",
            "replayed": False,
        }
    )


def test_deploy_publication_is_its_own_branch_with_the_approval_time_generation():
    f = vx("best_config_agent_head_config_schema", "DeployPublishRequest")
    spec = {
        "schema_version": "traigent.best_config.v1",
        "config_id": "c",
        "function_ref": "m:f",
        "environment": "default",
        "config": {},
        "provenance": {},
    }
    ok = {
        "schema_version": 1,
        "idempotency_key": KEY_D,
        "attempt_ref": r("attempt"),
        "grant_ref": r("grant"),
        "reservation_ref": r("reservation"),
        "reservation_generation": 1,
        "expected_head_generation": 4,
        "spec": spec,
    }
    props = load(EXE / "best_config_agent_head_config_schema.json")["definitions"][
        "DeployPublishRequest"
    ]
    assert props["additionalProperties"] is False and set(ok) == set(props["required"])
    assert (
        "APPROVAL-TIME" in props["properties"]["expected_head_generation"]["description"]
        or "READ AT APPROVAL" in props["properties"]["expected_head_generation"]["description"]
    )
    assert not f(ok)
    for needed in ok:
        assert f({k: x for k, x in ok.items() if k != needed}), f"{needed} must be required"
    assert f({**ok, "expected_head_generation": -1}) and f({**ok, "idempotency_key": "deploy:x"})
    assert [e for e in f({**ok, "extra": 1})]
    cat = load(EXE / "best_config_agent_head_config_endpoints.json")["paths"]
    desc = cat["/api/v1/best-configs/agent-heads/{agent_ref}/deploy-publications"]["post"][
        "description"
    ]
    assert (
        "APPROVAL-TIME" in desc
        and "BEFORE any stale-generation" in desc
        and "publication_cancelled" in desc
    )
    assert (
        "unchanged"
        not in load(EXE / "best_config_deploy_endpoints.json")["info"]["description"].split(
            "separate"
        )[0]
    )


# trace-level proof of the two lapse recoveries, against the real reference checker
def _tvl():
    """The reference checker.

    tvl-spec needs Python >= 3.12 and is a dev dependency there (pyproject dev extra,
    requirements-dev.txt). On >= 3.12 a missing package FAILS; the only skip is the
    interpreter-version one, and the required 3.12 CI job runs these tests.
    """
    if sys.version_info < (3, 12):
        pytest.skip("tvl-spec requires Python >= 3.12; these tests run in the 3.12 job")
    import tvl.runtime_trace as tvl  # noqa: PLC0415 - a missing package must fail, not skip

    return tvl


def _deploy_fixture():
    return yaml.safe_load(
        (FIXTURES / "deploy-write-fails-then-succeeds-on-same-occurrence-retry.yml").read_text(
            encoding="utf-8"
        )
    )


def test_lapsed_deployment_recovers_via_deploy_result_never_optimization_finished():
    rt = _tvl()
    case = _deploy_fixture()
    module, hist = case["module"], copy.deepcopy(case["input"]["history"])
    fact = {
        "response": "repair",
        "revision": "1",
        "rule": "fix",
        "scope": "episode-1",
        "occurrence": 0,
    }
    evs = hist["evaluations"][:2]  # through deploy_started + first failed write
    evs[1]["optimizations"] = [o for o in evs[1]["optimizations"] if o["fact"] != "deploy_result"]
    # recovery path A (finalize returned cancelled -> terminal failure on the SAME occurrence)
    a = copy.deepcopy(hist)
    a["evaluations"] = copy.deepcopy(evs) + [
        {
            "instant": 2,
            "optimizations": [
                {
                    **fact,
                    "fact": "deploy_result",
                    "checks": "passed",
                    "write": "failed",
                    "retries_exhausted": True,
                }
            ],
        }
    ]
    out_a = rt.notification_trace(module, a)
    assert [n["event"] for n in out_a] == ["deploy_failed"], out_a
    # recovery path B (finalize returned the stored success)
    b = copy.deepcopy(a)
    b["evaluations"][2]["optimizations"][0].update(write="succeeded", retries_exhausted=False)
    out_b = rt.notification_trace(module, b)
    assert out_b == [], out_b  # deployed: attempt closes with no failure notification
    # the forbidden recovery: optimization finished{cancelled} after the deployment started
    bad = copy.deepcopy(hist)
    bad["evaluations"] = copy.deepcopy(evs) + [
        {
            "instant": 2,
            "optimizations": [
                {**fact, "fact": "finished", "completion": "cancelled", "candidates": []}
            ],
        }
    ]
    with pytest.raises(rt.TraceError, match="optimization not running"):
        rt.notification_trace(module, bad)


def test_lapsed_optimization_cancel_projects_to_a_valid_trace_and_records_optimize_failed():
    rt = _tvl()
    case = _deploy_fixture()
    module, hist = case["module"], copy.deepcopy(case["input"]["history"])
    fact = {
        "response": "repair",
        "revision": "1",
        "rule": "fix",
        "scope": "episode-1",
        "occurrence": 0,
    }
    ev0 = copy.deepcopy(hist["evaluations"][0])
    ev0["optimizations"] = [
        o for o in ev0["optimizations"] if o["fact"] != "finished"
    ]  # lapsed: started, never finished
    cancel_fact = {**fact, "fact": "finished", "completion": "cancelled", "candidates": []}
    h = {
        "agent": hist["agent"],
        "environment": hist["environment"],
        "evaluations": [ev0, {"instant": 1, "optimizations": [cancel_fact]}],
    }
    assert not list(TRACE_SHAPE.iter_errors(h))
    transport = _to_transport(h["evaluations"][1], _Tokens())
    assert not FACTS_V(transport["optimizations"][0])
    rt.notification_trace(module, h)  # accepted by the reference checker


# ------------------------------------------------------------------ policy read (follow-up)
POLICY_PATH = "/api/v1/projects/{project_id}/agents/{agent_id}/production-reactive-policy"


def _notify(**o):
    rule = {
        "response": TOK,
        "rule": TOK2,
        "position": 0,
        "trigger": {"monitor": TOK, "event": "episode_opened"},
        "action": "notify",
        "approval": "none",
        "executes": "server",
        "only_while": [],
        "unless": [],
        "severity": "warning",
    }
    rule.update(o)
    return rule


def _opt(**o):
    rule = _notify(action="optimize", approval="human", deploy="if_promoted")
    rule.pop("severity")
    rule.update(o)
    return rule


def _policy(**o):
    pol = {
        "policy_revision_ref": r("policyrevision"),
        "contract_digest": H64,
        "rules": [_notify()],
        "promotion_gates": [],
        "control_limits": [],
    }
    pol.update(o)
    return pol


def _read(policy="__default__", **o):
    body = {
        "schema_version": 1,
        "agent_ref": r("agent"),
        "policy": _policy() if policy == "__default__" else policy,
    }
    body.update(o)
    return body


POLICY_READ = v("tvl_reactive_policy_schema", "PolicyReadResponse")


def test_policy_read_is_registered_and_closed():
    cat = load(POLICY_CATALOG)
    assert POLICY_PATH not in load(OPT / "tvl_reactive_endpoints.json")["paths"]
    get = cat["paths"][POLICY_PATH]["get"]
    assert all("x-content-class" not in p["schema"] for p in get["parameters"])
    assert get["operationId"] == "getTvlReactivePolicy"
    assert set(get["responses"]) == {"200", "400", "401", "403", "404", "429", "500", "503"}
    assert "P-human only" in get["description"]
    assert "agent_ref" in get["description"]
    for code, resp in get["responses"].items():
        if code != "200":
            assert resp["content"]["application/json"]["schema"]["$ref"].endswith(
                "tvl_reactive_common_schema.json#/definitions/Refusal"
            )
    assert not POLICY_READ(_read())
    assert not POLICY_READ(_read(policy=None))
    assert not POLICY_READ(_read(policy=_policy(rules=[])))
    assert POLICY_READ(_read(extra=1))
    assert POLICY_READ(_read(agent_ref="agent-1"))
    assert POLICY_READ({k: x for k, x in _read().items() if k != "policy"})
    assert POLICY_READ(_read(policy={**_policy(), "name": "x"}))
    assert POLICY_READ(_read(policy={k: x for k, x in _policy().items() if k != "contract_digest"}))


def test_policy_rules_use_tokens_and_reject_names_and_standing():
    assert not POLICY_READ(_read(policy=_policy(rules=[_notify(), _notify(position=1)])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify(rule="my_rule")])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify(name="Latency alert")])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify(approval="standing")])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify(action="rollback")])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify(position=64)])))
    assert POLICY_READ(_read(policy=_policy(rules=[_notify()] * 4097)))


def test_policy_rule_conditional_fields_follow_the_action():
    ok = lambda rule: not POLICY_READ(_read(policy=_policy(rules=[rule])))  # noqa: E731
    assert ok(_opt())
    assert ok(_opt(deploy="never"))
    assert not ok(_opt(deploy="never", approval="none"))
    # deploy iff optimize
    assert not ok(_notify(deploy="never"))
    assert not ok({k: x for k, x in _opt().items() if k != "deploy"})
    # if_promoted needs human approval
    assert not ok(_opt(approval="none"))
    # severity only on notify
    assert not ok(_opt(severity="info"))
    # local guards
    local = _notify(
        action="block_action",
        executes="sdk_local",
        on_check_error="block",
        trigger={"monitor": TOK, "event": "unit_violation"},
    )
    local.pop("severity")
    assert ok(local)
    assert ok({**local, "action": "halt_unit", "on_check_error": "allow"})
    assert not ok({k: x for k, x in local.items() if k != "on_check_error"})
    assert not ok({**local, "trigger": {"monitor": TOK, "event": "episode_opened"}})
    assert not ok({**local, "trigger": {"rule": TOK, "event": "optimize_failed"}})
    assert not ok({**local, "approval": "human"})
    assert not ok(_notify(trigger={"monitor": TOK, "event": "unit_violation"}))
    assert not ok(_opt(trigger={"monitor": TOK, "event": "unit_violation"}))
    # approval ladder: optimize human, every other supported action none
    assert not ok(_notify(approval="human"))
    assert not ok(_opt(approval="none"))
    # repeats: max_repeats needs repeat_after_hours; non-notify repeat must be bounded
    assert not ok(_notify(max_repeats=2))
    assert not ok(_opt(repeat_after_hours=2))
    assert ok(_opt(repeat_after_hours=2, max_repeats=2))
    assert not ok(_opt(max_repeats=2))
    assert not ok({**local, "executes": "server"})
    assert not ok(_notify(executes="sdk_local"))
    assert not ok(_notify(on_check_error="block"))
    # trigger hours iff open_for / unknown_for
    assert ok(_notify(trigger={"monitor": TOK, "event": "episode_open_for", "hours": 4}))
    assert not ok(_notify(trigger={"monitor": TOK, "event": "episode_open_for"}))
    assert not ok(_notify(trigger={"monitor": TOK, "event": "episode_opened", "hours": 4}))
    assert not ok(_notify(trigger={"monitor": TOK, "event": "recovery_overdue"}))
    # outcome triggers, unknown_for and guards only with notify; no repeats on outcome triggers
    outcome = {"rule": TOK2, "event": "optimize_failed"}
    assert ok(_notify(trigger=outcome))
    assert not ok(_opt(trigger=outcome))
    assert not ok(_notify(trigger=outcome, repeat_after_hours=2))
    assert not ok(_notify(trigger=outcome, max_repeats=2))
    assert ok(_notify(repeat_after_hours=2, max_repeats=3))
    assert not ok(_opt(trigger={"monitor": TOK, "event": "unknown_for", "hours": 2}))
    guard = {"monitor": TOK2, "state": "episode_open"}
    assert ok(_notify(unless=[guard], only_while=[{"rule": TOK2, "state": "attempt_open"}]))
    assert not ok(_opt(unless=[guard]))
    assert not ok(_notify(unless=[{"monitor": TOK2, "state": "attempt_open"}]))
    assert not ok(_notify(unless=[{**guard, "name": "x"}]))


def test_policy_gates_and_limits():
    gate = {
        "response": TOK,
        "rule": TOK2,
        "runtime_monitor": TOK,
        "promotion_monitors": [{"monitor": TOK2, "requirement": TOK}],
        "required_result": "Promote",
    }
    ok = lambda **o: not POLICY_READ(_read(policy=_policy(**o)))  # noqa: E731
    assert ok(promotion_gates=[gate])
    assert not ok(promotion_gates=[{**gate, "required_result": "Hold"}])
    assert not ok(promotion_gates=[{**gate, "promotion_monitors": []}])
    assert not ok(promotion_gates=[{**gate, "promotion_monitors": [{"monitor": TOK2}]}])
    assert not ok(promotion_gates=[{**gate, "verdict": "Promote"}])
    assert ok(control_limits=[{"monitor": TOK}])
    both = {"monitor": TOK, "max_active_obligations": 1, "max_tracked_correlations": 5}
    assert ok(control_limits=[both])
    assert not ok(control_limits=[{"monitor": TOK, "max_active_obligations": 0}])
    assert not ok(control_limits=[{"monitor": TOK, "max_tracked_correlations": 0}])
    assert not ok(control_limits=[{"monitor": TOK, "standing": 1}])
    assert not ok(control_limits=[{"monitor": TOK}] * 65)


def test_flag_off_is_the_closed_404_and_no_unknown_route_promise_remains():
    refusal = v("tvl_reactive_common_schema", "Refusal")
    body = {
        "success": False,
        "error": "reference_not_found",
        "error_code": "reference_not_found",
        "message": "Reference not found.",
    }
    assert not refusal(body)
    for path in [*CATALOGS, *REACTIVE_DOCS]:
        assert "unknown-route" not in path.read_text(encoding="utf-8"), path.name
    for cat in (OPT / "tvl_reactive_endpoints.json", POLICY_CATALOG):
        for entry in load(cat)["paths"].values():
            for op in entry.values():
                assert '"error":"reference_not_found"' in op["description"]
    common = load(OPT / "tvl_reactive_common_schema.json")
    assert "reference_not_found" in common["definitions"]["Refusal"]["description"]


def test_liveness_scope_may_be_established_by_the_first_liveness_fact():
    common = load(OPT / "tvl_reactive_common_schema.json")["definitions"]["HostedToken"]
    facts = load(OPT / "tvl_reactive_facts_schema.json")["definitions"]["LivenessFact"]
    assert "first authenticated" in common["description"]
    assert "continued" in common["description"]
    assert "without a preceding `opened` or `fired`" in facts["properties"]["scope"]["description"]
    assert not v("tvl_reactive_facts_schema", "LivenessFact")(
        {"monitor": TOK, "event": "stale", "scope": TOK2}
    )


def test_start_receipt_carries_the_post_start_lease_deadline():
    f = v("tvl_reactive_authority_schema", "StartReceipt")
    ok = {
        "schema_version": 1,
        "attempt_ref": r("attempt"),
        "effect": "optimize",
        "fact": "started",
        "started_at": "2026-10-22T10:00:00Z",
        "lease_expires_at": "2026-10-22T11:00:00Z",
        "replayed": False,
    }
    assert not f(ok)
    assert f({k: x for k, x in ok.items() if k != "lease_expires_at"})
    assert f({**ok, "extra": 1})


def test_compiler_valid_local_guard_is_a_valid_declaration():
    """Compile a local guard with tvl-spec and return its hosted shape as a declaration."""
    import hashlib  # noqa: PLC0415

    import yaml  # noqa: PLC0415

    _tvl()  # version gate first: tvl-spec needs Python >= 3.12
    import tvl  # noqa: PLC0415
    from tvl.runtime_compiler import compile_runtime_document  # noqa: PLC0415
    from tvl.runtime_projection import token_map_template  # noqa: PLC0415

    case = (
        Path(tvl.__file__).parent
        / "conformance/cases/runtime/lints/local-guard-error-policy-required.yml"
    )
    module = yaml.safe_load(case.read_text(encoding="utf-8"))["module"]
    module["responses"][0]["rules"][0]["on_check_error"] = "block"
    tokens = token_map_template([module])
    for entry in tokens["tokens"]:
        digest = hashlib.sha256((entry["namespace"] + entry["local"]).encode()).hexdigest()
        entry["hosted"] = "t" + digest[:16]
    hosted, _local, _profiles = compile_runtime_document(module, token_map_doc=tokens)
    response = hosted["declarations"]["responses"][0]
    compiled = response["rules"][0]
    assert compiled["trigger"]["event"] == "unit_violation" and compiled["do"] == "block_action"
    rule = {
        "response": response["name"],
        "rule": compiled["id"],
        "position": 0,
        "trigger": compiled["trigger"],
        "action": compiled["do"],
        "approval": compiled["approval"],
        "executes": "sdk_local",
        "only_while": [],
        "unless": [],
        "on_check_error": compiled["on_check_error"],
    }
    assert not POLICY_READ(_read(policy=_policy(rules=[rule])))
