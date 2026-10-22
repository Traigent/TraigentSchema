"""TRAIG-101 S1: closed wire contracts of the TVL 1.4 reactive layer (GNFR-PRIV-002(f) expansion)."""
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
REACTIVE_DOCS = sorted(OPT.glob("tvl_reactive_*_schema.json")) + [EXE / "best_config_deploy_schema.json"]
CATALOGS = [OPT / "tvl_reactive_endpoints.json", EXE / "best_config_deploy_endpoints.json"]

TOK = "t" + "A1_-" * 4
TOK2 = "t" + "b2c3" * 4
H64 = "a" * 64
H64B = "b" * 64
KEY = "0123456789abcdef0123456789abcdef"


def ref(name, **parts):
    return lambda inst: ref_errors(REGISTRY, f"{B}{name}", inst)


def v(doc, definition):
    return lambda inst: ref_errors(REGISTRY, f"{B}optimization/{doc}.json#/definitions/{definition}", inst)


def vx(doc, definition):
    return lambda inst: ref_errors(REGISTRY, f"{B}execution/{doc}.json#/definitions/{definition}", inst)


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
        if len(parent) >= 2 and (path.rsplit("/", 2)[-2] in ("properties", "definitions") or path.endswith("/items")):
            yield path, node


@pytest.mark.parametrize("path", REACTIVE_DOCS, ids=lambda p: p.name)
def test_every_value_is_bounded_and_closed(path):
    doc = load(path)
    problems = []
    for p, node in _walk(doc):
        if not isinstance(node, dict):
            continue
        t = node.get("type")
        if node.get("type") == "object" or "properties" in node and "oneOf" not in node and "type" in node:
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
        leaf = any(x in ("string", "integer", "boolean") for x in types) or "enum" in node or "const" in node
        if leaf and "x-content-class" not in node and not p.endswith("/allOf/0") and "/not/" not in p + "/" and "/if/" not in p + "/":
            missing.append(p)
    # branch re-constraints (oneOf/if/else) legitimately repeat a class; the lint walks those too
    assert not missing, "\n".join(missing)


def test_no_customer_chosen_name_fields():
    banned = re.compile(r"(^|_)(name|label|title|message_text|prompt|description_text|config_id|function_ref)$")
    for path in REACTIVE_DOCS[:-1]:
        for p, node in _walk(load(path)):
            if "/properties/" in p and p.rsplit("/", 1)[-1] and isinstance(node, dict):
                assert not banned.search(p.rsplit("/", 1)[-1]), f"{path.name}{p}"


# ------------------------------------------------------------------ common
def test_hosted_token_is_the_minted_shape_only():
    tok = v("tvl_reactive_common_schema", "HostedToken")
    assert not tok(TOK)
    for bad in ("", "x" * 17, "Alice_has_diabetes", "t" + "a" * 15, "t" + "a" * 17, "t" + "a" * 15 + "!", "T" + "a" * 16):
        assert tok(bad), bad


def test_digest_key_and_ref_shapes():
    assert not v("tvl_reactive_common_schema", "Digest")(H64)
    assert v("tvl_reactive_common_schema", "Digest")("sha256:" + H64)
    assert not v("tvl_reactive_common_schema", "IdempotencyKey")(KEY)
    for bad in (KEY.upper(), KEY[:-1], "Alice_has_diabetes_" + "0" * 13):
        assert v("tvl_reactive_common_schema", "IdempotencyKey")(bad)
    for d, kind in (("PolicyRevisionRef", "policyrevision"), ("AttemptRef", "attempt"), ("GrantRef", "grant"),
                    ("ReservationRef", "reservation"), ("NotificationRef", "notification")):
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
        assert br["properties"]["error_code"]["const"] == code and br["properties"]["message"]["const"] == msg
        assert "{" not in msg and "%" not in msg
    f = v("tvl_reactive_common_schema", "Refusal")
    ok = {"success": False, "error": "instant_sealed", "error_code": "instant_sealed", "message": "Instant is sealed."}
    assert not f(ok)
    assert f({**ok, "message": "Internal error."}) and f({**ok, "details": "x"}) and f({**ok, "success": True})
    for needed in ("batch_out_of_order", "instant_not_increasing", "evaluation_inputs_frozen", "instant_sealed",
                   "fact_contradicts_record", "fact_source_not_permitted", "head_generation_stale", "publication_cancelled"):
        assert needed in codes


# ------------------------------------------------------------------ facts
def window(**o):
    return {"monitor": TOK, "start": 0, "end": 24, "verdict": "MET", "usable": True, **o}


def test_window_unknown_reason_only_with_unknown():
    f = v("tvl_reactive_facts_schema", "WindowFact")
    assert not f(window()) and not f(window(verdict="BREACHED"))
    assert not f(window(verdict="UNKNOWN")) and not f(window(verdict="UNKNOWN", unknown_reason="insufficient"))
    assert f(window(unknown_reason="insufficient")) and f(window(verdict="UNKNOWN", unknown_reason="free text"))
    assert f(window(verdict="met")) and f(window(extra=1)) and f(window(start=-1))


def test_episode_reason_only_on_close():
    f = v("tvl_reactive_facts_schema", "EpisodeFact")
    base = {"monitor": TOK, "scope": TOK2}
    assert not f({**base, "event": "opened"}) and not f({**base, "event": "continued"})
    assert not f({**base, "event": "closed", "reason": "resolved"}) and not f({**base, "event": "closed", "reason": "withdrawn"})
    assert f({**base, "event": "closed"}) and f({**base, "event": "opened", "reason": "resolved"})
    assert f({**base, "event": "closed", "reason": "timeout"})


def opt(fact, **o):
    base = {"response": TOK, "revision": H64, "rule": TOK2, "scope": TOK, "occurrence": 0, "fact": fact}
    return {**base, **o}


VALID_OPT = {
    "fired": opt("fired"),
    "started": opt("started"),
    "finished": opt("finished", completion="normal", candidates=[]),
    "approval": opt("approval", effect="optimize", state="granted"),
    "authority": opt("authority", state="unreachable"),
    "deploy_started": opt("deploy_started"),
    "deploy_result": opt("deploy_result", checks="passed", write="succeeded", retries_exhausted=False),
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
    assert not f(opt("deploy_result", checks="refused", write="not_attempted", retries_exhausted=False))
    assert f(opt("deploy_result", checks="passed", write="succeeded", retries_exhausted="no"))
    assert f(opt("fired", occurrence=-1)) and f(opt("fired", revision="rev-1")) and f(opt("fired", scope="Alice has diabetes"))


def test_candidates_valid_and_invalid_evidence():
    c = v("tvl_reactive_facts_schema", "Candidate")
    assert not c({"evidence_valid": True, "legacy_decision": "Promote", "monitor_verdicts": ["MET", "UNKNOWN(insufficient)"],
                  "fingerprint": H64, "gate_result_digest": H64B})
    assert not c({"evidence_valid": False})
    assert c({"evidence_valid": True}) and c({"evidence_valid": False, "legacy_decision": "Promote"})
    assert c({"evidence_valid": True, "legacy_decision": "Promote", "monitor_verdicts": ["UNKNOWN(because I said so)"]})
    assert c({"evidence_valid": True, "legacy_decision": "Promote", "monitor_verdicts": ["MET"] * 33})


# ------------------------------------------------------------------ stage / complete
def stage(**o):
    return {"schema_version": 1, "stage_key": KEY, "policy_revision_ref": r("policyrevision"), "environment": TOK,
            "producer_kind": "customer_monitor", **o}


def test_stage_request_is_closed_and_bounded():
    f = v("tvl_reactive_stage_schema", "EvaluationStageRequest")
    assert not f(stage())
    assert not f(stage(windows=[window()], episodes=[{"monitor": TOK, "scope": TOK2, "event": "opened"}],
                       revisions=[{"kind": "monitor", "target": TOK, "value": H64}],
                       liveness=[{"monitor": TOK, "event": "stale", "scope": TOK2}], optimizations=[VALID_OPT["fired"]]))
    assert f(stage(extra=1)) and f(stage(producer_kind="backend_native")) and f(stage(environment="production"))
    assert not f(stage(windows=[window()] * 256)) and f(stage(windows=[window()] * 257))
    assert f(stage(optimizations=[VALID_OPT["fired"]] * 257)) and f(stage(windows=[{**window(), "note": "x"}]))


def test_complete_request_rules():
    f = v("tvl_reactive_stage_schema", "EvaluationCompleteRequest")
    base = {"schema_version": 1, "complete_key": KEY, "policy_revision_ref": r("policyrevision"), "environment": TOK}
    assert not f({**base, "producer_kind": "customer_monitor", "monitor": TOK, "completed_through_end": 24, "disposition": "complete"})
    assert not f({**base, "producer_kind": "optimization_reporter", "disposition": "defer"})
    assert not f({**base, "producer_kind": "optimization_reporter", "disposition": "complete"})
    assert f({**base, "producer_kind": "customer_monitor", "disposition": "complete"})
    assert f({**base, "producer_kind": "customer_monitor", "monitor": TOK, "completed_through_end": 24, "disposition": "defer"})
    assert f({**base, "producer_kind": "optimization_reporter", "disposition": "complete", "monitor": TOK})
    assert f({**base, "producer_kind": "native", "disposition": "complete"})


# ------------------------------------------------------------------ authority
def grant(**o):
    return {"schema_version": 1, "grant_key": KEY, "attempt_ref": r("attempt"), "contract_digest": H64, **o}


OPTIMIZE = dict(effect="optimize", decision="granted", duration_hours=1, ceiling={"max_trials": 10, "max_cost_micro_usd": 5000000})
DEPLOY = dict(effect="deploy", decision="granted", duration_hours=4,
              deploy={"candidate_fingerprint": H64, "gate_result_digest": H64B, "expected_head_generation": 3})


def test_grant_create_shapes():
    f = v("tvl_reactive_authority_schema", "GrantCreateRequest")
    assert not f(grant(**OPTIMIZE)) and not f(grant(**DEPLOY))
    assert not f(grant(effect="optimize", decision="declined")) and not f(grant(effect="deploy", decision="declined"))
    assert f(grant(**{**OPTIMIZE, "duration_hours": 2})) and f(grant(**{**OPTIMIZE, "duration_hours": 0}))
    assert f(grant(**{**OPTIMIZE, "deploy": DEPLOY["deploy"]})) and f(grant(**{**DEPLOY, "ceiling": OPTIMIZE["ceiling"]}))
    assert f(grant(effect="optimize", decision="granted")) and f(grant(effect="optimize", decision="declined", duration_hours=1))
    assert f(grant(**{**OPTIMIZE, "standing": True})) and f(grant(**{**OPTIMIZE, "approval": "standing"}))


def test_reservation_start_results_cancel():
    assert not v("tvl_reactive_authority_schema", "ReservationRequest")({"schema_version": 1, "reservation_key": KEY, "grant_ref": r("grant")})
    s = v("tvl_reactive_authority_schema", "StartRequest")
    assert not s({"schema_version": 1, "start_key": KEY, "reservation_ref": r("reservation"), "reservation_generation": 1})
    assert s({"schema_version": 1, "start_key": KEY, "reservation_ref": r("reservation")})
    o = v("tvl_reactive_authority_schema", "EffectOutcomeRequest")
    base = {"schema_version": 1, "result_key": KEY, "reservation_ref": r("reservation"), "reservation_generation": 1}
    assert not o({**base, "fact": "finished", "completion": "cost_limit", "candidates": []})
    assert not o({**base, "fact": "deploy_result", "checks": "passed", "write": "failed", "retries_exhausted": True})
    assert not o({**base, "fact": "authority", "state": "reachable"})
    assert o({**base, "fact": "started"}) and o({**base, "fact": "finished", "completion": "normal"})
    assert o({**base, "fact": "authority", "state": "reachable", "completion": "normal"})
    c = v("tvl_reactive_authority_schema", "CancelRequest")
    assert not c({"schema_version": 1, "cancel_key": KEY, "confirmation": "process_gone"})
    assert c({"schema_version": 1, "cancel_key": KEY, "confirmation": "yes"})


def test_read_models_are_closed():
    notif = {
        "schema_version": 1, "notification_ref": r("notification"), "policy_revision_ref": r("policyrevision"),
        "response": TOK, "rule": TOK2, "event": "unknown_for", "scope": TOK, "occurrence_index": 0, "repeat_index": 0,
        "evaluation_instant": 24, "decision": "suppressed",
        "guards": [{"kind": "monitor_episode_open", "monitor": TOK, "list": "unless", "value": "TRUE"},
                   {"kind": "rule_attempt_open", "rule": TOK2, "list": "only_while", "value": "UNDECIDED"}],
        "evidence_source": "recorded_by_customer", "producers_missing": False, "recorded_at": "2026-10-22T10:00:00Z",
    }
    f = v("tvl_reactive_notification_schema", "Notification")
    assert not f(notif)
    assert f({**notif, "title": "x"}) and f({**notif, "event": "deploy_held"}) and f({**notif, "decision": "sent"})
    g = copy.deepcopy(notif)
    g["guards"][0]["rule"] = TOK
    assert f(g)
    page = v("tvl_reactive_notification_schema", "NotificationPage")
    assert not page({"schema_version": 1, "items": [notif], "next_after": None}) and page({"schema_version": 1, "items": [notif] * 101, "next_after": 1})
    attempt = {
        "schema_version": 1, "attempt_ref": r("attempt"), "policy_revision_ref": r("policyrevision"), "response": TOK,
        "rule": TOK2, "scope": TOK, "occurrence": 0, "effect": "deploy", "state": "lapsed", "optimize_outcome": "promoted",
        "deploy_outcome": "none", "lapsed": True, "opened_at": "2026-10-22T10:00:00Z",
    }
    a = v("tvl_reactive_authority_schema", "Attempt")
    assert not a(attempt) and a({**attempt, "deploy_outcome": "deploy_held"}) and a({**attempt, "state": "hold"})
    gr = {"schema_version": 1, "grant_ref": r("grant"), "attempt_ref": r("attempt"), "policy_revision_ref": r("policyrevision"),
          "effect": "optimize", "state": "granted", "contract_digest": H64, "decided_by": "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f",
          "decided_at": "2026-10-22T10:00:00Z", "expires_at": "2026-10-22T11:00:00Z"}
    assert not v("tvl_reactive_authority_schema", "Grant")(gr) and v("tvl_reactive_authority_schema", "Grant")({**gr, "decided_by": "Nimrod"})


# ------------------------------------------------------------------ deploy
KEY_D = f"deploy:{r('attempt')}:{H64}:{H64B}"


def test_deploy_key_result_and_finalize():
    k = vx("best_config_deploy_schema", "DeployIdempotencyKey")
    assert not k(KEY_D) and k("deploy:x:y:z") and k(KEY_D + "0") and k(KEY_D.replace("attemptref_", "grantref_"))
    res = vx("best_config_deploy_schema", "DeployPublishResult")
    ok = {"schema_version": 1, "idempotency_key": KEY_D, "state": "succeeded", "head_generation": 4, "pinned_version": 2,
          "decided_at": "2026-10-22T10:00:00Z"}
    assert not res(ok)
    assert not res({**ok, "state": "cancelled", "head_generation": None, "pinned_version": None})
    assert not res({**ok, "state": "pending", "head_generation": None, "pinned_version": None, "decided_at": None})
    assert res({**ok, "state": "cancelled"}) and res({**ok, "state": "succeeded", "head_generation": None})
    assert res({**ok, "state": "failed"}) and res({**ok, "config": {}})
    assert not vx("best_config_deploy_schema", "DeployFinalizeRequest")({"schema_version": 1})
    assert vx("best_config_deploy_schema", "DeployFinalizeRequest")({"schema_version": 1, "force": True})


def test_pinned_read_response_declares_content_and_generation():
    doc = load(EXE / "best_config_agent_head_config_schema.json")
    resp = doc["definitions"]["AgentHeadConfigResponse"]
    assert resp["additionalProperties"] is False and set(resp["required"]) == {"schema_version", "generation", "version", "spec"}
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
            assert route.startswith(("/api/v1/production-reactive/agents/{agent_ref}", "/api/v1/best-configs/agent-heads/{agent_ref}"))
            for method, o in item.items():
                assert o["x-asserted-against-backend"] is False and o["operationId"]
                for status, resp in o["responses"].items():
                    ref_ = resp["content"]["application/json"]["schema"]["$ref"]
                    if status == "429":
                        assert ref_.endswith("rate_limit_info_schema.json")
                    elif int(status) >= 400:
                        assert ref_.endswith("tvl_reactive_common_schema.json#/definitions/Refusal"), (route, status)


def test_principal_split_is_stated_on_authority_routes():
    ops = {o["operationId"]: o for item in load(OPT / "tvl_reactive_endpoints.json")["paths"].values() for o in item.values()}
    assert "P-human only" in ops["createTvlReactiveGrant"]["description"]
    assert "P-human only" in ops["cancelTvlReactiveAttempt"]["description"]
    assert "P-ingest" in ops["reserveTvlReactiveAttempt"]["description"]
    assert "fact_source_not_permitted" in ops["stageTvlReactiveEvaluation"]["description"]
    assert "201" in ops["startTvlReactiveAttempt"]["description"]


def test_every_ref_resolves():
    for path in REACTIVE_DOCS:
        doc = load(path)
        for p, node in _walk(doc):
            if isinstance(node, dict) and isinstance(node.get("$ref"), str) and not node["$ref"].startswith("#"):
                target = (path.parent / node["$ref"].split("#")[0]).resolve()
                assert target.exists(), (path.name, node["$ref"])
