"""Contract tests for the crew domain (CREW-11): schemas validate, closed enums and
closed objects reject bad input, content/identifier annotations are present."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator, RefResolver

from traigent_schema.utils import get_schemas_dir

CREW_DIR = Path(get_schemas_dir()) / "crew"
SCHEMAS = Path(get_schemas_dir())
CREW = "crew_" + "ab" * 8
CREV = "crev_" + "cd" * 8
CROL = "crol_" + "ef" * 8
TOKEN = "rtk_" + "abcdefghij234567klmnopqrst"[:26]
TOKEN2 = "rtk_" + "pqrstuvwxyz234567abcdefghi"[:26]
RUN = "0191a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b"
INV = "0191a2b3-c4d5-4e6f-8a9b-0c1d2e3f4a5b"
DIGEST = "sha256:" + "a" * 64
NOW = "2026-11-06T10:00:00Z"


def _load(name: str) -> dict:
    return json.loads((CREW_DIR / name).read_text(encoding="utf-8"))


def _validator(name: str) -> Draft7Validator:
    store = {}
    for path in SCHEMAS.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(doc, dict) and "$id" in doc:
            store[doc["$id"]] = doc
    schema = _load(name)
    resolver = RefResolver(schema["$id"], schema, store=store)
    return Draft7Validator(schema, resolver=resolver)


def _ok(name: str, doc: dict) -> None:
    errors = list(_validator(name).iter_errors(doc))
    assert not errors, [e.message for e in errors]


def _bad(name: str, doc: dict) -> None:
    assert list(_validator(name).iter_errors(doc)), f"{name} accepted an invalid document"


CREW_DOC = {
    "crew_id": CREW,
    "crew_key": "triage-crew",
    "name": "Triage",
    "description": None,
    "archived_at": None,
    "created_by": "user_1",
    "created_at": NOW,
    "updated_at": NOW,
    "latest_revision_no": None,
    "role_count": 0,
    "bound_member_count": 0,
    "entry_role_id": None,
}
ROLE_DOC = {
    "role_id": CROL,
    "crew_id": CREW,
    "role_key": "triage",
    "role_token": TOKEN,
    "created_at": NOW,
}
BINDING_DOC = {
    "crew_id": CREW,
    "crew_revision_id": CREV,
    "role_id": CROL,
    "binding_kind": "agent",
    "agent_id": "agent_1",
    "unit_ref": None,
    "pinned_agent_revision": None,
    "pinned_config_digest": None,
    "entry": True,
    "state": "bound",
    "provenance": "portal",
}
REVISION_DOC = {
    "crew_revision_id": CREV,
    "crew_id": CREW,
    "revision_no": 1,
    "source": "portal",
    "created_by": "user_1",
    "created_at": NOW,
    "digest": DIGEST,
    "bindings": [BINDING_DOC],
}
HANDOFF_DOC = {
    "crew_run_id": RUN,
    "hop_seq": 1,
    "from_role_token": TOKEN,
    "to_role_token": TOKEN2,
    "from_invocation_id": INV,
    "to_invocation_id": None,
    "requested_at": NOW,
    "entered": False,
    "dedup_id": INV,
    "transfer_status": "completed",
    "context_truncated": False,
    "inherited_context_tokens": 10,
    "added_context_tokens": 5,
    "hop_latency_ms": 12.5,
}
RUN_DOC = {
    "crew_run_id": RUN,
    "crew_id": CREW,
    "crew_revision_id": CREV,
    "status": "completed",
    "completeness": "complete",
    "entry_role_token": TOKEN,
    "hop_count": 1,
    "loop_count": 0,
    "halted_by_policy": False,
    "halt_reason": None,
    "started_at": NOW,
    "exclusive_cost_usd": None,
}
EXEC_DOC = {
    "invocation_id": INV,
    "crew_run_id": RUN,
    "role_token": TOKEN,
    "attempt": 1,
    "exclusive_cost_usd": 0.01,
    "inclusive_cost_usd": 0.02,
    "exclusive_latency_ms": 10,
    "inclusive_latency_ms": 20,
    "started_at": NOW,
}

ENTITIES = {
    "crew_schema.json": CREW_DOC,
    "crew_role_schema.json": ROLE_DOC,
    "crew_role_binding_schema.json": BINDING_DOC,
    "crew_revision_schema.json": REVISION_DOC,
    "crew_handoff_schema.json": HANDOFF_DOC,
    "crew_run_schema.json": RUN_DOC,
    "crew_member_execution_schema.json": EXEC_DOC,
}


@pytest.mark.parametrize("name", sorted(p.name for p in CREW_DIR.glob("*.json")))
def test_every_crew_schema_is_valid_draft7(name: str) -> None:
    schema = _load(name)
    Draft7Validator.check_schema(schema)
    assert schema.get("$id", "").endswith("/crew/" + name) or name == "crew_endpoints.json"


@pytest.mark.parametrize("name", sorted(ENTITIES))
def test_valid_entity_examples(name: str) -> None:
    _ok(name, ENTITIES[name])


@pytest.mark.parametrize("name", sorted(ENTITIES))
def test_entities_are_closed(name: str) -> None:
    doc = copy.deepcopy(ENTITIES[name])
    doc["unknown_extra_field"] = 1
    _bad(name, doc)


@pytest.mark.parametrize(
    ("name", "field", "value"),
    [
        ("crew_schema.json", "crew_id", "crew_XYZ"),
        ("crew_schema.json", "crew_id", CREW + "\n"),
        ("crew_role_schema.json", "role_token", "k3j9x2m7"),  # old underscore-free form
        ("crew_role_schema.json", "role_token", "rtk_" + "A" * 26),
        ("crew_role_schema.json", "role_token", "rtk_" + "a" * 25),
        ("crew_role_schema.json", "role_token", "rtk_" + "1" * 26),  # base32 has no 0/1/8/9
        ("crew_schema.json", "crew_key", "has space"),
        ("crew_schema.json", "crew_key", "x" * 129),
        ("crew_schema.json", "crew_key", "tri.age"),
        ("crew_schema.json", "latest_revision_no", 0),
        ("crew_schema.json", "created_by", "u" * 256),
        ("crew_role_binding_schema.json", "unit_ref", "my_unit"),
        ("crew_role_binding_schema.json", "agent_id", "a" * 513),
        ("crew_role_binding_schema.json", "pinned_agent_digest", DIGEST),
        ("crew_role_schema.json", "display", {"icon": "free-text"}),
        ("crew_role_schema.json", "display", {"color": "red"}),
        ("crew_run_schema.json", "scenario_ref", "Alice_has_diabetes"),
        ("crew_handoff_schema.json", "dedup_id", "not-a-uuid"),
        ("crew_role_schema.json", "role_id", CREW),
        ("crew_role_binding_schema.json", "binding_kind", "unit"),
        ("crew_role_binding_schema.json", "state", "active"),
        ("crew_role_binding_schema.json", "provenance", "guessed"),
        ("crew_revision_schema.json", "source", "inferred_suggestion"),
        ("crew_revision_schema.json", "revision_no", 0),
        ("crew_handoff_schema.json", "transfer_status", "failed"),
        ("crew_handoff_schema.json", "hop_seq", 0),
        ("crew_run_schema.json", "crew_run_id", "0191a2b3-c4d5-4e6f-8a9b-0c1d2e3f4a5b"),
        ("crew_run_schema.json", "halt_reason", "because"),
        ("crew_run_schema.json", "status", "done"),
        ("crew_member_execution_schema.json", "exclusive_cost_usd", -1),
    ],
)
def test_invalid_values_rejected(name: str, field: str, value: object) -> None:
    doc = copy.deepcopy(ENTITIES[name])
    doc[field] = value
    _bad(name, doc)


def test_transfer_status_enum_is_exactly_the_closed_set() -> None:
    common = _load("crew_common_schema.json")["definitions"]
    assert common["TransferStatus"]["enum"] == [
        "completed",
        "dropped",
        "schema_error",
        "timeout",
        "loop_halted",
    ]
    for status in common["TransferStatus"]["enum"]:
        _ok("crew_handoff_schema.json", {**HANDOFF_DOC, "transfer_status": status})


def test_halt_reason_must_match_halted_flag() -> None:
    _ok(
        "crew_run_schema.json",
        {**RUN_DOC, "status": "halted", "halted_by_policy": True, "halt_reason": "loop_detected"},
    )
    _bad("crew_run_schema.json", {**RUN_DOC, "halted_by_policy": True, "halt_reason": None})
    _bad(
        "crew_run_schema.json",
        {**RUN_DOC, "halted_by_policy": False, "halt_reason": "loop_detected"},
    )


def test_requests() -> None:
    _ok("crew_create_request_schema.json", {"crew_key": "k", "name": "n"})
    _bad("crew_create_request_schema.json", {"crew_key": "k", "name": "n", "crew_id": CREW})
    _bad("crew_create_request_schema.json", {"name": "n"})
    _ok(
        "crew_role_upsert_request_schema.json",
        {"role_key": "triage", "display": {"color": "#aabbcc"}},
    )
    _bad("crew_role_upsert_request_schema.json", {"role_key": "triage", "role_token": TOKEN})
    _ok("crew_create_request_schema.json", {"crew_key": "Triage_Crew-1", "name": "n"})
    _bad("crew_create_request_schema.json", {"crew_key": "has space", "name": "n"})
    _ok("crew_update_request_schema.json", {"name": "n2"})
    _bad("crew_update_request_schema.json", {})
    _bad("crew_update_request_schema.json", {"crew_key": "new"})
    binding = {"role_id": CROL, "binding_kind": "agent", "agent_id": "agent_1"}
    req = {"source": "sdk_declared", "base_revision_no": 0, "bindings": [binding]}
    name = "crew_revision_create_request_schema.json"
    _ok(name, req)
    _ok(name, {**req, "base_revision_no": 3, "entry_role_id": CROL})
    _bad(name, {k: v for k, v in req.items() if k != "base_revision_no"})
    _bad(name, {**req, "base_revision_no": -1})
    _bad(name, {**req, "bindings": []})
    _bad(name, {**req, "bindings": [{**binding, "state": "bound"}]})
    # two entry bindings cannot be expressed: no per-binding entry flag is accepted
    two = [{**binding, "entry": True}, {**binding, "role_id": "crol_" + "12" * 8, "entry": True}]
    _bad(name, {**req, "bindings": two})
    _bad(name, {**req, "bindings": [{**binding, "unit_ref": "u"}]})
    _bad(name, {**req, "bindings": [{**binding, "agent_id": None}]})


def _binding(**kw: object) -> dict:
    return {**BINDING_DOC, **kw}


def test_binding_invariants() -> None:
    n = "crew_role_binding_schema.json"
    _ok(n, _binding(state="unbound", agent_id=None, provenance="inferred_suggestion"))
    _ok(n, _binding(state="retired", provenance="inferred_suggestion"))
    _ok(
        n,
        _binding(
            binding_kind="agent_unit", pinned_agent_revision="r7", pinned_config_digest=DIGEST
        ),
    )
    _bad(n, _binding(state="bound", provenance="inferred_suggestion"))
    _bad(n, _binding(state="bound", agent_id=None))
    _bad(n, _binding(state="unbound", agent_id="agent_1"))
    _bad(n, {k: v for k, v in BINDING_DOC.items() if k != "crew_id"})
    _bad(n, _binding(entry="yes"))


def test_revision_two_entry_flags_are_a_service_check() -> None:
    # Documented limit: draft-07 cannot count; the README lists it as a service check
    # (partial unique index). The request side makes it unrepresentable (see test_requests).
    readme = (CREW_DIR / "README.md").read_text(encoding="utf-8")
    assert "at most one entry binding per revision" in readme


def test_role_key_nullable_and_icon_enum() -> None:
    _ok("crew_role_schema.json", {**ROLE_DOC, "role_key": None})
    _ok("crew_role_schema.json", {**ROLE_DOC, "display": {"icon": "bolt", "color": "#00ff00"}})


def test_error_messages_are_fixed_templates() -> None:
    common = _load("crew_common_schema.json")["definitions"]["CrewErrorCode"]["enum"]
    assert "crew_feature_disabled" not in common
    tmpl = _load("crew_error_schema.json")
    mapped = {b["if"]["properties"]["error_code"]["const"] for b in tmpl["allOf"]}
    assert mapped == set(common)
    ok = {
        "success": False,
        "message": "Not found.",
        "error": "not_found",
        "error_code": "crew_not_found",
    }
    _ok("crew_error_schema.json", ok)
    _bad("crew_error_schema.json", {**ok, "message": "Crew Alice not found"})
    _bad(
        "crew_error_schema.json", {**ok, "message": "The crew is archived."}
    )  # wrong template for code


def test_role_list_response() -> None:
    _ok(
        "crew_role_list_response_schema.json",
        {"success": True, "message": "ok", "data": {"items": [ROLE_DOC]}},
    )


def test_run_cold_cache_nullability() -> None:
    cold = {
        **RUN_DOC,
        "completeness": "partial",
        "crew_revision_id": None,
        "entry_role_token": None,
    }
    _ok("crew_run_schema.json", cold)
    _bad("crew_run_schema.json", {**cold, "completeness": "complete"})
    _ok("crew_member_execution_schema.json", {**EXEC_DOC, "role_token": None})
    _ok("crew_run_schema.json", {**RUN_DOC, "scenario_ref": "scn_" + "ab" * 8})


def test_handoff_lifecycle_fields() -> None:
    _ok("crew_handoff_schema.json", {**HANDOFF_DOC, "entered": True, "to_invocation_id": INV})
    for field in ("requested_at", "entered", "dedup_id", "from_invocation_id", "to_invocation_id"):
        _bad("crew_handoff_schema.json", {k: v for k, v in HANDOFF_DOC.items() if k != field})


def test_trial_allocation() -> None:
    doc = {
        "configuration_run_id": "123e4567-e89b-42d3-a456-426614174000",
        "crew_id": CREW,
        "crew_revision_id": CREV,
        "role_token": TOKEN,
        "member_config_digest": DIGEST,
    }
    _ok("crew_trial_allocation_schema.json", doc)
    _bad("crew_trial_allocation_schema.json", {**doc, "member_config_digest": "abc"})
    _bad("crew_trial_allocation_schema.json", {**doc, "extra": 1})


def _vec_binding(role: str, agent: str, **kw: object) -> dict:
    base = {
        "role_id": role,
        "binding_kind": "agent",
        "agent_id": agent,
        "unit_ref": None,
        "pinned_agent_revision": None,
        "pinned_config_digest": None,
        "entry": False,
        "state": "bound",
        "provenance": "portal",
    }
    return {**base, **kw}


def _canonical(crew_id: str, bindings: list[dict]) -> str:
    ordered = sorted(bindings, key=lambda x: x["role_id"])
    return json.dumps(
        {"crew_id": crew_id, "bindings": ordered},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


DIGEST_VECTOR_JSON = (
    '{"bindings":[{"agent_id":"agent_a","binding_kind":"agent","entry":true,'
    '"pinned_agent_revision":null,"pinned_config_digest":null,"provenance":"portal",'
    '"role_id":"crol_0101010101010101","state":"bound","unit_ref":null},'
    '{"agent_id":"agént_é","binding_kind":"agent","entry":false,'
    '"pinned_agent_revision":null,"pinned_config_digest":null,"provenance":"portal",'
    '"role_id":"crol_0202020202020202","state":"bound","unit_ref":null}],'
    '"crew_id":"crew_abababababababab"}'
)
DIGEST_VECTOR = "sha256:579ab49c3699f17052f5134079ba84fbca7c313878773072a4020589f79bd8bc"


def test_digest_canonicalization_vectors() -> None:
    import hashlib

    readme = (CREW_DIR / "README.md").read_text(encoding="utf-8")
    assert 'sort_keys=True, separators=(",", ":"), ensure_ascii=False' in readme
    assert "raw UTF-8" in readme
    first = _vec_binding("crol_" + "01" * 8, "agent_a", entry=True)
    second = _vec_binding("crol_" + "02" * 8, "ag\u00e9nt_\u00e9")
    body = _canonical(CREW, [first, second])
    assert body == DIGEST_VECTOR_JSON
    assert "\\u00e9" not in body and "é" in body  # non-ASCII stays raw UTF-8
    digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert digest == DIGEST_VECTOR
    # reordered input gives the same canonical JSON and digest
    reordered = _canonical(CREW, [second, first])
    assert reordered == body
    assert "sha256:" + hashlib.sha256(reordered.encode("utf-8")).hexdigest() == DIGEST_VECTOR
    # any membership change changes the digest
    changed = _canonical(CREW, [{**first, "agent_id": "agent_b"}, second])
    assert "sha256:" + hashlib.sha256(changed.encode("utf-8")).hexdigest() != DIGEST_VECTOR
    _ok("crew_revision_schema.json", {**REVISION_DOC, "digest": DIGEST_VECTOR})


def test_revision_request_rejects_inferred_suggestion() -> None:
    name = "crew_revision_create_request_schema.json"
    binding = {"role_id": CROL, "binding_kind": "agent", "agent_id": "agent_1"}
    req = {"source": "portal", "base_revision_no": 0}
    _ok(name, {**req, "bindings": [{**binding, "provenance": "sdk_declared"}]})
    _ok(name, {**req, "bindings": [{**binding, "provenance": "portal"}]})
    _bad(name, {**req, "bindings": [{**binding, "provenance": "inferred_suggestion"}]})


def test_run_ids_are_server_issued_uuids_not_content() -> None:
    uid = "123e4567-e89b-42d3-a456-426614174000"
    _ok("crew_run_schema.json", {**RUN_DOC, "experiment_run_id": uid, "configuration_run_id": uid})
    canaries = ["Alice_has_diabetes", "agent_1", "my experiment", uid.upper(), uid + "\n"]
    for canary in canaries:
        _bad("crew_run_schema.json", {**RUN_DOC, "experiment_run_id": canary})
        _bad("crew_run_schema.json", {**RUN_DOC, "configuration_run_id": canary})
    alloc = {
        "configuration_run_id": uid,
        "crew_id": CREW,
        "crew_revision_id": CREV,
        "role_token": TOKEN,
        "member_config_digest": DIGEST,
    }
    _ok("crew_trial_allocation_schema.json", alloc)
    for canary in canaries:
        _bad("crew_trial_allocation_schema.json", {**alloc, "configuration_run_id": canary})


def test_closed_crew_429() -> None:
    n = "crew_rate_limit_schema.json"
    ok = {
        "success": False,
        "message": "Too many requests.",
        "error": "rate_limited",
        "error_code": "crew_rate_limited",
        "retry_after": 5,
    }
    _ok(n, ok)
    _bad(n, {**ok, "details": {"scope": "global", "retry_after": 5}})
    _bad(n, {**ok, "message": "Crew Alice is throttled"})
    _bad(n, {**ok, "error_code": "RATE_LIMIT_EXCEEDED"})
    _bad(n, {**ok, "retry_after": 0})
    _bad(n, {k: v for k, v in ok.items() if k != "retry_after"})
    doc = _load("crew_endpoints.json")
    for item in doc["paths"].values():
        for op in item.values():
            ref = op["responses"]["429"]["content"]["application/json"]["schema"]["$ref"]
            assert ref == "./crew_rate_limit_schema.json"


def test_handoff_entered_matches_destination_invocation() -> None:
    n = "crew_handoff_schema.json"
    _ok(n, {**HANDOFF_DOC, "entered": True, "to_invocation_id": INV})
    _ok(n, {**HANDOFF_DOC, "entered": False, "to_invocation_id": None})
    _bad(n, {**HANDOFF_DOC, "entered": True, "to_invocation_id": None})
    _bad(n, {**HANDOFF_DOC, "entered": False, "to_invocation_id": INV})


def test_member_null_role_token_is_an_ingestion_cross_record_check() -> None:
    readme = (CREW_DIR / "README.md").read_text(encoding="utf-8")
    assert "Ingestion cross-record check" in readme
    assert (
        "null `role_token` is rejected unless its parent `crew_run` has `completeness != complete`"
        in readme
    )


def test_error_body_is_closed_and_never_free_form() -> None:
    err = {
        "success": False,
        "message": "The binding conflicts with an existing binding.",
        "error": "conflict",
        "error_code": "crew_binding_conflict",
    }
    _ok("crew_error_schema.json", err)
    _bad("crew_error_schema.json", {**err, "error_code": "whatever"})
    _bad("crew_error_schema.json", {**err, "details": {"agent_id": "echoed"}})


def test_responses() -> None:
    env = {"success": True, "message": "ok"}
    _ok("crew_response_schema.json", {**env, "data": {**CREW_DOC, "roles": [ROLE_DOC]}})
    _ok("crew_revision_response_schema.json", {**env, "data": REVISION_DOC})
    page = {
        "page": 1,
        "per_page": 20,
        "total": 1,
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    }
    _ok(
        "crew_list_response_schema.json", {**env, "data": {"items": [CREW_DOC], "pagination": page}}
    )
    _ok(
        "crew_revision_list_response_schema.json",
        {**env, "data": {"items": [REVISION_DOC], "pagination": page}},
    )


MEMBERSHIP_DOC = {
    "agent_id": "agent_1",
    "crew_id": CREW,
    "role_id": CROL,
    "role_token": TOKEN,
    "revision_no": 1,
}


def test_crew_summary_fields() -> None:
    _ok(
        "crew_schema.json",
        {**CREW_DOC, "role_count": 2, "bound_member_count": 1, "entry_role_id": CROL},
    )
    for field, value in (
        ("role_count", -1),
        ("bound_member_count", -1),
        ("bound_member_count", "1"),
        ("entry_role_id", "crol_XYZ"),
    ):
        _bad("crew_schema.json", {**CREW_DOC, field: value})
    for field in ("role_count", "bound_member_count", "entry_role_id"):
        doc = {k: v for k, v in CREW_DOC.items() if k != field}
        _bad("crew_schema.json", doc)
    _ok(
        "crew_response_schema.json",
        {"success": True, "message": "ok", "data": {**CREW_DOC, "roles": [], "role_count": 3}},
    )


def test_membership_contract() -> None:
    _ok("crew_membership_schema.json", MEMBERSHIP_DOC)
    _bad("crew_membership_schema.json", {**MEMBERSHIP_DOC, "extra": 1})
    _bad("crew_membership_schema.json", {**MEMBERSHIP_DOC, "role_token": "rtk_short"})
    _bad("crew_membership_schema.json", {**MEMBERSHIP_DOC, "revision_no": 0})
    _bad("crew_membership_schema.json", {**MEMBERSHIP_DOC, "agent_id": None})
    for field in MEMBERSHIP_DOC:
        _bad("crew_membership_schema.json", {k: v for k, v in MEMBERSHIP_DOC.items() if k != field})
    page = {
        "page": 1,
        "per_page": 20,
        "total": 1,
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    }
    env = {"success": True, "message": "ok"}
    _ok(
        "crew_membership_list_response_schema.json",
        {**env, "data": {"items": [MEMBERSHIP_DOC], "pagination": page}},
    )
    _bad(
        "crew_membership_list_response_schema.json",
        {**env, "data": {"items": [{**MEMBERSHIP_DOC, "name": "x"}], "pagination": page}},
    )
    doc = json.loads((CREW_DIR / "crew_endpoints.json").read_text(encoding="utf-8"))
    op = doc["paths"]["/api/v1beta/projects/{project_id}/crews/memberships"]["get"]
    agent = next(p for p in op["parameters"] if p["name"] == "agent_id")
    assert agent["schema"]["maxItems"] == 100 and agent["explode"] is True
    assert any(p["name"] == "include_archived" for p in op["parameters"])


def test_endpoints_catalog_shape() -> None:
    schemas_dir = Path(get_schemas_dir())
    doc = json.loads((schemas_dir / "crew" / "crew_endpoints.json").read_text(encoding="utf-8"))
    base = "/api/v1beta/projects/{project_id}/crews"
    ops = {(m, p[len(base) :]) for p, item in doc["paths"].items() for m in item}
    assert ops == {
        ("post", ""),
        ("get", ""),
        ("get", "/memberships"),
        ("get", "/{crew_id}"),
        ("put", "/{crew_id}"),
        ("post", "/{crew_id}/archive"),
        ("post", "/{crew_id}/unarchive"),
        ("get", "/{crew_id}/roles"),
        ("post", "/{crew_id}/roles"),
        ("get", "/{crew_id}/revisions"),
        ("post", "/{crew_id}/revisions"),
    }
    assert all(p.startswith(base) for p in doc["paths"])
    assert "409" in doc["paths"][base + "/{crew_id}/revisions"]["post"]["responses"]
    for item in doc["paths"].values():
        for op in item.values():
            assert "429" in op["responses"] and "404" in op["responses"]
            assert "403" not in op["responses"]
            assert any(p["name"] == "project_id" for p in op["parameters"])
            for status, resp in op["responses"].items():
                ref = resp["content"]["application/json"]["schema"]["$ref"]
                if status == "429":
                    assert ref == "./crew_rate_limit_schema.json"
                elif status.startswith(("4", "5")):
                    assert ref == "./crew_error_schema.json"


def test_content_vs_identifier_annotations() -> None:
    crew = _load("crew_schema.json")["properties"]
    for field in ("crew_key", "name", "description"):
        assert crew[field]["x-content"] is True
        assert crew[field]["x-privacy-classification"] == "user_content"
    assert crew["crew_id"]["x-identifier"] is True
    role = _load("crew_role_schema.json")["properties"]
    assert role["role_key"]["x-content"] is True
    assert role["role_token"]["x-identifier"] is True and role["role_id"]["x-identifier"] is True
    assert _load("crew_run_schema.json")["properties"]["crew_run_id"]["x-identifier"] is True
    pattern = _load("crew_common_schema.json")["definitions"]["RoleToken"]["pattern"]
    assert pattern.startswith("^rtk_[a-z2-7]{26}")
    assert _load("crew_common_schema.json")["definitions"]["AgentId"]["maxLength"] == 512
