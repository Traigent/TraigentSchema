"""Release acceptance, release and head rollback: closed request, receipt and refusal contracts."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
OPT = SCHEMAS / "optimization"
BASE = "https://schemas.traigent.ai/"
DIGEST = "a" * 64
AGENT_REF = "agentref_" + "0" * 32
USER = "123e4567-e89b-42d3-a456-426614174000"
NOW = "2026-11-20T10:00:00Z"
CODES = [
    "invalid_request",
    "unauthenticated",
    "forbidden",
    "reference_not_found",
    "acceptance_required",
    "acceptance_expired",
    "acceptance_consumed",
    "acceptance_revoked",
    "acceptance_binding_mismatch",
    "head_generation_stale",
    "rollback_target_not_accepted",
    "internal_error",
]
REQUIRED_REFUSALS = {
    "acceptance_required",
    "acceptance_expired",
    "acceptance_consumed",
    "acceptance_binding_mismatch",
    "head_generation_stale",
    "rollback_target_not_accepted",
}


def _doc():
    return json.loads((OPT / "release_acceptance_schema.json").read_text(encoding="utf-8"))


def _registry():
    registry = Registry()
    for rel in (
        "optimization/session_capabilities_schema.json",
        "optimization/tvl_reactive_common_schema.json",
        "optimization/release_acceptance_schema.json",
        "labels/label_common_schema.json",
    ):
        doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
        registry = registry.with_resource(BASE + rel, Resource.from_contents(doc))
    return registry


def _validator(name):
    schema = {"$ref": BASE + "optimization/release_acceptance_schema.json#/definitions/" + name}
    return Draft7Validator(schema, registry=_registry())


def _errors(name, body):
    return list(_validator(name).iter_errors(body))


def _create():
    return {
        "environment": "production",
        "best_config_id": "bc_1",
        "best_config_version": 3,
        "candidate_fingerprint": DIGEST,
        "gate_result_digest": DIGEST,
        "configuration_space_digest": "b" * 64,
        "agent_code_version": "0123456789abcdef0123456789abcdef01234567",
        "expected_head_generation": 4,
    }


def _acceptance(state="accepted"):
    body = {
        "id": "rac_" + "1" * 32,
        "agent_id": AGENT_REF,
        **_create(),
        "decided_by_user_id": USER,
        "decided_at": NOW,
        "expires_at": "2026-11-21T10:00:00Z",
        "state": state,
        "consumed_at": None,
        "consumed_generation": None,
        "revoked_at": None,
    }
    if state == "consumed":
        body["consumed_at"], body["consumed_generation"] = NOW, 5
    if state == "revoked":
        body["revoked_at"] = NOW
    return body


def _head(extra=None):
    body = {
        "agent_id": AGENT_REF,
        "environment": "production",
        "generation": 5,
        "best_config_id": "bc_1",
        "best_config_version": 3,
    }
    body.update(extra or {})
    return body


def test_every_object_definition_is_closed():
    for name, definition in _doc()["definitions"].items():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False, name


def test_create_request_valid_and_closed():
    assert not _errors("CreateReleaseAcceptanceRequest", _create())
    assert not _errors(
        "CreateReleaseAcceptanceRequest", {**_create(), "gate_result_digest": "no_gate_run"}
    )
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "note": "free text"})


def test_create_request_requires_every_binding_field_including_gate_digest():
    required = set(_doc()["definitions"]["CreateReleaseAcceptanceRequest"]["required"])
    assert required == set(_create())
    for key in _create():
        body = _create()
        del body[key]
        assert _errors("CreateReleaseAcceptanceRequest", body), key


@pytest.mark.parametrize("bad", ["", "none", "sha256:" + DIGEST, "A" * 64, "a" * 63, "free text"])
def test_gate_result_digest_is_a_digest_or_the_explicit_no_gate_value(bad):
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "gate_result_digest": bad})


def test_create_request_rejects_bad_scalars():
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "environment": "prod"})
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "best_config_version": 0})
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "expected_head_generation": -1})
    assert _errors("CreateReleaseAcceptanceRequest", {**_create(), "agent_code_version": "a b"})


@pytest.mark.parametrize("state", ["accepted", "consumed", "revoked"])
def test_acceptance_read_model_valid_per_state(state):
    assert not _errors("ReleaseAcceptance", _acceptance(state))
    assert not _errors(
        "ReleaseAcceptanceResponse", {"success": True, "data": _acceptance(state)}
    )


def test_acceptance_state_is_closed_and_lifecycle_consistent():
    assert _errors("ReleaseAcceptance", {**_acceptance(), "state": "pending"})
    # consumed without its consumption fields, accepted with a revoke stamp
    assert _errors("ReleaseAcceptance", {**_acceptance(), "state": "consumed"})
    assert _errors("ReleaseAcceptance", {**_acceptance(), "revoked_at": NOW})
    assert _errors("ReleaseAcceptance", {**_acceptance("revoked"), "consumed_at": NOW})
    assert _errors("ReleaseAcceptance", {**_acceptance(), "extra": 1})
    body = _acceptance()
    del body["consumed_generation"]
    assert _errors("ReleaseAcceptance", body)


def test_acceptance_list_response():
    ok = {"success": True, "data": [_acceptance(), _acceptance("consumed")]}
    assert not _errors("ReleaseAcceptanceListResponse", ok)
    assert _errors("ReleaseAcceptanceListResponse", {**ok, "data": [{"id": "x"}]})


def _release_request(**overrides):
    body = {
        "acceptance_id": "rac_" + "1" * 32,
        "expected_head_generation": 4,
        "agent_code_version": "0123456789abcdef0123456789abcdef01234567",
        "configuration_space_digest": "b" * 64,
        "gate_result_digest": DIGEST,
    }
    body.update(overrides)
    return body


def test_release_request_requires_the_three_acceptance_bindings():
    required = set(_doc()["definitions"]["ReleaseRequest"]["required"])
    assert required == {
        "acceptance_id",
        "expected_head_generation",
        "agent_code_version",
        "configuration_space_digest",
        "gate_result_digest",
    }
    assert not _errors("ReleaseRequest", _release_request())
    for key in ("agent_code_version", "configuration_space_digest", "gate_result_digest"):
        body = _release_request()
        del body[key]
        assert _errors("ReleaseRequest", body), key


@pytest.mark.parametrize(
    "key,bad",
    [
        ("configuration_space_digest", "sha256:" + DIGEST),
        ("configuration_space_digest", "A" * 64),
        ("configuration_space_digest", "b" * 63),
        ("gate_result_digest", "none"),
        ("gate_result_digest", "A" * 64),
        ("agent_code_version", "a b"),
    ],
)
def test_release_request_rejects_malformed_bindings(key, bad):
    assert _errors("ReleaseRequest", _release_request(**{key: bad}))


@pytest.mark.parametrize(
    "value",
    [
        "0123456789abcdef0123456789abcdef01234567",  # 40-hex git commit id
        "src:" + "c" * 64,
        "tag:" + "d" * 64,
        "e" * 64,  # bare sha256
    ],
)
def test_agent_code_version_accepts_commit_id_and_sha256_digests(value):
    assert not _errors("AgentCodeVersion", value)
    assert not _errors("ReleaseRequest", _release_request(agent_code_version=value))


@pytest.mark.parametrize(
    "bad",
    [
        "v1.2.3",
        "Alice_has_diabetes",
        "A" * 64,  # uppercase hex
        "a" * 63,
        "a" * 65,
        "sha256:" + "a" * 64,
        "src:" + "a" * 40,
        "src:" + "a" * 64 + "\n",
        "a" * 40 + "\n",
        "a b",
        "x;y",
        "",
    ],
)
def test_agent_code_version_rejects_non_digest_values(bad):
    assert _errors("AgentCodeVersion", bad)
    assert _errors("ReleaseRequest", _release_request(agent_code_version=bad))


def test_release_request_and_receipt():
    assert not _errors("ReleaseRequest", _release_request())
    assert _errors("ReleaseRequest", {"acceptance_id": "rac_1"})
    assert _errors(
        "ReleaseRequest",
        _release_request(environment="production"),
    )
    receipt = {"success": True, "data": _head({"acceptance_id": "rac_" + "1" * 32})}
    assert not _errors("ReleaseReceipt", receipt)
    no_acc = {"success": True, "data": _head()}
    assert _errors("ReleaseReceipt", no_acc)


def test_rollback_request_and_receipt():
    ok = {"environment": "production", "target_generation": 2, "expected_head_generation": 5}
    assert not _errors("HeadRollbackRequest", ok)
    assert _errors("HeadRollbackRequest", {"target_generation": 2, "expected_head_generation": 5})
    no_env = {k: v for k, v in ok.items() if k != "environment"}
    assert _errors("HeadRollbackRequest", no_env)
    assert _errors("HeadRollbackRequest", {**ok, "environment": "prod"})
    assert _errors("HeadRollbackRequest", {**ok, "extra": 1})
    assert _errors("HeadRollbackRequest", {**ok, "target_generation": -1})
    with_acc = {**ok, "acceptance_id": "rac_" + "1" * 32}
    assert not _errors("HeadRollbackRequest", with_acc)
    assert _errors("HeadRollbackRequest", {**ok, "acceptance_id": ""})
    assert _errors("HeadRollbackRequest", {**ok, "acceptance_id": "a b"})
    assert _errors("HeadRollbackRequest", {**ok, "acceptance_id": "a" * 129})
    data = _head({"rolled_back_to_generation": 2, "acceptance_id": "rac_1"})
    assert not _errors("HeadRollbackReceipt", {"success": True, "data": data})
    # The receipt always names the consumed acceptance; null is no longer valid.
    null_acc = {**data, "acceptance_id": None}
    assert _errors("HeadRollbackReceipt", {"success": True, "data": null_acc})
    assert _errors("HeadRollbackReceipt", {"success": True, "data": {**data, "x": 1}})


def test_refusal_codes_are_a_closed_enum_with_one_fixed_branch_each():
    schema = _doc()["definitions"]["ReleaseRefusal"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["error_code"]["enum"] == CODES
    assert REQUIRED_REFUSALS <= set(CODES)
    branches = {b["properties"]["error_code"]["const"]: b["properties"] for b in schema["oneOf"]}
    assert list(branches) == CODES
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches.values()] == messages
    assert all("{" not in m and "%" not in m for m in messages)
    for code, props in branches.items():
        body = {
            "success": False,
            "error": props["error"]["const"],
            "error_code": code,
            "message": props["message"]["const"],
        }
        assert not _errors("ReleaseRefusal", body), code
        other = {**body, "message": messages[(CODES.index(code) + 1) % len(CODES)]}
        assert _errors("ReleaseRefusal", other), code
        assert _errors("ReleaseRefusal", {**body, "acceptance_id": "rac_1"}), code
        assert _errors("ReleaseRefusal", {**body, "error_code": "made_up_code"}), code


def test_head_history_entry_has_actor_and_acceptance():
    entry = _head(
        {
            "actor_id": USER,
            "actor_kind": "user",
            "acceptance_id": "rac_" + "1" * 32,
            "valid_from": NOW,
        }
    )
    assert not _errors("HeadHistoryEntry", entry)
    key_move = {**entry, "acceptance_id": None, "actor_kind": "service_principal"}
    assert not _errors("HeadHistoryEntry", key_move)
    assert _errors("HeadHistoryEntry", {**entry, "actor_kind": "api_key"})
    assert _errors("HeadHistoryEntry", {**entry, "move_kind": "release"})
    legacy = {**entry, "actor_id": None, "actor_kind": None, "acceptance_id": None}
    assert not _errors("HeadHistoryEntry", legacy)
    missing = copy.deepcopy(entry)
    del missing["actor_id"]
    assert _errors("HeadHistoryEntry", missing)
    assert not _errors("HeadHistoryResponse", {"success": True, "data": [entry]})


def test_routes_are_registered_with_operation_ids_and_closed_bodies():
    doc = json.loads((OPT / "release_endpoints.json").read_text(encoding="utf-8"))
    base = "/api/v1/projects/{project_id}/agents/{agent_ref}"
    ops = {
        (path, method): op["operationId"]
        for path, item in doc["paths"].items()
        for method, op in item.items()
    }
    assert ops == {
        (base + "/release-acceptances", "post"): "best_configs.create_release_acceptance",
        (base + "/release-acceptances", "get"): "best_configs.list_release_acceptances",
        (base + "/release-candidates", "post"): "best_configs.create_release_candidate",
        (base + "/release-candidates", "get"): "best_configs.list_release_candidates",
        (base + "/release-candidates/{candidate_ref}", "get"): "best_configs.get_release_candidate",
        (base + "/best-config-head/release", "post"): "best_configs.release_agent_head",
        (base + "/best-config-head/rollback", "post"): "best_configs.rollback_agent_head",
    }
    for item in doc["paths"].values():
        for op in item.values():
            refusal = op["responses"]["401"]["content"]["application/json"]["schema"]["$ref"]
            assert refusal.endswith("release_acceptance_schema.json#/definitions/ReleaseRefusal")
    mep = json.loads((SCHEMAS / "mep_endpoints.json").read_text(encoding="utf-8"))
    files = [m["paths_file"] for m in mep["x-endpoint-modules"]]
    assert "./optimization/release_endpoints.json" in files


TOMBSTONE = "deleted_user_0123456789abcdef01234567"


def test_acceptance_read_model_accepts_uuid_or_erasure_tombstone_only():
    assert not _errors("ReleaseAcceptance", _acceptance())
    erased = {**_acceptance(), "decided_by_user_id": TOMBSTONE}
    assert not _errors("ReleaseAcceptance", erased)
    assert not _errors("ReleaseAcceptanceListResponse", {"success": True, "data": [erased]})
    assert not _errors("ReleaseAcceptanceResponse", {"success": True, "data": erased})
    for bad in (
        "alice",
        "",
        "deleted_user_",
        "deleted_user_0123",
        "deleted_user_" + "0" * 25,
        "deleted_user_" + "G" * 24,
        "xdeleted_user_" + "0" * 24,
        TOMBSTONE + "\n",
    ):
        assert _errors("ReleaseAcceptance", {**_acceptance(), "decided_by_user_id": bad}), bad


def test_head_history_actor_id_accepts_the_tombstone():
    entry = _head(
        {
            "actor_id": TOMBSTONE,
            "actor_kind": "user",
            "acceptance_id": None,
            "valid_from": NOW,
        }
    )
    assert not _errors("HeadHistoryEntry", entry)


def test_release_request_carries_no_environment_but_receipts_echo_it():
    props = _doc()["definitions"]
    assert "environment" not in props["ReleaseRequest"]["properties"]
    for name in ("ReleaseReceiptData", "HeadRollbackReceiptData", "HeadHistoryEntry"):
        assert "environment" in props[name]["required"], name


def test_the_agent_in_the_path_and_the_receipt_is_the_opaque_agent_ref():
    """Customer-chosen agent ids are content: the path and every receipt agent field carry AgentRef (opaque_ref)."""
    ref = "../labels/label_common_schema.json#/definitions/AgentRef"
    endpoints = json.loads((OPT / "release_endpoints.json").read_text(encoding="utf-8"))
    seen = 0
    for path, item in endpoints["paths"].items():
        if "{agent_ref}" not in path:
            continue
        for params in [item.get("parameters", [])] + [op.get("parameters", []) for op in item.values() if isinstance(op, dict)]:
            for param in params:
                if param.get("name") == "agent_ref":
                    assert param["schema"] == {"$ref": ref}, path
                    seen += 1
    assert seen >= 4
    defs = json.loads((OPT / "release_acceptance_schema.json").read_text(encoding="utf-8"))["definitions"]
    assert "AgentId" not in defs
    agent_fields = [d["properties"]["agent_id"] for d in defs.values() if "agent_id" in d.get("properties", {})]
    assert len(agent_fields) == 4
    for field in agent_fields:
        assert field["$ref"] == ref


def test_rollback_route_is_person_only_with_acceptance_codes():
    path = "/api/v1/projects/{project_id}/agents/{agent_ref}/best-config-head/rollback"
    doc = json.loads((OPT / "release_endpoints.json").read_text(encoding="utf-8"))
    op = doc["paths"][path]["post"]
    assert "Person only" in op["description"]
    assert "403 forbidden" in op["description"]
    desc = op["responses"]["409"]["description"]
    for code in (
        "head_generation_stale",
        "rollback_target_not_accepted",
        "acceptance_required",
        "acceptance_expired",
        "acceptance_consumed",
        "acceptance_revoked",
        "acceptance_binding_mismatch",
    ):
        assert code in desc, code
    props = _doc()["definitions"]["HeadRollbackRequest"]["properties"]
    assert props["acceptance_id"]["x-content-class"] == "key_material"
