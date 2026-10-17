"""GET /api/v1/sessions/{session_id}/identity-binding (content identity M3 PR-5-lite).

Declared ahead of the Backend branch (TraigentBackend feat/content-identity-run-binding)
landing on develop: x-asserted-against-backend false, same convention as PR #517's
datasets/content_identity_endpoints.json.

The response is registered in optimization/optimization_endpoints.json (the sessions
catalog, under the sdk_tuning contract root -- every other /api/v1/sessions/* route
lives there), NOT in datasets/content_identity_endpoints.json: this route is
session-scoped, like next-trial/results/finalize, not a dataset-scoped route.

Valid fixtures mirror TraigentBackend's own serializer exactly
(src/services/content_identity/run_binding.py _run_binding_json / _trial_binding_json /
_stored_members) and the read route's own docstring
(src/routes/traigent_session_routes.py get_session_identity_binding), cross-checked
against tests/unit/routes/test_run_identity_binding_http.py. Identifiers are REAL: minted
with the reference implementation so a stated root recomputes from its members, exactly
as test_content_identity_endpoints.py does for the dataset-version identity endpoints.

Also covers the two request-side additions this PR-5-lite makes reachable
(execution/content_identity_wire_v1_schema.json SessionContentIdentityWireV1 /
TrialContentIdentityWireV1): the optional, non-breaking content_identity property on
POST /api/v1/sessions and on POST /api/v1/sessions/{session_id}/results'
metadata.content_identity.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import SchemaValidator
from traigent_schema import example_identity as ei

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
OPTIMIZATION = SCHEMAS / "optimization"
CATALOG_PATH = OPTIMIZATION / "optimization_endpoints.json"
CATALOG_BASE = "https://schemas.traigent.ai/optimization/optimization_endpoints.json"
RESPONSE_SCHEMA_PATH = OPTIMIZATION / "session_identity_binding_response_schema.json"
RESULTS_REQUEST_SCHEMA_PATH = OPTIMIZATION / "session_submit_results_request_schema.json"

IDENTITY_BINDING = "/api/v1/sessions/{session_id}/identity-binding"
SESSIONS = "/api/v1/sessions"
RESULTS = "/api/v1/sessions/{session_id}/results"


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()
CATALOG = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _response_validator(path: str, method: str, status: str) -> Draft7Validator:
    schema = CATALOG["paths"][path][method]["responses"][status]["content"]["application/json"][
        "schema"
    ]
    return Draft7Validator({"$id": CATALOG_BASE, "allOf": [schema]}, registry=_REGISTRY)


def _errors(validator: Draft7Validator, instance: Any) -> list[str]:
    return [error.message for error in validator.iter_errors(instance)]


def _envelope(data: Any, message: str = "Success") -> dict[str, Any]:
    return {"success": True, "message": message, "data": data}


# ---------------------------------------------------------------------------
# Real identifiers (reference implementation), mirroring
# test_content_identity_endpoints.py's approach.
# ---------------------------------------------------------------------------

TENANT_ID = "tenant_ci_run_binding"
KEYS = ei.derive_tenant_keys(bytes.fromhex("b6" * 16 + "6b" * 16), TENANT_ID)


def _member(input_text: str, expected: str, count: int) -> dict[str, Any]:
    example_id = ei.compute_example_id(KEYS, input_text)
    example_version = ei.compute_example_version(KEYS, example_id, expected=expected)
    return {"example_id": example_id, "example_version": example_version, "count": count}


MEMBERS = sorted(
    (_member("q1", "a1", 1), _member("q2", "a2", 2)),
    key=lambda m: (m["example_id"], m["example_version"]),
)
ROOT_DIGEST = ei.compute_multiset_root(
    [ei.MultisetMember(m["example_id"], m["example_version"], m["count"]) for m in MEMBERS]
).root

MEMBER_LIST: dict[str, Any] = {
    "members_ref": "ml1:cml_0123456789abcdef0123456789abcdef",
    "scheme": "traigent.content_identity.v1",
    "key_id": KEYS.key_id,
    "root": ROOT_DIGEST,
    "distinct_count": 2,
    "total_count": 3,
    "conflicting_example_ids": [],
    "members_source": "server_computed",
    "members": MEMBERS,
    "provenance": "server_recorded",
}

DIGEST = "sha256:" + "0" * 64

BINDING: dict[str, Any] = {
    "experiment_run_id": "run_0123456789abcdef",
    "scheme": "traigent.content_identity.v1",
    "key_id": KEYS.key_id,
    "record_state": "draft",
    "rejection_reason": None,
    "agent_id": "agent_0123456789abcdef",
    "agent_key": "support-router",
    "base_build_digest": DIGEST,
    "base_head_generation": None,
    "dataset_members_ref": MEMBER_LIST["members_ref"],
    "dataset_root": ROOT_DIGEST,
    "dataset_version_id": None,
    "facts": {
        "version": "traigent.run_identity_binding.facts.v1",
        "key_id": {"status": "verified", "provenance": "server_recorded"},
    },
    "declared": {"scheme": "traigent.content_identity.v1", "key_id": KEYS.key_id},
    "created_at": "2026-09-24T10:00:00+00:00",
    "completed_at": None,
    "dataset_members": MEMBER_LIST,
}

TRIAL: dict[str, Any] = {
    "configuration_run_id": "trial_0123456789abcdef",
    "experiment_run_id": BINDING["experiment_run_id"],
    "trial_origin": "server_issued",
    "rejection_reason": None,
    "candidate_build_digest": DIGEST,
    "evaluated_members_ref": MEMBER_LIST["members_ref"],
    "evaluated_root": ROOT_DIGEST,
    "observed_provider_versions": [
        {
            "provider": "openai",
            "requested_model": "gpt-4o",
            "response_model": "gpt-4o-2026-08-01",
            "system_fingerprint": None,
            "call_count": 5,
        }
    ],
    "facts": {"trial_origin": {"value": "server_issued", "provenance": "server_recorded"}},
    "declared": {"scheme": "traigent.content_identity.v1", "trial_id": "trial_0123456789abcdef"},
    "created_at": "2026-09-24T10:05:00+00:00",
    "evaluated_members": MEMBER_LIST,
}

TRIAL_UNBOUND: dict[str, Any] = {
    "configuration_run_id": "trial_fedcba9876543210",
    "experiment_run_id": BINDING["experiment_run_id"],
    "trial_origin": "client_submitted",
    "rejection_reason": "wire_schema_invalid",
    "candidate_build_digest": None,
    "evaluated_members_ref": None,
    "evaluated_root": None,
    "observed_provider_versions": [],
    "facts": {"wire": {"valid": False, "findings": [{"keyword": "required", "schema_path": ""}]}},
    "declared": {"scheme": "nope"},
    "created_at": "2026-09-24T10:06:00+00:00",
    "evaluated_members": None,
}

RESPONSE = _envelope({"session_id": "sess_0123456789abcdef", "binding": BINDING, "trials": [TRIAL]})


# ---------------------------------------------------------------------------
# 1. The schema and the catalog
# ---------------------------------------------------------------------------


def test_schema_is_valid_draft7() -> None:
    Draft7Validator.check_schema(json.loads(RESPONSE_SCHEMA_PATH.read_text(encoding="utf-8")))


def test_route_is_registered_as_a_session_scoped_get() -> None:
    op = CATALOG["paths"][IDENTITY_BINDING]["get"]
    assert op["x-asserted-against-backend"] is False
    assert op["operationId"]
    assert set(op["responses"]) == {"200", "401", "403", "404", "429", "500"}
    assert "requestBody" not in op
    (param,) = op["parameters"]
    assert param["name"] == "session_id"
    assert param["required"] is True


def test_every_catalog_ref_resolves() -> None:
    def refs(node: Any) -> list[str]:
        if isinstance(node, dict):
            found = [node["$ref"]] if isinstance(node.get("$ref"), str) else []
            return found + [r for value in node.values() for r in refs(value)]
        if isinstance(node, list):
            return [r for item in node for r in refs(item)]
        return []

    resolver = _REGISTRY.resolver(base_uri=CATALOG_BASE)
    for ref in refs(CATALOG["paths"][IDENTITY_BINDING]):
        resolver.lookup(ref)  # raises if the target file or pointer is missing


def test_validator_binds_the_route() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    assert f"GET:{IDENTITY_BINDING}" in validator._known_endpoints


def test_identity_binding_wire_schemas_are_now_reachable() -> None:
    report = json.loads(
        (ROOT / "reports" / "schema_reachability" / "unreachable_schemas.json").read_text(
            encoding="utf-8"
        )
    )
    unreachable = set(report["unreachableSchemas"])
    for rel in (
        "optimization/session_identity_binding_response_schema.json",
        "execution/content_identity_wire_v1_schema.json",
        "execution/run_identity_binding_v1_schema.json",
        "agents/agent_version_manifest_v1_schema.json",
        "evaluation/evaluator_version_manifest_v1_schema.json",
    ):
        assert rel not in unreachable, rel


# ---------------------------------------------------------------------------
# 2. GET .../identity-binding response: valid shapes
# ---------------------------------------------------------------------------

OK = _response_validator(IDENTITY_BINDING, "get", "200")


def test_valid_response_with_bound_trial_validates_and_recomputes() -> None:
    assert _errors(OK, RESPONSE) == []
    rebuilt = ei.compute_multiset_root(
        [ei.MultisetMember(m["example_id"], m["example_version"], m["count"]) for m in MEMBERS]
    )
    assert rebuilt.root == BINDING["dataset_root"] == TRIAL["evaluated_root"]
    for identifier in (BINDING["dataset_root"], *(m["example_id"] for m in MEMBERS)):
        assert ei.key_id_of(identifier) == BINDING["key_id"]


def test_valid_response_with_no_trials_and_a_never_bound_member_list() -> None:
    body = _envelope({"session_id": "sess_empty", "binding": BINDING, "trials": []})
    assert _errors(OK, body) == []


def test_rejected_and_unbound_trial_validates() -> None:
    body = _envelope(
        {"session_id": "sess_0123456789abcdef", "binding": BINDING, "trials": [TRIAL_UNBOUND]}
    )
    assert _errors(OK, body) == []


def test_minimal_draft_binding_before_any_content_identity_facts_resolve() -> None:
    """The very first row inserted: key_id/dataset/agent still null, only wire facts set."""
    minimal = {
        **BINDING,
        "key_id": None,
        "agent_id": None,
        "agent_key": None,
        "base_build_digest": None,
        "dataset_members_ref": None,
        "dataset_root": None,
        "dataset_version_id": None,
        "declared": None,
        "rejection_reason": "content_identity_too_large",
        "facts": {"version": "traigent.run_identity_binding.facts.v1", "wire": {"valid": False}},
        "dataset_members": None,
    }
    body = _envelope({"session_id": "sess_min", "binding": minimal, "trials": []})
    assert _errors(OK, body) == []


def test_member_list_load_error_shape_validates() -> None:
    """The narrow shape RunIdentityBindingService._stored_members serves when a stored
    list fails integrity verification -- documented, not yet Backend-tested."""
    load_error = {"members_ref": MEMBER_LIST["members_ref"], "status": "MemberListNotFound"}
    binding = {**BINDING, "dataset_members": load_error}
    body = _envelope({"session_id": "sess_err", "binding": binding, "trials": []})
    assert _errors(OK, body) == []


def test_declared_need_not_be_wire_schema_valid() -> None:
    """declared stores the raw client block up to the size cap even when it fails
    SessionContentIdentityWireV1 -- the response contract must not silently re-impose
    that constraint (rejection_reason communicates the failure instead)."""
    binding = {**BINDING, "declared": {"anything": "goes", "nested": {"ok": True}}}
    body = _envelope({"session_id": "sess_x", "binding": binding, "trials": []})
    assert _errors(OK, body) == []


def test_response_is_enveloped() -> None:
    assert _errors(OK, RESPONSE["data"])  # bare body refused
    assert _errors(OK, {"success": True, "data": RESPONSE["data"]})  # message required


# ---------------------------------------------------------------------------
# 3. Rejections
# ---------------------------------------------------------------------------


def _binding_mutations() -> dict[str, dict[str, Any]]:
    def with_(**changes: Any) -> dict[str, Any]:
        return {**copy.deepcopy(BINDING), **changes}

    def without(key: str) -> dict[str, Any]:
        body = copy.deepcopy(BINDING)
        del body[key]
        return body

    return {
        f"missing_{key}": without(key)
        for key in (
            "experiment_run_id",
            "scheme",
            "record_state",
            "rejection_reason",
            "facts",
            "declared",
            "created_at",
            "completed_at",
            "dataset_members",
        )
    } | {
        "unknown_scheme": with_(scheme="traigent.content_identity.v2"),
        "unknown_record_state": with_(record_state="complete_ish"),
        "unknown_rejection_reason": with_(rejection_reason="something_else"),
        "malformed_key_id": with_(key_id="not-a-kid"),
        "uppercase_dataset_root": with_(dataset_root=BINDING["dataset_root"].upper()),
        "dataset_root_with_trailing_newline": with_(dataset_root=BINDING["dataset_root"] + "\n"),
        "malformed_build_digest": with_(base_build_digest="md5:" + "0" * 32),
        "malformed_members_ref": with_(dataset_members_ref="cml_123"),
        "unknown_extra_field": with_(unexpected="value"),
        "facts_not_an_object": with_(facts="opaque"),
    }


@pytest.mark.parametrize("name", sorted(_binding_mutations()))
def test_binding_rejections(name: str) -> None:
    body = _envelope(
        {"session_id": "sess_bad", "binding": _binding_mutations()[name], "trials": []}
    )
    assert _errors(OK, body), name


def _trial_mutations() -> dict[str, dict[str, Any]]:
    def with_(**changes: Any) -> dict[str, Any]:
        return {**copy.deepcopy(TRIAL), **changes}

    def without(key: str) -> dict[str, Any]:
        body = copy.deepcopy(TRIAL)
        del body[key]
        return body

    return {
        f"missing_{key}": without(key)
        for key in (
            "configuration_run_id",
            "trial_origin",
            "observed_provider_versions",
            "facts",
            "declared",
            "evaluated_members",
        )
    } | {
        "unknown_trial_origin": with_(trial_origin="scheduled"),
        "malformed_evaluated_root": with_(evaluated_root="msr1:not-hex"),
        "observed_provider_versions_not_a_list": with_(observed_provider_versions={}),
    }


@pytest.mark.parametrize("name", sorted(_trial_mutations()))
def test_trial_rejections(name: str) -> None:
    body = _envelope(
        {"session_id": "sess_bad", "binding": BINDING, "trials": [_trial_mutations()[name]]}
    )
    assert _errors(OK, body), name


def test_member_list_shapes_are_closed() -> None:
    # Neither shape tolerates a foreign field, and the full shape cannot be partial.
    partial = {"members_ref": MEMBER_LIST["members_ref"], "root": ROOT_DIGEST}
    hybrid = {**MEMBER_LIST, "status": "ok"}
    for bad_members in (partial, hybrid):
        body = _envelope(
            {
                "session_id": "sess_bad",
                "binding": {**BINDING, "dataset_members": bad_members},
                "trials": [],
            }
        )
        assert _errors(OK, body)


# ---------------------------------------------------------------------------
# 4. POST /api/v1/sessions: content_identity is optional and additive
# ---------------------------------------------------------------------------


def _session_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "function_name": "identity_binding_probe",
        "configuration_space": {"model": {"type": "categorical", "choices": ["a", "b"]}},
        "objectives": ["accuracy"],
    }
    payload.update(overrides)
    return payload


def test_session_create_without_content_identity_still_validates() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    assert validator.validate_request(SESSIONS, "POST", _session_payload()) == []


def test_session_create_accepts_a_well_formed_content_identity_envelope() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    envelope = {
        "scheme": "traigent.content_identity.v1",
        "provenance": "declared",
        "key_status": "available",
        "key_id": KEYS.key_id,
        "agent_id_source": None,
        "agent": None,
        "evaluator_id_source": None,
        "evaluator": None,
        "dataset": None,
        "unavailable": {
            "agent": "agent_id_unavailable",
            "evaluator": "evaluator_id_unavailable",
            "dataset": "row_not_canonicalizable",
        },
    }
    errors = validator.validate_request(
        SESSIONS, "POST", _session_payload(content_identity=envelope)
    )
    assert errors == [], errors


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("not-an-object", id="string"),
        pytest.param(["a", "list"], id="array"),
        pytest.param({"scheme": "wrong"}, id="incomplete_object"),
        pytest.param(None, id="null"),
    ],
)
def test_session_create_accepts_backend_tolerated_malformed_content_identity(bad: Any) -> None:
    """TraigentBackend never 400s a session create over content_identity (M3 PR-5-lite
    tests/unit/routes/test_run_identity_binding_http.py::test_invalid_block_is_a_draft_
    with_a_reason parametrizes exactly these shapes and asserts 201): the request schema
    must stay permissive here or it would reject payloads the Backend accepts."""
    validator = SchemaValidator(contract="sdk_tuning")
    errors = validator.validate_request(SESSIONS, "POST", _session_payload(content_identity=bad))
    assert errors == [], errors


def test_session_create_schema_declares_content_identity_reachable() -> None:
    spec = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    props = spec["paths"][SESSIONS]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["properties"]
    assert "content_identity" in props
    assert "content_identity" not in spec["paths"][SESSIONS]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"].get("required", [])
    refs = json.dumps(props["content_identity"])
    assert "SessionContentIdentityWireV1" in refs


# ---------------------------------------------------------------------------
# 5. POST /api/v1/sessions/{session_id}/results: metadata.content_identity
# ---------------------------------------------------------------------------

RESULTS_SCHEMA = "session_submit_results_request_schema"


def _results_payload(**metadata_overrides: Any) -> dict[str, Any]:
    return {
        "trial_id": "trial_0123456789abcdef",
        "metrics": {"accuracy": 0.5},
        "metadata": {**metadata_overrides},
    }


def test_results_without_content_identity_still_validates() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    assert validator.validate_json(_results_payload(), RESULTS_SCHEMA) == []


def test_results_accepts_a_well_formed_trial_content_identity_envelope() -> None:
    validator = SchemaValidator(contract="sdk_tuning")
    envelope = {
        "scheme": "traigent.content_identity.v1",
        "provenance": "declared",
        "trial_id": TRIAL["configuration_run_id"],
        "candidate": None,
        "evaluated": None,
        "observed_provider_versions": [],
        "unavailable": {
            "candidate": "config_not_canonicalizable",
            "evaluated": "row_not_canonicalizable",
        },
    }
    errors = validator.validate_json(
        _results_payload(content_identity=envelope), RESULTS_SCHEMA
    )
    assert errors == [], errors


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param("nope", id="string"),
        pytest.param({"scheme": "nope"}, id="incomplete_object"),
    ],
)
def test_results_accepts_backend_tolerated_malformed_trial_content_identity(bad: Any) -> None:
    """Mirrors test_invalid_trial_block_is_a_draft_and_the_submit_succeeds: the Backend
    accepts the submit (200) and stores a draft trial binding with rejection_reason set."""
    validator = SchemaValidator(contract="sdk_tuning")
    errors = validator.validate_json(_results_payload(content_identity=bad), RESULTS_SCHEMA)
    assert errors == [], errors


def test_results_schema_declares_content_identity_reachable_and_optional() -> None:
    spec = json.loads(RESULTS_REQUEST_SCHEMA_PATH.read_text(encoding="utf-8"))
    metadata_props = spec["properties"]["metadata"]["properties"]
    assert "content_identity" in metadata_props
    assert "content_identity" not in spec["properties"]["metadata"].get("required", [])
    assert "TrialContentIdentityWireV1" in json.dumps(metadata_props["content_identity"])


def test_results_request_backward_compatible_payload_unaffected() -> None:
    """A pre-existing submission with no content_identity key at all must stay
    bit-identical: this is the additive-only guarantee breaking_schema_check enforces."""
    validator = SchemaValidator(contract="sdk_tuning")
    legacy = {
        "trial_id": "trial-legacy-1",
        "metrics": {"accuracy": 0.9},
        "duration": 1.2,
        "status": "completed",
        "metadata": {"suite": "plain"},
    }
    assert validator.validate_json(legacy, RESULTS_SCHEMA) == []
