"""Content-identity WIRE envelopes (execution/content_identity_wire_v1_schema.json).

The fixtures under tests/data/content_identity_wire/ are REAL payloads produced by
each SDK's own builders (scripts/content_identity_wire/capture_python.py and
capture_js.mts), not hand-written shapes. Every one must validate; every stated
digest and root must recompute from the payload with the reference implementation;
and the negative cases pin what the contract refuses (extra properties, unknown
reason codes, a dropped system_fingerprint, broken null-slot rules, the unused
in-record ``members_unavailable`` field).
"""

from __future__ import annotations

import copy
import json
import warnings
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import example_identity as ei

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
WIRE_SCHEMA_PATH = SCHEMAS / "execution" / "content_identity_wire_v1_schema.json"
GRANT_SCHEMA_PATH = SCHEMAS / "datasets" / "purpose_key_grant_v1_schema.json"
CONTENT_SCHEMA_PATH = SCHEMAS / "datasets" / "content_identity_v1_schema.json"
FIXTURES = ROOT / "tests" / "data" / "content_identity_wire"
SDK_FIXTURES = {
    "python": json.loads((FIXTURES / "python_sdk.json").read_text(encoding="utf-8")),
    "js": json.loads((FIXTURES / "js_sdk.json").read_text(encoding="utf-8")),
}


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()


def _validator(path: Path, definition: str) -> Draft7Validator:
    document = json.loads(path.read_text(encoding="utf-8"))
    return Draft7Validator(
        {"$ref": f"{document['$id']}#/definitions/{definition}"}, registry=_REGISTRY
    )


SESSION = _validator(WIRE_SCHEMA_PATH, "SessionContentIdentityWireV1")
TRIAL = _validator(WIRE_SCHEMA_PATH, "TrialContentIdentityWireV1")
REASON = _validator(WIRE_SCHEMA_PATH, "ContentIdentityUnavailableReasonV1")
GRANT = _validator(GRANT_SCHEMA_PATH, "PurposeKeyGrantV1")
MEMBER_LIST_REF = _validator(CONTENT_SCHEMA_PATH, "MemberListRefV1")

SESSION_CASES = [
    pytest.param(sdk, name, payload, id=f"{sdk}-{name}")
    for sdk, fixture in SDK_FIXTURES.items()
    for name, payload in fixture["session"].items()
]
TRIAL_CASES = [
    pytest.param(sdk, name, payload, id=f"{sdk}-{name}")
    for sdk, fixture in SDK_FIXTURES.items()
    for name, payload in fixture["trial"].items()
]


def _errors(validator: Draft7Validator, instance: Any) -> list[str]:
    return [error.message for error in validator.iter_errors(instance)]


# ---------------------------------------------------------------------------
# 1. The schemas themselves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [WIRE_SCHEMA_PATH, GRANT_SCHEMA_PATH, CONTENT_SCHEMA_PATH])
def test_schema_is_valid_draft7(path: Path) -> None:
    Draft7Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def test_every_pattern_uses_the_portable_end_anchor() -> None:
    def walk(node: Any) -> list[str]:
        if isinstance(node, dict):
            found = [node["pattern"]] if isinstance(node.get("pattern"), str) else []
            return found + [p for value in node.values() for p in walk(value)]
        if isinstance(node, list):
            return [p for item in node for p in walk(item)]
        return []

    for path in (WIRE_SCHEMA_PATH, GRANT_SCHEMA_PATH):
        for pattern in walk(json.loads(path.read_text(encoding="utf-8"))):
            assert pattern.endswith("(?![\\s\\S])"), (path.name, pattern)


# ---------------------------------------------------------------------------
# 2. Real SDK payloads validate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("sdk", "name", "payload"), SESSION_CASES)
def test_sdk_session_payload_validates(sdk: str, name: str, payload: dict[str, Any]) -> None:
    assert _errors(SESSION, payload) == []


@pytest.mark.parametrize(("sdk", "name", "payload"), TRIAL_CASES)
def test_sdk_trial_payload_validates(sdk: str, name: str, payload: dict[str, Any]) -> None:
    assert _errors(TRIAL, payload) == []


@pytest.mark.parametrize("sdk", sorted(SDK_FIXTURES))
def test_sdk_grant_input_validates(sdk: str) -> None:
    assert _errors(GRANT, SDK_FIXTURES[sdk]["purpose_key_grant"]) == []


@pytest.mark.parametrize("sdk", sorted(SDK_FIXTURES))
def test_fixtures_exercise_every_null_slot(sdk: str) -> None:
    fixture = SDK_FIXTURES[sdk]
    null_session = {
        slot
        for payload in fixture["session"].values()
        for slot in ("agent", "evaluator", "dataset")
        if payload[slot] is None
    }
    null_trial = {
        slot
        for payload in fixture["trial"].values()
        for slot in ("candidate", "evaluated")
        if payload[slot] is None
    }
    assert null_session == {"agent", "evaluator", "dataset"}
    assert null_trial == {"candidate", "evaluated"}
    observed = [
        o for p in fixture["trial"].values() for o in p["observed_provider_versions"]
    ]
    assert any(o["system_fingerprint"] is None for o in observed)
    assert any(o["system_fingerprint"] is not None for o in observed)


# ---------------------------------------------------------------------------
# 3. What the payloads state recomputes (the Backend's job in M3, proven here)
# ---------------------------------------------------------------------------


def _root_of(members: list[dict[str, Any]], key_id: str) -> ei.MultisetRoot:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ei.ConflictingExampleVersionsWarning)
        return ei.compute_multiset_root(
            [(m["example_id"], m["example_version"], m["count"]) for m in members],
            key_id=key_id,
        )


@pytest.mark.parametrize(("sdk", "name", "payload"), SESSION_CASES)
def test_session_digests_recompute(sdk: str, name: str, payload: dict[str, Any]) -> None:
    if payload["agent"] is not None:
        agent = payload["agent"]
        assert ei.compute_agent_build_digest(agent["manifest"]) == agent["build_digest"]
        assert agent["manifest"]["agent_id"] == agent["agent_id"]
    if payload["evaluator"] is not None:
        evaluator = payload["evaluator"]
        manifest = evaluator["manifest"]
        assert ei.compute_evaluator_version_digest(manifest) == evaluator["version_digest"]
        assert manifest["evaluator_id"] == evaluator["evaluator_id"]
    if payload["dataset"] is not None:
        dataset = payload["dataset"]
        assert dataset["key_id"] == payload["key_id"]
        recomputed = _root_of(dataset["members"], dataset["key_id"])
        assert recomputed.root == dataset["dataset_root"]
        assert recomputed.distinct_count == dataset["distinct_count"]
        assert recomputed.total_count == dataset["total_count"]
        assert list(recomputed.conflicting_example_ids) == dataset["conflicting_example_ids"]


@pytest.mark.parametrize(("sdk", "name", "payload"), TRIAL_CASES)
def test_trial_digests_recompute(sdk: str, name: str, payload: dict[str, Any]) -> None:
    if payload["candidate"] is not None:
        candidate = payload["candidate"]
        assert ei.compute_agent_build_digest(candidate["manifest"]) == candidate["build_digest"]
    evaluated = payload["evaluated"]
    if evaluated is not None:
        assert evaluated.get("trial_id", payload["trial_id"]) == payload["trial_id"]
        recomputed = _root_of(evaluated["members"], evaluated["key_id"])
        assert recomputed.root == evaluated["evaluated_root"]
        assert recomputed.distinct_count == evaluated["distinct_count"]
        assert recomputed.total_count == evaluated["total_count"]


def test_both_sdks_send_identical_dataset_and_evaluated_sets() -> None:
    """Same rows, same grant: the content-derived slots are byte-identical."""
    python, js = SDK_FIXTURES["python"], SDK_FIXTURES["js"]
    name = "all_slots_builtin_evaluator"
    assert python["session"][name]["dataset"] == js["session"][name]["dataset"]
    assert python["session"][name]["key_id"] == js["session"][name]["key_id"]
    for trial in ("full_dataset_with_observations", "subset_no_observations"):
        assert python["trial"][trial]["evaluated"] == js["trial"][trial]["evaluated"]
    trial = "full_dataset_with_observations"
    assert (
        python["trial"][trial]["observed_provider_versions"]
        == js["trial"][trial]["observed_provider_versions"]
    )
    assert list(python["session"][name]) == list(js["session"][name])
    assert list(python["trial"][trial]) == list(js["trial"][trial])


# ---------------------------------------------------------------------------
# 4. The reason vocabulary is exactly the union the SDKs declare
# ---------------------------------------------------------------------------


def test_reason_enum_is_the_union_of_both_sdk_vocabularies() -> None:
    schema = json.loads(WIRE_SCHEMA_PATH.read_text(encoding="utf-8"))
    enum = set(schema["definitions"]["ContentIdentityUnavailableReasonV1"]["enum"])
    python = set(SDK_FIXTURES["python"]["declared_reasons"])
    js = set(SDK_FIXTURES["js"]["declared_reasons"])
    assert enum == python | js
    # Known divergence, recorded rather than hidden: only the Python SDK reports
    # an invalid declared evaluator id separately (JS: evaluator_manifest_unavailable).
    assert python - js == {"evaluator_id_unavailable"}
    assert js - python == set()


@pytest.mark.parametrize(
    "code",
    [
        "members_unavailable",
        "unknown",
        "Evaluator_manifest_unavailable",
        "evaluator_manifest_unavailable\n",
        "",
    ],
)
def test_unknown_reason_codes_are_rejected(code: str) -> None:
    assert _errors(REASON, code)


# ---------------------------------------------------------------------------
# 5. Negative cases
# ---------------------------------------------------------------------------


def _session() -> dict[str, Any]:
    return copy.deepcopy(SDK_FIXTURES["python"]["session"]["all_slots_builtin_evaluator"])


def _trial() -> dict[str, Any]:
    return copy.deepcopy(SDK_FIXTURES["js"]["trial"]["full_dataset_with_observations"])


def _mutated(base: dict[str, Any], mutate: Any) -> dict[str, Any]:
    payload = copy.deepcopy(base)
    mutate(payload)
    return payload


def _members(n: int, key_id: str) -> list[dict[str, Any]]:
    return [
        {
            "example_id": f"ex1:{key_id}:{i:064x}",
            "example_version": f"exv1:{key_id}:{i:064x}",
            "count": 1,
        }
        for i in range(n)
    ]


@pytest.mark.parametrize(("n", "accepted"), [(2000, True), (2001, False)])
def test_inline_member_cap_is_enforced_by_the_schema(n: int, accepted: bool) -> None:
    """Spec §18 null-slot rule 4: above 2,000 distinct members the slot is null."""
    session = _session()
    key_id = session["key_id"]
    session["dataset"]["members"] = _members(n, key_id)
    trial = _trial()
    trial["evaluated"]["members"] = _members(n, trial["evaluated"]["members"][0]["example_id"].split(":")[1])
    for validator, payload in ((SESSION, session), (TRIAL, trial)):
        pending = list(validator.iter_errors(payload))
        cap_errors = []
        while pending:
            error = pending.pop()
            if error.validator == "maxItems":
                cap_errors.append(list(error.absolute_path))
            pending.extend(error.context or [])
        assert (not cap_errors) is accepted, cap_errors


SESSION_REJECTIONS = {
    "extra_top_level_property": lambda p: p.update(record_state="draft"),
    "extra_unavailable_slot": lambda p: p["unavailable"].update(
        trials="evaluation_results_unavailable"
    ),
    "unknown_reason_code": lambda p: (
        p.update(agent=None, agent_id_source=None),
        p["unavailable"].update(agent="no_reason_given"),
    ),
    "reason_for_another_slot": lambda p: (
        p.update(dataset=None),
        p["unavailable"].update(dataset="row_outside_dataset"),
    ),
    "null_agent_without_reason": lambda p: p.update(agent=None, agent_id_source=None),
    "null_agent_with_id_source": lambda p: (
        p.update(agent=None),
        p["unavailable"].update(agent="agent_id_unavailable"),
    ),
    "agent_with_reason": lambda p: p["unavailable"].update(agent="agent_id_unavailable"),
    "agent_without_id_source": lambda p: p.update(agent_id_source=None),
    "null_evaluator_with_id_source": lambda p: (
        p.update(evaluator=None),
        p["unavailable"].update(evaluator="evaluator_manifest_unavailable"),
    ),
    "evaluator_without_manifest": lambda p: p["evaluator"].pop("manifest"),
    "evaluator_witnessed_by_client": lambda p: p["evaluator"].update(
        resolution="witnessed_at_scoring"
    ),
    "null_dataset_without_reason": lambda p: p.update(dataset=None),
    "conflicts_truncated_without_dataset": lambda p: (
        p.update(dataset=None),
        p["unavailable"].update(
            dataset="members_exceed_inline_cap",
            conflicting_example_ids="conflicting_example_ids_truncated",
        ),
    ),
    "in_record_members_unavailable": lambda p: p["dataset"].update(
        members_unavailable="members_exceed_inline_cap"
    ),
    "members_ref_instead_of_members": lambda p: (
        p["dataset"].pop("members"),
        p["dataset"].update(members_ref="ml1:abc"),
    ),
    "complete_dataset_from_client": lambda p: p["dataset"].update(record_state="complete"),
    "agent_without_manifest": lambda p: p["agent"].pop("manifest"),
    "key_status_unavailable": lambda p: p.update(key_status="unavailable"),
    "server_recorded_provenance": lambda p: p.update(provenance="server_recorded"),
    "key_id_trailing_newline": lambda p: p.update(key_id=p["key_id"] + "\n"),
    "missing_unavailable": lambda p: p.pop("unavailable"),
}

TRIAL_REJECTIONS = {
    "extra_top_level_property": lambda p: p.update(repetition=0),
    "missing_system_fingerprint": lambda p: p["observed_provider_versions"][0].pop(
        "system_fingerprint"
    ),
    "missing_call_count": lambda p: p["observed_provider_versions"][0].pop("call_count"),
    "missing_response_model": lambda p: p["observed_provider_versions"][
        0
    ].pop("response_model"),
    "duplicate_observation": lambda p: p["observed_provider_versions"].append(
        copy.deepcopy(p["observed_provider_versions"][0])
    ),
    "missing_observations": lambda p: p.pop("observed_provider_versions"),
    "unknown_reason_code": lambda p: (
        p.update(evaluated=None),
        p["unavailable"].update(evaluated="members_unavailable"),
    ),
    "reason_for_another_slot": lambda p: (
        p.update(candidate=None),
        p["unavailable"].update(candidate="row_outside_dataset"),
    ),
    "null_evaluated_without_reason": lambda p: p.update(evaluated=None),
    "evaluated_with_reason": lambda p: p["unavailable"].update(
        evaluated="evaluation_results_unavailable"
    ),
    "null_candidate_without_reason": lambda p: p.update(candidate=None),
    "evaluated_members_ref": lambda p: (
        p["evaluated"].pop("members"),
        p["evaluated"].update(members_ref="ml1:abc"),
    ),
    "extra_unavailable_slot": lambda p: p["unavailable"].update(
        dataset="row_not_canonicalizable"
    ),
    "non_foreign_key_trial_id": lambda p: p.update(trial_id="trial 1"),
}


@pytest.mark.parametrize("name", sorted(SESSION_REJECTIONS))
def test_session_rejections(name: str) -> None:
    base = _session()
    assert _errors(SESSION, base) == []
    assert _errors(SESSION, _mutated(base, SESSION_REJECTIONS[name])), name


@pytest.mark.parametrize("name", sorted(TRIAL_REJECTIONS))
def test_trial_rejections(name: str) -> None:
    base = _trial()
    assert _errors(TRIAL, base) == []
    assert _errors(TRIAL, _mutated(base, TRIAL_REJECTIONS[name])), name


# ---------------------------------------------------------------------------
# 6. PurposeKeyGrantV1 and MemberListRefV1
# ---------------------------------------------------------------------------

_GRANT = SDK_FIXTURES["python"]["purpose_key_grant"]

GRANT_REJECTIONS: dict[str, Any] = {
    "missing_encoding": {k: v for k, v in _GRANT.items() if k != "encoding"},
    "base64_encoding": {**_GRANT, "encoding": "base64"},
    "uppercase_hex": {**_GRANT, "example_id_key": _GRANT["example_id_key"].upper()},
    "short_key": {**_GRANT, "example_version_key": _GRANT["example_version_key"][:-2]},
    "key_trailing_newline": {**_GRANT, "example_id_key": _GRANT["example_id_key"] + "\n"},
    "tenant_trailing_newline": {**_GRANT, "tenant_id": _GRANT["tenant_id"] + "\n"},
    "bad_kid": {**_GRANT, "kid": "K5fc87e16b0083664"},
    "master_key_field": {**_GRANT, "tenant_master": "00" * 32},
}


@pytest.mark.parametrize("name", sorted(GRANT_REJECTIONS))
def test_grant_rejections(name: str) -> None:
    assert _errors(GRANT, GRANT_REJECTIONS[name]), name


def test_grant_key_fields_are_marked_secret() -> None:
    schema = json.loads(GRANT_SCHEMA_PATH.read_text(encoding="utf-8"))
    properties = schema["definitions"]["PurposeKeyGrantV1"]["properties"]
    for field in ("example_id_key", "example_version_key"):
        assert properties[field]["x-privacy-classification"] == "secret"
        assert "never log" in properties[field]["description"].lower()
    for field in ("tenant_id", "kid", "encoding"):
        assert "x-privacy-classification" not in properties[field]


@pytest.mark.parametrize("value", ["ml1:abc", "ml1:0f6e2a1c-6d1b-4f7e-9a4e-3b2c1d0e9f8a", "ml1:" + "a" * 128])
def test_member_list_ref_accepts(value: str) -> None:
    assert _errors(MEMBER_LIST_REF, value) == []


@pytest.mark.parametrize(
    "value", ["ml1:", "ml1:abc\n", "ml2:abc", "abc", "ml1:a b", "ml1:" + "a" * 129]
)
def test_member_list_ref_rejects(value: str) -> None:
    assert _errors(MEMBER_LIST_REF, value)
