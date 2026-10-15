# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Pillar Legend v0 schemas (docs/identity/pillar-legend-v0.md).

Valid examples for every object, plus negatives: unknown fields, path-like strings, free text,
witnessed provenance on client events, impossible identity combinations, partial coverage
claiming ``exact``, contradictory capture reports, malformed timestamps, and a reference
model for the semantic rules JSON Schema cannot express.
"""

from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry

ROOT = Path(__file__).resolve().parents[1]
schemas_dir = ROOT / "traigent_schema" / "schemas"
# Literal path forms: how tests/test_schemas.py's orphan ratchet recognises a referenced schema.
LEGEND_PATH = schemas_dir / "legend" / "pillar_legend_v0.json"
MANIFEST_PATH = schemas_dir / "legend" / "recovery_manifest_v0.json"
PREDICATE_PATH = schemas_dir / "legend" / "legend_claim_predicate_v0.json"
OPS_PATH = schemas_dir / "legend" / "director_legend_ops_v0.json"
REQUESTS_PATH = schemas_dir / "legend" / "legend_requests_v0.json"
ALL_PATHS = [LEGEND_PATH, MANIFEST_PATH, PREDICATE_PATH, OPS_PATH, REQUESTS_PATH]
BASE = "https://schemas.traigent.ai/legend/v0/"
REGISTRY = build_registry()

H64 = "a" * 64
KID = "k0123456789abcdef"
SHA = "sha256:" + H64
MSR = f"msr1:{KID}:{H64}"
SSP = f"ssp1:{KID}:{H64}"
RMF = "rmf0:sha256:" + "b" * 64
HEX32 = "0123456789abcdef0123456789abcdef"
IDK = "idk_" + HEX32
TS = "2026-10-15T10:00:00Z"
REQUIRED = {
    "agent": ["code", "prompts", "helper_modules", "tool_definitions", "applied_config", "runtime"],
    "configuration": ["applied_config"],
    "evaluation_dataset": ["dataset_members", "dataset_order"],
    "evaluator": ["evaluator_code", "judge_config", "objectives", "helper_modules"],
    "search_space": ["search_space_definition"],
}
COMPLETE = {"status": "complete", "covered": ["code"], "missing": []}
PARTIAL = {"status": "partial", "covered": ["code"], "missing": ["prompts"]}


def full(kind: str) -> dict[str, Any]:
    return {"status": "complete", "covered": list(REQUIRED[kind]), "missing": []}


def ref_of(prefix: str) -> str:
    return f"{prefix}ref_{HEX32}"


def check(doc: str, definition: str | None, instance: Any) -> list[str]:
    ref = BASE + doc + (f"#/definitions/{definition}" if definition else "")
    validator = Draft7Validator(
        {"$ref": ref}, registry=REGISTRY, format_checker=Draft7Validator.FORMAT_CHECKER
    )
    return [e.message for e in validator.iter_errors(instance)]


def env(event_type: str, origin: str, evidence: str) -> dict[str, Any]:
    return {
        "schema_version": "0",
        "event_ref": ref_of("event"),
        "version_ref": ref_of("version"),
        "actor_ref": ref_of("actor"),
        "event_type": event_type,
        "origin": origin,
        "evidence_source": evidence,
        "recorded_at": TS,
        "idempotency_key": IDK,
        "request_digest": SHA,
    }


def version(kind: str, scheme: str, key: str | None, fp: str, parent: str | None) -> dict[str, Any]:
    return {
        "schema_version": "0",
        "version_ref": ref_of("version"),
        "entity_ref": ref_of("entity"),
        "kind": kind,
        "fingerprint_scheme": scheme,
        "key_id": key,
        "fingerprint": fp,
        "initial_parent_version_ref": parent,
        "identity_source": "client_declared",
        "authority_linked": True,
        "declared_at": TS,
    }


def instr(op: str, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": "0",
        "instruction_ref": ref_of("instruction"),
        "operation": op,
        **extra,
    }


def result(
    op: str, outcome: str = "succeeded", err: str | None = None, **extra: Any
) -> dict[str, Any]:
    return instr(op, outcome=outcome, error_code=err, **extra)


L = "pillar_legend_v0.json"
M = "recovery_manifest_v0.json"
P = "legend_claim_predicate_v0.json"
O = "director_legend_ops_v0.json"  # noqa: E741
Q = "legend_requests_v0.json"

MANIFEST = {
    "schema_version": "0",
    "manifest_scheme": "traigent.recovery_manifest.v0",
    "kind": "evaluation_dataset",
    "fingerprint_scheme": "dataset_multiset_root_v1",
    "key_id": KID,
    "pillar_fingerprint": MSR,
    "exporter": {"exporter_id": "dataset-rows", "exporter_version": "0.1.0"},
    "representations": [
        {"ordinal": 0, "representation_kind": "dataset_rows", "digest": SHA, "byte_length": 10}
    ],
    "ordering": "preserved",
    "dependencies": [{"version_ref": ref_of("version"), "kind": "agent"}],
    "coverage": full("evaluation_dataset"),
    "identity_digests_reproduced": True,
    "rederivation": {"source_entity_ref": ref_of("entity"), "skipped_file_count": 0},
}
SUBJECT = {
    "version_ref": ref_of("version"),
    "kind": "agent",
    "fingerprint_scheme": "agent_build_digest_v1",
    "key_id": None,
    "fingerprint": SHA,
}
PREDICATE = {
    "schema_version": "0",
    "predicate_type": "restore_verified_client_reported",
    "subject": SUBJECT,
    "evidence_source": "client_sdk_reported",
    "supporting_event_refs": [ref_of("event")],
    "recovery_manifest_fingerprint": RMF,
    "coverage_status": "complete",
    "run_tuple_digest": None,
    "evaluated_subset_root": None,
    "evaluation_protocol": None,
    "as_of": TS,
    "policy_version": "legend-claims-0",
}
DECLARE_REQ = {
    "schema_version": "0",
    "idempotency_key": IDK,
    "request_digest": SHA,
    "entity_ref": ref_of("entity"),
    "kind": "agent",
    "fingerprint_scheme": "agent_build_digest_v1",
    "key_id": None,
    "fingerprint": SHA,
    "initial_parent_version_ref": None,
    "provenance": "explicit",
    "identity_source": "sdk_fingerprinted",
}
CAPTURE_REQ = {
    "schema_version": "0",
    "idempotency_key": IDK,
    "request_digest": SHA,
    "version_ref": ref_of("version"),
    "recovery_manifest_fingerprint": RMF,
    "coverage": COMPLETE,
    "recovery_state": "stored_unverified",
    "conformance_passed": False,
    "exporter_version": "0.1.0",
}
RESTORE_REQ = {
    "schema_version": "0",
    "idempotency_key": IDK,
    "request_digest": SHA,
    "version_ref": ref_of("version"),
    "kind": "agent",
    "recovery_manifest_fingerprint": RMF,
    "outcome": "exact",
    "coverage": COMPLETE,
    "isolated_destination": True,
    "representation_digests_match": True,
    "pillar_fingerprint_match": True,
}
RESTORE_EVENT = {
    **env("restore_verified", "client", "client_sdk_reported"),
    "kind": "agent",
    "recovery_manifest_fingerprint": RMF,
    "outcome": "exact",
    "coverage": COMPLETE,
    "isolated_destination": True,
    "representation_digests_match": True,
    "pillar_fingerprint_match": True,
    "backend_match_result": "not_applicable",
}
SERVER_RESTORE = {
    **RESTORE_EVENT,
    **env("restore_verified", "server", "server_recorded"),
    "kind": "search_space",
    "backend_match_result": "match",
}
GOLDEN: dict[str, tuple[str, str, dict[str, Any]]] = {
    "entity": (
        L,
        "LegendEntityV0",
        {
            "schema_version": "0",
            "entity_ref": ref_of("entity"),
            "kind": "agent",
            "source_authority": "agent_builds",
            "created_at": TS,
        },
    ),
    "version_agent": (
        L,
        "LegendVersionV0",
        version("agent", "agent_build_digest_v1", None, SHA, None),
    ),
    "version_dataset": (
        L,
        "LegendVersionV0",
        version("evaluation_dataset", "dataset_multiset_root_v1", KID, MSR, ref_of("version")),
    ),
    "version_search_space": (
        L,
        "LegendVersionV0",
        version("search_space", "search_space_ssp1", KID, SSP, None),
    ),
    "declared": (
        L,
        "DeclaredEventV0",
        {
            **env("declared", "client", "client_reported"),
            "provenance": "explicit",
            "identity_source": "client_declared",
            "previous_version_ref": ref_of("version"),
            "change_reason": "rollback",
        },
    ),
    "declared_legacy": (
        L,
        "DeclaredEventV0",
        {
            **env("declared", "server", "client_reported"),
            "provenance": "implicit_legacy",
            "identity_source": "client_declared",
        },
    ),
    "captured": (
        L,
        "CapturedEventV0",
        {
            **env("captured", "client", "client_sdk_reported"),
            "recovery_manifest_fingerprint": RMF,
            "coverage": COMPLETE,
            "recovery_state": "round_trip_verified",
            "conformance_passed": True,
            "exporter_version": "0.1.0",
        },
    ),
    "restore_verified": (L, "RestoreVerifiedEventV0", RESTORE_EVENT),
    "restore_verified_server_search_space": (L, "RestoreVerifiedEventV0", SERVER_RESTORE),
    "bound_to_run": (
        L,
        "BoundToRunEventV0",
        {
            **env("bound_to_run", "server", "server_recorded"),
            "run_ref": ref_of("run"),
            "trial_ref": ref_of("trial"),
            "binding_role": "trial_candidate",
            "binding_slot": 0,
            "run_tuple_digest": SHA,
        },
    ),
    "evaluated_client": (
        L,
        "EvaluatedEventV0",
        {
            **env("evaluated", "client", "client_reported"),
            "run_ref": ref_of("run"),
            "run_tuple_digest": SHA,
            "evaluated_subset_root": MSR,
            "evaluation_protocol": "holdout",
        },
    ),
    "evaluated_witnessed": (
        L,
        "EvaluatedEventV0",
        {
            **env("evaluated", "server", "traigent_witnessed"),
            "run_ref": ref_of("run"),
            "run_tuple_digest": SHA,
            "evaluated_subset_root": MSR,
            "evaluation_protocol": "full_dataset",
        },
    ),
    "availability_changed": (
        L,
        "AvailabilityChangedEventV0",
        {
            **env("availability_changed", "client", "client_sdk_reported"),
            "recovery_manifest_fingerprint": RMF,
            "status": "missing",
        },
    ),
    "manifest": (M, "RecoveryManifestV0", MANIFEST),
    "predicate": (P, "ClaimPredicateV0", PREDICATE),
    "req_declare": (Q, "DeclareRequestV0", DECLARE_REQ),
    "req_query": (
        Q,
        "QueryRequestV0",
        {
            "schema_version": "0",
            "entity_ref": ref_of("entity"),
            "kind": None,
            "page_size": 20,
            "page_cursor": None,
        },
    ),
    "req_capture": (Q, "RecordCaptureRequestV0", CAPTURE_REQ),
    "req_restore": (Q, "RecordRestoreRequestV0", RESTORE_REQ),
    "ins_declare": (
        O,
        "DeclareVersionInstruction",
        instr("declare_version", kind="agent", entity_ref=None),
    ),
    "ins_query": (
        O,
        "QueryVersionsInstruction",
        instr("query_versions", entity_ref=ref_of("entity"), page_size=50, page_cursor=None),
    ),
    "ins_capture": (
        O,
        "CaptureVersionInstruction",
        instr("capture_version", version_ref=ref_of("version")),
    ),
    "ins_verify": (
        O,
        "VerifyRestoreInstruction",
        instr("verify_restore", version_ref=ref_of("version"), recovery_manifest_fingerprint=RMF),
    ),
    "ins_restore": (
        O,
        "RestoreVersionInstruction",
        instr("restore_version", version_ref=ref_of("version"), recovery_manifest_fingerprint=RMF),
    ),
    "res_declare": (
        O,
        "DeclareVersionResult",
        result("declare_version", version_ref=ref_of("version"), created=True),
    ),
    "res_query": (
        O,
        "QueryVersionsResult",
        result("query_versions", version_refs=[ref_of("version")], next_page_cursor=None),
    ),
    "res_capture": (
        O,
        "CaptureVersionResult",
        result(
            "capture_version",
            store_status="stored_unverified",
            recovery_manifest_fingerprint=RMF,
            coverage=PARTIAL,
            conformance_passed=False,
        ),
    ),
    "res_capture_failed": (
        O,
        "CaptureVersionResult",
        result(
            "capture_version",
            "failed",
            "store_key_conflict",
            store_status="store_key_conflict",
            recovery_manifest_fingerprint=None,
            coverage=None,
            conformance_passed=False,
        ),
    ),
    "res_verify": (
        O,
        "VerifyRestoreResult",
        result(
            "verify_restore",
            "failed",
            "restore_failed",
            restore_outcome="failed",
            coverage=None,
            store_status="corrupted",
            backend_match_result="not_checked",
        ),
    ),
    "res_verify_exact": (
        O,
        "VerifyRestoreResult",
        result(
            "verify_restore",
            restore_outcome="exact",
            coverage=COMPLETE,
            store_status="retrieved",
            backend_match_result="not_applicable",
        ),
    ),
    "res_restore": (
        O,
        "RestoreVersionResult",
        result(
            "restore_version",
            "refused",
            "foreign_ref",
            restore_outcome=None,
            coverage=None,
            store_status="not_captured",
            activated=False,
        ),
    ),
}


def ok(name: str, **override: Any) -> list[str]:
    doc, definition, instance = GOLDEN[name]
    return check(doc, definition, {**copy.deepcopy(instance), **override})


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden_examples_are_valid(name: str) -> None:
    assert ok(name) == []


@pytest.mark.parametrize("path", ALL_PATHS)
def test_schemas_are_meta_valid_and_versioned(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    assert schema["$id"] == BASE + path.name
    assert schema["version"] == "0.1.0"


def _objects(node: Any, where: str = ""):
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            yield where, node
        for key, value in node.items():
            yield from _objects(value, f"{where}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _objects(value, f"{where}[{i}]")


@pytest.mark.parametrize("path", ALL_PATHS)
def test_every_object_is_closed_and_no_free_text(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    for where, obj in _objects(schema):
        if where.count("/then/") or where.count("/properties/") and "/allOf[" in where:
            continue  # conditional refinements restate a property, not a new object shape
        assert obj.get("additionalProperties") is False, where
        for key, prop in obj["properties"].items():
            if prop.get("type") == "string":
                assert {"const", "enum", "pattern"} & set(prop), f"{where}/{key} is free text"


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_unknown_field_is_refused(name: str) -> None:
    assert ok(name, label="my agent") != []


@pytest.mark.parametrize(
    ("name", "field", "value"),
    [
        ("manifest", "pillar_fingerprint", "/home/alice/agent.py"),
        ("captured", "recovery_manifest_fingerprint", "../store/manifest.json"),
        ("bound_to_run", "run_ref", "C:\\runs\\1"),
        ("version_agent", "entity_ref", "entity_ref_Alice_has_diabetes"),
        ("ins_capture", "version_ref", "/tmp/dest"),
        ("captured", "exporter_version", "v1; rm -rf /"),
        ("declared", "change_reason", "because the prompt was too long"),
        ("evaluated_client", "evaluation_protocol", "my custom protocol"),
        ("res_capture", "store_status", "PermissionError: [Errno 13] /home/x"),
        ("res_restore", "error_code", "adapter said no"),
        ("availability_changed", "status", "gone, sorry"),
        ("res_declare", "operation", "activate"),
        ("req_declare", "provenance", "implicit_legacy"),
        ("req_declare", "idempotency_key", "my-own-key"),
    ],
)
def test_path_like_and_free_text_values_are_refused(name: str, field: str, value: str) -> None:
    assert ok(name, **{field: value}) != []


# ---- sol item 11: strict timestamps -------------------------------------------------------
@pytest.mark.parametrize(
    "bad",
    [
        TS + "\n",
        "2026-99-99T99:99:99Z",
        "2026-10-15T24:00:00Z",
        "2026-10-15T10:60:00Z",
        "2026-10-15T10:00:00+00:00",
        "2026-10-15 10:00:00Z",
        "٢٠٢٦-10-15T10:00:00Z",
    ],
)
def test_timestamp_is_strict(bad: str) -> None:
    assert ok("entity", created_at=bad) != []
    assert ok("entity", created_at="2026-10-15T10:00:00.123456Z") == []


def test_trailing_newline_is_not_a_second_spelling() -> None:
    assert ok("captured", recovery_manifest_fingerprint=RMF + "\n") != []


# ---- provenance non-escalation --------------------------------------------------------------
@pytest.mark.parametrize("name", ["declared", "captured", "availability_changed"])
@pytest.mark.parametrize("evidence", ["traigent_witnessed", "server_recorded"])
def test_client_events_cannot_carry_witnessed_or_server_provenance(
    name: str, evidence: str
) -> None:
    assert ok(name, evidence_source=evidence) != []


def test_client_restore_cannot_carry_server_evidence_or_backend_result() -> None:
    assert ok("restore_verified", evidence_source="server_recorded") != []
    assert ok("restore_verified", evidence_source="traigent_witnessed") != []
    assert ok("restore_verified", backend_match_result="match") != []


def test_evaluation_provenance_follows_origin() -> None:
    assert ok("evaluated_client", evidence_source="traigent_witnessed") != []
    assert ok("evaluated_witnessed", evidence_source="client_reported") != []


def test_server_only_events_refuse_client_origin() -> None:
    assert ok("bound_to_run", origin="client") != []
    assert ok("bound_to_run", evidence_source="client_reported") != []


# ---- sol item 10: declaration provenance ----------------------------------------------------
def test_declaration_provenance_rules() -> None:
    assert ok("declared", origin="server", provenance="explicit") != []
    assert ok("declared", origin="server", provenance="implicit_run") != []
    assert ok("declared_legacy", identity_source="sdk_fingerprinted") != []
    assert ok("declared_legacy", origin="client") != []
    assert ok("declared", previous_version_ref=None) == []
    # previous_version_ref is optional and independent (C3)
    doc, definition, good = GOLDEN["declared"]
    without = {k: v for k, v in good.items() if k != "previous_version_ref"}
    assert check(doc, definition, without) == []
    assert check(doc, definition, {**good, "initial_parent_version_ref": None}) != []


# ---- restore / exact rules ------------------------------------------------------------------
def test_exact_restore_requires_complete_coverage_and_equalities() -> None:
    assert ok("restore_verified", coverage=PARTIAL) != []
    assert ok("restore_verified", pillar_fingerprint_match=False) != []
    assert ok("restore_verified", representation_digests_match=False) != []
    assert ok("restore_verified", coverage=PARTIAL, outcome="partial") == []
    assert ok("restore_verified", isolated_destination=False) != []
    assert (
        ok("restore_verified", coverage={"status": "complete", "covered": [], "missing": []}) != []
    )


def test_backend_keyed_pillar_is_exact_only_with_server_match() -> None:
    assert ok("restore_verified", kind="search_space") != []  # client-only exact refused (C8)
    assert ok("restore_verified", kind="search_space", outcome="substituted") == []
    assert ok("restore_verified_server_search_space") == []
    assert ok("restore_verified_server_search_space", backend_match_result="mismatch") != []
    assert (
        ok(
            "restore_verified_server_search_space",
            outcome="substituted",
            backend_match_result="mismatch",
        )
        == []
    )
    assert ok("restore_verified_server_search_space", origin="client") != []
    assert check(Q, "RecordRestoreRequestV0", {**RESTORE_REQ, "kind": "search_space"}) != []
    assert (
        check(
            Q,
            "RecordRestoreRequestV0",
            {**RESTORE_REQ, "kind": "search_space", "outcome": "substituted"},
        )
        == []
    )


def test_round_trip_verified_needs_conformance_and_put_ack_is_unverified() -> None:
    assert ok("captured", conformance_passed=False) != []
    assert ok("captured", recovery_state="stored_unverified", conformance_passed=False) == []
    assert ok("captured", recovery_state="none") != []
    assert (
        check(Q, "RecordCaptureRequestV0", {**CAPTURE_REQ, "recovery_state": "round_trip_verified"})
        != []
    )


def test_coverage_status_and_missing_must_agree() -> None:
    bad = [
        {"status": "complete", "covered": ["code"], "missing": ["prompts"]},
        {"status": "partial", "covered": ["code"], "missing": []},
        {"status": "partial", "covered": ["code", "code"], "missing": ["prompts"]},
        {"status": "complete", "covered": [], "missing": []},  # sol item 6
    ]
    for cov in bad:
        assert check(L, "Coverage", cov) != [], cov


# ---- sol item 3: identity combinations shared across structures -------------------------
BAD_COMBOS = [
    {"kind": "agent", "fingerprint_scheme": "search_space_ssp1"},
    {"kind": "agent", "fingerprint_scheme": "agent_build_digest_v1", "key_id": KID},
    {
        "kind": "search_space",
        "fingerprint_scheme": "search_space_ssp1",
        "key_id": None,
        "fingerprint": SSP,
    },
    {"kind": "search_space", "fingerprint_scheme": "search_space_ssp1", "fingerprint": SHA},
    {"kind": "agent", "fingerprint_scheme": "agent_build_digest_v1", "fingerprint": MSR},
]


@pytest.mark.parametrize("combo", BAD_COMBOS)
def test_impossible_identity_combinations_fail_everywhere(combo: dict[str, Any]) -> None:
    assert check(L, "LegendVersionV0", {**GOLDEN["version_agent"][2], **combo}) != []
    fp = {"fingerprint": combo["fingerprint"]} if "fingerprint" in combo else {}
    manifest = {**MANIFEST, **{k: v for k, v in combo.items() if k != "fingerprint"}}
    if fp:
        manifest["pillar_fingerprint"] = fp["fingerprint"]
    assert check(M, "RecoveryManifestV0", manifest) != []
    assert check(P, "PredicateSubject", {**SUBJECT, **combo}) != []
    assert check(Q, "DeclareRequestV0", {**DECLARE_REQ, **combo}) != []


def test_kind_scheme_and_key_rules_on_versions() -> None:
    good = GOLDEN["version_agent"][2]
    assert check(L, "LegendVersionV0", {**good, "kind": "model"}) != []
    assert check(L, "LegendVersionV0", {**good, "authority_linked": "yes"}) != []


# ---- manifest -------------------------------------------------------------------------------
def test_manifest_ordering_coverage_and_rederivation_rules() -> None:
    assert check(M, "RecoveryManifestV0", {**MANIFEST, "ordering": "not_applicable"}) != []
    assert check(M, "RecoveryManifestV0", {**MANIFEST, "representations": []}) != []
    short = {
        **MANIFEST,
        "coverage": {"status": "complete", "covered": ["dataset_members"], "missing": []},
    }
    assert check(M, "RecoveryManifestV0", short) != []  # RequiredComponents(kind) not met
    skipped = {**MANIFEST, "rederivation": {"source_entity_ref": None, "skipped_file_count": 2}}
    assert check(M, "RecoveryManifestV0", skipped) != []  # skipped files force partial
    partial = {
        **skipped,
        "coverage": {
            "status": "partial",
            "covered": ["dataset_members"],
            "missing": ["dataset_order"],
        },
    }
    assert check(M, "RecoveryManifestV0", partial) == []


@pytest.mark.parametrize("kind", ["agent", "evaluator"])
def test_complete_agent_or_evaluator_must_reproduce_identity_digests(kind: str) -> None:
    scheme = {"agent": "agent_build_digest_v1", "evaluator": "evaluator_version_digest_v1"}[kind]
    m = {
        **MANIFEST,
        "kind": kind,
        "fingerprint_scheme": scheme,
        "key_id": None,
        "pillar_fingerprint": SHA,
        "ordering": "not_applicable",
        "coverage": full(kind),
        "identity_digests_reproduced": True,
    }
    assert check(M, "RecoveryManifestV0", m) == []
    assert check(M, "RecoveryManifestV0", {**m, "identity_digests_reproduced": False}) != []
    partial = {"status": "partial", "covered": ["code"], "missing": ["prompts"]}
    assert (
        check(
            M,
            "RecoveryManifestV0",
            {**m, "identity_digests_reproduced": False, "coverage": partial},
        )
        == []
    )


def test_conformance_namespace_is_disjoint_from_manifest_fingerprints() -> None:
    key = "rmfc0:sha256:" + "c" * 64
    assert check(L, "ConformanceKey", key) == []
    assert check(L, "ManifestFingerprint", key) != []
    assert ok("captured", recovery_manifest_fingerprint=key) != []
    assert check(L, "ConformanceKey", RMF) != []


# ---- idempotency (sol item 8) ---------------------------------------------------------------
def test_idempotency_key_is_opaque_and_request_digest_required() -> None:
    assert ok("declared", idempotency_key=H64) != []
    assert ok("declared", idempotency_key="same-key-different-payload") != []
    doc, definition, good = GOLDEN["declared"]
    assert check(doc, definition, {k: v for k, v in good.items() if k != "request_digest"}) != []
    assert ok("declared", request_digest=H64) != []


# ---- bindings and tuple (sol item 9) ------------------------------------------------------
def test_binding_slots_and_trial_reference_rules() -> None:
    assert ok("bound_to_run", trial_ref=None) != []  # trial candidate needs a trial
    assert ok("bound_to_run", binding_role="base_agent") != []  # base input has no trial
    assert ok("bound_to_run", binding_role="base_agent", trial_ref=None) == []
    assert ok("bound_to_run", binding_role="evaluator", trial_ref=None, binding_slot=1) == []
    assert ok("bound_to_run", binding_role="evaluator", binding_slot=1) == []  # per-trial evaluator
    assert ok("bound_to_run", binding_slot=-1) != []


# ---- predicates -----------------------------------------------------------------------------
def test_predicate_evidence_source_and_coverage_are_pinned_per_type() -> None:
    assert (
        check(P, "ClaimPredicateV0", {**PREDICATE, "evidence_source": "traigent_witnessed"}) != []
    )
    assert check(P, "ClaimPredicateV0", {**PREDICATE, "coverage_status": "partial"}) != []
    witnessed = {
        **PREDICATE,
        "predicate_type": "evaluated_traigent_witnessed",
        "evidence_source": "traigent_witnessed",
        "recovery_manifest_fingerprint": None,
        "coverage_status": None,
        "run_tuple_digest": SHA,
        "evaluated_subset_root": MSR,
        "evaluation_protocol": "holdout",
    }
    assert check(P, "ClaimPredicateV0", witnessed) == []
    assert check(P, "ClaimPredicateV0", {**witnessed, "evidence_source": "client_reported"}) != []
    assert check(P, "ClaimPredicateV0", {**witnessed, "run_tuple_digest": None}) != []
    assert check(P, "ClaimPredicateV0", {**witnessed, "evaluated_subset_root": None}) != []
    assert check(P, "ClaimPredicateV0", {**witnessed, "evaluation_protocol": None}) != []
    assert check(P, "ClaimPredicateV0", {**PREDICATE, "supporting_event_refs": []}) != []
    assert check(P, "ClaimPredicateV0", {**PREDICATE, "coverage_status": None}) != []
    backend = {
        **PREDICATE,
        "predicate_type": "restore_verified_backend_matched",
        "evidence_source": "server_recorded",
    }
    assert check(P, "ClaimPredicateV0", backend) == []
    assert check(P, "ClaimPredicateV0", {**backend, "evidence_source": "client_sdk_reported"}) != []


# ---- Director results (sol items 4, 5) ----------------------------------------------------
def test_director_results_are_closed_and_never_activate() -> None:
    assert ok("res_restore", activated=True) != []
    assert ok("res_restore", error_code=None) != []
    assert ok("res_declare", error_code="internal_error") != []
    assert ok("res_declare", message="adapter exception text") != []


def test_exact_verify_and_restore_results_need_complete_coverage() -> None:
    for name in ("res_verify_exact",):
        assert ok(name, coverage=PARTIAL) != []
        assert ok(name, coverage=None) != []
    restore = result(
        "restore_version",
        restore_outcome="exact",
        coverage=None,
        store_status="retrieved",
        activated=False,
    )
    assert check(O, "RestoreVersionResult", restore) != []
    assert check(O, "RestoreVersionResult", {**restore, "coverage": COMPLETE}) == []
    assert check(O, "RestoreVersionResult", {**restore, "coverage": PARTIAL}) != []


def test_capture_results_cannot_contradict_the_store_contract() -> None:
    assert ok("res_capture", store_status="round_trip_verified", conformance_passed=False) != []
    noop = {"store_status": "not_captured", "recovery_manifest_fingerprint": None, "coverage": None}
    assert ok("res_capture", **noop) != []  # no-op store must not report success
    assert ok("res_capture", recovery_manifest_fingerprint=None) != []
    assert ok("res_capture", coverage=None) != []
    assert ok("res_capture", store_status="retrieved") != []
    assert ok("res_capture_failed") == []


def test_store_statuses_include_get_success_and_key_conflict() -> None:
    for status in ("retrieved", "store_key_conflict"):
        assert check(L, "ClientStoreStatus", status) == []
    assert check(L, "LegendErrorCode", "store_key_conflict") == []


def test_root_documents_dispatch_on_shape() -> None:
    for key in ("entity", "version_agent", "declared", "captured"):
        assert check(L, None, GOLDEN[key][2]) == [], key
    for key in ("ins_capture", "res_query"):
        assert check(O, None, GOLDEN[key][2]) == [], key
    for key in ("req_declare", "req_query", "req_capture", "req_restore"):
        assert check(Q, None, GOLDEN[key][2]) == [], key


def test_requests_carry_client_fields_only() -> None:
    for key in ("req_declare", "req_capture", "req_restore", "req_query"):
        for server_field in (
            "version_ref",
            "event_ref",
            "actor_ref",
            "recorded_at",
            "origin",
            "evidence_source",
            "instruction_ref",
        ):
            doc, definition, good = GOLDEN[key]
            if server_field in good:
                continue
            assert check(doc, definition, {**good, server_field: ref_of("event")}) != []
    # later declaration: initial parent only honoured on the first declaration (semantic, see model)
    assert check(Q, "DeclareRequestV0", {**DECLARE_REQ, "previous_version_ref": None}) == []


def test_legacy_identity_schemas_are_untouched() -> None:
    out = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "origin/develop",
            "--",
            "traigent_schema/schemas/agents",
            "traigent_schema/schemas/datasets",
            "traigent_schema/schemas/evaluation",
            "traigent_schema/schemas/execution",
            "tests/data/content_identity_wire",
            "traigent_schema/data",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        pytest.skip("origin/develop not available")
    assert out.stdout.strip() == ""


# ---- reference model of the semantic rules ------------------------------------------------
class RefLedger:
    """Reference model of the declare / binding / availability / grading rules."""

    def __init__(self) -> None:
        self.versions: dict[tuple[str, str], str | None] = {}  # (entity, fp) -> initial parent
        self.events: list[dict[str, Any]] = []
        self.keys: dict[str, tuple[Any, ...]] = {}
        self.slots: dict[tuple[str, str | None, str, int], str] = {}
        self.avail: dict[str, str] = {}  # manifest -> latest availability, absent = unknown
        self.captures: dict[str, set[str]] = {}  # fp -> manifests

    def declare(
        self, entity: str, fp: str, parent: str | None, previous: str | None, key: str, digest: str
    ) -> str:
        if key in self.keys:  # retry vs conflict: the key is bound to ONE request digest
            if self.keys[key] != (digest,):
                raise ValueError("conflicting_idempotency_payload")
            return fp
        first = (entity, fp) not in self.versions
        if not first and parent is not None and parent != self.versions[(entity, fp)]:
            raise ValueError("invalid_request")  # initial parent is first-declaration only
        if first:
            if parent == fp:
                raise ValueError("invalid_request")
            if parent is not None and (entity, parent) not in self.versions:
                raise ValueError("unknown_ref")
            self.versions[(entity, fp)] = parent
        if previous is not None and (entity, previous) not in self.versions:
            raise ValueError("unknown_ref")
        self.keys[key] = (digest,)
        self.events.append({"fp": fp, "previous": previous})
        return fp

    def bind(self, run: str, trial: str | None, role: str, slot: int, tuple_digest: str) -> None:
        if role == "trial_candidate" and trial is None:
            raise ValueError("invalid_request")
        slot_key = (run, trial, role, slot)
        if slot_key in self.slots and self.slots[slot_key] != tuple_digest:
            raise ValueError("conflicting_report")  # consumed bindings are immutable
        self.slots[slot_key] = tuple_digest

    def capture(self, fp: str, manifest: str) -> None:
        self.captures.setdefault(fp, set()).add(manifest)

    def set_availability(self, manifest: str, status: str) -> None:
        self.avail[manifest] = status

    def restorable_now(self, manifest: str) -> bool:  # per manifest; unknown is NOT restorable
        return (
            any(manifest in ms for ms in self.captures.values())
            and self.avail.get(manifest, "unknown") == "available"
        )

    def version_restorable_now(self, fp: str) -> bool:  # version-level: any capture restorable
        return any(self.restorable_now(m) for m in self.captures.get(fp, ()))

    @staticmethod
    def grade(kind: str, client_exact: bool, backend_match: str) -> str:
        if not client_exact:
            return "partial"
        if kind == "search_space":
            return "exact" if backend_match == "match" else "substituted"
        return "exact"


def test_ref_model_revert_idempotent_retry_and_fresh_keys() -> None:
    led = RefLedger()
    led.declare("e", "v1", None, None, "k1", "d1")
    led.declare("e", "v2", "v1", "v1", "k2", "d2")
    led.declare("e", "v3", "v2", "v2", "k3", "d3")
    before = dict(led.versions)
    led.declare("e", "v1", None, "v3", "k4", "d4")  # revert v3 -> v1
    assert led.versions == before and len(led.events) == 4
    assert led.declare("e", "v1", None, "v3", "k4", "d4") == "v1" and len(led.events) == 4
    with pytest.raises(ValueError, match="conflicting_idempotency_payload"):
        led.declare("e", "v2", "v1", "v1", "k4", "dX")
    # A->B, B->A, A->B with fresh keys each append (no suppression by content digest)
    for i, (fp, prev) in enumerate([("v2", "v1"), ("v1", "v2"), ("v2", "v1")]):
        led.declare("e", fp, None, prev, f"fresh{i}", f"dig{i}")
    assert len(led.events) == 7
    with pytest.raises(ValueError, match="invalid_request"):
        led.declare("e", "v2", "v3", None, "k9", "d9")  # different initial parent on re-declaration
    with pytest.raises(ValueError, match="invalid_request"):
        led.declare("e", "v4", "v4", None, "k10", "d10")  # self initial parent
    with pytest.raises(ValueError, match="unknown_ref"):
        led.declare("e", "v5", "other-entity-version", None, "k11", "d11")


def test_ref_model_bindings_availability_and_grading() -> None:
    led = RefLedger()
    led.bind("r", "t1", "trial_candidate", 0, "T1")
    led.bind("r", "t2", "trial_candidate", 0, "T2")  # several versions per run
    led.bind("r", None, "evaluator", 0, "E1")
    led.bind("r", None, "evaluator", 1, "E2")  # legitimate multiple evaluator groups
    led.bind("r", "t1", "trial_candidate", 0, "T1")  # identical replay
    with pytest.raises(ValueError, match="conflicting_report"):
        led.bind("r", "t1", "trial_candidate", 0, "T9")
    with pytest.raises(ValueError, match="invalid_request"):
        led.bind("r", None, "trial_candidate", 1, "T1")
    led.capture("v1", "m1")
    led.capture("v1", "m2")
    assert not led.restorable_now("m1")  # unknown availability is not restorable
    led.set_availability("m1", "available")
    assert led.restorable_now("m1") and not led.restorable_now("m2")
    assert led.version_restorable_now("v1")
    led.set_availability("m1", "missing")
    assert not led.version_restorable_now("v1") and led.captures["v1"] == {"m1", "m2"}
    assert led.grade("agent", True, "not_checked") == "exact"
    assert led.grade("search_space", True, "not_checked") == "substituted"
    assert led.grade("search_space", True, "match") == "exact"
    assert led.grade("search_space", False, "match") == "partial"
