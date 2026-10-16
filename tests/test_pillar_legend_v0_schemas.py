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
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry
from traigent_schema.validator import _FORMAT_CHECKER

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
PARTIAL = {"status": "partial", "covered": ["code"], "missing": ["prompts"]}


def full(kind: str) -> dict[str, Any]:
    return {"status": "complete", "covered": list(REQUIRED[kind]), "missing": []}


COMPLETE = full("agent")
ONE_COMPONENT = {"status": "complete", "covered": ["code"], "missing": []}


def ref_of(prefix: str) -> str:
    return f"{prefix}ref_{HEX32}"


def check(doc: str, definition: str | None, instance: Any) -> list[str]:
    ref = BASE + doc + (f"#/definitions/{definition}" if definition else "")
    validator = Draft7Validator({"$ref": ref}, registry=REGISTRY, format_checker=_FORMAT_CHECKER)
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
        "ledger_position": 1,
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
    "backend_keyed": False,
    "identity_verification_ref": None,
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
    "trial_ref": None,
    "ledger_cutoff_position": 5,
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
    "backend_keyed": False,
    "identity_verification_ref": None,
    "representation_commitment": SHA,
    "identity_digests_reproduced": True,
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
    "historical_key_available": True,
    "dependencies_verified": True,
    "verified_artifact_digest": SHA,
    "backend_keyed": False,
}
AVAIL_REQ = {
    "schema_version": "0",
    "idempotency_key": IDK,
    "request_digest": SHA,
    "version_ref": ref_of("version"),
    "recovery_manifest_fingerprint": RMF,
    "status": "available",
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
    "historical_key_available": True,
    "dependencies_verified": True,
    "verified_artifact_digest": SHA,
    "backend_keyed": False,
    "backend_match_result": "not_applicable",
}
SERVER_RESTORE = {
    **RESTORE_EVENT,
    **env("restore_verified", "server", "server_recorded"),
    "kind": "search_space",
    "coverage": full("search_space"),
    "backend_keyed": True,
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
            "backend_keyed": False,
            "identity_verification_ref": None,
            "representation_commitment": SHA,
            "identity_digests_reproduced": True,
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
            "slot_scope": "trial",
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
            "trial_ref": None,
            "evaluation_protocol": "holdout",
            "evaluation_outcome": "inconclusive",
            "void_cause": None,
            "discrimination": "none",
            "discrimination_event_ref": None,
            "control_run": None,
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
            "trial_ref": ref_of("trial"),
            "evaluation_protocol": "full_dataset",
            "evaluation_outcome": "pass",
            "void_cause": None,
            "discrimination": "control",
            "discrimination_event_ref": ref_of("event"),
            "control_run": None,
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
    "req_availability": (Q, "RecordAvailabilityRequestV0", AVAIL_REQ),
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
    ss = {"kind": "search_space", "coverage": full("search_space")}
    assert ok("restore_verified", **ss) != []  # client-only exact refused (C8)
    assert ok("restore_verified", **ss, backend_keyed=True) != []
    assert ok("restore_verified", **ss, outcome="substituted", backend_keyed=True) == []
    # search_space must be flagged backend_keyed; keyed evaluator manifests follow the same rule
    assert ok("restore_verified", **ss, outcome="substituted", backend_keyed=False) != []
    ev = {"kind": "evaluator", "coverage": full("evaluator"), "backend_keyed": True}
    assert ok("restore_verified", **ev) != []
    assert ok("restore_verified", **ev, outcome="substituted") == []
    assert check(Q, "RecordRestoreRequestV0", {**RESTORE_REQ, **ev}) != []
    assert check(Q, "RecordRestoreRequestV0", {**RESTORE_REQ, **ev, "outcome": "partial"}) == []
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
    ssreq = {**RESTORE_REQ, "kind": "search_space", "coverage": full("search_space")}
    assert check(Q, "RecordRestoreRequestV0", ssreq) != []
    assert check(Q, "RecordRestoreRequestV0", {**ssreq, "backend_keyed": True}) != []
    assert (
        check(
            Q,
            "RecordRestoreRequestV0",
            {**ssreq, "outcome": "substituted", "backend_keyed": True},
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
def test_binding_roles_scopes_and_configuration_roles() -> None:
    assert ok("bound_to_run", trial_ref=None) != []  # trial-scope slot needs a context trial
    assert ok("bound_to_run", slot_scope="run") != []  # trial roles live in trial scope
    assert ok("bound_to_run", binding_role="base_agent") != []  # base roles live in run scope
    run = {"binding_role": "base_agent", "slot_scope": "run"}
    assert ok("bound_to_run", **run) == []  # a trial context may consume a run-scope slot
    assert ok("bound_to_run", **run, trial_ref=None) == []
    for role in ("run_base_configuration",):
        assert ok("bound_to_run", binding_role=role, slot_scope="run") == []
        assert ok("bound_to_run", binding_role=role, slot_scope="trial") != []
    assert ok("bound_to_run", binding_role="trial_configuration") == []
    assert ok("bound_to_run", binding_role="trial_configuration", slot_scope="run") != []
    # run-level and trial-level evaluator slots with the same number coexist (keyed by scope)
    for scope, trial in (("run", None), ("trial", ref_of("trial"))):
        ev = {"binding_role": "evaluator", "slot_scope": scope, "trial_ref": trial}
        assert ok("bound_to_run", **ev, binding_slot=1) == []
    assert ok("bound_to_run", binding_role="evaluator", slot_scope="trial", trial_ref=None) != []
    assert ok("bound_to_run", binding_slot=-1) != []
    assert ok("bound_to_run", binding_role="dataset", slot_scope="run", trial_ref=None) == []


# ---- sol round 3: schema negatives ----------------------------------------------------------
IDV = {
    **env("identity_verified", "server", "server_recorded"),
    "representation_commitment": SHA,
    "backend_recomputed": True,
    "result": "match",
}


def test_identity_verified_is_a_server_only_pre_capture_event() -> None:
    assert check(L, "IdentityVerifiedEventV0", IDV) == []
    assert check(L, "IdentityVerifiedEventV0", {**IDV, "origin": "client"}) != []
    assert check(L, "IdentityVerifiedEventV0", {**IDV, "evidence_source": "client_reported"}) != []
    assert check(L, "IdentityVerifiedEventV0", {**IDV, "result": "maybe"}) != []
    assert check(L, None, IDV) == []


def test_complete_backend_keyed_capture_must_cite_identity_verification() -> None:
    ev_ref = ref_of("event")
    good = {**GOLDEN["captured"][2], "backend_keyed": True}
    assert check(L, "CapturedEventV0", good) != []  # complete + keyed, no verification ref
    assert check(L, "CapturedEventV0", {**good, "identity_verification_ref": ev_ref}) == []
    assert check(Q, "RecordCaptureRequestV0", {**CAPTURE_REQ, "backend_keyed": True}) != []
    assert (
        check(
            Q,
            "RecordCaptureRequestV0",
            {**CAPTURE_REQ, "backend_keyed": True, "identity_verification_ref": ev_ref},
        )
        == []
    )
    partial = {**CAPTURE_REQ, "backend_keyed": True, "coverage": PARTIAL}
    assert check(Q, "RecordCaptureRequestV0", partial) == []  # partial needs no proof yet
    keyed = {**MANIFEST, "backend_keyed": True}
    assert check(M, "RecoveryManifestV0", keyed) != []
    assert check(M, "RecoveryManifestV0", {**keyed, "identity_verification_ref": ev_ref}) == []


def test_evaluation_events_and_predicates_carry_nullable_trial_context() -> None:
    assert ok("evaluated_client", trial_ref=ref_of("trial")) == []
    assert ok("evaluated_client", trial_ref=None) == []
    doc, definition, good = GOLDEN["evaluated_client"]
    assert check(doc, definition, {k: v for k, v in good.items() if k != "trial_ref"}) != []
    assert check(P, "ClaimPredicateV0", {**PREDICATE, "trial_ref": ref_of("trial")}) == []


CONTROL = {
    "control_kind": "known_bad_input",
    "expected_verdict": "fail",
    "observed_verdict": "fail",
    "evaluator_version_ref": ref_of("version"),
    "run_ref": ref_of("run"),
}


def _evaluated(**changes: Any) -> list[str]:
    doc, definition, good = GOLDEN["evaluated_witnessed"]
    return check(doc, definition, {**good, **changes})


def test_evaluation_outcome_has_five_states_and_void_needs_a_closed_cause() -> None:
    for state in ("pass", "fail", "not_exercised", "inconclusive"):
        assert _evaluated(evaluation_outcome=state) == [], state
    assert _evaluated(evaluation_outcome="void", void_cause="input_unavailable") == []
    assert _evaluated(evaluation_outcome="void") != []  # void without a cause
    assert _evaluated(evaluation_outcome="void", void_cause="because I said so") != []
    assert _evaluated(evaluation_outcome="pass", void_cause="input_unavailable") != []
    for bad in ("passed", "error", "skipped", None):
        assert _evaluated(evaluation_outcome=bad) != [], bad
    doc, definition, good = GOLDEN["evaluated_witnessed"]
    for field in ("evaluation_outcome", "void_cause", "discrimination"):
        assert check(doc, definition, {k: v for k, v in good.items() if k != field}) != [], field


def test_evaluated_discrimination_is_closed_and_ref_matches() -> None:
    for d in ("shown_by_run", "control", "prior_run"):
        assert _evaluated(discrimination=d, discrimination_event_ref=ref_of("event")) == []
        assert _evaluated(discrimination=d, discrimination_event_ref=None) != [], d
    assert _evaluated(discrimination="none", discrimination_event_ref=None) == []
    assert _evaluated(discrimination="none", discrimination_event_ref=ref_of("event")) != []
    assert _evaluated(discrimination="sometimes", discrimination_event_ref=None) != []


def test_control_run_shape_is_closed() -> None:
    held = {"discrimination": "none", "discrimination_event_ref": None}
    assert _evaluated(control_run=CONTROL, **held) == []
    assert _evaluated(control_run={**CONTROL, "input_text": "free text"}, **held) != []
    for field in CONTROL:
        assert (
            _evaluated(control_run={k: v for k, v in CONTROL.items() if k != field}, **held) != []
        )
    assert _evaluated(control_run={**CONTROL, "control_kind": "my kind"}, **held) != []
    assert _evaluated(control_run={**CONTROL, "expected_verdict": "void"}, **held) != []
    assert _evaluated(control_run={**CONTROL, "observed_verdict": "maybe"}, **held) != []
    assert _evaluated(control_run={**CONTROL, "run_ref": "run one"}, **held) != []
    # a control record is not itself discriminated
    assert (
        _evaluated(
            control_run=CONTROL, discrimination="control", discrimination_event_ref=ref_of("event")
        )
        != []
    )


def test_evaluation_predicates_carry_a_verdict_and_discrimination() -> None:
    def pred(**changes: Any) -> list[str]:
        base = {
            **PREDICATE,
            "predicate_type": "evaluated_traigent_witnessed",
            "evidence_source": "traigent_witnessed",
            "recovery_manifest_fingerprint": None,
            "coverage_status": None,
            "run_tuple_digest": SHA,
            "evaluated_subset_root": MSR,
            "evaluation_protocol": "holdout",
            "evaluation_outcome": "fail",
            "discrimination": "prior_run",
            "discrimination_event_ref": ref_of("event"),
        }
        return check(P, "ClaimPredicateV0", {**base, **changes})

    assert pred() == []
    assert pred(discrimination="none", discrimination_event_ref=None) == []
    assert pred(discrimination="none") != []  # a reference with no discrimination
    assert pred(discrimination_event_ref=None) != []  # discrimination with no reference
    for bad in ("not_exercised", "inconclusive", "void", "unknown"):
        assert pred(evaluation_outcome=bad) != [], bad
    full = {
        **PREDICATE,
        "predicate_type": "evaluated_client_reported",
        "evidence_source": "client_reported",
        "recovery_manifest_fingerprint": None,
        "coverage_status": None,
        "run_tuple_digest": SHA,
        "evaluated_subset_root": MSR,
        "evaluation_protocol": "holdout",
        "evaluation_outcome": "pass",
        "discrimination": "none",
        "discrimination_event_ref": None,
    }
    assert check(P, "ClaimPredicateV0", full) == []
    for field in ("evaluation_outcome", "discrimination", "discrimination_event_ref"):
        assert check(P, "ClaimPredicateV0", {k: v for k, v in full.items() if k != field}) != []
    # other predicate types may not carry evaluation fields
    assert (
        check(
            P,
            "ClaimPredicateV0",
            {**PREDICATE, "discrimination": "none", "discrimination_event_ref": None},
        )
        != []
    )


def test_declare_success_requires_a_version_ref() -> None:
    bad = result("declare_version", version_ref=None, created=True)
    assert check(O, "DeclareVersionResult", bad) != []
    assert ok("res_declare") == []
    refused = result("declare_version", "refused", "unknown_ref", version_ref=None, created=False)
    assert check(O, "DeclareVersionResult", refused) == []


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
        "evaluation_outcome": "pass",
        "discrimination": "none",
        "discrimination_event_ref": None,
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
    for key in ("req_declare", "req_query", "req_capture", "req_availability", "req_restore"):
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


# ---- sol round 2: schema negatives ------------------------------------------------------
def test_ledger_position_is_required_and_positive() -> None:
    doc, definition, good = GOLDEN["declared"]
    assert check(doc, definition, {k: v for k, v in good.items() if k != "ledger_position"}) != []
    for bad in (0, -1, 1.5, "1", 2**53):
        assert ok("declared", ledger_position=bad) != [], bad
    assert check(P, "ClaimPredicateV0", {**PREDICATE, "ledger_cutoff_position": 0}) != []
    assert (
        check(
            P,
            "ClaimPredicateV0",
            {k: v for k, v in PREDICATE.items() if k != "ledger_cutoff_position"},
        )
        != []
    )


def test_authority_link_is_an_append_only_server_event_not_a_version_field() -> None:
    event = {
        **env("authority_linked", "server", "server_recorded"),
        "source_authority": "evaluator_version_manifests",
    }
    assert check(L, "AuthorityLinkedEventV0", event) == []
    assert check(L, "AuthorityLinkedEventV0", {**event, "origin": "client"}) != []
    assert check(L, "AuthorityLinkedEventV0", {**event, "evidence_source": "client_reported"}) != []
    assert check(L, "AuthorityLinkedEventV0", {**event, "source_authority": "none"}) != []
    assert check(L, None, event) == []
    # the immutable version row has no mutable linkage flag
    assert ok("version_agent", authority_linked=True) != []
    assert check(L, "SourceAuthority", "evaluator_version_manifests") == []


def test_request_digest_description_excludes_only_key_and_digest() -> None:
    text = json.loads(LEGEND_PATH.read_text())["definitions"]["RequestDigest"]["description"]
    assert "excluding ONLY idempotency_key and request_digest" in text
    assert "absent" in text and "null" in text


def test_search_space_identity_is_client_declared_everywhere() -> None:
    assert (
        check(
            L,
            "LegendVersionV0",
            {**GOLDEN["version_search_space"][2], "identity_source": "sdk_fingerprinted"},
        )
        != []
    )
    ss = {
        **DECLARE_REQ,
        "kind": "search_space",
        "fingerprint_scheme": "search_space_ssp1",
        "key_id": KID,
        "fingerprint": SSP,
    }
    assert check(Q, "DeclareRequestV0", {**ss, "identity_source": "client_declared"}) == []
    assert check(Q, "DeclareRequestV0", {**ss, "identity_source": "sdk_fingerprinted"}) != []


def test_reporting_boundaries_require_kind_specific_complete_coverage() -> None:
    one = ONE_COMPONENT
    assert ok("restore_verified", coverage=one) != []  # agent exact with one component
    assert check(Q, "RecordRestoreRequestV0", {**RESTORE_REQ, "coverage": one}) != []
    assert ok("restore_verified", coverage=full("agent")) == []
    assert ok("restore_verified", coverage=PARTIAL, outcome="partial") == []


def test_director_exact_reports_need_retrieval_and_no_mismatch() -> None:
    assert ok("res_verify_exact", backend_match_result="mismatch") != []
    assert ok("res_verify_exact", store_status="missing") != []
    assert ok("res_verify_exact", outcome="failed", error_code="restore_failed") != []
    restore = result(
        "restore_version",
        restore_outcome="exact",
        coverage=COMPLETE,
        store_status="missing",
        activated=False,
    )
    assert check(O, "RestoreVersionResult", restore) != []
    assert check(O, "RestoreVersionResult", {**restore, "store_status": "retrieved"}) == []


def test_calendar_validity_uses_the_production_date_time_checker() -> None:
    assert _FORMAT_CHECKER.checks  # the production checker is registered, no optional extras
    for bad in ("2026-02-30T10:00:00Z", "2026-04-31T10:00:00Z", "2025-02-29T10:00:00Z"):
        assert ok("entity", created_at=bad) != [], bad
    assert ok("entity", created_at="2028-02-29T10:00:00Z") == []
    assert ok("entity", created_at="2026-10-15T10:00:60Z") != []  # leap second not in contract


def test_axis_state_has_no_singular_version_availability() -> None:
    state = {
        "identity_source": "client_declared",
        "authority_linked": False,
        "recovery_state": "stored_unverified",
        "restorable_now": False,
        "evaluation_state": "none",
    }
    assert check(L, "AxisState", state) == []
    assert check(L, "AxisState", {**state, "current_availability": "available"}) != []


# ---- reference model: the section-9 transition table ------------------------------------
class Refused(ValueError):
    """A refusal. The model guarantees no state change when this is raised."""


ROLE_KIND = {
    "base_agent": "agent",
    "trial_candidate": "agent",
    "run_base_configuration": "configuration",
    "trial_configuration": "configuration",
    "dataset": "evaluation_dataset",
    "search_set": "evaluation_dataset",
    "evaluator": "evaluator",
    "search_space": "search_space",
}
ROLE_ORDER = list(ROLE_KIND)
REPLACES = {"trial_candidate": "base_agent", "trial_configuration": "run_base_configuration"}
TRIAL_ONLY = {"trial_candidate", "trial_configuration"}
RUN_ONLY = {"base_agent", "run_base_configuration", "dataset", "search_set", "search_space"}
STRENGTH = {"stored_unverified": 1, "round_trip_verified": 2}
OUTCOMES = ("pass", "fail", "not_exercised", "inconclusive", "void")
VOID_CAUSES = (
    "evidence_does_not_hold",
    "evaluator_version_mismatch",
    "run_context_drifted",
    "input_unavailable",
    "withdrawn_by_producer",
)
DISCRIMINATIONS = ("shown_by_run", "control", "prior_run", "none")
CONTROL_KINDS = ("known_bad_input", "known_good_input", "empty_input", "mutated_input")
CONTROL_FIELDS = {
    "control_kind",
    "expected_verdict",
    "observed_verdict",
    "evaluator_version_ref",
    "run_ref",
}
STATEMENT_STRONG = "This version was evaluated by Traigent."
STATEMENT_WEAK = "Traigent evaluated this version; the evaluation was not shown able to fail."
PREDICATES = (
    "declared",
    "captured",
    "restorable_now",
    "restore_verified_client_reported",
    "restore_verified_backend_matched",
    "bound_to_run",
    "evaluated_client_reported",
    "evaluated_traigent_witnessed",
)


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


class Legend:
    """Transition-table model of section 9 (single ledger, single committer).

    Deliberate abstractions: hashes are sha256 of canonical JSON; the single-threaded commit stands
    for the per-ledger lock (positions are allocated at commit, so the sealed high-water mark is the
    committed length); artifact bytes are an opaque digest; tenants, signatures and wire validation
    are out of scope. Every piece of state lives in ``self.__dict__`` and refusals are compared
    against a deep copy of all of it.
    """

    def __init__(self) -> None:
        self.entities: dict[str, dict[str, Any]] = {}
        self.group_entities: dict[tuple[str, str], str] = {}
        self.versions: dict[tuple[str, str], dict[str, Any]] = {}
        self.links: dict[tuple[str, str], tuple[str, str]] = {}
        self.entity_links: dict[str, tuple[str, str]] = {}
        self.authority_rows: dict[tuple[str, str, str], bool] = {}
        self.ledger: list[dict[str, Any]] = []
        self.requests: dict[tuple[str, str], tuple[str, Any]] = {}
        self.proposals: dict[tuple[Any, ...], str] = {}
        self.contexts: dict[tuple[str, str | None], dict[str, Any]] = {}
        self.captures: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.artifacts: dict[tuple[str, str], str] = {}
        self.activated: dict[tuple[str, str], str] = {}
        self.instructions: dict[str, dict[str, Any]] = {}
        self.results: dict[str, tuple[str, Any]] = {}
        self.cursors: dict[str, tuple[str, int, int | None]] = {}
        self.next_entity = 1
        self.autokey = 0

    # -- infrastructure -------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        return copy.deepcopy(self.__dict__)

    def _append(self, **event: Any) -> int:
        self.ledger.append({**event, "position": len(self.ledger) + 1})
        return len(self.ledger)

    @property
    def high_water(self) -> int:
        return len(self.ledger)

    @staticmethod
    def request_digest(req: dict[str, Any]) -> str:
        """Digest over the FULL validated wire body, excluding only the two idempotency fields."""
        body = {k: v for k, v in req.items() if k not in ("idempotency_key", "request_digest")}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        raw = b"traigent.legend.request.v0\x00" + canonical.encode()
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def _wire(self, endpoint: str, req: dict[str, Any], definition: str) -> tuple[str, Any]:
        """Validate, recompute the digest over the whole wire body and consult the saved key."""
        if check(Q, definition, req):
            raise Refused("invalid_request")
        digest = self.request_digest(req)
        if req["request_digest"] != digest:
            raise Refused("invalid_request")  # the Backend always recomputes
        saved = self.requests.get((endpoint, req["idempotency_key"]))
        if saved is not None and saved[0] != digest:
            raise Refused("conflicting_idempotency_payload")
        return digest, (saved[1] if saved is not None else None)

    def _idem(
        self, endpoint: str, key: str, body: dict[str, Any], wire_digest: str | None = None
    ) -> tuple[str, Any]:
        """Endpoint-scoped key/digest check. Returns (digest, saved response or None)."""
        digest = wire_digest or _digest(endpoint, body)
        saved = self.requests.get((endpoint, key))
        if saved is not None:
            if saved[0] != digest:
                raise Refused("conflicting_idempotency_payload")
            return digest, saved[1]
        return digest, None

    def _key(self, key: str | None) -> str:
        return key if key is not None else f"auto{self.autokey}"

    def _save(self, endpoint: str, key: str, digest: str, response: Any) -> Any:
        self.requests[(endpoint, key)] = (digest, response)
        return response

    def _version(self, entity: str, fp: str) -> dict[str, Any]:
        if (entity, fp) not in self.versions:
            raise Refused("unknown_ref")
        return self.versions[(entity, fp)]

    def _captured(self, entity: str, fp: str, manifest: str, prefix: int | None = None) -> bool:
        events = self.ledger[: prefix if prefix is not None else len(self.ledger)]
        return any(
            e["type"] == "captured"
            and (e["entity"], e["fp"], e["manifest"]) == (entity, fp, manifest)
            for e in events
        )

    def backend_keyed(self, entity: str, fp: str) -> bool:
        v = self._version(entity, fp)
        return v["kind"] == "search_space" or (
            v["kind"] == "evaluator" and v["fmt"] in ("keyed", "unknown")
        )

    def format_known(self, entity: str, fp: str) -> bool:
        return self._version(entity, fp)["fmt"] != "unknown"

    # -- declare / link ---------------------------------------------------------------------
    def declare(
        self,
        key: str,
        entity: str | None,
        kind: str,
        fp: str,
        source: str,
        initial_parent: str | None = None,
        previous: str | None = None,
        fmt: str = "plain",
        group: str | None = None,
    ) -> Any:
        body = dict(
            entity=entity,
            kind=kind,
            fp=fp,
            source=source,
            ip=initial_parent,
            previous=previous,
            fmt=fmt,
            group=group,
        )
        digest, saved = self._idem("declare", key, body)
        if saved is not None:
            return saved
        if kind == "search_space" and source != "client_declared":
            raise Refused("invalid_request")
        target = entity
        if target is None and group is not None and (kind, group) in self.group_entities:
            target = self.group_entities[(kind, group)]  # reverse uniqueness: reuse the entity
        if target is not None and (
            target not in self.entities or self.entities[target]["kind"] != kind
        ):
            raise Refused("foreign_ref")
        if target is not None and group is not None and self.entities[target]["group"] != group:
            raise Refused("foreign_ref")
        first = target is None or (target, fp) not in self.versions
        if target is not None and not first:
            v = self.versions[(target, fp)]
            if (initial_parent is not None and initial_parent != v["ip"]) or source != v["source"]:
                raise Refused("invalid_request")
        if (
            first
            and initial_parent is not None
            and (
                target is None
                or initial_parent == fp
                or (target, initial_parent) not in self.versions
            )
        ):
            raise Refused("invalid_request" if initial_parent == fp else "unknown_ref")
        if previous is not None and (target is None or (target, previous) not in self.versions):
            raise Refused("unknown_ref")
        created_entity = target is None
        if created_entity:  # entity creation, version, event and response commit together
            target = f"ent{self.next_entity}"
            self.next_entity += 1
            self.entities[target] = {"kind": kind, "group": group}
            if group is not None:
                self.group_entities[(kind, group)] = target
        if first:
            self.versions[(target, fp)] = dict(kind=kind, ip=initial_parent, source=source, fmt=fmt)
        pos = self._append(type="declared", entity=target, fp=fp, previous=previous)
        return self._save(
            "declare", key, digest, {"entity": target, "created": first, "position": pos}
        )

    def link_authority(self, entity: str, fp: str, authority: str, group: str) -> None:
        v = self._version(entity, fp)
        if (authority, group, fp) not in self.authority_rows:
            raise Refused("unknown_ref")
        if (
            self.entities[entity]["group"] != group
            or self.group_entities.get((v["kind"], group)) != entity
        ):
            raise Refused("foreign_ref")  # another entity's authority group
        existing = self.entity_links.get(entity)
        if existing is not None and existing != (authority, group):
            raise Refused("conflicting_report")  # association holds across all versions
        if (entity, fp) in self.links:
            return  # unique immutable association; identical replay is a no-op
        self.links[(entity, fp)] = (authority, group)
        self.entity_links[entity] = (authority, group)
        self._append(type="authority_linked", entity=entity, fp=fp, authority=authority)

    # -- bindings and execution -------------------------------------------------------------
    def propose(
        self, run: str, trial: str | None, role: str, slot: int, entity: str, fp: str
    ) -> None:
        v = self._version(entity, fp)
        if ROLE_KIND[role] != v["kind"]:
            raise Refused("invalid_request")  # role-to-kind matrix
        if (role in TRIAL_ONLY and trial is None) or (role in RUN_ONLY and trial is not None):
            raise Refused("invalid_request")
        scope = "trial" if trial is not None else "run"
        slot_key = (run, scope, trial, role, slot)
        version = f"{entity}:{fp}"
        if self.proposals.get(slot_key) == version:
            return  # identical replay: a no-op, even after freezing
        if scope == "run" and (run, None) in self.contexts:
            raise Refused("conflicting_report")
        if trial is not None and (run, trial) in self.contexts:
            raise Refused("conflicting_report")
        self.proposals[slot_key] = version

    def effective(
        self, run: str, trial: str | None, override: dict[tuple[str, str, int], str] | None = None
    ) -> dict[tuple[str, str, int], str]:
        merged: dict[tuple[str, str, int], str] = {}
        base = self.contexts.get((run, None))
        for (r, scope, t, role, slot), version in self.proposals.items():
            if r != run:
                continue
            if scope == "run" and base is None:
                merged[(role, scope, slot)] = version
            elif scope == "trial" and t == trial:
                merged[(role, scope, slot)] = version
        if base is not None:  # inherited run-scope slots come from the frozen snapshot
            for k, v in base["snapshot"].items():
                if k[1] == "run":
                    merged[k] = v
        for k, v in (override or {}).items():
            merged[k] = v
        replaced = {REPLACES[role] for (role, _, _) in merged if role in REPLACES}
        kept = {k: v for k, v in merged.items() if k[0] not in replaced or k[1] == "trial"}
        return dict(
            sorted(kept.items(), key=lambda kv: (ROLE_ORDER.index(kv[0][0]), kv[0][1], kv[0][2]))
        )

    @staticmethod
    def tuple_digest(effective: dict[tuple[str, str, int], str]) -> str:
        entries = sorted((ROLE_ORDER.index(r), sc, sl, v) for (r, sc, sl), v in effective.items())
        return _digest("traigent.legend.run_tuple.v0", entries)

    def start_execution(
        self, run: str, trial: str | None, observed: dict[tuple[str, str, int], str], mode: str
    ) -> str:
        context = (run, trial)
        if context in self.contexts:  # replay: completeness first, then identity with the snapshot
            snap = self.contexts[context]["snapshot"]
            if set(observed) != set(snap):
                raise Refused("manifest_mismatch")
            if observed != snap:
                raise Refused("conflicting_report")  # already bound: use a fresh run/trial
            return self.contexts[context]["digest"]
        if trial is not None and (run, None) not in self.contexts:
            raise Refused("invalid_request")  # the run-base context freezes first
        if not observed:
            raise Refused("manifest_mismatch")  # an empty observation never freezes a context
        expected = self.effective(run, trial)
        if set(observed) != set(expected):
            raise Refused("manifest_mismatch")  # complete observation: key-set equality
        drift = {k: v for k, v in observed.items() if expected[k] != v}
        if drift and mode == "strict":
            raise Refused("manifest_mismatch")  # refuse before execution, nothing changes
        for (role, scope, _slot), v in drift.items():
            if trial is not None and scope == "run":
                raise Refused("conflicting_report")  # inherited frozen slots never drift
            entity, fp = v.split(":")
            if self._version(entity, fp)["kind"] != ROLE_KIND[role]:
                raise Refused("invalid_request")
        final = self.effective(run, trial, observed)
        digest = self.tuple_digest(final)
        for (role, scope, slot), v in drift.items():  # only context-local slots are rewritten
            self.proposals[(run, scope, trial if scope == "trial" else None, role, slot)] = v
        self.contexts[context] = {"digest": digest, "snapshot": dict(final)}
        for (role, scope, slot), v in final.items():
            self._append(
                type="bound_to_run",
                run=run,
                trial=trial,
                role=role,
                scope=scope,
                slot=slot,
                version=v,
                tuple=digest,
            )
        return digest

    def evaluate(
        self,
        run: str,
        trial: str | None,
        subject: str,
        tuple_digest: str,
        origin: str,
        subset: str = "msr-all",
        protocol: str = "full_dataset",
        key: str | None = None,
        outcome: str = "inconclusive",
        void_cause: str | None = None,
        discrimination: str = "none",
        disc_ref: int | None = None,
        control: dict[str, Any] | None = None,
    ) -> Any:
        """Record an evaluation. ``outcome`` defaults to ``inconclusive``: that is the mapping of
        a pre-outcome event (occurrence recorded, verdict unrecorded). ``disc_ref`` is the ledger
        position of the evaluated event that shows this check could fail."""
        key = self._key(key)
        body = dict(
            r=run,
            t=trial,
            s=subject,
            d=tuple_digest,
            o=origin,
            ss=subset,
            p=protocol,
            oc=outcome,
            vc=void_cause,
            dc=discrimination,
            dr=disc_ref,
            cr=control,
        )
        digest, saved = self._idem("evaluate", key, body)
        if saved is not None:
            return saved
        ctx = self.contexts.get((run, trial))
        if ctx is None or tuple_digest != ctx["digest"]:
            raise Refused("manifest_mismatch")  # must reference a started context
        if subject not in ctx["snapshot"].values():
            raise Refused("foreign_ref")  # membership comes from the persisted snapshot
        if outcome not in OUTCOMES or (outcome == "void") != (void_cause is not None):
            raise Refused("invalid_request")  # void needs a closed cause; nothing else has one
        if void_cause is not None and void_cause not in VOID_CAUSES:
            raise Refused("invalid_request")
        if discrimination not in DISCRIMINATIONS or (discrimination == "none") != (
            disc_ref is None
        ):
            raise Refused("invalid_request")  # a reference exactly when discrimination is stated
        if control is not None:
            self._check_control(control, run, outcome, discrimination, ctx)
        witnessed = origin == "server"
        if discrimination != "none":
            self._check_discrimination(discrimination, disc_ref, run, subject, ctx, witnessed)
        source = "traigent_witnessed" if witnessed else "client_reported"
        self.autokey += 1
        pos = self._append(
            type="evaluated",
            run=run,
            trial=trial,
            subject=subject,
            tuple=tuple_digest,
            source=source,
            subset=subset,
            protocol=protocol,
            outcome=outcome,
            void_cause=void_cause,
            discrimination=discrimination,
            disc_ref=disc_ref,
            control=copy.deepcopy(control),
        )
        return self._save("evaluate", key, digest, {"position": pos})

    def _check_control(
        self,
        control: dict[str, Any],
        run: str,
        outcome: str,
        discrimination: str,
        ctx: dict[str, Any],
    ) -> None:
        """A control-run record is closed, names a declared evaluator version of this run, and is
        itself an undiscriminated event whose outcome is the observed verdict."""
        if set(control) != CONTROL_FIELDS or discrimination != "none":
            raise Refused("invalid_request")
        if control["control_kind"] not in CONTROL_KINDS or control["run_ref"] != run:
            raise Refused("invalid_request")
        if control["expected_verdict"] not in ("pass", "fail"):
            raise Refused("invalid_request")
        if control["observed_verdict"] not in OUTCOMES or control["observed_verdict"] != outcome:
            raise Refused("invalid_request")
        entity, fp = control["evaluator_version_ref"].split(":")
        if self._version(entity, fp)["kind"] != "evaluator":
            raise Refused("invalid_request")
        executed = {v for (role, _s, _n), v in ctx["snapshot"].items() if role == "evaluator"}
        if control["evaluator_version_ref"] not in executed:
            raise Refused("invalid_request")  # the control names the evaluator this run executed

    def _check_discrimination(
        self,
        kind: str,
        position: int | None,
        run: str,
        subject: str,
        ctx: dict[str, Any],
        witnessed: bool,
    ) -> None:
        """The cited event must be an earlier evaluated event that really returned ``fail``."""
        cited = self.ledger[position - 1] if position and 0 < position <= len(self.ledger) else None
        if cited is None or cited["type"] != "evaluated" or cited["outcome"] != "fail":
            raise Refused("unknown_ref")
        if witnessed and cited["source"] != "traigent_witnessed":
            raise Refused("unknown_ref")  # witnessed claims never rest on client-reported fails
        if kind == "control":
            c = cited["control"]
            evaluators = {v for (role, _s, _n), v in ctx["snapshot"].items() if role == "evaluator"}
            ok = c is not None and (c["expected_verdict"], c["observed_verdict"]) == (
                "fail",
                "fail",
            )
            if not ok or c["evaluator_version_ref"] not in evaluators:
                raise Refused("unknown_ref")  # same evaluator version, known-bad input, real fail
        elif cited["control"] is not None:
            raise Refused("unknown_ref")  # a control record is evidence only as a control
        elif kind == "shown_by_run" and cited["run"] != run:
            raise Refused("unknown_ref")
        elif kind in ("shown_by_run", "prior_run"):
            if kind == "prior_run" and cited["subject"] != subject:
                raise Refused("unknown_ref")
            # the failure must come from the same evaluator version(s) as the claimed evaluation
            cited_ctx = self.contexts.get((cited["run"], cited["trial"]))
            cited_evaluators = (
                {v for (role, _s, _n), v in cited_ctx["snapshot"].items() if role == "evaluator"}
                if cited_ctx
                else set()
            )
            here = {v for (role, _s, _n), v in ctx["snapshot"].items() if role == "evaluator"}
            if not here or cited_evaluators != here:
                raise Refused("unknown_ref")

    @staticmethod
    def statement_text(ptype: str, discrimination: str, requested: str | None = None) -> str:
        """The compiler's text for an evaluation claim. A witnessed claim whose check was not
        shown able to fail may say only that an evaluation happened; the strong text is refused."""
        if ptype not in ("evaluated_client_reported", "evaluated_traigent_witnessed"):
            raise Refused("invalid_request")
        if discrimination not in DISCRIMINATIONS:
            raise Refused("invalid_request")
        if ptype == "evaluated_client_reported":
            text = "The client reported an evaluation of this version; Traigent did not witness it."
        elif discrimination == "none":
            if requested == STATEMENT_STRONG:
                raise Refused("coverage_insufficient")
            text = STATEMENT_WEAK
        else:
            if requested == STATEMENT_WEAK:
                raise Refused("invalid_request")  # the weak text cannot hide a discriminating check
            text = STATEMENT_STRONG
        if requested is not None and requested != text:
            raise Refused("invalid_request")
        return text

    # -- recovery -------------------------------------------------------------------------
    @staticmethod
    def commitment(representations: tuple[str, ...]) -> str:
        """The one construction (prefix + domain), shared by proofs and capture requests."""
        canonical = json.dumps(
            {"representations": list(representations)}, sort_keys=True, separators=(",", ":")
        )
        raw = b"traigent.legend.representation_commitment.v0\x00" + canonical.encode()
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def identity_verify(
        self,
        entity: str,
        fp: str,
        representations: tuple[str, ...],
        matched: bool,
        recomputed: bool = True,
        key: str | None = None,
    ) -> int:
        key = self._key(key)
        commitment = self.commitment(representations)
        body = dict(e=entity, f=fp, c=commitment, m=matched, r=recomputed)
        digest, saved = self._idem("identity_verify", key, body)
        if saved is not None:
            return saved["position"]
        self._version(entity, fp)
        if self.backend_keyed(entity, fp) and not self.format_known(entity, fp):
            raise Refused("store_unavailable")  # unknown format can never reach match
        self.autokey += 1
        pos = self._append(
            type="identity_verified",
            entity=entity,
            fp=fp,
            commitment=commitment,
            recomputed=recomputed,
            result="match" if matched else "mismatch",
        )
        self._save("identity_verify", key, digest, {"position": pos})
        return pos

    def capture(
        self,
        key: str,
        entity: str,
        fp: str,
        manifest: str,
        state: str,
        conformance: bool,
        complete: bool | dict[str, Any],
        reproduced: bool,
        claimed_keyed: bool,
        verification: int | None,
        commitment: str = "c0",
        wire_digest: str | None = None,
    ) -> Any:
        body = dict(
            entity=entity,
            fp=fp,
            manifest=manifest,
            state=state,
            conf=conformance,
            complete=complete,
            reproduced=reproduced,
            keyed=claimed_keyed,
            proof=verification,
            commitment=commitment,
        )
        digest, saved = self._idem("capture", key, body, wire_digest)
        if saved is not None:
            return saved
        self._version(entity, fp)
        coverage = self._coverage(self._version(entity, fp)["kind"], complete)
        complete = coverage["status"] == "complete"
        if manifest.startswith("rmfc0"):
            raise Refused("invalid_request")
        if claimed_keyed != self.backend_keyed(entity, fp):
            raise Refused("invalid_request")
        if state == "round_trip_verified" and not conformance:
            raise Refused("conformance_failed")
        if complete and not reproduced:
            raise Refused("coverage_insufficient")
        meta = dict(
            coverage=coverage,
            complete=complete,
            reproduced=reproduced,
            proof=verification,
            commitment=commitment,
        )
        if complete and claimed_keyed:
            proof = (
                next(
                    (
                        e
                        for e in self.ledger
                        if e["position"] == verification and e["type"] == "identity_verified"
                    ),
                    None,
                )
                if verification
                else None
            )
            if (
                proof is None
                or (proof["entity"], proof["fp"]) != (entity, fp)
                or proof["result"] != "match"
                or not proof["recomputed"]
                or proof["commitment"] != meta["commitment"]
            ):
                raise Refused("coverage_insufficient")  # proof must cover THESE representations
        existing = self.captures.get((entity, fp, manifest))
        if existing is not None and existing != meta:
            raise Refused("store_key_conflict")  # a manifest fingerprint is immutable
        pos = self._append(type="captured", entity=entity, fp=fp, manifest=manifest, state=state)
        self.captures[(entity, fp, manifest)] = meta
        return self._save("capture", key, digest, {"position": pos})

    @staticmethod
    def _coverage(kind: str, given: bool | dict[str, Any]) -> dict[str, Any]:
        """Validate coverage against RequiredComponents(kind) and return its canonical object."""
        if isinstance(given, bool):
            if given:
                given = {"status": "complete", "covered": list(REQUIRED[kind]), "missing": []}
            else:
                given = {
                    "status": "partial",
                    "covered": list(REQUIRED[kind][1:]),
                    "missing": [REQUIRED[kind][0]],
                }
        covered, missing = set(given["covered"]), set(given["missing"])
        if covered & missing or len(covered) != len(given["covered"]):
            raise Refused("invalid_request")
        if given["status"] == "complete":
            if missing or not set(REQUIRED[kind]) <= covered:
                raise Refused("coverage_insufficient")  # not complete for this kind
        elif not missing or not set(REQUIRED[kind]) <= covered | missing:
            raise Refused("invalid_request")  # covered and missing partition RequiredComponents
        return {"status": given["status"], "covered": sorted(covered), "missing": sorted(missing)}

    def capture_from_request(
        self, req: dict[str, Any], resolve: dict[str, tuple[str, str]], proofs: dict[str, int]
    ) -> Any:
        """Validated wire request -> model transition (digest over the whole wire body first)."""
        digest, saved = self._wire("capture", req, "RecordCaptureRequestV0")
        if saved is not None:
            return saved
        entity, fp = resolve[req["version_ref"]]
        proof_ref = req["identity_verification_ref"]
        return self.capture(
            req["idempotency_key"],
            entity,
            fp,
            req["recovery_manifest_fingerprint"],
            req["recovery_state"],
            req["conformance_passed"],
            req["coverage"],
            req["identity_digests_reproduced"],
            req["backend_keyed"],
            proofs.get(proof_ref) if proof_ref else None,
            req["representation_commitment"],
            wire_digest=digest,
        )

    def availability_from_request(
        self, req: dict[str, Any], resolve: dict[str, tuple[str, str]]
    ) -> Any:
        digest, saved = self._wire("availability", req, "RecordAvailabilityRequestV0")
        if saved is not None:
            return saved
        entity, fp = resolve[req["version_ref"]]
        return self.record_availability(
            req["idempotency_key"],
            entity,
            fp,
            req["recovery_manifest_fingerprint"],
            req["status"],
            wire_digest=digest,
        )

    def restore_from_request(self, req: dict[str, Any], resolve: dict[str, tuple[str, str]]) -> Any:
        digest, saved = self._wire("restore", req, "RecordRestoreRequestV0")
        if saved is not None:
            return saved
        entity, fp = resolve[req["version_ref"]]
        return self.record_restore(
            req["idempotency_key"],
            entity,
            fp,
            req["kind"],
            req["recovery_manifest_fingerprint"],
            req["outcome"],
            req["representation_digests_match"] and req["pillar_fingerprint_match"],
            req["isolated_destination"],
            req["historical_key_available"],
            req["dependencies_verified"],
            req["backend_keyed"],
            req["verified_artifact_digest"],
            coverage=req["coverage"],
            wire_digest=digest,
        )

    def record_availability(
        self,
        key: str,
        entity: str,
        fp: str,
        manifest: str,
        status: str,
        wire_digest: str | None = None,
    ) -> Any:
        digest, saved = self._idem(
            "availability", key, dict(e=entity, f=fp, m=manifest, s=status), wire_digest
        )
        if saved is not None:
            return saved
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")
        pos = self._append(
            type="availability_changed", entity=entity, fp=fp, manifest=manifest, status=status
        )
        return self._save("availability", key, digest, {"position": pos})

    def exact_prerequisites(
        self,
        entity: str,
        fp: str,
        manifest: str,
        equal: bool,
        isolated: bool,
        key_ok: bool,
        deps_ok: bool,
    ) -> None:
        """ExactPrerequisites(version, immutable capture metadata, restore-time measurements)."""
        meta = self.captures.get((entity, fp, manifest))
        if meta is None:
            raise Refused("unknown_ref")
        if not (meta["complete"] and meta["reproduced"]):
            raise Refused(
                "coverage_insufficient"
            )  # read from the immutable manifest, not the caller
        if self.backend_keyed(entity, fp) and (
            meta["proof"] is None or not self.format_known(entity, fp)
        ):
            raise Refused("coverage_insufficient")
        if not (equal and isolated and key_ok and deps_ok):
            raise Refused("coverage_insufficient")

    def _stage(self, entity: str, manifest: str, artifact: str) -> None:
        if self.artifacts.get((entity, manifest), artifact) != artifact:
            raise Refused("conflicting_report")  # one verified artifact digest per manifest
        self.artifacts[(entity, manifest)] = artifact

    def record_restore(
        self,
        key: str,
        entity: str,
        fp: str,
        kind: str,
        manifest: str,
        outcome: str,
        equal: bool,
        isolated: bool,
        key_ok: bool,
        deps_ok: bool,
        claimed_keyed: bool,
        artifact: str | None,
        coverage: dict[str, Any] | None = None,
        wire_digest: str | None = None,
    ) -> Any:
        body = dict(
            e=entity,
            f=fp,
            k=kind,
            m=manifest,
            o=outcome,
            eq=equal,
            iso=isolated,
            key=key_ok,
            deps=deps_ok,
            ck=claimed_keyed,
            a=artifact,
        )
        digest, saved = self._idem("restore", key, body, wire_digest)
        if saved is not None:
            return saved
        v = self._version(entity, fp)
        if kind != v["kind"] or claimed_keyed != self.backend_keyed(entity, fp):
            raise Refused("invalid_request")
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")  # Captured(version, manifest) join
        meta = self.captures[(entity, fp, manifest)]
        if coverage is not None and self._coverage(kind, coverage) != meta["coverage"]:
            raise Refused("manifest_mismatch")  # the report must agree with the same manifest
        if outcome == "exact":
            if artifact is None:
                raise Refused("invalid_request")  # exact carries the verified artifact digest
            if self.backend_keyed(entity, fp):
                raise Refused("coverage_insufficient")  # needs the server recompute
            self.exact_prerequisites(entity, fp, manifest, equal, isolated, key_ok, deps_ok)
            self._stage(entity, manifest, artifact)
        pos = self._append(
            type="restore_verified",
            entity=entity,
            fp=fp,
            manifest=manifest,
            outcome=outcome,
            origin="client",
            match="not_applicable" if outcome == "exact" else "not_checked",
            summary=dict(
                kind=kind,
                coverage=meta["coverage"],
                equal=equal,
                isolated=isolated,
                key_ok=key_ok,
                deps_ok=deps_ok,
                artifact=artifact,
                keyed=claimed_keyed,
            ),
        )
        return self._save("restore", key, digest, {"position": pos})

    def server_match(
        self,
        entity: str,
        fp: str,
        manifest: str,
        backend_has_key: bool,
        matched: bool,
        equal: bool,
        isolated: bool,
        deps_ok: bool,
        artifact: str,
        key: str | None = None,
    ) -> Any:
        key = self._key(key)
        body = dict(
            e=entity,
            f=fp,
            m=manifest,
            k=backend_has_key,
            ma=matched,
            eq=equal,
            iso=isolated,
            d=deps_ok,
            a=artifact,
        )
        digest, saved = self._idem("server_match", key, body)
        if saved is not None:
            return saved
        self._version(entity, fp)
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")
        if not self.format_known(entity, fp) or not backend_has_key:
            raise Refused("store_unavailable")  # key availability alone is not format availability
        if matched:
            self.exact_prerequisites(entity, fp, manifest, equal, isolated, True, deps_ok)
            self._stage(entity, manifest, artifact)
        self.autokey += 1
        pos = self._append(
            type="restore_verified",
            entity=entity,
            fp=fp,
            manifest=manifest,
            outcome="exact" if matched else "substituted",
            origin="server",
            match="match" if matched else "mismatch",
            summary=dict(
                kind=self._version(entity, fp)["kind"],
                coverage=self.captures[(entity, fp, manifest)]["coverage"],
                equal=equal,
                isolated=isolated,
                key_ok=backend_has_key,
                deps_ok=deps_ok,
                artifact=artifact if matched else None,
                keyed=self.backend_keyed(entity, fp),
            ),
        )
        return self._save("server_match", key, digest, {"position": pos})

    def restore_event_wire(self, event: dict[str, Any], manifest: str) -> dict[str, Any]:
        """Project a model restore event into the closed RestoreVerifiedEventV0 wire shape."""
        sm = event["summary"]
        server = event["origin"] == "server"
        base = env(
            "restore_verified",
            event["origin"],
            "server_recorded" if server else "client_sdk_reported",
        )
        return {
            **base,
            "kind": sm["kind"],
            "recovery_manifest_fingerprint": manifest,
            "outcome": event["outcome"],
            "coverage": sm["coverage"],
            "isolated_destination": True,
            "representation_digests_match": sm["equal"],
            "pillar_fingerprint_match": sm["equal"],
            "historical_key_available": sm["key_ok"],
            "dependencies_verified": sm["deps_ok"],
            "verified_artifact_digest": sm["artifact"],
            "backend_keyed": sm["keyed"],
            "backend_match_result": event["match"],
        }

    def activate(self, entity: str, manifest: str, artifact: str) -> None:
        staged = self.artifacts.get((entity, manifest))
        if staged is None or artifact != staged:
            raise Refused("manifest_mismatch")  # the very artifact that was verified
        self.activated[(entity, manifest)] = artifact

    # -- axes and predicates ----------------------------------------------------------------
    def restorable_now(
        self, entity: str, fp: str, manifest: str, prefix: int | None = None
    ) -> bool:
        events = self.ledger[: prefix if prefix is not None else len(self.ledger)]
        latest = [
            e["status"]
            for e in events
            if e["type"] == "availability_changed"
            and (e["entity"], e["fp"], e["manifest"]) == (entity, fp, manifest)
        ]
        return (
            self._captured(entity, fp, manifest, prefix)
            and bool(latest)
            and latest[-1] == "available"
        )

    def recovery_state(self, entity: str, fp: str, prefix: int | None = None) -> str:
        events = self.ledger[: prefix if prefix is not None else len(self.ledger)]
        best = max(
            (
                STRENGTH[e["state"]]
                for e in events
                if e["type"] == "captured" and (e["entity"], e["fp"]) == (entity, fp)
            ),
            default=0,
        )
        return ["none", "stored_unverified", "round_trip_verified"][best]

    def issue_predicate(
        self,
        ptype: str,
        subject: tuple[str, str, str],
        cutoff: int,
        manifest: str | None = None,
        tuple_digest: str | None = None,
        trial: str | None = None,
        subset: str | None = None,
        protocol: str | None = None,
        outcome: str | None = None,
        discrimination: str | None = None,
        disc_ref: int | None = None,
    ) -> bool:
        entity, fp, kind = subject
        v = self._version(entity, fp)
        if v["kind"] != kind or ptype not in PREDICATES:
            raise Refused("invalid_request")  # subject must equal the authoritative projection
        if not 0 < cutoff <= self.high_water:
            raise Refused("invalid_request")  # cutoff must be inside the sealed committed prefix
        ev = self.ledger[:cutoff]
        ref = f"{entity}:{fp}"
        if ptype == "declared":
            found = any(
                e["type"] == "declared" and (e["entity"], e["fp"]) == (entity, fp) for e in ev
            )
        elif ptype == "captured":
            found = manifest is not None and self._captured(entity, fp, manifest, cutoff)
        elif ptype == "restorable_now":
            if manifest is None or not self.restorable_now(entity, fp, manifest, cutoff):
                raise Refused("coverage_insufficient")
            return True
        elif ptype.startswith("restore_verified"):
            origin = "client" if ptype.endswith("client_reported") else "server"
            meta = self.captures.get((entity, fp, manifest or ""))
            found = bool(meta and meta["complete"]) and any(
                e["type"] == "restore_verified"
                and e["outcome"] == "exact"
                and e["origin"] == origin
                and (e["entity"], e["fp"], e["manifest"]) == (entity, fp, manifest)
                for e in ev
            )
        elif ptype == "bound_to_run":
            found = any(
                e["type"] == "bound_to_run"
                and e["version"] == ref
                and e["tuple"] == tuple_digest
                and e["trial"] == trial
                for e in ev
            )
        else:  # evaluated_*
            source = (
                "client_reported" if ptype.endswith("client_reported") else "traigent_witnessed"
            )
            if outcome is None or discrimination is None:
                raise Refused("invalid_request")  # evaluation claims state both, always
            if outcome not in ("pass", "fail"):
                raise Refused("coverage_insufficient")  # only a verdict is signed
            found = (
                subset is not None
                and protocol is not None
                and any(
                    e["type"] == "evaluated"
                    and e["subject"] == ref
                    and e["tuple"] == tuple_digest
                    and e["trial"] == trial
                    and e["source"] == source
                    and e["subset"] == subset
                    and e["protocol"] == protocol
                    and e["outcome"] == outcome
                    and e["discrimination"] == discrimination
                    and e["disc_ref"] == disc_ref
                    for e in ev
                )
            )
        if not found:
            raise Refused("unknown_ref")
        return True

    # -- Director ---------------------------------------------------------------------------
    def _ordered(self, entity: str, as_of: int | None = None) -> list[str]:
        """Deterministic order: by the ledger position of the version's first declaration.

        ``as_of`` (None = current) keeps only versions first declared at position <= as_of."""
        first: dict[str, int] = {}
        for e in self.ledger:
            if e["type"] == "declared" and e["entity"] == entity:
                first.setdefault(e["fp"], e["position"])
        if as_of is not None:
            first = {fp: pos for fp, pos in first.items() if pos <= as_of}
        return [fp for fp, _ in sorted(first.items(), key=lambda kv: kv[1])]

    @staticmethod
    def _token(entity: str, boundary: int, as_of: int | None = None) -> str:
        return "cursor_" + _digest("cursor", entity, boundary, as_of)[:32]

    def _cursor(self, entity: str, boundary: int, as_of: int | None = None) -> str:
        """The ONE cursor issuer, shared by the Legend API (query) and the Director."""
        token = self._token(entity, boundary, as_of)
        self.cursors[token] = (entity, boundary, as_of)
        return token

    def _resolve_cursor(self, entity: str, cursor: str | None, as_of: int | None) -> int:
        """Start boundary of a page; a cursor is issued, for this entity AND this as_of."""
        if as_of is not None and (as_of < 0 or as_of > len(self.ledger)):
            raise Refused("invalid_request")  # a future snapshot is not stable
        if cursor is None:
            return 0
        bound = self.cursors.get(cursor)
        if bound is None or bound[0] != entity or bound[2] != as_of:
            raise Refused("invalid_request")
        return bound[1]

    def query(
        self,
        entity: str,
        page_size: int,
        page_cursor: str | None = None,
        as_of_ledger_position: int | None = None,
    ) -> dict[str, Any]:
        """Legend API query (QueryRequestV0): read-only except for issuing the next cursor."""
        if not 1 <= page_size <= 100:
            raise Refused("invalid_request")
        start = self._resolve_cursor(entity, page_cursor, as_of_ledger_position)
        order = self._ordered(entity, as_of_ledger_position)
        end = start + page_size
        nxt = self._cursor(entity, end, as_of_ledger_position) if end < len(order) else None
        return {"fps": order[start:end], "next_page_cursor": nxt}

    def director_instruction(self, op: str, **refs: Any) -> str:
        if op not in (
            "declare_version",
            "query_versions",
            "capture_version",
            "verify_restore",
            "restore_version",
        ):
            raise Refused("invalid_request")
        refs = dict(refs)
        if op in ("capture_version", "verify_restore", "restore_version"):
            self._version(refs["entity"], refs["fp"])
        if op in ("verify_restore", "restore_version") and not self._captured(
            refs["entity"], refs["fp"], refs["manifest"]
        ):
            raise Refused("unknown_ref")
        if op == "query_versions":
            size = refs.get("page_size", 0)
            if not 1 <= size <= 100:
                raise Refused("invalid_request")
            cur = refs.get("page_cursor")
            if cur is not None:
                bound = self.cursors.get(cur)
                if bound is None or bound[2] is None:
                    raise Refused("invalid_request")  # issued, under an explicit snapshot
                as_of = bound[2]  # a continuation keeps the snapshot of its cursor
            else:
                as_of = len(self.ledger)  # first page: the snapshot is the current position
            refs["start"] = self._resolve_cursor(refs["entity"], cur, as_of)
            refs["as_of"] = as_of
            refs["snapshot"] = self._ordered(refs["entity"], as_of)
        ident = f"ins{len(self.instructions) + 1}"
        self.instructions[ident] = {"op": op, **refs}
        return ident

    def director_result(self, ident: str, result: dict[str, Any]) -> Any:
        if ident not in self.instructions:
            raise Refused("unknown_ref")
        ins = self.instructions[ident]
        digest = _digest(result)
        if ident in self.results:
            if self.results[ident][0] == digest:
                return self.results[ident][1]  # identical retry returns the saved result
            raise Refused("conflicting_report")
        op, ok_ = ins["op"], result.get("outcome") == "succeeded"
        cursor = None
        if not ok_ and op == "query_versions" and result.get("next_page_cursor") is not None:
            raise Refused("invalid_request")  # failed/refused carries no continuation
        if ok_ and op == "declare_version":
            ent = result.get("entity")
            if (
                ent not in self.entities
                or self.entities[ent]["kind"] != ins["kind"]
                or (ins.get("entity") is not None and ent != ins["entity"])
                or (ent, result.get("fp")) not in self.versions
            ):
                raise Refused("manifest_mismatch")
        if ok_ and op == "query_versions":
            order, start, size = ins["snapshot"], ins["start"], ins["page_size"]
            if list(result.get("fps", ())) != order[start : start + size]:
                raise Refused("foreign_ref")  # exact slice of the issued page
            end = start + size
            expected = self._token(ins["entity"], end, ins["as_of"]) if end < len(order) else None
            if result.get("next_page_cursor") != expected:
                raise Refused("invalid_request")
            cursor = expected
        if ok_ and op == "capture_version":
            if not self._captured(ins["entity"], ins["fp"], result.get("manifest", "")):
                raise Refused("manifest_mismatch")  # needs the capture evidence on the ledger
        if ok_ and op in ("verify_restore", "restore_version"):
            # the manifest comes ONLY from the saved instruction (results carry none)
            manifest = ins["manifest"]
            if result.get("restore_outcome") == "exact":
                have = any(
                    e["type"] == "restore_verified"
                    and e["outcome"] == "exact"
                    and (e["entity"], e["fp"], e["manifest"])
                    == (ins["entity"], ins["fp"], manifest)
                    for e in self.ledger
                )
                if (
                    not have
                    or result.get("store_status") != "retrieved"
                    or result.get("backend_match_result") == "mismatch"
                ):
                    raise Refused("manifest_mismatch")  # an agent-supplied match is not evidence
        if cursor is not None:
            self._cursor(ins["entity"], ins["start"] + ins["page_size"], ins["as_of"])  # on commit
        self.results[ident] = (digest, result)
        return result


def _atomic(led: Legend, code: str, fn: Any, *args: Any, **kwargs: Any) -> None:
    before = led.state()
    with pytest.raises(Refused, match=code):
        fn(*args, **kwargs)
    assert led.state() == before, "refusal changed state"


def _ent(led: Legend, fp: str) -> str:
    return next(e for (e, f) in led.versions if f == fp)


def _seed() -> Legend:
    led = Legend()
    led.declare("a", None, "agent", "A", "client_declared", group="g-agent")
    led.declare("b", None, "agent", "B", "client_declared", group="g-agent2")
    led.declare("c", None, "configuration", "C", "client_declared")
    led.declare("d", None, "evaluation_dataset", "D", "client_declared")
    led.declare("e0", None, "evaluator", "E0", "client_declared", fmt="plain")
    led.declare("e1", None, "evaluator", "E1", "client_declared", fmt="plain")
    led.declare("s", None, "search_space", "S", "client_declared")
    return led


def test_model_declare_creates_entities_atomically_and_never_mutates_on_refusal() -> None:
    led = Legend()
    first = led.declare("k1", None, "agent", "v1", "client_declared")
    assert first["created"] and first["entity"] in led.entities
    assert led.declare("k1", None, "agent", "v1", "client_declared") is first  # saved response
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.declare,
        "k1",
        None,
        "agent",
        "v2",
        "client_declared",
    )
    _atomic(
        led, "unknown_ref", led.declare, "k2", None, "agent", "v9", "client_declared", None, "ghost"
    )
    assert len(led.entities) == 1 and ("ent1", "v9") not in led.versions
    ent = first["entity"]
    led.declare("k3", ent, "agent", "v2", "client_declared", "v1", "v1")
    led.declare("k4", ent, "agent", "v3", "client_declared", "v2", "v2")
    led.declare("k5", ent, "agent", "v1", "client_declared", None, "v3")  # revert is legal
    _atomic(led, "invalid_request", led.declare, "k6", ent, "agent", "v2", "client_declared", "v3")
    _atomic(led, "invalid_request", led.declare, "k7", ent, "agent", "v1", "sdk_fingerprinted")
    _atomic(led, "invalid_request", led.declare, "k8", ent, "agent", "v9", "client_declared", "v9")
    _atomic(led, "foreign_ref", led.declare, "k9", ent, "configuration", "v1", "client_declared")
    _atomic(
        led, "invalid_request", led.declare, "k10", None, "search_space", "s1", "sdk_fingerprinted"
    )
    for i, (fp, prev) in enumerate([("v2", "v1"), ("v1", "v2"), ("v2", "v1")]):
        led.declare(f"f{i}", ent, "agent", fp, "client_declared", None, prev)
    assert [e["fp"] for e in led.ledger[-3:]] == ["v2", "v1", "v2"]
    # the same key on another endpoint is a different request scope
    led.requests[("capture", "k1")] = ("x", None)
    assert led.declare("k1", None, "agent", "v1", "client_declared") is first


def test_model_authority_uniqueness_is_two_directional() -> None:
    led = Legend()
    a = led.declare("a", None, "agent", "SAME", "client_declared", group="agent-1")["entity"]
    again = led.declare("a2", None, "agent", "OTHER", "client_declared", group="agent-1")
    assert again["entity"] == a and len(led.entities) == 1  # null ref reuses the grouped entity
    b = led.declare("b", None, "agent", "SAME", "client_declared", group="agent-2")["entity"]
    assert a != b
    for g in ("agent-1", "agent-2", "agent-9"):
        led.authority_rows[("agent_builds", g, "SAME")] = True
    led.authority_rows[("agent_builds", "agent-1", "OTHER")] = True
    _atomic(led, "foreign_ref", led.link_authority, a, "SAME", "agent_builds", "agent-2")
    _atomic(led, "unknown_ref", led.link_authority, a, "SAME", "agent_builds", "agent-8")
    led.link_authority(a, "SAME", "agent_builds", "agent-1")
    n = len(led.ledger)
    led.link_authority(a, "SAME", "agent_builds", "agent-1")  # identical replay: no-op
    assert len(led.ledger) == n
    led.link_authority(a, "OTHER", "agent_builds", "agent-1")  # another version, same group
    # the entity is bound to one group across ALL its versions
    led.entities[a]["group"] = "agent-9"
    led.group_entities[("agent", "agent-9")] = a
    _atomic(led, "conflicting_report", led.link_authority, a, "SAME", "agent_builds", "agent-9")
    led.link_authority(b, "SAME", "agent_builds", "agent-2")


def test_model_role_kind_matrix_configuration_roles_and_replacement_within_pillar() -> None:
    led = _seed()
    ent = lambda fp: _ent(led, fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "run_base_configuration", 0, ent("C"), "C")
    _atomic(led, "invalid_request", led.propose, "r", None, "base_agent", 1, ent("C"), "C")
    _atomic(led, "invalid_request", led.propose, "r", "t1", "base_agent", 0, ent("A"), "A")
    _atomic(led, "invalid_request", led.propose, "r", None, "trial_candidate", 0, ent("B"), "B")
    led.propose("r", "t1", "trial_candidate", 0, ent("B"), "B")
    eff = led.effective("r", "t1")
    assert ("base_agent", "run", 0) not in eff and eff[("trial_candidate", "trial", 0)].endswith(
        "B"
    )
    assert eff[("run_base_configuration", "run", 0)].endswith("C")  # config survives agent swap
    led.propose("r", "t1", "trial_configuration", 0, ent("C"), "C")
    assert ("run_base_configuration", "run", 0) not in led.effective("r", "t1")  # same pillar only
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    led.propose("r", "t1", "evaluator", 0, ent("E1"), "E1")
    keys = [k for k in led.effective("r", "t1") if k[0] == "evaluator"]
    assert keys == [("evaluator", "run", 0), ("evaluator", "trial", 0)]


def test_model_contexts_freeze_separately_and_persist_their_snapshot() -> None:
    led = _seed()
    ent = lambda fp: _ent(led, fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "dataset", 0, ent("D"), "D")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    assert led.ledger[-1]["type"] == "declared"  # proposals emit no evidence
    observed = dict(led.effective("r", None))
    td = led.start_execution("r", None, observed, "strict")
    bound = [e for e in led.ledger if e["type"] == "bound_to_run"]
    assert len(bound) == 3 and {e["tuple"] for e in bound} == {td}
    assert led.contexts[("r", None)]["snapshot"] == observed
    n = len(led.ledger)
    assert led.start_execution("r", None, observed, "strict") == td  # identical replay: no-op
    assert len(led.ledger) == n
    _atomic(
        led, "manifest_mismatch", led.start_execution, "r", None, {}, "strict"
    )  # replay completeness
    led.propose("r", None, "dataset", 0, ent("D"), "D")  # identical replay after freezing: no-op
    _atomic(led, "conflicting_report", led.propose, "r", None, "evaluator", 1, ent("E1"), "E1")
    led.propose("r", "t1", "trial_candidate", 0, ent("B"), "B")
    t_obs = dict(led.effective("r", "t1"))
    t1 = led.start_execution("r", "t1", t_obs, "strict")
    assert t1 != td and any(e.get("trial") == "t1" and e.get("tuple") == t1 for e in led.ledger)
    _atomic(led, "conflicting_report", led.propose, "r", "t1", "trial_candidate", 0, ent("A"), "A")
    led.propose("q", "t9", "trial_candidate", 0, ent("B"), "B")
    _atomic(led, "invalid_request", led.start_execution, "q", "t9", {}, "strict")


def test_model_drift_never_rewrites_inherited_frozen_slots() -> None:
    led = _seed()
    ent = lambda fp: _ent(led, fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    exp = led.effective("r", None)
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, {}, "strict")
    only = {k: v for k, v in exp.items() if k == ("evaluator", "run", 0)}
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, only, "strict")
    drifted = {**exp, ("base_agent", "run", 0): f"{ent('B')}:B"}
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, drifted, "strict")
    assert ("r", None) not in led.contexts
    _atomic(
        led,
        "unknown_ref",
        led.start_execution,
        "r",
        None,
        {**exp, ("base_agent", "run", 0): "ghost:X"},
        "permitted",
    )
    _atomic(
        led,
        "invalid_request",
        led.start_execution,
        "r",
        None,
        {**exp, ("base_agent", "run", 0): f"{ent('C')}:C"},
        "permitted",
    )
    dA = led.start_execution("r", None, drifted, "permitted")  # run-base drift: A -> B, then bind
    assert led.proposals[("r", "run", None, "base_agent", 0)].endswith("B")
    _atomic(led, "conflicting_report", led.start_execution, "r", None, exp, "permitted")
    # trial context: inherited run slots can never drift; only trial-local slots may
    base = dict(led.effective("r", "t1"))
    inherited = {**base, ("base_agent", "run", 0): f"{ent('A')}:A"}
    before = led.state()
    _atomic(led, "conflicting_report", led.start_execution, "r", "t1", inherited, "permitted")
    assert led.state() == before
    led.propose("r", "t1", "trial_candidate", 0, ent("A"), "A")
    expected = dict(led.effective("r", "t1"))
    drift_local = {**expected, ("trial_candidate", "trial", 0): f"{ent('B')}:B"}
    t = led.start_execution("r", "t1", drift_local, "permitted")
    # the shared run proposal and the run-base evidence are untouched; evaluation uses snapshots
    assert led.proposals[("r", "run", None, "base_agent", 0)].endswith("B")
    assert led.contexts[("r", None)]["digest"] == dA
    _atomic(led, "foreign_ref", led.evaluate, "r", None, f"{ent('A')}:A", dA, "server")
    assert led.evaluate("r", "t1", f"{ent('B')}:B", t, "server")["position"] > 0


def test_model_evaluation_needs_started_context_and_membership() -> None:
    led = _seed()
    ent = lambda fp: _ent(led, fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    td = led.start_execution("r", None, dict(led.effective("r", None)), "strict")
    led.propose("r", "t1", "trial_candidate", 0, ent("B"), "B")
    _atomic(
        led, "manifest_mismatch", led.evaluate, "r", "t1", f"{ent('B')}:B", _digest("x"), "server"
    )
    a = f"{ent('A')}:A"
    assert led.evaluate("r", None, a, td, "server")["position"] > 0
    _atomic(led, "foreign_ref", led.evaluate, "r", None, f"{ent('B')}:B", td, "server")
    _atomic(led, "manifest_mismatch", led.evaluate, "r", None, a, "wrong", "server")
    assert led.ledger[-1]["source"] == "traigent_witnessed" and led.ledger[-1]["trial"] is None


NONE_PASS = {"outcome": "pass", "discrimination": "none", "disc_ref": None}
NONE_FAIL = {"outcome": "fail", "discrimination": "none", "disc_ref": None}


def test_model_all_eight_predicates_positive_and_wrong_evidence() -> None:
    led = _seed()
    ent = lambda fp: _ent(led, fp)  # noqa: E731
    a, b = ent("A"), ent("B")
    led.propose("r", None, "base_agent", 0, a, "A")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    td = led.start_execution("r", None, dict(led.effective("r", None)), "strict")
    led.evaluate("r", None, f"{a}:A", td, "server", "msr-1", "holdout", outcome="pass")
    led.evaluate("r", None, f"{a}:A", td, "client", "msr-2", "full_dataset", outcome="fail")
    led.capture("c1", a, "A", "m1", "round_trip_verified", True, True, True, False, None)
    led.record_availability("av1", a, "A", "m1", "available")
    led.record_restore("rs1", a, "A", "agent", "m1", "exact", True, True, True, True, False, "art")
    hw = led.high_water
    sub = (a, "A", "agent")
    cases = {
        "declared": ({}, {"manifest": None}),
        "captured": ({"manifest": "m1"}, {"manifest": "m9"}),
        "restorable_now": ({"manifest": "m1"}, {"manifest": "m9"}),
        "restore_verified_client_reported": ({"manifest": "m1"}, {"manifest": "m9"}),
        "restore_verified_backend_matched": ({"manifest": "m1"}, {"manifest": "m1"}),  # client only
        "bound_to_run": ({"tuple_digest": td}, {"tuple_digest": "bad"}),
        "evaluated_client_reported": (
            {"tuple_digest": td, "subset": "msr-2", "protocol": "full_dataset", **NONE_FAIL},
            {"tuple_digest": td, "subset": "msr-1", "protocol": "full_dataset", **NONE_FAIL},
        ),
        "evaluated_traigent_witnessed": (
            {"tuple_digest": td, "subset": "msr-1", "protocol": "holdout", **NONE_PASS},
            {"tuple_digest": td, "subset": "msr-1", "protocol": "full_dataset", **NONE_PASS},
        ),
    }
    assert set(cases) == set(PREDICATES)
    for ptype, (good, bad) in cases.items():
        if ptype == "declared":
            assert led.issue_predicate(ptype, sub, hw)
            _atomic(led, "unknown_ref", led.issue_predicate, ptype, (b, "B", "agent"), 1)
            continue
        if ptype == "restore_verified_backend_matched":
            _atomic(led, "unknown_ref", led.issue_predicate, ptype, sub, hw, **good)
            continue
        assert led.issue_predicate(ptype, sub, hw, **good), ptype
        code = "coverage_insufficient" if ptype == "restorable_now" else "unknown_ref"
        _atomic(led, code, led.issue_predicate, ptype, sub, hw, **bad)
    # another version never inherits this evidence
    _atomic(
        led,
        "unknown_ref",
        led.issue_predicate,
        "bound_to_run",
        (b, "B", "agent"),
        hw,
        tuple_digest=td,
    )


def test_model_sealed_cutoff_subject_projection_and_captured_joins() -> None:
    led = _seed()
    a, b = _ent(led, "A"), _ent(led, "B")
    led.capture("c1", a, "A", "m1", "round_trip_verified", True, False, True, False, None)
    led.record_availability("av1", a, "A", "m1", "available")
    cutoff = led.high_water
    _atomic(
        led,
        "invalid_request",
        led.issue_predicate,
        "restorable_now",
        (a, "A", "agent"),
        cutoff + 1,
        "m1",
    )
    assert led.issue_predicate("restorable_now", (a, "A", "agent"), cutoff, "m1")
    led.record_availability("av2", a, "A", "m1", "missing")
    assert led.restorable_now(a, "A", "m1", cutoff) and not led.restorable_now(a, "A", "m1")
    _atomic(
        led,
        "coverage_insufficient",
        led.issue_predicate,
        "restorable_now",
        (a, "A", "agent"),
        led.high_water,
        "m1",
    )
    _atomic(
        led,
        "invalid_request",
        led.issue_predicate,
        "restorable_now",
        (a, "A", "evaluator"),
        cutoff,
        "m1",
    )
    _atomic(
        led,
        "coverage_insufficient",
        led.issue_predicate,
        "restorable_now",
        (b, "B", "agent"),
        cutoff,
        "m1",
    )
    _atomic(led, "unknown_ref", led.record_availability, "av3", b, "B", "m1", "available")
    _atomic(
        led,
        "unknown_ref",
        led.record_restore,
        "rs",
        b,
        "B",
        "agent",
        "m1",
        "exact",
        True,
        True,
        True,
        True,
        False,
        "art",
    )
    led.capture("c2", a, "A", "m2", "stored_unverified", False, False, True, False, None)
    assert led.recovery_state(a, "A") == "round_trip_verified"
    assert led.recovery_state(b, "B") == "none"
    _atomic(
        led,
        "conformance_failed",
        led.capture,
        "c3",
        a,
        "A",
        "m3",
        "round_trip_verified",
        False,
        False,
        True,
        False,
        None,
    )
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c4",
        a,
        "A",
        "m4",
        "stored_unverified",
        True,
        True,
        False,
        False,
        None,
    )
    _atomic(
        led,
        "invalid_request",
        led.capture,
        "c5",
        a,
        "A",
        "rmfc0:x",
        "stored_unverified",
        True,
        False,
        True,
        False,
        None,
    )
    _atomic(
        led,
        "invalid_request",
        led.capture,
        "c6",
        a,
        "A",
        "m5",
        "stored_unverified",
        True,
        False,
        True,
        True,
        None,
    )


def test_model_record_operations_are_idempotent_per_endpoint() -> None:
    led = _seed()
    a = _ent(led, "A")
    first = led.capture("c1", a, "A", "m1", "round_trip_verified", True, True, True, False, None)
    n = len(led.ledger)
    assert (
        led.capture("c1", a, "A", "m1", "round_trip_verified", True, True, True, False, None)
        is first
    )
    assert len(led.ledger) == n  # a logical retry appends nothing
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.capture,
        "c1",
        a,
        "A",
        "m2",
        "stored_unverified",
        False,
        False,
        True,
        False,
        None,
    )
    av = led.record_availability("a1", a, "A", "m1", "available")
    assert led.record_availability("a1", a, "A", "m1", "available") is av
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.record_availability,
        "a1",
        a,
        "A",
        "m1",
        "missing",
    )
    rs = led.record_restore(
        "r1", a, "A", "agent", "m1", "exact", True, True, True, True, False, "x"
    )
    assert (
        led.record_restore("r1", a, "A", "agent", "m1", "exact", True, True, True, True, False, "x")
        is rs
    )
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.record_restore,
        "r1",
        a,
        "A",
        "agent",
        "m1",
        "partial",
        True,
        True,
        True,
        True,
        False,
        "x",
    )
    # same logical content under a fresh key is a new record, not a retry
    led.record_availability("a2", a, "A", "m1", "available")
    assert len(led.ledger) == n + 3
    # a manifest fingerprint is immutable: different metadata needs a different manifest
    _atomic(
        led,
        "store_key_conflict",
        led.capture,
        "c9",
        a,
        "A",
        "m1",
        "round_trip_verified",
        True,
        False,
        True,
        False,
        None,
    )


def test_model_exact_reads_immutable_capture_metadata_not_caller_booleans() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", "partial-m", "stored_unverified", False, False, True, False, None)
    _atomic(
        led,
        "coverage_insufficient",
        led.record_restore,
        "r1",
        a,
        "A",
        "agent",
        "partial-m",
        "exact",
        True,
        True,
        True,
        True,
        False,
        "art",
    )  # partial capture can never be exact
    led.capture("c2", a, "A", "full-m", "round_trip_verified", True, True, True, False, None)
    _atomic(
        led,
        "coverage_insufficient",
        led.record_restore,
        "r2",
        a,
        "A",
        "agent",
        "full-m",
        "exact",
        False,
        True,
        True,
        True,
        False,
        "art",
    )  # restore-time measurement fails
    led.record_restore(
        "r3", a, "A", "agent", "full-m", "exact", True, True, True, True, False, "art"
    )
    # unreproduced identity digests keep a capture partial, so it cannot be complete at all
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c3",
        a,
        "A",
        "x-m",
        "stored_unverified",
        True,
        True,
        False,
        False,
        None,
    )


def test_model_backend_keyed_proof_commitment_and_format_gates() -> None:
    led = Legend()
    ss = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    reps = ("rep-a", "rep-b")
    rc = Legend.commitment(reps)
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c0",
        ss,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        None,
        rc,
    )  # no proof
    mismatch = led.identity_verify(ss, "S", reps, False)
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c1",
        ss,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        mismatch,
        rc,
    )
    proof = led.identity_verify(ss, "S", reps, True)
    # a proof for other representations (same version) cannot be reused by a different manifest
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c2",
        ss,
        "S",
        "m2",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        proof,
        Legend.commitment(("rep-a", "rep-X")),
    )
    weak = led.identity_verify(ss, "S", reps, True, recomputed=False)
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        "c3",
        ss,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        weak,
        rc,
    )
    led.capture("c4", ss, "S", "m", "round_trip_verified", True, True, True, True, proof, rc)
    _atomic(
        led,
        "coverage_insufficient",
        led.record_restore,
        "r1",
        ss,
        "S",
        "search_space",
        "m",
        "exact",
        True,
        True,
        True,
        True,
        True,
        "art",
    )
    _atomic(
        led,
        "invalid_request",
        led.record_restore,
        "r2",
        ss,
        "S",
        "search_space",
        "m",
        "exact",
        True,
        True,
        True,
        True,
        False,
        "art",
    )
    led.record_restore(
        "r3", ss, "S", "search_space", "m", "substituted", True, True, True, True, True, "art"
    )
    _atomic(
        led,
        "store_unavailable",
        led.server_match,
        ss,
        "S",
        "m",
        False,
        True,
        True,
        True,
        True,
        "art",
    )
    _atomic(
        led, "unknown_ref", led.server_match, ss, "S", "ghost", True, True, True, True, True, "art"
    )
    led.server_match(ss, "S", "m", True, False, True, True, True, "art")  # mismatch: substituted
    assert led.ledger[-1]["outcome"] == "substituted"
    led.server_match(ss, "S", "m", True, True, True, True, True, "art-X")
    # a partial keyed capture can never be upgraded by server_match prerequisites
    led.capture("c5", ss, "S", "pm", "stored_unverified", False, False, True, True, None, rc)
    _atomic(
        led,
        "coverage_insufficient",
        led.server_match,
        ss,
        "S",
        "pm",
        True,
        True,
        True,
        True,
        True,
        "art",
    )
    # unknown evaluator format never reaches a match or exact
    ev = led.declare("e", None, "evaluator", "EV", "client_declared", fmt="unknown")["entity"]
    assert led.backend_keyed(ev, "EV")
    _atomic(led, "store_unavailable", led.identity_verify, ev, "EV", reps, True)
    led.capture("c6", ev, "EV", "em", "stored_unverified", False, False, True, True, None, rc)
    _atomic(
        led,
        "store_unavailable",
        led.server_match,
        ev,
        "EV",
        "em",
        True,
        True,
        True,
        True,
        True,
        "art",
    )


def test_model_artifact_digest_flows_from_restore_to_activation() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", "m", "round_trip_verified", True, True, True, False, None)
    _atomic(led, "manifest_mismatch", led.activate, a, "m", "art-1")  # nothing staged yet
    led.record_restore("r1", a, "A", "agent", "m", "exact", True, True, True, True, False, "art-1")
    assert led.artifacts[(a, "m")] == "art-1"
    _atomic(led, "manifest_mismatch", led.activate, a, "m", "art-2")  # substituted artifact
    _atomic(
        led,
        "conflicting_report",
        led.record_restore,
        "r2",
        a,
        "A",
        "agent",
        "m",
        "exact",
        True,
        True,
        True,
        True,
        False,
        "art-2",
    )  # a second artifact cannot replace the first
    led.activate(a, "m", "art-1")
    assert led.activated[(a, "m")] == "art-1"


def test_model_director_query_pagination_is_deterministic_bound_and_sized() -> None:
    led = Legend()
    ent = led.declare("k0", None, "agent", "v1", "client_declared")["entity"]
    for i, fp in enumerate(("v2", "v3", "v4"), 1):
        led.declare(f"k{i}", ent, "agent", fp, "client_declared")
    _atomic(
        led, "invalid_request", led.director_instruction, "query_versions", entity=ent, page_size=0
    )
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=ent,
        page_size=101,
    )
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=ent,
        page_size=2,
        page_cursor="cursor_" + "0" * 32,
    )  # syntactically valid, never issued
    q = led.director_instruction("query_versions", entity=ent, page_size=2, page_cursor=None)
    _atomic(
        led,
        "foreign_ref",
        led.director_result,
        q,
        {"outcome": "succeeded", "fps": ["v1", "v2", "v3"], "next_page_cursor": None},
    )  # too many
    _atomic(
        led,
        "foreign_ref",
        led.director_result,
        q,
        {"outcome": "succeeded", "fps": ["v2", "v1"], "next_page_cursor": None},
    )  # wrong order
    _atomic(
        led,
        "invalid_request",
        led.director_result,
        q,
        {"outcome": "succeeded", "fps": ["v1", "v2"], "next_page_cursor": "cursor_" + "1" * 32},
    )
    nxt = led._cursor(ent, 2, led.instructions[q]["as_of"])
    page1 = {"outcome": "succeeded", "fps": ["v1", "v2"], "next_page_cursor": nxt}
    assert led.director_result(q, page1) is page1
    q2 = led.director_instruction("query_versions", entity=ent, page_size=2, page_cursor=nxt)
    page2 = {"outcome": "succeeded", "fps": ["v3", "v4"], "next_page_cursor": None}
    assert led.director_result(q2, page2) is page2
    other = led.declare("o", None, "agent", "w1", "client_declared")["entity"]
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=other,
        page_size=2,
        page_cursor=nxt,
    )  # a cursor is bound to its entity


def test_model_director_per_operation_relations_and_result_retries() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", "m1", "round_trip_verified", True, True, True, False, None)
    led.record_restore("r1", a, "A", "agent", "m1", "exact", True, True, True, True, False, "art")
    d = led.director_instruction("declare_version", kind="agent", entity=None)
    _atomic(
        led,
        "manifest_mismatch",
        led.director_result,
        d,
        {"outcome": "succeeded", "entity": "ghost", "fp": "A"},
    )
    ok = {"outcome": "succeeded", "entity": a, "fp": "A"}
    assert led.director_result(d, ok) is ok
    assert led.director_result(d, dict(ok)) is ok  # identical retry returns the saved result
    _atomic(led, "conflicting_report", led.director_result, d, {**ok, "fp": "B"})
    c = led.director_instruction("capture_version", entity=a, fp="A")
    _atomic(
        led,
        "manifest_mismatch",
        led.director_result,
        c,
        {"outcome": "succeeded", "manifest": "nope"},
    )
    led.director_result(c, {"outcome": "succeeded", "manifest": "m1"})
    # restore results carry no manifest on the wire: the saved instruction supplies it
    v = led.director_instruction("verify_restore", entity=a, fp="A", manifest="m1")
    exact = {
        "outcome": "succeeded",
        "restore_outcome": "exact",
        "store_status": "retrieved",
        "backend_match_result": "not_applicable",
    }
    _atomic(led, "manifest_mismatch", led.director_result, v, {**exact, "store_status": "missing"})
    assert led.director_result(v, exact) is exact
    led.capture("c2", a, "A", "m2", "stored_unverified", False, False, True, False, None)
    v2 = led.director_instruction("verify_restore", entity=a, fp="A", manifest="m2")
    _atomic(led, "manifest_mismatch", led.director_result, v2, exact)  # m2 has no exact evidence
    _atomic(
        led,
        "unknown_ref",
        led.director_instruction,
        "restore_version",
        entity=a,
        fp="A",
        manifest="ghost",
    )
    _atomic(led, "invalid_request", led.director_instruction, "activate")
    b = _ent(led, "B")
    led.capture("c3", b, "B", "mb", "stored_unverified", False, False, True, False, None)
    r = led.director_instruction("restore_version", entity=b, fp="B", manifest="mb")
    _atomic(
        led, "manifest_mismatch", led.director_result, r, {**exact, "backend_match_result": "match"}
    )  # an agent-supplied match is no evidence


# ---- sol round 5: schema negatives --------------------------------------------------------
def test_capture_carries_closed_commitment_and_reproduction_summary() -> None:
    for name, doc, definition, good in (
        ("event", L, "CapturedEventV0", GOLDEN["captured"][2]),
        ("request", Q, "RecordCaptureRequestV0", CAPTURE_REQ),
    ):
        for field in ("representation_commitment", "identity_digests_reproduced"):
            assert check(doc, definition, {k: v for k, v in good.items() if k != field}) != [], name
        assert check(doc, definition, {**good, "representation_commitment": H64}) != [], name
        assert check(doc, definition, {**good, "representation_commitment": "/tmp/x"}) != [], name
        assert check(doc, definition, {**good, "identity_digests_reproduced": "yes"}) != [], name
    text = json.loads(LEGEND_PATH.read_text())["definitions"]["RepresentationCommitment"][
        "description"
    ]
    assert "traigent.legend.representation_commitment.v0" in text and "ordinal" in text


def test_availability_request_is_closed_and_in_the_request_root() -> None:
    assert check(Q, "RecordAvailabilityRequestV0", AVAIL_REQ) == []
    assert check(Q, None, AVAIL_REQ) == []
    for field in AVAIL_REQ:
        assert (
            check(
                Q, "RecordAvailabilityRequestV0", {k: v for k, v in AVAIL_REQ.items() if k != field}
            )
            != []
        )
    assert check(Q, "RecordAvailabilityRequestV0", {**AVAIL_REQ, "status": "gone"}) != []
    assert check(Q, "RecordAvailabilityRequestV0", {**AVAIL_REQ, "recorded_at": TS}) != []
    assert (
        check(
            Q,
            "RecordAvailabilityRequestV0",
            {**AVAIL_REQ, "recovery_manifest_fingerprint": "rmfc0:sha256:" + "c" * 64},
        )
        != []
    )


# ---- sol round 5: model negatives ----------------------------------------------------------
def test_model_empty_observation_never_freezes_a_context() -> None:
    led = Legend()
    _atomic(led, "manifest_mismatch", led.start_execution, "empty", None, {}, "strict")
    assert led.contexts == {} and led.ledger == []


def test_model_remaining_record_writers_are_idempotent() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.propose("r", None, "base_agent", 0, a, "A")
    td = led.start_execution("r", None, dict(led.effective("r", None)), "strict")
    ev1 = led.evaluate("r", None, f"{a}:A", td, "server", key="ev-1")
    n = len(led.ledger)
    assert led.evaluate("r", None, f"{a}:A", td, "server", key="ev-1") is ev1
    assert len(led.ledger) == n  # identical retry appends nothing
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.evaluate,
        "r",
        None,
        f"{a}:A",
        td,
        "server",
        "other-subset",
        "holdout",
        "ev-1",
    )
    s = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    p1 = led.identity_verify(s, "S", ("x",), True, key="iv-1")
    n = len(led.ledger)
    assert led.identity_verify(s, "S", ("x",), True, key="iv-1") == p1
    assert len(led.ledger) == n
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.identity_verify,
        s,
        "S",
        ("y",),
        True,
        True,
        "iv-1",
    )
    led.identity_verify(s, "S", ("x",), True, key="iv-2")  # fresh key = a new record
    assert len(led.ledger) == n + 1
    led.capture(
        "c",
        s,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        p1,
        Legend.commitment(("x",)),
    )
    m1 = led.server_match(s, "S", "m", True, True, True, True, True, "art", key="sm-1")
    n = len(led.ledger)
    assert led.server_match(s, "S", "m", True, True, True, True, True, "art", key="sm-1") is m1
    assert len(led.ledger) == n
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.server_match,
        s,
        "S",
        "m",
        True,
        False,
        True,
        True,
        True,
        "art",
        "sm-1",
    )


def test_model_recovery_strength_upgrades_without_changing_manifest_metadata() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", "m", "stored_unverified", False, True, True, False, None)
    assert led.recovery_state(a, "A") == "stored_unverified"
    led.capture("c2", a, "A", "m", "round_trip_verified", True, True, True, False, None)
    assert led.recovery_state(a, "A") == "round_trip_verified"  # event evidence, not metadata
    # coverage / reproduction / commitment stay immutable for the fingerprint
    _atomic(
        led,
        "store_key_conflict",
        led.capture,
        "c3",
        a,
        "A",
        "m",
        "round_trip_verified",
        True,
        False,
        True,
        False,
        None,
    )
    _atomic(
        led,
        "store_key_conflict",
        led.capture,
        "c4",
        a,
        "A",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        False,
        None,
        "other-commitment",
    )


def test_model_wire_cursor_names_are_checked() -> None:
    led = Legend()
    ent = led.declare("k0", None, "agent", "v1", "client_declared")["entity"]
    for i, fp in enumerate(("v2", "v3"), 1):
        led.declare(f"k{i}", ent, "agent", fp, "client_declared")
    unissued = "cursor_" + "0" * 32
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=ent,
        page_size=2,
        page_cursor=unissued,
    )
    q = led.director_instruction("query_versions", entity=ent, page_size=3, page_cursor=None)
    _atomic(
        led,
        "invalid_request",
        led.director_result,
        q,
        {"outcome": "succeeded", "fps": ["v1", "v2", "v3"], "next_page_cursor": unissued},
    )
    ok = {"outcome": "succeeded", "fps": ["v1", "v2", "v3"], "next_page_cursor": None}
    assert led.director_result(q, ok) is ok
    # the wire fields exist in the closed schemas under exactly these names
    assert check(O, "QueryVersionsInstruction", GOLDEN["ins_query"][2]) == []
    assert "page_cursor" in GOLDEN["ins_query"][2] and "next_page_cursor" in GOLDEN["res_query"][2]


# -- delta over 9b0451d: snapshot selector, Director legend envelopes, cursor provenance -----------
def _member(op: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "0",
        "instruction_ref": ref_of("instruction"),
        "operation": op,
        "kind": None,
        "entity_ref": None,
        "version_ref": None,
        "recovery_manifest_fingerprint": None,
        "page_size": None,
        "page_cursor": None,
        "as_of_ledger_position": None,
    }
    return {**base, **extra}


def _ack(op: str, **extra: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "0",
        "instruction_ref": ref_of("instruction"),
        "operation": op,
        "ack_status": "stored",
        "error_code": None,
        "as_of_ledger_position": None,
    }
    return {**base, **extra}


def test_query_request_as_of_is_optional_nonnegative_integer() -> None:
    base = GOLDEN["req_query"][2]
    assert "as_of_ledger_position" not in base and check(Q, "QueryRequestV0", base) == []
    for good in (0, 7):
        assert check(Q, "QueryRequestV0", {**base, "as_of_ledger_position": good}) == []
    for bad in (-1, 1.5, "7", None, True):
        assert check(Q, "QueryRequestV0", {**base, "as_of_ledger_position": bad}) != [], bad
    assert check(Q, "QueryRequestV0", {**base, "as_of": 3}) != []


def test_director_legend_instruction_member_is_closed_and_carries_the_snapshot() -> None:
    M_ = "LegendInstructionMember"
    cur = "cursor_" + "a" * 32
    goods = [
        _member("declare_version", kind="agent"),
        _member("declare_version", kind="agent", entity_ref=ref_of("entity")),
        _member(
            "query_versions",
            entity_ref=ref_of("entity"),
            page_size=20,
            as_of_ledger_position=0,
        ),
        _member(
            "query_versions",
            entity_ref=ref_of("entity"),
            page_size=100,
            page_cursor=cur,
            as_of_ledger_position=12,
        ),
        _member("capture_version", version_ref=ref_of("version")),
        _member("verify_restore", version_ref=ref_of("version"), recovery_manifest_fingerprint=RMF),
        _member(
            "restore_version", version_ref=ref_of("version"), recovery_manifest_fingerprint=RMF
        ),
    ]
    for g in goods:
        assert check(O, M_, g) == [], g
    q = goods[2]
    bads = [
        {**q, "as_of_ledger_position": None},  # a query always carries its snapshot
        {**q, "as_of_ledger_position": -1},
        {**q, "page_size": 0},
        {**q, "page_cursor": "cursor_short"},
        {**q, "extra": 1},  # closed
        {**q, "operation": "activate_version"},  # closed menu
        {**q, "version_ref": ref_of("version")},  # foreign field for the operation
        {**goods[0], "as_of_ledger_position": 3},  # only a query has a snapshot
        {**goods[4], "page_cursor": cur},
        {**goods[5], "recovery_manifest_fingerprint": None},
        {k: v for k, v in q.items() if k != "as_of_ledger_position"},
    ]
    for b in bads:
        assert check(O, M_, b) != [], b
    props = json.loads((schemas_dir / "legend" / O).read_text(encoding="utf-8"))["definitions"]
    for name in ("LegendInstructionMember", "LegendResultAckMember"):
        assert "legend_snapshot" not in props[name]["properties"]


def test_director_legend_result_ack_member_is_closed() -> None:
    A = "LegendResultAckMember"
    goods = [
        _ack("declare_version"),
        _ack("query_versions", as_of_ledger_position=5),
        _ack("capture_version", ack_status="identical_retry"),
        _ack("verify_restore", ack_status="rejected", error_code="conflicting_report"),
    ]
    for g in goods:
        assert check(O, A, g) == [], g
    bads = [
        _ack("query_versions"),  # snapshot echo required for a query
        _ack("declare_version", as_of_ledger_position=5),
        _ack("capture_version", ack_status="rejected"),  # rejected needs an error code
        _ack("capture_version", error_code="invalid_request"),  # stored has none
        _ack("capture_version", ack_status="maybe"),
        _ack("capture_version", error_code="made_up"),
        {**_ack("capture_version"), "message": "free text"},
        {k: v for k, v in _ack("capture_version").items() if k != "ack_status"},
    ]
    for b in bads:
        assert check(O, A, b) != [], b


def test_failed_or_refused_query_result_carries_no_cursor() -> None:
    cur = "cursor_" + "b" * 32
    for outcome, err in (("failed", "internal_error"), ("refused", "invalid_request")):
        res = result("query_versions", outcome, err, version_refs=[])
        assert check(O, "QueryVersionsResult", {**res, "next_page_cursor": None}) == []
        assert check(O, "QueryVersionsResult", {**res, "next_page_cursor": cur}) != []
    ok_ = result("query_versions", version_refs=[ref_of("version")])
    assert check(O, "QueryVersionsResult", {**ok_, "next_page_cursor": cur}) == []


def _versioned(n: int = 4) -> tuple[Legend, str, list[int]]:
    led = Legend()
    ent = led.declare("k0", None, "agent", "v1", "client_declared")["entity"]
    for i in range(1, n):
        led.declare(f"k{i}", ent, "agent", f"v{i + 1}", "client_declared")
    firsts = [e["position"] for e in led.ledger if e["type"] == "declared"]
    return led, ent, firsts


def test_model_query_as_of_filters_by_first_declared_position() -> None:
    led, ent, firsts = _versioned()
    assert led.query(ent, 10)["fps"] == ["v1", "v2", "v3", "v4"]  # omitted = current
    for cut, want in (
        (firsts[0] - 1, []),
        (firsts[1], ["v1", "v2"]),
        (firsts[3], ["v1", "v2", "v3", "v4"]),
    ):
        assert led.query(ent, 10, None, cut)["fps"] == want
    # a later redeclaration of v1 does not move its first position
    led.declare("again", ent, "agent", "v1", "client_declared")
    assert led.query(ent, 10, None, firsts[0])["fps"] == ["v1"]
    # a snapshot beyond the ledger, or a negative one, is refused atomically
    _atomic(led, "invalid_request", led.query, ent, 10, None, len(led.ledger) + 1)
    _atomic(led, "invalid_request", led.query, ent, 10, None, -1)


def test_model_query_cursor_is_bound_to_as_of() -> None:
    led, ent, firsts = _versioned()
    cut = firsts[3]
    p1 = led.query(ent, 2, None, cut)
    assert p1["fps"] == ["v1", "v2"] and p1["next_page_cursor"] is not None
    cur = p1["next_page_cursor"]
    _atomic(led, "invalid_request", led.query, ent, 2, cur, firsts[2])  # another as_of
    _atomic(led, "invalid_request", led.query, ent, 2, cur, None)  # as_of omitted
    led.declare("late", ent, "agent", "v5", "client_declared")
    p2 = led.query(ent, 2, cur, cut)  # the snapshot is stable across later writes
    assert p2["fps"] == ["v3", "v4"] and p2["next_page_cursor"] is None
    # a cursor issued with no as_of is refused under an explicit one, and conversely
    c0 = led.query(ent, 2)["next_page_cursor"]
    _atomic(led, "invalid_request", led.query, ent, 2, c0, cut)
    assert led.query(ent, 2, c0)["fps"] == ["v3", "v4"]


def test_model_one_cursor_issuer_shared_by_legend_api_and_director() -> None:
    led, ent, _ = _versioned()
    page = led.query(ent, 2, None, len(led.ledger))
    cur = page["next_page_cursor"]
    q = led.director_instruction("query_versions", entity=ent, page_size=2, page_cursor=cur)
    assert led.instructions[q]["as_of"] == len(led.ledger)  # the cursor's snapshot is kept
    ok_ = {"outcome": "succeeded", "fps": ["v3", "v4"], "next_page_cursor": None}
    assert led.director_result(q, ok_) is ok_
    # a cursor the Director composes itself, or one issued without a snapshot, is refused
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=ent,
        page_size=2,
        page_cursor="cursor_" + "9" * 32,
    )
    unsnapped = led.query(ent, 2)["next_page_cursor"]
    _atomic(
        led,
        "invalid_request",
        led.director_instruction,
        "query_versions",
        entity=ent,
        page_size=2,
        page_cursor=unsnapped,
    )
    # and a cursor issued on the Director path is accepted by the Legend API
    q1 = led.director_instruction("query_versions", entity=ent, page_size=2, page_cursor=None)
    snap = led.instructions[q1]["as_of"]
    nxt = led._token(ent, 2, snap)
    first = {"outcome": "succeeded", "fps": ["v1", "v2"], "next_page_cursor": nxt}
    assert led.director_result(q1, first) is first
    assert led.query(ent, 2, nxt, snap)["fps"] == ["v3", "v4"]


def test_model_failed_or_refused_query_result_must_not_carry_a_cursor() -> None:
    led, ent, _ = _versioned()
    q = led.director_instruction("query_versions", entity=ent, page_size=2, page_cursor=None)
    cur = led._token(ent, 2, led.instructions[q]["as_of"])
    for outcome in ("failed", "refused"):
        _atomic(
            led,
            "invalid_request",
            led.director_result,
            q,
            {"outcome": outcome, "fps": [], "next_page_cursor": cur},
        )
        r = {"outcome": outcome, "fps": [], "next_page_cursor": None}
        assert led.director_result(q, r) is r
        led.results.pop(q)


def signed(req: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """A wire body with its request_digest recomputed over the whole body."""
    body = {**req, **changes}
    body["request_digest"] = Legend.request_digest(body)
    return body


def test_model_wire_requests_project_into_transitions() -> None:
    led = _seed()
    a = _ent(led, "A")
    resolve = {ref_of("version"): (a, "A")}
    req = signed(
        CAPTURE_REQ,
        recovery_state="round_trip_verified",
        conformance_passed=True,
        coverage=full("agent"),
        representation_commitment=Legend.commitment(("r0", "r1")),
    )
    first = led.capture_from_request(req, resolve, {})
    assert led.capture_from_request(req, resolve, {}) is first  # key/digest retry
    meta = led.captures[(a, "A", RMF)]
    assert meta["commitment"] == Legend.commitment(("r0", "r1")) and meta["reproduced"] is True
    assert meta["coverage"] == {
        "status": "complete",
        "covered": sorted(REQUIRED["agent"]),
        "missing": [],
    }
    bad = signed(req, representation_commitment="not-a-digest")
    _atomic(led, "invalid_request", led.capture_from_request, bad, resolve, {})
    stale = {**req, "representation_commitment": "sha256:" + "2" * 64}  # digest not recomputed
    _atomic(led, "invalid_request", led.capture_from_request, stale, resolve, {})
    missing = {k: v for k, v in req.items() if k != "identity_digests_reproduced"}
    _atomic(led, "invalid_request", led.capture_from_request, missing, resolve, {})
    # same key, any changed wire field (even one the model reduces away) is a conflict
    for change in (
        {"exporter_version": "0.2.0"},
        {"coverage": {**full("agent"), "covered": list(reversed(REQUIRED["agent"]))}},
        {"coverage": {**full("agent"), "covered": [*REQUIRED["agent"], "dependency_lock"]}},
    ):
        _atomic(
            led,
            "conflicting_idempotency_payload",
            led.capture_from_request,
            signed(req, **change),
            resolve,
            {},
        )
    av = led.availability_from_request(
        AVAIL_REQ | {"request_digest": Legend.request_digest(AVAIL_REQ)}, resolve
    )
    av_req = signed(AVAIL_REQ)
    assert led.availability_from_request(av_req, resolve) is av
    assert led.restorable_now(a, "A", RMF)
    bad_av = signed(AVAIL_REQ, idempotency_key="idk_" + "9" * 32, status="gone")
    _atomic(led, "invalid_request", led.availability_from_request, bad_av, resolve)


def test_model_keyed_capture_through_the_wire_matches_its_proof() -> None:
    led = Legend()
    s_ent = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    resolve = {ref_of("version"): (s_ent, "S")}
    reps = ("rep-a", "rep-b")
    proof = led.identity_verify(s_ent, "S", reps, True, key="iv")
    ev_ref = ref_of("event")
    base = signed(
        CAPTURE_REQ,
        recovery_state="round_trip_verified",
        conformance_passed=True,
        coverage=full("search_space"),
        backend_keyed=True,
        identity_verification_ref=ev_ref,
        representation_commitment=Legend.commitment(reps),
    )
    wrong = signed(
        base,
        idempotency_key="idk_" + "8" * 32,
        representation_commitment=Legend.commitment(("rep-a", "rep-X")),
    )
    _atomic(led, "coverage_insufficient", led.capture_from_request, wrong, resolve, {ev_ref: proof})
    ok_ = led.capture_from_request(base, resolve, {ev_ref: proof})
    assert ok_["position"] > 0 and led.captures[(s_ent, "S", RMF)]["proof"] == proof


def test_model_capture_coverage_is_validated_against_the_kind_and_persisted_in_full() -> None:
    led = _seed()
    a = _ent(led, "A")
    resolve = {ref_of("version"): (a, "A")}
    thin = signed(CAPTURE_REQ, coverage={"status": "complete", "covered": ["code"], "missing": []})
    _atomic(led, "coverage_insufficient", led.capture_from_request, thin, resolve, {})
    overlap = signed(
        CAPTURE_REQ, coverage={"status": "partial", "covered": ["code"], "missing": ["code"]}
    )
    _atomic(led, "invalid_request", led.capture_from_request, overlap, resolve, {})
    led.capture("c1", a, "A", "m", "stored_unverified", False, full("agent"), True, False, None)
    # a fresh-key report with different coverage arrays for the same manifest is a conflict
    other = {**full("agent"), "covered": [*REQUIRED["agent"], "dependency_lock"]}
    _atomic(
        led,
        "store_key_conflict",
        led.capture,
        "c2",
        a,
        "A",
        "m",
        "stored_unverified",
        False,
        other,
        True,
        False,
        None,
    )
    assert led.captures[(a, "A", "m")]["coverage"]["covered"] == sorted(REQUIRED["agent"])


def test_model_restore_wire_request_projection_and_exact_inputs() -> None:
    led = _seed()
    a = _ent(led, "A")
    resolve = {ref_of("version"): (a, "A")}
    led.capture("c1", a, "A", RMF, "round_trip_verified", True, full("agent"), True, False, None)
    exact = signed(RESTORE_REQ, coverage=full("agent"))
    for change in (
        {"historical_key_available": False},
        {"dependencies_verified": False},
        {"verified_artifact_digest": None},
        {"isolated_destination": False},
    ):
        _atomic(
            led,
            "invalid_request",
            led.restore_from_request,
            signed(exact, idempotency_key="idk_" + "5" * 32, **change),
            resolve,
        )
    other_cov = signed(
        exact,
        idempotency_key="idk_" + "6" * 32,
        coverage={**full("agent"), "covered": [*REQUIRED["agent"], "dependency_lock"]},
    )
    _atomic(led, "manifest_mismatch", led.restore_from_request, other_cov, resolve)
    first = led.restore_from_request(exact, resolve)
    assert led.restore_from_request(exact, resolve) is first
    assert led.artifacts[(a, RMF)] == exact["verified_artifact_digest"]
    _atomic(
        led,
        "conflicting_idempotency_payload",
        led.restore_from_request,
        signed(exact, outcome="partial", coverage=full("agent")),
        resolve,
    )
    partial = signed(
        exact,
        idempotency_key="idk_" + "7" * 32,
        outcome="partial",
        verified_artifact_digest=None,
        historical_key_available=False,
    )
    assert led.restore_from_request(partial, resolve)["position"] > 0


def test_model_partial_capture_issues_captured_and_restorable_now_but_not_restore() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", "pm", "stored_unverified", False, False, True, False, None)
    led.record_availability("a1", a, "A", "pm", "available")
    sub = (a, "A", "agent")
    assert led.issue_predicate("captured", sub, led.high_water, "pm")
    assert led.issue_predicate("restorable_now", sub, led.high_water, "pm")
    _atomic(
        led,
        "unknown_ref",
        led.issue_predicate,
        "restore_verified_client_reported",
        sub,
        led.high_water,
        "pm",
    )


def test_model_mismatching_server_match_authorises_no_activation() -> None:
    led = Legend()
    s_ent = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    proof = led.identity_verify(s_ent, "S", ("r",), True)
    led.capture(
        "c",
        s_ent,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        proof,
        Legend.commitment(("r",)),
    )
    led.server_match(s_ent, "S", "m", True, False, True, True, True, "art")
    assert (s_ent, "m") not in led.artifacts
    _atomic(led, "manifest_mismatch", led.activate, s_ent, "m", "art")


def test_model_restore_events_keep_summaries_and_project_into_the_closed_schema() -> None:
    led = _seed()
    a = _ent(led, "A")
    led.capture("c1", a, "A", RMF, "round_trip_verified", True, full("agent"), True, False, None)
    art = "sha256:" + "4" * 64
    led.record_restore("r1", a, "A", "agent", RMF, "exact", True, True, True, True, False, art)
    event = led.ledger[-1]
    assert event["summary"]["artifact"] == art and event["summary"]["key_ok"] is True
    assert check(L, "RestoreVerifiedEventV0", led.restore_event_wire(event, RMF)) == []
    led.record_restore(
        "r2", a, "A", "agent", RMF, "partial", False, True, False, False, False, None
    )
    partial = led.ledger[-1]
    assert partial["summary"]["artifact"] is None and partial["summary"]["deps_ok"] is False
    assert check(L, "RestoreVerifiedEventV0", led.restore_event_wire(partial, RMF)) == []
    s_ent = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    proof = led.identity_verify(s_ent, "S", ("r",), True)
    led.capture(
        "c2",
        s_ent,
        "S",
        RMF,
        "round_trip_verified",
        True,
        True,
        True,
        True,
        proof,
        Legend.commitment(("r",)),
    )
    led.server_match(s_ent, "S", RMF, True, True, True, True, True, art)
    server = led.ledger[-1]
    assert server["origin"] == "server" and server["summary"]["keyed"] is True
    assert check(L, "RestoreVerifiedEventV0", led.restore_event_wire(server, RMF)) == []
    led.server_match(s_ent, "S", RMF, True, False, True, True, True, art)
    mismatch = led.ledger[-1]
    assert mismatch["summary"]["artifact"] is None
    assert check(L, "RestoreVerifiedEventV0", led.restore_event_wire(mismatch, RMF)) == []


def test_model_coverage_partition_covers_every_required_component() -> None:
    led = _seed()
    a = _ent(led, "A")
    lost = {"status": "partial", "covered": ["code"], "missing": ["prompts"]}
    _atomic(
        led,
        "invalid_request",
        led.capture,
        "c1",
        a,
        "A",
        "m",
        "stored_unverified",
        False,
        lost,
        True,
        False,
        None,
    )  # runtime, helpers, ... are in neither list
    ok = {"status": "partial", "covered": REQUIRED["agent"][1:], "missing": [REQUIRED["agent"][0]]}
    led.capture("c2", a, "A", "m", "stored_unverified", False, ok, True, False, None)


def _eval_ledger() -> tuple[Legend, str, str, str]:
    led = _seed()
    a, e0 = _ent(led, "A"), _ent(led, "E0")
    led.propose("r", None, "base_agent", 0, a, "A")
    led.propose("r", None, "evaluator", 0, e0, "E0")
    td = led.start_execution("r", None, dict(led.effective("r", None)), "strict")
    return led, f"{a}:A", f"{e0}:E0", td


def _control(evaluator: str, **changes: Any) -> dict[str, Any]:
    return {
        "control_kind": "known_bad_input",
        "expected_verdict": "fail",
        "observed_verdict": "fail",
        "evaluator_version_ref": evaluator,
        "run_ref": "r",
        **changes,
    }


def test_model_outcome_states_and_void_cause_are_closed() -> None:
    led, a, _e, td = _eval_ledger()
    for outcome in ("pass", "fail", "not_exercised", "inconclusive"):
        assert led.evaluate("r", None, a, td, "server", outcome=outcome)["position"] > 0
    assert led.evaluate("r", None, a, td, "server", outcome="void", void_cause="input_unavailable")
    for bad in (
        {"outcome": "void"},  # void needs a closed cause
        {"outcome": "void", "void_cause": "because"},
        {"outcome": "pass", "void_cause": "input_unavailable"},
        {"outcome": "passed"},
    ):
        _atomic(led, "invalid_request", led.evaluate, "r", None, a, td, "server", **bad)


def test_model_legacy_event_without_outcome_maps_to_inconclusive_with_no_discrimination() -> None:
    led, a, _e, td = _eval_ledger()
    led.evaluate("r", None, a, td, "server")
    last = led.ledger[-1]
    assert (last["outcome"], last["discrimination"], last["disc_ref"]) == (
        "inconclusive",
        "none",
        None,
    )


def test_model_discrimination_needs_an_earlier_real_fail() -> None:
    led, a, e0, td = _eval_ledger()
    ev = led.evaluate
    # none carries no reference; any other kind must carry one
    _atomic(led, "invalid_request", ev, "r", None, a, td, "server", discrimination="prior_run")
    _atomic(led, "invalid_request", ev, "r", None, a, td, "server", disc_ref=1)
    passed = ev("r", None, a, td, "server", outcome="pass", subset="s1")["position"]
    _atomic(
        led, "unknown_ref", ev, "r", None, a, td, "server",
        discrimination="prior_run", disc_ref=passed,  # a pass shows nothing
    )  # fmt: skip
    _atomic(
        led, "unknown_ref", ev, "r", None, a, td, "server",
        discrimination="prior_run", disc_ref=9999,
    )  # fmt: skip
    failed = ev("r", None, a, td, "server", outcome="fail", subset="s2")["position"]
    for kind in ("prior_run", "shown_by_run"):
        assert ev("r", None, a, td, "server", discrimination=kind, disc_ref=failed, subset=kind)
    # a plain fail is not a control, and a control record is not a plain fail
    _atomic(led, "unknown_ref", ev, "r", None, a, td, "server",
            discrimination="control", disc_ref=failed)  # fmt: skip
    ctl = ev("r", None, a, td, "server", outcome="fail", subset="c", control=_control(e0))
    assert ev("r", None, a, td, "server", discrimination="control", disc_ref=ctl["position"],
              subset="c2")  # fmt: skip
    _atomic(led, "unknown_ref", ev, "r", None, a, td, "server",
            discrimination="prior_run", disc_ref=ctl["position"])  # fmt: skip


def test_model_prior_run_must_come_from_the_same_evaluator_version() -> None:
    led, a, e0, td = _eval_ledger()
    ev = led.evaluate
    # run r2 scores the same agent version under a different evaluator version (E1)
    e1 = f"{_ent(led, 'E1')}:E1"
    led.propose("r2", None, "base_agent", 0, a.split(":")[0], "A")
    led.propose("r2", None, "evaluator", 0, e1.split(":")[0], "E1")
    td2 = led.start_execution("r2", None, dict(led.effective("r2", None)), "strict")
    fail_e1 = ev("r2", None, a, td2, "server", outcome="fail", subset="f1")["position"]
    # same subject, but the failure was recorded under E1: it says nothing about E0
    _atomic(led, "unknown_ref", ev, "r", None, a, td, "server",
            discrimination="prior_run", disc_ref=fail_e1, subset="x")  # fmt: skip
    # the same failure under E1 does discriminate a later E1 evaluation
    assert ev("r2", None, a, td2, "server", discrimination="prior_run", disc_ref=fail_e1,
              subset="y")  # fmt: skip
    # and an E0 failure in another run still discriminates E0 (same evaluator version)
    led.propose("r3", None, "base_agent", 0, a.split(":")[0], "A")
    led.propose("r3", None, "evaluator", 0, e0.split(":")[0], "E0")
    td3 = led.start_execution("r3", None, dict(led.effective("r3", None)), "strict")
    fail_e0 = ev("r3", None, a, td3, "server", outcome="fail", subset="f0")["position"]
    assert ev("r", None, a, td, "server", discrimination="prior_run", disc_ref=fail_e0,
              subset="z")  # fmt: skip


def test_model_shown_by_run_must_come_from_the_same_evaluator_version() -> None:
    led, a, e0, td = _eval_ledger()
    ev = led.evaluate
    e1 = f"{_ent(led, 'E1')}:E1"
    # trial T0 binds E0 and fails; trial T1 of the same run overrides the evaluator to E1
    fail_t0 = ev("r", None, a, td, "server", outcome="fail", subset="f")["position"]
    led.propose("r", "t1", "evaluator", 0, e1.split(":")[0], "E1")
    obs = dict(led.effective("r", "t1"))
    td1 = led.start_execution("r", "t1", obs, "strict")
    _atomic(led, "unknown_ref", ev, "r", "t1", a, td1, "server",
            outcome="pass", discrimination="shown_by_run", disc_ref=fail_t0)  # fmt: skip
    assert fail_t0


def test_model_control_must_name_the_evaluator_its_own_run_executed() -> None:
    led, a, e0, td = _eval_ledger()
    e1 = f"{_ent(led, 'E1')}:E1"
    # a failing control executed under E0 cannot be labelled E1
    _atomic(led, "invalid_request", led.evaluate, "r", None, a, td, "server",
            outcome="fail", control=_control(e1))  # fmt: skip
    assert led.evaluate("r", None, a, td, "server", outcome="fail", control=_control(e0))
    # and an E1 evaluation cannot cite that E0 control
    led.propose("r2", None, "base_agent", 0, a.split(":")[0], "A")
    led.propose("r2", None, "evaluator", 0, e1.split(":")[0], "E1")
    td2 = led.start_execution("r2", None, dict(led.effective("r2", None)), "strict")
    ctl = next(
        i for i, ev in enumerate(led.ledger, 1) if ev["type"] == "evaluated" and ev["control"]
    )
    _atomic(led, "unknown_ref", led.evaluate, "r2", None, a, td2, "server",
            discrimination="control", disc_ref=ctl)  # fmt: skip


def test_model_control_run_is_closed_and_must_really_fail_under_this_evaluator() -> None:
    led, a, e0, td = _eval_ledger()
    ev = led.evaluate
    bad_controls = (
        _control(e0, input_text="free text"),
        _control(e0, control_kind="my kind"),
        _control(e0, run_ref="other"),
        _control(e0, expected_verdict="void"),
        _control(e0, observed_verdict="pass"),  # must equal the event's outcome (fail below)
        _control(a),  # an agent version is not an evaluator version
    )
    for c in bad_controls:
        _atomic(led, "invalid_request", ev, "r", None, a, td, "server", outcome="fail", control=c)
    # a control record is undiscriminated
    first = ev("r", None, a, td, "server", outcome="fail", subset="f")["position"]
    _atomic(led, "invalid_request", ev, "r", None, a, td, "server", outcome="fail",
            discrimination="prior_run", disc_ref=first, control=_control(e0))  # fmt: skip
    # a control whose evaluator returned PASS on a known-bad input shows nothing
    weak = ev("r", None, a, td, "server", outcome="pass",
              control=_control(e0, observed_verdict="pass"), subset="w")["position"]  # fmt: skip
    _atomic(led, "unknown_ref", ev, "r", None, a, td, "server",
            discrimination="control", disc_ref=weak)  # fmt: skip
    # a control labelled with a DIFFERENT evaluator version than the run executed is refused
    other = _ent(led, "E1")
    _atomic(led, "invalid_request", ev, "r", None, a, td, "server", outcome="fail",
            control=_control(f"{other}:E1"), subset="x")  # fmt: skip


def test_model_witnessed_discrimination_never_rests_on_client_reported_fails() -> None:
    led, a, _e, td = _eval_ledger()
    client_fail = led.evaluate("r", None, a, td, "client", outcome="fail")["position"]
    _atomic(led, "unknown_ref", led.evaluate, "r", None, a, td, "server",
            discrimination="prior_run", disc_ref=client_fail)  # fmt: skip
    assert led.evaluate("r", None, a, td, "client", discrimination="prior_run",
                        disc_ref=client_fail, subset="c")  # fmt: skip


def test_model_claims_are_issued_only_for_verdicts_and_must_state_the_events_discrimination() -> (
    None
):
    led, a, _e, td = _eval_ledger()
    fail = led.evaluate("r", None, a, td, "server", outcome="fail", subset="m1")["position"]
    led.evaluate("r", None, a, td, "server", outcome="pass", subset="m2",
                 discrimination="prior_run", disc_ref=fail)  # fmt: skip
    led.evaluate("r", None, a, td, "server", outcome="void", void_cause="input_unavailable",
                 subset="m3")  # fmt: skip
    led.evaluate("r", None, a, td, "server", outcome="inconclusive", subset="m4")
    hw = led.high_water
    ent, fp = a.split(":")
    sub = (ent, fp, "agent")
    base = {"tuple_digest": td, "protocol": "full_dataset"}
    kw = {"discrimination": "prior_run", "disc_ref": fail, "outcome": "pass", "subset": "m2"}
    assert led.issue_predicate("evaluated_traigent_witnessed", sub, hw, **base, **kw)
    # the claim must repeat what the event says, field by field
    for change in ({"outcome": "fail"}, {"discrimination": "none", "disc_ref": None},
                   {"disc_ref": fail + 1}):  # fmt: skip
        _atomic(led, "unknown_ref", led.issue_predicate, "evaluated_traigent_witnessed", sub, hw,
                **base, **{**kw, **change})  # fmt: skip
    # only pass and fail are signed
    for outcome, m in (("void", "m3"), ("inconclusive", "m4"), ("not_exercised", "m4")):
        _atomic(led, "coverage_insufficient", led.issue_predicate, "evaluated_traigent_witnessed",
                sub, hw, **base, outcome=outcome, discrimination="none", disc_ref=None,
                subset=m)  # fmt: skip
    # both fields are always stated
    _atomic(led, "invalid_request", led.issue_predicate, "evaluated_traigent_witnessed", sub, hw,
            **base, subset="m2")  # fmt: skip


def test_model_compiler_refuses_the_strong_witnessed_text_without_discrimination() -> None:
    text = Legend.statement_text
    assert text("evaluated_traigent_witnessed", "control") == STATEMENT_STRONG
    assert text("evaluated_traigent_witnessed", "none") == STATEMENT_WEAK
    _atomic_static("coverage_insufficient", text, "evaluated_traigent_witnessed", "none",
                   STATEMENT_STRONG)  # fmt: skip
    _atomic_static("invalid_request", text, "evaluated_traigent_witnessed", "prior_run",
                   STATEMENT_WEAK)  # fmt: skip
    # the client-reported text never claims Traigent evaluated it, discriminated or not
    for d in DISCRIMINATIONS:
        assert "did not witness" in text("evaluated_client_reported", d)
    _atomic_static("invalid_request", text, "declared", "none")
    _atomic_static("invalid_request", text, "evaluated_traigent_witnessed", "sometimes")


def _atomic_static(code: str, fn: Any, *args: Any) -> None:
    with pytest.raises(Refused) as exc:
        fn(*args)
    assert str(exc.value) == code
