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
    "backend_keyed": False,
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
import copy as _copy  # noqa: E402


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


def _digest(*parts: Any) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


class Legend:
    """Transition-table model of section 9 (single ledger, single committer).

    Deliberate abstractions: hashes are sha256 of a canonical JSON string; the ledger lock is the
    single-threaded commit (positions are allocated at commit, so the sealed high-water mark is the
    committed length); crypto, tenants and the wire schemas are out of scope. All state lives in
    ``self.__dict__`` and refusals are checked against a deep copy of all of it.
    """

    def __init__(self) -> None:
        self.entities: dict[str, dict[str, Any]] = {}
        self.versions: dict[tuple[str, str], dict[str, Any]] = {}
        self.links: dict[tuple[str, str], tuple[str, str]] = {}
        self.authority_rows: dict[tuple[str, str, str], bool] = {}
        self.ledger: list[dict[str, Any]] = []
        self.requests: dict[str, tuple[str, Any]] = {}
        self.proposals: dict[tuple[Any, ...], str] = {}
        self.started: dict[tuple[str, str | None], str] = {}
        self.staged: dict[tuple[str, str], str] = {}
        self.instructions: dict[str, dict[str, Any]] = {}
        self.results: dict[str, tuple[str, Any]] = {}
        self.next_entity = 1

    # -- infrastructure -------------------------------------------------------------------
    def state(self) -> dict[str, Any]:
        return _copy.deepcopy(self.__dict__)

    def _append(self, **event: Any) -> int:
        self.ledger.append({**event, "position": len(self.ledger) + 1})
        return len(self.ledger)

    @property
    def high_water(self) -> int:
        return len(self.ledger)

    def _digest_of(self, body: dict[str, Any]) -> str:
        return _digest({k: v for k, v in body.items() if k not in ("key", "digest")})

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
        digest = self._digest_of(body)
        if key in self.requests:
            if self.requests[key][0] != digest:
                raise Refused("conflicting_idempotency_payload")
            return self.requests[key][1]
        if kind == "search_space" and source != "client_declared":
            raise Refused("invalid_request")
        if entity is not None and (
            entity not in self.entities or self.entities[entity]["kind"] != kind
        ):
            raise Refused("foreign_ref")
        target = entity
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
        # ---- commit (entity creation, version, event, cached response: one atomic step) ----
        if target is None:
            target = f"ent{self.next_entity}"
            self.next_entity += 1
            self.entities[target] = {"kind": kind, "group": group}
        if first:
            self.versions[(target, fp)] = dict(kind=kind, ip=initial_parent, source=source, fmt=fmt)
        pos = self._append(type="declared", entity=target, fp=fp, previous=previous)
        response = {"entity": target, "created": first, "position": pos}
        self.requests[key] = (digest, response)
        return response

    def link_authority(self, entity: str, fp: str, authority: str, group: str) -> None:
        v = self._version(entity, fp)
        if (authority, group, fp) not in self.authority_rows:
            raise Refused("unknown_ref")
        if self.entities[entity]["group"] != group:
            raise Refused("foreign_ref")  # another entity's authority group (shared build digest)
        if (entity, fp) in self.links:
            if self.links[(entity, fp)] == (authority, group):
                return  # unique immutable association; identical replay is a no-op
            raise Refused("conflicting_report")
        self.links[(entity, fp)] = (authority, group)
        self._append(type="authority_linked", entity=entity, fp=fp, authority=authority)
        assert v["kind"]

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
        if (run, None) in self.started and scope == "run":
            raise Refused("conflicting_report")
        if trial is not None and (run, trial) in self.started:
            raise Refused("conflicting_report")
        if slot_key in self.proposals and self._consumed(slot_key):
            raise Refused("conflicting_report")
        self.proposals[slot_key] = version

    def _consumed(self, slot_key: tuple[Any, ...]) -> bool:
        run, scope, trial, _, _ = slot_key
        return (run, None) in self.started if scope == "run" else (run, trial) in self.started

    def effective(
        self, run: str, trial: str | None, override: dict[tuple[str, str, int], str] | None = None
    ) -> dict[tuple[str, str, int], str]:
        merged: dict[tuple[str, str, int], str] = {}
        for (r, scope, t, role, slot), version in self.proposals.items():
            if r == run and (scope == "run" or t == trial):
                merged[(role, scope, slot)] = version
        for k, v in (override or {}).items():
            merged[k] = v
        replaced = {REPLACES[role] for (role, _, _) in merged if role in REPLACES}
        return {k: v for k, v in merged.items() if k[0] not in replaced or k[1] == "trial"}

    @staticmethod
    def tuple_digest(effective: dict[tuple[str, str, int], str]) -> str:
        entries = sorted((ROLE_ORDER.index(r), sc, sl, v) for (r, sc, sl), v in effective.items())
        return _digest("traigent.legend.run_tuple.v0", entries)

    def start_execution(
        self, run: str, trial: str | None, observed: dict[tuple[str, str, int], str], mode: str
    ) -> str:
        context = (run, trial)
        if trial is not None and (run, None) not in self.started:
            raise Refused("invalid_request")  # the run-base context freezes first
        expected = self.effective(run, trial)
        if context in self.started:
            if self.tuple_digest(self.effective(run, trial, observed)) == self.started[context]:
                return self.started[context]  # identical replay
            raise Refused("conflicting_report")  # already bound: use a fresh context
        if set(observed) != set(expected):
            raise Refused("manifest_mismatch")  # complete observation: key-set equality
        drift = {k: v for k, v in observed.items() if expected[k] != v}
        if drift and mode == "strict":
            raise Refused("manifest_mismatch")  # refuse before execution, nothing changes
        for k, v in drift.items():  # permitted drift: declared, in the matrix, then bound
            entity, fp = v.split(":")
            if self._version(entity, fp)["kind"] != ROLE_KIND[k[0]]:
                raise Refused("invalid_request")
        final = self.effective(run, trial, observed)
        digest = self.tuple_digest(final)
        for (role, scope, slot), v in drift.items():
            self.proposals[(run, scope, trial if scope == "trial" else None, role, slot)] = v
        self.started[context] = digest
        for (role, scope, slot), v in sorted(final.items()):
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
        self, run: str, trial: str | None, subject: str, tuple_digest: str, origin: str
    ) -> int:
        if (run, trial) not in self.started:
            raise Refused("manifest_mismatch")  # must reference a started context
        if tuple_digest != self.started[(run, trial)]:
            raise Refused("manifest_mismatch")
        if subject not in self.effective(run, trial).values():
            raise Refused("foreign_ref")
        source = "traigent_witnessed" if origin == "server" else "client_reported"
        return self._append(
            type="evaluated",
            run=run,
            trial=trial,
            subject=subject,
            tuple=tuple_digest,
            source=source,
        )

    # -- recovery -------------------------------------------------------------------------
    def identity_verify(self, entity: str, fp: str, commitment: str, matched: bool) -> int:
        self._version(entity, fp)
        return self._append(
            type="identity_verified",
            entity=entity,
            fp=fp,
            commitment=commitment,
            result="match" if matched else "mismatch",
        )

    def capture(
        self,
        entity: str,
        fp: str,
        manifest: str,
        state: str,
        conformance: bool,
        complete: bool,
        reproduced: bool,
        claimed_keyed: bool,
        verification: int | None,
    ) -> None:
        self._version(entity, fp)
        if manifest.startswith("rmfc0"):
            raise Refused("invalid_request")
        if claimed_keyed != self.backend_keyed(entity, fp):
            raise Refused("invalid_request")
        if state == "round_trip_verified" and not conformance:
            raise Refused("conformance_failed")
        if complete and not reproduced:
            raise Refused("coverage_insufficient")
        if complete and claimed_keyed:
            ok_event = (
                verification is not None
                and 0 < verification <= len(self.ledger)
                and any(
                    e["position"] == verification
                    and e["type"] == "identity_verified"
                    and (e["entity"], e["fp"]) == (entity, fp)
                    and e["result"] == "match"
                    for e in self.ledger
                )
            )
            if not ok_event:
                raise Refused("coverage_insufficient")
        self._append(type="captured", entity=entity, fp=fp, manifest=manifest, state=state)

    def record_availability(self, entity: str, fp: str, manifest: str, status: str) -> None:
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")
        self._append(
            type="availability_changed", entity=entity, fp=fp, manifest=manifest, status=status
        )

    def exact_prerequisites(
        self, complete: bool, equal: bool, isolated: bool, key_ok: bool, deps_ok: bool
    ) -> None:
        """ExactPrerequisites: the one predicate both restore paths apply."""
        if not (complete and equal and isolated and key_ok and deps_ok):
            raise Refused("coverage_insufficient")

    def record_restore(
        self,
        entity: str,
        fp: str,
        kind: str,
        manifest: str,
        outcome: str,
        complete: bool,
        equal: bool,
        isolated: bool,
        key_ok: bool,
        deps_ok: bool,
        claimed_keyed: bool,
    ) -> None:
        v = self._version(entity, fp)
        if kind != v["kind"] or claimed_keyed != self.backend_keyed(entity, fp):
            raise Refused("invalid_request")
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")  # Captured(version, manifest) join
        if outcome == "exact":
            if self.backend_keyed(entity, fp):
                raise Refused("coverage_insufficient")  # needs the server recompute
            self.exact_prerequisites(complete, equal, isolated, key_ok, deps_ok)
        self._append(
            type="restore_verified",
            entity=entity,
            fp=fp,
            manifest=manifest,
            outcome=outcome,
            origin="client",
            match="not_checked",
        )
        if outcome == "exact":
            self.staged[(entity, manifest)] = "verified"

    def server_match(
        self,
        entity: str,
        fp: str,
        manifest: str,
        backend_has_key: bool,
        matched: bool,
        complete: bool,
        equal: bool,
        isolated: bool,
        deps_ok: bool,
    ) -> None:
        self._version(entity, fp)
        if not self._captured(entity, fp, manifest):
            raise Refused("unknown_ref")
        if not backend_has_key:
            raise Refused("store_unavailable")  # unknown format / no key: never exact
        if matched:
            self.exact_prerequisites(complete, equal, isolated, True, deps_ok)
        outcome = "exact" if matched else "substituted"
        self._append(
            type="restore_verified",
            entity=entity,
            fp=fp,
            manifest=manifest,
            outcome=outcome,
            origin="server",
            match="match" if matched else "mismatch",
        )
        if matched:
            self.staged[(entity, manifest)] = "verified"

    def activate(self, entity: str, manifest: str, staged_digest: str) -> None:
        if self.staged.get((entity, manifest)) != "verified" or staged_digest != "verified":
            raise Refused("manifest_mismatch")

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
    ) -> bool:
        entity, fp, kind = subject
        v = self._version(entity, fp)
        if v["kind"] != kind:
            raise Refused("invalid_request")  # subject must equal the authoritative projection
        if not 0 < cutoff <= self.high_water:
            raise Refused("invalid_request")  # cutoff must be inside the sealed committed prefix
        events = self.ledger[:cutoff]
        if ptype == "restorable_now":
            if manifest is None or not self.restorable_now(entity, fp, manifest, cutoff):
                raise Refused("coverage_insufficient")
            return True
        if ptype in ("restore_verified_client_reported", "restore_verified_backend_matched"):
            origin = "client" if ptype.endswith("client_reported") else "server"
            if not any(
                e["type"] == "restore_verified"
                and e["outcome"] == "exact"
                and e["origin"] == origin
                and (e["entity"], e["fp"], e["manifest"]) == (entity, fp, manifest)
                for e in events
            ):
                raise Refused("unknown_ref")
            return True
        if ptype == "evaluated_traigent_witnessed":
            if not any(
                e["type"] == "evaluated"
                and e["subject"] == f"{entity}:{fp}"
                and e["tuple"] == tuple_digest
                and e["trial"] == trial
                and e["source"] == "traigent_witnessed"
                for e in events
            ):
                raise Refused("unknown_ref")
            return True
        raise Refused("invalid_request")

    # -- Director ---------------------------------------------------------------------------
    def director_instruction(self, op: str, **refs: Any) -> str:
        if op not in (
            "declare_version",
            "query_versions",
            "capture_version",
            "verify_restore",
            "restore_version",
        ):
            raise Refused("invalid_request")
        if op in ("capture_version", "verify_restore", "restore_version"):
            self._version(refs["entity"], refs["fp"])
        if op in ("verify_restore", "restore_version") and not self._captured(
            refs["entity"], refs["fp"], refs["manifest"]
        ):
            raise Refused("unknown_ref")
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
            known = {fp for (e, fp) in self.versions if e == ins["entity"]}
            if not set(result.get("fps", ())) <= known:
                raise Refused("foreign_ref")
        if ok_ and op == "capture_version":
            if not self._captured(ins["entity"], ins["fp"], result.get("manifest", "")):
                raise Refused("manifest_mismatch")  # needs the capture evidence on the ledger
        if ok_ and op in ("verify_restore", "restore_version"):
            if result.get("manifest") != ins["manifest"]:
                raise Refused("manifest_mismatch")
            if result.get("restore_outcome") == "exact":
                have = any(
                    e["type"] == "restore_verified"
                    and e["outcome"] == "exact"
                    and (e["entity"], e["fp"], e["manifest"])
                    == (ins["entity"], ins["fp"], ins["manifest"])
                    for e in self.ledger
                )
                if (
                    not have
                    or result.get("store_status") != "retrieved"
                    or result.get("backend_match_result") == "mismatch"
                ):
                    raise Refused("manifest_mismatch")  # an agent-supplied match is not evidence
        self.results[ident] = (digest, result)
        return result


def _atomic(led: Legend, code: str, fn: Any, *args: Any, **kwargs: Any) -> None:
    before = led.state()
    with pytest.raises(Refused, match=code):
        fn(*args, **kwargs)
    assert led.state() == before, "refusal changed state"


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


def test_model_authority_link_uses_full_group_key_and_is_unique_and_immutable() -> None:
    led = Legend()
    a = led.declare("a", None, "agent", "SAME", "client_declared", group="agent-1")["entity"]
    b = led.declare("b", None, "agent", "SAME", "client_declared", group="agent-2")["entity"]
    led.authority_rows[("agent_builds", "agent-1", "SAME")] = True
    led.authority_rows[("agent_builds", "agent-2", "SAME")] = True
    _atomic(led, "foreign_ref", led.link_authority, a, "SAME", "agent_builds", "agent-2")
    _atomic(led, "unknown_ref", led.link_authority, a, "SAME", "agent_builds", "agent-9")
    led.link_authority(a, "SAME", "agent_builds", "agent-1")
    n = len(led.ledger)
    led.link_authority(a, "SAME", "agent_builds", "agent-1")  # identical replay: no-op
    assert len(led.ledger) == n
    led.authority_rows[("agent_builds", "agent-1b", "SAME")] = True
    led.entities[a]["group"] = "agent-1b"
    _atomic(led, "conflicting_report", led.link_authority, a, "SAME", "agent_builds", "agent-1b")
    led.link_authority(b, "SAME", "agent_builds", "agent-2")


def test_model_role_kind_matrix_configuration_roles_and_replacement_within_pillar() -> None:
    led = _seed()
    ent = lambda fp: next(e for (e, f) in led.versions if f == fp)  # noqa: E731
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
    # run- and trial-level evaluator slots with the same slot number coexist
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    led.propose("r", "t1", "evaluator", 0, ent("E1"), "E1")
    keys = [k for k in led.effective("r", "t1") if k[0] == "evaluator"]
    assert keys == [("evaluator", "run", 0), ("evaluator", "trial", 0)] or len(keys) == 2


def test_model_contexts_freeze_separately_and_emit_binding_evidence_with_final_digest() -> None:
    led = _seed()
    ent = lambda fp: next(e for (e, f) in led.versions if f == fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "dataset", 0, ent("D"), "D")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    assert led.ledger[-1]["type"] == "declared"  # proposals emit no evidence
    observed = dict(led.effective("r", None))
    td = led.start_execution("r", None, observed, "strict")
    bound = [e for e in led.ledger if e["type"] == "bound_to_run"]
    assert len(bound) == 3 and {e["tuple"] for e in bound} == {td}
    n = len(led.ledger)
    assert led.start_execution("r", None, observed, "strict") == td  # identical replay: no-op
    assert len(led.ledger) == n
    led.propose("r", None, "dataset", 0, ent("D"), "D")  # identical replay after freezing: no-op
    _atomic(led, "conflicting_report", led.propose, "r", None, "evaluator", 1, ent("E1"), "E1")
    # a trial generated after the run started can still bind its own candidate and start
    led.propose("r", "t1", "trial_candidate", 0, ent("B"), "B")
    t_obs = dict(led.effective("r", "t1"))
    t1 = led.start_execution("r", "t1", t_obs, "strict")
    assert t1 != td and any(e.get("trial") == "t1" and e.get("tuple") == t1 for e in led.ledger)
    _atomic(led, "conflicting_report", led.propose, "r", "t1", "trial_candidate", 0, ent("A"), "A")
    # a trial cannot start before the run-base context
    led.propose("q", "t9", "trial_candidate", 0, ent("B"), "B")
    _atomic(led, "invalid_request", led.start_execution, "q", "t9", {}, "strict")


def test_model_start_execution_requires_complete_observation_and_resolves_drift_first() -> None:
    led = _seed()
    ent = lambda fp: next(e for (e, f) in led.versions if f == fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    led.propose("r", None, "evaluator", 1, ent("E1"), "E1")
    exp = led.effective("r", None)
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, {}, "strict")  # empty
    only_e1 = {k: v for k, v in exp.items() if k == ("evaluator", "run", 1)}
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, only_e1, "strict")
    drifted = {**exp, ("base_agent", "run", 0): f"{ent('B')}:B"}
    _atomic(led, "manifest_mismatch", led.start_execution, "r", None, drifted, "strict")
    assert ("r", None) not in led.started and led.proposals[("r", "run", None, "base_agent", 0)]
    bad = {**exp, ("base_agent", "run", 0): "ghost:X"}
    _atomic(led, "unknown_ref", led.start_execution, "r", None, bad, "permitted")
    wrong_kind = {**exp, ("base_agent", "run", 0): f"{ent('C')}:C"}
    _atomic(led, "invalid_request", led.start_execution, "r", None, wrong_kind, "permitted")
    td = led.start_execution("r", None, drifted, "permitted")  # declared B replaces A, then binds
    assert led.proposals[("r", "run", None, "base_agent", 0)].endswith("B") and td
    _atomic(
        led, "conflicting_report", led.start_execution, "r", None, exp, "permitted"
    )  # fresh ctx


def test_model_evaluation_needs_started_context_and_membership() -> None:
    led = _seed()
    ent = lambda fp: next(e for (e, f) in led.versions if f == fp)  # noqa: E731
    led.propose("r", None, "base_agent", 0, ent("A"), "A")
    led.propose("r", None, "evaluator", 0, ent("E0"), "E0")
    td = led.start_execution("r", None, dict(led.effective("r", None)), "strict")
    led.propose("r", "t1", "trial_candidate", 0, ent("B"), "B")
    t_digest = _digest("unstarted")
    _atomic(led, "manifest_mismatch", led.evaluate, "r", "t1", f"{ent('B')}:B", t_digest, "server")
    a = f"{ent('A')}:A"
    assert led.evaluate("r", None, a, td, "server") > 0
    _atomic(led, "foreign_ref", led.evaluate, "r", None, f"{ent('B')}:B", td, "server")
    _atomic(led, "manifest_mismatch", led.evaluate, "r", None, a, "wrong", "server")
    assert led.ledger[-1]["source"] == "traigent_witnessed" and led.ledger[-1]["trial"] is None
    subject = (ent("A"), "A", "agent")
    assert led.issue_predicate(
        "evaluated_traigent_witnessed", subject, led.high_water, tuple_digest=td
    )
    _atomic(
        led,
        "unknown_ref",
        led.issue_predicate,
        "evaluated_traigent_witnessed",
        subject,
        led.high_water,
        None,
        td,
        "t1",
    )


def test_model_sealed_cutoff_subject_projection_and_captured_joins() -> None:
    led = _seed()
    a, b = (next(e for (e, f) in led.versions if f == fp) for fp in ("A", "B"))
    led.capture(a, "A", "m1", "round_trip_verified", True, False, True, False, None)
    led.record_availability(a, "A", "m1", "available")
    cutoff = led.high_water
    _atomic(
        led,
        "invalid_request",
        led.issue_predicate,
        "restorable_now",
        (a, "A", "agent"),
        cutoff + 1,
        "m1",
    )  # no future cutoff
    assert led.issue_predicate("restorable_now", (a, "A", "agent"), cutoff, "m1")
    led.record_availability(a, "A", "m1", "missing")  # later event never changes the issued prefix
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
    )  # substituted kind
    _atomic(
        led,
        "coverage_insufficient",
        led.issue_predicate,
        "restorable_now",
        (b, "B", "agent"),
        cutoff,
        "m1",
    )  # A's manifest is not B's capture
    _atomic(led, "unknown_ref", led.record_availability, b, "B", "m1", "available")
    _atomic(
        led,
        "unknown_ref",
        led.record_restore,
        b,
        "B",
        "agent",
        "m1",
        "exact",
        True,
        True,
        True,
        True,
        True,
        False,
    )
    led.capture(a, "A", "m2", "stored_unverified", False, False, True, False, None)
    assert led.recovery_state(a, "A") == "round_trip_verified"  # strongest historical proof
    assert led.recovery_state(b, "B") == "none"
    _atomic(
        led,
        "conformance_failed",
        led.capture,
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
        a,
        "A",
        "m5",
        "stored_unverified",
        True,
        False,
        True,
        True,
        None,
    )  # claimed backend_keyed must equal the derived value


def test_model_backend_keyed_capture_restore_and_activation_flow() -> None:
    led = Legend()
    ss = led.declare("s", None, "search_space", "S", "client_declared")["entity"]
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        ss,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        None,
    )  # complete keyed capture needs the pre-capture proof
    mismatch = led.identity_verify(ss, "S", "rep", False)
    _atomic(
        led,
        "coverage_insufficient",
        led.capture,
        ss,
        "S",
        "m",
        "round_trip_verified",
        True,
        True,
        True,
        True,
        mismatch,
    )
    proof = led.identity_verify(ss, "S", "rep", True)
    led.capture(ss, "S", "m", "round_trip_verified", True, True, True, True, proof)
    # client restore of a keyed pillar can never be exact, and caller flags are not trusted
    _atomic(
        led,
        "coverage_insufficient",
        led.record_restore,
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
        True,
    )
    _atomic(
        led,
        "invalid_request",
        led.record_restore,
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
        False,
    )
    _atomic(
        led,
        "invalid_request",
        led.record_restore,
        ss,
        "S",
        "agent",
        "m",
        "partial",
        False,
        False,
        True,
        True,
        True,
        True,
    )
    led.record_restore(
        ss, "S", "search_space", "m", "substituted", True, True, True, True, True, True
    )
    _atomic(led, "manifest_mismatch", led.activate, ss, "m", "verified")  # nothing exact yet
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
        True,
    )
    _atomic(
        led,
        "coverage_insufficient",
        led.server_match,
        ss,
        "S",
        "m",
        True,
        True,
        False,
        True,
        True,
        True,
    )  # ExactPrerequisites also gate the server path
    _atomic(
        led, "unknown_ref", led.server_match, ss, "S", "ghost", True, True, True, True, True, True
    )
    led.server_match(ss, "S", "m", True, False, True, True, True, True)  # mismatch: substituted
    assert led.ledger[-1]["outcome"] == "substituted"
    _atomic(led, "manifest_mismatch", led.activate, ss, "m", "verified")
    led.server_match(ss, "S", "m", True, True, True, True, True, True)
    _atomic(led, "manifest_mismatch", led.activate, ss, "m", "other-bytes")
    led.activate(ss, "m", "verified")
    ev = led.declare("e", None, "evaluator", "EV", "client_declared", fmt="unknown")["entity"]
    assert led.backend_keyed(ev, "EV")  # unknown format counts as keyed


def test_model_director_per_operation_relations_and_result_retries() -> None:
    led = _seed()
    a = next(e for (e, f) in led.versions if f == "A")
    led.capture(a, "A", "m1", "round_trip_verified", True, False, True, False, None)
    led.record_restore(a, "A", "agent", "m1", "exact", True, True, True, True, True, False)
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
    q = led.director_instruction("query_versions", entity=a)
    _atomic(led, "foreign_ref", led.director_result, q, {"outcome": "succeeded", "fps": ["ZZ"]})
    c = led.director_instruction("capture_version", entity=a, fp="A")
    _atomic(
        led,
        "manifest_mismatch",
        led.director_result,
        c,
        {"outcome": "succeeded", "manifest": "nope"},
    )
    led.director_result(c, {"outcome": "succeeded", "manifest": "m1"})
    v = led.director_instruction("verify_restore", entity=a, fp="A", manifest="m1")
    _atomic(
        led,
        "manifest_mismatch",
        led.director_result,
        v,
        {"outcome": "succeeded", "manifest": "other", "restore_outcome": "partial"},
    )
    _atomic(
        led,
        "manifest_mismatch",
        led.director_result,
        v,
        {
            "outcome": "succeeded",
            "manifest": "m1",
            "restore_outcome": "exact",
            "store_status": "missing",
            "backend_match_result": "match",
        },
    )
    led.director_result(
        v,
        {
            "outcome": "succeeded",
            "manifest": "m1",
            "restore_outcome": "exact",
            "store_status": "retrieved",
            "backend_match_result": "not_applicable",
        },
    )
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
    # an agent-supplied "match" never substitutes for Backend evidence
    led2 = _seed()
    b = next(e for (e, f) in led2.versions if f == "B")
    led2.capture(b, "B", "mb", "stored_unverified", False, False, True, False, None)
    r = led2.director_instruction("restore_version", entity=b, fp="B", manifest="mb")
    _atomic(
        led2,
        "manifest_mismatch",
        led2.director_result,
        r,
        {
            "outcome": "succeeded",
            "manifest": "mb",
            "restore_outcome": "exact",
            "store_status": "retrieved",
            "backend_match_result": "match",
        },
    )
