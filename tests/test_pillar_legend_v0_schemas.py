# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Pillar Legend v0 schemas (docs/identity/pillar-legend-v0.md).

Valid examples for every object, plus negatives: unknown fields, path-like strings,
free text where an enum belongs, witnessed provenance on client events, partial
coverage claiming ``exact``, and a legacy-fixture guard.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator

from tests._schema_refs import build_registry, ref_errors

ROOT = Path(__file__).resolve().parents[1]
schemas_dir = ROOT / "traigent_schema" / "schemas"
# Literal path forms: how tests/test_schemas.py's orphan ratchet recognises a referenced schema.
LEGEND_PATH = schemas_dir / "legend" / "pillar_legend_v0.json"
MANIFEST_PATH = schemas_dir / "legend" / "recovery_manifest_v0.json"
PREDICATE_PATH = schemas_dir / "legend" / "legend_claim_predicate_v0.json"
OPS_PATH = schemas_dir / "legend" / "director_legend_ops_v0.json"
BASE = "https://schemas.traigent.ai/legend/v0/"
REGISTRY = build_registry()

H64 = "a" * 64
KID = "k" + "0123456789abcdef"
SHA = "sha256:" + H64
MSR = f"msr1:{KID}:{H64}"
SSP = f"ssp1:{KID}:{H64}"
RMF = "rmf0:sha256:" + "b" * 64
HEX32 = "0123456789abcdef0123456789abcdef"
TS = "2026-10-15T10:00:00Z"
COMPLETE = {"status": "complete", "covered": ["code", "prompts"], "missing": []}
PARTIAL = {"status": "partial", "covered": ["code"], "missing": ["prompts"]}


def ref_of(prefix: str) -> str:
    return f"{prefix}ref_{HEX32}"


def check(doc: str, definition: str, instance: Any) -> list[str]:
    return ref_errors(REGISTRY, f"{BASE}{doc}#/definitions/{definition}", instance)


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
        "idempotency_key": H64,
    }


GOLDEN: dict[str, tuple[str, str, dict[str, Any]]] = {
    "entity": (
        "pillar_legend_v0.json",
        "LegendEntityV0",
        {"schema_version": "0", "entity_ref": ref_of("entity"), "kind": "agent", "created_at": TS},
    ),
    "version_agent": (
        "pillar_legend_v0.json",
        "LegendVersionV0",
        {
            "schema_version": "0",
            "version_ref": ref_of("version"),
            "entity_ref": ref_of("entity"),
            "kind": "agent",
            "fingerprint_scheme": "agent_build_digest_v1",
            "key_id": None,
            "fingerprint": SHA,
            "initial_parent_version_ref": None,
            "identity_source": "sdk_fingerprinted",
            "declared_at": TS,
        },
    ),
    "version_dataset": (
        "pillar_legend_v0.json",
        "LegendVersionV0",
        {
            "schema_version": "0",
            "version_ref": ref_of("version"),
            "entity_ref": ref_of("entity"),
            "kind": "evaluation_dataset",
            "fingerprint_scheme": "dataset_multiset_root_v1",
            "key_id": KID,
            "fingerprint": MSR,
            "initial_parent_version_ref": ref_of("version"),
            "identity_source": "client_declared",
            "declared_at": TS,
        },
    ),
    "version_search_space": (
        "pillar_legend_v0.json",
        "LegendVersionV0",
        {
            "schema_version": "0",
            "version_ref": ref_of("version"),
            "entity_ref": ref_of("entity"),
            "kind": "search_space",
            "fingerprint_scheme": "search_space_ssp1",
            "key_id": KID,
            "fingerprint": SSP,
            "initial_parent_version_ref": None,
            "identity_source": "client_declared",
            "declared_at": TS,
        },
    ),
    "declared": (
        "pillar_legend_v0.json",
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
        "pillar_legend_v0.json",
        "DeclaredEventV0",
        {
            **env("declared", "server", "client_reported"),
            "provenance": "implicit_legacy",
            "identity_source": "client_declared",
            "previous_version_ref": None,
        },
    ),
    "captured": (
        "pillar_legend_v0.json",
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
    "restore_verified": (
        "pillar_legend_v0.json",
        "RestoreVerifiedEventV0",
        {
            **env("restore_verified", "client", "client_sdk_reported"),
            "recovery_manifest_fingerprint": RMF,
            "outcome": "exact",
            "coverage": COMPLETE,
            "isolated_destination": True,
            "representation_digests_match": True,
            "pillar_fingerprint_match": True,
        },
    ),
    "bound_to_run": (
        "pillar_legend_v0.json",
        "BoundToRunEventV0",
        {
            **env("bound_to_run", "server", "server_recorded"),
            "run_ref": ref_of("run"),
            "trial_ref": ref_of("trial"),
            "binding_role": "trial_candidate",
            "run_tuple_digest": SHA,
        },
    ),
    "evaluated_client": (
        "pillar_legend_v0.json",
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
        "pillar_legend_v0.json",
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
        "pillar_legend_v0.json",
        "AvailabilityChangedEventV0",
        {
            **env("availability_changed", "client", "client_sdk_reported"),
            "recovery_manifest_fingerprint": RMF,
            "status": "missing",
        },
    ),
    "manifest": (
        "recovery_manifest_v0.json",
        "RecoveryManifestV0",
        {
            "schema_version": "0",
            "manifest_scheme": "traigent.recovery_manifest.v0",
            "kind": "evaluation_dataset",
            "fingerprint_scheme": "dataset_multiset_root_v1",
            "key_id": KID,
            "pillar_fingerprint": MSR,
            "exporter": {"exporter_id": "dataset-rows", "exporter_version": "0.1.0"},
            "representations": [
                {
                    "ordinal": 0,
                    "representation_kind": "dataset_rows",
                    "digest": SHA,
                    "byte_length": 10,
                }
            ],
            "ordering": "preserved",
            "dependencies": [{"version_ref": ref_of("version"), "kind": "agent"}],
            "coverage": COMPLETE,
        },
    ),
    "predicate": (
        "legend_claim_predicate_v0.json",
        "ClaimPredicateV0",
        {
            "schema_version": "0",
            "predicate_type": "restore_verified_client_reported",
            "subject": {
                "version_ref": ref_of("version"),
                "kind": "agent",
                "fingerprint_scheme": "agent_build_digest_v1",
                "key_id": None,
                "fingerprint": SHA,
            },
            "evidence_source": "client_sdk_reported",
            "supporting_event_refs": [ref_of("event")],
            "recovery_manifest_fingerprint": RMF,
            "coverage_status": "complete",
            "run_tuple_digest": None,
            "as_of": TS,
            "policy_version": "legend-claims-0",
        },
    ),
    "ins_declare": (
        "director_legend_ops_v0.json",
        "DeclareVersionInstruction",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "declare_version",
            "kind": "agent",
            "entity_ref": None,
        },
    ),
    "ins_query": (
        "director_legend_ops_v0.json",
        "QueryVersionsInstruction",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "query_versions",
            "entity_ref": ref_of("entity"),
            "page_size": 50,
            "page_cursor": None,
        },
    ),
    "ins_capture": (
        "director_legend_ops_v0.json",
        "CaptureVersionInstruction",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "capture_version",
            "version_ref": ref_of("version"),
        },
    ),
    "ins_verify": (
        "director_legend_ops_v0.json",
        "VerifyRestoreInstruction",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "verify_restore",
            "version_ref": ref_of("version"),
            "recovery_manifest_fingerprint": RMF,
        },
    ),
    "ins_restore": (
        "director_legend_ops_v0.json",
        "RestoreVersionInstruction",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "restore_version",
            "version_ref": ref_of("version"),
            "recovery_manifest_fingerprint": RMF,
        },
    ),
    "res_declare": (
        "director_legend_ops_v0.json",
        "DeclareVersionResult",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "declare_version",
            "outcome": "succeeded",
            "error_code": None,
            "version_ref": ref_of("version"),
            "created": True,
        },
    ),
    "res_query": (
        "director_legend_ops_v0.json",
        "QueryVersionsResult",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "query_versions",
            "outcome": "succeeded",
            "error_code": None,
            "version_refs": [ref_of("version")],
            "next_page_cursor": None,
        },
    ),
    "res_capture": (
        "director_legend_ops_v0.json",
        "CaptureVersionResult",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "capture_version",
            "outcome": "succeeded",
            "error_code": None,
            "store_status": "stored_unverified",
            "recovery_manifest_fingerprint": RMF,
            "coverage": PARTIAL,
            "conformance_passed": False,
        },
    ),
    "res_verify": (
        "director_legend_ops_v0.json",
        "VerifyRestoreResult",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "verify_restore",
            "outcome": "failed",
            "error_code": "restore_failed",
            "restore_outcome": "failed",
            "coverage": None,
            "store_status": "corrupted",
        },
    ),
    "res_restore": (
        "director_legend_ops_v0.json",
        "RestoreVersionResult",
        {
            "schema_version": "0",
            "instruction_ref": ref_of("instruction"),
            "operation": "restore_version",
            "outcome": "refused",
            "error_code": "foreign_ref",
            "restore_outcome": None,
            "store_status": "not_captured",
            "activated": False,
        },
    ),
}


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_golden_examples_are_valid(name: str) -> None:
    doc, definition, instance = GOLDEN[name]
    assert check(doc, definition, instance) == []


@pytest.mark.parametrize("path", [LEGEND_PATH, MANIFEST_PATH, PREDICATE_PATH, OPS_PATH])
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


@pytest.mark.parametrize("path", [LEGEND_PATH, MANIFEST_PATH, PREDICATE_PATH, OPS_PATH])
def test_every_object_is_closed_and_no_free_text(path: Path) -> None:
    schema = json.loads(path.read_text(encoding="utf-8"))
    for where, obj in _objects(schema):
        assert obj.get("additionalProperties") is False, where
    # every string-typed property is a const / enum / pattern / format-bound value
    for where, obj in _objects(schema):
        for key, prop in obj["properties"].items():
            if prop.get("type") == "string":
                assert {"const", "enum", "pattern"} & set(prop), f"{where}/{key} is free text"


@pytest.mark.parametrize("name", sorted(GOLDEN))
def test_unknown_field_is_refused(name: str) -> None:
    doc, definition, instance = GOLDEN[name]
    bad = {**copy.deepcopy(instance), "label": "my agent"}
    assert check(doc, definition, bad) != []


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
    ],
)
def test_path_like_and_free_text_values_are_refused(name: str, field: str, value: str) -> None:
    doc, definition, instance = GOLDEN[name]
    bad = copy.deepcopy(instance)
    bad[field] = value
    assert check(doc, definition, bad) != []


def test_trailing_newline_is_not_a_second_spelling() -> None:
    doc, definition, instance = GOLDEN["captured"]
    bad = {**instance, "recovery_manifest_fingerprint": RMF + "\n"}
    assert check(doc, definition, bad) != []


@pytest.mark.parametrize(
    "name", ["declared", "captured", "restore_verified", "availability_changed"]
)
@pytest.mark.parametrize("evidence", ["traigent_witnessed", "server_recorded"])
def test_client_events_cannot_carry_witnessed_or_server_provenance(
    name: str, evidence: str
) -> None:
    doc, definition, instance = GOLDEN[name]
    bad = {**instance, "evidence_source": evidence}
    assert check(doc, definition, bad) != []


def test_client_origin_evaluation_cannot_be_witnessed_and_server_must_be() -> None:
    doc, definition, good = GOLDEN["evaluated_client"]
    assert check(doc, definition, {**good, "evidence_source": "traigent_witnessed"}) != []
    _, _, witnessed = GOLDEN["evaluated_witnessed"]
    assert check(doc, definition, {**witnessed, "evidence_source": "client_reported"}) != []


def test_client_origin_cannot_be_claimed_on_server_only_events() -> None:
    doc, definition, instance = GOLDEN["bound_to_run"]
    assert check(doc, definition, {**instance, "origin": "client"}) != []
    assert check(doc, definition, {**instance, "evidence_source": "client_reported"}) != []


def test_exact_restore_requires_complete_coverage_and_equalities() -> None:
    doc, definition, good = GOLDEN["restore_verified"]
    assert check(doc, definition, {**good, "coverage": PARTIAL}) != []
    assert check(doc, definition, {**good, "pillar_fingerprint_match": False}) != []
    assert check(doc, definition, {**good, "representation_digests_match": False}) != []
    assert check(doc, definition, {**good, "coverage": PARTIAL, "outcome": "partial"}) == []
    assert check(doc, definition, {**good, "isolated_destination": False}) != []


def test_round_trip_verified_needs_conformance_and_put_ack_is_unverified() -> None:
    doc, definition, good = GOLDEN["captured"]
    assert check(doc, definition, {**good, "conformance_passed": False}) != []
    assert (
        check(
            doc,
            definition,
            {**good, "recovery_state": "stored_unverified", "conformance_passed": False},
        )
        == []
    )
    assert check(doc, definition, {**good, "recovery_state": "none"}) != []


def test_coverage_status_and_missing_must_agree() -> None:
    assert (
        check(
            "pillar_legend_v0.json",
            "Coverage",
            {"status": "complete", "covered": ["code"], "missing": ["prompts"]},
        )
        != []
    )
    assert (
        check(
            "pillar_legend_v0.json",
            "Coverage",
            {"status": "partial", "covered": ["code"], "missing": []},
        )
        != []
    )
    assert (
        check(
            "pillar_legend_v0.json",
            "Coverage",
            {"status": "partial", "covered": ["code", "code"], "missing": ["prompts"]},
        )
        != []
    )


def test_kind_scheme_and_key_rules() -> None:
    doc, definition, good = GOLDEN["version_agent"]
    assert check(doc, definition, {**good, "fingerprint_scheme": "dataset_multiset_root_v1"}) != []
    assert (
        check(doc, definition, {**good, "key_id": KID}) != []
    )  # unkeyed scheme must have null key
    _, _, keyed = GOLDEN["version_dataset"]
    assert check(doc, definition, {**keyed, "key_id": None}) != []  # keyed scheme needs a key
    assert check(doc, definition, {**keyed, "fingerprint": SHA}) != []  # wrong fingerprint family
    assert check(doc, definition, {**good, "kind": "model"}) != []


def test_dataset_manifest_must_preserve_ordering() -> None:
    doc, definition, good = GOLDEN["manifest"]
    assert check(doc, definition, {**good, "ordering": "not_applicable"}) != []
    assert check(doc, definition, {**good, "representations": []}) != []


def test_predicate_evidence_source_is_pinned_per_type() -> None:
    doc, definition, good = GOLDEN["predicate"]
    assert check(doc, definition, {**good, "evidence_source": "traigent_witnessed"}) != []
    witnessed = {
        **good,
        "predicate_type": "evaluated_traigent_witnessed",
        "evidence_source": "traigent_witnessed",
        "recovery_manifest_fingerprint": None,
        "coverage_status": None,
        "run_tuple_digest": SHA,
    }
    assert check(doc, definition, witnessed) == []
    assert check(doc, definition, {**witnessed, "evidence_source": "client_reported"}) != []
    assert check(doc, definition, {**witnessed, "run_tuple_digest": None}) != []
    assert check(doc, definition, {**good, "supporting_event_refs": []}) != []
    assert check(doc, definition, {**good, "coverage_status": None}) != []


def test_director_results_are_closed_and_never_activate() -> None:
    doc, definition, good = GOLDEN["res_restore"]
    assert check(doc, definition, {**good, "activated": True}) != []
    assert check(doc, definition, {**good, "error_code": None}) != []  # refused needs an error
    _, _, ok = GOLDEN["res_declare"]
    assert check(doc, "DeclareVersionResult", {**ok, "error_code": "internal_error"}) != []
    assert check(doc, "DeclareVersionResult", {**ok, "message": "adapter exception text"}) != []


def test_root_documents_dispatch_on_shape() -> None:
    for key in ("entity", "version_agent", "declared", "captured"):
        _, _, instance = GOLDEN[key]
        assert ref_errors(REGISTRY, BASE + "pillar_legend_v0.json", instance) == [], key
    for key in ("ins_capture", "res_query"):
        _, _, instance = GOLDEN[key]
        assert ref_errors(REGISTRY, BASE + "director_legend_ops_v0.json", instance) == [], key


def test_legacy_identity_schemas_are_untouched() -> None:
    import subprocess

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


def test_revert_redeclaration_is_a_valid_event_and_version_identity_has_no_mutable_parent() -> None:
    doc, definition, good = GOLDEN["declared"]
    # v3 -> v1 revert: a later declaration of v1 names the version the declarer moved from.
    assert (
        check(
            doc,
            definition,
            {**good, "previous_version_ref": ref_of("version"), "change_reason": "rollback"},
        )
        == []
    )
    # the declared event has no initial-parent field; that lives on the version only
    assert check(doc, definition, {**good, "initial_parent_version_ref": None}) != []
    _, vdef, ver = GOLDEN["version_agent"]
    assert check("pillar_legend_v0.json", vdef, {**ver, "previous_version_ref": None}) != []
    assert "parent_version_ref" not in ver


def test_idempotency_key_must_be_a_digest_so_payload_reuse_is_decidable() -> None:
    doc, definition, good = GOLDEN["declared"]
    assert check(doc, definition, {**good, "idempotency_key": "same-key-different-payload"}) != []


class _RefLedger:
    """Minimal reference model of the declare rules (conformance cases for the contract)."""

    def __init__(self) -> None:
        self.versions: dict[tuple[str, str], dict[str, Any]] = {}  # (entity, fingerprint) -> row
        self.events: list[dict[str, Any]] = []
        self.keys: dict[str, Any] = {}

    def declare(
        self, entity: str, fp: str, initial_parent: str | None, previous: str | None, key: str
    ) -> str:
        payload = (entity, fp, initial_parent, previous)
        if key in self.keys:
            if self.keys[key] != payload:
                raise ValueError("conflicting_idempotency_payload")
            return fp
        if initial_parent == fp and (entity, fp) not in self.versions:
            raise ValueError("initial_parent_cycle")
        for ref_fp in (initial_parent, previous):
            if ref_fp is not None and (entity, ref_fp) not in self.versions:
                raise ValueError("unknown_ref")  # same entity, declared first
        if (entity, fp) not in self.versions:
            if initial_parent == fp or self._reaches(entity, initial_parent, fp):
                raise ValueError("initial_parent_cycle")
            self.versions[(entity, fp)] = {"initial_parent": initial_parent}
        self.keys[key] = payload
        self.events.append({"fp": fp, "previous": previous})
        return fp

    def _reaches(self, entity: str, start: str | None, target: str) -> bool:
        while start is not None:
            if start == target:
                return True
            start = self.versions[(entity, start)]["initial_parent"]
        return False


def test_reference_model_revert_idempotency_and_cycle_rules() -> None:
    led = _RefLedger()
    led.declare("e", "v1", None, None, "k1")
    led.declare("e", "v2", "v1", "v1", "k2")
    led.declare("e", "v3", "v2", "v2", "k3")
    before = dict(led.versions)
    led.declare("e", "v1", None, "v3", "k4")  # revert v3 -> v1: a legal event, not a cycle
    assert led.versions == before  # version identity and initial parent never change
    assert led.events[-1] == {"fp": "v1", "previous": "v3"}
    assert (
        led.declare("e", "v1", None, "v3", "k4") == "v1" and len(led.events) == 4
    )  # idempotent replay
    with pytest.raises(ValueError, match="conflicting_idempotency_payload"):
        led.declare("e", "v2", "v1", "v1", "k4")
    with pytest.raises(ValueError, match="initial_parent_cycle"):
        led.declare("e", "v4", "v4", None, "k5")
    with pytest.raises(ValueError, match="unknown_ref"):
        led.declare("e", "v5", "other-entity-version", None, "k6")
