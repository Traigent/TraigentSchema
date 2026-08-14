# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the Agent Certificate v0 family (certification/).

Pins the Wave-C C6/C1 reconciled design rules structurally:

1. Tier 4 is PRESENT in the ClaimTier enum but UNCONSTRUCTIBLE in any v0 claim
   (C6: "Keep tier 4 in the schema, but make v0 emission of it a compile error").
2. ``Claim | NonClaim`` is a discriminated union with the empty-verifier compiler
   rule: a claim without a populated PASS verifier has no representable form
   (rejection, not downgrade), and a non-claim structurally forbids a verifier.
3. One explicit payload type per claim ID — only B1/B3/C1/D2/D5/G1/G3 are
   representable; the struck invented IDs B1c/D6a are not.
4. Claim sentences are versioned templates: no user-controlled free text is
   reachable from any certificate or registry record (every string is
   const/enum/pattern-bound; every object is closed).
5. The certificate prints its FOURTEEN mandatory NON-claims, in order, plus the
   const title "Agent Certificate" and the build-session scope line.
6. Claim B1 uses C1's NARROWER wording — "the issuer signed this seal
   statement" — never "the sealed history is intact".
7. Registry records are minimal blinded commitments: no counts, no date
   buckets, no timestamps.
8. The free-text quarantine: the certification family's transitive $ref closure
   never reaches an ``x-content``/``user_content`` carrier (the current-online
   tuned free-text exception stays a separate message family).

Referenced schema files (also anchors the orphan-schema ratchet in
tests/test_schemas.py):
    certification_common_v0_schema.json
    agent_certificate_v0_schema.json
    certificate_claims_v0_schema.json
    certificate_claim_payloads_v0_schema.json
    certificate_claim_templates_v0_schema.json
    certificate_evidence_refs_v0_schema.json
    certificate_ledger_seals_v0_schema.json
    certificate_signatures_v0_schema.json
    certificate_registry_agent_revision_v0_schema.json
    certificate_registry_measurement_contract_v0_schema.json
    certificate_rejection_v0_schema.json
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "traigent_schema" / "schemas"
CERT_DIR = SCHEMAS_DIR / "certification"

CERT_FILES = [
    "certification_common_v0_schema.json",
    "agent_certificate_v0_schema.json",
    "certificate_claims_v0_schema.json",
    "certificate_claim_payloads_v0_schema.json",
    "certificate_claim_templates_v0_schema.json",
    "certificate_evidence_refs_v0_schema.json",
    "certificate_ledger_seals_v0_schema.json",
    "certificate_signatures_v0_schema.json",
    "certificate_registry_agent_revision_v0_schema.json",
    "certificate_registry_measurement_contract_v0_schema.json",
    "certificate_rejection_v0_schema.json",
]

_SCHEMA_BASE = "https://schemas.traigent.ai/"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _registry() -> Registry:
    resources = []
    for path in SCHEMAS_DIR.rglob("*.json"):
        contents = _load(path)
        if isinstance(contents, dict) and "$id" in contents:
            resources.append((contents["$id"], Resource.from_contents(contents)))
    return Registry().with_resources(resources)


_REGISTRY = _registry()


def _validator(file_name: str) -> Draft7Validator:
    return Draft7Validator(_load(CERT_DIR / file_name), registry=_REGISTRY)


def _errors(file_name: str, instance: object) -> list:
    return list(_validator(file_name).iter_errors(instance))


_SHA = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64
_SIG = "A" * 128
_NONCE = "ab" * 16
_SDK_SHA = "e97b030f88d78a22dddb482d2aecf94a515b1938"

_COVERAGE = [
    "subject",
    "seal",
    "claims",
    "tiers",
    "evidence_digests",
    "non_claims",
    "privacy_mode",
    "sdk_identity",
    "compiler_register_versions",
    "key_ring_identifiers",
    "freshness",
]

_NON_CLAIM_ORDER = [
    ("A3", "tmpl.noncert.a3_no_deployment_binding.v1"),
    ("A4", "tmpl.noncert.a4_no_drift_detection.v1"),
    ("B2", "tmpl.noncert.b2_no_closeout_reconciliation.v1"),
    ("E2", "tmpl.noncert.e2_statistical_validity_suspended.v1"),
    ("E3", "tmpl.noncert.e3_winner_stability_suspended.v1"),
    ("F3", "tmpl.noncert.f3_no_offline_verifiability.v1"),
    ("G2", "tmpl.noncert.g2_no_selective_disclosure.v1"),
    ("H1", "tmpl.noncert.h1_no_criteria_epochs.v1"),
    ("NC_STEP_CAPTURE", "tmpl.noncert.nc_step_capture.v1"),
    ("NC_PRESEAL_RECORDER", "tmpl.noncert.nc_preseal_recorder.v1"),
    ("NC_TIER4_GAPCHECKED", "tmpl.noncert.nc_tier4_gapchecked.v1"),
    ("NC_TARGET_MINIMIZED", "tmpl.noncert.nc_target_minimized.v1"),
    ("NC_CURRENT_ONLINE_FREETEXT", "tmpl.noncert.nc_current_online_freetext.v1"),
    ("NC_BUILD_SESSION_SCOPE", "tmpl.noncert.nc_build_session_scope.v1"),
]


def _seal_statement() -> dict:
    return {
        "seal_ref": "seal:abcdef0123456789",
        "chain_schema_version": "traigent.cert_ledger.v0",
        "build_session_ref": "bsn:abcdef0123456789",
        "expected_stream_projection": {
            "decision_stream": {
                "stream_family": "decision",
                "chain_status": "sealed",
                "root_commitment": _SHA,
            },
            "receipt_event_stream": {
                "stream_family": "receipt_event",
                "chain_status": "empty_sealed",
                "root_commitment": _SHA_B,
            },
            "transition_stream": {
                "stream_family": "transition",
                "chain_status": "sealed",
                "root_commitment": _SHA,
            },
        },
        "seal_statement_digest": _SHA,
    }


def _b1_claim(tier: int = 3) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "B1",
        "tier": tier,
        "payload": {
            "claim_id": "B1",
            "template_id": "tmpl.cert.b1.issuer_signed_seal_statement.v1",
            "params": {
                "seal_ref": "seal:abcdef0123456789",
                "seal_statement_digest": _SHA,
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.seal_signature",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "seal_statement", "evidence_digest": _SHA}
        ],
    }


def _g1_claim(tier: int = 1) -> dict:
    return {
        "record_type": "claim",
        "claim_id": "G1",
        "tier": tier,
        "payload": {
            "claim_id": "G1",
            "template_id": "tmpl.cert.g1.client_evidence_manifest_commitment.v1",
            "params": {
                "manifest_root_digest": _SHA_B,
                "commitment_scheme": "sha256_secret_blinded_v1",
                "client_attestor_version": "0.1.0",
            },
        },
        "verifier": {
            "verifier_id": "ver.cert.manifest_commitment",
            "verifier_version": "0.1.0",
            "result": "PASS",
        },
        "evidence_refs": [
            {"evidence_kind": "verifier_report_digest", "evidence_digest": _SHA_B}
        ],
    }


def _non_claims() -> list:
    return [
        {
            "record_type": "non_claim",
            "non_claim_id": ncid,
            "reason_template_id": tmpl,
        }
        for ncid, tmpl in _NON_CLAIM_ORDER
    ]


def _co_attestation() -> dict:
    return {
        "algorithm": "ed25519",
        "client_key_ref": "ckey:abcdef0123456789",
        "signed_manifest_digest": _SHA,
        "nonce": _NONCE,
        "signature": _SIG,
    }


def _signatures(with_co: bool = False) -> dict:
    block = {
        "unsigned_manifest": {"manifest_digest": _SHA, "coverage": list(_COVERAGE)},
        "issuer_signature": {
            "algorithm": "ed25519",
            "issuer_key_ref": "ikey:abcdef0123456789",
            "trust_ring_ref": "ring:abcdef0123456789",
            "signed_payload": ["unsigned_manifest"],
            "signature": _SIG,
        },
    }
    if with_co:
        block["co_attestation"] = _co_attestation()
        block["issuer_signature"]["signed_payload"] = [
            "unsigned_manifest",
            "co_attestation",
        ]
    return block


def _certificate(claims: list | None = None, with_co: bool = False) -> dict:
    return {
        "schema_version": "traigent.agent_certificate.v0",
        "certificate_title": "Agent Certificate",
        "build_session_scope_line": (
            "Build-session scope: this certificate concerns a build session, not "
            "the deployed agent. It makes no deployment-identity, "
            "deployment-binding, drift-detection, or deployed-runtime claim."
        ),
        "subject": {
            "subject_kind": "build_session",
            "hash_algorithm": "v1",
            "build_session_ref": "bsn:abcdef0123456789",
            "session_commitment_digest": _SHA,
        },
        "semantics": {
            "semantics_manifest_digest": _SHA,
            "claim_template_catalog_digest": _SHA,
            "prohibited_register_digest": _SHA,
            "verifier_catalog_digest": _SHA,
            "non_claim_reason_catalog_digest": _SHA,
        },
        "disclosure_profile": {
            "profile_id": "customer_internal",
            "selective_disclosure_line": (
                "Data omitted from this disclosure profile is simply absent; "
                "selective disclosure is not proven."
            ),
        },
        "ledger_seal_projection": _seal_statement(),
        "claims": claims if claims is not None else [_b1_claim()],
        "non_claims": _non_claims(),
        "signatures": _signatures(with_co=with_co),
    }


ENVELOPE = "agent_certificate_v0_schema.json"
CLAIMS = "certificate_claims_v0_schema.json"
LEDGER = "certificate_ledger_seals_v0_schema.json"
REJECTION = "certificate_rejection_v0_schema.json"
REG_AR = "certificate_registry_agent_revision_v0_schema.json"
REG_MC = "certificate_registry_measurement_contract_v0_schema.json"
SIGNATURES = "certificate_signatures_v0_schema.json"
TEMPLATES = "certificate_claim_templates_v0_schema.json"


class TestEnvelope:
    def test_valid_certificate_accepted(self) -> None:
        assert not _errors(ENVELOPE, _certificate())

    def test_zero_claims_certificate_accepted(self) -> None:
        # Every v0 claim is conditional; a claims-empty certificate that still
        # prints all fourteen NON-claims is the honest v0 shape.
        assert not _errors(ENVELOPE, _certificate(claims=[]))

    def test_title_is_pinned(self) -> None:
        cert = _certificate()
        cert["certificate_title"] = "Agent Build Certificate"  # struck rename
        assert _errors(ENVELOPE, cert)

    def test_scope_line_is_pinned(self) -> None:
        cert = _certificate()
        cert["build_session_scope_line"] = "scope: build session"
        assert _errors(ENVELOPE, cert)

    def test_unknown_field_rejected(self) -> None:
        cert = _certificate()
        cert["narrative"] = "free text"
        assert _errors(ENVELOPE, cert)

    def test_subject_kind_is_build_session_only(self) -> None:
        cert = _certificate()
        cert["subject"]["subject_kind"] = "deployed_agent"
        assert _errors(ENVELOPE, cert)


class TestNonClaimPrintList:
    def test_thirteen_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"] = cert["non_claims"][:13]
        assert _errors(ENVELOPE, cert)

    def test_fifteen_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"] = cert["non_claims"] + [cert["non_claims"][0]]
        assert _errors(ENVELOPE, cert)

    def test_reordered_non_claims_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"][0], cert["non_claims"][1] = (
            cert["non_claims"][1],
            cert["non_claims"][0],
        )
        assert _errors(ENVELOPE, cert)

    def test_non_claim_with_verifier_rejected(self) -> None:
        cert = _certificate()
        cert["non_claims"][0]["verifier"] = {
            "verifier_id": "ver.cert.smuggled",
            "verifier_version": "0.1.0",
            "result": "PASS",
        }
        assert _errors(ENVELOPE, cert)


class TestTierFour:
    """C6: tier 4 stays in the enum; emitting it is a compile error."""

    def test_tier_enum_still_contains_four(self) -> None:
        common = _load(CERT_DIR / "certification_common_v0_schema.json")
        assert common["definitions"]["ClaimTier"]["enum"] == [1, 2, 3, 4]

    def test_tier_four_claim_is_unconstructible(self) -> None:
        assert _errors(CLAIMS, _b1_claim(tier=4))

    def test_tier_four_certificate_is_unconstructible(self) -> None:
        assert _errors(ENVELOPE, _certificate(claims=[_b1_claim(tier=4)]))

    def test_tiers_one_to_three_constructible(self) -> None:
        for tier in (1, 2, 3):
            claim = _b1_claim(tier=tier)
            assert not _errors(CLAIMS, claim), f"tier {tier} should be valid"


class TestClaimNonClaimUnion:
    def test_claim_without_verifier_rejected(self) -> None:
        claim = _b1_claim()
        del claim["verifier"]
        assert _errors(CLAIMS, claim)

    def test_claim_with_null_verifier_rejected(self) -> None:
        # verifier=None must compile only to NonClaim — as a claim it is
        # rejected outright, never downgraded.
        claim = _b1_claim()
        claim["verifier"] = None
        assert _errors(CLAIMS, claim)

    def test_claim_with_failed_verifier_rejected(self) -> None:
        claim = _b1_claim()
        claim["verifier"]["result"] = "FAIL"
        assert _errors(CLAIMS, claim)

    def test_claim_with_versionless_verifier_rejected(self) -> None:
        claim = _b1_claim()
        del claim["verifier"]["verifier_version"]
        assert _errors(CLAIMS, claim)

    def test_claim_without_evidence_rejected(self) -> None:
        claim = _b1_claim()
        claim["evidence_refs"] = []
        assert _errors(CLAIMS, claim)

    def test_unregistered_claim_ids_rejected(self) -> None:
        # B1c and D6a are struck invented IDs; A1/B4 are real matrix rows but
        # outside the conditional v0 allowlist. "D5" and "B3" are the C6
        # rulings' colliding aliases (D5 -> matrix F1 issuer signature; B3 is
        # the matrix's adverse-history row, NOT the registry receipt) — the
        # matrix IDs are canonical on the wire, so both raw aliases must be
        # rejected rather than silently accepted with the wrong semantics.
        for bogus in ("B1c", "D6a", "A1", "B4", "D5", "B3"):
            claim = _b1_claim()
            claim["claim_id"] = bogus
            claim["payload"]["claim_id"] = bogus
            assert _errors(CLAIMS, claim), bogus

    def test_claim_id_reconciliation_documented(self) -> None:
        # The claim-ID reconciliation (rulings namespace -> canonical matrix
        # IDs) must stay documented in the wire schema so matrix B3 (adverse
        # history, amendment A8) is visibly pending, never silently dropped.
        claims = _load(CERT_DIR / CLAIMS)
        doc = claims["definitions"]["ClaimIdV0"]["description"]
        assert "RECONCILIATION TABLE" in doc
        assert "Adverse history" in doc.replace("ADVERSE HISTORY", "Adverse history")
        assert "A8" in doc
        assert "F1" in doc and "REG1" in doc

    def test_payload_claim_id_mismatch_rejected(self) -> None:
        claim = _b1_claim()
        claim["payload"] = _g1_claim()["payload"]
        assert _errors(CLAIMS, claim)

    def test_free_text_param_rejected(self) -> None:
        claim = _b1_claim()
        claim["payload"]["params"]["note"] = "free text"
        assert _errors(CLAIMS, claim)

    def test_claim_sentence_field_unrepresentable(self) -> None:
        claim = _b1_claim()
        claim["claim_sentence"] = "The ledger is intact."
        assert _errors(CLAIMS, claim)


class TestTemplates:
    def test_b1_template_uses_narrow_wording(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        text = catalog["definitions"]["TemplateB1V1"]["properties"][
            "template_text"
        ]["const"]
        assert text.startswith("The issuer signed this seal statement")
        assert "intact" not in text
        assert "complete build history" not in text

    def test_exactly_seven_templates_pinned(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        ids = set()
        for definition in catalog["definitions"].values():
            ids.add(definition["properties"]["template_id"]["const"])
        assert len(ids) == 7
        for claim_id in ("b1", "c1", "d2", "f1", "g1", "g3", "reg1"):
            assert any(f".{claim_id}." in tid for tid in ids), claim_id

    def test_template_records_validate(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        for name, definition in catalog["definitions"].items():
            record = {
                "template_id": definition["properties"]["template_id"]["const"],
                "template_text": definition["properties"]["template_text"]["const"],
                "parameter_slots": definition["properties"]["parameter_slots"][
                    "const"
                ],
            }
            assert not _errors(TEMPLATES, record), name

    def test_template_slots_match_payload_params(self) -> None:
        catalog = _load(CERT_DIR / TEMPLATES)
        payloads = _load(CERT_DIR / "certificate_claim_payloads_v0_schema.json")
        slot_map = {}
        for definition in catalog["definitions"].values():
            tid = definition["properties"]["template_id"]["const"]
            slot_map[tid] = set(definition["properties"]["parameter_slots"]["const"])
        for name, payload in payloads["definitions"].items():
            if name == "ClaimPayloadV0":
                continue
            tid = payload["properties"]["template_id"]["const"]
            required = set(payload["properties"]["params"]["required"])
            assert slot_map[tid] <= required | set(
                payload["properties"]["params"]["properties"]
            ), name


class TestCoAttestationBinding:
    def test_tier_one_claim_requires_co_attestation(self) -> None:
        cert = _certificate(claims=[_g1_claim(tier=1)], with_co=False)
        assert _errors(ENVELOPE, cert)

    def test_tier_one_claim_with_co_attestation_accepted(self) -> None:
        cert = _certificate(claims=[_g1_claim(tier=1)], with_co=True)
        assert not _errors(ENVELOPE, cert)

    def test_issuer_must_cover_present_co_attestation(self) -> None:
        sigs = _signatures(with_co=True)
        sigs["issuer_signature"]["signed_payload"] = ["unsigned_manifest"]
        assert _errors(SIGNATURES, sigs)

    def test_issuer_cannot_claim_absent_co_attestation(self) -> None:
        sigs = _signatures(with_co=False)
        sigs["issuer_signature"]["signed_payload"] = [
            "unsigned_manifest",
            "co_attestation",
        ]
        assert _errors(SIGNATURES, sigs)

    def test_manifest_coverage_is_pinned(self) -> None:
        sigs = _signatures()
        sigs["unsigned_manifest"]["coverage"] = ["subject", "seal"]
        assert _errors(SIGNATURES, sigs)


class TestLedgerSeals:
    def test_valid_seal_statement_accepted(self) -> None:
        assert not _errors(LEDGER, _seal_statement())

    def test_missing_stream_rejected(self) -> None:
        seal = _seal_statement()
        del seal["expected_stream_projection"]["transition_stream"]
        assert _errors(LEDGER, seal)

    def test_sealed_stream_without_root_rejected(self) -> None:
        seal = _seal_statement()
        del seal["expected_stream_projection"]["decision_stream"]["root_commitment"]
        assert _errors(LEDGER, seal)

    def test_legacy_stream_with_root_rejected(self) -> None:
        # legacy-NULL-chain presented as chained: a legacy stream may not carry
        # a root commitment.
        seal = _seal_statement()
        entry = seal["expected_stream_projection"]["decision_stream"]
        entry["chain_status"] = "legacy_unsealed"
        assert _errors(LEDGER, seal)

    def test_legacy_stream_without_root_accepted(self) -> None:
        seal = _seal_statement()
        entry = seal["expected_stream_projection"]["decision_stream"]
        entry["chain_status"] = "legacy_unsealed"
        del entry["root_commitment"]
        assert not _errors(LEDGER, seal)

    def test_null_chain_status_rejected(self) -> None:
        seal = _seal_statement()
        seal["expected_stream_projection"]["decision_stream"]["chain_status"] = None
        assert _errors(LEDGER, seal)

    def test_counts_and_terminal_seq_unrepresentable(self) -> None:
        seal = _seal_statement()
        seal["event_count"] = 12
        assert _errors(LEDGER, seal)
        seal = _seal_statement()
        seal["expected_stream_projection"]["decision_stream"]["terminal_seq"] = 7
        assert _errors(LEDGER, seal)


class TestRegistries:
    def _agent_revision_record(self) -> dict:
        return {
            "schema_version": "traigent.certificate_registry.agent_revision.v0",
            "revision_id": "arv:abcdef0123456789",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization_profile": "jcs_v1",
            "blinded_revision_commitment": _SHA,
            "canonical_record_digest": _SHA_B,
        }

    def _measurement_contract_record(self) -> dict:
        return {
            "schema_version": (
                "traigent.certificate_registry.measurement_contract.v0"
            ),
            "contract_id": "mct:abcdef0123456789",
            "commitment_scheme": "sha256_secret_blinded_v1",
            "canonicalization_profile": "jcs_v1",
            "blinded_contract_commitment": _SHA,
            "canonical_record_digest": _SHA_B,
        }

    def test_valid_records_accepted(self) -> None:
        assert not _errors(REG_AR, self._agent_revision_record())
        assert not _errors(REG_MC, self._measurement_contract_record())

    def test_parent_ref_is_optional_declared_link(self) -> None:
        record = self._agent_revision_record()
        record["parent_revision_ref"] = "arv:fedcba9876543210"
        assert not _errors(REG_AR, record)

    def test_counts_unrepresentable(self) -> None:
        for field in ("material_kind_counts", "item_count", "event_count"):
            record = self._agent_revision_record()
            record[field] = 3
            assert _errors(REG_AR, record), field

    def test_date_buckets_and_timestamps_unrepresentable(self) -> None:
        for field in ("created_at", "created_bucket", "registration_date"):
            record = self._agent_revision_record()
            record[field] = "2026-08-11"
            assert _errors(REG_AR, record), field
            record = self._measurement_contract_record()
            record[field] = "2026-08-11"
            assert _errors(REG_MC, record), field

    def test_measurement_detail_fields_unrepresentable(self) -> None:
        # Metric IDs, dataset size, split policy, and seed stay inside the
        # committed client-local document.
        for field, value in (
            ("metric_ids", ["accuracy"]),
            ("dataset_size", 100),
            ("split_policy", "holdout"),
            ("seed", 42),
        ):
            record = self._measurement_contract_record()
            record[field] = value
            assert _errors(REG_MC, record), field

    def test_free_text_name_unrepresentable(self) -> None:
        record = self._agent_revision_record()
        record["name"] = "my agent"
        assert _errors(REG_AR, record)


class TestRejection:
    def test_valid_rejection_accepted(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "tier4_emission_attempt",
            "structural_path": [
                {"segment_kind": "property", "property_name": "claims"},
                {"segment_kind": "index", "index": 0},
                {"segment_kind": "property", "property_name": "tier"},
            ],
        }
        assert not _errors(REJECTION, rejection)

    def test_rejected_value_unrepresentable(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "unknown_field",
            "structural_path": [],
            "rejected_value": "tuned free text",
        }
        assert _errors(REJECTION, rejection)

    def test_message_field_unrepresentable(self) -> None:
        rejection = {
            "schema_version": "traigent.certificate_rejection.v0",
            "rejection_code": "unknown_field",
            "structural_path": [],
            "message": "boom",
        }
        assert _errors(REJECTION, rejection)

    def test_unsupported_definition_codes_present(self) -> None:
        # C6 Ruling 3(ii): the operational definition of "unsupported".
        schema = _load(CERT_DIR / REJECTION)
        codes = set(schema["definitions"]["RejectionCodeV0"]["enum"])
        assert {
            "unregistered_claim_id",
            "missing_or_versionless_verifier",
            "verifier_not_run_or_not_pass",
            "missing_evidence_binding",
            "prohibited_register_violation",
        } <= codes


def _walk(node: object):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


class TestBoundaryDiscipline:
    """Structural lint: no free-text channel exists anywhere in the family."""

    def test_every_string_is_bounded(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "string":
                    assert (
                        "const" in node or "enum" in node or "pattern" in node
                    ), f"{file_name}: unconstrained string node {node}"

    def test_every_object_is_closed(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "object" and "properties" in node:
                    assert node.get("additionalProperties") is False, (
                        f"{file_name}: open object node "
                        f"{sorted(node['properties'])}"
                    )

    def test_every_array_is_bounded(self) -> None:
        for file_name in CERT_FILES:
            schema = _load(CERT_DIR / file_name)
            for node in _walk(schema):
                if node.get("type") == "array":
                    assert "maxItems" in node, (
                        f"{file_name}: unbounded array node"
                    )

    def test_no_x_content_carrier_reachable(self) -> None:
        """The free-text quarantine (C1 Ruling 5): the certification family's
        transitive $ref closure must never reach an x-content / user_content
        carrier, and must not reach the known current-online free-text carrier
        files at all."""
        forbidden_files = {
            "execution/metric_submission_schema.json",
            "optimization/optimization_endpoints.json",
        }
        seen: set[str] = set()

        def resolve(current: Path, ref: str) -> Path | None:
            ref = ref.split("#")[0]
            if not ref:
                return None
            if ref.startswith(_SCHEMA_BASE):
                return SCHEMAS_DIR / ref[len(_SCHEMA_BASE):]
            if ref.startswith(("http://", "https://", "urn:")):
                return None
            return (current.parent / ref).resolve()

        def visit(path: Path) -> None:
            rel = path.resolve().relative_to(SCHEMAS_DIR.resolve()).as_posix()
            if rel in seen:
                return
            seen.add(rel)
            for match in re.finditer(
                r'"\$ref"\s*:\s*"([^"]+)"', path.read_text(encoding="utf-8")
            ):
                target = resolve(path, match.group(1))
                if target is not None and target.exists():
                    visit(target)

        for file_name in CERT_FILES:
            visit(CERT_DIR / file_name)

        assert not (seen & forbidden_files), seen & forbidden_files
        for rel in seen:
            assert not rel.startswith(("observability/", "datasets/")), rel
            content = (SCHEMAS_DIR / rel).read_text(encoding="utf-8")
            data = json.loads(content)
            for node in _walk(data):
                assert node.get("x-content") is not True, (
                    f"{rel}: x-content carrier reachable from certification/"
                )
                assert (
                    node.get("x-privacy-classification") != "user_content"
                ), f"{rel}: user_content carrier reachable from certification/"

    def test_schemas_are_valid_draft7(self) -> None:
        for file_name in CERT_FILES:
            Draft7Validator.check_schema(_load(CERT_DIR / file_name))


class TestClaimIdAllowlist:
    def test_exactly_seven_claim_ids(self) -> None:
        claims = _load(CERT_DIR / CLAIMS)
        assert claims["definitions"]["ClaimIdV0"]["enum"] == [
            "B1",
            "C1",
            "D2",
            "F1",
            "G1",
            "G3",
            "REG1",
        ]

    def test_fourteen_non_claim_ids(self) -> None:
        claims = _load(CERT_DIR / CLAIMS)
        assert len(claims["definitions"]["NonClaimIdV0"]["enum"]) == 14

    def test_all_seven_payloads_constructible(self) -> None:
        payload_examples = {
            "B1": _b1_claim()["payload"],
            "REG1": {
                "claim_id": "REG1",
                "template_id": "tmpl.cert.reg1.registry_commitment_receipt.v1",
                "params": {
                    "registry_kind": "agent_revision",
                    "registry_record_ref": "arv:abcdef0123456789",
                    "commitment_scheme": "sha256_secret_blinded_v1",
                    "canonical_record_digest": _SHA,
                },
            },
            "C1": {
                "claim_id": "C1",
                "template_id": (
                    "tmpl.cert.c1.artifact_scoped_no_unsupported_claims.v1"
                ),
                "params": {
                    "compiler_version": "0.1.0",
                    "semantics_manifest_digest": _SHA,
                    "prohibited_register_digest": _SHA,
                    "verifier_catalog_digest": _SHA,
                },
            },
            "D2": {
                "claim_id": "D2",
                "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
                "params": {
                    "declared_mode": "offline",
                    "witness_kind": "strace_network_trace",
                    "sdk_ref": _SDK_SHA,
                    "workload_class": (
                        "mock_grid_no_integrations_no_analytics_no_langfuse"
                    ),
                    "witness_bundle_digest": _SHA,
                },
            },
            "F1": {
                "claim_id": "F1",
                "template_id": "tmpl.cert.f1.issuer_signature_validity.v1",
                "params": {
                    "signed_manifest_digest": _SHA,
                    "signature_scheme": "ed25519",
                    "issuer_key_ref": "ikey:abcdef0123456789",
                    "trust_ring_ref": "ring:abcdef0123456789",
                },
            },
            "G1": _g1_claim()["payload"],
            "G3": {
                "claim_id": "G3",
                "template_id": "tmpl.cert.g3.cosigner_identity_binding.v1",
                "params": {
                    "client_key_ref": "ckey:abcdef0123456789",
                    "cosigned_manifest_digest": _SHA,
                },
            },
        }
        for claim_id, payload in payload_examples.items():
            claim = _b1_claim()
            claim["claim_id"] = claim_id
            claim["payload"] = copy.deepcopy(payload)
            assert not _errors(CLAIMS, claim), claim_id

    def test_d2_workload_class_is_closed(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "D2"
        claim["payload"] = {
            "claim_id": "D2",
            "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
            "params": {
                "declared_mode": "offline",
                "witness_kind": "strace_network_trace",
                "sdk_ref": _SDK_SHA,
                "workload_class": "any workload we like",
                "witness_bundle_digest": _SHA,
            },
        }
        assert _errors(CLAIMS, claim)

    def test_d2_requires_full_sha_pin(self) -> None:
        claim = _b1_claim()
        claim["claim_id"] = "D2"
        claim["payload"] = {
            "claim_id": "D2",
            "template_id": "tmpl.cert.d2.offline_backend_egress_witness.v1",
            "params": {
                "declared_mode": "offline",
                "witness_kind": "strace_network_trace",
                "sdk_ref": "e97b030f",  # short SHA: witness must be full-ref pinned
                "workload_class": (
                    "mock_grid_no_integrations_no_analytics_no_langfuse"
                ),
                "witness_bundle_digest": _SHA,
            },
        }
        assert _errors(CLAIMS, claim)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-q"])
