"""Contract tests for the closed process-record v1 schema family."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
SCHEMA_PATH = SCHEMAS / "certification" / "process_record_v1_schema.json"
SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SHA = "sha256:" + "a" * 64
PROJECT = "project-v1"
BUILD = "build:" + "b" * 8
RECEIPT = "receipt:" + "r" * 8


def _registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


REGISTRY = _registry()


def _validator(definition: str | None = None) -> Draft7Validator:
    if definition is None:
        document = SCHEMA
    else:
        document = {
            "$schema": SCHEMA["$schema"],
            "$id": f"{SCHEMA['$id']}#test-{definition}",
            "definitions": SCHEMA["definitions"],
            "allOf": [{"$ref": f"#/definitions/{definition}"}],
        }
    return Draft7Validator(document, registry=REGISTRY)


def _errors(value: object, definition: str | None = None) -> list:
    return list(_validator(definition).iter_errors(value))


def _receipt(*, stream_id: str = "receipt_event_stream", step_id: str = "evaluate") -> dict:
    return {
        "schema_version": "traigent.process_record.receipt.v1",
        "receipt_ref": RECEIPT,
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "stream_id": stream_id,
        "seq": 0,
        "step_id": step_id,
        "observation_basis": "backend_observed",
        "observed_at": "2026-09-05T10:11:12.123456Z",
        "registered_values": {
            "status_code": "completed",
            "accuracy_ppm": 950000,
            "evaluated_count": 100,
            "cost_microusd": 1250,
            "latency_us": 28000,
        },
        "receipt_digest": SHA,
    }


def _present_row(step_id: str, receipt: dict) -> dict:
    return {
        "step_id": step_id,
        "status": "present",
        "observation_kind": "backend_observed",
        "receipt_digests": [receipt["receipt_digest"]],
        "registered_values": copy.deepcopy(receipt["registered_values"]),
    }


def _report(receipt: dict | None = None) -> dict:
    receipt = receipt or _receipt()
    rows = [
        _present_row(step, receipt)
        for step in ("prepare", "evaluate", "aggregate", "select", "finalize")
    ]
    return {
        "schema_version": "traigent.process_record.report.v1",
        "project_ref": PROJECT,
        "build_session_ref": BUILD,
        "capture_policy": {
            "policy_id": "traigent.capture_policy.asap.v1",
            "policy_version": "1.0.0",
            "policy_digest": SHA,
        },
        "process_definition": {
            "definition_id": "traigent.process_definition.asap.v1",
            "definition_version": "1.0.0",
            "definition_digest": SHA,
        },
        "expected_step_count": 5,
        "rows": rows,
        "present_count": 5,
        "missing_count": 0,
        "backend_observed_present_count": 5,
        "backend_observed_missing_count": 0,
        "client_attested_present_count": 0,
        "client_attested_missing_count": 0,
        "report_digest": SHA,
    }


def test_schema_is_valid_and_all_external_refs_resolve() -> None:
    Draft7Validator.check_schema(SCHEMA)
    assert _errors({})  # The bundle is intentionally not a minimal object.
    for definition in SCHEMA["definitions"]:
        Draft7Validator.check_schema(
            {
                "$schema": SCHEMA["$schema"],
                "$id": f"{SCHEMA['$id']}#check-{definition}",
                "definitions": SCHEMA["definitions"],
                "allOf": [{"$ref": f"#/definitions/{definition}"}],
            }
        )


def test_receipt_accepts_fixed_unit_numeric_values_without_content() -> None:
    receipt = _receipt()
    assert _errors(receipt, "ProcessRecordReceiptV1") == []
    assert receipt["registered_values"]["accuracy_ppm"] == 950000
    assert receipt["registered_values"]["cost_microusd"] == 1250


@pytest.mark.parametrize(
    "field,value",
    [("seq", -1), ("seq", 2147483648), ("registered_values", {"accuracy_ppm": 1000001})],
)
def test_receipt_rejects_out_of_bounds_values(field: str, value: object) -> None:
    receipt = _receipt()
    receipt[field] = value
    assert _errors(receipt, "ProcessRecordReceiptV1")


@pytest.mark.parametrize("field", ["prompt", "response", "payload", "metadata"])
def test_receipt_rejects_content_and_unregistered_fields(field: str) -> None:
    receipt = _receipt()
    receipt[field] = "customer-content"
    assert _errors(receipt, "ProcessRecordReceiptV1")


def test_receipt_streams_are_three_closed_bounded_arrays() -> None:
    bundle = {
        "schema_version": "traigent.process_record.receipt_bundle.v1",
        "decision_stream": [],
        "receipt_event_stream": [_receipt()],
        "transition_stream": [],
        "receipt_bundle_digest": SHA,
    }
    assert _errors(bundle, "ProcessRecordReceiptBundleV1") == []
    bundle["unexpected_stream"] = []
    assert _errors(bundle, "ProcessRecordReceiptBundleV1")


def test_report_requires_fixed_five_rows_and_typed_values_match_receipt_fixture() -> None:
    receipt = _receipt()
    report = _report(receipt)
    assert _errors(report, "ProcessRecordReportV1") == []
    assert [row["step_id"] for row in report["rows"]] == [
        "prepare",
        "evaluate",
        "aggregate",
        "select",
        "finalize",
    ]
    evaluate = report["rows"][1]
    assert (
        evaluate["registered_values"]["accuracy_ppm"]
        == receipt["registered_values"]["accuracy_ppm"]
    )
    report["rows"] = report["rows"][1:]
    assert _errors(report, "ProcessRecordReportV1")
    reordered = _report(receipt)
    reordered["rows"][0], reordered["rows"][1] = reordered["rows"][1], reordered["rows"][0]
    assert _errors(reordered, "ProcessRecordReportV1")


def test_missing_report_row_cannot_carry_values_or_receipts() -> None:
    report = _report()
    row = report["rows"][2]
    row["status"] = "missing"
    assert _errors(report, "ProcessRecordReportV1")
    row.pop("receipt_digests")
    row.pop("registered_values")
    report["missing_count"] = 1
    report["present_count"] = 4
    assert _errors(report, "ProcessRecordReportV1") == []


def test_proc1_support_row_is_abstained_or_positive_only_with_full_bindings() -> None:
    abstained = {
        "claim_id": "PROC1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }
    assert _errors(abstained, "ProcessRecordClaimSupportRowV1") == []
    positive = {
        "claim_id": "PROC1",
        "evidence_basis": "issuer_verified",
        "assertion_digest": SHA,
        "process_report_digest": SHA,
        "receipt_bundle_digest": SHA,
        "verifier_result": "pass",
        "claim_material_digest": SHA,
    }
    assert _errors(positive, "ProcessRecordClaimSupportRowV1") == []
    positive.pop("process_report_digest")
    assert _errors(positive, "ProcessRecordClaimSupportRowV1")


def test_proc1_does_not_widen_v0_claim_id_vocabulary() -> None:
    row = {
        "claim_id": "B1",
        "evidence_basis": "abstained",
        "abstention_code": "verifier_not_run_or_not_pass",
    }
    assert _errors(row, "ProcessRecordClaimSupportRowV1")
    assertion = {
        "schema_version": "traigent.process_record.assertion.v1",
        "claim_id": "PROC1",
        "assertion_template_id": "process_record_correctness_v1",
        "capture_policy": {
            "policy_id": "traigent.capture_policy.asap.v1",
            "policy_version": "1.0.0",
            "policy_digest": SHA,
        },
        "rendered_text": SCHEMA["definitions"]["ProcessRecordAssertionV1"]["properties"][
            "rendered_text"
        ]["const"],
        "assertion_digest": SHA,
    }
    assert _errors(assertion, "ProcessRecordAssertionV1") == []
    assertion["rendered_text"] = "caller supplied claim"
    assert _errors(assertion, "ProcessRecordAssertionV1")


def test_registry_documents_are_closed_and_bind_same_fixed_workflow() -> None:
    policy = {
        "schema_version": "traigent.capture_policy_document.v1",
        "policy_id": "traigent.capture_policy.asap.v1",
        "policy_version": "1.0.0",
        "observable_surfaces": ["decision_stream", "receipt_event_stream", "transition_stream"],
        "expected_steps": ["prepare", "evaluate", "aggregate", "select", "finalize"],
        "canonicalization": "jcs_v1",
        "policy_digest": SHA,
    }
    process = {
        "schema_version": "traigent.process_definition_document.v1",
        "definition_id": "traigent.process_definition.asap.v1",
        "definition_version": "1.0.0",
        "expected_steps": ["prepare", "evaluate", "aggregate", "select", "finalize"],
        "stream_ids": ["decision_stream", "receipt_event_stream", "transition_stream"],
        "canonicalization": "jcs_v1",
        "definition_digest": SHA,
    }
    assert _errors(policy, "CapturePolicyDocumentV1") == []
    assert _errors(process, "ProcessDefinitionDocumentV1") == []
    process["label"] = "free text"
    assert _errors(process, "ProcessDefinitionDocumentV1")


def test_registry_and_trust_digests_have_explicit_non_circular_preimages() -> None:
    definitions = SCHEMA["definitions"]
    assert "policy_digest excluded" in definitions["CapturePolicyDocumentV1"]["description"]
    assert "definition_digest excluded" in definitions["ProcessDefinitionDocumentV1"]["description"]
    trust_description = definitions["TrustStatusSnapshotV1"]["description"]
    assert "snapshot_digest and signature excluded" in trust_description
    assert "trust_status_snapshot_signature.v1" in trust_description


def test_unsigned_manifest_coverage_excludes_signature_and_report_documents() -> None:
    coverage = SCHEMA["definitions"]["ProcessRecordUnsignedManifestV1"]["properties"][
        "coverage"
    ]["const"]
    assert "signature" not in coverage
    assert "report" not in coverage
    assert "claim_support_rows" not in coverage
    assert "receipts" not in coverage


def test_digest_domain_registry_pins_every_v1_preimage_role() -> None:
    document = {
        name: definition["const"]
        for name, definition in SCHEMA["definitions"]["ProcessRecordDigestDomainRegistryV1"][
            "properties"
        ].items()
    }
    assert _errors(document, "ProcessRecordDigestDomainRegistryV1") == []
    assert _errors(
        {**document, "report": "traigent.process_record.receipt.v1"},
        "ProcessRecordDigestDomainRegistryV1",
    )
    preimage = {
        "domain": "traigent.process_record.issuer_signature.v1",
        "framing": "UTF8(domain) || 0x00 || jcs_v1(unsigned_manifest)",
        "signed_projection": "unsigned_manifest",
    }
    assert _errors(preimage, "ProcessRecordSignaturePreimageV1") == []


def test_error_code_is_closed_and_receipt_limit_code_is_v1_only() -> None:
    valid = {
        "schema_version": "traigent.process_record.error.v1",
        "code": "process_record_receipt_limit_exceeded",
    }
    assert _errors(valid, "ProcessRecordErrorV1") == []
    invalid = {"schema_version": "traigent.process_record.error.v1", "code": "new_v0_code"}
    assert _errors(invalid, "ProcessRecordErrorV1")
