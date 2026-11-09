"""Contract tests for AGB-74 slice 5: the evidence export pack manifest and endpoint."""

from __future__ import annotations

from typing import Any

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema.utils import get_schemas_dir

SCHEMAS = get_schemas_dir()
READINESS = SCHEMAS / "agent_readiness"
SCHEMA_PATH = READINESS / "compliance_export_manifest_schema.json"
ENDPOINTS_PATH = READINESS / "compliance_export_endpoints.json"
ERROR_PATH = READINESS / "compliance_export_error_schema.json"
_REGISTRY = build_registry(SCHEMAS)
_ID = load_json(SCHEMA_PATH)["$id"]
_DIGEST = "a" * 64
_FILES = (
    "applicability.json",
    "attestations.json",
    "coverage.html",
    "coverage.json",
    "documents.json",
    "measurements.json",
)


def _errors(definition: str, instance: Any) -> list[str]:
    return ref_errors(_REGISTRY, f"{_ID}#/definitions/{definition}", instance)


def _section(**extra: Any) -> dict[str, Any]:
    return {"complete": True, "records": 0, **extra}


def _manifest() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0-beta.1",
        "export_id": "cee_" + "0" * 32,
        "generated_at": "2026-11-08T12:00:00+00:00",
        "subject": {
            "tenant_id": "t1",
            "project_id": "p1",
            "agent_id": "agent-key",
            "agent_row_id": "agent_row_1",
        },
        "catalogue": {"version": "0.1.0", "manifest_sha256": _DIGEST, "draft": True},
        "pack_versions": [{"framework_id": "FW-EU-AI-ACT", "semver": "0.1.0", "draft": True}],
        "files": [{"name": n, "sha256": _DIGEST, "bytes": 10} for n in _FILES],
        "completeness": {
            "coverage": _section(),
            "applicability": _section(),
            "attestations": _section(notes_withheld=0),
            "documents": _section(),
            "measurements": _section(),
            "change_history": _section(),
            "erased_identities": _section(),
            "tvl_offline_bundle": {"complete": False, "records": 0},
            "pdf": {"complete": False, "records": 0},
        },
        "limitations": ["Evidence coverage, not a compliance determination."],
        "integrity": "sha256 manifest",
        "pdf": "not_included",
        "pdf_reason": "none",
        "tvl_offline_bundle": "not_available",
        "tvl_offline_bundle_reason": "none",
        "contains_customer_content": True,
        "customer_content_note": "note",
    }


def test_manifest_is_valid_and_closed() -> None:
    assert _errors("Manifest", _manifest()) == []
    extra = {**_manifest(), "signature": "x"}
    assert _errors("Manifest", extra) != []


def test_manifest_integrity_is_a_digest_manifest_never_a_signature() -> None:
    for key, bad in (("integrity", "signed"), ("pdf", "included"), ("tvl_offline_bundle", "ok")):
        assert _errors("Manifest", {**_manifest(), key: bad}) != []


def test_manifest_requires_all_six_file_digests() -> None:
    manifest = _manifest()
    manifest["files"] = manifest["files"][:5]
    assert _errors("Manifest", manifest) != []
    manifest = _manifest()
    manifest["files"][0]["sha256"] = "xyz"
    assert _errors("Manifest", manifest) != []


def test_manifest_names_the_subject_it_is_about() -> None:
    manifest = _manifest()
    del manifest["subject"]
    assert _errors("Manifest", manifest) != []
    for key in ("tenant_id", "project_id", "agent_id", "agent_row_id"):
        broken = _manifest()
        del broken["subject"][key]
        assert _errors("Manifest", broken) != [], key
    assert _errors("Manifest", {**_manifest(), "subject": {**_manifest()["subject"], "x": 1}}) != []


def test_agent_row_id_accepts_the_agent_id_limit_of_512() -> None:
    for length, ok in ((1, True), (512, True), (513, False), (0, False)):
        manifest = _manifest()
        manifest["subject"]["agent_row_id"] = "a" * length
        assert (_errors("Manifest", manifest) == []) is ok, length


def _error_errors(instance: Any) -> list[str]:
    error_id = load_json(ERROR_PATH)["$id"]
    return ref_errors(_REGISTRY, error_id, instance)


_REAL_413 = {
    "success": False,
    "message": "Export too large",
    "error": "export_too_large",
    "error_code": "export_too_large",
}


def test_413_declares_the_export_specific_error_and_accepts_the_real_body() -> None:
    operation = next(iter(load_json(ENDPOINTS_PATH)["paths"].values()))["post"]
    ref = operation["responses"]["413"]["content"]["application/json"]["schema"]["$ref"]
    assert ref == "./compliance_export_error_schema.json"
    assert _error_errors(_REAL_413) == []


def test_413_error_is_closed_and_rejects_a_wrong_code() -> None:
    assert _error_errors({**_REAL_413, "error_code": "not_found"}) != []
    assert _error_errors({**_REAL_413, "error": "invalid_request"}) != []
    assert _error_errors({**_REAL_413, "message": "Not found"}) != []
    assert _error_errors({**_REAL_413, "detail": "x"}) != []


def test_request_is_the_empty_object() -> None:
    assert _errors("ExportRequest", {}) == []
    assert _errors("ExportRequest", {"format": "pdf"}) != []


def test_endpoint_returns_zip_and_declares_413_and_429() -> None:
    paths = load_json(ENDPOINTS_PATH)["paths"]
    assert len(paths) == 1
    operation = next(iter(paths.values()))["post"]
    assert operation["x-asserted-against-backend"] is False
    responses = operation["responses"]
    assert "application/zip" in responses["200"]["content"]
    assert responses["200"]["headers"]["Cache-Control"]["schema"]["enum"] == ["no-store"]
    assert {"400", "401", "403", "404", "413", "429"} <= set(responses)
    assert [p["name"] for p in operation["parameters"]] == ["project_id", "agent_id"]


def test_registered_and_free_of_determination_wording() -> None:
    assert "./agent_readiness/compliance_export_endpoints.json" in (
        SCHEMAS / "mep_endpoints.json"
    ).read_text(encoding="utf-8")
    for path in (SCHEMA_PATH, ENDPOINTS_PATH, ERROR_PATH):
        text = path.read_text(encoding="utf-8").lower()
        for word in ("compliant", "certified", "satisfies", "signed"):
            assert word not in text, (path.name, word)
