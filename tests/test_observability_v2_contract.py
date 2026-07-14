"""Observability Ingest v2 protocol contract (PR-1).

Publishes and gate-tests the v2 versioned-delta ingest contract described in
docs/architecture/cost-scale/14-observability-ingest-v2.md (protocol_version
"2.0"):

* the request envelope (§2.1) — scope is NEVER a client field;
* the six event kinds and their `data` deltas (§2.2);
* the authenticated object reference for large input/output (§2.1);
* the per-event status response and terminal states (§3.2);
* the stable error taxonomy and its code -> HTTP-status binding (§2.2/§3.1/§7).

Fixture files live in tests/test_data/observability_v2/. Naming is
self-describing: the prefix selects the target schema and the
`_valid` / `_invalid` suffix is the expected verdict, so new vectors
auto-register.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

DATA_DIR = Path(__file__).parent / "test_data" / "observability_v2"
OBS = get_schemas_dir() / "observability"

REQUEST_SCHEMA = "observability_v2_ingest_request_schema"
EVENT_SCHEMA = "observability_v2_event_schema"
STATUS_SCHEMA = "observability_v2_ingest_status_response_schema"
ERROR_SCHEMA = "observability_v2_error_schema"
OBJECT_REFERENCE_SCHEMA = "observability_v2_object_reference_schema"

# Fixture-filename prefix -> target schema name.
_PREFIX_SCHEMA = (
    ("object_reference_", OBJECT_REFERENCE_SCHEMA),
    ("request_", REQUEST_SCHEMA),
    ("event_", EVENT_SCHEMA),
    ("status_", STATUS_SCHEMA),
    ("error_", ERROR_SCHEMA),
)

EVENT_KINDS = [
    "trace.upsert",
    "trace.patch",
    "observation.upsert",
    "prompt_link.upsert",
    "prompt_link.delete",
    "trace.reparent",
]

ERROR_CODES = [
    "INGEST_ID_REUSE",
    "EVENT_ID_REUSE",
    "ENTITY_VERSION_COLLISION",
    "PENDING_VERSION_LIMIT",
    "VERSION_GAP",
    "VERSION_GAP_EXPIRED",
    "POSTGRES_ADMISSION_DEADLINE_EXCEEDED",
    "POSTGRES_ADMISSION_SLOW",
    "ADMISSION_BULKHEAD_SATURATED",
    "QUEUE_CAPACITY_EXHAUSTED",
    "EVENT_ID_EXPIRED",
    "OUTBOX_FULL",
    "SNAPSHOT_PROTOCOL_RETIRED",
]

# error_code -> ratified HTTP status (only the HTTP-surfaced codes).
CODE_HTTP_STATUS = {
    "INGEST_ID_REUSE": 409,
    "EVENT_ID_REUSE": 409,
    # ENTITY_VERSION_COLLISION: the owner-decided option-d claim gate detects
    # this atomically at ADMISSION (the global claim table's revision UNIQUE),
    # so -- unlike the materializer-terminal/SDK-side codes below -- it is a
    # synchronous client-integrity error at the admission edge, same family/
    # status as INGEST_ID_REUSE / EVENT_ID_REUSE (backend fix-contract review,
    # 2026-07). Corrected from a prior "no HTTP binding" classification.
    "ENTITY_VERSION_COLLISION": 409,
    "POSTGRES_ADMISSION_DEADLINE_EXCEEDED": 503,
    "POSTGRES_ADMISSION_SLOW": 503,
    "ADMISSION_BULKHEAD_SATURATED": 503,
    "QUEUE_CAPACITY_EXHAUSTED": 429,
    "SNAPSHOT_PROTOCOL_RETIRED": 410,
}


def _v() -> SchemaValidator:
    return SchemaValidator(contract="backend")


def _load_schema(name: str) -> dict:
    with open(OBS / f"{name}.json", encoding="utf-8") as handle:
        return json.load(handle)


def _load_fixture(name: str) -> dict:
    with open(DATA_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


def _schema_for_fixture(filename: str) -> str:
    for prefix, schema in _PREFIX_SCHEMA:
        if filename.startswith(prefix):
            return schema
    raise AssertionError(f"fixture {filename!r} has no known schema prefix")


def _fixtures(suffix: str) -> list[str]:
    return sorted(p.name for p in DATA_DIR.glob(f"*{suffix}.json"))


# --------------------------------------------------------------------------
# Fixture-driven accept / reject gate (STEP 4)
# --------------------------------------------------------------------------


def test_valid_and_invalid_fixtures_are_present():
    valid = _fixtures("_valid")
    invalid = _fixtures("_invalid")
    # Guard against an empty glob silently passing the parametrized gates.
    assert len(valid) >= 16, valid
    assert len(invalid) >= 10, invalid


@pytest.mark.parametrize("filename", _fixtures("_valid"))
def test_valid_fixtures_are_accepted(filename):
    errors = _v().validate_json(_load_fixture(filename), _schema_for_fixture(filename))
    assert errors == [], f"{filename} should be ACCEPTED: {errors}"


@pytest.mark.parametrize("filename", _fixtures("_invalid"))
def test_invalid_fixtures_are_rejected(filename):
    errors = _v().validate_json(_load_fixture(filename), _schema_for_fixture(filename))
    assert errors, f"{filename} should be REJECTED but validated clean"


# --------------------------------------------------------------------------
# Envelope + endpoint wiring (§2.1 / §3.2)
# --------------------------------------------------------------------------


def test_design_2_1_example_validates_verbatim():
    """The literal §2.1 envelope example is accepted (provenance anchor)."""
    example = {
        "protocol_version": "2.0",
        "ingest_id": "01JQ3A8T6CH3A7XVJQ1E2M8SNQ",
        "source": "traigent-python/1.18.0",
        "events": [
            {
                "event_id": "01JQ3A8V5JRZ0CN5Z2S9KYX6KA",
                "emitter_id": "01JQ3A7XW5K9J2N8M4P6R0T3V1",
                "emitter_version": 2,
                "occurred_at": "2026-07-12T10:15:28.001Z",
                "kind": "observation.upsert",
                "trace_id": "tr_123",
                "entity_id": "obs_llm_1",
                "data": {"type": "generation", "total_tokens": 368, "cost_usd": "0.001104"},
            }
        ],
    }
    assert _v().validate_json(example, REQUEST_SCHEMA) == []


def test_v2_events_endpoint_binds_request_schema():
    v = _v()
    assert v._endpoint_schemas.get("POST:/api/v2/observability/events") == REQUEST_SCHEMA
    # a concrete request validates through the endpoint path too
    assert (
        v.validate_request(
            "/api/v2/observability/events", "POST", _load_fixture("request_multi_event_valid.json")
        )
        == []
    )


def test_protocol_version_is_pinned_to_2_0():
    v = _v()
    req = _load_fixture("request_multi_event_valid.json")
    assert v.validate_json({**req, "protocol_version": "1.0"}, REQUEST_SCHEMA)
    no_version = {k: val for k, val in req.items() if k != "protocol_version"}
    assert v.validate_json(no_version, REQUEST_SCHEMA)


def test_scope_is_never_a_client_field():
    """tenant/project scope comes from the credential, not the request body."""
    v = _v()
    req = _load_fixture("request_multi_event_valid.json")
    for scope_field in ("tenant_id", "project_id", "customer_id"):
        assert v.validate_json({**req, scope_field: "x"}, REQUEST_SCHEMA), scope_field


def test_request_caps_events_at_100():
    v = _v()
    base_event = _load_fixture("request_multi_event_valid.json")["events"][0]
    over = {
        "protocol_version": "2.0",
        "ingest_id": "01JQ3A8T6CH3A7XVJQ1E2M8SNQ",
        "source": "traigent-python/1.18.0",
        "events": [base_event for _ in range(101)],
    }
    errors = v.validate_json(over, REQUEST_SCHEMA)
    assert any("maxItems" in e or "too long" in e for e in errors), errors


# --------------------------------------------------------------------------
# The six event kinds (§2.2)
# --------------------------------------------------------------------------


def test_event_schema_enumerates_exactly_the_six_kinds():
    schema = _load_schema(EVENT_SCHEMA)
    assert schema["definitions"]["EventKind"]["enum"] == EVENT_KINDS


def test_each_event_kind_has_a_valid_fixture():
    present = {_load_fixture(f)["kind"] for f in _fixtures("_valid") if f.startswith("event_")}
    assert set(EVENT_KINDS) <= present, set(EVENT_KINDS) - present


def test_event_requires_the_common_envelope_fields():
    v = _v()
    full = _load_fixture("event_observation_upsert_valid.json")
    for field in (
        "event_id",
        "emitter_id",
        "emitter_version",
        "occurred_at",
        "kind",
        "trace_id",
        "entity_id",
        "data",
    ):
        missing = {k: val for k, val in full.items() if k != field}
        assert v.validate_json(missing, EVENT_SCHEMA), f"missing {field} should be rejected"


def test_emitter_version_is_a_positive_integer():
    v = _v()
    ev = _load_fixture("event_trace_patch_valid.json")
    assert v.validate_json({**ev, "emitter_version": 0}, EVENT_SCHEMA)
    assert v.validate_json({**ev, "emitter_version": 1}, EVENT_SCHEMA) == []


# --------------------------------------------------------------------------
# Inline content vs object reference (§2.1)
#
# Small input/output stays inline within the 64-KiB canonical event cap;
# content that would exceed the cap uses an authenticated object reference.
# --------------------------------------------------------------------------


def test_object_reference_requires_content_addressed_fields():
    schema = _load_schema(OBJECT_REFERENCE_SCHEMA)
    assert set(schema["required"]) == {"key", "byte_count", "content_type", "sha256"}
    assert schema["additionalProperties"] is False


def test_object_reference_rejects_malformed_sha256():
    assert _v().validate_json(
        _load_fixture("object_reference_bad_sha256_invalid.json"), OBJECT_REFERENCE_SCHEMA
    )


def test_small_inline_content_is_accepted():
    """Small inline `input`/`output` is permitted alongside input_ref/output_ref."""
    assert (
        _v().validate_json(_load_fixture("request_inline_content_valid.json"), REQUEST_SCHEMA) == []
    )


def test_inline_string_content_over_the_event_cap_is_rejected():
    """Inline string content beyond the 64-KiB (x-max-event-bytes) cap must use input_ref."""
    fixture = _load_fixture("event_oversized_inline_invalid.json")
    assert len(fixture["data"]["input"]) > 65536
    assert _v().validate_json(fixture, EVENT_SCHEMA)


def test_inline_object_reference_and_inline_content_coexist():
    v = _v()
    # object-reference form (large payload) validates
    assert v.validate_json(_load_fixture("event_object_reference_valid.json"), EVENT_SCHEMA) == []
    # legacy v1 field names (input_data/output_data) are NOT part of the v2 wire
    assert v.validate_json(
        _load_fixture("request_legacy_input_data_field_invalid.json"), REQUEST_SCHEMA
    )


def test_event_schema_declares_the_event_byte_cap():
    schema = _load_schema(EVENT_SCHEMA)
    assert schema["x-max-event-bytes"] == 65536


# --------------------------------------------------------------------------
# Kind / entity identity (§2.2): trace-scoped kinds require entity_id == trace_id
#
# JSON Schema draft-07 cannot compare two sibling string values, so the schema
# DECLARES the equality via x-equal-to and the backend enforces it. The mismatch
# fixtures (entity_id != trace_id) are the backend-rejected vectors.
# --------------------------------------------------------------------------

TRACE_SCOPED_KINDS = ("trace.upsert", "trace.patch", "trace.reparent")
_MISMATCH_FIXTURES = {
    "trace.upsert": "event_trace_upsert_entity_trace_mismatch.json",
    "trace.patch": "event_trace_patch_entity_trace_mismatch.json",
    "trace.reparent": "event_trace_reparent_entity_trace_mismatch.json",
}


def test_trace_scoped_kinds_declare_entity_equals_trace_id():
    schema = _load_schema(EVENT_SCHEMA)
    declared = {}
    for branch in schema["allOf"]:
        kind = branch["if"]["properties"]["kind"].get("const")
        entity = branch["then"]["properties"].get("entity_id", {})
        if entity.get("x-equal-to"):
            declared[kind] = entity["x-equal-to"]
    for kind in TRACE_SCOPED_KINDS:
        assert declared.get(kind) == "#/properties/trace_id", kind
    # non-trace kinds must NOT force entity_id == trace_id (entity is obs/link id)
    for kind in ("observation.upsert", "prompt_link.upsert", "prompt_link.delete"):
        assert kind not in declared, kind


def test_entity_trace_mismatch_fixtures_violate_the_declared_rule():
    """Each mismatch fixture is a well-formed event whose entity_id != trace_id
    (the backend-enforced x-equal-to violation)."""
    for kind, fixture_name in _MISMATCH_FIXTURES.items():
        event = _load_fixture(fixture_name)
        assert event["kind"] == kind
        assert event["entity_id"] != event["trace_id"], fixture_name


# --------------------------------------------------------------------------
# Status response + terminal states (§3.2)
# --------------------------------------------------------------------------


def test_status_event_states_match_the_contract():
    schema = _load_schema(STATUS_SCHEMA)
    assert set(schema["definitions"]["EventState"]["enum"]) == {
        "ADMITTED",
        "DISPATCHING",
        "MATERIALIZING",
        "MATERIALIZED",
        "DUPLICATE",
        "PENDING_VERSION",
        "DEAD_LETTERED",
    }
    assert set(schema["definitions"]["ReplayOwner"]["enum"]) == {"tenant", "platform", None}


def test_dead_letter_record_requires_reason_and_replay_owner():
    assert _v().validate_json(
        _load_fixture("status_dead_letter_missing_reason_invalid.json"), STATUS_SCHEMA
    )


def test_all_terminal_states_require_reason_and_owner_keys():
    """MATERIALIZED / DUPLICATE / DEAD_LETTERED must carry terminal_reason and
    replay_owner keys (may be null for a clean MATERIALIZED); event_hash is
    globally required. A MATERIALIZED record missing them is rejected."""
    v = _v()
    assert v.validate_json(
        _load_fixture("status_materialized_missing_terminal_fields_invalid.json"), STATUS_SCHEMA
    )
    # present-but-null reason/owner is accepted for MATERIALIZED
    ok = {
        "ingest_id": "01JQ3A8T6CH3A7XVJQ1E2M8SNQ",
        "manifest_state": "COMPLETED",
        "events_detail_available": True,
        "events": [
            {
                "event_id": "01JQ3A8V5JRZ0CN5Z2S9KYX6KA",
                "state": "MATERIALIZED",
                "event_hash": "a" * 64,
                "attempted_count": 1,
                "capacity_disposition": "CONSUMED",
                "quota_disposition": "CONSUMED",
                "terminal_reason": None,
                "replay_owner": None,
            }
        ],
    }
    assert v.validate_json(ok, STATUS_SCHEMA) == []


def test_status_response_requires_events_detail_available_field():
    """`events_detail_available` is now REQUIRED (gate finding NEW-2): a
    manifest whose per-event receipts have age-purged (14-observability-
    ingest-v2.md §5.2) reports `events: []` honestly, distinguished from
    "detail is available" by this field -- so the field itself can no longer
    be omitted."""
    empty = {
        "ingest_id": "01JQ3A8T6CH3A7XVJQ1E2M8SNQ",
        "manifest_state": "ADMITTED",
        "events": [],
    }
    assert _v().validate_json(empty, STATUS_SCHEMA)


def test_empty_events_is_valid_only_when_detail_is_reported_unavailable():
    """Empty `events[]` is now a legitimate response shape (receipts purged
    past their 7-day retention while the manifest survives, §5.2) -- but ONLY
    paired with `events_detail_available: false`. Claiming detail is
    available with zero events is incoherent and still rejected: every
    admitted event gets exactly one receipt in the same admission
    transaction (§3.1), so "detail available" + "zero events" cannot happen
    honestly."""
    v = _v()
    base = {
        "ingest_id": "01JQ3A8T6CH3A7XVJQ1E2M8SNQ",
        "manifest_state": "ADMITTED",
        "events": [],
    }
    assert v.validate_json({**base, "events_detail_available": False}, STATUS_SCHEMA) == []
    assert v.validate_json({**base, "events_detail_available": True}, STATUS_SCHEMA)

    # CONVERSE guard: reporting detail UNAVAILABLE with a NON-EMPTY events[] is
    # fabricated per-event detail and rejected. The record used is otherwise
    # fully valid (taken from status_terminal_valid.json), so ONLY the
    # false-with-events incoherence can be what fails -- and the same payload
    # with events_detail_available: true is accepted.
    record = _load_fixture("status_terminal_valid.json")["events"][0]
    populated = {**base, "events": [record]}
    assert v.validate_json({**populated, "events_detail_available": False}, STATUS_SCHEMA)
    assert (
        v.validate_json({**populated, "events_detail_available": True}, STATUS_SCHEMA) == []
    )


def test_get_status_declares_required_ingest_id_path_parameter():
    with open(OBS / "observability_endpoints.json", encoding="utf-8") as handle:
        catalog = json.load(handle)
    op = catalog["paths"]["/api/v2/observability/ingests/{ingest_id}"]["get"]
    params = {p["name"]: p for p in op.get("parameters", [])}
    assert "ingest_id" in params, "GET status must declare the ingest_id path parameter"
    assert params["ingest_id"]["in"] == "path"
    assert params["ingest_id"]["required"] is True
    ref = params["ingest_id"]["schema"]["$ref"]
    assert ref.endswith("observability_v2_event_schema.json#/definitions/MonotonicId"), ref


# --------------------------------------------------------------------------
# Error taxonomy + code -> HTTP-status binding (§2.2/§3.1/§7)
# --------------------------------------------------------------------------


def test_error_taxonomy_lists_all_stable_codes():
    schema = _load_schema(ERROR_SCHEMA)
    assert set(schema["definitions"]["ErrorCode"]["enum"]) == set(ERROR_CODES)
    assert set(schema["x-error-catalog"]) == set(ERROR_CODES)


@pytest.mark.parametrize(("code", "status"), sorted(CODE_HTTP_STATUS.items()))
def test_http_surfaced_codes_bind_their_ratified_status(code, status):
    v = _v()
    body = {
        "success": False,
        "error": code.lower(),
        "error_code": code,
        "message": "m",
        "http_status": status,
    }
    if status in (429, 503):
        body["retry_after"] = 1
    assert v.validate_json(body, ERROR_SCHEMA) == [], code
    # a different (in-enum) status for the same code is a contract violation
    wrong = 429 if status != 429 else 503
    assert v.validate_json({**body, "http_status": wrong}, ERROR_SCHEMA), code


def test_snapshot_protocol_retired_is_410_only():
    assert (
        _v().validate_json(
            _load_fixture("error_snapshot_protocol_retired_410_valid.json"), ERROR_SCHEMA
        )
        == []
    )
    assert _v().validate_json(
        _load_fixture("error_snapshot_wrong_status_invalid.json"), ERROR_SCHEMA
    )


NO_HTTP_BINDING_CODES = [
    "PENDING_VERSION_LIMIT",
    "VERSION_GAP",
    "VERSION_GAP_EXPIRED",
    "EVENT_ID_EXPIRED",
    "OUTBOX_FULL",
]


@pytest.mark.parametrize("code", NO_HTTP_BINDING_CODES)
def test_terminal_and_sdk_codes_forbid_http_status(code):
    """Codes the design gives no HTTP binding must not carry http_status/retry_after."""
    v = _v()
    base = {"success": False, "error": code.lower(), "error_code": code, "message": "m"}
    assert v.validate_json(base, ERROR_SCHEMA) == [], code
    assert v.validate_json({**base, "http_status": 409}, ERROR_SCHEMA), code
    assert v.validate_json({**base, "retry_after": 1}, ERROR_SCHEMA), code


def test_x_error_catalog_status_matches_binding():
    catalog = _load_schema(ERROR_SCHEMA)["x-error-catalog"]
    for code, status in CODE_HTTP_STATUS.items():
        assert catalog[code]["http_status"] == status, code
    for code in NO_HTTP_BINDING_CODES:
        assert catalog[code]["http_status"] is None, code


def test_v1beta_ingest_publishes_typed_410_retirement_response():
    with open(OBS / "observability_endpoints.json", encoding="utf-8") as handle:
        catalog = json.load(handle)
    for path in (
        "/api/v1beta/observability/ingest",
        "/api/v1beta/projects/{project_id}/observability/ingest",
    ):
        responses = catalog["paths"][path]["post"]["responses"]
        assert "410" in responses, path
        ref = responses["410"]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("observability_v2_error_schema.json"), (path, ref)
