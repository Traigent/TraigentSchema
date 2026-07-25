"""Backend wire-shape conformance for the observability ingest v2 contract.

`tests/test_observability_v2_contract.py` gates the contract against its own
fixtures. This module gates it against the bytes **TraigentBackend actually
emits** on the two v2 routes, so the two repos cannot drift silently from
either side. Every instance below is transcribed from the backend's real
response-building code on `TraigentBackend@obs/ingest-v2-integration`
(d9c437b9):

* ``src/services/observability_ingest_status_service.py`` —
  ``IngestStatus.to_dict()`` / ``EventStatusRecord.to_dict()`` produce the
  status body's exact key set;
* ``src/routes/observability_ingest_v2_routes.py`` —
  ``_admission_error_response()`` builds the typed-refusal body
  (``success`` / ``error`` / ``error_code`` / ``message`` / ``http_status``,
  plus ``retry_after`` and ``details`` only when set), and
  ``_with_taxonomy_http_status()`` stamps ``http_status`` on the GENERIC
  413/422/404 refusals that this taxonomy deliberately does not cover.

**The status schema describes the envelope's ``data`` member, not the whole
envelope** (owner-decided "option c"). The backend returns
``success_response(data=status.to_dict(), ...)`` and its own conformance guard
(`tests/unit/routes/test_observability_ingest_v2_contract_conformance.py`)
validates ``response.get_json()["data"]``. The error bodies are the OPPOSITE:
``_admission_error_response`` builds a FLAT body (no ``data`` member), so the
error schema describes the whole body. Both directions are pinned below.

The frozen-negative tests mirror the backend's
``test_generic_request_shape_error_codes_are_not_in_the_v2_error_taxonomy``,
which asserts that ``ErrorCode`` excludes ``PAYLOAD_TOO_LARGE`` /
``VALIDATION_ERROR`` / ``NOT_FOUND`` and that ``http_status`` has no 404.
Widening either enum here would silently break that backend test, so these
tests exist to make such a change a deliberate, visible cross-repo decision.
"""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft7Validator

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OBS = get_schemas_dir() / "observability"

STATUS_SCHEMA = "observability_v2_ingest_status_response_schema"
ERROR_SCHEMA = "observability_v2_error_schema"

# A 26-char Crockford ULID and a lowercase-hex SHA-256, matching the
# MonotonicId / Sha256Hex definitions the backend's receipts satisfy.
INGEST_ID = "01JZQ8F5M3N7P9R2T4V6W8X0Y1"
EVENT_ID_A = "01JZQ8F5M3N7P9R2T4V6W8X0Y2"
EVENT_ID_B = "01JZQ8F5M3N7P9R2T4V6W8X0Y3"
EVENT_HASH = "3b1f" + "0" * 60


def _v() -> SchemaValidator:
    return SchemaValidator(contract="backend")


def _load(name: str) -> dict:
    with open(OBS / f"{name}.json", encoding="utf-8") as handle:
        return json.load(handle)


def _record(**overrides) -> dict:
    """The exact key set ``EventStatusRecord.to_dict()`` emits (all nine keys
    are always present; the terminal ones are null for a non-terminal event)."""
    record = {
        "event_id": EVENT_ID_A,
        "state": "ADMITTED",
        "event_hash": EVENT_HASH,
        "attempted_count": 0,
        "capacity_disposition": "RESERVED",
        "quota_disposition": "RESERVED",
        "terminal_reason": None,
        "terminal_code": None,
        "replay_owner": None,
    }
    record.update(overrides)
    return record


def _status(**overrides) -> dict:
    """The exact key set ``IngestStatus.to_dict()`` emits."""
    status = {
        "ingest_id": INGEST_ID,
        "manifest_state": "ADMITTED",
        "events_detail_available": True,
        "events": [_record()],
    }
    status.update(overrides)
    return status


def _admission_error(code: str, status: int, **extra) -> dict:
    """The exact body ``_admission_error_response()`` builds for an
    ``AdmissionError``: ``error`` and ``error_code`` both carry the code,
    ``http_status`` mirrors the HTTP status line, and ``retry_after`` /
    ``details`` appear only when the exception carries them."""
    body = {
        "success": False,
        "error": code,
        "error_code": code,
        "message": f"{code} refusal",
        "http_status": status,
    }
    body.update(extra)
    return body


# --------------------------------------------------------------------------
# Both schemas are structurally valid JSON Schema draft-07.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", [STATUS_SCHEMA, ERROR_SCHEMA])
def test_schema_is_valid_draft_07(name):
    schema = _load(name)
    assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
    assert schema["$id"] == f"https://schemas.traigent.ai/observability/{name}.json"
    Draft7Validator.check_schema(schema)


# --------------------------------------------------------------------------
# Status: the real POST-202 / GET-200 `data` members.
# --------------------------------------------------------------------------


def test_admitted_only_status_body_validates():
    """POST /api/v2/observability/events 202 right after admission: every
    receipt is ADMITTED with a RESERVED capacity/quota disposition and zero
    delivery attempts."""
    body = _status(events=[_record(), _record(event_id=EVENT_ID_B)])
    assert _v().validate_json(body, STATUS_SCHEMA) == []


def test_mixed_materialized_and_dead_lettered_status_body_validates():
    """GET 200 after one event materialized and one dead-lettered: the
    manifest rolls up to PARTIALLY_DEAD_LETTERED, the dead-letter record
    carries the sanitized reason text, its taxonomy code and a replay owner,
    and the clean MATERIALIZED record carries those keys as nulls."""
    body = _status(
        manifest_state="PARTIALLY_DEAD_LETTERED",
        events=[
            _record(
                state="MATERIALIZED",
                capacity_disposition="CONSUMED",
                quota_disposition="CONSUMED",
            ),
            _record(
                event_id=EVENT_ID_B,
                state="DEAD_LETTERED",
                attempted_count=3,
                capacity_disposition="RELEASED",
                quota_disposition="RELEASED",
                terminal_reason=(
                    "This event's emitter was blocked by an earlier unresolved version "
                    "gap; the emitter must resume with a new emitter ID."
                ),
                terminal_code="VERSION_GAP_EXPIRED",
                replay_owner="tenant",
            ),
        ],
    )
    assert _v().validate_json(body, STATUS_SCHEMA) == []


def test_purged_receipts_status_body_validates():
    """GET 200 after the day-7 receipt purge: the manifest still exists, so
    the response is not a 404 — it reports zero events and declares the
    per-event detail unavailable rather than guessing states."""
    body = _status(events=[], events_detail_available=False)
    assert _v().validate_json(body, STATUS_SCHEMA) == []


def test_poison_dead_letter_without_a_taxonomy_code_validates():
    """The backend maps terminal_reason POISON to ``terminal_code: None`` (the
    v2 taxonomy has no POISON code), so a DEAD_LETTERED record with a null
    terminal_code but a non-null reason/owner must still validate."""
    body = _status(
        manifest_state="DEAD_LETTERED",
        events=[
            _record(
                state="DEAD_LETTERED",
                attempted_count=5,
                capacity_disposition="RELEASED",
                quota_disposition="RELEASED",
                terminal_reason=(
                    "The event could not be applied after repeated delivery attempts "
                    "(a malformed payload or a permanent integrity error)."
                ),
                terminal_code=None,
                replay_owner="tenant",
            )
        ],
    )
    assert _v().validate_json(body, STATUS_SCHEMA) == []


def test_status_schema_describes_the_data_member_not_the_envelope():
    """Owner-decided "option c": the repo keeps its ``{success, message, data}``
    envelope and this schema describes ``data``. Handing it the whole envelope
    must therefore FAIL — if it ever validated, the schema would be describing
    two incompatible shapes at once and the backend's
    ``response.get_json()["data"]`` guard would be meaningless."""
    envelope = {"success": True, "message": "Observability v2 events admitted", "data": _status()}
    assert _v().validate_json(envelope, STATUS_SCHEMA)


# --------------------------------------------------------------------------
# Errors: the real `_admission_error_response()` bodies.
# --------------------------------------------------------------------------


def test_entity_version_collision_409_body_validates():
    body = _admission_error("ENTITY_VERSION_COLLISION", 409)
    assert "retry_after" not in body
    assert _v().validate_json(body, ERROR_SCHEMA) == []


def test_cross_ingest_event_id_reuse_409_body_validates():
    body = _admission_error("EVENT_ID_REUSE", 409, details={"reason": "cross_ingest_reuse"})
    assert _v().validate_json(body, ERROR_SCHEMA) == []


def test_admission_bulkhead_saturated_503_body_validates():
    body = _admission_error("ADMISSION_BULKHEAD_SATURATED", 503, retry_after=1)
    assert _v().validate_json(body, ERROR_SCHEMA) == []


def test_queue_capacity_exhausted_429_body_validates():
    body = _admission_error("QUEUE_CAPACITY_EXHAUSTED", 429, retry_after=1)
    assert _v().validate_json(body, ERROR_SCHEMA) == []


def test_back_pressure_codes_require_retry_after():
    """503/429 refusals tell the SDK when to retry the identical ingest_id;
    dropping ``retry_after`` from the body must not validate."""
    for code, status in (("ADMISSION_BULKHEAD_SATURATED", 503), ("QUEUE_CAPACITY_EXHAUSTED", 429)):
        assert _v().validate_json(_admission_error(code, status), ERROR_SCHEMA), code


# --------------------------------------------------------------------------
# FROZEN NEGATIVES — mirrored from the backend's own
# test_generic_request_shape_error_codes_are_not_in_the_v2_error_taxonomy.
# Widening either enum breaks that backend test; keep these red-on-widening.
# --------------------------------------------------------------------------

GENERIC_REQUEST_SHAPE_CODES = ["PAYLOAD_TOO_LARGE", "VALIDATION_ERROR", "NOT_FOUND"]


@pytest.mark.parametrize("code", GENERIC_REQUEST_SHAPE_CODES)
def test_generic_request_shape_codes_are_not_in_the_closed_taxonomy(code):
    assert code not in _load(ERROR_SCHEMA)["definitions"]["ErrorCode"]["enum"]


def test_http_status_enum_has_no_404():
    """The GET status route's 404 is a generic ``not_found_response`` body, not
    an admission-taxonomy refusal, so 404 is deliberately absent here."""
    assert 404 not in _load(ERROR_SCHEMA)["properties"]["http_status"]["enum"]


@pytest.mark.parametrize(
    ("code", "status"),
    [("PAYLOAD_TOO_LARGE", 413), ("VALIDATION_ERROR", 422), ("NOT_FOUND", 404)],
)
def test_generic_refusal_bodies_do_not_validate(code, status):
    """A real generic refusal body (``error_response`` + the route's
    ``http_status`` stamp) must NOT validate against the closed v2 taxonomy."""
    body = {
        "success": False,
        "error": code,
        "error_code": code,
        "message": f"{code} refusal",
        "http_status": status,
    }
    assert _v().validate_json(body, ERROR_SCHEMA), code
