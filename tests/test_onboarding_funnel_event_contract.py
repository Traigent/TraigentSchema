# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the cross-repo onboarding-funnel event (funnel.v1).

A single funnel.v1 event is one observation of a lead moving through onboarding:
``{run_id, ts, stage, event, actor, outcome, meta?}``. The tests are ADVERSARIAL
first: each submits the payload a careless or motivated emitter would send and
asserts the contract rejects it; the positive cases (every stage, the on-disk
per-stage fixtures) exist to prove the strictness did not also reject honest
telemetry.

Invariants JSON Schema cannot enforce (tenant ownership of run_id, funnel
stage-order across separate events, meta redaction) are NOT tested here — they
are not provable here. They are asserted to be *declared* as backend obligations,
so the next packet inherits a visible list rather than an assumption.
"""

from __future__ import annotations

import json
from pathlib import Path

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA = "onboarding_funnel_event_schema"

_SCHEMA_PATH = get_schemas_dir() / "onboarding" / "onboarding_funnel_event_schema.json"
_FIXTURES_DIR = Path(__file__).resolve().parent / "test_data" / "onboarding"

_STAGES = ["discover", "verify", "handoff", "assess", "baseline", "account", "key", "enhanced"]


def _v() -> SchemaValidator:
    return SchemaValidator()


def _load_schema() -> dict:
    with open(_SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _ok(payload: dict) -> bool:
    return _v().validate_json(payload, SCHEMA) == []


def _rejected(payload: dict) -> bool:
    return _v().validate_json(payload, SCHEMA) != []


def _event(**extra) -> dict:
    """A complete, honest funnel.v1 event. Overriding one key exercises exactly it."""
    event = {
        "run_id": "lead-9f3a.evt-01",
        "ts": "2026-07-18T09:00:00Z",
        "stage": "discover",
        "event": "funnel_entered",
        "actor": "system",
        "outcome": "ok",
    }
    event.update(extra)
    return event


# --------------------------------------------------------------------------- #
# posture: the schema auto-resolves and its declared obligations are visible
# --------------------------------------------------------------------------- #
def test_schema_resolves_and_the_honest_event_validates() -> None:
    assert SCHEMA in _v().available_schemas, "the schema must auto-discover by filename"
    assert _ok(_event()), "a complete, honest funnel.v1 event must validate"


def test_backend_obligations_are_declared_and_non_empty() -> None:
    """The invariants this per-event contract cannot enforce (tenant ownership of
    run_id, cross-event stage ordering, meta redaction) must be enumerated as backend
    obligations, so the gap is documented rather than assumed proven."""
    schema = _load_schema()
    obligations = schema.get("x-backend-obligations")
    assert isinstance(obligations, list) and obligations, (
        "x-backend-obligations must be a declared, non-empty list"
    )
    assert all(isinstance(item, str) and item.strip() for item in obligations)
    assert schema["x-stability"] == "pre-release"
    assert schema["x-asserted-against-backend"] is False


def test_the_contract_is_self_described_as_funnel_v1() -> None:
    schema = _load_schema()
    assert "funnel.v1" in schema["title"] or "funnel.v1" in schema["description"]
    assert schema["properties"]["schema"]["const"] == "funnel.v1"


# --------------------------------------------------------------------------- #
# stages
# --------------------------------------------------------------------------- #
def test_every_stage_is_representable() -> None:
    assert _load_schema()["properties"]["stage"]["enum"] == _STAGES
    for stage in _STAGES:
        assert _ok(_event(stage=stage)), stage


def test_unknown_stage_is_rejected() -> None:
    for stage in ("onboarded", "DISCOVER", "", "assess "):
        assert _rejected(_event(stage=stage)), stage


# --------------------------------------------------------------------------- #
# closed vocabularies: actor and outcome
# --------------------------------------------------------------------------- #
def test_actor_enum_is_closed() -> None:
    for actor in ("human", "agent", "system"):
        assert _ok(_event(actor=actor)), actor
    for bad in ("robot", "user", "Human", ""):
        assert _rejected(_event(actor=bad)), bad


def test_outcome_enum_is_closed() -> None:
    for outcome in ("ok", "retry", "fail", "abandon"):
        assert _ok(_event(outcome=outcome)), outcome
    for bad in ("success", "OK", "cancelled", ""):
        assert _rejected(_event(outcome=bad)), bad


# --------------------------------------------------------------------------- #
# required fields and the closed top-level shape
# --------------------------------------------------------------------------- #
def test_each_required_field_is_enforced_when_omitted() -> None:
    for field in ("run_id", "ts", "stage", "event", "actor", "outcome"):
        event = _event()
        del event[field]
        assert _rejected(event), f"{field}: a funnel event is incomplete without it"


def test_additional_top_level_keys_are_rejected() -> None:
    """A client-asserted tenant field, or any other unknown key, must not be
    representable: tenant/project scope is derived from the authenticated context,
    never from the event body."""
    assert _rejected(_event(tenant_id="t-other")), "a client-asserted tenant field must be rejected"
    assert _rejected(_event(surprise=1))
    # the optional, declared keys are still accepted
    assert _ok(_event(schema="funnel.v1"))
    assert _ok(_event(meta={"note": "reported"}))


# --------------------------------------------------------------------------- #
# run_id: opaque public id, shape-only guarantee
# --------------------------------------------------------------------------- #
def test_run_id_pattern_rejects_whitespace_and_at_sign() -> None:
    for bad in ("has spaces", "lead@example.com", "lead\t01", "", "a" * 129):
        assert _rejected(_event(run_id=bad)), bad
    for good in ("lead-9f3a.evt-01", "run_1:2.3-4", "A0"):
        assert _ok(_event(run_id=good)), good


def test_run_id_is_marked_an_identifier_and_is_public_only() -> None:
    run_id = _load_schema()["properties"]["run_id"]
    assert run_id["x-identifier"] is True
    assert run_id["pattern"] == "^[A-Za-z0-9_.:-]+$"


# --------------------------------------------------------------------------- #
# event: bounded opaque identifier label
# --------------------------------------------------------------------------- #
def test_event_is_a_bounded_identifier_label() -> None:
    for good in ("funnel_entered", "identity_verified", "enhanced_run_started", "v1.2"):
        assert _ok(_event(event=good)), good
    for bad in ("has spaces", "trailing_newline\n", "", "e" * 129):
        assert _rejected(_event(event=bad)), bad


# --------------------------------------------------------------------------- #
# ts: RFC-3339 UTC with a trailing Z, no local offset
# --------------------------------------------------------------------------- #
def test_ts_rejects_a_local_offset_and_other_non_utc_forms() -> None:
    """`format: date-time` also admits a local offset, so an offset-bearing timestamp
    read as UTC silently moves an event by hours and reorders the funnel. The stated
    form (trailing Z) is enforced, not merely described."""
    for bad in (
        "2026-07-18T09:00:00+03:00",  # the same instant, read three hours early
        "2026-07-18T09:00:00-05:00",
        "2026-07-18T09:00:00",  # no zone at all
        "2026-07-18 09:00:00Z",  # not RFC-3339
        "2026-07-18T09:00:00z",  # lowercase z is not the stated form
        "2026-07-18",
        "yesterday",
        "",
    ):
        assert _rejected(_event(ts=bad)), bad
    for good in ("2026-07-18T09:00:00Z", "2026-07-18T09:00:00.123Z", "2026-07-18T09:00:00.123456Z"):
        assert _ok(_event(ts=good)), good


# --------------------------------------------------------------------------- #
# meta: optional, bounded, user content
# --------------------------------------------------------------------------- #
def test_meta_is_optional_bounded_and_classified_as_user_content() -> None:
    assert _ok(_event()), "meta is optional"
    assert _ok(_event(meta={})), "an empty meta object is allowed"
    assert _rejected(_event(meta="a note")), "meta must be an object, not free text"
    oversized = {f"k{i}": i for i in range(65)}
    assert _rejected(_event(meta=oversized)), "meta is bounded (maxProperties)"
    meta = _load_schema()["properties"]["meta"]
    assert meta["x-content"] is True
    assert meta["x-privacy-classification"] == "user_content"


# --------------------------------------------------------------------------- #
# on-disk fixtures: one honest example per stage validates
# --------------------------------------------------------------------------- #
def test_every_on_disk_stage_fixture_validates() -> None:
    seen: set[str] = set()
    for path in sorted(_FIXTURES_DIR.glob("funnel_event_*.json")):
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        assert _ok(payload), f"{path.name} must validate against funnel.v1"
        seen.add(payload["stage"])
    assert seen == set(_STAGES), f"fixtures must cover every stage; missing {set(_STAGES) - seen}"
