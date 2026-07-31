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

_STAGES = [
    "discover",
    "verify",
    "handoff",
    "assess",
    "baseline",
    "account",
    "access_period_started",
    "key",
    "enhanced",
    "access_period_ended",
    "access_restored",
]


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
        "schema": "funnel.v1",
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


def test_near_miss_access_period_spellings_are_rejected() -> None:
    """The three access-period stages were named in full precisely because the short
    forms are ambiguous, so the short forms must not quietly validate. A producer that
    emits bare 'access' or 'lapse' has invented an unnamed stage; a producer that emits
    'ACCESS_PERIOD_STARTED' or a trailing-space variant has emitted a value no consumer
    can group with the canonical one. Both fail here rather than in the funnel report."""
    for stage in (
        "access",
        "access_period",
        "lapse",
        "restore",
        "restored",
        "access_period_start",
        "access_period_end",
        "ACCESS_PERIOD_STARTED",
        "Access_Period_Started",
        "access_period_started ",
        " access_period_started",
        "access-period-started",
        "access period started",
        "access_restored\n",
    ):
        assert _rejected(_event(stage=stage)), repr(stage)


def test_stage_description_pins_the_non_authorizing_key_and_the_lapse_outcome_rule() -> None:
    """Two decisions in this packet live in prose because enforcing them in-schema would
    over-constrain a producer that does not exist yet (see the reconciled plan §3, §4).
    Prose drifts unless something asserts it, so both are pinned here:

    1. `key` is API-key issuance and is NON-AUTHORIZING — a key authenticates a caller and
       never entitles one. This is the confusion the whole access-period split exists to
       prevent, so the contract must say it out loud.
    2. A lifecycle observation of the access period carries `outcome: "ok"` — the
       observation succeeded. `abandon` means "the lead stopped without completing", and a
       period elapsing is time passing, not the lead stopping; recording it as `abandon`
       would encode a behavioural claim from a temporal fact and corrupt drop-off analytics
       silently once two surfaces disagree.
    """
    description = _load_schema()["properties"]["stage"]["description"].lower()
    assert "non-authorizing" in description, "the contract must state that `key` is non-authorizing"
    assert "a key is a credential, never the entitlement" in description
    assert "outcome 'ok'" in description or 'outcome "ok"' in description, (
        "the lifecycle-observation outcome rule must be stated, not left to a reader"
    )
    assert "drop-off is not inferred from it" in description
    # ordering is documentation, and the contract must say so rather than imply enforcement
    assert "order is not enforced here" in description


def test_stage_description_does_not_disclose_credential_mechanics() -> None:
    """The public-repo leak guard, mirroring the one on run_id
    (`test_run_id_is_marked_an_identifier_and_described_as_public_only`). Describing the
    access period is legitimate; describing how a credential is minted or how long a code
    lives is disclosure, and this description is the natural place for it to creep in."""
    description = _load_schema()["properties"]["stage"]["description"].lower()
    for leaked in ("token", "six-digit", "six digit", "access code", "single-use", "secret"):
        assert leaked not in description, f"stage description must not disclose {leaked!r}"


def test_access_period_linkage_is_declared_as_a_backend_obligation() -> None:
    """`access_period_ended` and `access_restored` fire long after the originating
    onboarding attempt, so the run_id correlation must outlive the attempt — something no
    per-event schema can check. And the period's duration/deadline/policy are deliberately
    NOT on the wire, so that omission must read as a decision rather than an oversight."""
    obligations = _load_schema()["x-backend-obligations"]
    linkage = [o for o in obligations if "access_period_ended" in o]
    assert len(linkage) == 1, "exactly one obligation must own access-period linkage"
    entry = linkage[0].lower()
    assert "access_restored" in entry
    assert "run_id" in entry, "the obligation must name the correlation the producer must retain"
    assert "duration" in entry and "deadline" in entry and "policy" in entry, (
        "the obligation must say what this contract deliberately does NOT carry"
    )
    assert "server-side" in entry, "and that those are resolved server-side instead"


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
    for field in ("schema", "run_id", "ts", "stage", "event", "actor", "outcome"):
        event = _event()
        del event[field]
        assert _rejected(event), f"{field}: a funnel event is incomplete without it"


def test_wire_version_is_required_and_pinned() -> None:
    """`schema` is REQUIRED, not an optional const: a versionless event validating
    would be a forward-compat hazard once the closed enums evolve, because a consumer
    could not tell a funnel.v1 event from a later, differently-shaped one. Omitting it
    is rejected, and only the exact 'funnel.v1' value is accepted."""
    assert "schema" in _load_schema()["required"]
    versionless = _event()
    del versionless["schema"]
    assert _rejected(versionless), "a versionless event must not validate"
    assert _rejected(_event(schema="funnel.v2")), "a mismatched contract version is rejected"
    assert _rejected(_event(schema="")), "an empty version is rejected"
    assert _ok(_event(schema="funnel.v1"))


def test_additional_top_level_keys_are_rejected() -> None:
    """A client-asserted tenant field, or any other unknown key, must not be
    representable: tenant/project scope is derived from the authenticated context,
    never from the event body."""
    assert _rejected(_event(tenant_id="t-other")), "a client-asserted tenant field must be rejected"
    assert _rejected(_event(surprise=1))
    # the declared keys (required schema, optional meta) are still accepted
    assert _ok(_event(schema="funnel.v1"))
    assert _ok(_event(meta={"note": "reported"}))


# --------------------------------------------------------------------------- #
# run_id: opaque public id, shape-only guarantee
# --------------------------------------------------------------------------- #
def test_run_id_pattern_rejects_whitespace_at_sign_newline_and_punctuation_only() -> None:
    bad = (
        "has spaces",
        "lead@example.com",
        "lead\t01",
        "lead-1\n",  # a trailing newline: Python '$' would admit this, the lookahead must not
        "\nlead-1",
        "...",  # punctuation-only, no alphanumeric boundary
        "-lead",  # must start with an alphanumeric
        "lead-",  # must end with an alphanumeric
        " x",  # leading whitespace
        "",
        "a" * 129,  # over maxLength
    )
    for value in bad:
        assert _rejected(_event(run_id=value)), repr(value)
    for good in ("lead-9f3a.evt-01", "run_1:2.3-4", "A0", "leadrun_ab12", "a"):
        assert _ok(_event(run_id=good)), good


def test_run_id_is_marked_an_identifier_and_described_as_public_only() -> None:
    run_id = _load_schema()["properties"]["run_id"]
    assert run_id["x-identifier"] is True
    # the anchor is a negative lookahead, not '$', so a trailing newline is rejected
    assert run_id["pattern"] == "^[A-Za-z0-9]([A-Za-z0-9_.:-]*[A-Za-z0-9])?(?![\\s\\S])"
    # the public-repo leak guard: run_id is described only as an opaque public id, with
    # no disclosure of any onboarding secret/token/credential mechanism
    description = run_id["description"].lower()
    assert "opaque public correlation id" in description
    for leaked in ("token", "single-use", "secret token"):
        assert leaked not in description, f"run_id description must not disclose {leaked!r}"


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
        "2026-07-18T09:00:00.1234567890Z",  # 10 fractional digits: outside the ≤9-digit subset
    ):
        assert _rejected(_event(ts=bad)), bad
    for good in (
        "2026-07-18T09:00:00Z",
        "2026-07-18T09:00:00.123Z",
        "2026-07-18T09:00:00.123456Z",
        "2026-07-18T09:00:00.123456789Z",  # the subset admits up to nanosecond (9-digit) precision
    ):
        assert _ok(_event(ts=good)), good


# --------------------------------------------------------------------------- #
# meta: optional, bounded, user content
# --------------------------------------------------------------------------- #
def test_meta_is_optional_bounded_and_classified_as_user_content() -> None:
    assert _ok(_event()), "meta is optional"
    assert _ok(_event(meta={})), "an empty meta object is allowed"
    assert _ok(_event(meta={"note": "reported"})), "a bounded string->string map is allowed"
    assert _rejected(_event(meta="a note")), "meta must be an object, not free text"
    # bounded key count (maxProperties): string values isolate this to the key count
    too_many = {f"k{i}": "v" for i in range(65)}
    assert _rejected(_event(meta=too_many)), "meta is bounded (maxProperties)"
    assert _ok(_event(meta={f"k{i}": "v" for i in range(64)})), "64 keys is the ceiling"
    # bounded per-value size (maxLength via additionalProperties): a 1 MB value is
    # rejected even though maxProperties and x-max-event-bytes alone would not catch it
    assert _ok(_event(meta={"note": "x" * 8192})), "8192 chars is the per-value ceiling"
    assert _rejected(_event(meta={"note": "x" * 8193})), "an oversized meta value is rejected"
    assert _rejected(_event(meta={"note": "x" * 1_000_000})), "a ~1 MB meta value is rejected"
    # meta values are strings: a structured/numeric value is not representable
    assert _rejected(_event(meta={"attempt": 3})), "meta is a string map, not structured data"
    meta = _load_schema()["properties"]["meta"]
    assert meta["x-content"] is True
    assert meta["x-privacy-classification"] == "user_content"
    assert meta["additionalProperties"]["maxLength"] == 8192


def test_meta_byte_ceiling_is_declared_as_a_backend_obligation() -> None:
    """JSON Schema cannot count the canonicalized byte size of the event, so the
    65536-byte x-max-event-bytes ceiling is NOT enforced here. That gap must be
    explicit in the obligations rather than implied by the annotation."""
    obligations = " ".join(_load_schema()["x-backend-obligations"]).lower()
    assert "x-max-event-bytes" in obligations
    assert "65536" in obligations
    assert "backend-side" in obligations or "server-side" in obligations


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


def test_no_stage_fixture_labels_an_event_as_a_credential() -> None:
    """The `key` stage records API-key issuance and is non-authorizing, so the worked
    example must not call the artifact a "credential" — that is exactly the word that
    reads as entitlement-bearing, and a fixture is what a producer copies. The schema
    cannot enforce this (`event` is a free identifier label by design), so the examples
    this repo ships are pinned instead."""
    for path in sorted(_FIXTURES_DIR.glob("funnel_event_*.json")):
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)["event"].lower()
        assert "credential" not in event, (
            f"{path.name}: an event label must not present a key as a credential"
        )


LIFECYCLE_STAGES = ("access_period_started", "access_period_ended", "access_restored")


def test_access_period_lifecycle_stages_are_pinned_to_outcome_ok() -> None:
    """A lapse is time passing, not a user abandoning.

    Left to prose, an emitter could mark an automatic expiry `abandon` and
    silently corrupt the funnel's headline conversion metric -- silent because
    nothing errors and the number is simply wrong. A user can be actively
    running optimizations on the last day and still lapse.
    """
    for stage in LIFECYCLE_STAGES:
        assert _ok(_event(stage=stage, outcome="ok"))
        for wrong in ("abandon", "fail", "retry"):
            assert _rejected(
                _event(stage=stage, outcome=wrong)
            ), f"{stage} wrongly accepted outcome={wrong}"


def test_non_lifecycle_stages_keep_the_full_outcome_vocabulary() -> None:
    """The pin is scoped: it must not quietly narrow the other eight stages."""
    for outcome in ("ok", "retry", "fail", "abandon"):
        assert _ok(_event(stage="verify", outcome=outcome))
