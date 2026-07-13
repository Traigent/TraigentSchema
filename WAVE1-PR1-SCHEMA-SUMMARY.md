# Wave1 PR-1 — Observability Ingest v2 protocol contract (TraigentSchema)

Publishes the **observability ingest v2** versioned-delta contract in TraigentSchema
(`protocol_version` **"2.0"**), per
`docs/architecture/cost-scale/14-observability-ingest-v2.md`. Schema-only PR — no SDK
or backend code touched. `git push` / PR left to the captain.

## Files added (5 schemas)

All under `traigent_schema/schemas/observability/`:

| File | Purpose |
|------|---------|
| `observability_v2_ingest_request_schema.json` | Request envelope (§2.1): `protocol_version` "2.0", `ingest_id` (ULID/UUIDv7), `source`, `events[]` (1–100). `additionalProperties:false` — **scope is never a client field**. `x-max-request-bytes: 5242880` (5 MiB, edge-enforced). |
| `observability_v2_event_schema.json` | Canonical event unit + shared defs (`MonotonicId`, `Sha256Hex`, `EventKind`, `DecimalString`, `InlineContent`, `ObservationType`). Common envelope fields + `kind`-discriminated `data` for all **6 kinds** (`trace.upsert`, `trace.patch`, `observation.upsert`, `prompt_link.upsert`, `prompt_link.delete`, `trace.reparent`). `x-max-event-bytes: 65536`. **Small input/output inline (`input`/`output`, bounded); large content uses `input_ref`/`output_ref` object references.** Trace-scoped kinds declare `entity_id` `x-equal-to` `trace_id`. |
| `observability_v2_object_reference_schema.json` | Authenticated content-addressed reference: `key`, `byte_count`, `content_type`, `sha256`. |
| `observability_v2_ingest_status_response_schema.json` | GET status (§3.2): manifest state + `events` (**minItems 1**) with the 7 states, immutable `event_hash`, `attempted_count`, capacity/quota disposition, sanitized `terminal_reason`/`terminal_code`, `replay_owner ∈ {tenant, platform}`. **All terminal states (MATERIALIZED/DUPLICATE/DEAD_LETTERED) require reason+owner keys** (may be null; DEAD_LETTERED requires them non-null). |
| `observability_v2_error_schema.json` | Stable 13-code taxonomy + error envelope. Binds each HTTP-surfaced code to its ratified status via `if/then` (INGEST_ID_REUSE/EVENT_ID_REUSE→409, POSTGRES_ADMISSION_*/BULKHEAD→503, QUEUE_CAPACITY_EXHAUSTED→429, SNAPSHOT_PROTOCOL_RETIRED→410; 503/429 require `retry_after`). `x-error-catalog` maps every code → {phase, http_status, retryable}. |

## Files modified

- `observability_endpoints.json` — wired `POST /api/v2/observability/events` (→ request schema; 202/400/409/413/422/429/503 error responses) and `GET /api/v2/observability/ingests/{ingest_id}` (→ status response, with a **required `ingest_id` path parameter** typed as MonotonicId); published the **typed 410 SNAPSHOT_PROTOCOL_RETIRED** response on both existing v1beta ingest paths (documentation only — does not flip live v1beta behavior; cutover is §7/backend scope).
- `x_extensions_meta_schema.json` — registered new governed extensions `x-error-catalog`, `x-max-event-bytes`, `x-max-request-bytes`.

## Review-round blocker fixes (Codex terra)

1. **Bounded inline input/output permitted** — added optional `input`/`output` (permissive JSON via `InlineContent`, `x-content`/`x-privacy-classification: user_content`, string arm bounded to the 64-KiB event cap) alongside `input_ref`/`output_ref`. `additionalProperties:false` still forbids unknown fields. Fixture `request_inline_content_invalid.json` → renamed `request_inline_content_valid.json` (small inline now valid); added `event_oversized_inline_invalid.json` (inline string over the cap → rejected) and `request_legacy_input_data_field_invalid.json` (v1 `input_data`/`output_data` names rejected).
2. **Kind/entity identity** — trace.upsert/patch/reparent declare `entity_id` `x-equal-to` `#/properties/trace_id` (draft-07 cannot compare two sibling strings, so the equality is schema-declared + backend-enforced). Added 3 mismatch vectors (`event_trace_*_entity_trace_mismatch.json`, excluded from the accept/reject glob) driven by a dedicated test that asserts the rule is declared and each fixture violates it.
3. **Terminal fields for all terminal states** — MATERIALIZED/DUPLICATE/DEAD_LETTERED now require `terminal_reason`+`replay_owner` keys (nullable; DEAD_LETTERED requires non-null); `event_hash` was already globally required. `events` now `minItems: 1`. Added `status_materialized_missing_terminal_fields_invalid.json`.
4. **GET path parameter** — declared `ingest_id` as a required `in: path` parameter typed by the MonotonicId (ULID/UUIDv7) schema.

Non-blocking (done): error codes with no HTTP binding (`ENTITY_VERSION_COLLISION`, `PENDING_VERSION_LIMIT`, `VERSION_GAP`, `VERSION_GAP_EXPIRED`, `EVENT_ID_EXPIRED`, `OUTBOX_FULL`) now forbid `http_status`/`retry_after` via `if/then`.

## Fixtures (§9) — 29 files under `tests/test_data/observability_v2/`

16 `_valid`, 10 `_invalid` (auto-driven by prefix→schema), plus 3 `entity_trace_mismatch` backend-reject vectors handled by a dedicated test. Driven by `tests/test_observability_v2_contract.py`.

**Covered:** valid multi-event request; cross-emitter merge (same entity, two emitters); one example of **each of the 6 kinds**; object-reference (large payload) event; terminal-status response (MATERIALIZED + DEAD_LETTERED); **duplicate delivery** (DUPLICATE status record); **410 SNAPSHOT_PROTOCOL_RETIRED** error; **ID/hash collision → EVENT_ID_REUSE 409** (rejectable); **revision collision → ENTITY_VERSION_COLLISION**; INGEST_ID_REUSE 409. Invalid: scope-in-body, inline raw content, cross-kind data, unknown kind, reparent missing session, DEAD_LETTERED missing reason/owner, malformed sha256, code↔status mismatch (SNAPSHOT + 409).

**Deferred (NOT silently skipped):** the failure-injection / delivery-runtime vectors in §9 (partial-SQS-batch, relay-crash, lease-takeover, watchdog replay, pending-cap/gap-drain/gap-expiry, LocalStack/SQLite parity, load/deadline tests) are **backend + SDK runtime behavior, out of scope for a schema PR**. Duplicate-delivery is represented at the schema level as a DUPLICATE status record (a byte-identical wire resend is, by contract, an accepted request); same-hash idempotency vs different-hash rejection is server-side dedup, surfaced here as the EVENT_ID_REUSE error shape.

## Verification

- New module: **66 passing** (`tests/test_observability_v2_contract.py`).
- Full suite: **1152 passed, 1 skipped** (baseline 1086+1; +66). Includes orphan-reachability, endpoint-catalog, request-string-maxLength lint, and x-extension governance guards.
- `ruff 0.15.20 check` + `ruff format --check` clean on the new test file. (Repo has 58 pre-existing ruff errors in untouched test files — not introduced here.)
- The literal §2.1 envelope example validates verbatim (provenance-anchored test).

## Downstream pin note (NOT performed — captain/owner)

Cross-repo rollout item 1 is this PR. Consumers will later need a `traigent-schema` pin bump
(`pyproject.toml` / `requirements.txt`) once the SDK (item 2) and backend (item 3) adopt v2;
the release gate must reconcile the differing schema pins. No pin edited here.

## Open questions (minimal faithful choices — need owner/captain confirmation)

1. **Manifest-level state vocabulary.** The design enumerates the *per-event* admission state
   machine (§3.1) but not an aggregate manifest rollup. Chose `{ADMITTED, DISPATCHING,
   MATERIALIZING, COMPLETED, PARTIALLY_DEAD_LETTERED, DEAD_LETTERED}` as `manifest_state`.
   Confirm the aggregate vocabulary (backend PR-2 must agree).
2. **Inline field names + inline string cap.** Inline content uses `input`/`output`; large content
   uses `input_ref`/`output_ref` (object reference). The inline string arm is bounded at 65536
   (the 64-KiB event cap); the whole-event byte cap remains edge-enforced (`x-max-event-bytes`).
   Confirm field names for SDK/BE parity. **(Revised per review — small inline is now permitted.)**
3. **`cost_usd` as decimal string.** §2.1 shows `"cost_usd": "0.001104"` (string). Modeled as a
   non-negative decimal string to preserve precision (v1 used a number). Confirm.
4. **`source` required.** Made `source` a required envelope field (design example always includes
   it). Reversible if the SDK needs it optional.
