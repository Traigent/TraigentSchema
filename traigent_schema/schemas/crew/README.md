# crew domain

Contract for **crews** (CREW-11, Crews program slice 0; design: Crews v1 sections 1-3).
A *crew* is a named set of agents that cooperate on one job. A *fleet* is all agents of a
project (existing). A *role* is a slot in a crew; a *crew revision* is an immutable snapshot
of roles + bindings; a *crew run* is one end-to-end execution; a *handoff* is one directed
transfer of work between roles inside a run (not `agent_handoff`, which is team ownership).

## Files

| File | What |
|---|---|
| `crew_common_schema.json` | ids, closed enums, error codes |
| `crew_schema.json`, `crew_role_schema.json`, `crew_revision_schema.json`, `crew_role_binding_schema.json` | slice-1 entities; `crew_schema.json` and the crew response carry a required `source` (`portal` \| `sdk_declared`), where the crew was registered |
| `crew_*_request_schema.json`, `crew_*_response_schema.json`, `crew_error_schema.json` | slice-1 API shapes |
| `crew_endpoints.json` | `/api/v1beta/projects/{project_id}/crews` and `/{crew_id}` (GET, PUT name/description), `/archive`, `/unarchive`, `/memberships` (GET), `/memberships/query` (POST, agent filter in body), `/roles` (GET, POST upsert), `/revisions` (GET, POST). No PUT/DELETE on bindings (declared ahead of the backend: `x-asserted-against-backend: false`) |
| `crew_run_schema.json`, `crew_member_execution_schema.json`, `crew_handoff_schema.json`, `crew_trial_allocation_schema.json` | slice-3/4 execution shapes, **contract only, no API yet** |

## Summaries and memberships (read models)

Crew list rows and the crew response carry `role_count`, `bound_member_count` (distinct `agent_id`s bound in the latest revision) and `entry_role_id` (nullable), so the portal needs no per-crew fan-out. `GET /api/v1beta/projects/{project_id}/crews/memberships` is one paginated read for the fleet board: items `{agent_id, crew_id, role_id, role_token, crew_revision_id, revision_no}`, only `state=bound` bindings of each crew's latest revision, `include_archived` false by default. The GET has no agent filter, because agent ids are CONTENT and a query string is traced as `http.target`/`http.url`; the filter lives in the body of `POST /api/v1beta/projects/{project_id}/crews/memberships/query` (`{agent_ids: [<=100 raw, each AgentId>], include_archived?}`, `page`/`per_page` as query parameters), a read-only POST that is never replayed from the idempotency store. Items also carry `crew_revision_id`; crew objects carry `latest_revision_id` next to `latest_revision_no`. Same closed 404 and error rules as the other crew routes.

## Declarations from code (slice 2, CREW-20)

An SDK may send `metadata.crew_declaration` `{crew_key, role_key}` (`crew_declaration_schema.json`, both CONTENT) on `POST /api/v1/sessions`, beside `agent_key`. The backend removes it from metadata before any generic persistence or telemetry, then (after the session is created, in its own transaction) answers with `crew_binding` (`crew_binding_schema.json`) in the session-create response: closed `status` `bound | pending_portal | conflict | disabled | unknown` plus identifiers only. Ids (`crew_id`, `role_id`, `role_token`, `crew_revision_id`, `revision_no`) are all present when `bound`; `crew_id` alone may accompany `pending_portal` and `conflict`; `disabled` and `unknown` carry none. `unknown` means mock mode or a failed crew step, and the session itself never fails because of crews. The declaration never writes a revision: `bound` only when the latest revision already binds this agent to this role; otherwise a membership proposal (`crew_membership_proposal_schema.json`, id `cmp_<hex32>`) is recorded, one durable row per `(crew_id, role_id, agent_id)` across statuses (`open | accepted | dismissed`; dismissed stays dismissed when the SDK declares again, `seen_count` still increments). An archived `crew_key` answers `disabled`; a role bound to another agent answers `conflict` and records no proposal. Portal editors list proposals (`GET .../crews/{crew_id}/proposals`, `status` default `open`), accept (`POST .../proposals/{proposal_id}/accept`: appends a full-snapshot revision carrying every other binding and the entry role, marks the proposal accepted, one transaction; 409 `crew_binding_conflict` when the role has since been bound to another agent) or dismiss (`POST .../dismiss`, durable). Both are idempotent. API keys get the closed 404 on every crew route; an API key may only declare membership through session create, scoped to its own session agent.

## Privacy: content vs identifiers (constitution 11, GNFR-PRIV-002/003)

| Class | Fields | Annotation |
|---|---|---|
| CONTENT | `crew_key`, `name`, `description`, `role_key` | `x-content: true` + `x-privacy-classification: user_content`. Crew tables and portal only. |
| Identifier | `crew_id`, `crew_revision_id`, `role_id`, `role_token`, `crew_run_id`, `invocation_id` | `x-identifier: true`. The only crew values allowed in traces, baggage, optimizer keys (`<role_token>__<param>`) and Director inputs. |

`role_token` is `rtk_` + 26 lowercase base32 chars (128 random bits, server-issued). One `_` never forms `__`; split `<role_token>__<param>` on the FIRST `__`. A client-supplied `agent_id` is CONTENT for Director inputs and exports (GNFR-PRIV-003); exports use the backend `agent_ref`. Traces, baggage and
Director inputs carry only ids, counts and the closed enums defined here. Observability is
not privacy-preserving; content work stays customer-side.

## Rules encoded

- `crew_key` follows the `agent_key` rules: `[A-Za-z0-9_-]{1,128}`, case-sensitive, unique among ACTIVE crews (per creator on the default tenant), reusable after archive. Create replay: identical (crew_key, name, description) on an active crew returns 200 with the same crew; a differing payload is 409 `crew_key_conflict`; a key held only by an archived crew is free, so create makes a new crew. `crew_archived` (409) answers writes to an archived crew by id (PUT, roles, revisions). Unarchive is 409 `crew_key_conflict` while an active crew holds the key.
- Role upsert is idempotent by `role_key`. `role_key` is nullable on read (SDK roles may lack an alias).
- Feature off, an unauthorized principal (API keys in slice 1) and foreign or missing resources all answer the same closed 404 `crew_not_found`. There is no public 403 for the gate.
- Rate limits use the closed `crew_rate_limit_schema.json` (fixed message, constant error_code, integer `retry_after`, no details) instead of the shared 429 envelope. The revision request accepts `provenance` `portal` or `sdk_declared` only; `inferred_suggestion` is never accepted on this endpoint. Errors are closed: `message` is one fixed template per `error_code` (enum + `allOf` mapping), no `details`, no echo of client values. Unrecognised failures are the closed 500 `crew_internal_error`.
- Bindings are immutable: a membership change is a new revision (append-only revisions and bindings). Revision create carries `base_revision_no` (0 = none yet); stale is 409 `crew_revision_conflict`; `revision_no` is allocated under a row lock on the crew. The revision request names the single `entry_role_id`, so at most one entry exists by construction; stored bindings carry the derived `entry` flag.
- Binding invariants encoded in the schema: `state=bound` requires a string `agent_id`; `state=unbound` requires `agent_id=null`; `provenance=inferred_suggestion` forbids `state=bound`; `unit_ref` MUST be null until slice 4. `agent_unit` keeps the required host `agent_id`. `pinned_agent_revision` and `pinned_config_digest` are separate pins. Bindings carry `crew_id` for the composite FKs `(tenant_id, project_id, crew_id, revision_id)` and `(tenant_id, project_id, crew_id, role_id)`.
- Service-level checks (not expressible in draft-07): no duplicate `role_id` per revision (request and DB unique), at most one entry binding per revision (partial unique index), every `role_id` belongs to the same crew, every bound `agent_id` passes `authorize_resource_access(AGENT, read)`, and a stored revision has at least one binding.
- Accounting: exclusive (self) cost/latency/tokens are additive; inclusive is a view only; unknown stays `null`, never 0. Crew metrics aggregate by crew-run membership.
- `role.display.icon` is the closed set `agent, user, search, pen, check, shield, bolt, book, code, chat`; `color` is `#rrggbb`.
- `scenario_ref` is a server-issued `scn_<hex>` reference only.

## Revision digest (canonicalization)

`digest = "sha256:" + hex(SHA-256(UTF-8(canonical_json)))` where `canonical_json` is JSON with sorted object keys, separators `(",", ":")`, no non-significant whitespace and non-ASCII kept as UTF-8 (`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`: `ensure_ascii=False` means non-ASCII characters are emitted as raw UTF-8, never `\uXXXX`; separators have no spaces), over the object
`{"crew_id": <crew_id>, "bindings": [<binding>, ...]}`. Each `<binding>` has exactly the keys `role_id, binding_kind, agent_id, unit_ref, pinned_agent_revision, pinned_config_digest, entry, state, provenance` (nulls kept), and the list is sorted by `role_id` ascending. `revision_no`, timestamps, `created_by` and `source` are NOT hashed, so equal membership gives an equal digest, and the input order of bindings never changes it. Fixed test vectors live in `tests/test_crew_contract.py` (`DIGEST_VECTOR_*`).

## Execution semantics (slice 3, contract only)

- `crew_run.crew_revision_id` and `entry_role_token`, and `crew_member_execution.role_token`, are null only for cold-cache unbound runs (`completeness != complete`); a `complete` run requires both.
- A handoff is counted when REQUESTED; a loop is counted when the receiving role is ENTERED (`entered=true`). `hop_seq` is allocated by the sender from the baggage hop counter and is unique per run; ingest is idempotent per `(crew_run_id, dedup_id)`. `from_invocation_id` and `to_invocation_id` link the two invocations (`to` is null when never entered).
- Ingestion cross-record check (not expressible per record): a `crew_member_execution` with a null `role_token` is rejected unless its parent `crew_run` has `completeness != complete`; a `complete` run therefore never has an unresolved member role.
- `experiment_run_id` and `configuration_run_id` are server-issued lowercase UUIDs (the backend's real id shape), so customer content cannot occupy these exportable identifier slots.
- `crew_trial_allocation` maps `configuration_run_id -> role_token -> member_config_digest`.

SDK status: not implemented in the Python or JS SDK (see `parity/capabilities/registry.v1.json`,
capability `crew.declarations`).
