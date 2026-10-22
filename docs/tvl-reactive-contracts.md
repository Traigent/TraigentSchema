# TVL 1.4 reactive contracts (TRAIG-101, S1)

Closed wire contracts of the reactive layer that lets a customer run TVL Reactive Contracts
(TVL 1.4) end to end: facts in, authority records, recorded notifications out, and the
agent-head deploy target. This PR is contract-only: no Backend or SDK behaviour changes.

## Reviewed closed-contract expansion (GNFR-PRIV-002(f))

Adding a route group to the closed menu is a contract change that needs review by Opus and sol
(owner rule, plan 4.6). This document is the registration record; the review is recorded in the PR
thread. Each field of the reactive routes is one of: a hosted token, a server-issued ref, a closed
enum, a bounded integer, a boolean, a digest, an idempotency nonce, or a server timestamp. No free
text, no customer-chosen name, no config content. Errors are closed codes with fixed text that never
echo input. Observability is NOT privacy-preserving and must carry none of these facts (GNFR-PRIV).

## Field classification

| Class (`x-content-class`) | Fields | Constraint that proves it |
|---|---|---|
| hosted token (`key_material`) | `response`, `rule`, `scope`, `monitor`, `environment`, `target` | exactly `^t[A-Za-z0-9_-]{16}$` (the SDK mints `t` + 16 random base64url characters, never a hash or name); Backend ownership check against the stored policy revision or a previously announced scope |
| server ref (`opaque_ref`) | `policy_revision_ref`, `attempt_ref`, `grant_ref`, `reservation_ref`, `notification_ref`, `agent_ref`, `decided_by` (UUID) | `<kind>ref_<32 lowercase hex>` or UUID |
| closed enum (`closed_enum`) | verdicts, episode/liveness events, fact kinds, completion, approval and authority states, checks/write outcomes, effects, decisions, attempt and outcome states, evidence source, refusal codes and messages, `duration_hours` (1, 4, 24) | `enum` / `const` |
| bounded integer (`number`) | instants and window bounds (hours, 0..1e9), occurrence and repeat indices, generations (0..2^53-1), ceilings (`max_trials`, `max_cost_micro_usd`), counts | `minimum`/`maximum` |
| boolean (`closed_enum`) | `usable`, `evidence_valid`, `retries_exhausted`, `producers_missing`, `lapsed`, `replayed`, `head_moved_since_optimization_start` | boolean type |
| digest (`digest`) | `contract_digest`, `revision`, revision `value`, `fingerprint`, `gate_result_digest`, `candidate_fingerprint` | `^[0-9a-f]{64}$` |
| idempotency nonce (`key_material`) | `stage_key`, `complete_key`, `grant_key`, `reservation_key`, `start_key`, `result_key`, `cancel_key` | 32 lowercase hex, client-generated random |
| timestamp (`timestamp`) | `recorded_at`, `decided_at`, `expires_at`, `opened_at`, `started_at` | server clock, `date-time` |

Every array has `maxItems`; every object is closed (`additionalProperties: false`); unknown keys
are refused. `tests/test_tvl_reactive_contracts.py` pins all of this, and `scripts/content_class_lint.py`
walks the `optimization/` documents (the manifest `docs/content-class-manifest.json` lists every location).

## Trace shape versus transport shape

`optimization/tvl_reactive_facts_schema.json` is a SUPERSET of the fact shape the TVL reference trace
(`python/tvl/runtime_trace.py`) accepts. Transport-only fields: window `unknown_reason`, candidate
`fingerprint` and `gate_result_digest`; revision facts say `target` where the trace says `name`; hosted
tokens and digests stand in for local names and revision strings. `traigent_schema.tvl_reactive.project_fact`
/ `project_evaluation` drop or rename exactly these fields to produce a trace-shaped fact (the caller maps
tokens back to local names). `traigent_schema/data/tvl/trace-history-shape.json` is the exact trace shape;
`tests/test_tvl_reactive_contracts.py` validates all 13 TVL semantic-trace fixtures
(`tests/fixtures/tvl/semantic_traces/`, pinned in `SOURCE.json`) against it, translates each to transport
facts, validates those against the stage request, and checks the projection equals the original fact.

## Deploy contracts and the customer-content exception

`execution/best_config_deploy_schema.json` and `best_config_deploy_endpoints.json` (publish-result,
finalize, the deploy idempotency key `deploy:{attempt_ref}:{candidate_fingerprint}:{gate_result_digest}`,
a fixed shape of one ref and two digests) ARE content-class lint roots and are in the manifest.

`execution/best_config_agent_head_config_{schema,endpoints}.json` (the exact pinned version read) return
the stored configuration. That is customer content (plan 8.4): outside the closed contract, outside the
Director bridge guarantee, and never to be described as privacy-preserving. It is an explicit allow-listed
exception (`EXPLICIT_CONTENT_EXCEPTIONS` in `scripts/content_class_lint.py`, pinned by a test), not a
silent skip.

## Principals

| Record | Created by |
|---|---|
| approval grant, decline, human cancel | P-human only (portal/API session with agent write access) |
| reservation, start, results, customer-monitor facts and watermarks | P-ingest (SDK API key scoped to the agent) |
| native-monitor facts, `approval`/`started`/`deploy_started` facts, notifications, guard decisions | P-system (Backend); an ingestion claim never creates authority |

## Vendored TVL runtime schemas

`traigent_schema/data/tvl/` holds byte-exact copies of `tvl-runtime-contract` (/1, includes `deploy`),
`tvl-runtime-contract-v2` (/2), `tvl-runtime-local` (/1) and `tvl-runtime-local-v2` (/2) from the tvl
repository (`spec/grammar/`). `SOURCE.json` records the source commit, the v1.4.0 tag and per-file
SHA-256; `tests/test_tvl_vendored_schemas.py` fails if any byte drifts. To refresh: copy the four files
from the new pin with `git show <ref>:spec/grammar/<file>`, update `SOURCE.json`, and say so in the PR.
