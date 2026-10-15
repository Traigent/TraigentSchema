# Pillar Legend v0 — declared versions, optional capture, verified restore

Status: **design contract v0** (local branch `feat/pillar-legend`; nothing here is implemented in the
Backend or SDKs yet, and nothing is published). Builds on `content-identity-v1.md`
(scheme `traigent.content_identity.v1`), which stays authoritative for every fingerprint
construction below. The Legend is a thin catalogue and event layer on top of it.

| Artifact | Path |
|---|---|
| Entity, version, event types, axes, common types | `traigent_schema/schemas/legend/pillar_legend_v0.json` |
| Recovery manifest | `traigent_schema/schemas/legend/recovery_manifest_v0.json` |
| Claim predicates | `traigent_schema/schemas/legend/legend_claim_predicate_v0.json` |
| Director operation instructions and results | `traigent_schema/schemas/legend/director_legend_ops_v0.json` |
| Contract tests | `tests/test_pillar_legend_v0_schemas.py` |

Inputs: the plan `PLAN-LEGEND-v1` (items 1 and 9), reviews by two independent models, and the
code at Backend `origin/develop` (`src/services/content_identity/derivation.py`,
`src/models/{agent_build,evaluator_version,dataset_version,run_identity_binding,run_search_space_record}.py`)
and SDK `origin/develop` (`traigent/identity/*`). Where this note says "reuse", it means the
existing construction is called, not copied or re-derived.

---

## 1. Principles

1. **Reuse, do not duplicate.** `agent_builds`, `evaluator_versions`, `dataset_versions`,
   `run_identity_bindings`, `trial_identity_bindings` and `run_search_space_records` remain the
   identity authorities. The Legend copies no content snapshots and also supports declarations
   that have no source row yet.
2. **Existing fingerprints are kept.** A keyed fingerprint carries its scheme and `key_id`.
   Verification under a historical key never exposes Backend-only keys (`K_eval`, `K_search_space`
   are not in the purpose-key grant). A fingerprint that cannot be re-verified is never `exact`.
3. **Three independent axes** per version, each advanced only by appending events:
   identity (`identity_source`: `client_declared | sdk_fingerprinted`), recovery/availability
   (`none | stored_unverified | round_trip_verified`, with *current availability*
   `available | missing | corrupted | retired` kept separate from *historical capture*), and
   evaluation (`none | client_reported | traigent_witnessed`).
4. **Client-originated events can never carry witnessed (or server-recorded) provenance.**
5. **Store keys are scheme-qualified recovery-manifest fingerprints**, not pillar fingerprints
   (section 4). Distinct captures never overwrite each other.
6. **Closed bridge.** Only opaque server-issued refs and closed enums cross to the Director or the
   backend. `additionalProperties: false`, no free text, no names, no paths, no adapter messages.
   Capture, restore and activation run locally; the Director is advisory.

---

## 2. Per-pillar fingerprint construction (reused from content-identity v1)

Pillars: **agent**, **configuration**, **evaluation dataset**, **evaluator**, **search space**.
`scheme` below is the Legend `fingerprint_scheme` enum value.

| Pillar (`kind`) | `fingerprint_scheme` | Commitment (what it binds) | Preimage | Canonicalization | Domain string | Encoding | Derivation authority | Key id |
|---|---|---|---|---|---|---|---|---|
| agent | `agent_build_digest_v1` | the **build**: code revision, prompt/helper/tool asset digests, applied config digest, coverage, runtime | `AgentBuildManifestV1` (content-identity section 8) | `jcs_v1` | `traigent.content_identity.agent_build.v1` | `sha256:` + 64 hex | SDK computes; Backend recomputes and records (`agent_builds.build_digest`) | none (unkeyed) |
| configuration | `applied_config_digest_v1` | the **applied configuration**: a trial's candidate, a promoted head, or the base default (digest of `{}` when no knobs). Not the search space | the applied config object (`applied_config_digest` inside the agent manifest, content-identity section 8) | `jcs_v1` | the agent-build family (same digest the manifest embeds) | `sha256:` + 64 hex | SDK computes; Backend recomputes when it holds the config | none |
| evaluation dataset | `dataset_multiset_root_v1` | the **multiset of examples** `(example_id, example_version, count)`; order-free | members, sorted | RFC 9162 Merkle tree over `jcs_v1([id, version, count])` leaves | `traigent.content_identity.multiset_leaf.v1` | `msr1:<kid>:<64 hex>` | whoever holds content: SDK (local data) or Backend (hosted data), under the tenant purpose keys | tenant `kid` (**keyed leaves**) |
| evaluation dataset | `dataset_content_digest_v1` | hosted dataset **version snapshot** (`dataset_versions.content_digest`); unkeyed, not order-free-safe | `content_snapshot` | existing Schema `compute_dataset_version_content_digest` | `traigent.dataset_version.content.v1` | `sha256:` + 64 hex | Backend | none |
| evaluator | `evaluator_version_digest_v1` | **evaluator manifest**: code (efp2), judge, objectives, bound config, helpers, dependency versions; this is the one that certificates bind (claim C3) | `EvaluatorVersionManifestV1` (content-identity section 9) | `jcs_v1` | `traigent.content_identity.evaluator_version.v1` | `sha256:` + 64 hex | Backend (registered) / SDK (local); witnessed at scoring time for claims | none |
| evaluator | `judge_config_digest_v1` | **judge configuration only** (`evaluator_versions.judge_config_digest`): a component *inside* the evaluator manifest, never a substitute for it | judge config snapshot | existing evaluator-version identity helper | `traigent.evaluator.judge_config.v1` | `sha256:` + 64 hex | Backend mints at version creation | none |
| search space | `search_space_ssp1` | the run's **effective search space** (definition, seed or `"unseeded"`, ordered warm-start list); not the applied config | search-space payload `P_ss` | strict `jcs_v1` (unsafe numbers refuse) | `traigent.content_identity.search_space.v1` | `ssp1:<kid>:<64 hex>` (HMAC-SHA-256, full 32 bytes) | Backend (`K_search_space` is Backend-only) | tenant `kid` |

Rules that follow from the table:

- **The four commitments are distinct and never interchanged:** judge-config (`judge_config_digest_v1`)
  is a component of the evaluator manifest (`evaluator_version_digest_v1`); applied-config
  (`applied_config_digest_v1`) is a component of the agent build and is a *point* in the search
  space; the search space (`search_space_ssp1`) is the *region* a run explored. A version of one
  scheme is never accepted where another scheme is required (the schema pins `kind` to its allowed
  schemes).
- **Keyed schemes carry `key_id`; unkeyed schemes carry `null`.** The `kid` embedded in an `msr1:` or
  `ssp1:` fingerprint is its second colon field and MUST equal `key_id` (content-identity I3). The
  schema checks the family and the null/non-null split; the equality is a consumer check.
- **`key_id` is a tenant-scoped lookup key** (it is probabilistic, 64 bits).
- **Historical keys.** A verifier holding only the current tenant key may find a version minted under
  an older `kid`. It must answer "not comparable / unverifiable", never "changed" and never `exact`.
  Backend-only keys are never handed to the client to make a historical verification succeed.
- **Order-free dataset roots cannot prove ordering** (`dataset_multiset_root_v1` sorts members). Order,
  and therefore exact recovery of a dataset, is proved only by the recovery manifest (section 4).

---

## 3. Entity, version, events

### 3.1 Entity

An **entity** is an opaque, tenant- and project-scoped catalogue handle: `entity_ref`
(`entityref_<32 hex>`), `kind`, `created_at`. Human names stay client-side in a local alias file;
no name is on the wire. Tenant and project come from the canonical request context, never from a
header or a body field.

### 3.2 Version

A **version** is immutable: `(entity_ref, kind, fingerprint_scheme, key_id, fingerprint,
initial_parent_version_ref, identity_source, declared_at)` with its own `version_ref`.

- **Dedup key:** `(tenant, project, entity, fingerprint_scheme, key_id, fingerprint)`.
- **Initial parent.** `initial_parent_version_ref` is fixed at the version's *first* declaration, is
  nullable, names a version of the **same entity** declared earlier, and is the *only* edge that must
  be acyclic (a version is never its own initial ancestor). It is never rewritten.
- **Head movement is separate.** Where a declarer moved *from* is recorded on each `declared` event as
  `previous_version_ref` (nullable, same entity). These edges form a movement history, not a tree:
  a revert such as v3 -> v1 is a legal event, not a cycle.
- A version never changes its fingerprint, scheme, key, entity or initial parent.

### 3.3 Events

One append-only ledger; closed `event_type`. Every event carries `schema_version`, `event_ref`,
`version_ref`, opaque `actor_ref` (never a git user or email), `origin` (`client | server`),
`evidence_source`, server `recorded_at`, and `idempotency_key` (digest of the canonical payload).

| `event_type` | Origin | `evidence_source` | Type-specific fields |
|---|---|---|---|
| `declared` | client; server only for `implicit_legacy` backfill | `client_reported` | `provenance` (`explicit | implicit_run | implicit_legacy`), `identity_source`, `previous_version_ref` (nullable; where the declarer moved from), optional `change_reason` (closed list) |
| `captured` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `coverage`, `recovery_state` (`stored_unverified | round_trip_verified`), `conformance_passed`, `exporter_version` |
| `restore_verified` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `outcome` (`exact | partial | substituted | failed`), `coverage`, `isolated_destination` (always true), `representation_digests_match`, `pillar_fingerprint_match` |
| `bound_to_run` | server | `server_recorded` | `run_ref`, `trial_ref?`, `binding_role`, `run_tuple_digest` |
| `evaluated` | client or server | client: `client_reported`; server: `traigent_witnessed` | `run_ref`, `run_tuple_digest`, `evaluated_subset_root` (`msr1:`), `evaluation_protocol` |
| `availability_changed` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `status` (`available | missing | corrupted | retired`) |

Several versions may be bound to one run (base inputs plus each trial's candidate); the
`binding_role` and `trial_ref` distinguish them (SDK `run.py` and `run_identity_binding.py` already allow this).

### 3.4 Idempotency and conflict refusal

- Version identity is `(tenant, project, entity, scheme, key_id, fingerprint)`. `declare` of an
  existing identity **never creates a second version and never changes the stored version**; it
  appends a `declared` event carrying `previous_version_ref`. Rollback (returning to an older
  fingerprint) is exactly this case.
- Explicit and implicit (`implicit_run`) declarations of the same fingerprint converge on one version.
- The same `idempotency_key` with an equal canonical payload returns the first event (no new row); with
  a **different** payload it is refused (`conflicting_idempotency_payload`).
- A first declaration whose `initial_parent_version_ref` is its own version, or would make the initial-parent
  chain cyclic, or names a version of another entity or an undeclared version, is refused
  (`invalid_request` / `unknown_ref`).
- A report that conflicts with an earlier report for the same issued instruction is refused
  (`conflicting_report`).

---

## 4. Recovery manifest and the client store

A **recovery manifest** (`RecoveryManifestV0`) is built client-side and binds the pillar identity to
what is actually stored:

- the pillar `kind`, `fingerprint_scheme`, `key_id`, `pillar_fingerprint`;
- `exporter` id and **exporter version** (a new exporter version is a new manifest);
- **ordered** `representations`: `(ordinal, representation_kind, sha256 digest, byte_length)`; the
  order is part of the manifest and `ordinal` equals array position;
- `ordering` (`preserved` is required for evaluation datasets);
- `dependencies` (other declared versions by opaque ref);
- `coverage`: `{status: complete|partial, covered[], missing[]}` over a closed component list.

**Manifest fingerprint (the store key):**
`rmf0:sha256:` + hex SHA-256(`UTF8("traigent.recovery_manifest.v0") || 0x00 || jcs_v1(RecoveryManifestV0)`).
It is scheme-qualified, unkeyed, and contains only digests, so the manifest itself stays client-side
(or in the customer's store). Only the manifest fingerprint, `coverage` and enums cross the bridge.
The digests are over customer content, so the manifest is treated as customer data and is not uploaded.

**Why not the pillar fingerprint as the store key:** a shuffled dataset has the same order-free root, so
it would collide with, and could overwrite, the original; the manifest fingerprint differs, so
"shuffled rows pass the pillar root but fail the manifest" is a defined, tested outcome.

**ClientStore** (client-implemented, no delete): `put(manifest_fingerprint, stream)`,
`get(manifest_fingerprint, dest)`, `has(manifest_fingerprint)`. Store statuses (closed):
`not_captured`, `stored_unverified`, `round_trip_verified`, `missing`, `truncated`, `corrupted`,
`unreachable`, `permission_denied`, `conformance_failed`. A no-op store reports `not_captured`, never
success. A put acknowledgement alone is `stored_unverified`; `round_trip_verified` requires adapter
conformance **and** a per-capture isolated round trip (get, re-hash representation digests, recompute
the pillar fingerprint). `restore` writes into an isolated destination; **`activate` is a separate,
locally authorised step and is not a Director operation.** Restoration never reverses external effects.

---

## 5. Claim predicates

`ClaimPredicateV0` is what the claims compiler may sign. Each carries `evidence_source` and
`supporting_event_refs`; the schema pins the source per type:

| `predicate_type` | Requires event | `evidence_source` | Plain meaning (rendered with its source label) |
|---|---|---|---|
| `declared` | `declared` | `client_reported` | "this version was declared" |
| `captured` | `captured` | `client_sdk_reported` | "a capture was stored at T" (historical) |
| `restorable_now` | `captured` and latest availability `available` | `client_sdk_reported` | "restorable as of the statement time" (current) |
| `restore_verified_client_reported` | `restore_verified` with `outcome: exact` | `client_sdk_reported` | "the client-side SDK reports a verified restore" |
| `bound_to_run` | `bound_to_run` | `server_recorded` | "this version was bound to this run tuple" |
| `evaluated_client_reported` | `evaluated`, client origin | `client_reported` | "the client reports an evaluation" |
| `evaluated_traigent_witnessed` | `evaluated`, server origin | `traigent_witnessed` | "Traigent witnessed this evaluation" |

A signature authenticates the statement, not the truth of a client assertion (matching today's
certificate rule for client receipts). A later event produces a **new** statement; an issued
statement is never edited. The compiler extends the existing certification compiler and preserves
its refusals (for example `config_linkage_unverified`). Version-subject signing is a later item.

---

## 6. Director operations (closed menu)

Five operations, behind `director_legend_ops_enabled` (default off). Each has an **instruction**
(Director to agent; one operation plus opaque refs) and a **result** (agent to backend; enums, refs,
booleans). Refs are `<kind>ref_<32 hex>`; no names, paths, store messages or adapter text.

| Operation | Instruction fields | Result fields |
|---|---|---|
| `declare_version` | `kind`, `entity_ref|null` | `version_ref|null`, `created` |
| `query_versions` | `entity_ref`, `page_size`, `page_cursor|null` | `version_refs[]`, `next_page_cursor|null` |
| `capture_version` | `version_ref` | `store_status`, `recovery_manifest_fingerprint|null`, `coverage|null`, `conformance_passed` |
| `verify_restore` | `version_ref`, `recovery_manifest_fingerprint` | `restore_outcome|null`, `coverage|null`, `store_status` |
| `restore_version` | `version_ref`, `recovery_manifest_fingerprint` | `restore_outcome|null`, `store_status`, `activated` (always false) |

Every result has `outcome` (`succeeded | refused | failed`) and a closed `error_code`
(non-null iff the outcome is not `succeeded`): `invalid_request`, `unknown_ref`, `foreign_ref`,
`flag_disabled`, `conflicting_report`, `conflicting_idempotency_payload`, `store_not_configured`,
`store_unavailable`, `conformance_failed`, `manifest_mismatch`, `coverage_insufficient`,
`restore_failed`, `internal_error`. Adding an operation is a reviewed contract change (new menu
operation plus a closed result schema), never a widened field.

---

## 7. Invariants (for the model checker, item 9)

Numbered so counterexamples and conformance cases can cite them. "Events" means the ledger.

- **INV-1 Append-only.** The ledger only grows; no event or version row is updated or deleted; every
  derived axis state is a function of the event prefix.
- **INV-2 Non-escalation.** An event with `origin = client` has `evidence_source` in
  {`client_reported`, `client_sdk_reported`}; no sequence of client events produces `server_recorded`
  or `traigent_witnessed`; `traigent_witnessed` exists only on server-origin `evaluated` events.
- **INV-3 Exact is unreachable on partial coverage.** `restore_verified` with `outcome = exact` implies
  `coverage.status = complete`, `representation_digests_match`, `pillar_fingerprint_match` and an
  isolated destination; a missing historical key, missing dependency, unverifiable fingerprint or
  substitution yields `partial | substituted | failed`, never `exact`.
- **INV-4 Idempotent declare.** `declare` on an existing version identity appends a `declared` event and
  creates no second version; concurrent explicit and implicit declarations converge to one version; the
  same `idempotency_key` with an unequal payload is refused.
- **INV-5 Acyclic initial parents (scope).** Only `initial_parent_version_ref` is constrained: same entity,
  declared earlier, no cycle (including self). `previous_version_ref` edges are unconstrained history
  (same entity, nullable); a revert v3 -> v1 is legal.
- **INV-15 Version identity is stable under re-declaration.** Re-declaring a version changes none of its
  entity, scheme, key_id, fingerprint, initial parent, identity_source or declared_at; only the event
  ledger grows.
- **INV-6 Historical vs current availability.** `captured` is a fact about time T and is never erased;
  `availability_changed` changes only *current* availability; `restorable_now` holds iff the latest
  availability event for that capture is `available` (or none yet), and revoking it leaves `captured`
  intact.
- **INV-7 Activation separation.** No Director operation activates; `restore_version` always reports
  `activated = false`; activation requires a prior `restore_verified` of the same manifest fingerprint
  with `outcome = exact`.
- **INV-8 Capture vs round trip.** `recovery_state = round_trip_verified` implies `conformance_passed`
  and a completed isolated round trip; a put acknowledgement alone yields `stored_unverified`.
- **INV-9 Representation plus pillar equality.** Exact recovery requires both equalities: the
  ordered representation digests equal the manifest's, and the recomputed pillar fingerprint equals
  the declared one. Equal pillar root with different representation order is not exact.
- **INV-10 Scoped keyed identity.** The dedup key includes scheme and `key_id`; the same fingerprint
  under different `key_id` or tenant is never merged; keys are tenant-scoped.
- **INV-11 Immutable bindings.** `bound_to_run` events are immutable; several versions may bind to a
  run; a strict-drift refusal appends nothing.
- **INV-12 Evaluation binds the exact tuple.** An `evaluated` event and its predicates bind the
  `run_tuple_digest`; a predicate whose supporting events do not include the required event type does
  not exist (no statement without its signed predicate).
- **INV-13 Closed bridge.** Instructions and results contain only refs and enum values; a foreign
  ref (another tenant or project) is refused; conflicting reports for one instruction are refused.
- **INV-14 Distinct captures never overwrite.** Two captures with different manifest fingerprints never
  share a store key; a repeated `put` of an equal manifest is idempotent.

Abstract hash equality in the model does not prove exporter correctness or real recovery; the
implementation-conformance cases come from the schema examples and the tests above.

---

## 8. Names chosen in v0

Invented in this contract; a reviewer should confirm or rename them before consumers are built.

| Name / format | Value |
|---|---|
| Manifest fingerprint | `rmf0:sha256:<64 hex>`; domain `traigent.recovery_manifest.v0`; manifest scheme const `traigent.recovery_manifest.v0` |
| Opaque ref prefixes | `entityref_`, `versionref_`, `eventref_`, `runref_`, `trialref_`, `actorref_`, `instructionref_`, each + 32 lowercase hex |
| Page cursor | `cursor_<32 hex>` |
| `change_reason` | `code`, `prompt`, `configuration`, `dataset_content`, `dependency`, `rollback`, `unspecified` |
| Coverage components | `code`, `prompts`, `helper_modules`, `tool_definitions`, `applied_config`, `dependency_lock`, `dataset_members`, `dataset_order`, `evaluator_code`, `judge_config`, `objectives`, `search_space_definition` |
| `binding_role` | `base_agent`, `trial_candidate`, `dataset`, `search_set`, `evaluator`, `search_space` |
| `evaluation_protocol` | `full_dataset`, `holdout`, `sampled_subset`, `search_set` |
| Representation kinds | `source_bundle`, `prompt_files`, `helper_modules`, `tool_definitions`, `config_document`, `dependency_lock`, `dataset_rows`, `evaluator_bundle`, `judge_config_document`, `search_space_document` |
| Store statuses / error codes | as listed in sections 4 and 6 |
| Predicate types | as listed in section 5; `policy_version` is a lowercase token |
| Field `key_id` | the plan's `key_version`: the tenant `kid`, null for unkeyed schemes |

---

## 9. What stays outside this contract

Backend tables and API (items 2, 3), run binding and legacy backfill (item 4), Director dispatch
(item 5), signed version subjects (item 6), SDK client, store and activation (items 7, 8) are
implementations of this contract. They must not widen a field to free text.
