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
| Client request bodies (declare, query, record-capture, record-restore) | `traigent_schema/schemas/legend/legend_requests_v0.json` |
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
   **Unique mapping.** Each entity maps to at most one existing authoritative identity (internally:
   `(tenant, project, kind, source_authority, authority key)`; the key is never on the wire and
   `source_authority` is a closed enum). Two entities can never represent the same authoritative
   identity, so deduplication inside an entity is not the only guard. Where an authoritative version row
   exists (an `agent_builds` row, an `evaluator_versions` row, a `dataset_versions` row, a
   `run_search_space_records` row) the Legend version links to it exactly (`authority_linked = true`,
   the join is on the fingerprint, server-side); a declaration without a source row is allowed and is
   `authority_linked = false` until a row appears.
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
`scheme` below is the Legend `fingerprint_scheme` enum value. Where the table says "existing", the
Legend calls the construction that is already in the Schema, SDK or Backend; it does not re-derive it.

| Pillar (`kind`) | `fingerprint_scheme` | Commitment (what it binds) | Preimage | Canonicalization | Domain string | Encoding | Derivation authority | Key id |
|---|---|---|---|---|---|---|---|---|
| agent | `agent_build_digest_v1` | the **build**: code revision, prompt/helper/tool asset digests, applied config digest, coverage, runtime | `AgentBuildManifestV1` (content-identity section 8) | `jcs_v1` | `traigent.content_identity.agent_build.v1` | `sha256:` + 64 hex | SDK computes (`traigent/identity/content_identity.py`); Backend recomputes and records (`agent_builds.build_digest`) | none (unkeyed) |
| configuration | `applied_config_digest_v1` | the **applied configuration**: a trial's candidate, a promoted head, or the base default (the digest of `{}` when no knobs). Not the search space | the applied config object, `dict(config or {})` | existing `fp2.canonicalize` (RFC 8785 based) | **none**: existing `fp2.digest` is `"sha256:" + hex SHA-256(UTF8(fp2.canonicalize(config)))` with **no domain prefix and no NUL separator** (SDK `traigent/identity/run.py:180`, `traigent/utils/fp2.py:317`; Schema `traigent_schema/fp2.py:321`). It is *not* the agent-build domain | `sha256:` + 64 hex | SDK computes. **Backend recomputation is future work**: today the Backend deliberately preserves the `config_linkage_unverified` refusal (`src/services/content_identity/run_rules.py:133-142`), so a configuration digest alone is client-declared | none |
| evaluation dataset | `dataset_multiset_root_v1` | the **multiset of examples** `(example_id, example_version, count)`; order-free | members, sorted | RFC 9162 Merkle tree over `jcs_v1([id, version, count])` leaves | `traigent.content_identity.multiset_leaf.v1` | `msr1:<kid>:<64 hex>` | whoever holds content: SDK (local data) or Backend (hosted data), under the tenant purpose keys | tenant `kid` (keyed leaves) |
| evaluation dataset | `dataset_content_digest_v1` | hosted dataset **version snapshot** (`dataset_versions.content_digest`) | `content_snapshot` | existing Schema `compute_dataset_version_content_digest`. That helper **sorts and projects the rows itself**, so reordering the input list does not change the digest; like the multiset root it cannot prove ordering (`traigent_schema/content_identity.py:74-138`) | `traigent.dataset_version.content.v1` | `sha256:` + 64 hex | Backend | none |
| evaluator | `evaluator_version_digest_v1` | the **evaluator manifest**: code, judge, objectives, bound config, helpers, dependency versions; the one certificates bind (claim C3) | `EvaluatorVersionManifestV1` (content-identity section 9) | `jcs_v1` | `traigent.content_identity.evaluator_version.v1` | `sha256:` + 64 hex | Backend (registered/hosted) or SDK (local); witnessed at scoring time for claims | none (outer digest unkeyed) |
| evaluator | `judge_config_digest_v1` | **judge configuration only**: a component of an evaluator manifest, never a substitute for it. Applies to the legacy registered-judge format (`evaluator_versions.judge_config_digest`); SDK-local judge configuration uses raw fp2 hashing instead (`traigent/identity/evaluator_version.py:101-104`) | judge config snapshot | existing evaluator-version identity helper | `traigent.evaluator.judge_config.v1` | `sha256:` + 64 hex | Backend mints at version creation | none |
| search space | `search_space_ssp1` | the run's **effective search space** (definition, seed or `"unseeded"`, ordered warm-start list); not the applied config | payload `P_ss` | strict `jcs_v1` | `traigent.content_identity.search_space.v1` | `ssp1:<kid>:<64 hex>` (HMAC-SHA-256, full 32 bytes) | **Backend only** (`K_search_space` is not in the purpose-key grant). An SDK declares it with the Backend-minted id as `client_declared` | tenant `kid` |

Specification versus implementation divergence for evaluators (documented, both preserved):
content-identity v1 section 9 describes the evaluator manifest with an efp2 `code_digest` and the
legacy `judge.config_digest`. The Backend's hosted witnessed manifests are stored in
`evaluator_version_manifests` (format `be.evaluator_manifest.keyed_leaves.v0`), whose inner `code`,
`config` and `judge` leaves are **keyed `evd1:<kid>:<hex>`** digests under Backend-only `K_eval`
(`src/models/evaluator_version_manifest.py:9-22`, `src/services/content_identity/evaluator_witness.py`).
`evaluator_version_manifests` is the authority for hosted witnessed evaluators. Two checks must not be
confused: (a) recomputing the **unkeyed outer** `evaluator_version_digest` from a stored manifest needs no
key and any verifier can do it; (b) verifying **restored content** against the keyed leaves needs
Backend-only `K_eval`, so it is a server-side match report (section 4), never a client-side check.

Rules that follow from the table:

- **The commitments are distinct and never interchanged:** judge-config is a component of the evaluator
  manifest; applied-config is a component of the agent build and a *point* in the search space; the
  search space is the *region* a run explored. The schema pins `kind` to its allowed schemes, and pins
  scheme to key/fingerprint family, in the version, the recovery manifest and the claim-predicate subject.
- **Keyed schemes carry `key_id`; unkeyed schemes carry `null`.** The `kid` embedded in an `msr1:` or
  `ssp1:` fingerprint is its second colon field and MUST equal `key_id` (content-identity I3); the schema
  checks family and the null/non-null split, the equality is a consumer check.
- **`key_id` is tenant-scoped** (64 bits, probabilistic).
- **Historical keys.** A verifier holding only the current key may find a version minted under an older
  `kid`. It answers "not comparable / unverifiable", never "changed" and never `exact`. Backend-only keys
  are never handed to the client to make a historical verification succeed.
- **Order-free roots cannot prove ordering.** Order, and therefore exact recovery of a dataset, is proved
  only by the recovery manifest (section 4).

---

## 3. Entity, version, events

### 3.1 Entity

An **entity** is an opaque, tenant- and project-scoped catalogue handle: `entity_ref`
(`entityref_<32 hex>`), `kind`, `source_authority` (`agent_builds | evaluator_versions |
dataset_versions | run_search_space_records | run_identity_bindings | none`), `created_at`. The mapping
from an existing authoritative identity to its entity is unique (principle 1); the internal authority key
stays internal. Human names stay client-side in a local alias file. Tenant and project come from the
canonical request context, never from a header or body field.

### 3.2 Version

A **version** is immutable: `(entity_ref, kind, fingerprint_scheme, key_id, fingerprint,
initial_parent_version_ref, identity_source, authority_linked, declared_at)` with its own `version_ref`.

- **Version identity** is `(tenant, project, entity, scheme, key_id, fingerprint)`.
- **Initial parent.** `initial_parent_version_ref` is set **only on the version's first declaration**,
  is nullable, names a version of the **same entity** declared earlier, and is the *only* edge that must
  be acyclic. It is never rewritten: a later declaration of an existing version sends `null`, and a
  different non-null value is refused (`invalid_request`).
- **Head movement is separate.** Each `declared` event may carry `previous_version_ref` (optional,
  nullable, same entity): where the declarer moved *from*. It is independent of the initial parent. These
  edges form a movement history, so a revert v3 -> v1 is a legal event, not a cycle.
- A version never changes its fingerprint, scheme, key, entity, initial parent, `identity_source`.
- A Backend-keyed fingerprint (`ssp1`) is declared by the SDK with the Backend-minted id and
  `identity_source = client_declared`.

### 3.3 Events

One append-only ledger; closed `event_type`. Every event carries `schema_version`, `event_ref`,
`version_ref`, opaque `actor_ref` (never a git user or email), `origin` (`client | server`),
`evidence_source`, server `recorded_at`, `idempotency_key` and `request_digest` (section 3.4).

| `event_type` | Origin | `evidence_source` | Type-specific fields |
|---|---|---|---|
| `declared` | client; **server only for `implicit_legacy` backfill** | `client_reported` | `provenance` (`explicit | implicit_run | implicit_legacy`), `identity_source`, optional `previous_version_ref`, optional `change_reason`. `implicit_legacy` implies server origin and `identity_source = client_declared` (never `sdk_fingerprinted`) |
| `captured` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `coverage`, `recovery_state` (`stored_unverified | round_trip_verified`), `conformance_passed`, `exporter_version` |
| `restore_verified` | client, or server (Backend recompute) | client: `client_sdk_reported`; server: `server_recorded` | `kind`, `recovery_manifest_fingerprint`, `outcome`, `coverage`, `isolated_destination`, `representation_digests_match`, `pillar_fingerprint_match`, `backend_match_result` (`not_applicable | not_checked | match | mismatch`; `match|mismatch` only server-origin, `not_applicable|not_checked` only client-origin) |
| `bound_to_run` | server | `server_recorded` | `run_ref`, `trial_ref`, `binding_role`, `binding_slot`, `run_tuple_digest` |
| `evaluated` | client or server | client: `client_reported`; server: `traigent_witnessed` | `run_ref`, `run_tuple_digest`, `evaluated_subset_root` (`msr1:`), `evaluation_protocol` |
| `availability_changed` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `status` (`available | missing | corrupted | retired`) |

**Binding slots.** A run has immutable *slots*: the run's base inputs (`base_agent`, `dataset`,
`search_set`, `search_space`, with `trial_ref = null`) and, per trial, the trial's actual candidate
(`trial_candidate`, `trial_ref` required). Evaluator bindings may be per run or per trial and may use
several `binding_slot` values for legitimate evaluator groups. The slot key is
`(run_ref, trial_ref, binding_role, binding_slot)`; one slot binds exactly one run-tuple digest and a
second, different binding for the same slot is refused (`conflicting_report`). Several versions per run
remain allowed (different slots).

**Run tuple digest.** `run_tuple_digest = "sha256:" + hex SHA-256(UTF8("traigent.legend.run_tuple.v0") ||
0x00 || jcs_v1(T))` where `T` is the object `{agent, configuration, evaluation_dataset, evaluator,
search_space}` and each value is `{fingerprint_scheme, key_id, fingerprint}` of the version bound in that
pillar for the exact trial (or run) in question, or `null` when that pillar is not bound. It is computed
by the Backend from its own binding rows (authority: Backend), never accepted from a client.

### 3.4 Idempotency and conflict refusal

- **Request key.** `idempotency_key` is a fresh opaque key (`idk_<32 hex>`) minted once per *logical*
  declaration/record and reused unchanged on every retry of that request. Scope:
  `(tenant, project, endpoint)`. It is never derived from content, so repeated legitimate movements
  `A->B`, `B->A`, `A->B` each carry their own key and each append.
- **Request digest.** `request_digest = "sha256:" + hex SHA-256(UTF8("traigent.legend.request.v0") || 0x00
  || jcs_v1(body))` over the request body **excluding** `idempotency_key`, `request_digest` and every
  server-issued field (`event_ref`, `actor_ref`, `recorded_at`, `origin`, `evidence_source`, minted refs).
- Same key + equal digest = a retry: return the first result, append nothing. Same key + different
  digest is refused (`conflicting_idempotency_payload`).
- `declare` of an existing version identity never creates a second version and never changes the stored
  version; it appends a `declared` event (rollback is exactly this case). Explicit and `implicit_run`
  declarations of one fingerprint converge on one version.
- A first declaration whose initial parent is itself, another entity's version, or undeclared is refused
  (`invalid_request` / `unknown_ref`).
- A report that conflicts with an earlier report for the same issued instruction is refused
  (`conflicting_report`).

Client request bodies (`legend_requests_v0.json`) carry client fields only: `DeclareRequestV0`,
`QueryRequestV0`, `RecordCaptureRequestV0`, `RecordRestoreRequestV0`. The server issues refs, actor, time,
origin and evidence source. A client restore request can never report `exact` for `search_space`.

---

## 4. Recovery manifest and the client store

A **recovery manifest** (`RecoveryManifestV0`) is built client-side and binds the pillar identity to what
is actually stored:

- the pillar `kind`, `fingerprint_scheme`, `key_id`, `pillar_fingerprint`;
- `exporter` id and **exporter version** (a new exporter version is a new manifest);
- **ordered** `representations`: `(ordinal, representation_kind, sha256 digest, byte_length)`; `ordinal`
  equals array position and the order is part of the manifest;
- `ordering` (`preserved` is required for evaluation datasets);
- `dependencies` (declared versions by opaque ref);
- `coverage`: `{status, covered[], missing[]}`;
- `identity_digests_reproduced` (boolean) and `rederivation` (`source_entity_ref`, `skipped_file_count`).

**Coverage is defined, not a label.** `RequiredComponents(kind)` is fixed by the schema:

| kind | required components |
|---|---|
| agent | `code`, `prompts`, `helper_modules`, `tool_definitions`, `applied_config`, `runtime` |
| configuration | `applied_config` |
| evaluation_dataset | `dataset_members`, `dataset_order` |
| evaluator | `evaluator_code`, `judge_config`, `objectives`, `helper_modules` |
| search_space | `search_space_definition` |

`covered` and `missing` partition the applicable required components (disjointness is a consumer check);
`status = complete` iff `missing` is empty and every required component is in `covered` (the manifest
schema enforces the "contains" half). A category that is genuinely empty (for example no helper modules)
is `covered` with a zero-length representation, so an empty category is asserted, never silently skipped.
`dependency_lock` is optional extra coverage. Historical-key availability and dependency verification are
separate prerequisites of `exact` (INV-3), not components.

**Reproducing the identity digests (agent, evaluator).** A capture must reproduce the **same**
identity-construction digests recorded for the version: the agent build manifest's asset/helper digests
(prompts, helper modules, tool definitions, the applied config digest), and the evaluator manifest's
leaves. If the exporter's digests over the files it read differ from, or cannot be compared with, the
ledger version's, `identity_digests_reproduced = false` and coverage is `partial`. `complete` for `agent`
and `evaluator` requires `identity_digests_reproduced = true`. A capture whose files cannot be read
(`skipped_file_count > 0`) is `partial` by schema. Until exporters read the real files (code tree and
dirty state, prompts, helpers, evaluator source), coverage is partial and `exact` is unreachable.

**Manifest fingerprint (the store key):** `rmf0:sha256:` + hex SHA-256(`UTF8("traigent.recovery_manifest.v0")
|| 0x00 || jcs_v1(RecoveryManifestV0)`). Scheme-qualified, unkeyed, digests only. The manifest is customer
data and stays client-side; only its fingerprint, `coverage` and enums cross the bridge. A shuffled
dataset has the same order-free root but a different manifest fingerprint, so "passes the pillar root,
fails the manifest" is a defined outcome.

**ClientStore** (client-implemented, no delete): `put(manifest_fingerprint, stream)`,
`get(manifest_fingerprint, dest)`, `has(manifest_fingerprint)`. Closed statuses: `retrieved` (get
succeeded), `not_captured`, `stored_unverified`, `round_trip_verified`, `missing`, `truncated`,
`corrupted`, `unreachable`, `permission_denied`, `conformance_failed`, `store_key_conflict` (a put of an
existing key with different bytes). A no-op store reports `not_captured` and never success: a successful
capture result requires a stored status and a non-null manifest fingerprint and coverage. A put
acknowledgement alone is `stored_unverified`; `round_trip_verified` needs adapter conformance **and** a
per-capture isolated round trip. `restore` writes into an isolated destination; **`activate` is separate,
locally authorised, and not a Director operation.** Restoration never reverses external effects.

**Conformance namespace.** The store has no delete, so conformance self-test artifacts persist. They use
the reserved synthetic key form `rmfc0:sha256:<hex>` (`ConformanceKey`), disjoint from
`ManifestFingerprint`; no event, predicate or instruction may reference one.

**Backend-keyed pillars.** `search_space` (`ssp1`, `K_search_space`) and the keyed evaluator leaves
(`K_eval`) cannot be re-verified by the client. A client-side restore of such a pillar grades at most
`substituted`; it is `exact` only when the **Backend's own server-side recompute** of the same manifest
reports `match` (a server-origin `restore_verified` event with `backend_match_result = match`).

---

## 5. Claim predicates

`ClaimPredicateV0` is what the claims compiler may sign. Each carries `evidence_source` and
`supporting_event_refs`; the schema pins the source per type:

| `predicate_type` | Supporting event | `evidence_source` | Plain meaning (rendered with its source label) |
|---|---|---|---|
| `declared` | `declared` | `client_reported` | "this version was declared" |
| `captured` | `captured` | `client_sdk_reported` | "a capture was stored at T" (historical) |
| `restorable_now` | `captured` + latest `availability_changed` = `available`, per manifest | `client_sdk_reported` | "restorable as of the statement time" (current) |
| `restore_verified_client_reported` | `restore_verified` client origin, `outcome = exact`, coverage `complete` | `client_sdk_reported` | "the client-side SDK reports a verified restore" |
| `restore_verified_backend_matched` | `restore_verified` server origin, `outcome = exact`, coverage `complete` | `server_recorded` | "the Backend recomputed and matched the restored content" |
| `bound_to_run` | `bound_to_run` | `server_recorded` | "this version was bound to this run tuple" |
| `evaluated_client_reported` | `evaluated`, client origin | `client_reported` | "the client reports an evaluation" |
| `evaluated_traigent_witnessed` | `evaluated`, server origin | `traigent_witnessed` | "Traigent witnessed this evaluation" |

**Evidence must match, not just exist.** A supporting event counts only if it has the same
`version_ref` (subject), the same `recovery_manifest_fingerprint` (recovery predicates), the same
`run_tuple_digest` (and for `evaluated_*`, the same `evaluated_subset_root` and `evaluation_protocol`,
which are part of the signed predicate), the required origin/source, and `recorded_at <= as_of`
(statement cutoff). The required event *type* alone is not enough.

**Availability (conservative).** Availability starts **unknown** for every capture. Only an
`availability_changed` event establishes it (`available | missing | corrupted | retired`), and the latest
one per manifest wins:
`restorable_now(manifest, prefix) iff captured(manifest, prefix) and current_availability(manifest, prefix) = available`.
Version-level aggregation: a version is `restorable_now` iff **at least one** of its captures is
`restorable_now`; it carries no claim about which, nor about completeness or exactness (those are separate
predicates).

A signature authenticates the statement, not the truth of a client assertion. A later event produces a
**new** statement; an issued statement is never edited. The compiler extends the existing certification
compiler and preserves its refusals (for example `config_linkage_unverified`). `policy_version` is a
lowercase token, not a closed enum: the compiler holds an allowlist of issued policy versions and refuses
others. Syntax alone does not make a token content-free (an arbitrary lowercase token validates), so the
allowlist, not the pattern, is the safeguard.

---

## 6. Director operations (closed menu)

Five operations, behind `director_legend_ops_enabled` (default off). Each has an **instruction**
(Director to agent; one operation plus opaque refs) and a **result** (agent to backend; enums, refs,
digests, integers, booleans). Refs are `<kind>ref_<32 hex>`; no names, paths, store messages or adapter text.

| Operation | Instruction fields | Result fields |
|---|---|---|
| `declare_version` | `kind`, `entity_ref|null` | `version_ref|null`, `created` |
| `query_versions` | `entity_ref`, `page_size`, `page_cursor|null` | `version_refs[]`, `next_page_cursor|null` |
| `capture_version` | `version_ref` | `store_status`, `recovery_manifest_fingerprint|null`, `coverage|null`, `conformance_passed` |
| `verify_restore` | `version_ref`, `recovery_manifest_fingerprint` | `restore_outcome|null`, `coverage|null`, `store_status`, `backend_match_result` |
| `restore_version` | `version_ref`, `recovery_manifest_fingerprint` | `restore_outcome|null`, `coverage|null`, `store_status`, `activated` (always false) |

Result rules the schema enforces: `outcome` (`succeeded | refused | failed`) with `error_code` non-null iff
not `succeeded`; `restore_outcome = exact` requires non-null `coverage` with `status = complete`
(`verify_restore` and `restore_version`; the same-manifest evidence check is the Backend's); a
`capture_version` success requires a stored status (`stored_unverified | round_trip_verified`), a
manifest fingerprint and coverage, and `round_trip_verified` requires `conformance_passed`. Error codes:
`store_key_conflict`, `invalid_request`, `unknown_ref`, `foreign_ref`, `flag_disabled`,
`conflicting_report`, `conflicting_idempotency_payload`, `store_not_configured`, `store_unavailable`,
`conformance_failed`, `manifest_mismatch`, `coverage_insufficient`, `restore_failed`, `internal_error`.
Adding an operation is a reviewed contract change (a new menu operation plus a closed result schema),
never a widened field.

---

## 7. Invariants (for the model checker, item 9)

Numbered so counterexamples and conformance cases can cite them. "Events" means the ledger.

**Assumptions the model must state before checking.**
- *INV-1 fold.* Each axis state is a deterministic fold over the ledger in `(recorded_at, event_ref)`
  order; the fold rules are the ones in section 5 (availability: latest per manifest; evaluation:
  strongest source present). The model fixes this order and the fold, and does not model clock skew.
- *INV-2 trusted assignment.* `origin` and `evidence_source` are assigned by the server from the
  authenticated route, never read from the request body. The model treats the route as trusted and the
  body as adversarial.
- *INV-7 binding.* "Verified before activation" is bound to the **staged artifact**: activation consumes
  a restore whose manifest fingerprint and representation digests equal those verified. The model treats
  the staged bytes as an abstract value identified by that digest; real byte equality is outside it.
- Abstract hash equality does not prove exporter correctness or real recovery.

- **INV-1 Append-only.** The ledger only grows; no event or version row is updated or deleted; every
  derived axis state is a function of the event prefix.
- **INV-2 Non-escalation.** An event with `origin = client` has `evidence_source` in
  {`client_reported`, `client_sdk_reported`}; no sequence of client events produces `server_recorded`
  or `traigent_witnessed`; `traigent_witnessed` exists only on server-origin `evaluated` events.
- **INV-3 Exact is unreachable on partial coverage.** `restore_verified` with `outcome = exact` implies
  `coverage.status = complete` (every `RequiredComponents(kind)` covered), both equalities, an isolated
  destination, available historical key and verified dependencies; a missing key, dependency,
  unverifiable fingerprint or substitution yields `partial | substituted | failed`, never `exact`.
- **INV-4 Idempotent declare.** `declare` on an existing version identity appends a `declared` event and
  creates no second version, except that an identical retry (same `idempotency_key`, equal
  `request_digest`) appends nothing; concurrent explicit and implicit declarations converge to one
  version; the same key with a different digest is refused.
- **INV-5 Acyclic initial parents (scope).** Only `initial_parent_version_ref` is constrained: set on the
  first declaration only, same entity, declared earlier, no cycle (including self).
  `previous_version_ref` edges are unconstrained history; a revert v3 -> v1 is legal.
- **INV-6 Historical vs current availability.** `captured` is a fact about time T and is never erased;
  availability starts unknown; `restorable_now(manifest)` holds iff the manifest was captured and its
  latest availability event is `available`; a version is `restorable_now` iff at least one capture is.
  Revoking availability leaves `captured` intact.
- **INV-7 Activation separation.** No Director operation activates; `restore_version` always reports
  `activated = false`; activation requires a prior `restore_verified` of the same manifest fingerprint
  with `outcome = exact` on the same staged artifact.
- **INV-8 Capture vs round trip.** `recovery_state = round_trip_verified` implies `conformance_passed` and
  a completed isolated round trip; a put acknowledgement alone yields `stored_unverified`; a no-op store
  never yields a successful capture.
- **INV-9 Representation plus pillar equality.** Exact recovery requires both equalities: ordered
  representation digests equal the manifest's, and the recomputed pillar fingerprint equals the declared
  one. Equal pillar root with different representation order is not exact.
- **INV-10 Scoped keyed identity.** Version identity includes scheme and `key_id`; the same fingerprint
  under a different `key_id` or tenant is never merged; each entity maps to at most one authoritative
  identity.
- **INV-11 Immutable bindings.** Each binding slot `(run, trial, role, slot)` holds exactly one run-tuple
  digest; a conflicting second binding for a consumed slot is refused and appends nothing; several
  versions per run (different slots) remain allowed; a trial candidate always has a trial.
- **INV-12 Evaluation binds the exact tuple.** An `evaluated` event and its predicates bind the
  `run_tuple_digest`, the evaluated subset root and the protocol; a supporting event counts only if
  subject, manifest, tuple, source and cutoff match (section 5); a predicate whose matching evidence is
  absent does not exist.
- **INV-13 Closed bridge.** Instructions and results contain only the closed typed schemas' values (opaque
  refs, enums, digests, bounded integers, booleans); no free text; a foreign ref (another tenant or
  project) is refused; conflicting reports for one instruction are refused.
- **INV-14 Distinct captures never overwrite.** Captures with different manifest fingerprints never share
  a store key; a put of an existing key with different bytes is `store_key_conflict`; conformance keys are
  disjoint from manifest fingerprints.
- **INV-15 Version identity is stable under re-declaration.** Re-declaring a version changes none of its
  entity, scheme, key_id, fingerprint, initial parent, identity_source or declared_at; only the ledger
  grows.
- **INV-16 Backend-keyed grading.** For `search_space` (and keyed evaluator leaves) a client-origin
  restore is at most `substituted`; `exact` requires a server-origin restore event with
  `backend_match_result = match`; `mismatch` implies not `exact`.
- **INV-17 Identity-digest reproduction.** A capture of an agent or evaluator is `complete` only if the
  exporter reproduced the same identity-construction digests recorded for the version; otherwise
  coverage is `partial` and `exact` is unreachable. Skipped files force `partial`.

---

## 8. Names chosen in v0

Invented in this contract; a reviewer should confirm or rename them before consumers are built.

| Name / format | Value |
|---|---|
| Manifest fingerprint | `rmf0:sha256:<64 hex>`; domain and manifest scheme `traigent.recovery_manifest.v0` |
| Conformance key | `rmfc0:sha256:<64 hex>` (reserved synthetic namespace) |
| Idempotency key | `idk_<32 hex>` (fresh per logical request) |
| Request digest | `sha256:` + hex over domain `traigent.legend.request.v0` |
| Run tuple commitment | `sha256:` + hex over domain `traigent.legend.run_tuple.v0`, `jcs_v1` of the five-pillar object (section 3.3) |
| Opaque ref prefixes | `entityref_`, `versionref_`, `eventref_`, `runref_`, `trialref_`, `actorref_`, `instructionref_`, each + 32 lowercase hex |
| Page cursor | `cursor_<32 hex>` |
| `source_authority` | `agent_builds`, `evaluator_versions`, `dataset_versions`, `run_search_space_records`, `run_identity_bindings`, `none` |
| `change_reason` | `code`, `prompt`, `configuration`, `dataset_content`, `dependency`, `rollback`, `unspecified` |
| Coverage components | `code`, `prompts`, `helper_modules`, `tool_definitions`, `applied_config`, `dependency_lock`, `dataset_members`, `dataset_order`, `evaluator_code`, `judge_config`, `objectives`, `search_space_definition`, `runtime` |
| `binding_role` | `base_agent`, `trial_candidate`, `dataset`, `search_set`, `evaluator`, `search_space` |
| `evaluation_protocol` | `full_dataset`, `holdout`, `sampled_subset`, `search_set` |
| `backend_match_result` | `not_applicable`, `not_checked`, `match`, `mismatch` |
| Representation kinds | `source_bundle`, `prompt_files`, `helper_modules`, `tool_definitions`, `config_document`, `dependency_lock`, `dataset_rows`, `evaluator_bundle`, `judge_config_document`, `search_space_document` |
| Store statuses / error codes | as listed in sections 4 and 6 |
| Predicate types | as listed in section 5; `policy_version` is a lowercase token checked against a compiler-held allowlist |
| Field `key_id` | the plan's `key_version`: the tenant `kid`, null for unkeyed schemes |

---

## 9. What stays outside this contract

Backend tables and API (items 2, 3), run binding and legacy backfill (item 4), Director dispatch
(item 5), signed version subjects (item 6), SDK client, store and activation (items 7, 8) implement this
contract. They must not widen a field to free text. JSON Schema cannot express, and the consumers or the
reference model in `tests/test_pillar_legend_v0_schemas.py` must enforce: kid equals `key_id`, disjoint
`covered`/`missing`, `ordinal` equals position, calendar validity of timestamps (for example 30
February), the unique authority mapping, initial-parent acyclicity, key/digest conflict, slot
immutability, and evidence matching for predicates.
