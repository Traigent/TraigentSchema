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
   **Unique mapping.** Each entity maps to at most one existing authoritative identity. The internal
   grouping key is `(tenant, project, kind, source_authority, authoritative entity id)` where the authority
   has an entity id of its own (agent id for `agent_builds`, evaluator id for `evaluator_versions` and
   `evaluator_version_manifests`, dataset id for `dataset_versions`), and the entity is Legend-only
   (`source_authority = none`) otherwise (configuration, search space per run). The grouping key is never on
   the wire. Different agents can share a build digest, so a fingerprint alone never selects an authority
   row: the lookup is `(tenant, project, kind, authoritative entity id, fingerprint)`. Two entities can
   never represent the same authoritative identity: the mapping is two-directional. A `declare` with
   `entity_ref = null` and a scoped grouping key that already has an entity **resolves to that entity**; a
   link that would give an entity a second authority group (across any of its versions) or another entity's
   group is refused. A declaration without a source row is allowed. When a
   source row appears later the server appends an `authority_linked` event (append-only association,
   never an update of the immutable version); "linked" is derived from the ledger prefix.
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
(`entityref_<32 hex>`), `kind`, `source_authority` (`agent_builds | evaluator_versions | evaluator_version_manifests |
dataset_versions | run_search_space_records | run_identity_bindings | none`), `created_at`. The mapping
from an existing authoritative identity to its entity is unique (principle 1); the internal authority key
stays internal. Human names stay client-side in a local alias file. Tenant and project come from the
canonical request context, never from a header or body field.

### 3.2 Version

A **version** is immutable: `(entity_ref, kind, fingerprint_scheme, key_id, fingerprint,
initial_parent_version_ref, identity_source, declared_at)` with its own `version_ref`.

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
`evidence_source`, a server-assigned `ledger_position`, human-time `recorded_at`, `idempotency_key` and `request_digest` (section 3.4).

**Ledger position.** `ledger_position` is a strictly increasing integer per `(tenant, project)` ledger and is the only order. Events with equal `recorded_at` are ordered by position, never by ref or time. A signed predicate cites a prefix by `ledger_cutoff_position`; `as_of` stays the human timestamp. Reconstruction of a signed snapshot selects events with `ledger_position <= cutoff`.

**Sealed prefix.** A statement may cite only `cutoff <= sealed_committed_high_water_mark` of the authenticated tenant/project ledger (a larger cutoff is refused, `invalid_request`). Positions are allocated **at commit time under a per-ledger lock**, so an in-flight write has no position yet and a later-visible event can never acquire a position inside an issued prefix. The high-water mark is read under the same lock when the statement is signed.

| `event_type` | Origin | `evidence_source` | Type-specific fields |
|---|---|---|---|
| `authority_linked` | server | `server_recorded` | `source_authority` (appended when an authoritative source row for the version is found; never updates the version) |
| `declared` | client; **server only for `implicit_legacy` backfill** | `client_reported` | `provenance` (`explicit | implicit_run | implicit_legacy`), `identity_source`, optional `previous_version_ref`, optional `change_reason`. `implicit_legacy` implies server origin and `identity_source = client_declared` (never `sdk_fingerprinted`) |
| `captured` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `coverage`, `recovery_state` (`stored_unverified | round_trip_verified`), `conformance_passed`, `exporter_version`, `backend_keyed`, `identity_verification_ref` (required when `backend_keyed` and coverage `complete`), `representation_commitment`, `identity_digests_reproduced` |
| `restore_verified` | client, or server (Backend recompute) | client: `client_sdk_reported`; server: `server_recorded` | `kind`, `recovery_manifest_fingerprint`, `outcome`, `coverage`, `isolated_destination`, `representation_digests_match`, `pillar_fingerprint_match`, `backend_match_result` (`not_applicable | not_checked | match | mismatch`; `match|mismatch` only server-origin, `not_applicable|not_checked` only client-origin) |
| `identity_verified` | server | `server_recorded` | `representation_commitment` (sha256 over the ordered representation digests), `backend_recomputed`, `result` (`match | mismatch`); appended **before** capture, bound to the version |
| `bound_to_run` | server | `server_recorded` | `run_ref`, `trial_ref` (the **context's** trial, nullable), `slot_scope` (`run | trial`), `binding_role`, `binding_slot`, `run_tuple_digest` (the context's final digest); emitted atomically at `start_execution` |
| `evaluated` | client or server | client: `client_reported`; server: `traigent_witnessed` | `run_ref`, `trial_ref` (nullable; must name a started context), `run_tuple_digest`, `evaluated_subset_root` (`msr1:`), `evaluation_protocol` |
| `availability_changed` | client | `client_sdk_reported` | `recovery_manifest_fingerprint`, `status` (`available | missing | corrupted | retired`) |

**Role-to-kind matrix and scopes.** Every pillar has an explicit binding role:

| `binding_role` | pillar (`kind`) | scope |
|---|---|---|
| `base_agent` | agent | run |
| `run_base_configuration` | configuration | run |
| `dataset`, `search_set` | evaluation dataset | run |
| `search_space` | search space | run |
| `evaluator` | evaluator | run **or** trial |
| `trial_candidate` | agent | trial |
| `trial_configuration` | configuration | trial |

A version of the wrong kind for a role is refused (`invalid_request`). Replacement happens **only within the
same pillar**: `trial_candidate` replaces `base_agent`, `trial_configuration` replaces
`run_base_configuration`; neither touches the other pillar. Evaluator slots are keyed `(scope, slot)`, so a
run-level slot 0 and a trial-level slot 0 coexist and both appear in the tuple.

**Slots are proposals; contexts freeze them.** An *execution context* is `(run, trial | null)`; `null` is
the run-base context. Binding a slot before `start_execution` records a *proposal* and emits no evidence.
`start_execution(context)` freezes that context atomically: it fixes the effective bindings, computes the
context's final `run_tuple_digest`, and emits one `bound_to_run` event per consumed slot carrying that final
digest. The run-base context freezes separately from each trial's (a trial generated later can still bind
its own `trial_candidate`); a trial context requires the run-base context to be started. An identical
replay (same slot and version, or an identical start) is a no-op, including after freezing; a different
version for a frozen slot is refused (`conflicting_report`).

**Effective bindings and the run tuple.** `EB(context)` is every run-scope slot, minus those replaced within
their pillar by the trial's own slots, plus the trial's slots. The commitment is
`run_tuple_digest = "sha256:" + hex SHA-256(UTF8("traigent.legend.run_tuple.v0") || 0x00 || jcs_v1(T))`
with `T = {"entries": [{role, scope, slot, fingerprint_scheme, key_id, fingerprint}, ...]}`, sorted by (role
in matrix order, `scope`, `slot`, `fingerprint_scheme`, `key_id` (null first), `fingerprint`). The Backend
computes it from its own frozen rows; a client-supplied digest is never trusted.

**Strict and permitted drift.** `start_execution` compares the **complete** observation, keyed by
`(role, scope, slot)`, with the expected bindings: the key sets must be equal (an empty or partial
observation is refused, `manifest_mismatch`). In `strict` mode any version mismatch refuses before
execution and changes nothing. In `permitted` mode drift is allowed **only in the context's own slots**: a trial may drift its trial-local slots, but never an inherited run-scope slot, because that slot is already frozen by the run-base context (`conflicting_report`; a fresh run is needed). A drifted observation is resolved *before* the immutable
bindings are inserted: the observed version must already be declared and of the right kind
(`unknown_ref` / `invalid_request`); it replaces the proposal inside the same atomic step, then the context
freezes. A context that already started with a different tuple refuses (`conflicting_report`): drift after
binding needs a fresh run/trial context.

**Persisted snapshots.** `start_execution` persists the context's effective-binding snapshot together with its digest. Evaluation membership and replay use that snapshot, never the live proposals; a replay with an incomplete observation is refused before it can be accepted as identical.

**Evaluation admission.** An `evaluated` event names `(run_ref, trial_ref | null)` and is admitted only if
that context **has started**, its `run_tuple_digest` equals the stored final digest, and its subject
version is a member of the context's effective bindings (`foreign_ref` otherwise). Witnessed evidence must
derive from that scoring execution's context.

### 3.4 Idempotency and conflict refusal

- **Request key.** `idempotency_key` is a fresh opaque key (`idk_<32 hex>`) minted once per *logical*
  declaration/record and reused unchanged on every retry of that request. Scope:
  `(tenant, project, endpoint)`. It is never derived from content, so repeated legitimate movements
  `A->B`, `B->A`, `A->B` each carry their own key and each append.
- **Request digest.** `request_digest = "sha256:" + hex SHA-256(UTF8("traigent.legend.request.v0") || 0x00
  || jcs_v1(body))` over the **validated client request body, excluding only `idempotency_key` and
  `request_digest`**. Every input reference (`entity_ref`, `version_ref`, ...) is part of the body, so two
  requests that target different entities or versions never share a digest. An optional field that is
  absent is different from the same field present as `null`; clients send the canonical form. The Backend
  **recomputes** the digest from the validated body before comparing it with the stored one, and persists
  and returns the original result for a retry.
- Same key + equal digest = a retry: return the first result, append nothing. Same key + different
  digest is refused (`conflicting_idempotency_payload`).
- `declare` of an existing version identity never creates a second version and never changes the stored
  version; it appends a `declared` event (rollback is exactly this case). Explicit and `implicit_run`
  declarations of one fingerprint converge on one version.
- A first declaration whose initial parent is itself, another entity's version, or undeclared is refused
  (`invalid_request` / `unknown_ref`).
- A report that conflicts with an earlier report for the same issued instruction is refused
  (`conflicting_report`).

**Every record transition** (`declare`, `capture`, `record_restore`, `record_availability`, identity verification) applies the endpoint-scoped key/digest rule before any mutation: the saved key is `(endpoint, idempotency_key)`, a retry returns the saved response and appends nothing, and a different payload under the same key is `conflicting_idempotency_payload`. The same logical content under a fresh key is a new record.

Client request bodies (`legend_requests_v0.json`) carry client fields only: `DeclareRequestV0`,
`QueryRequestV0`, `RecordCaptureRequestV0`, `RecordAvailabilityRequestV0`, `RecordRestoreRequestV0`. The server issues refs, actor, time,
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

**Verified artifact identity.** Both exact paths record an abstract artifact digest for the verified staged artifact, immutable per `(entity, manifest)` (a second, different digest is `conflicting_report`). `activate` compares the actual target digest with it and records the activated artifact; a substituted artifact is refused (`manifest_mismatch`).

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

**Pre-capture identity verification.** For a Backend-keyed version the capture manifest cannot be both
complete and already server-matched (the match needs the capture). The server therefore appends an
`identity_verified` event *first*: bound to the version and to the exporter's `representation_commitment`
(sha256 over the ordered representation digests), with Backend recomputation for keyed kinds. The final
manifest is then built, citing that event (`identity_verification_ref`), and complete coverage on a
backend-keyed capture requires a cited event for the same version with `result = match`, `backend_recomputed = true`, and a `representation_commitment` **equal to the commitment derived from the manifest's own ordered representations** (so a proof for other representations cannot be reused; the SDK derives the commitment locally, the Backend joins it to the proof). Changing coverage after the
proof changes the manifest fingerprint but not the proof.

**ExactPrerequisites(version, capture metadata, restore measurements)** is one predicate, applied by both restore paths (client `record_restore` and the
Backend `server_match`). It **reads the immutable capture metadata** persisted at capture time for the manifest (coverage `complete`, identity digests reproduced, proof linkage, authoritative format known); no caller boolean can upgrade a partial capture. Only restore-time measurements come from the restore report: both equalities, isolated destination, historical key available, dependencies verified. A restore report must agree with that same manifest; improving a capture's coverage requires a **different manifest fingerprint**, and re-capturing an existing fingerprint with different metadata is `store_key_conflict`. For `BackendKeyed(version)` the Backend recomputation
(`server_match` returning `match`) is additionally required; the client path can never reach `exact`.

**Backend-keyed pillars.** `BackendKeyed(version)` is derived from the version's scheme and, for an
evaluator, from the authoritative manifest format: it is true for `search_space_ssp1` (`K_search_space`),
and for an evaluator whose authoritative manifest is `be.evaluator_manifest.keyed_leaves.v0` (keyed
`evd1` leaves, `K_eval`). Unknown format, or unavailable server verification, counts as backend-keyed (it
can never be graded `exact`). The request/event `kind` must match the resolved version, and the schema
carries `backend_keyed` so the rule is checkable at the wire: a backend-keyed pillar is never `exact` from a
client-origin report. It is `exact` only when the **Backend's own server-side recompute** of the same manifest
reports `match` (a server-origin `restore_verified` event with `backend_match_result = match`). A
Backend-assisted reproduction of the keyed identity digests during capture satisfies INV-17 through the
**pre-capture `identity_verified` proof** (below), not through a restore match; the client alone cannot claim
`identity_digests_reproduced` for such a pillar. **An unknown authoritative format never reaches `match` or
`exact`**: format availability is checked explicitly, before `identity_verify` can return `match` and
before `server_match` can return `exact`; key availability alone does not satisfy it (`store_unavailable`).

---

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

**Subject and joins.** The predicate subject (`version_ref`, `kind`, `fingerprint_scheme`, `key_id`,
`fingerprint`) must equal the authoritative version projection, not merely validate. Recovery predicates
join through `Captured(version, manifest)`: a `captured` event for exactly that version and manifest in the
prefix; availability and restore events count only through that join. A manifest captured for version A is
never evidence for version B.

**Evidence must match, not just exist.** A supporting event counts only if it has the same
`version_ref` (subject), the same `recovery_manifest_fingerprint` (recovery predicates), the same
`run_tuple_digest` (and for `evaluated_*`, the same `evaluated_subset_root` and `evaluation_protocol`,
which are part of the signed predicate), the required origin/source, and `ledger_position <= ledger_cutoff_position`
(signed prefix cutoff; `as_of` is only the human time). The required event *type* alone is not enough.

**All eight relations.** `declared`: a `declared` event for the subject in the prefix. `captured`: `Captured(version, manifest)`. `restorable_now`: as below. `restore_verified_client_reported` / `restore_verified_backend_matched`: an `exact` restore event of that origin for `(version, manifest)` whose immutable capture metadata is complete. `bound_to_run`: a `bound_to_run` event for the subject with the same context tuple digest and trial context. `evaluated_*`: an `evaluated` event with the same subject, tuple digest, trial context, source, **evaluated subset root and protocol**. Evaluation events retain subset root and protocol so issuance can compare them.

**Availability (conservative).** Availability is **per capture (manifest)** and starts **unknown**. Only an
`availability_changed` event establishes it, and the event with the highest `ledger_position` inside the
cited prefix wins:
`restorable_now(manifest, prefix) iff captured(manifest, prefix) and latest_availability(manifest, prefix) = available`.
There is no singular version-level availability. A version is `restorable_now` iff **at least one** of its
captures is; that carries no claim about which capture, completeness or exactness (separate predicates).

**Axis fold (total).** Over a ledger prefix: `identity_source` is the value of the version's first
declaration (immutable; later declarations with another value are refused); `recovery_state` is the
**strongest historical proof** over all captures (`round_trip_verified > stored_unverified > none`),
independent of order; `evaluation_state` is the strongest source present (`traigent_witnessed >
client_reported > none`); `authority_linked` is true iff an `authority_linked` event is in the prefix;
availability is per manifest as above. Example: M1 round-trip verified then M2 stored-unverified gives
`round_trip_verified`, not the latest event's state.

A signature authenticates the statement, not the truth of a client assertion. A later event produces a
**new** statement; an issued statement is never edited. The compiler extends the existing certification
compiler and preserves its refusals (for example `config_linkage_unverified`). `policy_version` is a
lowercase token, not a closed enum: the compiler holds an allowlist of issued policy versions and refuses
others. Syntax alone does not make a token content-free (an arbitrary lowercase token validates), so the
allowlist, not the pattern, is the safeguard.

### 5.1 Signed claim statement (relying-party verification)

The Backend signs each compiled predicate as a **claim statement** `{subject, signature}`
(`legend_claim_statement_v0.json`, closed schema, no free text: statement text is one of eight fixed templates
paired to its `type`, `evidence_source` and `source_label`). The subject carries `schema_version`
`traigent.legend_claim_subject.v0`, `policy_version`, `statement`, the predicate `version`, `commitments`,
`coverage_status`, `supporting_event_refs`, `ledger_cutoff_position`, the issuer-controlled `as_of` and `issued_at`, and
`predicate_digest` (the replay identity). The `signature` envelope pins `domain`, `algorithm`
(`ed25519` or `ecdsa_p256_sha256`), `key_id`, `encoding` (`base64`) and `value` (raw 64-byte signature, low-S P1363 for
ECDSA).

**Signing input** = `UTF8("traigent.legend_claim_subject.signature.v0") || 0x00 || canonical_json(subject)`, with
`canonical_json = json.dumps(subject, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`.
The schema restricts every subject string to ASCII, so these bytes equal the fp2/RFC 8785 form. The domain differs
from the process-record issuer domain (`traigent.process_record.issuer_signature.v1`), so a signature of one kind never
verifies as the other: the verifier refuses a foreign domain label (`DOMAIN`) and a foreign-domain signature under the
Legend label (`SIGNATURE_INVALID`).

**Verifier.** `traigent_schema.legend_claim_verifier.verify_legend_claim_statement(statement, trusted_keys)` is offline
and takes a pinned `{key_id: TrustedLegendKey(algorithm, public_key)}`. Order: structure, domain, closed schema,
algorithm/key lookup (unknown key `UNKNOWN_KEY`, algorithm mismatch `ALGORITHM`), signature decode, recomputed canonical
bytes, signature check. Any tampering fails `SIGNATURE_INVALID`. Errors carry only a fixed content-free code. Golden
vectors (test-only key, one valid, four negatives) are in `tests/legend_claim_statement_v0_vectors.json`. A valid
signature authenticates the statement, not the truth of a client assertion (section 5).

---

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

Result rules the schema enforces (an agent-supplied `backend_match_result = match` never substitutes for the Backend's own recompute; the Backend resolves the issued instruction's authoritative version and manifest and requires the applicable restore evidence before accepting `exact`): `outcome` (`succeeded | refused | failed`) with `error_code` non-null iff
not `succeeded`; `restore_outcome = exact` requires non-null `coverage` with `status = complete`, `store_status = retrieved`, outcome `succeeded`, and (for `verify_restore`) no `mismatch`
(`verify_restore` and `restore_version`; the same-manifest evidence check is the Backend's); a
`capture_version` success requires a stored status (`stored_unverified | round_trip_verified`), a
manifest fingerprint and coverage, and `round_trip_verified` requires `conformance_passed`. Error codes:
`store_key_conflict`, `invalid_request`, `unknown_ref`, `foreign_ref`, `flag_disabled`,
`conflicting_report`, `conflicting_idempotency_payload`, `store_not_configured`, `store_unavailable`,
`conformance_failed`, `manifest_mismatch`, `coverage_insufficient`, `restore_failed`, `internal_error`.
**Wire-to-model projection.** The closed restore results carry no manifest field. The manifest, version and entity of a `verify_restore` / `restore_version` result are those of the **saved instruction**; the Backend joins them to its ledger. Capture results carry `recovery_manifest_fingerprint`, compared with the instruction's version.

**Pagination.** `query_versions` orders versions deterministically by the ledger position of their first declaration, over a snapshot. `page_size` is 1..100. A continuation cursor is `cursor_<hex>`, bound to `(entity, boundary index, as_of)`; an unissued cursor, one issued for another entity, or one issued under another `as_of_ledger_position` (including none) is refused (`invalid_request`). The result must be exactly the instruction's slice `order[start:start+page_size]`, and `next_page_cursor` must be the cursor for the next boundary, or null at the end. The wire names are `page_cursor` (instruction and `QueryRequestV0`) and `next_page_cursor` (result); the model and tests use exactly these names. Projection: wire `version_refs` correspond to the model's ordered versions.

**Snapshot selector.** `QueryRequestV0` has an optional `as_of_ledger_position` (integer >= 0). Results include only versions whose first declared event has `ledger_position <= as_of_ledger_position`; omitted means current. A value above the current ledger position is refused (`invalid_request`). The cursor binding above makes a multi-page read stable under later writes only when every page passes the same explicit `as_of_ledger_position`; with it omitted each page reads the then-current ledger.

**Cursor provenance.** Page cursors are opaque, server-issued strings from ONE issuer shared by the Legend API and the Director. A Director query instruction carries a cursor returned by the Legend API (or by an earlier Director page), never one composed by the Director or the agent. On the Director path the cursor must have been issued under an explicit `as_of_ledger_position`, and the instruction keeps that position. A query result with outcome `failed` or `refused` MUST carry `next_page_cursor` null (schema `if/then` on `QueryVersionsResult`; the model refuses it with `invalid_request`).

**Director response envelopes** (`director_legend_ops_v0.json`, closed, no free text). `LegendInstructionMember` is the `legend` member added to a Director instruction: `operation`, the opaque refs and enums of that operation (the other fields null), `page_size`, `page_cursor`, and `as_of_ledger_position`, the instruction's snapshot ledger position, non-null exactly for `query_versions`. **That value is what the agent must pass as `as_of_ledger_position` in the Legend query request.** The snapshot is not a separate `legend_snapshot` member: it is folded into this one closed place. `LegendResultAckMember` is the `legend` member of the result acknowledgement: `ack_status` (`stored | identical_retry | rejected`), `error_code` (non-null iff `rejected`), and `as_of_ledger_position` (echo of the instruction's snapshot for `query_versions`, null otherwise).

**Per-operation relation between instruction and result** (the Backend checks these before storing a
result): `declare_version` — the returned version belongs to the instruction's entity (when given) and
kind and exists, and a success has a non-null `version_ref`; `query_versions` — every returned ref belongs
to the instruction's entity and the cursor continues the issued page; `capture_version` — the instruction's
version and the result's `recovery_manifest_fingerprint` have a `captured` event on the ledger; `verify_restore` /
`restore_version` — the instruction's version, the **instruction-bound** manifest (results carry none), and (for `exact`) a matching
Backend-recorded `exact` restore for that version and manifest plus the verified staged artifact. An
**identical** result retry returns the saved result; a differing report for the same instruction is
refused atomically (`conflicting_report`).

Adding an operation is a reviewed contract change (a new menu operation plus a closed result schema),
never a widened field.

---

## 7. Invariants (for the model checker, item 9)

Numbered so counterexamples and conformance cases can cite them. "Events" means the ledger.

**Assumptions the model must state before checking.**
- *INV-1 fold.* Each axis state is the total fold of section 5 over the ledger prefix ordered by
  `ledger_position` (never by time or ref, so timestamp ties do not matter).
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
- **INV-6 Historical vs current availability.** `captured` is a fact about position P and is never
  erased; availability is per manifest, starts unknown, and the highest-position `availability_changed`
  inside the cited prefix wins; `restorable_now(manifest)` holds iff captured and that latest availability
  is `available`; a version is `restorable_now` iff at least one capture is. There is no singular
  version availability. Revoking availability leaves `captured` intact.
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
- **INV-11 Immutable bindings.** Each binding slot `(run, trial, role, slot)` holds exactly one version
  (hence one tuple contribution); a conflicting second binding is refused and appends nothing; bindings
  are frozen at `start_execution`; several versions per run (different slots) remain allowed; a trial
  candidate always has a trial; `run_tuple_digest` is the canonical effective-binding digest of section 3.3.
- **INV-12 Evaluation binds the exact tuple and membership.** An `evaluated` event is admitted only if its
  digest equals the Backend's recomputation from frozen bindings and its subject version is a member of
  the effective bindings; predicates bind digest, subset root and protocol, and cite a ledger prefix; a
  supporting event counts only if subject, manifest, tuple, source and prefix match; absent matching
  evidence means the predicate does not exist.
- **INV-13 Closed bridge.** Instructions and results contain only the closed typed schemas' values (opaque
  refs, enums, digests, bounded integers, booleans); no free text; a foreign ref (another tenant or
  project) is refused; conflicting reports for one instruction are refused.
- **INV-14 Distinct captures never overwrite.** Captures with different manifest fingerprints never share
  a store key; a put of an existing key with different bytes is `store_key_conflict`; conformance keys are
  disjoint from manifest fingerprints.
- **INV-15 Version identity is stable under re-declaration.** Re-declaring a version changes none of its
  entity, scheme, key_id, fingerprint, initial parent, identity_source or declared_at; only the ledger
  grows.
- **INV-16 Backend-keyed grading.** For every `BackendKeyed(version)` (search space, keyed evaluator
  manifests, unknown format) a client-origin restore is at most `substituted`; `exact` requires a server-origin restore event with
  `backend_match_result = match`; `mismatch` implies not `exact`.
- **INV-17 Identity-digest reproduction.** A capture of an agent or evaluator is `complete` only if the
  exporter reproduced the same identity-construction digests recorded for the version; otherwise
  coverage is `partial` and `exact` is unreachable. Skipped files force `partial`.

- **INV-18 Atomic refusal.** A refused operation changes no state: no entity, version, event, slot,
  frozen context, cached response, staged artifact or instruction.
- **INV-19 Contexts.** A context `(run, trial|null)` freezes once; its `bound_to_run` evidence carries its
  own final tuple digest; the run-base freeze does not prevent later trial contexts; evaluation names a
  started context.
- **INV-20 Sealed prefix.** A signed statement's cutoff is at most the sealed committed high-water mark;
  positions are allocated at commit, so no event becomes visible inside an issued prefix.
- **INV-21 Subject and join integrity.** A predicate subject equals the authoritative version projection;
  recovery evidence joins through `Captured(version, manifest)`; a manifest of one version is never
  evidence for another.
- **INV-22 Exact prerequisites.** `exact` (client or server path) requires `ExactPrerequisites`; for a
  backend-keyed version it additionally requires a Backend recompute `match`, and complete backend-keyed
  coverage requires a prior matching `identity_verified` event for the version.

---

## 8. Names chosen in v0

Invented in this contract; a reviewer should confirm or rename them before consumers are built.

| Name / format | Value |
|---|---|
| Manifest fingerprint | `rmf0:sha256:<64 hex>`; domain and manifest scheme `traigent.recovery_manifest.v0` |
| Conformance key | `rmfc0:sha256:<64 hex>` (reserved synthetic namespace) |
| Ledger position | strictly increasing integer per (tenant, project) ledger; `ledger_cutoff_position` in predicates |
| Idempotency key | `idk_<32 hex>` (fresh per logical request) |
| Request digest | `sha256:` + hex over domain `traigent.legend.request.v0` |
| Run tuple commitment | `sha256:` + hex over domain `traigent.legend.run_tuple.v0`, `jcs_v1` of the sorted effective-binding entries (section 3.3) |
| Opaque ref prefixes | `entityref_`, `versionref_`, `eventref_`, `runref_`, `trialref_`, `actorref_`, `instructionref_`, each + 32 lowercase hex |
| Page cursor | `cursor_<32 hex>` |
| `source_authority` | `agent_builds`, `evaluator_versions`, `evaluator_version_manifests`, `dataset_versions`, `run_search_space_records`, `run_identity_bindings`, `none` |
| `change_reason` | `code`, `prompt`, `configuration`, `dataset_content`, `dependency`, `rollback`, `unspecified` |
| Coverage components | `code`, `prompts`, `helper_modules`, `tool_definitions`, `applied_config`, `dependency_lock`, `dataset_members`, `dataset_order`, `evaluator_code`, `judge_config`, `objectives`, `search_space_definition`, `runtime` |
| `binding_role` / `slot_scope` | `base_agent`, `run_base_configuration`, `dataset`, `search_set`, `evaluator`, `search_space`, `trial_candidate`, `trial_configuration`; `run | trial` |
| `evaluation_protocol` | `full_dataset`, `holdout`, `sampled_subset`, `search_set` |
| `backend_match_result` | `not_applicable`, `not_checked`, `match`, `mismatch` |
| Representation kinds | `source_bundle`, `prompt_files`, `helper_modules`, `tool_definitions`, `config_document`, `dependency_lock`, `dataset_rows`, `evaluator_bundle`, `judge_config_document`, `search_space_document` |
| Store statuses / error codes | as listed in sections 4 and 6 |
| Predicate types | as listed in section 5; `policy_version` is a lowercase token checked against a compiler-held allowlist |
| Field `key_id` | the plan's `key_version`: the tenant `kid`, null for unkeyed schemes |

---

## 9. Transition table

Every operation validates **all** guards first and commits its effects in one atomic step; a refusal
changes no state (no entity, version, event, slot, context, cached response, staged artifact,
instruction or counter). Codes are the closed `LegendErrorCode` values. "Prefix" is a ledger prefix by
`ledger_position`.

**Keyed transitions.** These seven use endpoint-scoped request keys: `declare`, `capture`,
`record_availability`, `record_restore` (client wire requests, key and digest on the wire) and the
server-side writers `identity_verify`, `server_match`, `evaluate` (the server mints its own key). The saved
key is `(endpoint, idempotency_key)`; before anything else the Backend validates the wire body, **recomputes
the digest over the complete validated body** (excluding only `idempotency_key` and `request_digest`; a
stale supplied digest is `invalid_request`), and only then projects references or reduces values. An
identical retry returns the **saved response** and appends nothing; the same key with a different recomputed
digest is `conflicting_idempotency_payload` (so a changed `exporter_version` or coverage arrays under one
key conflicts); the same content under a fresh key is a new record. **Omission creates a new logical write;
retries supply the retained original key** (generating another key during a real retry would defeat
deduplication).

**Exempt from the fresh-key rule.** `link_authority` and `start_execution` carry no request key; they are
idempotent by **natural identity**: `link_authority` by `(entity, fingerprint, authority group)` (an
identical association is a no-op, a different one is `conflicting_report`), and `start_execution` by
`(run, trial|null)` with the persisted snapshot (an identical complete observation returns the saved digest,
a different one is `conflicting_report`, an incomplete one `manifest_mismatch`). `bind` proposals replay by
`(slot, version)`.

| Operation | Wire input | Guards (refusal code) | Effects and saved response |
|---|---|---|---|
| `declare` | `DeclareRequestV0` | flag on (`flag_disabled`); valid body, kind/scheme/key/family, `ssp1` => `client_declared` (`invalid_request`); given entity in scope and of this kind (`foreign_ref`); `entity_ref = null` with a scoped grouping key that already has an entity **resolves to that entity** (no second entity); first declaration: initial parent not self (`invalid_request`), same entity and declared (`unknown_ref`); later: initial parent null or equal and `identity_source` equal (`invalid_request`); `previous` same entity and declared (`unknown_ref`) | creates the entity **only when none exists for the grouping key** (same commit as the version and event); creates the version on first declaration only; appends `declared`; saves `{entity, created, position}` |
| `link_authority` | server-side authority row | version in scope (`unknown_ref`); row exists for `(source_authority, group key, fingerprint)` (`unknown_ref`); the entity's group key equals the row's and the group maps back to this entity (`foreign_ref`); the entity has no different association across **any** of its versions (`conflicting_report`) | appends `authority_linked`; association unique and immutable; identical replay is a no-op |
| `bind` (proposal) | run, trial, role, slot, version | role-to-kind matrix and scope (`invalid_request`); version in scope; slot unfrozen or identical (`conflicting_report`) | stores the proposal; emits nothing; identical replay (also after freezing) is a no-op |
| `start_execution(context)` | run, trial, complete observation by `(role, scope, slot)`, mode | a trial context requires the run-base context started (`invalid_request`); **an empty observation always refuses** (`manifest_mismatch`), also when there are no proposals; replay: key set equals the snapshot (`manifest_mismatch`) then values equal (`conflicting_report`); key set equals expected (`manifest_mismatch`); **strict** mismatch refuses; **permitted** drift only in the context's own slots, never an inherited frozen run slot (`conflicting_report`), observed versions declared and of the right kind (`unknown_ref` / `invalid_request`) | persists the effective-binding snapshot and digest; rewrites only context-local proposals; appends one `bound_to_run` per consumed slot with the final digest; saves the digest |
| `identity_verify` | server-side: version, representation commitment, recomputation result | version in scope (`unknown_ref`); the authoritative format is known for backend-keyed kinds, key availability alone is not enough (`store_unavailable`) | appends `identity_verified` (`match | mismatch`, `backend_recomputed`, `representation_commitment`); saves `{position}` |
| `capture` (`capture_from_request` projection) | `RecordCaptureRequestV0` incl. `representation_commitment`, `identity_digests_reproduced`, `backend_keyed`, `identity_verification_ref` | version in scope; not a conformance key (`invalid_request`); claimed `backend_keyed` equals the derived value (`invalid_request`); `round_trip_verified` => `conformance_passed` (`conformance_failed`); **coverage is validated against `RequiredComponents(kind)` before any mutation** (`complete` without every required component is `coverage_insufficient`; overlapping or inconsistent arrays `invalid_request`); complete coverage => `identity_digests_reproduced` (`coverage_insufficient`); the `representation_commitment` has the single construction of the schema (`sha256:` + domain `traigent.legend.representation_commitment.v0`) in the proof and in the request; complete + backend-keyed: the cited `identity_verified` is for this version, `match`, `backend_recomputed`, and its commitment **equals the request's `representation_commitment`** (`coverage_insufficient`); the manifest fingerprint already exists with different coverage, reproduction, proof or commitment (`store_key_conflict`; recovery strength is not part of this comparison) | appends `captured` (client_sdk_reported) with the recovery state as **event evidence**; persists immutable metadata `{full canonical coverage object, reproduced, proof, commitment}` (a fresh-key report with other coverage arrays for the same manifest is `store_key_conflict`) (recovery strength is **not** metadata: a later round trip for the same manifest appends a stronger event); saves `{position}` |
| `record_availability` (`availability_from_request` projection) | `RecordAvailabilityRequestV0` | `Captured(version, manifest)` exists (`unknown_ref`); client origin | appends `availability_changed`; highest position per manifest wins; saves `{position}` |
| `record_restore` (`restore_from_request` projection) | `RecordRestoreRequestV0` incl. `historical_key_available`, `dependencies_verified`, `verified_artifact_digest` (required, true / non-null, for `exact`) | kind and `backend_keyed` equal the version's derived values (`invalid_request`); `Captured(version, manifest)` exists (`unknown_ref`); `exact` => `ExactPrerequisites` read from the immutable capture metadata plus restore-time measurements, and not backend-keyed (`coverage_insufficient`); no Backend match field (`invalid_request`); the reported coverage equals the immutable capture coverage (`manifest_mismatch`); `exact` without the artifact digest (`invalid_request`); a second, different verified artifact (`conflicting_report`) | appends client-origin `restore_verified` carrying the three summaries; an `exact` records the verified artifact digest; saves `{position}` |
| `server_match` | server-side recompute of the same manifest | `Captured(version, manifest)` exists (`unknown_ref`); format known and key held (`store_unavailable`); on `match`: `ExactPrerequisites` from the immutable metadata (`coverage_insufficient`); on `match` a second, different artifact (`conflicting_report`) | appends server-origin `restore_verified` (`match` => exact, `mismatch` => substituted); **only a `match` stages and records the artifact digest** — a mismatch records none and can never authorise activation; saves `{position}` |
| `evaluate` | server-side: run, trial, subject, tuple digest, subset root, protocol | context started and digest equals its persisted final digest (`manifest_mismatch`); subject in the persisted snapshot (`foreign_ref`); witnessed only from the scoring execution | appends `evaluated` with `trial_ref`, subset root and protocol; saves `{position}` |
| `issue_predicate` | type, subject projection, cutoff, manifest, tuple, trial, subset root, protocol | subject equals the authoritative projection and type is one of the eight (`invalid_request`); `0 < cutoff <= sealed high-water` (`invalid_request`); the type's matching evidence in the prefix (`unknown_ref`; `restorable_now`: `coverage_insufficient`): `declared`; `captured` through `Captured(version, manifest)` (partial captures are fine); `restorable_now` additionally needs the latest availability for that manifest to be `available` (`coverage_insufficient`), also for partial captures; `restore_verified_*` through `Captured(version, manifest)`, an `exact` event of the right origin, **and** complete immutable metadata; `bound_to_run` with tuple and trial, `evaluated_*` with tuple, trial, source, subset root and protocol | signs one statement citing the cutoff |
| `director_instruction` | operation, refs (`page_size` 1..100, `page_cursor`) | flag on; operation on the closed menu (`invalid_request`); refs in scope (`foreign_ref` / `unknown_ref`); restore operations need `Captured(version, manifest)`; `page_cursor` was issued for this entity (`invalid_request`) | stores the instruction with its entity/version/manifest binding and, for a query, the ordered snapshot and start boundary |
| `director_result` | instruction ref, closed result | instruction exists (`unknown_ref`); per-operation relation of section 6: declaration entity/kind/version, query exact slice and `next_page_cursor` (`foreign_ref` / `invalid_request`), capture manifest on the ledger, restore with the **instruction-bound** manifest, retrieval, no mismatch and Backend-recorded `exact` evidence (`manifest_mismatch`); an agent-supplied `match` is never evidence | stores the result once; issues the next cursor on commit; an identical retry returns the saved result; a differing second report is `conflicting_report` |
| `activate` | local, separately authorised | the artifact digest equals the one recorded by an `exact` restore of this manifest (`manifest_mismatch`); never a Director operation | records the activated artifact; never reverses external effects |

The model `Legend` in `tests/test_pillar_legend_v0_schemas.py` implements every row and checks refusal
atomicity against a deep copy of all of its state; wire requests reach it through the validated
projections `capture_from_request` and `availability_from_request`. Deliberate abstractions: hashes are
SHA-256 of canonical JSON; the single-threaded commit stands for the per-ledger lock; artifact bytes are an
opaque digest; tenants, signatures and wire validation beyond the closed schemas are out of scope.

---

## 10. What stays outside this contract, and who checks what

Locally measured by the **SDK** (the manifest and the content never leave the client) and *received by the
Backend only as closed summaries*; the Backend re-validates the summary, never the content:

| Local check (SDK) | Summary the Backend receives | Backend checks on the summary |
|---|---|---|
| ordinals/digests of the manifest, `representation_commitment` derived locally | `representation_commitment` | for a complete **backend-keyed** capture, equals the cited `identity_verified` proof's commitment (otherwise it is only stored); persisted immutably |
| identity digests reproduced from the real files | `identity_digests_reproduced` | complete coverage requires it; persisted immutably |
| conformance and per-capture isolated round trip | `recovery_state`, `conformance_passed` | `round_trip_verified` requires conformance; recorded as event evidence |
| restore-time measurements: both equalities, isolated destination, historical key, dependencies, the verified artifact digest | `RecordRestoreRequestV0`: `representation_digests_match`, `pillar_fingerprint_match`, `isolated_destination`, `historical_key_available`, `dependencies_verified`, `verified_artifact_digest` | **client-path `ExactPrerequisites`**: the SDK measures these; the Backend combines them with the immutable capture metadata (coverage, reproduction, proof) and never trusts a caller coverage claim; backend-keyed pillars cannot be `exact` on this path |
| `covered`/`missing` disjoint and together covering every `RequiredComponents(kind)` component, calendar validity | `coverage` object | closed enums and kind-specific required components |
| staged artifact bytes and digest at activation | none (local) | the Backend recorded the verified artifact digest; activation compares locally |

Backend-only checks: `kid` equals `key_id`, kind/scheme/family, role-to-kind matrix, request-digest
recomputation, tenant/project scoping, unique authority mapping and group key, effective-binding
recomputation and context snapshots, `BackendKeyed(version)` from the authoritative manifest format,
`identity_verified` recomputation, `server_match` (server-path `ExactPrerequisites`), `Captured(version,
manifest)` joins and prefix evidence, sealed cutoff, subject projection equality, predicate issuance and
Director instruction/result relations. Backend tables and API (items 2, 3), run binding and backfill
(item 4), Director dispatch (item 5), signed version subjects (item 6) and the SDK client, store and
activation (items 7, 8) implement this contract and must not widen a field to free text.

---

## 11. Changelog

**Delta over 9d71d82 (purely additive).** New `legend_claim_statement_v0.json` (signed claim statement: closed subject plus signature envelope with domain `traigent.legend_claim_subject.signature.v0`), reference verifier `traigent_schema/legend_claim_verifier.py`, golden vectors `tests/legend_claim_statement_v0_vectors.json`, tests `tests/test_legend_claim_verifier.py`, and section 5.1. No existing schema is changed.

**Delta over 9b0451d (additive; the 06a0f5f contract is otherwise unchanged).** This delta is **not** purely additive. Query results with `outcome` `failed` or `refused` that carry a non-null `next_page_cursor` were valid at 9b0451d and are now refused, intentionally (security narrowing found by sol review; the contract is unreleased and unconsumed). Both breaking findings are acknowledged in `scripts/breaking_schema_allowlist.json`: the `QueryVersionsResult` allOf branch change in `director_legend_ops_v0.json`, and the optional `as_of_ledger_position` property in `legend_requests_v0.json`. `python3 scripts/breaking_schema_check.py --check` reports no unacknowledged BREAKING findings.

1. `legend_requests_v0.json`: `QueryRequestV0` gains OPTIONAL `as_of_ledger_position` (integer >= 0; omitted = current); cursors are bound to it (section 6).
2. `director_legend_ops_v0.json`: new closed definitions `PageCursor`, `LegendInstructionMember` (carries `as_of_ledger_position`, the position the agent passes to the query request; no separate `legend_snapshot`) and `LegendResultAckMember`.
3. `director_legend_ops_v0.json`: `QueryVersionsResult` now requires `next_page_cursor` null when `outcome` is `failed` or `refused`; cursor provenance (one shared issuer) stated in section 6.
4. Model `Legend` and tests: `query()` (Legend API), cursors bound to `(entity, boundary, as_of)` from the single issuer `_cursor`, Director instructions record and keep their `as_of`, refusal of a failed/refused cursor-bearing result; the cursor-issuing line of one existing test now passes the instruction's `as_of`.
