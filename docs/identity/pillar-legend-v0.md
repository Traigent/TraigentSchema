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
   never represent the same authoritative identity. A declaration without a source row is allowed. When a
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
`evidence_source`, a server-assigned `ledger_position`, human-time `recorded_at`, `idempotency_key` and `request_digest` (section 3.4).

**Ledger position.** `ledger_position` is a strictly increasing integer per `(tenant, project)` ledger and is the only order. Events with equal `recorded_at` are ordered by position, never by ref or time. A signed predicate cites a prefix by `ledger_cutoff_position`; `as_of` stays the human timestamp. Reconstruction of a signed snapshot selects events with `ledger_position <= cutoff`.

| `event_type` | Origin | `evidence_source` | Type-specific fields |
|---|---|---|---|
| `authority_linked` | server | `server_recorded` | `source_authority` (appended when an authoritative source row for the version is found; never updates the version) |
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
`(run_ref, trial_ref, binding_role, binding_slot)`. A slot holds exactly one **version** (and therefore its
tuple contribution); a second binding of the same slot to a different version is refused
(`conflicting_report`), an identical replay is accepted. Bindings are frozen at `start_execution`
(section 9); after that no slot of the run may be added or changed.

**Effective bindings and the run tuple.** For a run `R` and, when applicable, a trial `t`, the effective
bindings `EB(R, t)` are: every run-level slot of `R`, except that the `base_agent` slot is *replaced* by
`t`'s `trial_candidate` slot(s) when `t` has one; plus `t`'s per-trial `evaluator` slots. `dataset` and
`search_set` are distinct roles and never compete. The commitment is
`run_tuple_digest = "sha256:" + hex SHA-256(UTF8("traigent.legend.run_tuple.v0") || 0x00 || jcs_v1(T))`
with `T = {"entries": [{role, slot, fingerprint_scheme, key_id, fingerprint}, ...]}`, entries sorted by
(role in the order `base_agent, trial_candidate, dataset, search_set, evaluator, search_space`, `slot`,
`fingerprint_scheme`, `key_id` (null first), `fingerprint`). Several evaluators therefore all appear; none
is picked as "the" evaluator. The Backend computes the digest from its own frozen binding rows; a
client-supplied tuple digest is never trusted.

**Evaluation admission.** An `evaluated` event is admitted only after the Backend resolves the exact
run/trial/evaluation context, recomputes `EB` and the tuple digest from the frozen consumed bindings, and
verifies that the event's subject version is a member of that effective-binding set and that the digest
equals the recomputed one. Witnessed evidence must derive from that scoring execution. A version that was
never bound (for example version B when the tuple holds agent A) is refused (`foreign_ref`).

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

**Backend-keyed pillars.** `BackendKeyed(version)` is derived from the version's scheme and, for an
evaluator, from the authoritative manifest format: it is true for `search_space_ssp1` (`K_search_space`),
and for an evaluator whose authoritative manifest is `be.evaluator_manifest.keyed_leaves.v0` (keyed
`evd1` leaves, `K_eval`). Unknown format, or unavailable server verification, counts as backend-keyed (it
can never be graded `exact`). The request/event `kind` must match the resolved version, and the schema
carries `backend_keyed` so the rule is checkable at the wire: a backend-keyed pillar is never `exact` from a
client-origin report. It is `exact` only when the **Backend's own server-side recompute** of the same manifest
reports `match` (a server-origin `restore_verified` event with `backend_match_result = match`). A
Backend-assisted reproduction of the keyed identity digests during capture satisfies INV-17 only through
that same server-side match; the client alone cannot claim `identity_digests_reproduced` for such a pillar.

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

**Evidence must match, not just exist.** A supporting event counts only if it has the same
`version_ref` (subject), the same `recovery_manifest_fingerprint` (recovery predicates), the same
`run_tuple_digest` (and for `evaluated_*`, the same `evaluated_subset_root` and `evaluation_protocol`,
which are part of the signed predicate), the required origin/source, and `ledger_position <= ledger_cutoff_position`
(signed prefix cutoff; `as_of` is only the human time). The required event *type* alone is not enough.

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

## 9. Transition table

Every operation validates **all** its guards first and commits its effects only if every guard passes;
a refusal changes no state (no row, no event, no cached response, no slot). Refusal codes are the
closed `LegendErrorCode` values. "Prefix" means a ledger prefix by `ledger_position`.

| Operation | Inputs | Guards (refusal code) | Effects |
|---|---|---|---|
| `declare` | `DeclareRequestV0` (key, digest, entity, scheme, key_id, fingerprint, initial parent, previous, provenance, identity_source) | flag on (`flag_disabled`); body valid, kind/scheme/key/family rules, `ssp1` => `client_declared` (`invalid_request`); recomputed digest vs key: equal = return the first stored response, different = `conflicting_idempotency_payload`; entity belongs to the caller's tenant/project (`foreign_ref`); first declaration: initial parent not self, same entity, declared earlier (`invalid_request` / `unknown_ref`); later declaration: initial parent null or equal, `identity_source` equal to the stored one (`invalid_request`); `previous_version_ref` same entity and declared (`unknown_ref`) | creates the version on first declaration only; appends one `declared` event with the next position; caches the response under the key |
| `link_authority` | server-side, authority row found for `(kind, authoritative entity id, fingerprint)` | version exists and is in scope (`unknown_ref`); the authority row matches the version's kind and fingerprint (`manifest_mismatch`) | appends `authority_linked`; never updates the version; derived `authority_linked` becomes true |
| `bind` | server-side from run/trial registration | run not frozen (`conflicting_report`); `trial_candidate` has a trial, base roles have none (`invalid_request`); version in scope (`foreign_ref`); slot empty or already holds the same version (`conflicting_report`) | stores the slot; appends `bound_to_run` (server_recorded); identical replay appends nothing |
| `start_execution` | run, trial, observed identities, mode `strict` or `permitted` | observed identity equals the effective binding for each role; **strict mismatch refuses before execution** (`manifest_mismatch`) and changes no binding; **permitted drift** requires the observed version to be declared and bound first (`unknown_ref`) | freezes the run's bindings; fixes `run_tuple_digest` from the frozen effective bindings |
| `capture` (`RecordCaptureRequestV0`) | version, manifest fingerprint, coverage, recovery_state, conformance, exporter version | version in scope; manifest not a conformance key (`invalid_request`); `round_trip_verified` => `conformance_passed` (`conformance_failed`); `complete` coverage meets `RequiredComponents(kind)` and, for agent/evaluator, the manifest reproduced the identity digests (`coverage_insufficient`); same key + different bytes is `store_key_conflict`; client-origin only | appends `captured` (client_sdk_reported); recovery_state fold may rise, never fall |
| `record_restore` (`RecordRestoreRequestV0`) | version, kind, manifest fingerprint, outcome, coverage, equalities, `backend_keyed` | kind equals the version's kind; the manifest was captured (`unknown_ref`); `exact` => complete coverage for the kind, both equalities, isolated destination, historical key and dependencies verified (`coverage_insufficient`); `BackendKeyed(version)` => client cannot report `exact` (`coverage_insufficient`); client body carries no `backend_match_result` (`invalid_request`) | appends client-origin `restore_verified` |
| `server_match` | server-side recompute of the same manifest for a BackendKeyed version | manifest captured and the Backend holds the key and format (`store_unavailable` if not); mismatch => outcome not `exact` | appends server-origin `restore_verified` with `backend_match_result` `match` or `mismatch` (server_recorded) |
| `record_availability` | manifest, status | the manifest was captured (`unknown_ref`); client-origin | appends `availability_changed`; the highest position per manifest wins |
| `evaluate` | run, trial, subject version, tuple digest, origin | run frozen; digest equals the recomputation from frozen bindings (`manifest_mismatch`); subject is a member of the effective bindings (`foreign_ref`); subset root and protocol present; `traigent_witnessed` only from the scoring execution on server origin | appends `evaluated` |
| `issue_predicate` | predicate type, subject, cutoff position, manifest or tuple | matching supporting events exist inside the prefix (subject, manifest, tuple, subset, protocol, origin, source) (`unknown_ref`); `restorable_now` needs latest availability `available` (`coverage_insufficient`); `restore_verified_*` needs `exact` and complete coverage; compiler policy version allowed | signs one statement citing the cutoff; later evidence is a new statement |
| `director_instruction` | operation, refs | flag on; refs belong to the caller's scope (`foreign_ref`); operation on the closed menu | issues one instruction bound to version and manifest; dispatch only |
| `director_result` | closed result | matches an issued, unanswered instruction (`conflicting_report`); `exact` only with `retrieved`, complete coverage, no mismatch, and the Backend's own matching restore evidence for the instruction's version and manifest; an agent-supplied `match` never substitutes (`manifest_mismatch`) | stores the closed result once; a conflicting second report is refused |
| `activate` | local, separately authorised | a prior `exact` restore of the same manifest fingerprint and the same staged artifact digest (`manifest_mismatch`); never a Director operation | activates locally; restoration never reverses external effects |

The reference model `Legend` in `tests/test_pillar_legend_v0_schemas.py` implements these transitions and
asserts atomic refusal.

---

## 10. What stays outside this contract

Backend tables and API (items 2, 3), run binding and legacy backfill (item 4), Director dispatch
(item 5), signed version subjects (item 6), SDK client, store and activation (items 7, 8) implement this
contract and must not widen a field to free text. JSON Schema cannot express, and consumers or the
reference model must enforce: kid equals `key_id`, disjoint `covered`/`missing`, `ordinal` equals
position, calendar validity of timestamps (the contract tests use the production date-time checker), the
unique authority mapping and grouping key, initial-parent acyclicity, key/digest conflict, slot
immutability, effective-binding recomputation, evidence matching for predicates, `BackendKeyed(version)`
resolution from the authoritative manifest, and the capture-coverage versus manifest agreement.
