# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`GET /api/v1/auth/me/tenants` (tenant switcher, TraigentFrontend#2250).** New
  `auth/auth_me_tenants_response_schema.json` (`{success, message, data: {items, switchable}}`,
  items = `TenantMembershipItem` {tenant_id, tenant_name, tenant_slug, role, is_default}, strict
  `additionalProperties: false`) and the route in `auth/auth_endpoints.json` (200 / 401 / 500).
  Items are only the caller's own active memberships; `switchable` is true only for an unpinned
  interactive session. Backend: Traigent/TraigentBackend#3501.
- **Fleet-posture inputs E1, E4, E5 (agent readiness).** Contract-first, all operations
  `x-asserted-against-backend: false`; from `business/product-personas/fleet-posture-census.md`
  ("Smallest extensions") and the 2026-09-24 owner rulings.
  - **E1 — anchor refs on the portfolio item.** `agent_readiness_portfolio_response_schema.json`
    items gain five optional, nullable members, emitted together or not at all:
    `anchor_evaluation_dataset_ref` / `anchor_evaluator_version_ref` (the detail response's
    `EvaluationDatasetRef` / `EvaluatorVersionRef` by `$ref`), `anchor_accuracy` (the common
    `AccuracyMetric`, always `client_reported`), `anchor_accuracy_sample_count` (positive; non-null
    only for an `accuracy.mean` anchor accuracy) and `anchor_reported_example_evaluations`. All are
    null when `anchor_run_id` is null. Optional so the Backend can ship `list_portfolio` support
    without a lockstep deploy; the fleet view then needs no per-agent detail fetch.
  - **E4 — manager-set agent posture.** New `agent_readiness/agent_posture_schema.json`
    (`PostureDeclarationRequest`, `PostureRevision`, `DeclaredPosture`, `NoPosture`,
    `AgentPosture`): `deployment_stage` reuses `agents/agent_deployment_schema.json`
    `definitions/Environment` by `$ref` (not forked), `criticality` is `low`/`medium`/`high`.
    New `POST /api/v1beta/projects/{project_id}/agent-readiness/{agent_id}/posture-revisions`
    (`agent_readiness/agent_posture_endpoints.json`, registered in `mep_endpoints.json`) follows the
    target-revisions convention: immutable revisions, `expected_current_revision_id`, a
    const-bodied 409 `revision_conflict`, human session with project owner/admin role only.
    `declared_by` (USER only) and `declared_at` are server-derived. The `agent_posture` member
    (`NONE_DECLARED` until set) is added to the portfolio item and the detail response, optional
    until TraigentBackend emits it (then required) so unrelated Backend schema-pin bumps keep
    passing. Fail closed: consumers treat an undeclared Agent as criticality `high`.
    The portfolio list operation gains optional single-value `deployment_stage` and `criticality`
    query filters (same convention as `stage`/`attention`; Agents without a declared posture are
    excluded when a filter is set).
  - **E5 — accuracy team target.** `agent_readiness_target_schema.json` gains
    `AccuracyRequirement` (`metric_id: SDK_MEAN_ACCURACY`, literal `source_key: accuracy.mean`,
    `unit: PROPORTION`, `comparison: at_least`, a `[0, 1]` decimal-string `threshold`,
    `confidence_level: "0.95"`, `clearing_ci_bound: lower` — the lower bound of the 95% interval
    must reach the threshold; a closed enum so another bound is a later, acknowledged widening; an
    observed mean outside `[0, 1]` is never rescaled but CANNOT_DETERMINE), its declaration,
    `AccuracyEvaluation` (MET/NOT_MET carry the observed mean, both interval bounds and the count;
    CANNOT_DETERMINE needs a reason, incl. the new `CONFIDENCE_INTERVAL_NOT_RECORDED`; closed
    `ci_method: clt_mean_standard_error` — mean ± z·SE over per-example scores (Miller 2024),
    computed by the Backend from per-example evaluations, never client-supplied),
    `AccuracyTargetRevision` (also listed in the schema's root `oneOf`) and `DeclaredAccuracyTarget`. `TargetDeclarationRequest.requirement`
    and the POST 201 `DeclaredTarget` become unions of the unchanged latency shape (now also named
    `DeclaredLatencyTarget`) and the accuracy shape. Each metric keeps its own revision chain; the
    detail response gains an optional (required once the Backend emits it) `team_accuracy_requirement` next to the unchanged
    latency `team_requirement`.
  - Response-side additions on closed objects and the two new unions are acknowledged in
    `scripts/breaking_schema_allowlist.json` (9 entries, each with its reason). Reachability report
    and parity manifest regenerated; `agents/agent_deployment_schema.json` is now reached through
    the endpoint graph.
- **Session identity-binding read + reachable session-create/results content_identity (M3
  PR-5-lite).** New `GET /api/v1/sessions/{session_id}/identity-binding`, registered in
  `optimization/optimization_endpoints.json` (the sessions catalog, under the `sdk_tuning`
  contract root — session-scoped, alongside `next-trial`/`results`/`finalize`, not the
  dataset-scoped `content_identity_endpoints.json`), `x-asserted-against-backend: false` ahead
  of TraigentBackend `feat/content-identity-run-binding` landing on develop. New
  `optimization/session_identity_binding_response_schema.json`: the standard success envelope
  wrapping the run binding (`RunIdentityBindingRowV1`: `experiment_run_id`, `scheme`, `key_id`,
  `record_state`, `rejection_reason`, `agent_id`/`agent_key`, `base_build_digest`,
  `base_head_generation`, `dataset_members_ref`/`dataset_root`/`dataset_version_id`, `facts`,
  `declared`, `created_at`/`completed_at`, `dataset_members`) and its trial bindings
  (`TrialIdentityBindingRowV1`), or `identity_binding_not_found` (404) in the standard error
  envelope. Deliberately named `*Row*` — this is the raw stored `run_identity_bindings` /
  `trial_identity_bindings` row as the Backend serializes it today, NOT the same shape as the
  pre-existing, still-unreachable `execution/run_identity_binding_v1_schema.json`
  `RunIdentityBindingV1` (the future normalized, certificate-oriented record); the two must
  never be confused. `dataset_members`/`evaluated_members` reuse `MultisetMemberV1` and
  `MemberListRefV1` by `$ref`; a documented but Backend-untested `MemberListLoadErrorV1` branch
  covers the rare case where a stored member list fails to reload. `declared` is typed as a
  bare nullable object, not a `SessionContentIdentityWireV1`/`TrialContentIdentityWireV1` `$ref`,
  because the Backend stores the client's raw block verbatim even when it FAILS that wire
  schema (`rejection_reason: wire_schema_invalid`) — refing the wire schema there would reject
  values the Backend itself accepts and stores. Also adds the optional, additive
  `content_identity` property (`anyOf` the real wire schema or an unconstrained catch-all, so a
  value the Backend tolerates but does not validate — non-object, schema-invalid, oversized —
  never turns an already-accepted request into a 400) to POST `/api/v1/sessions`'s top-level
  body and to `optimization/session_submit_results_request_schema.json`'s
  `metadata.content_identity`, making M3 PR-S1's `SessionContentIdentityWireV1` /
  `TrialContentIdentityWireV1` reachable from the catalog graph for the first time.
  `breaking_schema_check.py` confirms both request changes are additive-only. Reachability
  report and parity manifest regenerated.
- **Evaluation system validation (E3): expert sign-off record + reviewer capability grant.**
  New family `evaluation_system_validation/` (`evaluation_system_validation_schema.json`:
  `ValidationCreateRequest`/`ValidationRecord`/`ValidationListResponse`, closed and append-only;
  `evaluation_system_reviewer_grant_schema.json`: `ReviewerGrantCreateRequest`/`ReviewerGrantRecord`/
  `ReviewerGrantListResponse`/`ReviewerCanSignResponse`), registered in `mep_endpoints.json`.
  `evaluation_system_validation_endpoints.json` declares
  `POST/GET /api/v1beta/projects/{project_id}/evaluation-system-validations`,
  `GET .../evaluation-system-validations/{validation_id}`, and
  `POST/GET .../evaluation-system-reviewer-grants` + `GET .../evaluation-system-reviewer-grants/me`
  (`x-asserted-against-backend: false`). A separate family from Agent Readiness so
  `agent_readiness_endpoints.json`'s pinned path set never moves. A revocation is a new record
  naming the one it revokes (`record_kind: revocation`); the reviewer, signing time, and subject
  identity are always server-derived. Owner ruling: a project admin may grant the reviewer
  capability to themselves — `ReviewerGrantRecord.self_granted` and
  `ValidationRecord.signed_under_grant_id`/`signed_under_self_grant` disclose it on the wire.
  The derived, content-free `EvaluationSystemValidity` block (`level: V0|V1`, per-pillar
  `PillarValidity` status/reason/evidence, `decayed_reason`, `evidence_ids`) is added to
  `agent_readiness_common_schema.json` and referenced as the new required
  `evaluation_system_validity` member of the readiness portfolio item and detail response
  (allowlisted `property_added` — additive only). Owner ruling: a `ValidationCreateRequest` /
  `ValidationRecord` with `outcome: valid` must carry non-null `agreement` evidence
  (`compared_items >= 1`); `outcome: not_valid` may omit it; a revocation keeps it null regardless
  — a **contract tightening on the request side** (a validation submission that previously omitted
  `agreement` on a `valid` outcome is now rejected 400; `not_valid` submissions are unaffected). See
  `business/product-personas/e3-validation-record-design.md` (v0.2).
- **Content identity endpoint contracts (M3).** New catalog
  `datasets/content_identity_endpoints.json`, registered in `mep_endpoints.json`, declaring four
  Backend routes ahead of their merge (`x-asserted-against-backend: false`):
  `POST /api/v1/content-identity/purpose-keys` (bare `PurposeKeyGrantV1`, `Cache-Control:
  no-store`; 503 `content_identity_keys_unavailable` and 403 `tenant_context_required` in the
  standard error envelope, custody reasons never on the wire), `GET
  /api/v1/datasets/{dataset_id}/versions/{version_id}/content-identity` (new
  `HostedDatasetVersionContentIdentityV1`: available root + per-example map, or unavailable with a
  closed reason, incl. the creation-recorded `content_not_identifiable` / `keys_unavailable`), `GET /api/v1/datasets/versions/by-root/{dataset_root}` (DatasetVersionV1 list)
  and `PUT /api/v1/datasets/{dataset_id}/public-benchmark` (ruling D3 opt-in). Request/response
  schemas in `datasets/`; `purpose_key_grant_v1_schema.json` and `content_identity_v1_schema.json`
  are now reachable from the catalog graph. Additive; nothing existing changes.
- **Content identity wire envelopes (M3 PR-S1).** `execution/content_identity_wire_v1_schema.json`
  types what both SDKs already send: `SessionContentIdentityWireV1` (session-create
  `content_identity`) and `TrialContentIdentityWireV1` (trial `metadata.content_identity`), the
  closed reason vocabulary `ContentIdentityUnavailableReasonV1` with per-slot subsets, and the
  null-slot rules (a null slot names its reason; a withheld agent/evaluator claims no id source;
  above 2,000 members the whole slot is null with `members_exceed_inline_cap`). New
  `datasets/purpose_key_grant_v1_schema.json` (`PurposeKeyGrantV1`, the Backend -> SDK key grant;
  key fields marked secret) and `MemberListRefV1` (`ml1:<id>`) in
  `datasets/content_identity_v1_schema.json`. Spec section 18. Tests validate real payloads
  captured from both SDKs' builders (`scripts/content_identity_wire/`) and recompute every stated
  digest and root. Additive; nothing existing changes.
- **Content identity v1 (`traigent.content_identity.v1`): tenant-keyed example ids and
  order-free multiset dataset roots (owner rulings 2026-09-23).** New normative spec
  `docs/identity/content-identity-v1.md`; reference implementation
  `traigent_schema/example_identity.py`; cross-SDK conformance vectors
  `traigent_schema/data/content_identity_v1_vectors.json` (generator + freshness check:
  `scripts/generate_content_identity_v1_vectors.py --check`). `example_id` = HMAC-SHA-256 over
  jcs_v1 of the INPUT (+ context) under a per-tenant HKDF-derived key (tenant_id bound into every HKDF info;
  key custody, rotation and the public-digest opt-in follow owner rulings D1-D3 = A,
  2026-09-23); `example_version` = HMAC
  over example_id + expected output + version-relevant metadata; `dataset_root` /
  `evaluated_root` = RFC 9162 Merkle tree hash over sorted `[example_id, example_version, count]`
  leaves (order-free, duplicates counted, conflicting versions reported); RFC 9162 inclusion
  proofs that verify without any key; opt-in unkeyed `exu1` digest for public-benchmark
  contamination checks; unkeyed agent `build_digest` over a manifest that must cover code,
  prompts, helper modules, tool definitions and the candidate configuration, with a `coverage`
  declaration (only `complete` is certifiable; a dirty `code_revision` requires `source_digest`);
  unkeyed `evaluator_version_digest` over efp2 code + bound config + local helpers + judge +
  objective set + dependencies;
  `record_state` draft/complete on run bindings and dataset identities (only complete is
  certifiable); normative issuer rules binding only server-recorded linkage (ID1): issuance rules
  I1-I4 block a certificate, claim rules C1-C6 refuse only the affected claim. Canonicalization is jcs_v1 plus one rule stricter than fp2: any number,
  float included, with |v| > 2^53-1 is rejected so JS and Python cannot diverge. New additive schemas (no consumer yet):
  `datasets/content_identity_v1_schema.json`, `agents/agent_version_manifest_v1_schema.json`,
  `evaluation/evaluator_version_manifest_v1_schema.json`,
  `execution/run_identity_binding_v1_schema.json`. Nothing existing changes:
  `DatasetVersionV1.content_digest`, fp2 and every certification contract are untouched.
- **`POST /api/v1/model-parameters` and the two `/api/v1/example-sets` reads are now
  declared (unblocks TraigentBackend #3347, #3352, #3353).** All three endpoints were
  absent from this repo, which is why a Backend PR could reshape their request/response
  bodies with no schema lane objecting and why a Frontend break went unnoticed until a
  human traced it. New files:
  `agents/standalone_model_parameters_create_request_schema.json`,
  `agents/standalone_model_parameters_create_response_schema.json`,
  `datasets/example_set_list_response_schema.json`,
  `datasets/example_set_examples_list_response_schema.json`. Every declared shape is
  transcribed from Backend source read on `origin/develop` and cites its `file:line`;
  per-branch error shapes are declared per branch, because the standalone
  model-parameters route emits the canonical validation envelope from four branches and a
  bare `{error}` body from two, and the example-set reads' 404/500 branches are bare while
  their 200 is enveloped. A side effect: `validation_error_schema.json` was an ORPHAN
  before this change (nothing `$ref`'d it); it is now reachable, and the orphan count in
  `reports/schema_reachability/unreachable_schemas.json` drops 43 -> 42.

  The example-set item shapes are deliberately NOT `$ref`s to `example_set_schema.json`:
  that file's closed resource definition requires only `{id, name, description, examples}`
  with `additionalProperties: false` and declares none of `agent_id` / `example_set_id` /
  `tenant_id` / `project_id` / `type` / `selection_method` / `num_examples` /
  `similarity_threshold` / `tags`, and its `Example` definition requires a non-null
  `output` the column permits to be null. Reusing it would have declared a contract the
  serializers violate on every row.

- **`POST /api/v1/agents/{agent_id}/model-parameters` declares its 422.** It previously
  declared only a 201. TraigentBackend #3347 resolves `model_id` against the model catalog
  before constructing the row, so an unresolvable id is a field-attributed
  `VALIDATION_ERROR` instead of an FK-violation 500.

### Changed
- **`validation_error_schema.json` no longer claims to be a 422-only shape.** The same
  body is emitted at 400 and at 422 and the choice is per-branch, not per-shape: the
  canonical helper `response_handler.validation_error_response` pins 422, while call sites
  that invoke `error_response(..., status=400, error_code="VALIDATION_ERROR")` directly
  emit 400 - including every validation branch of `POST /api/v1/model-parameters`. The
  description now says both and tells consumers to branch on `error_code`, never on the
  status. Description-only; no shape change. The 400-vs-422 split is a real, unresolved
  Backend inconsistency and is recorded rather than silently narrowed to one status.

- **`success_envelope_schema.json#/x-wrap-map` gains a `mixed` classification.** A
  two-list bare/wrapped map cannot describe `example_set_routes` after TraigentBackend
  #3353, which migrated 2 of its ~10 operations to the envelope and left the rest bare.
  The file moves out of `bare` into `mixed`, where its `default` and its enveloped
  operations are enumerated; `x_extensions_meta_schema.json` documents the new key. The
  per-operation `x-wrap-status` annotations in the endpoint catalogs carry the same fact at
  the route level.

- **`success_envelope_schema.json` no longer declares a top-level `pagination`.**
  Pre-existing divergence, corrected here because #3353 makes it load-bearing: the
  canonical `paginated_response` helper is documented strict nested-only and emits
  `data.pagination` beside `data.items`, so no producer of this envelope ever emitted a
  `pagination` sibling of `data`. `additionalProperties` stays `true`, so this removes a
  false declaration without newly rejecting any body (the breaking-change gate classifies
  it INFO, not BREAKING, for exactly that reason). The nine `*_list_response_schema.json`
  files that declare a top-level `pagination` are inner-payload schemas (the `data` object
  itself), not envelopes, and are correct as they stand.

### Changed
- **Canonical `Confidence` / `ConfidenceLabel` common types (#314, owner decision
  2026-07-18: numeric canonical + derived qualitative label).** `confidence` was a
  `0-1` number in optimization/datasets/auth schemas but a qualitative
  `low`/`medium`/`high` enum in analytics responses — a dual wire form for one
  concept. Adds `common_types_schema.json#/definitions/Confidence` (canonical
  numeric `[0, 1]`) and `.../ConfidenceLabel` (canonical `low`/`medium`/`high`
  enum, documented as the derived bucketing of the numeric score, with documented
  thresholds) and re-points the occurrences listed below at the shared definition (a staged migration per #314 — `auth/agent_interaction_policy_request_schema.json`'s inline, unbounded `confidence` is NOT migrated here and is tracked separately):
  numeric side (`optimization/tvar_correlation_schema.json`,
  `optimization/tvar_value_recommendation_schema.json`,
  `auth/interaction_policy_schema.json`,
  `datasets/evaluation_set_schema.json`) and qualitative side
  (`analytics/decision_payload_schema.json`,
  `analytics/run_correlations_schema.json`,
  `analytics/run_leaderboard_schema.json`). No field is renamed and no numeric
  score is added to the client-safe analytics surfaces (which intentionally
  expose only the coarse bucket) — this documents and DRYs the existing split,
  it does not force a big-bang migration. `optimization/smart_pruning_schema.json`'s
  `confidence` is a distinct algorithm-parameter concept (open interval, request-side
  pruning threshold) and is intentionally left untouched.

- **Selection receipt in strict (certified-selection) sessions.** The server decides the
  winner there, so the Backend accepts a receipt only when `winner_trial_id` equals its
  certified winner; with no certified winner, or a different one, it persists
  `winner_not_eligible`. (The Python SDK sends no receipt in strict mode.) Also states that
  NaN/Infinity in an integer-typed receipt field is `non_finite`, not `invalid_receipt`.
  Description-only; no shape change.

### Changed
- **Selection receipt winner rule (unreleased contract from #491).** The Backend no longer
  requires `selection.winner_trial_id` to equal the trial it would rank best; it must be a
  completed trial of this session and in `eligible_trial_ids` (else `winner_not_eligible`).
  The SDK ranks by configuration average, weighted objectives and cost tie-breaks, so the
  old rule rejected honest receipts. `winner_not_best` now applies only when
  `margin.winner_trial_id` differs from `selection.winner_trial_id`. The receipt evidences
  which eligible trial the SDK selected — not which configuration was shipped, and not
  that the ranking was correct. Description-only; no shape change.

### Fixed
- **Submit-results optionals accept explicit `null` (completes part 1 of #454).**
  `summary_stats`, `execution_mode`, and `execution_environment` on
  `session_submit_results_request_schema.json` were declared as plain `object`/`string`,
  so a client that serializes an unset optional as `null` failed validation even though
  the server treats `null` exactly like an omitted field. Each now uses the schema's
  existing `["<type>", "null"]` form; wrong types are still rejected. Widening only.
- **`trial_sequencing: "client"` no longer reads as disabling cost controls (#323).**
  The description on both session-create surfaces said the server's "budget accounting"
  becomes informational only. It now scopes that to the optimizer's trial-count budget
  and states, as a requirement on implementers, that client sequencing does not disable or
  relax any spend, time, rate, or security limit that applies to the session.
  Description-only; no shape change.
- **`exportProjectFineTuningManifest` path drift in `planned_projects_endpoints.json`
  (#272).** The operation was declared at
  `/api/v1beta/projects/{project_id}/core-exports/fine-tuning.manifest`, but the real
  backend route lives on the `analytics` blueprint and is mounted at
  `/api/v1beta/projects/{project_id}/analytics/exports/fine-tuning.manifest` — a client
  following the declared path would 404. Corrected to the real, shipped path; the sibling
  `exportProjectFineTuningJsonl` operation already correctly used `core-exports` and is
  unchanged. This is a contract-breaking path rename, acknowledged in
  `scripts/breaking_schema_allowlist.json` and shipped as a reviewed pre-release exception: the
  catalog carries `x-asserted-against-backend: false`, and the Frontend, Python SDK and JS SDK
  callers at `origin/develop` already use the served path (none references the drifted one). (The other item this
  issue's title named, `lookupProjectMembershipCandidates`/`membership-candidates`, was
  re-verified and is not a defect — it is an intentionally planned, not-yet-backend-built
  contract per TraigentSchema#46, already excluded from the canonical backend surface by
  its own dedicated test suite; no change needed.)
- **Normalized `$id` base URL for 7 analytics schemas (breaking-check blind spot).**
  `curation_advice_schema.json`, `dataset_quality_schema.json`, `example_score_schema.json`,
  `next_steps_receipt_request_schema.json`, `next_steps_receipt_response_schema.json`,
  `next_steps_schema.json`, and `scoring_job_status_schema.json` declared `$id` under the
  legacy `https://traigent.ai/schemas/...` host instead of the `https://schemas.traigent.ai/...`
  host every other schema uses. `scripts/breaking_schema_check.py` resolves `$ref`s against
  `SCHEMA_ID_BASE = "https://schemas.traigent.ai/"`, so operations in
  `analytics/analytics_endpoints.json` referencing these 7 files came back `unresolved_ref` —
  a blind spot the checker could not verify as non-breaking. No runtime behavior changes; this
  is a pure `$id` rename with no `$ref` updates needed (nothing else referenced the old absolute
  form). Removes the now-moot `unresolved_ref` acknowledgement for these 7 operations from
  `scripts/breaking_schema_allowlist.json` (added on PR #471).
- **AWS Marketplace operations marked contract-first.** The three operations in
  `schemas/billing/marketplace_endpoints.json` (#474) now carry
  `x-asserted-against-backend: false`: their Backend routes are in TraigentBackend
  #3169, which has not merged, so the Backend's documented-routes conformance test
  failed every traigent-schema pin bump past #474 (seen on TraigentBackend #3333).
  Flip back to asserted when the Backend pins a commit containing those routes.

### Added
- **`NormalizationStrategy` re-widened to `min_max`, `z_score`, `robust`
  (`schemas/optimization/objective_definition_schema.json`, `0.9.3` -> `0.9.4`).**
  The enum was narrowed to `["min_max"]` when `z_score`/`robust` were advertised but
  unimplemented (fail-closed contract half of a bug fix). The optimization library's
  normalization math for all three strategies is now implemented and merged
  (deterministic handling of zero-span/zero-scale, single-sample populations, and
  non-finite observations), so the contract is widened back deliberately: the
  description now names the reference implementation's `normalize_objective_values()`/
  `NormalizationSpec` as the normative source for that edge-case behavior instead of
  restating it in the schema. Purely additive — `min_max` payloads are unaffected,
  and this only accepts values that previously failed validation. Parity manifest
  restamped (`scripts/refresh_parity.py --update`).
- **`metric_metadata` (per-metric `direction` + `role`) on the run-results response.**
  New optional, nullable `metric_metadata` map (`schemas/execution/run_results_response_schema.json`,
  `GET /api/v1/experiment-runs/runs/{run_id}/results`) carries, for every key present
  in the sibling `metrics` map, an authoritative `direction` (`maximize` | `minimize` | `band`,
  reusing `ObjectiveDirection` from `optimization/objective_definition_schema.json`) and a
  `role` (`quality` | `cost` | `latency` | `tokens`). Both keys are always present but
  individually nullable: `{direction: null, role: null}` is the honest "genuinely unknown"
  answer for an ad-hoc measure with no backing objective and no resolvable role — never a
  silent default to `maximize`. Purely additive (`metric_metadata` itself is optional and
  nullable; the map is not required); old readers that ignore it are unaffected. Fixes FE
  consumers re-deriving metric direction/role from the metric name, which misclassifies any
  metric whose name doesn't match a hardcoded keyword list.
- **`trial_sequencing` on session create (client-driven trial sequencing, Schema#323).**
  New optional `trial_sequencing` enum (`"client" | "backend"`, default `"backend"`,
  fully backward-compatible) on `POST /api/v1/sessions`
  (`schemas/optimization/optimization_endpoints.json`) and `POST /api/v1/hybrid/sessions`
  (`schemas/optimization/hybrid_session_create_request_schema.json`). `"backend"` preserves
  today's behavior: the server allocates trial ids from its own optimizer budget and may
  early-stop the session. `"client"` declares that the caller (e.g. a locally-sequenced
  exhaustive grid/random run) decides trial order and count; the server must allocate ids
  on demand and never early-stop from its own budget, which becomes informational only.
  Contract-first step of a Schema → Backend → SDK propagation; before this field existed
  both requests used `additionalProperties: true`, so any shape of `trial_sequencing` sent
  today validates with zero errors — this closes that gap with a real enum.
- **`selection` receipt on `SessionAggregationDTO` (R3 selection receipt, PR 1 of 3).**
  New optional `selection` (`schemas/optimization/session_aggregation_schema.json`),
  carried in the finalize request's `session_aggregation` and echoed in the finalize
  response. Client-attested, server-bound: records the SDK's selection decision and
  binds it to the session's own trials; does not recompute statistics. Discriminated
  on `disposition` (`oneOf` + `const`), `additionalProperties: false` at every level.
  The `selection` block carries only ids, counts, a digest, bounded numbers, bounded
  labels and closed enums and adds no free-text field; it does not make the enclosing
  `SessionAggregationDTO` content-free (e.g. `best_weighted_config` may carry
  configuration values):
  - `accepted` (the form a client sends; persisted when binding succeeds): optional
    `attestation` (`client_attested_server_bound`, server-set), optional
    `selection_reason` (the SDK result's `reason_code`; label or null — when absent or
    null the certificate must say no selection reason was supplied, never infer one),
    `winner_trial_id`, `eligible_trial_ids` (unique, 1..10000 = Backend `MAX_TRIALS`),
    `eligible_trial_count` (1..10000), `eligible_trial_ids_digest`, optional `margin`.
    Trial ids and the digest reject any whitespace, including a trailing newline.
  - Digest preimage (exact): `sha256:` + lowercase hex SHA-256 of the UTF-8 bytes of
    `json.dumps(sorted(eligible_trial_ids), separators=(",", ":"), ensure_ascii=False)`
    (sort by Unicode code point; ids are ASCII so JS `JSON.stringify([...ids].sort())`
    is byte-identical). Known answer: `["trial_a","trial_b","trial_c"]` →
    `4a31e7194d0ef1862bfa5db184d1486776997a10810f1a72c67ab24aef08e005`.
  - `margin` (null/omitted when the SDK has no runner-up): `winner_trial_id` (the
    trial the SDK computed the margin for; required in every verdict), `runner_up_trial_id`,
    `delta`, `ci95`, `p_value` and `effective_alpha` in [0, 1], `verdict` ∈
    `clear|statistical_tie|na`, `test` label, `n_shared_examples`, `n_configs` ≥ 2 —
    shaped per verdict with Draft-07 `if/then` to match the Python SDK's
    `compute_best_config_margin`: `clear`/`statistical_tie` require numeric `delta`,
    `ci95` and `p_value` and `n_shared_examples` ≥ 1; `na` (no p-value: winner and
    runner-up share fewer than the SDK's minimum shared examples, or none; the SDK
    then reports `n_shared_examples` as 0) requires `ci95: null`, `p_value: null`, `n_shared_examples: 0`, and allows a
    numeric or null `delta`. `ci95` is the interval at level 1 − `effective_alpha`
    (not a fixed 95%); the name is the SDK payload's key.
  - `rejected_inconsistent` (Backend-written): `reason` ∈ `invalid_receipt`,
    `unknown_trial`, `winner_not_best`, `winner_not_eligible`, `runner_up_not_eligible`,
    `runner_up_is_winner`, `count_mismatch`, `duplicate_ids`, `non_canonical_order`,
    `non_finite`, `out_of_range`, `exceeds_max_trials`, `digest_mismatch`.
    **Structural failures are classified, never fatal:** a `selection` value that fails
    this schema (missing/extra field, wrong type, bad pattern, bad `attestation`) does
    not fail the finalize — the Backend persists
    `{disposition: rejected_inconsistent, reason: invalid_receipt}` and the rest of the
    finalize proceeds. **Unsorted ids are rejected, never normalised:** a unique but
    unsorted list whose digest is the canonical (sorted) digest → `non_canonical_order`;
    with a non-canonical digest → `digest_mismatch`. **Precedence** (first that applies):
    `invalid_receipt` (structure only — not the two list checks next, and not a
    number's value) → `exceeds_max_trials` → `duplicate_ids` → `non_finite` (any NaN or
    ±Infinity, ahead of every numeric bound) → `out_of_range` (a finite number outside a
    schema bound, or ci95 low > high, or n_configs > eligible_trial_count) →
    `non_canonical_order` → `count_mismatch` → `digest_mismatch` → binding reasons
    (`unknown_trial`, `winner_not_eligible`, `winner_not_best`, `runner_up_not_eligible`,
    `runner_up_is_winner`). A client may send it (the
    request schema accepts it) but the Backend ignores a client-sent
    `rejected_inconsistent` and persists no `selection` for that finalize.
  - **Backend-enforced (not expressible in JSON Schema):** every id belongs to this
    session's trials for this tenant; `winner_trial_id` is a completed trial of this
    session and is in `eligible_trial_ids` (else `winner_not_eligible`) — it is the SDK's
    own selection, not required to equal the trial the server would rank best; `margin.winner_trial_id`
    equals `selection.winner_trial_id` (else `winner_not_best` — the SDK silently
    falls back to another trial when it cannot find the requested winner);
    `runner_up_trial_id` is in
    `eligible_trial_ids` and ≠ `winner_trial_id`; `eligible_trial_ids` is sorted by
    code point; `eligible_trial_count == len(eligible_trial_ids)`; the digest is
    recomputed by the preimage rule above and must match; `ci95[0] <= ci95[1]`;
    `n_configs <= eligible_trial_count` (`n_configs` counts distinct configs, so it
    may be smaller); every number is finite (`NaN`/`Infinity` survive common JSON
    parsers and JSON Schema `number` does not exclude them → `non_finite`). A
    schema-invalid or inconsistent receipt is persisted as the rejected form (never a
    partial claim) and never fails the finalize. Backend PR 2 must also: bind the
    receipt atomically to this tenant/session's completed trials
    (same transaction as the finalize); server-stamp `attestation` on every persisted
    accepted form; and on re-finalize never retain a stale accepted receipt from an
    earlier finalize.
  - Breaking-gate acknowledgement: `property_added` on a closed, bare-named schema
    (conservative role) is allowlisted — no producer emits `selection` before the
    Backend (PR 2) and Python SDK (PR 3) land.
  - JS SDK parity: R3 is Python-scoped; a parity follow-up issue in `traigent-js` is to
    be filed by the seat and linked before R3 completion.
- **`dataset_label` on `ExperimentGroupOverview` (agent+dataset history display label).**
  New optional, nullable `dataset_label` (`schemas/execution/experiment_group_schema.json`)
  carries the human-readable display label of the canonical dataset (`Benchmark.label`)
  for an identified cohort's group-list and group-detail overview; `null` when the group
  has no linked dataset or no label is available. Purely additive and display-only — it is
  never part of group identity, `identity_state`, sort vocabulary, or pagination/cursor
  keys, and old readers that ignore it are unaffected. Fixes the portal's agent+dataset
  history table showing only an opaque `dataset_id` or "No dataset".

### Changed
- **Agent-quality offline verifier: stronger project/scope-ref privacy canary.**
  Test-only. The `expected_project_ref`/`expected_build_session_ref` privacy canary in
  `tests/test_agent_quality_verifier.py` previously exercised only the SCOPE_MISMATCH
  failure path (a caller-supplied sentinel that never matched the bundle, proven not to
  mutate the bundle by snapshot equality). That failure-path canary stays -- it is the only
  test asserting the ref is absent from the raised error -- and is joined by two canaries that traverse the
  public entry point's real success and abstain outcomes
  (`AGENT_QUALITY_VERIFIED`/`AGENT_QUALITY_CLAIM_ABSTAINED`) and prove the caller's own
  scope-ref pins never surface in the exported `AgentQualityVerificationResult`, plus a
  non-vacuity meta-test. No production code changed.

### Fixed
- **`session_submit_results_request_schema.json` now declares `summary_stats`,
  `execution_mode`, and `execution_environment` (part 1 of the #454 contract audit).**
  `POST /api/v1/sessions/{session_id}/results` already accepted all three
  (`TraigentBackend`'s `_validate_results_payload`: `summary_stats`/`execution_environment`
  as optional objects, `execution_mode` as an optional string capped at 64 chars), but the
  schema's `additionalProperties: false` rejected them, so validating a real backend-accepted
  submission against this schema failed closed on valid traffic. All three are optional and
  additive — no existing required field, enum, or type changes; not a breaking change (see
  `scripts/breaking_schema_check.py` output in the PR). The remaining #454 scope (auditing all
  x-content/x-privacy-classification annotations across `schemas/optimization/`) is deferred to
  a follow-up PR pending a per-field classification decision.
- **`session_submit_results_request_schema.json` review fixes (round 2, #454).**
  `execution_mode`'s description had the interactive/classic routing backwards: it now says
  the backend records `execution_mode` into `metadata.mode` on the interactive (typed)
  submission path (`_typed_session_is_admitted(...)` branch), not the classic path, which
  instead receives it as its own `execution_mode` keyword argument
  (`TraigentBackend`'s `src/routes/traigent_session_routes.py`). Also tightens `status`
  (255 → 64 chars) and `error_message` (5000 → 2000 chars) to match the caps the backend
  already enforces for those two pre-existing fields on the same endpoint
  (`_validate_optional_string_field(data, "status", max_length=64)` and
  `MAX_TRIAL_ERROR_MESSAGE_LENGTH = 2_000` in `src/services/traigent/terminal_outcome.py`) —
  the same too-loose-vs-backend bug class this PR already fixed for the three new fields
  above. This is a breaking (stricter) request-field change per
  `scripts/breaking_schema_check.py`; acknowledged in `scripts/breaking_schema_allowlist.json`
  with a reason (no known producer in this workspace emits a `status`/`error_message` beyond
  the new caps — the backend has rejected them already).
- **`workflow_trace_schema.json`'s `SpanPayload` object description no longer claims
  `status` is a free, non-enum-enforced string.** #175 bound `status` to the closed
  `ObservabilitySpanStatus` enum (`RUNNING`/`COMPLETED`/`FAILED`/`REJECTED`/`TIMEOUT`/
  `CANCELLED`) and updated the field-level description, but left the object-level
  description saying "`span_type` and `status` are free strings on the wire ...
  accepts arbitrary status strings" — contradicting the enum enforcement actually in
  force. `span_type` is unaffected and remains genuinely free-form. Description-only;
  no validation behavior changes (`status` was already enum-enforced).
- **`status`'s own field-level description dropped a misleading "OTel-compatible" label
  (review follow-up on the fix above).** The enum vocabulary (`RUNNING`/`COMPLETED`/
  `FAILED`/`REJECTED`/`TIMEOUT`/`CANCELLED`) does not overlap with OTel's native span
  status set (`UNSET`/`OK`/`ERROR`), so labelling the field "OTel-compatible" could lead
  a caller to send OTel's own values and get a validation error. Description-only.

### Breaking
- **`generator_config`/`evaluator_config` create-request contracts now require `model_id` and
  `instructions` (requiredness-axis mirror of #200).** The dataset-create inner contracts
  (`schemas/datasets/generator_config_create_request_schema.json`,
  `evaluator_config_create_request_schema.json`) previously declared no `required[]` at all,
  so a schema-valid config omitting `model_id`/`instructions` reached the backend, which reads
  both via a hard subscript — an opaque 500 instead of a clean 422. Requiring both fields makes
  the contract mirror what the backend actually reads; `generator_config`/`evaluator_config`
  themselves stay optional at the outer `dataset_create_request_schema.json` level, so
  dataset-create without a config is unaffected. Flagged as a breaking contract tightening by
  `scripts/breaking_schema_check.py`; acknowledged in `scripts/breaking_schema_allowlist.json`.
- **PUT /api/v1/datasets/{dataset_id} (update) no longer inherits the create-only requiredness
  above.** `dataset_create_request_schema.json` is `$ref`'d by both the create and update
  routes; the update handler reads an existing `generator_config`/`evaluator_config` as a
  partial patch (`.get()` against the stored config — only the create-if-absent branch
  hard-subscripts), so requiring `model_id`/`instructions` there too would 422 a legitimate
  partial update. `PUT /api/v1/datasets/{dataset_id}` now resolves to a new
  `schemas/datasets/dataset_update_request_schema.json`, whose `generator_config`/
  `evaluator_config` reference new `generator_config_update_request_schema.json` /
  `evaluator_config_update_request_schema.json` (same field set, no `required[]`); the create
  path (`POST /api/v1/datasets`) is unchanged and keeps requiring both fields.

## [7.0.0] - 2026-09-17

### Breaking
- **Minted a canonical `ExperimentStatus` enum and rebound the experiment
  RESOURCE's `status` to it, correcting a mis-binding to `ExperimentRunStatus`
  (#262).** The experiment resource is backed by a distinct, 8-member status
  vocabulary (`{NOT_STARTED, PENDING, REGISTERED, RUNNING, FAILED, COMPLETED,
  CANCELLED, UNKNOWN}`) that differs from the 9-member run-level
  `ExperimentRunStatus` on three values: `REGISTERED` exists only at the
  experiment level (with no run-level equivalent), while `PAUSED` and
  `PARTIALLY_DELETED` are run-level states that are not members of the Backend's
  experiment persistence enum (creating an experiment with either returns 422). The Schema previously had no `ExperimentStatus` definition at
  all — the experiment resource simply `$ref`'d the run enum.
  - `status_schema.json#/definitions/ExperimentStatus` (new): the 8 canonical
    UPPER members above.
  - `evaluation/experiment_schema.json` top-level `status` (the experiment
    resource itself): rebound from `ExperimentRunStatus` to `ExperimentStatus`.
    The embedded `ExperimentListRunSummary.status` ("current status of the
    latest experiment run") is unchanged — it is correctly a run status.
  - `evaluation/experiment_create_request_schema.json` top-level `status`:
    same rebinding, for the same reason. Its embedded
    `ExperimentListRunSummary.status` is likewise unchanged.
  - Breaking because a request or response `status` of `PAUSED` or
    `PARTIALLY_DELETED` on the experiment resource, previously schema-valid,
    is now rejected, and `REGISTERED`, previously schema-invalid, is now
    accepted — a strict `validate_response` promotion of the experiment
    resource's `status` (planned, not yet wired) would otherwise false-reject
    real `REGISTERED` experiments.
- **Reconciled the `datasets:*` auth-vocab scope mapping with the runtime bridge; removed
  the orphaned `dataset.*` permission family (#266).** `api_key_authorization_vocabulary_schema.json`
  declared `datasets:read`/`datasets:write` mapping to a `dataset.read`/`dataset.write`
  permission family with `read:dataset`/`write:dataset` compatibility aliases that the
  backend never produced or consumed in either direction (the backend bridges
  `datasets`/`dataset` to the `benchmark` resource; there is no `ResourceType.DATASET`).
  - `x-scope-permission-map`: `datasets:read`/`datasets:write` now map to `benchmark.*`
    permissions and `benchmark` compatibility aliases, mirroring `benchmarks:*` exactly
    (both scopes are runtime aliases of the same `benchmark` resource).
  - `ApiKeyPermissionToken` enum: removed `dataset.read` and `dataset.write` — no producer
    or consumer exists for new grants. `AuditPermissionValue` deliberately still accepts them,
    through a new audit-only `LegacyAuditPermissionToken` definition, because audit rows are
    immutable history and rows written under the old vocabulary must keep decoding; the
    legacy tokens are not grantable and appear in no scope mapping.
    The audit comma-list pattern is now generated from the canonical + legacy token enums
    (it had silently omitted `director_evidence.read`, so a mixed value containing it failed
    to decode) and is strictly end-anchored, so a value with a trailing newline is rejected.
    Breaking because a consumer that generated or validated against the old enum could
    previously mint/accept `dataset.read`/`dataset.write`, which are no longer valid tokens.
  - Added `x-known-resource-aliases` (new governed `x-*` extension, registered in
    `x_extensions_meta_schema.json`) documenting that `dataset` is an alias of `benchmark`
    pending a full backend rename (tracked separately as BE#1267), so the alias is explicit
    rather than silently orphaned again.
  - The matching `tests/data/auth_taxonomy_known_drift.yaml` allowlist rows
    (`be-scope-perm-datasets-read`, `be-scope-perm-datasets-write`) are removed: the
    Schema/backend drift they named has converged.
  - Out of scope for this change: the `billing_limits_schema.json` /
    `project_scoped_analytics_summary_schema.json` `benchmarks` counters. The backend billing
    and analytics surfaces still emit only `benchmarks` (no `datasets` key exists anywhere in
    those code paths), so migrating those contract fields now would recreate the same
    orphaned-token pattern this change fixes; that migration needs a coordinated backend
    change first.

## [6.1.0] - 2026-09-17

### Added
### Fixed
- **`project_retention_policy_schema.json`'s response now requires all 8 `policy`
  fields and drops their `default`s, matching the rate-limit sibling
  (`project_rate_limit_policy_schema.json`, which already requires all 4 of its
  policy fields).** Backend's `_normalize_retention_policy` unconditionally clamps
  and fills every field on every GET/PATCH response, so none of them can actually
  be absent; the response schema previously required only 2 of 8 and carried
  `default`s on the other 6 (defaults that JSON-Schema never injects on a read, and
  that belong on the update-request schema, not the resource response). Flagged as
  a breaking contract tightening by `scripts/breaking_schema_check.py`; acknowledged
  in `scripts/breaking_schema_allowlist.json`.

## [6.0.0] - 2026-09-14

### Breaking
- **Legacy execution selectors removed, not deprecated (Traigent#2271, step 1 of 4 —
  TraigentSchema only; SDK/JS SDK/Backend follow in separate PRs).** Owner decision:
  no deployed clients exist for these selectors, so this is a removal rather than a
  deprecation cycle.
  - `execution_mode` is deleted from the SDK session-create request
    (`optimization_endpoints.json` `POST /api/v1/sessions`) and is now explicitly
    rejected — sending it (any value, including the two most commonly deployed
    ones, `local` and `edge_analytics`) fails validation. It was previously a
    free-form, non-enum-constrained string accepted for backward compatibility;
    `additionalProperties: true` on that request object meant deleting the property
    alone would not have rejected it, so an explicit `allOf`/`not`/`anyOf` branch was
    added to fail closed.
  - The same `execution_mode` + flat `hybrid_api_*` rejection (`hybrid_api_endpoint`,
    `hybrid_api_transport`, `hybrid_api_transport_type`, `hybrid_api_batch_size`,
    `hybrid_api_batch_parallelism`, `hybrid_api_keep_alive`,
    `hybrid_api_heartbeat_interval`, `hybrid_api_timeout`, `hybrid_api_auth_header`,
    `hybrid_api_auto_discover_tvars`, `hybrid_api_tunable_id`) is added to
    `POST /api/v1/hybrid/sessions` (`optimization_endpoints.json` inline body and
    `hybrid_session_create_request_schema.json`), which never declared these
    properties but accepted them silently under `additionalProperties: true`.
  - `algorithm`, `offline`, and the nested `hybrid_api_options` object (the
    canonical replacements) are unchanged and continue to validate.
  - `schemas/execution/execution_mode_schema.json` is deleted. It was never `$ref`'d
    from the reachable request/response graph (the 3 canonical OpenAPI catalog
    roots) or from any live endpoint — it was already allowlisted as a structural
    orphan in `tests/test_schemas.py`'s `KNOWN_ORPHAN_ALLOWLIST` and exercised only
    by its own now-removed direct-load tests. Deleting it drops no live contract
    path.
  - `optimization_strategy_schema.json`'s `x-traigent-optimization-capabilities`
    `execution_mode` capability metadata is narrowed to canonical values only:
    `local` (client-side grid/random, no backend egress) or `cloud` (backend-driven
    trial suggestion — auto, bayesian/tpe, hyperband, frontier_scout; previously
    `hybrid`). The `hybrid`/`hybrid_api`/`edge_analytics` values and the
    `OptimizationExecutionMode` definition are deleted; a new
    `OptimizationCapabilityExecutionMode` definition (enum `["local", "cloud"]`)
    replaces it. `deprecated_execution_modes` (the `edge_analytics` alias list on
    `grid`/`random`) is deleted with no replacement — an external evaluator is
    configured via `hybrid_api_options`, orthogonal to `execution_mode`.
  - Four breaking-schema-check findings acknowledged in
    `scripts/breaking_schema_allowlist.json` (file_removed on
    `execution_mode_schema.json`; `allOf_added` ×2 and `allOf_branch_count_changed`
    ×1 on the two session-create request bodies).
  - Consumers still reading these fields (Python SDK `traigent/api/decorators.py`,
    TraigentBackend `src/shared_infrastructure/types/execution_mode.py` +
    `src/services/traigent/{interactive_session_service,session_service_refactored}.py`
    + `src/routes/traigent_session_routes.py`) are unaffected by this PR — their
    removal is scoped to separate follow-up PRs per Traigent#2271.

### Added
- **Dataset-version content digest and evaluator judge-config digest (R3-1.1),
  corrected.** `#468` (merged 2026-09-13T20:58Z at `335d8fc`, `Unreleased`) shipped
  this contract but placed `current_version` on the datasets-bucket
  `evaluator_config_schema.json` resource -- the wrong resource, since it is
  not the evaluator the Backend actually builds against. This entry describes
  the corrected, final shape develop carries once the fix-round PR (this one)
  merges: `current_version` (and therefore `EvaluatorVersionV1`'s
  `judge_config_digest`) is pinned exclusively to the observability
  `EvaluatorDefinition` resource
  (`schemas/observability/evaluator_definition_schema.json`, already
  `additionalProperties: true`), not to `datasets/evaluator_config_schema.json`,
  which never carries this field. `evaluator_version_schema.json` itself moves
  (git rename) from `schemas/datasets/` to `schemas/observability/`, next to
  the resource it versions. No producer ever emitted the datasets-bucket
  placement and no consumer reads it -- both were merged minutes apart,
  unreleased, with no Backend/SDK pin bump in between -- so no producer emits
  the new fields yet and no consumer pin is bumped, meaning deployed
  behaviour is unchanged; the offline digest helpers' behaviour changed (content
  tie-break for duplicate ids, typed errors, lone-surrogate `example_id` rejection
  through fp2's encodable-text check) and the evaluator-version schema path moved.
  The three findings
  this correction produces
  (`datasets/dataset_schema.json` and `datasets/evaluator_config_schema.json`
  losing `current_version`, plus the `evaluator_version_schema.json` file
  move) are acknowledged in `scripts/breaking_schema_allowlist.json` rather
  than silenced, so the correction stays visible in the contract history
  alongside the original `#468` entry it supersedes.

  New `DatasetVersionV1` (`schemas/datasets/dataset_version_schema.json`) carries
  an optional, nullable `content_digest` = `sha256:<hex>` over
  `UTF8("traigent.dataset_version.content.v1") || 0x00 || jcs_v1(preimage)`,
  where `preimage` is the version's examples projected to
  `{input_text, expected_output}` and ordered by a sort key that is a pure
  function of content: `(example_id.encode("utf-16-be"),
  jcs_v1(projection).encode("utf-8"))`, each compared as unsigned bytes,
  ascending. Same-`example_id` rows therefore always sort by their own
  projected content, never by producer enumeration order -- a duplicated-row
  data-quality bug stays visible (both rows remain in the preimage), while the
  digest of a given logical example set no longer depends on how a producer
  happened to iterate it (fixes an order-dependence bug in the `#468`
  implementation, where two same-id rows supplied in opposite order hashed
  differently). New `EvaluatorVersionV1`
  (`schemas/observability/evaluator_version_schema.json`) carries an optional,
  nullable `judge_config_digest` under domain `traigent.evaluator.judge_config.v1`
  over the exact persisted `judge_config` object of the observability
  `EvaluatorDefinition` resource (`schemas/observability/evaluator_definition_schema.json#/definitions/JudgeConfig`,
  the evaluator the Backend's `POST /api/v1beta/projects/<id>/evaluators`
  actually persists) -- hashed whole, with no filtering or defaulting, so an
  absent key and a key present with `null` produce different digests (key
  order is irrelevant: jcs_v1 sorts object keys before hashing). Both
  digests reuse the certification family's existing fp2/JCS role-digest
  construction via new pure, offline helpers
  `traigent_schema.compute_dataset_version_content_digest` and
  `traigent_schema.compute_judge_config_digest`. Both now validate every input
  strictly: a non-`Mapping` preimage row raises `TypeError` naming the
  offending index (not the `AttributeError` a `#468` row like a bare string
  produced by calling `.get()` on it), a `preimage` argument that is itself a
  `str`/`bytes`/`Mapping` masquerading as a sequence is rejected before
  iteration, and `compute_judge_config_digest` continues to require its
  argument be a `Mapping`. `dataset_schema.json` gains an optional, nullable
  `current_version` pointing at `DatasetVersionV1`, default `null`; producers
  MUST OMIT the key -- never emit `null` -- for old readers that VALIDATE
  against the previous schema (a closed `additionalProperties: false` object
  rejects an unknown member). Consumers in release R3: Backend PR 2.1 (dataset
  version row + `content_digest`, returns `current_version` on the dataset)
  and Backend PR 2.2a (evaluator version row + `judge_config_digest`, returns
  `current_version` on the evaluator definition); no run or certificate
  contract pins a version in this PR. The content digest identifies the
  CONTENT of the examples a version contains; membership is fixed by the
  producer at mint time, and `splits` (train/selection/test policy +
  assignments) is a usage attribute of a run, not content, and is deliberately
  excluded from this digest -- a later receipt (R4 build-level receipts) pins
  the split assignment separately. The certification family's
  `process_record_v1` digest-domain registry is unchanged.
- **`DatasetVersionV1` shape corrected to match the Backend's actual
  dataset-version wire payload.** The Backend has returned dataset-version
  payloads since #273 (`src/routes/dataset_version_routes.py`), stored in
  dataset metadata and never validated against this schema; `#468` described
  them with a guessed shape (`{id, dataset_id, revision(required)}`). This
  correction makes the schema match that payload: it now requires
  `version_label` (unique per `dataset_id`), `example_ids`, `example_count`,
  and `created_at`, makes `revision` optional (row-stored versions only), and
  adds the immutable `content_snapshot` plus `content_digest_domain` so
  `content_digest` is recomputable offline -- acknowledged in
  `scripts/breaking_schema_allowlist.json` rather than silenced. No producer
  emits `dataset.current_version` or the new `content_digest` /
  `content_digest_domain` / `content_snapshot` fields yet, and no consumer
  reads them; `Unreleased`, so the correction changes no deployed behaviour.
- **`compute_judge_config_digest` documents that the digest is a function of
  the PERSISTED object, not the request body**: a producer that normalizes
  `JudgeConfig` on write (nulls included) never stores the absent form of an
  optional key, so an omitted request field and an explicit `null` request
  field persist -- and therefore digest -- identically for that producer,
  which is why cross-producer agreement on `judge_config_digest` requires
  persisting the same fully-populated, null-filled shape.

## [5.8.0] - 2026-09-05

### Changed
- **Agent Certificate v0 packaging** now declares `cryptography>=46,<51` as a
  mandatory base runtime dependency, so a plain `pip install traigent-schema`
  can import the public relying-party verifier. The historical `certification`
  extra remains available as a no-op compatibility alias. CI clean-installs
  and functionally probes the plain wheel and checks the extra declaration;
  the separate compatibility-extra clean install remains manually executed
  release evidence rather than a second CI install job.
- **Agent Certificate v0 client preparation bounds** now use a fail-closed
  512 KiB structural resource cap with conservative headroom for projections
  that can pass the current B1/G1 semantic restrictions. This is not an upper
  bound for every generic schema branch: the generic `ClaimV0.evidence_refs`
  property has structural `maxItems: 64`, while the complete conditional
  contract admits only B1/G1 and fixes each printable claim to exactly two refs;
  production admits at most one B1 plus one G1. Larger invalid projections may
  fail earlier with the same bounded `CO_PROJECTION` code. Final verification
  remains uncapped after canonical schema validation.
- **Agent Certificate v0 HTTP error contract** defines a certificate-specific,
  content-free Draft-07 contract. Every declared certificate-route error body
  is closed to `success`, `message`, `error`, and a status-pinned `error_code`;
  generic envelopes' `details`, maps, arrays, exception text, and request
  content are not representable. The generic error envelope remains unchanged
  for all other routes. This contract declaration does not establish Backend
  runtime conformance.
- **Agent Certificate v0 relying-party verification results** now distinguish
  cryptographic success from status evidence. All current paths, including
  validated retrieval wrappers, return `VERIFIED_SIGNATURE_ONLY` with
  `status_evidence="not_checked"`; wrapper status metadata is shape-checked but
  unsigned and cannot establish current validity or non-revocation. The
  `VERIFIED` / `issuer_status_snapshot` pair is reserved for a future
  issuer-asserted status snapshot backed by an authenticated, freshness-bounded
  status-proof contract; the current v0 retrieval schema provides no such proof.
  Reconstructing the former `VerificationResult(valid=True, code='VERIFIED')`
  without the reserved `status_evidence="issuer_status_snapshot"` now raises.
- **Agent Certificate v0 signing and certification API** now use an issuer-first
  prepare/finalize protocol for G1: the issuer signs the length-prefixed
  canonical unsigned manifest, `prepare` returns that single complete
  pre-co-attestation certificate projection, and the client signs the complete
  issuer-signed projection excluding only the outer co-attestation. Finalize
  preserves that prepared issuer projection and adds the client block. B1-only
  issuance neither produces nor consumes `PrepareResponseV0`; it issues with
  issuer material alone.
- **Agent Certificate v0 G1** now uses the v2 pinned-client signed declaration and emits the
  exact honesty scope line. G1 payloads carry structurally adjacent build-session/client-key
  references and rendered text; client key references use deterministic project-scoped
  derivation from canonical public verification material. Enrollment no longer accepts a
  caller-selected client key reference, and G1 finalization requires the client co-attestation.
- **Agent Certificate v0 audit reports** now expose one closed evidence_basis per fixed row;
  B1 may be issuer-verified only when the fixed seal and signing-envelope contract passes, while
  G1 remains a client-declared unopened commitment and unsupported rows abstain.

### Added
- **Agent Certificate v0 client preparation** now exposes
  `prepare_client_co_attestation` and frozen `ClientCoAttestationContext`, the
  Schema-owned source of truth for validating the issuer prepare response
  against client-owned project/session/freshness/key/G1 expectations and for
  deriving the defensive projection, canonical client signing bytes, and
  role-domain `signed_manifest_digest`. The public helper accepts only the G1
  prepare-response shape, never a final certificate or B1-only certificate,
  and derives the project-scoped key reference from the supplied public key.
  It is deterministic and offline; its first call reads installed packaged
  Schema resources to build cached validators, while later calls reuse them.
  It handles no private keys, performs no signing, network access, writes, or
  external-state changes, and accepts only the bounded content-free projection.
  The context requires the issuer's public verification key as additional
  public-only trust material; `prepare_client_co_attestation` authenticates the
  issuer signature over the canonical unsigned manifest before returning client
  signing bytes. The 19 projection-pin expectations are required and exposed
  through the ordered `CLIENT_CO_ATTESTATION_CONTEXT_FIELDS` manifest: session
  commitment, privacy, SDK, disclosure, issuer trust pins, compiler/register
  semantics, G1 commitment, G1 verifier identity/version, client algorithm,
  and derived public-key identity cannot be selected by the issuer unnoticed.
  The issuer public key is trust material, not a projection field, and is not
  included in that manifest. Issuer/compiler evidence remains co-signed as exact bytes
  but is not represented as a client assertion of its truth. Backend lifecycle
  bounds (`expires_at`, `created_at`, and `finalized_at`) remain issuer/server
  evidence outside `PrepareResponseV0`; the signed manifest nonce is the
  client-pinned freshness input. Missing G1 client-key fields and malformed or
  unsupported packaged schema dialects fail through the closed
  `CLIENT_CO_ATTESTATION_ERROR_CODES` vocabulary. Non-string enum inputs are
  rejected through bounded context/key-reference codes before membership checks.
  Draft-07-compatible finite integral floats are accepted within the existing
  JavaScript-safe integer range and canonicalized as integers; fractional,
  non-finite, and unsafe-range floats remain bounded preparation failures. An
  iterative depth cap with explicit headroom over the packaged prepare schema
  now rejects hostile deep nesting before jsonschema error rendering.
- **`task_type` on `POST /api/v1/sessions`** (optional string, 1-128 chars): a COARSE,
  client-declared task category (`multiple_choice`, `exact_match`, `text2sql`,
  `code_generation`, `summarization`, ...) that the backend maps internally to an
  evaluator-quality anchor policy. The client never names an anchor; unknown values
  resolve to no anchor. Same shape as `optimization_plan_request.task_type`. Until this
  field, the anchor policy's only live designation path (the hint) had no typed channel,
  so every real run audited as `no_anchor_designation`.
- **Agent Certificate v0 certification API and contract** now expose lazy relying-party
  verification exports, frozen B1/G1 claim verification with explicit D2 abstention, and
  canonical public-key material validation for supported issuer and client algorithms.
- **`ExampleMetrics` sibling identity fields** in `evaluation/configuration_run_schema.json`:
  `input_id`, `example_digest`, `output_digest`, `verified_match`, and `signal_key_id`. This
  documents fields the runtime contract already accepts rather than loosening it: the backend has
  preserved unknown sibling keys on a per-example measure since #1334 (`_collect_sibling_keys` /
  `validate_example_result` in `TraigentBackend/src/models/workflow_metadata.py`), and the SDK
  already ships `input_id` today — the schema's `additionalProperties: false` on `ExampleMetrics`
  simply never enumerated it. `example_digest`/`output_digest` are keyed, one-way, client-computed
  64-character lowercase-hex identity digests (keyed to the project's own credentials, per
  `Traigent#2191` commit `7559b983`); `signal_key_id` is a 12-character lowercase-hex tag
  identifying which key version produced those two digests, present only alongside them.
  `verified_match` is `0.0`/`1.0` and MUST be omitted entirely (not sent as `null` or `0.0`) when
  an example has no usable expected answer, since absence ("not checked") is semantically distinct
  from `0.0` ("checked and failed"). Unblocks the paired `TraigentBackend#2821` / `Traigent#2191`.
  `additionalProperties: false` is kept — every sibling the client may send is now enumerated, not
  the constraint loosened. This schema-first addition targets **5.8.0**.
- **`measures` / `metadata.measures` in `session_submit_results_request_schema.json` now express
  both backend-accepted shapes.** Previously a bare `$ref` to the flat `MeasureResults` dict, which
  only documented half of what `_validate_submission_measures`
  (`TraigentBackend/src/routes/traigent_session_routes.py`) actually dispatches: the flat dict
  (`validate_measures_dict`) or a list of per-example `ExampleMetrics` results
  (`validate_measures_list`) — the list form is what carries the new `ExampleMetrics` sibling
  fields above. Both properties are now `oneOf: [MeasureResults, array<ExampleMetrics>]`, each
  branch still referencing the single canonical definition (no duplicated bounds). Existing
  flat-dict producers are unaffected — confirmed by the pre-existing
  `test_submit_results_measures_inherit_measuresdict_contract` /
  `test_submit_results_legacy_metadata_measures_is_constrained` tests continuing to pass, plus a
  direct `SchemaValidator` check of both shapes on both properties. Targets **5.8.0**.
- **Canonical cached-token usage vocabulary** in `common_types_schema.json`:
  `CacheReadTokens`, `CacheCreationTokens`, `CacheCreationTokensByTtl`, and
  `UnreportedUsageFields`. Optional nullable counts preserve the difference between a provider
  reporting zero and not reporting the dimension at all. The vocabulary is applied to observation
  read/write schemas and aggregate cost usage; cache-write totals may also carry the provider's
  5-minute/1-hour TTL split so pricing code need not silently assume the cheaper tier. All new
  properties remain optional, closed objects reject misspelled tiers, and existing payloads remain
  valid. This schema-first addition targets **5.8.0**. The ingest additions are explicitly
  `x-asserted-against-backend: false`: land Schema first, then Backend acceptance/parity
  ([TraigentBackend#2511]), then SDK producer emission. SDKs must not send the new fields to the
  live route until the Backend step lands.
- **`input_tokens` disjointness migration (target 5.8.0)** on observation ingest/read, aggregate
  cost usage, and the harness usage description: new producers normalize `input_tokens` to fresh
  input only and carry cache reads separately in `cache_read_tokens`. Records written before each
  producer adopts the contract may retain its provider-native convention and have no wire-visible
  discriminator. Consumers must partition by a known producer rollout or ingest-time boundary and
  refuse to combine an unbounded mixed-convention window for cost calculation. The harness remains
  structurally non-nullable and must not subtract cache reads unless it can preserve a reliable
  separate cache-read count; otherwise it retains the provider-native input total. This semantic
  migration is not represented as a universally compatible description-only edit.
- **Agent Certificate v0 contract family** (`certification/`, network-boundary family, per the
  Wave-C C6/C1 reconciled rulings): the `Agent Certificate` envelope with a const title and a
  mandatory build-session scope line; a discriminated `Claim | NonClaim` union in which a claim
  requires a populated versioned PASS verifier and a non-claim structurally forbids one
  (rejection, not downgrade); ONE explicit payload type per conditional v0 claim ID, keyed by
  the V4 claim-matrix's CANONICAL row IDs after reconciling the C6 rulings' colliding
  namespace — wire IDs `B1/C1/D2/F1/G1/G3/REG1`, where the rulings' "D5" (issuer-signature
  validity) maps to matrix `F1` and the rulings' "B3" (registry commitment receipt) becomes
  extension ID `REG1` pending matrix registration, because matrix `B3` is the *different*
  adverse-history claim (documented as committee-gated, not silently dropped); no generic
  slot map; the struck invented IDs B1c/D6a and the raw aliases "D5"/"B3" are not
  representable; tier 4 kept in the `ClaimTier` enum but unconstructible in any v0 claim
  (`EmittableClaimTierV0` conjoins the enum with `not: {const: 4}`); claim sentences as
  versioned templates (`certificate_claim_templates_v0_schema.json` pins all seven v0 template
  texts — claim B1 deliberately uses the narrower "the issuer signed this seal statement"
  wording); a FOURTEEN-item tuple-validated mandatory NON-claim print list; sealed-ledger wire
  shapes (fixed three-stream expected projection with explicit `chain_status` states, no
  counts/terminal sequence values, server-internal HMAC material unrepresentable); issuer
  signature + full-manifest client co-attestation shapes (the issuer signs the unsigned
  manifest first and the client then signs the complete issuer-signed projection; tier-1
  claims require a co-attestation at issuance); minimal blinded
  AgentRevision/MeasurementContract registry commitment records (no counts, no date buckets,
  no timestamps, printed non-claims in the schema descriptions); and a bounded rejection
  diagnostic (closed code vocabulary + structural path of property names/indices only).
  Additive only — no existing schema changed. New tests:
  `tests/test_agent_certificate_v0_schemas.py` (59 cases), including a family-wide boundary
  lint (every string const/enum/pattern-bound, every object closed, every array bounded) and a
  free-text quarantine test proving the family's transitive `$ref` closure reaches no
  `x-content`/`user_content` carrier.
### Fixed
- **Relative `$ref`s now resolve from their declaring schema.** 169 schema files reference
  siblings through `./x.json` or `../x.json`, while inline endpoint-catalog schemas carry no
  `$id` of their own. `Draft7Validator(schema, registry=...)` previously started from an empty
  base URI, so populated `$ref` fields were rejected and omitted fields silently bypassed the
  referenced constraint. Validation now enters each standalone schema through its registered
  `$id`; inline request schemas are anchored at the schemas root. A static regression resolves
  every `$ref` in every schema, and unresolved references are reported as contract defects rather
  than misleading payload errors. No schema content or accepted payload contract changes.
- **Experiment-group browse-row provenance now represents unidentified runs without inventing a
  cohort.** `GroupedConfigurationRunProvenance` now carries the same
  `identity_state` discriminator as `ExperimentGroupOverview`: identified rows carry a real
  `(agent_id, dataset_id)` cohort; an unidentified row carries both cohort fields as `null`.
  The browse row's existing required `experiment_run_id` remains its singleton source-execution
  identity. This corrects a contradiction where the group contract allowed an unidentified
  singleton but the row provenance required a non-null agent id, making a complete truthful browse
  row impossible. Canonical source-execution ids are not duplicated in provenance.
- **Group-list identity ordering is now cross-dialect explicit.** After the requested primary sort,
  the fixed tie-break is `agent_id` ascending with nulls last, canonical `dataset_id` ascending with
  nulls first, then `run_id` ascending with nulls first. Producers must use portable `CASE`
  null-rank terms before each value instead of database-default null ordering. The `agent_id`
  nulls-last term places identified cohorts before unidentified singletons; `run_id` nulls-first is
  not the reason for that cross-state order.
- **`identity_state` moves to expand-contract instead of being declared required on day one.**
  The above `identity_state` discriminator landed as required on both `ExperimentGroupOverview`
  and `GroupedConfigurationRunProvenance`, but the active Backend does not yet emit it on every
  item or row; a required field the producer can't yet guarantee would make every legacy
  response fail validation. `identity_state` is now optional at the top level on both objects,
  while its own enum stays closed to `identified`/`unidentified` only — there is deliberately no
  third `legacy` enum member. A new, strictly validated absence-only branch enforces the live
  legacy shape when the field is omitted entirely: a declared string `agent_id`, a string-or-null
  `dataset_id` (via the existing `CanonicalDatasetId` rules), and, on the overview object,
  `run_id` null or absent, exactly like an identified cohort — a legacy item is never a
  singleton. Absence is a third, distinct reading from both explicit states: it must never be
  treated as `identified`, and a legacy item's null `dataset_id` does not establish the
  identified branch's explicit-none dataset claim, because it predates the discriminator
  entirely. The explicit `identified`/`unidentified` branches, and the unidentified
  per-run-singleton and no-copied-`run_id`-in-provenance invariants from the two fixes above,
  are unchanged. A follow-up MAJOR revision re-tightens `identity_state` back to required once
  the Backend backfills it on every item and row.

## [5.7.0] - 2026-08-11

### Added
- **Client-owned `example_id` on example-insights rows.** The flagship
  `run_example_insights` table showed only coarse enums (priority, difficulty bucket,
  suspicious flags, recommended action) attached to server-keyed HMAC `exref_` refs the
  customer cannot map back to their own data — so "we know which of YOUR examples are
  broken" could not be demoed end-to-end. Each `example_rows` item now carries an
  optional `example_id` (string, 1–255 chars): the client-owned example identifier as
  submitted in the evaluation dataset, enabling a local content join. This widens no
  signal disclosure — example identity already crosses the client boundary as
  `/example-scoring/{run_id}/scores` keys and as GuidancePlan `seed_ref`; the field is
  identity only and carries no signal values, scores, or ranks. `safe_example_ref`
  stays required and unchanged for joins across insights surfaces; rows the backend
  cannot resolve to a submitted example simply omit `example_id` (purely additive;
  `additionalProperties: false` preserved by declaring the property).

## [5.6.0] - 2026-08-11

### Added
- **Optional `winner_stability` block on the best-config `validation` key.** Post-selection
  rerun of the winning configuration on the same evaluation set; measured evidence only —
  carries no stability guarantee. The score a run reports for its winner is a single-pass
  mean, and no shipped surface re-executes the winner to measure run-to-run dispersion; this
  block gives that measurement a contract home so producers (SDK opt-in rerun) can record it
  and downstream consumers can read it. Shape: `{reps, mean, std, scores (bounded),
  config_hash, evaluated_at}` — every member optional, the block itself closed
  (`additionalProperties: false`), defined once in
  `best_config_v2_schema.json#/definitions/winner_stability` and `$ref`ed by the v1 envelope
  so the shape cannot drift between envelopes. Purely additive: `validation` stays an open
  object (`additionalProperties: true`), payloads without the block are untouched, and this
  revision attaches no gating and no claim semantics — recording the measurement is the
  entire contract.
  - Semantics per the C3/C5 committee rulings: `std` is the **sample** SD and is always shown
    when computable (no small-replicate suppression; undefined for a single replicate, hence
    optional); no numeric stability thresholds and no "flip" concept ship in v0; the
    description marks pairwise per-example comparisons as clustered/dependent (same frozen
    example set), prohibits feeding contrast selection or any noise floor, names the S2
    verdict path as the block's consumer (absent stability evidence the affected metric
    verdict is INDETERMINATE; a single execution may still be reported descriptively), and
    carries the two verbatim claim / NON-claim strings that any rendering of these numbers
    must ship together.
## [5.5.0] - 2026-08-01

### Added
- **Per-run narrative on the experiment run, and a stable `agent_key` on session creation.** An
  optimization run could record *what* was tuned and *which config won*, but not *what question the
  run was asking*. Across many runs on one agent the history is therefore unreadable, and engineers
  (or their coding agents) repeat experiments that were already run. Two purely additive fields fix
  the first half: optional **`name`** (≤512, the title — "Check best router model") and
  **`description`** (≤4000, the hypothesis or intent, recorded before results are known) on
  `evaluation/experiment_run_schema.json`. Both are author-supplied, written by a human or their
  coding agent and never generated by Traigent, so both carry `x-content: true` +
  `x-privacy-classification: user_content` and are now covered by
  `tests/test_content_privacy_annotations.py`. The columns already exist in the backend (added
  2026-07-05); this brings the wire contract level with storage. `required` is untouched and
  `additionalProperties: false` is preserved by declaring the new properties.
  - The obvious way to ship a run title would have broken the feature it serves. `function_name` on
    `POST /api/v1/sessions` is not only a label — the backend resolves the owning agent by
    normalizing it, and optimization history is grouped by (agent, dataset). A descriptive
    per-run `function_name` therefore mints a **new agent per run** and shatters that history into
    one-run cohorts. So this release also adds optional **`agent_key`** (a stable identity key,
    the sole basis for agent resolution when present) alongside **`run_title`** / **`run_description`**
    (the narrative, on the way in). Omitting `agent_key` preserves the legacy
    derive-identity-from-`function_name` behavior exactly, so existing callers are unaffected;
    `function_name`'s description now states the collision outright and points new callers at the
    split.
  - Three **`x-backend-obligations`** entries on the run schema record the invariants JSON Schema
    cannot enforce: the narrative must not influence any Traigent-computed output (scoring,
    certified selection, promotion, or next-steps guidance — recommendations stay reproducible from
    run data alone, byte-identical with or without a title); it must be excluded by default from
    telemetry, trace lanes, planner/LLM prompts, billing metadata, and logs, and redacted on export
    absent explicit opt-in; and agent identity must never be derived from a per-run title. Declaring
    them here documents the obligation — it is not evidence any consumer satisfies it.
## [5.4.0] - 2026-07-30

### Added
- **A canonical, additive HTTP `201` registration-success contract.**
  `auth/register_created_response_schema.json` models the Backend's real wrapped
  `{success, data}` envelope and makes the two successful outcomes explicit: a no-session result for
  cohort, invite, and ordinary registrations, or a complete access/refresh-token pair for the
  verified self-serve flow coordinated with TraigentBackend #2481. The self-serve producer is not
  deployed yet, so the schema is conservatively marked `x-asserted-against-backend: false`.
  `auth_endpoints.json` now publishes the `201` response; the previously published flat `200`
  contract remains accepted and is explicitly deprecated until its 6.0.0 removal. This is
  MINOR-safe: it adds a new schema/response entry without tightening or deleting any 5.3 validation
  behavior.

- **`auth/register_request_schema.json` now documents two of the three credential fields the register
  endpoint accepts.** `invite_token` and `registration_code` were undocumented, so the only credential a
  reader could discover was `access_code`. `registration_code` is the portal's unified wire field for
  the code shown to a reader as their "access code": it can carry either an administrator-issued cohort
  code or the single-use, address-bound code e-mailed to a self-serve registrant, and the server
  dispatches it to the appropriate credential store, cohort first. `access_code` remains the
  cohort-only field for callers that identify that credential type explicitly.

  Purely additive: both new property entries contain documentation annotations only, and
  `additionalProperties` remains `true`. They deliberately carry no `type`, `maxLength`, or other
  validating keyword in 5.4.0, because a named-property constraint would reject values that 5.3.0
  accepted while the same names were treated as unknown properties. Runtime constraints can be
  encoded with the closed property set in the next major release.

### Fixed
- **The register schema no longer claims the server ignores unknown keys.** Its description said
  "backend reads these keys and ignores unknown ones"; the server does the opposite and **rejects** an
  unknown key with a `400`. A client trusting the old text would send a retired or misspelled field,
  expect it to be dropped, and have the whole registration refused. The description now states the real
  behaviour.

  **Deliberately NOT encoding that as `additionalProperties: false` in this release**, though an earlier
  draft of this change did. The new fields are also annotation-only for the same compatibility reason.
  Two facts make either form of validation tightening a *major*, not a minor:
  its blast radius is external — a consumer pinned to `^5.3` would silently begin rejecting payloads it
  previously accepted, with no change on their side, which is precisely the break semver exists to
  signal; and a schema package's published shape *is* its compatibility surface, so "the old contract
  was inaccurate" does not downgrade the change. Scheduled for the next major, once the producer it
  describes is deployed.

- **The device-token `403` contract now documents entitlement loss after approval.** An
  `access_denied` token response can mean either that the person denied the device request or that the
  approved principal lost product access before token exchange; neither case issues credentials.

- **`entitlement_required_error_schema.json`: five backend obligations reduced to three**, with no
  obligation lost. The five contained two near-duplicate pairs and one internal contradiction:
  - the two `message` obligations are merged — the second was a strict superset of the first;
  - the two `reason`-precedence obligations are merged, and the contradiction removed. One stated that
    the producer "picks exactly one by a documented precedence rule" while leaving that rule unstated
    and asserting the contract "cannot determine which account state caused the refusal"; the other
    supplied the actual rule. The surviving text keeps the concrete rule — emit `access_period_ended`
    whenever a period existed and elapsed — *and* the honest statement that the contract cannot
    adjudicate, since both are true and only the vague half was redundant.
  - the HTTP-status obligation is unchanged.

## [5.3.0] - 2026-07-29

### Added
- **Access-period lifecycle stages on the `funnel.v1` onboarding-funnel contract, and a new shared
  `entitlement_required` error body (#361).** The funnel `stage` enum grows from 8 to 11 members,
  in place on `funnel.v1` rather than as a `funnel.v2`: the contract is `x-stability: pre-release`,
  the change is purely additive (all eight existing values survive and every existing fixture still
  validates), and no producer emits it yet, so minting a v2 would strand a v1 nothing ever wrote.
  - **`access_period_started`** (between `account` and `key`) records the account's portal access
    period beginning at registration; **`access_period_ended`** records that period elapsing and
    **`access_restored`** records access being restored on the same account — both appended after
    `enhanced`, since they are post-funnel lifecycle observations of an attempt that already
    completed. The stage description states outright that **`key` is non-authorizing**: an API key
    is a credential, never the entitlement, so possession of one is not an access period. It also
    pins the analytics rule that a lifecycle observation carries `outcome: "ok"` — the observation
    itself succeeded, and a lapse is time elapsing, not the lead-initiated stop that `outcome`
    already defines `abandon` to mean. Enum order remains documentation only, reconciled
    server-side, as for the economics funnel sibling.
  - A fifth **`x-backend-obligations`** entry declares the access-period linkage the wire cannot
    enforce: an `access_period_ended` or `access_restored` event fires long after the originating
    onboarding attempt, so the producer must durably retain the `run_id` correlation. The contract
    records observations of the period's lifecycle and never its duration, deadline, or policy,
    which stay server-resolved.
- **`entitlement_required_error_schema.json` — the "authenticated, but not entitled" response body
  (#361; coordinates with TraigentBackend #2461).** A new root-level schema composing
  `error_envelope_schema.json` exactly as `validation_error_schema.json` does, because the error
  can fire on any gated route and is not an onboarding-specific fragment. `error` is pinned to the
  const `entitlement_required`, and `details` is closed (`additionalProperties: false`) around a
  required **`reason`** ∈ `{access_period_ended, no_active_plan}` — so consumers branch on a
  machine-readable cause, never on prose. `reason` lives under `details` and not at the top level
  because the envelope is `additionalProperties: false` and `additionalProperties` does not see
  properties declared in a sibling `allOf` branch; a top-level `reason` would be rejected outright.
  `message` stays a bounded (≤512) free string rather than a `const`: it is client-rendered display
  text, and freezing English prose would block localization and make every reword a contract change.
  No `error_code` const is minted — `error` plus `details.reason` already determine every branch.
  - Marked `x-stability: pre-release` / `x-asserted-against-backend: false`. The properties JSON
    Schema cannot check are declared under `x-backend-obligations`: that `message` must carry no
    credential, internal identifier, route, or storage detail and must not be branched on; that
    `reason` precedence is the producer's documented decision when both causes describe one
    account; and that HTTP status selection is deliberately per-surface and not pinned here.

## [5.2.0] - 2026-07-28

### Added
- **Cross-repo onboarding-funnel event contract, `funnel.v1` (contract-first, pre-release).** A new
  standalone event schema `onboarding/onboarding_funnel_event_schema.json` defining the single wire
  unit of the onboarding funnel: `{run_id, ts, stage, event, actor, outcome, meta?}`, so any surface
  (SDK, coding agent, portal, backend) can emit a comparable event without inventing fields. The
  event object is closed (`additionalProperties: false`) with `schema, run_id, ts, stage, event,
  actor, outcome` required.
  - **`run_id`** is an opaque **public** correlation id for the onboarding attempt — not a secret,
    revealing nothing about credentials — bounded to an identifier grammar (alphanumeric-bounded, with
    `.`/`_`/`:`/`-` only between alphanumerics, 1–128 chars, `x-identifier: true`); the end is anchored
    with a negative lookahead rather than `$` so a trailing newline and a punctuation-only id are
    rejected. **`ts`** is RFC-3339 UTC pinned to a trailing `Z` by pattern (mirrors the economics
    `UtcTimestamp` shape, a ≤9-fractional-digit / nanosecond subset), so an offset-bearing timestamp
    read as UTC cannot silently reorder the funnel. **`stage`** is a closed 8-member enum
    (`discover, verify, handoff, assess, baseline, account, key, enhanced`); **`event`** is a
    bounded opaque identifier label (ShortLabel-style grammar, ≤128); **`actor`** ∈
    `{human, agent, system}`; **`outcome`** ∈ `{ok, retry, fail, abandon}`. Optional **`meta`** is a
    bounded string→string map (`maxProperties: 64`, per-value `maxLength: 8192`) marked
    `x-content: true` + `x-privacy-classification: user_content`. A **required** `schema` self-descriptor
    pins the wire version (`const: "funnel.v1"`) so every event self-identifies its contract version.
  - Marked `x-stability: pre-release` and `x-asserted-against-backend: false`. The invariants JSON
    Schema cannot enforce — tenant ownership of `run_id` from the authenticated request context,
    cross-event stage-order reconciliation, the 65536-byte event ceiling (`x-max-event-bytes`, a byte
    count JSON Schema cannot compute, enforced backend-side), and downstream `meta` redaction — are
    enumerated under `x-backend-obligations` so they are visible rather than assumed proven. No
    endpoint-catalog entry is added: the contract defines the wire, not a client-facing route.

## [5.1.0] - 2026-07-25

### Added
- **Observability v2 availability and v1beta retirement posture (contract-first, pre-release;
  TraigentBackend #2127).** The v2 event-admission and ingest-status routes were published with
  the v2 protocol contract before a backend serves either path. Both operations now carry the
  existing `x-stability: pre-release` / `x-asserted-against-backend: false` classification at
  operation scope, the truthful scope for a canonical observability catalog that otherwise
  contains live backend routes. Their documented 202/200 semantics remain the intended protocol,
  not an assertion of present backend behavior, until the open draft TraigentBackend #2127 lands.
  The same release had prematurely represented the two live v1beta snapshot-ingest routes as
  retired-only. They now document both states explicitly: current TraigentBackend `main` and
  `develop` accept each route with 202, while the typed 410 `SNAPSHOT_PROTOCOL_RETIRED` response
  is a declared-ahead-of-backend cutover state that waits on #2127. This keeps the v2 direct-cutover
  rule (no translation or materialization after retirement) visible without telling consumers that
  a presently working endpoint has already disappeared.
- **Optional first-party `attribution` provenance block on the next-steps and decision-payload
  response schemas (#352).** Mirrors `Traigent/TraigentBackend#2431` — a closed object
  (`source`/`label` consts, `headline`/`why`, a 5-token `basis` enum, `engine` in `{rules,policy}`)
  added under `properties` of `next_steps_schema.json` and `decision_payload_schema.json` (inherited
  by `decision_payload_response_schema.json` via `$ref`). Optional — absent on empty/degenerate
  responses; next-steps carries an `allOf` honesty guard requiring `attribution` be absent when there
  is no decision and no served step. Additive: strict consumers no longer reject the field the
  backend now emits.
- **Economics recommendation calculator contract (contract-first, pre-release).** The closed
  characterization submission and the backend-authoritative recommendation for a new canonical
  route `POST /api/v1/economics/recommendation`, published ahead of the backend recommendation
  service and the MCP survey tool per the cross-repo rule that request/response shapes start in
  TraigentSchema. Added to the existing `planned_projects` (non-canonical) economics catalog and
  marked `x-asserted-against-backend: false` — no backend serves it yet. The route documents 200
  (recommendation computed), 400/422 (validation), 401/403 (auth), and 503 (service unavailable).
  Every non-2xx status binds `error_envelope_schema.json`, the same shared envelope the sibling
  telemetry route binds since 5.0.0 (#343) — specified here rather than observed, since no
  implementation exists yet, and pinned by tests so the bare-description gap #343 closed next
  door cannot reopen on this route.
  - **Closed characterization submission** (`economics_recommendation_request_schema.json`): the
    five closed band fields and their optional typed overrides (reused from the characterization
    vocabulary by `$ref`, never restated), each with per-field `asked | inferred | defaulted`
    provenance, required confidence, and evidence accounting. The characterization payload reuses
    the WI-B telemetry characterization object so the closed-pipe egress rules are the SAME pipe
    here as in telemetry rather than a second, drifting restatement: a field reported
    `withheld_by_policy` is ABSENT from the transmitted value area, a transmitted value carries a
    `shared` report, a `shared` report carries its value, and an inferred value accounts for its
    evidence (a withheld pointer cannot ride along). `additionalProperties: false` at every object
    boundary, and no prose field is declared. Six client-authored strings remain
    (`request_id`, `source.name`, `source.version`, both `sharing_policy_version` labels,
    and the evidence pointer); each is bounded by an identifier grammar that blocks
    sentences but not content, since `Alice.Smith.SSN.123-45-6789` is a valid identifier.
    They are enumerated in a backend obligation requiring redaction and pinned by a test,
    rather than described as a closure the contract does not deliver.
  - **Structural client-side sharing policy.** A `sharing_policy` with a `policy_version` and an
    `allowlist` of the fields permitted to egress. Withholding is structural, not advisory: a
    value present in the transmitted value area REQUIRES its field on the allowlist (enforced per
    field), so a transmitted value for a non-allowlisted field is unrepresentable. An empty
    allowlist (share nothing, all fields reported `withheld_by_policy`) is honest and fully
    representable, and the recommendation still returns the spend-$0 case.
  - **No presentation channel at all.** An earlier draft of this contract carried an 80-character
    `agent_display_name` and argued that being bounded and control-character-free meant it "cannot
    become a free-text egress channel". That was false — 80 printable characters carry prose — so
    the field is removed rather than re-worded, and `additionalProperties: false` now makes it
    unrepresentable. Nothing replaced it: the agent renders the recommendation in the user's own
    terms from structured tokens, on its own machine, so the name never needs to be transmitted.
  - **Evidence pointers are narrowed to an opaque grammar in this request.** The shared WI-B
    `EvidencePointer` admits 280 characters of free text; inside this request it is intersected
    with the repo's opaque-identifier grammar, which rejects whitespace, quotes, at-signs,
    non-ASCII, and control characters — so a copied sentence or an email address is
    unrepresentable. It does NOT make PII or values unrepresentable: the grammar permits
    separators between alphanumerics, so `Alice_Smith_SSN_123-45-6789` remains a valid token.
    This bounds the channel and blocks the copy-a-sentence case; it is not a privacy boundary,
    and a test pins that residual so the wording cannot drift ahead of it. The shared definition
    is deliberately NOT changed
    here — narrowing a shipped contract is a breaking change owed a coordinated MAJOR release —
    and the narrowing is documented as BOUNDING the channel, not sealing it: a token can still
    encode a number, so treating pointers as user content (redact, never parse, never join to a
    withheld field) remains a declared backend obligation.
  - **Backend-authoritative recommendation** (`economics_recommendation_response_schema.json`):
    versioned formula/assumption identity with a required `assumptions_are_starting_assumptions:
    true` label and a **required** `published_reference` — required rather than optional because
    the auditability claim would otherwise outrun the contract: a response naming only two
    internal version labels leaves a consumer nothing to look up. That the reference actually
    resolves to a published document is a declared backend obligation the schema cannot enforce;
    archetype and dominant value channel (vocabulary `$ref`); a recommended daily
    build budget with archetype floor/cap (labelled starting assumptions, `const`-guarded) and a
    conservative-lower-bound basis carrying the value interval with its level; a structured
    payback statement where `payback_days` exists ONLY on a positive conservative lower bound and
    is forbidden otherwise; a closed stop rule; the required receipt kind (reused from the receipt
    contract by `$ref`); a first-class spend-$0 case that is ALWAYS present with `available: const
    true`; and a required, non-empty, bounded `why` of STRUCTURED, closed-vocabulary render tokens
    the coding agent turns into prose in the user's own terms (their value channel, volume band,
    error-cost band). No render token can claim an assumption was validated — the only
    validation-status token is `assumptions_are_starting_not_validated`.
  - **An undetermined recommendation cannot invent a value channel.** `ValueChannel` is a
    closed vocabulary with no `undetermined` member (unlike `Archetype`, which has one), while
    `dominant_value_channel` was unconditionally required — so the design's own "all-withheld
    submission still gets the honest spend-$0 answer" branch was unrepresentable: any 200 had
    to assert a channel the backend could not know, contradicting the no-backfill obligation.
    `dominant_value_channel` is now required only when the archetype is determined, and both
    channel fields are forbidden when it is `undetermined`.
  - **Independence from funding and pricing.** The recommendation is independent of credits,
    incentives, grants, promotional balances, wallet/billing state, and pricing: no such field is
    declared or representable in either contract (`additionalProperties: false` blocks any), so no
    such state can be SUBMITTED to or RETURNED from the recommendation. Note the honest limit: the
    schema cannot stop a backend from joining pricing or wallet state it already holds server-side —
    that is the NO PRICING/CREDIT/WALLET INPUT backend obligation, not a structural guarantee. Budget floors/caps are labelled starting
    assumptions, NOT funded amounts — funding (the seven-day credit envelope) is the separate WI-D
    owner-gated decision and is deliberately out of scope here.
  - **Deterministic example vectors** (`tests/test_data/economics/`): request/response pairs
    (solo builder, support automation, and an all-withheld submission paired with an
    `undetermined`-archetype spend-$0 recommendation that names NO value channel), paired by echoed `request_id` and carrying no computation implementation.
    They are schema-valid EXAMPLES, not conformance evidence: nothing implements this contract
    yet, so no claim is made that a backend or an offline path agrees with them. Conformance
    testing begins when the first producer exists.

## [5.0.0] - 2026-07-24

### Breaking

The 4.9.0 -> 4.14.0 develop-line aggregate contained public, intentional
contract tightenings (workspace no-silent-legacy policy) that were shipped
as `fix(contract)` PATCH/MINOR bumps. SemVer requires a MAJOR bump for any
of these; none was taken at the time. This release corrects the version
number only — no further schema behavior changes. Every item below was
verified against the actual schema diff (`git diff origin/main..origin/develop`
on the pre-5.0.0 tree); each is a strict narrowing of a previously-valid
request shape.

- **`billing_limits_schema.json` no longer accepts the formerly-required
  trials-only shape (#333, `57b4069`).** `required` changed from
  `["trials", "api_calls", "benchmarks", "users"]` to
  `["optimization_trials", "optimization_samples", "api_calls", "benchmarks",
  "users"]`. A payload that supplies only the deprecated `trials` alias
  (previously sufficient) is now rejected: `optimization_trials` and
  `optimization_samples` are both required.
- **`evaluator_definition_create_request_schema.json` no longer accepts an
  open/free-form `judge_config` on create (#337, `abee0b1`).** `judge_config`
  changed from `{"type": "object", "additionalProperties": true}` to
  `$ref: evaluator_definition_schema.json#/definitions/JudgeConfig` — the
  same strict contract as update (`additionalProperties: false`; requires
  `instructions`, `model_id`, `context_type`). A previously-valid partial or
  additional-property-bearing `judge_config` on create is now rejected.
- **`annotation_queue_update_request_schema.json` no longer accepts
  `measure_ids: []` (#341, `05e6afb`).** `measure_ids` gained `minItems: 1`,
  matching create. An update can no longer clear a queue's measure set to an
  empty array through this field.
- **`spend_approval_request_schema.json` no longer accepts unbounded or
  non-numeric `requested_estimate_usd` (#333, `57b4069`).** Previously
  `type: ["number", "string", "null"]` with only `maxLength: 64` and no
  `pattern`/`minimum`/`maximum` — any non-numeric string under 64 characters,
  any negative number, and any arbitrarily large number all validated. Now
  bounded to `[0, 1,000,000]` with a pattern constraining the string branch
  to the same range. This is a fourth breaking change found while auditing
  this range; it was not part of the original three-item report that
  triggered this release.

Only these four changes are breaking. Every other schema delta in the
4.9.0 -> 4.14.0 range (economics telemetry contracts — entirely new;
`execution_mode` becoming optional; `judge_config` parity note above;
pagination/enum/response-field widenings; the `measure_type` conditional
open-vocabulary escape hatch for `is_custom=true` records) is additive or
loosening, not breaking.

### Added

- **Economics telemetry endpoint contract completeness (`economics/economics_endpoints.json`).**
  The `POST /api/v1/economics/telemetry` OpenAPI entry documented `400`,
  `401`, `403`, `409`, `413`, and `422` with bare text descriptions and no
  response body schema. TraigentBackend (`origin/develop`,
  `src/routes/economics_routes.py` +
  `src/services/economics/telemetry_ingest_service.py`) already serves this
  route for real and validates its own responses against these exact
  `traigent_schema` files (`src/services/economics/schema_contract.py`
  loads `traigent_schema/schemas/economics/*` directly). Verified against
  that implementation:
  - `422` is not a generic error — the service builds it with
    `_build_response(..., replayed=False)` and validates it with
    `_validate_response(response, replayed=False)`, i.e. the exact same
    `economics_telemetry_ingest_response_initial_schema.json` shape as
    `201`, distinguished only by status code (all events rejected). The
    endpoint contract now `$ref`s that schema for `422` instead of leaving
    it bodyless.
  - `400`/`401`/`403`/`409`/`413` are all produced by the backend's
    `error_response()` helper, which emits exactly the
    `{success, message, error, error_code}` shape of
    `error_envelope_schema.json`. The endpoint contract now `$ref`s
    `../error_envelope_schema.json` for each, matching the convention used
    by canonical modules (e.g. `billing/spend_controls_endpoints.json`).
  - Added previously-undocumented `500` (unhandled ingestion failure /
    internal response-contract invariant breach) and `503`
    (`EconomicsSchemaUnavailable` — contract unavailable, fails closed),
    both also `error_envelope_schema.json`.
  - Left `x-stability: pre-release` / `x-asserted-against-backend: false`
    and the `planned_projects` catalog placement unchanged: an existing test
    (`tests/test_economics_telemetry_contract.py::test_route_is_not_claimed_as_canonical_backend_truth`)
    locks that classification in as an intentional, tested decision, and
    flipping it is a cross-repo release-posture call for the owner, not a
    schema-correctness fix. See the accompanying report for detail — the
    docstring backing that test ("no backend serves this yet") is now
    factually stale given the live TraigentBackend implementation, which is
    flagged separately rather than changed unilaterally here.

## [4.14.0] - 2026-07-19

### Changed
- **`measure_ids` create/update parity in annotation queues (#340):**
  `annotation_queue_update_request_schema.measure_ids` now enforces
  `minItems: 1`, matching `annotation_queue_create_request_schema` (which
  already required a non-empty array). An update can no longer clear the
  measure set to an empty array through this field, closing the create/update
  contract asymmetry.

## [4.13.0] - 2026-07-19

### Changed
- **`execution_mode` optional in `execution_mode_schema` (#334):** the schema's
  `required` set is now just `["experiment_id"]` (was
  `["execution_mode", "experiment_id"]`). `execution_mode` is a canonical
  selector that the backend defaults, so it need not be supplied by the client;
  the existing `if/then` conditional (hybrid_api → require api binding) is
  unchanged and still applies when `execution_mode` is present.
- **`judge_config` create/update parity in evaluator definitions (#335):**
  `evaluator_definition_create_request_schema.judge_config` now `$ref`s
  `evaluator_definition_schema.json#/definitions/JudgeConfig` — the same strict
  contract used by the update request (required: `instructions`, `model_id`,
  `context_type`; `additionalProperties: false`) — instead of an open
  `{type: object, additionalProperties: true}`. An incomplete judge config is
  now rejected on create as well as update. RESIDUAL: needs BE-owner
  confirmation (#335) that the backend accepts/emits the strict JudgeConfig on
  the create path.

## [4.12.0] - 2026-07-19

### Changed
- **Bound `requested_estimate_usd` in spend-approval requests (#330):**
  `spend_approval_request_schema` now constrains `requested_estimate_usd` to a
  non-negative, bounded money value — the string branch must match
  `^(?:\d{1,6}(?:\.\d{1,6})?|1000000(?:\.0{1,6})?)$` (non-negative decimal in
  `[0, 1,000,000]`, ≤6 fractional digits; the pattern itself caps the string
  value since JSON-Schema `minimum`/`maximum` bind only the number branch) and
  the number branch is bounded to `[0, 1,000,000]` — rejecting negative, non-numeric,
  and absurdly large estimates at the schema layer (mirrors the
  `wallet_admin_adjustment_request` money-bounds pattern). Authoritative
  policy-threshold enforcement remains backend-side.
- **Require the canonical optimization meter pair in `billing_limits` (#329):**
  `billing_limits_schema` now requires `optimization_trials` and
  `optimization_samples` (alongside `api_calls`, `benchmarks`, `users`) instead
  of the deprecated `trials` alias, so the admission-critical canonical meter
  pair must be present. RESIDUAL: TraigentBackend must emit
  `optimization_trials`/`optimization_samples` in billing-limits payloads for
  canonical read-back to pass.

## [4.11.0] - 2026-07-19

### Changed
- **Custom measure_type round-trip, conditionally (#321):** `measure_schema`
  now validates `measure_type` with an `is_custom`-keyed conditional:
  standard measures (`is_custom=false`, or absent) MUST use the closed
  `#/definitions/MeasureType` vocabulary, while custom (`is_custom=true`)
  measures may use any bounded, non-blank, control-char-free label
  (minLength 1, maxLength 255). A custom `measure_type` now round-trips
  create → read-back, WITHOUT opening `PUT /api/v1/measures/{measure_id}`
  (which consumes this schema as its request body) to blanks, typos, or
  arbitrary labels on standard measures. The create request
  (`measure_create_request_schema`) deliberately stays backend-modeled
  (free string, extra=allow — see `tests/test_create_request_contracts.py`);
  RESIDUAL: server-side enforcement of the conditional vocabulary on
  `POST /api/v1/measures` is a TraigentBackend follow-up — until then a
  standard-measure create with a junk `measure_type` is accepted by the
  backend but will (correctly) fail canonical read-back validation.
- **Measure value-type discriminator (#320):** added a canonical
  `MeasureValueType` enum (`numeric|categorical|boolean`) to `measure_schema`
  and `$ref`'d it from the observability `review_score`/`review_measure_summary`
  read schemas (previously duplicated inline). The measure-definition
  `value_type` stays a documented open free-form label; the closed enum applies
  only where a score value is projected onto a typed column.
- **Review-score source vocabulary (#318):** widened `review_score_schema`
  `source` to the create-request's eight values
  (`manual|evaluator|api|human|user|llm|model|sdk`) so a legitimately-POSTed
  source round-trips through `validate_response`.
- **Pagination canonicalization (#319):** added a canonical
  `offset_pagination_schema` (`limit/offset/total/has_more`) and `$ref`'d it
  from the comparison-examples list response (previously inlined). The flat
  `{page, per_page, total}` observability/costs list responses
  (session/trace/issue/trace_variant/cost_users) now also permit the optional
  canonical `total_pages`/`has_next`/`has_prev` fields.
  **Compatibility note:** `cost_users`, `issue_list`, and
  `trace_variant_list` responses were CLOSED schemas
  (`additionalProperties: false`) through 4.10.0 — a client validating
  responses against ≤4.10.0 will REJECT a server that starts emitting the
  new fields. Backend emission of `total_pages`/`has_next`/`has_prev` on
  those three endpoints is therefore gated on consumers regenerating to
  ≥4.11.0 first (additive-with-regeneration-gate, not zero-impact).
  `session_list`/`trace_list` were already open schemas; for them the fields
  are plainly additive.

### Deferred
- **Trace-ingest timestamp enforcement (#316 residual):** `workflow_trace_schema`
  span `start_time`/`end_time` keep their prose-only ISO-8601 promise; the
  planned `format: date-time` assertion is NOT applied. The repo validator
  enforces `format` (RFC 3339 via `FormatChecker`), and the Python SDK's
  ingest producer (`traigent/integrations/observability/workflow_traces.py`,
  `add_span` path, lines ~1383-1423 at time of writing) accepts
  `datetime | str`, emitting offset-less `.isoformat()` for naive datetimes
  and passing caller strings through verbatim — so machine-enforcement would
  reject payloads today's producers legitimately emit. Normalize the SDK
  producer (require tz-aware, normalize strings) first; then apply the
  format assertion in a follow-up schema release.

## [4.10.0] - 2026-07-17

### Added
- **Economics telemetry contract (contract-first, pre-release).** A strict, versioned
  shared contract for `POST /api/v1/economics/telemetry`, published ahead of backend
  ingestion and SDK emission per the cross-repo rule that request/response shapes start
  in TraigentSchema. Registered under the `planned_projects` (non-canonical) contract
  root and marked `x-asserted-against-backend: false` — no backend serves it yet.
  - **Exposure funnel events** across the nine stages (`eligible` →
    `production_retained`). Every exit carries a CLOSED reason code: `exit_reason` is
    required when `outcome` is `exited` and forbidden otherwise, and there is no `other`
    member and no free-text note — an exit that fits no code is a versioned enum
    addition, not a prose escape hatch. At the `production_retained` stage
    `occurred_in_environment` is REQUIRED and must be `production` (keyed on the stage,
    so an exit there obeys it too): production retention is the numerator of the
    retention rate, so a retention observation that omits its environment or names
    `development`/`staging` would inflate that numerator with runs that never reached
    production. Earlier stages leave `occurred_in_environment` optional and
    unconstrained.
  - **Run economics** is the SETTLED record of a run whose effect was measured (a
    failed/capped/insufficient-evidence run is a funnel exit, not a blank settlement),
    so the whole record is required, not just identity: characterization bands/overrides
    with per-field `asked | inferred | defaulted` provenance, confidence, and sharing
    outcomes; archetype; backend-authored budget recommendation/cap (`authored_by` is a
    `backend` const, so an agent-authored budget is unrepresentable); actual spend;
    explicitly-metered usage (`input_tokens`, `output_tokens`, `model_calls` required, so
    a $0 run reports explicit zeros rather than an empty object that meters nothing);
    model prices with a closed price source; evidence identity with the measured effect
    REQUIRED (baseline/candidate and evaluator, objective weights, effect estimate with a
    required interval and level, support, and explicit exclusions; `holdout_hash` stays
    optional because measuring without a holdout is a real fact); advisory behavior
    (recommendation, client action, closed off-menu classes, adherence probability,
    planner-blind information); and labor proxies where claimed hours avoided require
    human confirmation.
  - **Receipts** with closed kinds `winner | defect | savings` and kind-specific
    required evidence, discriminated so a receipt cannot carry another kind's block.
    Savings are metered-only: `measurement_method` is a `metered` const and
    `meter_source` is closed to authoritative meters, so an agent-authored estimate
    cannot be submitted as a savings receipt. A winner whose `promotion.status` is
    `promoted` or `reverted` MUST carry its `production_follow_up` (a pending one is
    truthful — `scheduled` with a `due_at`), so a promotion cannot stay silent about the
    eval-to-production transfer it depends on; and a `not_promoted` winner MUST NOT carry
    one — nothing was deployed, so a scheduled or confirmed production check on a
    configuration declared never deployed is production-transfer evidence for a transfer
    that by definition never happened, and forbidding it (rather than merely not
    requiring it) closes that hole.
  - **Field-level sharing rules, enforced by the contract.** `sharing_outcome` and a
    transmitted value form a biconditional, enforced per allowlisted field as presence
    checks keyed on a closed enum (which Draft-07 can express, so a client verifies them
    on its own machine before a payload egresses): a field reported
    `withheld_by_policy` must be ABSENT from `bands`/`overrides` (egress); a value
    present must carry a `shared` report (coverage); and a `shared` report must carry its
    value (substance), so a report cannot be an empty alibi that names a sharing outcome
    while transmitting nothing.
  - **Batch envelope** with stable contract/version identifiers, an idempotency key
    (also accepted via the `Idempotency-Key` header) and a 500-event cap. The response
    reports submitted/accepted/duplicate/rejected counts with closed rejection reasons
    and ALWAYS carries a `rejections` array (empty when none, so 'stored' is
    distinguishable from 'silently dropped'). Per-status response schemas bind the replay
    flag: HTTP 200 (replay) is `replayed: true`, HTTP 201 (initial ingest) is
    `replayed: false`, so status and body cannot disagree about whether state was
    written.
- `x-backend-obligations`: a governance-declared extension enumerating the invariants a
  contract requires but JSON Schema cannot enforce (tenant ownership, funnel order,
  proposer ≠ verifier, immutable/idempotent persistence, meter reconciliation, and the
  cross-field checks below). Declaring an obligation documents a gap; it is not evidence
  the gap is closed.
- Closed rejection reasons naming the cross-field and cross-record checks Draft-07
  cannot make, so an emitter is told which bug it has rather than a generic
  `schema_violation`: `duplicate_characterization_field` (`uniqueItems` compares whole
  objects, so one field reported twice with differing metadata passes),
  `interval_bounds_inconsistent` (`lower <= estimate <= upper` cannot be expressed, and
  the economics model leads with the lower bound), `support_counts_inconsistent`
  (`n_paired <= n_examples`), `withheld_field_value_present`, and
  `winner_receipt_reconciliation_failed` (a winner receipt's cost, paired delta, selected
  config, immutable run identity, and promotion evidence cannot be cross-record reconciled
  against the stored run in Draft-07).
- **`ShortLabel` is an opaque identifier grammar, not free-form text.** The shared
  `ShortLabel` type (consumed by `model_id`, the emitting-surface name, `evaluator_version`,
  `objective`, the metric name, and the policy-version fields) previously accepted any
  1–128 character string, so sensitive prose or PII could egress through those fields
  despite the "not free-form" prose. It now carries an identifier pattern: ASCII letters and
  digits, with `.` `_` `:` `/` `+` `-` allowed only between alphanumerics, and a portable
  end-of-input anchor (so a trailing newline cannot slip through Python's `$`). This admits
  real identifiers (`gpt-4o-mini`, `anthropic/claude-3.5`, `accuracy_v2`, `1.0.0`) and
  rejects content-shaped values such as `Alice Smith SSN 123-45-6789`, whitespace, control
  characters, quotes, and email text. The length bounds are unchanged.
- **`WINNER RECEIPT RECONCILIATION` backend obligation.** A winner receipt is structurally
  self-consistent but its `actual_cost_usd`, `paired_delta`, `selected_config_hash`,
  immutable run identity, and promotion evidence are only claims until reconciled, as a set,
  against the immutable stored run, the authoritative cost meter, the selected/measured
  config, the recorded baseline/candidate effect, and the recorded promotion evidence.
  JSON Schema validates one payload in isolation and has no stored run to compare against, so
  a structurally valid but contradictory winner receipt is contract-valid and must be
  rejected at the backend boundary (`winner_receipt_reconciliation_failed`). Declaring the
  obligation documents the gap; it does not close it.

## [4.9.0] - 2026-07-16

### Changed
- **Request-contract tightening (annotation queues):** `items` on
  `POST /api/v1beta/annotation-queues/{queue_id}/items` and the inline `scores`
  array on `POST /api/v1beta/annotation-queues/items/{item_id}/complete` now
  declare `maxItems: 1000`. Companion to TraigentBackend#2184 (DoS list caps,
  #2177/#2178): the backend rejects larger lists (422), so the published
  contract now says so. Requests within the cap are unaffected. The value
  mirrors the established `MAX_EXAMPLES_BATCH = 1000` batch limit.

## [4.8.0] - 2026-07-12

### Added
- A content-free `session_aggregation` contract on session finalization requests, with
  a response echo only when the server persisted the aggregation. Metric, objective,
  configuration-hash, selection, version, and significance labels are bounded, and
  unknown nested content is rejected outside the documented `best_weighted_config`
  configuration-value dataflow exception (which can include a tuned prompt value and
  is omitted in privacy mode).
- Optional `guidance_meta` provenance on analytics next-steps responses, identifying
  the served rules/policy variant, engine, policy-table revision, SmartOps version,
  and fallback reason.
- Authoritative lifecycle guidance contracts: one top-level decision, empty legacy
  `next_steps` in the feature lane, and experiment-run/decision-scoped execution receipt
  request and response schemas with allowlisted outcomes.
- Project-scoped observability intelligence contracts for trace/session/user reads,
  content-free trace analysis and projection, execution lineage, recurring issues and
  their human disposition, exact structural variants, tool analysis, and cohort
  comparison. Trace ingestion can bind execution context, while derived results carry
  bounded structural fingerprints and derivation provenance.
- A strict, content-free observability analysis-insights response and endpoint for
  structural conformance findings and deterministic recommendations with bounded
  measurement plans.
- Authenticated, project-scoped SmartOps Planner V2 decision, receipt,
  lifecycle-reopen, private decision-resolution, service-only shadow evaluation,
  artifact-revision registration/consumption, and authoritative producer-result
  contracts.
- Planner V1 routes and schemas remain unchanged.

### Changed
- Evaluator-registry aliases used by authoritative guidance are bounded and mutually
  exclusive, and parity metadata is refreshed for the full 4.8.0 schema surface.
- Planner V2 now distinguishes certified session-utility advantage from product KPI
  claims, describes rule parity as the absence of an applicable exact certificate,
  and exposes truthful closed fallback categories.
- Shadow and private execution contracts now bind exact Planner V2 actions,
  economics, implementation pins, receipts, producer lineage, revision fingerprints,
  successor runs, and certificate support semantics. Exact certified shadows preserve
  an honest unknown `advantage_ucb` when the signed certificate supplies no upper bound.

## [4.7.1] - 2026-06-29

### Changed
- Documented report payload configuration identity fields on
  `results/report_payload_response_schema.json`: aggregate rows now expose the
  redacted `config_label`, `config_hash`, and `config_params` identity surface, while
  raw example rows expose `config_label` and `config_hash` only. The contract also
  documents the report insight rows used for example anti-correlation and high-variance
  review flags.

## [4.7.0] - 2026-06-23

### Added
- Terminal-first run-analytics v0 contracts under `traigent_schema/schemas/analytics/`,
  the canonical shapes the backend computes, the `traigent-analytics-mcp` returns, and the
  Claude Code analytics skill / both SDKs code against (moving optimization-results analysis
  out of the web portal into the terminal):
  - `decision_payload_schema.json` — KEYSTONE decision-oriented run summary
    (`intent`, `headline`, `confidence`, `recommended_action`, `evidence`, `drilldowns`,
    `warnings`).
  - `run_pareto_schema.json` — cost/quality/latency Pareto frontier, knee, dominated set,
    and coarse frontier `shape`.
  - `run_correlations_schema.json` — measure-to-measure and parameter-to-measure
    correlations with coarse strength/confidence buckets.
  - `run_leaderboard_schema.json` — objective-ranked configurations with composite score,
    risk flags, and a winner/candidate/reject recommendation.
  - `run_parameter_insights_schema.json` — ranked parameter drivers (with confidence
    intervals and expand/freeze/narrow actions) and parameter interactions.
  - `run_example_insights_schema.json` — PRIVACY-BOUNDED example-level cohorts and dataset
    recommendations; carries no raw proprietary signals or prompt text by default and
    declares its `redactions`.
    Extends the contract with privacy-bounded quality posture prose, notable example rows,
    suspicious/difficulty review labels, and coarse summary counts without exposing raw scores.
  - `privacy_mode_schema.json` — shared `PrivacyMode` enum primitive
    (`safe_agent_projection` default, owner-gated `elevated`) reused by
    `run_example_insights`.
- Wired six `GET /api/v1/analytics/runs/{run_id}/...` operations into
  `analytics/analytics_endpoints.json` binding each response to its new contract.
- `tests/test_terminal_analytics_contracts.py` — happy-path fixtures plus enum / required /
  closed-object / privacy / canonical-id (`ForeignKeyId`) constraint coverage, with
  fixtures under `tests/test_data/analytics/`.
- These contracts reuse the canonical `common_types_schema.json#/definitions/ForeignKeyId`
  for `run_id` / `project_id` / `config_id`, so SDK-generated `trial_<hex>` ids validate.
  Downstream BE Pydantic models, Python SDK DTOs, and FE/JS TS types regenerate in
  merge-blocking follow-up PRs.

## [4.6.4] - 2026-06-18

### Added
- `traigent_schema/schemas/auth/auth_user_identity_schema.json` — shared canonical user
  identity sub-type pinning the minimum required fields (`id`, `email`) while permitting
  additional claims. Referenced by login / token-refresh / SSO-callback / register response
  `user` fields. Closes the zero-pinned-fields gap (#178).
- `traigent_schema/schemas/auth/register_response_schema.json` — 200 body for
  `POST /api/v1/auth/register` (`{success, message, user, requires_email_verification,
  email_sent}`). Closes the missing register response schema gap (#178).
- Wired `register_response_schema.json` into `auth/auth_endpoints.json`
  `POST /api/v1/auth/register` 200 response content (#178).
- 22 new contract tests in `tests/test_auth_onboarding_identity_contracts.py` covering
  register response shape, auth user identity sub-type, pinned user fields across
  login/refresh/SSO, auth_me required fields, and provisioned_workspace removal (#178).

### Changed
- `auth/login_response_schema.json` `data.user` — changed from
  `{type: ["object","null"], additionalProperties: true}` to
  `{$ref: auth_user_identity_schema.json}` which requires `id` + `email` when non-null (#178).
- `auth/token_refresh_response_schema.json` `data.user` — same pinning change (#178).
- `auth/sso_oidc_callback_response_schema.json` `data.user` — same pinning change (#178).
- `auth/auth_me_response_schema.json` `data` — added `required: ["id", "email"]`; the
  properties were already documented but not enforced (#178).

### Removed
- `traigent_schema/schemas/auth/provisioned_workspace_schema.json` — deleted as an orphan
  (no endpoint `$ref`, no FE usage). Its `default_project_id` field conflicts with
  `device_token_success_schema.json`'s `project_id` (the reference implementation for
  workspace provisioning data). Removed the 2 test cases that validated it and updated the
  device-flow schema discovery assertion (#178).

## [4.6.3] - 2026-06-18

### Added
- `GET /api/v1/experiments` 200 response schema in `execution/execution_endpoints.json`:
  paginated envelope `{success, message, data: {items: [experiment_schema], pagination}}`.
  Finishes the list-response coverage residual left by #128/#162 (#169).

### Fixed
- Added `maxItems`/`maxProperties` bounds to eval-domain result/embed arrays that
  were missing the bounding pattern already applied in `configuration_run.measures`
  and observability ingest (#130). Closes #171.
  - `evaluation/experiment_run_schema.json`: `results.metrics` → `maxProperties: 50`;
    `results.artifacts[]` → `maxItems: 1000`; `results.logs[]` → `maxItems: 1000`.
  - `evaluation/evaluation_results_schema.json`: `aggregate_metrics` / `detailed_metrics`
    / `comparative_analysis.improvement_percentages` / `comparative_analysis.significance_tests`
    → `maxProperties: 50`; `artifacts[]` → `maxItems: 1000`.
  - `datasets/dataset_schema.json`: `examples[]` → `maxItems: 10000`; `files[]` → `maxItems: 1000`.

### Deprecated
- `eval_dataset_id`, `evaluation_set_id` scalar-id aliases in `experiment_schema.json`,
  `generator_config_schema.json`, and `evaluator_config_schema.json` marked `x-deprecated`
  (canonical: `dataset_id`). Annotation-only; no fields removed (#169).
- `eval_dataset`, `evaluation_set` object aliases in `experiment_schema.json` marked
  `x-deprecated` (canonical: `dataset`). Annotation-only; no fields removed (#169).
- `agent` and `model_parameters` heavy-object fields in `experiment_schema.json`
  documented as hydrated-detail-only forms; canonical reference fields are `agent_id`
  and `model_parameters_id` (#169).

### Added
- 2xx response schemas for run-results read surfaces and comparison/report read GETs
  (TraigentSchema#170 — the residual from #128/#162):
  - `evaluation/experiment_run_list_response_schema.json` — `GET
    /api/v1/experiment-runs/{experiment_id}/runs` (bare `{runs:[...]}`, no envelope).
  - `execution/run_results_response_schema.json` — `GET
    /api/v1/experiment-runs/runs/{run_id}/results` (bare paginated payload via
    `_bound_run_results_payload`; over-materialization tracked in
    TraigentBackend#1106).
  - `results/comparison_response_schema.json` — `GET
    /api/v1/optimization-comparisons/{comparison_id}` (success-envelope-wrapped).
  - `results/comparison_examples_list_response_schema.json` — `GET
    /api/v1/optimization-comparisons/{comparison_id}/examples` (offset-paginated,
    wrapped).
  - `results/comparison_example_detail_response_schema.json` — `GET
    /api/v1/optimization-comparisons/{comparison_id}/examples/{example_id}` (wrapped).
  - `results/report_payload_response_schema.json` — `GET
    /api/v1/experiment-runs/runs/{run_id}/report-payload` (bare jsonify).
  - `results/report_module_status_response_schema.json` — `GET
    /api/v1/features/report-module-status` (bare jsonify; state ∈ {off, beta, ga}).
- Extended `tests/test_success_envelope_and_response_coverage.py` with 8 new tests
  asserting 100% schema coverage on the newly contracted surfaces.

## [4.6.2] - 2026-06-18

### Deprecated
- `configuration_run_id` in `execution/metric_submission_schema.json` and
  `projects/project_scoped_fine_tuning_manifest_schema.json` marked `x-deprecated`.
  The canonical name going forward is `trial_id`. This is an annotation-only
  pass — no fields removed, no wire format changed (Wave 4, step 1 of N).

## [Unreleased]

### Added
- **Agent tuning-history browse surface (experiment groups, Wave A).** Additive
  read-only enrichment of `execution/experiment_group_schema.json` and the
  `execution/execution_endpoints.json` experiment-group routes: complete browse
  rows (measures/summary-stats/error-state/provenance), a page-independent
  full-group column manifest, cursor pagination alongside legacy `page`/`per_page`,
  a `dataset_scope` (default `all`) group filter, and a read-only
  `POST /api/v1/experiment-groups/{group_id}/configuration-runs/query` surface.
  Group identity stays exactly visibility-scoped `agent_id` + canonical
  `dataset_id`; no cross-setup ranking or Wave B comparison signatures are added.
  Contract invariants are now enforced structurally rather than only described in
  prose:
  - `CursorPage` couples the fields — `has_more: true` requires a non-null opaque
    `next_cursor` and `has_more: false` requires `next_cursor: null`; the group-list
    and configuration-run-list payloads accept exactly one of `pagination` or
    `cursor` (never both, never neither).
  - The full-group column manifest has no `truncated` escape hatch (a partial
    manifest can no longer claim completeness), and each namespace array accepts
    only descriptors of its own `kind`.
  - Column predicates are exclusive by operator: scalar operators require a scalar
    operand, `in`/`not_in` require a bounded non-empty scalar array, and
    `is_null`/`is_not_null` forbid a value.
  - Group read/query routes expose canonical **redacted** error envelopes; a hidden
    group and a non-existent one are the single indistinguishable `404` (no `403`),
    so forbidden-vs-not-found never leaks.
  - `GroupedConfigurationRunProvenance` no longer duplicates the source-execution
    ids (Draft 7 cannot assert sibling equality); those ids stay canonical at the
    browse-row top level and provenance carries only group/display context.
    Runtime one-row-per-execution and exact scope/agent/dataset partitioning remain
    downstream backend/E2E acceptance criteria, not proven by this schema.
  - Group-list deterministic tie-break (unreleased correction): the group-list
    tie-breaker is the group's canonical visible identity — `agent_id` ascending
    with nulls ordered last, then canonical `dataset_id` ascending with nulls
    ordered first (the explicit no-dataset group sorts before any concrete dataset
    id within an identified agent), then `run_id` ascending with nulls ordered first
    — applied after the
    requested primary sort and fixed independent of the primary field, its
    direction, and `dataset_id` nullness. This replaces the earlier `group_id`
    ascending tie-break: `group_id` is a non-reversible SHA-derived lookup token
    that cannot be portably range-bounded, so it cannot back exact SQL-bounded
    cursor pagination, whereas `(agent_id, canonical dataset_id, run_id)` is the exact
    group identity, is fully range-orderable, and yields the same deterministic
    total order. Portable `CASE` null-rank terms before each value make this order
    independent of database-default null ordering. The `agent_id` nulls-last term,
    not `run_id` nulls-first, places identified cohorts before unidentified
    singletons. The tie-break has no user-facing semantic value; deterministic,
    exact, visible-identity order does. The configuration-run row tie-break
    (`configuration_run_id` ascending) is unchanged. The `GET /api/v1/experiment-groups`
    inline `sort_by` parameter description in `execution/execution_endpoints.json` now
    mirrors this authoritative `ExperimentGroupSortField` language byte-for-byte, so the
    endpoint copy can no longer contradict the field (it previously still read
    "group_id ascending").
  - Redacted error envelope (same Wave A surface): a strict
    `ExperimentGroupErrorEnvelope` subtype now backs every experiment-group
    `400`/`401`/`404`/`500` (rather than the generic envelope directly). It stays
    shape-compatible with the canonical envelope but forbids `details` structurally
    and closes every public string field to a finite, fixed server-controlled enum —
    `message` (display strings), `error`, and `error_code` are all enums — so no raw
    query/group/SQL/secret value, and not even a benign-looking opaque token such as a
    lowercase group id (`grp_...`), can validate in any public field. (An earlier draft
    bounded `message` by a display-safe character set and `error_code` by a lowercase
    token grammar, which still admitted such opaque tokens; the finite enums close that
    gap.) `GET /experiment-groups/{group_id}` gained its previously-missing malformed-id
    `400`, so every constrained-`group_id` route now has a safe malformed-id response.
  - Legacy `page`/`per_page` mode and `cursor`/`limit` mode are made exhaustive and
    mutually exclusive through the repository's established `x-excludes` extension on
    each pagination parameter; every cross-mix (cursor+page, cursor+per_page,
    limit+page, limit+per_page) is rejected, and omitting all four defaults to legacy
    page mode.
  - Predicate operands exclude `null` for both scalar and `in`/`not_in` set operators
    (absent-or-null matching is reserved for `is_null`/`is_not_null`); set operands
    are non-empty, bounded, and unique. String operands and every string set member
    have a shared `maxLength: 255` cap, aligned with Backend request validation.
  - `GroupedConfigurationRunErrorState` couples `has_error: false` with
    `error_code: null`; a classified code without a failure is rejected.
  - Manifest namespace arrays are `uniqueItems` (exact-duplicate descriptors
    rejected). Rejecting same-`(kind, key)` duplicates that disagree on metadata is
    recorded as a backend acceptance criterion, since Draft 7 cannot express
    uniqueness by a subproperty.
- **Experiment-group outage contract:** all four experiment-group browse/query
  operations now document the fail-closed authentication-backend `503` response.
  A dedicated strict envelope admits only the two fixed, redacted middleware
  representations of `AUTH_BACKEND_UNAVAILABLE`; it rejects diagnostic details,
  request-derived content, and additional properties. Existing `400`, `401`,
  `404`, and `500` response contracts are unchanged.
- `optimization/optimization_plan_request_schema.json` and
  `optimization/optimization_plan_response_schema.json` for
  `POST /api/v1/optimization/plan`, plus a dedicated
  `optimization/optimization_plan_endpoints.json` module wired into both
  backend and SDK tuning contract roots. The response contract is allowlist-only
  for safe plan labels, model ids, knob value lists, command templates, coarse
  evidence, and caveats.

### Changed
- Tightened response-DTO email fields to match the canonical request-side constraint:
  `auth/auth_me_response_schema.json` `data.email` and
  `costs/cost_user_usage_response_schema.json` `data.email` now declare `format: email`
  and `maxLength: 320` (the canonical cap already used by the request schemas and the
  `project_member_candidate` response). Additive backwards-tightening — the backend
  already emits real, bounded emails, so no realistic breakage (#223).
- **BREAKING (status vocabulary): aligned run/config status enums to the canonical
  UPPER backend vocabulary** (#172, #173). The whole producer ecosystem (backend
  model + native Postgres enum + REST wire + SDK write path) emits UPPER; the schema
  enums were the lone lowercase outliers and several carried the wrong member set.
  - `status_schema.json#/definitions/ExperimentRunStatus`: now the 9 canonical
    UPPER members `{NOT_STARTED, PENDING, PAUSED, RUNNING, FAILED, COMPLETED,
    CANCELLED, UNKNOWN, PARTIALLY_DELETED}` (adds the previously missing `PENDING`
    and `UNKNOWN`). Matches backend `src/models/status_enums.py:ExperimentRunStatus`
    (native PG type `experimentrunstatus`). Referenced by `experiment_run_schema`,
    `experiment_schema`, `experiment_create_request_schema`, and the status PUT in
    `execution/execution_endpoints.json`.
  - `status_schema.json#/definitions/ConfigurationRunStatus`: now the 7 canonical
    UPPER members `{NOT_STARTED, RUNNING, COMPLETED, FAILED, UNKNOWN, CANCELLED,
    PRUNED}`. Drops the mis-assigned ExperimentRun-only members
    (`paused`/`pending`/`partially_deleted`) and adds `UNKNOWN`. Matches backend
    `src/models/status_enums.py:ConfigurationRunStatus`.
  - `agents/agent_response_schema.json`: removed the inline duplicate
    `AgentExecutionStatus` definition (a silent-drift fork) and repointed the
    `status` binding to the central
    `../status_schema.json#/definitions/AgentExecutionStatus` (member set unchanged:
    `{success, failed, cancelled, timeout}`).

### Added
- Contract-documentation completeness (schema as single source of truth):
  - `measures/timing_metric_vocabulary_schema.json` — advisory canonical/legacy
    timing-metric vocabulary with units and alias->canonical mapping, so SDK/BE/FE
    stop minting timing names independently (#118). Non-constraining
    `x-timing-metric-vocabulary` pointer added to `metric_submission_schema`.
  - `optimization/session_next_trial_response_schema.json` — the previously
    undocumented 200 response of `POST /sessions/{id}/next-trial`, now referenced
    from `optimization_endpoints.json` (#145).
  - `auth/rbac_privilege_vocabulary_schema.json` — documents the admin/member
    privilege roles and the three admin-only scoping relaxations (owner filter,
    canonical-tenant pin / `X-Tenant-Id` override, project-membership gate) (#144).

## [4.6.1] - 2026-06-18

### Deprecated
- `benchmark_id` field in `evaluator_config_schema.json` — use `dataset_id` instead; annotated with `x-deprecated`.
- `benchmark_id` field in `generator_config_schema.json` — use `dataset_id` instead; annotated with `x-deprecated`.
- `benchmark_id` field in `experiment_schema.json` — use `dataset_id` instead; annotated with `x-deprecated`.
- `benchmark` field in `experiment_schema.json` — use `dataset` instead; annotated with `x-deprecated`.

All fields remain present (non-breaking); removal planned after 2026-Q4.

## [4.6.0] - 2026-06-14

### Added
- Two-dimensional optimization metering + differentiated quota enforcement
  contracts (unified quota/wallet cost model, v1):
  - `billing/quota_exceeded_error_schema.json` gains optional `action`,
    `reserved_usage`, and `enforcement_behavior` (`block`/`drop`/`sample`).
    Wallet/cost ceilings remain reported only via the wallet error contract,
    never folded into the quota error. Backward compatible — the prior minimal
    shape still validates.
  - `billing/billing_limits_schema.json` gains optional `optimization_trials`
    and `optimization_samples`; a new optimization run is admitted only when
    BOTH have headroom. `trials` retained as a deprecated alias during
    migration.
  - New read-only `billing/usage_summary_response_schema.json` (per-resource
    used/reserved/limit/reset/behavior + plan tier + enforcement mode) and
    `billing/quota_preflight_request_schema.json` /
    `billing/quota_preflight_response_schema.json` (admission preflight that
    lists ALL blockers — quota and wallet — so clients can distinguish
    "upgrade" from "top up"). These endpoints are never blocked by a cap.
- Optional `splits` object on `datasets/evaluation_set_schema.json`
  (TraigentSchema#126): split policy (`explicit`/`hash` strategy, seed,
  `locked_test`) plus per-example `train`/`selection`/`test` assignments.
  Contract discipline carried in descriptions: the selection split gates
  candidate acceptance; the test split is locked until run finalization.
  Backward compatible — instances without `splits` validate unchanged.
  Referential integrity of assignment keys is backend-enforced.
- Canonical API-key authorization vocabulary (TraigentSchema#107): new
  `auth/api_key_authorization_vocabulary_schema.json` pins API-key scope tokens,
  canonical permission tokens, and the scope-to-permission map that preserves the
  current colon scope / dot permission split. Device authorization `scope`, audit
  log `permission`, project membership `permission_required`, and
  `x-required-permission` annotations now reference the shared vocabulary metadata
  without changing backend/frontend runtime behavior. Device authorization uses
  the user-requestable scope subset so privileged `admin:all` remains vocabulary
  metadata only and is not valid in public device-flow scope requests.
- **Certified selection over the wire** (Phase 8, contract-decision REVISION 2,
  ChangeSession `cs_3122014091d19761`): new `certified_selection_schema.json`
  (`CertifiedSelectionReport`) — a CLIENT-ATTESTED, content-free report the SDK
  may attach to session finalize when strict evidence mode certified a winner
  locally: backend `trial_id` binding (the server returns the winner from ITS
  OWN trial record — client configs never cross at finalize), per-CVAR
  certificate decisions (shared `CERTIFIED_SELECTION | NO_DECISION |
  BEST_EFFORT_UNCERTIFIED` vocabulary), and the certificate's issued
  (freshness-context) sha256. Deliberately excluded (P8): calibrated values,
  `subject_value_hash` (dictionary-invertible on low-entropy values), evidence
  counts, pool hashes, target details. `optimization_endpoints.json` finalize
  requestBody gains the optional `certified_selection` `$ref` (top-level key;
  the finalize envelope stays open for legacy back-compat, so the SERVER
  additionally rejects reports tunneled under metadata).
  `session_finalize_response_schema.json` gains `selection_basis`
  (`certified_selection | objective_best`) and the content-free
  `selection_attestation {type: client_attested, attested_by, sdk_version}`,
  with the invariants ENFORCED as schema conditionals: basis ⊕ reason_code,
  basis ⇒ non-empty winner, reason_code ⇒ empty `best_config`, attestation ⇔
  certified basis — consumers key off `selection_basis` and must display
  certified winners as client-attested, never server-verified. Version 4.5.0.
- **TVL 1.1 governance crosses the wire** (Phase 7, contract-decision REVISION 1,
  ChangeSession `cs_ca64fcc251f489b1`): `promotion_policy_schema.json` gains the
  closed-shape `require_calibration {enabled, hash_covered_context}` strict
  evidence mode (field semantics mirror `tvl/spec/grammar/tvl.schema.json` —
  same required/enum members, plus `uniqueItems` wire hardening; the SDKs already
  serialize it — the backend rejected/dropped it until now).
  `optimization_endpoints.json` session-create now BINDS `promotion_policy` to the
  promotion-policy schema (was an unconstrained object), and the finalize 200
  gains `session_finalize_response_schema.json`: fail-closed contract — strict
  sessions without certified selection evidence return empty `best_config` +
  `reason_code: NO_CERTIFIED_SELECTION`, never a raw best. New
  `tvl_governance_schema.json` (`TvlGovernanceDTO`): content-free governance
  summary (cvar names/types/governed flags, per-CVAR certificate decisions using
  the shared `CERTIFIED_SELECTION | NO_DECISION | BEST_EFFORT_UNCERTIFIED`
  vocabulary, policy names/strategies) — P8: never values, evidence, or prompts;
  backends construct it from an allowlist, never caller-metadata passthrough.
- Planner draft-status contract (TraigentSchema#57): `planner/planner_endpoints.json`
  wires `GET /api/v1/planner/status/{draft_id}` (registered in `mep_endpoints.json`
  `x-endpoint-modules` as "Planner"), with `200` → new
  `planner/planner_status_response_schema.json` and `404` → `ErrorEnvelopeDTO`. The
  200 is the `{success, message, data}` envelope wrapping the live status object
  (`status`, `progress`, `message`, `generatedParts` camelCase, optional
  `timestamp`) — **distinct** from `planner_draft_schema.json`. Initial status is
  `created` (BE#658); missing/deleted drafts are a **404** (BE#659), not a 200 with
  a `not_found` status, so `not_found` is intentionally absent from the enum.
- `rate_limit_info_schema.json` (`RateLimitInfoDTO`) — the canonical 429 (Too Many
  Requests) response body standardized in BE#670 (TraigentSchema#60). Composes
  `error_envelope_schema.json` (Shape A) and constrains `error_code` to
  `RATE_LIMIT_EXCEEDED` with a `details` block (`scope`, `retry_after`, optional
  `limit` / `reset_time`). The accompanying response headers — `Retry-After`
  (always) and `X-RateLimit-Limit` / `-Remaining` / `-Reset` (when the limiter
  includes headers) — are documented via an `x-response-headers` extension so
  consumers can derive retry/backoff behavior from the contract (prerequisite for
  FE#870). Per-endpoint `responses["429"]` wiring is a follow-up as consumers opt in.
- Auth response contracts (TraigentSchema#58, #62), replacing the `default`
  "Response shape pending" placeholders in `auth/auth_endpoints.json`:
  `auth/login_response_schema.json` (`LoginResponseDTO`) and
  `auth/token_refresh_response_schema.json` (`TokenRefreshResponseDTO`) model the
  `{success, message, data:{access_token, refresh_token, user?, …}}` envelope the
  backend emits and the Python SDK consumes. **Session expiry is the
  `X-Session-Expires-At` response header, not a body field** (documented on both
  routes; `expires_at` lives only on `GET /auth/me`) — the schemas reject an
  expiry field in the body to prevent drift. `auth/csrf_token_response_schema.json`
  (`CSRFTokenResponseDTO`) + a new `GET /api/v1/auth/csrf-token` path document the
  cookie-mode CSRF flow (`traigent_csrf_token` cookie ↔ `X-CSRF-Token` header),
  with 401/403 composing `ErrorEnvelopeDTO`.
- `error_envelope_schema.json` (`ErrorEnvelopeDTO`) — the canonical error response
  envelope (Shape A: `{success:false, message, error, error_code?, details?}`) decided in
  BE#669 and already consumed by FE `errorUtils.ts`. Strict (`additionalProperties:false`)
  so raw internals / user-input echo cannot leak through an error body; `details` carries a
  documented redaction constraint. Resolves the canonical-envelope deliverable of
  TraigentSchema#59.
- `validation_error_schema.json` (`ValidationErrorDTO`) — composes `error_envelope_schema.json`
  via `allOf` and narrows `details` to a `{field: [reason, ...]}` map for 422 responses
  (aligned with BE#671).
- Note: migrating the four existing domain-specific error schemas (`quota_exceeded`,
  `wallet_insufficient_balance`, `project_context_error`, `project_member_lookup_error`) to
  *require* Shape A is intentionally deferred — today they validate as `{error_code, message, …}`
  with no `success`/`error`, matching current backend output. Forcing the envelope on them
  would assert a shape the backend does not yet emit; that migration is gated on the BE
  producer change (BE#669), which TraigentSchema#59 lists as out of scope.
- Field-level content/privacy annotations on the hybrid-path DTOs (TraigentSchema#78):
  content-bearing leaves now carry `x-content: true` + `x-privacy-classification:
  user_content` so redaction/governance tooling can enumerate user content from the
  contract — `trace`/`observation` `input_data`/`output_data`, `Example.input`/`output`,
  `EvaluationSetExample.input_text`/`expected_output`, and the metric-submission
  `ConfigurationParameters`. New `user_content` value documented in the README privacy
  vocabulary. Additive `x-` keywords; no type/required/validation change.
- `execution/workflow_trace_schema.json` — a real contract for `POST /api/v1/traces/ingest`
  (the Python-only LangGraph workflow-trace surface), replacing the inline opaque
  `{graph, spans}` body (TraigentSchema#64). Models the SDK producer
  `workflow_traces.py` field-for-field: `WorkflowGraph` (nodes / edges / loops topology)
  and a `SpanBatch` wrapper of `SpanPayload` (incl. LangGraph `node_id`, `decision_reason`,
  `span_type`). `span_type` / `status` are free strings with documented canonical values
  (the SDK sources them from OTel attributes), not enum-locked. Carries an explicit
  `$comment` that it is **distinct** from `observability/trace_schema.json` (v1beta OTel
  surface, backed by a different DB model). `execution_endpoints.json` now `$ref`s it.

### Changed
- Refreshed the Python/JavaScript parity manifest for the Python 0.12.0
  release line and classified advisory strategy-preset / recommendation helper
  exports as deferred from the JS 0.2.0 parity surface.
- Documented `metadata` on `trace_schema.json` and `observation_schema.json` as
  **opaque user-supplied data only** (TraigentSchema#63), with a root `$comment`
  recording the backend persistence mapping. `correlation_ids` / `prompt_reference`
  remain the dedicated top-level fields; no structural or breaking change.

## [4.3.0] - 2026-05-31

### Changed
- **Dual-licensed** under `AGPL-3.0-only OR LicenseRef-Traigent-Commercial`: the project is now
  offered under the GNU AGPL-3.0-only **or** a Traigent commercial license. Added an SPDX
  `License-Expression` (PEP 639 metadata via `hatchling>=1.27.0`), per-module SPDX headers, and
  `COMMERCIAL-LICENSE.md`, `LICENSING.md`, `CONTRIBUTING.md`, `CLA.md`; updated `NOTICE` and
  `README`. Dropped the deprecated AGPL trove classifier in favor of the SPDX expression.

### Added
- `audit/security_incidents_response_schema.json` pinning the response shape
  for `GET /api/v1/audit/security/incidents` (and the SOC2 alias). Locks the
  backend's canonical `timestamp` / `severity` fields plus dashboard aliases
  `detected_at` / `threat_level`, so backend/frontend field drift is caught by
  contract tests for TraigentSchema#35. `audit/audit_endpoints.json` now
  references the schema as the canonical `200` response for both routes.

## [4.2.0] - 2026-05-20

### Added
- `optimization/objective_schema.json` as the wire-format container for
  SDK-defined objective names, orientations, weights, and normalization defaults.
- Optional `objectives` fields on experiment and experiment-run schemas, plus
  `summary_stats`, `weighted_score`, and `multi_objective_analysis` support on
  configuration runs.
- Canonical backend endpoint modules for auth, audit, MFA, security events, and
  billing surfaces covering Paddle, subscriptions, spend controls, and wallet
  operations. These modules are registered from `mep_endpoints.json` so backend
  parity checks exercise the routes now present in TraigentBackend.

### Fixed
- Corrected stale sibling-directory `$ref` paths in agent, evaluation,
  configuration-run, experiment-run, and comparison schemas.
- Added `pruned` to `ConfigurationRunStatus` to reflect the SDK/backend trial
  submission contract.
- Corrected `workflow_metadata_schema.json`'s stale `3.0.0` version label to
  `3.1.0` and documented the `model_used` / `total_tokens` / flattened totals
  transition inline.

## [4.1.0] - 2026-05-09

### Added
- `multi_objective_semantics_schema.json` under `optimization/` codifies the
  normative behavioral contract for multi-objective normalization. Pins
  `zero_span_fallback = 0.5`, `zero_span_epsilon = 1e-9`,
  `weight_normalization = "sum_to_one"`, and `dominance_guard.max_normalized_weight = 0.99`
  with `validation_scope = ["sdk"]`. The document is a meta-contract: the
  constants are not wire-format fields, they describe behavior implementations
  must hard-code. Rolls out across Python SDK, traigent-js, TraigentBackend
  (recompute path), and TraigentFrontend.
- `objective_definition_schema.json` bumped to `0.9.1` with a description
  pointer to the new semantics doc; no field changes.
- `experiment_schema.json` bumped to `1.1.0` to expose list-stats fields:
  `configuration_runs_count`, `total_examples`, `optimization_runs_count`, and
  the `ExperimentListRunSummary` / `experiment_run` summary nested under
  `experiments[*]`. Consumed by the SDK list endpoint and the Frontend
  experiments table; no breaking changes to existing consumers.
- `parity/python-js-sdk.json` as the authoritative Python/JavaScript SDK
  parity manifest, including release-order and refresh-cadence policy.
- Manifest classifications for workflow-cost parity symbols used by the
  Python and JavaScript SDKs.
- CI coverage that validates Python root-symbol classifications and
  required JavaScript export coverage against the parity manifest.
- `planner/planner_draft_schema.json` for planner draft contracts.

### Changed
- Published the repository as the public source for `traigent-schema` contracts.
- Removed local-only agent instruction files and Sonar workspace configuration
  from version control, and ignored those local files going forward.
- Clarified that `planned_projects` is a pre-release contract surface that may
  change without a major-version bump until it graduates.

## [4.0.0] - 2026-03-28

### Changed
- Split endpoint catalogs into three explicit contract roots:
  - `mep_endpoints.json` is now the canonical current-backend contract
  - `sdk_tuning_endpoints.json` is the canonical direct-tuning contract for SDK session and hybrid flows
  - `planned_projects_endpoints.json` preserves the `/api/v1beta/projects/...` surface as planned/experimental
- `SchemaValidator` now accepts `contract="backend" | "sdk_tuning" | "planned_projects"`, while `get_openapi_path()` remains a backward-compatible alias for the backend contract root.
- Canonical backend endpoint modules now use explicit `/api/v1/...` paths and only reference current backend route families.

### Removed
- Planned project-scoped routes and legacy tunables/config-space routes are no longer part of the default backend contract.

### Fixed
- Request validation now supports inline OpenAPI request schemas in addition to `$ref`-based mappings, which keeps split contract files simpler without losing validator coverage.

## [3.2.2] - 2026-03-28

### Changed
- Relicensed open-source releases of `traigent-schema` to AGPL-3.0-only to align
  with the Traigent SDK release model.
- Added a release-oriented publish workflow with TestPyPI/PyPI verification.
- CI now validates build artifacts by building the wheel/sdist, running
  `twine check`, and importing the built wheel in a clean virtual environment.

### Fixed
- README release metadata now matches the package version and describes the
  repository as the shared contract source for backend, SDK, and frontend
  consumers.

## [3.2.1] - 2026-03-23

### Fixed
- `GET /api/v1/experiment-runs/runs/{run_id}/traces` no longer requires the legacy `trials` and `trials_pagination` fields alongside the standardized `trials_page` envelope.
- Added a stable `$id` to `pagination_schema.json` so registry-backed cross-file `$ref` resolution works for paginated response schemas.
- `SchemaValidator` now loads request mappings from endpoint modules declared in `mep_endpoints.json`, restoring request validation for modular contracts such as agents and optimization.
- Added the optimization endpoint module to the root `mep_endpoints.json` catalog for discoverability.

## [3.2.0] - 2026-03-05

### Added
- Shared pagination contract schema:
  - `pagination_schema.json`: canonical pagination metadata (`page`, `per_page`, `total`, `total_pages`, `has_next`, `has_prev`)
- New backend-aligned endpoint contracts in `execution_endpoints.json`:
  - `GET /api/v1/keys/accessible-resources`
  - `GET /api/v1/experiment-runs/runs/{run_id}/traces`
  - `GET /api/v1/traces/{trace_id}`

### Changed
- **BREAKING**: Standardized paginated list response envelope for target endpoint modules:
  - `agents/agents_endpoints.json`
  - `measures/measures_endpoints.json`
  - `execution/execution_endpoints.json`
  - `evaluation/evaluation_endpoints.json`
- **BREAKING**: List endpoints in those modules now model:
  - `success`, `message`, `data.items`, `data.pagination`
  - instead of legacy `data: []` and `count/total` top-level conventions.
- **BREAKING**: Query pagination parameters were aligned from legacy `limit/offset` to `page/per_page` in the updated list endpoints.

### Migration Guide (FE/SDK/Backend Consumers)
- Request update:
  - Replace `limit`/`offset` with `page`/`per_page`.
- Response parsing update:
  - **Before**: read list payload from `data` (array), and pagination-like totals from top-level fields.
  - **After**: read list payload from `data.items` and pagination metadata from `data.pagination`.
- Backward compatibility note:
  - Legacy list contracts are not modeled in this version for the updated endpoints.
  - Consumers should migrate parsing logic to the standardized paginated envelope.

## [3.1.0] - 2024-01-17

### Added
- **Analytics Schemas**: New schemas for example and dataset quality scoring
  - `example_score_schema.json`: Per-example quality scores (11 score fields)
  - `dataset_quality_schema.json`: Dataset-level metrics and recommendations
  - `scoring_job_status_schema.json`: Async scoring job status tracking
  - `analytics_endpoints.json`: OpenAPI spec for 4 new endpoints
- **AnalyticsValidator**: New validation utility class for analytics schemas
- Comprehensive test suite for analytics schemas (50+ test cases)

### Changed

- **BREAKING**: Nested Example Metrics Structure (`configuration_run_schema.json`):
  - `measures` array now uses `ExampleMetrics` structure instead of flat `MeasureResults`
  - New structure: `{"example_id": "ex_...", "metrics": {"score": 0.85, ...}}`
  - This prevents `example_id` from being stripped during numeric-only validation
  - Added `maxItems: 1000` constraint on measures array
- **Workflow Metadata Schema Enhancements** (`workflow_metadata_schema.json`):
  - `AgentCostBreakdown`: Added `agent_id` field (required), renamed `model` to `model_used`, added `total_tokens` field (required)
  - `WorkflowMetadata`: `workflow_name` is now required (was nullable), added `total_tokens`, `total_input_cost`, `total_output_cost` fields (all required)

### Added (Validators)

- `validate_example_metrics()` method in `AnalyticsValidator` for nested format validation
- Test suite for `ExampleMetrics` validation (15 test cases)

### Migration Guide (Nested Measures)

**Before (flat format - v3.0.x)**:

```json
{
  "measures": [
    {"example_id": "ex_abc123_0", "score": 0.85, "cost": 0.05}
  ]
}
```

**After (nested format - v3.1.0)**:

```json
{
  "measures": [
    {
      "example_id": "ex_abc123_0",
      "metrics": {"score": 0.85, "cost": 0.05}
    }
  ]
}
```

## [3.0.0] - 2024-01-15

### Added
- **Workflow Metadata**: New schema for multi-agent workflow cost tracking
  - `workflow_metadata_schema.json`: Tracks execution time, token usage, and costs per agent
  - `AgentCostBreakdown` definition for per-agent metrics
  - `WorkflowMetadata` definition for aggregate workflow metrics
- `workflow_metadata` field in `configuration_run_schema.json` for SDK integration

### Changed
- **BREAKING**: `MeasureResults` in `configuration_run_schema.json` now enforces:
  - Numeric values only (`["number", "null"]`) - string/boolean no longer accepted
  - Maximum 50 keys per result (`maxProperties: 50`)
- **BREAKING**: `MetricResults` in `metric_submission_schema.json` aligned with MeasureResults:
  - Numeric values only (`["number", "null"]`)
  - Maximum 50 keys per submission (`maxProperties: 50`)
  - Non-numeric values should be placed in `metadata` field instead

### Fixed
- Removed conflicting `$id` values from `configuration_run_schema.json` and `workflow_metadata_schema.json` to enable proper `$ref` resolution
- `workflow_metadata_schema.json` root type now correctly validates only `WorkflowMetadata` (not `AgentCostBreakdown`)

### Migration Guide

#### MeasureResults Contract Change
If your SDK or backend previously submitted string/boolean measure values:

**Before (v2.x)**:
```python
measures = {
    "accuracy": 0.95,
    "status": "passed",      # String - no longer valid
    "passed": True           # Boolean - no longer valid
}
```

**After (v3.x)**:
```python
measures = {
    "accuracy": 0.95,
    "pass_rate": 1.0         # Numeric representation
}
# Move non-numeric data to metadata
metadata = {
    "status": "passed",
    "details": {"passed": True}
}
```

#### Max Keys Limit
Ensure measure submissions have no more than 50 keys. If you need more:
1. Aggregate related measures
2. Use metadata for non-score information
3. Split into multiple submissions if necessary

## [2.x.x] - Previous Releases

See git history for changes prior to v3.0.0.
