# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
  signature + full-manifest client co-attestation shapes (issuer covers the co-attestation
  bytes when present; tier-1 claims require a co-attestation); minimal blinded
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
