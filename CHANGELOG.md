# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.6.2] - 2026-06-18

### Deprecated
- `configuration_run_id` in `execution/metric_submission_schema.json` and
  `projects/project_scoped_fine_tuning_manifest_schema.json` marked `x-deprecated`.
  The canonical name going forward is `trial_id`. This is an annotation-only
  pass — no fields removed, no wire format changed (Wave 4, step 1 of N).

## [Unreleased]

### Changed
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
