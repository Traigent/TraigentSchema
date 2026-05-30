# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.0] - 2026-05-31

### Added
- Supported Hyperband as an Optuna-backed smart optimization strategy in the SDK tuning
  contract, including `algorithm: "hyperband"` and `algorithm: "optuna"` with
  `pruner: "hyperband"` plus Hyperband resource/pruning knobs.

### Changed
- Constrained Optuna pruner/resource fields in optimization strategy payloads so
  Hyperband-specific knobs are accepted only for backend-routed Hyperband strategies.

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
