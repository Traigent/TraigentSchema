# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
