# Worker Report W2 - TraigentSchema Lifecycle Contracts

## Changes

- Added client-safe analytics response schemas:
  - `traigent_schema/schemas/analytics/next_steps_schema.json`
  - `traigent_schema/schemas/analytics/curation_advice_schema.json`
- Registered the new analytics GET response contracts in `analytics_endpoints.json`:
  - `/api/v1/analytics/experiments/{experiment_run_id}/next-steps`
  - `/api/v1/analytics/example-scoring/{experiment_run_id}/curation-advice`
- Added dataset instance versioning fields to `dataset_schema.json`:
  - optional `revision`, integer `minimum: 1`
  - optional `parent_dataset_id`, same string identifier style as `id`
- Added `traigent_schema/schemas/lifecycle/agent_playbook_schema.json` from the canonical brief, changing only the title envelope to repo style.
- Updated `AnalyticsValidator` to expose and validate `next_steps_schema` and `curation_advice_schema`.
- Added lifecycle contract tests in `tests/test_agent_lifecycle_schemas.py` and updated the analytics validator schema-list expectation.

## Local Commits

- `1b99509` - Add agent lifecycle schema contracts
- `feece96` - Test agent lifecycle schema contracts

## Verification

Baseline before changes:

```bash
PYTHONPATH=$PWD /tmp/venv-schema/bin/python -m pytest tests/ -q
```

Result: `607 passed, 2 warnings in 3.43s`.

Intermediate post-edit run:

```bash
PYTHONPATH=$PWD /tmp/venv-schema/bin/python -m pytest tests/ -q
```

Result: `1 failed, 630 passed, 2 warnings in 3.38s`.

Failure: `tests/test_analytics_validators.py::TestAnalyticsValidatorHelpers::test_available_schemas_lists_expected_contracts`, because the expected manual analytics schema list still omitted the two new analytics contracts. Fixed by updating the expectation.

Final full suite:

```bash
PYTHONPATH=$PWD /tmp/venv-schema/bin/python -m pytest tests/ -q
```

Result: `631 passed, 2 warnings in 3.45s`.

Diff whitespace check:

```bash
git diff --check
```

Result: exit 0, no output.

## Base-Suite Status

- Clean base status before edits: passing.
- Pre-existing failures: none observed.
- Final status after changes: passing.

## Deferred Items

- Backend, SDK, frontend implementation and live E2E are outside this W2 schema-contract packet.
- Release-readiness gate and witness approval are outside this local worker scope.

## Reviewer Risks

- `dataset_schema.json` was changed from a thin `allOf` alias into an explicit closed dataset object. This is necessary because `evaluation_set_schema.json` has `additionalProperties: false`, which prevents safely extending it with `revision` and `parent_dataset_id` through `allOf`.
- The canonical agent playbook artifact uses `playbook_version`, not `schema_version`. I did not add a `schema_version` payload field because the brief explicitly said not to change canonical property names or required sets.
- The leak guard is structural: it asserts forbidden proprietary signal names are not schema property names in the client-facing analytics contracts. It does not ban those words from explanatory prose.
