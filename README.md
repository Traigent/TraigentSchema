# Traigent Schema Library

The official contract package for the Traigent AI optimization platform. This
repository is the shared source of truth for JSON Schema definitions, endpoint
mappings, and validation utilities used across the backend, SDK, and frontend.

> **Before you push:** run `make install-hooks` once per clone, then
> `make local-gate` before every push. The local gate mirrors the cloud CI
> gates (`ruff check`, `mypy`, the `pytest`/parity **structural** gates, the
> spine-trail reminder, and — for main-bound branches — SonarQube) so avoidable
> reds are caught in seconds instead of after a push. See
> [docs/LOCAL_CI_GATE.md](docs/LOCAL_CI_GATE.md).

## Installation

For published package consumers:

```bash
pip install traigent-schema
```

For coordinated workspace development or release validation from GitHub
(requires repository access):

```bash
pip install git+https://github.com/Traigent/TraigentSchema.git
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

```python
from traigent_schema import SchemaValidator, load_schema

# Validate current backend requests
backend_validator = SchemaValidator()
errors = backend_validator.validate_request('/api/v1/agents', 'POST', request_data)

# Validate SDK direct-tuning requests
tuning_validator = SchemaValidator(contract="sdk_tuning")
errors = tuning_validator.validate_request('/api/v1/sessions', 'POST', session_request)

# Validate planned project-scoped beta routes
planned_validator = SchemaValidator(contract="planned_projects")
errors = planned_validator.validate_request(
    '/api/v1beta/projects/proj_123/analytics/summary',
    'GET',
    {},
)

if errors:
    print(f"Validation errors: {errors}")
else:
    print("Request is valid!")

# Load a specific schema
agent_schema = load_schema('agent_schema')
```

## Available Schemas

The library includes schemas organized by domain:

### Agents (`schemas/agents/`)
- `agent_schema.json` - Core agent configuration
- `agent_types_schema.json` - Agent type definitions
- `agent_deployment_schema.json` - Deployment configurations
- `agent_response_schema.json` - Response format specs
- `model_schema.json` - Model definitions
- `model_parameters_schema.json` - Model parameter specs
- `retriever_schema.json` - Retrieval configurations

### Datasets (`schemas/datasets/`)
- `dataset_schema.json` - Canonical public dataset resource
- `evaluation_set_schema.json` - Legacy-compatible evaluation dataset schema
- `example_set_schema.json` - Example set definitions
- `generator_config_schema.json` - Data generator configs
- `evaluator_config_schema.json` - Evaluator configurations

### Evaluation (`schemas/evaluation/`)
- `experiment_schema.json` - Experiment definitions
- `experiment_run_schema.json` - Experiment run records
- `configuration_run_schema.json` - Configuration run data
- `evaluation_schema.json` - Evaluation specifications
- `evaluation_request_schema.json` - Evaluation requests
- `evaluation_results_schema.json` - Evaluation results

### Execution (`schemas/execution/`)
- `execution_mode_schema.json` - Execution mode settings
- `hybrid_session_schema.json` - Hybrid session configs
- `saas_execution_schema.json` - SaaS execution specs
- `dataset_storage_schema.json` - Dataset storage configs
- `metric_submission_schema.json` - Metric submission format

### Measures (`schemas/measures/`)
- `measure_schema.json` - Measure definitions
- `score_schema.json` - Score specifications

### Results (`schemas/results/`)
- `report_schema.json` - Report definitions
- `report_request_schema.json` - Report request format
- `comparison_schema.json` - Comparison specs
- `visualization_schema.json` - Visualization configs
- `visualization_request_schema.json` - Visualization requests

## API Reference

### Contract Catalogs

`traigent-schema` now ships three endpoint catalogs:

- `backend`: current `TraigentBackend` truth, loaded by default through `SchemaValidator()`
- `sdk_tuning`: direct-tuning session and hybrid routes used by SDK clients
- `planned_projects`: planned and beta project-scoped `/api/v1beta/projects/...` routes

Use `get_openapi_path()` when you want the canonical backend contract root, or
`get_contract_path(...)` when you need one of the non-default catalogs.

### Contract Stability

The `backend` and `sdk_tuning` catalogs are the supported contract roots for
released Traigent surfaces. The `planned_projects` catalog documents planned
and beta project-scoped routes for coordinated development. It is not a stable
public API contract, may change without a major-version bump, and may break
between minor releases until those routes graduate. Pin a specific
`traigent-schema` version if you build directly against this pre-release
surface.

### Schema Governance

TraigentSchema is the canonical source of truth for Traigent data contracts
across the Python SDK, backend, frontend, and JavaScript SDK parity checks.
When changing schemas, update the JSON Schema first, then update downstream
DTOs, backend models, generated frontend types, tests, and the changelog as
needed.

The shared MeasuresDict contract is enforced across projects:

- max 50 keys
- keys match the Python identifier pattern `^[a-zA-Z_][a-zA-Z0-9_]*$`
- values are numeric or null

#### Field-level privacy classification (`x-privacy-classification`)

Schemas may tag fields (or object groupings) with a machine-readable privacy
class so redaction, retention, and export tooling can reason **by contract**
instead of hard-coding field names. Allowed values:

| Value | Meaning |
|-------|---------|
| `user_content` | Raw user-supplied content / model output (prompts, inputs, outputs). The hybrid-path content fields use this — paired with `x-content: true` so a consumer can enumerate content-bearing leaves directly from the contract. |
| `aggregate_safe` | Aggregated / derived values safe to surface broadly. |
| `auth_sensitive` | Authentication and authorization payloads such as device-flow tokens, API keys, and SSO auth responses. |
| `billing_sensitive` | Billing / pricing data (e.g. wallet, checkout). |
| `tenant_admin_safe` | Visible to tenant admins only. |
| `manifest_safe` | Safe to include in exported manifests. |

Content-bearing fields on the hybrid DTOs carry `x-content: true` +
`x-privacy-classification: user_content`: `trace`/`observation`
`input_data`/`output_data`, `Example.input`/`output`,
`EvaluationSetExample.input_text`/`expected_output`, and the metric-submission
`ConfigurationParameters`. Adding these `x-` keywords is additive and ignored by
standard JSON-Schema validators.

### SchemaValidator

```python
from traigent_schema import SchemaValidator

validator = SchemaValidator()
sdk_validator = SchemaValidator(contract="sdk_tuning")
planned_validator = SchemaValidator(contract="planned_projects")

# Validate by endpoint
errors = validator.validate_request(endpoint, method, data)

# Validate by schema name
errors = validator.validate_json(data, 'agent_schema')

# List available schemas
print(validator.available_schemas)
```

### Utility Functions

```python
from traigent_schema import (
    get_schemas_dir,      # Get path to schemas directory
    get_schema_path,      # Get path to specific schema
    get_all_schema_files, # List all schema files
    get_openapi_path,     # Get path to canonical backend contract root
    get_contract_path,    # Get path to backend/sdk_tuning/planned_projects root
    load_schema,          # Load and parse a schema
)
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .

# Type checking
mypy traigent_schema
```

## Version

Current release line: **4.5.0**

Package metadata is derived from `traigent_schema/version.py` to keep runtime and published versions aligned.

## License

`traigent-schema` is **dual-licensed**: **AGPL-3.0-only** (see [LICENSE](LICENSE)) **OR** a
**Traigent commercial license** for use without AGPL copyleft (see
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)).
SPDX: `AGPL-3.0-only OR LicenseRef-Traigent-Commercial`.

Use it free under AGPL-3.0, or contact **legal@traigent.ai** for a commercial license.
See [LICENSING.md](LICENSING.md) for a short FAQ, [NOTICE](NOTICE) for third-party
attributions, and [CONTRIBUTING.md](CONTRIBUTING.md) (contributions require a [CLA](CLA.md)).
