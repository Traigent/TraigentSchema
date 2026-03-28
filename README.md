# Traigent Schema Library

The official contract package for the Traigent AI optimization platform. This
repository is the shared source of truth for JSON Schema definitions, endpoint
mappings, and validation utilities used across the backend, SDK, and frontend.

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

# Validate API requests
validator = SchemaValidator()
errors = validator.validate_request('/api/v1/agents', 'POST', request_data)

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
- `example_set_schema.json` - Example set definitions
- `evaluation_set_schema.json` - Evaluation dataset specs
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

### SchemaValidator

```python
from traigent_schema import SchemaValidator

validator = SchemaValidator()

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
    get_openapi_path,     # Get path to OpenAPI spec
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

Current release line: **3.2.2**

Package metadata is derived from `traigent_schema/version.py` to keep runtime and published versions aligned.

## License

Open-source releases of this repository are licensed under the GNU Affero
General Public License v3.0 only. See [LICENSE](LICENSE) and [NOTICE](NOTICE)
for details.
