# CLAUDE.md

This file provides guidance to Claude Code when working with the TraigentSchema repository.

## Project Overview

TraigentSchema is the centralized schema library for the Traigent AI optimization platform. It provides:

- JSON Schema definitions for all API contracts
- Python validation utilities
- Schema loading and discovery functions

## Project Structure

```
TraigentSchema/
├── traigent_schema/        # Main Python package
│   ├── __init__.py         # Package exports
│   ├── version.py          # Version management (1.0.0)
│   ├── validator.py        # SchemaValidator class
│   ├── utils.py            # Utility functions
│   └── schemas/            # All JSON schema files
│       ├── mep.json        # MEP root definition
│       ├── mep_endpoints.json  # OpenAPI specification
│       ├── status_schema.json
│       ├── agents/         # Agent-related schemas
│       ├── datasets/       # Dataset schemas
│       ├── evaluation/     # Evaluation schemas
│       ├── execution/      # Execution schemas
│       ├── measures/       # Measure schemas
│       └── results/        # Results schemas
├── tests/                  # Test suite
├── docs/                   # Documentation
├── pyproject.toml          # Package configuration (hatchling)
└── README.md               # User documentation
```

## Common Tasks

### Adding a New Schema

1. Create the schema JSON file in the appropriate subdirectory under `traigent_schema/schemas/`
2. Follow existing naming conventions (`*_schema.json`)
3. Include proper `$id`, `title`, and `description` fields
4. Add tests for the new schema in `tests/`
5. Update the OpenAPI spec (`mep_endpoints.json`) if adding new endpoints

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=traigent_schema --cov-report=term-missing

# Run specific test file
pytest tests/test_validator.py -v
```

### Building the Package

```bash
pip install build
python -m build
```

### Installing Locally for Development

```bash
pip install -e ".[dev]"
```

## Key Components

### SchemaValidator (`validator.py`)

The main validation class that:
- Loads all schemas on initialization
- Builds a jsonschema Registry for `$ref` resolution
- Parses OpenAPI spec for endpoint-to-schema mappings
- Provides `validate_request()` and `validate_json()` methods

### Utility Functions (`utils.py`)

- `get_schemas_dir()`: Returns path to schemas directory
- `get_schema_path(name)`: Finds a schema by name (searches subdirectories)
- `get_all_schema_files()`: Lists all JSON schema files
- `get_openapi_path()`: Returns path to `mep_endpoints.json`
- `load_schema(name)`: Loads and parses a schema as dict

## Integration Points

This package is used by:

- **TraigentBackend**: Schema validation middleware, model generation
- **TraigentOptimizer**: Configuration validation
- **Traigent SDK**: Optional DTO validation

## Schema Naming Conventions

- Schema files: `{name}_schema.json`
- Endpoint files: `{domain}_endpoints.json`
- Use snake_case for all file names
- Organize by domain in subdirectories (agents/, datasets/, etc.)

## Important Notes

- **Modern Packaging**: Uses `pyproject.toml` with hatchling (no setup.py)
- **Single Schema Directory**: All schemas under `traigent_schema/schemas/`
- **MEP Protocol**: Model Experiment Protocol naming is preserved (protocol name)
- **Python 3.8+**: Minimum supported Python version
