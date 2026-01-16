# CLAUDE.md

This file provides guidance to Claude Code when working with the TraigentSchema repository.

## Project Overview

TraigentSchema is the centralized schema library for the Traigent AI optimization platform. It provides:

- JSON Schema definitions for all API contracts
- Python validation utilities
- Schema loading and discovery functions

## Claude Plans & IP Protection (CRITICAL)

**Implementation plans contain proprietary IP and MUST NOT be committed to version control.**

### Storage Location
- All Claude Code implementation plans are stored in `~/.claude/plans/` (user home directory)
- This directory is excluded by `.gitignore` (line 91: `.claude/`)
- **NEVER** create plan files inside the repository directory structure
- **NEVER** commit plan files or reference them in committed code

### Plan Security
- Plans are automatically written to `~/.claude/plans/` by Claude Code
- Verify the path starts with `/home/` or `~/` (outside repo)
- If accidentally created in repo, immediately move to `~/.claude/plans/`
- Plan names are auto-generated (e.g., `async-sprouting-summit.md`)

## Single Source of Truth: TraigentSchema (CRITICAL)

**TraigentSchema is the SINGLE SOURCE OF TRUTH for all data contracts across the Traigent ecosystem (SDK, Frontend, Backend).**

### Responsibilities

**This repository defines:**
1. ✅ **JSON Schemas** - All API request/response schemas
2. ✅ **Data Models** - Canonical structure for experiments, runs, configurations
3. ✅ **Validation Rules** - Constraints on fields (max keys, patterns, types)
4. ✅ **OpenAPI Spec** - Endpoint-to-schema mappings

**Other projects consume these schemas:**
- **Traigent SDK** - DTOs (`traigent/cloud/dtos.py`) implement these schemas
- **TraigentBackend** - Pydantic schemas mirror these definitions
- **TraigentFrontend** - TypeScript types generated from these schemas

### Schema → DTO → Model Flow

```
TraigentSchema (JSON Schema)
    ↓
Traigent SDK (Python DTOs)
    ↓
TraigentBackend (Pydantic + SQLAlchemy)
    ↓
TraigentFrontend (TypeScript Types)
```

### Critical Schema Contracts

**MeasuresDict Constraints** (enforced across all projects):
- **Max 50 keys** - Prevent unbounded memory usage
- **Python identifier keys** - Pattern: `^[a-zA-Z_][a-zA-Z0-9_]*$`
- **Numeric values only** - Types: int, float, None

**Example Schema** (`measures_schema.json`):
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "maxProperties": 50,
  "patternProperties": {
    "^[a-zA-Z_][a-zA-Z0-9_]*$": {
      "type": ["number", "null"]
    }
  },
  "additionalProperties": false
}
```

### Schema Evolution Guidelines

**When modifying schemas:**

1. ✅ **Check backward compatibility** - Can old clients still work?
2. ✅ **Update version** - Bump schema version in `version.py`
3. ✅ **Document breaking changes** - Note in CHANGELOG.md
4. ✅ **Update all projects**:
   - SDK: Update DTOs in `traigent/cloud/dtos.py`
   - Backend: Update Pydantic schemas in `src/schemas/`
   - Frontend: Regenerate TypeScript types

**Breaking Change Checklist:**
```bash
# 1. Update TraigentSchema
# Edit schema JSON files

# 2. Update Traigent SDK
cd ~/Traigent_enterprise/Traigent
# Update DTOs to match new schema

# 3. Update TraigentBackend
cd ~/Traigent_enterprise/TraigentBackend
# Update Pydantic schemas

# 4. Update TraigentFrontend
cd ~/Traigent_enterprise/TraigentFrontend
# Regenerate TypeScript types

# 5. Run integration tests across all projects
```

### Adding New Schemas

**When creating new schemas for cross-project features:**

1. **Design schema first** - Define in TraigentSchema (this repo)
2. **Validate structure** - Use `SchemaValidator.validate_json()`
3. **Add to OpenAPI** - Update `mep_endpoints.json` with endpoints
4. **Create SDK DTO** - Implement DTO in Traigent SDK matching schema
5. **Backend models** - Create SQLAlchemy models in TraigentBackend
6. **Frontend types** - Generate TypeScript types in TraigentFrontend
7. **Integration tests** - Test end-to-end data flow

**Example: Adding Example Scoring Schema**
```bash
# 1. Create schema
# traigent_schema/schemas/analytics/example_score_schema.json
{
  "type": "object",
  "required": ["example_id", "informativeness", "uniqueness"],
  "properties": {
    "example_id": {"type": "string"},
    "informativeness": {"type": "number"},
    "uniqueness": {"type": "number"},
    "composite_score": {"type": "number"}
  }
}

# 2. SDK DTO (Traigent/traigent/cloud/dtos.py)
@dataclass
class ExampleScoreDTO:
    example_id: str
    informativeness: float
    uniqueness: float
    composite_score: float | None = None

# 3. Backend model (TraigentBackend/src/models/example_score.py)
class ExampleScore(Base):
    example_id = Column(String, nullable=False)
    informativeness = Column(Float)
    uniqueness = Column(Float)
    composite_score = Column(Float)

# 4. Frontend type (TraigentFrontend/src/types/analytics.ts)
export interface ExampleScoreDTO {
  example_id: string;
  informativeness: number;
  uniqueness: number;
  composite_score?: number;
}
```

### Key Files

**This Repository:**
- `traigent_schema/schemas/` - All JSON schema definitions
- `traigent_schema/validator.py` - Validation utilities
- `traigent_schema/schemas/mep_endpoints.json` - OpenAPI specification

**Related Projects:**
- **SDK**: `traigent/cloud/dtos.py` - Python DTOs implementing schemas
- **Backend**: `src/schemas/` - Pydantic schemas, `src/models/` - SQLAlchemy models
- **Frontend**: `src/types/` - TypeScript types from schemas

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
