# Repository Guidelines

## Claude Plans & IP Protection (CRITICAL)

**Implementation plans contain proprietary IP and must not be committed to version control.**

- All Claude Code plans stored in `~/.claude/plans/` (user home, outside repo)
- Directory excluded by `.gitignore` (line 91: `.claude/`)
- Never create plan files inside repository
- Plans auto-named (e.g., `async-sprouting-summit.md`)

## Single Source of Truth: TraigentSchema (CRITICAL)

**TraigentSchema is the SINGLE SOURCE OF TRUTH for all data contracts across the Traigent ecosystem (SDK, Frontend, Backend).**

### Responsibilities
This repository defines:
- **JSON Schemas** - All API request/response schemas
- **Data Models** - Canonical structure for experiments, runs, configurations
- **Validation Rules** - Constraints (max keys, patterns, types)
- **OpenAPI Spec** - Endpoint-to-schema mappings

### Schema Flow
```
TraigentSchema (JSON Schema)
    ↓
Traigent SDK (Python DTOs)
    ↓
TraigentBackend (Pydantic + SQLAlchemy)
    ↓
TraigentFrontend (TypeScript Types)
```

### MeasuresDict Contract (Enforced Everywhere)
- Max 50 keys
- Python identifier keys (`^[a-zA-Z_][a-zA-Z0-9_]*$`)
- Numeric values only (int, float, None)

### Schema Evolution
When modifying schemas:
1. Check backward compatibility
2. Update version in `version.py`
3. Document breaking changes in CHANGELOG.md
4. Update all projects: SDK DTOs, Backend schemas, Frontend types

### Adding New Schemas
1. Design schema first (JSON in `traigent_schema/schemas/`)
2. Add to OpenAPI (`mep_endpoints.json`)
3. Create SDK DTO (Traigent)
4. Backend models (TraigentBackend)
5. Frontend types (TraigentFrontend)
6. Integration tests

### Key Files
- `traigent_schema/schemas/` - All schema definitions
- `traigent_schema/validator.py` - Validation utilities
- `traigent_schema/schemas/mep_endpoints.json` - OpenAPI spec

## Project Structure & Commands

- Schemas: `traigent_schema/schemas/` organized by domain (agents/, datasets/, evaluation/, etc.)
- Tests: `tests/` with pytest
- Package: Modern `pyproject.toml` with hatchling (no setup.py)
- Python 3.8+ required

### Common Commands
```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=traigent_schema --cov-report=term-missing

# Build package
pip install build && python -m build

# Install for development
pip install -e ".[dev]"
```

### Schema Naming
- Schema files: `{name}_schema.json`
- Endpoint files: `{domain}_endpoints.json`
- Use snake_case, organize by domain subdirectories

### Integration Points
Used by:
- **TraigentBackend** - Schema validation middleware, model generation
- **Traigent SDK** - Optional DTO validation
- **TraigentFrontend** - TypeScript type generation
