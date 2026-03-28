"""
Schema utility functions for the Traigent Schema Library.

Provides functions for locating, loading, and managing JSON schema files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

ContractName = Literal["backend", "sdk_tuning", "planned_projects"]

_CONTRACT_FILES: dict[ContractName, str] = {
    "backend": "mep_endpoints.json",
    "sdk_tuning": "sdk_tuning_endpoints.json",
    "planned_projects": "planned_projects_endpoints.json",
}


def _validate_contract_name(contract: str) -> ContractName:
    """Validate a runtime contract name and return the narrowed literal value."""
    if contract not in _CONTRACT_FILES:
        valid_contracts = ", ".join(sorted(_CONTRACT_FILES))
        raise ValueError(
            f"Unknown contract {contract!r}; expected one of: {valid_contracts}"
        )
    return contract  # type: ignore[return-value]


def get_schemas_dir() -> Path:
    """
    Get the path to the schemas directory.

    Returns:
        Path to the schemas directory within the package.
    """
    return Path(__file__).parent / "schemas"


def get_schema_path(schema_name: str) -> Path:
    """
    Get the full path to a specific schema file.

    Args:
        schema_name: Name of the schema (with or without .json extension)

    Returns:
        Path to the schema file.

    Raises:
        FileNotFoundError: If schema file doesn't exist.
    """
    schemas_dir = get_schemas_dir()

    # Normalize name
    if not schema_name.endswith('.json'):
        schema_name = f"{schema_name}.json"

    # Try direct path first
    schema_path = schemas_dir / schema_name
    if schema_path.exists():
        return schema_path

    # Search in subdirectories
    for subdir in schemas_dir.iterdir():
        if subdir.is_dir():
            candidate = subdir / schema_name
            if candidate.exists():
                return candidate

    # Try with _schema suffix
    if not schema_name.endswith('_schema.json'):
        alt_name = schema_name.replace('.json', '_schema.json')
        return get_schema_path(alt_name)

    raise FileNotFoundError(f"Schema not found: {schema_name}")


def get_all_schema_files() -> list[Path]:
    """
    Get all schema files in the package.

    Returns:
        List of paths to all JSON schema files.
    """
    schemas_dir = get_schemas_dir()
    return list(schemas_dir.rglob("*.json"))


def get_openapi_path() -> Path:
    """
    Get the path to the canonical backend OpenAPI contract.

    Returns:
        Path to mep_endpoints.json
    """
    return get_contract_path("backend")


def get_contract_path(contract: ContractName | str) -> Path:
    """
    Get the path to a named endpoint contract root.

    Args:
        contract: Contract catalog name.

    Returns:
        Path to the requested endpoint contract file.
    """
    contract_name = _validate_contract_name(contract)
    return get_schemas_dir() / _CONTRACT_FILES[contract_name]


def load_schema(schema_name: str) -> dict[str, Any]:
    """
    Load a schema by name.

    Args:
        schema_name: Name of the schema to load.

    Returns:
        Parsed JSON schema as a dictionary.
    """
    schema_path = get_schema_path(schema_name)
    with open(schema_path, encoding='utf-8') as f:
        result: dict[str, Any] = json.load(f)
        return result
