"""
Schema utility functions for the Traigent Schema Library.

Provides functions for locating, loading, and managing JSON schema files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

ContractName = Literal["backend", "sdk_tuning", "planned_projects"]

JSON_SUFFIX = ".json"

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


def _normalize_schema_filename(schema_name: str) -> str:
    """Return a safe schema filename for package-local lookup."""
    if not schema_name or schema_name in {".", ".."}:
        raise ValueError("Schema name must be a non-empty file name")

    raw_path = Path(schema_name)
    if raw_path.is_absolute() or raw_path.name != schema_name or "\\" in schema_name:
        raise ValueError("Schema name must not include path components")

    if not schema_name.endswith(JSON_SUFFIX):
        schema_name = f"{schema_name}{JSON_SUFFIX}"

    if schema_name in {JSON_SUFFIX, f".{JSON_SUFFIX}"}:
        raise ValueError("Schema name must be a non-empty file name")

    return schema_name


def _schema_candidate_if_safe(
    search_dir: Path,
    schema_name: str,
    allowed_root: Path,
) -> Path | None:
    candidate = search_dir / schema_name
    if not candidate.exists():
        return None

    schemas_root = allowed_root.resolve()
    resolved_candidate = candidate.resolve()
    if not resolved_candidate.is_relative_to(schemas_root):
        raise ValueError("Schema path escapes the package schema directory")

    if not resolved_candidate.is_file():
        raise FileNotFoundError(f"Schema not found: {schema_name}")

    return resolved_candidate


def get_schema_path(schema_name: str) -> Path:
    """
    Get the full path to a specific schema file.

    Args:
        schema_name: Name of the schema (with or without .json extension)

    Returns:
        Path to the schema file.

    Raises:
        FileNotFoundError: If schema file doesn't exist.
        ValueError: If schema_name contains path components.
    """
    schemas_dir = get_schemas_dir()
    normalized_name = _normalize_schema_filename(schema_name)
    candidate_names = [normalized_name]

    if not normalized_name.endswith(f"_schema{JSON_SUFFIX}"):
        candidate_names.append(
            normalized_name.removesuffix(JSON_SUFFIX) + f"_schema{JSON_SUFFIX}"
        )

    for candidate_name in candidate_names:
        if schema_path := _schema_candidate_if_safe(schemas_dir, candidate_name, schemas_dir):
            return schema_path

        for subdir in schemas_dir.iterdir():
            if not subdir.is_dir():
                continue
            if schema_path := _schema_candidate_if_safe(subdir, candidate_name, schemas_dir):
                return schema_path

    raise FileNotFoundError(f"Schema not found: {normalized_name}")


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
