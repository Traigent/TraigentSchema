"""Endpoint catalog registration integrity tests."""

from __future__ import annotations

import json
from pathlib import Path

from traigent_schema.utils import get_contract_path, get_schemas_dir

CONTRACT_ROOTS = ("backend", "sdk_tuning", "planned_projects")


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert isinstance(result, dict), f"{path} must contain a JSON object"
    return result


def test_every_endpoint_module_file_is_registered_by_a_contract_root() -> None:
    schemas_dir = get_schemas_dir()
    contract_root_paths = {
        get_contract_path(contract).resolve()
        for contract in CONTRACT_ROOTS
    }
    endpoint_module_files = {
        path.resolve()
        for path in schemas_dir.rglob("*_endpoints.json")
        if path.resolve() not in contract_root_paths
    }

    registered_module_files = set()
    for contract in CONTRACT_ROOTS:
        contract_root = _load_json(get_contract_path(contract))
        modules = contract_root.get("x-endpoint-modules", [])
        assert isinstance(modules, list), f"{contract} x-endpoint-modules must be a list"

        for index, module in enumerate(modules):
            assert isinstance(module, dict), (
                f"{contract} x-endpoint-modules[{index}] must be an object"
            )
            paths_file = module.get("paths_file")
            assert isinstance(paths_file, str), (
                f"{contract} x-endpoint-modules[{index}].paths_file must be a string"
            )
            registered_module_files.add((schemas_dir / paths_file).resolve())

    assert registered_module_files == endpoint_module_files
