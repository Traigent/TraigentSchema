"""Endpoint contract reference integrity tests."""

import json
from pathlib import Path
from urllib.parse import unquote

import pytest

from traigent_schema.utils import get_contract_path, get_schemas_dir

CONTRACT_ROOTS = ("backend", "sdk_tuning", "planned_projects")


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as handle:
        result = json.load(handle)
    assert isinstance(result, dict), f"{path} must contain a JSON object"
    return result


def _iter_refs(value: object, path: str = "$"):
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            yield path, ref
        for key, child in value.items():
            yield from _iter_refs(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_refs(child, f"{path}[{index}]")


def _decode_pointer_token(token: str) -> str:
    return unquote(token).replace("~1", "/").replace("~0", "~")


def _resolve_json_pointer(document: object, fragment: str, source: Path, ref_path: str) -> None:
    if fragment in ("", "#"):
        return

    if not fragment.startswith("#/"):
        pytest.fail(f"{source}:{ref_path} uses unsupported $ref fragment {fragment!r}")

    current = document
    for raw_token in fragment[2:].split("/"):
        token = _decode_pointer_token(raw_token)
        if isinstance(current, dict):
            if token not in current:
                pytest.fail(f"{source}:{ref_path} points to missing fragment token {token!r}")
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or int(token) >= len(current):
                pytest.fail(f"{source}:{ref_path} points to missing array index {token!r}")
            current = current[int(token)]
        else:
            pytest.fail(f"{source}:{ref_path} traverses through non-container JSON")


def test_contract_endpoint_modules_resolve_to_files():
    schemas_dir = get_schemas_dir()

    for contract in CONTRACT_ROOTS:
        root_path = get_contract_path(contract)
        root = _load_json(root_path)
        modules = root.get("x-endpoint-modules", [])

        assert isinstance(modules, list), f"{root_path} x-endpoint-modules must be a list"
        for index, module in enumerate(modules):
            assert isinstance(module, dict), (
                f"{root_path} x-endpoint-modules[{index}] must be an object"
            )
            paths_file = module.get("paths_file")
            assert isinstance(paths_file, str), (
                f"{root_path} x-endpoint-modules[{index}].paths_file must be a string"
            )

            target = (schemas_dir / paths_file).resolve()
            assert target.is_file(), (
                f"{root_path} x-endpoint-modules[{index}] points to missing {paths_file}"
            )


def test_endpoint_schema_refs_resolve_to_files_and_fragments():
    endpoint_files = sorted(get_schemas_dir().rglob("*_endpoints.json"))
    assert endpoint_files, "Expected at least one endpoint contract file"

    for source in endpoint_files:
        source_document = _load_json(source)
        for ref_path, ref in _iter_refs(source_document):
            target_document = source_document
            fragment = ref

            if not ref.startswith("#"):
                target_name, separator, fragment_name = ref.partition("#")
                assert "://" not in target_name, (
                    f"{source}:{ref_path} must use packaged local schema refs, got {ref!r}"
                )

                target = (source.parent / target_name).resolve()
                assert target.is_file(), f"{source}:{ref_path} points to missing {ref!r}"
                target_document = _load_json(target)
                fragment = f"#{fragment_name}" if separator else ""

            _resolve_json_pointer(target_document, fragment, source, ref_path)
