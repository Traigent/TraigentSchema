"""Prompt list retirement and the list/search contract (API refactor Phase 1).

The retired v1beta prompt list GETs (``GET /api/v1beta/prompts`` and
``GET /api/v1beta/projects/{project_id}/prompts``) are gone. Their replacements
live in ``prompts/prompts_endpoints.json``: ``prompt_management.list_prompts``
(``GET /api/v1/projects/{project_id}/prompts``, cursor pagination with ``limit``,
``cursor`` and ``prompt_type``) and ``prompt_management.search_prompts``
(``POST .../prompts/search``, whose body carries ``search``, ``label``,
``prompt_type``, ``cursor`` and ``limit``).

Deliberately dropped: the retired list's ``sort_by`` and ``sort_order``
parameters. Neither replacement declares them, so these tests pin their absence.

Contract roots: ``prompts_endpoints.json`` is indexed by
``planned_projects_endpoints.json``, not by ``mep_endpoints.json`` (the backend
root), which no longer declares any prompt module.
"""

import json
from typing import Any

from traigent_schema.utils import get_contract_path

_SCHEMAS = get_contract_path("planned_projects").parent
_PROMPTS_PATH = _SCHEMAS / "prompts" / "prompts_endpoints.json"
_WRITE_METHODS = {"post", "put", "patch", "delete"}
_RETIRED_LIST_KEYS = (
    ("/api/v1beta/prompts", "get"),
    ("/api/v1beta/projects/{project_id}/prompts", "get"),
)
_LIST_KEY = ("/api/v1/projects/{project_id}/prompts", "get")
_SEARCH_KEY = ("/api/v1/projects/{project_id}/prompts/search", "post")


def _load(path: Any) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _prompts_doc() -> dict:
    return _load(_PROMPTS_PATH)


def _root_operations(contract: str) -> dict[tuple[str, str], dict]:
    """Every (path, method) -> operation across the modules of one contract root."""
    root_path = get_contract_path(contract)
    root = _load(root_path)
    operations: dict[tuple[str, str], dict] = {}
    for module in root["x-endpoint-modules"]:
        module_doc = _load(root_path.parent / module["paths_file"])
        for path, item in module_doc.get("paths", {}).items():
            for method, operation in item.items():
                operations[(path, method)] = operation
    return operations


def _params(operation: dict) -> dict[str, dict]:
    return {p["name"]: p for p in operation.get("parameters", [])}


def _resolve(doc: dict, schema: dict) -> dict:
    ref = schema.get("$ref")
    if not ref:
        return schema
    node: Any = doc
    for part in ref.lstrip("#/").split("/"):
        node = node[part]
    return node


def test_retired_v1beta_prompt_list_routes_are_absent_from_both_roots() -> None:
    for contract in ("backend", "planned_projects"):
        operations = _root_operations(contract)
        for key in _RETIRED_LIST_KEYS:
            assert key not in operations, (contract, key)
    assert not (_SCHEMAS / "prompts" / "prompts_list_endpoints.json").exists()


def test_list_prompts_declares_exactly_limit_cursor_and_prompt_type() -> None:
    operation = _prompts_doc()["paths"][_LIST_KEY[0]][_LIST_KEY[1]]
    assert operation["operationId"] == "prompt_management.list_prompts"
    params = _params(operation)
    assert set(params) == {"project_id", "limit", "cursor", "prompt_type"}
    assert params["project_id"]["in"] == "path"
    assert params["project_id"]["required"] is True
    assert params["project_id"]["schema"]["type"] == "string"
    assert params["limit"]["schema"]["maximum"] == 100
    assert params["limit"]["schema"]["default"] == 20


def test_search_prompts_is_a_post_whose_body_carries_the_filters() -> None:
    doc = _prompts_doc()
    operation = doc["paths"][_SEARCH_KEY[0]][_SEARCH_KEY[1]]
    assert operation["operationId"] == "prompt_management.search_prompts"
    body_schema = _resolve(
        doc,
        operation["requestBody"]["content"]["application/json"]["schema"],
    )
    assert set(body_schema["properties"]) == {"search", "label", "prompt_type", "cursor", "limit"}
    assert body_schema.get("additionalProperties") is False


def test_no_prompt_writes_beyond_those_in_prompts_endpoints() -> None:
    declared = {
        (path, method)
        for path, item in _prompts_doc()["paths"].items()
        for method in item
    }
    declared_writes = {key for key in declared if key[1] in _WRITE_METHODS}
    for contract in ("backend", "planned_projects"):
        prompt_ops = {
            key for key in _root_operations(contract) if "/prompts" in key[0]
        }
        assert prompt_ops <= declared, (contract, prompt_ops - declared)
        writes = {key for key in prompt_ops if key[1] in _WRITE_METHODS}
        assert writes <= declared_writes, (contract, writes - declared_writes)


def test_list_and_search_declare_422_rather_than_leaving_it_to_the_envelope() -> None:
    """The earlier 'leave 422 to the backend envelope' rule belonged to the retired
    list routes. The replacement list and search operations declare 422 explicitly."""
    doc = _prompts_doc()
    assert "422" in doc["paths"][_LIST_KEY[0]][_LIST_KEY[1]]["responses"]
    assert "422" in doc["paths"][_SEARCH_KEY[0]][_SEARCH_KEY[1]]["responses"]


def test_backend_contract_declares_measures_has_evaluator() -> None:
    operation = _root_operations("backend")[("/api/v1/measures", "get")]
    assert _params(operation)["has_evaluator"]["schema"]["type"] == "boolean"


def test_measures_list_leaves_422_to_the_backend_error_envelope() -> None:
    operation = _root_operations("backend")[("/api/v1/measures", "get")]
    assert "422" not in operation["responses"]
