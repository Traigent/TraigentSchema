"""The backend contract (the one the backend serves) declares the list query params."""

import json

from traigent_schema.utils import get_contract_path


def _backend_operations() -> dict[tuple[str, str], dict]:
    root_path = get_contract_path("backend")
    root = json.loads(root_path.read_text(encoding="utf-8"))
    operations: dict[tuple[str, str], dict] = {}
    for module in root["x-endpoint-modules"]:
        module_doc = json.loads(
            (root_path.parent / module["paths_file"]).read_text(encoding="utf-8")
        )
        for path, item in module_doc.get("paths", {}).items():
            for method, operation in item.items():
                operations[(path, method)] = operation
    return operations


def _params(operation: dict) -> dict[str, dict]:
    return {p["name"]: p for p in operation.get("parameters", [])}


LIST_PARAMS = ["page", "per_page", "search", "prompt_type", "label", "sort_by", "sort_order"]
LIST_KEYS = (("/api/v1beta/prompts", "get"), ("/api/v1beta/projects/{project_id}/prompts", "get"))


def test_backend_contract_declares_both_prompt_list_gets() -> None:
    operations = _backend_operations()
    ids = set()
    for key in LIST_KEYS:
        operation = operations[key]
        params = _params(operation)
        for name in LIST_PARAMS:
            assert name in params, (key, name)
        assert params["sort_by"]["schema"]["enum"] == ["updated_at", "name", "version_count"]
        assert params["sort_order"]["schema"]["enum"] == ["asc", "desc"]
        assert params["page"]["schema"]["default"] == 1
        assert params["per_page"]["schema"]["default"] == 20
        assert params["per_page"]["schema"]["maximum"] == 100
        ids.add(operation["operationId"])
    assert len(ids) == 2


def test_project_prompt_list_requires_project_id_path_param() -> None:
    params = _params(_backend_operations()[LIST_KEYS[1]])
    assert params["project_id"]["in"] == "path"
    assert params["project_id"]["required"] is True
    assert params["project_id"]["schema"]["type"] == "string"
    assert "project_id" not in _params(_backend_operations()[LIST_KEYS[0]])


def test_backend_contract_declares_measures_has_evaluator() -> None:
    operation = _backend_operations()[("/api/v1/measures", "get")]
    assert _params(operation)["has_evaluator"]["schema"]["type"] == "boolean"


def test_no_prompt_writes_newly_in_backend_contract() -> None:
    prompt_ops = {
        key
        for key in _backend_operations()
        if "/prompts" in key[0]
        and key[0].startswith(("/api/v1beta/prompts", "/api/v1beta/projects"))
    }
    assert {m for _, m in prompt_ops} == {"get"}


def test_list_operations_leave_422_to_the_backend_error_envelope() -> None:
    operations = _backend_operations()
    for key in (*LIST_KEYS, ("/api/v1/measures", "get")):
        assert "422" not in operations[key]["responses"]
