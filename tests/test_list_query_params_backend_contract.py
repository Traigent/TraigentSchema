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


def test_backend_contract_declares_prompts_list_params() -> None:
    operation = _backend_operations()[("/api/v1beta/prompts", "get")]
    params = _params(operation)
    assert params["sort_by"]["schema"]["enum"] == ["updated_at", "name", "version_count"]
    assert params["sort_order"]["schema"]["enum"] == ["asc", "desc"]
    assert params["per_page"]["schema"]["default"] == 20


def test_backend_contract_declares_measures_has_evaluator() -> None:
    operation = _backend_operations()[("/api/v1/measures", "get")]
    assert _params(operation)["has_evaluator"]["schema"]["type"] == "boolean"


def test_list_operations_leave_422_to_the_backend_error_envelope() -> None:
    operations = _backend_operations()
    for key in (("/api/v1beta/prompts", "get"), ("/api/v1/measures", "get")):
        assert "422" not in operations[key]["responses"]
