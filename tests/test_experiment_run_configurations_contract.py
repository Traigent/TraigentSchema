"""Contract tests for the experiment-run configurations paths in execution_endpoints.json.

Guards two properties of the execution endpoints module:

(a) no two paths are equivalent templates (same path after every ``{name}`` is
    normalised to ``{}``), because OpenAPI treats them as the same path;
(b) every operation under ``/api/v1/experiment-runs`` carries a non-empty
    operationId, so the backend operation table can map it to a contract id.
"""

from __future__ import annotations

import re

from tests._schema_refs import load_json
from traigent_schema.utils import get_schemas_dir

ENDPOINTS_PATH = get_schemas_dir() / "execution" / "execution_endpoints.json"
_PARAM = re.compile(r"\{[^}]+\}")
_HTTP_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


def _paths() -> dict:
    return load_json(ENDPOINTS_PATH)["paths"]


def test_no_two_paths_are_equivalent_templates() -> None:
    seen: dict[str, str] = {}
    duplicates: list[tuple[str, str]] = []
    for path in _paths():
        normalised = _PARAM.sub("{}", path)
        if normalised in seen:
            duplicates.append((seen[normalised], path))
        else:
            seen[normalised] = path
    assert duplicates == [], f"equivalent path templates: {duplicates}"


def test_every_experiment_run_operation_has_operation_id() -> None:
    missing: list[str] = []
    for path, item in _paths().items():
        if not path.startswith("/api/v1/experiment-runs"):
            continue
        for method, operation in item.items():
            if method not in _HTTP_METHODS:
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id.strip():
                missing.append(f"{method.upper()} {path}")
    assert missing == [], f"experiment-run operations without operationId: {missing}"


def test_configuration_runs_path_is_single_item_with_operation_ids() -> None:
    paths = _paths()
    configurations = [p for p in paths if p.endswith("/configurations") and "/experiment-runs/runs/" in p]
    assert configurations == ["/api/v1/experiment-runs/runs/{run_id}/configurations"]
    item = paths[configurations[0]]
    assert item["post"]["operationId"] == "experiment_run.create_configuration_run_compat"
    assert item["get"]["operationId"] == "experiment_run.get_configuration_runs"
