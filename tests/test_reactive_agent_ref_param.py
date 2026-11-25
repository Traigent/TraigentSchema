"""Production-reactive ``agent_ref`` path parameters take the agent id the agents API returns.

The 14 ``agent_ref`` path parameters in ``optimization/tvl_reactive_endpoints.json`` are plain
strings (1 to 128 characters) carrying the ``opaque_ref`` content class. The content-class lint
accepts that shape only at ``AGENT_ID_LOCATIONS``; these tests pin the two to each other.
"""

import importlib.util
import json
import sys
from pathlib import Path

from traigent_schema.utils import get_schemas_dir

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "content_class_lint.py"
DOC_NAME = "optimization/tvl_reactive_endpoints.json"
DOC = Path(get_schemas_dir()) / DOC_NAME
EXPECTED_SCHEMA = {
    "x-content-class": "opaque_ref",
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
}
EXPECTED_COUNT = 14


def _load_lint():
    spec = importlib.util.spec_from_file_location("content_class_lint", SCRIPT)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _agent_ref_params():
    """Yield (pointer, parameter object) for every ``agent_ref`` path parameter in the document."""
    doc = json.loads(DOC.read_text(encoding="utf-8"))
    for path, item in doc["paths"].items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            for index, param in enumerate(op.get("parameters", [])):
                if param.get("name") == "agent_ref" and param.get("in") == "path":
                    pointer = (
                        f"{DOC_NAME}#/paths/{_escape(path)}/{method}/parameters/{index}/schema"
                    )
                    yield pointer, param


def test_every_agent_ref_path_parameter_has_the_agent_id_schema():
    found = list(_agent_ref_params())
    assert len(found) == EXPECTED_COUNT
    for pointer, param in found:
        assert param["schema"] == EXPECTED_SCHEMA, pointer
        assert "description" in param, pointer


def test_no_agent_ref_path_parameter_references_agent_ref_definition():
    for pointer, param in _agent_ref_params():
        schema = param["schema"]
        assert "$ref" not in schema, pointer
        assert "AgentRef" not in json.dumps(schema), pointer


def test_agent_ref_pointers_equal_the_content_class_lint_locations():
    lint = _load_lint()
    found = {pointer for pointer, _ in _agent_ref_params()}
    assert found == set(lint.AGENT_ID_LOCATIONS)
