"""Pin what the public agents catalogue says the project-scoped agents API does.

Source of truth is the backend runtime (src/routes/agent_routes.py on develop), not the
backend's private copy of the catalogue. The facts below were read from the handlers:

* only a guard's denial (unusable project, authentication) is ``application/problem+json``; the
  agents family is not a problem-format family, so in-handler 404/409/422 are the legacy JSON
  envelope, and request validation is ``validation_error_response`` (422 legacy);
* create, update, archive and unarchive answer the bare agent body (``id`` always present);
* import takes the export wrapper or the direct agent format; update is a partial update;
* every operation keeps its 429.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from traigent_schema.utils import get_schemas_dir

PATH = get_schemas_dir() / "agents" / "agents_endpoints.json"
DOC = json.loads(PATH.read_text(encoding="utf-8"))
PROBLEM = "application/problem+json"
LEGACY = "application/json"

OPS: dict[str, dict[str, Any]] = {
    op["operationId"]: op
    for item in DOC["paths"].values()
    for op in item.values()
    if isinstance(op, dict) and "operationId" in op
}
PROJECT_OPS = sorted(o for o in OPS if o != "agent.get_agent_types")
PER_AGENT_OPS = [
    "agent.get_agent",
    "agent.update_agent",
    "agent.delete_agent",
    "agent.archive_agent",
    "agent.unarchive_agent",
    "agent.check_agent_deletion",
    "agent.export_agent",
    "agent.get_agent_experiments",
    "agent.add_example_set",
    "agent.add_retrieval_config",
    "agent.get_model_parameters",
    "agent.add_model_parameters",
    "agent.update_model_parameters",
]


def _resolve(node: Any) -> Any:
    ref = node.get("$ref") if isinstance(node, dict) else None
    if ref and ref.startswith("#/components/"):
        cur: Any = DOC
        for part in ref[2:].split("/"):
            cur = cur[part]
        return cur
    return node


def _media(op_id: str, status: str) -> dict[str, Any]:
    return _resolve(OPS[op_id]["responses"][status]).get("content", {})


def _request_schema(op_id: str) -> Any:
    ref = OPS[op_id]["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    return json.loads((PATH.parent / ref).read_text(encoding="utf-8"))


def test_agent_admin_stats_stays_out_of_the_public_catalogue() -> None:
    assert "agent.get_agent_admin_stats" not in OPS


def test_the_agent_operation_ids_are_unchanged() -> None:
    assert len([o for o in OPS if o.startswith("agent.")]) == 19
    assert "createModelParametersStandalone" in OPS


@pytest.mark.parametrize("op_id", PROJECT_OPS)
def test_guard_denials_are_problem_documents(op_id: str) -> None:
    for status in ("401", "403"):
        if status in OPS[op_id]["responses"]:
            assert PROBLEM in _media(op_id, status), (op_id, status)
    if op_id.startswith("agent."):
        assert PROBLEM in _media(op_id, "404"), op_id


@pytest.mark.parametrize("op_id", PER_AGENT_OPS)
def test_a_missing_agent_is_also_the_legacy_json_404(op_id: str) -> None:
    media = _media(op_id, "404")
    assert PROBLEM in media, op_id
    assert LEGACY in media, op_id


@pytest.mark.parametrize("op_id", [o for o in PROJECT_OPS if o.startswith("agent.")])
def test_every_project_operation_declares_429(op_id: str) -> None:
    assert "429" in OPS[op_id]["responses"], op_id


@pytest.mark.parametrize(
    ("op_id", "status"),
    [
        ("agent.create_agent", "201"),
        ("agent.update_agent", "200"),
        ("agent.archive_agent", "200"),
        ("agent.unarchive_agent", "200"),
    ],
)
def test_bare_agent_body_requires_an_id(op_id: str, status: str) -> None:
    schema = _resolve(_media(op_id, status)[LEGACY]["schema"])
    assert schema["required"] == ["id"]
    assert "success" not in schema.get("properties", {})  # bare body, not the envelope


@pytest.mark.parametrize(
    "op_id",
    [
        "agent.create_agent",
        "agent.update_agent",
        "agent.add_example_set",
        "agent.add_retrieval_config",
        "agent.update_model_parameters",
        "agent.search_agents",
    ],
)
def test_validation_failures_are_legacy_422_and_keep_the_problem_form(op_id: str) -> None:
    media = _media(op_id, "422")
    assert LEGACY in media, op_id
    assert PROBLEM in media, op_id


def test_create_and_update_400_cover_both_forms() -> None:
    for op_id in ("agent.create_agent", "agent.update_agent"):
        media = _media(op_id, "400")
        assert LEGACY in media, op_id
        assert PROBLEM in media, op_id


def test_create_conflict_is_the_legacy_json_agent_already_exists() -> None:
    media = _media("agent.create_agent", "409")
    assert list(media) == [LEGACY]
    assert media[LEGACY]["schema"] == {"$ref": "./agent_conflict_error_schema.json"}


def test_unarchive_conflict_exists_in_both_forms() -> None:
    media = _media("agent.unarchive_agent", "409")
    assert LEGACY in media
    assert PROBLEM in media


def test_delete_has_200_with_tracking_204_without_and_409_legacy() -> None:
    assert {"200", "204", "409"} <= set(OPS["agent.delete_agent"]["responses"])
    assert LEGACY in _media("agent.delete_agent", "409")


def test_list_declares_the_sort_by_422() -> None:
    media = _media("agent.get_agents", "422")
    assert LEGACY in media
    assert PROBLEM in media


def test_import_400_distinguishes_validation_list_and_credential_problem() -> None:
    media = _media("agent.import_agent", "400")
    assert media[LEGACY]["schema"] == {"$ref": "./agent_import_validation_error_schema.json"}
    assert media[PROBLEM]["schema"] == {"$ref": "./agent_import_credential_error_schema.json"}


def test_create_429_is_the_quota_error_and_import_429_is_the_rate_limit() -> None:
    quota = _media("agent.create_agent", "429")[LEGACY]["schema"]
    assert quota == {"$ref": "../billing/quota_exceeded_error_schema.json"}
    limited = _media("agent.import_agent", "429")[LEGACY]["schema"]
    assert limited == {"$ref": "../rate_limit_info_schema.json"}


def test_import_request_accepts_the_export_wrapper_and_the_direct_format() -> None:
    schema = _request_schema("agent.import_agent")
    assert {"schema_version", "agent", "name"} <= set(schema["properties"])
    # additive-only: the wrapper keys are documented without a constraint (the open import
    # request used to accept any value for them); see test_agents_request_schemas_accept_compatible
    assert "type" not in schema["properties"]["agent"]
    assert "enum" not in schema["properties"]["schema_version"]
    assert not schema.get("required")  # the wrapper has no top-level name


def test_update_request_is_a_partial_update_with_no_required_field() -> None:
    schema = _request_schema("agent.update_agent")
    assert not schema.get("required")
    assert schema["additionalProperties"] is False  # the runtime refuses unknown keys
    assert OPS["agent.update_agent"]["requestBody"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "./agent_update_request_schema.json"}
    assert {"name", "agent_type_id", "agent_type", "description", "tags"} <= set(
        schema["properties"]
    )


def test_retrieval_config_request_requires_only_name() -> None:
    assert _request_schema("agent.add_retrieval_config")["required"] == ["name"]


def test_model_parameter_requests_are_partial_and_carry_model_id() -> None:
    update = _request_schema("agent.update_model_parameters")
    assert not update.get("required")
    assert {"model_id", "temperature", "max_tokens", "stop_sequences"} <= set(update["properties"])
    create = _request_schema("agent.add_model_parameters")
    assert {"model_id", "temperature", "top_p"} <= set(create["properties"])


def test_add_example_set_keeps_the_strict_runtime_request() -> None:
    schema = _request_schema("agent.add_example_set")
    assert OPS["agent.add_example_set"]["requestBody"]["content"]["application/json"][
        "schema"
    ] == {"$ref": "../datasets/example_set_create_request_schema.json"}
    assert schema["required"] == ["name", "selection_method"]
