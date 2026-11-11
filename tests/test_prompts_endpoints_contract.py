"""Pins the prompt-management endpoint module: eleven project-scoped operations."""

import json
from pathlib import Path

SCHEMAS = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas"
DOC = json.loads((SCHEMAS / "prompts" / "prompts_endpoints.json").read_text(encoding="utf-8"))
METHODS = {"get", "post", "put", "patch", "delete"}

EXPECTED = {
    "prompt_management.list_prompts",
    "prompt_management.create_prompt",
    "prompt_management.search_prompts",
    "prompt_management.get_prompt",
    "prompt_management.delete_prompt",
    "prompt_management.get_prompt_analytics",
    "prompt_management.resolve_prompt",
    "prompt_management.create_prompt_version",
    "prompt_management.get_prompt_version",
    "prompt_management.update_prompt_labels",
    "prompt_management.run_prompt_playground",
}


def _ops():
    for path, item in DOC["paths"].items():
        for method, op in item.items():
            if method in METHODS:
                yield path, method, op


def test_exactly_the_eleven_operations_with_unique_operation_ids() -> None:
    ids = [op["operationId"] for _, _, op in _ops()]
    assert len(ids) == len(set(ids))
    assert set(ids) == EXPECTED


def test_every_path_is_project_scoped_v1_and_never_name_addressed() -> None:
    for path in DOC["paths"]:
        assert path.startswith("/api/v1/projects/{project_id}/prompts")
        assert "prompt_name" not in path


def test_search_and_resolve_are_post_with_bodies() -> None:
    paths = DOC["paths"]
    search = paths["/api/v1/projects/{project_id}/prompts/search"]["post"]
    resolve = paths["/api/v1/projects/{project_id}/prompts/{prompt_ref}/resolve"]["post"]
    assert "PromptSearchRequest" in json.dumps(search["requestBody"])
    assert "PromptResolveRequest" in json.dumps(resolve["requestBody"])
    assert "get" not in paths["/api/v1/projects/{project_id}/prompts/{prompt_ref}/resolve"]


def test_cursor_pagination_block_is_closed_and_shared() -> None:
    page = DOC["components"]["schemas"]["PromptsPagination"]
    assert page["additionalProperties"] is False
    assert set(page["required"]) == {"limit", "next_cursor", "has_more"}
    analytics = DOC["components"]["schemas"]["PromptAnalytics"]
    assert analytics["properties"]["recent_links_pagination"]["$ref"].endswith("PromptsPagination")
    assert "recent_links_pagination" in analytics["required"]


def test_search_request_carries_sort_fields() -> None:
    props = DOC["components"]["schemas"]["PromptSearchRequest"]["properties"]
    assert props["sort_by"]["enum"] == ["updated_at", "name", "version_count"]
    assert props["sort_by"]["default"] == "updated_at"
    assert props["sort_order"]["enum"] == ["asc", "desc", None]
