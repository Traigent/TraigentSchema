"""#123: POST create ops reused full resource schemas (requiring server-generated id).
Create-request schemas now model the actual backend create DTOs (correct required
fields, additionalProperties:true, no server-generated id)."""
import json

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()

CREATE_REQUESTS = [
    "agents/agent_create_request_schema.json",
    "datasets/example_set_create_request_schema.json",
    "agents/retriever_create_request_schema.json",
    "agents/model_parameters_create_request_schema.json",
    "evaluation/experiment_create_request_schema.json",
    "evaluation/configuration_run_create_request_schema.json",
    "measures/measure_create_request_schema.json",
    "results/comparison_create_request_schema.json",
]

# (path, valid backend body, invalid backend body) — required fields mirror the BE create DTOs.
CASES = [
    ("/api/v1/agents", {"name": "a", "agent_type_id": "qa"}, {"name": "a"}),
    ("/api/v1/agents/import", {"name": "a", "agent_type_id": "qa"}, {"agent_type_id": "qa"}),
    ("/api/v1/agents/{agent_id}/example-sets",
     {"name": "s", "selection_method": "all"}, {"name": "s"}),
    ("/api/v1/agents/{agent_id}/retrieval-configs",
     {"name": "r", "vector_store": {}, "k": 1, "retrieval_k": 1, "chunk_size": 100, "overlap": 0},
     {"name": "r", "vector_store": {}}),
    ("/api/v1/agents/{agent_id}/model-parameters", {}, None),
    ("/api/v1/experiments",
     {"name": "e", "dataset_id": "d", "agent_id": "a"}, {"name": "e"}),
    ("/api/v1/experiment-runs/runs/{experiment_run_id}/configurations",
     {"experiment_parameters": {}}, {}),
    ("/api/v1/configuration-runs/runs/{experiment_run_id}/configurations",
     {"experiment_parameters": {}}, {}),
    ("/api/v1/measures",
     {"label": "L", "measure_type": "numeric"}, {"label": "L"}),
    ("/api/v1/optimization-comparisons",
     {"run_ids": ["r1", "r2"]}, {"run_ids": ["r1"]}),
]


def _load(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


def test_create_requests_never_require_server_generated_id():
    for rel in CREATE_REQUESTS:
        spec = _load(rel)
        assert "id" not in spec["required"], f"{rel} still requires server-generated id"
        assert "created_at" not in spec["required"]
        assert spec["additionalProperties"] is True


@pytest.mark.parametrize("path,valid,invalid", CASES)
def test_create_request_matches_backend_required_fields(path, valid, invalid):
    v = SchemaValidator(contract="backend")
    assert v.validate_request(path, "POST", valid) == [], f"{path} rejected a backend-valid body"
    if invalid is not None:
        assert v.validate_request(path, "POST", invalid), f"{path} accepted a backend-invalid body"


def test_comparison_run_ids_bounded_2_to_10():
    v = SchemaValidator(contract="backend")
    assert v.validate_request(
        "/api/v1/optimization-comparisons",
        "POST",
        {"run_ids": ["a", "b"]},
    ) == []
    assert v.validate_request("/api/v1/optimization-comparisons", "POST", {"run_ids": ["a"]})
    assert v.validate_request(
        "/api/v1/optimization-comparisons",
        "POST",
        {"run_ids": [str(i) for i in range(11)]},
    )


def test_example_set_similarity_threshold_matches_backend_bounds():
    v = SchemaValidator(contract="backend")
    base = {"name": "set", "selection_method": "all"}

    assert v.validate_request(
        "/api/v1/agents/{agent_id}/example-sets",
        "POST",
        {**base, "similarity_threshold": 0.7},
    ) == []
    assert v.validate_request(
        "/api/v1/agents/{agent_id}/example-sets",
        "POST",
        {**base, "similarity_threshold": 0},
    ) == []
    assert v.validate_request(
        "/api/v1/agents/{agent_id}/example-sets",
        "POST",
        {**base, "similarity_threshold": 1},
    ) == []
    assert v.validate_request(
        "/api/v1/agents/{agent_id}/example-sets",
        "POST",
        {**base, "similarity_threshold": -0.01},
    )
    assert v.validate_request(
        "/api/v1/agents/{agent_id}/example-sets",
        "POST",
        {**base, "similarity_threshold": 1.01},
    )
