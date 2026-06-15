"""#123: POST create ops bound the full resource schema (requiring server-generated
id/created_at). Create-request schemas omit those from `required`."""
import json

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

POST_BINDINGS = {
    "POST:/api/v1/agents": "agent_create_request_schema",
    "POST:/api/v1/agents/import": "agent_create_request_schema",
    "POST:/api/v1/experiments": "experiment_create_request_schema",
    "POST:/api/v1/measures": "measure_create_request_schema",
    "POST:/api/v1/optimization-comparisons": "comparison_create_request_schema",
    "POST:/api/v1/experiment-runs/runs/{experiment_run_id}/configurations": "configuration_run_create_request_schema",
}


def _load(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


def test_create_requests_omit_server_generated_required_fields():
    for rel in CREATE_REQUESTS:
        spec = _load(rel)
        assert "id" not in spec["required"], f"{rel} still requires server-generated id"
        if "comparison" in rel:
            assert "created_at" not in spec["required"]
        assert spec["additionalProperties"] is True
        # domain fields preserved (non-empty required set)
        assert spec["required"], f"{rel} has no required domain fields"


def test_post_create_ops_bound_to_create_requests():
    v = SchemaValidator(contract="backend")
    for key, schema_stem in POST_BINDINGS.items():
        assert v._endpoint_schemas.get(key) == schema_stem, key


def test_agent_create_no_id_but_domain_validated():
    v = SchemaValidator(contract="backend")
    # id no longer required
    assert v.validate_request("/api/v1/agents", "POST", {"name": "a", "agent_type": "qa"}) == []
    # a client-supplied id is tolerated (BE ignores it)
    assert v.validate_request("/api/v1/agents", "POST", {"id": "x", "name": "a", "agent_type": "qa"}) == []
    # domain field still required
    assert v.validate_request("/api/v1/agents", "POST", {"agent_type": "qa"})
    # domain enum still validated
    assert v.validate_request("/api/v1/agents", "POST", {"name": "a", "agent_type": "not-a-type"})
