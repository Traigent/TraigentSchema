"""Datasets contract: evaluation_set_id typo + missing routes (#124), create-request
admits the portal's client fields (#135/#123), score/confidence 0-1 unit (#139)."""
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

D = get_schemas_dir() / "datasets"


def _load(name):
    with open(D / name, encoding="utf-8") as fh:
        return json.load(fh)


def test_evaluation_set_id_typo_fixed():
    text = (D / "evaluation_set_schema.json").read_text(encoding="utf-8")
    assert "evaluation set_id" not in text
    file_def = _load("evaluation_set_schema.json")["definitions"]["EvaluationSetFile"]
    assert "evaluation_set_id" in file_def["properties"]


def test_score_confidence_are_ratio_0_1():
    example = _load("evaluation_set_schema.json")["definitions"]["EvaluationSetExample"]
    for field in ("score", "confidence"):
        prop = example["properties"][field]
        assert prop["maximum"] == 1, f"{field} should be a 0-1 ratio, not 0-100"
        assert prop["minimum"] == 0
        assert "percentage" not in prop["description"].lower()


def test_dataset_create_request_admits_client_fields_and_omits_server_fields():
    create = _load("dataset_create_request_schema.json")
    for client_field in ("model_parameters", "processing_functions", "draft_id"):
        assert client_field in create["properties"], client_field
    for server_field in ("id", "examples_count", "created_at", "updated_at"):
        assert server_field not in create["properties"], server_field
    assert set(create["required"]) == {"name", "type", "label"}
    assert create["additionalProperties"] is True


def test_create_route_accepts_portal_body():
    v = SchemaValidator(contract="backend")
    assert v._endpoint_schemas["POST:/api/v1/datasets"] == "dataset_create_request_schema"
    body = {
        "name": "my_ds", "type": "input-output", "label": "L",
        "model_parameters": {"temperature": 0.4}, "processing_functions": [], "draft_id": "d1",
    }
    assert v.validate_request("/api/v1/datasets", "POST", body) == []
    # domain fields still required
    assert v.validate_request("/api/v1/datasets", "POST", {"label": "L"})


def test_missing_dataset_routes_added():
    cat = _load("datasets_endpoints.json")
    paths = cat["paths"]
    assert "post" in paths["/api/v1/datasets/{dataset_id}/generate-examples"]
    assert "get" in paths["/api/v1/datasets/{dataset_id}/files"]
    assert "post" in paths["/api/v1/datasets/{dataset_id}/files"]
    assert "delete" in paths["/api/v1/datasets/{dataset_id}/files/{file_id}"]
    assert "put" in paths["/api/v1/datasets/{dataset_id}/examples/{example_id}"]


def test_generate_examples_request_bounds():
    v = SchemaValidator(contract="backend")
    route = "/api/v1/datasets/{dataset_id}/generate-examples"
    assert v.validate_request(route, "POST", {"count": 200})  # exceeds max 100
    assert v.validate_request(route, "POST", {"count": 5, "k_examples": 3}) == []
