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

    score_prop = example["properties"]["score"]
    assert score_prop["maximum"] == 1, "score should be a 0-1 ratio, not 0-100"
    assert score_prop["minimum"] == 0
    assert "percentage" not in score_prop["description"].lower()

    # #314: confidence is now the canonical numeric Confidence common type,
    # $ref'd (via allOf) rather than inlined — resolve it to check the bounds.
    confidence_prop = example["properties"]["confidence"]
    assert confidence_prop["allOf"][0]["$ref"] == (
        "../common_types_schema.json#/definitions/Confidence"
    )
    confidence_def = get_schemas_dir().joinpath("common_types_schema.json")
    with open(confidence_def, encoding="utf-8") as fh:
        common_types = json.load(fh)
    resolved_confidence = common_types["definitions"]["Confidence"]
    assert resolved_confidence["maximum"] == 1, "confidence should be a 0-1 ratio, not 0-100"
    assert resolved_confidence["minimum"] == 0
    assert "percentage" not in confidence_prop["description"].lower()


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
    ex_path = paths["/api/v1/datasets/{dataset_id}/examples/{example_id}"]
    assert "put" in ex_path
    assert "delete" in ex_path  # pre-existing DELETE must be preserved


def test_generate_examples_request_bounds():
    v = SchemaValidator(contract="backend")
    route = "/api/v1/datasets/{dataset_id}/generate-examples"
    assert v.validate_request(route, "POST", {"count": 200})  # exceeds max 100
    assert v.validate_request(route, "POST", {"count": 5, "k_examples": 3}) == []


# --------------------------------------------------------------------------- #
# Standalone /api/v1/example-sets read contracts (unblocks TraigentBackend#3353)
#
# Both routes were undeclared in this repo, which is why #3353 could change
# their response shape with no schema lane objecting. The item shapes are
# transcribed from the serializers, NOT $ref'd from example_set_schema.json —
# that file's closed resource definition omits fields the serializers emit and
# requires fields they do not, so reusing it would declare a contract the
# backend violates on every row.
# --------------------------------------------------------------------------- #

_SET_ITEM_KEYS = {
    "id", "example_set_id", "tenant_id", "project_id", "agent_id", "name",
    "description", "type", "selection_method", "num_examples",
    "similarity_threshold", "tags", "created_at", "updated_at", "examples",
}
_EXAMPLE_ITEM_KEYS = {
    "example_id", "tenant_id", "project_id", "example_set_id", "input",
    "output", "explanation", "tags",
}


def test_example_set_read_routes_are_declared():
    paths = _load("datasets_endpoints.json")["paths"]
    assert "get" in paths["/api/v1/example-sets"]
    assert "get" in paths["/api/v1/example-sets/{set_id}/examples"]


def test_example_set_list_item_matches_the_serializer_not_the_resource_schema():
    """ExampleSet.to_dict() (src/models/agent.py:287-305) emits 15 keys."""
    schema = _load("example_set_list_response_schema.json")
    item = schema["definitions"]["SerializedExampleSet"]
    assert set(item["properties"]) == _SET_ITEM_KEYS
    assert set(item["required"]) == _SET_ITEM_KEYS
    assert item["additionalProperties"] is False
    # the divergence this transcription exists to avoid
    resource = _load("example_set_schema.json")
    assert resource["additionalProperties"] is False
    omitted = _SET_ITEM_KEYS - set(resource["properties"])
    assert {"agent_id", "type", "selection_method", "tags"} <= omitted, (
        "if example_set_schema.json ever grows these, revisit the transcription"
    )
    # the list response must not $ref the closed resource definition
    items_ref = schema["properties"]["data"]["properties"]["items"]["items"]
    assert items_ref == {"$ref": "#/definitions/SerializedExampleSet"}


def test_example_item_matches_the_serializer_and_allows_a_null_output():
    """Example.to_dict() (src/models/agent.py:338-349); `output` is a nullable
    column, but example_set_schema.json#/definitions/Example requires it."""
    schema = _load("example_set_examples_list_response_schema.json")
    item = schema["definitions"]["SerializedExample"]
    assert set(item["properties"]) == _EXAMPLE_ITEM_KEYS
    assert set(item["required"]) == _EXAMPLE_ITEM_KEYS
    assert item["additionalProperties"] is False
    assert item["properties"]["output"]["type"] == ["string", "null"]
    closed = _load("example_set_schema.json")["definitions"]["Example"]
    assert "output" in closed["required"], "the divergence being avoided"
    assert "explanation" not in closed["properties"]
    assert set(item["properties"]) - set(closed["properties"]) >= {
        "explanation", "tags", "example_set_id", "tenant_id", "project_id",
    }


def test_example_content_fields_carry_the_privacy_annotation():
    """input/output/explanation are user content wherever they appear."""
    item = _load("example_set_examples_list_response_schema.json")["definitions"][
        "SerializedExample"
    ]
    for field in ("input", "output", "explanation"):
        prop = item["properties"][field]
        assert prop.get("x-content") is True, field
        assert prop.get("x-privacy-classification") == "user_content", field


def test_nested_examples_reuse_the_serialized_example_definition():
    """A set row embeds FULL example rows, so both surfaces must agree."""
    ref = _load("example_set_list_response_schema.json")["definitions"][
        "SerializedExampleSet"
    ]["properties"]["examples"]["items"]["$ref"]
    assert ref == (
        "./example_set_examples_list_response_schema.json#/definitions/SerializedExample"
    )


# --------------------------------------------------------------------------- #
# Standalone POST /api/v1/model-parameters (unblocks TraigentBackend#3352)
# --------------------------------------------------------------------------- #

def test_standalone_model_parameters_route_binds_its_own_request_schema():
    """It is not a synonym for the agent-scoped route: camelCase array body,
    agent named in the body, and a DIFFERENT request contract."""
    v = SchemaValidator(contract="backend")
    assert v._endpoint_schemas["POST:/api/v1/model-parameters"] == (
        "standalone_model_parameters_create_request_schema"
    )
    assert v._endpoint_schemas["POST:/api/v1/agents/{agent_id}/model-parameters"] == (
        "model_parameters_create_request_schema"
    )
    body = {
        "agentId": "a1",
        "modelParameters": [{"temperature": 0.7, "maxTokens": 1000, "topP": 0.9}],
    }
    assert v.validate_request("/api/v1/model-parameters", "POST", body) == []
    # agentId is what the handler refuses to mint an ownerless row without
    assert v.validate_request(
        "/api/v1/model-parameters",
        "POST",
        {"modelParameters": [{"temperature": 0.7, "maxTokens": 1000, "topP": 0.9}]},
    )
    # an empty array is the bare-400 branch, and the contract rejects it too
    assert v.validate_request(
        "/api/v1/model-parameters", "POST", {"agentId": "a1", "modelParameters": []}
    )
