import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

D = get_schemas_dir() / "datasets"


def _load(name: str) -> dict:
    with open(D / name, encoding="utf-8") as handle:
        return json.load(handle)


def _base_dataset_payload() -> dict:
    return {
        "name": "support_qa_dataset",
        "type": "input-output",
        "label": "Support QA Dataset",
    }


def test_backend_shaped_dataset_create_configs_validate_without_resource_ids():
    validator = SchemaValidator(contract="backend")
    payload = {
        **_base_dataset_payload(),
        "generator_config": {
            "model_id": "gpt-4o-mini",
            "parameters": {
                "temperature": 0.2,
                "max_tokens": 1024,
            },
            "context": {
                "system": "support",
                "examples": ["order status", "refund"],
            },
            "instructions": "Generate realistic support examples.",
            "context_type": "conversation",
            "context_source": "custom",
        },
        "evaluator_config": {
            "model_id": "gpt-4o",
            "parameters": {
                "temperature": 0,
            },
            "context": {
                "rubric": {"accuracy": 0.6, "tone": 0.4},
            },
            "instructions": "Evaluate response quality against the rubric.",
            "context_type": "structured",
            "context_source": "custom",
        },
    }

    assert "id" not in payload["generator_config"]
    assert "model_parameters_id" not in payload["generator_config"]
    assert "id" not in payload["evaluator_config"]
    assert "model_parameters_id" not in payload["evaluator_config"]
    assert validator.validate_request("/api/v1/datasets", "POST", payload) == []


def test_resource_shaped_dataset_create_configs_still_validate():
    validator = SchemaValidator(contract="backend")
    payload = {
        **_base_dataset_payload(),
        "generator_config": {
            "id": "generator_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "instructions": "Generate realistic customer support questions.",
            "context_type": "text",
            "context_source": "dataset",
        },
        "evaluator_config": {
            "id": "evaluator_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "instructions": "Evaluate answer quality.",
            "context_type": "text",
            "context_source": "dataset",
        },
    }

    assert validator.validate_request("/api/v1/datasets", "POST", payload) == []


def test_dataset_create_uses_request_scoped_config_refs():
    create_schema = _load("dataset_create_request_schema.json")
    assert (
        create_schema["properties"]["generator_config"]["$ref"]
        == "https://schemas.traigent.ai/datasets/generator_config_create_request_schema.json#"
    )
    assert (
        create_schema["properties"]["evaluator_config"]["$ref"]
        == "https://schemas.traigent.ai/datasets/evaluator_config_create_request_schema.json#"
    )

    validator = SchemaValidator(contract="backend")
    assert "generator_config_create_request_schema" in validator.available_schemas
    assert "evaluator_config_create_request_schema" in validator.available_schemas


def test_resource_config_schemas_remain_strict_and_canonical():
    for schema_name in ("generator_config_schema.json", "evaluator_config_schema.json"):
        resource_schema = _load(schema_name)
        required = set(resource_schema["required"])

        assert resource_schema["additionalProperties"] is False
        assert {"id", "model_parameters_id"} <= required
        assert "model_id" not in resource_schema["properties"]
        assert "parameters" not in resource_schema["properties"]
        assert "context" not in resource_schema["properties"]
