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
            "model_id": "gpt-4o-mini",
            "instructions": "Generate realistic customer support questions.",
            "context_type": "text",
            "context_source": "dataset",
        },
        "evaluator_config": {
            "id": "evaluator_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "model_id": "gpt-4o",
            "instructions": "Evaluate answer quality.",
            "context_type": "text",
            "context_source": "dataset",
        },
    }

    assert validator.validate_request("/api/v1/datasets", "POST", payload) == []


def test_generator_and_evaluator_config_require_model_id_and_instructions():
    """#267: BenchmarkCreator hard-subscripts model_id/instructions off both

    inner config objects (src/dal/benchmark_creator.py), so a schema-valid
    config missing either field previously 500'd instead of failing a clean
    422. Both fields must now be declared required on the create-request
    contracts whenever the config object itself is supplied.
    """
    validator = SchemaValidator(contract="backend")
    base_payload = _base_dataset_payload()

    missing_model_id = {
        **base_payload,
        "generator_config": {"instructions": "Generate support examples."},
    }
    errors = validator.validate_request("/api/v1/datasets", "POST", missing_model_id)
    assert errors, "expected a validation error when generator_config omits model_id"
    assert any("model_id" in str(e) for e in errors)

    missing_instructions = {
        **base_payload,
        "evaluator_config": {"model_id": "gpt-4o"},
    }
    errors = validator.validate_request("/api/v1/datasets", "POST", missing_instructions)
    assert errors, "expected a validation error when evaluator_config omits instructions"
    assert any("instructions" in str(e) for e in errors)

    for schema_name in (
        "generator_config_create_request_schema.json",
        "evaluator_config_create_request_schema.json",
    ):
        schema = _load(schema_name)
        assert set(schema["required"]) == {"model_id", "instructions"}


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


def test_dataset_update_put_keeps_partial_patch_semantics():
    """Round-2 review fix: dataset_create_request_schema.json is $ref'd by BOTH

    POST /api/v1/datasets (create) and PUT /api/v1/datasets/{dataset_id}
    (update) per datasets_endpoints.json. The update handler
    (src/dal/benchmark_dal.py) reads generator_config/evaluator_config as a
    partial patch against an existing config via .get() -- only the
    create-if-absent branch there hard-subscripts model_id/instructions --
    so PUT must NOT inherit the create-request required[] this PR added.
    PUT now resolves to dataset_update_request_schema.json, whose nested
    generator_config/evaluator_config point at the *_update_request_schema.json
    variants (no required[]), while POST keeps the strict create-request ones.
    """
    validator = SchemaValidator(contract="backend")
    base_payload = _base_dataset_payload()

    # A legitimate partial-patch PUT: tweak only `parameters` on an existing
    # generator_config, without resending model_id/instructions.
    partial_patch_payload = {
        **base_payload,
        "generator_config": {"parameters": {"temperature": 0.5}},
        "evaluator_config": {"parameters": {"temperature": 0}},
    }

    assert (
        validator.validate_request(
            "/api/v1/datasets/{dataset_id}", "PUT", partial_patch_payload
        )
        == []
    ), "PUT must accept a generator_config/evaluator_config partial patch"

    # The same payload on POST (create) must still be rejected: create has no
    # existing config to patch against, so model_id/instructions are required.
    create_errors = validator.validate_request(
        "/api/v1/datasets", "POST", partial_patch_payload
    )
    assert create_errors, "POST must still require model_id/instructions"

    endpoints = _load("datasets_endpoints.json")
    put_ref = endpoints["paths"]["/api/v1/datasets/{dataset_id}"]["put"]["requestBody"][
        "content"
    ]["application/json"]["schema"]["$ref"]
    assert put_ref == "./dataset_update_request_schema.json"

    update_schema = _load("dataset_update_request_schema.json")
    assert (
        update_schema["properties"]["generator_config"]["$ref"]
        == "https://schemas.traigent.ai/datasets/generator_config_update_request_schema.json#"
    )
    assert (
        update_schema["properties"]["evaluator_config"]["$ref"]
        == "https://schemas.traigent.ai/datasets/evaluator_config_update_request_schema.json#"
    )
    for update_config_name in (
        "generator_config_update_request_schema.json",
        "evaluator_config_update_request_schema.json",
    ):
        assert "required" not in _load(update_config_name)
