import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA = "session_submit_results_request_schema"


def _request(**overrides):
    payload = {
        "trial_id": "trial-sdk-local-1",
        "metrics": {"accuracy": 0.875},
        "config": {"modelVariant": "balanced", "temperature": 0.4},
        "duration": 0.5,
        "status": "COMPLETED",
        "metadata": {"sdk_version": "2.0.0"},
    }
    payload.update(overrides)
    return payload


def test_submit_results_accepts_top_level_config():
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_json(_request(), SCHEMA) == []


def test_submit_results_accepts_metadata_config_fallback_without_top_level_config():
    validator = SchemaValidator(contract="sdk_tuning")
    payload = _request(metadata={"config": {"temperature": 0.4}}, config=None)
    del payload["config"]

    assert validator.validate_json(payload, SCHEMA) == []


def test_submit_results_requires_trial_id_and_metrics_only():
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_json({"trial_id": "trial-1", "metrics": {}}, SCHEMA) == []
    assert validator.validate_json({"metrics": {}}, SCHEMA)
    assert validator.validate_json({"trial_id": "trial-1"}, SCHEMA)


def test_submit_results_rejects_invalid_config_and_metadata():
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_json(_request(config="temperature=0.4"), SCHEMA)
    assert validator.validate_json(_request(metadata="not-an-object"), SCHEMA)


def test_submit_results_rejects_unknown_top_level_field():
    validator = SchemaValidator(contract="sdk_tuning")

    assert validator.validate_json(_request(raw_prompt="should not be echoed"), SCHEMA)


def test_submit_results_endpoint_wires_named_request_schema():
    with open(
        get_schemas_dir() / "optimization" / "optimization_endpoints.json",
        encoding="utf-8",
    ) as fh:
        spec = json.load(fh)

    schema_ref = spec["paths"]["/api/v1/sessions/{session_id}/results"]["post"][
        "requestBody"
    ]["content"]["application/json"]["schema"]["$ref"]

    assert schema_ref.endswith("session_submit_results_request_schema.json")


def test_sdk_request_validator_accepts_top_level_config_and_rejects_invalid_config():
    validator = SchemaValidator(contract="sdk_tuning")

    assert (
        validator.validate_request(
            "/api/v1/sessions/sess_abc/results",
            "POST",
            _request(),
        )
        == []
    )
    assert validator.validate_request(
        "/api/v1/sessions/sess_abc/results",
        "POST",
        _request(config=["not", "object"]),
    )
