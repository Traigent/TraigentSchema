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


def test_trial_id_documents_workflow_trace_identifier_linkage():
    with open(
        get_schemas_dir() / "optimization" / "session_submit_results_request_schema.json",
        encoding="utf-8",
    ) as fh:
        spec = json.load(fh)

    trial_id = spec["properties"]["trial_id"]
    assert "configuration_run_id" in trial_id["description"]
    assert "MUST" in trial_id["description"]
    assert trial_id["x-reference"].endswith(
        "evaluation/configuration_run_schema.json#/properties/id"
    )
    assert trial_id["x-equal-to"] == [
        "../execution/workflow_trace_schema.json#/definitions/SpanBatch/properties/configuration_run_id",
        "../execution/workflow_trace_schema.json#/definitions/SpanPayload/properties/configuration_run_id",
    ]


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


def test_submit_results_measures_inherit_measuresdict_contract():
    """#119: metrics/measures must inherit the canonical MeasuresDict bounds."""
    validator = SchemaValidator(contract="sdk_tuning")

    # 51 keys exceeds the canonical max of 50
    too_many = {f"m{i}": 1 for i in range(51)}
    assert validator.validate_json(_request(metrics=too_many), SCHEMA)
    assert validator.validate_json(_request(metrics={"a": 1}, measures=too_many), SCHEMA)

    # non-identifier keys are rejected
    assert validator.validate_json(_request(measures={"bad-key": 1}), SCHEMA)
    assert validator.validate_json(_request(metrics={"has space": 1}), SCHEMA)

    # non-numeric values are rejected
    assert validator.validate_json(_request(measures={"f1": "high"}), SCHEMA)
    assert validator.validate_json(_request(metrics={"acc": True}), SCHEMA)

    # numeric|null values within 50 identifier keys are accepted
    assert validator.validate_json(
        _request(metrics={"accuracy": 0.9}, measures={"f1": 0.8, "loss": None}),
        SCHEMA,
    ) == []


def test_submit_results_legacy_metadata_measures_is_constrained():
    """#119: the legacy metadata.measures fallback path inherits the same contract."""
    validator = SchemaValidator(contract="sdk_tuning")
    payload = _request()
    payload["metadata"] = {"measures": {"f1": 0.8}}
    assert validator.validate_json(payload, SCHEMA) == []

    payload["metadata"] = {"measures": {"bad-key": 1}}
    assert validator.validate_json(payload, SCHEMA)


def test_submit_results_measures_reference_canonical_definition():
    """#119: the bounds are inherited from the single canonical MeasuresDict, not duplicated."""
    with open(
        get_schemas_dir() / "optimization" / "session_submit_results_request_schema.json",
        encoding="utf-8",
    ) as fh:
        spec = json.load(fh)
    ref = "../evaluation/configuration_run_schema.json#/definitions/MeasureResults"
    assert spec["properties"]["metrics"]["$ref"] == ref
    assert spec["properties"]["measures"]["$ref"] == ref
    assert spec["properties"]["metadata"]["properties"]["measures"]["$ref"] == ref
