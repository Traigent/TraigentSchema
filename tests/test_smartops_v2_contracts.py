from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


def _schema(name: str) -> dict:
    path = get_schemas_dir() / "smartops_v2" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_v2_routes_are_reachable_without_changing_v1() -> None:
    validator = SchemaValidator(contract="backend")
    assert validator._endpoint_schemas[
        "POST:/api/v2/experiment-runs/{run_id}/next-decision"
    ] == "next_decision_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/lifecycles/{lifecycle_id}/decisions/{decision_id}/receipts"
    ] == "receipt_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/lifecycles/{lifecycle_id}/reopen"
    ] == "reopen_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v2/internal/smartops/shadow-evaluate"
    ] == "shadow_evaluate_request_schema"
    assert validator._endpoint_schemas[
        "POST:/api/v1/analytics/experiments/{experiment_run_id}/next-steps/{decision_id}/receipt"
    ] == "next_steps_receipt_request_schema"


def test_submitted_receipt_requires_result_ref() -> None:
    validator = SchemaValidator(contract="backend")
    base = {
        "attempt_id": "attempt_0123456789abcdef",
        "status": "submitted",
    }
    assert validator.validate_request(
        "/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/decision_0123456789abcdef/receipts",
        "POST",
        base,
    )
    assert not validator.validate_request(
        "/api/v2/lifecycles/lifecycle_0123456789abcdef/decisions/decision_0123456789abcdef/receipts",
        "POST",
        {**base, "result_ref": "result_0123456789abcdef"},
    )


def test_public_command_and_private_argv_are_shell_free() -> None:
    response = _schema("next_decision_response_schema.json")
    command = response["properties"]["decision"]["properties"]["action"]["properties"][
        "command_template"
    ]
    assert "traigent guidance execute --decision" in command["pattern"]
    assert "x-content" not in json.dumps(response)

    resolved = _schema("resolve_decision_response_schema.json")
    assert resolved["properties"]["argv"]["type"] == "array"
    assert resolved["properties"]["execution_spec"]["additionalProperties"] is False


def test_internal_numeric_certificate_never_appears_in_public_decision() -> None:
    public = json.dumps(_schema("next_decision_response_schema.json"))
    internal = json.dumps(_schema("shadow_evaluate_response_schema.json"))
    assert "advantage_lcb" not in public
    assert "advantage_lcb" in internal
    assert "internal_confidential" in internal
