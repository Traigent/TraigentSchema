"""#140: v1beta ops mis-bound — measures PUT wrong schema, annotation PATCH
documents a forbidden `note`, evaluator execute/backfill wrong status code,
evaluator create binds server-managed fields."""
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _cat(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


def test_measures_put_accepts_measures_body():
    v = SchemaValidator(contract="backend")
    route = "/api/v1/configuration-runs/{config_run_id}/measures"
    assert v._endpoint_schemas[f"PUT:{route}"] == "configuration_run_measures_request_schema"
    assert v.validate_request(route, "PUT", {"measures": {"f1": 0.9}}) == []
    assert v.validate_request(route, "PUT", {"measures": [{"example_id": "e", "score": 1}]}) == []
    # inherits the MeasuresDict cap
    assert v.validate_request(route, "PUT", {"measures": {f"m{i}": 1 for i in range(51)}})


def test_annotation_patch_forbids_note_and_requires_a_field():
    v = SchemaValidator(contract="backend")
    route = "/api/v1beta/annotation-queues/items/{item_id}"
    assert v.validate_request(route, "PATCH", {"note": "x"})            # note forbidden
    assert v.validate_request(route, "PATCH", {})                       # at least one field
    assert v.validate_request(route, "PATCH", {"status": "completed"}) == []
    assert v.validate_request(route, "PATCH", {"assigned_user_id": "u1"}) == []


def test_evaluator_execute_backfill_are_202():
    cat = _cat("observability/observability_endpoints.json")
    for path in ("/api/v1beta/evaluators/{evaluator_id}/execute",
                 "/api/v1beta/evaluators/{evaluator_id}/backfill"):
        codes = set(cat["paths"][path]["post"]["responses"])
        assert "202" in codes and "201" not in codes, f"{path} should be 202, not 201"


def test_evaluator_create_omits_server_managed_fields():
    v = SchemaValidator(contract="backend")
    assert v._endpoint_schemas["POST:/api/v1beta/evaluators"] == "evaluator_definition_create_request_schema"
    body = {"name": "e", "measure_id": "m", "target_type": "trace", "judge_config": {}}
    assert v.validate_request("/api/v1beta/evaluators", "POST", body) == []
    # server-managed id is forbidden (extra=forbid)
    assert v.validate_request("/api/v1beta/evaluators", "POST", {**body, "id": "x"})
    # missing a required domain field is rejected
    assert v.validate_request("/api/v1beta/evaluators", "POST", {"name": "e"})
