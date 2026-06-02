"""Contract tests for the planner status endpoint (TraigentSchema#57).

GET /api/v1/planner/status/{draft_id} returns a {success, message, data} envelope
wrapping a live status object (distinct from planner_draft_schema). Missing drafts
return 404 (ErrorEnvelopeDTO), not a 200 with a not_found status. Modeled against
TraigentBackend develop (planner_routes.py + planning_service.py).
"""

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

SCHEMA = "planner_status_response_schema"


def _resp(**data_overrides):
    data = {
        "status": "processing",
        "progress": 33.3,
        "message": "Generating agent",
        "generatedParts": ["agent"],
        "timestamp": "2026-06-02T12:00:00Z",
    }
    data.update(data_overrides)
    return {"success": True, "message": "Plan status retrieved", "data": data}


def test_accepts_live_status():
    assert SchemaValidator().validate_json(_resp(), SCHEMA) == []


def test_accepts_without_timestamp():
    body = _resp()
    del body["data"]["timestamp"]
    assert SchemaValidator().validate_json(body, SCHEMA) == []


def test_initial_state_created_is_valid():
    assert SchemaValidator().validate_json(_resp(status="created"), SCHEMA) == []


def test_rejects_not_found_status():
    """Per BE#659 the missing signal is a 404, never a 200 status='not_found'."""
    assert SchemaValidator().validate_json(_resp(status="not_found"), SCHEMA)


def test_requires_core_data_fields():
    v = SchemaValidator()
    for missing in ("status", "progress", "message", "generatedParts"):
        body = _resp()
        del body["data"][missing]
        assert v.validate_json(body, SCHEMA), missing


def test_rejects_unknown_generated_part():
    assert SchemaValidator().validate_json(_resp(generatedParts=["widget"]), SCHEMA)


def test_progress_bounds():
    v = SchemaValidator()
    assert v.validate_json(_resp(progress=150), SCHEMA)
    assert v.validate_json(_resp(progress=-1), SCHEMA)


def test_endpoint_wired_and_module_registered():
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "planner" / "planner_endpoints.json", encoding="utf-8") as fh:
        spec = json.load(fh)
    op = spec["paths"]["/api/v1/planner/status/{draft_id}"]["get"]
    assert op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "planner_status_response_schema.json"
    )
    assert op["responses"]["404"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "error_envelope_schema.json"
    )
    with open(schemas_dir / "mep_endpoints.json", encoding="utf-8") as fh:
        mep = json.load(fh)
    modules = {m["name"]: m["paths_file"] for m in mep["x-endpoint-modules"]}
    assert modules.get("Planner") == "./planner/planner_endpoints.json"
