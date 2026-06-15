"""#136 canonical success envelope + recorded wrap-map; #128 2xx response-schema
coverage on stable detail GET ops."""
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _load(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


# ---- #136 ----

def test_canonical_success_envelope_exists():
    env = _load("success_envelope_schema.json")
    assert env["properties"]["success"]["const"] is True
    assert set(env["required"]) >= {"success", "data"}
    # the backend wrap-map (which route files wrap vs return bare) is recorded
    wm = env["x-wrap-map"]
    assert "benchmark_routes" in wm["wrapped"]      # datasets are wrapped
    assert "measure_routes" in wm["bare"]           # measures are bare
    assert not (set(wm["wrapped"]) & set(wm["bare"]))


def test_wrapped_detail_response_wraps_resource_in_envelope():
    v = SchemaValidator(contract="backend")
    from jsonschema import Draft7Validator, FormatChecker
    spec = v._schemas["dataset_detail_response_schema"]
    val = Draft7Validator(spec, registry=v._registry, format_checker=FormatChecker())
    good = {"success": True, "message": "ok", "data": {
        "id": "d1", "name": "n", "label": "L", "description": "x",
        "type": "input-output", "examples_count": 0}}
    assert not list(val.iter_errors(good))
    assert list(val.iter_errors({"success": True}))          # data required
    assert list(val.iter_errors({"success": False, "data": {}}))  # success must be true


# ---- #128 ----

DETAIL_GETS = {
    "agents/agents_endpoints.json": ["/api/v1/agents/{agent_id}"],
    "datasets/datasets_endpoints.json": ["/api/v1/datasets/{dataset_id}"],
    "execution/execution_endpoints.json": [
        "/api/v1/experiments/{experiment_id}",
        "/api/v1/experiment-runs/runs/{run_id}",
        "/api/v1/configuration-runs/{config_run_id}",
    ],
    "measures/measures_endpoints.json": ["/api/v1/measures/{measure_id}"],
}


def test_stable_detail_gets_reference_a_2xx_response_schema():
    for cat, paths in DETAIL_GETS.items():
        spec = _load(cat)
        for path in paths:
            op = spec["paths"][path]["get"]
            schema = op["responses"]["200"].get("content", {}).get("application/json", {}).get("schema", {})
            assert schema.get("$ref"), f"{path} GET 200 has no response schema"


def test_response_schema_coverage_metric_on_detail_gets():
    # coverage gate: 100% of the targeted detail GETs now carry a 2xx schema
    covered = total = 0
    for cat, paths in DETAIL_GETS.items():
        spec = _load(cat)
        for path in paths:
            total += 1
            op = spec["paths"][path]["get"]
            if op["responses"].get("200", {}).get("content"):
                covered += 1
    assert covered == total, f"detail-GET response coverage regressed: {covered}/{total}"
