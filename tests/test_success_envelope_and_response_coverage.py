"""#136 canonical success envelope + recorded wrap-map; #128 2xx response-schema
coverage on stable detail GET ops; #170 run-results LIST + results GET +
comparison/report read surfaces."""
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
    assert set(env["required"]) == {"success", "message", "data"}
    # the backend wrap-map (which route files wrap vs return bare) is recorded
    wm = env["x-wrap-map"]
    assert "benchmark_routes" in wm["wrapped"]      # datasets are wrapped
    assert "measure_routes" in wm["bare"]           # measures are bare
    assert "experiment_group_routes" in wm["wrapped"]  # experiment groups are wrapped
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
    assert list(val.iter_errors({"success": False, "message": "x", "data": {}}))  # success must be true
    assert list(val.iter_errors({"success": True, "data": {}}))  # message required (canonical {success,message,data})


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


def test_detail_gets_use_the_resource_not_an_unrelated_response_schema():
    # GET /agents/{id} must reference the AGENT resource, not agent_response_schema
    # (which is an execution/run response with required input/status/result).
    agents = _load("agents/agents_endpoints.json")
    ref = agents["paths"]["/api/v1/agents/{agent_id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("agent_schema.json"), ref
    # bare detail GETs reference the resource schema directly
    expected = {
        ("execution/execution_endpoints.json", "/api/v1/experiments/{experiment_id}"): "experiment_schema.json",
        ("execution/execution_endpoints.json", "/api/v1/measures/{measure_id}".replace("measures", "configuration-runs").replace("measure_id", "config_run_id")): "configuration_run_schema.json",
        ("measures/measures_endpoints.json", "/api/v1/measures/{measure_id}"): "measure_schema.json",
    }
    for (cat, path), stem in expected.items():
        op = _load(cat)["paths"][path]["get"]
        assert op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(stem), (cat, path)


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


# ---- #170 — run-results LIST + results GET + comparison/report read surfaces ----

# Surfaces added by #170: the residual from the #128/#162 cliff.
# experiment_run_routes is in the 'bare' wrap-map list — no envelope.
# optimization_comparison_routes is in the 'wrapped' list — success envelope.
# report_routes returns bare jsonify (not enveloped).
LIST_AND_RESULTS_GETS = {
    "execution/execution_endpoints.json": [
        "/api/v1/experiment-runs/{experiment_id}/runs",   # LIST — bare {runs:[...]}
        "/api/v1/experiment-runs/runs/{run_id}/results",  # results GET — bare paginated payload
    ],
    "results/results_endpoints.json": [
        "/api/v1/optimization-comparisons/{comparison_id}",                              # detail GET — wrapped
        "/api/v1/optimization-comparisons/{comparison_id}/examples",                    # list GET — wrapped
        "/api/v1/optimization-comparisons/{comparison_id}/examples/{example_id}",       # detail GET — wrapped
        "/api/v1/experiment-runs/runs/{run_id}/report-payload",                         # bare jsonify
        "/api/v1/features/report-module-status",                                        # bare jsonify
    ],
}

EXPERIMENT_GROUP_GETS = {
    "execution/execution_endpoints.json": [
        "/api/v1/experiment-groups",
        "/api/v1/experiment-groups/{group_id}",
        "/api/v1/experiment-groups/{group_id}/configuration-runs",
    ],
}


def test_run_results_and_comparison_read_surfaces_have_2xx_schemas():
    """#170 — coverage gate: all run-results LIST/GET and comparison/report read GETs carry a schema."""
    for cat, paths in LIST_AND_RESULTS_GETS.items():
        spec = _load(cat)
        for path in paths:
            op = spec["paths"][path]["get"]
            schema = op["responses"]["200"].get("content", {}).get("application/json", {}).get("schema", {})
            assert schema.get("$ref"), (
                f"#170: {path} GET 200 has no response schema in {cat}"
            )


def test_run_results_list_references_experiment_run_list_response_schema():
    """The experiment-runs LIST endpoint must reference the list-response schema, not the item schema directly."""
    spec = _load("execution/execution_endpoints.json")
    ref = (
        spec["paths"]["/api/v1/experiment-runs/{experiment_id}/runs"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    )
    assert ref.endswith("experiment_run_list_response_schema.json"), ref


def test_run_results_get_references_run_results_response_schema():
    """The run-results GET endpoint must reference the run_results_response_schema."""
    spec = _load("execution/execution_endpoints.json")
    ref = (
        spec["paths"]["/api/v1/experiment-runs/runs/{run_id}/results"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    )
    assert ref.endswith("run_results_response_schema.json"), ref


def test_comparison_read_surfaces_reference_correct_schemas():
    """Each comparison/report read GET references its own dedicated schema file."""
    spec = _load("results/results_endpoints.json")
    expected = {
        "/api/v1/optimization-comparisons/{comparison_id}": "comparison_response_schema.json",
        "/api/v1/optimization-comparisons/{comparison_id}/examples": "comparison_examples_list_response_schema.json",
        "/api/v1/optimization-comparisons/{comparison_id}/examples/{example_id}": "comparison_example_detail_response_schema.json",
        "/api/v1/experiment-runs/runs/{run_id}/report-payload": "report_payload_response_schema.json",
        "/api/v1/features/report-module-status": "report_module_status_response_schema.json",
    }
    for path, stem in expected.items():
        ref = (
            spec["paths"][path]["get"]
            ["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        )
        assert ref.endswith(stem), f"{path}: expected ref ending with {stem!r}, got {ref!r}"


def test_run_results_response_schema_structure():
    """run_results_response_schema.json has the expected top-level properties."""
    schema = _load("execution/run_results_response_schema.json")
    assert schema.get("type") == "object"
    props = schema.get("properties", {})
    assert "run_id" in props
    assert "experiment_id" in props
    assert "configurations" in props
    assert props["configurations"]["type"] == "array"
    assert "configurations_pagination" in props
    required = schema.get("required", [])
    assert "run_id" in required
    assert "experiment_id" in required
    assert "configurations" in required


def test_experiment_run_list_response_schema_structure():
    """experiment_run_list_response_schema.json has the expected shape."""
    schema = _load("evaluation/experiment_run_list_response_schema.json")
    assert schema.get("type") == "object"
    props = schema.get("properties", {})
    assert "runs" in props
    assert props["runs"]["type"] == "array"
    assert "runs" in schema.get("required", [])


def test_comparison_response_schema_wraps_envelope():
    """comparison_response_schema.json requires the success envelope structure."""
    schema = _load("results/comparison_response_schema.json")
    required = schema.get("required", [])
    assert "success" in required
    assert "message" in required
    assert "data" in required
    assert schema["properties"]["success"].get("const") is True


def test_report_module_status_schema_enumerates_states():
    """report_module_status_response_schema.json enumerates the valid rollout states."""
    schema = _load("results/report_module_status_response_schema.json")
    states = schema["properties"]["state"]["enum"]
    assert "off" in states
    assert "beta" in states
    assert "ga" in states
    assert "required" in schema and "state" in schema["required"]


# ---- Experiment group routes — wrapped success-envelope responses ----

def test_experiment_group_read_surfaces_have_2xx_response_schemas():
    """Experiment-group GETs must stay in the response-schema coverage set."""
    for cat, paths in EXPERIMENT_GROUP_GETS.items():
        spec = _load(cat)
        for path in paths:
            op = spec["paths"][path]["get"]
            schema = op["responses"]["200"].get("content", {}).get("application/json", {}).get("schema", {})
            assert schema.get("$ref"), (
                f"experiment group response coverage regressed: {path} GET 200 has no schema"
            )


def test_experiment_group_response_schemas_wrap_payloads_in_data():
    """Response definitions are success envelopes; the former bare bodies live under data."""
    schema = _load("execution/experiment_group_schema.json")
    expected_payload_refs = {
        "ExperimentGroupListResponse": "ExperimentGroupListPayload",
        "ExperimentGroupDetailResponse": "ExperimentGroupDetailPayload",
        "GroupedConfigurationRunListResponse": "GroupedConfigurationRunListPayload",
    }

    for response_name, payload_name in expected_payload_refs.items():
        definition = schema["definitions"][response_name]
        payload_definition = schema["definitions"][payload_name]
        properties = definition["properties"]

        assert {"$ref": "../success_envelope_schema.json"} in definition.get("allOf", [])
        assert {"success", "message", "data"} <= set(definition["required"])
        assert properties["success"].get("const") is True
        assert properties["data"]["$ref"] == f"#/definitions/{payload_name}"
        assert payload_definition["additionalProperties"] is False
        for bare_top_level_key in ("items", "group", "source_experiments", "pagination"):
            assert bare_top_level_key not in properties
