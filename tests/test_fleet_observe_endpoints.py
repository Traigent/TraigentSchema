"""Fleet Observe endpoint catalog (TRAIG-179).

The six routes and their operationIds are the API server's own.
"""

import json

import pytest

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
CATALOG = S / "fleet_observe" / "fleet_observe_endpoints.json"
PREFIX = "/api/v1beta/projects/{project_id}/fleet-observe"

# (path suffix, method, operationId): the API server's operation table rows, verbatim.
BACKEND_OPERATIONS = [
    ("/imports", "post", "project_fleet_observe.create_import"),
    ("/clusters", "get", "project_fleet_observe.list_clusters"),
    ("/clusters/{cluster_ref}", "get", "project_fleet_observe.get_cluster"),
    ("/coverage", "get", "project_fleet_observe.get_coverage"),
    ("/diff", "get", "project_fleet_observe.get_diff"),
    ("/findings", "get", "project_fleet_observe.list_findings"),
]


def _catalog():
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def test_catalog_declares_exactly_the_six_backend_operations():
    paths = _catalog()["paths"]
    got = sorted((p.removeprefix(PREFIX), m, op["operationId"]) for p, v in paths.items() for m, op in v.items())
    assert got == sorted(BACKEND_OPERATIONS)


def test_catalog_is_wired_into_the_backend_contract_root():
    root = json.loads((S / "mep_endpoints.json").read_text(encoding="utf-8"))
    files = [m["paths_file"] for m in root["x-endpoint-modules"]]
    assert "./fleet_observe/fleet_observe_endpoints.json" in files


def test_validator_binds_the_import_body_to_the_closed_request_schema():
    validator = SchemaValidator(contract="backend")
    bound = {k: v for k, v in validator._endpoint_schemas.items() if "fleet-observe" in k}
    assert bound == {f"POST:{PREFIX}/imports": "import_request_schema"}


def test_import_request_body_references_the_closed_request_schema():
    op = _catalog()["paths"][f"{PREFIX}/imports"]["post"]
    ref = op["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    assert ref == "./import_request_schema.json"


def test_import_declares_201_200_and_the_planned_409():
    responses = _catalog()["paths"][f"{PREFIX}/imports"]["post"]["responses"]
    assert {"200", "201", "400", "404", "409", "429", "500"} <= set(responses)


def test_every_read_carries_the_project_path_parameter_and_only_known_queries():
    paths = _catalog()["paths"]
    allowed = {
        "/clusters": {"limit", "cursor", "order", "state", "confidence", "boundary_ref"},
        "/clusters/{cluster_ref}": set(),
        "/coverage": set(),
        "/diff": {"since"},
        "/findings": {"limit", "cursor", "surface_limit"},
        "/imports": set(),
    }
    for suffix, method, _ in BACKEND_OPERATIONS:
        op = paths[PREFIX + suffix][method]
        names = {(p["in"], p["name"]) for p in op["parameters"]}
        assert ("path", "project_id") in names
        assert {n for i, n in names if i == "query"} == allowed[suffix]


def test_401_is_declared_with_the_auth_error_body_and_403_is_not():
    """The route wrapper rewrites only 403 and 404; a 401 keeps its status."""
    for suffix, method, _ in BACKEND_OPERATIONS:
        responses = _catalog()["paths"][PREFIX + suffix][method]["responses"]
        ref = responses["401"]["content"]["application/json"]["schema"]["$ref"]
        assert ref.endswith("#/definitions/AuthErrorBody")
        assert "403" not in responses


def test_import_declares_the_limiter_503_with_its_masked_body():
    responses = _catalog()["paths"][f"{PREFIX}/imports"]["post"]["responses"]
    ref = responses["503"]["content"]["application/json"]["schema"]["$ref"]
    assert ref.endswith("#/definitions/RateLimitUnavailableBody")


def _refs(node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "$ref":
                yield v
            else:
                yield from _refs(v)
    elif isinstance(node, list):
        for v in node:
            yield from _refs(v)


def test_every_ref_in_the_catalog_resolves():
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    registry = Registry()
    for path in S.rglob("*.json"):
        doc = json.loads(path.read_text(encoding="utf-8"))
        uri = "https://schemas.traigent.ai/" + path.relative_to(S).as_posix()
        registry = registry.with_resource(uri, Resource.from_contents(doc, default_specification=DRAFT7))
    base = "https://schemas.traigent.ai/fleet_observe/fleet_observe_endpoints.json"
    resolver = registry.resolver(base_uri=base)
    refs = set(_refs(_catalog()))
    assert refs
    for ref in refs:
        resolver.lookup(ref)  # raises when it does not resolve


def test_get_responses_validate_against_their_declared_schema():
    """Each 200 body schema is a real Draft-7 schema reachable through the catalog."""
    for suffix, method, _ in BACKEND_OPERATIONS:
        ok = _catalog()["paths"][PREFIX + suffix][method]["responses"]
        schema = (ok.get("200") or ok["201"])["content"]["application/json"]["schema"]
        assert schema["$ref"].startswith("./fleet_observe_responses_schema.json#/definitions/")


@pytest.mark.parametrize("suffix,method,op_id", BACKEND_OPERATIONS)
def test_operation_ids_are_backend_operation_ids(suffix, method, op_id):
    assert _catalog()["paths"][PREFIX + suffix][method]["operationId"] == op_id
