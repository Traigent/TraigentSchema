"""#150: the SDK-facing optimization/hybrid session routes must declare an error
contract (4xx/5xx) so SDK/FE code against a defined error shape, not an
undocumented body."""
import json

from traigent_schema.utils import get_schemas_dir

CATALOG = get_schemas_dir() / "optimization" / "optimization_endpoints.json"
ENVELOPE = "../error_envelope_schema.json"
RATE_LIMIT = "../rate_limit_info_schema.json"


def _load():
    with open(CATALOG, encoding="utf-8") as fh:
        return json.load(fh)


def _schema_ref(response):
    return response.get("content", {}).get("application/json", {}).get("schema", {}).get("$ref")


def test_every_optimization_route_declares_error_responses():
    catalog = _load()
    for path, methods in catalog["paths"].items():
        for method, op in methods.items():
            codes = set(op.get("responses", {}))
            error_codes = {c for c in codes if c[0] in {"4", "5"}}
            assert error_codes, f"{method.upper()} {path} declares no 4xx/5xx error response"
            # 401/403/500 must always be contracted on these authenticated routes
            assert {"401", "403", "500"} <= codes, f"{method.upper()} {path} missing core error codes"


def test_error_responses_reference_canonical_envelope():
    catalog = _load()
    for path, methods in catalog["paths"].items():
        for method, op in methods.items():
            for code, response in op.get("responses", {}).items():
                if code == "429":
                    assert _schema_ref(response) == RATE_LIMIT, f"{path} 429 must ref rate_limit_info"
                elif code[0] in {"4", "5"}:
                    assert _schema_ref(response) == ENVELOPE, (
                        f"{method.upper()} {path} {code} must ref the canonical error envelope"
                    )


def test_rate_limit_contracted_on_session_routes():
    catalog = _load()
    for path, methods in catalog["paths"].items():
        for method, op in methods.items():
            assert "429" in op.get("responses", {}), f"{method.upper()} {path} missing 429 contract"
