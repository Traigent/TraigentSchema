"""Plan v2.1 phase 1b-2a: the token-refs issuance contract."""
import json
import re
from pathlib import Path

from tests._schema_refs import build_registry, ref_errors
from traigent_schema.utils import get_schemas_dir

OPT = Path(get_schemas_dir()) / "optimization"
KEY = "0123456789abcdef0123456789abcdef"
AGENT = "agentref_" + "a" * 32
KNOB = "knobref_" + "b" * 32


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


REGISTRY = build_registry()
BASE = "https://schemas.traigent.ai/optimization/token_refs_schema.json"


class _V:
    def __init__(self, ref):
        self.ref = ref

    def iter_errors(self, instance):
        return ref_errors(REGISTRY, self.ref, instance)


def _validator(definition):
    return _V(f"{BASE}#/definitions/{definition}")


def _req(**over):
    body = {"schema_version": 1, "agent_ref": AGENT, "operation_key": KEY, "items": [{"kind": "knob"}]}
    body.update(over)
    return body


def _valid(body):
    return not list(_validator("TokenRefsRequest").iter_errors(body))


def test_request_is_closed_and_bounded():
    doc = _load("token_refs_schema.json")
    assert doc["additionalProperties"] is False
    assert set(doc["required"]) == {"schema_version", "agent_ref", "operation_key", "items"}
    assert doc["properties"]["items"]["minItems"] == 1 and doc["properties"]["items"]["maxItems"] == 200
    assert doc["properties"]["items"]["items"]["additionalProperties"] is False
    assert _valid(_req())
    assert not _valid(_req(extra=1))
    assert not _valid(_req(items=[]))
    assert _valid(_req(items=[{"kind": "knob"}] * 200))
    assert not _valid(_req(items=[{"kind": "knob"}] * 201))
    assert not _valid(_req(items=[{"kind": "knob", "name": "x"}]))


def test_operation_key_is_32_lowercase_hex():
    for bad in ("", KEY[:-1], KEY + "0", KEY.upper(), "g" * 32, "Alice_has_diabetes_" + "0" * 13):
        assert not _valid(_req(operation_key=bad)), bad


def test_parent_ref_rules():
    assert _valid(_req(items=[{"kind": "choice", "parent_ref": KNOB}]))
    assert not _valid(_req(items=[{"kind": "choice"}]))
    assert not _valid(_req(items=[{"kind": "choice", "parent_ref": "choiceref_" + "b" * 32}]))
    for kind in ("knob", "metric", "template"):
        assert not _valid(_req(items=[{"kind": kind, "parent_ref": KNOB}]))
    assert not _valid(_req(items=[{"kind": "dataset"}]))


def test_response_is_refs_only():
    v = _validator("TokenRefsResponse")
    assert not list(v.iter_errors({"refs": [KNOB, "choiceref_" + "c" * 32]}))
    assert list(v.iter_errors({"refs": [AGENT]}))
    assert list(v.iter_errors({"refs": [KNOB], "extra": 1}))
    assert list(v.iter_errors({"refs": []}))


def test_refusal_envelope_one_fixed_branch_per_code():
    schema = _load("token_refs_schema.json")["definitions"]["TokenRefsRefusal"]
    assert schema["additionalProperties"] is False
    codes = schema["properties"]["error_code"]["enum"]
    assert codes == ["invalid_request", "flag_disabled", "reference_not_found",
                     "operation_key_conflict", "quota_exceeded", "internal_error"]
    branches = [b["properties"] for b in schema["oneOf"]]
    assert [b["error_code"]["const"] for b in branches] == codes
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches] == messages
    assert all("{" not in m and "%" not in m for m in messages)


def test_route_is_declared_and_registered():
    doc = _load("token_refs_endpoints.json")
    post = doc["paths"]["/api/v1/optimization/token-refs"]["post"]
    assert post["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "token_refs_schema.json#/definitions/TokenRefsRequest")
    assert set(post["responses"]) == {"200", "400", "401", "403", "404", "409", "429", "500"}
    mep = json.loads((Path(get_schemas_dir()) / "mep_endpoints.json").read_text())
    assert any(re.search(r"token_refs_endpoints\.json$", e.get("paths_file", "")) for e in _entries(mep))


def _entries(node):
    if isinstance(node, dict):
        if "paths_file" in node:
            yield node
        for v in node.values():
            yield from _entries(v)
    elif isinstance(node, list):
        for v in node:
            yield from _entries(v)
