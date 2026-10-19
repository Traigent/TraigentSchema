"""Plan v2.1 phase 1b-2b: the negotiated label-write contract (POST /api/v1/optimization/labels)."""
import json
import re
from pathlib import Path

from tests._schema_refs import build_registry, ref_errors
from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
OPT = SCHEMAS / "optimization"
BASE = "https://schemas.traigent.ai/optimization/label_write_schema.json"
REGISTRY = build_registry()
REF = "knobref_" + "b" * 32
ENVELOPE = {"version": 1, "key_epoch": 1, "enc": "A" * 43, "ciphertext": "A" * 64}


def _load(name):
    return json.loads((OPT / name).read_text(encoding="utf-8"))


class _V:
    def __init__(self, ref):
        self.ref = ref

    def iter_errors(self, instance):
        return ref_errors(REGISTRY, self.ref, instance)


def _validator(definition):
    return _V(f"{BASE}#/definitions/{definition}")


def _req(**over):
    body = {"schema_version": 1, "object_ref": REF, "purpose": "knob", "base_revision": 0, "epoch": 1,
            "envelope": dict(ENVELOPE)}
    body.update(over)
    return body


def _valid(body):
    return not list(_validator("LabelWriteRequest").iter_errors(body))


def test_request_is_the_legacy_write_plus_schema_version_and_closed():
    doc = _load("label_write_schema.json")
    legacy = json.loads((SCHEMAS / "labels" / "label_io_schema.json").read_text())["definitions"][
        "LabelWriteRequest"]
    assert doc["additionalProperties"] is False
    assert set(doc["required"]) == set(legacy["required"]) | {"schema_version"}
    assert set(doc["properties"]) == set(legacy["properties"]) | {"schema_version"}
    assert _valid(_req())
    assert not _valid(_req(extra=1))
    body = _req()
    del body["schema_version"]
    assert not _valid(body)
    assert not _valid(_req(schema_version=2))
    assert not _valid(_req(object_ref="agent_key_alice"))
    assert not _valid(_req(purpose="name"))


def test_every_field_is_classed_and_only_the_envelope_is_content_bearing():
    doc = _load("label_write_schema.json")
    for name, prop in doc["properties"].items():
        if "$ref" in prop:
            continue
        assert "x-content-class" in prop, name
    refs = {n: p["$ref"] for n, p in doc["properties"].items() if "$ref" in p}
    assert refs["envelope"].endswith("label_envelope_schema.json")
    assert refs["object_ref"].endswith("#/definitions/ObjectRef")


def test_response_is_the_label_write_response():
    v = _validator("LabelWriteResponse")
    ok = {"object_ref": REF, "purpose": "knob", "revision": 1, "epoch": 1, "updated_at": "2026-10-19T00:00:00Z"}
    assert not list(v.iter_errors(ok))
    assert list(v.iter_errors({**ok, "envelope": ENVELOPE}))


def test_refusal_envelope_one_fixed_branch_per_code_and_adds_reference_not_issued():
    schema = _load("label_write_schema.json")["definitions"]["LabelWriteRefusal"]
    assert schema["additionalProperties"] is False
    codes = schema["properties"]["error_code"]["enum"]
    assert codes == ["invalid_request", "reference_not_issued", "stale_revision", "stale_epoch",
                     "conflict", "internal_error", "service_unavailable"]
    branches = [b["properties"] for b in schema["oneOf"]]
    assert [b["error_code"]["const"] for b in branches] == codes
    assert [b["error"]["const"] for b in branches] == codes
    messages = schema["properties"]["message"]["enum"]
    assert [b["message"]["const"] for b in branches] == messages
    assert all("{" not in m and "%" not in m for m in messages)
    legacy = {"invalid_request", "stale_revision", "stale_epoch", "conflict", "internal_error"}
    assert legacy < set(codes)


def test_route_is_declared_and_registered():
    doc = _load("label_write_endpoints.json")
    assert list(doc["paths"]) == ["/api/v1/optimization/labels"]
    post = doc["paths"]["/api/v1/optimization/labels"]["post"]
    assert post["requestBody"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "label_write_schema.json#/definitions/LabelWriteRequest")
    assert set(post["responses"]) == {"200", "400", "401", "403", "404", "409", "422", "429", "500", "503"}
    mep = json.loads((SCHEMAS / "mep_endpoints.json").read_text())
    assert any(re.search(r"label_write_endpoints\.json$", e.get("paths_file", "")) for e in _entries(mep))


def _entries(node):
    if isinstance(node, dict):
        if "paths_file" in node:
            yield node
        for v in node.values():
            yield from _entries(v)
    elif isinstance(node, list):
        for v in node:
            yield from _entries(v)


def test_service_unavailable_refusal_is_closed():
    v = _validator("LabelWriteRefusal")
    ok = {"success": False, "error": "service_unavailable", "error_code": "service_unavailable",
          "message": "Service is temporarily unavailable."}
    assert not list(v.iter_errors(ok))
    assert list(v.iter_errors({**ok, "message": "Internal error."}))
    assert list(v.iter_errors({**ok, "details": {"x": 1}}))
    assert list(v.iter_errors({**ok, "error": "internal_error"}))
