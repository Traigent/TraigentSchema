"""Observability ingest/read contract split (#121), full ObservationType enum
(#122), and ingest schema-bomb bounds + recursion guard (#130)."""
import json
import sys

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

OBS = get_schemas_dir() / "observability"
ALL_TYPES = [
    "span", "generation", "event", "tool_call", "agent", "chain", "tool",
    "retriever", "evaluator", "embedding", "guardrail",
]


def _v():
    return SchemaValidator(contract="backend")


def _trace(**extra):
    t = {"id": "t1", "name": "trace", "observations": []}
    t.update(extra)
    return t


def _ingest(**extra):
    body = {"traces": [_trace(**extra)]}
    return body


def _load(name):
    with open(OBS / name, encoding="utf-8") as fh:
        return json.load(fh)


# ---- #121: ingest/read split ----

def test_ingest_request_binds_ingest_schemas_not_read_schemas():
    req = _load("observability_ingest_request_schema.json")
    assert req["properties"]["traces"]["items"]["$ref"] == "./trace_ingest_schema.json"
    trace_ingest = _load("trace_ingest_schema.json")
    assert trace_ingest["additionalProperties"] is False
    assert trace_ingest["properties"]["observations"]["items"]["$ref"] == "./observation_ingest_schema.json"
    assert trace_ingest["properties"]["session"]["$ref"] == "./session_ingest_schema.json"


def test_ingest_forbids_unknown_and_read_only_fields():
    v = _v()
    assert v.validate_json(_ingest(), "observability_ingest_request_schema") == []
    # unknown top-level trace field
    assert v.validate_json(_ingest(surprise=1), "observability_ingest_request_schema")
    # read-only trace fields are not part of the ingest contract
    for ro in ("comments", "feedback", "collaboration", "prompt_links"):
        assert v.validate_json(_ingest(**{ro: []}), "observability_ingest_request_schema"), ro
    # unknown observation field (e.g. a server read-model field)
    bad_obs = _ingest(observations=[{"id": "o", "type": "span", "name": "n", "tenant_id": "x"}])
    assert v.validate_json(bad_obs, "observability_ingest_request_schema")


def test_read_schemas_still_tolerate_server_response_fields():
    v = _v()
    # read trace/observation responses carry server fields beyond the ingest set
    assert v.validate_json(
        {"id": "t", "name": "n", "tenant_id": "x", "observation_count": 3}, "trace_schema"
    ) == []
    assert v.validate_json(
        {"id": "o", "type": "retriever", "name": "n", "depth": 2, "otel_span_id": "s"},
        "observation_schema",
    ) == []


# ---- #122: full ObservationType enum ----

def test_full_observation_type_enum_accepted_on_read_and_ingest():
    v = _v()
    read = _load("observation_schema.json")
    assert set(read["properties"]["type"]["enum"]) == set(ALL_TYPES)
    for t in ALL_TYPES:
        assert v.validate_json(
            _ingest(observations=[{"id": "o", "type": t, "name": "n"}]),
            "observability_ingest_request_schema",
        ) == [], t
    # unknown type still rejected
    assert v.validate_json(
        _ingest(observations=[{"id": "o", "type": "made_up", "name": "n"}]),
        "observability_ingest_request_schema",
    )


# ---- #130: ingest schema-bomb bounds + recursion guard ----

def test_ingest_nested_arrays_have_maxitems():
    trace_ingest = _load("trace_ingest_schema.json")
    assert "maxItems" in trace_ingest["properties"]["observations"]
    assert "maxItems" in trace_ingest["properties"]["tags"]
    obs_ingest = _load("observation_ingest_schema.json")
    d1 = obs_ingest["definitions"]["Observation_d1"]
    assert "maxItems" in d1["properties"]["children"]


def test_observation_children_depth_is_bounded():
    v = _v()

    def nested(depth):
        root = {"id": "o", "type": "agent", "name": "n"}
        cur = root
        for _ in range(depth - 1):
            cur["children"] = [{"id": "o", "type": "chain", "name": "n"}]
            cur = cur["children"][0]
        return root

    assert v.validate_json(_ingest(observations=[nested(6)]), "observability_ingest_request_schema") == []
    assert v.validate_json(_ingest(observations=[nested(7)]), "observability_ingest_request_schema")


def test_validator_distinguishes_recursion_from_validation_error():
    v = _v()
    deep = {"id": "o", "type": "span", "name": "n"}
    cur = deep
    for _ in range(sys.getrecursionlimit() + 500):
        cur["children"] = [{"id": "o", "type": "span", "name": "n"}]
        cur = cur["children"][0]
    result = v.validate_json(deep, "observation_schema")
    assert isinstance(result, list) and result
    assert any("too deep" in m for m in result)


def test_event_observation_rejects_children():
    """#122/#121: backend forbids children on event observations
    (ObservationPayload.validate_observation); the ingest contract must too."""
    v = _v()
    event_with_children = {
        "id": "e", "type": "event", "name": "n",
        "children": [{"id": "c", "type": "span", "name": "child"}],
    }
    assert v.validate_json(_ingest(observations=[event_with_children]), "observability_ingest_request_schema")
    # event with no children, and non-event with children, are both fine
    event_empty = {"id": "e", "type": "event", "name": "n", "children": []}
    span_children = {"id": "s", "type": "span", "name": "n",
                     "children": [{"id": "c", "type": "span", "name": "child"}]}
    assert v.validate_json(_ingest(observations=[event_empty]), "observability_ingest_request_schema") == []
    assert v.validate_json(_ingest(observations=[span_children]), "observability_ingest_request_schema") == []


def test_session_ingest_forbids_read_only_rollup_fields():
    """Ingest session payload mirrors BE SessionPayload (extra=forbid): no rollups."""
    v = _v()
    sess = {"id": "s1", "user_id": "u"}
    assert v.validate_json(_ingest(session_id="s1", session=sess), "observability_ingest_request_schema") == []
    # trace_count is a read-only rollup, not an ingest field
    bad = {"id": "s1", "trace_count": 5}
    assert v.validate_json(_ingest(session_id="s1", session=bad), "observability_ingest_request_schema")
