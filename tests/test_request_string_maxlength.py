"""#138: request/ingest string fields must be length-bounded (maxLength) — or
constrained by enum/format/$ref, or explicitly marked x-content. A CI lint so new
unbounded request strings cannot regress."""
import json

from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _request_schema_files():
    return sorted(
        p for p in S.rglob("*.json")
        if ("request" in p.name or "ingest" in p.name) and "_endpoints" not in p.name
    )


def _unbounded_strings(node, out, leaf="root"):
    if isinstance(node, dict):
        t = node.get("type")
        is_str = t == "string" or (isinstance(t, list) and "string" in t)
        if is_str and not (
            "maxLength" in node or "enum" in node or "format" in node
            or node.get("x-content") or "$ref" in node
        ):
            out.append(leaf)
        for k, v in node.items():
            if k in ("properties", "definitions", "patternProperties") and isinstance(v, dict):
                for pk, pv in v.items():
                    _unbounded_strings(pv, out, pk)
            elif k in ("items", "additionalProperties", "then", "else"):
                _unbounded_strings(v, out, "items" if k == "items" else leaf)
            elif k in ("oneOf", "anyOf", "allOf") and isinstance(v, list):
                for sv in v:
                    _unbounded_strings(sv, out, leaf)


def test_no_unbounded_request_string_fields():
    offenders = {}
    for f in _request_schema_files():
        with open(f, encoding="utf-8") as fh:
            out = []
            _unbounded_strings(json.load(fh), out)
            if out:
                offenders[f.name] = out
    assert not offenders, (
        "request/ingest string fields without maxLength/enum/format/$ref/x-content "
        f"(input-hardening gap, #138): {offenders}"
    )


def test_maxlength_bounds_are_generous_enough_for_common_payloads():
    """Sanity: bounds didn't introduce a false-rejection on realistic input."""
    from traigent_schema import SchemaValidator
    v = SchemaValidator(contract="backend")
    # a realistic login + a long-ish dataset description still validate
    assert v.validate_request("/api/v1/auth/login", "POST",
                              {"email": "u@example.test", "password": "p" * 64}) == []
    assert v.validate_request("/api/v1/datasets", "POST",
                              {"name": "ds", "type": "input-output", "label": "L",
                               "description": "x" * 2000}) == []
