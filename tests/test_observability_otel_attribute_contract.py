# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Validation of traigent_schema/data/observability/otel_attribute_contract_v1.json.

The contract is vendored by the Backend OTLP receiver and the SDK exporters, each
pinning its sha256. This test checks structure, internal consistency, and executes
the precedence vectors with a tiny reference resolver; negative controls prove the
validator rejects broken copies.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from traigent_schema.utils import get_schemas_dir

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = (
    ROOT / "traigent_schema" / "data" / "observability" / "otel_attribute_contract_v1.json"
)
PROVENANCE = ROOT / "docs" / "observability" / "otel_attribute_contract_v1.md"
# Consumers pin this. Changing the contract means bumping it here deliberately.
CONTRACT_SHA256 = "0ce328a0cd9c9206573b34fdd5b63cf79897e132ce88d6f915fea6101b9b6900"


def _load() -> dict:
    return json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def _observation_types() -> set[str]:
    schema = json.loads(
        (get_schemas_dir() / "observability" / "observation_ingest_schema.json").read_text("utf-8")
    )
    return set(schema["definitions"]["_ObservationType"]["enum"])


def resolve(contract: dict, field: str, attributes: dict):
    """Reference precedence resolver: first present, valid value wins."""
    for name in contract["precedence"]["fields"][field]:
        if name not in attributes:
            continue
        value = attributes[name]
        if isinstance(value, bool):
            continue
        if field.startswith("usage_"):
            spec = contract["metadata_allowlist"]["attributes"][name]
            if not isinstance(value, int) or not spec["minimum"] <= value <= spec["maximum"]:
                continue
        elif not isinstance(value, str) or not value:
            continue
        return value
    return None


def map_observation_type(contract: dict, attributes: dict) -> str:
    """Reference mapper: explicit traigent.observation_type (valid enum member) wins."""
    m = contract["observation_type_mapping"]
    ex = m["explicit_attribute"]
    explicit = attributes.get(ex["name"])
    if isinstance(explicit, str) and explicit in ex["allowed_values"]:
        return explicit
    op = attributes.get("gen_ai.operation.name")
    if isinstance(op, str) and op in m["gen_ai_operation_name"]:
        return m["gen_ai_operation_name"][op]
    kind = attributes.get("openinference.span.kind")
    if isinstance(kind, str) and kind in m["openinference_span_kind"]:
        return m["openinference_span_kind"][kind]
    for fb in m["fallback_attributes"]:
        value = attributes.get(fb["if_present"])
        if isinstance(value, str) and value:
            return fb["type"]
    return m["default"]


def resolve_content_mode(contract: dict, configured: str, declared: dict) -> str:
    """Reference resolver: absent inherits, invalid fails closed, valid never loosens."""
    cm = contract["content_mode"]
    if not declared["present"]:
        return configured
    value = declared.get("value")
    if not isinstance(value, str) or value not in cm["values"]:
        return cm["default_when_missing_invalid_or_conflicting"]
    order = cm["restrictiveness_order_most_to_least"]
    return order[min(order.index(configured), order.index(value))]


def normalise_usage(contract: dict, vector: dict) -> dict:
    """Reference normaliser: inclusive wire usage to canonical disjoint buckets, once.

    Absent counters default to 0 for arithmetic but are reported in
    unreported_usage_fields; an invalid semantics marker is UNKNOWN (inclusive upper bound).
    """
    marker = contract["usage_classes"]["semantics_marker"]
    semantics = vector.get("semantics")
    unreported: list[str] = []
    if semantics is None:
        semantics = marker["default_when_absent"]
    elif semantics not in marker["values"]:
        semantics = "inclusive"
        unreported = ["cache_read_tokens", "cache_creation_tokens"]
    for key, name in (("cache_read", "cache_read_tokens"), ("cache_write", "cache_creation_tokens")):
        if vector.get(key) is None and name not in unreported:
            unreported.append(name)
    cr, cw, rs = vector.get("cache_read") or 0, vector.get("cache_write") or 0, vector.get("reasoning") or 0
    inp, out = vector["input"], vector["output"]
    if semantics == "inclusive":
        fresh = inp - cr - cw
        total_out = out
        if fresh < 0 or rs > total_out:
            fresh = None
    else:
        fresh = inp
        total_out = out + rs
    return {
        "input_fresh": fresh,
        "cache_read": cr,
        "cache_write": cw,
        "output_total": total_out,
        "reasoning": rs,
        "unreported_usage_fields": unreported,
    }


def validate_contract(c: dict) -> list[str]:
    errs: list[str] = []
    if c.get("contract_version") != 1:
        errs.append("contract_version must be 1")
    cm = c["content_mode"]
    if cm["default_when_missing_invalid_or_conflicting"] != "metadata":
        errs.append("default mode must be metadata")
    if cm["declaration_grants_permission"] is not False:
        errs.append("declaration must never grant permission")
    if cm["receiver_stores_content"] is not False:
        errs.append("receiver must not store content this round")
    if set(cm["values"]) != {"metadata", "redacted", "record"}:
        errs.append("mode values")
    allow = c["metadata_allowlist"]["attributes"]
    for name in allow:
        if "*" in name:
            errs.append(f"wildcard in allowlist: {name}")
    ck = c["content_keys"]
    for name in allow:
        prefixed = name not in ck["prefix_exceptions"] and any(
            name.startswith(p) for p in ck["prefixes"]
        )
        if name in ck["exact"] or prefixed:
            errs.append(f"allowlisted key is content-bearing: {name}")
    if set(c["usage_classes"]["classes"]) != {
        "input",
        "cache_read",
        "cache_write",
        "reasoning",
        "output",
    }:
        errs.append("usage classes")
    if set(c["usage_classes"]["attributes"]) != set(c["usage_classes"]["classes"]):
        errs.append("usage attribute classes mismatch")
    if c["usage_classes"].get("wire_semantics") != "inclusive":
        errs.append("usage wire semantics must be inclusive")
    usage_keys = {k for names in c["usage_classes"]["attributes"].values() for k in names}
    usage_keys |= set(c["usage_classes"]["total_tokens"])
    for k in sorted(usage_keys):
        spec = allow.get(k)
        if spec is None:
            errs.append(f"usage key missing from metadata egress set: {k}")
        elif (
            spec.get("type") != "non_negative_integer"
            or "minimum" not in spec
            or "maximum" not in spec
        ):
            errs.append(f"usage key must be a bounded non_negative_integer: {k}")
    marker = c["usage_classes"].get("semantics_marker", {})
    if marker.get("attribute") not in allow:
        errs.append("usage semantics marker must be in the metadata egress set")
    if c["content_mode"]["resource_attribute"] not in allow:
        errs.append("content mode declaration must be in the metadata egress set")
    for name, spec in allow.items():
        if "type" not in spec:
            errs.append(f"egress entry without type: {name}")
    types = _observation_types()
    m = c["observation_type_mapping"]
    targets = set(m["gen_ai_operation_name"].values()) | set(m["openinference_span_kind"].values())
    targets |= {f["type"] for f in m["fallback_attributes"]} | {m["default"]}
    if not targets <= types:
        errs.append(f"unknown observation types: {sorted(targets - types)}")
    ex = m["explicit_attribute"]
    if ex["name"] != "traigent.observation_type" or m["evaluation_order"][0] != ex["name"]:
        errs.append("explicit observation type must be first in evaluation_order")
    if set(ex["allowed_values"]) != types:
        errs.append("explicit allowed_values must equal the ingest schema observation types")
    if ex["name"] not in allow:
        errs.append("explicit observation type attribute must be allowlisted metadata")
    for src in c["sources"]:
        if not src.get("url", "").startswith("https://") or not src.get("purpose"):
            errs.append("source provenance incomplete")
    return errs


def test_contract_is_valid():
    assert validate_contract(_load()) == []


def test_contract_digest_is_pinned():
    digest = hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest()
    assert digest == CONTRACT_SHA256, f"update CONTRACT_SHA256 and notify consumers: {digest}"


@pytest.mark.parametrize("vector", _load()["precedence"]["vectors"], ids=lambda v: v["id"])
def test_precedence_vectors(vector):
    assert resolve(_load(), vector["field"], vector["attributes"]) == vector["expected"]


@pytest.mark.parametrize(
    "vector", _load()["observation_type_mapping"]["vectors"], ids=lambda v: v["id"]
)
def test_observation_type_vectors(vector):
    assert map_observation_type(_load(), vector["attributes"]) == vector["expected"]


@pytest.mark.parametrize(
    "vector", _load()["content_mode"]["resolution_vectors"], ids=lambda v: v["id"]
)
def test_content_mode_resolution_vectors(vector):
    got = resolve_content_mode(_load(), vector["configured"], vector["declared"])
    assert got == vector["expected"]


@pytest.mark.parametrize(
    "vector", _load()["usage_classes"]["normalisation_vectors"], ids=lambda v: v["id"]
)
def test_usage_normalisation_vectors(vector):
    assert normalise_usage(_load(), vector) == vector["expected"]


def test_inclusive_and_disjoint_representations_agree():
    c = _load()
    vecs = {v["id"]: v for v in c["usage_classes"]["normalisation_vectors"]}
    a = normalise_usage(c, vecs["inclusive_cache_read_subtracted"])
    b = normalise_usage(c, vecs["disjoint_same_usage_same_result"])
    assert (
        a
        == b
        == {
            "input_fresh": 60,
            "cache_read": 40,
            "cache_write": 0,
            "output_total": 50,
            "reasoning": 0,
            "unreported_usage_fields": [],
        }
    )


def test_omitted_and_explicit_zero_share_arithmetic_but_only_omitted_is_unreported():
    c = _load()
    vecs = {v["id"]: v for v in c["usage_classes"]["normalisation_vectors"]}
    omitted = normalise_usage(c, vecs["inclusive_cache_omitted_vs_explicit_zero_omitted"])
    explicit = normalise_usage(c, vecs["inclusive_cache_omitted_vs_explicit_zero_explicit"])
    assert {k: v for k, v in omitted.items() if k != "unreported_usage_fields"} == {
        k: v for k, v in explicit.items() if k != "unreported_usage_fields"
    }
    assert omitted["unreported_usage_fields"] == ["cache_read_tokens"]
    assert explicit["unreported_usage_fields"] == []


def test_unreported_vocabulary_is_the_common_types_enum():
    common = json.loads((get_schemas_dir() / "common_types_schema.json").read_text("utf-8"))
    vocab = set(common["definitions"]["UnreportedUsageFields"]["items"]["enum"])
    for v in _load()["usage_classes"]["normalisation_vectors"]:
        assert set(v["expected"]["unreported_usage_fields"]) <= vocab


def test_nc_invalid_semantics_silently_valid_changes_vector_result():
    c = _load()
    vec = next(
        v for v in c["usage_classes"]["normalisation_vectors"]
        if v["id"] == "invalid_semantics_is_unknown_inclusive"
    )
    silent = dict(vec, semantics="inclusive")
    assert normalise_usage(c, silent) != vec["expected"]


def test_nc_bounds_after_precedence_changes_vector_result():
    c = copy.deepcopy(_load())
    for spec in c["metadata_allowlist"]["attributes"].values():
        spec.pop("maximum", None)
        spec["maximum"] = 10**30  # simulates applying no bound before precedence
    vec = next(v for v in c["precedence"]["vectors"] if v["id"] == "over_max_first_alias_skipped")
    assert resolve(c, vec["field"], vec["attributes"]) != vec["expected"]


def test_content_mode_vectors_cover_absent_invalid_and_each_valid_value():
    c = _load()
    vecs = c["content_mode"]["resolution_vectors"]
    assert any(not v["declared"]["present"] for v in vecs)
    for mode in c["content_mode"]["values"]:
        assert any(v["declared"].get("value") == mode for v in vecs)
    invalid = [
        v
        for v in vecs
        if v["declared"]["present"] and v["declared"]["value"] not in c["content_mode"]["values"]
    ]
    assert {type(v["declared"]["value"]).__name__ for v in invalid} >= {
        "str",
        "NoneType",
        "int",
        "bool",
    }
    assert all(v["expected"] == "metadata" for v in invalid)


def test_fallback_vectors_cover_null_empty_boolean_number():
    ids = {v["id"] for v in _load()["observation_type_mapping"]["vectors"]}
    assert {
        "fallback_null_falls_through",
        "fallback_empty_string_falls_through",
        "fallback_boolean_falls_through",
        "fallback_number_falls_through",
    } <= ids


def test_every_precedence_field_has_a_vector():
    c = _load()
    covered = {v["field"] for v in c["precedence"]["vectors"]}
    assert {"model_name", "session_id", "usage_input", "provider", "environment"} <= covered


def test_provenance_doc_lists_every_source_url():
    text = PROVENANCE.read_text(encoding="utf-8")
    for src in _load()["sources"]:
        assert src["url"] in text


# ---- negative controls: each mutation must be caught -------------------------------


def _mut(fn):
    c = copy.deepcopy(_load())
    fn(c)
    return validate_contract(c)


def test_nc_wildcard_allowlist_entry_rejected():
    assert _mut(
        lambda c: c["metadata_allowlist"]["attributes"].update({"traigent.*": {"type": "string"}})
    )


def test_nc_content_key_in_allowlist_rejected():
    assert _mut(
        lambda c: c["metadata_allowlist"]["attributes"].update({"input.value": {"type": "string"}})
    )


def test_nc_dropping_prefix_exception_flags_prompt_name():
    assert _mut(lambda c: c["content_keys"].update({"prefix_exceptions": []}))


def test_nc_default_mode_record_rejected():
    assert _mut(
        lambda c: c["content_mode"].update(
            {"default_when_missing_invalid_or_conflicting": "record"}
        )
    )


def test_nc_declaration_grants_permission_rejected():
    assert _mut(lambda c: c["content_mode"].update({"declaration_grants_permission": True}))


def test_nc_unknown_observation_type_rejected():
    assert _mut(
        lambda c: c["observation_type_mapping"]["gen_ai_operation_name"].update({"chat": "llm"})
    )


def test_nc_missing_usage_class_rejected():
    def m(c):
        del c["usage_classes"]["attributes"]["reasoning"]
        c["usage_classes"]["classes"].remove("reasoning")

    assert _mut(m)


def test_nc_swapped_precedence_changes_vector_result():
    c = copy.deepcopy(_load())
    c["precedence"]["fields"]["model_name"].reverse()
    vec = next(
        v for v in c["precedence"]["vectors"] if v["id"] == "genai_beats_openinference_model"
    )
    assert resolve(c, vec["field"], vec["attributes"]) != vec["expected"]


def test_nc_explicit_allowed_values_drift_rejected():
    assert _mut(
        lambda c: c["observation_type_mapping"]["explicit_attribute"]["allowed_values"].append(
            "llm"
        )
    )


def test_nc_explicit_not_first_rejected():
    assert _mut(lambda c: c["observation_type_mapping"]["evaluation_order"].reverse())


def test_nc_explicit_not_allowlisted_rejected():
    assert _mut(lambda c: c["metadata_allowlist"]["attributes"].pop("traigent.observation_type"))


def test_nc_explicit_losing_to_genai_changes_vector_result():
    c = copy.deepcopy(_load())
    c["observation_type_mapping"]["explicit_attribute"]["name"] = "traigent.other"
    vec = next(
        v
        for v in c["observation_type_mapping"]["vectors"]
        if v["id"] == "explicit_wins_over_genai_operation"
    )
    assert map_observation_type(c, vec["attributes"]) != vec["expected"]


def test_nc_usage_key_missing_from_egress_set_rejected():
    assert _mut(
        lambda c: c["metadata_allowlist"]["attributes"].pop(
            "llm.token_count.prompt_details.cache_read"
        )
    )


def test_nc_usage_key_wrong_type_rejected():
    assert _mut(
        lambda c: c["metadata_allowlist"]["attributes"]["gen_ai.usage.input_tokens"].update(
            {"type": "string"}
        )
    )


def test_nc_wire_semantics_disjoint_rejected():
    assert _mut(lambda c: c["usage_classes"].update({"wire_semantics": "disjoint"}))


def test_nc_invalid_declaration_not_failing_closed_changes_vector_result():
    c = copy.deepcopy(_load())
    c["content_mode"]["default_when_missing_invalid_or_conflicting"] = "record"
    vec = next(
        v
        for v in c["content_mode"]["resolution_vectors"]
        if v["id"] == "invalid_unknown_string_under_record"
    )
    assert resolve_content_mode(c, vec["configured"], vec["declared"]) != vec["expected"]


def test_nc_subtracting_twice_changes_vector_result():
    c = _load()
    vec = dict(
        next(
            v
            for v in c["usage_classes"]["normalisation_vectors"]
            if v["id"] == "disjoint_same_usage_same_result"
        )
    )
    vec["semantics"] = "inclusive"
    assert normalise_usage(c, vec) != vec["expected"]


def test_nc_presence_only_fallback_changes_vector_result():
    vec = next(
        v
        for v in _load()["observation_type_mapping"]["vectors"]
        if v["id"] == "fallback_null_falls_through"
    )
    assert any(
        fb["if_present"] in vec["attributes"]
        for fb in _load()["observation_type_mapping"]["fallback_attributes"]
    )
    assert vec["expected"] == "span"  # a presence-only check would return "generation"
