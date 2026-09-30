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
CONTRACT_SHA256 = "6515d3e0c8c7a758189bfd156fc18362df9ad492ec5db35b817b62f6263da962"


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
            if not isinstance(value, int) or value < 0:
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
        if fb["if_present"] in attributes:
            return fb["type"]
    return m["default"]


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
        lambda c: c["observation_type_mapping"]["explicit_attribute"]["allowed_values"].append("llm")
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
