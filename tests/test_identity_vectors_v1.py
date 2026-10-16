# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Validation of traigent_schema/data/identity/identity_vectors_v1.json (guard G1).

The vectors are consumed by the Python SDK, the JS SDK and the Backend, each pinning the
sha256 below. This test checks structure, the closed sets, id uniqueness, and executes every
vector against a tiny reference implementation of the published rules so a wrong expected
value cannot ship.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "traigent_schema" / "data" / "identity"
VECTORS_PATH = DATA_DIR / "identity_vectors_v1.json"
SCHEMA_PATH = DATA_DIR / "identity_vectors_v1.schema.json"
# Consumers pin this. Changing the vectors means bumping it here deliberately.
VECTORS_SHA256 = "294814bec6a947b3c32cc4ec1c438b16f2c3fdcca815adb4883258ac7f0ff4d4"

REASONS = {
    "attributed",
    "conflict",
    "ineligible",
    "open_scope",
    "incomplete",
    "evidence_unavailable",
}
ENV_MAX = 64
# Python SDK _KNOWN_ENVIRONMENT_NAMES, traigent/utils/env_config.py:227 @d33cc24cd (origin/develop).
KNOWN_ENV_LABELS = {
    "prod",
    "production",
    "dev",
    "development",
    "local",
    "test",
    "testing",
    "stage",
    "staging",
    "ci",
}


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


# --- reference rules -------------------------------------------------------------------


def py_registration(func_name, objectives, knobs, max_knobs=4, max_total=120):
    """traigent/api/decorators.py:_build_default_experiment_name @cccae9c0."""
    obj = f"[{','.join(objectives)}]" if objectives is not None else ""
    knob = ""
    if knobs:
        if len(knobs) > max_knobs:
            knob = f"[{','.join(knobs[:max_knobs])},...]"
        else:
            knob = f"[{','.join(knobs)}]"
    suffix = obj + knob
    budget = max_total - len(suffix)
    if budget <= 0:
        if len(suffix) <= max_total:
            return suffix
        if knobs:
            combined = obj + f"[{knobs[0]}]"
            if len(combined) <= max_total:
                return combined
        return obj[:max_total]
    if len(func_name) <= budget:
        part = func_name
    elif budget >= 2:
        part = func_name[: budget - 1] + "~"
    else:
        part = func_name[:budget]
    return part + suffix


def backend_agent_key(name: str) -> str:
    """Reference implementation of the Backend registration key rule (see sources.backend_agent_key_rule)."""
    raw = str(name or "")
    printable = "".join(c for c in raw if c.isprintable() or c.isspace())
    text = re.sub(r"\s+", " ", printable.strip()) or "traigent_function"
    if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", text):
        return text
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-")[: 128 - 10 - 1] or "agent"
    return f"{slug}-{digest}"


def js_derive(name):
    """Reference implementation of the JS SDK deriveFunctionName rule (see sources.js_registration_rule)."""
    if not isinstance(name, str):
        return None
    derived = name.strip()
    while derived.startswith("bound "):
        derived = derived[len("bound ") :].strip()
    if derived and derived not in ("bound", "anonymous"):
        return derived
    return None


def provenance_outcome(inp: dict) -> dict:
    sdk = inp["sdk"]
    fn = inp.get("function_name")
    if inp["sdk"] == "python" and fn is None:
        return {"outcome": "unsupported", "error": "not_decoratable", "trace_agent_id": None}
    if sdk == "python":
        named = inp.get("agent_name") or inp.get("experiment_name_env")
        if named:
            reg, prov = named, "user_named"
        else:
            reg = (
                None
                if fn is None
                else py_registration(fn, inp.get("objectives") or ["accuracy"], inp.get("knobs"))
            )
            anonymous = fn is None or "<" in fn
            prov = "ineligible" if anonymous else "function_derived"
        warning_mismatch = False
    else:
        agent_name = inp.get("agent_name")
        if agent_name is not None:
            reg = agent_name.strip()
        else:
            reg = js_derive(fn) or "anonymous_js_trial"
        manifest = inp.get("manifest_agent_id")
        if agent_name is not None or manifest is not None:
            prov = "user_named"
        elif reg == "anonymous_js_trial":
            prov = "ineligible"
        else:
            prov = "function_derived"
        warning_mismatch = manifest is not None and manifest != reg
    warning = None
    if warning_mismatch:
        warning = "manifest_registration_mismatch"
    elif prov == "ineligible":
        warning = "anonymous_registration"
    out = {
        "registration_identity": reg,
        "provenance": prov,
        "trace_agent_id": backend_agent_key(reg) if prov == "function_derived" else None,
        "local_warning": warning,
    }
    if reg is not None:
        out["backend_agent_key"] = backend_agent_key(reg)
    return out


def attribution_outcome(inp: dict) -> dict:
    if "snapshots" in inp:
        stored = None
        seen_end = False
        for snap in inp["snapshots"]:
            if snap["has_incoming_end_time"]:
                seen_end = True
                stored = snap["agent_id"]
            else:
                stored = None
        if not seen_end:
            return {"attributed_to": None, "reason": "incomplete"}
        if stored is not None:
            return {"attributed_to": stored, "reason": "attributed"}
        final_had_identity = any(
            s["has_incoming_end_time"] and s["agent_id"] for s in inp["snapshots"]
        )
        return {
            "attributed_to": None,
            "reason": "incomplete" if final_had_identity else "ineligible",
        }
    if inp["transport"] == "native":
        if "legacy_trace_level_agent_id" in inp:
            return {"attributed_to": inp["legacy_trace_level_agent_id"], "reason": "attributed"}
        scopes = inp["scopes"]
        if not scopes or any(s["provenance"] != "function_derived" for s in scopes):
            return {"attributed_to": None, "reason": "ineligible"}
        if not inp["final_snapshot_delivered"]:
            return {"attributed_to": None, "reason": "incomplete"}
        if len({s["key"] for s in scopes}) > 1:
            return {"attributed_to": None, "reason": "conflict"}
        if any(s["state_at_finalization"] == "open" for s in scopes):
            return {"attributed_to": None, "reason": "open_scope"}
        return {"attributed_to": scopes[0]["key"], "reason": "attributed"}
    spans = [s for batch in inp["deliveries"] for s in batch]
    if not inp["metadata_readable"]:
        return {"attributed_to": None, "reason": "evidence_unavailable"}
    labels = {s["agent_id"] for s in spans if s["agent_id"] is not None}
    if len(labels) > 1:
        return {"attributed_to": None, "reason": "conflict"}
    if any(s["agent_id"] is None for s in spans) or not labels:
        return {"attributed_to": None, "reason": "incomplete"}
    result = {"attributed_to": next(iter(labels)), "reason": "attributed"}
    if inp.get("window_recorded"):
        result["late_after_record"] = sum(len(b) for b in inp.get("late_deliveries", []))
    return result


def resolve_environment(inp: dict) -> dict:
    env = inp["env"]
    explicit = inp.get("explicit")
    rungs = []
    if explicit is not None and explicit.strip():
        value = explicit.strip().lower()
        if len(value) > ENV_MAX:
            return {
                "valid": False,
                "environment": None,
                "source": None,
                "warning": None,
                "error": "too_long",
            }
        return {"valid": True, "environment": value, "source": "explicit", "warning": None}
    if "TRAIGENT_ENVIRONMENT" in env:
        rungs.append(("traigent_environment", env["TRAIGENT_ENVIRONMENT"], None))
    for pair in env.get("OTEL_RESOURCE_ATTRIBUTES", "").split(","):
        key, _, value = pair.partition("=")
        if key.strip() == "deployment.environment.name":
            rungs.append(("otel_resource", value, None))
    if "ENVIRONMENT" in env:
        rungs.append(("environment", env["ENVIRONMENT"], None))
    if "TRAIGENT_ENV" in env:
        rungs.append(("traigent_env_legacy", env["TRAIGENT_ENV"], "legacy_env_var_deprecated"))
    ignored = False
    for source, raw, warning in rungs:
        value = raw.strip().lower()
        if value not in KNOWN_ENV_LABELS:
            ignored = True
            continue
        return {
            "valid": True,
            "environment": value,
            "source": source,
            "warning": "invalid_env_value_ignored" if ignored else warning,
        }
    return {
        "valid": True,
        "environment": "default",
        "source": "default",
        "warning": "invalid_env_value_ignored" if ignored else "undeclared_default",
    }


# --- tests -----------------------------------------------------------------------------


def test_schema_is_valid_and_vectors_conform():
    schema = _schema()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(_vectors()), key=str)
    assert not errors, errors[:3]


def test_contract_hash_pin():
    digest = hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest()
    assert digest == VECTORS_SHA256, (
        "identity_vectors_v1.json changed: bump VECTORS_SHA256 and tell every consumer to re-pin"
    )


def _all_vectors(doc):
    return doc["provenance"] + doc["trace_attribution"] + doc["environment"]


def test_ids_unique_and_rule_in_closed_set():
    ids = [v["id"] for v in _all_vectors(_vectors())]
    assert len(ids) == len(set(ids))
    allowed = set(_vectors()["closed_sets"]["rule"])
    assert all(v["rule"] in allowed for v in _all_vectors(_vectors()))
    assert {v["rule"] for v in _all_vectors(_vectors())} == allowed, "every rule id must be used"
    assert all(v["anchor"] == "consumer" for v in _all_vectors(_vectors()))


def test_closed_sets_match_schema_and_reasons():
    doc = _vectors()
    assert set(doc["closed_sets"]["attribution_reason"]) == REASONS
    used = {v["expected"]["reason"] for v in doc["trace_attribution"]}
    assert used <= REASONS
    assert used == REASONS, "every reason value must be exercised by at least one vector"


def test_known_environment_labels_closed_set_matches_reference():
    assert set(_vectors()["closed_sets"]["known_environment_labels"]) == KNOWN_ENV_LABELS


def test_every_environment_value_is_within_limit():
    for v in _vectors()["environment"]:
        value = v["expected"]["environment"]
        assert value is None or len(value) <= ENV_MAX
        if v["expected"]["valid"]:
            assert value is not None and value == value.strip().lower()


def test_required_cases_present():
    doc = _vectors()
    env_values = {v["expected"]["environment"] for v in doc["environment"]}
    assert "team/eu" in env_values
    assert any(not v["expected"]["valid"] for v in doc["environment"])
    assert any("snapshots" in v["input"] for v in doc["trace_attribution"])
    for v in doc["provenance"]:
        if v["expected"].get("provenance") == "function_derived":
            assert v["expected"]["trace_agent_id"] == v["expected"]["backend_agent_key"]
    sources = {v["expected"]["source"] for v in doc["environment"]}
    assert set(doc["closed_sets"]["environment_source"]) <= sources
    transports = {v["input"]["transport"] for v in doc["trace_attribution"]}
    assert transports == {"native", "otlp"}


@pytest.mark.parametrize("vector", _vectors()["provenance"], ids=lambda v: v["id"])
def test_provenance_vector_matches_reference(vector):
    assert provenance_outcome(vector["input"]) == vector["expected"]


@pytest.mark.parametrize("vector", _vectors()["trace_attribution"], ids=lambda v: v["id"])
def test_attribution_vector_matches_reference(vector):
    assert attribution_outcome(vector["input"]) == vector["expected"]


@pytest.mark.parametrize("vector", _vectors()["environment"], ids=lambda v: v["id"])
def test_environment_vector_matches_reference(vector):
    got = resolve_environment(vector["input"])
    assert got == {**{"warning": None}, **vector["expected"]}


def test_same_result_as_references_resolve_to_equal_expectations():
    by_id = {v["id"]: v for v in _vectors()["trace_attribution"]}
    refs = [v for v in by_id.values() if "same_result_as" in v["input"]]
    assert refs
    for v in refs:
        other = by_id[v["input"]["same_result_as"]]
        assert v["expected"] == other["expected"]
        flat = lambda x: sorted(  # noqa: E731
            (s["span_id"], s["agent_id"]) for b in x["input"]["deliveries"] for s in b
        )
        assert flat(v) == flat(other)


def test_negative_controls_are_rejected():
    schema = _schema()
    validator = Draft7Validator(schema)
    doc = _vectors()
    bad = copy.deepcopy(doc)
    bad["trace_attribution"][0]["expected"]["reason"] = "maybe"
    assert list(validator.iter_errors(bad))
    bad = copy.deepcopy(doc)
    bad["environment"][0]["expected"]["environment"] = "x" * 65
    assert list(validator.iter_errors(bad))
    bad = copy.deepcopy(doc)
    bad["provenance"][0]["expected"]["provenance"] = "guessed"
    assert list(validator.iter_errors(bad))
    bad = copy.deepcopy(doc)
    del bad["provenance"][0]["rule"]
    assert list(validator.iter_errors(bad))
    bad = copy.deepcopy(doc)
    bad["provenance"][0]["rule"] = "provenance.invented"
    assert list(validator.iter_errors(bad))


def test_reference_rules_detect_a_broken_expectation():
    vector = copy.deepcopy(_vectors()["provenance"][0])
    vector["expected"]["registration_identity"] += "x"
    assert provenance_outcome(vector["input"]) != vector["expected"]


def test_packaging_includes_identity_data():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'packages = ["traigent_schema"]' in pyproject  # wheel ships the whole package
    assert '"traigent_schema/**/*.json"' in pyproject  # sdist include glob
    package_root = ROOT / "traigent_schema"
    for path in (VECTORS_PATH, SCHEMA_PATH):
        assert package_root in path.parents and path.is_file()
