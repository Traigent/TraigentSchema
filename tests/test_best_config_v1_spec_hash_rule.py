# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""The frozen legacy ``traigent.best_config.v1`` spec_hash rule and its vectors.

The Backend (v1 since #819) and the SDK (since #1022) hashed v1 specs with different
rules, so a real SDK publish raised an integrity error after the Backend had already
committed it. The rule is frozen once, here, in ``best_config_schema.json``
(``x-traigent-spec-hash``). ``tests/data/best_config_v1_spec_hash_vectors.json`` holds
language-neutral vectors produced by the Backend's implementation; the reference below
is written only from the schema text, and must reproduce every vector. Each consumer
vendors the vector file and runs its own implementation against it.

This is NOT the v2 rule: ``best_config_hash_contract_schema.json`` (fp2, domain
separation, complete spec) governs ``traigent.best_config.v2`` specs. Its
``hash_algorithm: "v1"`` names that contract's hash algorithm, not the legacy envelope.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.utils import get_schemas_dir

_SCHEMA = get_schemas_dir() / "optimization" / "best_config_schema.json"
_VECTORS = Path(__file__).parent / "data" / "best_config_v1_spec_hash_vectors.json"


def _rule() -> dict[str, Any]:
    return json.loads(_SCHEMA.read_text(encoding="utf-8"))["x-traigent-spec-hash"]


def _strip_validation(value: Any, excluded: frozenset[str]) -> Any:
    if isinstance(value, dict):
        return {k: _strip_validation(v, excluded) for k, v in value.items() if k not in excluded}
    if isinstance(value, list):
        return [_strip_validation(item, excluded) for item in value]
    return value


def _nfc(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_nfc(item) for item in value]
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", k): _nfc(v) for k, v in value.items()}
    return value


_MAX_JSON_DEPTH = 16


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("exceeds maximum JSON depth")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def _refusal_cases() -> list[dict[str, Any]]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))["refusal_cases"]


def _materialize(case: dict[str, Any]) -> dict[str, Any]:
    request = copy.deepcopy(case["request"])
    substitution = case.get("non_finite_substitution")
    if substitution:
        target = request
        for key in substitution["path"][:-1]:
            target = target[key]
        target[substitution["path"][-1]] = float(substitution["value"])
    return request


def _check_finite(value: Any) -> None:
    """Finiteness is checked over the ORIGINAL spec, before NFC and before validation exclusions."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("NaN and Infinity are refused")
    elif isinstance(value, dict):
        for item in value.values():
            _check_finite(item)
    elif isinstance(value, list):
        for item in value:
            _check_finite(item)


def reference_publish_ingress_check(spec: Any) -> None:
    """The extra refusal applies only to a NEW publish: object keys equal after NFC.

    The hash keeps last-wins.
    """
    if isinstance(spec, dict):
        seen: set[str] = set()
        for key, item in spec.items():
            normalized = unicodedata.normalize("NFC", key)
            if normalized in seen:
                raise ValueError("object keys collide after NFC")
            seen.add(normalized)
            reference_publish_ingress_check(item)
    elif isinstance(spec, list):
        for item in spec:
            reference_publish_ingress_check(item)


def reference_hashed_payload(
    spec: dict[str, Any], request_environment: str | None
) -> dict[str, Any]:
    """The payload that is serialized and digested, built only from the schema's rule text."""
    rule = _rule()
    excluded = frozenset(rule["validation_excluded_keys"])
    _check_finite(spec)
    _check_depth(spec)
    payload = _nfc(copy.deepcopy(spec))
    # Identifier normalization (after the NFC pass, so these two are NOT NFC-normalized).
    payload["config_id"] = spec["config_id"].strip()
    if spec.get("function_ref") is not None:
        payload["function_ref"] = spec["function_ref"].strip()
    environment = spec.get("environment")
    if environment is None:
        environment = request_environment if request_environment is not None else "default"
    payload["environment"] = environment.strip().lower()
    covered = {key: payload[key] for key in rule["covered_keys"] if key in payload}
    validation = covered.get("validation")
    if isinstance(validation, dict):
        cleaned = _strip_validation(validation, excluded)
        if cleaned:
            covered["validation"] = cleaned
        else:
            covered.pop("validation")
    return covered


def reference_canonical_json(payload: dict[str, Any]) -> str:
    options = _rule()["serialization"]
    return json.dumps(
        payload,
        ensure_ascii=options["ensure_ascii"],
        sort_keys=options["sort_keys"],
        separators=tuple(options["separators"]),
        allow_nan=options["allow_nan"],
    )


def reference_spec_hash(spec: dict[str, Any], request_environment: str | None = None) -> str:
    text = reference_canonical_json(reference_hashed_payload(spec, request_environment))
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cases() -> list[dict[str, Any]]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))["cases"]


def _historical_cases() -> list[dict[str, Any]]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))["historical_cases"]


def _ingress_refusal_cases() -> list[dict[str, Any]]:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))["ingress_refusal_cases"]


def test_schema_states_the_frozen_rule_and_scopes_it_to_the_legacy_envelope() -> None:
    rule = _rule()
    assert rule["applies_to"] == "traigent.best_config.v1"
    assert rule["covered_keys"] == [
        "schema_version",
        "config_id",
        "function_ref",
        "environment",
        "config",
        "validation",
    ]
    assert set(rule["excluded_keys"]) == {"provenance", "forward_compat"}
    assert set(rule["validation_excluded_keys"]) == {
        "guaranteed_selection",
        "certified_selection",
        "status",
        "deployable",
        "selected_config",
        "fallback_config",
        "certificate",
    }
    assert rule["digest_format"] == "sha256:<64 lowercase hex>"
    assert "traigent.best_config.v2" in rule["not_applicable_to"]
    assert "hash_algorithm" in rule["not_applicable_to"]
    assert rule["vectors"] == "tests/data/best_config_v1_spec_hash_vectors.json"


def test_v2_description_and_v1_rule_agree_that_only_v2_covers_provenance() -> None:
    v2 = json.loads((get_schemas_dir() / "optimization" / "best_config_v2_schema.json").read_text())
    assert "provenance" in v2["description"]
    assert "provenance" in _rule()["excluded_keys"]


@pytest.mark.parametrize("case", _cases() + _historical_cases(), ids=lambda c: c["name"])
def test_reference_reproduces_every_backend_vector(case: dict[str, Any]) -> None:
    request = case["request"]
    payload = reference_hashed_payload(request["spec"], request.get("environment"))
    assert payload == case["hashed_payload"]
    assert reference_canonical_json(payload) == case["canonical_json"]
    assert reference_spec_hash(request["spec"], request.get("environment")) == case["spec_hash"]


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_provenance_never_changes_the_hash(case: dict[str, Any]) -> None:
    spec = copy.deepcopy(case["request"]["spec"])
    environment = case["request"].get("environment")
    expected = reference_spec_hash(spec, environment)
    spec["provenance"] = {"source": "other", "published_at": "2030-01-01T00:00:00Z"}
    assert reference_spec_hash(spec, environment) == expected
    spec.pop("provenance")
    assert reference_spec_hash(spec, environment) == expected


def test_vectors_cover_every_mismatch_source() -> None:
    names = {case["name"] for case in _cases()}
    assert {
        "provenance_present",
        "provenance_absent_same_hash",
        "validation_nested_exclusions",
        "validation_ordinary_nested_status_is_dropped",
        "validation_empty_object_omitted",
        "validation_only_excluded_keys_omitted",
        "non_nfc_strings",
        "config_id_is_trimmed_not_nfc",
        "identifier_and_environment_normalized",
        "environment_from_request_envelope",
        "environment_defaults",
        "forward_compat_and_function_ref_absent",
        "number_forms",
    } <= names


@pytest.mark.parametrize("case", _refusal_cases(), ids=lambda c: c["name"])
def test_reference_refuses_every_refusal_case(case: dict[str, Any]) -> None:
    request = _materialize(case)
    with pytest.raises(ValueError):
        reference_spec_hash(request["spec"], request.get("environment"))


def test_refusal_cases_cover_non_finite_numbers_and_the_depth_boundary() -> None:
    names = {case["name"] for case in _refusal_cases()}
    assert {
        "nan_refused",
        "positive_infinity_refused",
        "negative_infinity_refused",
        "depth_boundary_refused",
        "nan_in_excluded_validation_member_refused",
        "non_finite_lost_to_nfc_collision_refused",
    } <= names


@pytest.mark.parametrize("case", _ingress_refusal_cases(), ids=lambda c: c["name"])
def test_publish_ingress_refuses_nfc_colliding_keys_but_the_hash_keeps_last_wins(
    case: dict[str, Any],
) -> None:
    spec = case["request"]["spec"]
    with pytest.raises(ValueError):
        reference_publish_ingress_check(spec)
    # The frozen hash rule is unchanged: a stored spec with such keys still verifies.
    assert reference_spec_hash(spec, case["request"].get("environment")).startswith("sha256:")


def test_every_historical_and_ordinary_case_passes_the_publish_ingress_check_or_is_historical() -> (
    None
):
    for case in _cases():
        reference_publish_ingress_check(case["request"]["spec"])
    for case in _historical_cases():
        with pytest.raises(ValueError):
            reference_publish_ingress_check(case["request"]["spec"])


def test_edge_case_vectors_pin_the_frozen_behaviour() -> None:
    by_name = {case["name"]: case for case in _cases() + _historical_cases()}
    # NFC-colliding keys collapse; the later key in document order wins; order matters.
    forward = by_name["nfc_colliding_keys_last_wins"]["hashed_payload"]["config"]
    reverse = by_name["nfc_colliding_keys_last_wins_reversed"]["hashed_payload"]["config"]
    assert forward == {"\u00e9": 2} and reverse == {"\u00e9": 1}
    assert (
        by_name["nfc_colliding_keys_last_wins"]["spec_hash"]
        != by_name["nfc_colliding_keys_last_wins_reversed"]["spec_hash"]
    )
    # -0.0 and 0.0, and 1 and 1.0 at the same position, are different digests.
    assert '"x":-0.0' in by_name["negative_zero"]["canonical_json"]
    assert (
        by_name["negative_zero"]["spec_hash"]
        != by_name["positive_zero_distinct_from_negative_zero"]["spec_hash"]
    )
    assert '"x":[1]' in by_name["array_integer_one"]["canonical_json"]
    assert '"x":[1.0]' in by_name["array_float_one_distinct_from_integer"]["canonical_json"]
    assert (
        by_name["array_integer_one"]["spec_hash"]
        != by_name["array_float_one_distinct_from_integer"]["spec_hash"]
    )
    assert "depth_boundary_accepted" in by_name


def test_publish_request_refusal_wording_does_not_promise_more_than_the_backend_does() -> None:
    """The ingress "no echo" promise covers exactly what is implemented (sol F1c P3).

    The collision detector's own message is fixed; the protected path maps every refusal
    to the closed ``head_body_invalid`` response; the legacy path keeps its legacy
    validation envelope, whose text may carry field paths (e.g. a NaN under
    ``spec.config.<key>``), because schema validation runs before collision detection.
    A blanket "the refusal never echoes keys or values" is therefore not promised.
    """
    schema = json.loads(
        (get_schemas_dir() / "execution" / "best_config_publish_request_schema.json").read_text()
    )
    description = " ".join(schema["description"].split())
    assert "never echoes keys or values" not in description
    assert "collision check's own message is fixed" in description
    assert "protected path: every refusal is the closed head_body_invalid 400" in description
    assert (
        "legacy path: the legacy validation 400, whose text may include field paths" in description
    )
