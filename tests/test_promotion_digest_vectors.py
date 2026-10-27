# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Shared TRAIG-101 candidate-fingerprint vectors (TVL canonical JSON sha256).

``tests/data/promotion_digest_vectors.json`` is a byte-identical copy of the Python SDK's
``tests/fixtures/runtime/promotion_digest_vectors.json`` (sha256 pinned below). The
reference here is the tvl-spec ``canonical_json_digest`` convention, written from the
schema prose: sorted keys, indent 2, ASCII escaping, trailing LF, non-finite refused.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

_PATH = Path(__file__).parent / "data" / "promotion_digest_vectors.json"
_SOURCE_SHA256 = "2db38aaeb42b0fa8dc4cbfb960bd2a695a2d8b06b30c462b785d5c18540555f9"
_DATA: dict[str, Any] = json.loads(_PATH.read_text(encoding="utf-8"))


def _fingerprint(config: Any) -> str:
    text = json.dumps(config, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
    return hashlib.sha256((text + "\n").encode("ascii")).hexdigest()


def test_fixture_is_byte_identical_to_source() -> None:
    assert hashlib.sha256(_PATH.read_bytes()).hexdigest() == _SOURCE_SHA256


@pytest.mark.parametrize("vector", _DATA["fingerprints"], ids=lambda v: v["name"])
def test_fingerprint_vector(vector: dict[str, Any]) -> None:
    assert _fingerprint(vector["config"]) == vector["fingerprint"]


def test_key_order_does_not_change_fingerprint() -> None:
    by_name = {v["name"]: v["fingerprint"] for v in _DATA["fingerprints"]}
    assert by_name["key-order-a"] == by_name["key-order-b"]


def test_gate_fingerprints_reference_known_vectors() -> None:
    known = {v["fingerprint"] for v in _DATA["fingerprints"]}
    assert _DATA["gates"]
    assert all(g["fingerprint"] in known for g in _DATA["gates"])


@pytest.mark.parametrize("case", _DATA["gates"], ids=lambda c: c["name"])
def test_gate_result_digest_recomputes(case: dict[str, Any]) -> None:
    doc = _DATA["gate_document"]
    document = {
        "format": doc["format"],
        **{k: case[k] for k in ("contract_digest", "fingerprint", "legacy_decision", "monitors", "decision")},
    }
    assert _fingerprint(document) == case["gate_result_digest"]


def _load(name: str) -> dict[str, Any]:
    path = Path(__file__).parents[1] / "traigent_schema" / "schemas" / "execution" / name
    return json.loads(path.read_text(encoding="utf-8"))


def test_best_config_response_accepts_optional_best_config_id() -> None:
    schema = _load("best_config_response_schema.json")
    prop = schema["properties"]["best_config_id"]
    deploy_defs = _load("best_config_deploy_schema.json")["definitions"]
    deploy = deploy_defs["DeployPublishRequest"]["properties"]["best_config_id"]
    for key in ("type", "pattern", "minLength", "maxLength"):
        assert prop[key] == deploy[key]
    assert "best_config_id" not in schema["required"]
