# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Known-answer vectors for the G1 client-local evidence construction.

Every vector in ``tests/data/client_evidence_kats.json`` is recomputed here from the
normative text in ``certification_common_v0_schema.json`` (``CommitmentSchemeV0``,
``DigestRoleDomainTagV0``) with an implementation written in this file: a minimal
RFC 8785 serializer for the float-free value subset, HMAC-SHA-256 and SHA-256 from the
standard library. It deliberately does not import ``traigent_schema.fp2`` or any SDK, so
the vectors cross-check independent implementations rather than restating one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

_ROOT = Path(__file__).resolve().parent
_VECTORS = json.loads((_ROOT / "data" / "client_evidence_kats.json").read_text("utf-8"))
_SCHEMAS = _ROOT.parent / "traigent_schema" / "schemas" / "certification"

_SLOT_DOMAIN = b"traigent.cert.v0.slot_commitment.v1"
_ROOT_DOMAIN = b"traigent.agent_certificate.client_evidence_manifest_root.v1"
_KINDS = ("agent_revision", "evaluation_dataset", "evaluator", "build_process_evidence")
_MAX_SAFE = 2**53 - 1


class Rejected(ValueError):
    """The construction refuses this input."""


def _jcs(value: Any) -> bytes:
    """RFC 8785 for the float-free subset: null, bool, int, str, list, dict."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, float):
        raise Rejected("float not allowed in a jcs_v1 preimage")
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE:
            raise Rejected("unsafe integer")
        return str(value).encode("ascii")
    if isinstance(value, str):
        return _jcs_string(value).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(_jcs(v) for v in value) + b"]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return (
            b"{"
            + b",".join(_jcs_string(k).encode("utf-8") + b":" + _jcs(value[k]) for k in keys)
            + b"}"
        )
    raise Rejected("unsupported type")


def _jcs_string(text: str) -> str:
    short = {
        '"': '\\"',
        "\\": "\\\\",
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
        "\b": "\\b",
        "\f": "\\f",
    }
    out = ['"']
    for ch in text:
        if ch in short:
            out.append(short[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def slot_commitment(blind: bytes, kind: str, document: Any) -> str:
    if len(blind) != 32:
        raise Rejected("blind must be exactly 32 bytes")
    if kind not in _KINDS:
        raise Rejected("unknown artifact_kind")
    data = _SLOT_DOMAIN + b"\x00" + kind.encode("utf-8") + b"\x00" + _jcs(document)
    return "sha256:" + hmac.new(blind, data, hashlib.sha256).hexdigest()


def manifest_of(digests: dict[str, str]) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "schema_version": "traigent.certificate_client_evidence_manifest.v0"
    }
    for kind in _KINDS:
        manifest[kind] = {
            "artifact_kind": kind,
            "commitment_scheme": "sha256_secret_blinded_v1",
            "slot_commitment_digest": digests[kind],
        }
    return manifest


def manifest_root(manifest: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_ROOT_DOMAIN + b"\x00" + _jcs(manifest)).hexdigest()


def _registry() -> Registry:
    resources = []
    for path in _SCHEMAS.rglob("*.json"):
        contents = json.loads(path.read_text("utf-8"))
        if isinstance(contents, dict) and "$id" in contents:
            resources.append((contents["$id"], Resource.from_contents(contents)))
    return Registry().with_resources(resources)


def _validator() -> Draft7Validator:
    schema = json.loads(
        (_SCHEMAS / "certificate_client_evidence_manifest_v0_schema.json").read_text("utf-8")
    )
    return Draft7Validator(schema, registry=_registry())


def test_vector_file_shape() -> None:
    assert _VECTORS["version"] == 1
    assert _VECTORS["slot_domain"] == _SLOT_DOMAIN.decode()
    assert _VECTORS["root_domain"] == _ROOT_DOMAIN.decode()
    assert len(_VECTORS["slot_cases"]) >= 8
    assert {c["artifact_kind"] for c in _VECTORS["slot_cases"]} == set(_KINDS)


@pytest.mark.parametrize("case", _VECTORS["slot_cases"], ids=lambda c: c["name"])
def test_slot_commitment_vector(case: dict[str, Any]) -> None:
    got = slot_commitment(
        bytes.fromhex(case["blind_hex"]), case["artifact_kind"], case["artifact_document"]
    )
    assert got == case["slot_commitment_digest"]
    assert _jcs(case["artifact_document"]).decode("utf-8") == case["jcs_utf8"]


@pytest.mark.parametrize("case", _VECTORS["manifests"], ids=lambda c: c["name"])
def test_manifest_vector(case: dict[str, Any]) -> None:
    digests = {}
    for kind in _KINDS:
        slot = case["slots"][kind]
        digests[kind] = slot_commitment(
            bytes.fromhex(slot["blind_hex"]), kind, slot["artifact_document"]
        )
        assert digests[kind] == slot["slot_commitment_digest"]
    manifest = manifest_of(digests)
    assert manifest == case["manifest"]
    assert manifest_root(manifest) == case["manifest_root_digest"]
    assert list(_validator().iter_errors(manifest)) == []


def test_build_process_evidence_document_vector() -> None:
    case = _VECTORS["build_process_evidence"]
    doc = case["artifact_document"]
    assert set(doc) == {"snapshot_format", "manifest_digest"}
    assert doc["snapshot_format"] == "tes1"
    assert doc["manifest_digest"].startswith("sha256:") and len(doc["manifest_digest"]) == 71
    assert _jcs(doc).decode("utf-8") == case["jcs_utf8"]
    full = _VECTORS["manifests"][0]["slots"]["build_process_evidence"]
    assert full["artifact_document"] == doc


@pytest.mark.parametrize("case", _VECTORS["negative_cases"], ids=lambda c: c["name"])
def test_negative_vector_rejected(case: dict[str, Any]) -> None:
    with pytest.raises(Rejected):
        slot_commitment(
            bytes.fromhex(case["blind_hex"]), case["artifact_kind"], case["artifact_document"]
        )


def test_tampering_any_slot_changes_root() -> None:
    case = _VECTORS["manifests"][0]
    digests = {k: case["slots"][k]["slot_commitment_digest"] for k in _KINDS}
    base = manifest_root(manifest_of(digests))
    assert base == case["manifest_root_digest"]
    for kind in _KINDS:
        tampered = dict(digests)
        tampered[kind] = "sha256:" + "0" * 64
        assert manifest_root(manifest_of(tampered)) != base


def test_blind_changes_commitment() -> None:
    case = _VECTORS["slot_cases"][0]
    other = bytes(32)
    assert (
        slot_commitment(other, case["artifact_kind"], case["artifact_document"])
        != case["slot_commitment_digest"]
    )


def test_manifest_schema_rejects_extra_and_malformed() -> None:
    case = _VECTORS["manifests"][0]["manifest"]
    bad = json.loads(json.dumps(case))
    bad["agent_revision"]["blind"] = "00"
    assert list(_validator().iter_errors(bad))
    bad = json.loads(json.dumps(case))
    bad["evaluator"]["slot_commitment_digest"] = "sha256:ABC"
    assert list(_validator().iter_errors(bad))
