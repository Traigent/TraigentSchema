# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the v2 manifest and certificate-binding envelopes.

Separate from ``test_best_config_hash_contract.py`` so the digest rules and the
envelopes carrying them can fail independently and say which broke.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator, RefResolver

from traigent_schema.utils import get_schemas_dir

_OPTIMIZATION = get_schemas_dir() / "optimization"
_MANIFEST_V2 = _OPTIMIZATION / "best_config_manifest_v2_schema.json"
_CERT_DELTA = _OPTIMIZATION / "guarantee_certificate_v2_delta_schema.json"
_SUBJECT = _OPTIMIZATION / "certificate_subject_schema.json"
_DIGEST = "sha256:" + "a" * 64


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _valid_subject() -> dict[str, Any]:
    return {
        "hash_algorithm": "v1",
        "config_hash": _DIGEST,
        "config_id": "checkout-router",
        "function_ref": "app.routing:route",
        "environment": "production",
        "best_config_schema_version": "traigent.best_config.v2",
    }


def _schema_store(root: Path) -> dict[str, dict[str, Any]]:
    store: dict[str, dict[str, Any]] = {}
    for path in root.rglob("*.json"):
        schema = _load(path)
        store[path.as_uri()] = schema
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            store[schema_id] = schema
    return store


def _errors(schema_path: Path, payload: dict[str, Any]) -> list[str]:
    """Validate with the packaged closure, mirroring test_best_config_contract_closure.

    Remote refs are denied rather than fetched: a schema that silently reached the
    network would validate against something not shipped in the package.
    """
    schema = _load(schema_path)

    def _deny_remote(uri: str) -> None:
        raise AssertionError(f"schema ref escaped packaged closure: {uri}")

    resolver = RefResolver.from_schema(
        schema,
        store=_schema_store(get_schemas_dir()),
        handlers={"http": _deny_remote, "https": _deny_remote},
    )
    Draft7Validator.check_schema(schema)
    validator = Draft7Validator(schema, resolver=resolver)
    return [error.message for error in validator.iter_errors(payload)]


# --- manifest ---------------------------------------------------------------


def test_manifest_entry_requires_hash_algorithm_per_entry() -> None:
    """Per entry, not per manifest: entries are written independently over time."""
    entry = _load(_MANIFEST_V2)["definitions"]["manifest_entry"]

    assert "hash_algorithm" in entry["required"]
    assert entry["additionalProperties"] is False
    assert set(entry["required"]) == {
        "path",
        "spec_hash",
        "config_hash",
        "hash_algorithm",
    }


def test_manifest_rejects_traversing_and_absolute_paths() -> None:
    """A manifest entry names a sibling file; anything else is a read primitive."""
    pattern = _load(_MANIFEST_V2)["definitions"]["manifest_entry"]["properties"]["path"]
    import re

    forbidden = re.compile(pattern["not"]["pattern"])
    for bad in ("../secrets.json", "/etc/passwd", "C:\\win.ini", "a\\b", "a\x00b"):
        assert forbidden.search(bad), f"{bad!r} must be rejected"
    assert not forbidden.search("checkout-router.json")


def test_manifest_moves_exported_at_out_of_the_hashed_spec() -> None:
    """Export time is a fact about the manifest, not about the configuration."""
    manifest = _load(_MANIFEST_V2)
    assert "exported_at" in manifest["properties"]

    v2_spec = _load(_OPTIMIZATION / "best_config_v2_schema.json")
    assert "exported_at" not in v2_spec["properties"]["provenance"]["properties"]


# --- certificate binding ----------------------------------------------------


def test_certificate_v2_removes_the_circular_spec_hash_binding() -> None:
    delta = _load(_CERT_DELTA)

    assert "spec_hash" not in delta["properties"]
    assert delta["definitions"]["removed_in_v2"]["items"]["enum"] == ["spec_hash"]
    assert "subject" in delta["required"]


def test_certificate_v2_keeps_the_freshness_hooks_outside_the_subject() -> None:
    """Freshness asks a different question than 'what is this certificate about?'."""
    properties = _load(_CERT_DELTA)["properties"]
    subject_members = _load(_SUBJECT)["properties"]

    for hook in ("runtime_config_hash", "price_snapshot_hash"):
        assert hook in properties, f"{hook} must survive v2"
        assert hook not in subject_members


def test_v1_certificate_binding_fields_were_optional_and_nullable() -> None:
    """Records the weakness v2 fixes: an unbound certificate validated under v1."""
    v1 = _load(_OPTIMIZATION / "guarantee_certificate_schema.json")

    for field in ("spec_hash", "config_hash", "config_id"):
        assert field not in v1["required"]
        assert "null" in v1["properties"][field]["type"]


# --- subject validates as a real payload ------------------------------------


def test_valid_subject_passes_validation() -> None:
    assert _errors(_SUBJECT, _valid_subject()) == []


def test_subject_rejects_a_missing_member() -> None:
    """Every member required, so a subject cannot be silently under-specified."""
    for member in _valid_subject():
        payload = _valid_subject()
        del payload[member]
        assert _errors(_SUBJECT, payload), f"removing {member} must fail validation"


def test_subject_allows_explicit_null_function_ref_but_not_omission() -> None:
    """null asserts 'no function binding'; absence would be ambiguous."""
    payload = _valid_subject()
    payload["function_ref"] = None
    assert _errors(_SUBJECT, payload) == []

    del payload["function_ref"]
    assert _errors(_SUBJECT, payload)


def test_subject_rejects_a_malformed_function_ref() -> None:
    """function_ref, when non-null, must satisfy best_config_v2's pattern -- not any string."""
    payload = _valid_subject()
    payload["function_ref"] = "not a function ref at all"
    assert _errors(_SUBJECT, payload)


def test_subject_rejects_an_empty_function_ref() -> None:
    payload = _valid_subject()
    payload["function_ref"] = ""
    assert _errors(_SUBJECT, payload)


def test_subject_rejects_a_missing_function_ref_key_distinct_from_null() -> None:
    """absent must fail even though null passes -- the two are not interchangeable."""
    payload = _valid_subject()
    del payload["function_ref"]
    assert _errors(_SUBJECT, payload)


def test_subject_config_id_rejects_the_same_values_best_config_v2_rejects() -> None:
    """v2, certificate, and manifest reject the same invalid config IDs -- one shared definition."""
    for bad_config_id in ("", "a" * 129, "has/slash", "has\\backslash", "has\x00nul"):
        payload = _valid_subject()
        payload["config_id"] = bad_config_id
        assert _errors(_SUBJECT, payload), f"{bad_config_id!r} must be rejected"

    payload = _valid_subject()
    payload["config_id"] = "a" * 128
    assert _errors(_SUBJECT, payload) == []


def test_manifest_configs_key_rejects_the_same_config_ids_best_config_v2_rejects() -> None:
    """The manifest's propertyNames must reject exactly what best_config_v2's config_id rejects."""
    entry = {
        "path": "checkout-router.json",
        "spec_hash": _DIGEST,
        "config_hash": _DIGEST,
        "hash_algorithm": "v1",
    }
    for bad_config_id in ("", "a" * 129, "has/slash", "has\\backslash"):
        payload = {
            "schema_version": "traigent.best_config_manifest.v2",
            "configs": {bad_config_id: entry},
        }
        assert _errors(_MANIFEST_V2, payload), (
            f"{bad_config_id!r} must be rejected as a manifest key"
        )

    valid_payload = {
        "schema_version": "traigent.best_config_manifest.v2",
        "configs": {"checkout-router": entry},
    }
    assert _errors(_MANIFEST_V2, valid_payload) == []


def test_best_config_v2_config_id_rejects_the_same_values() -> None:
    """The v2 envelope itself must reject what the shared definition rejects."""
    v2_path = _OPTIMIZATION / "best_config_v2_schema.json"
    base_payload = {
        "schema_version": "traigent.best_config.v2",
        "config_id": "checkout-router",
        "config": {},
    }
    for bad_config_id in ("", "a" * 129, "has/slash"):
        payload = dict(base_payload)
        payload["config_id"] = bad_config_id
        assert _errors(v2_path, payload), f"{bad_config_id!r} must be rejected"

    assert _errors(v2_path, base_payload) == []


def _every_ref(node: Any) -> list[str]:
    """Collect every $ref pointer appearing anywhere in a schema document."""
    refs: list[str] = []
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for value in node.values():
            refs.extend(_every_ref(value))
    elif isinstance(node, list):
        for item in node:
            refs.extend(_every_ref(item))
    return refs


def test_packaged_schema_closure_resolves_every_ref_in_the_new_envelopes() -> None:
    """Every $ref from the config_id/function_ref hoist must resolve inside the shipped package.

    Walks the schema document directly and resolves each $ref pointer found,
    rather than relying on a payload happening to reach every branch (anyOf
    and definitions unreferenced by a chosen instance would otherwise go
    unchecked). A $ref pointing outside traigent_schema/schemas would
    resolve against something not shipped in the distributed package -- the
    same failure mode _errors() already guards against for remote http(s)
    refs during payload validation.
    """
    for schema_path in (
        _SUBJECT,
        _MANIFEST_V2,
        _OPTIMIZATION / "best_config_v2_schema.json",
        _OPTIMIZATION / "best_config_hash_contract_schema.json",
    ):
        schema = _load(schema_path)
        Draft7Validator.check_schema(schema)
        refs = _every_ref(schema)
        assert refs, f"{schema_path.name}: expected to find at least one $ref"

        resolver = RefResolver.from_schema(schema, store=_schema_store(get_schemas_dir()))
        for ref in refs:
            with resolver.resolving(ref) as resolved:
                assert resolved, f"{schema_path.name}: $ref {ref!r} resolved to nothing"


def test_subject_rejects_an_unknown_hash_algorithm() -> None:
    payload = _valid_subject()
    payload["hash_algorithm"] = "v0"
    assert _errors(_SUBJECT, payload)


def test_subject_rejects_a_v1_spec_version() -> None:
    """A subject issued against one envelope must not be replayable against another."""
    payload = _valid_subject()
    payload["best_config_schema_version"] = "traigent.best_config.v1"
    assert _errors(_SUBJECT, payload)


def test_subject_rejects_a_malformed_digest() -> None:
    payload = _valid_subject()
    payload["config_hash"] = "sha256:NOTHEX"
    assert _errors(_SUBJECT, payload)
