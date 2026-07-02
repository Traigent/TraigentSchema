"""Cross-repo auth-taxonomy parity DETECTOR (#219) — non-blocking.

WHAT THIS IS
------------
``TraigentSchema`` declares the auth taxonomy (API-key scope/permission tokens,
the scope -> permission map, ResourceType, and the key-prefix vocabulary) and
marks it ``x-source-of-truth`` — but it is advisory only: no BE/SDK/FE module
imports the Schema enums, so each surface re-declares its own copy and drift
exists *by construction* (see Traigent/TraigentSchema#219).

This module makes that drift **mechanically visible and converging** WITHOUT
blocking PRs:

  * the Schema enums are read live from the JSON schemas (the source of truth);
  * the BE/SDK/FE constants are read from a CHECKED-IN snapshot
    (``tests/data/auth_taxonomy_surfaces.json``) because Schema CI cannot import
    BE Python / FE TypeScript at runtime — that fixture carries a documented
    regeneration pointer (repo + path + symbol + ref) for every value;
  * the detector COMPUTES the current drift from (Schema enums vs surfaces) and
    asserts every drift is covered by a row in the shrinking allowlist
    (``tests/data/auth_taxonomy_known_drift.yaml``);
  * a SHRINK assertion fails if drift grows beyond the allowlist OR a listed row
    is stale (so the manifest can only shrink, never silently grow);
  * setting ``SCHEMA_219_ENFORCE`` makes ANY remaining allowlist row fail — the
    switch a LATER issue flips to turn DETECT into ENFORCE.

This test is wired into CI as a NON-BLOCKING job (``.github/workflows/
auth-taxonomy-parity.yml`` with ``continue-on-error: true``); it is NOT part of
the required ``test`` job, and DETECT mode here is expected to PASS today
because every real drift is in the allowlist.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from traigent_schema import load_schema

VOCABULARY_SCHEMA = "api_key_authorization_vocabulary_schema"

_TESTS_DIR = Path(__file__).resolve().parent
_DATA_DIR = _TESTS_DIR / "data"
_SURFACES_PATH = _DATA_DIR / "auth_taxonomy_surfaces.json"
_KNOWN_DRIFT_PATH = _DATA_DIR / "auth_taxonomy_known_drift.yaml"

#: Canonical live-issuer prefix set. uk_=user, sk_=service, ak_=admin,
#: tk_=temporary (sk_ also issued for the device flow). Per #219 this is the set
#: every other prefix source is measured against; once Schema OWNS this set
#: (a later phase) it should be read from a schema enum instead of pinned here.
CANONICAL_KEY_PREFIXES: frozenset[str] = frozenset({"uk_", "sk_", "ak_", "tk_"})

#: Env toggle: when set (to anything non-empty), remaining allowlist rows fail
#: the test. This is how a follow-up issue flips DETECT -> ENFORCE.
ENFORCE_ENV = "SCHEMA_219_ENFORCE"


# --------------------------------------------------------------------------- #
# Fixture / manifest loading
# --------------------------------------------------------------------------- #
def _load_surfaces() -> dict[str, Any]:
    return json.loads(_SURFACES_PATH.read_text(encoding="utf-8"))


def _load_known_drift() -> list[dict[str, Any]]:
    manifest = yaml.safe_load(_KNOWN_DRIFT_PATH.read_text(encoding="utf-8"))
    return list(manifest.get("drifts", []))


# --------------------------------------------------------------------------- #
# Schema-side canonical vocabulary (the declared source of truth)
# --------------------------------------------------------------------------- #
def _schema_vocab() -> dict[str, Any]:
    return load_schema(VOCABULARY_SCHEMA)


def _schema_user_requestable_scopes() -> set[str]:
    return set(
        _schema_vocab()["definitions"]["UserRequestableApiKeyScopeToken"]["enum"]
    )


def _schema_permission_tokens() -> set[str]:
    return set(_schema_vocab()["definitions"]["ApiKeyPermissionToken"]["enum"])


def _schema_scope_permission_map() -> dict[str, set[str]]:
    """scope -> set(canonical permissions) from the Schema x-scope-permission-map."""
    raw = _schema_vocab()["x-scope-permission-map"]
    return {scope: set(meta["permissions"]) for scope, meta in raw.items()}


# --------------------------------------------------------------------------- #
# THE DETECTOR — compute current drift from (Schema enums vs surfaces fixture).
# Each detected drift is a (detector_key, human_description) pair. detector_key
# is the stable machine key the allowlist rows match on.
# --------------------------------------------------------------------------- #
def _detect_drift() -> dict[str, str]:
    surfaces = _load_surfaces()
    drift: dict[str, str] = {}

    be = surfaces["backend"]
    sdk = surfaces["sdk"]

    schema_scopes = _schema_user_requestable_scopes()
    schema_perms = _schema_permission_tokens()
    schema_map = _schema_scope_permission_map()

    # (#2) BE user-requestable scopes that Schema does not list.
    be_scopes = set(be["user_allowed_scopes"]["values"])
    for scope in sorted(be_scopes - schema_scopes):
        drift[f"backend.user_allowed_scopes.extra::{scope}"] = (
            f"BE USER_ALLOWED_SCOPES mints {scope!r}, absent from the Schema "
            f"UserRequestableApiKeyScopeToken enum"
        )

    # (#5/#6) BE scope -> permission map disagrees with Schema for shared scopes.
    # Only compare scopes present in BOTH maps so a missing-scope (e.g. harness:*)
    # is not double-counted here — it is already reported as a scope-extra drift.
    be_map = {
        scope: set(perms)
        for scope, perms in be["scope_permission_map"]["values"].items()
    }
    for scope in sorted(set(be_map) & set(schema_map)):
        if be_map[scope] != schema_map[scope]:
            drift[f"backend.scope_permission_map.mismatch::{scope}"] = (
                f"BE expands {scope!r} to {sorted(be_map[scope])}; "
                f"Schema maps it to {sorted(schema_map[scope])}"
            )

    # (#6) BE-emitted permission tokens not present in the Schema permission enum.
    be_emitted = set(be["emitted_permissions"]["values"])
    for perm in sorted(be_emitted - schema_perms):
        drift[f"backend.emitted_permissions.extra::{perm}"] = (
            f"BE emits permission {perm!r}, absent from the Schema "
            f"ApiKeyPermissionToken enum"
        )

    # (#12) BE carries two divergent ResourceType enums internally.
    rt = be["resource_types"]
    rt_unified = set(rt["unified_auth"]["values"])
    rt_api_key = set(rt["api_key_resource"]["values"])
    if rt_unified != rt_api_key:
        drift[
            "backend.resource_types.divergent::unified_auth-vs-api_key_resource"
        ] = (
            f"BE ResourceType enums diverge: unified_auth={sorted(rt_unified)} "
            f"!= api_key_resource={sorted(rt_api_key)}"
        )

    # (#1) Each API-key prefix SOURCE set that is not the canonical live set.
    prefix_sources: list[tuple[str, set[str]]] = [
        (
            "prefix.set.mismatch::backend.middleware_accepted",
            set(be["key_prefixes"]["middleware_accepted"]["values"]),
        ),
        (
            "prefix.set.mismatch::backend.config_default",
            set(be["key_prefixes"]["config_default"]["values"]),
        ),
        (
            "prefix.set.mismatch::sdk.validator_accepted",
            set(sdk["key_prefixes"]["validator_accepted"]["values"]),
        ),
        (
            "prefix.set.mismatch::schema.device_flow",
            _schema_device_flow_prefixes(),
        ),
    ]
    for key, prefixes in prefix_sources:
        if prefixes != set(CANONICAL_KEY_PREFIXES):
            extra = sorted(prefixes - set(CANONICAL_KEY_PREFIXES))
            missing = sorted(set(CANONICAL_KEY_PREFIXES) - prefixes)
            drift[key] = (
                f"prefix source {key.split('::', 1)[1]} = {sorted(prefixes)} "
                f"!= canonical {sorted(CANONICAL_KEY_PREFIXES)} "
                f"(extra={extra}, missing={missing})"
            )

    return drift


def _schema_device_flow_prefixes() -> set[str]:
    """The key prefix(es) the Schema device-flow success schema pins.

    Read live from the device-token success schema's ``api_key`` ``^<prefix>_``
    pattern so the detector measures Schema directly rather than a transcription.
    The Schema device flow returns only ``sk_``-prefixed keys (mismatch #1: only
    the device-flow path is consistent end-to-end).
    """
    device_schema = load_schema("device_token_success_schema")
    pattern = device_schema["properties"]["api_key"]["pattern"]
    # pattern looks like "^sk_[A-Za-z0-9._-]{20,}$" -> prefix is between ^ and [/(
    body = pattern.lstrip("^")
    prefix = body.split("[", 1)[0].split("(", 1)[0]
    assert prefix.endswith("_"), f"unexpected device-flow key pattern: {pattern!r}"
    return {prefix}


# --------------------------------------------------------------------------- #
# (b) DETECTOR — passes when every detected drift is covered by an allowlist row.
# --------------------------------------------------------------------------- #
def test_detected_drift_is_covered_by_allowlist() -> None:
    detected = _detect_drift()
    allow = {row["detector_key"] for row in _load_known_drift()}

    uncovered = sorted(set(detected) - allow)
    assert not uncovered, (
        "Auth-taxonomy drift detected that is NOT in the allowlist "
        "(tests/data/auth_taxonomy_known_drift.yaml). Either reconcile the "
        "surfaces or, if this is a known/accepted divergence, add a row with an "
        "owner + phase_issue + remove_by: 'Schema#219-enforce'.\n"
        + "\n".join(f"  - {k}: {detected[k]}" for k in uncovered)
    )


# --------------------------------------------------------------------------- #
# (c) SHRINK assertion — the manifest can only shrink:
#   * fails if any allowlist row is STALE (names a drift that no longer exists);
#   * (the grow case is the (b) test above — an uncovered drift).
# Together they pin |allowlist| == |detected| and make the lists identical.
# --------------------------------------------------------------------------- #
def test_allowlist_has_no_stale_rows() -> None:
    detected = set(_detect_drift())
    rows = _load_known_drift()
    allow = {row["detector_key"] for row in rows}

    stale = sorted(allow - detected)
    assert not stale, (
        "Stale allowlist rows in tests/data/auth_taxonomy_known_drift.yaml: the "
        "drift they describe no longer exists (the surfaces converged — good!). "
        "Remove these rows so the manifest shrinks:\n"
        + "\n".join(f"  - {k}" for k in stale)
    )


def test_allowlist_and_detected_drift_are_identical_sets() -> None:
    """Defensive: |allowlist| == |detected| and same membership (no dupes)."""
    detected = set(_detect_drift())
    rows = _load_known_drift()
    keys = [row["detector_key"] for row in rows]

    assert len(keys) == len(set(keys)), "duplicate detector_key in allowlist"
    assert set(keys) == detected, (
        "allowlist detector_keys and detected drift must be identical sets; "
        f"only-in-allowlist={sorted(set(keys) - detected)}, "
        f"only-in-detected={sorted(detected - set(keys))}"
    )


# --------------------------------------------------------------------------- #
# Allowlist hygiene — every row carries the fields that keep it a SHRINKING
# ledger and not a permanent escape hatch.
# --------------------------------------------------------------------------- #
def test_allowlist_rows_are_well_formed() -> None:
    required = {
        "id",
        "detector_key",
        "symbol_or_value",
        "repo",
        "owner",
        "phase_issue",
        "remove_by",
    }
    rows = _load_known_drift()
    assert rows, "allowlist must not be empty while drift exists"

    ids: list[str] = []
    for row in rows:
        missing = required - set(row)
        assert not missing, f"row {row.get('id', row)} missing fields: {sorted(missing)}"
        assert (
            row["remove_by"] == "Schema#219-enforce"
        ), f"row {row['id']} must set remove_by: 'Schema#219-enforce' (the enforcement gate)"
        ids.append(row["id"])

    assert len(ids) == len(set(ids)), "duplicate row id in allowlist"


# --------------------------------------------------------------------------- #
# (d) ENFORCE toggle — when SCHEMA_219_ENFORCE is set, ANY remaining allowlist
# row fails the test. This is the DETECT -> ENFORCE switch a later issue flips.
# Skipped by default so DETECT mode stays green/non-blocking.
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(
    not os.environ.get(ENFORCE_ENV),
    reason=f"{ENFORCE_ENV} not set — running in DETECT (non-blocking) mode",
)
def test_enforce_mode_fails_on_any_remaining_drift() -> None:
    rows = _load_known_drift()
    assert not rows, (
        f"{ENFORCE_ENV} is set (ENFORCE mode) but the auth-taxonomy drift "
        f"allowlist still has {len(rows)} row(s). Reconcile the surfaces and "
        f"empty tests/data/auth_taxonomy_known_drift.yaml before enforcing:\n"
        + "\n".join(
            f"  - {row['id']} [{row['repo']}] {row['symbol_or_value']}" for row in rows
        )
    )


# --------------------------------------------------------------------------- #
# Self-consistency of the fixture against the Schema it claims to be measured
# against — catches a fixture that drifted from the Schema in a way the
# allowlist does not describe (e.g. someone edited the Schema enum).
# --------------------------------------------------------------------------- #
def test_surfaces_fixture_is_loadable_and_shaped() -> None:
    surfaces = _load_surfaces()
    for path in (
        ("backend", "user_allowed_scopes", "values"),
        ("backend", "scope_permission_map", "values"),
        ("backend", "emitted_permissions", "values"),
        ("backend", "resource_types", "unified_auth", "values"),
        ("backend", "resource_types", "api_key_resource", "values"),
        ("backend", "key_prefixes", "middleware_accepted", "values"),
        ("backend", "key_prefixes", "config_default", "values"),
        ("sdk", "key_prefixes", "validator_accepted", "values"),
        ("frontend", "key_types", "create_dialog", "values"),
        ("frontend", "admin_predicate", "roles_checked"),
    ):
        node: Any = surfaces
        for key in path:
            assert key in node, f"surfaces fixture missing path {'/'.join(path)}"
            node = node[key]


def test_every_surface_value_has_a_regeneration_pointer() -> None:
    """Each measured surface block must name its source repo/path/symbol/ref so a
    human can regenerate it — the fixture is only trustworthy if it is traceable.
    """
    surfaces = _load_surfaces()

    def _assert_source(block: dict[str, Any], where: str) -> None:
        src = block.get("source")
        assert isinstance(src, dict), f"{where}: missing 'source' regeneration pointer"
        for field in ("repo", "path", "symbol", "ref"):
            assert src.get(field), f"{where}: source.{field} missing/empty"

    be = surfaces["backend"]
    _assert_source(be["user_allowed_scopes"], "backend.user_allowed_scopes")
    _assert_source(be["scope_permission_map"], "backend.scope_permission_map")
    _assert_source(be["emitted_permissions"], "backend.emitted_permissions")
    _assert_source(
        be["resource_types"]["unified_auth"], "backend.resource_types.unified_auth"
    )
    _assert_source(
        be["resource_types"]["api_key_resource"],
        "backend.resource_types.api_key_resource",
    )
    _assert_source(
        be["key_prefixes"]["middleware_accepted"],
        "backend.key_prefixes.middleware_accepted",
    )
    _assert_source(
        be["key_prefixes"]["config_default"], "backend.key_prefixes.config_default"
    )
    _assert_source(
        surfaces["sdk"]["key_prefixes"]["validator_accepted"],
        "sdk.key_prefixes.validator_accepted",
    )
    _assert_source(
        surfaces["frontend"]["key_types"]["create_dialog"],
        "frontend.key_types.create_dialog",
    )
    _assert_source(
        surfaces["frontend"]["admin_predicate"], "frontend.admin_predicate"
    )
