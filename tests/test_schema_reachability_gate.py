# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Tests for scripts/schema_reachability.py: the orphan-schema reachability gate.

This does NOT re-check that the checked-in report is fresh -- that's
.github/workflows/schema-orphan-check.yml's job (mirrors how
parity-check.yml, not a pytest test, owns parity/python-js-sdk.json
freshness). What belongs here is the same thing test_python_js_parity_
manifest.py does for the parity manifest: assert invariants about the
CONTENT/structure of the checked-in artifacts, and -- the part that matters
most -- a durable, CI-enforced version of the reachability rule's negative
control (a synthetic orphan must be caught; a synthetic $ref must not trip
the gate), so that guarantee survives as a regression test rather than
living only in a one-off manual demo.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "schema_reachability.py"
_REPORTS_DIR = _REPO_ROOT / "reports" / "schema_reachability"
_REPORT_PATH = _REPORTS_DIR / "unreachable_schemas.json"
_CONSUMER_MANIFEST_PATH = _REPORTS_DIR / "consumer_references.json"
_ALLOWLIST_PATH = _REPORTS_DIR / "allowlist.json"


def _load_gate_module():
    """Import scripts/schema_reachability.py without a scripts/__init__.py or
    a permanent sys.path mutation -- mirrors the stdlib-recommended pattern
    for loading a script-shaped module by file path."""
    spec = importlib.util.spec_from_file_location("schema_reachability_gate", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_GATE = _load_gate_module()


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


# ---------------------------------------------------------------------------
# Drift guards: the gate hardcodes its root set rather than importing the
# package (see the script's module docstring for why); this is what keeps
# that duplication from silently drifting out of sync.
# ---------------------------------------------------------------------------


def test_master_roots_match_contract_files_and_endpoint_completeness_test():
    from traigent_schema.utils import _CONTRACT_FILES

    assert set(_GATE._MASTER_ENDPOINT_ROOTS) == set(_CONTRACT_FILES.values())

    # tests/test_endpoint_catalog_completeness.py's MASTERS set is the third
    # independent copy of this same list; keep all three in lockstep.
    endpoint_completeness_src = (
        _REPO_ROOT / "tests" / "test_endpoint_catalog_completeness.py"
    ).read_text(encoding="utf-8")
    for root in _GATE._MASTER_ENDPOINT_ROOTS:
        assert f'"{root}"' in endpoint_completeness_src, (
            f"{root} is in schema_reachability.py's roots but not in "
            "test_endpoint_catalog_completeness.py's MASTERS -- the two have drifted."
        )


def test_master_roots_exist():
    for root in _GATE._MASTER_ENDPOINT_ROOTS:
        assert (_GATE._SCHEMAS_DIR / root).is_file(), f"missing root file: {root}"


# ---------------------------------------------------------------------------
# Rule 2 (mandatory negative control), as a durable regression test rather
# than only a one-off manual demo. Uses a real temp schema tree so the BFS
# in compute_graph_reachable_schemas runs unmodified against it.
# ---------------------------------------------------------------------------


def test_negative_control_new_unreferenced_file_is_flagged_orphan(tmp_path, monkeypatch):
    """A schema file referenced by nothing must be reported as unreachable."""
    fake_schemas = tmp_path / "schemas"
    fake_schemas.mkdir()

    (fake_schemas / "mep_endpoints.json").write_text(
        json.dumps({"paths": {}, "x-endpoint-modules": []}), encoding="utf-8"
    )
    (fake_schemas / "sdk_tuning_endpoints.json").write_text(
        json.dumps({"paths": {}}), encoding="utf-8"
    )
    (fake_schemas / "planned_projects_endpoints.json").write_text(
        json.dumps({"paths": {}}), encoding="utf-8"
    )
    # A file nothing points at.
    (fake_schemas / "truly_orphaned_schema.json").write_text(
        json.dumps({"type": "object"}), encoding="utf-8"
    )

    monkeypatch.setattr(_GATE, "_SCHEMAS_DIR", fake_schemas)
    monkeypatch.setattr(_GATE, "_CONSUMER_MANIFEST_PATH", tmp_path / "does-not-exist.json")
    monkeypatch.setattr(_GATE, "_ALLOWLIST_PATH", tmp_path / "does-not-exist.json")

    report = _GATE.build_report()

    assert "truly_orphaned_schema.json" in report["unreachableSchemas"], (
        "negative control FAILED: a schema referenced by nothing was not flagged"
    )


def test_negative_control_ref_from_reachable_schema_is_not_flagged(tmp_path, monkeypatch):
    """The inverse: a schema $ref'd (even indirectly) by a reachable schema
    must NOT be flagged, and must not trip the gate."""
    fake_schemas = tmp_path / "schemas"
    fake_schemas.mkdir()

    (fake_schemas / "mep_endpoints.json").write_text(
        json.dumps(
            {
                "paths": {
                    "/x": {
                        "get": {
                            "responses": {
                                "200": {
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": "./top_level_schema.json"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (fake_schemas / "sdk_tuning_endpoints.json").write_text(
        json.dumps({"paths": {}}), encoding="utf-8"
    )
    (fake_schemas / "planned_projects_endpoints.json").write_text(
        json.dumps({"paths": {}}), encoding="utf-8"
    )
    # top_level_schema.json is directly $ref'd by the endpoint catalog above.
    # It in turn $refs nested_schema.json -- two hops deep, confirming the
    # walk does not stop at depth 1.
    (fake_schemas / "top_level_schema.json").write_text(
        json.dumps({"properties": {"nested": {"$ref": "./nested_schema.json"}}}),
        encoding="utf-8",
    )
    (fake_schemas / "nested_schema.json").write_text(
        json.dumps({"type": "object"}), encoding="utf-8"
    )

    monkeypatch.setattr(_GATE, "_SCHEMAS_DIR", fake_schemas)
    monkeypatch.setattr(_GATE, "_CONSUMER_MANIFEST_PATH", tmp_path / "does-not-exist.json")
    monkeypatch.setattr(_GATE, "_ALLOWLIST_PATH", tmp_path / "does-not-exist.json")

    report = _GATE.build_report()

    assert "top_level_schema.json" not in report["unreachableSchemas"]
    assert "nested_schema.json" not in report["unreachableSchemas"], (
        "a 2-hop-deep $ref target was wrongly flagged -- reachability must not "
        "stop at depth 1"
    )
    assert report["totals"]["unreachableCount"] == 0


# ---------------------------------------------------------------------------
# Structural sanity of the checked-in artifacts (content, not freshness).
# ---------------------------------------------------------------------------


def test_unreachable_report_lists_only_real_existing_schema_files():
    report = _load(_REPORT_PATH)
    schemas_dir = _GATE._SCHEMAS_DIR
    for rel in report["unreachableSchemas"]:
        assert (schemas_dir / rel).is_file(), f"reported orphan does not exist on disk: {rel}"


def test_unreachable_report_list_is_sorted_and_deduplicated():
    report = _load(_REPORT_PATH)
    listed = report["unreachableSchemas"]
    assert listed == sorted(listed)
    assert len(listed) == len(set(listed))


def test_unreachable_report_totals_are_internally_consistent():
    report = _load(_REPORT_PATH)
    totals = report["totals"]
    assert totals["unreachableCount"] == len(report["unreachableSchemas"])
    assert totals["reachableCount"] + totals["unreachableCount"] == totals["schemaFileCount"]
    assert sum(totals["reachableByRule"].values()) == totals["reachableCount"]


def test_consumer_reference_manifest_basenames_are_real_schema_basenames():
    """Rule 3 input sanity: every recorded basename must actually name a
    schema file in this repo (guards against a stale manifest entry surviving
    a schema rename/deletion and silently keeping the old name 'reachable')."""
    manifest = _load(_CONSUMER_MANIFEST_PATH)
    real_basenames = {p.name for p in _GATE._SCHEMAS_DIR.rglob("*.json")}
    stale = set(manifest["referencedBasenames"]) - real_basenames
    assert not stale, f"consumer_references.json names schema files that no longer exist: {stale}"


def test_allowlist_entries_have_owner_and_reason():
    allowlist = _load(_ALLOWLIST_PATH)
    for entry in allowlist["entries"]:
        assert entry.get("path"), f"allowlist entry missing 'path': {entry}"
        assert entry.get("owner"), f"allowlist entry missing 'owner': {entry}"
        assert entry.get("reason"), f"allowlist entry missing 'reason': {entry}"
        assert (_GATE._SCHEMAS_DIR / entry["path"]).is_file(), (
            f"allowlist entry names a schema that does not exist: {entry['path']}"
        )
