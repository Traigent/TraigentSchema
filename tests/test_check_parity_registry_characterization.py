"""Characterization tests for ``check`` in scripts/check_parity_registry.py.

Each case writes a small self-contained parity tree (its own registry schema, registry,
allowlist, fixture index and fixtures) into a temporary directory, applies one or more
edits, and pins the exact list of error strings ``check`` returns, in order. The tree does
not depend on the repository's own parity files, so editing those cannot move the
recorded output. The
expected values in tests/data/check_parity_registry_characterization.json were recorded
from the implementation before ``check`` was split into smaller helpers. The cases reach
every branch of ``check``.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests._characterization import REPO_ROOT, Case, load_golden, load_script, observe

GOLDEN_FILE = "check_parity_registry_characterization.json"
TARGET = load_script(
    "check_parity_registry_characterization_target",
    REPO_ROOT / "scripts" / "check_parity_registry.py",
)

Edit = Callable[[Path], None]


def _rw(path: Path, mutate: Callable[[Any], Any]) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _registry(mutate: Callable[[Any], Any]) -> Edit:
    return lambda tree: _rw(tree / "capabilities" / "registry.v1.json", mutate)


def _allowlist(mutate: Callable[[Any], Any]) -> Edit:
    return lambda tree: _rw(tree / "capabilities" / "phase-a-allowlist.json", mutate)


def _index(mutate: Callable[[Any], Any]) -> Edit:
    return lambda tree: _rw(tree / "fixtures" / "index.json", mutate)


def _write(rel: str, text: str) -> Edit:
    def edit(tree: Path) -> None:
        path = tree / "fixtures" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    return edit


def _delete(rel: str) -> Edit:
    return lambda tree: (tree / "fixtures" / rel).unlink()


def _reindex(tree: Path) -> None:
    def fix(d: dict[str, Any]) -> None:
        for entry in d.values():
            path = tree / "fixtures" / entry["path"]
            if path.is_file():
                entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    _rw(tree / "fixtures" / "index.json", fix)


SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["capabilities"],
    "properties": {
        "capabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "fixtures"],
                "properties": {
                    "id": {"type": "string"},
                    "fixtures": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                },
            },
        }
    },
}

CAPABILITIES = {
    "optimizer.grid-enumeration": ["optimizer.grid-enumeration.v1"],
    "multi-objective.normalization-selection": ["multi-objective.normalization-selection.v1"],
    "optimize.stop-rules": ["optimize.stop-rules.v1", "optimize.stop-limits.v1"],
}


def _fixture_rel(fid: str) -> str:
    area, _, name = fid.partition(".")
    return f"{area}/{name}.json"


def _build_tree(tree: Path) -> None:
    (tree / "capabilities").mkdir(parents=True)
    (tree / "fixtures").mkdir()
    (tree / "capabilities" / "registry.schema.json").write_text(json.dumps(SCHEMA))
    registry = {
        "capabilities": [{"id": cid, "fixtures": fids} for cid, fids in CAPABILITIES.items()]
    }
    (tree / "capabilities" / "registry.v1.json").write_text(json.dumps(registry))
    all_fixtures = [fid for fids in CAPABILITIES.values() for fid in fids]
    allowlist = {"capabilityIds": list(CAPABILITIES), "fixtures": all_fixtures}
    (tree / "capabilities" / "phase-a-allowlist.json").write_text(json.dumps(allowlist))
    index = {}
    for cid, fids in CAPABILITIES.items():
        for fid in fids:
            path = tree / "fixtures" / _fixture_rel(fid)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"fixtureId": fid, "capability": cid}))
            index[fid] = {
                "path": _fixture_rel(fid),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
    (tree / "fixtures" / "index.json").write_text(json.dumps(index))


def _case(*edits: Edit) -> Case:
    def run(m: ModuleType) -> Any:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "parity"
            _build_tree(tree)
            for edit in edits:
                edit(tree)
            return m.check(tree)

    return run


GRID = "optimizer.grid-enumeration.v1"
GRID_REL = _fixture_rel(GRID)
STOP = "optimize.stop-rules.v1"


def _first_cap(mutate: Callable[[dict[str, Any]], None]) -> Edit:
    return _registry(lambda d: mutate(d["capabilities"][0]))


def _fixture_json(rel: str, mutate: Callable[[Any], Any]) -> Edit:
    return lambda tree: _rw(tree / "fixtures" / rel, mutate)


ALL_CASES: dict[str, Case] = {
    "consistent_tree": _case(),
    "schema_invalid_registry": _case(_registry(lambda d: d.pop("capabilities"))),
    "schema_invalid_nested": _case(_first_cap(lambda c: c.__setitem__("id", 5))),
    "duplicate_capability_id": _case(
        _registry(lambda d: d["capabilities"].append(dict(d["capabilities"][0])))
    ),
    "capability_not_allowlisted": _case(
        _allowlist(lambda d: d["capabilityIds"].remove("optimizer.grid-enumeration"))
    ),
    "allowlist_keys_missing": _case(
        _allowlist(lambda d: (d.pop("capabilityIds"), d.pop("fixtures")))
    ),
    "fixture_not_in_index": _case(_index(lambda d: d.pop(GRID))),
    "index_entry_unreferenced": _case(
        _write("optimizer/extra.v1.json", '{"fixtureId": "extra.v1", "capability": "x"}'),
        _index(lambda d: d.__setitem__("extra.v1", {"path": "optimizer/extra.v1.json"})),
        _reindex,
    ),
    "fixture_not_allowlisted": _case(_allowlist(lambda d: d["fixtures"].remove(STOP))),
    "path_escapes": _case(_index(lambda d: d[GRID].__setitem__("path", "../outside.json"))),
    "file_missing": _case(_delete(GRID_REL)),
    "file_missing_then_later_entries": _case(
        _delete(_fixture_rel("multi-objective.normalization-selection.v1")),
        _index(lambda d: d[STOP].__setitem__("sha256", "e" * 64)),
    ),
    "sha_mismatch": _case(_index(lambda d: d[GRID].__setitem__("sha256", "0" * 64))),
    "fixture_not_json": _case(_write(GRID_REL, "{not json"), _reindex),
    "fixture_json_list": _case(_write(GRID_REL, "[1, 2]"), _reindex),
    "fixture_id_mismatch": _case(
        _fixture_json(GRID_REL, lambda d: d.__setitem__("fixtureId", "other")), _reindex
    ),
    "fixture_id_missing": _case(_fixture_json(GRID_REL, lambda d: d.pop("fixtureId")), _reindex),
    "fixture_capability_mismatch": _case(
        _fixture_json(GRID_REL, lambda d: d.__setitem__("capability", "optimize.stop-rules")),
        _reindex,
    ),
    "fixture_capability_missing": _case(
        _fixture_json(GRID_REL, lambda d: d.pop("capability", None)), _reindex
    ),
    "unindexed_fixture_file": _case(_write("optimizer/extra.json", "{}")),
    "nested_index_json_not_exempt": _case(_write("optimizer/index.json", "{}")),
    "unindexed_non_json_ignored": _case(_write("optimizer/notes.txt", "x")),
    "several_problems_ordering": _case(
        _registry(lambda d: d["capabilities"].append(dict(d["capabilities"][1]))),
        _allowlist(lambda d: d["fixtures"].clear()),
        _index(lambda d: d[STOP].__setitem__("sha256", "f" * 64)),
        _delete(GRID_REL),
        _write("zz/late.json", "{}"),
        _write("aa/early.json", "{}"),
    ),
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], TARGET) == _golden()[case_id]
