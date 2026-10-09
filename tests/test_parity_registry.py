"""Happy path and mutation tests for scripts/check_parity_registry.py.

Every mutation works on a tmp_path copy of the parity tree; real files are never edited.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_parity_registry.py"
FIXTURE_REL = "optimizer/grid-enumeration.v1.json"
FID = "optimizer.grid-enumeration.v1"

_spec = importlib.util.spec_from_file_location("check_parity_registry", SCRIPT)
assert _spec and _spec.loader
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    dest = tmp_path / "parity"
    shutil.copytree(REPO / "parity", dest, ignore=shutil.ignore_patterns("python-js-sdk.json"))
    return dest


def _rw(path: Path, mutate) -> None:
    data = json.loads(path.read_text())
    mutate(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _registry(tree: Path, mutate) -> None:
    _rw(tree / "capabilities" / "registry.v1.json", lambda d: mutate(d["capabilities"][0], d))


def _set_planned(c: dict) -> None:
    """Turn the copied grid row into a planned row so the planned-only mutations apply to it."""
    c.update(
        disposition="planned",
        owner="sdk-maintainers",
        targetMilestone="SDKS-3: Python and JS conformance adapters",
    )


def _reindex(tree: Path) -> None:
    def fix(d):
        for entry in d.values():
            data = (tree / "fixtures" / entry["path"]).read_bytes()
            entry["sha256"] = hashlib.sha256(data).hexdigest()

    _rw(tree / "fixtures" / "index.json", fix)


def _errors(tree: Path) -> list[str]:
    return checker.check(tree)


def test_happy_path_real_tree():
    assert checker.check(REPO / "parity") == []


def test_happy_path_copy(tree: Path):
    assert _errors(tree) == []


def test_planned_row_may_list_fixtures(tree: Path):
    _registry(tree, lambda c, d: _set_planned(c))
    row = json.loads((tree / "capabilities" / "registry.v1.json").read_text())["capabilities"][0]
    assert row["disposition"] == "planned" and row["fixtures"]
    assert _errors(tree) == []


def test_duplicate_id_fails(tree: Path):
    _rw(
        tree / "capabilities" / "registry.v1.json",
        lambda d: d["capabilities"].append(copy.deepcopy(d["capabilities"][0])),
    )
    assert any("duplicate capability id" in e for e in _errors(tree))


def test_parity_row_without_fixtures_fails(tree: Path):
    _registry(tree, lambda c, d: c.update(disposition="parity", fixtures=[]))
    assert any(e.startswith("schema:") for e in _errors(tree))


def test_idiomatic_equivalent_without_fixtures_fails(tree: Path):
    _registry(tree, lambda c, d: c.update(disposition="idiomatic-equivalent", fixtures=[]))
    assert any(e.startswith("schema:") for e in _errors(tree))


def test_planned_row_requires_target_milestone(tree: Path):
    def mutate(c, d):
        _set_planned(c)
        c.pop("targetMilestone")

    _registry(tree, mutate)
    assert any(e.startswith("schema:") for e in _errors(tree))


def test_planned_with_empty_owner_fails(tree: Path):
    def mutate(c, d):
        _set_planned(c)
        c.update(owner="")

    _registry(tree, mutate)
    assert any(e.startswith("schema:") for e in _errors(tree))


def test_missing_fixture_file_fails(tree: Path):
    (tree / "fixtures" / FIXTURE_REL).unlink()
    assert any("file missing" in e for e in _errors(tree))


def test_edited_fixture_byte_fails(tree: Path):
    p = tree / "fixtures" / FIXTURE_REL
    p.write_bytes(p.read_bytes() + b" ")
    assert any("sha256 mismatch" in e for e in _errors(tree))


def test_fixture_not_in_index_fails(tree: Path):
    _rw(tree / "fixtures" / "index.json", lambda d: d.clear())
    assert any("not in index" in e for e in _errors(tree))


def test_id_not_in_allowlist_fails(tree: Path):
    _rw(tree / "capabilities" / "phase-a-allowlist.json", lambda d: d.update(capabilityIds=[]))
    assert any("not in Phase A allowlist" in e for e in _errors(tree))


def test_fixture_not_in_allowlist_fails(tree: Path):
    _rw(tree / "capabilities" / "phase-a-allowlist.json", lambda d: d.update(fixtures=[]))
    assert any(f"fixture {FID} not in Phase A allowlist" in e for e in _errors(tree))


def test_index_path_traversal_fails(tree: Path):
    outside = tree / "capabilities" / "registry.v1.json"
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()

    def mutate(d):
        d[FID]["path"] = "../capabilities/registry.v1.json"
        d[FID]["sha256"] = digest

    _rw(tree / "fixtures" / "index.json", mutate)
    assert any("path escapes fixtures dir" in e for e in _errors(tree))


def test_unreferenced_index_entry_fails(tree: Path):
    _rw(
        tree / "fixtures" / "index.json",
        lambda d: d.update(extra=copy.deepcopy(d[FID])),
    )
    assert any("index entry extra is not referenced" in e for e in _errors(tree))


def test_extra_unindexed_fixture_file_fails(tree: Path):
    (tree / "fixtures" / "optimizer" / "stray.json").write_text("{}\n")
    assert any("fixture file not in index: optimizer/stray.json" in e for e in _errors(tree))


def test_fixture_id_mismatch_fails(tree: Path):
    _rw(tree / "fixtures" / FIXTURE_REL, lambda d: d.update(fixtureId="other.v1"))
    _reindex(tree)
    assert any("fixtureId does not match index key" in e for e in _errors(tree))


def test_fixture_capability_mismatch_fails(tree: Path):
    _rw(tree / "fixtures" / FIXTURE_REL, lambda d: d.update(capability="optimizer.other"))
    _reindex(tree)
    assert any("capability does not reference this fixture" in e for e in _errors(tree))


def test_cli_exit_codes(tree: Path):
    assert checker.main(["--root", str(tree)]) == 0
    (tree / "fixtures" / FIXTURE_REL).unlink()
    assert checker.main(["--root", str(tree)]) == 1
