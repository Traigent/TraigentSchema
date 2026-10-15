#!/usr/bin/env python3
"""Validate the SDK parity capability registry and its fixtures.

Checks, each of which fails the run:
  * registry validates against parity/capabilities/registry.schema.json
  * capability ids are unique and listed in the Phase A allowlist
  * every fixture a capability references is present in parity/fixtures/index.json
    and listed in the Phase A allowlist
  * every index entry is referenced, exists inside parity/fixtures/, and its
    sha256 matches the file bytes
  * every *.json under parity/fixtures/ (except index.json) is indexed
  * each fixture's fixtureId equals its index key and its capability is a
    registry capability that references it

Usage: python3 scripts/check_parity_registry.py [--root PARITY_DIR]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import jsonschema

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "parity"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_errors(caps_dir: Path) -> tuple[list[str], dict]:
    """Validate the registry against its schema; return the errors and the registry."""
    schema = _load(caps_dir / "registry.schema.json")
    jsonschema.Draft202012Validator.check_schema(schema)
    registry = _load(caps_dir / "registry.v1.json")
    errors: list[str] = []
    for err in jsonschema.Draft202012Validator(schema).iter_errors(registry):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        errors.append(f"schema: {loc}: {err.message[:200]}")
    return errors, registry


def _capability_id_errors(ids: list[str], allow_caps: set[str]) -> list[str]:
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    errors = [f"duplicate capability id: {dup}" for dup in duplicates]
    for cid in ids:
        if cid not in allow_caps:
            errors.append(f"capability id not in Phase A allowlist: {cid}")
    return errors


def _index_reference_errors(
    capabilities: list[dict], index: dict, allow_fixtures: set[str]
) -> tuple[list[str], dict[str, set[str]]]:
    """Cross-check registry fixture references, the index and the fixture allowlist.

    Returns the errors and, per fixture id, the capability ids that reference it.
    """
    errors: list[str] = []
    referrers: dict[str, set[str]] = {}
    for cap in capabilities:
        for fid in cap["fixtures"]:
            referrers.setdefault(fid, set()).add(cap["id"])
            if fid not in index:
                errors.append(f"{cap['id']}: fixture {fid} not in index")
    for fid in sorted(set(index) - set(referrers)):
        errors.append(f"index entry {fid} is not referenced by the registry")
    for fid in sorted(index):
        if fid not in allow_fixtures:
            errors.append(f"fixture {fid} not in Phase A allowlist")
    return errors, referrers


def _fixture_content_errors(fid: str, path: Path, referrers: dict[str, set[str]]) -> list[str]:
    """Errors for one indexed fixture file's JSON content: id and capability back-reference."""
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return [f"fixture {fid}: not valid JSON"]
    if not isinstance(meta, dict) or meta.get("fixtureId") != fid:
        return [f"fixture {fid}: fixtureId does not match index key"]
    if meta.get("capability") not in referrers.get(fid, set()):
        return [f"fixture {fid}: capability does not reference this fixture"]
    return []


def _indexed_fixture_errors(
    fix_dir: Path, fix_root: Path, index: dict, referrers: dict[str, set[str]]
) -> tuple[list[str], set[Path]]:
    """Check every index entry's path, presence, digest and content.

    Returns the errors and the resolved paths of entries that stay inside the fixtures dir.
    """
    errors: list[str] = []
    indexed_paths: set[Path] = set()
    for fid, entry in sorted(index.items()):
        path = (fix_dir / entry["path"]).resolve()
        if not path.is_relative_to(fix_root):
            errors.append(f"fixture {fid}: path escapes fixtures dir")
            continue
        indexed_paths.add(path)
        if not path.is_file():
            errors.append(f"fixture {fid}: file missing: {entry['path']}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            errors.append(
                f"fixture {fid}: sha256 mismatch (index {entry['sha256']}, file {actual})"
            )
        errors.extend(_fixture_content_errors(fid, path, referrers))
    return errors, indexed_paths


def _unindexed_file_errors(fix_root: Path, indexed_paths: set[Path]) -> list[str]:
    errors: list[str] = []
    for path in sorted(fix_root.rglob("*.json")):
        if path.name == "index.json" and path.parent == fix_root:
            continue
        if path.resolve() not in indexed_paths:
            errors.append(f"fixture file not in index: {path.relative_to(fix_root)}")
    return errors


def check(root: Path) -> list[str]:
    caps_dir = root / "capabilities"
    fix_dir = root / "fixtures"

    errors, registry = _schema_errors(caps_dir)
    if errors:
        return errors

    capabilities = registry["capabilities"]
    ids = [c["id"] for c in capabilities]
    allowlist = _load(caps_dir / "phase-a-allowlist.json")
    allow_caps = set(allowlist.get("capabilityIds", []))
    allow_fixtures = set(allowlist.get("fixtures", []))
    errors.extend(_capability_id_errors(ids, allow_caps))

    index = _load(fix_dir / "index.json")
    reference_errors, referrers = _index_reference_errors(capabilities, index, allow_fixtures)
    errors.extend(reference_errors)

    fix_root = fix_dir.resolve()
    fixture_errors, indexed_paths = _indexed_fixture_errors(fix_dir, fix_root, index, referrers)
    errors.extend(fixture_errors)
    errors.extend(_unindexed_file_errors(fix_root, indexed_paths))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    errors = check(args.root)
    if errors:
        print("parity registry check FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("parity registry check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
