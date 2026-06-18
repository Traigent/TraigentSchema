#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
refresh_parity.py — Parity manifest freshness checker / updater.

The parity manifest (parity/python-js-sdk.json) records the set of Python
root exports and their JavaScript parity classification.  It is intentionally
hand-curated (symbol classifications require human decisions), but the
``schemaVersion`` field and the ``lastSchemaRefreshSha`` field can be verified
automatically.

Usage
-----
Check mode (default, used by CI):
    python scripts/refresh_parity.py --check

Update mode (run locally when schema files change):
    python scripts/refresh_parity.py --update

What is verified / updated
--------------------------
1. ``parity.schemaRefresh.lastSchemaFileSha`` — a deterministic hash of the
   sorted list of schema file paths + their content digests.  If schema files
   have changed since the manifest was last stamped, the hash will differ and
   ``--check`` will fail, signalling that a human should review the manifest
   and re-run ``--update`` to stamp the new hash.

2. ``parity.schemaRefresh.schemaFileCount`` — the current number of JSON
   schema files.  A mismatch (files added/removed without updating the
   manifest) also fails ``--check``.

Exit codes
----------
0  All checks pass (or ``--update`` completed successfully).
1  Checks failed; manifest is stale.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST_PATH = _REPO_ROOT / "parity" / "python-js-sdk.json"
_SCHEMAS_DIR = _REPO_ROOT / "traigent_schema" / "schemas"

_REFRESH_KEY = "schemaRefresh"


def _compute_schema_digest(schemas_dir: Path) -> tuple[str, int]:
    """Return (hex-digest, file-count) for all JSON schema files.

    The digest is computed over the sorted list of (relative-path, sha256)
    pairs so that it is deterministic and content-sensitive.
    """
    entries: list[tuple[str, str]] = []
    for f in sorted(schemas_dir.rglob("*.json")):
        rel = f.relative_to(schemas_dir).as_posix()
        content_hash = hashlib.sha256(f.read_bytes()).hexdigest()
        entries.append((rel, content_hash))

    manifest_input = "\n".join(f"{rel}:{h}" for rel, h in entries)
    combined_hash = hashlib.sha256(manifest_input.encode()).hexdigest()
    return combined_hash, len(entries)


def _load_manifest() -> dict:
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _save_manifest(manifest: dict) -> None:
    _MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def cmd_check() -> int:
    """Return 0 if manifest is up-to-date, 1 otherwise."""
    manifest = _load_manifest()
    current_digest, current_count = _compute_schema_digest(_SCHEMAS_DIR)

    refresh_block = manifest.get(_REFRESH_KEY, {})
    recorded_digest = refresh_block.get("lastSchemaFileSha", "")
    recorded_count = refresh_block.get("schemaFileCount", -1)

    ok = True

    if recorded_digest != current_digest:
        print(
            f"[FAIL] schemaRefresh.lastSchemaFileSha mismatch:\n"
            f"       recorded : {recorded_digest or '(missing)'}\n"
            f"       current  : {current_digest}\n"
            f"\n"
            f"Schema files have changed since the parity manifest was last stamped.\n"
            f"Review the changes, then run:\n"
            f"\n"
            f"    python scripts/refresh_parity.py --update\n"
            f"\n"
            f"and commit the updated parity/python-js-sdk.json.",
            file=sys.stderr,
        )
        ok = False

    if recorded_count != current_count:
        print(
            f"[FAIL] schemaRefresh.schemaFileCount mismatch:\n"
            f"       recorded : {recorded_count}\n"
            f"       current  : {current_count}",
            file=sys.stderr,
        )
        ok = False

    if ok:
        print(
            f"[OK] parity manifest is up-to-date "
            f"(digest={current_digest[:12]}…, files={current_count})"
        )
        return 0

    return 1


def cmd_update() -> int:
    """Stamp the manifest with the current schema digest and file count."""
    manifest = _load_manifest()
    current_digest, current_count = _compute_schema_digest(_SCHEMAS_DIR)

    if _REFRESH_KEY not in manifest:
        manifest[_REFRESH_KEY] = {}

    manifest[_REFRESH_KEY]["lastSchemaFileSha"] = current_digest
    manifest[_REFRESH_KEY]["schemaFileCount"] = current_count
    manifest[_REFRESH_KEY]["note"] = (
        "Auto-stamped by scripts/refresh_parity.py. "
        "Do not hand-edit this block."
    )

    _save_manifest(manifest)
    print(
        f"[OK] Stamped parity manifest: "
        f"digest={current_digest[:12]}…, files={current_count}\n"
        f"Commit the updated parity/python-js-sdk.json."
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        default=True,
        help="Check that the manifest is up-to-date (default).",
    )
    mode.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Re-stamp the manifest with current schema digests.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.update:
        sys.exit(cmd_update())
    else:
        sys.exit(cmd_check())


if __name__ == "__main__":
    main()
