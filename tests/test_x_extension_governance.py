# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""#132: x-* extension governance.

The repo uses ~34 distinct `x-*` JSON-Schema extension keywords with no
registry, so a typo (`x-priacy-classification`) or an undocumented new keyword
merges silently and governance tooling that reads `x-*` annotations drifts. This
gate asserts every `x-*` key used under traigent_schema/schemas/ is registered in
tests/data/x_extensions_registry.json with a description — turning ad-hoc x-*
sprawl into a documented, reviewable vocabulary.

Adding a new `x-*` keyword to a schema requires adding it to the registry in the
same PR; the registry diff is the review surface.
"""

from __future__ import annotations

import json
from pathlib import Path

from traigent_schema.utils import get_all_schema_files

_REGISTRY_PATH = Path(__file__).resolve().parent / "data" / "x_extensions_registry.json"


def _registry() -> dict[str, dict]:
    return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))["extensions"]


def _used_x_extensions() -> dict[str, list[str]]:
    """Map every x-* key used (in key position) to the files that use it."""
    used: dict[str, list[str]] = {}

    def walk(node: object, file_name: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.startswith("x-"):
                    used.setdefault(key, [])
                    if file_name not in used[key]:
                        used[key].append(file_name)
                walk(value, file_name)
        elif isinstance(node, list):
            for value in node:
                walk(value, file_name)

    for path in get_all_schema_files():
        walk(json.loads(path.read_text(encoding="utf-8")), path.name)
    return used


def test_every_used_x_extension_is_registered() -> None:
    """Only-known x-* keys: every x-* used in a schema must be in the registry."""
    registered = set(_registry())
    used = _used_x_extensions()
    unregistered = {k: v for k, v in used.items() if k not in registered}
    assert not unregistered, (
        "x-* extension keyword(s) used in schemas but not in "
        "tests/data/x_extensions_registry.json (#132 — register with a description "
        "or fix the typo):\n"
        + "\n".join(f"  - {k}  (in: {', '.join(sorted(v))})" for k, v in sorted(unregistered.items()))
    )


def test_registry_entries_have_descriptions() -> None:
    bad = [k for k, meta in _registry().items() if not str(meta.get("description", "")).strip()]
    assert not bad, f"registry entries missing a description (#132): {sorted(bad)}"


def test_registry_has_no_stale_unused_entries() -> None:
    """Registry should not carry x-* keys no schema uses (keeps the registry honest)."""
    registered = set(_registry())
    used = set(_used_x_extensions())
    stale = sorted(registered - used)
    assert not stale, (
        "registry lists x-* keyword(s) no schema uses (#132 — remove or it drifts):\n"
        + "\n".join(f"  - {k}" for k in stale)
    )
