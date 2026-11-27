"""No OpenAPI component name is defined twice with different bodies.

Consumers merge the ``components`` sections of every schema file into one
document; the same name with two different bodies makes that merge fail.
"""

from __future__ import annotations

import json
from collections import defaultdict

from traigent_schema.utils import get_schemas_dir


def _canonical(body: object) -> str:
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def test_same_named_components_have_identical_bodies():
    root = get_schemas_dir()
    seen: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for path in sorted(root.rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        components = data.get("components") if isinstance(data, dict) else None
        if not isinstance(components, dict):
            continue
        rel = path.relative_to(root).as_posix()
        for section, entries in components.items():
            if not isinstance(entries, dict):
                continue
            for name, body in entries.items():
                seen[(section, name)][_canonical(body)].add(rel)

    conflicts = [
        f"{section}/{name}: "
        + " vs ".join(sorted("+".join(sorted(f)) for f in bodies.values()))
        for (section, name), bodies in sorted(seen.items())
        if len(bodies) > 1
    ]
    assert not conflicts, "component name collisions:\n" + "\n".join(conflicts)
