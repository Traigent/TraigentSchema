#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""schema_reachability.py — orphan-schema reachability gate.

Azure runs "Avocado" on every PR to azure-rest-api-specs: a spec file must be
referenced by a readme configuration or by another spec's ``$ref``, or the PR
is rejected. See https://github.com/Azure/azure-rest-api-specs/wiki/Swagger-Avocado
We have the same disease (JSON schema files nobody loads) and, until this
script, no equivalent gate.

A schema file under ``traigent_schema/schemas/`` is REACHABLE if any of:

  1. it is ``$ref``'d by another schema, transitively (the graph is walked to
     any depth — see ``compute_graph_reachable_schemas``);
  2. it is referenced by an ``*_endpoints.json`` contract document. Rules 1
     and 2 are computed together below: the walk starts at the three
     canonical OpenAPI catalog roots (``_MASTER_ENDPOINT_ROOTS`` — the only
     files this repo's own code loads unconditionally, see
     ``traigent_schema/utils.py:_CONTRACT_FILES``) and follows BOTH
     ``x-endpoint-modules[].paths_file`` links and ``$ref`` edges, because an
     ``*_endpoints.json`` document and a schema document use the identical
     ``$ref`` mechanism to point at the next file. Every ``*_endpoints.json``
     file in the repo is already guaranteed reachable from these 3 roots by
     ``tests/test_endpoint_catalog_completeness.py::test_no_orphan_endpoint_
     catalogs``, so a single walk covers both rules without a second root set.
  3. its filename is recorded in ``reports/schema_reachability/consumer_
     references.json`` — a snapshot of literal name references found in the
     five consumer repos (Traigent, TraigentBackend, TraigentFrontend,
     traigent-js, traigent-smartopt). See "Cross-repo reachability is
     necessarily approximate" below and that file's own header.
  4. its path is listed in ``reports/schema_reachability/allowlist.json``
     with an owner and a reason (human-curated; never auto-populated here).

Cross-repo reachability is necessarily approximate
---------------------------------------------------
Unlike Avocado, our reachability graph is not self-contained: a schema can be
consumed by name from a SIBLING repo this repo's CI cannot see. An in-repo-only
gate would call such schemas "orphaned" incorrectly. Rather than have this
script reach across repos live (which would make ``--check`` depend on network
access and four other repos' checkout state, and be unrunnable in this repo's
own CI, which has no access to Traigent/TraigentBackend/TraigentFrontend/
traigent-js/traigent-smartopt), rule 3 reads a COMMITTED, periodically-refreshed
manifest (``reports/schema_reachability/consumer_references.json``) built by
the separate, workspace-only ``scripts/refresh_consumer_schema_references.py``.
That manifest documents its own known limitations (literal-name matching only,
snapshot staleness, textual-mention-vs-live-use) — read them before trusting a
"reachable via rule 3" verdict at face value.

Non-blocking on arrival, deliberately
--------------------------------------
As of this writing the orphan set is non-empty (see the checked-in report).
This script does NOT fail the build on a non-empty orphan set — only on a
STALE report (the computed report disagreeing with what's checked in). A gate
that is red the day it lands gets disabled; there is direct precedent for that
in this workspace. The ``--max-orphans`` flag exists for the day the backlog
reaches zero (see its help text) but nothing wires it into CI yet — that is
tracked as a TODO in ``.github/workflows/schema-orphan-check.yml``, not encoded
as a number in this script.

Usage
-----
    python3 scripts/schema_reachability.py --check    # CI default
    python3 scripts/schema_reachability.py --update   # regenerate + write

Exit codes: 0 = report fresh (regardless of orphan count, unless
--max-orphans is passed and exceeded); 1 = stale report / max-orphans exceeded.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS_DIR = _REPO_ROOT / "traigent_schema" / "schemas"
_REPORT_DIR = _REPO_ROOT / "reports" / "schema_reachability"
_REPORT_PATH = _REPORT_DIR / "unreachable_schemas.json"
_CONSUMER_MANIFEST_PATH = _REPORT_DIR / "consumer_references.json"
_ALLOWLIST_PATH = _REPORT_DIR / "allowlist.json"

_HTTP_PREFIX = "https://schemas.traigent.ai/"

#: The only files this repo's own code loads unconditionally (mirrors
#: traigent_schema/utils.py's ``_CONTRACT_FILES.values()`` and
#: tests/test_endpoint_catalog_completeness.py's ``MASTERS`` — duplicated
#: literally, matching that test's existing convention, rather than imported,
#: so this script has no import-time dependency on the installed package.
#: tests/test_schema_reachability_gate.py asserts the three stay in sync.)
_MASTER_ENDPOINT_ROOTS = (
    "mep_endpoints.json",
    "planned_projects_endpoints.json",
    "sdk_tuning_endpoints.json",
)


def _load_json(path: Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _iter_refs(node: Any):
    """Yield every ``$ref`` string value anywhere in a parsed JSON document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_refs(value)


def _normalize_target(referencing_rel: str, file_part: str) -> str | None:
    """Resolve a ``$ref``/``paths_file`` string to a path relative to the
    schemas dir, or ``None`` if it resolves outside the schemas tree."""
    schemas_root = _SCHEMAS_DIR.resolve()
    if file_part.startswith(_HTTP_PREFIX):
        candidate = (schemas_root / file_part[len(_HTTP_PREFIX) :]).resolve()
    else:
        candidate = (schemas_root / referencing_rel).parent.joinpath(file_part).resolve()
    try:
        return candidate.relative_to(schemas_root).as_posix()
    except ValueError:
        return None


def compute_graph_reachable_schemas() -> set[str]:
    """BFS from the 3 canonical OpenAPI catalog roots (rules 1+2, see module
    docstring). Returns schema paths relative to ``traigent_schema/schemas``,
    posix-separated. Deliberately walks the FULL transitive closure — do not
    stop at depth 1 (schemas directly named by an endpoint route); a schema
    reached only via another schema's internal ``$ref`` (e.g. a shared
    ``common_types_schema.json`` definition several hops deep) is exactly the
    case a depth-1 check would miss.
    """
    visited: set[str] = set()
    frontier: deque[str] = deque()
    for root in _MASTER_ENDPOINT_ROOTS:
        if (_SCHEMAS_DIR / root).exists():
            visited.add(root)
            frontier.append(root)

    while frontier:
        rel = frontier.popleft()
        try:
            doc = _load_json(_SCHEMAS_DIR / rel)
        except (OSError, json.JSONDecodeError):
            continue

        targets: set[str] = set()
        if isinstance(doc, dict):
            for module in doc.get("x-endpoint-modules", []) or []:
                if isinstance(module, dict):
                    paths_file = module.get("paths_file")
                    if isinstance(paths_file, str):
                        targets.add(paths_file)
        for ref in _iter_refs(doc):
            file_part, _, _fragment = ref.partition("#")
            if file_part:
                targets.add(file_part)

        for target in targets:
            normalized = _normalize_target(rel, target)
            if normalized is None or normalized in visited:
                continue
            if (_SCHEMAS_DIR / normalized).exists():
                visited.add(normalized)
                frontier.append(normalized)

    return visited


def _load_consumer_referenced_basenames() -> set[str]:
    """Rule 3 input: basenames recorded in the committed consumer-reference
    manifest. Missing file -> empty set (fails safe toward MORE orphans
    reported, never toward silently trusting an absent manifest)."""
    if not _CONSUMER_MANIFEST_PATH.exists():
        return set()
    manifest = _load_json(_CONSUMER_MANIFEST_PATH)
    return set(manifest.get("referencedBasenames", []))


def _load_allowlist_paths() -> dict[str, dict[str, str]]:
    """Rule 4 input: relative schema path -> {"owner", "reason"}."""
    if not _ALLOWLIST_PATH.exists():
        return {}
    data = _load_json(_ALLOWLIST_PATH)
    out: dict[str, dict[str, str]] = {}
    for entry in data.get("entries", []):
        path = entry["path"]
        out[path] = {"owner": entry.get("owner", ""), "reason": entry.get("reason", "")}
    return out


def _all_schema_relpaths() -> list[str]:
    return sorted(p.relative_to(_SCHEMAS_DIR).as_posix() for p in _SCHEMAS_DIR.rglob("*.json"))


def build_report() -> dict[str, Any]:
    """Compute the full reachability report. Pure function of repo content —
    deliberately carries no timestamp or other non-reproducible field, so
    re-running --update on an unchanged tree byte-for-byte reproduces the
    checked-in report (a timestamp would make --check flap on every run
    regardless of real drift)."""
    all_files = _all_schema_relpaths()
    graph_reachable = compute_graph_reachable_schemas()
    consumer_basenames = _load_consumer_referenced_basenames()
    allowlist = _load_allowlist_paths()

    counts_by_rule = {"refOrEndpointGraph": 0, "consumerReference": 0, "allowlist": 0}
    unreachable: list[str] = []

    for rel in all_files:
        if rel in graph_reachable:
            counts_by_rule["refOrEndpointGraph"] += 1
            continue
        basename = rel.rsplit("/", 1)[-1]
        if basename in consumer_basenames:
            counts_by_rule["consumerReference"] += 1
            continue
        if rel in allowlist:
            counts_by_rule["allowlist"] += 1
            continue
        unreachable.append(rel)

    return {
        "reportVersion": 1,
        "note": (
            "Auto-generated by scripts/schema_reachability.py --update. Do not "
            "hand-edit. Regenerate after changing schema files, "
            "reports/schema_reachability/consumer_references.json, or "
            "reports/schema_reachability/allowlist.json."
        ),
        "rules": {
            "1_2_refOrEndpointGraph": (
                "reachable transitively via $ref / x-endpoint-modules from the 3 "
                "canonical OpenAPI catalog roots (mep_endpoints.json, "
                "sdk_tuning_endpoints.json, planned_projects_endpoints.json)"
            ),
            "3_consumerReference": (
                "schema basename appears in reports/schema_reachability/"
                "consumer_references.json, a snapshot of literal name references "
                "found in the 5 consumer repos -- see that file's own header for "
                "what this cannot see"
            ),
            "4_allowlist": (
                "schema path is listed in reports/schema_reachability/"
                "allowlist.json with an owner and a reason"
            ),
        },
        "totals": {
            "schemaFileCount": len(all_files),
            "reachableCount": len(all_files) - len(unreachable),
            "unreachableCount": len(unreachable),
            "reachableByRule": counts_by_rule,
        },
        "unreachableSchemas": sorted(unreachable),
    }


def _serialize(report: dict[str, Any]) -> str:
    # sort_keys=True + fixed indent + trailing single newline: deterministic
    # byte-for-byte output so --check is a plain text comparison, and no
    # trailing whitespace is ever emitted (verified by
    # tests/test_schema_reachability_gate.py and the "grep -cP '[ \t]+$'"
    # check in the negative-control writeup).
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def cmd_check(max_orphans: int | None) -> int:
    report = build_report()
    current_text = _serialize(report)

    if not _REPORT_PATH.exists():
        print(
            f"[FAIL] {_REPORT_PATH.relative_to(_REPO_ROOT)} does not exist.\n"
            f"       Run: python3 scripts/schema_reachability.py --update",
            file=sys.stderr,
        )
        return 1

    on_disk = _REPORT_PATH.read_text(encoding="utf-8")
    if on_disk != current_text:
        try:
            on_disk_unreachable = set(json.loads(on_disk).get("unreachableSchemas", []))
        except json.JSONDecodeError:
            on_disk_unreachable = set()
        current_unreachable = set(report["unreachableSchemas"])
        newly_unreachable = sorted(current_unreachable - on_disk_unreachable)
        newly_reachable = sorted(on_disk_unreachable - current_unreachable)

        print(
            f"[FAIL] {_REPORT_PATH.relative_to(_REPO_ROOT)} is stale: the computed "
            "reachability report no longer matches the checked-in one.\n"
            "       Schema files, the consumer-reference manifest, or the "
            "allowlist changed without regenerating the report.",
            file=sys.stderr,
        )
        if newly_unreachable:
            print(
                "       Newly unreachable (not in the checked-in report):",
                file=sys.stderr,
            )
            for path in newly_unreachable:
                print(f"         - {path}", file=sys.stderr)
        if newly_reachable:
            print(
                "       No longer unreachable (checked-in report is stricter than current):",
                file=sys.stderr,
            )
            for path in newly_reachable:
                print(f"         - {path}", file=sys.stderr)
        print(
            "       Run:\n"
            "           python3 scripts/schema_reachability.py --update\n"
            "       and commit the result.",
            file=sys.stderr,
        )
        return 1

    totals = report["totals"]
    print(
        f"[OK] schema reachability report up-to-date: "
        f"{totals['unreachableCount']} unreachable / {totals['schemaFileCount']} total "
        f"(rule breakdown: {totals['reachableByRule']})"
    )

    if max_orphans is not None and totals["unreachableCount"] > max_orphans:
        print(
            f"[FAIL] unreachableCount {totals['unreachableCount']} exceeds "
            f"--max-orphans {max_orphans}.",
            file=sys.stderr,
        )
        return 1

    return 0


def cmd_update() -> int:
    report = build_report()
    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    _REPORT_PATH.write_text(_serialize(report), encoding="utf-8")
    totals = report["totals"]
    print(
        f"[OK] wrote {_REPORT_PATH.relative_to(_REPO_ROOT)}: "
        f"{totals['unreachableCount']} unreachable / {totals['schemaFileCount']} total"
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
        help="Check that the checked-in report is up-to-date (default).",
    )
    mode.add_argument(
        "--update",
        action="store_true",
        default=False,
        help="Regenerate the report and write it to disk.",
    )
    parser.add_argument(
        "--max-orphans",
        type=int,
        default=None,
        help=(
            "OPTIONAL future gate (--check only): fail if unreachableCount "
            "exceeds this. NOT wired into CI yet -- the orphan set is non-empty "
            "on arrival and a gate that is red the day it lands gets disabled "
            "(direct precedent for that exists in this workspace). Once the "
            "backlog reaches zero, wire `--max-orphans 0` into "
            ".github/workflows/schema-orphan-check.yml instead of hand-editing "
            "a number here."
        ),
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.update:
        sys.exit(cmd_update())
    else:
        sys.exit(cmd_check(args.max_orphans))


if __name__ == "__main__":
    main()
