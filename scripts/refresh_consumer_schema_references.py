#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""refresh_consumer_schema_references.py — refresh the cross-repo consumer
reference manifest used by ``scripts/schema_reachability.py`` rule 3.

WORKSPACE-ONLY TOOL. This repo's own CI has no checkout of Traigent,
TraigentBackend, TraigentFrontend, traigent-js, or traigent-smartopt, so this
script cannot run there and is not wired into any GitHub workflow. It is run
manually, from the multi-repo workspace, against fresh checkouts of those five
repos, and its output — ``reports/schema_reachability/consumer_
references.json`` — is committed so the (CI-runnable) reachability gate can
read it without needing those checkouts itself.

What this measures
-------------------
For every schema basename under ``traigent_schema/schemas/`` (e.g.
``agent_schema.json``), does that EXACT literal token — including the
``.json`` suffix — appear anywhere in a consumer repo's tracked source at the
given ref? A hit is recorded per repo with up to a few sample sites
(file:line) for human spot-checking.

Why the ``.json`` suffix is required, not optional
----------------------------------------------------
An earlier version of this scan also matched the bare stem (e.g.
``report_schema`` without ``.json``) and produced a confirmed false positive:
traigent-smartopt uses a dict key literally named ``report_schema`` as an
internal version tag (``"report_schema": "tier25-stage0-v2"``), which has
nothing to do with ``results/report_schema.json``. Bare ``*_schema`` stems are
ordinary compound technical phrases and collide with unrelated identifiers;
requiring the ``.json`` suffix turns a match into an actual file reference.
This trades away references made ONLY via a bare stem (e.g. a
``validator.validate_json(data, "report_schema")`` call with no ``.json``
literal anywhere nearby) — a real but believed-rare pattern; grep the sample
sites in the output if you suspect a specific schema is affected.

Known limitations (read before trusting a "reachable via rule 3" verdict)
---------------------------------------------------------------------------
* Literal-name matching only. A schema referenced only by a dynamically
  constructed name, or only by its ``$id`` URL host+path with the bare
  filename never appearing as a standalone token, is invisible here.
* A WILDCARD/domain-level consumer (e.g. traigent-js's
  ``scripts/generate-schema-types.mjs``, which walks whole schema
  subdirectories and generates TypeScript types for every ``*_schema.json``
  file it finds, rather than naming files individually) is only caught
  because its GENERATED output happens to embed a ``// source: <path>``
  comment per file. If a future codegen script stops emitting that trace
  comment, its whole domain's schemas would silently stop being detected here
  even though they are still genuinely consumed. There's no rule-based
  substitute for this short of parsing every consumer's build tooling.
* A textual mention (including inside a historical ``reports/*.md`` narrative
  write-up, a stale/quarantined test, or a code comment) counts identically to
  an active, load-bearing reference. This snapshot cannot distinguish live
  consumption from dead-but-still-present mentions, so on net it is more
  likely to UNDER-count orphans (rescue something not really used) than
  over-count them — which is the direction this repo's own reachability gate
  wants to err, per its "do not falsely orphan something a consumer imports"
  design goal.
* This file is a snapshot as of the shas recorded in ``sources``. Unlike
  ``parity/python-js-sdk.json`` (which hashes THIS repo's own schema tree and
  can therefore detect its own staleness), there is no cheap way for
  TraigentSchema's CI to hash 4 sibling repos it cannot see — so
  ``schema_reachability.py --check`` can verify this manifest is
  internally well-formed and consistently applied, but NOT that it is still
  current. Re-run this script periodically (e.g. before a scheduled
  reachability review) or after a consumer repo lands a new schema
  integration you know about.

Usage
-----
    python3 scripts/refresh_consumer_schema_references.py \\
        --repo Traigent=/path/to/core_project/develop/Traigent \\
        --repo TraigentBackend=/path/to/core_project/develop/TraigentBackend \\
        --repo TraigentFrontend=/path/to/core_project/develop/TraigentFrontend \\
        --repo traigent-js=/path/to/core_project/develop/traigent-js \\
        --repo traigent-smartopt=/path/to/core_project/develop/traigent-smartopt

By default each ``--repo`` path is archived at ``origin/<ref>`` (default
``develop``, matching this workspace's PR-target policy for all five) into a
clean temp directory before scanning — this avoids scanning a dirty or
behind-origin working tree (see this workspace's "review-freshness guard").
Pass ``--no-archive`` to scan a path's on-disk contents as-is instead (only
appropriate if you already extracted a known-clean tree yourself, e.g. via
``git archive`` into a scratch directory).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS_DIR = _REPO_ROOT / "traigent_schema" / "schemas"
_OUT_PATH = _REPO_ROOT / "reports" / "schema_reachability" / "consumer_references.json"

_TEXT_EXT = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".yaml", ".yml",
    ".toml", ".cfg", ".ini", ".txt", ".sh", ".mjs", ".cjs", ".graphql",
}
_SKIP_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", "node_modules"}
# Lock files are hash/version ledgers, not source code choosing to load a
# schema by name -- excluded so a coincidental hash collision can't hit.
_SKIP_FILENAMES = {"package-lock.json", "uv.lock", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"}
_MAX_SAMPLE_SITES = 5

_SAFE_REPO_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Shared path/git-ref containment helpers (scripts/_path_safety.py) — see that module's
# docstring for why these are no longer copy-pasted between the two scripts. Single
# `import ... as` so isort/ruff-format keeps it to one statement.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import _path_safety as _ps  # noqa: E402  (deliberately follows the sys.path insert above)

_is_relative_to = _ps.is_relative_to
_resolve_existing_dir = _ps.resolve_existing_dir
_resolve_path_within = _ps.resolve_path_within
_safe_git_ref = _ps.safe_git_ref
_validate_tar_members_stay_within = _ps.validate_tar_members_stay_within


def _resolve_git_repo(raw_path: str | Path, arg_name: str) -> Path:
    repo_path = _resolve_existing_dir(raw_path, arg_name)
    if not (repo_path / ".git").exists():
        raise ValueError(f"{arg_name} is not a git checkout: {repo_path}")
    return repo_path


def _safe_repo_name(raw_name: str) -> str:
    name = raw_name.strip()
    if name != raw_name or not name:
        raise ValueError(
            "--repo NAME must be non-empty and have no surrounding whitespace"
        )
    if not _SAFE_REPO_NAME_RE.fullmatch(name):
        raise ValueError(f"--repo NAME contains unsupported characters: {raw_name!r}")
    return name


def _schema_basenames() -> list[str]:
    return sorted(p.name for p in _SCHEMAS_DIR.rglob("*.json"))


def _iter_text_files(root: Path):
    safe_root = _resolve_existing_dir(root, "scan root")
    for path in safe_root.rglob("*"):
        try:
            resolved_path = path.resolve()
            rel_parts = path.relative_to(safe_root).parts
        except (OSError, ValueError):
            continue
        if (
            resolved_path != safe_root
            and not _is_relative_to(resolved_path, safe_root)
        ):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        if path.name in _SKIP_FILENAMES:
            continue
        if path.suffix.lower() not in _TEXT_EXT:
            continue
        yield path


def _archive_ref(repo_path: Path, ref: str, dest: Path, archive_root: Path) -> str:
    """git-archive ``origin/<ref>`` into ``dest`` and return its resolved sha."""
    safe_repo_path = _resolve_git_repo(repo_path, "--repo PATH")
    safe_ref = _safe_git_ref(ref, "--ref")
    remote_ref = _safe_git_ref(f"origin/{safe_ref}", "remote ref")
    safe_dest = _resolve_path_within(dest, archive_root, "archive destination")
    sha = subprocess.run(
        ["git", "-C", str(safe_repo_path), "rev-parse", remote_ref],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    safe_dest.mkdir(parents=True, exist_ok=True)
    archive_proc = subprocess.run(
        ["git", "-C", str(safe_repo_path), "archive", remote_ref],
        check=True,
        capture_output=True,
    )
    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp_tar:
        tmp_tar.write(archive_proc.stdout)
        tmp_tar.flush()
        with tarfile.open(tmp_tar.name) as tar:
            _validate_tar_members_stay_within(tar, safe_dest)
            tar.extractall(safe_dest)
    return sha


def _scan_repo(root: Path, pattern: re.Pattern[str]) -> dict[str, list[str]]:
    """Return basename -> [relpath:line, ...] (capped) for this one repo root."""
    hits: dict[str, list[str]] = {}
    safe_root = _resolve_existing_dir(root, "scan root")
    for path in _iter_text_files(safe_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not text:
            continue
        rel = path.relative_to(safe_root).as_posix()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in pattern.finditer(line):
                basename = match.group(1)
                sites = hits.setdefault(basename, [])
                if len(sites) < _MAX_SAMPLE_SITES:
                    sites.append(f"{rel}:{lineno}")
    return hits


def _build_pattern(basenames: list[str]) -> re.Pattern[str]:
    # Longest-first alternation + "not adjacent to another identifier char"
    # boundary. Deliberately does NOT exclude '/' or '.' from the boundary set:
    # the most common way a consumer names a schema is embedded in a path
    # ("schemas/projects/foo_schema.json") or a generated-file comment
    # ("// source: traigent_schema/schemas/x.json") -- excluding '/' there
    # silently drops most real references.
    terms = sorted(set(basenames), key=len, reverse=True)
    alternation = "|".join(re.escape(t) for t in terms)
    return re.compile(r"(?<![A-Za-z0-9_])(" + alternation + r")(?![A-Za-z0-9_])")


def _parse_repo_arg(raw: str) -> tuple[str, Path]:
    if "=" not in raw:
        raise ValueError(f"--repo must be NAME=PATH, got: {raw!r}")
    name, _, path_str = raw.partition("=")
    return _safe_repo_name(name), Path(path_str).expanduser().resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--repo",
        action="append",
        required=True,
        metavar="NAME=PATH",
        help="A consumer repo checkout, repeatable. E.g. --repo Traigent=/path/to/Traigent",
    )
    parser.add_argument(
        "--ref",
        default="develop",
        help="Branch to archive as origin/<ref> for every --repo (default: develop, "
        "matching this workspace's PR-target policy for all five consumer repos).",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Scan each --repo path's on-disk contents as-is instead of git-archiving "
        "origin/<ref> into a clean temp dir first. Only use this if you already "
        "extracted a known-clean tree yourself.",
    )
    args = parser.parse_args()

    try:
        ref = _safe_git_ref(args.ref, "--ref")
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    basenames = _schema_basenames()
    pattern = _build_pattern(basenames)

    sources: dict[str, dict[str, str]] = {}
    all_hits: dict[str, dict[str, list[str]]] = {}

    with tempfile.TemporaryDirectory(prefix="consumer-schema-scan-") as tmp_root_str:
        tmp_root = Path(tmp_root_str).resolve()
        for raw in args.repo:
            try:
                name, path = _parse_repo_arg(raw)
                if args.no_archive:
                    scan_root = _resolve_existing_dir(path, f"--repo {name}=PATH")
                    sources[name] = {"ref": "(unarchived on-disk path)", "sha": "unknown"}
                else:
                    source_repo = _resolve_git_repo(path, f"--repo {name}=PATH")
                    scan_root = _resolve_path_within(tmp_root / name, tmp_root, "scan root")
                    sha = _archive_ref(source_repo, ref, scan_root, tmp_root)
                    sources[name] = {"ref": f"origin/{ref}", "sha": sha}
            except ValueError as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2

            repo_hits = _scan_repo(scan_root, pattern)
            print(f"{name}: {len(repo_hits)} schema basenames referenced", file=sys.stderr)
            for basename, sites in repo_hits.items():
                all_hits.setdefault(basename, {})[name] = sites

    manifest = {
        "manifestVersion": 1,
        "description": (
            "Snapshot of literal schema-filename references found in the 5 "
            "consumer repos (Traigent, TraigentBackend, TraigentFrontend, "
            "traigent-js, traigent-smartopt). Feeds rule 3 of "
            "scripts/schema_reachability.py. Refreshed manually via "
            "scripts/refresh_consumer_schema_references.py -- see that "
            "script's module docstring for what this cannot see."
        ),
        "sources": sources,
        "referencedBasenames": sorted(all_hits.keys()),
        "referenceSites": {k: all_hits[k] for k in sorted(all_hits.keys())},
    }

    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _OUT_PATH.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        f"[OK] wrote {_OUT_PATH.relative_to(_REPO_ROOT)}: "
        f"{len(all_hits)} basenames referenced across {len(sources)} repos.\n"
        f"     Now run: python3 scripts/schema_reachability.py --update",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
