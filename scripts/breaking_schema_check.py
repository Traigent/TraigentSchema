#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""
breaking_schema_check.py — a contract breaking-change gate for traigent_schema/schemas/**.

Why
---
This repository is the single source of truth for API contracts consumed by the SDK, the
backend, and the frontend. A schema file can drift out from under a hand-written DTO (or a
generated client) with nothing catching it — TraigentSchema's own tests only prove the schema
tree is internally *valid*, not that a change to it is *compatible* with what shipped before.
A codegen coexistence report run 2026-08-07 found 19 of 66 schema/DTO pairs disagreeing, two of
them live contract violations (`ConfigurationRunDTO`/`configuration_run_schema.json`,
`ExperimentRunDTO`). This script is Azure's `BreakingChange` PR check, scoped to this repo.

What it does
------------
For every ``traigent_schema/schemas/**/*.json`` file that changed between a base ref and a head
ref (default: the merge-base with ``origin/develop``/``origin/main`` vs. the working tree), it
diffs the OLD and NEW shape of the schema and classifies every difference as BREAKING or
non-breaking (informational).

The direction that counts as "breaking" is NOT the same for every schema: a *request* schema
getting stricter breaks clients that submit the old shape; a *response* schema getting *looser*
(guaranteeing less than before) breaks clients that consume the old shape. See
``classify_file_role`` and ``_keyword_finding`` for the full mirror-image rule table, and
``docs/`` / the PR description this script shipped with for the write-up of *why* each direction
is what it is.

Differ choice
-------------
This hand-writes the structural comparator, but NOT the $ref resolution: that reuses the
``referencing`` library (already a pinned runtime dependency of this very package — see
``traigent_schema/validator.py``, which resolves the exact same cross-file ``$ref`` graph the
same way). Two PyPI packages that look adjacent (``jsonschema-diff``, ``api-schema-diff``) were
evaluated and rejected — see the PR description for why (short version: neither understands a
multi-file ``$ref`` graph the way this repo uses it, and neither can know this repo's
request/response mirror-image semantics, which is the actual hard part).

Usage
-----
    python scripts/breaking_schema_check.py --check
    python scripts/breaking_schema_check.py --check --base-ref origin/develop --head-ref HEAD
    # seed a historical commit:
    python scripts/breaking_schema_check.py --check --base-ref <sha>^1 --head-ref <sha>

Exit codes
----------
0  No un-acknowledged BREAKING findings.
1  At least one BREAKING finding is not covered by scripts/breaking_schema_allowlist.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import quote, urldefrag, urljoin, urlparse

from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMAS_SUBDIR = "traigent_schema/schemas"
SCHEMA_ID_BASE = "https://schemas.traigent.ai/"
DEFAULT_ALLOWLIST = REPO_ROOT / "scripts" / "breaking_schema_allowlist.json"

# Shared path/git-ref containment helpers (scripts/_path_safety.py). These used to be
# copy-pasted into this file AND refresh_consumer_schema_references.py; the copies drifted
# and only one of them gained tar-member validation, so they now live in one place.
#
# scripts/ is sys.path[0] when this file runs as a script, but not when a test loads it via
# spec_from_file_location (tests/test_breaking_schema_check.py deliberately avoids putting
# scripts/ on sys.path), so the directory is added here first. A single `import ... as`
# keeps this to one statement that isort/ruff-format will not split apart.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import _path_safety as _ps  # noqa: E402  (deliberately follows the sys.path insert above)

_is_relative_to = _ps.is_relative_to
_extract_validated_tar_members = _ps.extract_validated_tar_members
_resolve_path_within = _ps.resolve_path_within
_safe_git_ref = _ps.safe_git_ref

Role = Literal["request", "response", "conservative"]
Severity = Literal["BREAKING", "INFO"]

_MAX_KEYS = ("maxLength", "maximum", "maxItems", "maxProperties")
_MIN_KEYS = ("minLength", "minimum", "minItems", "minProperties")


def _resolve_repo_root(raw_path: str | Path) -> Path:
    repo_root = Path(raw_path).expanduser().resolve()
    if not repo_root.is_dir():
        raise ValueError(f"--repo-root is not a directory: {repo_root}")
    if not (repo_root / ".git").exists():
        raise ValueError(f"--repo-root is not a git checkout: {repo_root}")
    schemas_dir = _resolve_path_within(repo_root / SCHEMAS_SUBDIR, repo_root, SCHEMAS_SUBDIR)
    if not schemas_dir.is_dir():
        raise ValueError(f"--repo-root does not contain {SCHEMAS_SUBDIR}: {repo_root}")
    return repo_root


def _as_dict(value: Any) -> dict[str, Any]:
    """Narrow an untrusted JSON value to a dict, or {} — used throughout so a malformed/
    unexpected shape (e.g. `properties` accidentally a list) degrades to "nothing here"
    instead of crashing the gate."""
    return value if isinstance(value, dict) else {}


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    file: str
    pointer: str
    rule: str
    severity: Severity
    role: str
    message: str
    subject: Any = None
    old: Any = None
    new: Any = None

    def identity(self) -> dict[str, Any]:
        """Return the structured, stable identity used by allowlist matching."""
        return {
            "pointer": self.pointer,
            "role": self.role,
            "subject": _canonical_value(self.subject),
            "old": _canonical_value(self.old),
            "new": _canonical_value(self.new),
        }

    def fingerprint(self) -> str:
        """Return a deterministic digest of the complete finding identity."""
        payload = {"file": self.file, "rule": self.rule, **self.identity()}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def line(self) -> str:
        tag = "BREAKING" if self.severity == "BREAKING" else "info    "
        return (
            f"  [{tag}] {self.pointer}  ({self.rule}, role={self.role})\n            {self.message}"
        )


def emit(
    findings: list[Finding],
    file: str,
    pointer: str,
    rule: str,
    severity: Severity,
    role: str,
    message: str,
    *,
    subject: Any = None,
    old: Any = None,
    new: Any = None,
) -> None:
    findings.append(
        Finding(
            file=file,
            pointer=pointer,
            rule=rule,
            severity=severity,
            role=role,
            message=message,
            subject=subject,
            old=old,
            new=new,
        )
    )


def _canonical_value(value: Any) -> Any:
    """Normalize JSON-like values for deterministic finding identities."""
    if isinstance(value, (set, frozenset, tuple, list)):
        values = [_canonical_value(item) for item in value]
        if isinstance(value, (set, frozenset)):
            return sorted(values, key=lambda item: json.dumps(item, sort_keys=True))
        return values
    if isinstance(value, dict):
        return {str(key): _canonical_value(item) for key, item in sorted(value.items())}
    return value


def _keyword_finding(
    findings: list[Finding],
    file: str,
    pointer: str,
    role: Role,
    keyword: str,
    *,
    narrowed: bool,
    detail: str,
    subject: Any = None,
    old: Any = None,
    new: Any = None,
) -> None:
    """Route a single keyword-level diff through the role's mirror-image rule.

    ``narrowed=True``  means the schema now accepts/guarantees LESS than before — the classic
                        "request got stricter" direction.
    ``narrowed=False`` means the schema now accepts/guarantees MORE than before, OR walked back
                        a guarantee — the "response got looser" direction.

    request:      narrowed  -> BREAKING (a previously-valid submission is now rejected)
    response:     not narrowed -> BREAKING (a consumer relying on the old, tighter guarantee can
                  now see something it didn't plan for)
    conservative: either direction -> BREAKING (union of both rule sets — we don't know which
                  way this schema is used, so both a client-submits and a client-consumes
                  reading are treated as plausible)
    """
    if role == "request":
        severity: Severity = "BREAKING" if narrowed else "INFO"
    elif role == "response":
        severity = "BREAKING" if not narrowed else "INFO"
    else:
        severity = "BREAKING"
    suffix = f" [{subject}]" if subject else ""
    emit(
        findings,
        file,
        pointer,
        keyword,
        severity,
        role,
        detail + suffix,
        subject=subject if subject is not None else keyword,
        old=old,
        new=new,
    )


# ---------------------------------------------------------------------------
# Loading a schema tree (a directory on disk, materialized from disk or a git ref)
# ---------------------------------------------------------------------------


@dataclass
class SchemaTree:
    label: str
    files: dict[str, Any]
    registry: Registry
    file_base_uri: dict[str, str]

    def get(self, relpath: str) -> Any | None:
        return self.files.get(relpath)


def load_tree_from_dir(root: Path, label: str) -> SchemaTree:
    files: dict[str, Any] = {}
    bad: list[str] = []
    if root.is_dir():
        resolved_root = root.resolve()
        for f in sorted(root.rglob("*.json")):
            # rglob follows directory symlinks and read_text() follows file symlinks, so
            # a symlinked *.json could pull content from outside the tree into the diff
            # (and into the CI log). Skip links outright and re-check containment for
            # everything else.
            if f.is_symlink():
                continue
            try:
                resolved = f.resolve()
            except OSError:
                continue
            if not _is_relative_to(resolved, resolved_root):
                continue
            rel = f.relative_to(root).as_posix()
            try:
                files[rel] = json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                bad.append(f"{rel}: {exc}")
    if bad:
        raise SystemExit(f"Invalid JSON while loading {label}:\n  " + "\n  ".join(bad))
    registry, base_uri_for = _build_registry(files)
    return SchemaTree(label=label, files=files, registry=registry, file_base_uri=base_uri_for)


def _build_registry(files: dict[str, Any]) -> tuple[Registry, dict[str, str]]:
    """Register every file (resource schemas AND *_endpoints.json OpenAPI docs) so both
    cross-file $ref (e.g. evaluation/configuration_run_schema.json -> datasets/...) and a
    same-document self-$ref (an *_endpoints.json's own `#/definitions/...`, used for local
    reuse across its own paths) resolve. traigent_schema/validator.py only registers resource
    schemas because it never needs to resolve an endpoints doc's *own* internal $refs — this
    differ does, since it walks the raw OpenAPI structure directly (see compare_endpoints_file)."""
    resources: list[tuple[str, Resource]] = []
    base_uri_for: dict[str, str] = {}
    for rel, schema in files.items():
        if not isinstance(schema, dict):
            continue
        base_uri = schema.get("$id") or (SCHEMA_ID_BASE + rel)
        base_uri_for[rel] = base_uri
        contents = schema if schema.get("$id") == base_uri else {**schema, "$id": base_uri}
        try:
            if "_endpoints" in Path(rel).name:
                # OpenAPI docs declare "openapi": "3.0.0", not "$schema", so automatic
                # specification detection fails; they're still plain-enough JSON Schema
                # (definitions + $ref + JSON Pointer) for draft-07 resolution to work.
                resource = Resource(contents=contents, specification=DRAFT7)  # type: ignore[call-arg]
            else:
                resource = Resource.from_contents(contents)
        except Exception:  # noqa: BLE001 - a malformed/undetectable schema just can't be a $ref target
            continue
        resources.append((base_uri, resource))
    return Registry().with_resources(resources), base_uri_for


def load_tree_from_ref(repo_root: Path, ref: str, dest: Path, extraction_root: Path) -> SchemaTree:
    safe_repo_root = _resolve_repo_root(repo_root)
    safe_ref = _safe_git_ref(ref, "git ref")
    safe_dest = _resolve_path_within(dest, extraction_root, "archive destination")
    safe_dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(
        ["git", "-C", str(safe_repo_root), "archive", safe_ref, "--", SCHEMAS_SUBDIR],
        capture_output=True,
        check=True,
    )
    if not archive.stdout:
        raise ValueError(f"git archive contains no {SCHEMAS_SUBDIR}: {safe_ref}")
    # Extract via tarfile, not `tar -x`, so every member can be checked BEFORE it
    # lands: a member path containing `..`, or a symlink pointing outside the
    # destination, would otherwise let a crafted commit place or alias a file
    # anywhere this process can write, and the *.json reader below would then
    # happily read through it. The shared helper keeps this materialization rule
    # identical for both archive-consuming scripts.
    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp_tar:
        tmp_tar.write(archive.stdout)
        tmp_tar.flush()
        with tarfile.open(tmp_tar.name) as tar:
            _extract_validated_tar_members(tar, safe_dest, required_paths=(SCHEMAS_SUBDIR,))
    sha = subprocess.run(
        ["git", "-C", str(safe_repo_root), "rev-parse", "--short=12", safe_ref],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return load_tree_from_dir(safe_dest / SCHEMAS_SUBDIR, label=f"{safe_ref}@{sha}")


# ---------------------------------------------------------------------------
# $ref resolution (built on the `referencing` library — see module docstring)
# ---------------------------------------------------------------------------


class UnresolvedRef(Exception):
    pass


def _split_ref(base_uri: str, ref: str) -> tuple[str, str]:
    absolute = urljoin(base_uri, ref)
    doc_uri, frag = urldefrag(absolute)
    return doc_uri, frag


def _json_pointer_get(doc: Any, pointer: str) -> Any:
    if not pointer or pointer == "/":
        return doc
    node = doc
    for raw in pointer.lstrip("/").split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(pointer)
    return node


def deref(
    node: Any,
    base_uri: str,
    registry: Registry,
    visited: frozenset[str],
    *,
    max_hops: int = 25,
) -> tuple[Any, str, frozenset[str], bool]:
    """Fully resolve a (possibly chained, possibly cross-file) $ref.

    Returns (resolved_node, resolved_base_uri, updated_visited, cyclic). ``cyclic=True`` means
    resolution was stopped early (a real cycle, or a chain too deep to plausibly be legitimate)
    and the caller should not recurse further below this point.
    """
    hops = 0
    while isinstance(node, dict) and isinstance(node.get("$ref"), str):
        hops += 1
        if hops > max_hops:
            return node, base_uri, visited, True
        doc_uri, pointer = _split_ref(base_uri, node["$ref"])
        key = f"{doc_uri}#{pointer}"
        if key in visited:
            return node, base_uri, visited, True
        try:
            doc = registry.contents(doc_uri)
            target = _json_pointer_get(doc, pointer)
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a finding, not a crash
            raise UnresolvedRef(f"{node['$ref']} (resolved to {doc_uri}#{pointer}): {exc}") from exc
        visited = visited | {key}
        node, base_uri = target, doc_uri
    return node, base_uri, visited, False


# ---------------------------------------------------------------------------
# Structural comparator
# ---------------------------------------------------------------------------


def _type_set(schema: dict) -> frozenset[str] | None:
    t = schema.get("type")
    if t is None:
        return None
    if isinstance(t, str):
        return frozenset({t})
    if isinstance(t, list):
        return frozenset(t)
    return None


def _enum_set(schema: dict) -> frozenset[str] | None:
    e = schema.get("enum")
    if e is None:
        return None
    return frozenset(json.dumps(v, sort_keys=True) for v in e)


def _closedness_rank(schema: dict) -> int:
    """0 = open (extras of any shape allowed), 1 = constrained map (extras must match a value
    schema), 2 = fully closed (no extras at all). Higher = tighter."""
    ap = schema.get("additionalProperties", True)
    if ap is False:
        return 2
    if isinstance(ap, dict):
        return 1
    return 0


_CLOSEDNESS_LABEL = {
    0: "open (true/absent)",
    1: "constrained (a value schema)",
    2: "closed (false)",
}


def compare_node(  # noqa: PLR0913 - internal recursive worker, not a public API
    old_raw: Any,
    new_raw: Any,
    *,
    old_base: str,
    new_base: str,
    old_reg: Registry,
    new_reg: Registry,
    old_visited: frozenset[str],
    new_visited: frozenset[str],
    pointer: str,
    role: Role,
    file: str,
    findings: list[Finding],
    depth: int = 0,
) -> None:
    if depth > 60:
        emit(
            findings,
            file,
            pointer,
            "depth_limit",
            "INFO",
            role,
            "comparison stopped: nesting exceeded the safety depth limit",
        )
        return

    try:
        old, old_base, old_visited, old_cyclic = deref(old_raw, old_base, old_reg, old_visited)
    except UnresolvedRef as exc:
        emit(
            findings,
            file,
            pointer,
            "unresolved_ref",
            "BREAKING",
            role,
            f"$ref on the BASE side could not be resolved: {exc}",
        )
        return
    try:
        new, new_base, new_visited, new_cyclic = deref(new_raw, new_base, new_reg, new_visited)
    except UnresolvedRef as exc:
        emit(
            findings,
            file,
            pointer,
            "unresolved_ref",
            "BREAKING",
            role,
            f"$ref on the HEAD side could not be resolved: {exc}",
        )
        return

    if not isinstance(old, dict) or not isinstance(new, dict):
        if old != new:
            emit(
                findings,
                file,
                pointer,
                "leaf_changed",
                "INFO",
                role,
                f"non-object schema fragment changed: {old!r} -> {new!r} (manual review)",
            )
        return

    if old_cyclic or new_cyclic:
        emit(
            findings,
            file,
            pointer,
            "cyclic_ref",
            "INFO",
            role,
            "recursive $ref chain detected at or below this point; not compared further",
        )
        return

    # ---- type ----
    old_types, new_types = _type_set(old), _type_set(new)
    if old_types != new_types:
        removed = (old_types or frozenset()) - (new_types or frozenset())
        added = (new_types or frozenset()) - (old_types or frozenset())
        if old_types is None and new_types is not None:
            removed = frozenset({"<was unconstrained>"})
        if new_types is None and old_types is not None:
            added = frozenset({"<now unconstrained>"})
        old_repr = sorted(old_types) if old_types else None
        new_repr = sorted(new_types) if new_types else None
        if removed:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "type",
                narrowed=True,
                detail=f"type no longer allows {sorted(removed)} (was {old_repr}, now {new_repr})",
                subject={"direction": "removed", "values": sorted(removed)},
                old=old_repr,
                new=new_repr,
            )
        if added:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "type",
                narrowed=False,
                detail=(
                    f"type now additionally allows {sorted(added)} (was {old_repr}, now {new_repr})"
                ),
                subject={"direction": "added", "values": sorted(added)},
                old=old_repr,
                new=new_repr,
            )

    # ---- enum ----
    old_enum, new_enum = _enum_set(old), _enum_set(new)
    if old_enum != new_enum and (old_enum is not None or new_enum is not None):
        removed_e = (old_enum or frozenset()) - (new_enum or frozenset())
        added_e = (new_enum or frozenset()) - (old_enum or frozenset())
        if old_enum is not None and new_enum is None:
            removed_e = frozenset({"<enum constraint removed entirely>"})
        if new_enum is not None and old_enum is None:
            added_e = frozenset({"<enum constraint added>"})
        if removed_e:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "enum",
                narrowed=True,
                detail=f"enum member(s) removed: {sorted(removed_e)}",
                subject={"direction": "removed", "values": sorted(removed_e)},
                old=sorted(old_enum) if old_enum is not None else None,
                new=sorted(new_enum) if new_enum is not None else None,
            )
        if added_e:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "enum",
                narrowed=False,
                detail=f"enum member(s) added: {sorted(added_e)}",
                subject={"direction": "added", "values": sorted(added_e)},
                old=sorted(old_enum) if old_enum is not None else None,
                new=sorted(new_enum) if new_enum is not None else None,
            )

    # ---- additionalProperties: open/constrained/closed, and a map's value schema ----
    old_rank, new_rank = _closedness_rank(old), _closedness_rank(new)
    if old_rank != new_rank:
        _keyword_finding(
            findings,
            file,
            pointer,
            role,
            "additionalProperties",
            narrowed=new_rank > old_rank,
            detail=(
                f"additionalProperties {_CLOSEDNESS_LABEL[old_rank]} -> "
                f"{_CLOSEDNESS_LABEL[new_rank]}"
            ),
            old=_CLOSEDNESS_LABEL[old_rank],
            new=_CLOSEDNESS_LABEL[new_rank],
        )
    old_ap, new_ap = old.get("additionalProperties"), new.get("additionalProperties")
    if isinstance(old_ap, dict) and isinstance(new_ap, dict):
        compare_node(
            old_ap,
            new_ap,
            old_base=old_base,
            new_base=new_base,
            old_reg=old_reg,
            new_reg=new_reg,
            old_visited=old_visited,
            new_visited=new_visited,
            pointer=f"{pointer}/additionalProperties",
            role=role,
            file=file,
            findings=findings,
            depth=depth + 1,
        )

    # ---- pattern ----
    old_pat, new_pat = old.get("pattern"), new.get("pattern")
    if old_pat != new_pat:
        if old_pat is None and new_pat is not None:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "pattern",
                narrowed=True,
                detail=f"pattern constraint added: {new_pat!r} (previously unconstrained)",
                old=old_pat,
                new=new_pat,
            )
        elif old_pat is not None and new_pat is None:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "pattern",
                narrowed=False,
                detail=f"pattern constraint removed (was {old_pat!r})",
                old=old_pat,
                new=new_pat,
            )
        else:
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "pattern",
                narrowed=True,
                detail=(
                    f"pattern changed: {old_pat!r} -> {new_pat!r} (regex containment isn't "
                    "decidable in general; treated conservatively as a narrowing — verify by hand)"
                ),
                old=old_pat,
                new=new_pat,
            )

    # ---- bounds ----
    for kw in _MAX_KEYS:
        ov, nv = old.get(kw), new.get(kw)
        if ov != nv:
            ov_eff = ov if ov is not None else float("inf")
            nv_eff = nv if nv is not None else float("inf")
            if nv_eff < ov_eff:
                _keyword_finding(
                    findings,
                    file,
                    pointer,
                    role,
                    kw,
                    narrowed=True,
                    detail=f"{kw} lowered: {ov} -> {nv}",
                    old=ov,
                    new=nv,
                )
            elif nv_eff > ov_eff:
                _keyword_finding(
                    findings,
                    file,
                    pointer,
                    role,
                    kw,
                    narrowed=False,
                    detail=f"{kw} raised: {ov} -> {nv}",
                    old=ov,
                    new=nv,
                )
    for kw in _MIN_KEYS:
        ov, nv = old.get(kw), new.get(kw)
        if ov != nv:
            ov_eff = ov if ov is not None else float("-inf")
            nv_eff = nv if nv is not None else float("-inf")
            if nv_eff > ov_eff:
                _keyword_finding(
                    findings,
                    file,
                    pointer,
                    role,
                    kw,
                    narrowed=True,
                    detail=f"{kw} raised: {ov} -> {nv}",
                    old=ov,
                    new=nv,
                )
            elif nv_eff < ov_eff:
                _keyword_finding(
                    findings,
                    file,
                    pointer,
                    role,
                    kw,
                    narrowed=False,
                    detail=f"{kw} lowered: {ov} -> {nv}",
                    old=ov,
                    new=nv,
                )

    # ---- required ----
    old_req, new_req = set(old.get("required") or []), set(new.get("required") or [])
    if old_req != new_req:
        for name in sorted(new_req - old_req):
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "required",
                narrowed=True,
                subject=name,
                detail=f"'{name}' added to required",
                old=False,
                new=True,
            )
        for name in sorted(old_req - new_req):
            _keyword_finding(
                findings,
                file,
                pointer,
                role,
                "required",
                narrowed=False,
                subject=name,
                detail=f"'{name}' removed from required",
                old=True,
                new=False,
            )

    # ---- properties (recurse) ----
    old_props = _as_dict(old.get("properties"))
    new_props = _as_dict(new.get("properties"))
    for name in sorted(set(old_props) | set(new_props)):
        child_pointer = f"{pointer}/properties/{name}"
        if name in old_props and name not in new_props:
            if new_rank >= 1:
                _keyword_finding(
                    findings,
                    file,
                    child_pointer,
                    role,
                    "property_removed",
                    narrowed=True,
                    detail=f"property '{name}' removed",
                    subject=name,
                    old=True,
                    new=False,
                )
            else:
                emit(
                    findings,
                    file,
                    child_pointer,
                    "property_removed",
                    "INFO",
                    role,
                    (
                        f"property '{name}' removed from the schema, but additionalProperties "
                        "stays open on the new side — a payload/response that still carries "
                        f"'{name}' remains schema-valid, it just loses type-checking on that field"
                    ),
                )
        elif name not in old_props and name in new_props:
            # A request can safely grow an object shape: submissions valid against the
            # old schema remain valid.  A response is the mirror image only when old
            # consumers could already accept the new member.  An old closed object
            # rejects every newly-emitted member; an old constrained map may reject
            # it depending on its value schema.  Both are a compatibility risk for a
            # response consumer, so route it through the normal role matrix instead
            # of unconditionally calling it informational.
            #
            # This intentionally applies whether the new property is optional or
            # required.  ``required`` answers whether the producer promises to emit
            # it, not whether an old strict consumer can parse it when it does.
            if old_rank >= 1:
                _keyword_finding(
                    findings,
                    file,
                    child_pointer,
                    role,
                    "property_added",
                    narrowed=False,
                    detail=(
                        f"property '{name}' added while the old schema's "
                        f"additionalProperties was {_CLOSEDNESS_LABEL[old_rank]}; "
                        "an old response consumer may reject that newly-emitted member"
                    ),
                    subject=name,
                    old=False,
                    new=True,
                )
            else:
                emit(
                    findings,
                    file,
                    child_pointer,
                    "property_added",
                    "INFO",
                    role,
                    (
                        f"property '{name}' added while the old schema was open; "
                        "old consumers already accepted unknown members (optional unless "
                        "also newly required — see 'required' findings above)"
                    ),
                )
        else:
            compare_node(
                old_props[name],
                new_props[name],
                old_base=old_base,
                new_base=new_base,
                old_reg=old_reg,
                new_reg=new_reg,
                old_visited=old_visited,
                new_visited=new_visited,
                pointer=child_pointer,
                role=role,
                file=file,
                findings=findings,
                depth=depth + 1,
            )

    # ---- patternProperties (recurse, keyed by exact regex string) ----
    old_pp = _as_dict(old.get("patternProperties"))
    new_pp = _as_dict(new.get("patternProperties"))
    for pat in sorted(set(old_pp) | set(new_pp)):
        child_pointer = f"{pointer}/patternProperties/{pat}"
        if pat in old_pp and pat not in new_pp:
            severity_narrowed = new_rank >= 1
            _keyword_finding(
                findings,
                file,
                child_pointer,
                role,
                "patternProperties_removed",
                narrowed=severity_narrowed,
                detail=f"patternProperties key {pat!r} removed",
                subject=pat,
                old=True,
                new=False,
            )
        elif pat not in old_pp and pat in new_pp:
            if old_rank >= 1:
                _keyword_finding(
                    findings,
                    file,
                    child_pointer,
                    role,
                    "patternProperties_added",
                    narrowed=False,
                    detail=(
                        f"patternProperties key {pat!r} added while the old schema's "
                        f"additionalProperties was {_CLOSEDNESS_LABEL[old_rank]}; matching "
                        "members accepted by the new response may be rejected by an old consumer"
                    ),
                    subject=pat,
                    old=False,
                    new=True,
                )
            else:
                emit(
                    findings,
                    file,
                    child_pointer,
                    "patternProperties_added",
                    "INFO",
                    role,
                    (
                        f"patternProperties key {pat!r} added while the old schema was open; "
                        "old consumers already accepted matching unknown members"
                    ),
                )
        else:
            compare_node(
                old_pp[pat],
                new_pp[pat],
                old_base=old_base,
                new_base=new_base,
                old_reg=old_reg,
                new_reg=new_reg,
                old_visited=old_visited,
                new_visited=new_visited,
                pointer=child_pointer,
                role=role,
                file=file,
                findings=findings,
                depth=depth + 1,
            )

    # ---- items (array element schema) ----
    old_items, new_items = old.get("items"), new.get("items")
    if isinstance(old_items, dict) and isinstance(new_items, dict):
        compare_node(
            old_items,
            new_items,
            old_base=old_base,
            new_base=new_base,
            old_reg=old_reg,
            new_reg=new_reg,
            old_visited=old_visited,
            new_visited=new_visited,
            pointer=f"{pointer}/items",
            role=role,
            file=file,
            findings=findings,
            depth=depth + 1,
        )
    elif old_items is None and isinstance(new_items, dict):
        _keyword_finding(
            findings,
            file,
            f"{pointer}/items",
            role,
            "items",
            narrowed=True,
            detail="array items constraint added (elements were previously unconstrained)",
            old=old_items,
            new=new_items,
        )
    elif isinstance(old_items, dict) and new_items is None:
        _keyword_finding(
            findings,
            file,
            f"{pointer}/items",
            role,
            "items",
            narrowed=False,
            detail="array items constraint removed (elements are now unconstrained)",
            old=old_items,
            new=new_items,
        )
    elif old_items != new_items and (old_items is not None or new_items is not None):
        emit(
            findings,
            file,
            f"{pointer}/items",
            "items_structure_changed",
            "INFO",
            role,
            (
                "items uses tuple-validation (a list) or another shape this differ doesn't "
                "model precisely — manual review"
            ),
        )

    # ---- oneOf / anyOf / allOf (positional, best-effort) ----
    for combinator in ("oneOf", "anyOf", "allOf"):
        old_list, new_list = old.get(combinator), new.get(combinator)
        if old_list is None and new_list is None:
            continue
        if old_list is None and isinstance(new_list, list):
            if combinator == "allOf" and not new_list:
                emit(
                    findings,
                    file,
                    f"{pointer}/{combinator}",
                    f"{combinator}_added",
                    "INFO",
                    role,
                    (
                        "empty allOf appeared; it accepts every instance and does not "
                        "change the contract"
                    ),
                )
            else:
                _keyword_finding(
                    findings,
                    file,
                    f"{pointer}/{combinator}",
                    role,
                    f"{combinator}_added",
                    narrowed=True,
                    detail=f"{combinator} constraint appeared ({len(new_list)} branch(es))",
                    subject=combinator,
                    old=0,
                    new=len(new_list),
                )
            continue
        if isinstance(old_list, list) and new_list is None:
            if combinator == "allOf" and not old_list:
                emit(
                    findings,
                    file,
                    f"{pointer}/{combinator}",
                    f"{combinator}_removed",
                    "INFO",
                    role,
                    (
                        "empty allOf disappeared; it accepted every instance and did not "
                        "constrain the contract"
                    ),
                )
            else:
                _keyword_finding(
                    findings,
                    file,
                    f"{pointer}/{combinator}",
                    role,
                    f"{combinator}_removed",
                    narrowed=False,
                    detail=f"{combinator} constraint disappeared ({len(old_list)} branch(es))",
                    subject=combinator,
                    old=len(old_list),
                    new=0,
                )
            continue
        if not isinstance(old_list, list) or not isinstance(new_list, list):
            emit(
                findings,
                file,
                f"{pointer}/{combinator}",
                f"{combinator}_shape_changed",
                "BREAKING",
                role,
                (
                    f"{combinator} is not a list on one or both sides; direction cannot be "
                    "established, so the malformed/unsupported change is flagged conservatively"
                ),
            )
            continue
        if len(old_list) != len(new_list):
            emit(
                findings,
                file,
                f"{pointer}/{combinator}",
                f"{combinator}_branch_count_changed",
                "BREAKING",
                role,
                (
                    f"{combinator} branch count changed ({len(old_list)} -> {len(new_list)}); "
                    "branches can't be confidently aligned positionally to classify direction, "
                    "flagged conservatively — review by hand"
                ),
                subject=combinator,
                old=len(old_list),
                new=len(new_list),
            )
            continue
        for i, (ob, nb) in enumerate(zip(old_list, new_list, strict=True)):
            compare_node(
                ob,
                nb,
                old_base=old_base,
                new_base=new_base,
                old_reg=old_reg,
                new_reg=new_reg,
                old_visited=old_visited,
                new_visited=new_visited,
                pointer=f"{pointer}/{combinator}/{i}",
                role=role,
                file=file,
                findings=findings,
                depth=depth + 1,
            )


# ---------------------------------------------------------------------------
# OpenAPI (*_endpoints.json) walker: local request/response context is unambiguous here
# ---------------------------------------------------------------------------


def _localize_schema_fragment(
    reg: Registry, base_uri: str, fragment_pointer: str, fragment: Any
) -> tuple[Registry, str]:
    """*_endpoints.json request/response schemas are often inlined with their own local
    `definitions`/`$defs`, self-$ref'd as `#/definitions/X` — which is only valid if THIS
    fragment (not the whole enclosing OpenAPI document) is treated as the base resource, i.e.
    exactly how a validator that extracts this one fragment and calls
    jsonschema.validate(instance, schema=fragment) would resolve it. Register the fragment
    under a synthetic per-pointer $id so such refs resolve against it, not the document root."""
    if not (isinstance(fragment, dict) and ("definitions" in fragment or "$defs" in fragment)):
        return reg, base_uri
    # A "#..." fragment on base_uri would be silently discarded by RFC 3986 fragment-only
    # resolution (urljoin replaces the whole fragment, keeping only the non-fragment part of
    # base_uri) — so the synthetic scope has to be a distinct DOCUMENT uri, not just a
    # different fragment on the same one. A query string does that without colliding with any
    # real schema $id (none of this repo's schemas use query strings in their $id).
    local_uri = f"{base_uri}?local-fragment-scope={quote(fragment_pointer, safe='')}"
    try:
        resource = Resource(contents=fragment, specification=DRAFT7)  # type: ignore[call-arg]
    except Exception:  # noqa: BLE001 - fall back to document-root resolution
        return reg, base_uri
    return reg.with_resource(local_uri, resource), local_uri


def _compare_media_schemas(
    old_content, new_content, *, role, file, pointer, old_base, new_base, old_reg, new_reg, findings
):
    old_content = _as_dict(old_content)
    new_content = _as_dict(new_content)
    for media_type in sorted(set(old_content) | set(new_content)):
        old_schema = (
            (old_content.get(media_type) or {}).get("schema") if media_type in old_content else None
        )
        new_schema = (
            (new_content.get(media_type) or {}).get("schema") if media_type in new_content else None
        )
        mp = f"{pointer}/content/{media_type}/schema"
        if isinstance(old_schema, dict) and isinstance(new_schema, dict):
            local_old_reg, local_old_base = _localize_schema_fragment(
                old_reg, old_base, mp, old_schema
            )
            local_new_reg, local_new_base = _localize_schema_fragment(
                new_reg, new_base, mp, new_schema
            )
            compare_node(
                old_schema,
                new_schema,
                old_base=local_old_base,
                new_base=local_new_base,
                old_reg=local_old_reg,
                new_reg=local_new_reg,
                old_visited=frozenset(),
                new_visited=frozenset(),
                pointer=mp,
                role=role,
                file=file,
                findings=findings,
            )
        elif old_schema is None and isinstance(new_schema, dict):
            emit(findings, file, mp, "schema_added", "INFO", role, f"{media_type} schema added")
        elif isinstance(old_schema, dict) and new_schema is None:
            emit(
                findings,
                file,
                mp,
                "schema_removed",
                "BREAKING",
                role,
                f"{media_type} schema removed",
            )


def _compare_operation(
    old_op, new_op, *, file, pointer, old_base, new_base, old_reg, new_reg, findings
):
    old_rb, new_rb = old_op.get("requestBody"), new_op.get("requestBody")
    if isinstance(old_rb, dict) and isinstance(new_rb, dict):
        old_flag, new_flag = (
            bool(old_rb.get("required", False)),
            bool(new_rb.get("required", False)),
        )
        if not old_flag and new_flag:
            emit(
                findings,
                file,
                f"{pointer}/requestBody",
                "request_body_required",
                "BREAKING",
                "request",
                "requestBody became required",
            )
        elif old_flag and not new_flag:
            emit(
                findings,
                file,
                f"{pointer}/requestBody",
                "request_body_optional",
                "INFO",
                "request",
                "requestBody became optional",
            )
        _compare_media_schemas(
            old_rb.get("content"),
            new_rb.get("content"),
            role="request",
            file=file,
            pointer=f"{pointer}/requestBody",
            old_base=old_base,
            new_base=new_base,
            old_reg=old_reg,
            new_reg=new_reg,
            findings=findings,
        )
    elif old_rb is None and isinstance(new_rb, dict):
        sev: Severity = "BREAKING" if new_rb.get("required") else "INFO"
        emit(
            findings,
            file,
            f"{pointer}/requestBody",
            "request_body_added",
            sev,
            "request",
            "requestBody added" + (" and marked required" if new_rb.get("required") else ""),
        )
    elif isinstance(old_rb, dict) and new_rb is None:
        emit(
            findings,
            file,
            f"{pointer}/requestBody",
            "request_body_removed",
            "INFO",
            "request",
            (
                "requestBody removed — clients that stop sending one are unaffected; a client "
                "that still sends one is simply ignored, not rejected, by this contract"
            ),
        )

    old_params = {
        p.get("name"): p
        for p in (old_op.get("parameters") or [])
        if isinstance(p, dict) and "name" in p
    }
    new_params = {
        p.get("name"): p
        for p in (new_op.get("parameters") or [])
        if isinstance(p, dict) and "name" in p
    }
    for name in sorted(set(old_params) | set(new_params)):
        ptr = f"{pointer}/parameters/{name}"
        if name in old_params and name not in new_params:
            sev = "BREAKING" if old_params[name].get("required") else "INFO"
            emit(
                findings,
                file,
                ptr,
                "parameter_removed",
                sev,
                "request",
                f"parameter '{name}' removed",
            )
        elif name not in old_params and name in new_params:
            sev = "BREAKING" if new_params[name].get("required") else "INFO"
            emit(
                findings,
                file,
                ptr,
                "parameter_added",
                sev,
                "request",
                f"parameter '{name}' added"
                + (" as required" if new_params[name].get("required") else ""),
            )
        else:
            old_flag2, new_flag2 = (
                bool(old_params[name].get("required", False)),
                bool(new_params[name].get("required", False)),
            )
            if not old_flag2 and new_flag2:
                emit(
                    findings,
                    file,
                    ptr,
                    "parameter_required",
                    "BREAKING",
                    "request",
                    f"parameter '{name}' became required",
                )
            elif old_flag2 and not new_flag2:
                emit(
                    findings,
                    file,
                    ptr,
                    "parameter_optional",
                    "INFO",
                    "request",
                    f"parameter '{name}' became optional",
                )
            old_pschema, new_pschema = (
                old_params[name].get("schema"),
                new_params[name].get("schema"),
            )
            if isinstance(old_pschema, dict) and isinstance(new_pschema, dict):
                compare_node(
                    old_pschema,
                    new_pschema,
                    old_base=old_base,
                    new_base=new_base,
                    old_reg=old_reg,
                    new_reg=new_reg,
                    old_visited=frozenset(),
                    new_visited=frozenset(),
                    pointer=f"{ptr}/schema",
                    role="request",
                    file=file,
                    findings=findings,
                )

    old_resp = _as_dict(old_op.get("responses"))
    new_resp = _as_dict(new_op.get("responses"))
    for status in sorted(set(old_resp) | set(new_resp)):
        ptr = f"{pointer}/responses/{status}"
        if status in old_resp and status not in new_resp:
            emit(
                findings,
                file,
                ptr,
                "response_status_removed",
                "BREAKING",
                "response",
                f"documented response status {status} removed",
            )
            continue
        if status not in old_resp and status in new_resp:
            emit(
                findings,
                file,
                ptr,
                "response_status_added",
                "INFO",
                "response",
                f"response status {status} added",
            )
            continue
        old_status_obj = _as_dict(old_resp[status])
        new_status_obj = _as_dict(new_resp[status])
        _compare_media_schemas(
            old_status_obj.get("content"),
            new_status_obj.get("content"),
            role="response",
            file=file,
            pointer=ptr,
            old_base=old_base,
            new_base=new_base,
            old_reg=old_reg,
            new_reg=new_reg,
            findings=findings,
        )


def compare_endpoints_file(
    old_doc, new_doc, *, file, old_base, new_base, old_reg, new_reg, findings
):
    old_paths = (
        old_doc.get("paths")
        if isinstance(old_doc, dict) and isinstance(old_doc.get("paths"), dict)
        else {}
    )
    new_paths = (
        new_doc.get("paths")
        if isinstance(new_doc, dict) and isinstance(new_doc.get("paths"), dict)
        else {}
    )
    for path in sorted(set(old_paths) | set(new_paths)):
        old_methods = _as_dict(old_paths.get(path))
        new_methods = _as_dict(new_paths.get(path))
        for method in sorted(set(old_methods) | set(new_methods)):
            ptr = f"#/paths/{path}/{method}"
            if method not in new_methods:
                emit(
                    findings,
                    file,
                    ptr,
                    "endpoint_removed",
                    "BREAKING",
                    "request",
                    f"{method.upper()} {path} removed",
                )
                continue
            if method not in old_methods:
                emit(
                    findings,
                    file,
                    ptr,
                    "endpoint_added",
                    "INFO",
                    "request",
                    f"{method.upper()} {path} added",
                )
                continue
            old_op, new_op = old_methods[method], new_methods[method]
            if isinstance(old_op, dict) and isinstance(new_op, dict):
                _compare_operation(
                    old_op,
                    new_op,
                    file=file,
                    pointer=ptr,
                    old_base=old_base,
                    new_base=new_base,
                    old_reg=old_reg,
                    new_reg=new_reg,
                    findings=findings,
                )


# ---------------------------------------------------------------------------
# Request/response role classification
# ---------------------------------------------------------------------------


def _relpath_from_ref_string(current_file: str, ref: str) -> str | None:
    if ref.startswith("#"):
        return None
    doc_part = ref.split("#", 1)[0]
    if not doc_part:
        return None
    if doc_part.startswith(SCHEMA_ID_BASE):
        return doc_part[len(SCHEMA_ID_BASE) :]
    if urlparse(doc_part).scheme in {"http", "https"}:
        return None
    base_dir = PurePosixPath(current_file).parent
    parts: list[str] = []
    for part in (base_dir / doc_part).parts:
        if part == "..":
            if parts:
                parts.pop()
        elif part in (".", ""):
            continue
        else:
            parts.append(part)
    return "/".join(parts)


def crawl_endpoint_roles(files: dict[str, Any]) -> dict[str, set[str]]:
    """Direct request/response role, straight from *_endpoints.json requestBody/responses/params."""
    direct: dict[str, set[str]] = defaultdict(set)

    def walk(node: Any, current_file: str, context: str | None) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str) and context is not None:
                    target = _relpath_from_ref_string(current_file, value)
                    if target:
                        direct[target].add(context)
                    continue
                next_context = context
                if key == "requestBody" or key == "parameters":
                    next_context = "request"
                elif key == "responses":
                    next_context = "response"
                walk(value, current_file, next_context)
        elif isinstance(node, list):
            for item in node:
                walk(item, current_file, context)

    for relpath, doc in files.items():
        if "_endpoints" not in Path(relpath).name:
            continue
        paths = doc.get("paths") if isinstance(doc, dict) else None
        if isinstance(paths, dict):
            walk(paths, relpath, None)
    return dict(direct)


def build_ref_graph(files: dict[str, Any]) -> dict[str, set[str]]:
    """file -> set of schema files it $refs anywhere (for transitive role propagation)."""
    graph: dict[str, set[str]] = defaultdict(set)

    def walk(node: Any, current_file: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "$ref" and isinstance(value, str):
                    target = _relpath_from_ref_string(current_file, value)
                    if target and target != current_file:
                        graph[current_file].add(target)
                    continue
                walk(value, current_file)
        elif isinstance(node, list):
            for item in node:
                walk(item, current_file)

    for relpath, doc in files.items():
        if "_endpoints" in Path(relpath).name:
            continue
        walk(doc, relpath)
    return dict(graph)


def propagate_roles(direct: dict[str, set[str]], graph: dict[str, set[str]]) -> dict[str, set[str]]:
    roles: dict[str, set[str]] = defaultdict(set)
    for f, rs in direct.items():
        roles[f] |= rs
    changed = True
    while changed:
        changed = False
        for f, targets in graph.items():
            if f not in roles:
                continue
            for t in targets:
                before = len(roles[t])
                roles[t] |= roles[f]
                if len(roles[t]) != before:
                    changed = True
    return dict(roles)


def classify_file_role(relpath: str, graph_roles: set[str]) -> tuple[Role, str]:
    name = Path(relpath).name
    name_hint: str | None = None
    if name.endswith("_request_schema.json"):
        name_hint = "request"
    elif name.endswith("_response_schema.json"):
        name_hint = "response"

    if name_hint == "request" and "response" not in graph_roles:
        return (
            "request",
            "filename ends in _request_schema.json and the endpoint-reference graph never "
            "reaches it from a response — treated as request-only",
        )
    if name_hint == "response" and "request" not in graph_roles:
        return (
            "response",
            "filename ends in _response_schema.json and the endpoint-reference graph never "
            "reaches it from a request body/parameter — treated as response-only",
        )
    if name_hint is None:
        return (
            "conservative",
            "bare resource name (no _request_/_response_ suffix) — this repo's own history "
            "shows bare-named resource schemas get reused bidirectionally as both a request "
            "body and a response shape (e.g. billing_limits_schema.json, "
            "configuration_run_schema.json), so both the request-breaking and "
            "response-breaking rule sets are applied",
        )
    return (
        "conservative",
        f"filename suggests {name_hint!r} but the endpoint-reference graph reaches it via "
        f"{sorted(graph_roles) or ['nothing']} — signals disagree (or the graph is "
        "incomplete), applying both rule sets",
    )


# ---------------------------------------------------------------------------
# git plumbing
# ---------------------------------------------------------------------------


def auto_base_ref(repo_root: Path) -> str:
    safe_repo_root = _resolve_repo_root(repo_root)
    branch = subprocess.run(
        [
            "git",
            "-C",
            str(safe_repo_root),
            "rev-parse",
            "--abbrev-ref",
            "HEAD",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    base_branch = "main" if re.match(r"^(release|hotfix)/", branch) else "develop"
    remote_ref = _safe_git_ref(f"origin/{base_branch}", "remote base ref")
    try:
        mb = subprocess.run(
            [
                "git",
                "-C",
                str(safe_repo_root),
                "merge-base",
                "HEAD",
                remote_ref,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return _safe_git_ref(mb, "merge-base sha") if mb else remote_ref
    except subprocess.CalledProcessError:
        return remote_ref


def _relative_to_schemas_dir(repo_relative_path: str) -> str | None:
    """git diff paths are repo-relative (traigent_schema/schemas/...); SchemaTree keys are
    relative to traigent_schema/schemas/ itself. Returns None for anything outside that dir
    (shouldn't happen given the `--` pathspec, but stay defensive)."""
    prefix = SCHEMAS_SUBDIR + "/"
    if not repo_relative_path.startswith(prefix):
        return None
    return repo_relative_path[len(prefix) :]


def changed_schema_files(
    repo_root: Path, base_ref: str, head_ref: str | None
) -> list[tuple[str, str]]:
    safe_repo_root = _resolve_repo_root(repo_root)
    safe_base_ref = _safe_git_ref(base_ref, "--base-ref")
    safe_head_ref = _safe_git_ref(head_ref, "--head-ref") if head_ref else None
    args = ["git", "-C", str(safe_repo_root), "diff", "--name-status", "--find-renames"]
    args.append(safe_base_ref)
    if safe_head_ref:
        args.append(safe_head_ref)
    args += ["--", SCHEMAS_SUBDIR]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    result: list[tuple[str, str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status.startswith("R") or status.startswith("C"):
            old_path, new_path = parts[1], parts[2]
            if old_path.endswith(".json"):
                rel = _relative_to_schemas_dir(old_path)
                if rel:
                    result.append(("D", rel))
            if new_path.endswith(".json"):
                rel = _relative_to_schemas_dir(new_path)
                if rel:
                    result.append(("A", rel))
            continue
        path = parts[1]
        if path.endswith(".json"):
            rel = _relative_to_schemas_dir(path)
            if rel:
                result.append((status[0], rel))
    return result


# ---------------------------------------------------------------------------
# Allowlist (the "explicit versioned opt-out")
#
# The gate's job is not "you may not break the contract" — it is "you may not break it
# SILENTLY". A change stays allowed; the silence does not. An allowlist entry is the
# acknowledgement: a human looked at this exact tightening, decided it was intentional, and
# said why. That means a `reason` field that just points elsewhere ("see PR", "TODO", a bare
# issue number) is not an acknowledgement — it's the same non-answer a placeholder value
# would be anywhere else evidence is required. Reject it the same way.
# ---------------------------------------------------------------------------

# Patterns that mean "this reason field is a placeholder, not prose explaining a decision".
# Matched against the trimmed, case-folded reason with `.match` (i.e. anchored at the start —
# a reason that merely CONTAINS "see PR" as part of a real sentence, e.g. "narrowed per the
# security review; see PR #333 for the audit trail", is fine).
_PLACEHOLDER_REASON_PATTERNS = [
    re.compile(
        r"^\s*(todo|tbd|tba|n/?a|wip|pending|placeholder|reason|approved)\s*[:.]?\s*$",
        re.IGNORECASE,
    ),
    re.compile(r"^\s*see\s+(pr|above|below|issue|ticket)\b\s*[:.#0-9]*\s*$", re.IGNORECASE),
    re.compile(r"^\s*(#|pr\s*#?|issue\s*#?)\s*\d+\s*$", re.IGNORECASE),
    re.compile(r"^\s*(intentional|breaking change|because)\s*[:.]?\s*$", re.IGNORECASE),
]
_MIN_REASON_LENGTH = 20


def reason_rejection(reason: Any) -> str | None:
    """Return why `reason` is not an acceptable acknowledgement, or None if it's fine.

    This is intentionally a bit stricter than "non-empty string" — that bar was proven too
    low elsewhere in this workspace (evidence fields that accepted any non-empty string
    accepted a placeholder as if it were a real answer). Anchored placeholder-phrase matches,
    a bare issue/PR reference with no prose, and a minimum length + "more than one word" floor
    together catch the common non-answers without being a full NLP judge of reason quality —
    a human reviewer still has to read it; this only screens out the mechanically-empty ones.
    """
    if not isinstance(reason, str):
        return "reason is missing or not a string"
    stripped = reason.strip()
    if not stripped:
        return "reason is empty"
    for pattern in _PLACEHOLDER_REASON_PATTERNS:
        if pattern.match(stripped):
            return f"reason {stripped!r} is a placeholder, not an explanation"
    if len(stripped) < _MIN_REASON_LENGTH:
        return (
            f"reason is only {len(stripped)} chars (< {_MIN_REASON_LENGTH}) — "
            "say why, not just that"
        )
    if " " not in stripped:
        return "reason is a single token, not a sentence explaining the decision"
    return None


def load_allowlist(path: Path, repo_root: Path) -> list[dict[str, Any]]:
    safe_path = _resolve_path_within(path, repo_root, "--allowlist")
    if not safe_path.exists():
        return []
    data = json.loads(safe_path.read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = data.get("entries", [])
    return entries


@dataclass
class AllowMatch:
    entry: dict[str, Any] | None
    # Entries that matched on file+rule+finding identity (exact or prefix) but were rejected
    # for a fixable reason (bad/missing reason, missing version) — surfaced so the failure
    # message can
    # say "you have an entry for this, but:" instead of a bare "no match".
    rejected: list[tuple[dict[str, Any], str]]


def find_allow_entry(finding: Finding, entries: list[dict[str, Any]]) -> AllowMatch:
    rejected: list[tuple[dict[str, Any], str]] = []
    for e in entries:
        if e.get("file") != finding.file:
            continue
        if e.get("rule") and e["rule"] != finding.rule:
            continue
        if "findings" in e:
            exact_findings = e["findings"]
            # New acknowledgements must name every accepted finding identity explicitly.
            # Invalid values fail closed and cannot accidentally become a wildcard.
            if not (
                isinstance(exact_findings, list)
                and all(isinstance(identity, dict) for identity in exact_findings)
                and finding.identity() in exact_findings
            ):
                continue
        elif "pointers" in e or "pointer" in e:
            # Pointer-only acknowledgements are intentionally no longer accepted: they
            # cannot distinguish same-pointer semantic changes.
            continue
        elif not finding.pointer.startswith(e.get("pointer_prefix", "")):
            continue
        problems = []
        if bad_reason := reason_rejection(e.get("reason")):
            problems.append(bad_reason)
        if not e.get("version"):
            problems.append("version is missing — which contract version does this ship in?")
        if problems:
            rejected.append((e, "; ".join(problems)))
            continue
        return AllowMatch(entry=e, rejected=rejected)
    return AllowMatch(entry=None, rejected=rejected)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


@dataclass
class Report:
    base_label: str
    head_label: str
    changed: list[tuple[str, str]]
    findings: list[Finding]
    breaking_unacked: list[Finding]
    breaking_acked: list[tuple[Finding, dict[str, Any]]]
    # For each unacked finding, any allowlist entries that matched on file+rule+identity but
    # were rejected (placeholder reason, missing version) — so the report can say "you have
    # an entry for this, but:" instead of leaving the author to guess why it didn't count.
    near_miss_allow_entries: dict[int, list[tuple[dict[str, Any], str]]]
    role_notes: dict[str, tuple[str, str]]


def compare_trees(
    base: SchemaTree,
    head: SchemaTree,
    changed: list[tuple[str, str]],
    allow_entries: list[dict[str, Any]],
) -> Report:
    base_graph_roles = propagate_roles(
        crawl_endpoint_roles(base.files), build_ref_graph(base.files)
    )
    head_graph_roles = propagate_roles(
        crawl_endpoint_roles(head.files), build_ref_graph(head.files)
    )
    merged_graph_roles: dict[str, set[str]] = defaultdict(set)
    for src in (base_graph_roles, head_graph_roles):
        for relp, rs in src.items():
            merged_graph_roles[relp] |= rs

    findings: list[Finding] = []
    role_notes: dict[str, tuple[str, str]] = {}

    for status, relpath in changed:
        if status == "A":
            emit(
                findings,
                relpath,
                "#",
                "new_file",
                "INFO",
                "n/a",
                "new schema file — no baseline to diff",
            )
            continue
        if status == "D":
            emit(
                findings,
                relpath,
                "#",
                "file_removed",
                "BREAKING",
                "n/a",
                "schema file removed entirely — any consumer resolving this path/$id breaks",
            )
            continue

        old_doc, new_doc = base.get(relpath), head.get(relpath)
        if old_doc is None or new_doc is None:
            emit(
                findings,
                relpath,
                "#",
                "missing_side",
                "INFO",
                "n/a",
                (
                    f"could not load both sides (old_present={old_doc is not None}, "
                    f"new_present={new_doc is not None})"
                ),
            )
            continue

        old_base_uri = base.file_base_uri.get(relpath, SCHEMA_ID_BASE + relpath)
        new_base_uri = head.file_base_uri.get(relpath, SCHEMA_ID_BASE + relpath)

        if "_endpoints" in Path(relpath).name:
            compare_endpoints_file(
                old_doc,
                new_doc,
                file=relpath,
                old_base=old_base_uri,
                new_base=new_base_uri,
                old_reg=base.registry,
                new_reg=head.registry,
                findings=findings,
            )
        else:
            role, why = classify_file_role(relpath, merged_graph_roles.get(relpath, set()))
            role_notes[relpath] = (role, why)
            compare_node(
                old_doc,
                new_doc,
                old_base=old_base_uri,
                new_base=new_base_uri,
                old_reg=base.registry,
                new_reg=head.registry,
                old_visited=frozenset(),
                new_visited=frozenset(),
                pointer="#",
                role=role,
                file=relpath,
                findings=findings,
            )

    breaking = [f for f in findings if f.severity == "BREAKING"]
    unacked: list[Finding] = []
    acked: list[tuple[Finding, dict[str, Any]]] = []
    near_miss: dict[int, list[tuple[dict[str, Any], str]]] = {}
    for f in breaking:
        match = find_allow_entry(f, allow_entries)
        if match.entry is not None:
            acked.append((f, match.entry))
        else:
            unacked.append(f)
            if match.rejected:
                near_miss[id(f)] = match.rejected

    return Report(base.label, head.label, changed, findings, unacked, acked, near_miss, role_notes)


def _suggest_allowlist_json(file: str, rule: str, group_findings: list[Finding]) -> str:
    """A ready-to-paste exact-identity acknowledgement for one unacked group."""
    suggestion = {
        "file": file,
        "rule": rule,
        "findings": [finding.identity() for finding in group_findings],
        "reason": "<explain WHY this is intentional and reviewed, not just that it happened>",
        "version": "<the contract version this change ships in, e.g. 5.6.0>",
        "pr": "<#NNN>",
    }
    lines = [json.dumps(suggestion, indent=6)]
    if len(group_findings) > 1:
        # Findings can share a JSON pointer (e.g. three names added to the same `required`
        # array all point at the object root) — show the message, not just the repeated
        # pointer, so each covered finding is actually distinguishable in the list.
        covered = "\n".join(
            f"      {f.pointer} — {f.message}"
            for f in sorted(group_findings, key=lambda f: (f.pointer, f.message))
        )
        lines.append(f"    # covers {len(group_findings)} findings in this file:\n{covered}")
    return "\n".join(lines)


def print_report(report: Report, *, quiet_info: bool) -> None:
    print(f"breaking_schema_check: {report.base_label}  ->  {report.head_label}")
    if not report.changed:
        print("  no traigent_schema/schemas/**/*.json changes between base and head.")
        return

    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in report.findings:
        by_file[f.file].append(f)

    for relpath in sorted(by_file):
        role_line = ""
        if relpath in report.role_notes:
            role, why = report.role_notes[relpath]
            role_line = f"  role={role} — {why}\n"
        print(f"\n{relpath}")
        if role_line:
            print(role_line, end="")
        for f in sorted(by_file[relpath], key=lambda x: (x.severity != "BREAKING", x.pointer)):
            if quiet_info and f.severity != "BREAKING":
                continue
            print(f.line())

    print("\n" + "-" * 72)
    print(f"files changed:        {len(report.changed)}")
    print(f"findings:             {len(report.findings)}")
    print(f"BREAKING (unacked):   {len(report.breaking_unacked)}")
    print(f"BREAKING (allowed):   {len(report.breaking_acked)}")
    for f, entry in report.breaking_acked:
        pr = entry.get("pr", "?")
        reason = entry.get("reason", "")
        print(f"  - {f.file}{f.pointer} ({f.rule}) — allowed by {pr}: {reason}")

    if report.breaking_unacked:
        print("\nFAILED: un-acknowledged BREAKING contract changes found (see above).")
        print(
            'This is not "you may not break the contract" — it is "you may not break it '
            'silently". The change stays allowed; write the acknowledgement.'
        )

        near_miss_ids = {id(f) for f in report.breaking_unacked} & set(
            report.near_miss_allow_entries
        )
        if near_miss_ids:
            print(
                "\nYou already have scripts/breaking_schema_allowlist.json entries for some of "
                "these, but they don't count yet:"
            )
            for f in report.breaking_unacked:
                for _entry, why in report.near_miss_allow_entries.get(id(f), []):
                    print(f"  - {f.file}{f.pointer} ({f.rule}): existing entry rejected — {why}")

        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for f in report.breaking_unacked:
            groups[(f.file, f.rule)].append(f)

        print(
            f"\nAdd {len(groups)} entr{'y' if len(groups) == 1 else 'ies'} to "
            'scripts/breaking_schema_allowlist.json\'s "entries" array — fill in reason/'
            "version/pr, then re-run:\n"
        )
        for (file, rule), group_findings in sorted(groups.items()):
            print(_suggest_allowlist_json(file, rule, group_findings))
            print()
    else:
        print("\nPASSED: no un-acknowledged BREAKING contract changes.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Breaking-change gate for traigent_schema/schemas/**"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="run the gate (default action; kept for CLI symmetry with other repo gates)",
    )
    parser.add_argument(
        "--base-ref",
        default=None,
        help=(
            "git ref for the OLD side (default: merge-base with origin/develop, or "
            "origin/main on release|hotfix branches)"
        ),
    )
    parser.add_argument(
        "--head-ref", default=None, help="git ref for the NEW side (default: the working tree)"
    )
    parser.add_argument("--repo-root", default=str(REPO_ROOT))
    parser.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST))
    parser.add_argument(
        "--json",
        dest="json_out",
        default=None,
        help="also write a machine-readable JSON summary to this path",
    )
    parser.add_argument(
        "--quiet-info", action="store_true", help="print only BREAKING findings + the summary"
    )
    args = parser.parse_args(argv)

    try:
        repo_root = _resolve_repo_root(args.repo_root)
        base_ref = (
            _safe_git_ref(args.base_ref, "--base-ref")
            if args.base_ref
            else auto_base_ref(repo_root)
        )
        head_ref = _safe_git_ref(args.head_ref, "--head-ref") if args.head_ref else None
        json_out = (
            _resolve_path_within(args.json_out, repo_root, "--json") if args.json_out else None
        )

        with tempfile.TemporaryDirectory(prefix="breaking-schema-check-") as tmp:
            tmp_path = Path(tmp).resolve()
            base_tree = load_tree_from_ref(repo_root, base_ref, tmp_path / "base", tmp_path)
            if head_ref:
                head_tree = load_tree_from_ref(repo_root, head_ref, tmp_path / "head", tmp_path)
            else:
                head_tree = load_tree_from_dir(repo_root / SCHEMAS_SUBDIR, label="working tree")

            changed = changed_schema_files(repo_root, base_ref, head_ref)
            allow_entries = load_allowlist(Path(args.allowlist), repo_root)
            report = compare_trees(base_tree, head_tree, changed, allow_entries)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print_report(report, quiet_info=args.quiet_info)

    if json_out:
        json_out.write_text(
            json.dumps(
                {
                    "base": report.base_label,
                    "head": report.head_label,
                    "changed": report.changed,
                    "findings": [f.__dict__ for f in report.findings],
                    "breaking_unacked": [f.__dict__ for f in report.breaking_unacked],
                    "breaking_acked": [
                        {"finding": f.__dict__, "allowlist_entry": e}
                        for f, e in report.breaking_acked
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    return 1 if report.breaking_unacked else 0


if __name__ == "__main__":
    sys.exit(main())
