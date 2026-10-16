#!/usr/bin/env python3
"""Content-class lint for the optimization channel contracts.

Every value an optimization channel carries between a customer machine and
Traigent servers must declare an ``x-content-class`` (see
``docs/content-classes.md``).  This lint walks every schema used by the
optimization routes, recursively through object properties, map keys
(``additionalProperties`` / ``patternProperties`` / ``propertyNames``), array
items, request/response bodies, parameters and response headers, following
``$ref`` into other schema files.  It fails on any value node that has no
class, prints a count per class, and lists every ``legacy_content`` location
(the P3 removal checklist).

Usage::

    python3 scripts/content_class_lint.py            # lint, exit 1 on gaps
    python3 scripts/content_class_lint.py --report   # + per-class counts
    python3 scripts/content_class_lint.py --legacy   # + legacy_content list
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMAS_DIR = REPO_ROOT / "traigent_schema" / "schemas"
ID_BASE = "https://schemas.traigent.ai/"

CLASS_KEY = "x-content-class"
KEY_CLASS_KEY = "x-content-key-class"
NOTE_KEY = "x-content-note"

CONTENT_CLASSES = frozenset(
    {
        "opaque_ref",
        "closed_enum",
        "number",
        "digest",
        "timestamp",
        "code_identifier",
        "encrypted_blob",
        "auth_header",
        "legacy_content",
    }
)
LEGACY = "legacy_content"

# Full-document roots: every schema document under optimization/ (endpoint
# inventories are walked as OpenAPI), plus the guidance and run-measure
# documents the optimization routes reference.  Other referenced documents
# are walked only at the fragment that is referenced.
ROOT_DIRS = ("optimization",)
EXTRA_ROOT_FILES = (
    "guidance/guidance_plan_request_schema.json",
    "guidance/guidance_plan_schema.json",
    "guidance/guidance_plan_item_schema.json",
    "guidance/guidance_action_schema.json",
    "guidance/guidance_result_submission_schema.json",
)
# Closed by design (privacy bridge), not field-audited here.
EXCLUDED_PREFIXES = ("legend/",)

_SCHEMA_LIST_SLOTS = ("allOf", "anyOf", "oneOf")
_SCHEMA_MAP_SLOTS = ("definitions", "$defs", "dependencies")
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options"}


@dataclass
class Finding:
    loc: str
    kind: str  # value | key
    cls: str | None
    note: str | None = None


@dataclass
class LintResult:
    findings: list[Finding] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    documents: list[str] = field(default_factory=list)

    @property
    def counts(self) -> Counter[str]:
        return Counter(f.cls for f in self.findings if f.cls)

    @property
    def legacy(self) -> list[Finding]:
        return [f for f in self.findings if f.cls == LEGACY]

    @property
    def ok(self) -> bool:
        return not (self.missing or self.invalid or self.unresolved)


_MISSING = object()


def _esc(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _unesc(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


class Linter:
    def __init__(self, schemas_dir: Path = SCHEMAS_DIR) -> None:
        self.dir = schemas_dir
        self.docs: dict[str, Any] = {}
        self.seen: set[tuple[str, str]] = set()
        self.result = LintResult()

    # -- documents -----------------------------------------------------
    def load(self, rel: str) -> Any:
        if rel not in self.docs:
            self.docs[rel] = json.loads((self.dir / rel).read_text(encoding="utf-8"))
            self.result.documents.append(rel)
        return self.docs[rel]

    def roots(self) -> list[str]:
        out: list[str] = []
        for d in ROOT_DIRS:
            out += sorted(
                p.relative_to(self.dir).as_posix() for p in (self.dir / d).rglob("*.json")
            )
        out += [f for f in EXTRA_ROOT_FILES if (self.dir / f).exists()]
        return out

    def _resolve(self, doc: str, scope: list[tuple[str, Any, str]], ref: str):
        """Return (doc, absolute pointer, node, new_scope) or None."""
        path, _, frag = ref.partition("#")
        if frag and not frag.startswith("/"):
            return None
        if path.startswith(ID_BASE):
            target = path[len(ID_BASE) :]
        elif path:
            parts: list[str] = []
            for seg in (Path(doc).parent / path).as_posix().split("/"):
                if seg == "..":
                    if parts:
                        parts.pop()
                elif seg not in ("", "."):
                    parts.append(seg)
            target = "/".join(parts)
        else:
            target = ""
        if target:
            if not (self.dir / target).exists():
                return None
            root = self.load(target)
            cur_doc, base, base_ptr = target, root, ""
            new_scope = [(target, root, "")]
        else:
            cur_doc = doc
            new_scope = scope
            base, base_ptr = (scope[-1][1], scope[-1][2]) if scope else (self.load(doc), "")
        node = self._pointer(base, frag)
        if node is _MISSING and not target and scope:
            # inline schema scope did not hold it: fall back to the file root
            base, base_ptr = self.load(doc), ""
            node = self._pointer(base, frag)
        if node is _MISSING:
            return None
        return cur_doc, base_ptr + frag, node, new_scope

    @staticmethod
    def _pointer(base: Any, frag: str) -> Any:
        node = base
        if frag:
            try:
                for tok in frag[1:].split("/"):
                    node = node[_unesc(tok)] if isinstance(node, dict) else node[int(tok)]
            except (KeyError, IndexError, ValueError, TypeError):
                return _MISSING
        return node

    # -- classification helpers ---------------------------------------
    def effective_class(self, doc: str, scope, node: Any, depth: int = 0) -> str | None:
        if not isinstance(node, dict) or depth > 12:
            return None
        if CLASS_KEY in node:
            return node[CLASS_KEY]
        ref = node.get("$ref")
        if isinstance(ref, str):
            res = self._resolve(doc, scope, ref)
            if res:
                return self.effective_class(res[0], res[3], res[2], depth + 1)
            return None
        for slot in _SCHEMA_LIST_SLOTS:
            branches = node.get(slot)
            if isinstance(branches, list):
                classes = {
                    self.effective_class(doc, scope, b, depth + 1)
                    for b in branches
                    if self._is_value_branch(b)
                }
                classes.discard(None)
                if len(classes) == 1 and all(
                    self.effective_class(doc, scope, b, depth + 1) or not self._is_value_branch(b)
                    for b in branches
                ):
                    return next(iter(classes))
        return None

    @staticmethod
    def _is_value_branch(node: Any) -> bool:
        """A branch that declares a value (not a constraint overlay or null)."""
        if not isinstance(node, dict):
            return False
        if node.get("type") == "null" or ("const" in node and node["const"] is None):
            return False
        if "$ref" in node or CLASS_KEY in node:
            return True
        if any(
            k in node
            for k in (
                "enum",
                "const",
                "format",
                "pattern",
                "properties",
                "items",
                "additionalProperties",
                "patternProperties",
            )
        ):
            return True
        typ = node.get("type")
        types = set(typ) if isinstance(typ, list) else {typ}
        if types & {"string", "number", "integer", "boolean"}:
            return True
        return any(k in node for k in _SCHEMA_LIST_SLOTS)

    def _children(self, node: dict) -> bool:
        """True when the node's content is described by child schemas."""
        return (
            any(
                isinstance(node.get(k), dict) and node.get(k) not in ({}, True)
                for k in ("properties", "patternProperties")
            )
            or isinstance(node.get("items"), (dict, list))
            or isinstance(node.get("additionalProperties"), dict)
            and node["additionalProperties"] != {}
        )

    def _open_extras(self, node: dict) -> bool:
        ap = node.get("additionalProperties")
        return ap is True or ap == {}

    def _is_container(self, doc, scope, node: dict) -> bool:
        """Object/array whose content is covered by (separately checked) children."""
        if "enum" in node or "const" in node:
            return False
        typ = node.get("type")
        types = typ if isinstance(typ, list) else [typ]
        if "string" in types or "number" in types or "integer" in types or "boolean" in types:
            return False
        if "properties" in node or "items" in node or "patternProperties" in node:
            return True
        if (
            isinstance(node.get("additionalProperties"), dict)
            and node["additionalProperties"] != {}
        ):
            return True
        for slot in _SCHEMA_LIST_SLOTS:
            branches = node.get(slot)
            if isinstance(branches, list) and branches:
                structural = [b for b in branches if self._is_value_branch(b)]
                if structural and all(
                    self.effective_class(doc, scope, b) or self._is_branch_structural(doc, scope, b)
                    for b in structural
                ):
                    return True
        ref = node.get("$ref")
        if isinstance(ref, str):
            res = self._resolve(doc, scope, ref)
            if res and isinstance(res[2], dict):
                return self.effective_class(
                    res[0], res[3], res[2]
                ) is not None or self._is_container(res[0], res[3], res[2])
        return False

    def _is_branch_structural(self, doc, scope, b: Any) -> bool:
        return isinstance(b, dict) and self._is_container(doc, scope, b)

    # -- recording ----------------------------------------------------
    def _record_value(self, loc: str, node: dict, doc, scope, kind: str = "value") -> None:
        own = node.get(CLASS_KEY)
        if own is not None:
            if own not in CONTENT_CLASSES:
                self.result.invalid.append(f"{loc}: unknown class {own!r}")
                return
            self.result.findings.append(Finding(loc, kind, own, node.get(NOTE_KEY)))
            if own == LEGACY and not node.get(NOTE_KEY):
                self.result.invalid.append(f"{loc}: legacy_content needs x-content-note")
            return
        eff = self.effective_class(doc, scope, node)
        if eff is not None:
            return  # inherited from a classed definition
        if self._is_container(doc, scope, node) and not self._open_extras(node):
            return
        self.result.missing.append(loc)

    def _record_keys(self, loc: str, node: dict, doc, scope) -> None:
        pn = node.get("propertyNames")
        if isinstance(pn, dict) and self.effective_class(doc, scope, pn):
            return
        key_cls = node.get(KEY_CLASS_KEY)
        if key_cls is None:
            self.result.missing.append(
                f"{loc} (map keys: add propertyNames x-content-class or {KEY_CLASS_KEY})"
            )
            return
        if key_cls not in CONTENT_CLASSES:
            self.result.invalid.append(f"{loc}: unknown key class {key_cls!r}")
            return
        self.result.findings.append(Finding(loc + " [keys]", "key", key_cls, node.get(NOTE_KEY)))
        if key_cls == LEGACY and not node.get(NOTE_KEY):
            self.result.invalid.append(f"{loc} [keys]: legacy_content needs x-content-note")

    # -- schema walk ----------------------------------------------------
    def walk_schema(
        self, doc: str, scope, node: Any, ptr: str, *, value: bool, depth: int = 0
    ) -> None:
        if not isinstance(node, dict) or depth > 60:
            return
        key = (doc, ptr)
        if key in self.seen:
            return
        self.seen.add(key)
        loc = f"{doc}#{ptr}" if ptr else doc
        if node.get("definitions") or node.get("$defs"):
            scope = scope + [(doc, node, ptr)]

        if value:
            self._record_value(loc, node, doc, scope)

        for k in ("properties", "patternProperties"):
            sub = node.get(k)
            if isinstance(sub, dict):
                composed = any(c in node for c in _SCHEMA_LIST_SLOTS) or "$ref" in node
                for name, child in sub.items():
                    if child == {} and composed:
                        # placeholder redeclaration (keeps additionalProperties:false
                        # valid); the real declaration lives in the composed branch.
                        continue
                    self.walk_schema(
                        doc, scope, child, f"{ptr}/{k}/{_esc(name)}", value=True, depth=depth + 1
                    )
        ap = node.get("additionalProperties")
        if isinstance(ap, dict) and ap != {}:
            self.walk_schema(
                doc, scope, ap, f"{ptr}/additionalProperties", value=True, depth=depth + 1
            )
        if isinstance(ap, dict) and ap != {} or isinstance(node.get("patternProperties"), dict):
            self._record_keys(loc, node, doc, scope)
        pn = node.get("propertyNames")
        if isinstance(pn, dict):
            self.walk_schema(doc, scope, pn, f"{ptr}/propertyNames", value=True, depth=depth + 1)
        items = node.get("items")
        if isinstance(items, dict):
            self.walk_schema(doc, scope, items, f"{ptr}/items", value=True, depth=depth + 1)
        elif isinstance(items, list):
            for i, child in enumerate(items):
                self.walk_schema(doc, scope, child, f"{ptr}/items/{i}", value=True, depth=depth + 1)
        # not/if/then/else/contains only constrain values declared elsewhere:
        # they declare no new fields, so they are not walked as value nodes.
        for k in _SCHEMA_LIST_SLOTS:
            if isinstance(node.get(k), list):
                for i, child in enumerate(node[k]):
                    self.walk_schema(
                        doc, scope, child, f"{ptr}/{k}/{i}", value=False, depth=depth + 1
                    )
        for k in _SCHEMA_MAP_SLOTS:
            if isinstance(node.get(k), dict):
                for name, child in node[k].items():
                    if isinstance(child, dict):
                        self.walk_schema(
                            doc,
                            scope,
                            child,
                            f"{ptr}/{k}/{_esc(name)}",
                            value=(k != "dependencies"),
                            depth=depth + 1,
                        )
        ref = node.get("$ref")
        if isinstance(ref, str):
            res = self._resolve(doc, scope, ref)
            if res is None:
                self.result.unresolved.append(f"{loc}: {ref}")
            else:
                rdoc, rptr, rnode, rscope = res
                if any(rdoc.startswith(p) for p in EXCLUDED_PREFIXES):
                    return
                # follow without re-asserting the target as a value (its own
                # parent slot does that); definitions are walked as values.
                self.walk_schema(rdoc, rscope, rnode, rptr, value=bool(rptr), depth=depth + 1)

    # -- openapi walk -------------------------------------------------
    def walk_openapi(self, doc: str, data: dict) -> None:
        for path, item in (data.get("paths") or {}).items():
            if not isinstance(item, dict):
                continue
            for p in item.get("parameters", []) or []:
                self._param(doc, [], p, f"/paths/{_esc(path)}/parameters")
            for method, op in item.items():
                if method not in _HTTP_METHODS or not isinstance(op, dict):
                    continue
                base = f"/paths/{_esc(path)}/{method}"
                for i, p in enumerate(op.get("parameters", []) or []):
                    self._param(doc, [], p, f"{base}/parameters/{i}")
                rb = op.get("requestBody")
                if isinstance(rb, dict):
                    self._content(doc, rb.get("content"), f"{base}/requestBody/content")
                for status, resp in (op.get("responses") or {}).items():
                    if not isinstance(resp, dict):
                        continue
                    self._content(doc, resp.get("content"), f"{base}/responses/{status}/content")
                    for hname, h in (resp.get("headers") or {}).items():
                        if isinstance(h, dict) and isinstance(h.get("schema"), dict):
                            self.walk_schema(
                                doc,
                                [],
                                h["schema"],
                                f"{base}/responses/{status}/headers/{_esc(hname)}/schema",
                                value=True,
                            )

    def _param(self, doc, scope, p: Any, ptr: str) -> None:
        if isinstance(p, dict) and isinstance(p.get("schema"), dict):
            self.walk_schema(doc, scope, p["schema"], f"{ptr}/schema", value=True)

    def _content(self, doc, content: Any, ptr: str) -> None:
        for media, body in (content or {}).items():
            if isinstance(body, dict) and isinstance(body.get("schema"), dict):
                self.walk_schema(
                    doc, [], body["schema"], f"{ptr}/{_esc(media)}/schema", value=False
                )

    # -- driver ---------------------------------------------------------
    def run(self) -> LintResult:
        for rel in self.roots():
            if any(rel.startswith(p) for p in EXCLUDED_PREFIXES):
                continue
            data = self.load(rel)
            if isinstance(data, dict) and "paths" in data and "openapi" in data:
                self.walk_openapi(rel, data)
            elif isinstance(data, dict):
                self.walk_schema(rel, [], data, "", value=False)
        self.result.missing = sorted(set(self.result.missing))
        return self.result


def run_lint(schemas_dir: Path = SCHEMAS_DIR) -> LintResult:
    return Linter(schemas_dir).run()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", action="store_true", help="print per-class counts")
    ap.add_argument("--legacy", action="store_true", help="list every legacy_content location")
    args = ap.parse_args(argv)
    res = run_lint()
    for line in res.invalid:
        print(f"INVALID  {line}")
    for line in res.unresolved:
        print(f"UNRESOLVED  {line}")
    for line in res.missing:
        print(f"MISSING  {line}")
    if args.report or args.legacy or res.ok:
        print("class counts:")
        for cls in sorted(CONTENT_CLASSES):
            print(f"  {cls:16} {res.counts.get(cls, 0)}")
        print(f"documents walked: {len(res.documents)}")
    if args.legacy:
        print("legacy_content locations:")
        for f in sorted(res.legacy, key=lambda f: f.loc):
            print(f"  {f.loc}  -- {f.note}")
    if not res.ok:
        print(
            f"FAIL: {len(res.missing)} missing, {len(res.invalid)} invalid, {len(res.unresolved)} unresolved"
        )
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
