# Content classes (`x-content-class`)

Phase 1 of the content-less optimization design: every application-level value an
optimization channel carries between a customer machine and Traigent servers must be
one of the classes below. This note defines the vocabulary; `scripts/content_class_lint.py`
enforces it and `tests/test_content_class_lint.py` pins it.

| Class | Meaning |
|---|---|
| `opaque_ref` | Server-issued opaque reference (UUIDs, `<kind>ref_<32 hex>`, keyed content-identity tokens). |
| `closed_enum` | Value from a closed vocabulary (enums, constants, booleans). |
| `number` | Bounded number (counts, scores, durations, costs). |
| `digest` | Approved hash or digest (`sha256:...`, git object ids). |
| `key_material` | Public key, signature, salt, nonce or authenticator-generated credential id: base64url, bounded. |
| `timestamp` | Point in time. |
| `code_identifier` | Verified code identifier (function ref, module, repo-relative path). |
| `encrypted_blob` | Label-service ciphertext, accepted only by the label service. |
| `auth_header` | Allow-listed transport or authentication header. |
| `legacy_content` | **Transitional.** Carries, or may carry, customer content today and is scheduled for removal by the content-less plan. |

`legacy_content` makes today's leaks visible instead of passing them: it is not a class a
new field may use. Every `legacy_content` annotation carries an `x-content-note` citing the
inventory row (for example `INV S1-14 (LEAK): function_name`), or `INV-GAP` when the field
is not in the inventory. The lint lists every `legacy_content` location; that list is the
checklist for the removal phase (P3). The manifest (below) pins every location.

## What each class must prove

A class name alone proves nothing, so the lint checks the node's own keywords
(`semantic_problem` in `scripts/content_class_lint.py`; negative tests for each in
`tests/test_content_class_lint.py`). A value that cannot meet its class is `legacy_content`, never
a looser class.

| Class | Required |
|---|---|
| `closed_enum` | `enum`, `const`, or a boolean type |
| `number` | integer/number type, numeric bounds, `minimum <= maximum` |
| `digest` | a pattern that accepts a 64-hex digest (bare or `sha256:`) and nothing of other lengths or free text |
| `key_material` | the base64url pattern `^[A-Za-z0-9_-]+$` and a `maxLength` |
| `timestamp` | `format: date-time`/`date`, or a timestamp pattern |
| `opaque_ref` | an approved ref pattern: UUID, `<kind>ref_<32 lowercase hex>` (the Backend's minting convention), key id, or one of the fixed derived-token patterns listed in the lint |
| `code_identifier` | a dotted `module:qualname` or repo-relative path pattern that rejects free text |
| `encrypted_blob` | only inside `labels/` (base64url + `maxLength`); elsewhere a node must `$ref` the label envelope |

Map-key classes are checked against `propertyNames` the same way.

## Where the annotation goes

On every value node of an optimization-channel contract: object properties, array `items`,
map values (`additionalProperties` / `patternProperties`), `propertyNames`, parameter
schemas and response-header schemas. Map keys are classed by `x-content-class` on
`propertyNames`, or by `x-content-key-class` on the map node. A node that is a `$ref` (or a
composition of refs) inherits the class of its target; pure containers (an object or array
whose children are all classed) need none. An object with open extras
(`additionalProperties: true`) is a value node: its class describes the extra keys and values.
`if`/`then`/`else`/`not` branches are walked: a branch may re-constrain a property whose primary
declaration (own `properties`, `allOf`, `$ref`) is already classified, but any property it
introduces must carry its own class. Empty placeholder properties (`{}`) next to `allOf`/`$ref`
are skipped.

Composition branches (`oneOf`/`anyOf`/`allOf`) are walked too: a class declared inside a branch is
recorded at the branch's own pointer (`.../oneOf/0`) in the manifest and, for `legacy_content`, in the
register. A class placed on a node that is only a union is a claim about every branch, so each
branch is validated against it (a `closed_enum` union with a free-string branch is invalid).
Any object (root or nested) that accepts extra properties must declare both `x-content-class` and `x-content-key-class` (open roots can only
be `legacy_content`: their extra names are unconstrained) or be closed with
`additionalProperties: false` (or `unevaluatedProperties: false`). Open-object checks also run on objects inside `oneOf`/`anyOf`/`allOf` branches (not when the
enclosing node or an `allOf` sibling closes the object). `then`/`else` branches are checked too unless
an enclosing object node is already classified there, so a conditional-only root whose `then` is an
open object must classify it; `if` and `not` accept nothing and are not checked. In Draft-4/6/7
(and OpenAPI 3.0, and documents without `$schema`) keywords beside `$ref` are ignored, so the
`$ref` target alone is checked against a class claim; a branch's own class never proves the
parent's claim, the parent's class is checked against the branch's constraints. `unevaluatedProperties: false` closes an object only in 2019-09+ documents
(or OpenAPI 3.1); Draft-7 documents must use `additionalProperties: false`.
A content-free class must hold for every branch that can accept a value: `allOf` members
intersect (one restricting member suffices), every `anyOf`/`oneOf` alternative must hold, and
unconstrained `{}` / `true` alternatives fail. An object that OMITS
`additionalProperties` is open in JSON Schema and is treated as open; existing ones are
classified `legacy_content` ("implicit-open, reclassified by review") rather than tightened.

## Manifest and dispositions

`docs/content-class-manifest.json` maps every annotated location (`file#pointer`) to its class;
`python3 scripts/content_class_manifest.py --update` regenerates it and the test fails if it
differs from the live annotations. `docs/content-class-dispositions.json` holds the
`legacy_register` (every location that was `legacy_content` when the manifest was created) and the
dispositions. `legacy_content` can be added nowhere. A location leaves it only with a disposition
entry `{location, from, to, reason, reference}` (reason in words, reference to the inventory row or
design section); the test fails for a declassified location without one. Locations whose note
reads `INV-GAP: was <class>` were claimed content-free by the first annotation pass, but their
contract has no enum or ref pattern to prove it. Notes reading `reclassified by review` mark the
2026-10-16 honesty pass, the one pass allowed to add to the register.

### Anchored ratchet

The manifest and dispositions sit in the same tree as the annotations, so the ratchet reads the
copies on `origin/develop` (`git show`, 30 s timeout) as its anchor. With an anchor: a
`legacy_content` location absent from the anchored manifest fails, a registry entry or disposition
cannot be removed or edited, and an anchored legacy location moved to a content-free class needs a
disposition whose `reference` verifies (`path:line` of an existing line, `INV <route>-<row>` (the field row must exist in
`docs/content-class-reference-ids.json`), or `DESIGN-v2.2 §<section>`). Without an anchor (first
introduction) the working-tree manifest must equal the live annotations exactly. If git or the ref
is unavailable the check fails; it never skips (`python3 scripts/content_class_manifest.py --check`).

## Scope and commands

Every document under `traigent_schema/schemas/optimization/` and `traigent_schema/schemas/labels/` (OpenAPI inventories included),
the guidance plan/result documents, and every fragment those reference (configuration-run
measures, content identity, common types, error/success envelopes). `legend/*` is closed by
design and excluded.

```bash
python3 scripts/content_class_lint.py --report   # per-class counts
python3 scripts/content_class_lint.py --legacy   # + every legacy_content location
python3 scripts/content_class_manifest.py --check
python3 -m pytest tests/test_content_class_lint.py -q
```

The extension keywords are registered in `x_extensions_meta_schema.json`. Annotations are
documentation: they change no type, `required` entry or validation.
