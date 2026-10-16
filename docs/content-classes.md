# Content classes (`x-content-class`)

Phase 1 of the content-less optimization design: every application-level value an
optimization channel carries between a customer machine and Traigent servers must be
one of the classes below. This note defines the vocabulary; `scripts/content_class_lint.py`
enforces it and `tests/test_content_class_lint.py` pins it.

| Class | Meaning |
|---|---|
| `opaque_ref` | Server-issued opaque reference (run, trial, session, project ids). |
| `closed_enum` | Value from a closed vocabulary (enums, constants, booleans). |
| `number` | Bounded number (counts, scores, durations, costs). |
| `digest` | Approved hash or digest (`sha256:...`, etags). |
| `timestamp` | Point in time. |
| `code_identifier` | Verified code identifier (function ref, module, repo-relative path). |
| `encrypted_blob` | Label-service ciphertext, accepted only by the label service. |
| `auth_header` | Allow-listed transport or authentication header. |
| `legacy_content` | **Transitional.** Carries, or may carry, customer content today and is scheduled for removal by the content-less plan. |

`legacy_content` makes today's leaks visible instead of passing them: it is not a class a
new field may use. Every `legacy_content` annotation carries an `x-content-note` citing the
inventory row (for example `INV S1-14 (LEAK): function_name`), or `INV-GAP` when the field
is not in the inventory. The lint lists every `legacy_content` location; that list is the
checklist for the removal phase (P3), and a test pins its size so it can only go down.

## Where the annotation goes

On every value node of an optimization-channel contract: object properties, array `items`,
map values (`additionalProperties` / `patternProperties`), `propertyNames`, parameter
schemas and response-header schemas. Map keys are classed by `x-content-class` on
`propertyNames`, or by `x-content-key-class` on the map node. A node that is a `$ref` (or a
composition of refs) inherits the class of its target; pure containers (an object or array
whose children are all classed) need none. An object with open extras
(`additionalProperties: true`) is a value node: its class describes the extra keys and values.
`if`/`then`/`else`/`not` branches only constrain fields declared elsewhere and are not
walked, nor are empty placeholder properties (`{}`) next to `allOf`/`$ref`.

## Scope and commands

Every document under `traigent_schema/schemas/optimization/` (OpenAPI inventories included),
the guidance plan/result documents, and every fragment those reference (configuration-run
measures, content identity, common types, error/success envelopes). `legend/*` is closed by
design and excluded.

```bash
python3 scripts/content_class_lint.py --report   # per-class counts
python3 scripts/content_class_lint.py --legacy   # + every legacy_content location
python3 -m pytest tests/test_content_class_lint.py -q
```

The extension keywords are registered in `x_extensions_meta_schema.json`. Annotations are
documentation: they change no type, `required` entry or validation.
