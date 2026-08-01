# fp2 — canonical fingerprint specification

Normative for every Traigent SDK. Two SDKs computing a version for the same
artifact MUST produce byte-identical digests. Divergence splits optimization
cohorts by client language, and the split is invisible until someone compares
two runs and gets a wrong answer.

## Scope

fp2 defines four manifest algorithms:

| Id | Artifact | Manifest input |
|----|----------|----------------|
| `afp2` | agent | callable source text, plus canonical bound state when observable |
| `dfp2o` | dataset | the **ordered** evaluation rows |
| `efp2` | evaluator | evaluator source text, or a declared immutable revision |
| `cfp2` | configuration space | the normalized configuration space |

fp2 supersedes fp1. fp1 digests remain valid history and are never rewritten;
they are stored with `schema: "fp1"` and are not comparable with fp2 digests.

## Canonical JSON

A manifest is serialized to canonical JSON before hashing.

- UTF-8, no byte-order mark.
- No insignificant whitespace: no spaces after `:` or `,`.
- Strings use the shortest valid escaping; non-ASCII characters are emitted
  literally, never as `\uXXXX`.

## Key ordering

Object keys are sorted by **code point** of their UTF-16 representation,
ascending.

Implementations MUST NOT use locale-aware comparison. JavaScript's
`String.prototype.localeCompare` is forbidden: it orders differently by locale
and differs from Python's `sorted()`. Use `<` on the raw strings in JavaScript
and `sorted()` in Python, which both compare by code unit.

## Numbers

- Integers within the IEEE-754 double safe range are emitted without a decimal
  point or exponent.
- Non-integer finite numbers are emitted using the shortest round-trip
  representation.
- `-0` is emitted as `0`.
- `NaN`, `Infinity` and `-Infinity` are **unsupported values** (see below).
  They are NOT emitted as `null`, which is what bare `JSON.stringify` does.

## Null and undefined

- `null` is a value and is serialized as `null`.
- An absent object property and a property whose value is `undefined` are
  treated identically: the property is omitted from the manifest.
- `undefined` inside an array is an **unsupported value**. It is NOT converted
  to `null`.

## Unsupported values

The following make a manifest **incomplete**: `NaN`, `Infinity`, `-Infinity`,
`undefined` in an array, functions, symbols, `BigInt`, circular references, and
any object that is not a plain object, array, string, number, boolean or null
(including `Date`, `Map`, `Set`, class instances and `Proxy`).

When a manifest is incomplete the implementation MUST return
`state: "unknown"` with no digest.

It MUST NOT coerce the value and continue. Python's
`json.dumps(..., default=str)` does exactly this — it stringifies whatever it
cannot serialize — which produces a digest that looks verified but silently
depends on an object's `repr`. That is the specific trap fp2 exists to close.
`default=str` is forbidden in every fp2 implementation.

## Manifests

### afp2 — agent

```
{"kind":"afp2","source":<callable source text>,"bound":<canonical bound state or omitted>}
```

`source` is the text of the decorated callable after unwrapping decorators.
`bound` carries partial arguments, closure cells or instance state **when they
are observable and canonically serializable**; otherwise the manifest is
incomplete and the result is `unknown`.

Coverage limit, which implementations MUST surface rather than hide: `afp2`
covers the decorated body only. A change to an imported prompt, helper or model
client leaves the digest equal.

### dfp2o — dataset, order significant

```
{"kind":"dfp2o","rows":[<row 0>,<row 1>,...]}
```

Each row is `{"input":<input>,"expected":<expected or null>}`.

Row order is **significant**. It is part of the manifest, not a formatting
detail, because execution consumes an ordered prefix under a budget: with a
cap of N, `[easy, hard]` and `[hard, easy]` evaluate different examples. An
order-independent digest would declare those two runs comparable.

An order-independent multiset digest MAY be computed separately for
deduplication. It MUST NOT be used for comparability, and MUST NOT be stored in
the `dataset` slot of `artifact_versions`.

### efp2 — evaluator

```
{"kind":"efp2","source":<evaluator source text>}
{"kind":"efp2","external":{"kind":<kind>,"revision":<declared revision>}}
```

For an external evaluator reached over a network, the caller MUST supply an
immutable `revision`. Without one the manifest is incomplete and the result is
`unknown`, because behavior behind a stable URL can change invisibly and a
digest over the endpoint alone would assert a false equality.

### cfp2 — configuration space

```
{"kind":"cfp2","space":<normalized configuration space>}
```

## Digest format

```
sha256:<64 lowercase hex characters>
```

The digest is SHA-256 over the UTF-8 bytes of the canonical JSON manifest. The
algorithm prefix is mandatory: a bare hex string is not a valid fp2 digest.

## Versioning

The manifest `kind` and the `schema` field in `artifact_versions` MUST agree.
Changing any rule in this document requires a new algorithm id (`afp3`, …).
Existing stored digests are never recomputed or rewritten; they remain valid
facts about the algorithm that produced them.
