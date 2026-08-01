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

Object keys are sorted ascending by their **UTF-16 code unit sequence**,
compared numerically, unit by unit, shorter-is-smaller on a common prefix.
This is the rule RFC 8785 (JSON Canonicalization Scheme) specifies, and it is
NOT the same as ordering by Unicode code point.

Code point and code unit order **invert** for any key containing an astral
character (above U+FFFF). An astral character is encoded as a surrogate pair
whose leading unit is in `D800`–`DBFF`, which is numerically *below* every
character in `E000`–`FFFF`, while its code point is *above* all of them:

| Key | Code point | UTF-16 code units |
|-----|-----------|-------------------|
| `😀` U+1F600 | `0x1F600` | `D83D DE00` |
| `Ａ` U+FF21 | `0xFF21` | `FF21` |

Code-point order puts `Ａ` first (`0xFF21 < 0x1F600`); code-unit order puts
`😀` first (`0xD83D < 0xFF21`). Two SDKs disagreeing here produce different
canonical bytes and therefore different digests for identical data.

Per language:

- **JavaScript**: `keys.sort()`, or `<`/`>` on the raw strings. JavaScript
  strings are UTF-16 and its relational operators compare code units, so this
  is already the required order. `String.prototype.localeCompare` is
  **forbidden**: it orders by locale.
- **Python**: `sorted(keys, key=lambda k: k.encode("utf-16-be"))`. Bare
  `sorted()` is **forbidden**: Python compares code points and inverts against
  JavaScript on astral keys. Comparing UTF-16 big-endian bytes lexicographically
  is exactly comparing code-unit sequences numerically.

A key that is not encodable text — a lone surrogate — is an **unsupported
value**: no two implementations can agree on bytes that do not exist.

## Numbers

Numbers are serialized with the **ECMAScript `Number::toString` algorithm**
(ECMA-262 §6.1.6.1.20), which RFC 8785 adopts. Round-tripping is necessary but
not sufficient: two shortest round-trip representations of the same double can
still be different text, and different text is a different digest.

Concretely, ECMAScript switches between fixed and exponential notation at fixed
thresholds and never zero-pads an exponent. Python's `repr` does neither, so
`repr` MUST NOT be used directly:

| Value | Python `repr` | ECMAScript (required) |
|-------|---------------|----------------------|
| `1e16` | `1e+16` | `10000000000000000` |
| `1e20` | `1e+20` | `100000000000000000000` |
| `1e-5` | `1e-05` | `0.00001` |
| `1e-7` | `1e-07` | `1e-7` |
| `1e21` | `1e+21` | `1e+21` |

- `-0` is emitted as `0`.
- Integers are emitted without a decimal point or exponent when the algorithm
  above yields fixed notation, which it does for every integer up to `1e21`.
- An **integer outside the IEEE-754 safe integer range** (`|v| > 2^53 - 1`) is
  an **unsupported value**. JavaScript cannot hold it in a `Number` without
  losing precision, so Python's arbitrary-precision `int` and a JavaScript
  `Number` would silently disagree — the same divergence as `BigInt`, which is
  already unsupported. A *float* of the same magnitude is fine: it round-trips
  through a `Number` exactly and both languages serialize it identically.
- `NaN`, `Infinity` and `-Infinity` are **unsupported values** (see below).
  They are NOT emitted as `null`, which is what bare `JSON.stringify` does.

## Null and undefined

- `null` is a value and is serialized as `null`.
- An absent object property and a property whose value is `undefined` are
  treated identically: the property is omitted from the manifest.
- `undefined` inside an array is an **unsupported value**. It is NOT converted
  to `null`.

## Nesting depth

A manifest MUST NOT nest containers (objects and arrays) more than **100**
levels deep. The outermost container is level 1. A manifest that exceeds the
limit is an **unsupported value**.

The number is normative and identical in every implementation. It is specified
rather than left to the runtime because "as deep as the language allows" is not
a specification: CPython at its default recursion limit gives out around 332
levels, while a JavaScript engine manages thousands. Two SDKs inheriting their
own runtime's stack would disagree about which manifests are digestible at all
— one returning a digest where the other returns `unknown` — which is the
cross-language divergence this document exists to prevent. 100 is far above any
real agent, dataset, evaluator or configuration-space manifest and far below
every target runtime's capacity, so a plain recursive implementation can comply
without special measures.

Implementations SHOULD NOT let the limit be enforced *by* the runtime stack.
A recursive encoder consumes the caller's stack, so the same manifest can
canonicalize when called from `main` and abort when called from deeper inside
an application — the outcome becomes a property of the call site rather than of
the data. An explicit work stack, or a hard depth check applied before any
recursion, keeps the result a function of the manifest alone.

## Unsupported values

The following make a manifest **incomplete**: `NaN`, `Infinity`, `-Infinity`,
`undefined` in an array, functions, symbols, `BigInt`, integers outside the
IEEE-754 safe integer range, lone surrogates in a string or key, nesting beyond
the depth limit above, circular references, and any object that is not a plain
object, array, string, number, boolean or null (including `Date`, `Map`, `Set`,
class instances and `Proxy`).

When a manifest is incomplete the implementation MUST return
`state: "unknown"` with no digest. It MUST signal this through the one error
type the caller is documented to catch, and that type MUST be the only one the
entry points can raise. An implementation that lets a different exception
escape — a `UnicodeEncodeError` from an un-encodable string, a `RecursionError`
from deep nesting — crashes the run instead of degrading to `unknown`, which is
a fail-open in the other direction: the caller never gets the chance to record
the honest answer.

This is a rule about the *class*, not a list of known offenders. Canonicalizing
either produces bytes or does not; there is no third outcome. An implementation
MUST therefore translate any unexpected failure into the documented error type
rather than enumerate the failures it has thought of so far — the list is
exactly what keeps turning out to be incomplete.

It MUST NOT coerce the value and continue. Python's
`json.dumps(..., default=str)` does exactly this — it stringifies whatever it
cannot serialize — which produces a digest that looks verified but silently
depends on an object's `repr`. That is the specific trap fp2 exists to close.
`default=str` is forbidden in every fp2 implementation.

The same trap reappears one level down, and implementations MUST close it
there too: `repr`/`toString` on a **numeric subclass** is caller-controlled.
`repr(numpy.float64(0.1))` is `np.float64(0.1)`, not `0.1`. A number MUST be
converted to the exact builtin type before it is formatted, so that no
user-defined `repr` can reach the canonical bytes.

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
