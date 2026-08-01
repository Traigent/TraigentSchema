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

### Types are matched exactly, never by subclass

An implementation MUST dispatch on the **exact** type, not on an "is a"
relationship. A subclass supplies its own iteration and conversion behaviour,
so accepting one hands the choice of canonical bytes to the code that built the
manifest. A Python `dict` subclass overriding `items()`, a `list` or `str`
subclass overriding `__iter__`, and an `int` subclass overriding `__int__` all
change the digest of data that looks identical — the same failure as formatting
a number through `repr`, reached through a different door.

Concretely, in Python: `type(x) is dict`, not `isinstance(x, dict)`. This makes
`OrderedDict`, `defaultdict`, `IntEnum`, `namedtuple` and `numpy` scalars
unsupported. That is intended and it fails closed: the caller gets `unknown`
and loses a comparison, rather than a digest nobody can reproduce. Converting
to plain types is the manifest builder's job, and it must happen before
hashing, not inside it.

**Tuples are the one deliberate exception**, and they are accepted as arrays.
The test is not "does the language have this type" but "do the two SDKs produce
the same bytes for the same data". A Python `tuple` and a JavaScript array of
the same items canonicalize identically, so accepting it makes the SDKs
*converge*; rejecting it would make Python answer `unknown` where JavaScript
answers with a digest for the same logical manifest, which is divergence — the
thing this document exists to prevent. Dataset rows are routinely tuples in
Python, so this is a common path, not an edge case. The exception is exact
`tuple` only: a `namedtuple` is a subclass, is semantically a record rather
than a sequence, and would be an object in JavaScript, so it stays unsupported.

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

Canonicalization only guarantees that the same manifest hashes to the same
bytes. If two SDKs build *different manifests* from the same run, identical
canonicalization still yields different digests, and the failure looks exactly
like the key-ordering bug one level up. So construction is normative too: each
algorithm below states what goes in, in what order, and what is deliberately
left out.

**Comparability scope.** `afp2` and `efp2` digest source text, which is
language-specific by nature: a Python agent and a JavaScript agent are never
byte-equal and are not meant to be. Those two are comparable **within one
language runtime**, across runs and machines. `dfp2o` and `cfp2` digest data
that crosses the wire unchanged and MUST be equal across languages for equal
input. Every algorithm uses the identical canonicalization rules regardless.

### afp2 — agent

```
{"kind":"afp2","source":<source text>,"bound":<bound state, omitted when empty>}
```

Construction:

1. Unwrap decorator wrappers to the innermost user-authored callable, so that
   re-decorating or re-tuning does not change the digest.
2. Take that callable's source text **excluding its decorator lines**. A
   decorator carries tuning configuration, which `cfp2` already covers;
   including it would make the agent version move whenever the search space
   moved, conflating two artifacts the contract deliberately separates.
3. Normalize line endings to `\n`, remove the common leading indentation, and
   strip trailing whitespace at the end of the text. Nothing else: no comment
   stripping, no reformatting, no parsing. Every further normalization needs a
   parser, and two parsers are two more things that can disagree.

`bound` carries state the callable closes over, present **only** when non-empty:

```
{"partial_args":[...],"partial_kwargs":{...},"closure":{...},"instance":{...}}
```

Each key is omitted when it has no entries. `closure` and `instance` are keyed
by variable and attribute name. If any bound value is not canonically
serializable the manifest is incomplete and the result is `unknown` — bound
state changes behaviour, so a digest that quietly skipped it would assert an
equality that is not there.

Coverage limit, which implementations MUST surface rather than hide: `afp2`
covers the unwrapped callable's own text and bound state. A change to an
imported prompt, helper or model client leaves the digest equal.

### dfp2o — dataset, order significant

```
{"kind":"dfp2o","rows":[<row 0>,<row 1>,...]}
```

Construction: every row of the evaluation dataset, in dataset order, each
reduced to exactly

```
{"input":<input>,"expected":<expected or null>}
```

- **All** rows are included, never the budget-capped prefix actually executed.
  The digest describes the dataset; the budget belongs to the run.
- `expected` is `null` when the row has no expected output. Absent and null are
  the same row.
- Any other field on a source row — an id, a split label, free-form metadata —
  is **excluded**. This is a stated coverage limit, not an oversight: two
  datasets differing only in row metadata get equal digests.
- A row that is a positional pair is read as `(input, expected)`.

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

Exactly one of `source` or `external` is present.

- `source` is built by the same three normalization steps as `afp2`.
- `external` describes an evaluator this process does not contain. `kind` is a
  short caller-supplied token naming the evaluator type or transport; it is
  descriptive only and never carries a URL, host, credential, or any other
  value that could identify an endpoint. `revision` is an immutable string the
  caller asserts changes whenever the evaluator's behaviour changes.

For an external evaluator reached over a network, the caller MUST supply an
immutable `revision`. Without one the manifest is incomplete and the result is
`unknown`, because behavior behind a stable URL can change invisibly and a
digest over the endpoint alone would assert a false equality.

### cfp2 — configuration space

```
{"kind":"cfp2","space":<configuration space as sent on the wire>}
```

`space` is the **exact value the client sends as `configuration_space` on
session create**, canonicalized by the rules above and otherwise untouched.

This is the whole normalization rule, and it is deliberately defined by
reference to the wire contract rather than to any internal representation.
"Normalized configuration space" without that anchor is unimplementable: an SDK
that expands sugar into an internal form, or orders variables by insertion, or
represents a choice list as a typed object, would produce a different manifest
from one that does not — while both authors believed they had followed the
spec. Pinning it to the transmitted value means the two SDKs hash the same
bytes because they already agreed to send the same bytes.

Consequences an implementer must know:

- Any client-side sugar is expanded **before** hashing, because expansion
  happens before sending.
- The order of values within a choice list is **significant**, for the same
  reason row order is: search consumes them in order under a trial budget, so
  two orders explore different configurations first.
- A configuration space that cannot be canonicalized makes the manifest
  incomplete, exactly as elsewhere.

### Anything not listed here

`afp2`, `dfp2o`, `efp2` and `cfp2` are the complete set for this contract
version. Prompts, toolsets and deployment identifiers have no slot and MUST NOT
be smuggled into one of the four above; adding an artifact means adding a slot,
which is a contract change.

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
