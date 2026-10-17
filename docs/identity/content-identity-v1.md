# Content identity v1 — the thing and its versions

Scheme tag: `traigent.content_identity.v1`. Status: **normative** for canonicalization,
key derivation, example identity, multiset roots and inclusion proofs (sections 2–7);
**design contract** for agent, evaluator, run/trial binding and certificates (sections 8–11),
which the Backend and SDKs implement in follow-up PRs.

| Artifact | Path |
|---|---|
| Reference implementation | `traigent_schema/example_identity.py` |
| Conformance vectors (every SDK and the Backend MUST pass them) | `traigent_schema/data/content_identity_v1_vectors.json` |
| Vector generator / freshness check | `scripts/generate_content_identity_v1_vectors.py --check` |
| Example / dataset / trial / proof wire shapes | `traigent_schema/schemas/datasets/content_identity_v1_schema.json` |
| Agent version manifest | `traigent_schema/schemas/agents/agent_version_manifest_v1_schema.json` |
| Evaluator version manifest | `traigent_schema/schemas/evaluation/evaluator_version_manifest_v1_schema.json` |
| Run identity binding (what a certificate binds) | `traigent_schema/schemas/execution/run_identity_binding_v1_schema.json` |
| SDK wire envelopes (session create, trial metadata) and reason codes | `traigent_schema/schemas/execution/content_identity_wire_v1_schema.json` (section 18) |
| Purpose-key grant (Backend → SDK) | `traigent_schema/schemas/datasets/purpose_key_grant_v1_schema.json` (section 18) |
| Tests (known answers, properties, conformance) | `tests/test_example_identity.py` |
| Wire tests over real SDK payloads | `tests/test_content_identity_wire.py`, fixtures `tests/data/content_identity_wire/` |

Inputs this design follows: the owner rulings of 2026-09-23, the MLOps platform survey of the
same date, and the Director session's identity/concurrency map and synthesis (build-order items
1, 2, 4 and 5 are the Director session's; item 3 and the certificate binding are this spec).

---

## 1. The model in one table

Identity says **which thing**; version says **which bits of that thing**. A version never
changes an identity, and ranking or averaging is only allowed between results whose versions
match.

| Entity | Identity (stable handle) | Version (content) | Who mints it |
|---|---|---|---|
| Example | `example_id` = tenant-keyed HMAC of the **input** (+ context) | `example_version` = tenant-keyed HMAC of id + expected output + version-relevant metadata | whoever holds the content: SDK for local data, Backend for hosted data |
| Dataset | `dataset_id` (Backend, a name) | `dataset_root` = order-free **multiset** Merkle root over `(example_id, example_version, count)` | same as examples |
| Trial's evaluated examples | the trial | `evaluated_root` + member list, same construction | the process that ran the trial |
| Agent | `agent_id`, declared and **project-owned** (Backend) | `build_digest` over a build manifest, plus per-trial **observed** provider versions | SDK computes, Backend records |
| Evaluator | `evaluator_id` (Backend definition or declared) | `evaluator_version_digest` over code (efp2) + judge + objective set + dependencies, **witnessed at scoring time** | Backend (registered) / SDK (local) |
| Run | `run_id` | the run identity binding (section 10) | Backend |
| Agent head (what is served) | `(tenant, project, agent, environment)` | monotonic `generation`, advanced only by compare-and-set | Backend (Director contract) |

---

## 2. Canonicalization (`jcs_v1`, strict profile)

Every hashed payload is serialized with `jcs_v1`, which is `traigent_schema.fp2.canonicalize`
(RFC 8785: keys sorted by UTF-16 code unit, ECMAScript number formatting, no whitespace).
The strict content-identity profile is fp2's rules plus one stricter number rule. The
content-identity vectors pin all of it:

- `NaN`, `Infinity`, `-Infinity` → **reject** (never `null`).
- Lone surrogates, in values **and in object keys** → **reject**.
- **Any number, integer or float, with |v| > 2^53 − 1 → reject.** This is stricter than
  fp2, which accepts a large *float*.
  - Why: once JavaScript has parsed `9007199254740993` or `9007199254740993.0`, it holds
    `9007199254740992`. Accepting any number beyond the safe range would let Python and JS
    hash different values for the same text.
  - **On JSON text**, the check applies to the literal's **exact decimal value, before
    rounding** (relay decision E). `9007199254740991.1` is rejected even though it rounds to
    `9007199254740991.0`. Python compares `Decimal(literal)`. A JS strict parser must compare
    the literal's digits, not the rounded `Number`.
  - **On in-memory values**, which have already been rounded, the check is
    `abs(v) <= 2^53 − 1`. In JS that is `Math.abs(v) <= Number.MAX_SAFE_INTEGER`. A value that
    was rounded *before* it reached the producer cannot be detected.
  - `9007199254740991.0` is accepted and hashes like the integer `9007199254740991`.
- Non-plain types (subclasses, dates, bytes, sets, class instances) → **reject**.
- Nesting deeper than 100 containers → **reject** (fp2's limit, counting the outermost
  container as 1).
  - The id payload `{"input": …}` adds one level, so `input` and `context` may nest at most
    **99** levels. The vectors pin both sides of the boundary: `nesting_at_limit` (99) is
    accepted and `nesting_over_limit` (100) is rejected.
  - `expected` is likewise limited to 99 levels. Each `metadata` value is limited to 98.
- **No Unicode normalization.** `"café"` (U+00E9) and `"café"` are different inputs
  with different ids. Normalizing would make two byte-different prompts collide, and prompts
  are sent to models byte for byte.

**Duplicate object keys** exist only in JSON *text*. Any producer that parses JSON text before
hashing MUST use a strict parser that rejects duplicate keys, `NaN`/`Infinity` literals, and
number literals whose exact decimal value is beyond ±(2^53 − 1). The Python reference is `parse_strict_json`. JavaScript's
`JSON.parse` silently keeps the last duplicate and rounds big numbers, so the JS SDK needs its
own strict parser (or `JSON.parse` with source-text access where the runtime provides it). The
`json_text` rejection vectors pin this, and `example_input` rejection vectors pin the in-memory
check (`{"a": 1e16}`, `{"a": 9007199254740992}`). The `json_text` vectors cover:

- duplicate keys;
- `NaN` and `Infinity` literals, and `1e400`;
- `2^53`, `2^53 + 1`, `-2^53`, `9007199254740993.0`, `1e16` and `9007199254740991.1`;
- a lone surrogate in a value, and one in a key.

Known false equality, inherited from fp2 and impossible to close across languages: `1` and
`1.0` canonicalize identically, and `-0` becomes `0`.

---

## 3. Keys

```
tenant_master  : 32 random bytes, one per tenant per key version (custody: section 12)
tenant_id      : the Backend's exact tenant id string (enterprise_tenants.id, e.g. "tenant_<hex>"),
                 matching ^[A-Za-z0-9_-]{1,128}$ -- ASCII, case-sensitive, never folded
info(D)        = UTF8(D) || 0x00 || UTF8(tenant_id)
PRK            = HMAC-SHA-256(key = UTF8("traigent.content_identity.v1"), msg = tenant_master)   # HKDF-Extract
K_example_id   = HKDF-Expand(PRK, info("traigent.content_identity.example_id.v1"), 32)
K_example_ver  = HKDF-Expand(PRK, info("traigent.content_identity.example_version.v1"), 32)
kid            = "k" + hex(HKDF-Expand(PRK, info("traigent.content_identity.key_id.v1"), 8))
```

- HKDF is RFC 5869 with SHA-256. The tests check the implementation against RFC 5869 test
  cases A.1 and A.3.
- **Full-string matching.** Every identifier and `tenant_id` pattern is matched against the
  whole string (Python `re.fullmatch`; in JSON Schema, the portable end anchor `(?![\s\S])`).
  A trailing newline is rejected (relay decision E). A plain `$` also matches before a final
  `\n` in Python, which would create a second spelling of one id.
- `kid` is public. It names the key version inside every identifier, so an id minted under a
  rotated key can never be mistaken for one minted under the old key, and a verifier holding
  the wrong key version finds out immediately. It is derived rather than assigned, so no
  registry is needed to produce it. Human-readable key labels belong in the key registry
  (section 12), not in ids.
- **`kid` is probabilistic** (64 bits; relay decision G). It is only unique within a tenant
  with high probability. Key lookups are therefore always **tenant-scoped** (`(tenant_id, kid)`,
  never `kid` alone). A `kid` collision among one tenant's key versions is a **hard error at
  key creation**: the Backend discards the new master and generates another.
- The master must be exactly 32 bytes and SHOULD be unique per tenant (ruling D1).
- The tenant id is bound into every HKDF `info` (review item F2, adopted 2026-09-23). If a
  master is ever reused by mistake across two tenants, their keys, `kid`s and ids are still
  unrelated. The `reused_master_other_tenant` vector pins this.
- `tenant_id` is the Backend's stored string, byte for byte. A producer that lower-cases or
  reformats it derives different keys.

---

## 4. Example identity

### 4.1 Payloads

```
example_id      = "ex1:"  + kid + ":" + hex(HMAC(K_example_id,  UTF8(D_id)  || 0x00 || jcs_v1(P_id)))
example_version = "exv1:" + kid + ":" + hex(HMAC(K_example_ver, UTF8(D_ver) || 0x00 || jcs_v1(P_ver)))

P_id  = {"input": <input>, "context": <context>}                   # context omitted when absent
P_ver = {"example_id": <example_id>, "expected": <expected>, "metadata": <metadata>}   # each optional key omitted when absent
```

`D_id` and `D_ver` are the example_id and example_version domain strings. Digests are full
32-byte values in lowercase hex and are **never truncated**. MLflow's 32-bit digests and Opik's
8-character hashes are the failures to avoid.

`example_version` chains the example_id rather than repeating the input. It is therefore a
commitment to input + context + expected + metadata, as the owner ruled, and a version can
never be attached to the wrong id.

### 4.2 Absent versus null (pinned by vectors)

| Field | Treated as absent | Hashed as a value |
|---|---|---|
| `context` | missing, `null` | anything else, **including `{}` and `""`** |
| `expected` | missing, `null` | anything else |
| `metadata` | missing, `null`, `{}` | a non-empty object |

`input` is required and may be any `jcs_v1` value.

### 4.3 Metadata participation

`metadata` holds **version-relevant** facts only: anything that changes how the answer should
be graded, such as a rubric or grading notes. The reserved annotation keys below never take
part. The projection strips them. The primitive `compute_example_version` **rejects** them, so a
caller that skipped the projection fails loudly. The alternative would be a version that
changes every time someone re-tags a row.

`context, example_id, external_id, source_ref, supersedes, tags, split, splits, difficulty,
confidence, status, score, explanation, created_at, updated_at`

This list extends the annotation exclusions of `DatasetVersionV1`: tags, explanation,
difficulty, confidence, status and score.

### 4.4 Projections from product shapes

Each producer MUST project its native example into `(input, context, expected, metadata)`
exactly as follows. The `projections` vectors pin the SDK rule.

| Producer | input | context | expected | metadata |
|---|---|---|---|---|
| Python SDK `EvaluationExample` / JS SDK `EvaluationExample` | `input_data` / `inputData` | `metadata["context"]` when present and not null | `expected_output` / `expectedOutput` | `metadata` minus reserved keys; empty means absent |
| Backend hosted example (`benchmark_example`) | `input_text` (string, or list for multi-turn) | absent (no column today) | `expected_output` | absent (every other column is a reserved annotation) |

**Consequence to know about.** Identity is over the canonical *value*. An SDK-local row
`{"question": "x"}` and a hosted row whose `input_text` is `"x"` have different ids. When an
SDK evaluates a *hosted* dataset, it MUST use the Backend-computed ids for that dataset rather
than recompute them from a reshaped value. This spec deliberately does not define a mapping
between the two shapes, because such a mapping would be a silent collision rule.

### 4.5 Opt-in unkeyed digest for public benchmarks

```
public_input_digest = "exu1:" + hex(SHA-256(UTF8("traigent.content_identity.public_input.v1") || 0x00 || jcs_v1(P_id)))
```

This digest is unkeyed, so anyone who can guess the input can confirm it. Producers emit it
**only** when the tenant has opted in **and** the example comes from a public benchmark. Its
sole purpose is contamination checks: detecting that a tenant's evaluation set, or another
tenant's training data, overlaps a public benchmark. Keyed ids cannot support that check,
because keys are per tenant.

---

## 5. Dataset version: the multiset root

```
members   = distinct (example_id, example_version) pairs with count = multiplicity (≥ 1)
            sorted ascending by (example_id, example_version)
leaf_data = UTF8("traigent.content_identity.multiset_leaf.v1") || 0x00 || jcs_v1([example_id, example_version, count])
root      = "msr1:" + kid + ":" + hex(MTH(leaf_data_0 … leaf_data_{n-1}))     # RFC 9162 §2.1.1
MTH({})   = SHA-256("")
MTH({d})  = SHA-256(0x00 || d)
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),  k = largest power of two < n
```

- **Order-free.** Members are sorted before hashing. Every id is fixed-width lowercase ASCII,
  so byte order, code-point order and UTF-16 order agree, and every runtime sorts them the same
  way.
- **A multiset.** A repeated pair is merged into `count`, so `[a, a, b]` and `[(a, 2), b]` give
  the same root, and that root differs from `[a, b]`. Duplicates are never silently collapsed,
  which is the MLflow failure recorded in the survey.
- **One key version per root, checked everywhere** (relay decision G). The `kid` is,
  normatively, the **second colon-separated field** of every `ex1:`, `exv1:` and `msr1:`
  identifier (`key_id_of` in the reference). A consumer MUST check that it equals the record's
  `key_id` for the record, for every root it carries (`dataset_root`, `evaluated_root`), and for
  every member's id and version. Members minted under different `kid`s are rejected.
- **Counts are bounded.** Each member's `count` and the multiset's `total_count` are at most
  2^53 − 1 (relay decision E). Summing past that bound is rejected.
- **Conflicting labels.** If one `example_id` appears with more than one `example_version`, the
  root is still defined, but the producer MUST warn and MUST report the ids in
  `conflicting_example_ids`. Paired comparisons exclude those ids (section 13).
- **Repetitions are not multiplicity.** Evaluating the same example three times as epochs is
  recorded as a trial `repetition`, never folded into `count`.
- **The tree is unkeyed over keyed leaves.** This is a deliberate departure from the survey's
  "keyed hash (or HMAC over the MTH)". The leaves are already HMAC tokens, so keying the nodes
  adds no privacy. Leaving the nodes unkeyed lets a **third party verify an inclusion proof
  with no key**, which is the point of choosing a Merkle tree.
- **Why not an algebraic multiset hash** (MSet-Add or MSet-XOR)? Those need keying and are
  subtle to get right. Datasets are small enough to sort, and a Merkle tree also provides
  inclusion proofs.

**Consumers recompute.** Every record that states a root, whether a dataset identity or
an evaluated set, carries its members inline (`members`) **or** by reference (`members_ref`).
For an evaluated set, the schema's `oneOf` requires exactly one of the two. A consumer MUST
obtain the member list and **recompute the root from it**, then compare the result with the
stated root. A stated root, and the member order, are never trusted on their own.

`dataset_root` and every trial's `evaluated_root` use this **same** construction under the
same key. A trial that evaluated the whole dataset exactly once therefore has
`evaluated_root == dataset_root`.

### 5.1 Relation to existing digests (nothing is replaced in this PR)

| Existing | What it is | Relationship |
|---|---|---|
| `DatasetVersionV1.content_digest` (`datasets/dataset_version_schema.json`, `content_identity.py`) | Unkeyed. Orders rows by the *assigned* example_id and hashes `{input_text, expected_output}`. Keeps duplicates | Stays as it is. The Backend should store `dataset_root` next to it on each `dataset_versions` row |
| fp2 `dfp2o` | Unkeyed. Over the **ordered** evaluation rows | Stays as the SDK comparability fingerprint until both SDKs emit `dataset_root`. It is order-dependent, so it is not a dataset identity |
| `dataset_record_v1` `item_set_root` | Blind-HMAC leaves, a flat sorted-list digest, **set** semantics, certification-only | Frozen contract, left untouched. A later dataset-record revision may bind `dataset_root` |
| SDK positional `example_{i}` fallback | Shifts whenever a row is inserted | Superseded by `example_id`. The SDKs keep `external_id` for the user's own ids |
| Backend `configuration_run_outcome_cells.example_content_fingerprint` | A per-cell content key | Maps onto `example_version` |

---

## 6. Inclusion proofs

Proof generation and verification follow RFC 9162 §2.1.3. A proof commits to the exact member,
**including its count**, its leaf index, the tree size, the audit path and the root.
Verification needs no key.

**Tree size is not authenticated by the proof.** For a leaf inside a complete left subtree,
a proof verifies identically for several tree sizes; for example, leaf 2 verifies against both
size 7 and size 8. This matches Certificate Transparency, where the tree size comes from the
signed tree head. The relying party MUST take `tree_size` from the **signed record's
`distinct_count`**, never from the proof itself. The vectors intentionally contain no
"wrong tree size" tamper case, and the generator records why.

Consistency proofs (RFC 9162 §2.1.4) are not provided. Sorted multisets are not append-only,
because inserting an example shifts every later leaf. "Dataset v2 extends v1" is therefore
shown with `is_sub_multiset` over the member lists, not with a log proof.

---

## 7. Interop fields (annotation only, never hashed)

- `external_id`: the example's id in its source system. That is Phoenix `external_id`,
  Braintrust or LangSmith example `id`, MLflow `dataset_record_id`, Inspect `Sample.id`, Opik
  item id, Promptfoo `testIdx`, or OpenAI `datasource_item_id`.
- `source_ref = {platform, dataset_id, version}`, where `version` is the source's own handle:
  - LangSmith `as_of` or a tag;
  - Braintrust `_xact_id`;
  - Opik `version_hash`;
  - Phoenix version id;
  - W&B `artifact:vN` or its digest;
  - the Hugging Face revision SHA;
  - the DVC `.dir` md5;
  - the MLflow `digest`.

- `supersedes`: the `example_id` this example replaces (relay decision H). A typo fix changes
  the input, and so the id; `supersedes` keeps the lineage visible.
  - It is an annotation on `ExampleIdentityV1` and never hashed.
  - It is a reserved metadata key, so the projection strips it.
  - The `with_annotations` vector proves that `external_id`, `source_ref` and `supersedes`
    change neither `example_id` nor `example_version`.

These fields let a Traigent root be mapped back to the source platform's own version handle.
Identity still comes from content, never from them.

---

## 8. Agent identity and version

- **Identity: `agent_id`.** It is declared, stable, **project-owned** and minted by the Backend.
  Today agents are unique per `(tenant, created_by, name)`, which makes identity per user; the
  target is unique per `(tenant, project, agent_key)`. That is a Backend change.
  - Identity is never derived from code, knobs or objectives.
  - The Python fallback label, which is built from objectives, knob names and a path hash,
    splits an agent's history whenever a knob is added. The SDKs MUST warn when `agent_name` is
    absent.
- **Version: `build_digest`.** It is `"sha256:" + hex(SHA-256(UTF8("traigent.content_identity.agent_build.v1") || 0x00 || jcs_v1(AgentBuildManifestV1)))`.
  It is unkeyed, because the manifest holds only digests and version strings. The manifest MUST
  commit to the **full behaviour-affecting surface** (relay decision A, section 16):
  - **Code:** `code_revision` (a full git commit plus a `dirty` flag) and/or `source_digest`
    (afp2). When `dirty` is true, `source_digest` is **required**; otherwise two different
    uncommitted trees on one commit would share a `build_digest`.
  - **Assets, all three categories required:** `asset_digests.prompts`,
    `asset_digests.helper_modules` (project source the agent imports) and
    `asset_digests.tool_definitions` (tool, function-calling and retriever specs). Each is a map
    from a stable name to a `sha256:` digest. An empty map `{}` asserts that the category is
    empty; it is not the same as "unknown".
  - **Candidate configuration, required:** `applied_config_digest`. That is the trial's
    configuration for a candidate, the promoted one for a head, or the default for a base
    build (the digest of `{}` when there are no knobs).
  - **Coverage, required:** `coverage` is `complete` or `partial`. `partial` admits that some
    behaviour-affecting input is missing, for example a helper the SDK could not locate. A
    partial manifest still gets a `build_digest`, which is useful for history and comparison.
    It is **not certifiable**:
    - the schema's `CertifiableAgentBuildManifestV1` requires `coverage: "complete"`;
    - `compute_agent_build_digest(manifest, certifiable=True)` rejects it;
    - the vectors pin both.
  - **Runtime, required:** `runtime` (language, SDK version and optionally the language
    version). A build's runtime affects its behaviour, so it is part of the version.
  - Optional fields: `dependency_lock_digest` and `label`.
  - Changing only a helper module, only a prompt, only a tool definition, or only the
    configuration changes `build_digest` (the `agent_builds` vectors).
  - Relabelling produces a new version by design, so a label can never be moved onto different
    bits.
- **Observed provider versions** are recorded per trial from provider *responses*: requested
  model, the model the response reports, and the system fingerprint.
  - An alias such as `gpt-4o` is not a version.
  - If a response does not report a model, the record says `null` ("unknown"). It never copies
    the requested model into that field.
  - Observed versions are deliberately **not** part of `build_digest`. Build is what was
    shipped; observation is what ran. A certificate binds both.

## 9. Evaluator identity and version

- **Identity:** `evaluator_id`, the Backend evaluator definition, or a declared name for an
  SDK-local metric set.
- **Version: `evaluator_version_digest`** (relay decision B). It is
  `"sha256:" + hex(SHA-256(UTF8("traigent.content_identity.evaluator_version.v1") || 0x00 || jcs_v1(EvaluatorVersionManifestV1)))`,
  defined by `schemas/evaluation/evaluator_version_manifest_v1_schema.json` and computed by
  `compute_evaluator_version_digest`. The manifest commits to everything that changes a score:
  - `code_digest`: the fp2 **efp2** digest of the evaluator code. fp2 and efp2 are consumed
    here, not changed.
  - `judge`: `{provider, model, config_digest}`, or an **explicit `null`** for a model-free
    evaluator. Omitting the field is rejected. For a registered judge, `config_digest` is the
    existing `EvaluatorVersionV1.judge_config_digest`.
  - `objectives`: the objective set, as `{name, orientation, weight}`. It MUST be sorted by
    `name` with unique names, and anything else is rejected, so that one set has exactly one
    spelling. This closes Director map gap G7.
  - `config_digest`: the evaluator's **bound configuration**, meaning thresholds, captured
    parameters and closure-bound values. efp2 covers source only, so without this a
    model-free evaluator's threshold change would not be a new version. Use the digest of `{}`
    when there is none.
  - `helper_digests`: the contents of the **local helper files** the evaluator calls (project
    source), keyed by name. `{}` asserts none.
  - `dependency_versions`: behaviour-affecting third-party dependency versions. `{}` asserts
    none.
  - Changing an objective's orientation or weight, the judge model, the judge configuration, a
    dependency or the code changes the digest. So does changing only a model-free evaluator's
    threshold or only a local helper file. The `evaluator_versions` vectors pin all of these.
- **Resolution:** a run records `witnessed_at_scoring` only when the **server** observed the
  version that actually scored (section 11, claim rule C3). Today the Backend records the version
  *declared* at session start (`experiment_run_identity_snapshot`), and certification never
  reads it.

## 10. Runs, trials, candidates and promotion

A run records one `RunIdentityBindingV1` with a `record_state` (relay decision C):

- **`draft`**: still being assembled. It may lack any linkage and is **never certifiable**.
- **`complete`**: the schema's `if`/`then` requires all of the following:
  - `base_head_generation`;
  - a certifiable base `agent`: its manifest is inlined and has `coverage: "complete"`;
  - a `dataset` whose own `record_state` is `complete`;
  - an inlined evaluator `manifest`;
  - at least one trial, and a certifiable `candidate` on every trial.
- **Only `complete` records are certifiable.**

`DatasetIdentityV1` carries its own `record_state`. Like `EvaluatedSetV1`, it carries its
members either inline or by reference, exactly one of the two (`oneOf(members | members_ref)`).
A consumer MUST obtain the list and recompute the root.

The record contains:

- the base `agent` version and `base_head_generation`, the agent head generation captured when
  the run **starts**;
- the `dataset` and, optionally, a separate `search_set`;
- the `evaluator` binding: `version_digest`, `resolution` and the manifest;
- for each trial:
  - `evaluated`: an `EvaluatedSetV1`;
  - `candidate`: the agent version this trial's configuration defines;
  - `observed_provider_versions`.

**Candidates versus promotion (Director items 1 and 2; not implemented here, but this contract
matches them):**

- A run produces **candidates**. It never applies a winner as a side effect. Today the Python
  SDK auto-applies at `optimized_function.py:2685`; Director item 1 separates "produce
  candidate" from "apply".
- Promotion is a separate event.
  - It is an atomic **compare-and-set** on the agent head `(tenant, project, agent,
    environment)`, carrying the `expected_generation` = `base_head_generation` captured at step
    start (Director item 2).
  - The Director synthesis found why the start value matters: the SDK currently fetches the
    etag *immediately before* publishing, so a stale candidate can overwrite a newer winner.
  - At most one successor is accepted per generation. A loser keeps its candidate and its
    certificate.
- **Certification is not promotion.** A certificate says "this candidate measured X on these
  exact identities". A promotion record says "the head moved from generation g to g+1 onto this
  candidate, citing certificate c".

## 11. What certificates will bind

This section is **normative** for the certificate contract revision (relay decision D). The
issuer implements it in milestones M3 and M4; it is not implemented in this PR, and the frozen
v0 and v1 certificate families are untouched.

**Provenance labels.** Every identity fact in a run binding comes from one of two sources:

- **server-recorded**: the Backend itself created or observed the fact. Examples are run and
  trial rows it minted, candidate linkage it persisted when the trial was registered, roots it
  recomputed from member lists it stores, and an evaluator version it observed when scoring.
- **declared**: a client sent the fact and the server could not witness it. Examples are an
  SDK-computed root with no stored member list, a client-asserted candidate, and an evaluator
  version declared at session start.

The certificate MUST label every bound fact with its source. **Declared facts cannot satisfy
ID1.** A certificate may carry them only as labelled declarations, never as issuer-attested
claims.

**What the issuer binds.** It binds only server-recorded linkage and server-witnessed evaluator
versions, under the rules below:

1. The `scheme` (`traigent.content_identity.v1`) and the `kid`.
2. `agent_id` and the candidate `build_digest`, plus the base `build_digest` and
   `base_head_generation`. Each is recomputed from the inlined, certifiable manifest.
3. `dataset_id`, `dataset_root`, `distinct_count`, `total_count` and `conflicting_example_ids`.
   The root is recomputed from the stored member list. A non-empty conflict list is disclosed.
4. For every trial on the claimed front: `trial_id`, `evaluated_root` (recomputed), its counts,
   `repetition`, and the observed provider versions.
5. The evaluator id and its `evaluator_version_digest` (recomputed from the inlined manifest).
   This counts as a claim only with `resolution = witnessed_at_scoring` (C3).
6. For selection-versus-evaluation claims: the search-set root and the size of the
   `example_id` overlap (section 13). Zero is itself the claim.

**Two kinds of rule** (made precise by the re-review, relay decision I, section 16). A
`complete` record (section 10) guarantees that the needed fields are *present*. The rules below
decide whether each fact is *server-recorded*. There are two kinds:

- **Issuance rules (I1–I4)** cover the facts **every** certificate needs. If one fails, the
  issuer issues nothing.
- **Claim rules (C1–C6)** each gate one specific claim. If a claim's server-recorded facts are
  missing, the issuer **refuses that claim only**. The certificate is still issued without it.
  The facts involved may appear in it only as labelled declarations, and a relying party must
  not read a declaration as a claim.

**Issuance rules: if any fails, nothing is issued.**

- **I1 (complete record):** the run binding's `record_state` is `complete`, and so is its
  dataset identity's.
- **I2 (a real run):** the run and every bound trial are rows the Backend minted itself. The
  run-to-trial linkage is server-recorded. Without that, nothing in the certificate is attached
  to anything that actually ran.
- **I3 (key consistency):** the `kid` of the record, of every root, and of every member id and
  version equals the record's `key_id` (section 5).
- **I4 (the dataset):** `dataset_root` recomputes from the **server-stored** member list and
  equals the recorded root. Every certificate is a statement about some evaluation data, so a
  certificate whose dataset is only declared says nothing.

**Claim rules: if one fails, only that claim is refused.**

| Claim | Server-recorded facts it requires | Property |
|---|---|---|
| **C1: evaluated set** of trial *t* ("*t* was scored on exactly this multiset") | `evaluated_root` recomputes from the server-stored member list, and the multiset is a sub-multiset of the dataset | ID1 |
| **C2: agent version** of candidate *c* ("the measured candidate is build *B*") | trial-to-candidate linkage recorded by the server at trial registration; the candidate's manifest is certifiable (`coverage: complete`) and recomputes to `build_digest`; the same holds for the base build, plus `base_head_generation` | ID1 |
| **C3: evaluator version** ("scores came from evaluator version *E*") | `resolution = witnessed_at_scoring`, and `version_digest` recomputes from the inlined manifest. A declared-at-session-start version may be carried, labelled declared, but never claimed | ID1 |
| **C4: comparable front** ("these trials are comparable") | C1 and C3 hold for every front trial, and all front trials share one `dataset_root` and one `evaluator_version_digest` | ID2 |
| **C5: no selection leakage** ("search and evaluation examples do not overlap") | `search_set` is server-recorded with a recomputed root; the certificate states the size of the `example_id` overlap (section 13), and zero is itself the claim | — |
| **C6: winner or ranking** ("*c* is best among these") | C4, plus C2 for every ranked candidate | ID1, ID2 |

This removes the earlier contradiction, where a blanket "refuse to issue" sat beside a rule
allowing a declared evaluator. A certificate whose evaluator is only declared **is** issued, if
I1–I4 pass. It carries the declared version with that label and simply has no C3, C4 or C6
claim.

Relying parties can then check, **without any tenant key**:

- that an example (id, version, count) was in the certified evaluated set, using an inclusion
  proof whose `tree_size` equals the signed `distinct_count`;
- that two certificates used the same dataset (equal roots under the same `kid`).

Model-checking properties:

- **ID1** (certificate identities resolve to server records that actually ran): every
  issuer-attested root, build digest and evaluator digest equals a server-recorded value. This
  is enforced by I1–I4 for the certificate itself and by C1–C3 for each claim. Declared facts
  never count.
- **ID2** (the claimed front shares one dataset and one evaluator version): C4.
- **ID3** (promotion CAS: at most one accepted successor per generation, candidates never lost):
  generation compare-and-set (Director item 2).

---

## 12. Key management

What the spec fixes:

- Derivation (section 3). A 32-byte master per tenant per key version, bound to the tenant
  id. `kid` inside every id.
- **Rotation changes every id.** A new master produces a new `kid`, and every `example_id`,
  `example_version` and root changes. Old records stay verifiable because they carry their
  `kid`.
- To compare across a rotation, the Backend recomputes ids from stored content under the new
  key and keeps an `old id → new id` map. SDK-local datasets must be re-hashed by the SDK.
  Certificates are never rewritten.
- Keys never appear in logs, reprs or error messages. The reference `TenantIdentityKeys` repr
  hides them, and a test checks this.
- The SDK receives **derived purpose keys**, never the master.

Custody, rotation and the public-digest opt-in are settled by the owner rulings in section 16
(D1 = A, D2 = A, D3 = A, 2026-09-23).

## 13. Statistical use

- **Search-versus-evaluation overlap (leakage)** is measured on **`example_id`**, the input,
  not on `(id, version)`. A relabelled example still leaks its input from the search split into
  the evaluation split. `example_id_overlap(search, evaluated)` is the reference.
- **Paired comparison** between two candidates, or two runs, happens per
  **`(example_id, example_version)`**. A pair counts only when both sides evaluated the same id
  at the same version.
  - Ids in `conflicting_example_ids`, on either side, are excluded.
  - Ids whose version differs between the two runs are excluded and reported. Their label
    changed, so their score difference measures the label, not the agent.
- **Comparability of aggregates.** A mean over run A and a mean over run B may be compared
  directly only when `evaluated_root` is equal (the same multiset). Otherwise, compare only on
  the paired intersection.
- **Multiplicity.** A duplicated row (count 2) is weighted twice in a dataset-level mean, which
  is what the dataset author wrote down. Repetitions and epochs are a separate axis, averaged
  within a pair first.
- **Subsampling.** `is_sub_multiset(evaluated, dataset)` proves that a trial drew only from the
  certified dataset.

## 14. Privacy analysis

| Exposure | Who can exploit it | Consequence and mitigation |
|---|---|---|
| Equality leak inside a tenant | Anyone who sees ids | Equal inputs have equal ids. This is intended, because it is what makes overlap checks work |
| Dictionary attack on low-entropy inputs ("yes", a 4-digit PIN) | Only holders of `K_example_id`, meaning the tenant's own SDK users and the Backend | Keyed ids stop outsiders, including other tenants and certificate readers, from confirming guesses. They do **not** hide low-entropy inputs from the tenant's own key holders. Ids are not encryption |
| Key compromise | Whoever holds the key | Every id under that `kid` becomes open to dictionary attack. Rotate (D2), which changes every id |
| Cross-tenant linkage | Nobody | Different masters, and a different `tenant_id` in the HKDF `info` even if a master were reused, make the ids unlinkable. `kid` links ids within one tenant only |
| Unkeyed `exu1` digest | Anyone | Confirms guessed inputs. Opt-in, public benchmarks only (4.5) |
| Member lists and counts | Readers of the record | Disclose dataset size, duplicate structure and conflict count. No content |
| Inclusion proof | Its recipient | Discloses one leaf, the tree size and about log2(n) opaque sibling hashes. No other member |
| Agent build manifest | Readers of the record | Digests and version strings only. A git commit id reveals a revision, not code |
| Error messages | Log readers | Messages never echo inputs; a test checks this |

## 15. Honest limits

1. **An edited input is a new example.** `example_id` hashes the input, so fixing a typo in a
   prompt mints a new id, and history across that edit is not joined automatically. Lineage
   across input edits needs an explicit link: `external_id`, or the `supersedes` annotation
   (section 7).
   The Director synthesis recommended an assigned id plus a separate content digest for exactly
   this reason. The owner ruled for the hash, and this is its price.
2. **Low-entropy inputs are guessable by key holders** (section 14).
3. **Rotation re-keys everything.** Comparison across a rotation needs the remap.
4. **Shape-sensitive.** `{"q": "x"}` and `"x"` are different inputs (4.4). `1` equals `1.0`
   (section 2).
5. **Metadata participation is a denylist.** Any non-reserved metadata key changes the version.
   A producer that stuffs volatile bookkeeping, such as a file path, into metadata will see
   spurious new versions.
6. **Declared versus witnessed.** Nothing here proves that a client computed its ids honestly.
   Ids and roots are client-*reported* until the Backend recomputes them from content it holds,
   or a receipt witnesses them. That is the same limit the certificate ledger already has.
7. **Tree size comes from the signed record, not the proof** (section 6).
8. **No consistency proofs.** Sorted multisets are not append-only.
9. **Number range before rounding is a text-only check.** Once a value has been rounded, for
   example `9007199254740991.1` to `9007199254740991.0`, or a JS `Number` that has lost
   precision, the original is gone. The exact-decimal rule is therefore enforceable only where
   JSON text is parsed (section 2). In-memory values get the post-rounding check.
10. **Performance.** Building a proof recomputes subtrees, which is O(n log n). That is fine for
    evaluation datasets. Millions of rows would want a cached tree.
11. **Coverage and completeness are declarations.** `coverage: "complete"` is the producer's
    claim that every behaviour-affecting input is in the agent manifest. Nothing offline can
    prove the absence of an unlisted helper or prompt. The certifiable gate ensures that the
    claim was *made*, not that it is *true*. An issuer can strengthen it only with its own
    evidence, for example by rebuilding from `code_revision` when `dirty` is false.

## 16. Owner rulings (2026-09-23)

The three decisions this spec left open were ruled by the owner on 2026-09-23. The
recommended option was taken in each case.

**D1 = A: custody.** Each tenant has one random 32-byte master per key version.
- The Backend holds it in KMS/Vault (envelope-encrypted). It never leaves the Backend.
- Authenticated SDK sessions receive only the two derived purpose keys plus `kid`. The SDK
  keeps them in memory and never on disk.
- Why: the blast radius of a leak is one tenant, rotation is per tenant, and privacy-mode SDKs
  can hash locally without content leaving the machine.
- Not chosen: B (every tenant key derived from one platform root) and C (customer-held keys).

**D2 = A: rotation.** Keys are rotated only on suspected compromise, not on a schedule.
- On rotation, the Backend recomputes ids for stored content under the new `kid` and keeps an
  `old id → new id` map. SDK-local datasets are re-hashed by the SDK.
- Certificates are never rewritten. They stay verifiable under the `kid` they carry.

**D3 = A: public-benchmark opt-in.** A per-dataset flag, `public_benchmark: true`, settable by
a tenant admin. It gates the unkeyed `exu1` digest.
- The flag is off by default. It never becomes tenant-wide.

**F2 (review item), adopted with D1:** `tenant_id` is bound into every HKDF `info` (section 3).
- This is defence in depth against a master reused by mistake.
- It changed every derived key, id and vector. That was done before any adoption, still under
  `traigent.content_identity.v1`, because nothing had shipped.
- The canonical tenant-id string (the Backend's `enterprise_tenants.id`, charset
  `^[A-Za-z0-9_-]{1,128}$`) is now a cross-SDK agreement point. The SDKs receive it from the
  Backend together with the purpose keys and never construct it themselves.

### Relay decisions 2026-09-23 (owner-delegated)

The owner was unavailable and delegated these decisions to the relay coordinator. They come
from the milestone M1 reviews: astra BLOCK, and Fable APPROVE with must-fixes. Each is recorded
here as a relay decision, 2026-09-23 (owner-delegated).

- **A: agent version coverage** (astra P1-1). `asset_digests` is required, with three
  categories: prompts, helper modules and tool definitions. `applied_config_digest` is required.
  `coverage` is required, `complete` or `partial`, and only `complete` is certifiable
  (section 8).
- **B: evaluator version** (astra P1-2, Fable M2). `EvaluatorVersionManifestV1` and
  `evaluator_version_digest` are defined in this spec, covering efp2 code, judge, objectives and
  dependencies. fp2 and efp2 are unchanged (section 9).
- **C: complete versus draft** (astra P1-3, Fable F2/F5). `record_state` is added to the run
  binding and to the dataset identity. A `complete` record requires `base_head_generation` and
  every candidate. `DatasetIdentityV1` gets `oneOf(members | members_ref)`. Only `complete`
  records are certifiable (section 10).
- **D: ID1 linkage** (astra P1-4). The issuer binds only server-recorded linkage and
  server-witnessed evaluator versions. Declared facts are labelled and cannot satisfy ID1.
  The issuer rules apply (section 11; made precise by decision I as issuance rules I1–I4 and claim rules C1–C6). Implemented in M3/M4.
- **E: validation** (astra P2).
  - Full-string matching for `tenant_id` and every identifier pattern.
  - Number literals are judged by their exact decimal value before rounding.
  - `total_count` ≤ 2^53 − 1.
  - Rejection vectors pin each rule (sections 2, 3 and 5).
- **F: in-memory big numbers** (Fable F1). `example_input` rejection vectors for `1e16` and
  `2^53`.
- **G: kid** (Fable F3, astra P3). The kid is the second colon field. Consumers check it on the
  record, the roots and every member. Lookups are tenant-scoped, and a collision is a hard error
  at key creation (sections 3 and 5).
- **I: re-review of `0c3c96fb`** (astra; items 1 and 3 were resolved there, and these three
  still blocked):
  - **Item 2:** `EvaluatorVersionManifestV1` requires `config_digest` (the bound configuration)
    and `helper_digests` (local helper contents; `{}` means none). Vectors show that a
    threshold-only change and a helper-only change each change the digest (section 9).
  - **Item 4:** §11 now separates issuance rules I1–I4, which cover facts every certificate
    needs and block issuance, from claim rules C1–C6, which refuse only the affected claim.
    This removes the "refuse to issue" versus declared-evaluator contradiction.
  - **Item 5:** the literal range check uses exact `Decimal(text).copy_abs()` comparison.
    `abs()` rounded under the 28-digit context and accepted `9007199254740991.0000000000001`.
    Vectors cover rejection of that value and its negative, and acceptance of a just-under
    value and of the limit with trailing zeros (the `json_text_accepted` section).
- **J: re-review of `24961a9e`** (Fable APPROVE; a Node reimplementation built only from this
  doc passed ok=405 bad=0).
  - **Fable F6:** `runtime` is a **required** part of `AgentBuildManifestV1`. The doc had
    listed it as optional; the doc is corrected. `compute_agent_build_digest` rejects a manifest
    without it, and a rejection vector pins this (section 8).
  - **Nit:** the vector constant `tenant_id_pattern` uses the `(?![\s\S])` end anchor, like
    decision E.
  - **Dataset root in the every-certificate tier:** I4 in section 11 is accepted. The dataset
    root is an issuance rule, not a per-claim rule, because a certificate whose dataset is only
    declared says nothing checkable. If narrow process certificates that carry no dataset are
    wanted later, I4 moves to the claim tier by a new decision.
- **H: `supersedes`** (Fable F4). An optional annotation, never hashed, pinned by a vector
  (section 7).

## 17. What each implementation must do next

The rule for every implementation: pass **every** section of
`traigent_schema/data/content_identity_v1_vectors.json`. The Python reference harness to mirror
is `tests/test_example_identity.py` ("Conformance vectors").

**Python SDK (Traigent)**

0. Apply the section 2 number rule: reject |v| > 2^53 − 1, even for floats. This goes
   beyond fp2.

1. Implement the canonicalization, keys, example_id and example_version, multiset root and
   inclusion proof, reusing its fp2 canonicalizer. Pass the vectors.
2. Apply `project_sdk_example` (4.4). Replace the positional `example_{i}` fallback with
   `example_id`, and keep a user-supplied id as `external_id`.
3. Record `evaluated_root` and members for each trial, with repetitions kept separate from
   counts.
4. Emit `AgentBuildManifestV1` and `build_digest`:
   - all three asset categories (prompts, helper modules, tool definitions);
   - `applied_config_digest`;
   - an honest `coverage`: `partial` whenever a behaviour-affecting file could not be located.

   Emit `EvaluatorVersionManifestV1` and `evaluator_version_digest`. Capture observed provider
   versions from responses.
5. Stop auto-applying winners (Director item 1). Capture `base_head_generation` at step start
   (Director item 2).

**JS SDK (traigent-js)**

1. The same as Python, plus a **strict JSON text parser** (duplicate keys, `NaN`/`Infinity`,
   and **any** number literal beyond ±(2^53 − 1), in integer, fractional or exponent form).
2. Stop sending `agent = unknown`. Emit the manifest.

**Backend**

1. Implement key custody per ruling D1 (KMS/Vault, one master per tenant per key version),
   rotation per D2, and the per-dataset `public_benchmark` flag per D3. Add a purpose-key
   issuance endpoint that returns `{tenant_id, kid, example_id_key, example_version_key}`
   (`PurposeKeyGrantV1`, section 18) and a
   key registry
   `(tenant, kid, status, created_at)`.
2. Compute ids and `dataset_root` for hosted datasets. Store `dataset_root` on
   `dataset_versions`. Resolve a run's dataset version by root.
3. Persist `RunIdentityBindingV1` per run with a `record_state`, and a member-list store behind
   `members_ref` for both datasets and trials. Record run, trial and candidate linkage
   server-side, and label every fact server-recorded or declared (section 11).
4. Resolve evaluator versions **at scoring time** (`witnessed_at_scoring`).
5. Make agents project-owned.
6. Add the agent-head generation compare-and-set (Director item 2).
7. Revise the certificate contract to bind section 11 and enforce issuance rules I1–I4 and claim rules C1–C6
   (milestones M3/M4). Add ID1 through ID3 to the model-checking
   contract.

## 18. The SDK wire envelopes

Sections 8–10 define the records; this section defines what the SDKs actually **send** before
the Backend has turned anything into a record. Schema:
`execution/content_identity_wire_v1_schema.json`. The fixtures in
`tests/data/content_identity_wire/` are real payloads captured from both SDKs' own builders.

**No grant, no envelope.** An SDK sends an envelope only when it holds a purpose-key grant.
Without one it sends no `content_identity` at all: the payloads are byte-identical to an SDK
without content identity. So `key_status` is always `"available"`.

**The grant.** `PurposeKeyGrantV1` (`datasets/purpose_key_grant_v1_schema.json`) is the
Backend's response to an authenticated session:
`{tenant_id, kid, example_id_key, example_version_key, encoding: "hex"}`.

- Each key is 32 bytes, sent as 64 lowercase hex characters.
- `encoding` is always `"hex"`. A consumer rejects any other value rather than guessing.
- The two keys are **secrets**. They are never logged, written to disk, echoed in an error,
  exported or forwarded. SDKs hold them in memory only and redact them from every rendering.
- The grant never contains the tenant master (ruling D1).

**Two envelopes.** Both carry `scheme` and `provenance: "declared"`. Everything in them is a
client declaration: the Backend stores it, recomputes it and labels it (section 11). A declared
fact never satisfies a certificate claim on its own.

| Envelope | Where it travels | Slots |
|---|---|---|
| `SessionContentIdentityWireV1` | session-create body, top-level `content_identity` | `key_status`, `key_id`, `agent_id_source`, `agent`, `evaluator_id_source`, `evaluator`, `dataset`, `unavailable` |
| `TrialContentIdentityWireV1` | trial result `metadata.content_identity` | `trial_id`, `candidate`, `evaluated`, `observed_provider_versions`, `unavailable` |

Each slot holds its own contract, narrowed to what the SDKs send:

- `agent` and `candidate` are an `AgentVersionV1` with the manifest always inlined. They need not
  be certifiable: `coverage` may be `partial`.
- `evaluator` is an `EvaluatorVersionBindingV1` with the manifest inlined and
  `resolution: "declared_at_session_start"`. A client never sends `witnessed_at_scoring`. The
  SDKs emit it only when **every** manifest field is known, either because scoring is built-in
  or because the caller declared it. `{}` and a `null` judge are claims, never defaults.
- `dataset` is a `DatasetIdentityV1` with `record_state: "draft"` and `members` inlined.
- `evaluated` is an `EvaluatedSetV1` with `members` inlined.
- `observed_provider_versions` holds `ObservedProviderVersionV1` entries. Every field is present,
  and an unknown is an explicit `null`; this includes `system_fingerprint`. `call_count` is
  always stated. An empty list means nothing was observed, which is an honest unknown.

**Null-slot rules** (enforced by the schema):

1. A slot is `null` exactly when `unavailable` names a reason for it. `unavailable` is
   `{slot: reason}` and is `{}` when nothing is withheld.
2. When `agent` or `evaluator` is `null`, its `*_id_source` is `null` too: nothing was sourced.
   When the slot is present, its id source is `"declared"` or `"fallback"`.
3. `unavailable.conflicting_example_ids` (truncation) only accompanies a non-null `dataset`.
4. Above 2,000 distinct members the **whole slot** is `null` with `members_exceed_inline_cap`.
   There is no in-record `members_unavailable` field, and `members_ref` is not sent until the
   Backend's member-list store exists. Its handle will be a `MemberListRefV1` (`ml1:<id>`).
   Admitting it on the wire then is a widening, not a breaking change.

Consumers also check what the schema cannot express:

- `dataset.key_id` and every `evaluated.key_id` equal the session's `key_id`;
- `evaluated.trial_id`, when present, equals the envelope's `trial_id`;
- every stated digest and root recomputes from the inlined manifest or members.

**Reason codes** (`ContentIdentityUnavailableReasonV1`) form a closed vocabulary, the union of
both SDKs. Each slot accepts only its own subset.

| Code | Slots | Meaning |
|---|---|---|
| `agent_id_unavailable` | agent, candidate | no usable agent id |
| `agent_manifest_unavailable` | agent, candidate | the build manifest could not be built |
| `config_not_canonicalizable` | agent, candidate | the configuration cannot be fp2-digested |
| `evaluator_id_unavailable` | evaluator | the declared evaluator id is malformed (Python SDK only; see below) |
| `evaluator_manifest_unavailable` | evaluator | some manifest field is unknown |
| `row_not_canonicalizable` | dataset, evaluated | some dataset row cannot be canonicalized |
| `members_exceed_inline_cap` | dataset, evaluated | more than 2,000 distinct members |
| `evaluation_results_unavailable` | dataset (JS only), evaluated | per-example results (JS session: the dataset rows) were not available |
| `row_outside_dataset` | evaluated | the trial evaluated a row that is not in the identified dataset |
| `conflicting_example_ids_truncated` | conflicting_example_ids | the list was cut to its first 1,000 ids |
| `purpose_keys_unavailable`, `purpose_key_provider_failed` | none | reserved: no grant means no envelope, so neither SDK sends them today |

**Known divergence between the SDKs**, recorded rather than hidden (tests pin it):

- A malformed declared evaluator id is `evaluator_id_unavailable` in Python and
  `evaluator_manifest_unavailable` in JS.
- A JS run whose dataset rows the SDK does not hold reports the session `dataset` slot as
  `evaluation_results_unavailable`. Python has no such case.

Both are inside the vocabulary. The content-derived slots (`dataset`, `evaluated`,
`observed_provider_versions`) are byte-identical across SDKs for the same rows and grant.
