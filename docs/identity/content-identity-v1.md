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
| Run identity binding (what a certificate binds) | `traigent_schema/schemas/execution/run_identity_binding_v1_schema.json` |
| Tests (known answers, properties, conformance) | `tests/test_example_identity.py` |

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
| Evaluator | `evaluator_id` (Backend definition or declared) | judge-config digest / efp2, **witnessed at scoring time** | Backend (registered) / SDK (local) |
| Run | `run_id` | the run identity binding (section 10) | Backend |
| Agent head (what is served) | `(tenant, project, agent, environment)` | monotonic `generation`, advanced only by compare-and-set | Backend (Director contract) |

---

## 2. Canonicalization (`jcs_v1`, strict profile)

Every hashed payload is serialized with `jcs_v1`, which is `traigent_schema.fp2.canonicalize`
(RFC 8785: keys sorted by UTF-16 code unit, ECMAScript number formatting, no whitespace).
The strict Traigent profile, all of it already enforced by fp2 and pinned by
`traigent_schema/data/fp2_conformance.json`:

- `NaN`, `Infinity`, `-Infinity` → **reject** (never `null`).
- Lone surrogates → **reject**.
- Integers with |v| > 2^53 − 1 → **reject**. (A *float* of that magnitude is accepted, as in fp2.)
- Non-plain types (subclasses, dates, bytes, sets, class instances) → **reject**.
- Nesting deeper than 100 containers → **reject**. The payload wraps the input in one object,
  so an input may nest at most 99 levels.
- **No Unicode normalization.** `"café"` (U+00E9) and `"café"` are different inputs
  with different ids. Normalizing would make two byte-different prompts collide, and prompts
  are sent to models byte for byte.

**Duplicate object keys** exist only in JSON *text*. Any producer that parses JSON text before
hashing MUST use a strict parser that rejects duplicate keys, `NaN`/`Infinity` literals, and
integer literals beyond ±(2^53 − 1). The Python reference is `parse_strict_json`. JavaScript's
`JSON.parse` silently keeps the last duplicate and rounds big integers, so the JS SDK needs its
own strict parser (or `JSON.parse` with source-text access where the runtime provides it). The
`json_text` rejection vectors pin this.

Known false equality, inherited from fp2 and impossible to close across languages: `1` and
`1.0` canonicalize identically, and `-0` becomes `0`.

---

## 3. Keys

```
tenant_master  : 32 random bytes, one per tenant per key version (custody: section 12)
PRK            = HMAC-SHA-256(key = UTF8("traigent.content_identity.v1"), msg = tenant_master)   # HKDF-Extract
K_example_id   = HKDF-Expand(PRK, info = UTF8("traigent.content_identity.example_id.v1"), 32)
K_example_ver  = HKDF-Expand(PRK, info = UTF8("traigent.content_identity.example_version.v1"), 32)
kid            = "k" + hex(HKDF-Expand(PRK, info = UTF8("traigent.content_identity.key_id.v1"), 8))
```

- HKDF is RFC 5869 with SHA-256. The tests check the implementation against RFC 5869 test
  cases A.1 and A.3.
- `kid` is public. It names the key version inside every identifier, so an id minted under a
  rotated key can never be mistaken for one minted under the old key, and a verifier holding
  the wrong key version finds out immediately. It is derived rather than assigned, so no
  registry is needed to produce it. Human-readable key labels belong in the key registry
  (section 12), not in ids.
- The master must be exactly 32 bytes and unique per tenant. The spec does not bind the
  tenant id into the derivation, so reusing one master across two tenants would make their ids
  linkable. Custody (section 12) must prevent that.

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

`context, example_id, external_id, source_ref, tags, split, splits, difficulty, confidence,
status, score, explanation, created_at, updated_at`

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
- **One key version per root.** Members minted under different `kid`s are rejected.
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
  - The manifest must contain at least one of `code_revision` (full git commit plus a `dirty`
    flag) or `source_digest` (afp2).
  - It may also contain `dependency_lock_digest`, `asset_digests` (prompts and tool specs that
    live outside the function), `applied_config_digest`, `label` and `runtime`.
  - It is unkeyed, because the manifest holds only digests and version strings.
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
- **Version:**
  - For a registered judge, the existing `EvaluatorVersionV1.judge_config_digest`.
  - For a local evaluator, the fp2 `efp2` digest. The objective set (name, orientation, weight)
    should be folded into it, per the Director map, gap G7.
- **Resolution:** a run records `witnessed_at_scoring` only when the scorer reported the version
  it actually executed. Today the Backend records the version *declared* at session start
  (`experiment_run_identity_snapshot`), and certification never reads it. A certificate MUST NOT
  make an evaluator-version claim from a declared-only binding.

## 10. Runs, trials, candidates and promotion

A run records one `RunIdentityBindingV1`:

- the base `agent` version;
- `base_head_generation`, the agent head generation captured when the run **starts**;
- the `dataset` (`DatasetIdentityV1` with `dataset_root`) and, optionally, a separate
  `search_set`;
- the `evaluator` binding;
- for each trial:
  - `evaluated`: an `EvaluatedSetV1` with `evaluated_root`, the counts, and `members` or
    `members_ref`;
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

This is the input to the certificate contract revision. It is not implemented in this PR, and
the frozen v0 and v1 certificate families are untouched. An issuer-signed certificate about a
candidate binds:

1. The `scheme` (`traigent.content_identity.v1`) and the `kid`, so a verifier knows which key
   version the ids are under.
2. `agent_id` and the candidate `build_digest`, plus the base `build_digest` and
   `base_head_generation`.
3. `dataset_id`, `dataset_root`, `distinct_count`, `total_count` and `conflicting_example_ids`.
   A non-empty conflict list must be disclosed.
4. For every trial on the claimed front: `trial_id`, `evaluated_root`, its counts,
   `repetition`, and the observed provider versions.
5. The evaluator id, its version digest, and `resolution`. Only `witnessed_at_scoring` may
   support an evaluator claim.
6. For selection-versus-evaluation claims: the search-set root and the size of the
   `example_id` overlap (section 13). Zero is itself the claim.

Relying parties can then check, **without any tenant key**:

- that an example (id, version, count) was in the certified evaluated set, using an inclusion
  proof whose `tree_size` equals the signed `distinct_count`;
- that two certificates used the same dataset (equal roots under the same `kid`).

This makes the model-checking properties proposed in CONSOLIDATED concrete:

- **ID1** (certificate identities resolve to server records that actually ran): the roots and
  build digests in the certificate equal those in the run binding.
- **ID2** (the claimed front shares one dataset and one evaluator version): every front trial
  has the same `dataset_root` and the same evaluator digest.
- **ID3** (promotion CAS: at most one accepted successor per generation, candidates never lost):
  generation compare-and-set.

---

## 12. Key management

What the spec fixes:

- Derivation (section 3). A 32-byte master per tenant per key version. `kid` inside every id.
- **Rotation changes every id.** A new master produces a new `kid`, and every `example_id`,
  `example_version` and root changes. Old records stay verifiable because they carry their
  `kid`.
- To compare across a rotation, the Backend recomputes ids from stored content under the new
  key and keeps an `old id → new id` map. SDK-local datasets must be re-hashed by the SDK.
  Certificates are never rewritten.
- Keys never appear in logs, reprs or error messages. The reference `TenantIdentityKeys` repr
  hides them, and a test checks this.
- The SDK receives **derived purpose keys**, never the master.

What the spec does not fix, because it cannot be derived from the code: **where tenant masters
live and who may obtain the derived keys**. See owner decisions D1 and D2 in section 16.

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
| Cross-tenant linkage | Nobody, given distinct masters | Different keys make the ids unlinkable. `kid` links ids within one tenant only |
| Unkeyed `exu1` digest | Anyone | Confirms guessed inputs. Opt-in, public benchmarks only (4.5) |
| Member lists and counts | Readers of the record | Disclose dataset size, duplicate structure and conflict count. No content |
| Inclusion proof | Its recipient | Discloses one leaf, the tree size and about log2(n) opaque sibling hashes. No other member |
| Agent build manifest | Readers of the record | Digests and version strings only. A git commit id reveals a revision, not code |
| Error messages | Log readers | Messages never echo inputs; a test checks this |

## 15. Honest limits

1. **An edited input is a new example.** `example_id` hashes the input, so fixing a typo in a
   prompt mints a new id, and history across that edit is not joined automatically. Lineage
   across input edits needs an explicit link: `external_id`, or a future `supersedes` record.
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
9. **JS strict parsing.** JS cannot tell an integer from a float in memory, so the big-integer
   rule is enforceable only where JSON text is parsed (section 2).
10. **Performance.** Building a proof recomputes subtrees, which is O(n log n). That is fine for
    evaluation datasets. Millions of rows would want a cached tree.

## 16. Owner decisions

**D1: Where tenant masters live, and who gets the derived keys.**

- A (recommended): one random 32-byte master per tenant per key version, held in KMS/Vault
  (envelope-encrypted) by the Backend. Authenticated SDK sessions receive only the two derived
  purpose keys plus `kid`, held in memory, never on disk.
  - Why: per-tenant blast radius and per-tenant rotation. Privacy-mode SDKs can hash locally
    without content leaving the machine.
- B: derive each tenant master from one platform root as `HKDF(root, tenant_id)`.
  - One secret to guard, but a compromise of the root exposes every tenant, and rotation is
    global.
- C: customer-held keys (BYOK), in the SDK only.
  - Strongest privacy, but the Backend cannot compute ids for hosted datasets, and a customer
    who loses the key loses its history.

**D2: Rotation policy.**

- A (recommended): rotate only on suspected compromise. The Backend keeps an old-to-new id map
  for stored content.
  - Why: every rotation breaks comparisons over time, so rotation should be rare.
- B: scheduled rotation, for example yearly. This pays the remap cost every period.

**D3: Granularity of the public-benchmark opt-in (the unkeyed `exu1` digest).**

- A (recommended): a per-dataset flag `public_benchmark: true`, settable by a tenant admin.
- B: a single tenant-wide flag.
  - This risks emitting unkeyed digests for private datasets.

## 17. What each implementation must do next

The rule for every implementation: pass **every** section of
`traigent_schema/data/content_identity_v1_vectors.json`. The Python reference harness to mirror
is `tests/test_example_identity.py` ("Conformance vectors").

**Python SDK (Traigent)**

1. Implement the canonicalization, keys, example_id and example_version, multiset root and
   inclusion proof, reusing its fp2 canonicalizer. Pass the vectors.
2. Apply `project_sdk_example` (4.4). Replace the positional `example_{i}` fallback with
   `example_id`, and keep a user-supplied id as `external_id`.
3. Record `evaluated_root` and members for each trial, with repetitions kept separate from
   counts.
4. Emit `AgentBuildManifestV1` and `build_digest`. Capture observed provider versions from
   responses.
5. Stop auto-applying winners (Director item 1). Capture `base_head_generation` at step start
   (Director item 2).

**JS SDK (traigent-js)**

1. The same as Python, plus a **strict JSON text parser** (duplicate keys, `NaN`/`Infinity`,
   integer literals beyond ±(2^53 − 1)).
2. Stop sending `agent = unknown`. Emit the manifest.

**Backend**

1. Implement key custody per D1, with a purpose-key issuance endpoint and a key registry
   `(tenant, kid, status, created_at)`.
2. Compute ids and `dataset_root` for hosted datasets. Store `dataset_root` on
   `dataset_versions`. Resolve a run's dataset version by root.
3. Persist `RunIdentityBindingV1` per run, with a member-list store behind `members_ref`.
4. Resolve evaluator versions **at scoring time** (`witnessed_at_scoring`).
5. Make agents project-owned.
6. Add the agent-head generation compare-and-set (Director item 2).
7. Revise the certificate contract to bind section 11. Add ID1 through ID3 to the model-checking
   contract.
