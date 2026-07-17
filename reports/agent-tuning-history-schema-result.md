# Agent tuning-history browse contract — remediation result

Packet `pkt_c88286ff11fd2edf`, ChangeSession `cs_dbd17dd6bfabeed7`.
Remediates the gpt-5.6-terra xhigh review BLOCK of the prior uncommitted draft.

Audit chronology (exact):
1. `d725fe0` — Wave A schema draft made its browse/query invariants structurally
   enforceable (first remediation pass). See "Design decisions" below.
2. `5ad6311` — companion commit re-stamped the parity provenance hash
   (`parity/python-js-sdk.json`) for the `d725fe0` schema edit, so parity was fresh
   at that point.
3. **This commit** — second remediation pass against a fresh gpt-5.6-terra xhigh
   review that still BLOCKED advancing to Backend. See "Second remediation pass"
   below. Because it edits schema files again, the parity hash goes stale again and a
   subsequent re-stamp is required — owned by the separate approved packet
   `pkt_1c3f2ce482d11d82`, not stamped here (that file is outside this packet's
   allowed set).

## Scope

Additive, read-only Wave A browse surface over experiment groups in
`TraigentSchema`. The draft's *shape* was sound; Terra blocked it because the
key contract invariants were asserted in prose but not **enforced structurally**,
plus a duplicated-id provenance object that Draft 7 cannot honestly validate and
missing safe-error responses. This pass makes each invariant enforceable in Draft
7 and adds decisive negative tests, without widening the feature.

Preserved exactly (unchanged intent): group identity = authenticated visibility
scope + `agent_id` + canonical `dataset_id`; configuration/content/KPI/tvar/
implementation changes stay browsable together; no cross-setup rankings or Wave B
comparison signatures; legacy `GET` + `page`/`page_size` compatibility; the
explicit no-dataset group; bounded deterministic queries and safe errors.

Files changed (allowed set only):
- `traigent_schema/schemas/execution/experiment_group_schema.json`
- `traigent_schema/schemas/execution/execution_endpoints.json`
- `tests/test_experiment_group_contract.py`
- `tests/test_success_envelope_and_response_coverage.py`
- `CHANGELOG.md`
- `reports/agent-tuning-history-schema-result.md` (this file)

## Design decisions (per Terra finding)

1. **Cursor invariants.** `CursorPage` gains a top-level `oneOf`: `has_more: true`
   requires a non-null `OpaqueCursor`; `has_more: false` requires `next_cursor:
   null`. Both `ExperimentGroupListPayload` and `GroupedConfigurationRunListPayload`
   changed from `anyOf` → `oneOf` over `{required: pagination}` / `{required:
   cursor}`, so a payload carrying **both** modes now fails (two branches match)
   and one carrying **neither** also fails. Negatives added for every rejected
   combination.

2. **Full-group manifest.** Removed the `truncated` boolean — a `truncated: true`
   with no continuation mechanism is a dishonest completeness claim, and
   `additionalProperties: false` now rejects it outright. Each namespace array
   constrains its items to the matching `kind` (`parameter`/`measure`/
   `summary_stat`) via `allOf` + `const`, so a descriptor of the wrong namespace is
   rejected. The manifest is complete by construction or the response is invalid;
   the per-namespace `maxItems: 200` is the maximum browsable column count (a group
   exceeding it is an upstream rejection, never a silent truncation here — see
   downstream handoff). Negatives cover wrong-namespace descriptors and full-group
   coverage beyond the first row/page.

3. **Predicate grammar.** `ColumnPredicate` gains a `oneOf` over three exclusive
   variants: scalar operators (`eq/ne/gt/gte/lt/lte`) require a scalar operand and
   reject arrays; `in`/`not_in` require a bounded non-empty scalar array;
   `is_null`/`is_not_null` forbid a value (`not: {required: [value]}`). Negatives
   include scalar-op-with-array, null-op-with-value, and value-required cases, both
   against the bare definition and through the authoritative `SchemaValidator`
   request path.

4. **Safe errors.** Added canonical **redacted** `error_envelope_schema.json`
   responses to the group read/query routes: `400` (malformed query — with prose
   that it never echoes raw query text/values/internals), `401`, `500`, and a
   single `404` for the indistinguishable hidden-or-not-found condition. No `403`
   on any group-scoped resource, so forbidden-vs-not-found never leaks. Tests
   inspect the actual response `$ref`s and the presence/absence of status codes,
   not only prose.

5. **`dataset_scope` default.** `ExperimentGroupDatasetScope` now declares
   `default: "all"`. Date-bound ordering (`created_at_from ≤ created_at_to`) is
   **not** encodable in Draft 7 and is deliberately left to backend runtime tests;
   no dishonest structural claim was added.

6. **Provenance linkage.** `GroupedConfigurationRunProvenance` no longer carries
   `experiment_id`/`experiment_run_id`/`configuration_run_id`. Draft 7 cannot
   compare siblings, so duplicating them while only claiming equality in prose
   invites drift. The source-execution ids stay canonical (and required) at the
   browse-row top level; provenance carries only group identity (`agent_id`,
   canonical `dataset_id`) + optional display `experiment_name`.
   `additionalProperties: false` rejects re-introducing the ids. Tests assert the
   ids are absent from provenance and present/required on the row.

7. **Lint.** No new lint introduced in changed test code (see below).

## Second remediation pass (this commit)

The fresh Terra review still blocked; this pass closes the remaining structural
gaps without widening the feature or changing group identity/compatibility.

1. **Strict error subtype.** New `ExperimentGroupErrorEnvelope` definition. It stays
   shape-compatible with the canonical generic error envelope (any value it accepts
   also validates against `error_envelope_schema.json`) but is tightened
   structurally for this browse surface: `details` is not a property and
   `additionalProperties` is `false` (the generic envelope's free-form diagnostic
   sink cannot exist), every public string is bounded, `message` carries a
   display-safe pattern (no quotes, angle brackets, backticks, braces, semicolons, or
   backslashes), `error` is a closed vocabulary (`bad_request`/`unauthorized`/
   `not_found`/`internal_error`), and `error_code` is a bounded server-controlled
   token. So no raw query text, group id, tuned-variable value, SQL, or secret can
   validate. Every experiment-group `400`/`401`/`404`/`500` now points at this
   subtype rather than the generic envelope. The single indistinguishable `404` and
   the absence of any group-scoped `403` are preserved. Tests inject sentinel
   query/SQL/secret content and `details` objects and assert rejection, and assert
   shape-compatibility against the generic envelope.

2. **Malformed-id 400.** `GET /experiment-groups/{group_id}` gained its
   previously-missing `400` for a malformed `group_id`. Every route whose `group_id`
   is the constrained `OpaqueExperimentGroupId` now has a safe malformed-id response
   (all pointing at the strict subtype). A well-formed but unknown/hidden group is
   still the indistinguishable `404`, never this `400`.

3. **Legacy vs cursor modes — exhaustive and unambiguous.** OpenAPI cannot express
   cross-parameter mutual exclusion structurally, so the two modes — legacy page
   mode (`page`/`per_page`) and cursor mode (`cursor`/`limit`) — are declared through
   the repository's **established** machine-readable `x-excludes` extension on each
   pagination parameter (each legacy param excludes the cursor set and vice versa).
   `x-excludes` is used rather than a new `x-mutually-exclusive-parameter-sets` key
   because a brand-new `x-*` keyword must be declared in the governed
   `x_extensions_meta_schema.json` (enforced by `test_x_extensions_governance.py`),
   which is outside this packet's allowed-file set; `x-excludes` is already the
   repo's declared mutual-exclusion extension, so this stays in-scope. The exclusion
   relation is symmetric and its induced rejected-pair set is the complete
   cross-product (`cursor+page`, `cursor+per_page`, `limit+page`, `limit+per_page`);
   the descriptions state that omitting all four defaults to legacy page mode. A
   complete-matrix test derives the cross-product from `x-excludes` and asserts it.

4. **Predicate operands exclude null.** Scalar (`eq/ne/gt/gte/lt/lte`) and set
   (`in`/`not_in`) operands no longer admit `null`; absent-or-null matching is
   reserved for `is_null`/`is_not_null`. Set operands are non-empty, bounded
   (`maxItems: 100`), and `uniqueItems`. Negatives cover `eq`/`gt`/`in`/`not_in` with
   null both against the bare definition and through the authoritative
   `SchemaValidator` request path.

5. **Error-state coupling.** `GroupedConfigurationRunErrorState` uses `if`/`then` so
   `has_error: false` requires `error_code: null`; `has_error: true` may carry a
   stable non-null code or null for an unclassified failure. Negative: `has_error:
   false` with a non-null code is rejected.

6. **Manifest duplicate descriptors.** Each manifest namespace array is now
   `uniqueItems`, so exact-duplicate descriptors are rejected. Draft 7 cannot express
   uniqueness by the `(kind, key)` subtuple, so same-kind/key descriptors that
   disagree on `value_type`/`occurrence_count`/`filterable`/`sortable` must be
   rejected by the backend manifest builder — recorded in the manifest prose and in
   the downstream handoff.

## Exact command outcomes

Run in the repo `.venv` (Python 3.11.15).

| Check | Command | Result |
|-------|---------|--------|
| JSON parse | `json.load` on both changed schema files | OK (both) |
| Validator load | `SchemaValidator(contract="backend")` | `experiment_group_schema` present; loads clean |
| Focused tests | `pytest tests/test_experiment_group_contract.py tests/test_success_envelope_and_response_coverage.py` | **77 passed** |
| x-extension governance | `pytest tests/test_x_extensions_governance.py` | **5 passed** (`x-excludes` reuse needs no new registry entry) |
| Full suite | `pytest tests/ -q -p no:cacheprovider` | **1138 passed, 1 skipped** (2 pre-existing deprecation warnings) |
| Whitespace | `git diff --check` | clean |
| Lint (repo gate) | `ruff check traigent_schema/` | All checks passed |
| Lint (changed tests) | `ruff check --line-length 100 --select E,F,I,UP,B` | contract test 1→1, envelope test 20→20 (baseline == current; **zero new**); no added line exceeds 100 chars |
| Typecheck (repo gate) | `mypy traigent_schema/ --ignore-missing-imports` | Success, no issues (5 source files) |
| Parity | `python3 scripts/refresh_parity.py --check` | **exit 1 (stale)** — expected after schema edits; re-stamp owned by `pkt_1c3f2ce482d11d82`, see risks |

Focused test count went 66 → 77 (11 new decisive-negative tests this pass:
strict-error shape-compat + details/SQL/secret/raw-value rejection, group-routes
point at the strict subtype, malformed-id `400` on every constrained-`group_id`
route, complete legacy/cursor cross-mix matrix via `x-excludes`, predicate
null-operand exclusion incl. validator path, predicate set uniqueness/bounds,
error-state `has_error`/`error_code` coupling, and manifest duplicate-descriptor
rejection).

## Downstream runtime acceptance handoff (schema does NOT prove these)

These are mandatory backend/E2E acceptance criteria; the JSON Schema records them
as explicit handoff risks, not proven behavior:

- **One row per source execution** and **exact scope/agent/dataset partitioning**
  of groups — enforced by the backend query, not the row schema.
- **Provenance/top-level id agreement** — the row's top-level source-execution ids
  are canonical; backend must ensure they trace to the exact execution (no sibling
  equality check exists in the contract).
- **Cursor snapshot semantics** (insert-stable walk, filter/sort binding, expiry
  rejection) and **deterministic tie-breakers** (`group_id` / `configuration_run_id`
  ascending) — runtime guarantees.
- **Date-bound ordering** (`*_from ≤ *_to`) — runtime validation.
- **Manifest union completeness across all rows** and the browsable-column cap
  (`maxItems: 200` per namespace) — backend must reject groups whose true column
  union would exceed the cap rather than emit a partial manifest.
- **Manifest descriptor uniqueness by subproperty** — `uniqueItems` catches exact
  duplicate descriptors, but Draft 7 cannot assert uniqueness by the `(kind, key)`
  subtuple, so two descriptors sharing a `(kind, key)` while disagreeing on
  `value_type`/`occurrence_count`/`filterable`/`sortable` must be rejected by the
  backend manifest builder.
- **Cross-parameter pagination-mode exclusion** — `x-excludes` declares that legacy
  `page`/`per_page` and cursor `cursor`/`limit` are mutually exclusive; OpenAPI
  cannot enforce cross-parameter exclusion, so backend request validation must reject
  every cross-mix and default an all-omitted request to legacy page mode.
- **Non-disclosure timing/behavior** — the contract removes status/message leakage;
  the backend must also avoid timing side-channels between hidden and not-found.
- **Token re-authorization** — group ids and cursors are opaque lookup/continuation
  tokens only; the backend must re-authorize every request by tenant/project/user
  context.

## Remaining risks / follow-ups

- **Parity manifest re-stamp is required again (`parity/python-js-sdk.json`).**
  Chronology: commit `5ad6311` re-stamped the parity provenance hash after the
  `d725fe0` schema edit, so parity was fresh going into this pass; this commit edits
  the schema files again, so `python3 scripts/refresh_parity.py --check` is expected
  to report `exit 1 (stale)` — verified. The manifest is **outside this packet's
  allowed-file set** and its refresh is owned by the separate approved packet
  `pkt_1c3f2ce482d11d82`, so it was intentionally **not** stamped here. That packet
  runs `refresh_parity.py --update` (and the SDK/BE/FE propagation) after this schema
  commit. Not relaxed, not bypassed — reported honestly and handed off.
- **Pre-existing test-file lint** (contract test line 3 import ordering; ~20 E501 in
  the envelope-coverage test) predates this packet and was left untouched per the
  "do not edit unrelated baseline lint failures" instruction. The repo lint gate
  (`ruff check traigent_schema/`) does not cover `tests/`.
- Cross-repo propagation (SDK DTOs, BE Pydantic, FE TS types) is downstream of this
  schema-first change and out of this packet's scope.

No release-readiness claim is made here.
