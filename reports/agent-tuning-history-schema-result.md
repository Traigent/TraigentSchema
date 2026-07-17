# Agent tuning-history browse contract — remediation result

Packet `pkt_c88286ff11fd2edf`, ChangeSession `cs_dbd17dd6bfabeed7`.
Remediates the gpt-5.6-terra xhigh review BLOCK of the prior uncommitted draft.

Audit chronology (exact):
1. `d725fe0` — Wave A schema draft made its browse/query invariants structurally
   enforceable (first remediation pass). See "Design decisions" below.
2. `5ad6311` — companion commit re-stamped the parity provenance hash
   (`parity/python-js-sdk.json`) for the `d725fe0` schema edit, so parity was fresh
   at that point.
3. `d319a9d` — second remediation pass against a fresh gpt-5.6-terra xhigh review
   that still BLOCKED advancing to Backend (strict error subtype, malformed-id
   `400`, exhaustive legacy/cursor modes, null-operand exclusion, error-state
   coupling, manifest duplicate rejection). See "Second remediation pass" below.
4. `00fa4e8` — companion commit re-stamped the parity provenance hash for the
   `d319a9d` schema edit, so parity was fresh again going into this pass.
5. **This pass (third remediation, two commits)** — a final narrow remediation after
   an independent Codex Terra xhigh review, closing one residual redaction gap in the
   strict error envelope. See "Third remediation pass" below.
   - **Primary commit** (packet `pkt_c88286ff11fd2edf`): the schema fix + decisive
     regression tests + this report + CHANGELOG.
   - **Companion commit** (approved packet `pkt_1c3f2ce482d11d82`): re-stamps the
     parity provenance hash (`parity/python-js-sdk.json`) for this schema edit, so
     parity is fresh at the final HEAD. That file is outside the primary packet's
     allowed set, so it is stamped only by the companion commit — not the primary one.

   At that pass's HEAD `python3 scripts/refresh_parity.py --check` was `exit 0`
   (digest `0214a09c89ba…`, files=364).
6. `fdbf599` / `f35d85d` — Wave A pass 3 (execution-group error envelope closed to
   finite enums) plus its companion parity re-stamp; this was the HEAD that then went
   to a fresh Terra Backend gate.
7. **This pass (fourth remediation, two commits)** — a fresh gpt-5.6-terra xhigh
   *Backend* review **BLOCKED** advancing to Backend continuation. The load-bearing
   reason: the frozen group-list ordering mandated `group_id` ascending as the
   group-list tie-breaker, but `group_id` is an opaque, non-reversible SHA-derived
   token, so exact SQL-bounded cursor pagination cannot portably sort by it without
   persistence/crypto-extension machinery. A first Backend band algorithm still
   materialized **all** groups in the all-primary-tied case, and Terra BLOCKED it.
   The tie-break carries no user-facing semantic value; deterministic, exact,
   visible-identity order does. This pass amends the unreleased tie-break to the
   group's canonical visible identity and nothing else. See "Fourth remediation pass"
   below.
   - **Primary commit** (packet `pkt_c88286ff11fd2edf`): the schema tie-break
     amendment + the decisive regression test + this report + CHANGELOG.
   - **Companion commit** (approved packet `pkt_1c3f2ce482d11d82`): re-stamps the
     parity provenance hash (`parity/python-js-sdk.json`) for this schema edit, in
     its own commit, so parity is fresh at the final HEAD. That file is outside the
     primary packet's allowed set.

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

Files changed across the full remediation (primary packet `pkt_c88286ff11fd2edf`
allowed set): `traigent_schema/schemas/execution/experiment_group_schema.json`,
`traigent_schema/schemas/execution/execution_endpoints.json`,
`tests/test_experiment_group_contract.py`,
`tests/test_success_envelope_and_response_coverage.py`, `CHANGELOG.md`,
`reports/agent-tuning-history-schema-result.md` (this file).

The third pass edited only:
- `traigent_schema/schemas/execution/experiment_group_schema.json` (strict error
  envelope `message`/`error_code` → finite enums)
- `tests/test_experiment_group_contract.py` (three decisive regression tests)
- `CHANGELOG.md`
- `reports/agent-tuning-history-schema-result.md` (this file)
- `parity/python-js-sdk.json` — companion packet `pkt_1c3f2ce482d11d82` only, in a
  separate commit.

The **fourth** pass (this pass, the group-list tie-break correction) edits the same
allowed set minus `execution_endpoints.json`; see "Fourth remediation pass" below for
its exact file list.  `tests/test_success_envelope_and_response_coverage.py` is
unchanged in this pass (its earlier-pass edits stand).

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

## Third remediation pass (this pass)

The independent Codex Terra xhigh review found one residual redaction gap: the
strict `ExperimentGroupErrorEnvelope` bounded its public strings by *character set*
(`message`) and *token grammar* (`error_code`) rather than by a closed vocabulary,
so the same benign-looking lowercase opaque token — e.g. `grp_secretvalue`, which is
a legal `OpaqueExperimentGroupId` — still validated as a `message` and as an
`error_code` (and, being opaque, as a group id). A raw group id, query fragment, or
secret-shaped token could therefore be echoed through those two fields. This pass
closes that gap and nothing else:

1. **`message` → finite fixed enum.** Replaced the display-safe character-set pattern
   with a closed enum of four fixed, display-safe server strings (one coarse display
   message per error class). No caller-supplied value — raw query text, group id,
   column value, SQL, secret, markup, or an opaque token — is a member, so none can
   validate. Finer client branching stays on `error_code`, never on request-derived
   message text.
2. **`error_code` → finite fixed enum.** Replaced the lowercase-token grammar with a
   closed enum of six fixed server codes covering this surface's real conditions
   (`validation.malformed_request`, `validation.malformed_group_id`,
   `validation.limit_out_of_range`, `auth.required`, `group.not_found`,
   `internal.unexpected`). Kept as an optional field (documented finer-branching
   classification) rather than removed, so existing accepted contract behavior and
   the field's shape are preserved; a closed enum is the only structurally safe
   encoding for a public classification field. `error` was already a closed enum and
   is unchanged.

Preserved exactly: shape compatibility with the canonical generic error envelope
(every value the strict subtype accepts still validates under
`error_envelope_schema.json`); the required fields (`success`, `message`, `error`);
the single indistinguishable `404`; and the absence of any group-scoped `403`.

Tests (allowed set): added three decisive tests to
`tests/test_experiment_group_contract.py` — (a) the public fields are finite fixed
enums with no pattern/length escape hatch and the enums are exactly the intended
vocabularies; (b) the opaque-id sentinel `grp_secretvalue` (proven group-id-shaped)
is rejected in `message`, `error`, and `error_code`, alongside raw-group-id,
raw-query, and secret-shaped sentinels — while the generic envelope would have
accepted them, which is exactly the leak the subtype closes; (c) positive white-list
coverage that every allowed `error` × `message` combination and every allowed
`error_code` validates and stays shape-compatible with the generic envelope. The
pre-existing negative tests (SQL/quotes/uppercase/`details` rejection,
shape-compatibility) continue to pass unchanged under the enums.

## Fourth remediation pass (this pass) — group-list tie-break

A fresh gpt-5.6-terra xhigh **Backend** review BLOCKED advancing to Backend
continuation. The frozen group-list ordering mandated `group_id` **ascending** as the
group-list tie-breaker. `group_id` is an opaque, non-reversible SHA-derived token, so
exact SQL-bounded cursor pagination cannot portably ORDER BY / range-bound it without
persistence or a crypto extension. A first Backend band algorithm, unable to
keyset-paginate on the opaque token, still **materialized all groups** in the
all-primary-tied case, and Terra BLOCKED it. The tie-break has no user-facing semantic
value; deterministic, exact, visible-identity order does. This pass amends only the
unreleased tie-break contract and nothing else (no feature widening, no identity
change, no configuration-run row-tie-break change).

**Amendment.** The group-list deterministic tie-breaker is now the group's canonical
visible identity, applied **after** the requested primary sort and **independent of**
the primary field, the primary direction, and `dataset_id` nullness:

1. `agent_id` ascending, then
2. canonical `dataset_id` ascending with an explicit deterministic null position —
   **NULLS FIRST**: the explicit no-dataset group (`dataset_id` null) sorts before any
   concrete dataset id.

`(agent_id, canonical dataset_id)` is exactly the group identity, is a real,
range-orderable column pair, and gives the same deterministic total order over groups
that `group_id` ascending was meant to give — but is exactly SQL keyset-paginable.
**NULLS FIRST** was chosen as the documented default; this Schema repo carries no
existing backend null-ordering convention that would require NULLS LAST, so the
instructed default stands (a backend that must use NULLS LAST would be a follow-up
contract note, not a silent divergence). The opaque `group_id` is now explicitly
documented as **not** the tie-break/sort key. `configuration_run_id` ascending remains
the configuration-run row tie-breaker, unchanged, because `configuration_run_id` is a
real range-orderable source id.

Edited (allowed set) this pass:
- `traigent_schema/schemas/execution/experiment_group_schema.json` — top-level
  invariant (4), `ExperimentGroupSortField` description, `SortDirection` description
  (direction-independence of the tie-break), and the configuration-run query `sort`
  description (adds direction-independence, keeps `configuration_run_id` ascending).
- `tests/test_experiment_group_contract.py` — one decisive regression test
  (`test_group_list_tie_break_is_canonical_identity_not_opaque_group_id`) asserting
  `group_id` is not the mandated sort/tie-break key, the canonical-identity tie
  (`agent_id` asc, then `dataset_id` asc, NULLS FIRST) is documented for both the sort
  field and the top-level invariant, the tie is fixed independent of primary
  direction/null, the old `group_id ascending` mandate is gone, the configuration-run
  row tie-break is untouched, and identity stays exactly `agent_id` + canonical
  `dataset_id`.
- `CHANGELOG.md` — a narrow Unreleased bullet under the Wave A entry.
- `reports/agent-tuning-history-schema-result.md` — this file.
- `parity/python-js-sdk.json` — companion packet `pkt_1c3f2ce482d11d82` only, in a
  separate commit.

**Out-of-scope residual (flagged, not silently shipped):**
`traigent_schema/schemas/execution/execution_endpoints.json` carries an *inline*
`sort_by` parameter description that still reads "Ties are broken deterministically by
group_id ascending." That parameter `$ref`s the amended `ExperimentGroupSortField`
(whose own description is authoritative and now correct), but the inline copy is
drift. `execution_endpoints.json` is **outside this packet's allowed-file set**, so it
is deliberately not edited here. No test asserts that inline string, so nothing is
red on it — but a fresh Terra review of the final HEAD may flag the inline drift. It
should be swept either by widening this packet's allowed set or in an immediate
follow-up packet. This is a documented handoff, not a silent contradiction.

Preserved exactly: group identity = visibility scope + `agent_id` + canonical
`dataset_id`; opaque `group_id`/cursors remain non-authorization lookup/continuation
tokens; the configuration-run row tie-break (`configuration_run_id` ascending); all
Wave A structural invariants from passes 1–3; and legacy/cursor compatibility.

## Exact command outcomes

Run in the repo `.venv` (Python 3.11.15).

| Check | Command | Result |
|-------|---------|--------|
| JSON parse | `json.load` on the changed schema file | OK |
| Validator load | `SchemaValidator(contract="backend")` | `experiment_group_schema` present; loads clean |
| Focused tests | `pytest tests/test_experiment_group_contract.py tests/test_success_envelope_and_response_coverage.py` | **81 passed** |
| Full suite | `pytest tests/ -q -p no:cacheprovider` | **1142 passed, 1 skipped** (2 pre-existing deprecation warnings) |
| Whitespace | `git diff --check` | clean |
| Lint (repo gate) | `ruff check traigent_schema/` | All checks passed |
| Lint (changed test) | `ruff check --line-length 100 --select E,F,I,UP,B tests/test_experiment_group_contract.py` | 1 error (pre-existing `I001` import ordering, predates this packet); **zero new**; no added line exceeds 100 chars (`--select E501` clean) |
| Typecheck (repo gate) | `mypy traigent_schema/ --ignore-missing-imports` | Success, no issues (5 source files) |
| Parity (companion re-stamp) | `python3 scripts/refresh_parity.py --update` then `--check` | `--update` exit 0 (digest `570c2b4a5728…`, files=364); `--check` **exit 0 (up-to-date)** at the final HEAD after the companion commit |

Focused test count went 80 → 81 (1 new decisive tie-break regression test this pass:
`group_id` is not the mandated sort/tie-break key; the canonical-identity tie
(`agent_id` asc, then canonical `dataset_id` asc, NULLS FIRST) is documented on both
the sort field and the top-level invariant; the tie is fixed independent of primary
direction/null; the old `group_id ascending` mandate is gone; the configuration-run
row tie-break stays `configuration_run_id` ascending; identity stays exactly
`agent_id` + canonical `dataset_id`). Full-suite count went 1141 → 1142 for that test.

## Downstream runtime acceptance handoff (schema does NOT prove these)

These are mandatory backend/E2E acceptance criteria; the JSON Schema records them
as explicit handoff risks, not proven behavior:

- **One row per source execution** and **exact scope/agent/dataset partitioning**
  of groups — enforced by the backend query, not the row schema.
- **Provenance/top-level id agreement** — the row's top-level source-execution ids
  are canonical; backend must ensure they trace to the exact execution (no sibling
  equality check exists in the contract).
- **Cursor snapshot semantics** (insert-stable walk, filter/sort binding, expiry
  rejection) and **deterministic tie-breakers** — runtime guarantees. The group list
  tie-breaks on canonical visible identity (`agent_id` ascending, then canonical
  `dataset_id` ascending **NULLS FIRST**), applied after and independent of the
  requested primary sort/direction; configuration-run rows tie-break on
  `configuration_run_id` ascending. Backend keyset pagination must ORDER BY the
  requested primary key then this exact identity tie-break (not the opaque
  `group_id`, which cannot be portably range-bounded).
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

- **Parity manifest is fresh at the final HEAD (`parity/python-js-sdk.json`).**
  This pass edits `experiment_group_schema.json`, which invalidates the parity
  provenance hash. The companion approved packet `pkt_1c3f2ce482d11d82` re-stamps it
  in its own commit: `python3 scripts/refresh_parity.py --update` produced digest
  `570c2b4a5728…` (files=364) and `--check` then returns
  `exit 0 (up-to-date)`. The manifest is **outside the primary packet's allowed-file
  set**, so it is stamped only by the companion commit, preserving packet separation.
  Not relaxed, not bypassed.
- **`execution_endpoints.json` inline `sort_by` drift (out of scope, flagged).** Its
  inline `sort_by` parameter description still reads "Ties are broken deterministically
  by group_id ascending", now inconsistent with the amended authoritative
  `ExperimentGroupSortField` it `$ref`s. The file is outside this packet's allowed set
  and no test asserts the inline string, so nothing is red — but a fresh Terra review
  of the final HEAD may flag it. Sweep by widening the allowed set or in an immediate
  follow-up packet.
- **Pre-existing test-file lint** (contract test import ordering, `I001`) predates
  this packet and was left untouched per the "do not edit unrelated baseline lint
  failures" instruction; the three tests added this pass introduce **zero new** lint
  (`--select E,F,I,UP,B` on the file is unchanged at the single pre-existing `I001`,
  and `--select E501` is clean). The repo lint gate (`ruff check traigent_schema/`)
  does not cover `tests/` and passes clean.
- Cross-repo propagation (SDK DTOs, BE Pydantic, FE TS types) is downstream of this
  schema-first change and out of this packet's scope.

No release-readiness claim is made here.
