# Agent tuning-history browse contract — remediation result

Packet `pkt_c88286ff11fd2edf`, ChangeSession `cs_dbd17dd6bfabeed7`.
Remediates the gpt-5.6-terra xhigh review BLOCK of the prior uncommitted draft.

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

## Exact command outcomes

Run in the repo `.venv` (Python 3.11.15).

| Check | Command | Result |
|-------|---------|--------|
| JSON parse | `json.load` on both changed schema files | OK (both) |
| Validator load | `SchemaValidator(contract="backend")` | `experiment_group_schema` present; loads clean |
| Focused tests | `pytest tests/test_experiment_group_contract.py tests/test_success_envelope_and_response_coverage.py` | **66 passed** |
| Full suite | `pytest tests/ -q -p no:cacheprovider` | **1127 passed, 1 skipped** (2 pre-existing deprecation warnings) |
| Whitespace | `git diff --check` | clean |
| Lint (repo gate) | `ruff check traigent_schema/` | All checks passed |
| Lint (changed tests) | `ruff check --line-length 100 --select E,F,I,UP,B` | contract test 1→1, envelope test 20→20 (baseline == current; **zero new**); no added line exceeds 100 chars |
| Typecheck (repo gate) | `mypy traigent_schema/ --ignore-missing-imports` | Success, no issues (5 source files) |
| Parity | `python3 scripts/refresh_parity.py --check` | **exit 1 (stale)** — see downstream/risks |

Test count on this surface went from 57 → 66 focused (9 new decisive-negative
tests: cursor coupling, both-modes payloads, manifest truncation/wrong-namespace/
full-group coverage, predicate exclusive variants incl. validator path, provenance
canonical-id location, dataset_scope default, safe-error envelopes).

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
- **Non-disclosure timing/behavior** — the contract removes status/message leakage;
  the backend must also avoid timing side-channels between hidden and not-found.
- **Token re-authorization** — group ids and cursors are opaque lookup/continuation
  tokens only; the backend must re-authorize every request by tenant/project/user
  context.

## Remaining risks / follow-ups

- **Parity manifest is stale (`parity/python-js-sdk.json`, exit 1).** This is the
  expected consequence of changing schema files; the manifest is **outside this
  packet's allowed-file set**, so it was intentionally not stamped. Follow-up
  (separate scope/owner): run `python scripts/refresh_parity.py --update` and commit
  the manifest alongside SDK/BE/FE propagation. Not relaxed, not bypassed — recorded.
- **Pre-existing test-file lint** (contract test line 3 import ordering; ~20 E501 in
  the envelope-coverage test) predates this packet and was left untouched per the
  "do not edit unrelated baseline lint failures" instruction. The repo lint gate
  (`ruff check traigent_schema/`) does not cover `tests/`.
- Cross-repo propagation (SDK DTOs, BE Pydantic, FE TS types) is downstream of this
  schema-first change and out of this packet's scope.

No release-readiness claim is made here.
