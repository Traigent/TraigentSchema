# WI-C Schema — economics recommendation calculator contract (evidence)

> **Update — rebased onto develop 5.0.0 on 2026-07-25 (captain).** The packet below was
> written against the pre-5.0.0 develop line and then parked. Everything in the body
> described the contract as it stood on 2026-07-18. Read the body as the ORIGINAL
> record, not as current truth: the passages marked SUPERSEDED below no longer hold,
> and where the body and this note disagree, this note is authoritative.
>
> Superseded numbers:
>
> | Body says | Now |
> |---|---|
> | version `4.10.0 → 4.11.0`, CHANGELOG `[4.11.0] - 2026-07-18` | `5.0.0 → 5.1.0`, CHANGELOG `[5.1.0] - 2026-07-25` (develop shipped the 5.0.0 honest-SemVer release, #343, while this was parked) |
> | `schemaFileCount` 375 → 377, `files=377` | 376 → **378** (develop added one schema file meanwhile); parity re-stamped with `scripts/refresh_parity.py --update` |
> | `47 passed` in this file, `1222 passed` overall | **52** in this file (2 endpoint-binding tests, 2 pointer tests, 1 vocabulary-wide allowlist test added; 3 display-name tests replaced by 2); full suite **1305 passed / 1 skipped** |
>
> **Terra review round 1 returned BLOCK; all three findings were real and are fixed
> in the same branch.** (1) `agent_display_name` was an 80-character free-text field
> whose own description claimed it "cannot become a free-text egress channel" — removed
> outright, since the agent renders locally and never needs to transmit it; and
> `evidence_pointer` is now intersected with the opaque-identifier grammar inside this
> request, documented as bounding the channel rather than sealing it (the shared WI-B
> definition is untouched — narrowing a shipped contract is a breaking change owed a
> coordinated MAJOR release, raised to the owner instead). (2) The claim that "an offline
> path returns the same shapes" and that fixtures are agreed by "both the offline path
> and the backend" was unsupported — no producer exists — so the vectors are now
> described as schema-valid examples, not conformance evidence. (3) `published_reference`
> was optional while the schema claimed the formula is published and re-derivable; it is
> now required, with resolution declared as a backend obligation. Terra's non-blocking
> item is also done: the allowlist gate is now driven from the vocabulary across all ten
> fields instead of spot-checking two. Each fix was mutation-tested — removing the
> narrowing, re-adding a display name, making the reference optional, and deleting one
> allowlist gate each fail their guard.
>
> One substantive addition on rebase: develop's #343 bound every non-2xx status of the
> sibling telemetry route to `error_envelope_schema.json` and pinned those bindings with
> tests. This route documented its five error statuses as bare descriptions — the exact
> gap #343 had just closed next door — so the same convention is now applied here and
> pinned by two new tests (`test_every_error_status_binds_the_shared_error_envelope`,
> `test_the_route_documents_exactly_the_expected_status_set`), verified to fail when the
> binding is removed. It is a contract-first **specification**, not an observation: no
> backend serves this route, and `x-asserted-against-backend: false` still holds.

Branch `feature/econ-model-wi-c-schema`, worktree `TraigentSchema-wi-c`, continued from
accepted WI-B HEAD `c27a034`. All changes left UNCOMMITTED (HEAD still `c27a034`; captain owns
refs/commits). Schema-only WI-C: the closed characterization submission request and the
backend-authoritative recommendation response, one canonical POST route, deterministic offline
fixtures, adversarial tests. No `credit`/`incentive`/`grant`/`promo`/`wallet`/`billing`/pricing/
`dollar_gate`/Evidence-Gym/WI-D fields anywhere.

## Deliverables (files)

New schemas:
- `traigent_schema/schemas/economics/economics_recommendation_request_schema.json`
- `traigent_schema/schemas/economics/economics_recommendation_response_schema.json`

Wiring / docs / manifest (modified):
- `traigent_schema/schemas/economics/economics_endpoints.json` — added `POST
  /api/v1/economics/recommendation` (200/400/401/403/422/503); retitled the catalog. Still
  `x-stability: pre-release`, `x-asserted-against-backend: false`, under the `planned_projects`
  root.
- `traigent_schema/version.py` 4.10.0 → 4.11.0; `CHANGELOG.md` new dated `[4.11.0] - 2026-07-18`
  section (WI-B's `[4.10.0]` left intact so the two stacked PRs don't collide on the same lines);
  `README.md` release line → 4.11.0.
- `parity/python-js-sdk.json` — re-stamped digest + `schemaFileCount` 375 → 377.

Tests + example vectors (new) — SUPERSEDED wording: these were called "deterministic
 offline fixtures"; nothing implements the contract, so they are schema-valid EXAMPLES,
 not evidence that any offline path or backend agrees with them:
- `tests/test_economics_recommendation_contract.py` (47 tests)
- `tests/test_data/economics/recommendation_{request,response}_*.json` — 3 request/response pairs
  (solo builder, support automation, all-withheld → spend-$0), paired by echoed `request_id`, no
  computation implementation. Placed under `tests/test_data/` (NOT the schema tree) so they are
  not loaded as schemas / counted in the parity digest / flagged as orphans.

## Request contract — verified properties

- Closed five band fields + optional typed overrides reused from
  `economics_characterization_vocabulary_schema.json` by `$ref` (enums/bounds NOT restated).
- Per-field provenance `asked|inferred|defaulted`, required confidence, and evidence accounting;
  the characterization payload reuses the WI-B `CharacterizationTelemetry` definition by `$ref`, so
  the egress/coverage/substance/evidence closed-pipe rules are the SAME pipe, not a restatement.
- ~~Presentation-only `agent_display_name`~~ **SUPERSEDED — the field was REMOVED on 2026-07-25.**
  The original text argued that being bounded (1–80) and control-character-free meant it could not
  become a free-text egress channel. Terra's review showed that claim was false — 80 printable
  characters carry prose — so the field was deleted rather than re-worded, and
  `additionalProperties: false` now makes it unrepresentable. The request carries no presentation
  string of any kind.
- Structural client-side sharing policy: `sharing_policy.{policy_version, allowlist}`; a value in the
  transmitted area REQUIRES its field on the allowlist (enforced per field), so an off-allowlist
  value is unrepresentable. Empty-allowlist / all-withheld submission is honest and representable.
- `additionalProperties:false` at every boundary; no free-form raw survey/user content; no
  client-asserted tenant/project (tenant/project from auth context — backend obligation).

## Response contract — verified properties

- Versioned `formula_identity` with `assumptions_are_starting_assumptions: const true`.
- Archetype + dominant value channel (vocabulary `$ref`).
- `budget`: recommended daily with archetype floor/cap (`floor_cap_are_starting_assumptions: const
  true`) and a conservative-lower-bound basis (`uses_conservative_lower_bound: const true`, value
  interval carries its `level`).
- `payback`: structured; `payback_days` present ONLY on a positive conservative lower bound and
  forbidden otherwise; explanation is bounded structured render tokens, not free text.
- Closed `stop_rule`; `required_receipt.receipt_kind` reused from the receipt contract by `$ref`.
- `spend_zero_case` REQUIRED with `available: const true` (always present).
- `why`: required, non-empty, bounded array of closed render tokens the agent renders in the user's
  own bands (`references_field` from the vocabulary); NO token can claim assumptions were validated
  (only `assumptions_are_starting_not_validated` exists).
- Independent of credits/incentives/pricing/wallet/billing/WI-D: no such field declared or
  representable; asserted by a property-name scan over both contracts.

## Verification — exact commands + counts

- Focused (new file): `pytest tests/test_economics_recommendation_contract.py` → **47 passed**.
- Focused (new + WI-B economics): `pytest tests/test_economics_recommendation_contract.py
  tests/test_economics_telemetry_contract.py` → **136 passed**.
- Full suite: `pytest tests/ -q` → **1222 passed, 1 skipped, 2 warnings** (the 1 skip + 2
  DeprecationWarnings are pre-existing, in `test_auth_taxonomy_parity.py` /
  `test_best_config_contract_closure.py`, not WI-C).
- Ruff (CI gate): `ruff check traigent_schema/` → **All checks passed**. New test file
  `ruff check tests/test_economics_recommendation_contract.py` → **All checks passed**. (Repo-wide
  `ruff check tests/` shows pre-existing E501/I001 drift in OTHER test files; CI only lints
  `traigent_schema/`, so this is not WI-C and not gated.)
- Mypy (CI gate): `mypy traigent_schema/ --ignore-missing-imports` → **Success: no issues found in
  5 source files** (the `python_version 3.9 not supported` line is a pre-existing config warning,
  not an error; mypy still succeeds).
- Parity / generator: `python3 scripts/refresh_parity.py --update` then `--check` → **[OK] parity
  manifest is up-to-date (files=377)**. (`refresh_parity` is the repo's only manifest generator;
  no separate codegen exists.)
- Local CI gate: `bash scripts/local_gate.sh` (LOCAL_GATE_SKIP=sonar) → **local gate PASSED**
  (ruff ✅, mypy ✅, pytest 1222 passed ✅, parity ✅, auth-taxonomy detector 6 passed/1 skipped
  ✅). Sonar correctly skipped (develop-bound). Spine-trail = non-blocking reminder only (see
  residuals).
- Structural / governance gates specifically re-confirmed green with the new files:
  `test_structural_validity.py` (meta-valid + cross-file `$ref` resolution + version↔CHANGELOG),
  `test_endpoint_catalog_completeness.py`, `test_x_extensions_governance.py` (no new x-* key
  introduced), `test_request_string_maxlength.py` (#138), `test_ci_and_readme_hygiene.py`,
  `test_schemas.py` orphan/count.
- Diff check: `git status --porcelain` / `git diff --stat` → 5 modified tracked files, 9 new
  untracked (2 schemas + 6 fixtures + 1 test). `git rev-parse HEAD` = `c27a034` (no commits made).

## Design decisions (smallest reversible compatible choices — no owner card needed)

- Endpoint name `POST /api/v1/economics/recommendation` (singular resource the POST computes),
  consistent with the sibling `/api/v1/economics/telemetry`.
- Version bumped to a NEW `[4.11.0]` section rather than folding into WI-B's `[4.10.0]`, so the two
  stacked PRs don't produce overlapping edits on the same CHANGELOG lines. Reversible.
- Reused the WI-B `CharacterizationTelemetry` definition (via `$ref`) for the submission's
  characterization intake instead of re-expressing ~25 withholding/coverage/substance/evidence
  conditionals. This maximizes "reference, don't restate", guarantees the submission's closed pipe
  is byte-identical to telemetry's, and keeps `sharing_policy` at the request top level
  (telemetry's object correctly carries neither). SUPERSEDED: this sentence originally also named
  `agent_display_name`, which no longer exists in the contract. Reversible (could be forked into an
  independent definition later without a contract-shape change to callers).

## Residuals / notes for the captain

- Changes are UNCOMMITTED by design; HEAD = `c27a034`. Captain owns commit/push/PR.
- Spine-trail: none on the branch (the local gate flagged it as a non-blocking reminder). Stamp a
  `Spine-Trail:`/`Spine:` line before `gh pr create` per workspace policy; this is a captain action
  at PR time and does not affect the contract.
- Branch is behind `origin/develop` because it is intentionally stacked on the frozen WI-B HEAD
  (contract-first, not yet merged). The local gate's freshness preflight warns but does not fail
  (develop-bound, non-strict). No rebase attempted (would depend on WI-B merge order — captain's
  call).
- Backend obligations (things Draft-07 cannot enforce) are declared as `x-backend-obligations` on
  both schemas and asserted-as-declared by the tests: tenant/project from context, budget
  floor≤recommended≤cap ordering, that the lower-bound/positive-bound booleans reflect real signs,
  no pricing/credit join, evidence-pointer redaction (the pointer narrowing bounds the channel but
  does not seal it), published-reference resolution, and 200/422/503 status selection.
  These transfer to the backend packet.
