# EvidenceCase Schema rebase result

> **Historical snapshot, not current state.** This report describes reachability
> and gate results AS OF this session's own head. The "7 remain unreachable"
> figure below was correct only at that point in the branch's history. Do not
> cite "7" as the present figure; run `python3 scripts/schema_reachability.py
> --check` for the live number. As of this correction, `origin/develop`
> reports 19 unreachable / 386 total, and this branch's own head reports 26
> unreachable / 394 total. The +7 (394 vs 386) is exactly the same seven-schema
> v2 optimization/certificate family this report already names
> (best_config_hash_contract_schema.json,
> guarantee_certificate_statistical_body_schema.json,
> guarantee_certificate_v2_delta_schema.json, guarantee_certificate_v2_schema.json,
> best_config_manifest_v2_schema.json, best_config_v2_schema.json,
> certificate_subject_schema.json), which are intentionally not yet wired into
> any endpoint catalog or `$ref` graph and so score unreachable on rules 1/2.
> The PRE-EXISTING unreachable count of 19 is itself unaffected by that
> family -- it is 19 on `origin/develop` and still 19 on this branch, with or
> without the seven new v2 schemas. The TOTAL rising to 26 is caused
> precisely by those seven schemas being intentionally unrooted; the two
> effects are separate, not in tension. Why the pre-existing 19 remain
> unresolved (rather than shrinking) is itself a separate, stale-snapshot
> issue: `reports/schema_reachability/consumer_references.json` -- the
> committed snapshot rule 3 reads -- currently records 34 basenames as
> consumer-referenced, both at base and on this branch (it was not touched by
> this branch). A fresh scan of the five live consumer-repo checkouts records
> 53, which would rescue exactly the pre-existing 19 (both at base and on
> this branch) and leave only the 7 v2-family schemas above as genuinely
> unrooted. That refresh has deliberately not been performed here -- it is a
> separate, cross-repo-verified, sha-pinned manual operation
> (`scripts/refresh_consumer_schema_references.py`), out of scope for this
> patch -- so the 19 pre-existing entries remain committed as unreachable,
> unchanged from `origin/develop`, and are not a regression this branch
> introduced. EvidenceCase itself (`evidence_case_schema.json`) is rooted via
> `shadow_evaluate_response_schema.json` and is not part of either unreachable
> set.

## Scope and result

This branch integrated current `origin/develop` (`e9a28cb5a74ad40ed141996ff6b74f96142494bb`)
into the EvidenceCase Schema candidate.  The previous common base was
`f30f53c4d7323816e339b069388e1d73707fe455`; the pre-integration EvidenceCase
head was `e120c6f038b2b7a31b254d9474c53667a035d55d`.

The integration commit is:

```text
6671b40c17bb1324b6020ea14e96f0a7f6f22696
merge(schema): integrate develop contract gates into EvidenceCase
```

It preserves the existing Spine-Trail claim: `st_21bd5a6dad95`.

## Merge and generated artifacts

The only merge conflict was `parity/python-js-sdk.json`.  It was not resolved
by selecting either side: after temporarily supplying the existing manifest
metadata to make the JSON parseable, this combined-tree command regenerated
the derived stamp:

```bash
python3 scripts/refresh_parity.py --update
```

Result: `schemaFileCount=394`,
`lastSchemaFileSha=4d835aa8d0c93286d192ab81c7f4231a65dd07d9798c2e9b4a1d0c5b492fd38b`.

Consumer references were refreshed from clean archives of each sibling's
current `origin/develop` ref, then the reachability report was regenerated:

```bash
for repo in Traigent TraigentBackend TraigentFrontend traigent-js traigent-smartopt; do
  git -C /home/nimrod/TraigentProjects/$repo fetch origin develop
done
python3 scripts/refresh_consumer_schema_references.py \
  --repo Traigent=/home/nimrod/TraigentProjects/Traigent \
  --repo TraigentBackend=/home/nimrod/TraigentProjects/TraigentBackend \
  --repo TraigentFrontend=/home/nimrod/TraigentProjects/TraigentFrontend \
  --repo traigent-js=/home/nimrod/TraigentProjects/traigent-js \
  --repo traigent-smartopt=/home/nimrod/TraigentProjects/traigent-smartopt
python3 scripts/schema_reachability.py --update
python3 scripts/schema_reachability.py --check
```

Result AT THIS SESSION'S HEAD (see the historical-snapshot note above for the
current figure): 394 schemas total; 334 are reached by schema/endpoint graph,
53 by the consumer-reference snapshot, 0 by allowlist, and 7 remain
unreachable. Those seven are intentionally left visible and unallowlisted:

```text
optimization/best_config_hash_contract_schema.json
optimization/best_config_manifest_v2_schema.json
optimization/best_config_v2_schema.json
optimization/certificate_subject_schema.json
optimization/guarantee_certificate_statistical_body_schema.json
optimization/guarantee_certificate_v2_delta_schema.json
optimization/guarantee_certificate_v2_schema.json
```

They are the not-yet-rooted v2 optimization/certificate family.  An allowlist
would hide the missing consumer/endpoint integration rather than resolve it.
The new develop gate is deliberately non-blocking while the repository carries
such a backlog, so its passing freshness check is not a claim that the seven
schemas are usable yet.

## Compatibility and validation

The new breaking-contract gate was run with the correct develop PR semantics,
not against the branch's old base:

```bash
.venv/bin/python scripts/breaking_schema_check.py --check \
  --base-ref origin/develop --head-ref HEAD \
  --json /tmp/evidence-case-breaking-schema-check.json
```

Result at `HEAD=94d2bf1dca20d8d1ba9e0ed981563833cef1cf5f`: 9 changed
schema files, 10 findings — 9 informational and **1 acknowledged breaking
finding**, with **0 unacknowledged breaking findings**.  Eight EvidenceCase/v2
schemas are new files.  The changed existing
`smartops_v2/shadow_evaluate_response_schema.json` adds required
`evidence_case` while the old response contract was closed with
`additionalProperties: false`.  That property addition is correctly classified
as response-breaking because an old strict consumer can reject the newly
emitted member; adding it to `required` is a separate informational finding on
the response side.

The allowlist acknowledgement is scoped to
`#/properties/evidence_case` and records the coordinated-rollout condition:
pinning TraigentBackend to this Schema revision before planner emission is a
necessary prerequisite, but rollout remains blocked until every strict or
generated response consumer is reconciled with `evidence_case`.  The
acknowledgement makes the intended break explicit; it does not claim that the
response addition is backwards-compatible or waive any consumer-reconciliation
requirement.

Combined-tree verification:

```bash
PATH="$PWD/.venv/bin:$PATH" pytest tests/ -q -p no:cacheprovider
PATH="$PWD/.venv/bin:$PATH" ruff check traigent_schema/
PATH="$PWD/.venv/bin:$PATH" mypy traigent_schema/ --ignore-missing-imports
.venv/bin/python -m pytest tests/test_breaking_schema_check.py -q
.venv/bin/python scripts/refresh_parity.py --check
.venv/bin/python scripts/schema_reachability.py --check
PATH="$PWD/.venv/bin:$PATH" pytest \
  tests/test_validator.py tests/test_analytics_schemas.py \
  tests/test_evidence_case_contract.py -q -p no:cacheprovider
```

Results:

* full suite: **1766 passed, 1 skipped** (4 pre-existing `RefResolver`
  deprecation warnings), Python 3.13.14;
* breaking-gate regression suite: **56 passed**;
* ruff: passed;
* mypy: passed (with the repository's existing Python-3.9 configuration
  warning);
* parity: passed; reachability freshness: passed;
* focused validator + analytics + EvidenceCase suite: **133 passed**.

## What develop added, and its effect on EvidenceCase

`origin/develop` adds three useful guardrails:

1. An unknown endpoint can no longer silently look valid. `SchemaValidator`
   now defaults to `warn`, returning an `UNVALIDATED_ENDPOINT` signal; callers
   must explicitly request `allow` for the old behavior or `strict` to raise.
   EvidenceCase validation uses named-schema `validate_json`, not endpoint
   lookup, so this does not change its contract or its current tests.
2. Analytics advice retires the subtractive `remove_redundant` vocabulary at
   the client boundary. It does not alter EvidenceCase fields. It is aligned
   with EvidenceCase's measured-vs-supported discipline, but the free-text
   analytics action remains a producer-side policy rather than a fully
   schema-enforced rule.
3. Schema changes now acquire two checks: a PR-relative breaking-change gate
   and a committed cross-repo reachability snapshot. EvidenceCase passes the
   former with one explicit, versioned acknowledgement for its closed-response
   expansion—not by classifying the expansion as compatible. The latter
   correctly exposes the unrooted v2 schemas above.

## Residual risks and PR readiness

* The v2 optimization/certificate schemas are not currently rooted by an
  endpoint or present in the five consumers' current develop snapshots. They
  must become reachable through subsequent consumer/endpoint work before they
  can support a production feature claim.
* Python SDK reconciliation is still required for G4.  Current SDK `develop`
  contains a generated `ShadowEvaluateResponseSchema` without the required
  `evidence_case` member.  Running its generator check against this exact
  Schema worktree fails and shows the missing field in the generated diff:

  ```bash
  TRAIGENT_SCHEMA_REPO="$PWD" \
    /home/nimrod/TraigentProjects/Traigent/.venv/bin/python \
    /home/nimrod/TraigentProjects/core_project/develop/Traigent/scripts/generate_schema_types.py \
    --check
  ```

  The EvidenceCase SDK candidate at
  `ea8b7d5eb7690e0a6a0b0eaf5222984667d6eed4` is six commits behind current
  SDK `origin/develop` and predates the committed generated-type gate entirely.
  G4 therefore requires integrating current SDK develop, regenerating against
  the final Schema SHA, committing the generated output, and passing the
  generated-type drift check.  The Backend pin alone does not clear this
  strict/generated-consumer requirement.
* The local run used Python 3.13.14 whereas the new hosted breaking-check
  workflow pins Python 3.12; hosted CI remains the release authority.
* `origin/main` was 17 commits ahead of this develop-bound candidate during
  the local gate. That is expected for a develop-targeted integration, not a
  main-readiness assertion.

**PR-ready: yes for this scoped Schema integration** (clean merge, combined
tree gates passing, and no hidden reachability allowlist).  This does not
clear the wider multi-repo EvidenceCase G4 gate, and no branch was pushed or
PR opened/updated by this work.
