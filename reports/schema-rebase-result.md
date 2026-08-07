# EvidenceCase Schema rebase result

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

Result: 394 schemas total; 334 are reached by schema/endpoint graph, 53 by
the consumer-reference snapshot, 0 by allowlist, and 7 remain unreachable.
Those seven are intentionally left visible and unallowlisted:

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

Result: 9 changed schema files, 10 informational findings, **0 unacknowledged
breaking findings**.  Eight EvidenceCase/v2 schemas are new files.  The only
changed existing response schema adds required `evidence_case`; the gate treats
that as response-side informational rather than request compatibility breakage.

Combined-tree verification:

```bash
PATH="$PWD/.venv/bin:$PATH" pytest tests/ -q -p no:cacheprovider
PATH="$PWD/.venv/bin:$PATH" ruff check traigent_schema/
PATH="$PWD/.venv/bin:$PATH" mypy traigent_schema/ --ignore-missing-imports
.venv/bin/python scripts/refresh_parity.py --check
.venv/bin/python scripts/schema_reachability.py --check
PATH="$PWD/.venv/bin:$PATH" pytest \
  tests/test_validator.py tests/test_analytics_schemas.py \
  tests/test_evidence_case_contract.py -q -p no:cacheprovider
```

Results:

* full suite: **1736 passed, 1 skipped** (4 pre-existing `RefResolver`
  deprecation warnings), Python 3.13.14;
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
   former; the latter correctly exposes the unrooted v2 schemas above.

## Residual risks and PR readiness

* The v2 optimization/certificate schemas are not currently rooted by an
  endpoint or present in the five consumers' current develop snapshots. They
  must become reachable through subsequent consumer/endpoint work before they
  can support a production feature claim.
* The local run used Python 3.13.14 whereas the new hosted breaking-check
  workflow pins Python 3.12; hosted CI remains the release authority.
* `origin/main` was 17 commits ahead of this develop-bound candidate during
  the local gate. That is expected for a develop-targeted integration, not a
  main-readiness assertion.

**PR-ready: yes for this scoped Schema integration** (clean merge, combined
tree gates passing, and no hidden reachability allowlist).  This does not
clear the wider multi-repo EvidenceCase G4 gate, and no branch was pushed or
PR opened/updated by this work.
