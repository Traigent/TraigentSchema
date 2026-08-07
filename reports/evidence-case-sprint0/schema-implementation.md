# Evidence-case Sprint 0 — Schema implementation

> **Historical snapshot.** "Explicit exclusions and gaps" below records what
> was NOT yet done as of this session's own head. The unsafe-integral-float
> gap it names was closed in a later session on this same branch:
> `traigent_schema/best_config_profile.py` now implements exactly that policy
> (rejecting an unsafe integral VALUE across both int and float, before fp2
> ever runs, via an iterative, cycle/depth-bounded prevalidation pass) — see
> `tests/test_best_config_profile.py`. Do not read "no fp2 change or
> unsafe-integral-float policy was implemented" as a statement about the
> current codebase.

## Execution identity

- Requested worker model/effort: `gpt-5.6-terra` / `high`.
- Actual observable runtime: Codex worker; this session exposes no model or reasoning-effort telemetry beyond the task request, so the requested model/effort cannot be independently verified here.
- Repair-pass telemetry: no new model/effort override was exposed; the repair continued under the original `gpt-5.6-terra` / `high` request, with the same observable limitation above.
- Starting SHA: `8d97ad5ba896e949d27f8c1924fe6916289e1521`.
- Starting branch: `feature/evidence-case-hash-v2-integration-20260807`.

## Implemented contract delta

- Added `guarantee_certificate_statistical_body_schema.json`, the reusable unchanged statistical body.
- Added the closed, composed reader-only `guarantee_certificate_v2_schema.json`; it composes that body with the pre-existing v2 binding delta and rejects unknown top-level properties under Draft-07.
- Tightened `guarantee_certificate_v2_delta_schema.json` to reject top-level v1 binding members `spec_hash`, `config_hash`, and `config_id` even for direct consumers of the delta.
- Added the internal/shadow-only Planner V2 `evidence_case_schema.json`, with deterministic evidence/provenance fields and the derived `OBSERVED_ONLY | SUPPORTED_RECOMMENDATION` publication basis. `SUPPORTED_RECOMMENDATION` requires both certified and policy-eligible evidence.
- Architecture repair: EvidenceCase provenance now requires exact lowercase 64-hex `data_layer_hash` and `data_version_hash` pins, so a projection cannot omit the data layer or its version identity.
- Required the EvidenceCase in `shadow_evaluate_response_schema.json`; updated its existing focused fixture.
- Added executable positive and negative contract coverage in `tests/test_evidence_case_contract.py`.
- Re-stamped `parity/python-js-sdk.json` via the repository script.

## Verification

1. `uv run --with pytest pytest tests/test_structural_validity.py -q`
   - PASS: 3 passed. This initial command updated `uv.lock`; that worker-caused dependency drift was restored before the final checks and is not part of this change.
2. `uv run --frozen --with pytest pytest tests/test_evidence_case_contract.py tests/test_smartops_v2_contracts.py tests/test_guaranteed_modes_schemas.py tests/test_best_config_hash_contract.py tests/test_best_config_hash_contract_envelopes.py tests/test_structural_validity.py -q`
   - PASS: 65 passed; 2 existing `jsonschema.RefResolver` deprecation warnings.
3. `uv run --frozen --with ruff ruff check traigent_schema tests/test_evidence_case_contract.py tests/test_smartops_v2_contracts.py`
   - PASS.
4. `python3 scripts/refresh_parity.py --update && python3 scripts/refresh_parity.py --check`
   - PASS: schema digest `725413bca38369b55da756bf1632ef4f458837eb47987cfe326aff4eb291c2e3`, 394 schema files.
5. `git diff --check`
   - PASS.

### Architecture repair verification from clean HEAD `62e4db84be17ff77a7be68b8b3e38af54cfe66b4`

1. `uv run --frozen --with pytest pytest tests/test_evidence_case_contract.py tests/test_smartops_v2_contracts.py -q`
   - PASS: 27 passed, including missing and malformed negative controls for each required data pin.
2. `python3 scripts/refresh_parity.py --update && python3 scripts/refresh_parity.py --check`
   - PASS: schema digest `ee03842d90b506b8c19ee0607209c49a2a4df61d2a49a8686e11668fd3f76da9`, 394 schema files.
3. `uv run --frozen --with pytest pytest tests/test_evidence_case_contract.py tests/test_smartops_v2_contracts.py tests/test_guaranteed_modes_schemas.py tests/test_best_config_hash_contract.py tests/test_best_config_hash_contract_envelopes.py tests/test_structural_validity.py -q`
   - PASS: 69 passed; 2 existing `jsonschema.RefResolver` deprecation warnings.
4. `uv run --frozen --with ruff ruff check traigent_schema tests/test_evidence_case_contract.py tests/test_smartops_v2_contracts.py`
   - PASS.
5. `git diff --check`
   - PASS.

## Assumptions

- V2 is an envelope/certificate version; its `subject.hash_algorithm` remains the existing supported value `v1`, because the pinned domain tags end in `.v1`.
- `lifecycle_revision` is a non-negative integer, matching Planner V2/Backend lifecycle revision semantics.
- The complete v2 body legitimately retains stable statistical/evidence fields, while binding is exclusively the required v2 `subject` plus the existing runtime and price freshness hooks.

## Explicit exclusions and gaps

- No v2 certificate issuer was added; the new schema is reader-only.
- No public best-config publish/request/response issuance surface changed.
- No fp2 change or unsafe-integral-float policy was implemented; that gap remained
  explicit AS OF THIS SESSION'S HEAD (see the historical-snapshot note above: a later
  session closed it in traigent_schema/best_config_profile.py).
- No JavaScript reader parity was implemented; it remains a post-Sprint-0 gap.
- EvidenceCase is internal/shadow-only and does not authorize publishing, execution, persistence, signatures, or live-key material.

## Commit

Final implementation commit SHA: `f5e3d5dc445940c4f20d10edabb7ea9a050286ff`.

This report is committed separately because a Git commit cannot contain its own final object ID; the worktree HEAD after the companion report commit is reported in the handoff.
