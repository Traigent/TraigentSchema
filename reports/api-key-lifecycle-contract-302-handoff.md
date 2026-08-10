# API-key lifecycle contract #302 handoff

## Scope delivered

- Catalogued public API-key create, list, update, revoke, rotate, suspend,
  reactivate, and validate paths in `auth/keys_endpoints.json`.
- Added strict rotate request and successful rotate-response contracts.  The
  rotate strategy defaults to `immediate`; `data.new_key` is marked secret and
  one-time.
- Added action, update, validation, create-response, detail, and list-response
  schemas.  List filters match the live route names and defaults.
- Corrected the pre-existing create wire model to use live field names:
  `key_name`, `expires_in_days`, `rotation_enabled`,
  `rotation_interval_days`, and `auto_rotate`; corrected the create secret
  field from the stale `create_secret` to live `data.key`.
- Added lifecycle contract regressions to
  `tests/test_admin_onboarding_contract.py` and restamped the parity manifest.
- Catalogued GET `/api/v1/keys/{key_id}` and its optional management-visible
  fields.  The list `scope` default is explicitly `user`.
- The suspend and validation body schemas remain permissive for extra fields,
  matching the current routes' documented-field parsing.  Rotate and update
  retain their live strict request validation.

## Deliberate boundaries

This is Schema-only.  It does not change Backend or Frontend behavior, add a
workflow, or describe implementation details.  Existing Backend routes are the
source for names, enumerations, and defaults.

## Verification

- `uv run --extra dev python -m pytest tests/test_admin_onboarding_contract.py -q -p no:cacheprovider`
  — 32 passed.  The table-driven matrix covers every catalogued lifecycle
  method, concrete success response schema, and all exposed defaults.
- `uv run --extra dev ruff check traigent_schema tests/test_admin_onboarding_contract.py`
  — passed.
- `uv run --extra dev python scripts/refresh_parity.py --check` — passed after
  the manifest refresh.
- `uv lock --check` — passed.
- Targeted `SchemaValidator` checks for concrete rotate endpoint resolution and
  successful rotate-response validation — passed.
- The full `tests/` suite was launched and ran beyond the early modules; the
  execution wrapper detached before recording its final exit code.  It is not
  claimed as passing evidence.
