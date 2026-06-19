# Local CI gate — catch policy/CI failures before you push

Coding agents (and humans) repeatedly miss a check that is cheap to run locally
and only discover it when the cloud PR goes **red** — a wasted push + a full CI
round-trip per miss. Most of TraigentSchema's CI checks are runnable **locally
in seconds**. This repo ships a single local gate that mirrors them so the
failure is caught before the push.

## TL;DR

```bash
make install-hooks   # once per clone: installs the git pre-push hook
make local-gate      # before every push: run the gate manually (agents: do this)
```

`make local-gate` (a.k.a. `scripts/local_gate.sh`) exits non-zero on anything CI
would reject. Fix what it reports, then push.

## What it runs

| Step | Mirrors cloud check | Notes |
|------|---------------------|-------|
| `ruff check traigent_schema/` | `CI / test` → *Run linting* (`ci.yml`) | The #1 source of avoidable reds. Fix with `ruff check --fix traigent_schema/`. |
| `mypy traigent_schema/ --ignore-missing-imports` | `CI / test` → *Run type checking* (`ci.yml`) | Same flags as CI. |
| `pytest tests/` | `CI / test` → *Run tests* (`ci.yml`) | **The structural / contract gate.** Includes `test_structural_validity.py` plus every per-contract test. DB-free, ~5s. |
| `python3 scripts/refresh_parity.py --check` | `Parity manifest freshness` (`parity-check.yml`) | Fails if schema files changed without re-stamping `parity/python-js-sdk.json`. Fix with `make format` (re-stamp), then commit. |
| spine preflight (reminder) | `spine-trail present` (`spine-trail-gate.yml`) | **Reminder only** — see below. |
| SonarQube quality gate | `SonarQube Quality Gate` (`sonarqube-local.yml`) | **Only for `release/*` / `hotfix/*` branches** (or `LOCAL_GATE_SONAR=1`). Runs `sonar-scanner -Dsonar.qualitygate.wait=true`. |

### Why no `ruff format --check`?

CI (`ci.yml`) runs only `ruff check` (lint), **not** `ruff format --check`, and
the existing tree is not format-clean. Adding a format gate locally would block
your push on pre-existing, unrelated drift — a false blocker. The gate
deliberately mirrors what CI **enforces**, so it does not run `ruff format`.

## The spine rule (trail reminder)

This repo is a pure JSON-Schema / contracts library. It has **no policy-surface
globs file** and **no `require-spine-session` gate** (unlike TraigentBackend), so
the local gate does **not** demand a `Spine-Session`. What CI *does* enforce is
`spine-trail-gate.yml`: every product PR's **body** must carry one of:

```
Spine-Trail: st_xxxxxxxxxxxx     (a Tier-0 WorkIntent)
Spine: cs_xxxxxxxx               (a promoted ChangeSession)
Spine: none (reason: <why>)      (an explicit, owner-visible waiver)
```

That check reads the **PR body**, which doesn't exist before you push, so the
gate surfaces it as a **reminder**. Create a trail *before* `gh pr create`:

```bash
python3 <workspace>/tools/spine-trail/spine_trail.py get-or-create \
  --repo TraigentSchema --branch "$(git branch --show-current)" --base-branch develop \
  --kind <feature|bug_fix|change> --source-type <type> --source-ref "<ref>" \
  --changed-paths "<files>"
# then add its  Spine-Trail: st_xxxx  line to the PR body.
```

If a `require-spine-session` workflow + a `.github/spine-policy-surface-globs.txt`
are ever added here, port TraigentBackend's `scripts/ci/spine_preflight.py` and
wire it into `scripts/local_gate.sh` in place of this reminder.

## SonarQube locally before a main PR

`sonarqube-local.yml` is **REQUIRED on `main`**, optional on `develop`. For
`release/*` / `hotfix/*` branches the gate runs the SonarQube quality gate
locally and **blocks the push if it fails**. Configure once:

```bash
export SONAR_HOST_URL="https://<your-sonarqube>"   # or SonarCloud / http://localhost:9000
export SONAR_TOKEN="<token>"                         # or keep a .env.sonar entry
```

It runs the Dockerized `sonar-scanner` (or a local one) with
`-Dsonar.qualitygate.wait=true` against `Traigent_TraigentSchema`, producing the
same pass/fail verdict the `SonarQube Quality Gate` required check produces on
the PR — before you push. If you don't have SonarQube access, run it another way
or bypass consciously (`git push --no-verify`) and have a reviewer who can run
it.

## Bypassing

`git push --no-verify` skips the pre-push hook (leaves a reflog trail). Use only
when you've verified another way — the gate exists to stop avoidable cloud reds,
not to block you.

## Where this came from

This mirrors the proven local pre-push gate in TraigentBackend
(`scripts/local_gate.sh` + `scripts/ci/spine_preflight.py`, BE PR #1266),
adapted to TraigentSchema's checks: `ruff check` (no format gate), `mypy`, the
`pytest`/parity **structural** gates, a spine-trail **reminder** (no policy
surface here), and the SonarQube quality gate for main-bound branches. Because
this repo has no `.pre-commit-config.yaml`, the hook is a plain `hooks/pre-push`
installed by `make install-hooks` rather than a pre-commit `pre-push` stage.
