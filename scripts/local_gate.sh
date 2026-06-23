#!/usr/bin/env bash
#
# local_gate.sh — run the locally-checkable CI/policy gates BEFORE pushing.
#
# Why: coding agents (and humans) routinely miss a check that is cheap to run
# locally and only find out when the cloud PR goes red — a ruff/lint red, an
# mypy red, a stale structural/parity gate, the spine-trail gate, or SonarQube.
# This mirrors those gates locally so the failure is caught in seconds, not
# after a push + a full CI round-trip.
#
# Runs (fast → slow), mirroring .github/workflows/*:
#   0. freshness preflight   (origin/develop + origin/main)
#   1. ruff check            (CI: ci.yml "Run linting")
#   2. mypy                  (CI: ci.yml "Run type checking")
#   3. pytest (structural)   (CI: ci.yml "Run tests" — incl. structural_validity)
#   4. parity --check        (CI: parity-check.yml — schema manifest freshness)
#   5. spine preflight       (CI: spine-trail-gate.yml — trail reminder)
#   6. SonarQube quality gate (CI: sonarqube-local.yml — main-bound branches only)
#
# Usage:
#   scripts/local_gate.sh            # auto: 1-5 always; sonar if main-bound
#   LOCAL_GATE_SONAR=1 scripts/local_gate.sh      # force the sonar step
#   LOCAL_GATE_SKIP=sonar scripts/local_gate.sh          # skip optional named steps
#   LOCAL_GATE_STRICT_FRESHNESS=1 scripts/local_gate.sh   # fail on any remote drift
# It is also installed as a git pre-push hook (see `make install-hooks`).
#
# This repo is a pure JSON-Schema / contracts library: there is NO policy-surface
# globs file and NO require-spine-session workflow, so the spine step is a
# trail REMINDER only (the authoritative spine-trail check reads the PR body in
# CI). If a require-spine-session gate is ever added, port BE's
# scripts/ci/spine_preflight.py and wire it in here.
#
# SonarQube: REQUIRED on main, optional on develop (see sonarqube-local.yml).
#   The gate runs it only for main-bound branches (release/*, hotfix/*, or a PR
#   whose base is main) or when LOCAL_GATE_SONAR=1. Set SONAR_HOST_URL +
#   SONAR_TOKEN (the in-cluster/self-hosted SonarQube, or SonarCloud), or keep a
#   .env.sonar entry. Needs Docker (or a local sonar-scanner). Runs with
#   -Dsonar.qualitygate.wait=true so a failing gate fails the push.
#
# Bypass (discouraged, leaves a paper trail in reflog): git push --no-verify
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
BRANCH="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)"
FAIL=0
skip() { [[ ",${LOCAL_GATE_SKIP:-}," == *",$1,"* ]]; }

hr() { printf '─%.0s' {1..64}; echo; }
section() { hr; echo "▶ $1"; }

# release/hotfix branches target main; everything else targets develop.
base_branch="develop"; [[ "$BRANCH" =~ ^(release|hotfix)/ ]] && base_branch="main"
base_ref="origin/$base_branch"

MAIN_BOUND=0
[[ "$BRANCH" =~ ^(release|hotfix)/ ]] && MAIN_BOUND=1
[[ "${LOCAL_GATE_SONAR:-0}" == "1" ]] && MAIN_BOUND=1

freshness_preflight() {
  section "remote freshness preflight (origin/develop + origin/main)"
  local rc=0 strict=0 ref sha counts ahead behind
  [[ "$MAIN_BOUND" == "1" || "${LOCAL_GATE_STRICT_FRESHNESS:-0}" == "1" ]] && strict=1

  echo "  • branch=${BRANCH}; base=${base_branch}; strict_freshness=${strict}"
  for remote_branch in develop main; do
    ref="origin/${remote_branch}"
    if ! git rev-parse --verify --quiet "$ref" >/dev/null; then
      if [[ "$ref" == "$base_ref" || "$strict" == "1" ]]; then
        echo "  ❌ required remote ref $ref is missing; fetch origin before trusting local gates"
        rc=1
      else
        echo "  ⚠️  remote ref $ref is missing; not used for this ${base_branch}-bound gate"
      fi
      continue
    fi

    sha="$(git rev-parse --short=12 "$ref")"
    if counts="$(git rev-list --left-right --count "HEAD...$ref" 2>/dev/null)"; then
      read -r ahead behind <<< "$counts"
      echo "  • $ref@$sha (HEAD ahead $ahead / behind $behind)"
      if [[ "$behind" =~ ^[0-9]+$ && "$behind" -gt 0 ]]; then
        if [[ "$strict" == "1" ]] || { [[ "$ref" == "origin/main" ]] && [[ "$MAIN_BOUND" == "1" ]]; }; then
          echo "    ❌ HEAD is behind $ref; refresh/rebase before a main-bound gate"
          rc=1
        else
          echo "    ⚠️  HEAD is behind $ref; develop-bound local results may differ from hosted CI"
        fi
      fi
    else
      if [[ "$strict" == "1" || "$ref" == "$base_ref" ]]; then
        echo "  ❌ unable to compare HEAD with $ref; local gate freshness is untrusted"
        rc=1
      else
        echo "  ⚠️  unable to compare HEAD with $ref"
      fi
    fi
  done

  return "$rc"
}

if ! freshness_preflight; then FAIL=1; fi

for required_step in ruff mypy pytest; do
  if skip "$required_step"; then
    hr
    echo "❌ LOCAL_GATE_SKIP cannot skip required CI mirror step: $required_step"
    echo "   Run the tool directly for partial checks; the Schema local gate must mirror CI."
    FAIL=1
  fi
done

# ── 1. ruff check (lint) ──────────────────────────────────────────────────
# Mirrors ci.yml exactly: `ruff check traigent_schema/`. NOTE: CI does NOT run
# `ruff format --check`, and the tree is not format-clean, so we deliberately do
# not add a format gate here (it would block on pre-existing, unrelated drift).
if ! skip ruff; then
  section "ruff check (ci.yml: Run linting)"
  if command -v ruff >/dev/null 2>&1; then
    if ruff check traigent_schema/; then echo "  ✅ ruff check clean"
    else echo "  ❌ ruff check found issues — run 'ruff check --fix traigent_schema/'"; FAIL=1; fi
  else
    echo "  ❌ ruff not installed (pip install -e '.[dev]'); required because this gate mirrors CI"
    FAIL=1
  fi
fi

# ── 2. mypy (type check) ──────────────────────────────────────────────────
if ! skip mypy; then
  section "mypy (ci.yml: Run type checking)"
  if command -v mypy >/dev/null 2>&1; then
    if mypy traigent_schema/ --ignore-missing-imports; then echo "  ✅ mypy clean"
    else echo "  ❌ mypy found issues — fix the types above"; FAIL=1; fi
  else
    echo "  ❌ mypy not installed (pip install -e '.[dev]'); required because this gate mirrors CI"
    FAIL=1
  fi
fi

# ── 3. pytest — the structural / contract gate ────────────────────────────
# The schema-integrity gate IS the pytest suite (test_structural_validity.py +
# the per-contract tests). It is DB-free and runs in seconds, so it belongs in
# the local gate.
if ! skip pytest; then
  section "pytest — structural + contract gate (ci.yml: Run tests)"
  if command -v pytest >/dev/null 2>&1; then
    if pytest tests/ -q -p no:cacheprovider; then echo "  ✅ pytest clean"
    else echo "  ❌ pytest failed — fix the contract/structural breakage above"; FAIL=1; fi
  else
    echo "  ❌ pytest not installed (pip install -e '.[dev]'); required because this gate mirrors CI"
    FAIL=1
  fi
fi

# ── 4. parity manifest freshness ──────────────────────────────────────────
# Mirrors parity-check.yml. Fails if schema files changed without re-stamping
# parity/python-js-sdk.json. Only meaningful when scripts/refresh_parity.py and
# the schema tree are present.
if ! skip parity; then
  section "parity manifest freshness (parity-check.yml)"
  if [[ -f scripts/refresh_parity.py ]]; then
    if python3 scripts/refresh_parity.py --check; then echo "  ✅ parity manifest up-to-date"
    else echo "  ❌ parity manifest stale — run 'python3 scripts/refresh_parity.py --update' and commit"; FAIL=1; fi
  else
    echo "  ℹ️  scripts/refresh_parity.py absent; skipping parity check"
  fi
fi

# ── 4b. auth-taxonomy parity detector (NON-BLOCKING) ──────────────────────
# Mirrors auth-taxonomy-parity.yml (Schema#219). This is a DETECTOR that makes
# cross-repo auth-taxonomy drift visible; it is intentionally NON-BLOCKING here
# exactly as in CI (continue-on-error). It never sets FAIL — a red is surfaced
# as a warning only. DETECT->ENFORCE (SCHEMA_219_ENFORCE) is a later issue.
if ! skip authparity; then
  section "auth-taxonomy parity detector (auth-taxonomy-parity.yml — NON-BLOCKING)"
  if command -v pytest >/dev/null 2>&1 && [[ -f tests/test_auth_taxonomy_parity.py ]]; then
    if pytest tests/test_auth_taxonomy_parity.py -q -p no:cacheprovider; then
      echo "  ✅ auth-taxonomy parity detector clean (all drift covered by the allowlist)"
    else
      echo "  ⚠️  auth-taxonomy drift not covered by the allowlist (or a stale row)."
      echo "      NON-BLOCKING (Schema#219 DETECT phase). Refresh"
      echo "      tests/data/auth_taxonomy_surfaces.json + reconcile"
      echo "      tests/data/auth_taxonomy_known_drift.yaml (shrink-only)."
    fi
  else
    echo "  ℹ️  detector/test absent or pytest missing; skipping"
  fi
fi

# ── 5. spine preflight (trail reminder) ───────────────────────────────────
# This repo has no policy-surface globs / require-spine-session gate, so this is
# a REMINDER, not a blocker: CI's spine-trail-gate.yml checks the PR BODY for a
# Spine-Trail:/Spine: line, which doesn't exist pre-push. Surface it so the
# branch gets a trail before `gh pr create`.
if ! skip spine; then
  section "spine preflight (spine-trail-gate.yml — reminder)"
  range="HEAD"; git rev-parse --verify --quiet "$base_ref" >/dev/null && range="${base_ref}..HEAD"
  if git log "$range" --format=%B 2>/dev/null | grep -Eqi '^[[:space:]]*Spine-Trail:[[:space:]]*st_[0-9a-f]{12}' \
     || git log "$range" --format=%B 2>/dev/null | grep -Eqi '^[[:space:]]*Spine:[[:space:]]*(cs_[0-9a-z]{6,}|none[[:space:]]*\(reason:)'; then
    echo "  ✅ a Spine-Trail/Spine mark is present in this branch's commits"
  else
    echo "  ⚠️  no Spine-Trail detected on this branch (CI's spine-trail-gate reads the PR BODY)."
    echo "      Create one BEFORE 'gh pr create', then add its line to the PR body:"
    echo "        python3 <workspace>/tools/spine-trail/spine_trail.py get-or-create \\"
    echo "          --repo TraigentSchema --branch ${BRANCH} --base-branch ${base_branch} \\"
    echo "          --kind <feature|bug_fix|change> --source-type <type> \\"
    echo "          --source-ref \"<ref>\" --changed-paths \"<files>\""
    echo "      Accepted PR-body markers: 'Spine-Trail: st_…', 'Spine: cs_…', 'Spine: none (reason: …)'."
  fi
fi

# ── 6. SonarQube quality gate (main-bound only) ───────────────────────────
# sonarqube-local.yml is REQUIRED on main, optional on develop. Run it locally
# only for main-bound work so develop pushes stay fast.
if [[ "$MAIN_BOUND" == "1" ]] && ! skip sonar; then
  section "SonarQube quality gate (main-bound: $BRANCH)"
  have_creds=0
  { [[ -n "${SONAR_TOKEN:-}" ]] || [[ -f .env.sonar ]]; } && have_creds=1
  if [[ "$have_creds" == "0" ]]; then
    echo "  ❌ main-bound push requires the SonarQube gate, but no SONAR_TOKEN/.env.sonar found."
    echo "     Set SONAR_HOST_URL + SONAR_TOKEN (self-hosted SonarQube or SonarCloud) and re-run,"
    echo "     or run the scan another way, then push. (bypass: git push --no-verify)"
    FAIL=1
  elif ! command -v docker >/dev/null 2>&1 && ! command -v sonar-scanner >/dev/null 2>&1; then
    echo "  ❌ need Docker or sonar-scanner for the local SonarQube gate (main-bound)."
    FAIL=1
  else
    host="${SONAR_HOST_URL:-http://localhost:9000}"
    echo "  🔎 scanning against $host with qualitygate.wait=true …"
    # Produce coverage so the gate's new-code conditions can evaluate it.
    if command -v pytest >/dev/null 2>&1; then
      pytest tests/ -q -p no:cacheprovider \
        --cov=traigent_schema --cov-report=xml:coverage.xml >/dev/null 2>&1 || true
    fi
    rc=0
    if command -v docker >/dev/null 2>&1; then
      net=""; [[ "$host" == *localhost* || "$host" == *127.0.0.1* ]] && net="--network=host"
      docker run --rm $net -e SONAR_HOST_URL="$host" -e SONAR_TOKEN \
        -v "$PWD":/usr/src sonarsource/sonar-scanner-cli:latest \
        -Dsonar.projectKey=Traigent_TraigentSchema \
        -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300 || rc=$?
    else
      sonar-scanner -Dsonar.host.url="$host" \
        -Dsonar.projectKey=Traigent_TraigentSchema \
        -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300 || rc=$?
    fi
    if [[ $rc -eq 0 ]]; then echo "  ✅ SonarQube quality gate passed"
    else echo "  ❌ SonarQube quality gate FAILED — fix locally before the main PR"; FAIL=1; fi
  fi
else
  hr; echo "ℹ️  SonarQube step skipped (not a release/hotfix branch). For main-bound"
  echo "   work set LOCAL_GATE_SONAR=1 or push a release/* branch."
fi

hr
if [[ "$FAIL" == "0" ]]; then
  echo "✅ local gate PASSED — safe to push"
else
  echo "❌ local gate FAILED — fix the items above (or 'git push --no-verify' to bypass)"
fi
exit "$FAIL"
