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
#   LOCAL_GATE_SKIP=pytest,sonar scripts/local_gate.sh   # skip named steps
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
    echo "  ⚠️  ruff not installed (pip install -e '.[dev]'); skipping — CI will still run it"
  fi
fi

# ── 2. mypy (type check) ──────────────────────────────────────────────────
if ! skip mypy; then
  section "mypy (ci.yml: Run type checking)"
  if command -v mypy >/dev/null 2>&1; then
    if mypy traigent_schema/ --ignore-missing-imports; then echo "  ✅ mypy clean"
    else echo "  ❌ mypy found issues — fix the types above"; FAIL=1; fi
  else
    echo "  ⚠️  mypy not installed (pip install -e '.[dev]'); skipping — CI will still run it"
  fi
fi

# ── 3. pytest — the structural / contract gate ────────────────────────────
# The schema-integrity gate IS the pytest suite (test_structural_validity.py +
# the per-contract tests). It is DB-free and runs in seconds, so it belongs in
# the local gate. Skippable with LOCAL_GATE_SKIP=pytest for a lint-only pass.
if ! skip pytest; then
  section "pytest — structural + contract gate (ci.yml: Run tests)"
  if command -v pytest >/dev/null 2>&1; then
    if pytest tests/ -q -p no:cacheprovider; then echo "  ✅ pytest clean"
    else echo "  ❌ pytest failed — fix the contract/structural breakage above"; FAIL=1; fi
  else
    echo "  ⚠️  pytest not installed (pip install -e '.[dev]'); skipping — CI will still run it"
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

# ── 5. spine preflight (trail reminder) ───────────────────────────────────
# This repo has no policy-surface globs / require-spine-session gate, so this is
# a REMINDER, not a blocker: CI's spine-trail-gate.yml checks the PR BODY for a
# Spine-Trail:/Spine: line, which doesn't exist pre-push. Surface it so the
# branch gets a trail before `gh pr create`.
if ! skip spine; then
  section "spine preflight (spine-trail-gate.yml — reminder)"
  base="develop"; [[ "$BRANCH" =~ ^(release|hotfix)/ ]] && base="main"
  # Prefer the remote-tracking ref; fall back to a local ref of the same name.
  base_ref=""
  for ref in "origin/${base}" "${base}"; do
    git rev-parse --verify --quiet "$ref" >/dev/null && { base_ref="$ref"; break; }
  done
  range="HEAD"; [[ -n "$base_ref" ]] && range="${base_ref}..HEAD"
  if git log "$range" --format=%B 2>/dev/null | grep -Eqi '^[[:space:]]*Spine-Trail:[[:space:]]*st_[0-9a-f]{12}' \
     || git log "$range" --format=%B 2>/dev/null | grep -Eqi '^[[:space:]]*Spine:[[:space:]]*(cs_[0-9a-z]{6,}|none[[:space:]]*\(reason:)'; then
    echo "  ✅ a Spine-Trail/Spine mark is present in this branch's commits"
  else
    echo "  ⚠️  no Spine-Trail detected on this branch (CI's spine-trail-gate reads the PR BODY)."
    echo "      Create one BEFORE 'gh pr create', then add its line to the PR body:"
    echo "        python3 <workspace>/tools/spine-trail/spine_trail.py get-or-create \\"
    echo "          --repo TraigentSchema --branch ${BRANCH} --base-branch ${base} \\"
    echo "          --kind <feature|bug_fix|change> --source-type <type> \\"
    echo "          --source-ref \"<ref>\" --changed-paths \"<files>\""
    echo "      Accepted PR-body markers: 'Spine-Trail: st_…', 'Spine: cs_…', 'Spine: none (reason: …)'."
  fi
fi

# ── 6. SonarQube quality gate (main-bound only) ───────────────────────────
# sonarqube-local.yml is REQUIRED on main, optional on develop. Run it locally
# only for main-bound work so develop pushes stay fast.
MAIN_BOUND=0
[[ "$BRANCH" =~ ^(release|hotfix)/ ]] && MAIN_BOUND=1
[[ "${LOCAL_GATE_SONAR:-0}" == "1" ]] && MAIN_BOUND=1
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
