"""Every rate-limited operation in an endpoint catalog declares the canonical 429 (#271).

The backend's global default rate limiter is attached to the same app as every API
route; only kube-probe/metrics paths (``/health``, ``/status``,
``/metrics`` and their ``/api``-prefixed forms) are exempt. So a catalog operation that
declares no 429 under-documents a response the client really receives.

``FULLY_COVERED`` is the set of catalogs #271 verified and fixed: every operation in them
that declares responses must declare ``429`` -> ``rate_limit_info_schema.json``, except the
operations named in ``DELIBERATE_EXCEPTIONS``.
``KNOWN_UNCOVERED`` records how many operations in every other catalog still lack a 429.
Operations that declare no ``responses`` at all are a separate gap and are not counted.
The budget may only shrink: a new operation without a 429 fails here instead of drifting silently.
"""

from __future__ import annotations

import json
import posixpath
from pathlib import Path

import pytest

from traigent_schema.utils import get_schemas_dir

SCHEMAS = Path(get_schemas_dir())
METHODS = ("get", "post", "put", "patch", "delete")
EXEMPT_PREFIXES = ("/health", "/status", "/metrics", "/api/health", "/api/status", "/api/metrics")

FULLY_COVERED = (
    "audit/audit_endpoints.json",
    "billing/paddle_endpoints.json",
    "billing/spend_controls_endpoints.json",
    "billing/subscription_lifecycle_endpoints.json",
    "billing/wallet_endpoints.json",
    "costs/costs_endpoints.json",
    "datasets/datasets_endpoints.json",
    "execution/best_config_endpoints.json",
    "execution/execution_endpoints.json",
    "measures/measures_endpoints.json",
    "observability/observability_endpoints.json",
    "planned_projects_endpoints.json",
    "planner/planner_endpoints.json",
    "prompts/prompts_endpoints.json",
    "results/results_endpoints.json",
    "security/security_endpoints.json",
)

# Operations in the fixed catalogs that deliberately carry no 429. They are rate-limited
# at runtime; giving them a 429 needs an owner decision on the envelope, so they are
# excluded here rather than silently counted. The reason for each group is noted inline.
DELIBERATE_EXCEPTIONS = {
    # Every experiment-group 4xx/5xx must reference the strict ExperimentGroupErrorEnvelope
    # subtype (test_experiment_group_contract.py), which has no 429 variant yet.
    ("execution/execution_endpoints.json", "get", "/api/v1/experiment-groups"),
    ("execution/execution_endpoints.json", "get", "/api/v1/experiment-groups/{group_id}"),
    (
        "execution/execution_endpoints.json",
        "get",
        "/api/v1/experiment-groups/{group_id}/configuration-runs",
    ),
    (
        "execution/execution_endpoints.json",
        "post",
        "/api/v1/experiment-groups/{group_id}/configuration-runs/query",
    ),
    # Pre-release v1beta ingest pins its response set to exactly {202, 410}
    # (test_observability_v2_contract.py).
    ("observability/observability_endpoints.json", "post", "/api/v1beta/observability/ingest"),
    (
        "observability/observability_endpoints.json",
        "post",
        "/api/v1beta/projects/{project_id}/observability/ingest",
    ),
    # These operations can return a 429 whose body does NOT match rate_limit_info, so
    # declaring that envelope would mis-document them. Which envelope they declare is an
    # owner decision (widen rate_limit_info, a oneOf, or align the backend bodies).
    # A per-route limiter adds details.remaining and an integer details.limit, which the
    # closed rate_limit_info details block rejects:
    ("execution/execution_endpoints.json", "post", "/api/v1/experiments"),
    ("execution/execution_endpoints.json", "post", "/api/v1/experiment-runs/{experiment_id}/runs"),
    ("execution/execution_endpoints.json", "post", "/api/v1/traces/ingest"),
    (
        "observability/observability_endpoints.json",
        "post",
        "/api/v1beta/annotation-queues/{queue_id}/items",
    ),
    # A subscription quota breach answers 429 with billing/quota_exceeded_error_schema.json
    # (and generate-examples also has a legacy limiter body with a top-level rate_limit):
    ("datasets/datasets_endpoints.json", "post", "/api/v1/datasets"),
    ("datasets/datasets_endpoints.json", "post", "/api/v1/datasets/{dataset_id}/generate-examples"),
    (
        "observability/observability_endpoints.json",
        "post",
        "/api/v1beta/evaluators/{evaluator_id}/execute",
    ),
}

# The v1 envelope, plus the v2 observability API's own error envelope (pre-existing on
# POST /api/v2/observability/events; that API family uses one error schema for every 4xx).
CANONICAL_429_ENVELOPES = {
    "rate_limit_info_schema.json",
    "observability/observability_v2_error_schema.json",
}

# Operations still missing a 429, per catalog. Shrink-only: lower a count when you add
# 429s, never raise it. (Catalogs not listed here and not in FULLY_COVERED have 0.)
KNOWN_UNCOVERED = {
    "agent_readiness/agent_posture_endpoints.json": 1,
    "agent_readiness/agent_readiness_endpoints.json": 4,
    "agent_readiness/fleet_posture_endpoints.json": 1,
    "agents/agents_endpoints.json": 16,
    "analytics/analytics_endpoints.json": 9,
    "auth/auth_endpoints.json": 8,
    "auth/keys_endpoints.json": 7,
    "billing/marketplace_endpoints.json": 3,
    "datasets/content_identity_endpoints.json": 3,
    "economics/economics_endpoints.json": 2,
    "evaluation_system_validation/evaluation_system_validation_endpoints.json": 6,
    "mfa/mfa_endpoints.json": 4,
    "smartops_v2/smartops_v2_endpoints.json": 8,
}


def _catalogs() -> list[str]:
    return sorted(str(p.relative_to(SCHEMAS)) for p in SCHEMAS.rglob("*_endpoints.json"))


def _operations(rel: str):
    doc = json.loads((SCHEMAS / rel).read_text(encoding="utf-8"))
    for path, item in (doc.get("paths") or {}).items():
        for method, op in item.items():
            if method in METHODS:
                yield path, method, op


def _is_exempt(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in EXEMPT_PREFIXES)


def _uncovered(rel: str) -> list[str]:
    return [
        f"{method.upper()} {path}"
        for path, method, op in _operations(rel)
        if "responses" in op
        and not _is_exempt(path)
        and "429" not in op["responses"]
        and (rel, method, path) not in DELIBERATE_EXCEPTIONS
    ]


@pytest.mark.parametrize("rel", FULLY_COVERED)
def test_fixed_catalogs_declare_429_on_every_operation(rel: str) -> None:
    assert _uncovered(rel) == [], f"{rel}: operations without a 429"


@pytest.mark.parametrize("rel", FULLY_COVERED)
def test_fixed_catalogs_429_points_at_the_canonical_rate_limit_envelope(rel: str) -> None:
    for path, method, op in _operations(rel):
        if (
            "responses" not in op
            or _is_exempt(path)
            or (rel, method, path) in DELIBERATE_EXCEPTIONS
        ):
            continue
        ref = op["responses"]["429"]["content"]["application/json"]["schema"]["$ref"]
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(rel), ref))
        assert resolved in CANONICAL_429_ENVELOPES, f"{rel} {method} {path}: {ref}"
        assert (SCHEMAS / resolved).is_file()


def test_uncovered_operation_counts_only_shrink() -> None:
    grown = {}
    for rel in _catalogs():
        if rel in FULLY_COVERED:
            continue
        missing = len(_uncovered(rel))
        allowed = KNOWN_UNCOVERED.get(rel, 0)
        if missing > allowed:
            grown[rel] = (allowed, missing)
    assert grown == {}, f"new operations without a 429 (allowed, actual): {grown}"


def test_known_uncovered_entries_are_not_stale() -> None:
    catalogs = set(_catalogs())
    stale = {rel for rel in KNOWN_UNCOVERED if rel not in catalogs or rel in FULLY_COVERED}
    assert stale == set()
    tightenable = {
        rel: (allowed, len(_uncovered(rel)))
        for rel, allowed in KNOWN_UNCOVERED.items()
        if len(_uncovered(rel)) < allowed
    }
    assert tightenable == {}, f"lower these KNOWN_UNCOVERED counts: {tightenable}"


def test_deliberate_exceptions_still_exist_and_still_lack_a_429() -> None:
    """An exception must name a real operation that still has no 429; once someone gives
    it one, the entry is stale and must be removed so the coverage check applies again."""
    stale = []
    for rel, method, path in sorted(DELIBERATE_EXCEPTIONS):
        ops = {(m, p): op for p, m, op in _operations(rel)}
        op = ops.get((method, path))
        if op is None or "429" in op.get("responses", {}):
            stale.append((rel, method, path))
    assert stale == []
