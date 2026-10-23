# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Projection of TVL reactive transport facts onto the TVL reference trace's fact shape.

The closed wire contract (``schemas/optimization/tvl_reactive_facts_schema.json``) is a superset
of what ``tvl.runtime_trace`` accepts. Projecting a stored fact into a trace history removes:

* window ``unknown_reason`` (transport/stored metadata);
* candidate ``fingerprint`` and ``gate_result_digest`` (deploy bindings);
* revision fact ``target``, which is renamed to the trace field ``name``.

Hosted tokens are NOT translated here: the caller maps tokens back to the compiler's local names.
"""

from __future__ import annotations

from typing import Any

_WINDOW_ONLY = frozenset({"unknown_reason"})
_CANDIDATE_ONLY = frozenset({"fingerprint", "gate_result_digest"})
CATEGORIES = ("revisions", "windows", "episodes", "liveness", "optimizations")


def project_fact(category: str, fact: dict[str, Any]) -> dict[str, Any]:
    """Return the trace-shaped copy of one transport fact of ``category``."""
    if category not in CATEGORIES:
        raise ValueError("unknown fact category")
    out = dict(fact)
    if category == "revisions":
        out = {("name" if k == "target" else k): v for k, v in out.items()}
    elif category == "windows":
        out = {k: v for k, v in out.items() if k not in _WINDOW_ONLY}
    elif category == "optimizations" and isinstance(out.get("candidates"), list):
        out["candidates"] = [
            {k: v for k, v in c.items() if k not in _CANDIDATE_ONLY} for c in out["candidates"]
        ]
    return out


def project_evaluation(evaluation: dict[str, Any]) -> dict[str, Any]:
    """Project one staged evaluation (``instant`` plus per-category fact lists)."""
    out: dict[str, Any] = {"instant": evaluation["instant"]}
    for category in CATEGORIES:
        if category in evaluation:
            out[category] = [project_fact(category, f) for f in evaluation[category]]
    return out
