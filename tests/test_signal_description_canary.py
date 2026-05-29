"""Canary: client-facing analytics schemas must not document signal formulas.

The analytics scoring schemas describe the INTERNAL scoring record. Their field
descriptions must not disclose how the proprietary tuning signals are computed
(the formulas) or name the signals as client-facing rankings. If this fails, a
formula phrase crept back into a schema description — scrub it, do not relax.
"""

from __future__ import annotations

import json
from pathlib import Path

_ANALYTICS_DIR = (
    Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas" / "analytics"
)

# Formula / how-computed phrases that previously leaked the signal stack.
_FORBIDDEN_PHRASES = [
    "TF-IDF",
    "variance across",
    "variance within",
    "correlation with config",
    "Information gain per",
    "distance from dataset centroid",
    "discriminates well",
    "differentiates between configurations",
    "highest informativeness",
    "highest difficulty",
    "weighted composite of all",
    "Sensitivity of metrics",
    "Variance in metrics",
]


def _iter_descriptions(obj):
    if isinstance(obj, dict):
        desc = obj.get("description")
        if isinstance(desc, str):
            yield desc
        for value in obj.values():
            yield from _iter_descriptions(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_descriptions(value)


def test_analytics_schema_descriptions_have_no_signal_formulas() -> None:
    for name in ("example_score_schema.json", "dataset_quality_schema.json"):
        path = _ANALYTICS_DIR / name
        schema = json.loads(path.read_text())
        descriptions = "\n".join(_iter_descriptions(schema))
        leaked = [phrase for phrase in _FORBIDDEN_PHRASES if phrase in descriptions]
        assert not leaked, f"signal formula phrase(s) leaked into {name} descriptions: {leaked}"
