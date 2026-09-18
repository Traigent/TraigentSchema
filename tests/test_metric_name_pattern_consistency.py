"""#304: one metric-name character set, applied consistently across every surface.

A metric name is user-supplied ("response-time", "cost.usd"). A TVAR name becomes a
Python keyword argument, so it must stay a Python identifier. Both used to share the
same strict pattern, which meant widening metric names for #304 risked either missing
a surface -- leaving an objective accepted at one endpoint and rejected at another --
or widening the TVAR names by accident.

This test pins both halves. It walks every schema file rather than naming the ones we
happened to know about, so a NEW schema that constrains a metric name with the strict
pattern fails here instead of silently reintroducing the split.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

SCHEMAS_DIR = Path(__file__).resolve().parents[1] / "traigent_schema" / "schemas"

STRICT_IDENTIFIER = r"^[a-zA-Z_][a-zA-Z0-9_]*$"
METRIC_NAME = r"^[a-zA-Z_][a-zA-Z0-9_.-]*$"

# The only places a strict Python identifier is still correct. Each entry is
# (schema-relative path, json-pointer-ish location) and carries the reason, because
# "why is this one different" is the question a future reader will have.
STRICT_IDENTIFIER_SITES = {
    ("optimization/tvar_definition_schema.json", ".properties.name"): (
        "a TVAR name is passed to user code as a Python keyword argument"
    ),
    ("optimization/tvar_definition_schema.json", ".properties.agent"): (
        "agent names group TVARs and share the identifier constraint"
    ),
}


def _walk(node, path):
    """Yield (location, pattern) for every pattern / patternProperties key."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                yield path, value
            if key == "patternProperties" and isinstance(value, dict):
                for prop_pattern in value:
                    yield f"{path}.patternProperties", prop_pattern
            yield from _walk(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{path}[{index}]")


def _identifier_like_sites():
    for schema_file in sorted(SCHEMAS_DIR.rglob("*.json")):
        rel = schema_file.relative_to(SCHEMAS_DIR).as_posix()
        document = json.loads(schema_file.read_text())
        for location, pattern in _walk(document, ""):
            if pattern in (STRICT_IDENTIFIER, METRIC_NAME):
                yield rel, location, pattern


def test_metric_name_pattern_is_consistent_across_surfaces():
    """Every metric-name surface uses the widened set; only TVAR names stay strict."""
    offenders = []
    for rel, location, pattern in _identifier_like_sites():
        is_declared_strict = (rel, location) in STRICT_IDENTIFIER_SITES
        if is_declared_strict and pattern != STRICT_IDENTIFIER:
            offenders.append(
                f"{rel}{location}: expected the strict identifier pattern "
                f"(reason: {STRICT_IDENTIFIER_SITES[(rel, location)]}), got {pattern!r}"
            )
        if not is_declared_strict and pattern == STRICT_IDENTIFIER:
            offenders.append(
                f"{rel}{location}: constrains a metric name with the strict identifier "
                f"pattern. Metric names carry hyphens and dots -- use {METRIC_NAME!r}, "
                f"or add this site to STRICT_IDENTIFIER_SITES with the reason it is "
                f"genuinely a Python identifier."
            )
    assert not offenders, "inconsistent metric-name patterns:\n  " + "\n  ".join(offenders)


def test_the_strict_sites_still_exist():
    """Guard the guard: if a TVAR site is renamed away, this test must not silently pass."""
    found = {(rel, location) for rel, location, _ in _identifier_like_sites()}
    missing = sorted(site for site in STRICT_IDENTIFIER_SITES if site not in found)
    assert not missing, (
        "STRICT_IDENTIFIER_SITES names locations that no longer exist, so the strict "
        f"half of this test is no longer checking anything: {missing}"
    )


@pytest.mark.parametrize(
    "name",
    ["response-time", "cost.usd", "p95.latency_ms", "f1-macro", "accuracy"],
)
def test_realistic_metric_names_match_the_widened_pattern(name):
    import re

    assert re.match(METRIC_NAME, name), f"{name!r} should be a valid metric name"


@pytest.mark.parametrize(
    "name",
    ["has space", "9leading", "bad/key", "", "-leading-hyphen", ".leading-dot"],
)
def test_malformed_metric_names_still_rejected(name):
    """Widening is not the same as accepting anything: the boundary still exists."""
    import re

    assert not re.match(METRIC_NAME, name), f"{name!r} must not be a valid metric name"


def test_widened_pattern_is_a_strict_superset_of_the_old_one():
    """No name that validated before this change can fail after it.

    This is the whole justification for the breaking-gate allowlist entries: the
    checker sees the old patternProperties key removed and a new one added, which is
    mechanically a removal, but semantically the character class only grew. If this
    ever stops holding, the allowlist reasons become false and the entries must go.
    """
    import itertools
    import re

    old = re.compile(STRICT_IDENTIFIER)
    new = re.compile(METRIC_NAME)

    alphabet = "aZ_9.-/ "
    # exhaustive over every string up to length 3 from a set that spans the boundary
    # characters on both sides, plus the empty string
    candidates = [""]
    for length in (1, 2, 3):
        candidates += ["".join(c) for c in itertools.product(alphabet, repeat=length)]

    regressions = [c for c in candidates if old.match(c) and not new.match(c)]
    assert not regressions, (
        "the widened pattern REJECTS names the strict pattern accepted, so it is not a "
        f"superset and the allowlist rationale is wrong: {regressions[:10]}"
    )

    # and it must genuinely be wider, not merely equal -- otherwise the change is a no-op
    widened = [c for c in candidates if new.match(c) and not old.match(c)]
    assert widened, "the widened pattern accepts nothing new; the change would be inert"
