"""The normative fp2 vectors must ship in the Schema distribution."""

from __future__ import annotations

import json
from importlib import resources


def test_fp2_conformance_vectors_are_packaged_and_nontrivial() -> None:
    root = resources.files("traigent_schema").joinpath("data")
    for name, minimum, spec in (
        ("fp2_conformance.json", 12, "fp2"),
        ("agent_lifecycle_cases.json", 1, "fp2-agent-lifecycle-parity"),
    ):
        resource = root.joinpath(name)
        corpus = json.loads(resource.read_text(encoding="utf-8"))
        assert resource.is_file()
        assert corpus["spec"] == spec
        assert len(corpus["cases"]) >= minimum
