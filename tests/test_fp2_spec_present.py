"""The fp2 canonicalization spec is a contract artifact, not documentation.

Both SDKs implement against it; if it drifts or disappears, digests
diverge silently and cohorts split by language.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SPEC = REPO_ROOT / "docs" / "fingerprints" / "fp2.md"

REQUIRED_SECTIONS = (
    "## Scope",
    "## Canonical JSON",
    "## Key ordering",
    "## Numbers",
    "## Null and undefined",
    "## Nesting depth",
    "## Unsupported values",
    "## Manifests",
    "## Digest format",
    "## Versioning",
)

REQUIRED_ALGORITHMS = ("afp2", "dfp2o", "efp2", "cfp2")


def test_spec_exists() -> None:
    assert SPEC.is_file(), f"fp2 spec missing at {SPEC}"


def test_spec_defines_every_required_section() -> None:
    text = SPEC.read_text(encoding="utf-8")
    missing = [section for section in REQUIRED_SECTIONS if section not in text]

    assert not missing, f"fp2 spec is missing sections: {missing}"


def test_spec_names_every_algorithm_used_by_the_schema() -> None:
    text = SPEC.read_text(encoding="utf-8")
    missing = [algorithm for algorithm in REQUIRED_ALGORITHMS if algorithm not in text]

    assert not missing, f"fp2 spec does not define algorithms: {missing}"


def test_spec_forbids_silent_coercion_of_unsupported_values() -> None:
    text = SPEC.read_text(encoding="utf-8").lower()

    assert "default=str" in text, "The spec must call out Python's default=str trap by name"
    assert "unknown" in text, "Unsupported values must resolve to unknown, never a coerced string"


def test_spec_states_the_depth_limit_as_a_number() -> None:
    """Plan 3 implements two SDKs from this text.

    A limit only the Python implementation knows is a new cross-SDK divergence:
    one client would digest a manifest the other rejects. The number has to be
    in the spec, and it has to match the reference implementation.
    """
    from traigent_schema.fp2 import MAX_DEPTH

    text = SPEC.read_text(encoding="utf-8")

    assert str(MAX_DEPTH) in text, f"the spec never states the limit ({MAX_DEPTH})"
    assert "depth" in text.lower()


def test_spec_forbids_foreign_exception_types_as_a_class_rule() -> None:
    """Enumerating known offenders is what left RecursionError uncovered."""
    text = SPEC.read_text(encoding="utf-8").lower()

    assert "recursionerror" in text, "deep nesting is not named as an incomplete manifest"
    assert "third outcome" in text, "the class rule is not stated, only instances"


def test_spec_requires_dataset_order_to_be_significant() -> None:
    text = SPEC.read_text(encoding="utf-8").lower()

    assert "ordered" in text, "dfp2o must be specified as order-significant"
