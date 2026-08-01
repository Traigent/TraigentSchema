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


def test_spec_specifies_manifest_construction_not_just_canonicalization() -> None:
    """Identical canonicalization of DIFFERENT manifests still diverges.

    Two SDKs can follow the canonicalization rules faithfully, build different
    manifests from the same run, and get different valid digests -- the
    key-ordering failure one level up, where no amount of canonicalization
    saves you. Each algorithm must say what goes in and what is left out.
    """
    text = SPEC.read_text(encoding="utf-8")
    # Markdown reflows, so match against whitespace-normalized prose: the test
    # pins what the spec SAYS, not where its line breaks fall.
    flowed = " ".join(text.split())

    assert "Construction" in text, "no algorithm states how its manifest is built"
    # cfp2 was the worst offender: 'normalized configuration space' with
    # normalization defined nowhere. It is now anchored to the wire value.
    assert "configuration_space" in flowed, "cfp2 normalization is still unanchored"
    # afp2/efp2 digest source text and cannot be equal across languages; the
    # spec must say so rather than implying a parity it cannot deliver.
    assert "within one language runtime" in flowed


def test_spec_records_the_tuple_decision_explicitly() -> None:
    """A Python-only type needs a stated decision, not silence."""
    text = SPEC.read_text(encoding="utf-8").lower()
    flowed = " ".join(text.split())

    assert "tuple" in text, "the tuple decision is unrecorded"
    assert "namedtuple" in text, "the exact edge of the tuple rule is unstated"
    assert "isinstance" in text, "the exact-type rule is not spelled out for implementers"
    # Rejecting tuples only works if the builder is told to normalize positional
    # rows; otherwise Plan 3 rediscovers the problem as a broken dataset digest.
    assert "tuples are rejected" in flowed, "the reversal is not recorded"
    assert "positional" in flowed, "the builder's normalization duty is unstated"


def test_spec_gives_source_manifests_a_runtime_discriminator() -> None:
    """A scope that lives only in prose is a scope no comparator can honour.

    afp2/efp2 are comparable only within one language runtime, but a digest is
    opaque, so the manifest itself has to make a cross-runtime match impossible.
    """
    # Strip markdown code ticks too: the spec writes `runtime`, and the test
    # pins the statement, not its typography.
    flowed = " ".join(SPEC.read_text(encoding="utf-8").replace("`", "").split())

    assert '"runtime"' in flowed, "afp2/efp2 carry no runtime discriminator"
    assert "runtime is mandatory" in flowed.lower()
    # ...and dfp2o/cfp2 must NOT carry one: they are required to match across
    # languages, so a runtime token would break the parity they exist to give.
    assert "carry no such field" in flowed


def test_spec_forbids_echoing_caller_content_in_errors() -> None:
    """Same disclosure rule as telemetry and exports; fp2 sees user content."""
    flowed = " ".join(SPEC.read_text(encoding="utf-8").split()).lower()

    assert "must not echo the offending value" in flowed
    assert "never the content" in flowed


def test_spec_records_the_int_float_false_equality_as_a_known_limit() -> None:
    """Same family as the tuple collision, but this one cannot be closed.

    JSON has one number type and JavaScript cannot express the distinction, so
    any rule separating int from float would guarantee cross-SDK divergence.
    Recorded so a reader meets it here rather than in a wrong comparison.
    """
    flowed = " ".join(SPEC.read_text(encoding="utf-8").split()).lower()

    assert "does not distinguish integer from float" in flowed
    assert "known false-equality" in flowed


def test_spec_requires_dataset_order_to_be_significant() -> None:
    text = SPEC.read_text(encoding="utf-8").lower()

    assert "ordered" in text, "dfp2o must be specified as order-significant"
