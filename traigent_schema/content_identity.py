# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Pure, offline content-identity digests for dataset versions and evaluator versions.

Both digests use the certification family's own role-digest construction --
``sha256(UTF8(domain) || 0x00 || jcs_v1(payload))`` via :mod:`traigent_schema.fp2`
for the ``jcs_v1`` canonicalization -- mirroring
``traigent_schema.certification.evaluator_quality_verifier._role_digest``. This
module is a standalone, dependency-free peer of that verifier package: it does
not import from ``traigent_schema.certification`` and carries no verification
logic of its own, only the two pure digest functions the contracts in
``schemas/datasets/dataset_version_schema.json`` and
``schemas/observability/evaluator_version_schema.json`` reference.

Both functions are pure and offline: no network, no filesystem, no randomness.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from traigent_schema import fp2

__all__ = [
    "DATASET_VERSION_CONTENT_DIGEST_DOMAIN",
    "EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN",
    "compute_dataset_version_content_digest",
    "compute_judge_config_digest",
]

# Must match DatasetVersionContentDigestDomainV1's "const" in
# schemas/datasets/dataset_version_schema.json.
DATASET_VERSION_CONTENT_DIGEST_DOMAIN = "traigent.dataset_version.content.v1"

# Must match EvaluatorJudgeConfigDigestDomainV1's "const" in
# schemas/observability/evaluator_version_schema.json.
EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN = "traigent.evaluator.judge_config.v1"


def _role_digest(domain: str, payload: Any) -> str:
    canonical = fp2.canonicalize(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + b"\x00" + canonical).hexdigest()


def _validate_example(index: int, example: Mapping[str, Any]) -> None:
    example_id = example.get("example_id")
    if not isinstance(example_id, str):
        raise TypeError(
            f"preimage[{index}].example_id must be str, got {type(example_id).__name__}"
        )
    input_text = example.get("input_text")
    if not (
        isinstance(input_text, str)
        or (isinstance(input_text, list) and all(isinstance(item, str) for item in input_text))
    ):
        raise TypeError(
            f"preimage[{index}].input_text must be str or list[str], "
            f"got {type(input_text).__name__}"
        )
    if "expected_output" in example:
        expected_output = example["expected_output"]
        if expected_output is not None and not isinstance(expected_output, str):
            raise TypeError(
                f"preimage[{index}].expected_output must be str or None, "
                f"got {type(expected_output).__name__}"
            )


def compute_dataset_version_content_digest(preimage: Sequence[Mapping[str, Any]]) -> str:
    """Return the DatasetVersionV1.content_digest for a version's examples.

    ``preimage`` is the version's examples, each a mapping supplying at least
    ``example_id`` (str, the primary sort key) and ``input_text`` (str or
    list[str]), plus an optional ``expected_output`` (str or None). This
    function performs the projection AND the ordering itself: it sorts by
    ``(example_id.encode("utf-16-be"), jcs_v1(projection).encode("utf-8"))``
    -- UTF-16 code-unit order on the id, tied-broken by the canonical JCS
    bytes of the row's own projected ``{input_text, expected_output}``
    payload -- so the order is a pure function of content, never of input
    position: two rows sharing an ``example_id`` sort identically regardless
    of which one the producer enumerated first. Duplicate rows (same id,
    same projection) are therefore adjacent and BOTH remain in the preimage
    -- a duplicated-row data-quality bug must stay visible to the digest, not
    be silently absorbed by it -- while distinct rows sharing an id sort by
    their own content, not by producer enumeration order. Only the projected
    ``{input_text, expected_output}`` pair per example is hashed.
    ``example_id`` itself is NOT part of the hashed payload: it determines
    order, nothing else. ``example_id`` MUST be encodable text (Unicode
    scalar values only; a lone surrogate is rejected by every runtime with a
    typed error, never hashed), so the UTF-16 code-unit order is defined for
    every accepted id -- this function validates each id via
    :func:`traigent_schema.fp2._utf16_sort_key` before sorting, letting
    ``Fp2UnsupportedValue`` propagate unchanged. Consequently:

    * The same set of examples, supplied in any order, produces the same
      digest -- reordering the ``preimage`` argument has no effect, even
      when ids collide.
    * Any change to an example's ``input_text`` or ``expected_output``
      changes the digest.
    * ``expected_output`` missing from an example is normalized to ``None``
      (JSON ``null``) in the projection, so its presence/absence is
      deterministic rather than caller-dependent.

    Raises:
        TypeError: ``preimage`` is not a sequence (or is a ``str``/``bytes``/
            ``Mapping`` masquerading as one), an entry is not a ``Mapping``,
            or an example's ``example_id``, ``input_text``, or
            ``expected_output`` is not the expected type -- naming the field
            and the offending index.
        traigent_schema.fp2.Fp2UnsupportedValue: an ``example_id`` is not
            encodable text (a lone surrogate), or a projected value cannot be
            canonicalized (e.g. non-finite float, unpaired surrogate).
    """
    if isinstance(preimage, (str, bytes, Mapping)) or not isinstance(preimage, Sequence):
        raise TypeError(f"preimage must be a sequence of mappings, got {type(preimage).__name__}")
    for index, example in enumerate(preimage):
        if not isinstance(example, Mapping):
            raise TypeError(f"preimage[{index}] must be a mapping, got {type(example).__name__}")
        _validate_example(index, example)
    projections = [
        {
            "input_text": example["input_text"],
            "expected_output": example.get("expected_output"),
        }
        for example in preimage
    ]
    ordered = sorted(
        zip((example["example_id"] for example in preimage), projections, strict=True),
        key=lambda pair: (
            fp2._utf16_sort_key(pair[0]),
            fp2.canonicalize(pair[1]).encode("utf-8"),
        ),
    )
    ordered_projections = [projection for _, projection in ordered]
    return _role_digest(DATASET_VERSION_CONTENT_DIGEST_DOMAIN, ordered_projections)


def compute_judge_config_digest(judge_config: Mapping[str, Any]) -> str:
    """Return the EvaluatorVersionV1.judge_config_digest for a judge configuration.

    The preimage is the evaluator definition's persisted judge_config object
    as returned by the evaluator response's judge_config field, hashed WHOLE
    -- every key present, no filtering, no defaulting; a key that is absent
    stays absent and a key present with null stays null (jcs_v1 distinguishes
    them, so ``{"context_source": null}`` and ``{}`` differ); nested objects
    (``parameters``, ``scoring_rubric``) are hashed as-is; no key outside
    JudgeConfig (observability/evaluator_definition_schema.json#/definitions/JudgeConfig)
    may be added by producers (the schema is closed). Key order in
    judge_config is irrelevant: jcs_v1 canonicalization sorts object keys
    before hashing. Any change to a value changes the digest.

    Raises:
        TypeError: ``judge_config`` is not a ``Mapping``.
        traigent_schema.fp2.Fp2UnsupportedValue: ``judge_config`` cannot be
            canonicalized (e.g. non-finite float, unpaired surrogate).
    """
    if not isinstance(judge_config, Mapping):
        raise TypeError(f"judge_config must be a Mapping, got {type(judge_config).__name__}")
    return _role_digest(EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN, judge_config)
