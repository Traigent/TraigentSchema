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
``schemas/datasets/evaluator_version_schema.json`` reference.

Both functions are pure and offline: no network, no filesystem, no randomness.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

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
# schemas/datasets/evaluator_version_schema.json.
EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN = "traigent.evaluator.judge_config.v1"


def _role_digest(domain: str, payload: Any) -> str:
    canonical = fp2.canonicalize(payload).encode("utf-8")
    return "sha256:" + hashlib.sha256(domain.encode("utf-8") + b"\x00" + canonical).hexdigest()


def compute_dataset_version_content_digest(preimage: Sequence[Mapping[str, Any]]) -> str:
    """Return the DatasetVersionV1.content_digest for a version's examples.

    ``preimage`` is the version's examples, each a mapping supplying at least
    ``example_id`` (str, the stable sort key) and ``input_text``, plus an
    optional ``expected_output``. This function performs the projection AND
    the ordering itself: it sorts by ``example_id`` (Python's stable sort, so
    duplicate ids keep their relative input order rather than being collapsed
    -- a duplicated-row data-quality bug must stay visible to the digest, not
    be silently absorbed by it) and then hashes only the projected
    ``{input_text, expected_output}`` pair per example. ``example_id`` itself
    is NOT part of the hashed payload: it determines order, nothing else.
    Consequently:

    * The same set of examples, supplied in any order, produces the same
      digest -- reordering the ``preimage`` argument has no effect.
    * Any change to an example's ``input_text`` or ``expected_output``
      changes the digest.
    * ``expected_output`` missing from an example is normalized to ``None``
      (JSON ``null``) in the projection, so its presence/absence is
      deterministic rather than caller-dependent.

    Raises:
        traigent_schema.fp2.Fp2UnsupportedValue: a projected value cannot be
            canonicalized (e.g. non-finite float, unpaired surrogate).
    """
    projected = [
        {
            "input_text": example["input_text"],
            "expected_output": example.get("expected_output"),
        }
        for example in sorted(preimage, key=lambda example: example["example_id"])
    ]
    return _role_digest(DATASET_VERSION_CONTENT_DIGEST_DOMAIN, projected)


def compute_judge_config_digest(judge_config: Mapping[str, Any]) -> str:
    """Return the EvaluatorVersionV1.judge_config_digest for a judge configuration.

    ``judge_config`` is hashed as-is under jcs_v1 canonicalization, which
    sorts object keys before hashing -- so the digest is independent of the
    key order in the mapping supplied by the caller. Any change to a value
    changes the digest.

    Raises:
        traigent_schema.fp2.Fp2UnsupportedValue: ``judge_config`` cannot be
            canonicalized (e.g. non-finite float, unpaired surrogate).
    """
    return _role_digest(EVALUATOR_JUDGE_CONFIG_DIGEST_DOMAIN, judge_config)
