# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Reference implementation of the best-config integrity digest profile.

Normative document: traigent_schema/schemas/optimization/best_config_hash_contract_schema.json

This profile composes four steps, in order, none of which change fp2 itself:

1. Full recursive best-config prevalidation: reject an unsafe integral JSON
   numeric VALUE - abs(n) > 2**53-1 when the value is integral - whether it
   arrived as a Python ``int`` or a ``float``. fp2 (traigent_schema/fp2.py)
   only rejects the unsafe ``int`` TYPE and, by design, canonicalizes an
   equal-magnitude float (``fp2.digest({"n": 1e20})`` succeeds), because an
   ordinary finite float is otherwise valid fp2 input. This step closes that
   gap before fp2 ever sees the value.
2. Unchanged fp2 canonicalization (``fp2.canonicalize``).
3. A post-canonicalization UTF-8 byte bound: fp2 performs no byte-length
   check at all, because the bound is on canonical text that does not exist
   until fp2 has already run.
4. A domain-separated SHA-256 digest: ``sha256(domain_tag + b"\\x00" + canonical_bytes)``.

Every normative constant here (the byte bound, the domain tags) is read from
the packaged ``best_config_hash_contract_schema.json`` rather than
hardcoded, so a contract change cannot silently diverge from this
implementation. If that schema is missing or malformed, importing this
module fails closed - there is no fallback literal for a normative value.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from . import fp2
from .utils import get_schemas_dir

__all__ = [
    "BestConfigProfileError",
    "UnsafeIntegralValueError",
    "CanonicalSpecTooLargeError",
    "MAX_CANONICAL_SPEC_BYTES",
    "DOMAIN_TAG_CONFIG",
    "DOMAIN_TAG_SPEC",
    "config_digest",
    "spec_digest",
]

_MAX_SAFE_INTEGER = 2**53 - 1

_CONTRACT_FILENAME = "best_config_hash_contract_schema.json"


class BestConfigProfileError(Exception):
    """Base class for every best-config hash profile failure.

    No digest is ever returned when one of these is raised: rejection
    happens before ``fp2.canonicalize`` (prevalidation) or before hashing
    (the byte bound), never after a digest has already been computed.
    """

    code = "best_config_profile_error"


class UnsafeIntegralValueError(BestConfigProfileError):
    """A numeric VALUE is an integral magnitude outside the IEEE-754 safe range.

    Raised for the Python VALUE, independent of ``int``/``float`` type - see
    the ``rejected_values`` entry ``unsafe_integral_number`` in
    best_config_hash_contract_schema.json.
    """

    code = "unsafe_integral_number"


class CanonicalSpecTooLargeError(BestConfigProfileError):
    """The fp2-canonical UTF-8 encoding exceeds MAX_CANONICAL_SPEC_BYTES.

    See the ``rejected_values`` entry ``exceeds_max_canonical_spec_bytes``.
    """

    code = "exceeds_max_canonical_spec_bytes"


def _load_contract() -> dict[str, Any]:
    """Read the normative constants from the packaged contract schema.

    Raises BestConfigProfileError rather than falling back to a literal:
    a normative value that this module cannot verify against the shipped
    schema must not be guessed.
    """
    contract_path = get_schemas_dir() / "optimization" / _CONTRACT_FILENAME
    try:
        raw = contract_path.read_text(encoding="utf-8")
        contract = json.loads(raw)
        definitions = contract["definitions"]
        max_bytes = definitions["canonicalization"]["properties"]["max_canonical_spec_bytes"][
            "const"
        ]
        domain_tags = definitions["domain_tag"]["enum"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise BestConfigProfileError(
            f"{_CONTRACT_FILENAME} is missing or malformed; cannot derive "
            f"normative best-config hash profile constants: {error}"
        ) from error

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes <= 0:
        raise BestConfigProfileError(
            "canonicalization.max_canonical_spec_bytes must be a positive integer"
        )

    if not isinstance(domain_tags, list) or not all(isinstance(t, str) for t in domain_tags):
        raise BestConfigProfileError("domain_tag.enum must be a list of strings")

    config_tags = [tag for tag in domain_tags if tag.endswith(".config.v1")]
    spec_tags = [tag for tag in domain_tags if tag.endswith(".spec.v1")]
    if len(config_tags) != 1 or len(spec_tags) != 1:
        raise BestConfigProfileError(
            "domain_tag.enum must declare exactly one *.config.v1 tag and exactly one *.spec.v1 tag"
        )

    return {
        "max_canonical_spec_bytes": max_bytes,
        "config_tag": config_tags[0],
        "spec_tag": spec_tags[0],
    }


_CONTRACT = _load_contract()

#: Upper bound, in UTF-8 bytes, on the fp2-canonical text of a preimage.
#: Sourced from best_config_hash_contract_schema.json - see _load_contract.
MAX_CANONICAL_SPEC_BYTES: int = _CONTRACT["max_canonical_spec_bytes"]

#: Domain separator for config_hash preimages.
DOMAIN_TAG_CONFIG: str = _CONTRACT["config_tag"]

#: Domain separator for spec_hash preimages.
DOMAIN_TAG_SPEC: str = _CONTRACT["spec_tag"]


def _is_unsafe_integral(value: Any) -> bool:
    """True if value is an integral JSON number outside the safe-integer range.

    bool is excluded even though it is an int subclass: JSON has no boolean
    number, and a bool value here should be judged as the JSON literal
    true/false it represents, not as the integer 0 or 1.
    """
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return abs(value) > _MAX_SAFE_INTEGER
    if isinstance(value, float):
        if not math.isfinite(value):
            # Non-finite values are fp2's rejection to raise, not this rule's.
            return False
        if value != int(value):
            # Non-integral floats are ordinary fp2 input.
            return False
        return abs(value) > _MAX_SAFE_INTEGER
    return False


def _reject_unsafe_integral(value: Any, path: str = "$") -> None:
    """Walk value fully, raising on the first unsafe integral VALUE found."""
    if _is_unsafe_integral(value):
        raise UnsafeIntegralValueError(
            f"{path}: integral value outside the IEEE-754 safe integer range "
            f"(limit {_MAX_SAFE_INTEGER})"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if isinstance(key, str) else f"{path}[?]"
            _reject_unsafe_integral(item, child_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_unsafe_integral(item, f"{path}[{index}]")


def _canonical_bytes(value: Any) -> bytes:
    """Prevalidate, canonicalize with fp2 unchanged, then enforce the byte bound.

    Raises:
        UnsafeIntegralValueError: an unsafe integral VALUE was found before
            fp2 ever ran.
        fp2.Fp2UnsupportedValue: fp2 canonicalization rejected the value
            (non-finite number, exceeds max depth, lone surrogate, circular
            reference, unsupported type, or the int-type unsafe-integer case
            fp2 itself covers).
        CanonicalSpecTooLargeError: the canonical UTF-8 encoding exceeds
            MAX_CANONICAL_SPEC_BYTES.
    """
    _reject_unsafe_integral(value)
    canonical = fp2.canonicalize(value)
    encoded = canonical.encode("utf-8")
    if len(encoded) > MAX_CANONICAL_SPEC_BYTES:
        raise CanonicalSpecTooLargeError(
            f"canonical spec is {len(encoded)} bytes, exceeds the limit of "
            f"{MAX_CANONICAL_SPEC_BYTES}"
        )
    return encoded


def _domain_digest(value: Any, domain_tag: str) -> str:
    encoded = _canonical_bytes(value)
    preimage = domain_tag.encode("ascii") + b"\x00" + encoded
    return "sha256:" + hashlib.sha256(preimage).hexdigest()


def config_digest(config: Any) -> str:
    """Return the config_hash digest for a raw, as-published best-config config.

    See digest_roles.config_hash in best_config_hash_contract_schema.json:
    computed over the exact raw spec.config, before any allowlist filtering
    or default merging.
    """
    return _domain_digest(config, DOMAIN_TAG_CONFIG)


def spec_digest(spec: Any) -> str:
    """Return the spec_hash digest for a complete best-config spec object.

    See digest_roles.spec_hash in best_config_hash_contract_schema.json:
    computed over the complete spec, with no exclusion list.
    """
    return _domain_digest(spec, DOMAIN_TAG_SPEC)
