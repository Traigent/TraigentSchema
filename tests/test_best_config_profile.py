# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Tests for traigent_schema/best_config_profile.py, the best-config hash profile.

Separate from tests/test_fp2_conformance.py (fp2's own corpus, unchanged by
this profile) and from tests/test_best_config_hash_contract.py (the schema's
own structural claims). This file proves the PYTHON REFERENCE IMPLEMENTATION
actually behaves the way best_config_hash_contract_schema.json says the
profile must: it is a top-up layer over an unmodified fp2, not a
reimplementation of it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from traigent_schema import best_config_profile as bcp
from traigent_schema import fp2

_VECTORS = json.loads(
    (Path(__file__).resolve().parent / "data" / "best_config_profile_vectors.json").read_text(
        encoding="utf-8"
    )
)


# --- fp2 vs. profile divergence on the unsafe-integral rule -----------------


def test_fp2_accepts_1e20_but_the_profile_rejects_it() -> None:
    """The entire reason this profile exists over fp2 alone.

    fp2 rejects the unsafe Python ``int`` TYPE but, by design, canonicalizes
    an equal-magnitude ``float`` because an ordinary finite float is
    otherwise valid fp2 input. The profile closes that gap by rejecting the
    numeric VALUE before fp2 ever runs.
    """
    payload = {"n": 1e20}

    # fp2 alone: succeeds.
    assert fp2.digest(payload)

    # the profile: rejects, and never reaches fp2 or hashlib.
    with pytest.raises(bcp.UnsafeIntegralValueError):
        bcp.config_digest(payload)


def test_fp2_and_the_profile_agree_on_the_unsafe_int_type() -> None:
    """fp2's own int-type rule and the profile's value-based rule overlap here."""
    payload = {"n": 10**20}

    with pytest.raises(fp2.Fp2UnsupportedValue):
        fp2.digest(payload)
    with pytest.raises(bcp.UnsafeIntegralValueError):
        bcp.config_digest(payload)


# --- vectors: safe boundary, unsafe int/float, nested ------------------------


def test_safe_integer_boundary_is_accepted() -> None:
    vector = _VECTORS["safe_integer_boundary"]
    assert vector["valid"] is True
    assert bcp.config_digest(vector["value"])


def test_unsafe_integral_int_is_rejected() -> None:
    vector = _VECTORS["unsafe_integral_int"]
    assert vector["valid"] is False
    assert isinstance(vector["value"]["n"], int)
    with pytest.raises(bcp.UnsafeIntegralValueError) as excinfo:
        bcp.config_digest(vector["value"])
    assert excinfo.value.code == vector["error_code"]


def test_unsafe_integral_float_is_rejected() -> None:
    vector = _VECTORS["unsafe_integral_float"]
    assert vector["valid"] is False
    assert isinstance(vector["value"]["n"], float)
    with pytest.raises(bcp.UnsafeIntegralValueError) as excinfo:
        bcp.config_digest(vector["value"])
    assert excinfo.value.code == vector["error_code"]


def test_nested_unsafe_integral_is_rejected() -> None:
    """Prevalidation must walk the full structure, not just top-level values."""
    vector = _VECTORS["nested_unsafe_integral"]
    assert vector["valid"] is False
    with pytest.raises(bcp.UnsafeIntegralValueError) as excinfo:
        bcp.config_digest(vector["value"])
    assert excinfo.value.code == vector["error_code"]


@pytest.mark.parametrize(
    ("magnitude_sign", "value"),
    [("positive", 1e20), ("negative", -1e20)],
)
def test_unsafe_integral_float_rejected_both_signs(magnitude_sign: str, value: float) -> None:
    del magnitude_sign  # parametrize id only
    with pytest.raises(bcp.UnsafeIntegralValueError):
        bcp.config_digest({"n": value})


def test_ordinary_nonintegral_and_small_values_are_left_for_fp2() -> None:
    """Values the profile does NOT reject still pass through to fp2 untouched."""
    assert bcp.config_digest({"n": 0.7, "s": "ok", "i": 42})


# --- representative config/spec digest vectors -------------------------------


def test_config_digest_vectors_match_the_reference_implementation() -> None:
    for vector in _VECTORS["config_digest_vectors"]:
        assert bcp.config_digest(vector["config"]) == vector["expected_config_hash"]


def test_spec_digest_vectors_match_the_reference_implementation() -> None:
    for vector in _VECTORS["spec_digest_vectors"]:
        assert bcp.spec_digest(vector["spec"]) == vector["expected_spec_hash"]


def test_config_and_spec_digests_use_distinct_domain_tags() -> None:
    """The same payload must hash differently under both roles -- the point of domain separation."""
    payload = {"same": "payload"}
    assert bcp.config_digest(payload) != bcp.spec_digest(payload)
    assert bcp.DOMAIN_TAG_CONFIG != bcp.DOMAIN_TAG_SPEC


# --- canonical byte bound: exact limit, limit+1, astral bytes-as-bytes ------
#
# Generated programmatically rather than stored in the vectors fixture: a
# ~256KiB literal string baked into a JSON file would bloat the repo for no
# conformance benefit fp2's own corpus doesn't already provide coverage of
# canonicalization itself. What is being tested here is exclusively the
# profile's post-canonicalization length check.


def _padded_payload(canonical_extra_bytes: int) -> dict[str, str]:
    """Return {"k": "x"*n} such that its fp2-canonical UTF-8 length is exactly
    MAX_CANONICAL_SPEC_BYTES + canonical_extra_bytes."""
    overhead = len(fp2.canonicalize({"k": ""}).encode("utf-8"))
    target = bcp.MAX_CANONICAL_SPEC_BYTES + canonical_extra_bytes
    n = target - overhead
    assert n >= 0
    return {"k": "x" * n}


def test_canonical_byte_length_exactly_at_limit_is_accepted() -> None:
    payload = _padded_payload(0)
    canonical_len = len(fp2.canonicalize(payload).encode("utf-8"))
    assert canonical_len == bcp.MAX_CANONICAL_SPEC_BYTES
    assert bcp.config_digest(payload)


def test_canonical_byte_length_one_over_limit_is_rejected() -> None:
    payload = _padded_payload(1)
    canonical_len = len(fp2.canonicalize(payload).encode("utf-8"))
    assert canonical_len == bcp.MAX_CANONICAL_SPEC_BYTES + 1
    with pytest.raises(bcp.CanonicalSpecTooLargeError) as excinfo:
        bcp.config_digest(payload)
    assert excinfo.value.code == "exceeds_max_canonical_spec_bytes"


def test_astral_characters_are_counted_as_utf8_bytes_not_code_points() -> None:
    """One astral code point is one Python character but four UTF-8 bytes.

    A length check performed on ``len(text)`` (code points/UTF-16 units)
    rather than ``len(text.encode("utf-8"))`` would under-count astral text
    and let an over-large preimage through.
    """
    astral = "\U0001f600"  # 😀 - 1 code point, 4 UTF-8 bytes once encoded
    canonical = fp2.canonicalize({"k": astral})
    encoded = canonical.encode("utf-8")
    assert len(encoded) > len(canonical), "the fixture must actually exercise multi-byte encoding"

    overhead_ascii_only = len(fp2.canonicalize({"k": ""}).encode("utf-8"))
    # Room for exactly one astral character over the limit, using code-point
    # counting; if bytes were miscounted as code points this would pass.
    n = bcp.MAX_CANONICAL_SPEC_BYTES - overhead_ascii_only
    payload = {"k": ("x" * (n - 1)) + astral}
    canonical_len = len(fp2.canonicalize(payload).encode("utf-8"))
    # n-1 ASCII bytes + 4 bytes for the astral char = overhead + n - 1 + 4
    # = MAX_CANONICAL_SPEC_BYTES + 3, i.e. over the limit because the astral
    # character contributed 4 bytes, not 1.
    assert canonical_len == bcp.MAX_CANONICAL_SPEC_BYTES + 3
    with pytest.raises(bcp.CanonicalSpecTooLargeError):
        bcp.config_digest(payload)


# --- raw formatting is not part of the parsed reference API ------------------


def test_reference_api_operates_on_parsed_python_values_not_raw_json_text() -> None:
    """Documents rather than fakes a raw-JSON-text entry point.

    best_config_profile.config_digest/spec_digest accept already-parsed
    Python values (dict/list/str/int/float/bool/None), matching fp2's own
    surface. There is no "raw pretty-printed JSON in, digest out" API: two
    different raw JSON texts that parse to the same value (different
    whitespace, key order, or number spelling such as "1.0" vs "1.0e0")
    MUST produce the same digest, and the only way to guarantee that is to
    operate on the parsed value, never on the original text or its
    formatting.
    """
    pretty = '{\n  "n" : 1.0,\n  "s": "ok"\n}\n'
    compact = '{"s":"ok","n":1.0}'
    assert bcp.config_digest(json.loads(pretty)) == bcp.config_digest(json.loads(compact))


# --- no digest call/result on profile failure --------------------------------


def test_no_digest_is_returned_when_prevalidation_fails() -> None:
    with pytest.raises(bcp.UnsafeIntegralValueError) as excinfo:
        bcp.config_digest({"n": 1e20})
    # The exception carries no digest-shaped value; failure produces no
    # partial or placeholder result for a caller to mistake for success.
    assert not hasattr(excinfo.value, "digest")


def test_no_digest_is_returned_when_the_byte_bound_fails() -> None:
    payload = _padded_payload(1)
    with pytest.raises(bcp.CanonicalSpecTooLargeError) as excinfo:
        bcp.spec_digest(payload)
    assert not hasattr(excinfo.value, "digest")


def test_no_digest_is_returned_when_fp2_itself_rejects() -> None:
    """fp2 rejection (e.g. non-finite) must also short-circuit before hashing."""
    with pytest.raises(fp2.Fp2UnsupportedValue):
        bcp.config_digest({"n": float("nan")})


# --- typed errors are distinguishable and carry contract-aligned codes ------


def test_errors_carry_the_contract_rejected_values_code() -> None:
    assert bcp.UnsafeIntegralValueError.code == "unsafe_integral_number"
    assert bcp.CanonicalSpecTooLargeError.code == "exceeds_max_canonical_spec_bytes"
    assert issubclass(bcp.UnsafeIntegralValueError, bcp.BestConfigProfileError)
    assert issubclass(bcp.CanonicalSpecTooLargeError, bcp.BestConfigProfileError)


# --- fail-closed derivation from the packaged schema -------------------------


def test_constants_are_derived_from_the_packaged_contract_schema() -> None:
    """No fallback literal: these must trace back to the shipped schema file."""
    from traigent_schema.utils import get_schemas_dir

    contract_path = get_schemas_dir() / "optimization" / "best_config_hash_contract_schema.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    definitions = contract["definitions"]

    assert (
        bcp.MAX_CANONICAL_SPEC_BYTES
        == (definitions["canonicalization"]["properties"]["max_canonical_spec_bytes"]["const"])
    )
    tags = definitions["domain_tag"]["enum"]
    assert bcp.DOMAIN_TAG_CONFIG in tags
    assert bcp.DOMAIN_TAG_SPEC in tags
    assert bcp.DOMAIN_TAG_CONFIG.endswith(".config.v1")
    assert bcp.DOMAIN_TAG_SPEC.endswith(".spec.v1")


def test_load_contract_fails_closed_on_malformed_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A malformed packaged schema must raise, never fall back to a hardcoded literal."""
    broken_schemas_dir = tmp_path / "schemas"
    (broken_schemas_dir / "optimization").mkdir(parents=True)
    (broken_schemas_dir / "optimization" / "best_config_hash_contract_schema.json").write_text(
        json.dumps({"definitions": {}}), encoding="utf-8"
    )
    monkeypatch.setattr(bcp, "get_schemas_dir", lambda: broken_schemas_dir)

    with pytest.raises(bcp.BestConfigProfileError):
        bcp._load_contract()


def test_load_contract_fails_closed_on_missing_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bcp, "get_schemas_dir", lambda: tmp_path / "does-not-exist")

    with pytest.raises(bcp.BestConfigProfileError):
        bcp._load_contract()
