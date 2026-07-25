"""Exhaustive anti-whack-a-mole proof for the custom `measure_type` ban.

The banned-character set is DERIVED from Unicode categories + the
Default_Ignorable set in ``tests._charban`` — the same predicate that generates
the schema pattern. These tests assert:

1. the committed schema pattern (both sites) EQUALS the generated pattern, so the
   schema can never silently drift from the predicate;
2. across the entire Unicode scalar space, the pattern's accept/reject verdict
   MATCHES ``is_banned(cp)`` for every codepoint — i.e. the pattern is complete,
   not a hand-enumerated subset;
3. the specific invisible/format controls that slipped past the hand-rolled
   ranges (incl. sol's five escapees and the trailing-newline bypass) are
   rejected, while visible RTL / international / emoji labels pass — verified
   through the actual ``PUT /api/v1/measures/{measure_id}`` request mapping.

All test strings are built with ``chr()`` so this file stays pure ASCII.
"""

from __future__ import annotations

import json
import re

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

from tests._charban import MAX_CODEPOINT, is_banned, pattern

SCHEMA_NAME = "measure_schema"


def _committed_patterns() -> list[str]:
    with open(
        get_schemas_dir() / "measures" / "measure_schema.json", encoding="utf-8"
    ) as f:
        schema = json.load(f)
    return [
        schema["properties"]["measure_type"]["pattern"],
        schema["allOf"][0]["then"]["properties"]["measure_type"]["pattern"],
    ]


def _base_measure(measure_type: str) -> dict:
    return {
        "id": "m-1",
        "version": "1.0.0",
        "label": "L",
        "description": "d",
        "category": "Quality",
        "measure_type": measure_type,
        "evaluation_method": "deterministic",
        "target_aspect": "overall",
        "metric_type": "single_turn",
        "output_type": "discrete",
        "agent_types": ["chat"],
        "domain_min": None,
        "domain_max": None,
        "inverse": False,
        "is_custom": True,
    }


def test_committed_schema_pattern_equals_generated() -> None:
    """Both measure_type pattern sites must be the machine-generated string."""
    gen = pattern()
    for p in _committed_patterns():
        assert p == gen, "schema pattern drifted from tests._charban.pattern()"


def test_pattern_accept_reject_matches_category_predicate_exhaustively() -> None:
    """For every scalar codepoint, embedded in an otherwise-valid label, the
    pattern rejects iff the codepoint is in the derived banned set."""
    rx = re.compile(pattern())
    checked = 0
    mismatches: list[int] = []
    for cp in range(0x20, MAX_CODEPOINT):
        if 0xD800 <= cp <= 0xDFFF:  # surrogates are not scalar values
            continue
        checked += 1
        label = "a" + chr(cp) + "z"  # non-blank framing isolates the char-class ban
        accepted = bool(rx.search(label))
        if accepted == is_banned(cp):
            mismatches.append(cp)
    assert checked > 1_000_000, f"scan too small: {checked}"
    assert not mismatches, (
        f"{len(mismatches)} codepoints where pattern disagrees with is_banned(); "
        f"first: {[hex(c) for c in mismatches[:10]]}"
    )


def test_sol_escapees_and_bypasses_rejected_through_put_mapping() -> None:
    """sol's runtime escapees + the trailing-newline bypass, each rejected on the
    real PUT write path — both as the whole label and embedded."""
    v = SchemaValidator(contract="backend")
    escapees = {
        "U+061C ARABIC LETTER MARK": chr(0x061C),
        "U+206A INHIBIT SYMMETRIC SWAPPING": chr(0x206A),
        "U+206F NOMINAL DIGIT SHAPES": chr(0x206F),
        "U+00AD SOFT HYPHEN": chr(0x00AD),
        "U+180E MONGOLIAN VOWEL SEPARATOR": chr(0x180E),
        "U+FFF9 INTERLINEAR ANNOTATION ANCHOR": chr(0xFFF9),
        "U+200D ZERO WIDTH JOINER": chr(0x200D),
        "U+202E RIGHT-TO-LEFT OVERRIDE": chr(0x202E),
        "U+E0001 LANGUAGE TAG": chr(0xE0001),
    }
    for name, ch in escapees.items():
        for label in (ch, "metric" + ch, "met" + ch + "ric"):
            errors = v.validate_request(
                "/api/v1/measures/m-1", "PUT", _base_measure(label)
            )
            assert errors != [], f"PUT accepted a {name} label: {label!r}"

    # trailing-newline bypass (a bare `$` end-anchor would let this through)
    assert (
        v.validate_request("/api/v1/measures/m-1", "PUT", _base_measure("metric\n"))
        != []
    )
    # blank / whitespace-only
    for blank in (" ", "  ", "\t", chr(0x00A0)):
        assert (
            v.validate_request("/api/v1/measures/m-1", "PUT", _base_measure(blank))
            != []
        )


def test_visible_international_labels_accepted_through_put_mapping() -> None:
    """The ban is invisibles-only: visible RTL, accented, CJK, emoji all pass."""
    v = SchemaValidator(contract="backend")
    hebrew = chr(0x05DE) + chr(0x05D3) + chr(0x05D3)
    arabic = chr(0x0645) + chr(0x062F) + chr(0x0649)  # Arabic LETTERS, not signs
    accented = "qualit" + chr(0x00E9)
    cjk = chr(0x6E2C) + chr(0x5B9A) + chr(0x5024)
    emoji = chr(0x1F600)  # bare emoji, no variation selector
    checkmark = chr(0x2705)
    for good in (hebrew, arabic, accented, cjk, emoji, checkmark, "a b", "custom_x"):
        errors = v.validate_request(
            "/api/v1/measures/m-1", "PUT", _base_measure(good)
        )
        assert errors == [], f"PUT over-banned a visible label {good!r}: {errors}"
