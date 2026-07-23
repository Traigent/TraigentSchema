"""Single source of truth for the custom `measure_type` invisible-character ban.

The measure_type validator runs through `jsonschema` on the stdlib `re` engine,
which has NO `\\p{Cf}` / `\\p{DI}` unicode-property classes, so the negated
character class in the schema pattern must spell out explicit codepoint ranges.
Rather than hand-enumerate ranges (whack-a-mole — every missed Cf codepoint is a
spoofing bypass), we DERIVE the banned set programmatically here and generate the
pattern from it. The exhaustive test asserts the committed schema pattern equals
`pattern()` AND that its accept/reject verdict matches `is_banned()` across the
whole codepoint space — so the pattern is provably complete against the predicate.

Banned = Unicode general category in {Cc, Cf, Zl, Zp} (controls, format chars,
line/paragraph separators) UNION the Default_Ignorable_Code_Point members that
carry a visible-script category (Mn/Lo/…) or are reserved-but-default-ignorable
and therefore are NOT category-flagged. Cn (unassigned) is deliberately EXCLUDED
except the reserved default-ignorable slots enumerated below — banning general Cn
would over-ban codepoints Unicode may assign to visible glyphs in future.
"""

from __future__ import annotations

import unicodedata

# Default_Ignorable_Code_Point members (Unicode DerivedCoreProperties) that
# `unicodedata.category` does NOT return as Cc/Cf/Zl/Zp — they are rendering-
# invisible but categorised Mn/Lo/… or are reserved default-ignorable (Cn). Kept
# explicit because stdlib `re` cannot express Default_Ignorable as a class.
_DEFAULT_IGNORABLE_EXTRA: set[int] = set()
for _lo, _hi in [
    (0x00AD, 0x00AD),   # SOFT HYPHEN (Cf — belt-and-braces; also caught by category)
    (0x034F, 0x034F),   # COMBINING GRAPHEME JOINER (Mn)
    (0x061C, 0x061C),   # ARABIC LETTER MARK (Cf — belt-and-braces)
    (0x115F, 0x1160),   # HANGUL CHOSEONG/JUNGSEONG FILLER (Lo)
    (0x17B4, 0x17B5),   # KHMER VOWEL INHERENT AQ/AA (Mn)
    (0x180B, 0x180F),   # MONGOLIAN FVS1-4 + VOWEL SEPARATOR (Mn/Cf)
    (0x2065, 0x2065),   # reserved default-ignorable (Cn)
    (0x3164, 0x3164),   # HANGUL FILLER (Lo)
    (0xFE00, 0xFE0F),   # VARIATION SELECTOR-1..16 (Mn)
    (0xFFA0, 0xFFA0),   # HALFWIDTH HANGUL FILLER (Lo)
    (0xFFF0, 0xFFF8),   # reserved default-ignorable (Cn)
    (0x13439, 0x1343F),  # EGYPTIAN HIEROGLYPH format controls added in Unicode 15
                         # (Cf on Py>=3.12; Cn/unassigned on Py3.11's Unicode 14 tables).
                         # Pinned so a downlevel host still bans them and pattern()
                         # is stable across supported Pythons (3.11 CI vs 3.12 dev).
    (0x1BCA0, 0x1BCA3),  # SHORTHAND FORMAT CONTROLS (Cf)
    (0x1D173, 0x1D17A),  # MUSICAL SYMBOL BEGIN/END … (Cf)
    (0xE0000, 0xE0FFF),  # TAGS + VARIATION SELECTORS SUPPLEMENT + reserved (Cf/Mn/Cn)
]:
    _DEFAULT_IGNORABLE_EXTRA.update(range(_lo, _hi + 1))

_BANNED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})

# Surrogates (Cs) are not valid scalar values in a well-formed string; skip them
# in the scan so `chr()`/`re` never sees a lone surrogate.
_SURROGATE_LO, _SURROGATE_HI = 0xD800, 0xDFFF

MAX_CODEPOINT = 0x110000


def is_banned(cp: int) -> bool:
    """True iff codepoint `cp` must be forbidden inside a custom measure_type."""
    if cp in _DEFAULT_IGNORABLE_EXTRA:
        return True
    if _SURROGATE_LO <= cp <= _SURROGATE_HI:
        return False
    return unicodedata.category(chr(cp)) in _BANNED_CATEGORIES


def banned_ranges(upto: int = MAX_CODEPOINT) -> list[tuple[int, int]]:
    """Minimal contiguous (lo, hi) ranges of banned codepoints below `upto`."""
    ranges: list[tuple[int, int]] = []
    start: int | None = None
    prev = -1
    for cp in range(upto):
        if _SURROGATE_LO <= cp <= _SURROGATE_HI:
            continue
        if is_banned(cp):
            if start is None:
                start = cp
            prev = cp
        elif start is not None:
            ranges.append((start, prev))
            start = None
    if start is not None:
        ranges.append((start, prev))
    return ranges


def _esc(cp: int) -> str:
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


def char_class_body(upto: int = MAX_CODEPOINT) -> str:
    parts = []
    for lo, hi in banned_ranges(upto):
        parts.append(_esc(lo) if lo == hi else f"{_esc(lo)}-{_esc(hi)}")
    return "".join(parts)


def pattern(upto: int = MAX_CODEPOINT) -> str:
    """The full measure_type regex.

    * ``^`` + ``(?![\\s\\S])`` anchor the whole string (jsonschema uses
      ``re.search``; a bare ``$`` would let a trailing newline slip through).
    * ``(?=.*\\S)`` requires at least one non-whitespace character (no blank /
      whitespace-only labels).
    * the negated class forbids every banned codepoint.
    """
    return "^(?=.*\\S)[^" + char_class_body(upto) + "]+(?![\\s\\S])"


if __name__ == "__main__":  # pragma: no cover - regeneration helper
    print(pattern())
