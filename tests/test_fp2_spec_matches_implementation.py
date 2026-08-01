"""The spec and the implementation are checked against each other, by execution.

Two contradictions survived four review rounds -- the spec told an implementer
to turn a positional dataset row into an array while dfp2o requires an object,
and it told them to coerce a numeric subclass while the encoder rejects one --
because the document was edited in pieces while the code moved underneath it.
Reading did not catch either. Running does.

These tests deliberately DERIVE their expectations from docs/fingerprints/fp2.md
rather than restating them. Editing the spec therefore changes what the
implementation must do, and drift fails here instead of in Plan 3's second SDK.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

from traigent_schema.fp2 import MAX_DEPTH, Fp2UnsupportedValue, canonicalize

SPEC = Path(__file__).resolve().parents[1] / "docs" / "fingerprints" / "fp2.md"


def _spec() -> str:
    return SPEC.read_text(encoding="utf-8")


def _flowed() -> str:
    """Prose with typography normalized away: markdown reflows and re-emphasizes,
    statements do not. Strips line wrapping, code ticks and bold/italic markers
    so these tests pin what the spec SAYS, never how it is formatted."""
    return " ".join(_spec().replace("`", "").replace("*", "").split())


def _section(title: str) -> str:
    text = _spec()
    start = text.index(f"## {title}")
    remainder = text[start + 3 :]
    end = remainder.find("\n## ")
    return remainder if end == -1 else remainder[:end]


def _number_table_rows() -> list[tuple[str, str]]:
    """(input literal, required ECMAScript output) parsed from the Numbers table."""
    rows: list[tuple[str, str]] = []
    for line in _section("Numbers").splitlines():
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) != 3 or cells[0] in ("Value", ""):
            continue
        if set(cells[0]) <= set("-: "):
            continue
        try:
            float(cells[0])
        except ValueError:
            continue
        rows.append((cells[0], cells[2]))
    return rows


def test_the_number_table_is_not_decorative() -> None:
    """Every row of the spec's ECMAScript table is executed against the encoder.

    The table exists because Python repr and ECMAScript Number::toString pick
    different notation. If someone edits a row, this test makes the encoder
    answer for it.
    """
    rows = _number_table_rows()

    assert len(rows) >= 5, f"the Numbers table lost its rows: {rows}"
    for literal, required in rows:
        produced = canonicalize({"n": float(literal)})
        assert produced == f'{{"n":{required}}}', (
            f"spec says {literal} -> {required}, implementation produced {produced}"
        )


def test_the_depth_limit_in_the_spec_is_the_one_the_code_enforces() -> None:
    """A limit only the implementation knows is a cross-SDK divergence."""
    stated = re.search(r"more than \*\*(\d+)\*\*", _section("Nesting depth"))

    assert stated, "the Nesting depth section no longer states a number"
    assert int(stated.group(1)) == MAX_DEPTH, (
        f"spec says {stated.group(1)}, implementation enforces {MAX_DEPTH}"
    )


# Each entry: the phrase the spec's unsupported list must contain, and a value
# the implementation must reject. Both halves have to stay true together, so
# deleting one from the spec fails here rather than silently diverging.
_UNSUPPORTED: tuple[tuple[str, Any], ...] = (
    ("NaN", float("nan")),
    ("Infinity", float("inf")),
    ("integers outside the IEEE-754 safe integer range", 2**53),
    ("lone surrogates in a string or key", "a\ud800b"),
    ("tuples", (1, 2)),
    ("subclasses of the supported types", type("D", (dict,), {})()),
)


@pytest.mark.parametrize("phrase,value", _UNSUPPORTED, ids=[p for p, _ in _UNSUPPORTED])
def test_every_named_unsupported_value_is_actually_rejected(phrase: str, value: Any) -> None:
    assert phrase in _flowed(), f"the spec no longer lists {phrase!r} as unsupported"
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"k": value})


def test_the_spec_never_instructs_coercion_of_a_numeric_subclass() -> None:
    """C2: the text said convert, the encoder rejects.

    That sentence was true while the encoder coerced, and survived the change to
    exact-type dispatch. An SDK following it would return a digest where this
    implementation returns unknown.
    """
    flowed = _flowed()

    assert "converted to the exact builtin type" not in flowed, (
        "the spec still instructs coercion, which the encoder does not do"
    )
    assert "numeric subclass is therefore an unsupported value" in flowed
    # ...and the rationale that makes it load-bearing must survive the edit.
    assert "caller-controlled" in flowed


def test_the_dataset_row_shape_is_specified_once_and_as_an_object() -> None:
    """C1: two sections specified the same row incompatibly.

    An array and an object are different canonical bytes, so an SDK reading the
    tuple section built [input, expected] while one reading dfp2o built
    {"input":..,"expected":..} -- the key-ordering failure at the spec layer.
    """
    flowed = _flowed()

    assert '{"input":<input>,"expected":<expected or null>}' in flowed, (
        "dfp2o no longer states the row shape"
    )
    assert "converts it to an array" not in flowed, (
        "the tuple section still tells the builder to produce an array"
    )
    # The tuple section must defer to dfp2o rather than restate the shape.
    assert "authoritative for row shape" in flowed


def test_positional_normalization_is_assigned_to_the_builder_not_the_encoder() -> None:
    """The principle under the corrected example still has to be stated.

    canonicalize rejects tuples, so if the spec does not tell the builder to
    resolve a positional row, Plan 3 discovers it as a broken dataset digest.
    """
    flowed = _flowed()

    assert "manifest builder" in flowed
    assert "positional" in flowed
    with pytest.raises(Fp2UnsupportedValue):
        canonicalize({"rows": [("in", "out")]})
    assert canonicalize({"rows": [{"input": "in", "expected": "out"}]}) == (
        '{"rows":[{"expected":"out","input":"in"}]}'
    )
