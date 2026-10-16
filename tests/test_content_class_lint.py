"""Content-class lint for the optimization channel contracts (Phase 1).

``legacy_content`` is allowed while the content-less plan is rolled out, but the
count is a ratchet: it may only go down (see ``LEGACY_CONTENT_PIN``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "content_class_lint.py"
META = (
    Path(__file__).resolve().parent.parent
    / "traigent_schema"
    / "schemas"
    / "x_extensions_meta_schema.json"
)

# Ratchet. Lower this when legacy_content annotations are removed; the test below
# fails in both directions so the pin always equals the current count.
LEGACY_CONTENT_PIN = 241


def _load():
    spec = importlib.util.spec_from_file_location("content_class_lint", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


lint = _load()


def _mini(tmp_path: Path, schema: dict, name: str = "t_schema.json"):
    root = tmp_path / "schemas"
    (root / "optimization").mkdir(parents=True)
    (root / "optimization" / name).write_text(json.dumps(schema), encoding="utf-8")
    return lint.run_lint(root)


def test_every_optimization_value_has_a_content_class() -> None:
    result = lint.run_lint()
    assert not result.invalid, result.invalid
    assert not result.unresolved, result.unresolved
    assert not result.missing, "unclassified: " + "; ".join(result.missing[:20])


def test_lint_walks_the_optimization_documents() -> None:
    docs = set(lint.run_lint().documents)
    assert "optimization/optimization_endpoints.json" in docs
    assert "optimization/session_submit_results_request_schema.json" in docs
    assert "guidance/guidance_result_submission_schema.json" in docs
    assert "evaluation/configuration_run_schema.json" in docs  # via $ref


def test_class_vocabulary_matches_the_registered_extension() -> None:
    meta = json.loads(META.read_text(encoding="utf-8"))["properties"]
    for key in ("x-content-class", "x-content-key-class"):
        assert set(meta[key]["enum"]) == set(lint.CONTENT_CLASSES)
    assert "x-content-note" in meta
    assert "legacy_content" in lint.CONTENT_CLASSES


def test_legacy_content_count_only_goes_down() -> None:
    count = len(lint.run_lint().legacy)
    assert count <= LEGACY_CONTENT_PIN, (
        f"legacy_content grew to {count} (pin {LEGACY_CONTENT_PIN}): new fields must "
        "use a real content class, never legacy_content"
    )
    assert count == LEGACY_CONTENT_PIN, (
        f"legacy_content fell to {count}: lower LEGACY_CONTENT_PIN to {count} so the "
        "ratchet cannot regrow"
    )


def test_every_legacy_content_location_is_justified() -> None:
    legacy = lint.run_lint().legacy
    assert legacy
    assert all(f.note and f.note.startswith("INV") for f in legacy)


def test_lint_flags_unclassified_property(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {"type": "object", "properties": {"a": {"type": "string"}}},
    )
    assert result.missing == ["optimization/t_schema.json#/properties/a"]


def test_lint_recurses_into_items_maps_and_keys(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "list": {"type": "array", "items": {"type": "string"}},
                "by_name": {
                    "type": "object",
                    "additionalProperties": {"type": "number"},
                },
                "pat": {
                    "type": "object",
                    "patternProperties": {"^k_": {"type": "string"}},
                },
                "free": {"type": "object", "additionalProperties": True},
                "ref": {"$ref": "#/definitions/D"},
            },
            "definitions": {"D": {"type": "string"}},
        },
    )
    missing = "\n".join(result.missing)
    for part in (
        "/properties/list/items",
        "/properties/by_name/additionalProperties",
        "/properties/by_name (map keys",
        "/properties/pat/patternProperties/^k_",
        "/properties/pat (map keys",
        "/properties/free",
        "/definitions/D",
    ):
        assert part in missing, part


def test_classified_schema_passes_and_counts(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "id": {"type": "string", "x-content-class": "opaque_ref"},
                "scores": {
                    "type": "object",
                    "propertyNames": {"type": "string", "x-content-class": "closed_enum"},
                    "additionalProperties": {"type": "number", "x-content-class": "number"},
                },
                "name": {
                    "type": "string",
                    "x-content-class": "legacy_content",
                    "x-content-note": "INV S1-1 (LEAK): name",
                },
                "alias": {"$ref": "#/definitions/D"},
            },
            "definitions": {"D": {"type": "string", "x-content-class": "digest"}},
        },
    )
    assert result.ok, (result.missing, result.invalid)
    assert result.counts["legacy_content"] == 1
    assert result.counts["opaque_ref"] == 1
    assert result.counts["digest"] == 1


def test_legacy_content_requires_a_note_and_unknown_class_is_rejected(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "properties": {
                "a": {"type": "string", "x-content-class": "legacy_content"},
                "b": {"type": "string", "x-content-class": "free_text"},
            },
        },
    )
    assert len(result.invalid) == 2
