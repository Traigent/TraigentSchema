"""Content-class lint for the optimization channel contracts (Phase 1).

``legacy_content`` is allowed while the content-less plan is rolled out, but only
through the checked-in manifest: every annotated location is pinned in
``docs/content-class-manifest.json``, ``legacy_content`` can be added nowhere, and a
location may leave it only with a disposition record
(``docs/content-class-dispositions.json``).
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

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "docs" / "content-class-manifest.json"
DISPOSITIONS = ROOT / "docs" / "content-class-dispositions.json"
MANIFEST_SCRIPT = ROOT / "scripts" / "content_class_manifest.py"
CONTENT_FREE = {
    "opaque_ref",
    "closed_enum",
    "number",
    "digest",
    "key_material",
    "timestamp",
    "code_identifier",
    "encrypted_blob",
    "auth_header",
}


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
    (root / "optimization").mkdir(parents=True, exist_ok=True)
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


def _manifest_module():
    spec = importlib.util.spec_from_file_location("content_class_manifest", MANIFEST_SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_manifest_equals_the_live_annotations() -> None:
    live = {f.loc: f.cls for f in lint.run_lint().findings if f.cls}
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))["classes"]
    changed = sorted(k for k in live.keys() & recorded.keys() if live[k] != recorded[k])
    added = sorted(live.keys() - recorded.keys())
    removed = sorted(recorded.keys() - live.keys())
    assert not (changed or added or removed), (
        "content-class manifest is stale (python3 scripts/content_class_manifest.py --update): "
        f"changed={changed[:5]} added={added[:5]} removed={removed[:5]}"
    )
    assert _manifest_module().render(live) == MANIFEST.read_text(encoding="utf-8")


def test_legacy_content_is_never_added() -> None:
    register = set(json.loads(DISPOSITIONS.read_text(encoding="utf-8"))["legacy_register"])
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))["classes"]
    legacy_now = {k for k, v in recorded.items() if v == "legacy_content"}
    assert legacy_now <= register, (
        "new legacy_content locations (use a real content class): "
        f"{sorted(legacy_now - register)[:10]}"
    )


def test_every_legacy_removal_has_a_disposition() -> None:
    data = json.loads(DISPOSITIONS.read_text(encoding="utf-8"))
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))["classes"]
    register = set(data["legacy_register"])
    by_loc = {d["location"]: d for d in data["dispositions"]}
    assert len(by_loc) == len(data["dispositions"]), "duplicate disposition entries"
    for loc, d in by_loc.items():
        assert loc in register, f"disposition for a location never in the register: {loc}"
        assert d["from"] == "legacy_content"
        assert d["to"] in CONTENT_FREE | {"removed"}, d
        assert len(d["reason"].strip()) >= 20, f"{loc}: reason too short"
        assert d["reference"].startswith(("INV", "DESIGN-v2.2", "GNFR-", "TraigentSchema#")), (
            f"{loc}: reference must cite the inventory row or design/issue"
        )
    for loc in sorted(register):
        now = recorded.get(loc)
        if now == "legacy_content":
            assert loc not in by_loc, f"{loc} is still legacy_content but has a disposition"
            continue
        assert loc in by_loc, (
            f"{loc} left legacy_content ({now or 'removed'}) with no disposition in "
            "docs/content-class-dispositions.json"
        )
        assert by_loc[loc]["to"] == (now or "removed"), (
            f"{loc}: disposition says {by_loc[loc]['to']}"
        )


def test_a_declassified_location_without_a_disposition_is_caught() -> None:
    register = {"a.json#/properties/x"}
    recorded = {"a.json#/properties/x": "opaque_ref"}
    data = {"legacy_register": sorted(register), "dispositions": []}
    missing = [
        loc
        for loc in register
        if recorded.get(loc) != "legacy_content"
        and loc not in {d["location"] for d in data["dispositions"]}
    ]
    assert missing == ["a.json#/properties/x"]


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
                "id": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
                    "x-content-class": "opaque_ref",
                },
                "scores": {
                    "type": "object",
                    "propertyNames": {
                        "type": "string",
                        "enum": ["f1", "cost"],
                        "x-content-class": "closed_enum",
                    },
                    "additionalProperties": {"type": "number", "x-content-class": "number"},
                },
                "name": {
                    "type": "string",
                    "x-content-class": "legacy_content",
                    "x-content-note": "INV S1-1 (LEAK): name",
                },
                "alias": {"$ref": "#/definitions/D"},
            },
            "definitions": {
                "D": {
                    "type": "string",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                    "x-content-class": "digest",
                }
            },
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


# --- class semantics: a class name must be backed by a constraint ------------------------


def _bad(tmp_path: Path, prop: dict) -> list[str]:
    result = _mini(tmp_path, {"type": "object", "properties": {"a": prop}})
    assert not result.missing, result.missing
    return result.invalid


def _ok(tmp_path: Path, prop: dict) -> None:
    result = _mini(tmp_path, {"type": "object", "properties": {"a": prop}})
    assert result.ok, (result.missing, result.invalid)


UUID = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
B64 = "^[A-Za-z0-9_-]+$"


def test_closed_enum_requires_enum_or_const(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "closed_enum"})
    assert _bad(
        tmp_path,
        {"type": "string", "pattern": "^[a-z]{1,64}$", "x-content-class": "closed_enum"},
    )
    _ok(tmp_path, {"type": "string", "enum": ["a", "b"], "x-content-class": "closed_enum"})
    _ok(tmp_path, {"const": 1, "x-content-class": "closed_enum"})
    _ok(tmp_path, {"type": "boolean", "x-content-class": "closed_enum"})


def test_number_requires_a_numeric_type_and_sane_bounds(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "number"})
    assert _bad(tmp_path, {"type": "boolean", "x-content-class": "number"})
    assert _bad(tmp_path, {"x-content-class": "number", "type": ["number", "string"]})
    assert _bad(tmp_path, {"type": "integer", "minimum": "0", "x-content-class": "number"})
    assert _bad(
        tmp_path, {"type": "integer", "minimum": 5, "maximum": 1, "x-content-class": "number"}
    )
    _ok(tmp_path, {"type": ["integer", "null"], "minimum": 0, "x-content-class": "number"})


def test_digest_requires_an_approved_hash_pattern(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "digest"})
    assert _bad(tmp_path, {"type": "string", "pattern": ".*", "x-content-class": "digest"})
    assert _bad(tmp_path, {"type": "string", "pattern": B64, "x-content-class": "digest"})
    _ok(
        tmp_path,
        {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "x-content-class": "digest"},
    )


def test_timestamp_requires_format_or_pattern(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "timestamp"})
    assert _bad(tmp_path, {"type": "string", "pattern": ".*", "x-content-class": "timestamp"})
    _ok(tmp_path, {"type": "string", "format": "date-time", "x-content-class": "timestamp"})


def test_opaque_ref_requires_the_ref_pattern(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "opaque_ref"})
    assert _bad(
        tmp_path,
        {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,128}$", "x-content-class": "opaque_ref"},
    )
    _ok(tmp_path, {"type": "string", "pattern": UUID, "x-content-class": "opaque_ref"})
    _ok(
        tmp_path,
        {"type": "string", "pattern": "^knobref_[0-9a-f]{32}$", "x-content-class": "opaque_ref"},
    )


def test_code_identifier_requires_an_identifier_pattern(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "code_identifier"})
    assert _bad(tmp_path, {"type": "string", "pattern": ".*", "x-content-class": "code_identifier"})
    _ok(
        tmp_path,
        {
            "type": "string",
            "pattern": (
                "^[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$"
            ),
            "x-content-class": "code_identifier",
        },
    )


def test_key_material_requires_bounded_base64url(tmp_path: Path) -> None:
    assert _bad(tmp_path, {"type": "string", "x-content-class": "key_material"})
    assert _bad(
        tmp_path,
        {"type": "string", "pattern": ".*", "maxLength": 43, "x-content-class": "key_material"},
    )
    assert _bad(tmp_path, {"type": "string", "pattern": B64, "x-content-class": "key_material"})
    _ok(
        tmp_path,
        {"type": "string", "pattern": B64, "maxLength": 43, "x-content-class": "key_material"},
    )


def test_encrypted_blob_must_come_from_the_label_envelope(tmp_path: Path) -> None:
    # outside labels/ an inline encrypted_blob is refused: it must $ref the label contract
    assert _bad(
        tmp_path,
        {"type": "string", "pattern": B64, "maxLength": 300, "x-content-class": "encrypted_blob"},
    )
    assert lint.run_lint().counts["encrypted_blob"] >= 1
    tmp_path = tmp_path / "labels_case"
    root = tmp_path / "schemas"
    (root / "labels").mkdir(parents=True)
    (root / "optimization").mkdir()
    node = {"type": "string", "pattern": B64, "maxLength": 300, "x-content-class": "encrypted_blob"}
    (root / "labels" / "x_schema.json").write_text(
        json.dumps({"type": "object", "properties": {"c": node}}), encoding="utf-8"
    )
    assert lint.run_lint(root).ok
    del node["maxLength"]
    (root / "labels" / "x_schema.json").write_text(
        json.dumps({"type": "object", "properties": {"c": node}}), encoding="utf-8"
    )
    assert lint.run_lint(root).invalid


def test_map_key_classes_are_checked_against_property_names(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "properties": {
            "m": {
                "type": "object",
                "x-content-key-class": "closed_enum",
                "additionalProperties": {"type": "number", "x-content-class": "number"},
            }
        },
    }
    assert _mini(tmp_path, schema).invalid
    pn = {"type": "string", "x-content-class": "closed_enum"}
    schema["properties"]["m"]["propertyNames"] = pn
    assert _mini(tmp_path, schema).invalid  # propertyNames classed without an enum
    pn["enum"] = ["a", "b"]
    assert _mini(tmp_path, schema).ok


# --- conditional branches ------------------------------------------------------------------


def _conditional(extra: dict, slot: str = "then") -> dict:
    return {
        "type": "object",
        "properties": {"kind": {"type": "string", "enum": ["a"], "x-content-class": "closed_enum"}},
        slot: extra,
    }


def test_conditional_branch_cannot_introduce_an_unclassified_property(tmp_path: Path) -> None:
    for slot in ("then", "else"):
        result = _mini(
            tmp_path,
            _conditional({"properties": {"customer_label": {"type": "string"}}}, slot),
        )
        assert any(f"/{slot}/properties/customer_label" in m for m in result.missing), (
            result.missing
        )
    schema = _conditional({"properties": {"customer_label": {"type": "string"}}})
    schema["if"] = {"properties": {"kind": {"const": "a"}}}
    assert _mini(tmp_path, schema).missing  # the if-branch kind is fine, then-branch is not
    nested = {"allOf": [_conditional({"properties": {"x": {"type": "string"}}})]}
    assert _mini(tmp_path, nested).missing
    negated = _conditional({"properties": {"y": {"type": "string"}}}, "not")
    assert _mini(tmp_path, negated).missing


def test_conditional_branch_may_constrain_a_classified_property(tmp_path: Path) -> None:
    schema = _conditional({"properties": {"kind": {"const": "a"}}})
    schema["if"] = {"properties": {"kind": {"const": "a"}}}
    assert _mini(tmp_path, schema).ok
    schema = _conditional(
        {
            "properties": {
                "extra": {"type": "string", "enum": ["x"], "x-content-class": "closed_enum"}
            }
        }
    )
    assert _mini(tmp_path, schema).ok  # a branch property that carries its own class is fine


# --- review follow-up: composition branches and open roots ---------------------------


def test_closed_enum_on_a_union_that_accepts_text_is_invalid(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "v": {
                    "x-content-class": "closed_enum",
                    "anyOf": [
                        {"type": "string", "maxLength": 64, "pattern": "^[A-Za-z0-9_.:/-]+$"},
                        {"type": "boolean"},
                    ],
                }
            },
        },
    )
    assert any("anyOf/0" in line and "accepts text" in line for line in result.invalid)
    assert not any("anyOf/1" in line for line in result.invalid)


def test_closed_enum_union_of_enums_is_accepted(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "v": {
                    "x-content-class": "closed_enum",
                    "oneOf": [{"enum": ["a", "b"]}, {"type": "boolean"}],
                }
            },
        },
    )
    assert result.ok


def test_open_payload_root_must_classify_extra_properties(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": True,
            "properties": {"has_next": {"x-content-class": "closed_enum", "type": "boolean"}},
        },
    )
    assert any("open payload root" in m for m in result.missing)


def test_closed_or_classified_root_passes(tmp_path: Path) -> None:
    closed = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {"a": {"x-content-class": "closed_enum", "type": "boolean"}},
        },
    )
    assert closed.ok
    classified = _mini(
        tmp_path / "c",
        {
            "type": "object",
            "additionalProperties": True,
            "x-content-class": "legacy_content",
            "x-content-key-class": "legacy_content",
            "x-content-note": "INV-GAP test",
            "properties": {"a": {"x-content-class": "closed_enum", "type": "boolean"}},
        },
    )
    assert classified.ok
    assert any(f.loc.endswith("[keys]") and f.cls == "legacy_content" for f in classified.findings)


def test_open_root_cannot_claim_a_content_free_key_class(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": True,
            "x-content-class": "closed_enum",
            "x-content-key-class": "closed_enum",
            "properties": {},
        },
    )
    assert any("content-free key class" in m for m in result.invalid)


def test_legacy_in_a_nullable_union_branch_reaches_the_manifest(tmp_path: Path) -> None:
    result = _mini(
        tmp_path,
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "note": {
                    "oneOf": [
                        {
                            "x-content-class": "legacy_content",
                            "x-content-note": "INV-GAP test",
                            "type": "string",
                        },
                        {"type": "null"},
                    ]
                }
            },
        },
    )
    legacy = [f.loc for f in result.legacy]
    assert legacy == ["optimization/t_schema.json#/properties/note/oneOf/0"]
    live = {f.loc: f.cls for f in result.findings if f.cls}
    assert live["optimization/t_schema.json#/properties/note/oneOf/0"] == "legacy_content"
    # a legacy branch with no note is invalid, like any other legacy location
    bad = _mini(
        tmp_path / "b",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "note": {"anyOf": [{"x-content-class": "legacy_content", "type": "string"}]}
            },
        },
    )
    assert any("needs x-content-note" in line for line in bad.invalid)


def test_tenant_and_project_ids_are_approved_opaque_refs() -> None:
    for pat in ("^tenant_[0-9a-f]{32}$", "^project_[0-9a-f]{32}$"):
        assert lint.semantic_problem("opaque_ref", {"type": "string", "pattern": pat}) is None
    assert lint.semantic_problem("opaque_ref", {"type": "string", "pattern": "^tenant_.+$"})
