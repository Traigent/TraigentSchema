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


def _mini(tmp_path: Path, schema: dict, name: str = "t_schema.json", *, close: bool = True):
    if close and schema.get("type") == "object":
        schema = {"additionalProperties": False, **schema}  # an omitted value means open
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
        why = _manifest_module().reference_problem(d["reference"])
        assert why is None, f"{loc}: {why}"
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
        json.dumps({"type": "object", "additionalProperties": False, "properties": {"c": node}}),
        encoding="utf-8",
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
    assert any("anyOf/0" in line and "closed_enum needs" in line for line in result.invalid)
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


def test_object_without_additional_properties_is_open(tmp_path: Path) -> None:
    # The reviewer's reproduction: no additionalProperties, so {"patient_note": ...} validates.
    schema = {
        "type": "object",
        "properties": {"has_next": {"x-content-class": "closed_enum", "type": "boolean"}},
    }
    result = _mini(tmp_path, schema, close=False)
    assert any("open payload root" in m for m in result.missing)
    nested = _mini(
        tmp_path / "n",
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {"inner": {"type": "object", "properties": {"a": {"type": "boolean"}}}},
        },
        close=False,
    )
    assert any("/properties/inner" in m and "open payload root" in m for m in nested.missing)
    try:
        import jsonschema

        jsonschema.validate({"has_next": True, "patient_note": "Alice has diabetes"}, schema)
    except ImportError:  # pragma: no cover
        pass


def test_explicitly_closed_and_classified_objects_pass(tmp_path: Path) -> None:
    base = {
        "type": "object",
        "properties": {"a": {"x-content-class": "closed_enum", "type": "boolean"}},
    }
    assert _mini(tmp_path / "a", {**base, "additionalProperties": False}, close=False).ok
    modern = {**base, "unevaluatedProperties": False}
    draft2019 = {"$schema": "https://json-schema.org/draft/2019-09/schema", **modern}
    assert _mini(tmp_path / "b", draft2019, close=False).ok
    # Draft-7 (or no $schema) validators ignore unevaluatedProperties: still open
    draft7 = {"$schema": "http://json-schema.org/draft-07/schema#", **modern}
    assert any("open payload root" in m for m in _mini(tmp_path / "d", draft7, close=False).missing)
    assert any("open payload root" in m for m in _mini(tmp_path / "e", modern, close=False).missing)
    legacy = {
        **base,
        "x-content-class": "legacy_content",
        "x-content-key-class": "legacy_content",
        "x-content-note": "INV-GAP test",
    }
    assert _mini(tmp_path / "c", legacy, close=False).ok


# --- ratchet anchored on origin/develop ------------------------------------------------


def _git_repo(tmp_path: Path, files: dict[str, str] | None) -> Path:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                *args,
            ],
            check=True,
            capture_output=True,
        )

    git("init", "-q")
    (repo / "keep.txt").write_text("x\n")
    for rel, text in (files or {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    git("add", "-A")
    git("commit", "-q", "-m", "base")
    git("update-ref", "refs/remotes/origin/develop", "HEAD")
    return repo


def test_the_working_tree_satisfies_the_anchored_ratchet() -> None:
    mod = _manifest_module()
    a_manifest, a_disp = mod.load_anchor()  # raises (fails the test) when git/ref is unavailable
    live = {f.loc: f.cls for f in lint.run_lint().findings if f.cls}
    problems = mod.ratchet_problems(
        live,
        json.loads(MANIFEST.read_text(encoding="utf-8"))["classes"],
        json.loads(DISPOSITIONS.read_text(encoding="utf-8")),
        a_manifest,
        a_disp,
    )
    assert problems == []


def test_anchor_text_absent_present_and_unavailable(tmp_path: Path) -> None:
    import pytest

    mod = _manifest_module()
    repo = _git_repo(tmp_path, {"docs/m.json": "{}"})
    assert mod.anchor_text("docs/m.json", repo) == "{}"
    assert mod.anchor_text("docs/missing.json", repo) is None  # first introduction
    with pytest.raises(mod.RatchetError):
        mod.anchor_text("docs/m.json", tmp_path / "not_a_repo")
    with pytest.raises(mod.RatchetError):
        mod.anchor_text("docs/m.json", repo, ref="origin/nope")


def test_first_introduction_requires_the_manifest_to_equal_live() -> None:
    mod = _manifest_module()
    live = {"a.json#/x": "closed_enum"}
    assert mod.ratchet_problems(live, dict(live), {}, None, None) == []
    hidden = {**live, "b.json#/y": "legacy_content"}
    assert mod.ratchet_problems(live, hidden, {}, None, None)


def test_edited_manifest_cannot_hide_a_new_legacy_location() -> None:
    mod = _manifest_module()
    anchor = {"a.json#/x": "closed_enum"}
    live = {"a.json#/x": "closed_enum", "b.json#/y": "legacy_content"}
    tree_manifest = dict(live)  # the manifest was edited to match
    tree_disp = {"legacy_register": ["b.json#/y"], "dispositions": []}  # and so was the register
    problems = mod.ratchet_problems(
        live, tree_manifest, tree_disp, anchor, {"legacy_register": [], "dispositions": []}
    )
    assert any("new legacy_content" in p and "b.json#/y" in p for p in problems)
    # relabelling an anchored closed_enum as legacy is also an addition
    live2 = {"a.json#/x": "legacy_content"}
    assert any(
        "new legacy_content" in p
        for p in mod.ratchet_problems(
            live2, dict(live2), {"legacy_register": ["a.json#/x"]}, anchor, None
        )
    )


def test_relabelling_legacy_to_content_free_needs_a_verifiable_disposition() -> None:
    mod = _manifest_module()
    loc = "a.json#/x"
    anchor = {loc: "legacy_content"}
    a_disp = {"legacy_register": [loc], "dispositions": []}
    live = {loc: "opaque_ref"}
    base = {"location": loc, "from": "legacy_content", "to": "opaque_ref", "reason": "x" * 30}

    def run(disp: list[dict]) -> list[str]:
        tree = {"legacy_register": [loc], "dispositions": disp}
        return mod.ratchet_problems(live, dict(live), tree, anchor, a_disp)

    assert any("no disposition" in p for p in run([]))
    assert any("not file:line" in p for p in run([{**base, "reference": "see the PR"}]))
    assert any("unknown inventory row" in p for p in run([{**base, "reference": "INV Z99-1"}]))
    for fake in ("INV S5-999999", "INV S5-0", "INV S5-36", "INV H5-1"):
        assert any("unknown inventory row" in p for p in run([{**base, "reference": fake}])), fake
    assert any("names a route" in p for p in run([{**base, "reference": "INV S5"}]))
    assert any("no line" in p for p in run([{**base, "reference": "docs/labels-v0.md:99999"}]))
    assert any("not a file" in p for p in run([{**base, "reference": "nope/missing.py:1"}]))
    assert any(
        "unknown design section" in p for p in run([{**base, "reference": "DESIGN-v2.2 §9.9"}])
    )
    for good in ("INV S5-5", "INV H2-1", "DESIGN-v2.2 §3.6", "docs/labels-v0.md:1"):
        assert run([{**base, "reference": good}]) == [], good
    wrong_to = {**base, "to": "digest", "reference": "INV S5-5"}
    assert any("disposition says digest" in p for p in run([wrong_to]))


def test_anchored_dispositions_and_register_cannot_be_edited_away() -> None:
    mod = _manifest_module()
    loc = "a.json#/x"
    disp = {
        "location": loc,
        "from": "legacy_content",
        "to": "digest",
        "reason": "x" * 30,
        "reference": "INV S5-5",
    }
    a_disp = {"legacy_register": [loc], "dispositions": [disp]}
    live = {loc: "digest"}
    tree = {"legacy_register": [], "dispositions": [{**disp, "reference": "INV S1-1"}]}
    problems = mod.ratchet_problems(live, dict(live), tree, live, a_disp)
    assert any("lost anchored entries" in p for p in problems)
    assert any("edited or removed" in p for p in problems)


def _probe(tmp_path: Path, prop: dict):
    return _mini(
        tmp_path, {"type": "object", "additionalProperties": False, "properties": {"v": prop}}
    )


def test_semantics_cover_allof_and_unconstrained_alternatives(tmp_path: Path) -> None:
    bad_allof = _probe(tmp_path / "a", {"x-content-class": "number", "allOf": [{"type": "string"}]})
    assert bad_allof.invalid
    bad_any = _probe(
        tmp_path / "b", {"x-content-class": "closed_enum", "anyOf": [{}, {"enum": ["safe"]}]}
    )
    assert any("unconstrained alternative" in line for line in bad_any.invalid)
    bad_true = _probe(
        tmp_path / "c", {"x-content-class": "closed_enum", "oneOf": [True, {"enum": ["safe"]}]}
    )
    assert bad_true.invalid
    bad_ref = _probe(
        tmp_path / "d",
        {"x-content-class": "closed_enum", "anyOf": [{"$ref": "#/definitions/T"}, {"enum": ["a"]}]},
    )
    assert bad_ref.invalid or bad_ref.unresolved
    ok = _probe(
        tmp_path / "e",
        {"x-content-class": "closed_enum", "anyOf": [{"enum": ["a"]}, {"type": "boolean"}]},
    )
    assert ok.ok
    ok_allof = _probe(
        tmp_path / "f", {"x-content-class": "number", "allOf": [{"type": "integer", "minimum": 0}]}
    )
    assert ok_allof.ok


def test_open_object_inside_a_composition_branch_is_flagged(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "strategy": {
                "oneOf": [
                    {"x-content-class": "closed_enum", "type": "string", "enum": ["auto"]},
                    {
                        "type": "object",
                        "required": ["algorithm"],
                        "properties": {
                            "algorithm": {"x-content-class": "closed_enum", "enum": ["auto"]}
                        },
                    },
                ]
            }
        },
    }
    result = _mini(tmp_path, schema)
    assert any("/properties/strategy/oneOf/1" in m for m in result.missing)
    schema["properties"]["strategy"]["oneOf"][1].update(
        {
            "x-content-class": "legacy_content",
            "x-content-key-class": "legacy_content",
            "x-content-note": "INV-GAP test",
        }
    )
    fixed = _mini(tmp_path / "fixed", schema)
    assert fixed.ok
    locs = {f.loc for f in fixed.legacy}
    assert "optimization/t_schema.json#/properties/strategy/oneOf/1" in locs
    assert "optimization/t_schema.json#/properties/strategy/oneOf/1 [keys]" in locs
    closed = {**schema["properties"]["strategy"]["oneOf"][1]}
    for k in ("x-content-class", "x-content-key-class", "x-content-note"):
        closed.pop(k)
    closed["additionalProperties"] = False
    schema["properties"]["strategy"]["oneOf"][1] = closed
    assert _mini(tmp_path / "closed", schema).ok


# --- review round 3: conditional-only objects, $ref siblings, branch class compatibility ---


def test_conditional_only_root_with_an_open_then_object_is_flagged(tmp_path: Path) -> None:
    schema = {
        "if": {},
        "then": {
            "type": "object",
            "properties": {"flag": {"type": "boolean", "x-content-class": "closed_enum"}},
        },
    }
    result = _mini(tmp_path, schema, close=False)
    assert any("/then" in m and "open payload root" in m for m in result.missing)
    # classified honestly, it passes and the extra keys reach the manifest
    schema["then"].update(
        {
            "x-content-class": "legacy_content",
            "x-content-key-class": "legacy_content",
            "x-content-note": "INV-GAP test",
        }
    )
    fixed = _mini(tmp_path / "fixed", schema, close=False)
    assert fixed.ok
    assert "optimization/t_schema.json#/then [keys]" in {f.loc for f in fixed.legacy}
    # closed branches and unconditionally closed parents need nothing
    schema["then"] = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"flag": {"type": "boolean", "x-content-class": "closed_enum"}},
    }
    assert _mini(tmp_path / "closed", schema, close=False).ok
    parent_closed = {
        "type": "object",
        "additionalProperties": False,
        "if": {},
        "then": {"type": "object", "properties": {}},
    }
    assert _mini(tmp_path / "pc", parent_closed, close=False).ok


def test_draft7_ref_siblings_are_ignored_by_the_semantics(tmp_path: Path) -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "definitions": {
            "Text": {
                "x-content-class": "legacy_content",
                "x-content-note": "INV-GAP test",
                "type": "string",
            }
        },
        "properties": {
            "v": {"x-content-class": "number", "type": "number", "$ref": "#/definitions/Text"}
        },
    }
    result = _mini(tmp_path, schema)
    assert any("/properties/v" in line for line in result.invalid)
    # in 2019-09 the siblings do apply, so the type restricts the value to numbers
    modern = {**schema, "$schema": "https://json-schema.org/draft/2019-09/schema"}
    assert not any("/properties/v:" in line for line in _mini(tmp_path / "m", modern).invalid)


def test_a_branch_class_does_not_prove_the_parents_class(tmp_path: Path) -> None:
    bad = _probe(
        tmp_path,
        {
            "x-content-class": "number",
            "allOf": [{"x-content-class": "closed_enum", "type": "string", "enum": ["safe"]}],
        },
    )
    assert bad.invalid
    ok = _probe(
        tmp_path / "ok",
        {
            "x-content-class": "closed_enum",
            "allOf": [{"x-content-class": "closed_enum", "type": "string", "enum": ["safe"]}],
        },
    )
    assert ok.ok


def test_old_dialect_ref_target_alone_decides_whatever_the_siblings_say(tmp_path: Path) -> None:
    text = {
        "x-content-class": "legacy_content",
        "x-content-note": "INV-GAP test",
        "type": "string",
    }
    siblings = [
        {"type": "null"},
        {"type": "number"},
        {"type": "integer", "minimum": 0},
        {"enum": ["a"]},
        {"const": 1},
        {"anyOf": [{"type": "null"}]},
        {"allOf": [{"type": "number"}]},
        {"x-content-class": "closed_enum", "enum": ["a"]},
    ]
    for i, sib in enumerate(siblings):
        for j, cls in enumerate(("number", "closed_enum")):
            schema = {
                "type": "object",
                "additionalProperties": False,
                "definitions": {"Text": text},
                "properties": {"v": {"$ref": "#/definitions/Text", "x-content-class": cls, **sib}},
            }
            # Draft-7 (and no $schema): the legacy string target is accepted whatever sits beside it
            for k, dialect in enumerate(
                ({}, {"$schema": "http://json-schema.org/draft-07/schema#"})
            ):
                res = _mini(tmp_path / f"{i}{j}{k}", {**schema, **dialect})
                assert any("/properties/v" in line for line in res.invalid), (sib, cls, dialect)


def test_old_dialect_sibling_definitions_next_to_a_ref_are_not_a_resolution_scope(
    tmp_path: Path,
) -> None:
    text = {
        "x-content-class": "legacy_content",
        "x-content-note": "INV-GAP test",
        "type": "string",
    }
    number = {"type": "number", "x-content-class": "number"}
    for i, (key, dialect) in enumerate(
        (
            ("definitions", {}),
            ("definitions", {"$schema": "http://json-schema.org/draft-07/schema#"}),
            ("$defs", {}),
            ("$defs", {"$schema": "http://json-schema.org/draft-07/schema#"}),
        )
    ):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "definitions": {"Text": text},
            "properties": {
                "v": {
                    "$ref": f"#/{key}/Text" if key == "$defs" else "#/definitions/Text",
                    "x-content-class": "number",
                    key: {"Text": number},
                }
            },
            **dialect,
        }
        if key == "$defs":
            schema["$defs"] = {"Text": text}
        res = _mini(tmp_path / str(i), schema)
        assert any("/properties/v" in line for line in res.invalid), (key, dialect, res.invalid)


def test_old_dialect_nested_definitions_without_an_id_do_not_open_a_resolution_root(
    tmp_path: Path,
) -> None:
    text = {
        "x-content-class": "legacy_content",
        "x-content-note": "INV-GAP test",
        "type": "string",
    }
    number = {"type": "number", "x-content-class": "number"}
    for i, key in enumerate(("definitions", "$defs")):
        for j, dialect in enumerate(({}, {"$schema": "http://json-schema.org/draft-07/schema#"})):
            ref = f"#/{key}/Text"
            schema = {
                "type": "object",
                "additionalProperties": False,
                key: {"Text": text},
                "properties": {
                    "box": {
                        "type": "object",
                        "additionalProperties": False,
                        "x-content-class": "closed_enum",
                        key: {"Text": number},
                        "properties": {"v": {"$ref": ref, "x-content-class": "number"}},
                    }
                },
                **dialect,
            }
            res = _mini(tmp_path / f"{i}{j}", schema)
            assert any("/box/properties/v" in line for line in res.invalid), (key, dialect)
            # with an $id the nested definitions really are the base, so the number is honoured
            schema["properties"]["box"]["$id"] = "https://example.test/box.json"
            ok = _mini(tmp_path / f"id{i}{j}", schema)
            assert not any("/box/properties/v" in line for line in ok.invalid), (key, dialect)
