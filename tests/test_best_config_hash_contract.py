# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Contract tests for the best-config integrity digests.

These bind the frozen constants to the fp2 reference implementation rather than
restating them. A test that only asserted ``max_depth == 100`` would pass while
fp2 enforced something else entirely, which is precisely the class of drift this
contract exists to end: the previous state of the world was a response schema
that pinned the digest FORMAT and nothing about how the digest was produced.
"""

from __future__ import annotations

import json
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from traigent_schema import fp2
from traigent_schema.utils import get_schemas_dir

_OPTIMIZATION = get_schemas_dir() / "optimization"
_CONTRACT = _OPTIMIZATION / "best_config_hash_contract_schema.json"
_BEST_CONFIG_V2 = _OPTIMIZATION / "best_config_v2_schema.json"
_SUBJECT = _OPTIMIZATION / "certificate_subject_schema.json"

# Event timestamps removed by v2. Each one is minted at the moment of an action,
# so leaving any of them in provenance would make an identical republished config
# look new -- the reason v1 had to exclude provenance from spec_hash at all.
_VOLATILE_PROVENANCE_FIELDS = ("published_at", "exported_at", "created_at")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _definitions(path: Path) -> dict[str, Any]:
    return _load(path)["definitions"]


def test_contract_constants_match_the_fp2_reference() -> None:
    """The frozen limits must be fp2's actual limits, not a copy that can drift."""
    canonicalization = _definitions(_CONTRACT)["canonicalization"]["properties"]

    assert canonicalization["profile"]["const"] == "fp2"
    assert canonicalization["max_depth"]["const"] == fp2.MAX_DEPTH


def test_domain_tags_are_one_per_digest_role_and_carry_the_version() -> None:
    definitions = _definitions(_CONTRACT)
    tags = definitions["domain_tag"]["enum"]
    roles = definitions["digest_roles"]["properties"]

    assert len(tags) == len(set(tags)), "a repeated tag would defeat domain separation"
    assert len(tags) == len(roles), "every digest role needs exactly one tag"
    for tag in tags:
        assert tag.endswith(".v1"), f"{tag} must carry the algorithm version"
    for role in roles:
        assert any(tag.endswith(f".{role.removesuffix('_hash')}.v1") for tag in tags)


def test_domain_separator_cannot_collide_with_canonical_output() -> None:
    """`tag || NUL || canonical` is only unambiguous if neither side can contain a raw NUL."""
    for tag in _definitions(_CONTRACT)["domain_tag"]["enum"]:
        assert "\x00" not in tag
        assert tag.isascii()

    # fp2 escapes NUL rather than emitting the byte, so the separator stays unique.
    canonical = fp2.canonicalize({"k": "a\x00b"})
    assert "\\u0000" in canonical
    assert "\x00" not in canonical


def test_rejected_values_are_actually_rejected_by_fp2() -> None:
    """Rejection must be real. Silent coercion yields a digest that looks verified."""
    rejected = set(_definitions(_CONTRACT)["rejected_values"]["items"]["enum"])
    assert {"non_finite_number", "unsafe_integral_number"} <= rejected

    with pytest.raises(fp2.Fp2UnsupportedValue):
        fp2.digest({"n": float("nan")})
    with pytest.raises(fp2.Fp2UnsupportedValue):
        fp2.digest({"n": float("inf")})
    with pytest.raises(fp2.Fp2UnsupportedValue):
        fp2.digest({"n": 2**53})


def test_unsafe_integral_rule_is_language_neutral() -> None:
    """fp2 rejects int 10**20 but accepts float 1e20 -- the same value, two Python types.

    A JS implementation sees one Number for both. If the contract inherited that
    asymmetry, a payload digestible in JavaScript would be rejected in Python, so
    the rule must be stated over the VALUE and not the type.
    """
    with pytest.raises(fp2.Fp2UnsupportedValue):
        fp2.digest({"n": 10**20})

    # Documents the hole this contract must close in validation, above fp2.
    assert fp2.digest({"n": 1e20})


def test_v2_removes_every_event_timestamp_from_provenance() -> None:
    v1 = _load(_OPTIMIZATION / "best_config_schema.json")
    v2 = _load(_BEST_CONFIG_V2)

    v1_provenance = v1["properties"]["provenance"]["properties"]
    v2_provenance = v2["properties"]["provenance"]["properties"]

    for field in _VOLATILE_PROVENANCE_FIELDS:
        assert field in v1_provenance, f"expected v1 to carry {field}"
        assert field not in v2_provenance, f"v2 must not carry the volatile {field}"

    # Only the timestamps go; stable evidence must survive so it can be covered.
    assert set(v1_provenance) - set(v2_provenance) == set(_VOLATILE_PROVENANCE_FIELDS)


def test_v2_provenance_is_stable_under_republication() -> None:
    """The property that lets spec_hash cover provenance instead of excluding it."""
    allowed = set(_load(_BEST_CONFIG_V2)["properties"]["provenance"]["properties"])
    assert not any(field.endswith("_at") for field in allowed)


def test_v1_remains_packaged_for_migration_reads() -> None:
    """Cutover has to read both envelopes; deleting v1 would strand stored rows."""
    assert (_OPTIMIZATION / "best_config_schema.json").is_file()
    assert (
        _load(_OPTIMIZATION / "best_config_schema.json")["properties"]["schema_version"]["const"]
        == "traigent.best_config.v1"
    )
    assert _load(_BEST_CONFIG_V2)["properties"]["schema_version"]["const"] == (
        "traigent.best_config.v2"
    )


def test_certificate_subject_binds_config_hash_not_spec_hash() -> None:
    """The rebinding that dissolves the circularity."""
    subject = _load(_SUBJECT)

    assert "config_hash" in subject["required"]
    assert "spec_hash" not in subject["properties"], (
        "binding spec_hash is what made the certificate a member of its own preimage"
    )
    # Every member required, so a subject can never be silently under-specified.
    assert set(subject["required"]) == set(subject["properties"])
    assert subject["additionalProperties"] is False


def test_certificate_subject_function_ref_is_required_but_nullable() -> None:
    """null asserts 'no function binding'; absence would be ambiguous.

    Expressed as anyOf[$ref to best_config_v2's definition, null] rather than
    a local type: ["string", "null"] with its own maxLength -- see
    test_certificate_subject_refs_v2_definitions_instead_of_duplicating_them
    for why the $ref form is required rather than merely permitted.
    """
    subject = _load(_SUBJECT)
    function_ref = subject["properties"]["function_ref"]
    assert "function_ref" in subject["required"]

    any_of = function_ref["anyOf"]
    assert {"type": "null"} in any_of
    ref_branches = [branch for branch in any_of if "$ref" in branch]
    assert len(ref_branches) == 1
    assert ref_branches[0]["$ref"] == "./best_config_v2_schema.json#/definitions/function_ref"


def test_certificate_subject_refs_v2_definitions_instead_of_duplicating_them() -> None:
    """Schema drift guard: config_id/function_ref must $ref best_config_v2, not repeat its pattern.

    A local copy of the pattern or minLength/maxLength keywords can silently
    diverge from best_config_v2's definition the moment either file is edited
    without the other -- exactly the class of drift this contract exists to
    end (see the module docstring). Requiring a $ref makes that drift
    syntactically impossible rather than merely policed by convention.
    """
    subject_properties = _load(_SUBJECT)["properties"]
    v2_definitions = _definitions(_BEST_CONFIG_V2)

    assert subject_properties["config_id"] == {
        "$ref": "./best_config_v2_schema.json#/definitions/config_id"
    }
    for keyword in ("pattern", "minLength", "maxLength", "not"):
        assert keyword not in subject_properties["config_id"]

    function_ref_ref_branch = next(
        branch for branch in subject_properties["function_ref"]["anyOf"] if "$ref" in branch
    )
    assert function_ref_ref_branch == {
        "$ref": "./best_config_v2_schema.json#/definitions/function_ref"
    }
    for keyword in ("pattern", "minLength", "maxLength"):
        assert keyword not in function_ref_ref_branch

    # The v2 side is the one place the pattern/length constraints are allowed to live.
    assert "pattern" in v2_definitions["config_id"]["not"]
    assert "pattern" in v2_definitions["function_ref"]


def test_manifest_configs_property_names_ref_v2_config_id() -> None:
    """Schema drift guard: manifest keys must be constrained by the same config_id definition."""
    manifest = _load(_OPTIMIZATION / "best_config_manifest_v2_schema.json")
    property_names = manifest["properties"]["configs"]["propertyNames"]
    assert property_names == {"$ref": "./best_config_v2_schema.json#/definitions/config_id"}


def test_unknown_hash_algorithm_has_no_fallback_encoded() -> None:
    """A permissive enum here would license the downgrade path the contract forbids."""
    algorithm = _definitions(_CONTRACT)["hash_algorithm"]
    assert algorithm["enum"] == ["v1"]
    assert "default" not in algorithm


def test_normalization_policy_preserves_customer_content() -> None:
    """NFC/NFD must stay distinct: normalizing a prompt changes what reaches the model."""
    policy = _definitions(_CONTRACT)["normalization_policy"]["properties"]
    assert policy["customer_content"]["const"] == "preserve"

    # Built with unicodedata rather than written as literals: the two forms are
    # visually identical, so a literal pair silently degrades into the same string
    # the moment any editor or pre-commit hook normalizes this file -- and the test
    # would then pass while asserting nothing.
    precomposed = unicodedata.normalize("NFC", "Re\u0301sume\u0301")
    decomposed = unicodedata.normalize("NFD", precomposed)
    assert decomposed != precomposed, "fixture must actually differ"
    assert unicodedata.normalize("NFC", decomposed) == precomposed

    assert fp2.digest({"p": decomposed}) != fp2.digest({"p": precomposed})
    # Keys too: a normalizing canonicalizer would collapse these into one member.
    assert fp2.digest({decomposed: 1}) != fp2.digest({precomposed: 1})
