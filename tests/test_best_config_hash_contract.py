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

    Expressed as a $ref to best_config_v2's shared nullable_function_ref
    definition (anyOf[$ref function_ref, null]) rather than a local
    anyOf/type: ["string", "null"] with its own maxLength -- see
    test_certificate_subject_refs_v2_definitions_instead_of_duplicating_them
    and test_best_config_v2_and_subject_function_ref_share_one_definition
    for why the shared $ref form is required rather than merely permitted.
    """
    subject = _load(_SUBJECT)
    assert "function_ref" in subject["required"]
    assert subject["properties"]["function_ref"] == {
        "$ref": "./best_config_v2_schema.json#/definitions/nullable_function_ref"
    }

    nullable_function_ref = _definitions(_BEST_CONFIG_V2)["nullable_function_ref"]
    any_of = nullable_function_ref["anyOf"]
    assert {"type": "null"} in any_of
    ref_branches = [branch for branch in any_of if "$ref" in branch]
    assert len(ref_branches) == 1
    assert ref_branches[0]["$ref"] == "#/definitions/function_ref"


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

    assert subject_properties["function_ref"] == {
        "$ref": "./best_config_v2_schema.json#/definitions/nullable_function_ref"
    }
    for keyword in ("pattern", "minLength", "maxLength", "anyOf"):
        assert keyword not in subject_properties["function_ref"]

    # The v2 side is the one place the pattern/length constraints are allowed to live.
    assert "pattern" in v2_definitions["config_id"]["not"]
    assert "pattern" in v2_definitions["function_ref"]


def test_best_config_v2_and_subject_function_ref_share_one_definition() -> None:
    """best_config_v2's own function_ref property and subject's must $ref the identical target.

    Proves the hoist actually removed the duplication rather than merely
    matching by coincidence: both properties must point at literally the
    same nullable_function_ref definition, not two definitions with equal
    content.
    """
    v2_properties = _load(_BEST_CONFIG_V2)["properties"]
    subject_properties = _load(_SUBJECT)["properties"]

    assert v2_properties["function_ref"] == {"$ref": "#/definitions/nullable_function_ref"}
    assert subject_properties["function_ref"] == {
        "$ref": "./best_config_v2_schema.json#/definitions/nullable_function_ref"
    }
    assert "environment" in _load(_BEST_CONFIG_V2)["required"]
    assert "function_ref" in _load(_BEST_CONFIG_V2)["required"]


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


# --- mechanical drift: statistical body vs. v1, and the v2 envelope mirror ---

_STATISTICAL_BODY = _OPTIMIZATION / "guarantee_certificate_statistical_body_schema.json"
_GUARANTEE_V1 = _OPTIMIZATION / "guarantee_certificate_schema.json"
_GUARANTEE_V2 = _OPTIMIZATION / "guarantee_certificate_v2_schema.json"
_GUARANTEE_V2_DELTA = _OPTIMIZATION / "guarantee_certificate_v2_delta_schema.json"

# v1 members that are binding or envelope-only and therefore have no
# equivalent in the reusable statistical body: schema_version identifies the
# ENVELOPE, not the statistics, and the other five are exactly the v1 binding
# fields v2's subject replaced (see guarantee_certificate_v2_delta_schema.json's
# own description).
_V1_BINDING_AND_ENVELOPE_ONLY_MEMBERS = frozenset(
    {
        "schema_version",
        "config_id",
        "spec_hash",
        "config_hash",
        "runtime_config_hash",
        "price_snapshot_hash",
    }
)

# Prose-only keys: allowed to differ between v1 and the statistical body
# without breaking constraint equivalence, per the assignment's own framing
# ("after ... normalizing title/$id/description/$comment"). "version" is
# also prose (v1's top-level informational version string; the body has no
# such field at all).
_PROSE_ONLY_KEYS = frozenset({"description", "title", "$comment", "$id", "$schema", "version"})


def _strip_prose(node: Any) -> Any:
    """Recursively drop prose-only keys so two schema fragments can be
    compared on constraints alone."""
    if isinstance(node, dict):
        return {
            key: _strip_prose(value) for key, value in node.items() if key not in _PROSE_ONLY_KEYS
        }
    if isinstance(node, list):
        return [_strip_prose(item) for item in node]
    return node


def test_statistical_body_is_constraint_equivalent_to_v1_after_excluding_binding_fields() -> None:
    """guarantee_certificate_statistical_body_schema.json must not silently drift from v1.

    v1 (guarantee_certificate_schema.json) is READ ONLY here -- this test
    proves the reusable body still says exactly what v1 says about the
    shared statistics, never that v1 itself changed. Constraint-equivalent
    after excluding the binding/envelope-only members and normalizing prose
    (title/$id/description/$comment/version) means: identical member sets
    once those six are excluded, identical required sets once schema_version
    is excluded, and byte-for-byte identical constraint schemas (everything
    except the normalized-away prose keys) for every shared member,
    definition, and the shared allOf accuracy_then_cost rule.
    """
    v1 = _load(_GUARANTEE_V1)
    body = _load(_STATISTICAL_BODY)

    assert v1["type"] == body["type"] == "object"

    v1_only = set(v1["properties"]) - set(body["properties"])
    body_only = set(body["properties"]) - set(v1["properties"])
    assert v1_only == _V1_BINDING_AND_ENVELOPE_ONLY_MEMBERS
    assert body_only == set(), "the statistical body must not carry a member v1 never had"

    assert set(v1["required"]) - set(body["required"]) == {"schema_version"}
    assert set(body["required"]) - set(v1["required"]) == set()

    shared_members = set(v1["properties"]) & set(body["properties"])
    assert shared_members, "expected at least one shared statistical member"
    for member in sorted(shared_members):
        v1_member = _strip_prose(v1["properties"][member])
        body_member = _strip_prose(body["properties"][member])
        assert v1_member == body_member, member

    assert _strip_prose(v1["definitions"]) == _strip_prose(body["definitions"])
    assert _strip_prose(v1["allOf"]) == _strip_prose(body["allOf"])


def test_v2_envelope_mirrors_exactly_the_union_of_its_composed_branches() -> None:
    """guarantee_certificate_v2_schema.json's placeholder properties block must
    track the union of the statistical body and the v2 binding delta exactly.

    The v2 envelope repeats every composed property name with an empty `{}`
    schema (see the file itself) purely so additionalProperties: false can
    close the object over BOTH allOf branches -- draft-07 evaluates
    additionalProperties within each branch, not across an allOf composition,
    so without this mirror a property from either branch would be silently
    rejected. If a future field is added to the statistical body or the v2
    delta without adding it here too, this test fails: the union and the
    mirror would diverge, which is exactly the class of drift a placeholder
    list invites once someone forgets to update it.
    """
    body_members = set(_load(_STATISTICAL_BODY)["properties"])
    delta_members = set(_load(_GUARANTEE_V2_DELTA)["properties"])
    mirrored_members = set(_load(_GUARANTEE_V2)["properties"])

    union = body_members | delta_members
    assert mirrored_members == union
    assert mirrored_members - union == set(), (
        "v2 mirrors a property neither composed branch declares"
    )
    assert union - mirrored_members == set(), (
        "a composed-branch property is missing from the v2 mirror"
    )

    # selected_id is intentionally intersected (not merely mirrored as `{}`)
    # with best_config_v2's config_id definition in the v2 envelope -- see
    # guarantee_certificate_v2_schema.json and
    # test_selected_id_matches_subject_config_id_has_no_violation /
    # test_selected_id_mismatch_is_schema_valid_but_semantically_caught in
    # test_evidence_case_contract.py for the accompanying declared invariant.
    v2_properties = _load(_GUARANTEE_V2)["properties"]
    assert v2_properties["selected_id"] != {}
    assert (
        v2_properties["selected_id"]["$ref"]
        == "./best_config_v2_schema.json#/definitions/config_id"
    )
    non_intersected_mirrors = mirrored_members - {"selected_id"}
    for member in non_intersected_mirrors:
        assert v2_properties[member] == {}, member


def test_v2_envelope_composes_exactly_the_two_expected_branches_and_is_closed() -> None:
    """guarantee_certificate_v2_schema.json's own top-level shape, not just its mirror.

    The property-union mirror test above proves the `properties` placeholder
    block tracks both composed branches; it says nothing about the `allOf`
    that actually pulls those two branches in, or about whether the envelope
    itself stays an object closed to anything outside them. A future edit
    that dropped one `$ref`, added a third, changed `type`, or dropped
    `additionalProperties: false` would leave the property-union mirror test
    green (it only compares property NAME sets) while silently widening or
    narrowing the certificate's actual composed shape.
    """
    v2 = _load(_GUARANTEE_V2)

    assert v2["type"] == "object"
    assert v2["additionalProperties"] is False
    assert v2["allOf"] == [
        {"$ref": "./guarantee_certificate_statistical_body_schema.json"},
        {"$ref": "./guarantee_certificate_v2_delta_schema.json"},
    ]


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
