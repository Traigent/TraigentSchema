#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Generate / check the content identity v1 conformance vectors.

The vectors pin the reference implementation (traigent_schema/example_identity.py)
so that the JS SDK, the Python SDK and the Backend can prove byte-for-byte
agreement. They are NOT evidence that the reference is right -- that evidence
is tests/test_example_identity.py (RFC 5869 known answers, an independent
Merkle recomputation, and the order/duplicate/key-order properties).

Usage:
    python3 scripts/generate_content_identity_v1_vectors.py --check   # CI / local gate
    python3 scripts/generate_content_identity_v1_vectors.py --update  # rewrite the file

Changing an expected value in the committed file is a BREAKING change to a
cross-SDK contract: every implementation's ids change. Bump the scheme
version instead.
"""

from __future__ import annotations

import argparse
import json
import sys
import warnings
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from traigent_schema import example_identity as ei  # noqa: E402

VECTORS_PATH = _REPO_ROOT / "traigent_schema" / "data" / "content_identity_v1_vectors.json"

# Fixed, PUBLIC test secrets. Never use these for a real tenant.
# name -> (tenant_id, tenant master hex). tenant_a_rotated is tenant_a after a
# key rotation (same tenant_id, new master). tenant_c_reused_master shares
# tenant_a's master by mistake: binding tenant_id into HKDF info still gives
# it unrelated keys.
TENANTS = {
    "tenant_a": ("tenant_0a0a0a0a", bytes(range(32)).hex()),
    "tenant_a_rotated": ("tenant_0a0a0a0a", bytes(range(1, 33)).hex()),
    "tenant_b": ("tenant_0b0b0b0b", bytes(range(255, 223, -1)).hex()),
    "tenant_c_reused_master": ("tenant_0c0c0c0c", bytes(range(32)).hex()),
}

_Q = {"question": "What is 2+2?", "lang": "en"}


def _nested(depth: int) -> list[Any]:
    """``depth`` nested lists: _nested(1) == [], _nested(2) == [[]]."""
    value: list[Any] = []
    for _ in range(depth - 1):
        value = [value]
    return value


# name, description, tenant, fields. A field key that is absent here is
# ABSENT; a key present with None is JSON null (normalized to absent).
EXAMPLES: list[tuple[str, str, str, dict[str, Any]]] = [
    ("baseline", "Plain object input with expected output.", "tenant_a",
     {"input": dict(_Q), "expected": "4"}),
    ("key_order_permuted", "Same as baseline with input keys inserted in the other order; "
     "must equal baseline (jcs_v1 sorts keys).", "tenant_a",
     {"input": {"lang": "en", "question": "What is 2+2?"}, "expected": "4"}),
    ("expected_changed", "Same input as baseline, different expected output: SAME example_id, "
     "DIFFERENT example_version.", "tenant_a",
     {"input": dict(_Q), "expected": "four"}),
    ("expected_absent", "Baseline input with no expected output.", "tenant_a",
     {"input": dict(_Q)}),
    ("expected_null", "expected: null is the same as absent; must equal expected_absent.",
     "tenant_a", {"input": dict(_Q), "expected": None}),
    ("with_metadata", "Baseline plus version-relevant metadata: same id, different version.",
     "tenant_a", {"input": dict(_Q), "expected": "4",
                  "metadata": {"rubric": "exact match"}}),
    ("metadata_empty", "metadata: {} is the same as absent; must equal baseline.", "tenant_a",
     {"input": dict(_Q), "expected": "4", "metadata": {}}),
    ("with_context", "Baseline plus retrieval context: context is part of the INPUT, so the "
     "example_id differs from baseline.", "tenant_a",
     {"input": dict(_Q), "context": ["Arithmetic facts."], "expected": "4"}),
    ("context_null", "context: null is the same as absent; must equal baseline.", "tenant_a",
     {"input": dict(_Q), "context": None, "expected": "4"}),
    ("context_empty_object", "context: {} is a value, NOT absent; must differ from baseline.",
     "tenant_a", {"input": dict(_Q), "context": {}, "expected": "4"}),
    ("string_input", "Bare string input (Backend input_text shape).", "tenant_a",
     {"input": "What is 2+2?", "expected": "4"}),
    ("list_input", "Multi-turn list input (Backend input_text list shape).", "tenant_a",
     {"input": ["Hi", "What is 2+2?"], "expected": "4"}),
    ("unicode_nfc", "U+00E9 precomposed. No Unicode normalization: differs from unicode_nfd.",
     "tenant_a", {"input": {"q": "caf\u00e9"}}),
    ("unicode_nfd", "e + U+0301 combining acute. Must differ from unicode_nfc.", "tenant_a",
     {"input": {"q": "cafe\u0301"}}),
    ("non_bmp_keys", "Keys U+1F600 and U+FF21: UTF-16 code-unit order puts U+1F600 first.",
     "tenant_a", {"input": {"\uff21": 2, "\U0001f600": 1}}),
    ("escapes_and_controls", "Quote, backslash, newline, tab and U+0001 inside a string.",
     "tenant_a", {"input": {"s": "a\"b\\c\nd\te\u0001f"}}),
    ("floats", "ECMAScript number formatting inside the safe range: 1e-7, 0.1, 1.5e15, "
     "123.456, -0.0 -> 0.", "tenant_a",
     {"input": {"a": 1.5e15, "b": 1e-7, "c": 0.1, "d": 123.456, "e": -0.0}}),
    ("int_one", "Integer 1.", "tenant_a", {"input": {"n": 1}}),
    ("float_one", "Float 1.0 canonicalizes like integer 1 (documented fp2 limit); must equal "
     "int_one.", "tenant_a", {"input": {"n": 1.0}}),
    ("bool_true", "true is not 1; must differ from int_one.", "tenant_a", {"input": {"n": True}}),
    ("max_safe_integer", "2**53-1 is the largest accepted integer.", "tenant_a",
     {"input": {"n": 2**53 - 1}}),
    ("max_safe_float", "9007199254740991.0 (float, = 2**53-1) is accepted and equals the "
     "integer; any number of larger magnitude, float or integer, is rejected.", "tenant_a",
     {"input": {"n": float(2**53 - 1)}}),
    ("nesting_at_limit", "input nested 99 containers deep: with the payload wrapper that is "
     "the jcs_v1 limit of 100, so it is ACCEPTED (100 is rejected, see rejections).",
     "tenant_a", {"input": _nested(99)}),
    ("nested_empty_containers", "Empty object and array nested.", "tenant_a",
     {"input": {"a": {}, "b": [], "c": [{}, []], "d": None}}),
    ("cross_tenant", "Baseline under tenant_b: different kid and different ids.", "tenant_b",
     {"input": dict(_Q), "expected": "4"}),
    ("rotated_key", "Baseline under tenant_a's rotated master: different kid and ids.",
     "tenant_a_rotated", {"input": dict(_Q), "expected": "4"}),
    ("reused_master_other_tenant", "Baseline under tenant_c, which reuses tenant_a's master "
     "by mistake: tenant_id in the HKDF info still gives a different kid and ids.",
     "tenant_c_reused_master", {"input": dict(_Q), "expected": "4"}),
]

RELATIONS: list[tuple[str, str, str, str]] = [
    # (a, b, field, relation)
    ("baseline", "key_order_permuted", "example_id", "equal"),
    ("baseline", "key_order_permuted", "example_version", "equal"),
    ("baseline", "expected_changed", "example_id", "equal"),
    ("baseline", "expected_changed", "example_version", "different"),
    ("expected_absent", "expected_null", "example_version", "equal"),
    ("baseline", "with_metadata", "example_id", "equal"),
    ("baseline", "with_metadata", "example_version", "different"),
    ("baseline", "metadata_empty", "example_version", "equal"),
    ("baseline", "with_context", "example_id", "different"),
    ("baseline", "context_null", "example_id", "equal"),
    ("baseline", "context_empty_object", "example_id", "different"),
    ("baseline", "string_input", "example_id", "different"),
    ("unicode_nfc", "unicode_nfd", "example_id", "different"),
    ("int_one", "float_one", "example_id", "equal"),
    ("max_safe_integer", "max_safe_float", "example_id", "equal"),
    ("int_one", "bool_true", "example_id", "different"),
    ("baseline", "cross_tenant", "example_id", "different"),
    ("baseline", "rotated_key", "example_id", "different"),
    ("baseline", "reused_master_other_tenant", "example_id", "different"),
]

PROJECTIONS: list[tuple[str, str, dict[str, Any]]] = [
    ("plain", "input_data/expected_output/metadata map straight across.",
     {"input_data": {"q": "x"}, "expected_output": "y", "metadata": {"rubric": "r"}}),
    ("reserved_keys_stripped", "Every reserved annotation key is dropped from metadata; "
     "context is lifted into the id payload.",
     {"input_data": {"q": "x"}, "expected_output": "y",
      "metadata": {"context": "ctx", "example_id": "row-7", "external_id": "ext-1",
                   "source_ref": {"platform": "langsmith"}, "tags": ["a"], "split": "test",
                   "splits": ["test"], "difficulty": "hard", "confidence": 0.9,
                   "status": "ok", "score": 1, "explanation": "e", "created_at": "t",
                   "updated_at": "t", "rubric": "kept"}}),
    ("nulls_are_absent", "expected_output None and metadata.context None are absent; "
     "a metadata map left empty after stripping is absent.",
     {"input_data": {"q": "x"}, "expected_output": None,
      "metadata": {"context": None, "tags": ["only annotations"]}}),
]

_BUILD = {
    "manifest_version": 1,
    "agent_id": "agent_0001",
    "label": "v1.3",
    "code_revision": {"vcs": "git", "commit": "0123456789abcdef0123456789abcdef01234567",
                      "dirty": False},
    "source_digest": "sha256:" + "11" * 32,
    "dependency_lock_digest": "sha256:" + "22" * 32,
    "asset_digests": {"prompts/system.txt": "sha256:" + "33" * 32},
    "runtime": {"language": "python", "language_version": "3.12", "sdk_version": "0.28.0"},
}

AGENT_BUILDS: list[tuple[str, str, dict[str, Any]]] = [
    ("full", "A full build manifest.", _BUILD),
    ("full_reordered", "Same manifest, keys in reverse order; must equal full.",
     dict(reversed(list(_BUILD.items())))),
    ("config_applied", "Same build with a configuration applied: a different version.",
     {**_BUILD, "applied_config_digest": "sha256:" + "44" * 32}),
    ("relabelled", "Same bits, different label: a different version by design.",
     {**_BUILD, "label": "v1.4"}),
]

JSON_TEXT_REJECTIONS: list[tuple[str, str, str]] = [
    ("duplicate_key", "Duplicate object key in the input JSON text.",
     '{"input": {"a": 1, "a": 2}}'),
    ("nan_literal", "NaN literal.", '{"input": {"a": NaN}}'),
    ("infinity_literal", "Infinity literal.", '{"input": {"a": Infinity}}'),
    ("float_overflow", "1e400 overflows to Infinity.", '{"input": {"a": 1e400}}'),
    ("integer_above_safe", "2**53 as an integer literal.", '{"input": {"a": 9007199254740992}}'),
    ("integer_below_safe", "-(2**53) as an integer literal.",
     '{"input": {"a": -9007199254740992}}'),
    ("lone_surrogate", "A lone high surrogate escape in a value.",
     '{"input": {"a": "\\ud800"}}'),
    ("lone_surrogate_key", "A lone low surrogate escape in an object KEY.",
     '{"input": {"\\udc00": 1}}'),
    ("integer_2_53_plus_1", "9007199254740993 (2**53+1) as an integer literal: JS JSON.parse "
     "would silently round it to 2**53.", '{"input": {"a": 9007199254740993}}'),
    ("float_literal_2_53_plus_1", "9007199254740993.0: a fractional-form literal outside the "
     "safe range is rejected like the integer form, so JS and Python cannot diverge.",
     '{"input": {"a": 9007199254740993.0}}'),
    ("float_literal_1e16", "1e16: exponent-form literal outside the safe range.",
     '{"input": {"a": 1e16}}'),
]


def _keys(tenant: str) -> ei.TenantIdentityKeys:
    tenant_id, master_hex = TENANTS[tenant]
    return ei.derive_tenant_keys(bytes.fromhex(master_hex), tenant_id)


def _field(fields: dict[str, Any], name: str) -> Any:
    return fields[name] if name in fields else ei.ABSENT


def _example_vector(name: str, description: str, tenant: str, fields: dict[str, Any]) -> dict:
    keys = _keys(tenant)
    input_value = fields["input"]
    context = _field(fields, "context")
    expected = _field(fields, "expected")
    metadata = fields.get("metadata")
    example_id = ei.compute_example_id(keys, input_value, context=context)
    example_version = ei.compute_example_version(
        keys, example_id, expected=expected, metadata=metadata
    )
    vector: dict[str, Any] = {"name": name, "description": description, "tenant": tenant}
    vector.update(fields)
    vector["expect"] = {
        "id_payload_jcs": ei.canonical_bytes(
            ei.example_id_payload(input_value, context=context)
        ).decode("utf-8"),
        "example_id": example_id,
        "version_payload_jcs": ei.canonical_bytes(
            ei.example_version_payload(example_id, expected=expected, metadata=metadata)
        ).decode("utf-8"),
        "example_version": example_version,
        "public_input_digest": ei.compute_public_input_digest(input_value, context=context),
    }
    return vector


def _projection_vector(name: str, description: str, given: dict[str, Any]) -> dict:
    projection = ei.project_sdk_example(
        given["input_data"], given.get("expected_output", ei.ABSENT), given.get("metadata")
    )
    expect: dict[str, Any] = {"input": projection.input}
    if projection.context is not ei.ABSENT:
        expect["context"] = projection.context
    if projection.expected is not ei.ABSENT:
        expect["expected"] = projection.expected
    if projection.metadata is not None:
        expect["metadata"] = projection.metadata
    return {"name": name, "description": description, "given": given, "expect": expect}


def _members_json(root: ei.MultisetRoot) -> list[list[Any]]:
    return [[m.example_id, m.example_version, m.count] for m in root.members]


def build_vectors() -> dict[str, Any]:
    examples = [_example_vector(*row) for row in EXAMPLES]
    by_name = {v["name"]: v["expect"] for v in examples}

    def pair(name: str) -> list[str]:
        return [by_name[name]["example_id"], by_name[name]["example_version"]]

    relations = []
    for a, b, field_name, relation in RELATIONS:
        actual = "equal" if by_name[a][field_name] == by_name[b][field_name] else "different"
        if actual != relation:
            raise SystemExit(f"relation {a} vs {b} on {field_name}: expected {relation}")
        relations.append({"a": a, "b": b, "field": field_name, "relation": relation})

    # Distinct examples for multisets (tenant_a only).
    base = pair("baseline")
    changed = pair("expected_changed")  # same id as base, other version
    others = [pair(n) for n in ("string_input", "list_input", "unicode_nfc", "unicode_nfd",
                                "non_bmp_keys", "floats", "int_one")]
    multiset_cases: list[tuple[str, str, list[list[Any]]]] = [
        ("single", "One member.", [base]),
        ("two", "Two distinct members.", [base, others[0]]),
        ("order_a", "Five members in one order.", [base, *others[:4]]),
        ("order_b", "Same five members reversed; must equal order_a.",
         list(reversed([base, *others[:4]]))),
        ("with_duplicate", "base listed twice plus one other: base counted 2.",
         [base, others[0], base]),
        ("explicit_count", "base with explicit count 2 plus one other; must equal "
         "with_duplicate.", [[*base, 2], others[0]]),
        ("without_duplicate", "base once plus one other; must DIFFER from with_duplicate "
         "(multiset, not set).", [base, others[0]]),
        ("conflicting_versions", "One example_id with two versions: root defined, conflict "
         "reported.", [base, changed, others[0]]),
        ("seven", "Seven members (unbalanced tree).", [base, *others[:6]]),
        ("eight", "Eight members (complete tree).", [base, *others]),
    ]
    multisets = []
    roots: dict[str, ei.MultisetRoot] = {}
    for name, description, items in multiset_cases:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ei.ConflictingExampleVersionsWarning)
            root = ei.compute_multiset_root([tuple(item) for item in items])
        roots[name] = root
        multisets.append({
            "name": name,
            "description": description,
            "items": items,
            "expect": {
                "root": root.root,
                "members": _members_json(root),
                "distinct_count": root.distinct_count,
                "total_count": root.total_count,
                "conflicting_example_ids": list(root.conflicting_example_ids),
                "leaf_data_hex": [ei.multiset_leaf_data(m).hex() for m in root.members],
            },
        })
    empty = ei.compute_multiset_root([], key_id=_keys("tenant_a").key_id)
    multisets.append({
        "name": "empty",
        "description": "Empty multiset: RFC 9162 MTH of no leaves = SHA-256 of the empty "
                       "string; needs an explicit key_id.",
        "items": [],
        "key_id": empty.key_id,
        "expect": {"root": empty.root, "members": [], "distinct_count": 0, "total_count": 0,
                   "conflicting_example_ids": [], "leaf_data_hex": []},
    })

    proofs = []
    for name in ("seven", "conflicting_versions"):
        root = roots[name]
        for member in root.members:
            proof = ei.build_inclusion_proof(root, member)
            proofs.append({
                "multiset": name,
                "member": [member.example_id, member.example_version, member.count],
                "leaf_index": proof.leaf_index,
                "tree_size": proof.tree_size,
                "audit_path": list(proof.audit_path),
                "root": proof.root,
                "valid": True,
            })
    good = proofs[2]
    tampered = [
        ("wrong_count", {**good, "member": [*good["member"][:2], good["member"][2] + 1]}),
        ("wrong_index", {**good, "leaf_index": good["leaf_index"] + 1}),
        # No "wrong tree_size" case: RFC 9162 proofs do not authenticate tree_size for
        # a leaf inside a complete left subtree (7 -> 8 verifies identically). The
        # relying party takes tree_size from the signed record (distinct_count).
        ("flipped_path_node", {**good, "audit_path": [
            ("0" if good["audit_path"][0][0] != "0" else "1") + good["audit_path"][0][1:],
            *good["audit_path"][1:]]}),
        ("truncated_path", {**good, "audit_path": good["audit_path"][:-1]}),
    ]
    for label, case in tampered:
        proof = ei.InclusionProof(
            member=ei.MultisetMember(*case["member"]),
            leaf_index=case["leaf_index"],
            tree_size=case["tree_size"],
            audit_path=tuple(case["audit_path"]),
            root=case["root"],
        )
        if ei.verify_inclusion_proof(proof):
            raise SystemExit(f"tampered proof {label} verified")
        proofs.append({**case, "valid": False, "tamper": label})

    rejections = []
    keys_a = _keys("tenant_a")
    for name, description, text in JSON_TEXT_REJECTIONS:
        try:
            ei.compute_example_id(keys_a, ei.parse_strict_json(text)["input"])
        except ei.ContentIdentityError:
            pass
        else:
            raise SystemExit(f"rejection {name} was accepted")
        rejections.append({"name": name, "description": description, "kind": "json_text",
                           "json_text": text})
    rejections.extend([
        {"name": "reserved_metadata_key", "kind": "example_version",
         "description": "compute_example_version with a reserved annotation key in metadata "
                        "(caller skipped the projection).",
         "example_id": by_name["baseline"]["example_id"], "expected": "4",
         "metadata": {"tags": ["x"]}},
        {"name": "zero_count", "kind": "multiset",
         "description": "A member count of 0.", "items": [[*base, 0]]},
        {"name": "mixed_key_ids", "kind": "multiset",
         "description": "Members minted under two key ids.",
         "items": [base, pair("rotated_key")]},
        {"name": "short_tenant_master", "kind": "key_derivation",
         "description": "A 31-byte tenant master secret.", "tenant_master_hex": "00" * 31,
         "tenant_id": "tenant_0a0a0a0a"},
        {"name": "tenant_id_with_colon", "kind": "key_derivation",
         "description": "tenant_id outside ^[A-Za-z0-9_-]{1,128}$.",
         "tenant_master_hex": TENANTS["tenant_a"][1], "tenant_id": "tenant:0a"},
        {"name": "tenant_id_empty", "kind": "key_derivation",
         "description": "Empty tenant_id.", "tenant_master_hex": TENANTS["tenant_a"][1],
         "tenant_id": ""},
        {"name": "tenant_id_non_ascii", "kind": "key_derivation",
         "description": "Non-ASCII tenant_id (U+00E9).",
         "tenant_master_hex": TENANTS["tenant_a"][1], "tenant_id": "tenant_\u00e9"},
        {"name": "nesting_over_limit", "kind": "example_input",
         "description": "input nested 100 containers deep: 101 with the payload wrapper, over "
                        "the jcs_v1 limit of 100 (nesting_at_limit, 99, is accepted).",
         "input": _nested(100)},
        {"name": "agent_build_dirty_without_source_digest", "kind": "agent_build",
         "description": "code_revision.dirty=true without source_digest: two different dirty "
                        "trees on one commit would share a build_digest.",
         "manifest": {**{k: v for k, v in _BUILD.items() if k != "source_digest"},
                      "code_revision": {**_BUILD["code_revision"], "dirty": True}}},
        {"name": "agent_build_without_revision_or_source", "kind": "agent_build",
         "description": "Neither code_revision nor source_digest: identifies nothing.",
         "manifest": {k: v for k, v in _BUILD.items()
                      if k not in ("code_revision", "source_digest")}},
    ])

    key_derivation = []
    for tenant, (tenant_id, master_hex) in TENANTS.items():
        keys = _keys(tenant)
        key_derivation.append({
            "tenant": tenant,
            "tenant_id": tenant_id,
            "tenant_master_hex": master_hex,
            "key_id": keys.key_id,
            "example_id_key_hex": keys.example_id_key.hex(),
            "example_version_key_hex": keys.example_version_key.hex(),
        })

    return {
        "spec": ei.SCHEME,
        "note": (
            "Conformance vectors for traigent.content_identity.v1 (docs/identity/"
            "content-identity-v1.md). Generated by scripts/generate_content_identity_v1_"
            "vectors.py from traigent_schema/example_identity.py; do not hand-edit. Tenant "
            "master secrets here are PUBLIC TEST VALUES. In 'examples', a field that is "
            "absent means ABSENT and a field set to null means null, which the spec "
            "normalizes to absent for context, expected and metadata. 'rejections' of kind "
            "json_text must be fed through the implementation's STRICT JSON text parser "
            "(JSON.parse alone keeps the last duplicate key and rounds big integers), then "
            "example_id must be computed from the parsed 'input'; every step may raise but "
            "none may yield an id."
        ),
        "constants": {
            "hkdf_salt_utf8": ei.HKDF_SALT.decode("ascii"),
            "hkdf_info": "UTF8(domain) || 0x00 || UTF8(tenant_id)",
            "tenant_id_pattern": "^[A-Za-z0-9_-]{1,128}$",
            "domains": {
                "agent_build": ei.DOMAIN_AGENT_BUILD,
                "example_id": ei.DOMAIN_EXAMPLE_ID,
                "example_version": ei.DOMAIN_EXAMPLE_VERSION,
                "key_id": ei.DOMAIN_KEY_ID,
                "multiset_leaf": ei.DOMAIN_MULTISET_LEAF,
                "public_input": ei.DOMAIN_PUBLIC_INPUT,
            },
            "reserved_metadata_keys": sorted(ei.RESERVED_METADATA_KEYS),
        },
        "key_derivation": key_derivation,
        "examples": examples,
        "relations": relations,
        "projections": [_projection_vector(*row) for row in PROJECTIONS],
        "multisets": multisets,
        "inclusion_proofs": proofs,
        "rejections": rejections,
        "agent_builds": [
            {"name": name, "description": description, "manifest": manifest,
             "expect": {"build_digest": ei.compute_agent_build_digest(manifest)}}
            for name, description, manifest in AGENT_BUILDS
        ],
    }


def render() -> str:
    return json.dumps(build_vectors(), indent=2, ensure_ascii=True) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--update", action="store_true")
    args = parser.parse_args()
    rendered = render()
    if args.update:
        VECTORS_PATH.write_text(rendered, encoding="utf-8")
        print(f"wrote {VECTORS_PATH.relative_to(_REPO_ROOT)}")
        return 0
    current = VECTORS_PATH.read_text(encoding="utf-8") if VECTORS_PATH.exists() else ""
    if current != rendered:
        print("content identity vectors are stale; run --update and review the diff")
        return 1
    print("content identity vectors are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
