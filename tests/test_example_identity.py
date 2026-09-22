# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Tests for traigent.content_identity.v1 (traigent_schema/example_identity.py).

Three kinds of evidence, deliberately separated:

1. INDEPENDENT known answers -- RFC 5869 HKDF test cases, a hand-built
   HMAC preimage, and a Merkle root recomputed with bare hashlib. These can
   fail even if the module and the vectors agree with each other.
2. PROPERTIES the owner ruled on -- order independence, duplicates counted,
   key order irrelevant, no Unicode normalization, conflicting versions warned.
3. CONFORMANCE -- the module reproduces every committed vector (this is the
   harness the JS SDK and the Backend must mirror), and the committed vector
   file is exactly what the generator emits.

Schemas exercised here: content_identity_v1_schema, agent_version_manifest_v1_schema,
run_identity_binding_v1_schema, evaluator_version_manifest_v1_schema.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import random
import warnings
from importlib import resources
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import example_identity as ei

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "traigent_schema" / "schemas"
CONTENT_SCHEMA_PATH = SCHEMAS / "datasets" / "content_identity_v1_schema.json"
AGENT_SCHEMA_PATH = SCHEMAS / "agents" / "agent_version_manifest_v1_schema.json"
RUN_SCHEMA_PATH = SCHEMAS / "execution" / "run_identity_binding_v1_schema.json"
EVALUATOR_SCHEMA_PATH = SCHEMAS / "evaluation" / "evaluator_version_manifest_v1_schema.json"
VECTORS = json.loads(
    resources.files("traigent_schema")
    .joinpath("data", "content_identity_v1_vectors.json")
    .read_text(encoding="utf-8")
)
MASTER_A = bytes(range(32))
TENANT_A = "tenant_0a0a0a0a"
KEYS_A = ei.derive_tenant_keys(MASTER_A, TENANT_A)


def _field(case: dict[str, Any], name: str) -> Any:
    return case[name] if name in case else ei.ABSENT


def _registry() -> Registry:
    resources_list = []
    for path in SCHEMAS.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and isinstance(document.get("$id"), str):
            resources_list.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources_list)


def _validator(path: Path, definition: str) -> Draft7Validator:
    document = json.loads(path.read_text(encoding="utf-8"))
    schema = {"$ref": f"{document['$id']}#/definitions/{definition}"}
    return Draft7Validator(schema, registry=_registry())


# ---------------------------------------------------------------------------
# 1. Independent known answers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ikm", "salt", "info", "length", "okm"),
    [
        (  # RFC 5869 A.1
            "0b" * 22,
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865",
        ),
        (  # RFC 5869 A.3 (zero-length salt and info)
            "0b" * 22,
            "",
            "",
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
            "9d201395faa4b61a96c8",
        ),
    ],
)
def test_hkdf_matches_rfc5869_known_answers(
    ikm: str, salt: str, info: str, length: int, okm: str
) -> None:
    derived = ei.hkdf_sha256(
        bytes.fromhex(ikm), salt=bytes.fromhex(salt), info=bytes.fromhex(info), length=length
    )
    assert derived.hex() == okm


def test_example_id_matches_a_hand_built_preimage() -> None:
    prk = hmac.new(b"traigent.content_identity.v1", MASTER_A, hashlib.sha256).digest()
    tenant = b"\x00" + TENANT_A.encode()
    key = hmac.new(
        prk, b"traigent.content_identity.example_id.v1" + tenant + b"\x01", hashlib.sha256
    ).digest()
    kid = hmac.new(
        prk, b"traigent.content_identity.key_id.v1" + tenant + b"\x01", hashlib.sha256
    )
    preimage = b'traigent.content_identity.example_id.v1\x00{"input":{"a":1,"b":[true,null]}}'
    expected = f"ex1:k{kid.hexdigest()[:16]}:{hmac.new(key, preimage, hashlib.sha256).hexdigest()}"
    assert ei.compute_example_id(KEYS_A, {"b": [True, None], "a": 1}) == expected


def test_multiset_root_matches_an_independent_merkle_recomputation() -> None:
    pairs = [ei.identify_example(KEYS_A, ei.ExampleProjection(input=i)) for i in range(3)]
    root = ei.compute_multiset_root(pairs)

    def leaf(member: ei.MultisetMember) -> bytes:
        body = json.dumps(
            [member.example_id, member.example_version, member.count], separators=(",", ":")
        ).encode()
        return hashlib.sha256(b"\x00traigent.content_identity.multiset_leaf.v1\x00" + body).digest()

    ordered = sorted(pairs)
    members = [ei.MultisetMember(i, v, 1) for i, v in ordered]
    left = hashlib.sha256(b"\x01" + leaf(members[0]) + leaf(members[1])).digest()
    expected = hashlib.sha256(b"\x01" + left + leaf(members[2])).hexdigest()
    assert root.root == f"msr1:{KEYS_A.key_id}:{expected}"


def test_empty_multiset_root_is_sha256_of_nothing() -> None:
    root = ei.compute_multiset_root([], key_id=KEYS_A.key_id)
    assert root.root.endswith(hashlib.sha256(b"").hexdigest())
    assert (root.distinct_count, root.total_count) == (0, 0)


# ---------------------------------------------------------------------------
# 2. Properties
# ---------------------------------------------------------------------------


def _pairs(n: int) -> list[tuple[str, str]]:
    return [
        ei.identify_example(KEYS_A, ei.ExampleProjection(input={"i": i}, expected=str(i)))
        for i in range(n)
    ]


def test_root_is_order_free() -> None:
    pairs = _pairs(17) + _pairs(5)  # with duplicates
    expected = ei.compute_multiset_root(pairs).root
    rng = random.Random(20260923)
    for _ in range(25):
        shuffled = pairs[:]
        rng.shuffle(shuffled)
        assert ei.compute_multiset_root(shuffled).root == expected


def test_duplicates_are_counted_not_collapsed() -> None:
    a, b = _pairs(2)
    twice = ei.compute_multiset_root([a, a, b])
    once = ei.compute_multiset_root([a, b])
    explicit = ei.compute_multiset_root([(*a, 2), b])
    assert twice.root == explicit.root
    assert twice.root != once.root
    assert (twice.distinct_count, twice.total_count) == (2, 3)


def test_input_key_order_is_irrelevant_but_unicode_is_not_normalized() -> None:
    assert ei.compute_example_id(KEYS_A, {"x": 1, "y": 2}) == ei.compute_example_id(
        KEYS_A, {"y": 2, "x": 1}
    )
    assert ei.compute_example_id(KEYS_A, "caf\u00e9") != ei.compute_example_id(
        KEYS_A, "cafe\u0301"
    )


def test_label_change_keeps_id_and_changes_version() -> None:
    projection = ei.ExampleProjection(input={"q": "x"}, expected="a")
    relabelled = ei.ExampleProjection(input={"q": "x"}, expected="b")
    id1, v1 = ei.identify_example(KEYS_A, projection)
    id2, v2 = ei.identify_example(KEYS_A, relabelled)
    assert id1 == id2 and v1 != v2


def test_conflicting_versions_warn_and_are_reported() -> None:
    eid = ei.compute_example_id(KEYS_A, "q")
    v1 = ei.compute_example_version(KEYS_A, eid, expected="a")
    v2 = ei.compute_example_version(KEYS_A, eid, expected="b")
    with pytest.warns(ei.ConflictingExampleVersionsWarning):
        root = ei.compute_multiset_root([(eid, v1), (eid, v2)])
    assert root.conflicting_example_ids == (eid,)


def test_no_warning_without_conflicts() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        ei.compute_multiset_root(_pairs(4))


def test_tenants_and_rotations_are_unlinkable() -> None:
    other = ei.derive_tenant_keys(bytes(range(1, 33)), TENANT_A)
    assert other.key_id != KEYS_A.key_id
    assert ei.compute_example_id(other, "q").split(":")[2] != ei.compute_example_id(
        KEYS_A, "q"
    ).split(":")[2]


def test_mixing_key_ids_is_rejected() -> None:
    other = ei.derive_tenant_keys(bytes(range(1, 33)), TENANT_A)
    mine = _pairs(1)[0]
    theirs = ei.identify_example(other, ei.ExampleProjection(input="q"))
    with pytest.raises(ei.ContentIdentityError):
        ei.compute_multiset_root([mine, theirs])
    with pytest.raises(ei.ContentIdentityError):
        ei.compute_example_version(other, mine[0], expected="x")


@pytest.mark.parametrize("count", [0, -1, 2**53, True, 1.0])
def test_member_count_bounds(count: Any) -> None:
    eid, ver = _pairs(1)[0]
    with pytest.raises(ei.ContentIdentityError):
        ei.MultisetMember(eid, ver, count)


def test_keys_never_appear_in_repr() -> None:
    text = repr(KEYS_A)
    assert KEYS_A.example_id_key.hex() not in text
    assert "example_id_key" not in text


def test_errors_never_echo_user_content() -> None:
    secret = "PATIENT-4471 has condition X"
    with pytest.raises(ei.ContentIdentityError) as info:
        ei.compute_example_id(KEYS_A, {"q": secret, "n": float("nan")})
    assert secret not in str(info.value)
    with pytest.raises(ei.ContentIdentityError) as info:
        ei.parse_strict_json(json.dumps({secret: 1})[:-1] + f', "{secret}": 2}}')
    assert secret not in str(info.value)


def test_reserved_metadata_is_rejected_by_the_primitive() -> None:
    eid = ei.compute_example_id(KEYS_A, "q")
    for key in sorted(ei.RESERVED_METADATA_KEYS):
        with pytest.raises(ei.ContentIdentityError):
            ei.compute_example_version(KEYS_A, eid, metadata={key: 1})


@pytest.mark.parametrize("bad", [b"", bytes(31), bytes(33), "0" * 32])
def test_tenant_master_must_be_32_bytes(bad: Any) -> None:
    with pytest.raises(ei.ContentIdentityError):
        ei.derive_tenant_keys(bad, TENANT_A)


def test_reused_master_across_tenants_still_gives_unrelated_keys() -> None:
    other = ei.derive_tenant_keys(MASTER_A, "tenant_0c0c0c0c")
    assert other.key_id != KEYS_A.key_id
    assert other.example_id_key != KEYS_A.example_id_key
    assert other.example_version_key != KEYS_A.example_version_key


@pytest.mark.parametrize("bad", ["", "tenant:1", "t" * 129, "tenant_\u00e9", None, b"t"])
def test_tenant_id_must_be_a_plain_ascii_id(bad: Any) -> None:
    with pytest.raises(ei.ContentIdentityError):
        ei.derive_tenant_keys(MASTER_A, bad)


@pytest.mark.parametrize("n", list(range(1, 34)))
def test_every_inclusion_proof_verifies_and_tampering_fails(n: int) -> None:
    root = ei.compute_multiset_root(_pairs(n))
    for member in root.members:
        proof = ei.build_inclusion_proof(root, member)
        assert ei.verify_inclusion_proof(proof)
        bumped = ei.MultisetMember(member.example_id, member.example_version, member.count + 1)
        assert not ei.verify_inclusion_proof(
            ei.InclusionProof(bumped, proof.leaf_index, proof.tree_size, proof.audit_path,
                              proof.root)
        )
        if proof.audit_path:
            assert not ei.verify_inclusion_proof(
                ei.InclusionProof(member, proof.leaf_index, proof.tree_size,
                                  proof.audit_path[:-1], proof.root)
            )


def test_proof_for_a_non_member_cannot_be_built() -> None:
    root = ei.compute_multiset_root(_pairs(3))
    outsider = ei.MultisetMember(*_pairs(4)[3])
    with pytest.raises(ei.ContentIdentityError):
        ei.build_inclusion_proof(root, outsider)


def test_sub_multiset_and_overlap() -> None:
    pairs = _pairs(6)
    dataset = ei.compute_multiset_root(pairs)
    evaluated = ei.compute_multiset_root(pairs[:3])
    assert ei.is_sub_multiset(evaluated, dataset)
    assert not ei.is_sub_multiset(ei.compute_multiset_root(pairs[:3] * 2), dataset)
    relabelled = [
        (eid, ei.compute_example_version(KEYS_A, eid, expected="changed"))
        for eid, _ in pairs[:2]
    ]
    search = ei.compute_multiset_root(relabelled)
    # Relabelled examples still leak their INPUT: overlap is judged on example_id.
    assert ei.example_id_overlap(search, evaluated) == tuple(sorted(e for e, _ in pairs[:2]))
    assert not ei.is_sub_multiset(search, dataset)


def test_full_dataset_evaluated_once_has_the_dataset_root() -> None:
    pairs = _pairs(5)
    rng = random.Random(7)
    order = pairs[:]
    rng.shuffle(order)
    assert ei.compute_multiset_root(order).root == ei.compute_multiset_root(pairs).root


# ---------------------------------------------------------------------------
# 3. Conformance vectors (mirror this harness in every implementation)
# ---------------------------------------------------------------------------


def _keys_for(tenant: str) -> ei.TenantIdentityKeys:
    row = next(k for k in VECTORS["key_derivation"] if k["tenant"] == tenant)
    return ei.derive_tenant_keys(bytes.fromhex(row["tenant_master_hex"]), row["tenant_id"])


def test_vector_file_is_packaged_current_and_nontrivial() -> None:
    spec = importlib.util.spec_from_file_location(
        "gen_vectors", ROOT / "scripts" / "generate_content_identity_v1_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    committed = (ROOT / "traigent_schema" / "data" / "content_identity_v1_vectors.json").read_text(
        encoding="utf-8"
    )
    assert committed == generator.render(), "run scripts/generate_content_identity_v1_vectors.py"
    assert VECTORS["spec"] == ei.SCHEME
    assert len(VECTORS["examples"]) >= 20 and len(VECTORS["rejections"]) >= 10


def test_vector_constants_match_the_module_and_schema() -> None:
    constants = VECTORS["constants"]
    assert constants["hkdf_salt_utf8"].encode() == ei.HKDF_SALT
    assert sorted(constants["reserved_metadata_keys"]) == sorted(ei.RESERVED_METADATA_KEYS)
    registry = json.loads(CONTENT_SCHEMA_PATH.read_text(encoding="utf-8"))["definitions"][
        "ContentIdentityDomainRegistryV1"
    ]["properties"]
    assert {k: v["const"] for k, v in registry.items()} == constants["domains"]


@pytest.mark.parametrize("case", VECTORS["key_derivation"], ids=lambda c: c["tenant"])
def test_key_derivation_vectors(case: dict[str, Any]) -> None:
    keys = ei.derive_tenant_keys(bytes.fromhex(case["tenant_master_hex"]), case["tenant_id"])
    assert keys.key_id == case["key_id"]
    assert keys.example_id_key.hex() == case["example_id_key_hex"]
    assert keys.example_version_key.hex() == case["example_version_key_hex"]


@pytest.mark.parametrize("case", VECTORS["examples"], ids=lambda c: c["name"])
def test_example_vectors(case: dict[str, Any]) -> None:
    keys = _keys_for(case["tenant"])
    context = _field(case, "context")
    expected = _field(case, "expected")
    metadata = case.get("metadata")
    expect = case["expect"]
    payload = ei.example_id_payload(case["input"], context=context)
    assert ei.canonical_bytes(payload).decode("utf-8") == expect["id_payload_jcs"]
    example_id = ei.compute_example_id(keys, case["input"], context=context)
    assert example_id == expect["example_id"]
    version_payload = ei.example_version_payload(example_id, expected=expected, metadata=metadata)
    assert ei.canonical_bytes(version_payload).decode("utf-8") == expect["version_payload_jcs"]
    assert (
        ei.compute_example_version(keys, example_id, expected=expected, metadata=metadata)
        == expect["example_version"]
    )
    assert (
        ei.compute_public_input_digest(case["input"], context=context)
        == expect["public_input_digest"]
    )


@pytest.mark.parametrize("case", VECTORS["relations"], ids=lambda c: f"{c['a']}~{c['b']}")
def test_relation_vectors(case: dict[str, Any]) -> None:
    by_name = {v["name"]: v["expect"] for v in VECTORS["examples"]}
    same = by_name[case["a"]][case["field"]] == by_name[case["b"]][case["field"]]
    assert same is (case["relation"] == "equal")


@pytest.mark.parametrize("case", VECTORS["projections"], ids=lambda c: c["name"])
def test_projection_vectors(case: dict[str, Any]) -> None:
    given = case["given"]
    projection = ei.project_sdk_example(
        given["input_data"], given.get("expected_output", ei.ABSENT), given.get("metadata")
    )
    expect = case["expect"]
    assert projection.input == expect["input"]
    assert projection.context == expect.get("context", ei.ABSENT)
    assert projection.expected == expect.get("expected", ei.ABSENT)
    assert projection.metadata == expect.get("metadata")


@pytest.mark.parametrize("case", VECTORS["multisets"], ids=lambda c: c["name"])
def test_multiset_vectors(case: dict[str, Any]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ei.ConflictingExampleVersionsWarning)
        root = ei.compute_multiset_root(
            [tuple(item) for item in case["items"]], key_id=case.get("key_id")
        )
    expect = case["expect"]
    assert root.root == expect["root"]
    assert [[m.example_id, m.example_version, m.count] for m in root.members] == expect["members"]
    assert root.distinct_count == expect["distinct_count"]
    assert root.total_count == expect["total_count"]
    assert list(root.conflicting_example_ids) == expect["conflicting_example_ids"]
    assert [ei.multiset_leaf_data(m).hex() for m in root.members] == expect["leaf_data_hex"]


def test_multiset_vector_relations() -> None:
    roots = {m["name"]: m["expect"]["root"] for m in VECTORS["multisets"]}
    assert roots["order_a"] == roots["order_b"]
    assert roots["with_duplicate"] == roots["explicit_count"]
    assert roots["with_duplicate"] != roots["without_duplicate"]


@pytest.mark.parametrize(
    "case",
    VECTORS["inclusion_proofs"],
    ids=lambda c: f"{c['multiset']}-{c['leaf_index']}-{c.get('tamper', 'valid')}",
)
def test_inclusion_proof_vectors(case: dict[str, Any]) -> None:
    proof = ei.InclusionProof(
        member=ei.MultisetMember(*case["member"]),
        leaf_index=case["leaf_index"],
        tree_size=case["tree_size"],
        audit_path=tuple(case["audit_path"]),
        root=case["root"],
    )
    assert ei.verify_inclusion_proof(proof) is case["valid"]


@pytest.mark.parametrize("case", VECTORS["json_text_accepted"], ids=lambda c: c["name"])
def test_json_text_accepted_vectors(case: dict[str, Any]) -> None:
    parsed = ei.parse_strict_json(case["json_text"])
    assert ei.compute_example_id(KEYS_A, parsed["input"]) == case["expect"]["example_id"]
    if case["equals_example"]:
        by_name = {v["name"]: v["expect"] for v in VECTORS["examples"]}
        assert case["expect"]["example_id"] == by_name[case["equals_example"]]["example_id"]


def test_decimal_range_check_is_independent_of_the_decimal_context() -> None:
    import decimal

    with decimal.localcontext() as context:
        context.prec = 5  # a hostile context must not change the verdict
        for text in ("9007199254740991.0000000000001", "-9007199254740991.0000000000001"):
            with pytest.raises(ei.ContentIdentityError):
                ei.parse_strict_json(text)
        assert ei.parse_strict_json("9007199254740990.9999999999999999999") == float(2**53 - 1)


@pytest.mark.parametrize("case", VECTORS["rejections"], ids=lambda c: c["name"])
def test_rejection_vectors(case: dict[str, Any]) -> None:
    with pytest.raises(ei.ContentIdentityError):
        kind = case["kind"]
        if kind == "json_text":
            ei.compute_example_id(KEYS_A, ei.parse_strict_json(case["json_text"])["input"])
        elif kind == "example_version":
            ei.compute_example_version(
                KEYS_A, case["example_id"], expected=case["expected"], metadata=case["metadata"]
            )
        elif kind == "multiset":
            ei.compute_multiset_root([tuple(item) for item in case["items"]])
        elif kind == "key_derivation":
            ei.derive_tenant_keys(bytes.fromhex(case["tenant_master_hex"]), case["tenant_id"])
        elif kind == "example_input":
            ei.compute_example_id(KEYS_A, case["input"])
        elif kind == "agent_build":
            ei.compute_agent_build_digest(case["manifest"])
        elif kind == "agent_build_certifiable":
            ei.compute_agent_build_digest(case["manifest"], certifiable=True)
        elif kind == "evaluator_version":
            ei.compute_evaluator_version_digest(case["manifest"])
        else:  # pragma: no cover - a new kind must be wired here
            pytest.fail(f"unknown rejection kind {kind}")


@pytest.mark.parametrize("case", VECTORS["agent_builds"], ids=lambda c: c["name"])
def test_agent_build_vectors(case: dict[str, Any]) -> None:
    manifest = case["manifest"]
    assert ei.compute_agent_build_digest(manifest) == case["expect"]["build_digest"]
    assert not list(_validator(AGENT_SCHEMA_PATH, "AgentBuildManifestV1").iter_errors(manifest))
    certifiable_errors = list(
        _validator(AGENT_SCHEMA_PATH, "CertifiableAgentBuildManifestV1").iter_errors(manifest)
    )
    if case["expect"]["certifiable"]:
        assert not certifiable_errors
        assert ei.compute_agent_build_digest(manifest, certifiable=True) == (
            case["expect"]["build_digest"]
        )
    else:
        assert certifiable_errors
        with pytest.raises(ei.ContentIdentityError):
            ei.compute_agent_build_digest(manifest, certifiable=True)


def test_every_behaviour_input_changes_the_build_digest() -> None:
    digests = {c["name"]: c["expect"]["build_digest"] for c in VECTORS["agent_builds"]}
    assert digests["full"] == digests["full_reordered"]
    for name in ("config_changed", "helper_changed", "prompt_changed", "tool_changed",
                 "relabelled", "partial_coverage"):
        assert digests[name] != digests["full"], name


@pytest.mark.parametrize("case", VECTORS["evaluator_versions"], ids=lambda c: c["name"])
def test_evaluator_version_vectors(case: dict[str, Any]) -> None:
    manifest = case["manifest"]
    assert (
        ei.compute_evaluator_version_digest(manifest)
        == case["expect"]["evaluator_version_digest"]
    )
    validator = _validator(EVALUATOR_SCHEMA_PATH, "EvaluatorVersionManifestV1")
    assert not list(validator.iter_errors(manifest))


def test_every_score_input_changes_the_evaluator_digest() -> None:
    digests = {
        c["name"]: c["expect"]["evaluator_version_digest"] for c in VECTORS["evaluator_versions"]
    }
    assert digests["base"] == digests["base_reordered_keys"]
    for name in ("orientation_changed", "weight_changed", "judge_model_changed",
                 "judge_config_changed", "dependency_changed", "code_changed", "model_free",
                 "no_helpers"):
        assert digests[name] != digests["base"], name
    # Model-free evaluators: efp2 sees neither of these; the manifest must.
    for name in ("model_free_threshold_changed", "model_free_helper_changed"):
        assert digests[name] != digests["model_free"], name


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path", [CONTENT_SCHEMA_PATH, AGENT_SCHEMA_PATH, RUN_SCHEMA_PATH, EVALUATOR_SCHEMA_PATH]
)
def test_new_schemas_are_meta_valid(path: Path) -> None:
    Draft7Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))


def _dataset_identity(
    root: ei.MultisetRoot, *, members: bool = True, record_state: str = "complete"
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "scheme": ei.SCHEME,
        "record_state": record_state,
        "key_id": root.key_id,
        "dataset_root": root.root,
        "distinct_count": root.distinct_count,
        "total_count": root.total_count,
        "conflicting_example_ids": list(root.conflicting_example_ids),
    }
    if members:
        record["members"] = [
            {"example_id": m.example_id, "example_version": m.example_version, "count": m.count}
            for m in root.members
        ]
    else:
        record["members_ref"] = "blob://dataset/members"
    return record


def test_reference_outputs_validate_against_the_schemas() -> None:
    pairs = _pairs(4)
    dataset = ei.compute_multiset_root(pairs + pairs[:1])
    evaluated = ei.compute_multiset_root(pairs[:2])
    proof = ei.build_inclusion_proof(dataset, dataset.members[0])
    dataset_record = _dataset_identity(dataset)
    dataset_validator = _validator(CONTENT_SCHEMA_PATH, "DatasetIdentityV1")
    assert not list(dataset_validator.iter_errors(dataset_record))
    proof_record = {
        "member": {"example_id": proof.member.example_id,
                   "example_version": proof.member.example_version,
                   "count": proof.member.count},
        "leaf_index": proof.leaf_index,
        "tree_size": proof.tree_size,
        "audit_path": list(proof.audit_path),
        "root": proof.root,
    }
    assert not list(_validator(CONTENT_SCHEMA_PATH, "InclusionProofV1").iter_errors(proof_record))
    binding = _complete_binding(dataset_record, dataset.root, evaluated)
    errors = list(_validator(RUN_SCHEMA_PATH, "RunIdentityBindingV1").iter_errors(binding))
    assert not errors, [e.message for e in errors]


def _agent_version(manifest: dict[str, Any]) -> dict[str, Any]:
    return {"agent_id": manifest["agent_id"],
            "build_digest": ei.compute_agent_build_digest(manifest),
            "manifest": manifest}


def _complete_binding(
    dataset_record: dict[str, Any], dataset_root: str, evaluated: ei.MultisetRoot
) -> dict[str, Any]:
    manifest = VECTORS["agent_builds"][0]["manifest"]
    candidate = next(c["manifest"] for c in VECTORS["agent_builds"]
                     if c["name"] == "config_changed")
    evaluator = VECTORS["evaluator_versions"][0]["manifest"]
    return {
        "scheme": ei.SCHEME,
        "record_state": "complete",
        "run_id": "run_1",
        "agent": _agent_version(manifest),
        "base_head_generation": 3,
        "dataset": dataset_record,
        "evaluator": {"evaluator_id": evaluator["evaluator_id"],
                      "version_digest": ei.compute_evaluator_version_digest(evaluator),
                      "resolution": "witnessed_at_scoring",
                      "manifest": evaluator},
        "trials": [{
            "trial_id": "trial_1",
            "candidate": _agent_version(candidate),
            "evaluated": {
                "scheme": ei.SCHEME, "trial_id": "trial_1", "repetition": 0,
                "key_id": evaluated.key_id, "dataset_root": dataset_root,
                "evaluated_root": evaluated.root, "distinct_count": evaluated.distinct_count,
                "total_count": evaluated.total_count, "members_ref": "blob://trial_1/members",
            },
            "observed_provider_versions": [{
                "provider": "openai", "requested_model": "gpt-4o",
                "response_model": "gpt-4o-2024-08-06", "system_fingerprint": "fp_abc",
            }],
        }],
    }


def _break(binding: dict[str, Any], how: str) -> dict[str, Any]:
    broken = json.loads(json.dumps(binding))
    if how == "no_base_head_generation":
        del broken["base_head_generation"]
    elif how == "no_candidate":
        del broken["trials"][0]["candidate"]
    elif how == "partial_agent":
        broken["agent"]["manifest"]["coverage"] = "partial"
    elif how == "partial_candidate":
        broken["trials"][0]["candidate"]["manifest"]["coverage"] = "partial"
    elif how == "agent_manifest_not_inlined":
        del broken["agent"]["manifest"]
    elif how == "draft_dataset":
        broken["dataset"]["record_state"] = "draft"
    elif how == "evaluator_manifest_not_inlined":
        del broken["evaluator"]["manifest"]
    elif how == "no_trials":
        broken["trials"] = []
    return broken


_COMPLETE_BREAKS = [
    "no_base_head_generation", "no_candidate", "partial_agent", "partial_candidate",
    "agent_manifest_not_inlined", "draft_dataset", "evaluator_manifest_not_inlined", "no_trials",
]


@pytest.mark.parametrize("how", _COMPLETE_BREAKS)
def test_complete_run_binding_requires_full_linkage(how: str) -> None:
    pairs = _pairs(3)
    dataset = ei.compute_multiset_root(pairs)
    evaluated = ei.compute_multiset_root(pairs[:2])
    binding = _complete_binding(_dataset_identity(dataset), dataset.root, evaluated)
    validator = _validator(RUN_SCHEMA_PATH, "RunIdentityBindingV1")
    assert not list(validator.iter_errors(binding))
    broken = _break(binding, how)
    assert list(validator.iter_errors(broken)), how
    # The same record is acceptable as a DRAFT (never certifiable).
    broken["record_state"] = "draft"
    assert not list(validator.iter_errors(broken)), how


def test_record_state_is_required() -> None:
    dataset = ei.compute_multiset_root(_pairs(2))
    record = _dataset_identity(dataset)
    del record["record_state"]
    assert list(_validator(CONTENT_SCHEMA_PATH, "DatasetIdentityV1").iter_errors(record))


def test_dataset_identity_members_xor_reference() -> None:
    dataset = ei.compute_multiset_root(_pairs(2))
    validator = _validator(CONTENT_SCHEMA_PATH, "DatasetIdentityV1")
    by_ref = _dataset_identity(dataset, members=False)
    assert not list(validator.iter_errors(by_ref))
    both = {**_dataset_identity(dataset), "members_ref": "blob://x"}
    assert list(validator.iter_errors(both))
    neither = _dataset_identity(dataset)
    del neither["members"]
    assert list(validator.iter_errors(neither))


def test_supersedes_is_an_annotation_on_the_example_identity() -> None:
    old_id = ei.compute_example_id(KEYS_A, {"q": "typo"})
    new_id, new_version = ei.identify_example(KEYS_A, ei.ExampleProjection(input={"q": "fixed"}))
    record = {"example_id": new_id, "example_version": new_version, "supersedes": old_id}
    assert not list(_validator(CONTENT_SCHEMA_PATH, "ExampleIdentityV1").iter_errors(record))
    assert ei.project_sdk_example({"q": "fixed"}, None, {"supersedes": old_id}).metadata is None


@pytest.mark.parametrize(
    ("definition", "value"),
    [
        ("KeyIdV1", KEYS_A.key_id + "\n"),
        ("ExampleIdV1", ei.compute_example_id(KEYS_A, "q") + "\n"),
        ("MultisetRootV1", ei.compute_multiset_root([], key_id=KEYS_A.key_id).root + "\n"),
        ("PublicInputDigestV1", ei.compute_public_input_digest("q") + "\n"),
        ("Sha256HexV1", "0" * 64 + "\n"),
    ],
)
def test_schema_patterns_reject_a_trailing_newline(definition: str, value: str) -> None:
    assert list(_validator(CONTENT_SCHEMA_PATH, definition).iter_errors(value))
    assert not list(_validator(CONTENT_SCHEMA_PATH, definition).iter_errors(value[:-1]))


def test_every_pattern_in_the_new_schemas_uses_the_portable_end_anchor() -> None:
    def patterns(node: Any) -> list[str]:
        if isinstance(node, dict):
            found = [v for k, v in node.items() if k == "pattern" and isinstance(v, str)]
            return found + [p for v in node.values() for p in patterns(v)]
        if isinstance(node, list):
            return [p for v in node for p in patterns(v)]
        return []

    for path in (CONTENT_SCHEMA_PATH, AGENT_SCHEMA_PATH, RUN_SCHEMA_PATH, EVALUATOR_SCHEMA_PATH):
        for pattern in patterns(json.loads(path.read_text(encoding="utf-8"))):
            assert pattern.endswith("(?![\\s\\S])"), (path.name, pattern)


@pytest.mark.parametrize(
    "value",
    [
        KEYS_A.key_id + "\n",
        "\n" + ei.compute_example_id(KEYS_A, "q"),
        ei.compute_example_id(KEYS_A, "q") + "\n",
    ],
)
def test_key_id_of_uses_full_string_matching(value: str) -> None:
    with pytest.raises(ei.ContentIdentityError):
        ei.key_id_of(value)


def test_key_id_of_is_the_second_colon_field_everywhere() -> None:
    eid, ver = _pairs(1)[0]
    root = ei.compute_multiset_root([(eid, ver)])
    assert ei.key_id_of(eid) == ei.key_id_of(ver) == ei.key_id_of(root.root) == KEYS_A.key_id


@pytest.mark.parametrize(
    ("definition", "value"),
    [
        ("ExampleIdV1", "ex1:k21ab3e05e9431431:" + "A" * 64),  # uppercase hex
        ("ExampleIdV1", "ex1:" + "0" * 64),  # no kid
        ("ExampleVersionV1", "ex1:k21ab3e05e9431431:" + "0" * 64),  # wrong prefix
        ("MultisetRootV1", "msr1:k21ab3e05e9431431:" + "0" * 63),  # truncated
        ("PublicInputDigestV1", "exu1:k21ab3e05e9431431:" + "0" * 64),  # unkeyed has no kid
        ("MultisetMemberV1", {"example_id": "ex1:k21ab3e05e9431431:" + "0" * 64,
                              "example_version": "exv1:k21ab3e05e9431431:" + "0" * 64,
                              "count": 0}),
    ],
)
def test_schema_rejects_malformed_identifiers(definition: str, value: Any) -> None:
    assert list(_validator(CONTENT_SCHEMA_PATH, definition).iter_errors(value))


def test_evaluated_set_needs_members_or_a_reference() -> None:
    root = ei.compute_multiset_root(_pairs(2))
    record = {
        "scheme": ei.SCHEME, "key_id": root.key_id, "dataset_root": root.root,
        "evaluated_root": root.root, "distinct_count": 2, "total_count": 2,
    }
    assert list(_validator(CONTENT_SCHEMA_PATH, "EvaluatedSetV1").iter_errors(record))


def test_agent_manifest_needs_a_revision_or_a_source_digest() -> None:
    manifest = {"manifest_version": 1, "agent_id": "agent_0001",
                "runtime": {"language": "python", "sdk_version": "0.28.0"}}
    assert list(_validator(AGENT_SCHEMA_PATH, "AgentBuildManifestV1").iter_errors(manifest))


@pytest.mark.parametrize(
    "case",
    [c for c in VECTORS["rejections"] if c["kind"] == "agent_build"],
    ids=lambda c: c["name"],
)
def test_schema_also_rejects_the_agent_build_rejection_vectors(case: dict[str, Any]) -> None:
    assert list(
        _validator(AGENT_SCHEMA_PATH, "AgentBuildManifestV1").iter_errors(case["manifest"])
    )


def test_dirty_build_with_source_digest_is_accepted_by_code_and_schema() -> None:
    manifest = {**VECTORS["agent_builds"][0]["manifest"]}
    manifest["code_revision"] = {**manifest["code_revision"], "dirty": True}
    assert ei.compute_agent_build_digest(manifest).startswith("sha256:")
    assert not list(_validator(AGENT_SCHEMA_PATH, "AgentBuildManifestV1").iter_errors(manifest))


def test_evaluated_set_rejects_both_members_and_a_reference() -> None:
    root = ei.compute_multiset_root(_pairs(1))
    member = root.members[0]
    record = {
        "scheme": ei.SCHEME, "key_id": root.key_id, "dataset_root": root.root,
        "evaluated_root": root.root, "distinct_count": 1, "total_count": 1,
        "members": [{"example_id": member.example_id,
                     "example_version": member.example_version, "count": 1}],
        "members_ref": "blob://x",
    }
    validator = _validator(CONTENT_SCHEMA_PATH, "EvaluatedSetV1")
    assert list(validator.iter_errors(record))
    del record["members_ref"]
    assert not list(validator.iter_errors(record))


@pytest.mark.parametrize(
    "value", [float(2**53), 1e16, -1e21, 9007199254740993.0, [1.0, {"k": 2e53}]]
)
def test_in_memory_numbers_beyond_the_safe_range_are_rejected(value: Any) -> None:
    # fp2 alone accepts these floats; content identity must not, or a JS
    # producer (which cannot distinguish them after parsing) would diverge.
    with pytest.raises(ei.ContentIdentityError):
        ei.compute_example_id(KEYS_A, value)


def test_nesting_limit_boundary() -> None:
    def nested(depth: int) -> list[Any]:
        value: list[Any] = []
        for _ in range(depth - 1):
            value = [value]
        return value

    ei.compute_example_id(KEYS_A, nested(99))
    with pytest.raises(ei.ContentIdentityError):
        ei.compute_example_id(KEYS_A, nested(100))


@pytest.mark.parametrize(
    "text", ["9007199254740993", "9007199254740993.0", "1e16", "-1e400", '{"a": [2e53]}']
)
def test_strict_parser_itself_rejects_out_of_range_number_literals(text: str) -> None:
    # Pins the parser layer on its own (the JS SDK must reject at parse time,
    # before JSON.parse rounds the value), independent of canonical_bytes.
    with pytest.raises(ei.ContentIdentityError):
        ei.parse_strict_json(text)


def test_strict_parser_accepts_the_safe_boundary() -> None:
    assert ei.parse_strict_json("[9007199254740991, 9007199254740991.0, -1e-7]") == [
        2**53 - 1, float(2**53 - 1), -1e-7
    ]


@pytest.mark.parametrize("name", ["1accuracy", ".cost", "-x", "a" * 129, "acc\n"])
def test_objective_names_follow_the_canonical_metric_name_pattern(name: str) -> None:
    manifest = {**VECTORS["evaluator_versions"][0]["manifest"],
                "objectives": [{"name": name, "orientation": "maximize", "weight": 1}]}
    with pytest.raises(ei.ContentIdentityError):
        ei.compute_evaluator_version_digest(manifest)
    assert list(
        _validator(EVALUATOR_SCHEMA_PATH, "EvaluatorVersionManifestV1").iter_errors(manifest)
    )
