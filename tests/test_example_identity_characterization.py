"""Characterization tests for the manifest digests and multiset proofs in example_identity.

Pins the observable behaviour of ``compute_agent_build_digest``,
``compute_evaluator_version_digest``, ``compute_multiset_root`` and
``verify_inclusion_proof``: the digest or result returned, the exception type and message
for every rejection, and every warning emitted. The expected values in
tests/data/example_identity_characterization.json were recorded from the implementation
before these functions were split into smaller helpers. The cases reach every branch of
the four functions.
"""

from __future__ import annotations

import dataclasses
from types import ModuleType
from typing import Any

import pytest

from tests._characterization import Case, load_golden, observe
from traigent_schema import example_identity

GOLDEN_FILE = "example_identity_characterization.json"
TARGET = example_identity

KID = "k" + "0123456789abcdef"
OTHER_KID = "k" + "fedcba9876543210"


def _digest(char: str) -> str:
    return "sha256:" + char * 64


def _eid(n: int, kid: str = KID) -> str:
    return f"ex1:{kid}:{n:064x}"


def _ever(n: int, kid: str = KID) -> str:
    return f"exv1:{kid}:{n:064x}"


# ---------------------------------------------------------------------------
# compute_agent_build_digest
# ---------------------------------------------------------------------------


def _agent_manifest(**overrides: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "code_revision": {"commit": "abc", "dirty": False},
        "asset_digests": {
            "helper_modules": {"a.py": _digest("a")},
            "prompts": {},
            "tool_definitions": {"t": _digest("b")},
        },
        "applied_config_digest": _digest("c"),
        "runtime": {"language": "python", "sdk_version": "1.2.3"},
        "coverage": "complete",
    }
    for key, value in overrides.items():
        if value is _DROP:
            manifest.pop(key, None)
        else:
            manifest[key] = value
    return manifest


_DROP = object()


def _agent(manifest: Any, **kwargs: Any) -> Case:
    return lambda m: m.compute_agent_build_digest(manifest, **kwargs)


def _assets(**overrides: Any) -> dict[str, Any]:
    assets: dict[str, Any] = {"helper_modules": {}, "prompts": {}, "tool_definitions": {}}
    assets.update(overrides)
    return assets


AGENT_CASES: dict[str, Case] = {
    "valid_complete": _agent(_agent_manifest()),
    "valid_partial": _agent(_agent_manifest(coverage="partial")),
    "certifiable_complete": _agent(_agent_manifest(), certifiable=True),
    "certifiable_partial": _agent(_agent_manifest(coverage="partial"), certifiable=True),
    "not_a_dict": _agent([("coverage", "complete")]),
    "no_revision_no_source": _agent(_agent_manifest(code_revision=_DROP)),
    "source_digest_only": _agent(
        _agent_manifest(code_revision=_DROP, source_digest=_digest("d"))
    ),
    "revision_none_with_source": _agent(
        _agent_manifest(code_revision=None, source_digest=_digest("d"))
    ),
    "revision_string": _agent(_agent_manifest(code_revision="abc")),
    "dirty_without_source": _agent(_agent_manifest(code_revision={"dirty": True})),
    "dirty_with_source": _agent(
        _agent_manifest(code_revision={"dirty": True}, source_digest=_digest("d"))
    ),
    "dirty_truthy_not_true": _agent(_agent_manifest(code_revision={"dirty": 1})),
    "assets_missing": _agent(_agent_manifest(asset_digests=_DROP)),
    "assets_list": _agent(_agent_manifest(asset_digests=["prompts"])),
    "assets_extra_category": _agent(_agent_manifest(asset_digests=_assets(extra={}))),
    "assets_missing_category": _agent(
        _agent_manifest(asset_digests={"helper_modules": {}, "prompts": {}})
    ),
    "assets_category_not_map": _agent(_agent_manifest(asset_digests=_assets(prompts=[]))),
    "assets_bad_digest": _agent(
        _agent_manifest(asset_digests=_assets(tool_definitions={"t": "sha256:xyz"}))
    ),
    "assets_digest_not_str": _agent(
        _agent_manifest(asset_digests=_assets(helper_modules={"h": 7}))
    ),
    "applied_config_missing": _agent(_agent_manifest(applied_config_digest=_DROP)),
    "applied_config_uppercase": _agent(
        _agent_manifest(applied_config_digest="sha256:" + "A" * 64)
    ),
    "runtime_missing": _agent(_agent_manifest(runtime=_DROP)),
    "runtime_not_dict": _agent(_agent_manifest(runtime="python")),
    "runtime_no_language": _agent(_agent_manifest(runtime={"sdk_version": "1"})),
    "runtime_empty_language": _agent(_agent_manifest(runtime={"language": "", "sdk_version": "1"})),
    "runtime_no_sdk_version": _agent(_agent_manifest(runtime={"language": "python"})),
    "coverage_missing": _agent(_agent_manifest(coverage=_DROP)),
    "coverage_unknown": _agent(_agent_manifest(coverage="full")),
}


# ---------------------------------------------------------------------------
# compute_evaluator_version_digest
# ---------------------------------------------------------------------------


def _evaluator_manifest(**overrides: Any) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "code_digest": _digest("1"),
        "config_digest": _digest("2"),
        "helper_digests": {"h.py": _digest("3")},
        "judge": {"model": "judge-model", "config_digest": _digest("4")},
        "objectives": [
            {"name": "accuracy", "orientation": "maximize", "weight": 1},
            {"name": "cost", "orientation": "minimize", "weight": 0.5},
        ],
        "dependency_versions": {"lib": "1.0"},
    }
    for key, value in overrides.items():
        if value is _DROP:
            manifest.pop(key, None)
        else:
            manifest[key] = value
    return manifest


def _evaluator(manifest: Any) -> Case:
    return lambda m: m.compute_evaluator_version_digest(manifest)


def _objective(name: Any = "accuracy", orientation: Any = "maximize", weight: Any = 1) -> Any:
    return {"name": name, "orientation": orientation, "weight": weight}


EVALUATOR_CASES: dict[str, Case] = {
    "valid": _evaluator(_evaluator_manifest()),
    "valid_null_judge": _evaluator(_evaluator_manifest(judge=None)),
    "valid_empty_helpers": _evaluator(_evaluator_manifest(helper_digests={})),
    "not_a_dict": _evaluator("manifest"),
    "code_digest_missing": _evaluator(_evaluator_manifest(code_digest=_DROP)),
    "config_digest_bad": _evaluator(_evaluator_manifest(config_digest="sha256:00")),
    "helpers_missing": _evaluator(_evaluator_manifest(helper_digests=_DROP)),
    "helpers_list": _evaluator(_evaluator_manifest(helper_digests=[])),
    "helper_value_bad": _evaluator(_evaluator_manifest(helper_digests={"h": "nope"})),
    "judge_absent": _evaluator(_evaluator_manifest(judge=_DROP)),
    "judge_not_dict": _evaluator(_evaluator_manifest(judge="judge-model")),
    "judge_model_missing": _evaluator(
        _evaluator_manifest(judge={"config_digest": _digest("4")})
    ),
    "judge_model_not_str": _evaluator(
        _evaluator_manifest(judge={"model": 3, "config_digest": _digest("4")})
    ),
    "judge_config_digest_bad": _evaluator(_evaluator_manifest(judge={"model": "m"})),
    "objectives_missing": _evaluator(_evaluator_manifest(objectives=_DROP)),
    "objectives_tuple": _evaluator(_evaluator_manifest(objectives=(_objective(),))),
    "objectives_empty": _evaluator(_evaluator_manifest(objectives=[])),
    "objective_not_dict": _evaluator(_evaluator_manifest(objectives=["accuracy"])),
    "objective_name_missing": _evaluator(
        _evaluator_manifest(objectives=[{"orientation": "maximize", "weight": 1}])
    ),
    "objective_name_not_str": _evaluator(_evaluator_manifest(objectives=[_objective(name=5)])),
    "objective_name_bad_start": _evaluator(
        _evaluator_manifest(objectives=[_objective(name="1accuracy")])
    ),
    "objective_name_too_long": _evaluator(
        _evaluator_manifest(objectives=[_objective(name="a" * 129)])
    ),
    "objective_orientation_bad": _evaluator(
        _evaluator_manifest(objectives=[_objective(orientation="max")])
    ),
    "objective_weight_bool": _evaluator(_evaluator_manifest(objectives=[_objective(weight=True)])),
    "objective_weight_str": _evaluator(_evaluator_manifest(objectives=[_objective(weight="1")])),
    "objective_weight_missing": _evaluator(
        _evaluator_manifest(objectives=[{"name": "a", "orientation": "maximize"}])
    ),
    "objectives_unsorted": _evaluator(
        _evaluator_manifest(objectives=[_objective(name="b"), _objective(name="a")])
    ),
    "objectives_duplicate": _evaluator(
        _evaluator_manifest(objectives=[_objective(name="a"), _objective(name="a")])
    ),
    "dependency_versions_missing": _evaluator(_evaluator_manifest(dependency_versions=_DROP)),
    "dependency_versions_list": _evaluator(_evaluator_manifest(dependency_versions=[])),
}


# ---------------------------------------------------------------------------
# compute_multiset_root
# ---------------------------------------------------------------------------


def _root(items: list[Any], **kwargs: Any) -> Case:
    return lambda m: m.compute_multiset_root(items, **kwargs)


MAX_COUNT = example_identity.MAX_COUNT

MULTISET_CASES: dict[str, Case] = {
    "single_pair": _root([(_eid(1), _ever(1))]),
    "repeated_pairs_summed": _root(
        [(_eid(2), _ever(2)), (_eid(1), _ever(1), 3), (_eid(2), _ever(2))]
    ),
    "member_objects": lambda m: m.compute_multiset_root(
        [m.MultisetMember(_eid(5), _ever(5), 2), m.MultisetMember(_eid(4), _ever(4))]
    ),
    "matching_explicit_key_id": _root([(_eid(1), _ever(1))], key_id=KID),
    "empty_without_key_id": _root([]),
    "empty_with_key_id": _root([], key_id=KID),
    "key_id_not_str": _root([], key_id=123),
    "key_id_bad_format": _root([], key_id="k123"),
    "key_id_differs_from_members": _root([(_eid(1), _ever(1))], key_id=OTHER_KID),
    "members_mix_key_ids": _root(
        [(_eid(1), _ever(1)), (_eid(2, OTHER_KID), _ever(2, OTHER_KID))]
    ),
    "conflicting_versions_warn": _root(
        [(_eid(1), _ever(1)), (_eid(1), _ever(2)), (_eid(3), _ever(3)), (_eid(3), _ever(4))]
    ),
    "total_count_at_limit": _root([(_eid(1), _ever(1), MAX_COUNT - 1), (_eid(2), _ever(2), 1)]),
    "total_count_overflow": _root([(_eid(1), _ever(1), MAX_COUNT), (_eid(2), _ever(2), 1)]),
    "bad_item": _root(["not-a-pair"]),
}


# ---------------------------------------------------------------------------
# verify_inclusion_proof
# ---------------------------------------------------------------------------


def _members(n: int) -> list[tuple[str, str, int]]:
    return [(_eid(i + 1), _ever(i + 1), (i % 3) + 1) for i in range(n)]


def _proof_case(size: int, index: int, **changes: Any) -> Case:
    def run(m: ModuleType) -> Any:
        multiset = m.compute_multiset_root(_members(size))
        proof = m.build_inclusion_proof(multiset, multiset.members[index])
        if changes:
            proof = dataclasses.replace(proof, **changes)
        return m.verify_inclusion_proof(proof)

    return run


def _proof_with(size: int, index: int, mutate: Any) -> Case:
    def run(m: ModuleType) -> Any:
        multiset = m.compute_multiset_root(_members(size))
        proof = m.build_inclusion_proof(multiset, multiset.members[index])
        return m.verify_inclusion_proof(mutate(m, proof))

    return run


def _flip_last_hex(text: str) -> str:
    return text[:-1] + ("0" if text[-1] != "0" else "1")


PROOF_CASES: dict[str, Case] = {}
for _size in range(1, 9):
    for _index in range(_size):
        PROOF_CASES[f"valid_size{_size}_index{_index}"] = _proof_case(_size, _index)

PROOF_CASES.update(
    {
        "root_not_str": _proof_case(3, 0, root=None),
        "root_bad_format": _proof_case(3, 0, root="msr1:nope"),
        "root_other_key_id": _proof_with(
            3,
            1,
            lambda m, p: dataclasses.replace(p, root=p.root.replace(KID, OTHER_KID)),
        ),
        "root_hash_wrong": _proof_with(
            5, 2, lambda m, p: dataclasses.replace(p, root=_flip_last_hex(p.root))
        ),
        "leaf_index_bool": _proof_case(2, 0, leaf_index=False),
        "leaf_index_str": _proof_case(2, 0, leaf_index="0"),
        "tree_size_float": _proof_case(2, 0, tree_size=2.0),
        "leaf_index_negative": _proof_case(3, 0, leaf_index=-1),
        "leaf_index_equals_size": _proof_case(3, 2, leaf_index=3),
        "leaf_index_equals_size_single_leaf": _proof_case(1, 0, leaf_index=1),
        "tree_size_inflated_single_leaf": _proof_case(1, 0, tree_size=2),
        "tree_size_inflated_unconsumed": _proof_case(2, 0, tree_size=4),
        "leaf_index_wrong": _proof_case(4, 1, leaf_index=2),
        "tree_size_wrong": _proof_case(5, 4, tree_size=6),
        "audit_node_not_str": _proof_with(
            4, 0, lambda m, p: dataclasses.replace(p, audit_path=(b"\x00" * 32,) + p.audit_path[1:])
        ),
        "audit_node_bad_hex": _proof_with(
            4, 0, lambda m, p: dataclasses.replace(p, audit_path=("zz",) + p.audit_path[1:])
        ),
        "audit_path_extra_node": _proof_with(
            4, 3, lambda m, p: dataclasses.replace(p, audit_path=p.audit_path + ("0" * 64,))
        ),
        "audit_path_short": _proof_with(
            7, 6, lambda m, p: dataclasses.replace(p, audit_path=p.audit_path[:-1])
        ),
        "audit_path_empty_size2": _proof_case(2, 1, audit_path=()),
        "audit_node_tampered": _proof_with(
            6,
            3,
            lambda m, p: dataclasses.replace(
                p, audit_path=(_flip_last_hex(p.audit_path[0]),) + p.audit_path[1:]
            ),
        ),
        "member_count_changed": _proof_with(
            3,
            0,
            lambda m, p: dataclasses.replace(
                p,
                member=m.MultisetMember(p.member.example_id, p.member.example_version, 9),
            ),
        ),
    }
)


ALL_CASES: dict[str, Case] = {
    **{f"agent_build/{k}": v for k, v in AGENT_CASES.items()},
    **{f"evaluator_version/{k}": v for k, v in EVALUATOR_CASES.items()},
    **{f"multiset_root/{k}": v for k, v in MULTISET_CASES.items()},
    **{f"inclusion_proof/{k}": v for k, v in PROOF_CASES.items()},
}


def _golden() -> dict[str, Any]:
    return load_golden(GOLDEN_FILE)


def test_recorded_cases_match_case_list() -> None:
    assert sorted(_golden()) == sorted(ALL_CASES)


@pytest.mark.parametrize("case_id", sorted(ALL_CASES))
def test_case_matches_recorded_output(case_id: str) -> None:
    assert observe(ALL_CASES[case_id], example_identity) == _golden()[case_id]
