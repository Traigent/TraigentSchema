"""Fleet Observe canonical request digest: every shared vector reproduces."""

import hashlib
import json
import re

import pytest

from traigent_schema import fleet_observe_digest as digest
from traigent_schema.utils import get_schemas_dir

DATA = get_schemas_dir().parent / "data" / "fleet_observe"
VECTORS = json.loads((DATA / "request_digest_vectors.json").read_text(encoding="utf-8"))
CANON = json.loads((DATA / "identifier_canonicalization.json").read_text(encoding="utf-8"))
SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


@pytest.mark.parametrize("vector", VECTORS["valid"], ids=lambda v: v["name"])
def test_valid_vector_reproduces(vector):
    got = digest.request_digest(vector["input"])
    assert got == vector["expected_request_digest"]
    assert SHA.match(got)
    assert digest.idempotency_key(got) == vector["expected_idempotency_key"]


@pytest.mark.parametrize("vector", VECTORS["invalid"], ids=lambda v: v["name"])
def test_invalid_vector_is_rejected(vector):
    with pytest.raises(ValueError):
        digest.request_digest(vector["input"])


def test_same_digest_groups_agree_and_other_vectors_are_all_distinct():
    groups: dict[str, set[str]] = {}
    singles: list[str] = []
    for v in VECTORS["valid"]:
        if "same_digest_group" in v:
            groups.setdefault(v["same_digest_group"], set()).add(v["expected_request_digest"])
        else:
            singles.append(v["expected_request_digest"])
    assert all(len(g) == 1 for g in groups.values())
    everything = singles + [d for g in groups.values() for d in g]
    assert len(set(everything)) == len(everything)
    assert {"base", "frac"} <= set(groups)


def test_idempotency_key_is_excluded_from_the_digest():
    base = next(v for v in VECTORS["valid"] if v["name"] == "base")["input"]
    a = digest.request_digest({**base, "idempotency_key": "sha256:" + "1" * 64})
    b = digest.request_digest({**base, "idempotency_key": "sha256:" + "2" * 64})
    assert a == b


def test_idempotency_key_construction_matches_the_spec():
    d = "sha256:" + "ab" * 32
    expected = "sha256:" + hashlib.sha256(b"fleet_idem_v1\x1f" + d.encode()).hexdigest()
    assert digest.idempotency_key(d) == expected


def test_preimage_is_compact_ordered_ascii_json():
    base = next(v for v in VECTORS["valid"] if v["name"] == "base")["input"]
    raw = digest.canonical_preimage(base).decode("ascii")
    assert " " not in raw and "\n" not in raw
    assert raw.startswith('{"v":"fleet_import_request_v1","source_kind":')
    keys = list(json.loads(raw))
    assert keys == [
        "v", "source_kind", "boundary_kind", "boundary_digest",
        "observed_at", "retention_class", "members",
    ]
    assert json.loads(raw)["observed_at"].endswith(".000000Z")


def test_null_parent_sorts_before_any_parent():
    d = lambda c: "sha256:" + c * 64  # noqa: E731
    members = [
        {"member_kind": "credential", "member_digest": d("c"), "parent_member_digest": d("a")},
        {"member_kind": "principal", "member_digest": d("a")},
    ]
    req = {
        "source_kind": "sdk_declaration",
        "boundary": {"boundary_kind": "repository", "boundary_digest": d("1")},
        "observed_at": "2026-11-10T09:00:00Z",
        "members": members,
    }
    got = json.loads(digest.canonical_preimage(req))["members"]
    assert got == [["credential", d("c"), d("a")], ["principal", d("a"), None]]


KEY = bytes.fromhex(CANON["test_key_hex"])


@pytest.mark.parametrize("vector", CANON["vectors"], ids=lambda v: f"{v['role']}-{v['source']}-{v['canonical_id'][:12]}")
def test_identifier_vector_reproduces(vector):
    got = digest.identifier_digest(KEY, vector["role"], vector["source"], vector["canonical_id"])
    assert got == vector["expected_digest"]


def test_identifier_domain_separation_and_key_id():
    a = digest.identifier_digest(KEY, "principal", "sdk_declaration", "x")
    assert a != digest.identifier_digest(KEY, "credential", "sdk_declaration", "x")
    assert a != digest.identifier_digest(KEY, "principal", "aws_iam", "x")
    assert a != digest.identifier_digest(bytes(32), "principal", "sdk_declaration", "x")
    assert digest.key_id(KEY) == CANON["test_key_id"]
    assert re.fullmatch(r"[0-9a-f]{16}", digest.key_id(KEY))


@pytest.mark.parametrize("bad", ["", "a\x1fb", "a\nb", "a\x00b"])
def test_identifier_rejects_empty_and_control_characters(bad):
    with pytest.raises(ValueError):
        digest.identifier_digest(KEY, "principal", "sdk_declaration", bad)


def test_canonicalization_file_names_every_role_for_every_source_rule():
    assert CANON["digest"]["roles"] == ["boundary", "principal", "credential", "workload"]
    for source in CANON["sources"].values():
        assert set(source) <= set(CANON["digest"]["roles"])


def test_member_cap_applies_to_the_original_array_before_collapse():
    member = {"member_kind": "principal", "member_digest": "sha256:" + "a" * 64}
    req = {
        "source_kind": "sdk_declaration",
        "boundary": {"boundary_kind": "repository", "boundary_digest": "sha256:" + "1" * 64},
        "observed_at": "2026-11-10T09:00:00Z",
        "members": [member] * 5000,
    }
    assert digest.request_digest(req)  # exactly 5000 duplicates collapse to one: accepted
    with pytest.raises(ValueError):
        digest.request_digest({**req, "members": [member] * 5001})


def test_omitted_and_explicit_null_parent_are_the_same_vector_group():
    names = {v["name"] for v in VECTORS["valid"] if v.get("same_digest_group") == "base"}
    assert {"base", "explicit_null_parent"} <= names


def test_cycle_vectors_are_present_and_rejected():
    names = {v["name"] for v in VECTORS["invalid"]}
    assert {"two_member_parent_cycle", "three_member_parent_cycle"} <= names


REPO = CANON["repository_vectors"]


@pytest.mark.parametrize("vector", REPO["valid"], ids=lambda v: v["remote"].strip()[:40])
def test_repository_remote_vector_reproduces(vector):
    assert digest.canonical_repository(vector["remote"]) == vector["canonical"]


@pytest.mark.parametrize("remote", REPO["invalid"])
def test_repository_remote_invalid_vector_is_rejected(remote):
    with pytest.raises(ValueError):
        digest.canonical_repository(remote)


def test_repository_forms_of_one_remote_share_one_boundary_digest():
    forms = [
        "https://github.com/acme/agents.git",
        "git@github.com:acme/agents.git",
        "ssh://git@GitHub.com:22/acme/agents.git/",
        "https://user:tok@github.com/acme/agents?x=1#y",
    ]
    ids = {digest.canonical_repository(f) for f in forms}
    assert ids == {"github.com/acme/agents"}
    assert len({digest.identifier_digest(KEY, "boundary", "sdk_declaration", i) for i in ids}) == 1


def test_repository_credentials_never_survive_canonicalization():
    out = digest.canonical_repository("https://user:s3cr3t-token@github.com/acme/agents")
    assert "s3cr3t" not in out and "user" not in out


def test_repository_host_edge_rules():
    # a dotless scp host is valid; exactly one trailing dot is stripped; two are rejected
    assert digest.canonical_repository("git@forge:org/repo.git") == "forge/org/repo"
    assert digest.canonical_repository("https://github.com./a/b") == "github.com/a/b"
    for bad in ("https://github.com../a/b", "git@forge..:org/repo.git"):
        with pytest.raises(ValueError):
            digest.canonical_repository(bad)
    remotes = {v["remote"] for v in REPO["valid"]}
    assert {"git@forge:org/repo.git", "https://github.com./acme/agents"} <= remotes
    assert {"https://github.com../acme/agents", "git@forge..:org/repo.git"} <= set(REPO["invalid"])
