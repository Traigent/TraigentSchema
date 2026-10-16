# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Label-service contract (docs/labels-v0.md): schemas, crypto vectors, negative cases.

The reference crypto in scripts/labels_reference.py is first proven against the
RFC 9180 Appendix A.1 / A.2 X25519 base-mode vectors, then used to check the
committed conformance vectors.  All keys are TEST-ONLY.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tests._schema_refs import build_registry, load_json, ref_errors
from traigent_schema.utils import get_schemas_dir

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


L = _load("labels_reference")
GEN = _load("generate_label_vectors")
VECTORS = json.loads(
    (ROOT / "traigent_schema" / "data" / "label_vectors_v0.json").read_text("utf-8")
)
RFC = json.loads((ROOT / "tests" / "data" / "rfc9180_x25519_base_vectors.json").read_text("utf-8"))
REGISTRY = build_registry()
BASE = "https://schemas.traigent.ai/labels/"
REFS = VECTORS["refs"]
K = VECTORS["keys"]


def _x(hex_: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(hex_))


def errors(doc: str, pointer: str, instance) -> list[str]:
    return ref_errors(REGISTRY, f"{BASE}{doc}#{pointer}", instance)


# --- RFC 9180 ---------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(RFC))
def test_rfc9180_base_mode_vectors(name: str) -> None:
    aead_id = RFC[name]["aead_id"]
    v = {k: bytes.fromhex(x) for k, x in RFC[name].items() if isinstance(x, str) and k != "source"}
    sk_e, pk_e = L.derive_keypair(v["ikmE"])
    assert pk_e == v["enc"]
    _, pk_r = L.derive_keypair(v["ikmR"])
    assert pk_r == v["pkRm"]
    shared = L._extract_and_expand(L._dh(sk_e, v["pkRm"]), v["enc"] + v["pkRm"])
    assert shared == v["shared_secret"]
    assert L._key_schedule(aead_id, shared, v["info"]) == (v["key"], v["base_nonce"])
    enc, ct = L.hpke_seal(v["pkRm"], v["info"], v["aad"], v["pt"], v["ikmE"], RFC[name]["aead_id"])
    assert (enc, ct) == (v["enc"], v["ct"])
    assert (
        L.hpke_open(_x(RFC[name]["skRm"]), enc, v["info"], v["aad"], ct, RFC[name]["aead_id"])
        == v["pt"]
    )


def test_suite_uses_a_256_bit_aead_key() -> None:
    key, nonce = L._key_schedule(L.AEAD_AES256, bytes(32), b"")
    assert (len(key), len(nonce)) == (32, 12)


# --- committed vectors are reproducible ---------------------------------------------


def test_committed_vectors_match_the_generator() -> None:
    assert GEN.render() == (ROOT / "traigent_schema" / "data" / "label_vectors_v0.json").read_text(
        "utf-8"
    )


# --- envelopes ------------------------------------------------------------------------


def _open(entry: dict, **override):
    args = dict(
        tenant_ref=REFS["tenant_ref"],
        project_ref=REFS["project_ref"],
        purpose=entry["purpose"],
        object_ref=entry["object_ref"],
        revision=entry["revision"],
    )
    args.update(override)
    return L.open_label(_x(K["project_private_hex"]), entry["envelope"], **args)


def test_one_envelope_per_purpose_opens_and_validates() -> None:
    assert [e["purpose"] for e in VECTORS["label_envelopes"]] == [
        "label",
        "knob",
        "choice",
        "metric",
        "template",
    ]
    for entry in VECTORS["label_envelopes"]:
        assert _open(entry) == entry["plaintext"]
        assert errors("label_envelope_schema.json", "", entry["envelope"]) == []
        packed = bytes.fromhex(entry["packed_hex"])
        assert (
            packed[0] == 1 and int.from_bytes(packed[1:5], "big") == entry["envelope"]["key_epoch"]
        )
        assert len(L.unb64u(entry["envelope"]["ciphertext"])) in (48, 80, 144, 272)


@pytest.mark.parametrize(
    "override",
    [
        {"purpose": "metric"},
        {"object_ref": "knobref_00000000000000000000000000000000"},
        {"revision": 99},
        {"tenant_ref": "tenant_00000000000040008000000000000001"},
        {"project_ref": "00000000-0000-4000-8000-000000000002"},
    ],
)
def test_aad_mismatch_is_rejected(override: dict) -> None:
    entry = VECTORS["label_envelopes"][0]
    if override.get("purpose") == entry["purpose"]:
        pytest.skip("same purpose")
    with pytest.raises(L.LabelCryptoError):
        _open(entry, **override)


def test_epoch_and_tamper_are_rejected() -> None:
    entry = VECTORS["label_envelopes"][1]
    wrong_epoch = {**entry["envelope"], "key_epoch": 2}
    with pytest.raises(L.LabelCryptoError):
        L.open_label(
            _x(K["project_private_hex"]),
            wrong_epoch,
            tenant_ref=REFS["tenant_ref"],
            project_ref=REFS["project_ref"],
            purpose=entry["purpose"],
            object_ref=entry["object_ref"],
            revision=entry["revision"],
        )
    ct = bytearray(L.unb64u(entry["envelope"]["ciphertext"]))
    ct[0] ^= 1
    with pytest.raises(L.LabelCryptoError):
        _open({**entry, "envelope": {**entry["envelope"], "ciphertext": L.b64u(bytes(ct))}})
    with pytest.raises(L.LabelCryptoError):
        L.open_label(
            _x(K["member_private_hex"]),
            entry["envelope"],
            tenant_ref=REFS["tenant_ref"],
            project_ref=REFS["project_ref"],
            purpose=entry["purpose"],
            object_ref=entry["object_ref"],
            revision=entry["revision"],
        )


def test_envelope_schema_is_closed_and_bounded() -> None:
    good = VECTORS["label_envelopes"][0]["envelope"]
    assert errors("label_envelope_schema.json", "", {**good, "plaintext": "x"})
    assert errors("label_envelope_schema.json", "", {**good, "version": 2})
    assert errors("label_envelope_schema.json", "", {**good, "ciphertext": "A" * 400})
    assert errors("label_envelope_schema.json", "", {**good, "enc": good["enc"] + "="})


# --- padding --------------------------------------------------------------------------


def test_padding_vectors() -> None:
    for case in VECTORS["padding"]["ok"]:
        padded = L.pad(case["plaintext"])
        assert padded.hex() == case["padded_hex"] and len(padded) == case["bucket"]
        assert case["bucket"] in L.BUCKETS and L.unpad(padded) == case["plaintext"]
    by_name = {c["name"]: c for c in VECTORS["padding"]["ok"]}
    assert by_name["31_bytes_fills_bucket_32"]["bucket"] == 32
    assert by_name["32_bytes_next_bucket_64"]["bucket"] == 64
    assert by_name["255_bytes_max"]["bucket"] == 256


def test_malformed_padding_is_refused() -> None:
    for case in VECTORS["padding"]["malformed"]:
        with pytest.raises(L.LabelCryptoError):
            if case["operation"] == "pad":
                L.pad(case["plaintext"])
            else:
                L.unpad(bytes.fromhex(case["padded_hex"]))


# --- member wrap, recovery wrap, local protection -------------------------------------


def test_member_wrap() -> None:
    wrap = VECTORS["member_wrap"]["wrap"]
    assert errors("label_wrap_schema.json", "/definitions/MemberWrap", wrap) == []
    sk = L.unwrap_from_member(
        _x(K["member_private_hex"]),
        wrap,
        tenant_ref=REFS["tenant_ref"],
        project_ref=REFS["project_ref"],
    )
    assert sk.private_bytes_raw().hex() == K["project_private_hex"]
    with pytest.raises(L.LabelCryptoError):  # addressed to another key
        L.unwrap_from_member(
            _x(K["project_private_hex"]),
            wrap,
            tenant_ref=REFS["tenant_ref"],
            project_ref=REFS["project_ref"],
        )
    with pytest.raises(L.LabelCryptoError):  # info mismatch
        L.unwrap_from_member(
            _x(K["member_private_hex"]),
            wrap,
            tenant_ref=REFS["tenant_ref"],
            project_ref="00000000-0000-4000-8000-000000000002",
        )
    with pytest.raises(L.LabelCryptoError):  # epoch is bound
        L.unwrap_from_member(
            _x(K["member_private_hex"]),
            {**wrap, "epoch": 2},
            tenant_ref=REFS["tenant_ref"],
            project_ref=REFS["project_ref"],
        )


def test_recovery_wraps() -> None:
    secret = bytes.fromhex(K["recovery_secret_hex"])
    for key, expect in (
        ("project_key", K["project_private_hex"]),
        ("root_key", K["root_ed25519_seed_hex"]),
    ):
        wrap = VECTORS["recovery_wraps"][key]
        assert errors("label_wrap_schema.json", "/definitions/RecoveryWrap", wrap) == []
        assert (
            L.recovery_unwrap(
                secret, wrap, tenant_ref=REFS["tenant_ref"], project_ref=REFS["project_ref"]
            ).hex()
            == expect
        )
    wrap = VECTORS["recovery_wraps"]["project_key"]
    with pytest.raises(L.LabelCryptoError):
        L.recovery_unwrap(
            bytes(32), wrap, tenant_ref=REFS["tenant_ref"], project_ref=REFS["project_ref"]
        )
    with pytest.raises(L.LabelCryptoError):
        L.recovery_unwrap(
            secret,
            {**wrap, "epoch": 2},
            tenant_ref=REFS["tenant_ref"],
            project_ref=REFS["project_ref"],
        )


def test_recovery_wrap_subject_is_bound_into_the_aad() -> None:
    secret = bytes.fromhex(K["recovery_secret_hex"])
    project = VECTORS["recovery_wraps"]["project_key"]
    root = VECTORS["recovery_wraps"]["root_key"]
    for wrap, other in ((project, "root_key"), (root, "project_key")):
        with pytest.raises(L.LabelCryptoError):  # same bytes, other subject
            L.recovery_unwrap(
                secret,
                {**wrap, "subject": other},
                tenant_ref=REFS["tenant_ref"],
                project_ref=REFS["project_ref"],
            )
    assert '"subject":"project_key"' in VECTORS["recovery_wraps"]["project_key_aad_jcs"]
    assert '"subject":"root_key"' in VECTORS["recovery_wraps"]["root_key_aad_jcs"]
    assert (
        VECTORS["recovery_wraps"]["project_key_aad_jcs"]
        != VECTORS["recovery_wraps"]["root_key_aad_jcs"]
    )
    with pytest.raises(L.LabelCryptoError):
        L.recovery_aad(REFS["tenant_ref"], REFS["project_ref"], 1, "other")


def test_member_registration_has_no_self_signature() -> None:
    reg = {
        "version": 1,
        "project_ref": REFS["project_ref"],
        "key_id": L.key_id(bytes.fromhex(K["member_public_hex"])),
        "public_key": L.b64u(bytes.fromhex(K["member_public_hex"])),
        "algorithm": "x25519",
        "member_kind": "human",
        "requested_access": "read_write",
    }
    assert errors("label_member_key_schema.json", "/definitions/MemberKeyRegistration", reg) == []
    for field in ("signature", "self_signature", "signer_key_id", "binding"):
        assert errors(
            "label_member_key_schema.json",
            "/definitions/MemberKeyRegistration",
            {**reg, field: "x" * 86},
        )


def test_ref_formats_follow_the_backend() -> None:
    common = "label_common_schema.json"
    for name, prefix in (("TenantRef", "tenant"), ("ProjectRef", "project")):
        good = f"{prefix}_7c0b2f6e5d1a4f3e9a410c2d8e6b1f01"
        assert errors(common, f"/definitions/{name}", good) == []
        assert errors(common, f"/definitions/{name}", "ten_TestVector0001")
        assert errors(common, f"/definitions/{name}", good.upper())
        assert errors(common, f"/definitions/{name}", good + "0")
        assert errors(common, f"/definitions/{name}", "7c0b2f6e-5d1a-4f3e-9a41-0c2d8e6b1f01")
    for name, kind in (
        ("KnobRef", "knob"),
        ("ChoiceRef", "choice"),
        ("MetricRef", "metric"),
        ("AgentRef", "agent"),
        ("DatasetRef", "dataset"),
        ("EvaluationSetRef", "evaluationset"),
        ("EvaluatorRef", "evaluator"),
    ):
        assert errors(common, f"/definitions/{name}", f"{kind}ref_" + "0f" * 16) == []
        assert errors(common, f"/definitions/{name}", f"{kind}ref_" + "0F" * 16)  # lowercase hex
        assert errors(common, f"/definitions/{name}", f"{kind}ref_" + "0f" * 15)  # 32 hex exactly
        assert errors(common, f"/definitions/{name}", "knb_TestVector0001")
    assert errors(common, "/definitions/KnobRef", "metricref_" + "0f" * 16)  # kind is checked
    assert errors(common, "/definitions/ObjectRef", "templateref_" + "0f" * 16) == []
    assert errors(common, "/definitions/ObjectRef", "obj_TestVector0001")
    for entry in VECTORS["label_envelopes"]:
        assert errors(common, "/definitions/ObjectRef", entry["object_ref"]) == []


def test_key_material_fields_are_not_digests() -> None:
    classes = {
        name: load_json(get_schemas_dir() / "labels" / "label_common_schema.json")["definitions"][
            name
        ]["x-content-class"]
        for name in ("PublicKey", "Signature", "Nonce12", "Salt")
    }
    assert set(classes.values()) == {"key_material"}


def test_local_protection_metadata_and_no_secret_fields() -> None:
    lp = VECTORS["local_protection"]
    for key in ("passkey_prf", "passphrase_argon2id"):
        assert (
            errors("label_local_protection_schema.json", "/definitions/LocalProtection", lp[key])
            == []
        )
    ikm = bytes.fromhex(lp["test_only_wrapping_ikm_hex"])
    raw = L.local_unwrap(
        ikm,
        lp["passkey_prf"],
        tenant_ref=REFS["tenant_ref"],
        member_key_id=lp["passkey_prf"]["member_key_id"],
    )
    assert raw.hex() == K["member_private_hex"]
    # a PRF output / passphrase / wrapping key has nowhere to go in the closed schema
    for forbidden in ("prf_output", "prf_results", "passphrase", "wrapping_key", "ikm"):
        assert errors(
            "label_local_protection_schema.json",
            "/definitions/LocalProtection",
            {**lp["passkey_prf"], forbidden: "x"},
        )
    assert errors(
        "label_local_protection_schema.json",
        "/definitions/LocalProtection",
        {**lp["passkey_prf"], "protection": "passphrase_argon2id"},
    )
    bad = copy.deepcopy(lp["passkey_prf"])
    del bad["credential_id"]
    assert errors("label_local_protection_schema.json", "/definitions/LocalProtection", bad)


# --- signed binding chain --------------------------------------------------------------


def _chain(**tweak):
    chain = copy.deepcopy(VECTORS["binding_chain"])
    root_pub = bytes.fromhex(K["root_public_hex"])
    return dict(
        pinned_root_fingerprint=tweak.get("pinned", K["root_fingerprint_sha256"]),
        root_pub=root_pub,
        admin_binding=tweak.get("admin", chain["admin_identity"]),
        project_binding=tweak.get("project", chain["project_key"]),
        member_binding=tweak.get("member", chain["member_key"]),
        tenant_ref=REFS["tenant_ref"],
        project_ref=REFS["project_ref"],
        binding_list=tweak.get("blist", VECTORS["binding_list"]),
        retained_sequence=tweak.get("retained", 1),
        now=tweak.get("now", "2026-10-16T00:00:01Z"),
    )


def test_binding_chain_verifies_and_validates() -> None:
    for binding in VECTORS["binding_chain"].values():
        assert errors("label_key_binding_schema.json", "/definitions/KeyBinding", binding) == []
    L.verify_chain(**_chain())


def test_binding_chain_failures() -> None:
    chain = VECTORS["binding_chain"]
    with pytest.raises(L.LabelCryptoError):
        L.verify_chain(**_chain(pinned="0" * 64))
    tampered = {**chain["project_key"], "epoch": 2}
    with pytest.raises(L.LabelCryptoError):
        L.verify_chain(**_chain(project=tampered))
    swapped_key = {**chain["member_key"], "public_key": chain["project_key"]["public_key"]}
    with pytest.raises(L.LabelCryptoError):  # server key substitution
        L.verify_chain(**_chain(member=swapped_key))
    with pytest.raises(L.LabelCryptoError):  # purposes cannot be exchanged
        L.verify_chain(**_chain(project=chain["member_key"], member=chain["project_key"]))
    with pytest.raises(
        L.LabelCryptoError
    ):  # signed by the wrong key (member signed by root, not admin)
        root_sk = L.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(K["root_ed25519_seed_hex"]))
        body = {
            k: v for k, v in chain["member_key"].items() if k not in ("signature", "signer_key_id")
        }
        forged = L.make_binding(root_sk, bytes.fromhex(K["root_public_hex"]), body)
        L.verify_chain(**_chain(member=forged))
    with pytest.raises(L.LabelCryptoError):
        L.verify_chain(**{**_chain(), "tenant_ref": "tenant_00000000000040008000000000000001"})


def _root_sk():
    return L.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(K["root_ed25519_seed_hex"]))


def _signed_list(**fields):
    body = {
        k: v for k, v in VECTORS["binding_list"].items() if k not in ("signature", "signer_key_id")
    }
    return L.make_binding(_root_sk(), bytes.fromhex(K["root_public_hex"]), {**body, **fields})


def test_binding_list_vector_validates() -> None:
    assert (
        errors(
            "label_key_binding_schema.json", "/definitions/KeyBindingList", VECTORS["binding_list"]
        )
        == []
    )


def test_revoked_retired_admin_cannot_sign_new_project_key() -> None:
    chain = VECTORS["binding_chain"]
    revoked = _signed_list(revoked_key_ids=[chain["admin_identity"]["key_id"]], sequence=2)
    with pytest.raises(L.LabelCryptoError, match="revoked"):
        L.verify_chain(**_chain(blist=revoked, retained=2))


def test_revoked_project_or_member_key_is_rejected() -> None:
    chain = VECTORS["binding_chain"]
    for name in ("project_key", "member_key"):
        revoked = _signed_list(revoked_key_ids=[chain[name]["key_id"]], sequence=2)
        with pytest.raises(L.LabelCryptoError, match="revoked"):
            L.verify_chain(**_chain(blist=revoked, retained=2))


def test_binding_not_yet_active_is_rejected() -> None:
    chain = VECTORS["binding_chain"]
    root_pub = bytes.fromhex(K["root_public_hex"])
    body = {
        k: v for k, v in chain["admin_identity"].items() if k not in ("signature", "signer_key_id")
    }
    future = L.make_binding(_root_sk(), root_pub, {**body, "not_before": "2099-01-01T00:00:00Z"})
    with pytest.raises(L.LabelCryptoError, match="not yet active"):
        L.verify_chain(**_chain(admin=future))
    with pytest.raises(L.LabelCryptoError, match="not yet active"):
        L.verify_chain(**_chain(now="2026-10-15T23:59:59Z"))


def test_binding_list_rollback_and_forgery_are_rejected() -> None:
    with pytest.raises(L.LabelCryptoError, match="sequence"):
        L.verify_chain(**_chain(retained=2))  # list sequence 1 < retained 2
    forged = {**VECTORS["binding_list"], "revoked_key_ids": ["A" * 22]}
    with pytest.raises(L.LabelCryptoError):
        L.verify_chain(**_chain(blist=forged))
    other_tenant = _signed_list(tenant_ref="tenant_" + "0" * 32)
    with pytest.raises(L.LabelCryptoError, match="tenant"):
        L.verify_chain(**_chain(blist=other_tenant))


def test_binding_schema_rules() -> None:
    chain = VECTORS["binding_chain"]
    assert errors(
        "label_key_binding_schema.json",
        "/definitions/KeyBinding",
        {**chain["project_key"], "project_ref": None},
    )
    assert errors(
        "label_key_binding_schema.json",
        "/definitions/KeyBinding",
        {**chain["admin_identity"], "epoch": 1},
    )
    assert errors(
        "label_key_binding_schema.json",
        "/definitions/KeyBinding",
        {**chain["project_key"], "extra": 1},
    )
    assert errors(
        "label_key_binding_schema.json",
        "/definitions/KeyBinding",
        {**chain["project_key"], "purpose": "root"},
    )


def test_jcs_is_rfc8785_for_this_subset() -> None:
    assert (
        L.jcs({"b": 1, "a": [True, None, "x"], "c": {"z": 0, "y": "é"}})
        == '{"a":[true,null,"x"],"b":1,"c":{"y":"é","z":0}}'.encode()
    )
    with pytest.raises(L.LabelCryptoError):
        L.jcs({"a": 1.5})


# --- service bodies, epochs, member keys --------------------------------------------------


def test_label_io_schemas() -> None:
    env = VECTORS["label_envelopes"][0]
    write = {
        "object_ref": env["object_ref"],
        "purpose": "label",
        "base_revision": 0,
        "epoch": 1,
        "envelope": env["envelope"],
    }
    assert errors("label_io_schema.json", "/definitions/LabelWriteRequest", write) == []
    assert errors(
        "label_io_schema.json", "/definitions/LabelWriteRequest", {**write, "purpose": "free_text"}
    )
    assert errors(
        "label_io_schema.json", "/definitions/LabelWriteRequest", {**write, "label": "plain text"}
    )
    assert errors(
        "label_io_schema.json",
        "/definitions/LabelWriteRequest",
        {k: v for k, v in write.items() if k != "epoch"},
    )
    resp = {
        "object_ref": env["object_ref"],
        "purpose": "label",
        "revision": 1,
        "epoch": 1,
        "updated_at": "2026-10-16T00:00:00Z",
    }
    assert errors("label_io_schema.json", "/definitions/LabelWriteResponse", resp) == []
    read = {**resp, "envelope": env["envelope"]}
    assert errors("label_io_schema.json", "/definitions/LabelReadResponse", read) == []
    assert (
        errors(
            "label_io_schema.json",
            "/definitions/LabelListResponse",
            {"items": [read], "next_cursor": None},
        )
        == []
    )


def test_epoch_and_member_schemas() -> None:
    kid = L.key_id(bytes.fromhex(K["member_public_hex"]))
    epoch = {
        "version": 1,
        "project_ref": REFS["project_ref"],
        "epoch": 1,
        "status": "current",
        "reason": "bootstrap",
        "project_key_id": VECTORS["binding_chain"]["project_key"]["key_id"],
        "created_at": "2026-10-16T00:00:00Z",
    }
    assert errors("label_epoch_schema.json", "/definitions/EpochRecord", epoch) == []
    assert errors(
        "label_epoch_schema.json", "/definitions/EpochRecord", {**epoch, "reason": "because"}
    )
    rot = {
        "version": 1,
        "project_ref": REFS["project_ref"],
        "from_epoch": 1,
        "to_epoch": 2,
        "state": "reencrypting",
        "objects_total": 10,
        "objects_reencrypted": 4,
        "started_at": "2026-10-16T00:00:00Z",
        "updated_at": "2026-10-16T00:00:00Z",
    }
    assert errors("label_epoch_schema.json", "/definitions/RotationRecord", rot) == []
    reg = {
        "version": 1,
        "project_ref": REFS["project_ref"],
        "key_id": kid,
        "public_key": L.b64u(bytes.fromhex(K["member_public_hex"])),
        "algorithm": "x25519",
        "member_kind": "machine",
        "requested_access": "write_only",
    }
    assert errors("label_member_key_schema.json", "/definitions/MemberKeyRegistration", reg) == []
    approval = {
        "version": 1,
        "status": "approved",
        "access": "write_only",
        "binding": VECTORS["binding_chain"]["member_key"],
        "updated_at": "2026-10-16T00:00:00Z",
    }
    assert errors("label_member_key_schema.json", "/definitions/MemberKeyApproval", approval) == []


# --- structural guarantees over the new schemas ----------------------------------------------


def _walk(node, path=""):
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            yield from _walk(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}/{i}")


def test_label_schemas_are_closed_and_classed() -> None:
    files = sorted((get_schemas_dir() / "labels").glob("*.json"))
    assert len(files) == 8
    for f in files:
        doc = load_json(f)
        for path, node in _walk(doc):
            if node.get("type") == "object" and "properties" in node:
                assert node.get("additionalProperties") is False, f"{f.name}{path} is not closed"
            if "/if/" in path or "/then/" in path or "/else/" in path:
                continue
            if (
                "/properties/" in path
                and path.rsplit("/", 2)[-2] == "properties"
                and isinstance(node, dict)
            ):
                assert "x-content-class" in node or any(
                    k in node for k in ("$ref", "oneOf", "items")
                ), f"{f.name}{path}"
            assert node.get("x-content-class") != "legacy_content", f"{f.name}{path}"


def test_optimization_additions_validate() -> None:
    knob_a, knob_b = "knobref_" + "a" * 32, "knobref_" + "b" * 32
    choice, metric_a, metric_b = (
        "choiceref_" + "c" * 32,
        "metricref_" + "d" * 32,
        "metricref_" + "e" * 32,
    )
    cfg = {knob_a: choice, knob_b: 4}
    assert errors("label_common_schema.json", "/definitions/ConfigRefMap", cfg) == []
    assert errors(
        "label_common_schema.json", "/definitions/ConfigRefMap", {"temperature": 0.2}
    )  # a name is not a ref
    assert errors(
        "label_common_schema.json",
        "/definitions/ConfigRefMap",
        {knob_a: "gpt-5.2-mini"},
    )
    assert (
        errors(
            "label_common_schema.json",
            "/definitions/MetricValueMap",
            {metric_a: 0.9, metric_b: None},
        )
        == []
    )
    assert errors("label_common_schema.json", "/definitions/MetricValueMap", {"accuracy": 0.9})
    submit = BASE.replace("labels/", "optimization/") + "session_submit_results_request_schema.json"
    ok = {
        "trial_id": "trial_1",
        "metrics": {},
        "config_refs": cfg,
        "metric_values": {metric_a: 0.9},
    }
    assert ref_errors(REGISTRY, submit, ok) == []
    assert ref_errors(REGISTRY, submit, {**ok, "config_refs": {"temperature": 1}})
