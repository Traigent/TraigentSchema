#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Generate / check the label-service conformance vectors (docs/labels-v0.md).

Every key, seed and secret in the output is a TEST-ONLY value derived from a public
constant string.  None of them protects anything; never use them outside tests.

Usage:
    python3 scripts/generate_label_vectors.py --check    # CI / local gate
    python3 scripts/generate_label_vectors.py --update   # rewrite the file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
import labels_reference as L  # noqa: E402

VECTORS_PATH = (
    Path(__file__).resolve().parent.parent / "traigent_schema" / "data" / "label_vectors_v0.json"
)

# Tenant and project ids are UUIDs in the Backend; the other refs follow its
# ``<kind>ref_<32 hex>`` convention.  All values here are TEST-ONLY.
TENANT = "7c0b2f6e-5d1a-4f3e-9a41-0c2d8e6b1f01"
PROJECT = "3a9e4d10-8b27-4c65-b1f2-5e7a90c4d202"
OBJECT_KIND = {
    "label": "agent",
    "knob": "knob",
    "choice": "choice",
    "metric": "metric",
    "template": "template",
}
NOW = "2026-10-16T00:00:00Z"


def seed(name: str) -> bytes:
    return hashlib.sha256(b"traigent.label.TEST-ONLY-VECTOR-SEED.v0/" + name.encode()).digest()


def test_ref(kind: str, name: str) -> str:
    return f"{kind}ref_" + seed("ref/" + kind + "/" + name)[:16].hex()


def build() -> dict:
    root_sk = Ed25519PrivateKey.from_private_bytes(seed("root"))
    root_pub = L.ed25519_raw_public(root_sk)
    admin_sk = Ed25519PrivateKey.from_private_bytes(seed("admin"))
    admin_pub = L.ed25519_raw_public(admin_sk)
    proj_sk, proj_pub = L.derive_keypair(seed("project-epoch-1"))
    mem_sk, mem_pub = L.derive_keypair(seed("member"))
    epoch = 1

    admin_binding = L.make_binding(
        root_sk,
        root_pub,
        {
            "version": 1,
            "tenant_ref": TENANT,
            "project_ref": None,
            "epoch": None,
            "purpose": "admin_identity",
            "key_id": L.key_id(admin_pub),
            "public_key": L.b64u(admin_pub),
            "not_before": NOW,
        },
    )
    project_binding = L.make_binding(
        admin_sk,
        admin_pub,
        {
            "version": 1,
            "tenant_ref": TENANT,
            "project_ref": PROJECT,
            "epoch": epoch,
            "purpose": "project_key",
            "key_id": L.key_id(proj_pub),
            "public_key": L.b64u(proj_pub),
            "not_before": NOW,
        },
    )
    member_binding = L.make_binding(
        admin_sk,
        admin_pub,
        {
            "version": 1,
            "tenant_ref": TENANT,
            "project_ref": PROJECT,
            "epoch": epoch,
            "purpose": "member_key",
            "key_id": L.key_id(mem_pub),
            "public_key": L.b64u(mem_pub),
            "not_before": NOW,
        },
    )

    texts = {
        "label": "Customer support triage agent",
        "knob": "temperature",
        "choice": "gpt-5.2-mini",
        "metric": "answer_correctness",
        "template": "You are a careful assistant. Answer using only {context}.",
    }
    envelopes = []
    for i, (purpose, text) in enumerate(texts.items()):
        object_ref = test_ref(OBJECT_KIND[purpose], purpose)
        revision = i + 1
        ikm = seed(f"writer-{purpose}")
        env = L.seal_label(
            proj_pub,
            text,
            tenant_ref=TENANT,
            project_ref=PROJECT,
            purpose=purpose,
            object_ref=object_ref,
            key_epoch=epoch,
            revision=revision,
            ikm_e=ikm,
        )
        envelopes.append(
            {
                "purpose": purpose,
                "object_ref": object_ref,
                "revision": revision,
                "plaintext": text,
                "ephemeral_ikm_hex": ikm.hex(),
                "aad_jcs": L.label_aad(
                    TENANT, PROJECT, purpose, object_ref, epoch, revision
                ).decode(),
                "envelope": env,
                "packed_hex": L.pack_envelope(
                    1, epoch, L.unb64u(env["enc"]), L.unb64u(env["ciphertext"])
                ).hex(),
            }
        )

    padding_ok = []
    for label, text in (
        ("empty", ""),
        ("one_byte", "a"),
        ("31_bytes_fills_bucket_32", "x" * 31),
        ("32_bytes_next_bucket_64", "x" * 32),
        ("63_bytes", "x" * 63),
        ("64_bytes_next_bucket_128", "x" * 64),
        ("127_bytes", "x" * 127),
        ("128_bytes_next_bucket_256", "x" * 128),
        ("255_bytes_max", "x" * 255),
        ("multibyte_utf8", "café ☃ \U0001f600"),
    ):
        padded = L.pad(text)
        padding_ok.append(
            {
                "name": label,
                "plaintext": text,
                "utf8_bytes": len(text.encode()),
                "bucket": len(padded),
                "padded_hex": padded.hex(),
            }
        )
    b = lambda n: bytes(n)  # noqa: E731
    padding_bad = [
        {"name": "too_long_256_bytes", "operation": "pad", "plaintext": "x" * 256},
        {"name": "all_zero_no_marker", "operation": "unpad", "padded_hex": b(32).hex()},
        {"name": "no_0x80_marker", "operation": "unpad", "padded_hex": (b"abc" + b(29)).hex()},
        {
            "name": "nonzero_after_marker",
            "operation": "unpad",
            "padded_hex": (b"abc\x80\x01" + b(27)).hex(),
        },
        {
            "name": "not_a_bucket_length",
            "operation": "unpad",
            "padded_hex": (b"abc\x80" + b(29)).hex(),
        },
        {
            "name": "non_minimal_bucket",
            "operation": "unpad",
            "padded_hex": (b"abc\x80" + b(60)).hex(),
        },
        {
            "name": "invalid_utf8",
            "operation": "unpad",
            "padded_hex": (b"\xff\xfe\x80" + b(29)).hex(),
        },
    ]

    wrap_ikm = seed("member-wrap-writer")
    member_wrap = L.wrap_to_member(
        proj_sk, mem_pub, tenant_ref=TENANT, project_ref=PROJECT, epoch=epoch, ikm_e=wrap_ikm
    )

    recovery_secret = seed("recovery-secret")
    rec_nonce_p, rec_nonce_r = seed("recovery-nonce-project")[:12], seed("recovery-nonce-root")[:12]
    recovery_project = L.recovery_wrap(
        recovery_secret,
        proj_sk.private_bytes_raw(),
        tenant_ref=TENANT,
        project_ref=PROJECT,
        epoch=epoch,
        nonce=rec_nonce_p,
        subject="project_key",
    )
    recovery_root = L.recovery_wrap(
        recovery_secret,
        seed("root"),
        tenant_ref=TENANT,
        project_ref=PROJECT,
        epoch=L.ROOT_WRAP_EPOCH,
        nonce=rec_nonce_r,
        subject="root_key",
    )

    local_ikm = seed("local-wrap-ikm-standin")
    local_nonce = seed("local-nonce")[:12]
    mem_kid = L.key_id(mem_pub)
    local_rec = L.local_wrap(
        local_ikm,
        mem_sk.private_bytes_raw(),
        tenant_ref=TENANT,
        member_key_id=mem_kid,
        nonce=local_nonce,
    )
    prf_salt = hashlib.sha256(b"traigent.label.member.v1" + mem_kid.encode()).digest()
    local_passkey = {
        "version": 1,
        "member_key_id": mem_kid,
        "protection": "passkey_prf",
        "credential_id": L.b64u(seed("credential-id")),
        "prf_input_salt": L.b64u(prf_salt),
        **local_rec,
    }
    local_pass = {
        "version": 1,
        "member_key_id": mem_kid,
        "protection": "passphrase_argon2id",
        "argon2id": {
            "salt": L.b64u(seed("argon2-salt")[:16]),
            "memory_kib": 65536,
            "iterations": 3,
            "parallelism": 1,
        },
        **local_rec,
    }

    return {
        "_comment": (
            "TEST-ONLY conformance vectors for docs/labels-v0.md. Every key, seed and secret below "
            "is derived "
            "from a public constant and protects nothing. Regenerate with "
            "scripts/generate_label_vectors.py --update; do not hand-edit."
        ),
        "suite": {
            "kem": "DHKEM(X25519, HKDF-SHA256)",
            "kdf": "HKDF-SHA256",
            "aead": "AES-256-GCM",
            "hpke_ids": [32, 1, 2],
            "hpke_info": L.HPKE_INFO_LABEL.decode(),
        },
        "refs": {"tenant_ref": TENANT, "project_ref": PROJECT},
        "keys": {
            "root_ed25519_seed_hex": seed("root").hex(),
            "root_public_hex": root_pub.hex(),
            "root_fingerprint_sha256": L.root_fingerprint(root_pub),
            "admin_ed25519_seed_hex": seed("admin").hex(),
            "admin_public_hex": admin_pub.hex(),
            "project_epoch1_x25519_ikm_hex": seed("project-epoch-1").hex(),
            "project_public_hex": proj_pub.hex(),
            "project_private_hex": proj_sk.private_bytes_raw().hex(),
            "member_x25519_ikm_hex": seed("member").hex(),
            "member_public_hex": mem_pub.hex(),
            "member_private_hex": mem_sk.private_bytes_raw().hex(),
            "recovery_secret_hex": recovery_secret.hex(),
        },
        "label_envelopes": envelopes,
        "padding": {"ok": padding_ok, "malformed": padding_bad},
        "member_wrap": {
            "ephemeral_ikm_hex": wrap_ikm.hex(),
            "wrap": member_wrap,
            "info_jcs": L.member_wrap_info(TENANT, PROJECT, epoch, L.key_id(mem_pub)).decode(),
        },
        "recovery_wraps": {
            "project_key": recovery_project,
            "root_key": recovery_root,
            "project_key_aad_jcs": L.recovery_aad(TENANT, PROJECT, epoch, "project_key").decode(),
            "root_key_aad_jcs": L.recovery_aad(
                TENANT, PROJECT, L.ROOT_WRAP_EPOCH, "root_key"
            ).decode(),
        },
        "local_protection": {
            "test_only_wrapping_ikm_hex": local_ikm.hex(),
            "passkey_prf": local_passkey,
            "passphrase_argon2id": local_pass,
            "aad_jcs": L.local_aad(TENANT, mem_kid).decode(),
        },
        "binding_chain": {
            "admin_identity": admin_binding,
            "project_key": project_binding,
            "member_key": member_binding,
        },
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true")
    g.add_argument("--update", action="store_true")
    args = ap.parse_args()
    text = render()
    if args.update:
        VECTORS_PATH.write_text(text, encoding="utf-8")
        print(f"wrote {VECTORS_PATH}")
        return 0
    if not VECTORS_PATH.exists() or VECTORS_PATH.read_text(encoding="utf-8") != text:
        print(f"{VECTORS_PATH} is stale; run with --update", file=sys.stderr)
        return 1
    print("label vectors up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
