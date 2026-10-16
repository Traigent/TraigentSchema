#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Reference implementation of the label-service crypto, for conformance vectors only.

Not a production library.  It exists so that the SDK, browser and Backend
implementations have an independent oracle for ``docs/labels-v0.md``.  It
implements RFC 9180 base mode (mode 0) for the suite

    DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM   (0x0020, 0x0001, 0x0002)

on top of ``cryptography`` primitives (the installed ``cryptography`` has no HPKE
module).  Correctness of the KEM, key schedule and AEAD framing is proven against the
RFC 9180 Appendix A.1 and A.2 vectors in ``tests/test_labels_vectors.py``; the AES-256
key size differs from A.1 only in ``Nk`` (the suite id and key length are the only
inputs that change), and A.1 uses the same AES-GCM primitive with a 16-byte key.

Everything here that takes a seed is for TEST VECTORS ONLY.  Never feed real key
material through the deterministic helpers.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

LABEL_VERSION = 1
BUCKETS = (32, 64, 128, 256)
MAX_LABEL_BYTES = 255
HPKE_INFO_LABEL = b"traigent.label.v1"
BINDING_DOMAIN = b"traigent.label.binding.v1\x00"
RECOVERY_INFO = b"traigent.label.recovery.v1"
LOCAL_INFO = b"traigent.label.local.v1"
ROOT_WRAP_EPOCH = 0  # recovery wrap of the root signing key uses this reserved epoch


class LabelCryptoError(ValueError):
    """Any verification, padding, decryption or format failure (fail closed)."""


# --- encodings -----------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64u(text: str) -> bytes:
    if not isinstance(text, str) or "=" in text or not text.isascii():
        raise LabelCryptoError("not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:  # noqa: BLE001
        raise LabelCryptoError("not base64url") from exc
    if b64u(raw) != text:
        raise LabelCryptoError("non-canonical base64url")
    return raw


def jcs(value: object) -> bytes:
    """RFC 8785 canonical JSON for the subset used here (str, int, bool, null, list, dict).

    Floats are refused: no AAD/info/binding field is fractional.  Strings must be
    ASCII-free of control characters other than the escapes JCS defines, which every
    field here satisfies (refs, enums, base64url, RFC 3339 timestamps).
    """

    def enc(v: object) -> str:
        if v is None:
            return "null"
        if v is True:
            return "true"
        if v is False:
            return "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, str):
            return json.dumps(v, ensure_ascii=False, separators=(",", ":"))
        if isinstance(v, list):
            return "[" + ",".join(enc(i) for i in v) + "]"
        if isinstance(v, dict):
            keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(enc(k) + ":" + enc(v[k]) for k in keys) + "}"
        raise LabelCryptoError(f"unsupported JCS type {type(v).__name__}")

    return enc(value).encode("utf-8")


# --- HKDF-SHA256 -----------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


# --- RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256) ----------------------------------

KEM_ID = 0x0020
KDF_ID = 0x0001
AEAD_AES128 = 0x0001
AEAD_AES256 = 0x0002
AEAD_CHACHA = 0x0003
_AEAD = {AEAD_AES128: (16, AESGCM), AEAD_AES256: (32, AESGCM), AEAD_CHACHA: (32, ChaCha20Poly1305)}
_NN = 12


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


def _le(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, _i2osp(length, 2) + b"HPKE-v1" + suite + label + info, length)


def _lx(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


_KEM_SUITE = b"KEM" + _i2osp(KEM_ID, 2)


def x25519_raw_public(sk: X25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_keypair(ikm: bytes) -> tuple[X25519PrivateKey, bytes]:
    """RFC 9180 DeriveKeyPair for X25519.  Use only with test seeds or CSPRNG output."""
    prk = _lx(_KEM_SUITE, b"", b"dkp_prk", ikm)
    sk = X25519PrivateKey.from_private_bytes(_le(_KEM_SUITE, prk, b"sk", b"", 32))
    return sk, x25519_raw_public(sk)


def _dh(sk: X25519PrivateKey, pk: bytes) -> bytes:
    shared = sk.exchange(X25519PublicKey.from_public_bytes(pk))
    if shared == b"\x00" * 32:
        raise LabelCryptoError("low-order point")
    return shared


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _lx(_KEM_SUITE, b"", b"eae_prk", dh)
    return _le(_KEM_SUITE, eae_prk, b"shared_secret", kem_context, 32)


def _key_schedule(aead_id: int, shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    suite = b"HPKE" + _i2osp(KEM_ID, 2) + _i2osp(KDF_ID, 2) + _i2osp(aead_id, 2)
    nk = _AEAD[aead_id][0]
    psk_id_hash = _lx(suite, b"", b"psk_id_hash", b"")
    info_hash = _lx(suite, b"", b"info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _lx(suite, shared_secret, b"secret", b"")
    return (
        _le(suite, secret, b"key", context, nk),
        _le(suite, secret, b"base_nonce", context, _NN),
    )


def hpke_seal(
    pk_r: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    ikm_e: bytes,
    aead_id: int = AEAD_AES256,
) -> tuple[bytes, bytes]:
    """Single-shot base-mode seal.  ``ikm_e`` MUST be 32 CSPRNG bytes outside test vectors."""
    sk_e, enc = derive_keypair(ikm_e)
    shared = _extract_and_expand(_dh(sk_e, pk_r), enc + pk_r)
    key, nonce = _key_schedule(aead_id, shared, info)
    return enc, _AEAD[aead_id][1](key).encrypt(nonce, plaintext, aad)


def hpke_open(
    sk_r: X25519PrivateKey,
    enc: bytes,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
    aead_id: int = AEAD_AES256,
) -> bytes:
    pk_r = x25519_raw_public(sk_r)
    shared = _extract_and_expand(_dh(sk_r, enc), enc + pk_r)
    key, nonce = _key_schedule(aead_id, shared, info)
    try:
        return _AEAD[aead_id][1](key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise LabelCryptoError("authentication failed") from exc


# --- padding ----------------------------------------------------------------------


def pad(text: str) -> bytes:
    raw = text.encode("utf-8")
    if len(raw) > MAX_LABEL_BYTES:
        raise LabelCryptoError("label longer than 255 UTF-8 bytes")
    for bucket in BUCKETS:
        if len(raw) + 1 <= bucket:
            return raw + b"\x80" + b"\x00" * (bucket - len(raw) - 1)
    raise LabelCryptoError("unreachable")  # pragma: no cover


def unpad(padded: bytes) -> str:
    if len(padded) not in BUCKETS:
        raise LabelCryptoError("padded length is not a bucket")
    stripped = padded.rstrip(b"\x00")
    if not stripped or stripped[-1] != 0x80:
        raise LabelCryptoError("malformed padding")
    body = stripped[:-1]
    # canonical: the smallest bucket that fits, so one label has one padded form
    if len(padded) != next(b for b in BUCKETS if len(body) + 1 <= b):
        raise LabelCryptoError("non-minimal bucket")
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LabelCryptoError("label is not UTF-8") from exc


# --- label envelope ---------------------------------------------------------------


def label_aad(
    tenant_ref: str, project_ref: str, purpose: str, object_ref: str, key_epoch: int, revision: int
) -> bytes:
    return jcs(
        {
            "schema_version": LABEL_VERSION,
            "tenant_ref": tenant_ref,
            "project_ref": project_ref,
            "purpose": purpose,
            "object_ref": object_ref,
            "key_epoch": key_epoch,
            "revision": revision,
        }
    )


def pack_envelope(version: int, epoch: int, enc: bytes, ciphertext: bytes) -> bytes:
    """version(1) || key_epoch(4, big-endian) || enc(32) || ciphertext."""
    return bytes([version]) + struct.pack(">I", epoch) + enc + ciphertext


def unpack_envelope(blob: bytes) -> tuple[int, int, bytes, bytes]:
    if len(blob) < 1 + 4 + 32 + 16 + min(BUCKETS):
        raise LabelCryptoError("envelope too short")
    version, epoch = blob[0], struct.unpack(">I", blob[1:5])[0]
    if version != LABEL_VERSION:
        raise LabelCryptoError("unsupported envelope version")
    return version, epoch, blob[5:37], blob[37:]


def seal_label(
    pk_project: bytes,
    text: str,
    *,
    tenant_ref: str,
    project_ref: str,
    purpose: str,
    object_ref: str,
    key_epoch: int,
    revision: int,
    ikm_e: bytes,
) -> dict:
    enc, ct = hpke_seal(
        pk_project,
        HPKE_INFO_LABEL,
        label_aad(tenant_ref, project_ref, purpose, object_ref, key_epoch, revision),
        pad(text),
        ikm_e,
    )
    return {
        "version": LABEL_VERSION,
        "key_epoch": key_epoch,
        "enc": b64u(enc),
        "ciphertext": b64u(ct),
    }


def open_label(
    sk_project: X25519PrivateKey,
    envelope: dict,
    *,
    tenant_ref: str,
    project_ref: str,
    purpose: str,
    object_ref: str,
    revision: int,
) -> str:
    if envelope.get("version") != LABEL_VERSION:
        raise LabelCryptoError("unsupported envelope version")
    epoch = envelope["key_epoch"]
    padded = hpke_open(
        sk_project,
        unb64u(envelope["enc"]),
        HPKE_INFO_LABEL,
        label_aad(tenant_ref, project_ref, purpose, object_ref, epoch, revision),
        unb64u(envelope["ciphertext"]),
    )
    return unpad(padded)


# --- signed bindings (Ed25519) -----------------------------------------------------


def ed25519_raw_public(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def key_id(public_key: bytes) -> str:
    """First 16 bytes of SHA-256(raw public key), base64url (22 chars)."""
    return b64u(hashlib.sha256(public_key).digest()[:16])


def root_fingerprint(public_key: bytes) -> str:
    """Full SHA-256 of the raw root public key, lowercase hex, the value customers pin."""
    return hashlib.sha256(public_key).hexdigest()


def sign_body(sk: Ed25519PrivateKey, body: dict) -> str:
    return b64u(sk.sign(BINDING_DOMAIN + jcs(body)))


def verify_body(public_key: bytes, body: dict, signature: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            unb64u(signature), BINDING_DOMAIN + jcs(body)
        )
    except InvalidSignature as exc:
        raise LabelCryptoError("bad signature") from exc


def make_binding(signer_sk: Ed25519PrivateKey, signer_pub: bytes, body: dict) -> dict:
    body = dict(body, signer_key_id=key_id(signer_pub))
    return dict(body, signature=sign_body(signer_sk, body))


def verify_binding(signer_pub: bytes, binding: dict) -> None:
    body = {k: v for k, v in binding.items() if k != "signature"}
    if body.get("signer_key_id") != key_id(signer_pub):
        raise LabelCryptoError("signer key id mismatch")
    verify_body(signer_pub, body, binding["signature"])


def verify_chain(
    pinned_root_fingerprint: str,
    root_pub: bytes,
    admin_binding: dict,
    project_binding: dict,
    member_binding: dict,
    *,
    tenant_ref: str,
    project_ref: str,
) -> None:
    """root (pinned) -> admin identity -> project key (epoch) -> member key.  Fail closed."""
    if not hmac.compare_digest(root_fingerprint(root_pub), pinned_root_fingerprint):
        raise LabelCryptoError("root key does not match pinned fingerprint")
    verify_binding(root_pub, admin_binding)
    if admin_binding["purpose"] != "admin_identity":
        raise LabelCryptoError("wrong purpose for admin binding")
    admin_pub = unb64u(admin_binding["public_key"])
    for binding, purpose in ((project_binding, "project_key"), (member_binding, "member_key")):
        verify_binding(admin_pub, binding)
        if binding["purpose"] != purpose:
            raise LabelCryptoError(f"wrong purpose, expected {purpose}")
    for binding in (admin_binding, project_binding, member_binding):
        if binding["tenant_ref"] != tenant_ref:
            raise LabelCryptoError("tenant mismatch")
    for binding in (project_binding, member_binding):
        if binding["project_ref"] != project_ref:
            raise LabelCryptoError("project mismatch")
    if member_binding["epoch"] != project_binding["epoch"]:
        raise LabelCryptoError("epoch mismatch")


# --- flow (b): project private key wrapped to a member -------------------------------


def member_wrap_info(tenant_ref: str, project_ref: str, epoch: int, recipient_key_id: str) -> bytes:
    return jcs(
        {
            "tenant_ref": tenant_ref,
            "project_ref": project_ref,
            "epoch": epoch,
            "recipient_key_id": recipient_key_id,
            "purpose": "member_wrap",
            "version": LABEL_VERSION,
        }
    )


def wrap_to_member(
    project_sk: X25519PrivateKey,
    member_pk: bytes,
    *,
    tenant_ref: str,
    project_ref: str,
    epoch: int,
    ikm_e: bytes,
) -> dict:
    rid = key_id(member_pk)
    enc, ct = hpke_seal(
        member_pk,
        member_wrap_info(tenant_ref, project_ref, epoch, rid),
        b"",
        project_sk.private_bytes_raw(),
        ikm_e,
    )
    return {
        "version": LABEL_VERSION,
        "epoch": epoch,
        "recipient_key_id": rid,
        "enc": b64u(enc),
        "ciphertext": b64u(ct),
    }


def unwrap_from_member(
    member_sk: X25519PrivateKey, wrap: dict, *, tenant_ref: str, project_ref: str
) -> X25519PrivateKey:
    if wrap["recipient_key_id"] != key_id(x25519_raw_public(member_sk)):
        raise LabelCryptoError("wrap is addressed to a different key")
    raw = hpke_open(
        member_sk,
        unb64u(wrap["enc"]),
        member_wrap_info(tenant_ref, project_ref, wrap["epoch"], wrap["recipient_key_id"]),
        b"",
        unb64u(wrap["ciphertext"]),
    )
    return X25519PrivateKey.from_private_bytes(raw)


# --- flow (c): recovery wrap ----------------------------------------------------------


def recovery_aad(tenant_ref: str, project_ref: str, epoch: int) -> bytes:
    return jcs(
        {
            "tenant_ref": tenant_ref,
            "project_ref": project_ref,
            "epoch": epoch,
            "purpose": "recovery_wrap",
            "version": LABEL_VERSION,
        }
    )


def recovery_wrap(
    recovery_secret: bytes,
    secret_key_raw: bytes,
    *,
    tenant_ref: str,
    project_ref: str,
    epoch: int,
    nonce: bytes,
    subject: str,
) -> dict:
    """Wrap a root signing key (``subject`` root_key, epoch 0) or an epoch project key."""
    if len(recovery_secret) != 32 or len(nonce) != 12:
        raise LabelCryptoError("bad recovery secret or nonce size")
    key = hkdf(recovery_secret, RECOVERY_INFO, 32)
    ct = AESGCM(key).encrypt(nonce, secret_key_raw, recovery_aad(tenant_ref, project_ref, epoch))
    return {
        "version": LABEL_VERSION,
        "epoch": epoch,
        "subject": subject,
        "nonce": b64u(nonce),
        "ciphertext": b64u(ct),
    }


def recovery_unwrap(
    recovery_secret: bytes, wrap: dict, *, tenant_ref: str, project_ref: str
) -> bytes:
    key = hkdf(recovery_secret, RECOVERY_INFO, 32)
    try:
        return AESGCM(key).decrypt(
            unb64u(wrap["nonce"]),
            unb64u(wrap["ciphertext"]),
            recovery_aad(tenant_ref, project_ref, wrap["epoch"]),
        )
    except InvalidTag as exc:
        raise LabelCryptoError("authentication failed") from exc


# --- flow (a): local protection of a member private key --------------------------------


def local_aad(tenant_ref: str, member_key_id: str) -> bytes:
    return jcs(
        {
            "tenant_ref": tenant_ref,
            "member_key_id": member_key_id,
            "purpose": "local_member_key",
            "version": LABEL_VERSION,
        }
    )


def local_wrap(
    ikm: bytes, secret_raw: bytes, *, tenant_ref: str, member_key_id: str, nonce: bytes
) -> dict:
    """``ikm`` is the PRF output or Argon2id output.  It is an input here and never serialized."""
    key = hkdf(ikm, LOCAL_INFO, 32)
    ct = AESGCM(key).encrypt(nonce, secret_raw, local_aad(tenant_ref, member_key_id))
    return {"nonce": b64u(nonce), "ciphertext": b64u(ct)}


def local_unwrap(ikm: bytes, record: dict, *, tenant_ref: str, member_key_id: str) -> bytes:
    key = hkdf(ikm, LOCAL_INFO, 32)
    try:
        return AESGCM(key).decrypt(
            unb64u(record["nonce"]),
            unb64u(record["ciphertext"]),
            local_aad(tenant_ref, member_key_id),
        )
    except InvalidTag as exc:
        raise LabelCryptoError("authentication failed") from exc
