# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Standalone, offline verifier for signed Pillar Legend claim statements (v0).

A statement is ``{"subject": ..., "signature": ...}`` (schema
``legend/legend_claim_statement_v0.json``).  The relying party supplies a pinned
trusted-key set; nothing is fetched, no Backend code is imported.  The verifier

* checks the signature domain is exactly ``LEGEND_SIGNATURE_DOMAIN`` (so a signature
  made for the process-record issuer domain is refused as ``DOMAIN``);
* validates the whole statement against the closed schema;
* looks up ``(key_id, algorithm)`` in the trusted set (unknown key or wrong algorithm
  is refused before any signature maths);
* RECOMPUTES the canonical bytes from the presented subject and verifies the signature
  over ``domain || 0x00 || canonical_json(subject)``, so any tampering is refused.

Signing input and canonical form mirror TraigentBackend
``src/services/certification/legend_claims.py`` (``LEGEND_SIGNATURE_DOMAIN``,
``_canonical_json``).  Failures raise :class:`LegendClaimVerificationError` carrying
only a fixed content-free code: statement fields may be customer-influenced.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema.validator import _FORMAT_CHECKER

LEGEND_SIGNATURE_DOMAIN = b"traigent.legend_claim_subject.signature.v0"
LEGEND_SIGNATURE_ALGORITHMS = frozenset({"ed25519", "ecdsa_p256_sha256"})

LEGEND_CLAIM_VERIFICATION_ERROR_CODES = frozenset(
    {
        "STRUCTURE",
        "DOMAIN",
        "SCHEMA",
        "CANONICALIZATION",
        "ALGORITHM",
        "UNKNOWN_KEY",
        "KEY_ALGORITHM",
        "SIGNATURE_BASE64",
        "SIGNATURE_SCALAR",
        "SIGNATURE_HIGH_S",
        "SIGNATURE_INVALID",
        "VERIFICATION_FAILED",
    }
)

_SCHEMAS_DIR = Path(__file__).resolve().parent / "schemas"
_STATEMENT_PATH = _SCHEMAS_DIR / "legend" / "legend_claim_statement_v0.json"
_SIG_RE = re.compile(r"^[A-Za-z0-9+/]{86}==$")
_ECDSA_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_ECDSA_HALF_ORDER = _ECDSA_ORDER // 2


class LegendClaimVerificationError(ValueError):
    """A fixed-code verification failure that never includes statement data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> Any:
    raise LegendClaimVerificationError(code) from None


@dataclass(frozen=True)
class TrustedLegendKey:
    """One pinned signer key: the algorithm it is trusted for and its public key."""

    algorithm: str
    public_key: Any  # ed25519.Ed25519PublicKey | ec.EllipticCurvePublicKey (P-256)


@dataclass(frozen=True)
class LegendClaimVerification:
    """Successful result; only the verified, schema-valid subject is returned."""

    subject: Mapping[str, Any]
    key_id: str
    algorithm: str
    canonical_bytes: bytes


def canonical_subject_json(subject: Any) -> str:
    """Canonical subject text; byte-identical to the Backend's ``_canonical_json``."""
    return json.dumps(
        subject, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def legend_signing_material(subject: Any) -> bytes:
    """``domain || 0x00 || canonical_json(subject)`` as UTF-8 bytes (the signed input)."""
    return LEGEND_SIGNATURE_DOMAIN + b"\x00" + canonical_subject_json(subject).encode("utf-8")


@lru_cache(maxsize=1)
def _statement_validator() -> Draft7Validator:
    resources = []
    for path in _SCHEMAS_DIR.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    schema = json.loads(_STATEMENT_PATH.read_text(encoding="utf-8"))
    return Draft7Validator(
        schema, registry=Registry().with_resources(resources), format_checker=_FORMAT_CHECKER
    )


def _decode_signature(encoded: object) -> bytes:
    if type(encoded) is not str or not _SIG_RE.fullmatch(encoded):
        _fail("SIGNATURE_BASE64")
    try:
        raw = base64.b64decode(cast(str, encoded).encode("ascii"), validate=True)
    except ValueError:
        _fail("SIGNATURE_BASE64")
    if len(raw) != 64 or base64.b64encode(raw).decode("ascii") != encoded:
        _fail("SIGNATURE_BASE64")
    return raw


def _verify(key: TrustedLegendKey, material: bytes, raw: bytes) -> None:
    try:
        if key.algorithm == "ed25519":
            if not isinstance(key.public_key, ed25519.Ed25519PublicKey):
                _fail("KEY_ALGORITHM")
            key.public_key.verify(raw, material)
            return
        pub = key.public_key
        if not isinstance(pub, ec.EllipticCurvePublicKey) or not isinstance(
            pub.curve, ec.SECP256R1
        ):
            _fail("KEY_ALGORITHM")
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        if not 1 <= r < _ECDSA_ORDER or not 1 <= s < _ECDSA_ORDER:
            _fail("SIGNATURE_SCALAR")
        if s > _ECDSA_HALF_ORDER:
            _fail("SIGNATURE_HIGH_S")
        pub.verify(utils.encode_dss_signature(r, s), material, ec.ECDSA(hashes.SHA256()))
    except LegendClaimVerificationError:
        raise
    except (InvalidSignature, ValueError):
        _fail("SIGNATURE_INVALID")
    except Exception:
        _fail("VERIFICATION_FAILED")


def verify_legend_claim_statement(
    statement: object, trusted_keys: Mapping[str, TrustedLegendKey]
) -> LegendClaimVerification:
    """Verify one signed Legend claim statement against a pinned trusted-key set.

    ``trusted_keys`` maps ``key_id`` to the key and the single algorithm it is trusted for.
    Raises :class:`LegendClaimVerificationError` (closed, content-free code) on any failure.
    """
    if type(statement) is not dict or set(statement) != {"subject", "signature"}:
        _fail("STRUCTURE")
    stmt = cast(dict[str, Any], statement)
    sig = stmt["signature"]
    if type(sig) is not dict:
        _fail("STRUCTURE")
    # Domain first: a signature framed for another domain is never even schema-checked.
    if sig.get("domain") != LEGEND_SIGNATURE_DOMAIN.decode("ascii"):
        _fail("DOMAIN")
    if _statement_validator().is_valid(stmt) is not True:
        _fail("SCHEMA")
    algorithm, key_id = sig["algorithm"], sig["key_id"]
    if algorithm not in LEGEND_SIGNATURE_ALGORITHMS:
        _fail("ALGORITHM")
    key = trusted_keys.get(key_id)
    if key is None:
        _fail("UNKNOWN_KEY")
    if key.algorithm != algorithm:
        _fail("ALGORITHM")
    raw = _decode_signature(sig["value"])
    try:
        material = legend_signing_material(stmt["subject"])
    except (TypeError, ValueError, RecursionError):
        _fail("CANONICALIZATION")
    _verify(key, material, raw)
    return LegendClaimVerification(
        subject=stmt["subject"], key_id=key_id, algorithm=algorithm, canonical_bytes=material
    )
