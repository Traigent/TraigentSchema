# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Loader for the owner-ratified prohibited-claims register baseline (P-1..P-40).

Ships the 40-entry historical baseline of TraigentBackend's certificate-compiler
prohibited-claims register as repository-owned package data, plus a CI-pinned
content digest, so this document -- not a working-tree copy, not a comment, not
a re-transcription -- is the thing consumers import.

Three files make up the shipped artifact, all under
``traigent_schema/data/certification/``:

* ``prohibited_register_baseline.json`` -- the 40-entry document itself,
  transcribed verbatim (owner ratification decision A, 2026-09-07) from the
  "Prohibited sentence form" column of
  ``runs/response-comparison-debugging/prohibited-register-P1-P40-DRAFT.md``.
* ``prohibited_register_baseline.digest.json`` -- the CI pin: the sha256
  digest the document above MUST hash to, plus provenance (source document,
  its own sha256, ratification metadata).
* the schema at
  ``traigent_schema/schemas/certification/prohibited_register_baseline_v1_schema.json``,
  which the document is validated against before it is trusted.

DIGEST CONSTRUCTION -- plain, no domain tag
--------------------------------------------
``"sha256:" + lowercase_hex(SHA-256(jcs_v1(document)))``. This repo's other
load-bearing certificate digests are role-domain-separated
(``certification_common_v0_schema.json#/definitions/DigestRoleDomainTagV0``,
SHA-256(domain || 0x00 || jcs_v1(document))), but that enum is a CLOSED list
inside a frozen v0 schema this packet may not edit. This document therefore
uses the plain construction and says so, in both this docstring and the pin
file's own ``construction`` field, rather than silently reusing a domain tag
that was never registered for it.

CONTENT-FREE FAILURE
---------------------
Every failure this module can raise at import time -- a missing file, a
schema violation, a digest that does not match the pin -- surfaces as
:class:`ProhibitedRegisterBaselineError` with a single fixed message. No
prohibited-claim text, local_id, or raw document/pin content is ever part of
the raised exception or its chain: the whole check runs inside one guarded
boundary (see :func:`_verify_baseline`), and the boundary clears
``__context__`` before re-raising so a caught ``jsonschema``/``json``/``OSError``
exception -- which WOULD carry document content -- becomes unreachable rather
than merely undisplayed. This mirrors
``traigent_schema/certification/process_record_verifier.py``'s
``_load_registry_constant`` boundary.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from traigent_schema import fp2
from traigent_schema.utils import get_schemas_dir

__all__ = [
    "ProhibitedRegisterBaselineError",
    "PROHIBITED_REGISTER_BASELINE_DIGEST",
    "PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST",
    "load_prohibited_register_baseline",
]

_SHA256_PREFIX = "sha256:"

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "certification"
_DOCUMENT_PATH = _DATA_DIR / "prohibited_register_baseline.json"
_DIGEST_PIN_PATH = _DATA_DIR / "prohibited_register_baseline.digest.json"
_SCHEMA_PATH = get_schemas_dir() / "certification" / "prohibited_register_baseline_v1_schema.json"


class ProhibitedRegisterBaselineError(RuntimeError):
    """The shipped prohibited-register baseline document or its pin is invalid.

    Content-free by construction: the message is a single fixed string, never
    document content, a filesystem path, or a wrapped exception's text. See
    the module docstring for the boundary that guarantees this.
    """

    def __init__(self) -> None:
        super().__init__("PROHIBITED_REGISTER_BASELINE_INVALID")


def _fail() -> None:
    """Raise :class:`ProhibitedRegisterBaselineError` with no exception chain.

    Must only be called from OUTSIDE an ``except`` block (see
    :func:`_verify_baseline`) -- calling it from inside one still links the
    caught exception as ``__context__`` even though ``from None`` suppresses
    its display; this two-step raise/clear/re-raise is what makes the caught
    exception (and any document content it carries) genuinely unreachable.
    """
    failure = ProhibitedRegisterBaselineError()
    try:
        raise failure from None
    except ProhibitedRegisterBaselineError:
        failure.__context__ = None
        raise


def _registry_for(schemas_dir: Path) -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in schemas_dir.rglob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(document, dict) and "$id" in document:
            resources.append((document["$id"], Resource.from_contents(document)))
    return Registry().with_resources(resources)


def _plain_digest(document: Any) -> str:
    """``sha256:`` + hex over ``jcs_v1(document)``, with no domain-tag prefix."""
    canonical = cast(str, fp2.canonicalize(document)).encode("utf-8")
    return _SHA256_PREFIX + hashlib.sha256(canonical).hexdigest()


def _verify_baseline(
    document: Any,
    schema: dict[str, Any],
    registry: Registry,
    pinned_digest: str,
) -> str:
    """Validate ``document`` against ``schema`` and check its digest against the pin.

    Returns the computed digest on success. This is the pure, injectable core
    of the boundary -- tests call it directly with synthetic documents/pins
    rather than through package-resource loading, so a mismatch can be
    exercised without touching the shipped files.

    Raises :class:`ProhibitedRegisterBaselineError`, content-free, on ANY
    failure: schema violation, canonicalization failure, or digest mismatch.
    """
    ok: str | None
    try:
        # Counted, not collected: a retained ValidationError list would keep
        # the offending instance (i.e. document content) alive in this frame.
        validator = Draft7Validator(schema, registry=registry)
        error_count = sum(1 for _ in validator.iter_errors(document))
        if error_count:
            raise ValueError("schema violation")
        computed = _plain_digest(document)
        if computed != pinned_digest:
            raise ValueError("digest mismatch")
        ok = computed
    except Exception:
        ok = None
    if ok is None:
        _fail()
    return cast(str, ok)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_and_verify() -> tuple[dict[str, Any], str, str]:
    """Load the shipped document + pin, verify, and return (document, computed, pinned).

    The single content-free boundary around the whole read/validate/digest
    sequence: a missing file, undecodable JSON, a malformed pin, a schema
    violation, or a digest mismatch all become the same fixed
    :class:`ProhibitedRegisterBaselineError`.
    """
    result: tuple[dict[str, Any], str, str] | None
    try:
        document = _load_json(_DOCUMENT_PATH)
        pin = _load_json(_DIGEST_PIN_PATH)
        pinned_digest = pin["digest"] if isinstance(pin, dict) else None
        if not isinstance(pinned_digest, str):
            raise ValueError("pin file missing a string digest field")
        schema = _load_json(_SCHEMA_PATH)
        registry = _registry_for(get_schemas_dir())
        computed = _verify_baseline(document, schema, registry, pinned_digest)
        result = (document, computed, pinned_digest)
    except ProhibitedRegisterBaselineError:
        result = None
    except Exception:
        result = None
    if result is None:
        _fail()
    return cast("tuple[dict[str, Any], str, str]", result)


_loaded = _load_and_verify()
_BASELINE_DOCUMENT: dict[str, Any] = _loaded[0]
PROHIBITED_REGISTER_BASELINE_DIGEST: str = _loaded[1]
PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST: str = _loaded[2]
del _loaded


def load_prohibited_register_baseline() -> dict[str, Any]:
    """Return the validated, pin-checked 40-entry baseline document.

    The document was already loaded, schema-validated, and digest-checked
    against the pin at import time (see :data:`PROHIBITED_REGISTER_BASELINE_DIGEST`
    and :data:`PROHIBITED_REGISTER_BASELINE_PINNED_DIGEST`); this function
    returns that same result rather than re-reading package data on every
    call.
    """
    return _BASELINE_DOCUMENT
