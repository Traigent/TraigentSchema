# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Reference implementation of the Fleet Observe canonical request digest.

Specified in ``traigent_schema/data/fleet_observe/request_digest_v1.md``; the shared vectors in
``traigent_schema/data/fleet_observe/request_digest_vectors.json`` are reproduced by these
functions and are what the SDK and the API server test against. Pure and offline: no network,
filesystem or randomness. It validates the same shapes the API server accepts (digest and
timestamp patterns, member and boundary enums), so a vector input the API server would reject
raises ``ValueError``.

The identifier digests (HMAC with domain separation, see ``identifier_canonicalization.json``)
are included so the SDK and a test can share one reference.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "IDEMPOTENCY_DOMAIN",
    "REQUEST_DIGEST_VERSION",
    "canonical_observed_at",
    "canonical_preimage",
    "canonical_repository",
    "identifier_digest",
    "idempotency_key",
    "key_id",
    "request_digest",
]

REQUEST_DIGEST_VERSION = "fleet_import_request_v1"
IDEMPOTENCY_DOMAIN = "fleet_idem_v1\x1f"
DEFAULT_RETENTION_CLASS = "ledger_minimal"
_SHA256_PREFIX = "sha256:"
_ERR_REMOTE = "invalid repository remote"
_ERR_HOST = "invalid repository host"

# Byte-identical to the API server contract mirror.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|02-(?:0[1-9]|1[0-9]|2[0-9]))T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z$"
)
_SOURCE_KINDS = frozenset(
    {
        "cloud_iam_principal",
        "credential_inventory",
        "kubernetes_workload",
        "llm_gateway_log",
        "otel_trace_export",
        "sdk_declaration",
        "spawn_parent_report",
        "parent_evidence_inherit",
        "vendor_platform_registry",
    }
)
_BOUNDARY_KINDS = frozenset(
    {"cloud_account", "orchestrator_cluster", "gateway", "agent_platform", "repository"}
)
_MEMBER_KINDS = frozenset({"principal", "credential", "workload"})
_RETENTION_CLASSES = frozenset(
    {"ledger_minimal", "evidence_short", "evidence_standard", "legal_hold"}
)
_ROLES = frozenset({"boundary", "principal", "credential", "workload"})
_MAX_MEMBERS = 5000


def _fail(what: str) -> ValueError:
    return ValueError(f"invalid fleet import request: {what}")


def _digest(value: Any, what: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise _fail(what)
    return value


def canonical_observed_at(stamp: str) -> str:
    """Normalize a contract Timestamp to ``YYYY-MM-DDTHH:MM:SS.ffffffZ`` (UTC, six digits).

    Only the contract ``Timestamp`` form (trailing ``Z``) is accepted: the API server rejects
    ``+00:00`` offsets, so they have no canonical form.
    """
    if not isinstance(stamp, str) or _TIMESTAMP_RE.match(stamp) is None:
        raise _fail("observed_at")
    try:
        parsed = datetime.fromisoformat(stamp[:-1] + "+00:00").astimezone(UTC)
    except ValueError:
        raise _fail("observed_at") from None
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _reject_parent_cycles(parent_of: Mapping[str, str | None]) -> None:
    """A parent cycle (A -> B -> A) has no coherent cluster: rejected, like the API server."""
    state: dict[str, int] = {}  # 1 = on the current path, 2 = proven acyclic
    for start in parent_of:
        if start in state:
            continue
        path: list[str] = []
        node: str | None = start
        while node is not None and node in parent_of and node not in state:
            state[node] = 1
            path.append(node)
            node = parent_of[node]
        if node is not None and state.get(node) == 1:
            raise _fail("parent cycle")
        for visited in path:
            state[visited] = 2


def _member_entry(item: Any) -> tuple[str, str, str | None]:
    """Validate one member mapping and return ``(kind, digest, parent)``."""
    if not isinstance(item, Mapping) or not {"member_kind", "member_digest"} <= set(item):
        raise _fail("member")
    if not set(item) <= {"member_kind", "member_digest", "parent_member_digest"}:
        raise _fail("member")
    kind = item["member_kind"]
    if kind not in _MEMBER_KINDS:
        raise _fail("member_kind")
    digest = _digest(item["member_digest"], "member_digest")
    parent = item.get("parent_member_digest")
    if parent is not None:
        parent = _digest(parent, "parent_member_digest")
        if parent == digest:
            raise _fail("parent_member_digest")
    return kind, digest, parent


def _members(raw: Any) -> list[list[Any]]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise _fail("members")
    seen: set[tuple[str, str, str | None]] = set()
    parent_of: dict[str, str | None] = {}
    for item in raw:
        kind, digest, parent = _member_entry(item)
        if parent_of.setdefault(digest, parent) != parent:
            raise _fail("member with two parents")
        seen.add((kind, digest, parent))
    if not 1 <= len(raw) <= _MAX_MEMBERS:
        raise _fail("members count")
    _reject_parent_cycles(parent_of)
    # tuple order (kind, digest, parent) with a null parent before any digest
    return [list(m) for m in sorted(seen, key=lambda m: (m[0], m[1], m[2] is not None, m[2] or ""))]


def canonical_preimage(request: Mapping[str, Any]) -> bytes:
    """The UTF-8 bytes hashed into the request digest (``idempotency_key`` is excluded)."""
    source_kind = request.get("source_kind")
    boundary = request.get("boundary")
    if source_kind not in _SOURCE_KINDS:
        raise _fail("source_kind")
    if not isinstance(boundary, Mapping) or set(boundary) != {"boundary_kind", "boundary_digest"}:
        raise _fail("boundary")
    if boundary["boundary_kind"] not in _BOUNDARY_KINDS:
        raise _fail("boundary_kind")
    retention = request.get("retention_class", DEFAULT_RETENTION_CLASS)
    if retention not in _RETENTION_CLASSES:
        raise _fail("retention_class")
    document = {
        "v": REQUEST_DIGEST_VERSION,
        "source_kind": source_kind,
        "boundary_kind": boundary["boundary_kind"],
        "boundary_digest": _digest(boundary["boundary_digest"], "boundary_digest"),
        "observed_at": canonical_observed_at(request.get("observed_at")),  # type: ignore[arg-type]
        "retention_class": retention,
        "members": _members(request.get("members")),
    }
    return json.dumps(document, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def request_digest(request: Mapping[str, Any]) -> str:
    """``sha256:<hex>`` of the canonical preimage."""
    return _SHA256_PREFIX + hashlib.sha256(canonical_preimage(request)).hexdigest()


def idempotency_key(digest: str) -> str:
    """The idempotency key derived from a request digest (deterministic, not circular)."""
    _digest(digest, "request_digest")
    return (
        _SHA256_PREFIX + hashlib.sha256((IDEMPOTENCY_DOMAIN + digest).encode("utf-8")).hexdigest()
    )


def identifier_digest(key: bytes, role: str, source: str, canonical_id: str) -> str:
    """HMAC-SHA256(key, ``tfl1 US role US source US canonical_id``) as ``sha256:<hex>``.

    ``canonical_id`` is the already-canonicalized identifier (see
    ``identifier_canonicalization.json``); this function applies only Unicode NFC.
    """
    if role not in _ROLES or not re.fullmatch(r"[a-z0-9_]{1,64}", source):
        raise ValueError("invalid role or source")
    text = unicodedata.normalize("NFC", canonical_id)
    if not text or "\x1f" in text or any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise ValueError("identifier is empty or contains a control character")
    message = "\x1f".join(("tfl1", role, source, text)).encode("utf-8")
    return _SHA256_PREFIX + hmac.new(key, message, hashlib.sha256).hexdigest()


def key_id(key: bytes) -> str:
    """16 hex of HMAC-SHA256(key, ``tfl1-key-id``): names the key without revealing it."""
    return hmac.new(key, b"tfl1-key-id", hashlib.sha256).hexdigest()[:16]


_ALLOWED_SCHEMES = {
    "https": "443",
    "http": "80",
    "ssh": "22",
    "git": "9418",
    "git+ssh": "22",
    "ssh+git": "22",
}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_HOST_PORT = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[^:/\[\]]+)(?::([0-9]{1,5}))?$")
_SCP = re.compile(r"^(?:[^@/:]+@)?([^/:@]+):(?!//)(.*)$")


def _normalize_escapes(path: str) -> str:
    def fix(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else "%" + match.group(1).upper()

    return _PERCENT.sub(fix, path)


def _split_remote(text: str) -> tuple[str | None, str, str]:
    """Split a normalised remote into ``(scheme, authority, path)``; credentials are dropped."""
    scheme = None
    if "://" in text:
        scheme, _, rest = text.partition("://")
        scheme = scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ValueError("unsupported repository scheme")
        rest = re.split(r"[?#]", rest, maxsplit=1)[0]
        authority, slash, path = rest.partition("/")
        if "@" in authority:
            authority = authority.rsplit("@", 1)[1]
    else:
        text = re.split(r"[?#]", text, maxsplit=1)[0]
        scp = _SCP.match(text)
        first_slash = text.find("/")
        if scp and (first_slash == -1 or text.find(":") < first_slash):
            authority, path = scp.group(1), scp.group(2)
        else:  # already canonical: host[:port]/path
            authority, _, path = text.partition("/")
            if "@" in authority:
                raise ValueError(_ERR_REMOTE)
    return scheme, authority, path


def _host_and_port(authority: str, scheme: str | None) -> tuple[str, str | None]:
    """Validate ``authority`` and return the lower-cased host and the non-default port."""
    match = _HOST_PORT.match(authority)
    if match is None:
        raise ValueError(_ERR_HOST)
    host = match.group(1).lower()
    if not host.startswith("[") and host.endswith("."):
        host = host[:-1]  # exactly one trailing dot
    if host.endswith("."):
        raise ValueError(_ERR_HOST)
    port = match.group(2)
    if not host or (port is not None and not 1 <= int(port) <= 65535):
        raise ValueError(_ERR_HOST)
    if port is not None and scheme is not None and port == _ALLOWED_SCHEMES[scheme]:
        port = None
    return host, port


def canonical_repository(remote: str) -> str:
    """Canonical ``host[:port]/path`` of a git remote (see ``identifier_canonicalization.json``).

    Accepts ``scheme://[userinfo@]host[:port]/path[?query][#fragment]`` (schemes https, http,
    ssh, git, git+ssh, ssh+git), the scp form ``[user@]host:path`` and an already-canonical
    ``host[:port]/path``. Credentials, query and fragment are dropped before anything else.
    Raises ``ValueError`` for anything else.
    """
    if not isinstance(remote, str):
        raise ValueError(_ERR_REMOTE)
    text = unicodedata.normalize("NFC", remote.strip(" \t"))
    if not text or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in text) or "\\" in text:
        raise ValueError(_ERR_REMOTE)
    scheme, authority, path = _split_remote(text)
    host, port = _host_and_port(authority, scheme)
    path = _normalize_escapes(path)
    path = re.sub(r"/{2,}", "/", path).strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    path = path.strip("/")
    if not path or any(seg in (".", "..") for seg in path.split("/")):
        raise ValueError("invalid repository path")
    return f"{host}{':' + port if port else ''}/{path}"
