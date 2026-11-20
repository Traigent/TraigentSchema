# Fleet Observe canonical request digest, version 1

Status: contract (TRAIG-179). Reference implementation:
`traigent_schema/fleet_observe_digest.py`. Shared vectors: `request_digest_vectors.json`.

## Why

A resumable import re-sends the same bytes after a disconnect. The server must be able to tell
"the same request again" (replay, 200) from "the same idempotency key with a different request"
(a bug, closed 409 `fleet_observe_idempotency_conflict`). That needs one digest of the request that
does not depend on member order, duplicate members, timestamp spelling or defaulted fields.

## Input

A parsed import request as accepted by `POST .../fleet-observe/imports`
(`import_request_schema.json`): `source_kind`, `boundary{boundary_kind, boundary_digest}`,
`observed_at`, optional `retention_class`, `members`. `idempotency_key` is **excluded**: it is derived
from the digest below, so including it would be circular.

## Canonical preimage

UTF-8 JSON, no whitespace (`separators=(",", ":")`), keys in exactly this order, all values ASCII:

1. `v`: the string `fleet_import_request_v1`
2. `source_kind`
3. `boundary_kind`
4. `boundary_digest`
5. `observed_at`: normalized to UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always six fractional digits. Every
   contract `Timestamp` spelling of one instant (`...00Z`, `...00.0Z`, `...00.000000Z`, `.5Z`,
   `.500000Z`) maps to one string. Only the trailing-`Z` form is a valid input: the API server rejects
   a `+00:00` offset with its closed 400, so an offset has no canonical form and is rejected.
6. `retention_class`: the default `ledger_minimal` applied when absent
7. `members`: exact duplicates collapsed; each member is the array `[member_kind, member_digest,
   parent_member_digest-or-null]`; the list is sorted ascending by (member_kind, member_digest,
   parent) comparing strings bytewise, a null parent before any digest. An omitted parent and an
   explicit `null` are the same. A parent change therefore changes the digest. Validity rules the
   digest does not repair, all rejected: one member digest with two different parents (a null and a
   digest count as different); a parent equal to the member; a parent cycle of any length (A to B to
   A); and fewer than 1 or more than 5000 members **in the original array, counted before
   collapse**. Because one member digest has one parent, the parent never decides the order of two
   members in a valid request; it only completes the total order.

## Digests

- `request_digest` = `sha256:` + lowercase hex of SHA-256(preimage bytes).
- `idempotency_key` = `sha256:` + lowercase hex of SHA-256(UTF-8 of `fleet_idem_v1` + U+001F +
  `request_digest`), where `request_digest` is the full `sha256:<hex>` string. Deterministic and not
  circular.

## Server use (planned)

The API server recomputes the request digest from the parsed request (after de-duplication and
defaults) and stores it on the import event. On both replay paths (the pre-check and the concurrent
insert path) a stored digest that differs from the recomputed one answers the closed 409. Rows
stored before the digest column existed have no digest and keep replaying on the key alone.

## Vectors

`request_digest_vectors.json` lists `valid` inputs with exact expected digests and idempotency keys,
groups of inputs that must produce one digest (`same_digest_group`: order permutation, duplicate
collapse, key exclusion, default vs explicit retention, fractional-second spellings), inputs that
must differ (a parent change, retention, source, boundary, one microsecond), and `invalid` inputs
that must be rejected. Both the SDK and the API server run these through their own implementation.
