# Content classes (`x-content-class`)

Phase 1 of the content-less optimization design: every application-level value an
optimization channel carries between a customer machine and Traigent servers must be
one of the classes below. This note defines the vocabulary; `scripts/content_class_lint.py`
enforces it and `tests/test_content_class_lint.py` pins it.

| Class | Meaning |
|---|---|
| `opaque_ref` | Server-issued opaque reference (UUIDs, `<kind>ref_<32 hex>`, keyed content-identity tokens). |
| `closed_enum` | Value from a closed vocabulary (enums, constants, booleans). |
| `number` | Bounded number (counts, scores, durations, costs). |
| `digest` | Approved hash or digest (`sha256:...`, git object ids). |
| `key_material` | Public key, signature, salt, nonce or authenticator-generated credential id: base64url, bounded. |
| `timestamp` | Point in time. |
| `code_identifier` | Verified code identifier (function ref, module, repo-relative path). |
| `encrypted_blob` | Label-service ciphertext, accepted only by the label service. |
| `auth_header` | Allow-listed transport or authentication header. |
| `version` | Dotted numeric version string (digit groups only, bounded). |
| `server_text` | Server-composed text from fixed templates; never request-derived. |
| `legacy_content` | **Transitional.** Carries, or may carry, customer content today and is scheduled for removal by the content-less plan. |

`legacy_content` makes today's leaks visible instead of passing them: it is not a class a
new field may use. Every `legacy_content` annotation carries an `x-content-note` citing the
inventory row (for example `INV S1-14 (LEAK): function_name`), or `INV-GAP` when the field
is not in the inventory. The lint lists every `legacy_content` location; that list is the
checklist for the removal phase (P3). The manifest (below) pins every location.

## What each class must prove

A class name alone proves nothing, so the lint checks the node's own keywords
(`semantic_problem` in `scripts/content_class_lint.py`; negative tests for each in
`tests/test_content_class_lint.py`). A value that cannot meet its class is `legacy_content`, never
a looser class.

| Class | Required |
|---|---|
| `closed_enum` | `enum`, `const`, or a boolean type |
| `number` | integer/number type, numeric bounds, `minimum <= maximum` |
| `digest` | a pattern that accepts a 64-hex digest (bare or `sha256:`) and nothing of other lengths or free text |
| `key_material` | the base64url pattern `^[A-Za-z0-9_-]+$` and a `maxLength` |
| `timestamp` | `format: date-time`/`date`, or a timestamp pattern |
| `opaque_ref` | an approved ref pattern: UUID, `<kind>ref_<32 lowercase hex>` (a Backend-issued opaque reference resolved within tenant/project, distinct from the Backend primary key), key id, or one of the fixed derived-token patterns listed in the lint |
| `code_identifier` | a dotted `module:qualname` or repo-relative path pattern that rejects free text |
| `version` | an anchored pattern of digit groups joined by dots (`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?![\s\S])`, an absolute end that a trailing newline cannot pass) that accepts `1.2.3` and rejects text, and a `maxLength` |
| `server_text` | a `maxLength` and an `x-content-note` naming the fixed-template source. Keywords cannot prove it (prose is prose), so it is an assertion by the contract owner, accepted only at the exact (file, JSON pointer) locations in the lint's `SERVER_TEXT_LOCATIONS` allow-list (today one response field); never in a request, a parameter, a map key (it is not a key class) or through a `$ref` from elsewhere |
| `encrypted_blob` | only inside `labels/` (base64url + `maxLength`); elsewhere a node must `$ref` the label envelope |

Map-key classes are checked against `propertyNames` the same way.

## Where the annotation goes

On every value node of an optimization-channel contract: object properties, array `items`,
map values (`additionalProperties` / `patternProperties`), `propertyNames`, parameter
schemas and response-header schemas. Map keys are classed by `x-content-class` on
`propertyNames`, or by `x-content-key-class` on the map node. A node that is a `$ref` (or a
composition of refs) inherits the class of its target; pure containers (an object or array
whose children are all classed) need none. An object with open extras
(`additionalProperties: true`) is a value node: its class describes the extra keys and values.
`if`/`then`/`else`/`not` branches are walked: a branch may re-constrain a property whose primary
declaration (own `properties`, `allOf`, `$ref`) is already classified, but any property it
introduces must carry its own class. Empty placeholder properties (`{}`) next to `allOf`/`$ref`
are skipped.

Composition branches (`oneOf`/`anyOf`/`allOf`) are walked too: a class declared inside a branch is
recorded at the branch's own pointer (`.../oneOf/0`) in the manifest and, for `legacy_content`, in the
register. A class placed on a node that is only a union is a claim about every branch, so each
branch is validated against it (a `closed_enum` union with a free-string branch is invalid).
Any object (root or nested) that accepts extra properties must declare both `x-content-class` and `x-content-key-class` (open roots can only
be `legacy_content`: their extra names are unconstrained) or be closed with
`additionalProperties: false` (or `unevaluatedProperties: false`). Open-object checks also run on objects inside `oneOf`/`anyOf`/`allOf` branches (not when the
enclosing node or an `allOf` sibling closes the object). `then`/`else` branches are checked too unless
an enclosing object node is already classified there, so a conditional-only root whose `then` is an
open object must classify it; `if` and `not` accept nothing and are not checked. In Draft-4/6/7
(and OpenAPI 3.0, and documents without `$schema`) keywords beside `$ref` are ignored, so the
`$ref` target alone is checked against a class claim; a branch's own class never proves the
parent's claim, the parent's class is checked against the branch's constraints. `unevaluatedProperties: false` closes an object only in 2019-09+ documents
(or OpenAPI 3.1); Draft-7 documents must use `additionalProperties: false`.
A content-free class must hold for every branch that can accept a value: `allOf` members
intersect (one restricting member suffices), every `anyOf`/`oneOf` alternative must hold, and
unconstrained `{}` / `true` alternatives fail. An object that OMITS
`additionalProperties` is open in JSON Schema and is treated as open; existing ones are
classified `legacy_content` ("implicit-open, reclassified by review") rather than tightened.

## Manifest and dispositions

`docs/content-class-manifest.json` maps every annotated location (`file#pointer`) to its class;
`python3 scripts/content_class_manifest.py --update` regenerates it and the test fails if it
differs from the live annotations. `docs/content-class-dispositions.json` holds the
`legacy_register` (every location that was `legacy_content` when the manifest was created) and the
dispositions. `legacy_content` can be added nowhere: a NEW contract property is never allowed to be `legacy_content`, and the
inventory exception below does not change that. A location leaves it only with a disposition
entry `{location, from, to, reason, reference}` (reason in words, reference to the inventory row or
design section); the test fails for a declassified location without one. Locations whose note
reads `INV-GAP: was <class>` were claimed content-free by the first annotation pass, but their
contract has no enum or ref pattern to prove it. Notes reading `reclassified by review` mark the
2026-10-16 honesty pass. The second sanctioned addition is the 2026-10-17 phase 0c pass. It discovers EXISTING wire locations that the lint
did not yet walk and records them as `legacy_content`; it never authorizes a new `legacy_content` field, and a
property added to any contract after that pass must carry a content-free class. In that pass the
best-config endpoints and their publish / rollback request bodies
(`execution/best_config_endpoints.json`, `best_config_publish_request_schema.json`,
`best_config_rollback_request_schema.json`) became lint roots, so values that were always on the wire
became visible. Customer-chosen values there (`config_id`, `function_ref`, free-form `metadata`, and the
already annotated legacy response branches) are `legacy_content` with an `INV` note; ETag preconditions
(`If-Match`, `If-None-Match`) are `auth_header`; the rollback `version` is a `number`. Nothing was relabelled to a
content-free class that its schema cannot prove.

### Anchored ratchet

The manifest and dispositions sit in the same tree as the annotations, so the ratchet reads the
copies on `origin/develop` (`git show`, 30 s timeout) as its anchor. With an anchor: a
`legacy_content` location absent from the anchored manifest fails, a registry entry or disposition
cannot be removed or edited, and an anchored legacy location moved to a content-free class needs a
disposition whose `reference` verifies (`path:line` of an existing line, `INV <route>-<row>` (the field row must exist in
`docs/content-class-reference-ids.json`), or `DESIGN-v2.2 §<section>`). Without an anchor (first
introduction) the working-tree manifest must equal the live annotations exactly. If git or the ref
is unavailable the check fails; it never skips (`python3 scripts/content_class_manifest.py --check`).

### Old-dialect references

In Draft 4-7, OpenAPI 3.0 and documents without `$schema`, a `$ref` resolves against the document
root. The lint does not model base URIs, so such a document may not declare a nested `id`/`$id` or a
`definitions`/`$defs` outside the root,. Anything else fails with a fixed error; shared definitions live in their own schema file and are
referenced by file.

## Session-create identity and capability negotiation (P3 group 1, additive)

`POST /api/v1/sessions` carries these additive, optional members (old fields stay `legacy_content`
until the Backend and SDKs stop sending them; nothing is reclassified by adding them):

| Member | Class | Source |
|---|---|---|
| `dataset_ref`, `evaluation_set_ref`, `evaluator_ref`, `agent_ref` | `opaque_ref` (`<kind>ref_<32 hex>`) | `labels/label_common_schema.json` |
| `environment` | `closed_enum` (`production`, `staging`, `development`, `test`, `default`) | `optimization/session_capabilities_schema.json` |
| `capabilities` (request and 201 response) | list of `closed_enum` (`content_less_v1`) | `optimization/session_capabilities_schema.json` |

**How the Backend tells the shapes apart.** One request contract serves both, because every new member is
optional. A session is content-less if and only if the request `capabilities` contains `content_less_v1`;
the Backend records that shape at create. Absence means the legacy shape. The response `capabilities`
advertises what the Backend supports; a content-less client that does not find `content_less_v1` there
refuses with `backend_upgrade_required` and never falls back to plaintext.

Negotiation by membership: request `capabilities` absent or `[]` means the legacy shape (accepted before the
tenant cutoff, refused after it with `client_upgrade_required`). Response `capabilities` absent or `[]`
means the Backend does not support the content-less contract: a content-less client refuses locally
with `backend_upgrade_required` and never falls back to plaintext. `backend_upgrade_required` is
client-local and never appears on the wire; the wire refusal envelope
(`optimization/optimization_refusal_schema.json`) therefore admits only `client_upgrade_required` and
`session_shape_legacy`. No other closed optimization refusal codes exist in the Schema today.

Closed refusal codes (`OptimizationRefusalCode`, carried in the error envelope's `error_code`; a refusal
never echoes the request): `client_upgrade_required` (legacy client after tenant cutoff),
`backend_upgrade_required` (client-side refusal, Backend lacks the capability), `session_shape_legacy`
(content-less client resumed a legacy-shape session; it ends that session locally and starts a new one).
The error envelope's own `error_code` is still a free string (`legacy_content`); these three are the first
members of its closed vocabulary.

## Ref-addressed agent head and best-config publish

| Item | Contract |
|---|---|
| `GET /api/v1/projects/{project_id}/agents/{agent_ref}/best-config-head?environment=<SessionEnvironment>` | `optimization/best_config_head_endpoints.json`; 200 body is declared inline there = `{success, data: {agent_id, environment, generation (integer >= 0), best_config_id, best_config_version, promoted_by_run_id, updated_at}}`; `generation` 0 means never promoted (the by-ref form and its closed `exists` response schema were removed: the backend never served them) |
| `X-Traigent-Agent-Ref` (request header) | `opaque_ref`, `agentref_<32 lowercase hex>` |
| `X-Traigent-Expected-Head-Generation` (request header) | `number`, integer 0 .. 2^53-1 |

The head read returns 400 for a malformed path ref or `environment` and 404 for an
unknown or foreign ref.

**Publish never moves the head.** When `X-Traigent-Agent-Id`, `X-Traigent-Agent-Ref`
and `X-Traigent-Expected-Head-Generation` are all absent, this is an ordinary publish.
For a new configuration, omit `If-Match`. For a changed existing configuration, send the
current ETag as `If-Match`. An identical spec returns the current version even with a stale
`If-Match`.

The presence of any of the three head headers, including an empty value, requests a head
move. Send exactly one of `X-Traigent-Agent-Id` or `X-Traigent-Agent-Ref` together with
`X-Traigent-Expected-Head-Generation` for a syntactically valid head-move request.
The agent ID must be non-empty and at most 512 characters after trimming. The agent ref must
be `agentref_` followed by 32 lowercase hex digits. The expected generation must be 1 to 16
decimal digits with a value from 0 through 9007199254740991.

Before the route, malformed JSON and some unsafe strings can be refused with 400. The
idempotency check runs before the separate unsafe-JSON-string guard that can return 422, and
before the route checks head headers. If a reused Idempotency-Key has a different request
fingerprint, including added, changed or removed head headers, it can return 409 before
those later checks.

Authentication, `experiment.write` permission, editor role and an explicit tenant and
project write scope gate the route. In the route, incomplete, conflicting or malformed head
headers return 400 `AGENT_HEAD_VALIDATION_ERROR` before agent authorization. The body has
`success: false` and the same fixed validation text in `error` and `message`. An empty JSON
body that reaches the head-move handler returns 400 `BEST_CONFIG_VALIDATION_ERROR` after
header validation and before the agent decision.

An unknown agent, an agent outside the request's tenant and project, an opaque reference
that cannot be resolved in that scope, or a caller without agent write access receives the
same 404 `reference_not_found`. Where per-owner access applies, an agent whose creator is
missing or differs from the caller also receives that 404. Per-owner access applies to
non-platform-admin callers in the shared default tenant on an unpinned deployment. In an
explicitly scoped collaboration project, an editor with agent write access can receive 409
`acceptance_required` for an agent created by another member.

The masked 404 has the following body.

```json
{"success":false,"error":"reference_not_found","error_code":"reference_not_found","message":"Reference not found."}
```

An agent the caller is authorized to write returns 409 `acceptance_required` with the
following body.

```json
{"success":false,"error":"release_precondition_refused","error_code":"acceptance_required","message":"A release acceptance is required."}
```

The agent decision precedes configuration validation. Neither refusal publishes a configuration
or version or changes the head or head history. Both refusals set `Cache-Control: private, no-store`
and `Vary: Authorization`, and omit `ETag` and `X-Traigent-Head-Generation`.
The cross-origin response can also vary by `Origin`.
A retry of a refused request with the same `Idempotency-Key` may return an idempotency 409
instead of the refusal. It never returns a success.

To move an agent's head, publish without the head headers, record a person's release
acceptance with `best_configs.create_release_acceptance`, then call `best_configs.release_agent_head`.

## Token issuance (plan v2.1, phase 1b-2a, additive, flag-gated)

| Item | Contract |
|---|---|
| `POST /api/v1/optimization/token-refs` | `optimization/token_refs_endpoints.json`; bodies in `optimization/token_refs_schema.json`: request `{schema_version (1), agent_ref, operation_key, items:[{kind: knob/choice/metric/template, parent_ref?}] (1..200)}`, response `{refs:[<kind>ref_<32 hex>]}` in item order |
| `operation_key` | `key_material`, a client-generated 128-bit random nonce, 32 lowercase hex characters; idempotency key per tenant and project |
| `parent_ref` | `opaque_ref`, `knobref_<32 hex>`; required for `choice`, forbidden for the other kinds |
| Closed envelope | `invalid_request` (400), `flag_disabled` (reserved; flag off answers the uniform unknown-route 404), `reference_not_found` (404), `operation_key_conflict` (409), `quota_exceeded` (429, reserved), `internal_error` (500), `service_unavailable` (503, Retry-After preserved); fixed text, nothing echoed |

Replay: the same key with the same agent, item count and items returns the stored refs; any difference is
`operation_key_conflict`, and a replay never adds or removes tokens. No field carries customer content: refs,
closed enums and a random nonce.

## Negotiated label write (plan v2.1, phase 1b-2b, additive, flag-gated)

| Item | Contract |
|---|---|
| `POST /api/v1/optimization/labels` | `optimization/label_write_endpoints.json`; bodies in `optimization/label_write_schema.json`: request = the label write (`labels/label_io_schema.json#/definitions/LabelWriteRequest`: `object_ref`, `purpose`, `base_revision`, `epoch`, `envelope`) plus `schema_version` (1); response = `LabelWriteResponse` (no envelope) |
| `object_ref` | `opaque_ref`; on this route it must be an ISSUED reference of its kind in the caller's tenant and project (mode switch `LABEL_VALIDATE_ISSUED_REFS` = `off` / `negotiated` / `global`, shipped `off`) |
| `envelope` | `encrypted_blob`, the only content-bearing field, classed exactly as in the label contract |
| Closed envelope | `invalid_request` (400), `reference_not_issued` (422), `stale_revision` / `stale_epoch` / `conflict` (409), `internal_error` (500), `service_unavailable` (503, Retry-After preserved); fixed text, nothing echoed. While dark the route answers the uniform unknown-route 404 |

The legacy `PUT /api/v1/labels/objects` is unchanged. The discriminator is the route, not a header or body flag.

## Release acceptance, release and head rollback (additive)

`optimization/release_acceptance_schema.json` holds the closed request, receipt, read-model and
refusal definitions; `optimization/release_endpoints.json` declares the planned routes
(`.../agents/{agent_ref}/release-acceptances` POST and GET, `.../best-config-head/release`,
`.../best-config-head/rollback`). A person's acceptance binds the candidate fingerprint, a
required gate-result digest (a 64-hex digest, or the fixed value `no_gate_run`), the configuration-space
digest, the agent code version and the expected head generation. The refusal envelope
(`ReleaseRefusal`) has one fixed message per code and echoes no request value. `HeadHistoryEntry`
adds `actor_id`, `actor_kind` (`user` | `service_principal`, both null on entries written before actors were recorded) and a nullable `acceptance_id` to the head
history read model.

## Scope and commands

Every document under `traigent_schema/schemas/optimization/` and `traigent_schema/schemas/labels/` (OpenAPI inventories included),
the guidance plan/result documents, and every fragment those reference (configuration-run
measures, content identity, common types, error/success envelopes). `legend/*` is closed by
design and excluded.

```bash
python3 scripts/content_class_lint.py --report   # per-class counts
python3 scripts/content_class_lint.py --legacy   # + every legacy_content location
python3 scripts/content_class_manifest.py --check
python3 -m pytest tests/test_content_class_lint.py -q
```

The extension keywords are registered in `x_extensions_meta_schema.json`. Annotations are
documentation: they change no type, `required` entry or validation.
