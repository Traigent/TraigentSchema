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
dispositions. `legacy_content` can be added nowhere. A location leaves it only with a disposition
entry `{location, from, to, reason, reference}` (reason in words, reference to the inventory row or
design section); the test fails for a declassified location without one. Locations whose note
reads `INV-GAP: was <class>` were claimed content-free by the first annotation pass, but their
contract has no enum or ref pattern to prove it. Notes reading `reclassified by review` mark the
2026-10-16 honesty pass. The second sanctioned addition is the 2026-10-17 phase 0c pass: the
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

## Ref-addressed agent head and protected publish (plan v2.1, phase 0b, additive)

| Item | Contract |
|---|---|
| `GET /api/v1/best-configs/agent-heads/by-ref/{agent_ref}?environment=<SessionEnvironment>` | `optimization/best_config_head_endpoints.json`; 200 body `optimization/agent_head_by_ref_response_schema.json` = `{agent_ref, environment, generation (integer >= 0), exists}`, closed, no raw ids or names; `exists` is false iff `generation` is 0 |
| `X-Traigent-Agent-Ref` (request header) | `opaque_ref`, `agentref_<32 hex>` |
| `X-Traigent-Expected-Head-Generation` (request header) | `number`, integer 0 .. 2^53-1 |
| Closed envelope | `optimization/best_config_head_refusal_schema.json`: `reference_not_found` (404, the existing identity-ref refusal), `head_capture_invalid` (400), `head_environment_mismatch` (409), `head_agent_mismatch` (409), `head_generation_stale` (409), `head_write_unauthorized` (403), `head_body_invalid` (400), `head_publish_conflict` (409), and for the read route `unauthenticated` (401), `forbidden` (403), `internal_error` (500) |

**Applicability (decision table in the `POST /api/v1/best-configs` description).** Everything on this route applies only while the content-less identity layer is enabled (a server
deployment condition; the flag defaults OFF). With the layer disabled every response on this route is the legacy
one, whatever the headers. With the layer enabled, a publish is protected if and
only if it carries `X-Traigent-Agent-Ref` or belongs to a session negotiated with `content_less_v1`
(`content_less_v2` once it exists). Agent-Ref without a valid generation, or together with
`X-Traigent-Agent-Id`, is `head_capture_invalid`; the legacy `X-Traigent-Agent-Id` promotion outside a content-less
session, and a publish with no capture headers outside one, are the legacy path and unchanged.

**Protected rule.** The Backend resolves agent, run and environment from the stored session binding (never the
body), keeps agent WRITE authorization, and on any refusal writes no publication row and moves no head. Publish
and promote are one transaction; the head moves g -> g+1 (first promotion 0 -> 1) atomically with the
publication; of several promotions naming the same expected generation exactly one wins.

**Stale means the result is stale.** A `head_generation_stale` refusal is never cured by refreshing the
generation and resubmitting the same result. The SDK never auto-retries it: it starts a new run (or re-evaluates
against the new head) and publishes with that run's own captured generation.

**Canonical session id.** One parse, used identically to classify the publish and to store it. The session id is
`spec.provenance.source_session_id` (a string; the provenance object is closed, so there is no other session field, and
JSON null is not a valid value). Surrounding whitespace is trimmed once; an omitted or empty-after-trim value means the
publish names no session id (a manual publication). An id that is not a string, is longer than 128 characters after the
trim, or holds a whitespace or control character inside, or changes under Unicode NFC is malformed (an identifier is never
silently rewritten): it is refused and never treated as a manual publication, 400 `head_capture_invalid` on the protected
path (Agent-Ref present) and the existing legacy 400 validation body otherwise (no closed `error_code`); nothing is written
and no head moves. Only the trimmed value is stored, so a padded genuine session id is that session. Division of labour: the
request schema bounds source_session_id to a string of at most 512 characters; the trim, the 128-character limit, the
whitespace/control check and NFC stability are applied by the Backend to the raw value, identically for classification and
storage.

**Protected publish never returns free text.** Body validation failures are `head_body_invalid` (no key or value of the request
appears), the ordinary publish conflicts (If-Match on a new configuration, a changed configuration without a matching
If-Match, function_ref conflict) are `head_publish_conflict`, other server failures `internal_error`. The 409 response
(`optimization/best_config_publish_409_schema.json`) has two disjoint branches: the closed protected refusals and the
unchanged legacy bodies (which must not carry a protected closed code). The 500 response
(`optimization/best_config_publish_500_schema.json`) is built the same way: the closed `internal_error` refusal, or the
unchanged legacy generic body (`BEST_CONFIG_ERROR`), which must not carry `internal_error`. The 401 and 403 responses (`optimization/best_config_publish_401_schema.json`, `..._403_schema.json`) are built the same way for a request that carries `X-Traigent-Agent-Ref` while the layer is enabled: the authentication, permission and project-role layers answer with the closed `unauthenticated` / `forbidden` envelope (and the handler's `head_write_unauthorized`), never the generic body; the legacy branch must not carry any closed refusal code.

**Refusal precedence.** One order; the first stage that applies answers: (1) not authenticated, 401
`unauthenticated`; (2) permissions or project role denied, 403 `forbidden`; (3) malformed or incomplete capture, 400
`head_capture_invalid` (decision-table rows 1-3, judged from the request headers alone, before any session is read; a malformed provenance session id, see **Canonical session id**, is refused here the same way once the headers pass); (4)
**session binding resolution**, only when `spec.provenance` names a session id: the caller may not use the session 403
`head_write_unauthorized`, including a classic session positively read but owned by another caller, never 500 (a classic session is used by its owner only: for a user the central owner policy decides; for an API key that carries no user id in the default tenant the owner is the server-stamped key that created the session, so the same key reads it and publishes on the legacy path and a different key is refused), the session is deleted, not registered or outside the caller's scope 404 `reference_not_found`,
the lookup is ambiguous, fails or times out, or the stored binding is damaged (a typed id without a well-formed
`content_less` block) 500 `internal_error`; (5) the resolved binding against the request (decision-table rows 4 and 6), 400
`head_capture_invalid`; (6) a well-formed but unknown or foreign ref, 404 `reference_not_found` (nothing echoed); (7) agent
WRITE denied, 403 `head_write_unauthorized`; (8) session agreement, 409 `head_agent_mismatch`; (9) 409
`head_environment_mismatch`; (10) the body, 400 `head_body_invalid`; (11) the head compare, 409 `head_generation_stale`; (12)
the ordinary conflict, 409 `head_publish_conflict`. Stages 1 and 2 are the closed envelopes of the publish's authentication
layers and are selected by a header predicate alone, evaluated before any session is resolved: the request is protected for
that stage iff the layer is enabled and it carries `X-Traigent-Agent-Ref` (layer disabled: every response is legacy).
Everything after authentication follows the session-based decision table of the publish operation. Decision-table row 4
(Agent-Ref without a resolvable content-less binding) is stage 5: it applies only when stage 4 resolved a binding that is not
content-less, or the publish names no session; a session that cannot be positively read is answered by stage 4, never by
row 4. **Legacy allow-list:** the legacy path is taken only when (a) the publish names no session id, or (b) the named
session was positively read (a lookup that succeeded and returned a well-formed record) and is not content-less (a classic
session, or a typed session whose stored shape is legacy), or the named id is outside the typed namespace and positively
absent (every lookup succeeded and found nothing); every other outcome is refused at stage 4 and writes nothing. A
content_less_v1-session publish without the header therefore gets the generic 401/403 on an authentication or permission
failure (accepted: it is refused 400 `head_capture_invalid` once authenticated, so it never succeeds without the capture).
On the read route a malformed path ref or `environment` is 400, an unknown or foreign ref 404.

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
