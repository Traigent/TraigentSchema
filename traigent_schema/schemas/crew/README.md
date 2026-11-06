# crew domain

Contract for **crews** (CREW-11, Crews program slice 0; design: Crews v1 sections 1-3).
A *crew* is a named set of agents that cooperate on one job. A *fleet* is all agents of a
project (existing). A *role* is a slot in a crew; a *crew revision* is an immutable snapshot
of roles + bindings; a *crew run* is one end-to-end execution; a *handoff* is one directed
transfer of work between roles inside a run (not `agent_handoff`, which is team ownership).

## Files

| File | What |
|---|---|
| `crew_common_schema.json` | ids, closed enums, error codes |
| `crew_schema.json`, `crew_role_schema.json`, `crew_revision_schema.json`, `crew_role_binding_schema.json` | slice-1 entities |
| `crew_*_request_schema.json`, `crew_*_response_schema.json`, `crew_error_schema.json` | slice-1 API shapes |
| `crew_endpoints.json` | `/api/v1/crews`, `/{crew_id}`, `/{crew_id}/archive`, `/{crew_id}/roles`, `/{crew_id}/revisions` (declared ahead of the backend: `x-asserted-against-backend: false`) |
| `crew_run_schema.json`, `crew_member_execution_schema.json`, `crew_handoff_schema.json` | slice-3 execution shapes, **contract only, no API yet** |

## Privacy: content vs identifiers (constitution 11, GNFR-PRIV-002/003)

| Class | Fields | Annotation |
|---|---|---|
| CONTENT | `crew_key`, `name`, `description`, `role_key` | `x-content: true` + `x-privacy-classification: user_content`. Crew tables and portal only. |
| Identifier | `crew_id`, `crew_revision_id`, `role_id`, `role_token`, `crew_run_id`, `invocation_id` | `x-identifier: true`. The only crew values allowed in traces, baggage, optimizer keys (`<role_token>__<param>`) and Director inputs. |

`role_token` is lowercase alphanumeric so it never contains `__`. Traces, baggage and
Director inputs carry only ids, counts and the closed enums defined here. Observability is
not privacy-preserving; content work stays customer-side.

## Rules encoded

- `crew_key` is the create idempotency key; role upsert is idempotent by `role_key`.
- Errors are closed: 409 carries a `crew_error_schema.json` body with a closed `error_code`
  (e.g. `crew_binding_conflict`) and never echoes client values.
- Accounting: exclusive (self) cost/latency/tokens are additive; inclusive is a view only;
  unknown stays `null`, never 0. Crew metrics aggregate by crew-run membership.
- `unit_ref` is reserved (must be null until slice 4). `inferred_suggestion` provenance never
  grants membership.

SDK status: not implemented in the Python or JS SDK (see `parity/capabilities/registry.v1.json`,
capability `crew.declarations`).
