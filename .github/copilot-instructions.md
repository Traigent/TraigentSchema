## Traigent Spine workflow

For feature, cross-repository, unfamiliar, release-impacting, or high-risk
work, call `traigent-ops` before planning edits:

1. Call `ops.agent.orient` and task-scoped `ops.agent_rules.context`.
2. Call `ops.agent.ground` once for the affected feature, module, or change
   set. Treat unresolved anchors, conflicts, and stale references as work to
   verify, not proof of current product state.
3. Execute every blocking product-verification obligation against current code,
   tests, and effective runtime/deployment state before claiming completion.
4. For policy surfaces, security, billing, tenant, privacy, incidents, or
   cross-repository work, create/link a `Spine-Session` and keep changes within
   its admitted packet scope.

Because TraigentSchema is the single source of truth for API contracts, start
request/response shape changes here and propagate them to the SDK, backend, and
frontend consumers in the same change set.

The Spine is advisory navigation and governance. It never grants write,
approval, waiver, or release authority and never replaces product verification.

MCP client setup for `traigent-ops` (server command, project path, profile)
belongs to your workspace or user-profile bootstrap, not to a repository-local
config. This repository intentionally ships no committed client MCP
configuration; configure the server once in your environment so the same setup
serves every repository.
