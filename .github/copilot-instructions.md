## Traigent Spine workflow

The read-only `traigent-ops` MCP server (Spine profile `core`) is available in
VS Code once it is registered in your **user profile** (run the
`code --add-mcp …` command printed by the workspace agent-bootstrap `render`);
it is user-scoped, not a committed repository file. For feature,
cross-repository, unfamiliar, release-impacting, or high-risk work, consult the
Spine before planning edits:

1. Call `ops.state.snapshot`, then `ops.gaps.top_blockers` (compact), then
   `ops.gaps.explain` / `ops.recommend.patch_plan` for the top blocker.
2. For a specific feature, add `ops.features.manifest`,
   `ops.features.release_readiness`, and `ops.features.related_gaps`. Treat
   unresolved anchors, conflicts, and stale references as work to verify — not
   as proof of current product state.
3. Execute every blocking product-verification obligation against current code,
   tests, and effective runtime/deployment state before claiming completion.
4. For policy surfaces, security, billing, tenant, privacy, incidents, or
   cross-repository work, create/link a Spine ChangeSession and keep changes
   within its admitted packet scope.

The Spine is advisory navigation and governance. It never grants write,
approval, waiver, or release authority, and it never replaces product
verification. "Ready" from the bootstrap doctor means the local client wiring is
trustworthy — required prerequisites pass, every installed client resolves to the
canonical Spine runtime, and that checkout is clean — **not** that a change is
correct or a release is safe.

Because TraigentSchema is the single source of truth for API contracts, start
request/response shape changes here and propagate them to the SDK, backend, and
frontend consumers in the same change set.
