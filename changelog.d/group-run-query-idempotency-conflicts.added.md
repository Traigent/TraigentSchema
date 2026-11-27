- **Idempotency conflicts on the group run query.**
  `experiment_group.query_group_runs` declares its `409` responses
  (`idempotency_conflict`, `idempotency_in_progress`).
