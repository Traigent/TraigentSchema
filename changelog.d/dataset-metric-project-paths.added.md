- **Project-scoped dataset paths.** Datasets, their examples, files, upload,
  example generation, public-benchmark marking and version content identity
  are declared under `/api/v1/projects/{project_id}/datasets/...`. Additive:
  no existing path is removed; the unscoped dataset paths stay and are marked
  deprecated, with removal unscheduled.
- **Metric operations.** New `metric.*` operations: list and create a
  project's metrics at `/api/v1/projects/{project_id}/metrics`; list and
  create library metrics at `/api/v1/metrics`; and get, update (`PATCH`) and
  delete one metric at `/api/v1/metrics/{metric_ref}`. Metric descriptions may
  be null. Writes reject evaluator fields with a closed validation problem.
- **Fragment references.** The schema validator resolves `$ref` values that
  point into another file (`file.json#/pointer`).
