# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Pin `exportProjectFineTuningManifest`'s path to the real, shipped backend route.

Closes TraigentSchema#272. `planned_projects_endpoints.json` declared this operation at
`/api/v1beta/projects/{project_id}/core-exports/fine-tuning.manifest`, but the backend
implements it on `analytics_bp` (`src/routes/analytics_routes.py`, route
`/exports/fine-tuning.manifest`), which the v1beta project-scoped registrar
(`src/routes/api_v1beta.py::_register_project_scoped`) mounts at
`/api/v1beta/projects/<project_id>/analytics/exports/fine-tuning.manifest` — there is no
`core-exports`-prefixed route for this operation anywhere in the backend (that prefix is used
by the sibling `exportProjectFineTuningJsonl` operation only, which the schema already declares
correctly). A client following the old declared path would 404.
"""
from __future__ import annotations

import json

from traigent_schema.utils import get_schemas_dir

CORRECT_PATH = "/api/v1beta/projects/{project_id}/analytics/exports/fine-tuning.manifest"
DRIFTED_PATH = "/api/v1beta/projects/{project_id}/core-exports/fine-tuning.manifest"


def _load_planned_projects_spec() -> dict:
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "planned_projects_endpoints.json", encoding="utf-8") as handle:
        return json.load(handle)


def test_export_fine_tuning_manifest_path_matches_live_backend_route() -> None:
    spec = _load_planned_projects_spec()
    paths = spec["paths"]

    assert CORRECT_PATH in paths, (
        "exportProjectFineTuningManifest must be declared at the real, shipped "
        f"analytics-blueprint path; got paths={sorted(paths)}"
    )
    operation = paths[CORRECT_PATH]["get"]
    assert operation["operationId"] == "exportProjectFineTuningManifest"


def test_export_fine_tuning_manifest_no_longer_uses_drifted_core_exports_path() -> None:
    spec = _load_planned_projects_spec()
    assert DRIFTED_PATH not in spec["paths"], (
        "the drifted core-exports path must not reappear; the real backend route for "
        "this operation lives under /analytics/exports, not /core-exports"
    )


def test_sibling_fine_tuning_jsonl_export_still_uses_core_exports_path() -> None:
    """exportProjectFineTuningJsonl genuinely lives under core-exports (backend
    `core_exports_bp`, `src/routes/core_metrics_routes.py`) — only the manifest
    operation had drifted, so this sibling path must be left untouched."""
    spec = _load_planned_projects_spec()
    jsonl_path = "/api/v1beta/projects/{project_id}/core-exports/fine-tuning.jsonl"
    assert jsonl_path in spec["paths"]
    assert spec["paths"][jsonl_path]["get"]["operationId"] == "exportProjectFineTuningJsonl"
