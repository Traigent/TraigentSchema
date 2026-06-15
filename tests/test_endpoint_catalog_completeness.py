"""#127: every endpoint catalog must be wired into a master module list, and the
previously-orphaned best-config family must resolve through SchemaValidator."""
from __future__ import annotations

import json
from pathlib import Path

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

MASTERS = {
    "mep_endpoints.json",
    "sdk_tuning_endpoints.json",
    "planned_projects_endpoints.json",
}


def _referenced_catalogs() -> set[str]:
    """Transitive set of catalogs reachable from the master roots."""
    schemas = get_schemas_dir()
    referenced: set[str] = set()

    def collect(rel_path: str) -> None:
        path = schemas / rel_path
        if not path.exists():
            return
        with open(path, encoding="utf-8") as fh:
            spec = json.load(fh)
        for module in spec.get("x-endpoint-modules", []):
            paths_file = module.get("paths_file")
            if not paths_file:
                continue
            target = (Path(rel_path).parent / paths_file).as_posix().lstrip("./")
            target = target.replace("../", "")
            if target not in referenced:
                referenced.add(target)
                collect(target)

    for master in MASTERS:
        collect(master)
    return referenced


def test_no_orphan_endpoint_catalogs():
    schemas = get_schemas_dir()
    all_catalogs = {p.relative_to(schemas).as_posix() for p in schemas.rglob("*_endpoints.json")}
    referenced = _referenced_catalogs()
    orphans = sorted(c for c in all_catalogs if c not in referenced and c not in MASTERS)
    assert not orphans, (
        f"endpoint catalogs not referenced by any master (SchemaValidator never loads them, "
        f"so their routes fail-open): {orphans}"
    )


def test_best_config_routes_resolve_through_validator():
    validator = SchemaValidator(contract="backend")
    # POST /api/v1/best-configs must now bind its publish request schema...
    assert validator._endpoint_schemas.get("POST:/api/v1/best-configs") == (
        "best_config_publish_request_schema"
    )
    # ...and validate (was fail-open / [] before wiring): an empty body violates required `spec`.
    assert validator.validate_request("/api/v1/best-configs", "POST", {})
    assert validator.validate_request("/api/v1/best-configs/c1/rollback", "POST", {}) is not None
