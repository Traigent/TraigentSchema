# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Regression guards for the mixed-maturity economics endpoint catalog."""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

_TELEMETRY_BOUND_LEAVES = (
    "economics_telemetry_ingest_request_schema.json",
    "economics_telemetry_ingest_response_schema.json",
    "economics_telemetry_ingest_response_initial_schema.json",
    "economics_telemetry_ingest_response_replay_schema.json",
)
_STALE_TELEMETRY_PROSE = (
    "before backend ingestion",
    "ahead of backend ingestion",
    "no backend route serves",
    "when backend ingestion lands",
)


def _load_json(path) -> dict:
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def test_economics_catalog_is_discoverable_with_operation_scoped_assertions() -> None:
    """#365 — canonical discovery must not suppress asserted telemetry."""
    schemas_dir = get_schemas_dir()
    with open(schemas_dir / "mep_endpoints.json", encoding="utf-8") as handle:
        root = json.load(handle)

    assert any(
        module.get("paths_file") == "./economics/economics_endpoints.json"
        for module in root["x-endpoint-modules"]
    )

    validator = SchemaValidator(contract="backend")
    assert validator._endpoint_schemas.get("POST:/api/v1/economics/telemetry") == (
        "economics_telemetry_ingest_request_schema"
    )
    assert validator._endpoint_schemas.get("POST:/api/v1/economics/recommendation") == (
        "economics_recommendation_request_schema"
    )

    with open(
        schemas_dir / "economics" / "economics_endpoints.json", encoding="utf-8"
    ) as handle:
        catalog = json.load(handle)

    assert "x-stability" not in catalog
    assert "x-asserted-against-backend" not in catalog
    operations = {path: item["post"] for path, item in catalog["paths"].items()}
    assert [
        path
        for path, operation in operations.items()
        if operation.get("x-asserted-against-backend") is False
    ] == ["/api/v1/economics/recommendation"]
    assert (
        operations["/api/v1/economics/telemetry"]["x-asserted-against-backend"] is True
    )


def test_operation_scope_is_the_only_telemetry_assertion_authority() -> None:
    """#365 - bound leaves and compatibility prose must not contradict the operation."""
    schemas_dir = get_schemas_dir()
    economics_dir = schemas_dir / "economics"
    catalog = _load_json(economics_dir / "economics_endpoints.json")
    operations = {path: item["post"] for path, item in catalog["paths"].items()}

    assert (
        operations["/api/v1/economics/telemetry"]["x-asserted-against-backend"] is True
    )
    assert (
        operations["/api/v1/economics/recommendation"]["x-asserted-against-backend"]
        is False
    )

    for filename in _TELEMETRY_BOUND_LEAVES:
        leaf = _load_json(economics_dir / filename)
        assert "x-asserted-against-backend" not in leaf, filename
        leaf_prose = json.dumps(leaf).lower()
        for stale_phrase in _STALE_TELEMETRY_PROSE:
            assert stale_phrase not in leaf_prose, (filename, stale_phrase)

    planned = _load_json(schemas_dir / "planned_projects_endpoints.json")
    economics_module = next(
        module
        for module in planned["x-endpoint-modules"]
        if module["paths_file"] == "./economics/economics_endpoints.json"
    )
    planned_prose = " ".join(
        (
            planned["info"]["description"],
            planned["x-traigent-contract"]["description"],
            economics_module["description"],
        )
    ).lower()
    assert "telemetry is implemented and asserted at operation scope" in planned_prose
    assert "recommendation remains contract-first and unasserted" in planned_prose

    current_telemetry_prose = f"{json.dumps(catalog)} {planned_prose}".lower()
    for stale_phrase in _STALE_TELEMETRY_PROSE:
        assert stale_phrase not in current_telemetry_prose, stale_phrase
