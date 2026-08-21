# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Regression guards for the mixed-maturity economics endpoint catalog."""

from __future__ import annotations

import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir


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
    operations = {
        path: item["post"] for path, item in catalog["paths"].items()
    }
    assert [
        path
        for path, operation in operations.items()
        if operation.get("x-asserted-against-backend") is False
    ] == ["/api/v1/economics/recommendation"]
    assert operations["/api/v1/economics/telemetry"]["x-asserted-against-backend"] is True
