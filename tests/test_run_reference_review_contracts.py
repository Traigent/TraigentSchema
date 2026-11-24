# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""Run reference review is declared at their current paths.

Fixtures are built key-for-key from what the server emits: the platform success envelope around
the closed run payloads. Every key of a closed object is always present, except the optional
example identifier of a queue item.
"""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()
CATALOG = json.loads((S / "analytics" / "analytics_endpoints.json").read_text(encoding="utf-8"))

REVIEW = "/api/v1/analytics/runs/{run_id}/reference-review"
OPS = [
    (REVIEW, "analytics_runs.get_run_reference_review"),
]
SHARED = {
    "400": "AnalyticsMwBadRequestGet",
    "401": "AnalyticsMwUnauthorized",
    "403": "AnalyticsMwForbidden",
    "404": "AnalyticsMwNotFound",
    "413": "AnalyticsMwPayloadTooLarge",
    "422": "AnalyticsMwUnprocessable",
    "429": "AnalyticsMwRateLimited",
    "500": "AnalyticsMwInternal",
    "503": "AnalyticsMwUnavailableGet",
}


def _validator(stem: str) -> Draft7Validator:
    v = SchemaValidator(contract="backend")
    return Draft7Validator(v._schemas[stem], registry=v._registry, format_checker=FormatChecker())


def _env(data, message="Run reference review queue retrieved successfully") -> dict:
    return {"success": True, "message": message, "data": data}


def _review(**over) -> dict:
    row = {
        "run_id": "run-7f3a",
        "privacy_mode": "safe_agent_projection",
        "status": "available",
        "unavailable_reason": None,
        "counts": {
            "needs_reference_check": 3,
            "insufficient_evidence": 1,
            "unclassified": 2,
            "classified": 6,
        },
        "page": 1,
        "page_size": 50,
        "total_count": 3,
        "total_pages": 1,
        "items": [
            {"safe_example_ref": "exref_0123456789abcdef", "example_id": "case-17"},
            {"safe_example_ref": "exref_fedcba9876543210"},
        ],
    }
    row.update(over)
    return row


@pytest.mark.parametrize(("path", "op_id"), OPS)
def test_operation_declared_with_backend_id_at_current_template(path, op_id):
    assert CATALOG["paths"][path]["get"]["operationId"] == op_id


def test_operation_ids_are_unique_and_reachable_through_master_catalog():
    master = json.loads((S / "mep_endpoints.json").read_text(encoding="utf-8"))
    ids: list[str] = []
    for module in master["x-endpoint-modules"]:
        doc = json.loads((S / module["paths_file"].removeprefix("./")).read_text(encoding="utf-8"))
        ids += [
            op["operationId"]
            for item in doc["paths"].values()
            for op in item.values()
            if isinstance(op, dict) and "operationId" in op
        ]
    known = SchemaValidator(contract="backend")._known_endpoints
    for path, op_id in OPS:
        assert ids.count(op_id) == 1
        assert f"GET:{path}" in known


@pytest.mark.parametrize(("path", "_op"), OPS)
def test_responses_reuse_the_shared_app_wide_components(path, _op):
    responses = CATALOG["paths"][path]["get"]["responses"]
    assert set(responses) == {"200", *SHARED}
    for status, component in SHARED.items():
        assert responses[status] == {"$ref": f"#/components/responses/{component}"}
        assert component in CATALOG["components"]["responses"]
    # the same references the evaluator promotion list declares, except its inline 422
    promotion = CATALOG["paths"]["/api/v1/analytics/runs/{run_id}/evaluator-promotion"]["get"]
    for status in SHARED.keys() - {"422"}:
        assert promotion["responses"][status] == responses[status]


def test_reference_review_query_matches_backend_model():
    params = {p["name"]: p for p in CATALOG["paths"][REVIEW]["get"]["parameters"]}
    assert set(params) == {"run_id", "page", "page_size"}
    assert params["page"]["schema"] == {"type": "integer", "minimum": 1, "default": 1}
    assert params["page_size"]["schema"] == {
        "type": "integer",
        "minimum": 1,
        "maximum": 200,
        "default": 50,
    }
    assert all(not params[name]["required"] for name in ("page", "page_size"))


def test_reference_review_validates_a_realistic_page_and_is_closed():
    v = _validator("run_reference_review_response_schema")
    ok = _env(_review(), "Run reference review queue retrieved successfully")
    assert not list(v.iter_errors(ok))
    for reason in ("dataset_quality_missing", "diagnostics_missing", "classification_missing"):
        unavailable = _review(
            status="unavailable",
            unavailable_reason=reason,
            counts={
                "needs_reference_check": 0,
                "insufficient_evidence": 0,
                "unclassified": 0,
                "classified": 0,
            },
            total_count=0,
            total_pages=0,
            items=[],
        )
        assert not list(v.iter_errors(_env(unavailable)))

    def broken(mutate):
        doc = copy.deepcopy(ok)
        mutate(doc["data"])
        return list(v.iter_errors(doc))

    assert broken(lambda d: d.update(extra=1))
    assert broken(lambda d: d["counts"].update(extra=1))
    assert broken(lambda d: d["items"][0].update(label="x"))
    assert broken(lambda d: d["items"][1].update(example_id=None))
    assert broken(lambda d: d["items"][0].update(example_id=""))
    assert broken(lambda d: d["items"][0].update(example_id="x" * 256))
    assert broken(lambda d: d["items"][0].update(safe_example_ref="exref_xyz"))
    assert broken(lambda d: d.pop("unavailable_reason"))
    assert broken(lambda d: d.update(privacy_mode="full"))
    assert broken(lambda d: d.update(status="partial"))
    assert broken(lambda d: d.update(unavailable_reason="other"))
    assert broken(lambda d: d.update(page=0))
    assert broken(lambda d: d.update(page_size=201))
    assert broken(lambda d: d.update(total_pages=-1))
    assert broken(lambda d: d.update(items=[_review()["items"][1]] * 201))


def _walk(node, where="$"):
    if isinstance(node, dict):
        yield where, node
        for key, value in node.items():
            yield from _walk(value, f"{where}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{where}/{index}")


def test_every_property_is_classified_and_customer_text_is_content():
    stem = "run_reference_review_schema"
    schema = SchemaValidator(contract="backend")._schemas[stem]
    customer_chosen = {
        "run_id",
        "project_id",
        "experiment_id",
        "configuration_run_id",
        "measure_name",
        "identifier",
        "content_fingerprint",
        "example_id",
    }
    seen = set()
    for where, node in _walk(schema):
        props = node.get("properties") if isinstance(node.get("properties"), dict) else {}
        for name, prop in props.items():
            if not isinstance(prop, dict):
                continue
            assert "x-privacy-classification" in prop, f"{where}/{name}"
            if "$ref" in prop:
                continue
            if "array" == prop.get("type") or prop.get("type") == "object":
                continue
            assert "x-content-class" in prop, f"{where}/{name}"
            if name in customer_chosen:
                seen.add(name)
                assert prop["x-privacy-classification"] == "user_content", f"{where}/{name}"
                assert prop["x-content-class"] == "legacy_content", f"{where}/{name}"
                assert prop["x-content-note"].startswith("INV-GAP:"), f"{where}/{name}"
    assert seen, stem
    assert {"run_id", "example_id"} <= seen


def test_envelope_is_closed_to_what_the_server_emits():
    v = _validator("run_reference_review_response_schema")
    good = _env(_review())
    assert not list(v.iter_errors(good))
    assert list(v.iter_errors({**good, "meta": {}}))
    assert list(v.iter_errors({**good, "metadata": {}}))
    assert list(v.iter_errors({**good, "success": False}))
    assert list(v.iter_errors({**good, "message": "other"}))


def test_evaluator_quality_declares_its_path_parameter_and_shared_responses():
    op = CATALOG["paths"]["/api/v1/analytics/runs/{run_id}/evaluator-quality"]["get"]
    assert [p["name"] for p in op["parameters"]] == ["run_id"]
    assert op["parameters"][0]["in"] == "path" and op["parameters"][0]["required"] is True
    assert set(op["responses"]) == {"200", *SHARED}
    for status, component in SHARED.items():
        assert op["responses"][status] == {"$ref": f"#/components/responses/{component}"}


MIDDLEWARE_BODIES = {
    "middleware_message_error_schema": [
        {"error": "Security middleware error", "message": "Failed to apply CORS response headers"},
        {
            "error": "Security middleware error",
            "message": "Failed to apply security response headers",
        },
        {
            "error": "Transaction commit failed",
            "message": "A database error occurred. Please retry.",
        },
        {
            "error": "Database transaction error",
            "message": "The previous operation failed. Please retry.",
            "recovery": "automatic",
        },
        {
            "error": "Database operation failed",
            "message": "A database error occurred. Please retry.",
        },
        {
            "error": "Internal server error",
            "message": "An unexpected error occurred. The system state has been reset.",
        },
    ],
    "payload_too_large_schema": [
        {
            "error": "Request Too Large",
            "message": "Request size exceeds maximum allowed size of 1048576 bytes",
            "max_size": 1048576,
        }
    ],
    "idempotency_middleware_error_schema": [
        {"error": "Invalid Idempotency-Key", "message": "Key too long"},
        {"error": "Invalid idempotent request", "message": "Unable to fingerprint request body"},
        {
            "error": "Idempotency conflict",
            "message": "Idempotency-Key already used with different payload",
        },
        {"error": "Idempotency conflict", "message": "Idempotency record is in an unknown state"},
        {"error": "Idempotency conflict", "message": "Idempotency key already used"},
        {
            "error": "Request in progress",
            "message": "A request with this Idempotency-Key is currently processing",
        },
        {"error": "Idempotency unavailable", "message": "Operation is not registered"},
        {"error": "Idempotency unavailable", "message": "Unable to reserve idempotency lease"},
        {
            "error": "Idempotency unavailable",
            "message": "Unable to reserve idempotency lease for billable request",
        },
        {
            "error": "Idempotency unavailable",
            "message": "Stored idempotent response is unreadable",
        },
        {
            "error": "Idempotency unavailable",
            "message": "Unable to sanitize hybrid replay receipt",
        },
        {"error": "Idempotency unavailable", "message": "Unable to finalize idempotency record"},
    ],
    "feature_disabled_response_schema": [
        {
            "success": False,
            "error": "Empirical Intelligence feature not implemented",
            "message": "The 'empirical_intelligence' feature is disabled in local mode",
            "error_code": "FEATURE_DISABLED",
            "feature": "empirical_intelligence",
            "local_mode": True,
            "upgrade_message": (
                "This feature is available in our cloud platform. Contact us to upgrade."
            ),
        }
    ],
}


@pytest.mark.parametrize(
    ("stem", "body"),
    [(stem, body) for stem, bodies in MIDDLEWARE_BODIES.items() for body in bodies],
)
def test_middleware_bodies_accept_the_servers_fixed_messages(stem, body):
    assert not list(_validator(stem).iter_errors(body))


@pytest.mark.parametrize("stem", list(MIDDLEWARE_BODIES))
def test_middleware_bodies_reject_client_chosen_text_and_request_ids(stem):
    v = _validator(stem)
    real = MIDDLEWARE_BODIES[stem][0]
    for field in ("error", "message"):
        assert list(v.iter_errors({**real, field: "client-secret"})), (stem, field)
    assert list(v.iter_errors({**real, "error": "client-secret", "message": "client-secret"}))
    assert list(v.iter_errors({**real, "request_id": "client-secret"}))
    assert "request_id" not in v.schema["properties"]
    assert "request_id" not in v.schema.get("required", [])


def test_middleware_error_and_message_are_tied_together():
    v = _validator("middleware_message_error_schema")
    assert list(
        v.iter_errors(
            {
                "error": "Transaction commit failed",
                "message": "Failed to apply CORS response headers",
            }
        )
    )
    assert list(
        v.iter_errors(
            {
                "error": "Database transaction error",
                "message": "The previous operation failed. Please retry.",
            }
        )
    )
    idem = _validator("idempotency_middleware_error_schema")
    assert list(
        idem.iter_errors(
            {"error": "Invalid Idempotency-Key", "message": "Idempotency key already used"}
        )
    )
    big = _validator("payload_too_large_schema")
    assert list(
        big.iter_errors(
            {
                "error": "Request Too Large",
                "message": "Request size exceeds maximum allowed size of x bytes",
                "max_size": 1,
            }
        )
    )


def test_feature_disabled_body_is_pinned_to_its_single_feature():
    v = _validator("feature_disabled_response_schema")
    real = MIDDLEWARE_BODIES["feature_disabled_response_schema"][0]
    assert not list(v.iter_errors(real))
    substituted = {
        **real,
        "error": "Client Secret feature not implemented",
        "message": "The 'client_secret' feature is disabled in local mode",
        "feature": "client_secret",
    }
    assert list(v.iter_errors(substituted))
    for field in ("error", "message", "feature", "upgrade_message"):
        assert list(v.iter_errors({**real, field: "client-secret"})), field
