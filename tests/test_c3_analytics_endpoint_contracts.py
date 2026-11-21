# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Traigent-Commercial
# Copyright (c) 2024-2026 Traigent Ltd. Dual-licensed: AGPL-3.0 or commercial.
"""C3-PR1c: the 33 unchanged analytics operations are declared once, with backend ids.

The backend serves one blueprint (`src/routes/analytics_routes.py`) under three mounts
(`analytics`, `legacy_analytics`, `project_analytics`). Eleven of its operations keep their
URL; each is declared on each mount at its existing method and path, and the
`operationId` equals the backend register `op_id` (`<family>.<suffix>`).

Fixtures are built key-for-key from what the handlers and
`core_domain_analytics_service` emit, not from the schemas' required lists.
"""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft7Validator, FormatChecker

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()

FAMILIES = {
    "analytics": "/api/v1/analytics",
    "legacy_analytics": "/api/v1beta/analytics",
    "project_analytics": "/api/v1beta/projects/{project_id}/analytics",
}

# suffix -> URL suffix (the plan's authoritative list of 11 unchanged operations)
SUFFIXES = {
    "get_project_analytics_summary": "/summary",
    "get_project_pricing_catalog": "/pricing-catalog",
    "get_project_optimization_overview_dashboard": "/dashboards/optimization-overview",
    "get_project_evaluator_quality_dashboard": "/dashboards/evaluator-quality",
    "get_project_usage_dashboard": "/dashboards/project-usage",
    "get_project_observability_summary_dashboard": "/dashboards/observability-summary",
    "get_project_run_volume_trend": "/trends/run-volume",
    "get_project_measure_distribution": "/distributions/measures/{measure_key}",
    "export_project_fine_tuning_manifest": "/exports/fine-tuning.manifest",
    "list_project_export_jobs": "/export-jobs",
    "get_project_export_job": "/export-jobs/{job_id}",
}

EXPECTED = sorted(
    ("get", prefix + url, f"{family}.{suffix}")
    for family, prefix in FAMILIES.items()
    for suffix, url in SUFFIXES.items()
)

# suffix -> response schema (envelope) stem
ENVELOPES = {
    "get_project_analytics_summary": "project_analytics_summary_response_schema",
    "get_project_pricing_catalog": "project_pricing_catalog_response_schema",
    "get_project_optimization_overview_dashboard": (
        "optimization_overview_dashboard_response_schema"
    ),
    "get_project_evaluator_quality_dashboard": (
        "project_evaluator_quality_dashboard_response_schema"
    ),
    "get_project_usage_dashboard": "project_usage_dashboard_response_schema",
    "get_project_observability_summary_dashboard": (
        "project_observability_summary_dashboard_response_schema"
    ),
    "get_project_run_volume_trend": "project_run_volume_trend_response_schema",
    "get_project_measure_distribution": "project_measure_distribution_response_schema",
    "export_project_fine_tuning_manifest": "project_fine_tuning_manifest_response_schema",
    "list_project_export_jobs": "project_export_job_list_envelope_response_schema",
    "get_project_export_job": "project_export_job_envelope_response_schema",
}

# suffix -> {query parameter: (minimum, maximum, default)} from ProjectAnalytics*Query
BOUNDS = {
    "get_project_analytics_summary": {"days": (1, 3660, 30)},
    "get_project_optimization_overview_dashboard": {"days": (1, 3660, 30), "limit": (1, 25, 5)},
    "get_project_evaluator_quality_dashboard": {"days": (1, 3660, 30), "limit": (1, 25, 5)},
    "get_project_usage_dashboard": {"days": (1, 3660, 30), "limit": (1, 25, 5)},
    "get_project_observability_summary_dashboard": {"days": (1, 3660, 30), "limit": (1, 25, 5)},
    "get_project_run_volume_trend": {"days": (1, 3660, 30)},
    "get_project_measure_distribution": {"bins": (1, 100, 10)},
    "export_project_fine_tuning_manifest": {"limit": (1, 5000, 1000)},
    "list_project_export_jobs": {"page": (1, None, 1), "per_page": (1, 100, 20)},
}
# handler not-found branches: analytics_routes.py (origin/develop) not_found_response at
# :289 (experiment), :317 (measure), :320 (experiment), :422 (experiment), :543 (export job)
RESOURCE_404 = {
    "get_project_run_volume_trend",
    "get_project_measure_distribution",
    "export_project_fine_tuning_manifest",
    "get_project_export_job",
}
NO_QUERY_VALIDATION = {"get_project_pricing_catalog", "get_project_export_job"}
PATH_PARAMS = {
    "get_project_measure_distribution": {"measure_key"},
    "get_project_export_job": {"job_id"},
}


def _load(rel: str) -> dict:
    return json.loads((S / rel).read_text(encoding="utf-8"))


CATALOG = _load("analytics/analytics_endpoints.json")


def _operation(family: str, suffix: str) -> dict:
    return CATALOG["paths"][FAMILIES[family] + SUFFIXES[suffix]]["get"]


def _all_cases():
    return [(f, s) for f in FAMILIES for s in SUFFIXES]


def _validator(stem: str) -> Draft7Validator:
    v = SchemaValidator(contract="backend")
    return Draft7Validator(v._schemas[stem], registry=v._registry, format_checker=FormatChecker())


# ---- the exact 33 triples -------------------------------------------------------------


def test_exactly_the_33_method_path_operation_id_triples_are_declared():
    found = sorted(
        (method, path, op["operationId"])
        for path, item in CATALOG["paths"].items()
        for method, op in item.items()
        if op.get("operationId", "").split(".")[0] in FAMILIES
        and op["operationId"].split(".", 1)[1] in SUFFIXES
    )
    assert len(EXPECTED) == 33
    assert found == EXPECTED


def test_operation_ids_are_unique_across_the_whole_backend_catalog():
    master = _load("mep_endpoints.json")
    ids: list[str] = []
    for module in master["x-endpoint-modules"]:
        doc = _load(module["paths_file"].removeprefix("./"))
        ids += [
            op["operationId"]
            for item in doc["paths"].values()
            for op in item.values()
            if isinstance(op, dict) and "operationId" in op
        ]
    wanted = [e[2] for e in EXPECTED]
    assert all(ids.count(i) == 1 for i in wanted), [i for i in wanted if ids.count(i) != 1]
    assert "getOptimizationOverviewDashboard" not in ids


def test_all_33_are_reachable_through_the_backend_master_catalog():
    validator = SchemaValidator(contract="backend")
    for method, path, _ in EXPECTED:
        assert f"{method.upper()}:{path}" in validator._known_endpoints, path


@pytest.mark.parametrize(("family", "suffix"), _all_cases())
def test_path_and_query_parameters_match_the_backend_query_models(family, suffix):
    op = _operation(family, suffix)
    params = op["parameters"]
    path_names = {p["name"] for p in params if p["in"] == "path"}
    expected_path = set(PATH_PARAMS.get(suffix, set()))
    if family == "project_analytics":
        expected_path.add("project_id")
    assert path_names == expected_path
    assert all(p["required"] is True for p in params if p["in"] == "path")
    assert ("{project_id}" in FAMILIES[family] + SUFFIXES[suffix]) == (
        family == "project_analytics"
    )
    for p in params:
        if p["in"] == "path":
            assert f"{{{p['name']}}}" in FAMILIES[family] + SUFFIXES[suffix]

    queries = {p["name"]: p for p in params if p["in"] == "query"}
    for name, (lo, hi, default) in BOUNDS.get(suffix, {}).items():
        schema = queries[name]["schema"]
        assert schema["type"] == "integer"
        assert schema["minimum"] == lo
        assert schema.get("maximum") == hi
        assert schema["default"] == default
        assert queries[name]["required"] is False
    assert all(not p["required"] for p in queries.values())
    assert "requestBody" not in op


def test_run_volume_bucket_and_export_query_declarations():
    trend = {
        p["name"]: p for p in _operation("analytics", "get_project_run_volume_trend")["parameters"]
    }
    assert trend["bucket"]["schema"]["enum"] == ["hour", "day", "week", "month"]
    assert trend["experiment_id"]["schema"]["minLength"] == 1
    export = {
        p["name"]: p
        for p in _operation("analytics", "export_project_fine_tuning_manifest")["parameters"]
    }
    assert set(export) == {"experiment_id", "experiment_run_id", "limit", "include_content"}
    assert export["include_content"]["schema"] == {"type": "boolean", "default": False}


def test_query_bounds_reject_out_of_range_values():
    for suffix, bounds in BOUNDS.items():
        queries = {
            p["name"]: p["schema"]
            for p in _operation("analytics", suffix)["parameters"]
            if p["in"] == "query"
        }
        for name, (lo, hi, _default) in bounds.items():
            validator = Draft7Validator(queries[name])
            assert validator.is_valid(lo)
            assert not validator.is_valid(lo - 1)
            if hi is not None:
                assert validator.is_valid(hi)
                assert not validator.is_valid(hi + 1)


# ---- responses ------------------------------------------------------------------------


@pytest.mark.parametrize(("family", "suffix"), _all_cases())
def test_success_response_is_the_envelope_and_errors_follow_the_handlers(family, suffix):
    op = _operation(family, suffix)
    schema = op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    assert schema == f"./{ENVELOPES[suffix]}.json"
    codes = set(op["responses"])
    assert {"200", "401", "403", "404", "429", "500"} <= codes
    # 404 is the ordinary error envelope on every operation (PROJECT_NOT_FOUND from project-context)
    assert "404" in codes
    # validation failures are 422 (response_handler.validation_error_response), never 400
    assert "400" not in codes
    assert ("422" in codes) == (suffix not in NO_QUERY_VALIDATION)
    assert (
        op["responses"]["429"]["content"]["application/json"]["schema"]["$ref"]
        == "../rate_limit_info_schema.json"
    )


def test_validation_and_not_found_components_use_the_closed_shapes():
    responses = CATALOG["components"]["responses"]
    assert responses["AnalyticsValidationFailed"]["content"]["application/json"]["schema"][
        "$ref"
    ] == ("../validation_error_schema.json")
    # no project-entry problem+json 404 is declared: the analytics mounts carry no
    # project-entry guards today, so the backend never emits it. Every 404 is the
    # ordinary error envelope (PROJECT_NOT_FOUND from project-context resolution,
    # NOT_FOUND from the handler not_found_response branches).
    for name in ("AnalyticsProjectNotFound", "AnalyticsResourceNotFound"):
        assert set(responses[name]["content"]) == {"application/json"}
        schema = responses[name]["content"]["application/json"]["schema"]
        assert schema["$ref"] == "../error_envelope_schema.json"
    # ops with a handler not-found branch (experiment, measure, export job) use the resource 404
    for suffix in sorted(RESOURCE_404):
        assert _operation("analytics", suffix)["responses"]["404"] == {
            "$ref": "#/components/responses/AnalyticsResourceNotFound"
        }
    assert _operation("analytics", "get_project_analytics_summary")["responses"]["404"] == {
        "$ref": "#/components/responses/AnalyticsProjectNotFound"
    }


def test_export_is_documented_as_an_artifact_producing_get():
    op = _operation("project_analytics", "export_project_fine_tuning_manifest")
    description = op["description"]
    assert "creates an export job" in description and "audit" in description
    assert "truncated" in description and "empty_reason" in description
    assert op["responses"]["403"] == {"$ref": "#/components/responses/AnalyticsExportPolicyDenied"}
    assert op["responses"]["500"] == {"$ref": "#/components/responses/AnalyticsExportFailed"}


def test_observability_summary_is_a_read_plus_required_admission_audit():
    description = _operation("analytics", "get_project_observability_summary_dashboard")[
        "description"
    ]
    assert "required durable admission audit" in description
    assert "observability read grant" in description


def test_observability_is_never_called_privacy_safe_or_privacy_preserving():
    obs_ops = [_operation(f, "get_project_observability_summary_dashboard") for f in FAMILIES]
    payload = _load("projects/project_scoped_observability_summary_dashboard_schema.json")
    envelope = _load("analytics/project_observability_summary_dashboard_response_schema.json")
    texts = [json.dumps(x).lower() for x in (*obs_ops, payload, envelope)]
    for text in texts:
        assert "privacy-safe" not in text
        assert "privacy-preserving" not in text
        assert "privacy safe" not in text


# ---- fixtures built from the service ---------------------------------------------------

CONTEXT = {
    "tenant_id": "tenant_a",
    "project_id": "project_a",
    "generated_at": "2026-11-20T10:00:00+00:00",
    "privacy_classification": "aggregate_safe",
}
COST_SOURCES = {
    "observed_usage": 7,
    "recorded_metrics": 3,
    "catalog_fallback": 2,
    "unknown_unpriced": 0,
}

SUMMARY = {
    "context": CONTEXT,
    "range_days": 30,
    "entity_counts": {
        "agents": 1,
        "benchmarks": 1,
        "measures": 2,
        "experiments": 1,
        "experiment_runs": 3,
        "configuration_runs": 9,
    },
    "status_breakdowns": {
        "experiments": {"running": 1},
        "experiment_runs": {"completed": 3},
        "configuration_runs": {"completed": 9},
    },
    "usage_summary": {
        "experiment_runs": 3,
        "configuration_runs": 9,
        "priced_configuration_runs": 8,
        "unpriced_configuration_runs": 1,
        "total_cost_usd": 1.23,
        "avg_cost_usd": 0.41,
        "cost_source_breakdown": COST_SOURCES,
        "total_tokens": 12345,
        "avg_latency_ms": 250.1,
        "p95_latency_ms": 410.0,
    },
    "measure_summaries": [],
}
PRICING = {
    "context": CONTEXT,
    "catalog_source": "static_catalog",
    "catalog_last_updated": "2026-11-01T08:55:00+00:00",
    "total_providers": 1,
    "total_models": 1,
    "providers": [
        {
            "provider": "openai",
            "model_count": 1,
            "pricing_resolution_mode": "static_catalog",
            "models": [
                {
                    "model": "gpt-4o",
                    "input_price_per_1k_usd": 0.005,
                    "output_price_per_1k_usd": 0.015,
                    "context_window": None,
                    "available_tiers": [],
                    "supports_catalog_fallback": True,
                }
            ],
        }
    ],
}
OVERVIEW = {
    "context": CONTEXT,
    "range_days": 30,
    "summary_cards": {
        # the eight keys the handler emitted before plus experiments_in_range (service :672)
        "experiments_total": 3,
        "experiments_in_range": 2,
        "experiment_runs_in_range": 5,
        "configuration_runs_in_range": 12,
        "priced_configuration_runs_in_range": 10,
        "unpriced_configuration_runs_in_range": 2,
        "total_cost_usd_in_range": None,
        "avg_latency_ms_in_range": 820.5,
        "total_tokens_in_range": 4096,
    },
    "cost_source_breakdown": COST_SOURCES,
    "recent_experiments": [],
}
EVALUATOR = {
    "context": CONTEXT,
    "range_days": 30,
    "resolved_bucket": "day",
    "summary_cards": {
        "evaluator_definitions_total": 2,
        "evaluator_runs_in_range": 4,
        "completed_runs_in_range": 3,
        "failed_runs_in_range": 1,
        "scored_runs_in_range": 3,
        "avg_numeric_score_in_range": 0.92,
        "total_cost_usd_in_range": 0.37,
    },
    "quality_trend": [],
    "recent_evaluators": [],
}
USAGE = {
    "context": CONTEXT,
    "range_days": 30,
    "resolved_bucket": "day",
    "summary_cards": {
        "experiment_runs_in_range": 4,
        "configuration_runs_in_range": 9,
        "priced_configuration_runs_in_range": 8,
        "unpriced_configuration_runs_in_range": 1,
        "total_cost_usd_in_range": 1.24,
        "total_tokens_in_range": 2048,
        "avg_latency_ms_in_range": 120.5,
        "p95_latency_ms_in_range": 210.0,
    },
    "usage_trend": [],
    "top_experiments": [],
}
OBSERVABILITY = {
    "context": CONTEXT,
    "range_days": 30,
    "resolved_bucket": "day",
    "summary_cards": {
        "sessions_in_range": 2,
        "traces_in_range": 3,
        "observations_in_range": 9,
        "bookmarked_traces_in_range": 1,
        "published_traces_in_range": 1,
        "commented_traces_in_range": 2,
        "total_cost_usd_in_range": 0.42,
        "total_tokens_in_range": 840,
    },
    "activity_trend": [],
    "top_traces": [],
}
TREND = {
    "context": CONTEXT,
    "metric_id": "run_volume",
    "experiment_id": None,
    "range_days": 30,
    "requested_bucket": None,
    "resolved_bucket": "day",
    "series": [
        {
            "series_key": "experiment_runs",
            "label": "Experiment runs",
            "unit": "count",
            "points": [
                {
                    "bucket_start": "2026-11-19T00:00:00+00:00",
                    "bucket_label": "2026-11-19",
                    "value": 2,
                }
            ],
        },
        {
            "series_key": "configuration_runs",
            "label": "Configuration runs",
            "unit": "count",
            "points": [],
        },
    ],
}
DISTRIBUTION = {
    "context": CONTEXT,
    "measure_key": "accuracy",
    "measure_id": None,
    "label": "accuracy",
    "experiment_id": None,
    "value_type": "numeric",
    "sample_count": 0,
    "mean": None,
    "min": None,
    "max": None,
    "bucket_count": 10,
    "histogram": [],
}
JOB = {
    "job_id": "export_job_1",
    "export_type": "fine_tuning_manifest",
    "status": "completed",
    "privacy_classification": "manifest_safe",
    "export_mode": "manifest",
    "privacy_mode": True,
    "include_content": False,
    "retention_category": "export_artifact",
    "record_count": 0,
    "artifact_filename": "fine-tuning-manifest.json",
    "artifact_content_type": "application/json",
    "experiment_id": None,
    "experiment_run_id": None,
    "limit": 1000,
    "requested_by": "user_1",
    "requested_at": "2026-11-20T10:00:00+00:00",
    "expires_at": "2026-12-20T10:00:00+00:00",
    "completed_at": "2026-11-20T10:00:01+00:00",
    "error_message": None,
}
JOB_LIST = {
    "context": CONTEXT,
    "items": [JOB],
    "pagination": {
        "page": 1,
        "per_page": 20,
        "total": 1,
        "total_pages": 1,
        "has_next": False,
        "has_prev": False,
    },
}
JOB_ONE = {"context": CONTEXT, "job": JOB}


def _manifest(**overrides):
    base = {
        "context": {**CONTEXT, "privacy_classification": "manifest_safe"},
        "export_mode": "manifest",
        "privacy_mode": True,
        "source_privacy_protected": True,
        "include_content": False,
        "job_id": "export_job_1",
        "record_count": 1,
        "truncated": False,
        "empty_reason": None,
        "records": [
            {
                "record_id": "config_1",
                "experiment_id": "exp_1",
                "experiment_run_id": "run_1",
                "configuration_run_id": "config_1",
                "input_hash": "h1",
                "output_hash": "h2",
                "input_ref": "configuration_run:config_1:input",
                "output_ref": "configuration_run:config_1:output",
                "input_content": None,
                "output_content": None,
                "materialization": "local_only",
                "measure_summary": {"accuracy": 0.91},
                "metadata": {},
            }
        ],
    }
    base.update(overrides)
    return base


PAYLOADS = {
    "get_project_analytics_summary": SUMMARY,
    "get_project_pricing_catalog": PRICING,
    "get_project_optimization_overview_dashboard": OVERVIEW,
    "get_project_evaluator_quality_dashboard": EVALUATOR,
    "get_project_usage_dashboard": USAGE,
    "get_project_observability_summary_dashboard": OBSERVABILITY,
    "get_project_run_volume_trend": TREND,
    "get_project_measure_distribution": DISTRIBUTION,
    "export_project_fine_tuning_manifest": _manifest(),
    "list_project_export_jobs": JOB_LIST,
    "get_project_export_job": JOB_ONE,
}


def _wrap(payload):
    return {"success": True, "message": "ok", "data": payload}


@pytest.mark.parametrize("suffix", sorted(SUFFIXES))
def test_a_real_response_validates_and_malformed_ones_are_rejected(suffix):
    validator = _validator(ENVELOPES[suffix])
    payload = PAYLOADS[suffix]
    assert list(validator.iter_errors(_wrap(payload))) == []
    # the bare payload (what the old planned declarations described) is not the wire body
    assert list(validator.iter_errors(payload))
    # envelope discipline
    assert list(validator.iter_errors({"success": True, "data": payload}))
    assert list(validator.iter_errors({"message": "ok", "data": payload}))
    assert list(validator.iter_errors({"success": False, "message": "x", "data": payload}))
    assert list(validator.iter_errors({"success": True, "message": "ok"}))
    # data must still be a valid payload
    assert list(validator.iter_errors(_wrap({})))
    # a payload missing any single required field is rejected
    for field in PAYLOADS[suffix]:
        broken = {k: v for k, v in payload.items() if k != field}
        assert list(validator.iter_errors(_wrap(broken))), field


def test_overview_real_response_validates_with_experiments_in_range():
    """The backend emits summary_cards.experiments_in_range, so a real response is clean."""
    validator = _validator("optimization_overview_dashboard_response_schema")
    assert list(validator.iter_errors(_wrap(OVERVIEW))) == []
    missing = copy.deepcopy(OVERVIEW)
    del missing["summary_cards"]["experiments_in_range"]
    errors = list(validator.iter_errors(_wrap(missing)))
    assert [(tuple(e.absolute_path), e.validator) for e in errors] == [
        (("data", "summary_cards"), "required")
    ]


def test_fine_tuning_manifest_states_populated_empty_truncated_and_unrecorded_job():
    validator = _validator("project_fine_tuning_manifest_response_schema")
    populated = _manifest()
    empty = _manifest(
        record_count=0,
        records=[],
        empty_reason="no_prompt_response_pair_captured_for_fine_tuning_export",
    )
    truncated = _manifest(truncated=True)
    job_unrecorded = _manifest(job_id=None)
    materialized = _manifest(
        context={**CONTEXT, "privacy_classification": "raw_content"},
        export_mode="materialized",
        privacy_mode=False,
        source_privacy_protected=False,
        include_content=True,
    )
    for body in (populated, empty, truncated, job_unrecorded, materialized):
        assert list(validator.iter_errors(_wrap(body))) == []
    # closed: the two emitted fields are required and constrained
    for field in ("truncated", "empty_reason"):
        broken = {k: v for k, v in populated.items() if k != field}
        assert list(validator.iter_errors(_wrap(broken))), field
    assert list(validator.iter_errors(_wrap(_manifest(empty_reason="because"))))
    assert list(validator.iter_errors(_wrap(_manifest(truncated="yes"))))


# ---- compatibility and untouched declarations ------------------------------------------


def test_planned_project_catalog_references_the_canonical_path_items():
    planned = _load("planned_projects_endpoints.json")["paths"]
    prefix = FAMILIES["project_analytics"]
    for suffix, url in SUFFIXES.items():
        item = planned[prefix + url]
        pointer = (prefix + url).replace("~", "~0").replace("/", "~1")
        assert item == {"$ref": f"./analytics/analytics_endpoints.json#/paths/{pointer}"}
        assert CATALOG["paths"][prefix + url]["get"]["operationId"] == f"project_analytics.{suffix}"


def test_run_scoring_and_other_declarations_are_preserved():
    paths = CATALOG["paths"]
    for path in (
        "/api/v1/analytics/runs/{run_id}/decision-payload",
        "/api/v1/analytics/runs/{run_id}/report",
        "/api/v1/analytics/runs/{run_id}/pareto",
        "/api/v1/analytics/runs/{run_id}/director-evidence",
        "/api/v1/analytics/example-scoring/{experiment_run_id}/compute",
        "/api/v1/analytics/experiments/{experiment_run_id}/next-steps",
    ):
        assert path in paths
    # the two run operations are not part of the 33 on the other mounts
    for family in ("legacy_analytics", "project_analytics"):
        for url in ("/runs/{run_id}/decision-payload", "/runs/{run_id}/report"):
            assert FAMILIES[family] + url not in paths
    assert "certification_endpoints_v0.json" in json.dumps(_load("mep_endpoints.json"))


def test_planned_contract_still_knows_the_project_analytics_routes_through_the_refs():
    known = SchemaValidator(contract="planned_projects")._known_endpoints
    for suffix, url in SUFFIXES.items():
        assert f"GET:{FAMILIES['project_analytics']}{url}" in known, suffix
