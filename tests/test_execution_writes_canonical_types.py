"""#134 execution write contracts bound to canonical status enum + SummaryStats;
#137 canonical id/timestamp types + relaxing the metric_submission format:uuid outlier."""
import json

from traigent_schema import SchemaValidator
from traigent_schema.utils import get_schemas_dir

S = get_schemas_dir()


def _load(rel):
    with open(S / rel, encoding="utf-8") as fh:
        return json.load(fh)


# ---- #137 canonical types ----

def test_canonical_types_exist():
    canon = _load("common_types_schema.json")["definitions"]
    fk = canon["ForeignKeyId"]
    assert fk["type"] == "string"
    assert "format" not in fk  # NOT uuid — accepts SDK trial_<hex> + server uuid4
    assert fk["pattern"] == "^[A-Za-z0-9_-]+$"
    assert canon["Timestamp"]["format"] == "date-time"


def test_metric_submission_fk_ids_no_longer_uuid_only():
    ms = _load("execution/metric_submission_schema.json")
    for fk in ("configuration_run_id", "experiment_run_id"):
        assert ms["properties"][fk]["$ref"].endswith(
            "common_types_schema.json#/definitions/ForeignKeyId"
        )
    v = SchemaValidator(contract="backend")
    base = {
        "submission_id": "550e8400-e29b-41d4-a716-446655440000", "session_id": "s1",
        "metrics": {"acc": 0.9}, "configuration": {}, "status": "submitted",
        "timestamp": "2026-06-15T00:00:00Z",
    }
    # SDK trial_<hex> ids (NOT uuids) now accepted — the concrete 422 the issue flagged
    assert v.validate_json(
        {
            **base,
            "configuration_run_id": "trial_a1b2c3d4",
            "experiment_run_id": "trial_x",
        },
        "metric_submission_schema",
    ) == []
    # uuids still accepted
    assert v.validate_json(
        {
            **base,
            "configuration_run_id": "550e8400-e29b-41d4-a716-446655440000",
            "experiment_run_id": "exp_run_1",
        },
        "metric_submission_schema",
    ) == []
    # malformed id still rejected
    assert v.validate_json(
        {
            **base,
            "configuration_run_id": "bad id!",
            "experiment_run_id": "x",
        },
        "metric_submission_schema",
    )


def test_best_config_timestamps_have_format():
    bc = _load("execution/best_config_response_schema.json")
    for fld in ("created_at", "updated_at"):
        assert bc["properties"][fld].get("format") == "date-time"

    inner = _load("optimization/best_config_schema.json")
    provenance = inner["properties"]["provenance"]["properties"]
    for fld in ("created_at", "exported_at", "published_at"):
        assert provenance[fld]["format"] == "date-time"


def test_best_config_response_rejects_invalid_inner_provenance_timestamps():
    v = SchemaValidator(contract="backend")
    payload = {
        "config_id": "support-answerer",
        "environment": "default",
        "version": 1,
        "etag": 'W/"1-abcdef"',
        "spec_hash": "sha256:" + "a" * 64,
        "config_hash": "sha256:" + "b" * 64,
        "spec": {
            "schema_version": "traigent.best_config.v1",
            "config_id": "support-answerer",
            "function_ref": "tests.best_config:answer",
            "environment": "default",
            "config": {"model": "gpt-4o-mini"},
            "provenance": {
                "algorithm": "tpe",
                "created_at": "yesterday",
                "exported_at": "later",
                "published_at": "soon",
                "optimization_id": "opt_1",
            },
        },
        "created_at": "2026-06-08T00:00:00Z",
        "updated_at": "2026-06-08T00:00:00Z",
    }

    assert v.validate_json(payload, "best_config_response_schema")


# ---- #134 execution write contracts ----

def test_status_puts_bound_to_canonical_enum():
    v = SchemaValidator(contract="backend")
    # Canonical UPPER vocabulary (matches backend status_enums.py). Valid enum
    # accepted, invalid rejected, extra props rejected (additionalProperties:false).
    assert v.validate_request(
        "/api/v1/configuration-runs/{config_run_id}/status",
        "PUT",
        {"status": "RUNNING"},
    ) == []
    assert v.validate_request(
        "/api/v1/configuration-runs/{config_run_id}/status",
        "PUT",
        {"status": "PRUNED"},
    ) == []
    assert v.validate_request(
        "/api/v1/configuration-runs/{config_run_id}/status",
        "PUT",
        {"status": "not_a_status"},
    )
    # lowercase is the legacy outlier vocabulary and is now rejected (#172/#173)
    assert v.validate_request(
        "/api/v1/configuration-runs/{config_run_id}/status",
        "PUT",
        {"status": "running"},
    )
    assert v.validate_request(
        "/api/v1/experiment-runs/runs/{run_id}/status",
        "PUT",
        {"status": "COMPLETED"},
    ) == []
    assert v.validate_request(
        "/api/v1/experiment-runs/runs/{run_id}/status",
        "PUT",
        {"status": "COMPLETED", "x": 1},
    )


def test_summary_stats_put_references_summarystats():
    v = SchemaValidator(contract="backend")
    assert v.validate_request("/api/v1/configuration-runs/{config_run_id}/summary-stats", "PUT",
                              {"summary_stats": {}}) == []
    assert v.validate_request("/api/v1/configuration-runs/{config_run_id}/summary-stats", "PUT",
                              {"summary_stats": "not-an-object"})
