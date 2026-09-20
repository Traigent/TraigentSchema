"""Tests for schema file integrity and structure."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from traigent_schema import AnalyticsValidator, SchemaValidator
from traigent_schema.utils import get_all_schema_files, get_schemas_dir

# ---------------------------------------------------------------------------
# Item 4 — Orphan-schema reachability report
#
# KNOWN_ORPHAN_ALLOWLIST is seeded from the current state of the repo so
# that CI is green immediately.  It serves as a ratchet: adding a NEW
# schema file that isn't referenced anywhere will fail this test.  When
# an existing orphan is deliberately connected (or removed), remove it
# from the allowlist so the ratchet tightens.
#
# How "referenced" is defined:
#   • Another schema file contains a "$ref" or "paths_file" that resolves
#     to the file (i.e. the file is reachable from the catalog graph).
#   • A test file under tests/ contains a literal path segment that
#     matches the schema filename or its relative path.
#   • An endpoint-root file (mep_endpoints.json, sdk_tuning_endpoints.json,
#     planned_projects_endpoints.json) lists the file via x-endpoint-modules.
# ---------------------------------------------------------------------------

KNOWN_ORPHAN_ALLOWLIST: frozenset[str] = frozenset(
    [
        # Stand-alone resource schemas not yet wired into an endpoint catalog.
        "agents/agent_deployment_schema.json",
        "agents/agent_types_schema.json",
        "agents/model_schema.json",
        "agents/retriever_schema.json",
        # Billing sub-schema referenced only by product code, not catalog.
        "billing/wallet_top_up_pack_schema.json",
        # Dataset internal sub-schemas (used by backend DTOs directly).
        "datasets/evaluator_config_schema.json",
        "datasets/example_set_schema.json",
        "datasets/generator_config_schema.json",
        # Evaluation sub-schema not yet surfaced in catalog.
        "evaluation/evaluation_request_schema.json",
        # Execution sub-schemas for internal modes.
        "execution/best_config_response_schema.json",
        "execution/dataset_storage_schema.json",
        "execution/hybrid_session_schema.json",
        "execution/saas_execution_schema.json",
        "execution/service_registration_schema.json",
        # Harness / agent-work schemas.
        "harness_session_record.json",
        # Measures sub-schemas.
        "measures/score_schema.json",
        "measures/timing_metric_vocabulary_schema.json",
        # Observability sub-schemas not yet in catalog.
        "observability/session_list_response_schema.json",
        "observability/trace_list_response_schema.json",
        "observability/trace_observations_response_schema.json",
        "observability/user_summary_schema.json",
        # Optimization sub-schemas.
        "optimization/config_space_schema.json",
        "optimization/multi_objective_semantics_schema.json",
        "optimization/session_next_trial_response_schema.json",
        "optimization/tunable_schema.json",
        # Project sub-schemas.
        "projects/project_context_error_schema.json",
        "projects/project_scoped_fine_tuning_export_query_schema.json",
        # Prompt sub-schemas.
        "prompts/prompt_analytics_schema.json",
        "prompts/resolved_prompt_schema.json",
        # Results sub-schemas.
        "results/comparison_schema.json",
        "results/report_request_schema.json",
        "results/report_schema.json",
        "results/visualization_request_schema.json",
        "results/visualization_schema.json",
    ]
)


_SCHEMA_BASE_URL = "https://schemas.traigent.ai/"


def _resolve_ref_url(ref_val: str, schema_file: Path, schemas_dir: Path) -> Path | None:
    """Resolve a $ref value to a schema Path relative to schemas_dir, or None."""
    # Strip JSON pointer fragment  (file.json#/definitions/Foo → file.json)
    ref_val = ref_val.split("#")[0]
    if not ref_val:
        return None

    # Absolute URL with the canonical schema base
    if ref_val.startswith(_SCHEMA_BASE_URL):
        relative_part = ref_val[len(_SCHEMA_BASE_URL):]
        candidate = schemas_dir / relative_part
        if candidate.exists():
            return Path(relative_part)
        return None

    # Skip other absolute URLs (http/https without our base, urn:, …)
    if ref_val.startswith(("http://", "https://", "urn:")):
        return None

    # Relative file reference
    ref_path = (schema_file.parent / ref_val).resolve()
    schemas_root = schemas_dir.resolve()
    try:
        return ref_path.relative_to(schemas_root)
    except ValueError:
        return None


def _compute_referenced_schemas(schemas_dir: Path) -> set[Path]:
    """Return the set of schema files (relative to schemas_dir) that are reachable.

    Reachability is determined by:
    1. $ref / paths_file links between schema files (relative and absolute URL).
    2. Explicit file-path literals in test source files.
    3. Bare schema names used in validate_json / validate_request test calls.
    """
    all_schema_files = list(schemas_dir.rglob("*.json"))
    referenced: set[Path] = set()

    # --- Pass 1: schema-internal $ref / paths_file links ---
    for sf in all_schema_files:
        try:
            content = sf.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in re.finditer(
            r'"(?:\$ref|paths_file)"\s*:\s*"([^"]+)"', content
        ):
            if not m.group(1).endswith(".json") and ".json#" not in m.group(1):
                continue
            resolved = _resolve_ref_url(m.group(1), sf, schemas_dir)
            if resolved is not None:
                referenced.add(resolved)

    # --- Pass 2: test-file references ---
    tests_root = Path(__file__).parent
    for tf in tests_root.rglob("*.py"):
        try:
            content = tf.read_text(encoding="utf-8")
        except OSError:
            continue
        # Pattern: schemas_dir / "subdir" / "filename.json"
        for m in re.finditer(
            r'schemas_dir\s*/\s*"([^"]+)"\s*/\s*"([^"]+)"', content
        ):
            candidate = Path(m.group(1)) / m.group(2)
            if (schemas_dir / candidate).exists():
                referenced.add(candidate)
        # Pattern: schemas_dir / "filename.json"  (single segment)
        for m in re.finditer(r'schemas_dir\s*/\s*"([^"]+)"', content):
            candidate = Path(m.group(1))
            if (schemas_dir / candidate).exists():
                referenced.add(candidate)
        # Bare schema names used in validate_json / validate_request calls
        for m in re.finditer(r'["\'](\w+_schema)(?:\.json)?["\']', content):
            name = m.group(1) + ".json"
            for sf in all_schema_files:
                if sf.name == name:
                    referenced.add(sf.relative_to(schemas_dir))

    return referenced


class TestOrphanSchemas:
    """Item 4: orphan-schema reachability report.

    Ensures that every schema file that is NOT in the known-orphan allowlist
    is reachable from at least one catalog, endpoint root, or test.  New
    schemas that are not yet connected will fail this test — add them to the
    allowlist only as a temporary measure and open a tracking issue.
    """

    def test_no_unexpected_orphan_schemas(self) -> None:
        schemas_dir = get_schemas_dir()
        all_files = {
            f.relative_to(schemas_dir)
            for f in schemas_dir.rglob("*.json")
        }

        referenced = _compute_referenced_schemas(schemas_dir)
        unreferenced = all_files - referenced

        # Express as forward-slash strings for platform-independent comparison.
        unreferenced_str = {p.as_posix() for p in unreferenced}
        unexpected_orphans = unreferenced_str - KNOWN_ORPHAN_ALLOWLIST

        # Build report for diagnostics (always printed so it's visible in CI).
        lines = [
            "",
            "=== Orphan Schema Reachability Report ===",
            f"Total schema files   : {len(all_files)}",
            f"Referenced           : {len(referenced)}",
            f"Unreferenced (total) : {len(unreferenced)}",
            f"Known orphans        : {len(KNOWN_ORPHAN_ALLOWLIST)}",
            f"Unexpected orphans   : {len(unexpected_orphans)}",
        ]
        if unreferenced_str:
            lines.append("")
            lines.append("All unreferenced schemas (known + unexpected):")
            for name in sorted(unreferenced_str):
                marker = "  [KNOWN]" if name in KNOWN_ORPHAN_ALLOWLIST else "  [NEW!] "
                lines.append(f"  {marker}  {name}")
        stale_allowlist = KNOWN_ORPHAN_ALLOWLIST - unreferenced_str
        if stale_allowlist:
            lines.append("")
            lines.append(
                "Allowlist entries that are now reachable (consider removing them):"
            )
            for name in sorted(stale_allowlist):
                lines.append(f"    {name}")
        report = "\n".join(lines)
        print(report)  # always emit so it appears in pytest -s / CI logs

        assert not unexpected_orphans, (
            f"New unreferenced schema files detected — either connect them to a "
            f"catalog/test or add to KNOWN_ORPHAN_ALLOWLIST in tests/test_schemas.py "
            f"with a comment explaining why they are currently standalone.\n"
            f"Unexpected orphans:\n"
            + "\n".join(f"  {n}" for n in sorted(unexpected_orphans))
        )


class TestSchemaFileIntegrity:
    """Tests to verify all schema files are valid JSON."""

    def test_all_json_files_parse(self):
        """All JSON files should parse without errors."""
        schema_files = get_all_schema_files()
        for schema_file in schema_files:
            try:
                with open(schema_file, encoding='utf-8') as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Failed to parse {schema_file}: {e}")

    def test_schema_file_count(self):
        """Should have expected number of schema files."""
        schema_files = get_all_schema_files()
        # #131: floor was stale by ~8x (35 vs 273 files); min-aligned
        # ratchet so catastrophic schema-file loss fails CI.
        assert len(schema_files) >= 273


def _objective_schema_payload():
    return {
        "schema_version": "1.0.0",
        "objectives": [
            {
                "name": "accuracy",
                "orientation": "maximize",
                "weight": 0.3,
                "normalization": "min_max",
            },
            {
                "name": "cost",
                "orientation": "minimize",
                "weight": 0.2,
                "normalization": "min_max",
                "unit": "usd",
            },
            {
                "name": "latency",
                "orientation": "minimize",
                "weight": 0.5,
                "normalization": "min_max",
                "bounds": [0, 1000],
                "unit": "ms",
            },
        ],
    }


def _infrastructure_payload():
    return {
        "infrastructure_id": "infra_123",
        "compute": "cpu",
        "memory": "8GB",
        "timeout": 300,
    }


class TestSchemaStructure:
    """Tests for schema file structure."""

    @pytest.fixture
    def schemas_dir(self):
        """Get the schemas directory."""
        return get_schemas_dir()

    def test_has_agents_directory(self, schemas_dir):
        """Should have agents subdirectory."""
        agents_dir = schemas_dir / "agents"
        assert agents_dir.exists()
        assert agents_dir.is_dir()

    def test_has_datasets_directory(self, schemas_dir):
        """Should have datasets subdirectory."""
        datasets_dir = schemas_dir / "datasets"
        assert datasets_dir.exists()
        assert datasets_dir.is_dir()

    def test_has_evaluation_directory(self, schemas_dir):
        """Should have evaluation subdirectory."""
        evaluation_dir = schemas_dir / "evaluation"
        assert evaluation_dir.exists()
        assert evaluation_dir.is_dir()

    def test_has_execution_directory(self, schemas_dir):
        """Should have execution subdirectory."""
        execution_dir = schemas_dir / "execution"
        assert execution_dir.exists()
        assert execution_dir.is_dir()

    def test_has_measures_directory(self, schemas_dir):
        """Should have measures subdirectory."""
        measures_dir = schemas_dir / "measures"
        assert measures_dir.exists()
        assert measures_dir.is_dir()

    def test_has_results_directory(self, schemas_dir):
        """Should have results subdirectory."""
        results_dir = schemas_dir / "results"
        assert results_dir.exists()
        assert results_dir.is_dir()

    def test_has_costs_directory(self, schemas_dir):
        costs_dir = schemas_dir / "costs"
        assert costs_dir.exists()
        assert costs_dir.is_dir()


class TestNoBrandingIssues:
    """Tests to verify proper rebranding."""

    def test_no_optigen_references(self):
        """Schema files should not contain OptiGen references."""
        schema_files = get_all_schema_files()
        for schema_file in schema_files:
            with open(schema_file, encoding='utf-8') as f:
                content = f.read()

            assert "OptiGen" not in content, f"Found 'OptiGen' in {schema_file}"
            assert "optigen" not in content.lower(), \
                f"Found 'optigen' in {schema_file}"


class TestRequiredSchemas:
    """Tests to verify all required schemas exist."""

    @pytest.fixture
    def schemas_dir(self):
        """Get the schemas directory."""
        return get_schemas_dir()

    def test_mep_json_exists(self, schemas_dir):
        """Should have mep.json root file."""
        assert (schemas_dir / "mep.json").exists()

    def test_mep_endpoints_exists(self, schemas_dir):
        """Should have mep_endpoints.json."""
        assert (schemas_dir / "mep_endpoints.json").exists()

    def test_sdk_tuning_endpoints_exists(self, schemas_dir):
        assert (schemas_dir / "sdk_tuning_endpoints.json").exists()

    def test_planned_projects_endpoints_exists(self, schemas_dir):
        assert (schemas_dir / "planned_projects_endpoints.json").exists()

    def test_agent_schema_exists(self, schemas_dir):
        """Should have agent_schema.json."""
        assert (schemas_dir / "agents" / "agent_schema.json").exists()

    def test_experiment_schema_exists(self, schemas_dir):
        """Should have experiment_schema.json."""
        assert (schemas_dir / "evaluation" / "experiment_schema.json").exists()

    def test_measure_schema_exists(self, schemas_dir):
        """Should have measure_schema.json."""
        assert (schemas_dir / "measures" / "measure_schema.json").exists()

    def test_observability_trace_score_summary_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "observability" / "trace_score_summary_schema.json"
        ).exists()

    def test_observability_review_score_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "observability" / "review_score_schema.json"
        ).exists()

    def test_observability_evaluator_definition_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "observability" / "evaluator_definition_schema.json"
        ).exists()

    def test_observability_annotation_queue_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "observability" / "annotation_queue_schema.json"
        ).exists()

    def test_project_schema_exists(self, schemas_dir):
        """Should have project_schema.json."""
        assert (schemas_dir / "projects" / "project_schema.json").exists()

    def test_project_analytics_summary_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_analytics_summary_schema.json"
        ).exists()

    def test_project_analytics_trend_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_analytics_trend_schema.json"
        ).exists()

    def test_project_pricing_catalog_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_pricing_catalog_schema.json"
        ).exists()

    def test_project_optimization_overview_dashboard_schema_exists(self, schemas_dir):
        assert (
            schemas_dir
            / "projects"
            / "project_scoped_optimization_overview_dashboard_schema.json"
        ).exists()

    def test_project_evaluator_quality_dashboard_schema_exists(self, schemas_dir):
        assert (
            schemas_dir
            / "projects"
            / "project_scoped_evaluator_quality_dashboard_schema.json"
        ).exists()

    def test_project_usage_dashboard_schema_exists(self, schemas_dir):
        assert (
            schemas_dir
            / "projects"
            / "project_scoped_project_usage_dashboard_schema.json"
        ).exists()

    def test_project_observability_summary_dashboard_schema_exists(self, schemas_dir):
        assert (
            schemas_dir
            / "projects"
            / "project_scoped_observability_summary_dashboard_schema.json"
        ).exists()

    def test_project_measure_distribution_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_measure_distribution_schema.json"
        ).exists()

    def test_project_fine_tuning_manifest_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_scoped_fine_tuning_manifest_schema.json"
        ).exists()

    def test_project_export_job_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_export_job_schema.json"
        ).exists()

    def test_project_export_job_list_response_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_export_job_list_response_schema.json"
        ).exists()

    def test_cost_response_schemas_exist(self, schemas_dir):
        assert (schemas_dir / "costs" / "cost_users_response_schema.json").exists()
        assert (schemas_dir / "costs" / "cost_user_usage_response_schema.json").exists()

    def test_hybrid_session_create_request_schema_exists(self, schemas_dir):
        assert (
            schemas_dir
            / "optimization"
            / "hybrid_session_create_request_schema.json"
        ).exists()

    def test_project_rate_limit_policy_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_rate_limit_policy_schema.json"
        ).exists()

    def test_project_rate_limit_policy_update_request_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_rate_limit_policy_update_request_schema.json"
        ).exists()

    def test_project_retention_policy_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_retention_policy_schema.json"
        ).exists()

    def test_project_retention_policy_update_request_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_retention_policy_update_request_schema.json"
        ).exists()


    def test_project_membership_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_membership_schema.json"
        ).exists()

    def test_project_membership_list_response_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_membership_list_response_schema.json"
        ).exists()

    def test_project_membership_create_request_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_membership_create_request_schema.json"
        ).exists()

    def test_backend_root_lists_only_canonical_backend_modules(self, schemas_dir):
        with open(schemas_dir / "mep_endpoints.json", encoding="utf-8") as handle:
            openapi = json.load(handle)

        modules = openapi.get("x-endpoint-modules", [])
        paths_files = {
            module.get("paths_file")
            for module in modules
            if isinstance(module, dict)
        }
        assert "./optimization/optimization_endpoints.json" not in paths_files
        assert "./optimization/optimization_plan_endpoints.json" in paths_files
        assert "./projects/projects_endpoints.json" not in paths_files
        assert "./datasets/datasets_endpoints.json" in paths_files
        assert "./observability/observability_endpoints.json" in paths_files
        assert "./auth/auth_endpoints.json" in paths_files
        assert "./audit/audit_endpoints.json" in paths_files
        assert "./billing/paddle_endpoints.json" in paths_files
        assert "./billing/subscription_lifecycle_endpoints.json" in paths_files
        assert "./billing/spend_controls_endpoints.json" in paths_files
        assert "./billing/wallet_endpoints.json" in paths_files
        assert "./mfa/mfa_endpoints.json" in paths_files
        assert "./security/security_endpoints.json" in paths_files

    def test_dataset_schema_exists(self, schemas_dir):
        assert (schemas_dir / "datasets" / "dataset_schema.json").exists()

    def test_dataset_schema_declares_stable_id(self, schemas_dir):
        with open(schemas_dir / "datasets" / "dataset_schema.json", encoding="utf-8") as handle:
            schema = json.load(handle)
        assert schema["$id"] == "https://schemas.traigent.ai/datasets/dataset_schema.json"

    def test_sdk_tuning_root_references_direct_tuning_module(self, schemas_dir):
        with open(schemas_dir / "sdk_tuning_endpoints.json", encoding="utf-8") as handle:
            openapi = json.load(handle)

        modules = openapi.get("x-endpoint-modules", [])
        assert any(
            module.get("paths_file") == "./optimization/optimization_endpoints.json"
            for module in modules
            if isinstance(module, dict)
        )

    def test_traces_response_requires_typed_trials_shape(self, schemas_dir):
        with open(
            schemas_dir / "execution" / "execution_endpoints.json",
            encoding="utf-8",
        ) as handle:
            execution_openapi = json.load(handle)

        data_schema = (
            execution_openapi["paths"]["/api/v1/experiment-runs/runs/{run_id}/traces"][
                "get"
            ]["responses"]["200"]["content"]["application/json"]["schema"]["properties"][
                "data"
            ]
        )
        required = data_schema["required"]
        assert "trials" in required
        assert "trials_pagination" in required
        assert "trials_page" not in required
        assert (
            data_schema["properties"]["trials"]["items"]["$ref"]
            == "./workflow_trace_trial_response_schema.json"
        )
        assert (
            data_schema["properties"]["trials_pagination"]["$ref"]
            == "../pagination_schema.json"
        )
        assert (
            schemas_dir
            / "execution"
            / data_schema["properties"]["trials"]["items"]["$ref"].removeprefix("./")
        ).exists()

    def test_workflow_metadata_schema_version_matches_field_set(self, schemas_dir):
        with open(
            schemas_dir / "execution" / "workflow_metadata_schema.json",
            encoding="utf-8",
        ) as handle:
            schema = json.load(handle)

        agent_definition = schema["definitions"]["AgentCostBreakdown"]
        workflow_required = set(schema["definitions"]["WorkflowMetadata"]["required"])

        assert schema["version"] == "3.1.0"
        assert "v3.1.0" in schema["$comment"]
        assert "model_used" in agent_definition["required"]
        assert "model" not in agent_definition["properties"]
        assert "total_tokens" in agent_definition["required"]
        assert {
            "total_input_tokens",
            "total_output_tokens",
            "total_tokens",
            "total_input_cost",
            "total_output_cost",
            "total_cost",
        } <= workflow_required

    def test_project_membership_update_request_schema_exists(self, schemas_dir):
        assert (
            schemas_dir / "projects" / "project_membership_update_request_schema.json"
        ).exists()


class TestExampleMetricsSchema:
    """Tests for ExampleMetrics nested structure validation.

    The ExampleMetrics structure separates example identification from
    metric values to prevent example_id from being stripped during validation.

    Structure: {"example_id": "ex_...", "metrics": {"score": 0.85, ...}}
    """

    @pytest.fixture
    def validator(self):
        """Create an AnalyticsValidator instance."""
        return AnalyticsValidator()

    def test_valid_nested_format_passes(self, validator):
        """Valid nested format should pass validation."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"score": 0.85, "cost": 0.05}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_nested_format_with_null_metric(self, validator):
        """Valid nested format with null metric values should pass."""
        data = {
            "example_id": "ex_abc12345de_42",
            "metrics": {"score": 0.85, "pending_metric": None}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_valid_nested_format_empty_metrics(self, validator):
        """Valid nested format with empty metrics dict should pass."""
        data = {
            "example_id": "ex_abc12345de_0",
            "metrics": {}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"

    def test_missing_example_id_fails(self, validator):
        """Missing example_id should fail."""
        data = {"metrics": {"score": 0.85}}
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("example_id" in e for e in errors)

    def test_missing_metrics_fails(self, validator):
        """Missing metrics should fail."""
        data = {"example_id": "ex_a3f4b2c8d1_0"}
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("metrics" in e for e in errors)

    def test_invalid_example_id_format_fails(self, validator):
        """Invalid example_id format should fail."""
        data = {
            "example_id": "invalid_format",
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("example_id" in e.lower() or "format" in e.lower() for e in errors)

    def test_example_id_uppercase_hex_fails(self, validator):
        """Example ID with uppercase hex should fail."""
        data = {
            "example_id": "ex_ABC12345_0",  # Uppercase not allowed
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0

    def test_example_id_wrong_prefix_fails(self, validator):
        """Example ID with wrong prefix should fail."""
        data = {
            "example_id": "example_abc12345_0",  # Should be 'ex_'
            "metrics": {"score": 0.85}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0

    def test_non_numeric_metric_fails(self, validator):
        """Non-numeric metric values should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"score": "not a number"}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("score" in e or "numeric" in e for e in errors)

    def test_boolean_metric_fails(self, validator):
        """Boolean metric values should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {"passed": True}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("passed" in e or "numeric" in e for e in errors)

    def test_exceeding_max_metrics_fails(self, validator):
        """More than 50 metrics should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {f"metric_{i}": float(i) for i in range(51)}
        }
        errors = validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("50" in e or "max" in e.lower() for e in errors)

    def test_exactly_50_metrics_passes(self, validator):
        """Exactly 50 metrics should pass."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": {f"metric_{i}": float(i) / 100 for i in range(50)}
        }
        errors = validator.validate_example_metrics(data)
        assert errors == [], f"Unexpected errors: {errors}"


class TestProjectContracts:
    """Tests for project-layer schema contracts and path normalization."""

    @pytest.fixture
    def validator(self):
        return SchemaValidator(contract="planned_projects")

    @pytest.fixture
    def analytics_validator(self):
        return AnalyticsValidator()

    def test_project_create_request_validates_against_schema(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects",
            "POST",
            {
                "name": "Core Platform",
                "slug": "core-platform",
                "description": "Primary project"
            },
        )
        assert errors == []

    def test_project_update_request_uses_templated_path_normalization(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123",
            "PATCH",
            {"name": "Updated Name"},
        )
        assert errors == []

    def test_project_update_request_reports_validation_errors(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123",
            "PATCH",
            {"unexpected": True},
        )
        assert errors

    def test_project_analytics_summary_path_normalizes_and_validates(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/analytics/summary",
            "GET",
            {},
        )
        assert errors == []

    def test_project_run_volume_trend_path_normalizes_and_validates(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/analytics/trends/run-volume",
            "GET",
            {},
        )
        assert errors == []

    def test_planned_projects_root_references_prompt_and_observability_modules(self):
        schemas_dir = get_schemas_dir()
        with open(schemas_dir / "planned_projects_endpoints.json", encoding="utf-8") as handle:
            openapi = json.load(handle)

        modules = openapi.get("x-endpoint-modules", [])
        paths_files = {
            module.get("paths_file")
            for module in modules
            if isinstance(module, dict)
        }
        assert "./prompts/prompts_endpoints.json" in paths_files
        assert "./observability/observability_endpoints.json" in paths_files

    def test_prompt_create_request_validates_against_planned_contract(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/prompts",
            "POST",
            {
                "name": "langfuse.prompt.support",
                "prompt_type": "text",
                "prompt_text": "Hello {{name}}",
                "labels": ["production"],
                "config": {"model": "mock-model"},
            },
        )
        assert errors == []

    def test_playground_run_request_validates_against_planned_contract(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/prompts/langfuse.prompt.support/playground/run",
            "POST",
            {
                "version": 1,
                "variables": {"name": "Dana"},
                "provider": "mock",
                "model": "mock-model",
                "dry_run": False,
            },
        )
        assert errors == []

    def test_observability_ingest_request_validates_against_planned_contract(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/observability/ingest",
            "POST",
            {
                "traces": [
                    {
                        "id": "trace_123",
                        "name": "dataset-run",
                        "session": {"id": "session_123", "user_id": "user_123"},
                        "observations": [
                            {
                                "id": "obs_123",
                                "type": "generation",
                                "name": "llm_call",
                            }
                        ],
                    }
                ]
            },
        )
        assert errors == []

    def test_observability_ingest_request_rejects_oversized_trace_batches(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/observability/ingest",
            "POST",
            {
                "traces": [
                    {
                        "id": f"trace_{index}",
                        "name": "dataset-run",
                    }
                    for index in range(101)
                ]
            },
        )
        assert any("maxItems" in error or "too long" in error for error in errors)

    def test_trace_feedback_request_rejects_missing_rating(self, validator):
        errors = validator.validate_request(
            "/api/v1beta/projects/proj_123/observability/traces/trace_123/feedback",
            "PUT",
            {"comment": "Helpful"},
        )
        assert errors

    def test_metrics_not_dict_fails(self, analytics_validator):
        """Metrics as non-dict type should fail."""
        data = {
            "example_id": "ex_a3f4b2c8d1_0",
            "metrics": [0.85, 0.05]  # Array instead of dict
        }
        errors = analytics_validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("dict" in e for e in errors)

    def test_example_id_not_string_fails(self, analytics_validator):
        """Example ID as non-string type should fail."""
        data = {
            "example_id": 12345,  # Number instead of string
            "metrics": {"score": 0.85}
        }
        errors = analytics_validator.validate_example_metrics(data)
        assert len(errors) > 0
        assert any("string" in e or "example_id" in e for e in errors)

    def test_project_analytics_schemas_define_privacy_classification(self):
        schemas_dir = get_schemas_dir()
        schema_names = [
            "project_scoped_analytics_summary_schema.json",
            "project_scoped_analytics_trend_schema.json",
            "project_scoped_measure_distribution_schema.json",
            "project_scoped_fine_tuning_manifest_schema.json",
        ]
        for schema_name in schema_names:
            with open(schemas_dir / "projects" / schema_name, encoding="utf-8") as handle:
                payload = json.load(handle)
            assert payload.get("x-privacy-classification") in {"aggregate_safe", "manifest_safe"}


class TestDatasetContracts:
    """Tests for canonical dataset contract validation and nested ref resolution."""

    @pytest.fixture
    def validator(self):
        return SchemaValidator()

    @staticmethod
    def _valid_dataset_payload() -> dict[str, object]:
        return {
            "id": "dataset_123",
            "name": "support_qa_dataset",
            "label": "Support QA Dataset",
            "description": "Evaluation dataset for support-style Q&A flows",
            "type": "input-output",
            "agent_type": "qa",
            "examples_count": 1,
            "generator_config": {
                "id": "generator_123",
                "dataset_id": "dataset_123",
                "model_parameters_id": "model_parameters_123",
                "instructions": "Generate realistic customer support questions",
                "context_type": "text",
                "context_source": "dataset",
            },
            "evaluator_config": {
                "id": "evaluator_123",
                "dataset_id": "dataset_123",
                "model_parameters_id": "model_parameters_123",
                "instructions": "Evaluate answer quality against the reference output",
                "context_type": "text",
                "context_source": "dataset",
            },
        }

    def test_dataset_create_request_validates_with_nested_refs(self, validator):
        # #267: the create-request generator_config/evaluator_config contracts now
        # require model_id (in addition to instructions), so the shared
        # resource-shaped fixture needs model_id added for this create-request path.
        payload = self._valid_dataset_payload()
        payload["generator_config"]["model_id"] = "gpt-4o-mini"
        payload["evaluator_config"]["model_id"] = "gpt-4o"
        errors = validator.validate_request(
            "/api/v1/datasets",
            "POST",
            payload,
        )
        assert errors == []

    def test_dataset_create_request_reports_schema_errors_not_ref_failures(self, validator):
        payload = self._valid_dataset_payload()
        payload["agent_type"] = "not-a-real-agent-type"
        errors = validator.validate_request("/api/v1/datasets", "POST", payload)
        assert errors
        assert not any("Unresolvable" in error or "Validation error:" in error for error in errors)
        assert any("agent_type" in error for error in errors)

    def test_experiment_create_request_validates_dataset_alias_and_nested_dataset(self, validator):
        errors = validator.validate_request(
            "/api/v1/experiments",
            "POST",
            {
                "id": "experiment_123",
                "name": "support-qa-experiment",
                "description": "Compares prompt variants on the support QA dataset",
                "configurations": {
                    "infrastructure": {
                        "infrastructure_id": "infra_123",
                        "compute": "cpu",
                        "memory": "8GB",
                        "timeout": 300,
                    }
                },
                "agent_id": "agent_123",
                "model_parameters_id": "model_parameters_123",
                "dataset_id": "dataset_123",
                "dataset": self._valid_dataset_payload(),
                "measures": ["measure_123"],
            },
        )
        assert errors == []

    def test_experiment_create_request_reports_nested_ref_validation_errors(self, validator):
        payload = {
            "id": "experiment_123",
            "name": "support-qa-experiment",
            "description": "Compares prompt variants on the support QA dataset",
            "configurations": {
                "infrastructure": {
                    "infrastructure_id": "infra_123",
                    "compute": "cpu",
                    "memory": "8GB",
                    "timeout": 300,
                }
            },
            "agent_id": "agent_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "dataset": self._valid_dataset_payload(),
            "status": "not-a-real-status",
            "measures": ["measure_123"],
        }
        errors = validator.validate_request("/api/v1/experiments", "POST", payload)
        assert errors
        assert not any("Unresolvable" in error or "Validation error:" in error for error in errors)
        assert any("status" in error for error in errors)

    def test_experiment_schema_accepts_nested_model_parameters_object(self, validator):
        payload = {
            "id": "experiment_456",
            "name": "support-qa-experiment",
            "description": "Compares prompt variants on the support QA dataset",
            "configurations": {
                "infrastructure": {
                    "infrastructure_id": "infra_123",
                    "compute": "cpu",
                    "memory": "8GB",
                    "timeout": 300,
                }
            },
            "agent_id": "agent_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "dataset": self._valid_dataset_payload(),
            "model_parameters": {
                "id": "model_parameters_123",
                "model_id": "gpt-4o-mini",
                "temperature": 0.2,
            },
            "measures": ["measure_123"],
        }

        errors = validator.validate_json(payload, "experiment_schema")
        assert errors == []

    def test_experiment_schema_accepts_list_response_stats(self, validator):
        payload = {
            "id": "experiment_789",
            "name": "support-qa-experiment",
            "description": "List response with compact run stats",
            "configurations": {
                "infrastructure": {
                    "infrastructure_id": "infra_123",
                    "compute": "cpu",
                    "memory": "8GB",
                    "timeout": 300,
                }
            },
            "agent_id": "agent_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "measures": ["measure_123"],
            "configuration_runs_count": 3,
            "total_examples": 42,
            "optimization_runs_count": 2,
            "experiment_run": {
                "id": "run_123",
                "run_id": "run_123",
                "experiment_id": "experiment_789",
                "status": "COMPLETED",
                "configuration_runs_count": 1,
                "summary_stats": {
                    "total_examples": 12,
                    "accuracy": 0.91,
                    "metrics": {"latency_ms": 120},
                },
                "metrics": {"latency_ms": 120},
            },
        }

        errors = validator.validate_json(payload, "experiment_schema")
        assert errors == []


class TestExperimentStatusEnumBinding:
    """#262: the experiment RESOURCE's status must bind to the canonical
    ExperimentStatus enum (the backend's distinct 8-member PG enum), not to
    ExperimentRunStatus (the 9-member run-level vocabulary it was
    previously mis-bound to). The embedded latest-run summary
    (`ExperimentListRunSummary.status`) is correctly a *run* status and must
    stay bound to ExperimentRunStatus."""

    @staticmethod
    def _status_definitions() -> dict[str, object]:
        with open(get_schemas_dir() / "status_schema.json", encoding="utf-8") as fh:
            return json.load(fh)["definitions"]

    @staticmethod
    def _base_experiment_payload(status: str | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "id": "experiment_123",
            "name": "support-qa-experiment",
            "description": "Compares prompt variants on the support QA dataset",
            "configurations": {
                "infrastructure": {
                    "infrastructure_id": "infra_123",
                    "compute": "cpu",
                    "memory": "8GB",
                    "timeout": 300,
                }
            },
            "agent_id": "agent_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "measures": ["measure_123"],
        }
        if status is not None:
            payload["status"] = status
        return payload

    def test_experiment_status_enum_exists_and_matches_backend_member_set(self):
        definitions = self._status_definitions()
        assert "ExperimentStatus" in definitions
        experiment_status = set(definitions["ExperimentStatus"]["enum"])
        run_status = set(definitions["ExperimentRunStatus"]["enum"])
        # Backend's distinct experiment-level PG enum (status_enums.py:97-107).
        assert experiment_status == {
            "NOT_STARTED",
            "PENDING",
            "REGISTERED",
            "RUNNING",
            "FAILED",
            "COMPLETED",
            "CANCELLED",
            "UNKNOWN",
        }
        # REGISTERED exists only at the experiment level.
        assert "REGISTERED" in experiment_status
        assert "REGISTERED" not in run_status
        # PAUSED / PARTIALLY_DELETED are run-level states: they are not members
        # of the Backend's experiment persistence enum (status_enums.py:97 at
        # TraigentBackend 56e66ca824fa).
        assert experiment_status.isdisjoint({"PAUSED", "PARTIALLY_DELETED"})
        assert {"PAUSED", "PARTIALLY_DELETED"} <= run_status

    def test_experiment_resource_status_binds_to_experiment_status(self):
        with open(
            get_schemas_dir() / "evaluation" / "experiment_schema.json", encoding="utf-8"
        ) as fh:
            schema = json.load(fh)
        assert schema["properties"]["status"]["$ref"].endswith(
            "status_schema.json#/definitions/ExperimentStatus"
        )
        # The embedded latest-run summary is a *run* status and stays as-is.
        run_summary_status = schema["definitions"]["ExperimentListRunSummary"]["properties"][
            "status"
        ]
        assert run_summary_status["$ref"].endswith(
            "status_schema.json#/definitions/ExperimentRunStatus"
        )

    def test_experiment_create_request_status_binds_to_experiment_status(self):
        with open(
            get_schemas_dir() / "evaluation" / "experiment_create_request_schema.json",
            encoding="utf-8",
        ) as fh:
            schema = json.load(fh)
        assert schema["properties"]["status"]["$ref"].endswith(
            "status_schema.json#/definitions/ExperimentStatus"
        )
        run_summary_status = schema["definitions"]["ExperimentListRunSummary"]["properties"][
            "status"
        ]
        assert run_summary_status["$ref"].endswith(
            "status_schema.json#/definitions/ExperimentRunStatus"
        )

    def test_experiment_schema_accepts_registered_status(self):
        validator = SchemaValidator()
        errors = validator.validate_json(
            self._base_experiment_payload(status="REGISTERED"), "experiment_schema"
        )
        assert errors == []

    def test_experiment_schema_rejects_run_only_paused_status(self):
        # PAUSED is a valid ExperimentRunStatus member but not a member of the
        # Backend's experiment persistence enum (creating an experiment with it
        # returns 422), so the experiment contract must reject it too.
        validator = SchemaValidator()
        errors = validator.validate_json(
            self._base_experiment_payload(status="PAUSED"), "experiment_schema"
        )
        assert errors
        # Name the rejected VALUE, not just the word "status": a $ref
        # resolution failure against status_schema.json would also mention
        # "status" and must not satisfy this test.
        assert any("PAUSED" in error for error in errors)

    def test_experiment_schema_rejects_run_only_partially_deleted_status(self):
        validator = SchemaValidator()
        errors = validator.validate_json(
            self._base_experiment_payload(status="PARTIALLY_DELETED"), "experiment_schema"
        )
        assert errors
        assert any("PARTIALLY_DELETED" in error for error in errors)

    @staticmethod
    def _base_experiment_create_payload(status: str | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "name": "support-qa-experiment",
            "dataset_id": "dataset_123",
            "agent_id": "agent_123",
        }
        if status is not None:
            payload["status"] = status
        return payload

    def test_experiment_create_request_accepts_registered_and_absent_status(self):
        # The request-role half of the rebinding: REGISTERED was schema-invalid
        # before this change and is what the Backend accepts on create (201).
        validator = SchemaValidator()
        for payload in (
            self._base_experiment_create_payload(),
            self._base_experiment_create_payload(status="REGISTERED"),
        ):
            assert validator.validate_json(payload, "experiment_create_request_schema") == []

    @pytest.mark.parametrize("run_only_status", ["PAUSED", "PARTIALLY_DELETED"])
    def test_experiment_create_request_rejects_run_only_statuses(self, run_only_status):
        # The Backend answers 422 for these on POST /api/v1/experiments; the
        # contract must reject them too instead of validating a doomed request.
        validator = SchemaValidator()
        errors = validator.validate_json(
            self._base_experiment_create_payload(status=run_only_status),
            "experiment_create_request_schema",
        )
        assert errors
        assert any(run_only_status in error for error in errors)


class TestObjectiveSchemaContracts:
    def test_objective_schema_accepts_sdk_defined_objectives(self):
        validator = SchemaValidator()

        errors = validator.validate_json(_objective_schema_payload(), "objective_schema")

        assert errors == []

    def test_objective_schema_requires_orientation_and_weight(self):
        validator = SchemaValidator()
        payload = {
            "objectives": [
                {
                    "name": "accuracy",
                }
            ]
        }

        errors = validator.validate_json(payload, "objective_schema")

        assert errors
        assert any("orientation" in error for error in errors)
        assert any("weight" in error for error in errors)

    def test_experiment_schema_accepts_objectives_contract(self):
        validator = SchemaValidator()
        payload = {
            "id": "experiment_objectives_123",
            "name": "support-qa-experiment",
            "description": "Experiment with SDK-defined objectives",
            "configurations": {
                "infrastructure": _infrastructure_payload(),
            },
            "agent_id": "agent_123",
            "model_parameters_id": "model_parameters_123",
            "dataset_id": "dataset_123",
            "measures": ["measure_123"],
            "objectives": _objective_schema_payload(),
        }

        errors = validator.validate_json(payload, "experiment_schema")

        assert errors == []

    def test_experiment_run_schema_accepts_objectives_contract(self):
        validator = SchemaValidator()
        payload = {
            "id": "experiment_run_123",
            "experiment_id": "experiment_objectives_123",
            "experiment_data": {},
            "objectives": _objective_schema_payload(),
        }

        errors = validator.validate_json(payload, "experiment_run_schema")

        assert errors == []

    def test_configuration_run_schema_accepts_multi_objective_summary_stats(self):
        validator = SchemaValidator()
        payload = {
            "id": "configuration_run_123",
            "experiment_run_id": "experiment_run_123",
            "experiment_parameters": {
                "infrastructure": _infrastructure_payload(),
            },
            "status": "PRUNED",
            "weighted_score": 0.89,
            "summary_stats": {
                "weighted_score": 0.89,
                "metrics": {
                    "accuracy": 0.94,
                    "cost": 0.12,
                    "latency": 180,
                },
                "multi_objective_analysis": {
                    "weighted_score": 0.89,
                    "objective_weights": {
                        "accuracy": 0.3,
                        "cost": 0.2,
                        "latency": 0.5,
                    },
                    "normalization_ranges": {
                        "accuracy": {"min": 0.7, "max": 0.99},
                        "cost": {"min": 0.1, "max": 0.5},
                        "latency": {"min": 100, "max": 400},
                    },
                    "analysis_timestamp": "2026-05-09T07:00:00Z",
                },
            },
        }

        errors = validator.validate_json(payload, "configuration_run_schema")

        assert errors == []

    @pytest.mark.parametrize(
        ("schema_name", "payload"),
        [
            (
                "agent_schema",
                {
                    "id": "agent_123",
                    "name": "Support Agent",
                    "agent_type": "qa",
                    "measures": [{}],
                },
            ),
            (
                "evaluation_schema",
                {
                    "evaluation_id": "eval_123",
                    "configuration_id": "configuration_run_123",
                    "experiment_run_id": "experiment_run_123",
                    "experiment_id": "experiment_123",
                    "metrics": ["accuracy"],
                    "status": "completed",
                    "scores": {},
                    "responses": [{}],
                },
            ),
            (
                "evaluation_results_schema",
                {
                    "id": "eval_results_123",
                    "evaluation_id": "eval_123",
                    "scores": {},
                    "detailed_metrics": {"accuracy": {}},
                    "created_at": "2026-05-09T07:00:00Z",
                },
            ),
        ],
    )
    def test_schema_references_resolve_without_unresolvable_errors(
        self, schema_name, payload
    ):
        validator = SchemaValidator()

        errors = validator.validate_json(payload, schema_name)

        assert not any(
            "Unresolvable" in error or "Validation error:" in error
            for error in errors
        )


class TestProjectRetentionPolicyResponseRequiredness:
    """#331: the retention-policy response under-required 2 of 8 policy fields and
    carried `default`s on the other 6, unlike its rate-limit sibling which requires
    all 4 of its policy fields. Backend's ``_normalize_retention_policy``
    (`src/services/project_service.py` in the backend repo) unconditionally fills all 8
    fields (clamped to a default when absent), so the response contract can — and
    should — require all 8 and drop the response-schema `default`s (defaults belong
    on the update-request schema, not the resource response).
    """

    @staticmethod
    def _full_retention_payload() -> dict[str, object]:
        return {
            "tenant_id": "tenant_123",
            "project_id": "project_123",
            "updated_at": None,
            "updated_by": None,
            "policy": {
                "export_artifact_retention_days": 30,
                "materialized_export_retention_days": 7,
                "trace_retention_days": 30,
                "dataset_retention_days": 30,
                "dataset_storage_limit_bytes": 5368709120,
                "observability_ingest_rpm": 600,
                "inline_payload_max_bytes": 262144,
                "payload_max_bytes": 10485760,
            },
        }

    def test_full_backend_shaped_payload_validates(self):
        validator = SchemaValidator()
        errors = validator.validate_json(
            self._full_retention_payload(), "project_retention_policy_schema"
        )
        assert errors == []

    @pytest.mark.parametrize(
        "missing_field",
        [
            "trace_retention_days",
            "dataset_retention_days",
            "dataset_storage_limit_bytes",
            "observability_ingest_rpm",
            "inline_payload_max_bytes",
            "payload_max_bytes",
        ],
    )
    def test_response_missing_a_previously_optional_field_now_fails(self, missing_field):
        validator = SchemaValidator()
        payload = self._full_retention_payload()
        del payload["policy"][missing_field]
        errors = validator.validate_json(payload, "project_retention_policy_schema")
        assert errors, f"expected a validation error when policy omits {missing_field}"

    def test_response_schema_requires_all_eight_policy_fields_and_drops_defaults(self):
        with open(
            get_schemas_dir() / "projects" / "project_retention_policy_schema.json",
            encoding="utf-8",
        ) as handle:
            schema = json.load(handle)
        policy_schema = schema["properties"]["policy"]
        assert set(policy_schema["required"]) == set(policy_schema["properties"].keys())
        for field_schema in policy_schema["properties"].values():
            assert "default" not in field_schema

