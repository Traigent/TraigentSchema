"""Validation for the Python/JS SDK parity manifest."""

from __future__ import annotations

import json
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parents[1] / "parity" / "python-js-sdk.json"
PYTHON_DEVELOP_SHA = "4fe3cd370eb4f8945644543bce9f03ed12e4857c"

PYTHON_DEVELOP_UNCONDITIONAL_ROOT_SYMBOLS = {
    "ADVISORY_SELECTION_NOTICE",
    "AndCondition",
    "AnnotationQueueDTO",
    "AnnotationQueueItemDTO",
    "AnnotationQueueItemListResponse",
    "AnnotationQueueItemStatus",
    "AnnotationQueueListResponse",
    "AnnotationQueueStatus",
    "BackfillResultDTO",
    "BenchmarkClient",
    "BenchmarkClientConfig",
    "BoolExpr",
    "ChatPromptMessage",
    "Choices",
    "Condition",
    "ConfigAccessWarning",
    "ConfigSpace",
    "ConfigurationComparison",
    "Constraint",
    "ConstraintManager",
    "ConstraintScopeError",
    "ConstraintValidationResult",
    "ConstraintValidator",
    "ConstraintViolation",
    "CoreMetricsClient",
    "CoreMetricsConfig",
    "CorrelationIds",
    "DTOSerializationError",
    "DataIntegrityError",
    "Dataset",
    "EnterpriseAdminClient",
    "EnterpriseAdminConfig",
    "EvaluationClient",
    "EvaluationConfig",
    "EvaluationExample",
    "EvaluationTargetRefDTO",
    "EvaluationTargetType",
    "EvaluatorDefinitionDTO",
    "EvaluatorListResponse",
    "EvaluatorRunDTO",
    "EvaluatorRunListResponse",
    "EvaluatorRunStatus",
    "IntRange",
    "JudgeConfigDTO",
    "LogRange",
    "LoggingCallback",
    "MeasureValueType",
    "MetricExtractionError",
    "MultiObjectiveMetrics",
    "NormalizedStrategyPreset",
    "NotCondition",
    "ObservabilityClient",
    "ObservabilityConfig",
    "ObservationDTO",
    "ObservationRecord",
    "ObservationType",
    "ObserveContext",
    "OptimizationResult",
    "OptimizationState",
    "OptimizationStateError",
    "OptimizationStatus",
    "OptimizationValidator",
    "OrCondition",
    "PaginationInfo",
    "ParameterImportanceAnalyzer",
    "ParameterRange",
    "ParetoFront",
    "ParetoFrontCalculator",
    "PersistenceManager",
    "PlatformCapabilityError",
    "PlotGenerator",
    "PresetSelection",
    "ProgressBarCallback",
    "ProjectManagementClient",
    "ProjectManagementConfig",
    "PromptDetail",
    "PromptListResponse",
    "PromptManagementClient",
    "PromptManagementConfig",
    "PromptPlaygroundConfig",
    "PromptPlaygroundResult",
    "PromptPlaygroundTokenUsage",
    "PromptSummary",
    "PromptType",
    "PromptVersionRecord",
    "PythonConstraintValidator",
    "Range",
    "ResolvedPrompt",
    "RetryConfig",
    "SSOProviderType",
    "SatResult",
    "SatStatus",
    "ScoreRecordDTO",
    "ScoreRecordListResponse",
    "ScoreSource",
    "SensitivityAnalysis",
    "SessionDTO",
    "SessionListResponse",
    "SessionRecord",
    "StatisticsCallback",
    "StrategyConfig",
    "StrategyPresetError",
    "StrategyPresetValidationError",
    "TenantDTO",
    "TenantListResponse",
    "TenantMembershipDTO",
    "TenantMembershipListResponse",
    "TenantMembershipRole",
    "TenantMembershipStatus",
    "TenantSSOConfigDTO",
    "TextDocument",
    "ThumbRating",
    "TraceCollaborationState",
    "TraceCommentRecord",
    "TraceCommentsResponse",
    "TraceDTO",
    "TraceFeedbackRecord",
    "TraceFeedbackResponse",
    "TraceFeedbackSummary",
    "TraceListResponse",
    "TraceObservationsResponse",
    "TraceRecord",
    "TraigentConfig",
    "TraigentDeprecationWarning",
    "TraigentMetadata",
    "TraigentWarning",
    "TrialError",
    "TrialResult",
    "UnknownStrategyPresetError",
    "VALID_PRESET_NAMES",
    "ValidationResult",
    "WhenBuilder",
    "add_agent_span",
    "configure",
    "configure_for_budget",
    "constraints_to_callables",
    "copy_context_to_thread",
    "create_quick_plot",
    "get_available_strategies",
    "get_config",
    "get_current_config",
    "get_default_callbacks",
    "get_default_observability_client",
    "get_optimization_insights",
    "get_trial_config",
    "get_trial_context",
    "get_verbose_callbacks",
    "get_version_info",
    "implies",
    "initialize",
    "is_traigent_metadata",
    "list_recommendation_agent_types",
    "max_tokens_constraint",
    "model_cost_constraint",
    "normalize_strategy_preset",
    "normalize_constraints",
    "observe",
    "optimize",
    "override_config",
    "require",
    "recommend_configuration_space",
    "retry",
    "serialize_trials",
    "select_strategy_preset",
    "set_default_observability_client",
    "set_strategy",
    "temperature_constraint",
    "validate_and_suggest",
    "when",
    "with_usage",
}

PYTHON_DEVELOP_CONDITIONAL_ROOT_SYMBOLS = {
    "AgentCostBreakdown",
    "MeasuresDict",
    "WorkflowCostSummary",
}

PYTHON_DEVELOP_ROOT_SYMBOLS = (
    PYTHON_DEVELOP_UNCONDITIONAL_ROOT_SYMBOLS | PYTHON_DEVELOP_CONDITIONAL_ROOT_SYMBOLS
)


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def conditional_root_exports(manifest: dict) -> list[dict]:
    value = manifest["python"].get("conditionalRootExports")
    assert isinstance(value, list)
    assert value
    return value


def conditional_symbols_by_js_runtime(manifest: dict, js_runtime: str) -> set[str]:
    symbols: set[str] = set()
    for block in conditional_root_exports(manifest):
        runtime = block.get("runtime", {})
        assert runtime.get("python") == "conditional"
        if runtime.get("js") == js_runtime:
            symbols.update(block["symbols"])
    return symbols


def test_manifest_tracks_python_develop_pin() -> None:
    manifest = load_manifest()

    assert manifest["authority"] == "TraigentSchema"
    assert manifest["python"]["targetRef"] == "origin/develop"
    assert manifest["python"]["targetSha"] == PYTHON_DEVELOP_SHA
    assert manifest["python"]["releaseSurface"] == "next-release"


def test_manifest_records_js_observed_sha_as_informational() -> None:
    manifest = load_manifest()
    observed_sha = manifest["javascript"]["observedSha"]

    assert manifest["javascript"]["observedRef"] == "origin/main"
    assert len(observed_sha) == 40
    assert set(observed_sha) <= set("0123456789abcdef")
    assert "Informational only" in manifest["javascript"]["observedShaPolicy"]


def test_every_python_root_symbol_has_one_classification() -> None:
    manifest = load_manifest()
    classifications = manifest["classifications"]

    seen: dict[str, str] = {}
    duplicates: dict[str, list[str]] = {}
    for classification, symbols in classifications.items():
        for symbol in symbols:
            if symbol in seen:
                duplicates.setdefault(symbol, [seen[symbol]]).append(classification)
            seen[symbol] = classification

    assert duplicates == {}
    assert set(seen) == PYTHON_DEVELOP_ROOT_SYMBOLS


def test_conditional_python_root_exports_are_modeled_explicitly() -> None:
    manifest = load_manifest()
    blocks = conditional_root_exports(manifest)
    by_source = {block["source"]: block for block in blocks}

    assert set(by_source) == {
        "traigent.cloud.agent_dtos",
        "traigent.cloud.dtos",
    }
    assert set(by_source["traigent.cloud.agent_dtos"]["symbols"]) == {
        "AgentCostBreakdown",
        "WorkflowCostSummary",
    }
    assert by_source["traigent.cloud.agent_dtos"]["runtime"] == {
        "python": "conditional",
        "js": "not-required",
    }
    assert by_source["traigent.cloud.agent_dtos"]["classification"] == "deferred-backlog"

    measures_runtime = by_source["traigent.cloud.dtos"]["runtime"]
    assert by_source["traigent.cloud.dtos"]["symbols"] == ["MeasuresDict"]
    assert measures_runtime["python"] == "conditional"
    assert measures_runtime["js"] == "required"
    assert measures_runtime["javascriptKind"] == "type"
    assert measures_runtime["javascriptRuntimeCompanion"] == "MeasuresDictSchema"
    assert by_source["traigent.cloud.dtos"]["classification"] == "matched"

    conditional_symbols = {
        symbol
        for block in blocks
        for symbol in block["symbols"]
    }
    assert conditional_symbols == PYTHON_DEVELOP_CONDITIONAL_ROOT_SYMBOLS


def test_required_js_exports_are_classified() -> None:
    manifest = load_manifest()
    required = set(manifest["javascript"]["requiredRootExports"])
    stub_exports = set(manifest["javascript"]["stubRootExports"])
    deferred_out_of_release = set(manifest["javascript"]["deferredOutOfRelease"])
    classifications = manifest["classifications"]
    classified = {
        symbol
        for symbols in classifications.values()
        for symbol in symbols
    }
    production_exports = set(classifications["matched"]) | set(classifications["additive-js-alias"])

    assert required <= classified
    assert production_exports <= required
    assert conditional_symbols_by_js_runtime(manifest, "required") <= required
    assert conditional_symbols_by_js_runtime(manifest, "not-required").isdisjoint(required)
    assert stub_exports <= required
    assert stub_exports.isdisjoint(deferred_out_of_release)
    assert required.isdisjoint(deferred_out_of_release)


def test_removed_stub_symbols_are_deferred_not_exported() -> None:
    """BenchmarkClient/EnterpriseAdmin stubs were removed from the JS SDK.

    They remain Python root symbols, so they must stay classified (deferred),
    but they must no longer be advertised as JS exports or stubs.
    """
    manifest = load_manifest()
    required = set(manifest["javascript"]["requiredRootExports"])
    stub_exports = set(manifest["javascript"]["stubRootExports"])
    classifications = manifest["classifications"]

    removed_stubs = {
        "BenchmarkClient",
        "BenchmarkClientConfig",
        "EnterpriseAdminClient",
        "EnterpriseAdminConfig",
    }

    assert {"BenchmarkClient", "BenchmarkClientConfig"} <= set(
        classifications["deferred-schema"]
    )
    assert {"EnterpriseAdminClient", "EnterpriseAdminConfig"} <= set(
        classifications["deferred-backlog"]
    )
    assert removed_stubs.isdisjoint(required)
    assert removed_stubs.isdisjoint(stub_exports)


def test_release_policy_documents_forward_binding_and_refresh_cadence() -> None:
    manifest = load_manifest()
    release_policy = manifest["releasePolicy"]

    assert "may ship before Python 0.12.0" in release_policy["js020PythonReleaseOrder"]
    assert "Python 0.11.4" in release_policy["publishedPythonCompatibilityNote"]
    assert len(release_policy["refreshCadence"]) >= 4
    assert "manifestRefresh" in manifest["decisions"]


def test_observability_default_wrappers_are_deferred_out_of_0_2_0() -> None:
    manifest = load_manifest()
    deferred = set(manifest["classifications"]["deferred-backlog"])

    assert {
        "ObserveContext",
        "get_default_observability_client",
        "observe",
        "set_default_observability_client",
    } <= deferred
    assert set(manifest["javascript"]["deferredOutOfRelease"]) <= deferred
