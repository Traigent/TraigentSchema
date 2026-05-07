"""Validation for the Python/JS SDK parity manifest."""

from __future__ import annotations

import json
from pathlib import Path


MANIFEST_PATH = Path(__file__).resolve().parents[1] / "parity" / "python-js-sdk.json"
PYTHON_DEVELOP_SHA = "f9f1adcb19ea8c3874bb1b7ef21f6d11b1b95a18"

PYTHON_DEVELOP_ROOT_SYMBOLS = {
    "AndCondition",
    "AgentCostBreakdown",
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
    "MeasuresDict",
    "MeasureValueType",
    "MetricExtractionError",
    "MultiObjectiveMetrics",
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
    "PlotGenerator",
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
    "TenantDTO",
    "TenantListResponse",
    "TenantMembershipDTO",
    "TenantMembershipListResponse",
    "TenantMembershipRole",
    "TenantMembershipStatus",
    "TenantSSOConfigDTO",
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
    "ValidationResult",
    "WhenBuilder",
    "WorkflowCostSummary",
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
    "max_tokens_constraint",
    "model_cost_constraint",
    "normalize_constraints",
    "observe",
    "optimize",
    "override_config",
    "require",
    "retry",
    "serialize_trials",
    "set_default_observability_client",
    "set_strategy",
    "temperature_constraint",
    "validate_and_suggest",
    "when",
    "with_usage",
}


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_manifest_tracks_python_develop_pin() -> None:
    manifest = load_manifest()

    assert manifest["authority"] == "TraigentSchema"
    assert manifest["python"]["targetRef"] == "origin/develop"
    assert manifest["python"]["targetSha"] == PYTHON_DEVELOP_SHA
    assert manifest["python"]["releaseSurface"] == "next-python-release"


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


def test_required_js_exports_are_classified_and_include_stubs() -> None:
    manifest = load_manifest()
    required = set(manifest["javascript"]["requiredRootExports"])
    stub_exports = set(manifest["javascript"]["stubRootExports"])
    classified = {
        symbol
        for symbols in manifest["classifications"].values()
        for symbol in symbols
    }

    assert required <= classified
    assert stub_exports <= required
    assert {"BenchmarkClient", "BenchmarkClientConfig"} <= stub_exports
    assert {"EnterpriseAdminClient", "EnterpriseAdminConfig"} <= stub_exports


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
