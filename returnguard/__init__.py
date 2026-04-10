"""returnguard — AI-powered returns fraud detection for retail and eCommerce."""
from returnguard.models import (
    CustomerProfile,
    FraudScore,
    FraudSignal,
    ReturnRequest,
    ReturnReason,
    RiskLevel,
)
from returnguard.scorer import FraudScorer
from returnguard.exceptions import (
    ProfileError,
    ReturnGuardError,
    ScoringError,
    ValidationError,
)
from returnguard.advanced import (
    AuditLog,
    CancellationToken,
    CustomerRiskProfile,
    CustomerRiskProfiler,
    FraudCache,
    FraudDiff,
    FraudPipeline,
    FraudProfiler,
    FraudSignalExplainer,
    PIIScrubber,
    PolicyScenario,
    PolicySimulationResult,
    RateLimiter,
    ReturnPolicySimulator,
    ReturnRule,
    ReturnSpanEmitter,
    ReturnValidator,
    RiskTrend,
    abatch_score,
    batch_score,
    diff_scores,
    scores_to_ndjson,
    stream_scores,
)

__version__ = "1.1.0"
__all__ = [
    # Core
    "FraudScorer",
    "FraudScore",
    "FraudSignal",
    "ReturnRequest",
    "ReturnReason",
    "RiskLevel",
    "CustomerProfile",
    # Exceptions
    "ReturnGuardError",
    "ScoringError",
    "ProfileError",
    "ValidationError",
    # Advanced — base
    "FraudCache",
    "FraudPipeline",
    "ReturnValidator",
    "ReturnRule",
    "RateLimiter",
    "CancellationToken",
    "batch_score",
    "abatch_score",
    "FraudProfiler",
    "RiskTrend",
    "stream_scores",
    "scores_to_ndjson",
    "FraudDiff",
    "diff_scores",
    "AuditLog",
    "PIIScrubber",
    # Advanced — expert
    "CustomerRiskProfiler",
    "CustomerRiskProfile",
    "ReturnPolicySimulator",
    "PolicyScenario",
    "PolicySimulationResult",
    "FraudSignalExplainer",
    "ReturnSpanEmitter",
]
