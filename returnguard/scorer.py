"""Fraud scoring engine for returnguard."""
from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional

from returnguard.models import (
    CustomerProfile,
    FraudScore,
    FraudSignal,
    ReturnRequest,
    RiskLevel,
)

logger = logging.getLogger(__name__)

# Risk thresholds
_RISK_THRESHOLDS = {
    RiskLevel.LOW: 0.3,
    RiskLevel.MEDIUM: 0.55,
    RiskLevel.HIGH: 0.75,
    RiskLevel.CRITICAL: 1.0,
}


def _classify_risk(score: float) -> RiskLevel:
    for level, threshold in _RISK_THRESHOLDS.items():
        if score <= threshold:
            return level
    return RiskLevel.CRITICAL


class FraudScorer:
    """Rule-based fraud scorer for return requests."""

    def __init__(
        self,
        return_rate_threshold: float = 0.30,
        high_value_threshold: float = 200.0,
        velocity_window_days: int = 30,
        velocity_limit: int = 3,
        max_days_since_purchase: int = 60,
    ) -> None:
        self.return_rate_threshold = return_rate_threshold
        self.high_value_threshold = high_value_threshold
        self.velocity_window_days = velocity_window_days
        self.velocity_limit = velocity_limit
        self.max_days_since_purchase = max_days_since_purchase
        self._lock = threading.Lock()

    def _check_return_rate(self, profile: Optional[CustomerProfile], signals: List[FraudSignal]) -> float:
        if profile and profile.return_rate > self.return_rate_threshold:
            signals.append(FraudSignal.HIGH_RETURN_RATE)
            return min(0.4, profile.return_rate)
        return 0.0

    def _check_wardrobing(self, request: ReturnRequest, signals: List[FraudSignal]) -> float:
        """Detect use-and-return pattern: changed_mind + short window + high value."""
        from returnguard.models import ReturnReason
        if (
            request.reason == ReturnReason.CHANGED_MIND
            and request.days_since_purchase < 7
            and request.order_value >= self.high_value_threshold
        ):
            signals.append(FraudSignal.WARDROBING)
            return 0.3
        return 0.0

    def _check_velocity(self, profile: Optional[CustomerProfile], signals: List[FraudSignal]) -> float:
        if profile and profile.total_returns >= self.velocity_limit:
            signals.append(FraudSignal.VELOCITY)
            return 0.2
        return 0.0

    def _check_serial_returner(self, profile: Optional[CustomerProfile], signals: List[FraudSignal]) -> float:
        if profile and profile.flagged_count >= 2:
            signals.append(FraudSignal.SERIAL_RETURNER)
            return 0.25
        return 0.0

    def _check_policy_abuse(self, request: ReturnRequest, signals: List[FraudSignal]) -> float:
        if request.days_since_purchase > self.max_days_since_purchase:
            signals.append(FraudSignal.POLICY_ABUSE)
            return 0.15
        return 0.0

    def score(
        self,
        request: ReturnRequest,
        profile: Optional[CustomerProfile] = None,
    ) -> FraudScore:
        """Score a return request and return a FraudScore."""
        signals: List[FraudSignal] = []
        total = 0.0

        total += self._check_return_rate(profile, signals)
        total += self._check_wardrobing(request, signals)
        total += self._check_velocity(profile, signals)
        total += self._check_serial_returner(profile, signals)
        total += self._check_policy_abuse(request, signals)

        score = min(1.0, total)
        risk = _classify_risk(score)

        action_map = {
            RiskLevel.LOW: "Auto-approve return",
            RiskLevel.MEDIUM: "Flag for manual review",
            RiskLevel.HIGH: "Require photo evidence + manual review",
            RiskLevel.CRITICAL: "Block return and escalate to fraud team",
        }

        explanation_parts = [f"Score: {score:.2f}"]
        if signals:
            explanation_parts.append(f"Signals: {', '.join(s.value for s in signals)}")

        result = FraudScore(
            return_id=request.return_id,
            customer_id=request.customer_id,
            score=score,
            risk_level=risk,
            signals=signals,
            explanation=". ".join(explanation_parts),
            recommended_action=action_map[risk],
        )
        logger.info("Scored return %s: risk=%s score=%.2f signals=%s", request.return_id, risk.value, score, [s.value for s in signals])
        return result

    def batch_score(
        self,
        requests: List[ReturnRequest],
        profiles: Optional[Dict[str, CustomerProfile]] = None,
    ) -> List[FraudScore]:
        """Score a batch of return requests."""
        profiles = profiles or {}
        return [self.score(r, profiles.get(r.customer_id)) for r in requests]
