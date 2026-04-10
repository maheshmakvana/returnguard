"""Fraud scoring engine for returnguard."""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from returnguard.models import (
    CustomerProfile,
    FraudScore,
    FraudSignal,
    ReturnRequest,
    ReturnReason,
    RiskLevel,
)

logger = logging.getLogger(__name__)

# Risk thresholds — score ranges that map to risk levels
_RISK_THRESHOLDS = {
    RiskLevel.LOW:      0.30,
    RiskLevel.MEDIUM:   0.55,
    RiskLevel.HIGH:     0.75,
    RiskLevel.CRITICAL: 1.0,
}

# Signal weights — contribution of each signal to the overall fraud score
_SIGNAL_WEIGHTS: Dict[str, float] = {
    FraudSignal.HIGH_RETURN_RATE.value:  0.35,   # strongest structural signal
    FraudSignal.SERIAL_RETURNER.value:   0.30,
    FraudSignal.WARDROBING.value:        0.28,
    FraudSignal.EMPTY_BOX.value:         0.25,
    FraudSignal.REFUND_ONLY.value:       0.20,
    FraudSignal.VELOCITY.value:          0.20,
    FraudSignal.COUPON_STACKING.value:   0.18,
    FraudSignal.ADDRESS_MISMATCH.value:  0.18,
    FraudSignal.POLICY_ABUSE.value:      0.15,
    FraudSignal.ACCOUNT_AGE.value:       0.15,
}


def _classify_risk(score: float) -> RiskLevel:
    for level, threshold in _RISK_THRESHOLDS.items():
        if score <= threshold:
            return level
    return RiskLevel.CRITICAL


class FraudScorer:
    """
    Weighted rule-based fraud scorer for return requests.

    Each check contributes a weighted component to the total fraud score.
    Signal weights are calibrated so that a single moderate signal stays
    below the auto-block threshold, while two or more signals stack into
    high/critical territory — matching real-world fraud operations patterns.
    """

    def __init__(
        self,
        return_rate_threshold: float = 0.30,
        high_value_threshold: float = 200.0,
        velocity_window_days: int = 30,
        velocity_limit: int = 3,
        max_days_since_purchase: int = 60,
        new_account_days: int = 30,
    ) -> None:
        self.return_rate_threshold = return_rate_threshold
        self.high_value_threshold = high_value_threshold
        self.velocity_window_days = velocity_window_days
        self.velocity_limit = velocity_limit
        self.max_days_since_purchase = max_days_since_purchase
        self.new_account_days = new_account_days
        self._lock = threading.Lock()

    # ─── Signal detectors ────────────────────────────────────────────────────

    def _check_return_rate(
        self, profile: Optional[CustomerProfile], signals: List[FraudSignal]
    ) -> float:
        """High historical return rate relative to order volume."""
        if profile and profile.return_rate > self.return_rate_threshold:
            signals.append(FraudSignal.HIGH_RETURN_RATE)
            # Scale contribution with how far above threshold the rate is
            excess = min(1.0, (profile.return_rate - self.return_rate_threshold) / (1.0 - self.return_rate_threshold))
            return _SIGNAL_WEIGHTS[FraudSignal.HIGH_RETURN_RATE.value] * (0.5 + 0.5 * excess)
        return 0.0

    def _check_wardrobing(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """Use-and-return: changed_mind reason within a short window on a high-value order."""
        if (
            request.reason == ReturnReason.CHANGED_MIND
            and request.days_since_purchase < 7
            and request.order_value >= self.high_value_threshold
        ):
            signals.append(FraudSignal.WARDROBING)
            return _SIGNAL_WEIGHTS[FraudSignal.WARDROBING.value]
        return 0.0

    def _check_velocity(
        self, profile: Optional[CustomerProfile], signals: List[FraudSignal]
    ) -> float:
        """High return volume within the velocity window."""
        if profile and profile.total_returns >= self.velocity_limit:
            signals.append(FraudSignal.VELOCITY)
            # Scale up for extreme velocity
            multiplier = min(2.0, profile.total_returns / self.velocity_limit)
            return _SIGNAL_WEIGHTS[FraudSignal.VELOCITY.value] * multiplier
        return 0.0

    def _check_serial_returner(
        self, profile: Optional[CustomerProfile], signals: List[FraudSignal]
    ) -> float:
        """Customer has been flagged multiple times historically."""
        if profile and profile.flagged_count >= 2:
            signals.append(FraudSignal.SERIAL_RETURNER)
            excess = min(3, profile.flagged_count - 1)  # cap at 3 extra flags
            return _SIGNAL_WEIGHTS[FraudSignal.SERIAL_RETURNER.value] * (1 + excess * 0.1)
        return 0.0

    def _check_policy_abuse(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """Return submitted outside the allowed return window."""
        if request.days_since_purchase > self.max_days_since_purchase:
            signals.append(FraudSignal.POLICY_ABUSE)
            overshoot_pct = min(1.0, (request.days_since_purchase - self.max_days_since_purchase) / self.max_days_since_purchase)
            return _SIGNAL_WEIGHTS[FraudSignal.POLICY_ABUSE.value] * (0.5 + 0.5 * overshoot_pct)
        return 0.0

    def _check_account_age(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """New account submitting a high-value return immediately."""
        metadata = request.metadata or {}
        account_created_str = metadata.get("account_created_at")
        if account_created_str:
            try:
                created = datetime.fromisoformat(str(account_created_str))
                age_days = (datetime.utcnow() - created).days
                if age_days < self.new_account_days and request.order_value >= self.high_value_threshold:
                    signals.append(FraudSignal.ACCOUNT_AGE)
                    # Shorter account age = higher risk
                    youth_factor = 1.0 - (age_days / self.new_account_days)
                    return _SIGNAL_WEIGHTS[FraudSignal.ACCOUNT_AGE.value] * (0.5 + 0.5 * youth_factor)
            except (ValueError, TypeError):
                pass
        return 0.0

    def _check_address_mismatch(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """Return shipping address differs from the original delivery address."""
        metadata = request.metadata or {}
        delivery_zip = metadata.get("delivery_zip")
        return_zip = metadata.get("return_zip")
        if delivery_zip and return_zip and str(delivery_zip) != str(return_zip):
            signals.append(FraudSignal.ADDRESS_MISMATCH)
            return _SIGNAL_WEIGHTS[FraudSignal.ADDRESS_MISMATCH.value]
        return 0.0

    def _check_coupon_stacking(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """Order used multiple promotional codes — common in price-arbitrage fraud."""
        metadata = request.metadata or {}
        coupon_count = int(metadata.get("coupon_count", 0))
        if coupon_count >= 2:
            signals.append(FraudSignal.COUPON_STACKING)
            excess = min(3, coupon_count - 1)
            return _SIGNAL_WEIGHTS[FraudSignal.COUPON_STACKING.value] * (1 + excess * 0.05)
        return 0.0

    def _check_empty_box(
        self, request: ReturnRequest, signals: List[FraudSignal]
    ) -> float:
        """Customer claims the package was empty upon delivery."""
        metadata = request.metadata or {}
        if metadata.get("claimed_empty_box") is True or str(metadata.get("claimed_empty_box", "")).lower() == "true":
            signals.append(FraudSignal.EMPTY_BOX)
            return _SIGNAL_WEIGHTS[FraudSignal.EMPTY_BOX.value]
        return 0.0

    def _check_refund_only(
        self, profile: Optional[CustomerProfile], signals: List[FraudSignal]
    ) -> float:
        """Customer has never exchanged — only ever requested full cash refunds."""
        if profile and profile.return_reasons:
            total_returns = sum(profile.return_reasons.values())
            refund_only_count = profile.return_reasons.get("refund_only_flag", 0)
            # Infer from high changed_mind rate (proxy for cash-refund-seeking)
            changed_mind = profile.return_reasons.get("changed_mind", 0)
            if total_returns > 2 and changed_mind / total_returns >= 0.80:
                signals.append(FraudSignal.REFUND_ONLY)
                return _SIGNAL_WEIGHTS[FraudSignal.REFUND_ONLY.value]
            if refund_only_count > 0 and total_returns > 2 and refund_only_count / total_returns >= 0.80:
                signals.append(FraudSignal.REFUND_ONLY)
                return _SIGNAL_WEIGHTS[FraudSignal.REFUND_ONLY.value]
        return 0.0

    # ─── Public API ──────────────────────────────────────────────────────────

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
        total += self._check_account_age(request, signals)
        total += self._check_address_mismatch(request, signals)
        total += self._check_coupon_stacking(request, signals)
        total += self._check_empty_box(request, signals)
        total += self._check_refund_only(profile, signals)

        # Cap at 1.0
        score = min(1.0, total)
        risk = _classify_risk(score)

        action_map = {
            RiskLevel.LOW:      "Auto-approve return",
            RiskLevel.MEDIUM:   "Flag for manual review",
            RiskLevel.HIGH:     "Require photo evidence + manual review",
            RiskLevel.CRITICAL: "Block return and escalate to fraud team",
        }

        signal_names = [s.value for s in signals]
        explanation_parts = [f"Score: {score:.3f}", f"Risk: {risk.value}"]
        if signals:
            explanation_parts.append(f"Signals ({len(signals)}): {', '.join(signal_names)}")

        result = FraudScore(
            return_id=request.return_id,
            customer_id=request.customer_id,
            score=round(score, 4),
            risk_level=risk,
            signals=signals,
            explanation=". ".join(explanation_parts),
            recommended_action=action_map[risk],
        )
        logger.info(
            "Scored return %s: risk=%s score=%.4f signals=%s",
            request.return_id, risk.value, score, signal_names,
        )
        return result

    def batch_score(
        self,
        requests: List[ReturnRequest],
        profiles: Optional[Dict[str, CustomerProfile]] = None,
    ) -> List[FraudScore]:
        """Score a batch of return requests; returns scores sorted by fraud score descending."""
        profiles = profiles or {}
        scores = [self.score(r, profiles.get(r.customer_id)) for r in requests]
        return sorted(scores, key=lambda s: s.score, reverse=True)

    def score_summary(self, scores: List[FraudScore]) -> Dict[str, object]:
        """Aggregate statistics across a batch of FraudScores."""
        if not scores:
            return {"total": 0}
        by_risk: Dict[str, int] = {}
        for s in scores:
            by_risk[s.risk_level.value] = by_risk.get(s.risk_level.value, 0) + 1
        avg_score = sum(s.score for s in scores) / len(scores)
        high_risk = [s for s in scores if s.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
        return {
            "total": len(scores),
            "avg_score": round(avg_score, 4),
            "by_risk_level": by_risk,
            "high_risk_count": len(high_risk),
            "high_risk_pct": round(len(high_risk) / len(scores) * 100, 2),
            "top_signals": _top_signals(scores, n=5),
        }


def _top_signals(scores: List[FraudScore], n: int = 5) -> List[Dict[str, object]]:
    """Return the most frequently triggered fraud signals across a batch."""
    counts: Dict[str, int] = {}
    for s in scores:
        for sig in s.signals:
            counts[sig.value] = counts.get(sig.value, 0) + 1
    return [
        {"signal": k, "count": v, "pct": round(v / len(scores) * 100, 2)}
        for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]
    ]
