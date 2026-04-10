"""Advanced features for returnguard — caching, pipeline, async, observability, diff, security."""
from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, TypeVar

from returnguard.models import CustomerProfile, FraudScore, ReturnRequest

logger = logging.getLogger(__name__)
T = TypeVar("T")


# ─────────────────────────────────────────────────────────────────────────────
# CACHING
# ─────────────────────────────────────────────────────────────────────────────

class FraudCache:
    """LRU + TTL cache for fraud scores, keyed by SHA-256."""

    def __init__(self, max_size: int = 512, ttl_seconds: float = 600.0) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._store: OrderedDict[str, Tuple[Any, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._lock = threading.Lock()

    def _key(self, *args: Any, **kwargs: Any) -> str:
        raw = json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                self._misses += 1
                return None
            value, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            self._store[key] = (value, time.monotonic() + self.ttl_seconds)
            while len(self._store) > self.max_size:
                self._store.popitem(last=False)

    def memoize(self, fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            key = self._key(fn.__name__, *args, **kwargs)
            cached = self.get(key)
            if cached is not None:
                return cached  # type: ignore[return-value]
            result = fn(*args, **kwargs)
            self.set(key, result)
            return result
        return wrapper

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 3) if total else 0.0,
            "size": len(self._store),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds,
        }

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class _Step:
    name: str
    fn: Callable
    args: Tuple = field(default_factory=tuple)
    kwargs: Dict = field(default_factory=dict)


class FraudPipeline:
    """Fluent pipeline for chaining return fraud analysis steps."""

    def __init__(self) -> None:
        self._steps: List[_Step] = []
        self._audit: List[Dict[str, Any]] = []
        self._retry_count = 0
        self._retry_delay = 0.5

    def map(self, fn: Callable[[List[FraudScore]], List[FraudScore]], name: str = "") -> "FraudPipeline":
        self._steps.append(_Step(name=name or fn.__name__, fn=fn))
        return self

    def filter(self, predicate: Callable[[FraudScore], bool], name: str = "") -> "FraudPipeline":
        def _filter(scores: List[FraudScore]) -> List[FraudScore]:
            return [s for s in scores if predicate(s)]
        self._steps.append(_Step(name=name or "filter", fn=_filter))
        return self

    def with_retry(self, count: int = 3, delay: float = 0.5) -> "FraudPipeline":
        self._retry_count = count
        self._retry_delay = delay
        return self

    def run(self, scores: List[FraudScore]) -> List[FraudScore]:
        result = scores
        for step in self._steps:
            attempts = 0
            while True:
                try:
                    t0 = time.monotonic()
                    result = step.fn(result)
                    elapsed = time.monotonic() - t0
                    self._audit.append({"step": step.name, "in": len(scores), "out": len(result), "elapsed_ms": round(elapsed * 1000, 2), "ok": True})
                    break
                except Exception as exc:
                    attempts += 1
                    if attempts > self._retry_count:
                        self._audit.append({"step": step.name, "error": str(exc), "ok": False})
                        raise
                    time.sleep(self._retry_delay)
        return result

    async def arun(self, scores: List[FraudScore]) -> List[FraudScore]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.run(scores))

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReturnRule:
    field: str
    rule_type: str   # "max_order_value", "allowed_reasons", "min_days", "max_days"
    value: Any
    message: str = ""


class ReturnValidator:
    """Declarative validator for return requests."""

    def __init__(self) -> None:
        self._rules: List[ReturnRule] = []

    def add_rule(self, rule: ReturnRule) -> "ReturnValidator":
        self._rules.append(rule)
        return self

    def validate(self, request: ReturnRequest) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        for rule in self._rules:
            if rule.rule_type == "max_order_value" and request.order_value > rule.value:
                errors.append(rule.message or f"Order value {request.order_value} exceeds max {rule.value}")
            elif rule.rule_type == "allowed_reasons" and request.reason.value not in rule.value:
                errors.append(rule.message or f"Reason {request.reason.value} not in allowed list")
            elif rule.rule_type == "max_days" and request.days_since_purchase > rule.value:
                errors.append(rule.message or f"Return window {request.days_since_purchase}d exceeds max {rule.value}d")
            elif rule.rule_type == "min_days" and request.days_since_purchase < rule.value:
                errors.append(rule.message or f"Return submitted too soon ({request.days_since_purchase}d)")
        return len(errors) == 0, errors

    def validate_batch(self, requests: List[ReturnRequest]) -> Dict[str, List[str]]:
        return {r.return_id: self.validate(r)[1] for r in requests if not self.validate(r)[0]}


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC & CONCURRENCY
# ─────────────────────────────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter (sync + async)."""

    def __init__(self, rate: float, capacity: float) -> None:
        self.rate = rate
        self.capacity = capacity
        self._tokens = capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def acquire(self, tokens: float = 1.0) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    async def async_acquire(self, tokens: float = 1.0) -> bool:
        while not self.acquire(tokens):
            await asyncio.sleep(0.05)
        return True


class CancellationToken:
    def __init__(self) -> None:
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled


def batch_score(
    requests: List[ReturnRequest],
    score_fn: Callable[[ReturnRequest], FraudScore],
    max_workers: int = 4,
    token: Optional[CancellationToken] = None,
) -> List[FraudScore]:
    results: List[FraudScore] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(score_fn, r): r for r in requests}
        for future in as_completed(futures):
            if token and token.is_cancelled:
                break
            results.append(future.result())
    return results


async def abatch_score(
    requests: List[ReturnRequest],
    score_fn: Callable[[ReturnRequest], FraudScore],
    max_concurrency: int = 4,
    token: Optional[CancellationToken] = None,
) -> List[FraudScore]:
    sem = asyncio.Semaphore(max_concurrency)
    loop = asyncio.get_event_loop()

    async def run_one(r: ReturnRequest) -> FraudScore:
        async with sem:
            if token and token.is_cancelled:
                raise asyncio.CancelledError()
            return await loop.run_in_executor(None, lambda: score_fn(r))

    return list(await asyncio.gather(*[run_one(r) for r in requests]))


# ─────────────────────────────────────────────────────────────────────────────
# OBSERVABILITY
# ─────────────────────────────────────────────────────────────────────────────

class FraudProfiler:
    def __init__(self) -> None:
        self._records: List[Dict[str, Any]] = []

    def profile(self, fn: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            t0 = time.monotonic()
            try:
                result = fn(*args, **kwargs)
                self._records.append({"fn": fn.__name__, "elapsed_ms": round((time.monotonic() - t0) * 1000, 2), "ok": True})
                return result
            except Exception as exc:
                self._records.append({"fn": fn.__name__, "elapsed_ms": round((time.monotonic() - t0) * 1000, 2), "error": str(exc), "ok": False})
                raise
        return wrapper

    def report(self) -> List[Dict[str, Any]]:
        return list(self._records)


class RiskTrend:
    """Track rolling fraud score trends with volatility."""

    def __init__(self, window: int = 10) -> None:
        self._window = window
        self._scores: List[float] = []

    def record(self, score: float) -> None:
        self._scores.append(score)
        if len(self._scores) > self._window:
            self._scores.pop(0)

    def trend(self) -> str:
        if len(self._scores) < 2:
            return "insufficient_data"
        first_half = self._scores[: len(self._scores) // 2]
        second_half = self._scores[len(self._scores) // 2 :]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)
        if avg_second > avg_first * 1.05:
            return "increasing"
        if avg_second < avg_first * 0.95:
            return "decreasing"
        return "stable"

    def volatility(self) -> float:
        import statistics
        if len(self._scores) < 2:
            return 0.0
        return round(statistics.stdev(self._scores), 4)


# ─────────────────────────────────────────────────────────────────────────────
# STREAMING
# ─────────────────────────────────────────────────────────────────────────────

def stream_scores(scores: List[FraudScore]) -> Generator[FraudScore, None, None]:
    for score in scores:
        yield score


def scores_to_ndjson(scores: List[FraudScore]) -> Generator[str, None, None]:
    for score in scores:
        yield score.model_dump_json() + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# DIFF & REGRESSION
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FraudDiff:
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {"added": len(self.added), "removed": len(self.removed), "modified": len(self.modified)}

    def to_json(self) -> str:
        return json.dumps({"added": self.added, "removed": self.removed, "modified": self.modified})


def diff_scores(a: List[FraudScore], b: List[FraudScore]) -> FraudDiff:
    map_a = {s.return_id: s for s in a}
    map_b = {s.return_id: s for s in b}
    diff = FraudDiff(
        added=[rid for rid in map_b if rid not in map_a],
        removed=[rid for rid in map_a if rid not in map_b],
    )
    for rid in set(map_a) & set(map_b):
        changes: Dict[str, Any] = {}
        for f in ("score", "risk_level"):
            va, vb = getattr(map_a[rid], f), getattr(map_b[rid], f)
            if va != vb:
                changes[f] = {"old": va, "new": vb}
        if changes:
            diff.modified[rid] = changes
    return diff


# ─────────────────────────────────────────────────────────────────────────────
# SECURITY
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog:
    def __init__(self) -> None:
        self._entries: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, action: str, return_id: str, detail: Optional[str] = None) -> None:
        with self._lock:
            self._entries.append({"ts": datetime.utcnow().isoformat(), "action": action, "return_id": return_id, "detail": detail})

    def export(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._entries)


class PIIScrubber:
    import re as _re
    _EMAIL = _re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    _SSN = _re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    _PHONE = _re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")

    @classmethod
    def scrub(cls, text: str) -> str:
        text = cls._EMAIL.sub("[EMAIL]", text)
        text = cls._SSN.sub("[SSN]", text)
        text = cls._PHONE.sub("[PHONE]", text)
        return text


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: CUSTOMER RISK PROFILER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CustomerRiskProfile:
    """Aggregated risk profile derived from a CustomerProfile."""
    customer_id: str
    return_rate: float
    avg_fraud_score: float
    flagged_count: int
    dominant_reason: Optional[str]
    risk_tier: str          # "trusted", "watch", "restricted", "blocked"
    recommended_policy: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "return_rate": round(self.return_rate, 4),
            "avg_fraud_score": round(self.avg_fraud_score, 4),
            "flagged_count": self.flagged_count,
            "dominant_reason": self.dominant_reason,
            "risk_tier": self.risk_tier,
            "recommended_policy": self.recommended_policy,
        }


class CustomerRiskProfiler:
    """
    Build structured risk profiles from CustomerProfile objects.

    Classifies customers into four tiers based on return rate, fraud score
    history, and flagged count. Produces policy recommendations that can drive
    automated return workflow rules (auto-approve, manual review, restrict, block).

    Usage::

        profiler = CustomerRiskProfiler()
        profile = profiler.profile(customer_profile)
        print(profile.risk_tier)  # "watch"
        print(profile.recommended_policy)
    """

    _TIER_THRESHOLDS = {
        "blocked":    {"fraud_score": 0.80, "return_rate": None, "flagged": 5},
        "restricted": {"fraud_score": 0.60, "return_rate": 0.40, "flagged": 3},
        "watch":      {"fraud_score": 0.35, "return_rate": 0.20, "flagged": 1},
        "trusted":    {"fraud_score": 0.0,  "return_rate": 0.0,  "flagged": 0},
    }

    _POLICIES: Dict[str, str] = {
        "blocked":    "Block return submission; escalate to fraud ops team for manual review.",
        "restricted": "Require photo evidence + supervisor approval before processing any refund.",
        "watch":      "Flag for manual review; allow return but hold refund pending verification.",
        "trusted":    "Auto-approve return; issue refund immediately.",
    }

    def profile(self, cp: CustomerProfile) -> CustomerRiskProfile:
        """Derive a risk profile from a CustomerProfile."""
        dominant_reason: Optional[str] = None
        if cp.return_reasons:
            dominant_reason = max(cp.return_reasons, key=lambda k: cp.return_reasons[k])

        tier = self._classify(cp)
        return CustomerRiskProfile(
            customer_id=cp.customer_id,
            return_rate=cp.return_rate,
            avg_fraud_score=cp.avg_fraud_score,
            flagged_count=cp.flagged_count,
            dominant_reason=dominant_reason,
            risk_tier=tier,
            recommended_policy=self._POLICIES[tier],
        )

    def _classify(self, cp: CustomerProfile) -> str:
        t = self._TIER_THRESHOLDS
        if cp.avg_fraud_score >= t["blocked"]["fraud_score"] or cp.flagged_count >= t["blocked"]["flagged"]:
            return "blocked"
        if cp.avg_fraud_score >= t["restricted"]["fraud_score"] or \
           cp.return_rate >= t["restricted"]["return_rate"] or \
           cp.flagged_count >= t["restricted"]["flagged"]:
            return "restricted"
        if cp.avg_fraud_score >= t["watch"]["fraud_score"] or \
           cp.return_rate >= t["watch"]["return_rate"] or \
           cp.flagged_count >= t["watch"]["flagged"]:
            return "watch"
        return "trusted"

    def bulk_profile(self, profiles: List[CustomerProfile]) -> List[CustomerRiskProfile]:
        """Profile multiple customers; returns list sorted by risk tier severity."""
        order = {"blocked": 0, "restricted": 1, "watch": 2, "trusted": 3}
        results = [self.profile(cp) for cp in profiles]
        return sorted(results, key=lambda x: order[x.risk_tier])

    def to_markdown(self, profiles: List[CustomerRiskProfile]) -> str:
        """Render a Markdown risk summary table."""
        lines = ["# Customer Risk Profiles", "",
                 "| Customer ID | Return Rate | Avg Fraud Score | Flagged | Tier | Policy |",
                 "|-------------|------------|----------------|---------|------|--------|"]
        for p in profiles:
            lines.append(
                f"| {p.customer_id} | {p.return_rate:.1%} | {p.avg_fraud_score:.3f} | "
                f"{p.flagged_count} | {p.risk_tier.upper()} | {p.recommended_policy[:60]}… |"
            )
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: RETURN POLICY SIMULATOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PolicyScenario:
    """A return policy configuration to simulate."""
    name: str
    max_return_window_days: int
    max_order_value: float
    allowed_reasons: List[str]
    require_receipt: bool = False
    max_returns_per_customer_30d: int = 10


@dataclass
class PolicySimulationResult:
    """Outcome of simulating a policy against a batch of return requests."""
    scenario_name: str
    total_requests: int
    approved: int
    rejected: int
    rejection_rate: float
    rejection_reasons: Dict[str, int]
    estimated_fraud_prevented: int   # count of high-score requests rejected

    def summary(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario_name,
            "total": self.total_requests,
            "approved": self.approved,
            "rejected": self.rejected,
            "rejection_rate": round(self.rejection_rate, 4),
            "estimated_fraud_prevented": self.estimated_fraud_prevented,
            "top_rejection_reason": max(self.rejection_reasons, key=lambda r: self.rejection_reasons[r]) if self.rejection_reasons else None,
        }


class ReturnPolicySimulator:
    """
    Simulate different return policies against historical return request data.

    Lets merchants test tighter or looser policies before rolling them out,
    estimating approval rates and fraud prevention impact without affecting live
    operations.

    Usage::

        sim = ReturnPolicySimulator()
        scenario = PolicyScenario(
            name="strict_90d",
            max_return_window_days=90,
            max_order_value=500.0,
            allowed_reasons=["defective", "wrong_item"],
        )
        result = sim.simulate(scenario, requests, fraud_scores)
        print(result.summary())
    """

    def simulate(
        self,
        scenario: PolicyScenario,
        requests: List[ReturnRequest],
        fraud_scores: Optional[List[FraudScore]] = None,
        high_risk_threshold: float = 0.70,
    ) -> PolicySimulationResult:
        """Run a policy simulation over a batch of return requests."""
        score_map: Dict[str, float] = {}
        if fraud_scores:
            score_map = {fs.return_id: fs.score for fs in fraud_scores}

        # Track per-customer 30-day return counts for velocity rule
        customer_counts: Dict[str, int] = {}
        for r in requests:
            customer_counts[r.customer_id] = customer_counts.get(r.customer_id, 0) + 1

        approved = 0
        rejected = 0
        rejection_reasons: Dict[str, int] = {}
        fraud_prevented = 0

        for req in requests:
            reason = self._evaluate(req, scenario, customer_counts, score_map, high_risk_threshold)
            if reason is None:
                approved += 1
            else:
                rejected += 1
                rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
                score = score_map.get(req.return_id, 0.0)
                if score >= high_risk_threshold:
                    fraud_prevented += 1

        total = len(requests)
        return PolicySimulationResult(
            scenario_name=scenario.name,
            total_requests=total,
            approved=approved,
            rejected=rejected,
            rejection_rate=rejected / total if total else 0.0,
            rejection_reasons=rejection_reasons,
            estimated_fraud_prevented=fraud_prevented,
        )

    def _evaluate(
        self,
        req: ReturnRequest,
        scenario: PolicyScenario,
        customer_counts: Dict[str, int],
        score_map: Dict[str, float],
        high_risk_threshold: float,
    ) -> Optional[str]:
        """Return a rejection reason string, or None if approved."""
        if req.days_since_purchase > scenario.max_return_window_days:
            return "exceeded_return_window"
        if req.order_value > scenario.max_order_value:
            return "order_value_too_high"
        if req.reason.value not in scenario.allowed_reasons:
            return "reason_not_allowed"
        if customer_counts.get(req.customer_id, 0) > scenario.max_returns_per_customer_30d:
            return "velocity_limit_exceeded"
        if score_map.get(req.return_id, 0.0) >= high_risk_threshold:
            return "high_fraud_score"
        return None

    def compare(
        self,
        scenarios: List[PolicyScenario],
        requests: List[ReturnRequest],
        fraud_scores: Optional[List[FraudScore]] = None,
    ) -> List[Dict[str, Any]]:
        """Run multiple scenarios and return a comparison table."""
        results = [self.simulate(s, requests, fraud_scores) for s in scenarios]
        return sorted([r.summary() for r in results], key=lambda x: x["rejection_rate"])

    def to_markdown(self, results: List[Dict[str, Any]]) -> str:
        """Render scenario comparison as Markdown."""
        lines = ["# Policy Simulation Comparison", "",
                 "| Scenario | Approved | Rejected | Rejection Rate | Fraud Prevented |",
                 "|----------|----------|----------|----------------|-----------------|"]
        for r in results:
            lines.append(
                f"| {r['scenario']} | {r['approved']} | {r['rejected']} | "
                f"{r['rejection_rate']:.1%} | {r['estimated_fraud_prevented']} |"
            )
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: FRAUD SIGNAL EXPLAINER
# ─────────────────────────────────────────────────────────────────────────────

_SIGNAL_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "high_return_rate": {
        "label": "High Return Rate",
        "description": "Customer has returned more than 30% of all orders historically.",
        "action": "Request photo proof of issue before approving.",
    },
    "wardrobing": {
        "label": "Wardrobing Pattern",
        "description": "Customer typically returns items after high-traffic events (holidays, weekends).",
        "action": "Require tags-on condition check before accepting return.",
    },
    "empty_box": {
        "label": "Empty Box Claim",
        "description": "Customer claims item was missing from package.",
        "action": "Escalate to fulfillment team to verify packing records.",
    },
    "policy_abuse": {
        "label": "Policy Abuse",
        "description": "Return submitted at the boundary of the policy window repeatedly.",
        "action": "Flag account; require manager approval on future returns.",
    },
    "coupon_stacking": {
        "label": "Coupon Stacking",
        "description": "Order used multiple discount codes; return may be a price arbitrage attempt.",
        "action": "Issue store credit rather than cash refund.",
    },
    "account_age": {
        "label": "New Account",
        "description": "Account is less than 30 days old with an immediate high-value return.",
        "action": "Delay refund by 5 business days; verify identity.",
    },
    "velocity": {
        "label": "High Return Velocity",
        "description": "More than 3 returns submitted within the last 30 days.",
        "action": "Place account on manual review for all future returns.",
    },
    "address_mismatch": {
        "label": "Address Mismatch",
        "description": "Return shipping address differs from delivery address.",
        "action": "Contact customer to confirm return legitimacy.",
    },
    "refund_only": {
        "label": "Refund-Only Pattern",
        "description": "Customer has never exchanged — only requested full refunds.",
        "action": "Offer exchange or store credit; block cash refund path.",
    },
    "serial_returner": {
        "label": "Serial Returner",
        "description": "Customer appears in the top 1% of returners by volume.",
        "action": "Add to watchlist; consider return restriction policy.",
    },
}


class FraudSignalExplainer:
    """
    Translate FraudScore signal codes into human-readable explanations.

    Produces structured explanations, markdown-formatted decision summaries,
    and customer-facing decline messages for use in email templates or
    support tooling.

    Usage::

        explainer = FraudSignalExplainer()
        print(explainer.explain(fraud_score))
    """

    def explain(self, score: FraudScore) -> Dict[str, Any]:
        """Return structured explanation for all signals on a fraud score."""
        explained = []
        for signal in score.signals:
            meta = _SIGNAL_EXPLANATIONS.get(signal.value, {
                "label": signal.value,
                "description": "Unknown fraud signal.",
                "action": "Manual review recommended.",
            })
            explained.append({"signal": signal.value, **meta})
        return {
            "return_id": score.return_id,
            "customer_id": score.customer_id,
            "risk_level": score.risk_level.value,
            "score": score.score,
            "signals": explained,
            "recommended_action": score.recommended_action,
        }

    def to_markdown(self, score: FraudScore) -> str:
        """Render a full Markdown decision report for a fraud score."""
        data = self.explain(score)
        lines = [
            f"# Fraud Decision Report — Return {score.return_id}",
            f"**Risk Level**: {data['risk_level'].upper()}  |  **Score**: {data['score']:.3f}",
            f"**Recommended Action**: {data['recommended_action']}",
            "",
            "## Fraud Signals Detected",
        ]
        if not data["signals"]:
            lines.append("_No fraud signals detected._")
        else:
            for s in data["signals"]:
                lines.append(f"### {s['label']}")
                lines.append(f"- **What it means**: {s['description']}")
                lines.append(f"- **Suggested action**: {s['action']}")
        return "\n".join(lines)

    def customer_decline_message(self, score: FraudScore) -> str:
        """
        Generate a polite, non-accusatory customer-facing decline message.
        Safe to include in email templates.
        """
        return (
            f"Thank you for reaching out regarding return #{score.return_id}. "
            "After reviewing your request, we are unable to process this return at this time "
            "based on our current return policy. If you believe this is an error, "
            "please contact our support team with your order details and we will be happy to assist."
        )

    def bulk_explain(self, scores: List[FraudScore]) -> List[Dict[str, Any]]:
        """Explain multiple scores; sorted by score descending."""
        return sorted([self.explain(s) for s in scores], key=lambda x: x["score"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT: RETURN SPAN EMITTER (OpenTelemetry with stdlib fallback)
# ─────────────────────────────────────────────────────────────────────────────

class ReturnSpanEmitter:
    """
    Emit OpenTelemetry spans for returns fraud scoring operations.
    Falls back to structured logging when opentelemetry-sdk is not installed.
    """

    def __init__(self, service_name: str = "returnguard") -> None:
        self._service = service_name
        self._otel_available = False
        self._tracer: Any = None
        try:
            from opentelemetry import trace  # type: ignore[import-untyped]
            from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-untyped]
            provider = TracerProvider()
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(service_name)
            self._otel_available = True
            logger.debug("ReturnSpanEmitter: OpenTelemetry tracer initialised")
        except ImportError:
            logger.debug("ReturnSpanEmitter: opentelemetry not installed — using log fallback")

    def span(self, operation: str, attributes: Optional[Dict[str, Any]] = None) -> Any:
        """Context manager: emit an OTEL span or log span start/end."""
        if self._otel_available and self._tracer is not None:
            span = self._tracer.start_span(operation)
            if attributes:
                for k, v in attributes.items():
                    span.set_attribute(k, str(v))
            return span
        return _LogSpan(operation, attributes or {}, self._service)

    def emit_score(self, score: FraudScore) -> None:
        """Emit a span for a completed fraud scoring result."""
        attrs = {
            "return_id": score.return_id,
            "customer_id": score.customer_id,
            "score": score.score,
            "risk_level": score.risk_level.value,
            "signal_count": len(score.signals),
        }
        with self.span("returnguard.score", attrs):
            pass


class _LogSpan:
    """Stdlib-logging fallback span used when OTEL is unavailable."""

    def __init__(self, name: str, attrs: Dict[str, Any], service: str) -> None:
        self._name = name
        self._attrs = attrs
        self._service = service
        self._t0 = time.monotonic()

    def __enter__(self) -> "_LogSpan":
        logger.debug("[span:start] service=%s operation=%s attrs=%s", self._service, self._name, self._attrs)
        return self

    def __exit__(self, *args: Any) -> None:
        elapsed = round((time.monotonic() - self._t0) * 1000, 2)
        logger.debug("[span:end] service=%s operation=%s elapsed_ms=%s", self._service, self._name, elapsed)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT v1.2.0: REFUND ANOMALY DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RefundAnomaly:
    """A detected statistical anomaly in a refund amount."""
    return_id: str
    customer_id: str
    refund_amount: float
    z_score: float
    population_mean: float
    population_std: float
    anomaly_type: str    # "extreme_high", "extreme_low", "round_number", "duplicate_amount"
    confidence: float
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "return_id": self.return_id,
            "customer_id": self.customer_id,
            "refund_amount": round(self.refund_amount, 2),
            "z_score": round(self.z_score, 3),
            "anomaly_type": self.anomaly_type,
            "confidence": round(self.confidence, 3),
            "description": self.description,
        }


class RefundAnomalyDetector:
    """
    Detect statistical anomalies in refund amounts using z-score analysis.

    Maintains a rolling population of refund amounts and flags individual
    refunds that deviate significantly from the norm. Also detects round-number
    manipulation and exact-duplicate refund patterns that human reviewers miss.

    Usage::

        detector = RefundAnomalyDetector(z_threshold=3.0)
        detector.fit(historical_amounts)
        anomalies = detector.detect(return_requests)
        for a in anomalies:
            print(a.anomaly_type, a.refund_amount)
    """

    def __init__(self, z_threshold: float = 3.0, window: int = 500) -> None:
        self.z_threshold = z_threshold
        self.window = window
        self._amounts: List[float] = []
        self._lock = threading.Lock()

    def fit(self, amounts: List[float]) -> "RefundAnomalyDetector":
        """Seed the detector with historical refund amounts."""
        with self._lock:
            self._amounts = list(amounts[-self.window:])
        return self

    def record(self, amount: float) -> None:
        """Add a new refund amount to the rolling population."""
        with self._lock:
            self._amounts.append(amount)
            if len(self._amounts) > self.window:
                self._amounts.pop(0)

    def _stats(self) -> Tuple[float, float]:
        """Return (mean, std) of current population."""
        import statistics
        if len(self._amounts) < 2:
            return 0.0, 1.0
        mean = sum(self._amounts) / len(self._amounts)
        std = statistics.stdev(self._amounts) or 1.0
        return mean, std

    def detect(self, requests: List[ReturnRequest]) -> List[RefundAnomaly]:
        """
        Detect anomalies across a batch of return requests.

        Checks: extreme z-score, round-number manipulation, duplicate amounts.
        """
        mean, std = self._stats()
        anomalies: List[RefundAnomaly] = []
        seen_amounts: Dict[float, int] = {}

        for req in requests:
            amount = req.order_value
            seen_amounts[amount] = seen_amounts.get(amount, 0) + 1

        for req in requests:
            amount = req.order_value
            z = (amount - mean) / std if std > 0 else 0.0

            if abs(z) >= self.z_threshold:
                atype = "extreme_high" if z > 0 else "extreme_low"
                conf = min(0.99, abs(z) / (self.z_threshold * 2))
                anomalies.append(RefundAnomaly(
                    return_id=req.return_id,
                    customer_id=req.customer_id,
                    refund_amount=amount,
                    z_score=z,
                    population_mean=mean,
                    population_std=std,
                    anomaly_type=atype,
                    confidence=conf,
                    description=(
                        f"Refund amount ${amount:.2f} is {abs(z):.1f} std devs "
                        f"{'above' if z > 0 else 'below'} mean ${mean:.2f}."
                    ),
                ))
            elif amount > 0 and amount % 100 == 0 and amount >= 500:
                anomalies.append(RefundAnomaly(
                    return_id=req.return_id,
                    customer_id=req.customer_id,
                    refund_amount=amount,
                    z_score=z,
                    population_mean=mean,
                    population_std=std,
                    anomaly_type="round_number",
                    confidence=0.45,
                    description=f"Refund amount ${amount:.0f} is a suspiciously round number.",
                ))
            elif seen_amounts.get(amount, 0) >= 3:
                anomalies.append(RefundAnomaly(
                    return_id=req.return_id,
                    customer_id=req.customer_id,
                    refund_amount=amount,
                    z_score=z,
                    population_mean=mean,
                    population_std=std,
                    anomaly_type="duplicate_amount",
                    confidence=0.60,
                    description=f"Refund amount ${amount:.2f} appears {seen_amounts[amount]} times in this batch.",
                ))

        return sorted(anomalies, key=lambda x: x.confidence, reverse=True)

    def summary(self, anomalies: List[RefundAnomaly]) -> Dict[str, Any]:
        """Return aggregate statistics over detected anomalies."""
        by_type: Dict[str, int] = {}
        for a in anomalies:
            by_type[a.anomaly_type] = by_type.get(a.anomaly_type, 0) + 1
        return {
            "total_anomalies": len(anomalies),
            "by_type": by_type,
            "population_size": len(self._amounts),
            "population_mean": round(self._stats()[0], 2),
            "population_std": round(self._stats()[1], 2),
        }

    def to_markdown(self, anomalies: List[RefundAnomaly]) -> str:
        """Render a Markdown anomaly report."""
        lines = [
            "# Refund Anomaly Detection Report",
            "",
            "| Return ID | Customer | Amount | Z-Score | Type | Confidence |",
            "|-----------|----------|--------|---------|------|------------|",
        ]
        for a in anomalies:
            lines.append(
                f"| {a.return_id} | {a.customer_id} | ${a.refund_amount:.2f} | "
                f"{a.z_score:+.2f} | {a.anomaly_type.replace('_', ' ')} | "
                f"{a.confidence:.0%} |"
            )
        if not anomalies:
            lines.append("| _No anomalies detected_ | — | — | — | — | — |")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# EXPERT v1.2.0: BEHAVIOR FINGERPRINTER
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BehaviorFingerprint:
    """
    A compact behavioral fingerprint for a customer's return history.

    Feature vector encodes: return rate, avg days to return, dominant reason,
    avg order value, % high-value returns, velocity (returns per month).
    Used for similarity scoring and cohort matching.
    """
    customer_id: str
    return_rate: float
    avg_days_to_return: float
    dominant_reason: Optional[str]
    avg_order_value: float
    high_value_pct: float     # fraction of returns above merchant's 75th-pct order value
    velocity_per_month: float
    _vector: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "customer_id": self.customer_id,
            "return_rate": round(self.return_rate, 4),
            "avg_days_to_return": round(self.avg_days_to_return, 1),
            "dominant_reason": self.dominant_reason,
            "avg_order_value": round(self.avg_order_value, 2),
            "high_value_pct": round(self.high_value_pct, 4),
            "velocity_per_month": round(self.velocity_per_month, 3),
        }


@dataclass
class FingerprintSimilarity:
    """Cosine similarity between two customer fingerprints."""
    customer_a: str
    customer_b: str
    similarity: float   # 0.0 – 1.0
    shared_signals: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "customer_a": self.customer_a,
            "customer_b": self.customer_b,
            "similarity": round(self.similarity, 4),
            "shared_signals": self.shared_signals,
        }


class BehaviorFingerprinter:
    """
    Build compact behavioral fingerprints from customer return histories.

    Fingerprints encode return rate, timing, reason distribution, order value
    distribution, and velocity into a normalised feature vector. Cosine
    similarity between fingerprints identifies customers who share fraud patterns
    — useful for ring-fraud and coordinated abuse detection.

    Usage::

        fp = BehaviorFingerprinter(high_value_threshold=200.0)
        fingerprints = fp.build_all(customer_profiles)
        similar_pairs = fp.find_similar_pairs(fingerprints, threshold=0.85)
    """

    def __init__(self, high_value_threshold: float = 200.0) -> None:
        self.high_value_threshold = high_value_threshold

    def build(self, cp: CustomerProfile, history: Optional[List[ReturnRequest]] = None) -> BehaviorFingerprint:
        """Build a fingerprint from a CustomerProfile (and optional raw history)."""
        dominant: Optional[str] = None
        if cp.return_reasons:
            dominant = max(cp.return_reasons, key=lambda k: cp.return_reasons[k])

        avg_days = 0.0
        high_val_pct = 0.0
        avg_ov = 0.0
        velocity = 0.0
        if history:
            days_list = [r.days_since_purchase for r in history if r.days_since_purchase > 0]
            avg_days = sum(days_list) / len(days_list) if days_list else 0.0
            ovs = [r.order_value for r in history]
            avg_ov = sum(ovs) / len(ovs) if ovs else 0.0
            high_val_pct = sum(1 for v in ovs if v >= self.high_value_threshold) / len(ovs) if ovs else 0.0
            # estimate monthly velocity: total returns / period — assume 12 months
            velocity = len(history) / 12.0

        # Build normalised feature vector [0..1]
        reason_enc = {
            "defective": 1, "wrong_item": 2, "changed_mind": 3,
            "not_as_described": 4, "damaged": 5, "other": 6,
        }
        reason_val = reason_enc.get(dominant or "", 0) / 6.0

        vector = [
            min(1.0, cp.return_rate),
            min(1.0, avg_days / 90.0),
            reason_val,
            min(1.0, avg_ov / 1000.0),
            high_val_pct,
            min(1.0, velocity / 10.0),
        ]
        fp = BehaviorFingerprint(
            customer_id=cp.customer_id,
            return_rate=cp.return_rate,
            avg_days_to_return=avg_days,
            dominant_reason=dominant,
            avg_order_value=avg_ov,
            high_value_pct=high_val_pct,
            velocity_per_month=velocity,
        )
        fp._vector = vector
        return fp

    def build_all(
        self,
        profiles: List[CustomerProfile],
        history_map: Optional[Dict[str, List[ReturnRequest]]] = None,
    ) -> List[BehaviorFingerprint]:
        """Build fingerprints for multiple customers."""
        history_map = history_map or {}
        return [self.build(cp, history_map.get(cp.customer_id)) for cp in profiles]

    def similarity(self, a: BehaviorFingerprint, b: BehaviorFingerprint) -> FingerprintSimilarity:
        """Compute cosine similarity between two fingerprints."""
        import math
        va, vb = a._vector, b._vector
        if not va or not vb or len(va) != len(vb):
            return FingerprintSimilarity(a.customer_id, b.customer_id, 0.0, [])

        dot = sum(x * y for x, y in zip(va, vb))
        mag_a = math.sqrt(sum(x * x for x in va))
        mag_b = math.sqrt(sum(x * x for x in vb))
        sim = dot / (mag_a * mag_b) if (mag_a * mag_b) > 0 else 0.0

        shared: List[str] = []
        dims = ["return_rate", "timing", "reason", "order_value", "high_value", "velocity"]
        for i, (x, y) in enumerate(zip(va, vb)):
            if abs(x - y) < 0.1 and (x + y) > 0.1:
                shared.append(dims[i])

        return FingerprintSimilarity(a.customer_id, b.customer_id, round(sim, 4), shared)

    def find_similar_pairs(
        self,
        fingerprints: List[BehaviorFingerprint],
        threshold: float = 0.85,
    ) -> List[FingerprintSimilarity]:
        """
        Find all pairs of customers with similarity >= threshold.

        O(n²) — suitable for batches up to ~10,000 customers.
        """
        pairs: List[FingerprintSimilarity] = []
        for i in range(len(fingerprints)):
            for j in range(i + 1, len(fingerprints)):
                sim = self.similarity(fingerprints[i], fingerprints[j])
                if sim.similarity >= threshold:
                    pairs.append(sim)
        return sorted(pairs, key=lambda x: x.similarity, reverse=True)

    def to_markdown(self, pairs: List[FingerprintSimilarity]) -> str:
        """Render a Markdown table of similar customer pairs."""
        lines = [
            "# Behavioral Fingerprint Similarity Report",
            "",
            "| Customer A | Customer B | Similarity | Shared Signals |",
            "|------------|------------|------------|----------------|",
        ]
        for p in pairs:
            shared = ", ".join(p.shared_signals) if p.shared_signals else "—"
            lines.append(f"| {p.customer_a} | {p.customer_b} | {p.similarity:.1%} | {shared} |")
        if not pairs:
            lines.append("| _No similar pairs found_ | — | — | — |")
        return "\n".join(lines)
