"""Tests for returnguard — returns fraud detection."""
import asyncio
import pytest
from datetime import datetime, timedelta

from returnguard import (
    FraudScorer,
    ReturnRequest,
    ReturnReason,
    RiskLevel,
    FraudSignal,
    CustomerProfile,
    FraudCache,
    FraudPipeline,
    ReturnValidator,
    ReturnRule,
    RateLimiter,
    CancellationToken,
    batch_score,
    diff_scores,
    stream_scores,
    scores_to_ndjson,
    AuditLog,
    PIIScrubber,
    RiskTrend,
)


def make_request(
    return_id="R001",
    customer_id="C001",
    reason=ReturnReason.CHANGED_MIND,
    order_value=100.0,
    days_ago=5,
    channel="shopify",
) -> ReturnRequest:
    now = datetime.utcnow()
    return ReturnRequest(
        return_id=return_id,
        order_id=f"ORD-{return_id}",
        customer_id=customer_id,
        sku="SKU-TEST",
        quantity=1,
        reason=reason,
        order_date=now - timedelta(days=days_ago),
        order_value=order_value,
        channel=channel,
    )


# ─── Models ───────────────────────────────────────────────────────────────────

def test_return_request_days_since_purchase():
    req = make_request(days_ago=10)
    assert req.days_since_purchase == 10


def test_customer_profile_return_rate():
    profile = CustomerProfile(customer_id="C1", total_orders=10, total_returns=3)
    assert abs(profile.return_rate - 0.3) < 1e-6


def test_customer_profile_avg_fraud_score():
    profile = CustomerProfile(customer_id="C1", fraud_scores=[0.2, 0.8])
    assert abs(profile.avg_fraud_score - 0.5) < 1e-6


# ─── Scorer ───────────────────────────────────────────────────────────────────

def test_score_low_risk_normal_return():
    scorer = FraudScorer()
    req = make_request(reason=ReturnReason.DEFECTIVE, order_value=50.0, days_ago=2)
    result = scorer.score(req)
    assert result.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM)


def test_score_wardrobing_detected():
    scorer = FraudScorer(high_value_threshold=150.0)
    req = make_request(reason=ReturnReason.CHANGED_MIND, order_value=220.0, days_ago=3)
    result = scorer.score(req)
    assert FraudSignal.WARDROBING in result.signals
    assert result.score > 0.2


def test_score_high_return_rate():
    scorer = FraudScorer(return_rate_threshold=0.30)
    req = make_request()
    profile = CustomerProfile(customer_id="C001", total_orders=10, total_returns=5)
    result = scorer.score(req, profile=profile)
    assert FraudSignal.HIGH_RETURN_RATE in result.signals


def test_score_serial_returner():
    scorer = FraudScorer()
    req = make_request()
    profile = CustomerProfile(customer_id="C001", total_orders=20, total_returns=5, flagged_count=3)
    result = scorer.score(req, profile=profile)
    assert FraudSignal.SERIAL_RETURNER in result.signals


def test_score_policy_abuse():
    scorer = FraudScorer(max_days_since_purchase=30)
    req = make_request(days_ago=45)
    result = scorer.score(req)
    assert FraudSignal.POLICY_ABUSE in result.signals


def test_score_velocity():
    scorer = FraudScorer(velocity_limit=3)
    req = make_request()
    profile = CustomerProfile(customer_id="C001", total_orders=20, total_returns=5)
    result = scorer.score(req, profile=profile)
    assert FraudSignal.VELOCITY in result.signals


def test_score_clamped_at_one():
    scorer = FraudScorer(return_rate_threshold=0.01, high_value_threshold=1.0, velocity_limit=1, max_days_since_purchase=1)
    req = make_request(order_value=500.0, days_ago=90)
    profile = CustomerProfile(customer_id="C001", total_orders=2, total_returns=2, flagged_count=5)
    result = scorer.score(req, profile=profile)
    assert result.score <= 1.0


def test_batch_score():
    scorer = FraudScorer()
    requests = [make_request(return_id=f"R{i}") for i in range(5)]
    results = scorer.batch_score(requests)
    assert len(results) == 5


def test_recommended_action_low():
    scorer = FraudScorer()
    req = make_request(reason=ReturnReason.WRONG_ITEM, order_value=20.0, days_ago=1)
    result = scorer.score(req)
    assert "Auto-approve" in result.recommended_action or "review" in result.recommended_action.lower()


# ─── Cache ────────────────────────────────────────────────────────────────────

def test_cache_set_get():
    cache = FraudCache(max_size=10, ttl_seconds=60)
    cache.set("k1", "v1")
    assert cache.get("k1") == "v1"


def test_cache_stats():
    cache = FraudCache(max_size=10, ttl_seconds=60)
    cache.set("k", "v")
    cache.get("k")
    cache.get("missing")
    s = cache.stats()
    assert s["hits"] == 1
    assert s["misses"] == 1


def test_cache_memoize():
    cache = FraudCache(max_size=10, ttl_seconds=60)
    calls = [0]

    @cache.memoize
    def fn(x):
        calls[0] += 1
        return x + 1

    assert fn(5) == 6
    assert fn(5) == 6
    assert calls[0] == 1


# ─── Pipeline ─────────────────────────────────────────────────────────────────

def test_pipeline_filter():
    scorer = FraudScorer(high_value_threshold=50.0)
    requests = [make_request(return_id=f"R{i}", order_value=i * 100, days_ago=3) for i in range(5)]
    scores = scorer.batch_score(requests)
    pipeline = FraudPipeline().filter(lambda s: s.score > 0.0, name="nonzero")
    result = pipeline.run(scores)
    assert all(s.score > 0.0 for s in result)


def test_pipeline_audit_log():
    scorer = FraudScorer()
    scores = scorer.batch_score([make_request()])
    pipeline = FraudPipeline().filter(lambda s: True, name="pass_all")
    pipeline.run(scores)
    log = pipeline.audit_log()
    assert log[0]["ok"] is True


def test_pipeline_async():
    scorer = FraudScorer()
    scores = scorer.batch_score([make_request()])
    pipeline = FraudPipeline().filter(lambda s: True)
    result = asyncio.run(pipeline.arun(scores))
    assert len(result) == 1


# ─── Validator ────────────────────────────────────────────────────────────────

def test_validator_max_days():
    validator = ReturnValidator()
    validator.add_rule(ReturnRule(field="days", rule_type="max_days", value=30))
    req = make_request(days_ago=40)
    ok, errors = validator.validate(req)
    assert not ok


def test_validator_passes():
    validator = ReturnValidator()
    validator.add_rule(ReturnRule(field="days", rule_type="max_days", value=60))
    req = make_request(days_ago=5)
    ok, errors = validator.validate(req)
    assert ok


# ─── Batch ────────────────────────────────────────────────────────────────────

def test_batch_score_concurrent():
    scorer = FraudScorer()
    requests = [make_request(return_id=f"R{i}") for i in range(10)]
    results = batch_score(requests, scorer.score, max_workers=4)
    assert len(results) == 10


def test_cancellation_token():
    token = CancellationToken()
    assert not token.is_cancelled
    token.cancel()
    assert token.is_cancelled


# ─── Diff ─────────────────────────────────────────────────────────────────────

def test_diff_scores():
    scorer = FraudScorer()
    a = scorer.batch_score([make_request(return_id="R1"), make_request(return_id="R2")])
    b = scorer.batch_score([make_request(return_id="R1"), make_request(return_id="R3")])
    diff = diff_scores(a, b)
    assert "R3" in diff.added
    assert "R2" in diff.removed


# ─── Streaming ────────────────────────────────────────────────────────────────

def test_stream_scores():
    scorer = FraudScorer()
    scores = scorer.batch_score([make_request(return_id=f"R{i}") for i in range(5)])
    result = list(stream_scores(scores))
    assert len(result) == 5


def test_scores_to_ndjson():
    scorer = FraudScorer()
    scores = scorer.batch_score([make_request()])
    lines = list(scores_to_ndjson(scores))
    assert len(lines) == 1
    assert lines[0].endswith("\n")


# ─── Risk Trend ───────────────────────────────────────────────────────────────

def test_risk_trend_increasing():
    trend = RiskTrend(window=6)
    for v in [0.1, 0.2, 0.3, 0.5, 0.7, 0.9]:
        trend.record(v)
    assert trend.trend() == "increasing"


def test_risk_trend_stable():
    trend = RiskTrend(window=6)
    for v in [0.5, 0.5, 0.5, 0.5, 0.5, 0.5]:
        trend.record(v)
    assert trend.trend() == "stable"


def test_risk_trend_volatility():
    trend = RiskTrend(window=4)
    for v in [0.1, 0.9, 0.1, 0.9]:
        trend.record(v)
    assert trend.volatility() > 0.3


# ─── Audit & PII ──────────────────────────────────────────────────────────────

def test_audit_log():
    log = AuditLog()
    log.record("scored", "R001", detail="risk=medium")
    entries = log.export()
    assert len(entries) == 1
    assert entries[0]["return_id"] == "R001"


def test_pii_scrubber():
    result = PIIScrubber.scrub("SSN: 123-45-6789 email: a@b.com phone: 555-123-4567")
    assert "[SSN]" in result
    assert "[EMAIL]" in result
    assert "[PHONE]" in result
