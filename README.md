# returnguard

**AI-powered returns fraud detection for retail and eCommerce** — score return requests, detect wardrobing, serial returners, bot patterns, and policy abuse. No $50K enterprise contract required.

[![PyPI version](https://badge.fury.io/py/returnguard.svg)](https://pypi.org/project/returnguard/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)

## The Problem

Returns fraud costs US retailers $101B/year. AI-generated fraud has "exploded overnight." Enterprise solutions (Happy Returns, Narvar) target only large retail — Shopify has **zero** built-in fraud scoring. Mid-market merchants are on their own.

## Installation

```bash
pip install returnguard
```

## Quick Start

```python
from returnguard import FraudScorer, ReturnRequest, ReturnReason
from datetime import datetime, timedelta

scorer = FraudScorer(
    return_rate_threshold=0.30,
    high_value_threshold=150.0,
    velocity_limit=3,
)

request = ReturnRequest(
    return_id="RET-001",
    order_id="ORD-5521",
    customer_id="CUST-42",
    sku="SKU-JACKET-XL",
    quantity=1,
    reason=ReturnReason.CHANGED_MIND,
    order_date=datetime.utcnow() - timedelta(days=3),
    order_value=220.00,
    channel="shopify",
)

result = scorer.score(request)
print(result.risk_level)        # RiskLevel.HIGH
print(result.score)             # 0.6
print(result.signals)           # [FraudSignal.WARDROBING]
print(result.recommended_action)  # "Require photo evidence + manual review"
```

## Fraud Signals Detected

| Signal | Description |
|---|---|
| `HIGH_RETURN_RATE` | Customer's return rate exceeds threshold |
| `WARDROBING` | Use-and-return: changed_mind + < 7 days + high-value item |
| `VELOCITY` | Too many returns in a short window |
| `SERIAL_RETURNER` | Customer has been flagged multiple times |
| `POLICY_ABUSE` | Return submitted after policy window |

## Customer Profile Tracking

```python
from returnguard import CustomerProfile

profile = CustomerProfile(
    customer_id="CUST-42",
    total_orders=20,
    total_returns=8,
    flagged_count=2,
)

result = scorer.score(request, profile=profile)
# Score accounts for historical return behaviour
```

## Risk Levels & Actions

| Risk Level | Score | Recommended Action |
|---|---|---|
| LOW | 0.0–0.30 | Auto-approve |
| MEDIUM | 0.30–0.55 | Flag for manual review |
| HIGH | 0.55–0.75 | Require photo evidence |
| CRITICAL | 0.75–1.0 | Block + escalate to fraud team |

## Batch Scoring

```python
from returnguard import batch_score, abatch_score

# Sync
scores = batch_score(requests, scorer.score, max_workers=8)

# Async
scores = await abatch_score(requests, scorer.score, max_concurrency=8)
```

## Advanced Features

### Pipeline

```python
from returnguard import FraudPipeline

pipeline = (
    FraudPipeline()
    .filter(lambda s: s.score > 0.5, name="high_risk_only")
    .map(lambda scores: sorted(scores, key=lambda s: -s.score), name="sort_by_risk")
    .with_retry(count=2)
)

high_risk = pipeline.run(all_scores)
print(pipeline.audit_log())
```

### Caching

```python
from returnguard import FraudCache

cache = FraudCache(max_size=1000, ttl_seconds=600)

@cache.memoize
def score_with_cache(request):
    return scorer.score(request)

print(cache.stats())
```

### Validation

```python
from returnguard import ReturnValidator, ReturnRule

validator = ReturnValidator()
validator.add_rule(ReturnRule("max_days", 60, "Return window expired"))
validator.add_rule(ReturnRule("max_order_value", 1000, "High-value item requires manual review"))

valid, errors = validator.validate(request)
```

### Diff & Trend

```python
from returnguard import diff_scores, RiskTrend

diff = diff_scores(previous_scores, current_scores)
print(diff.summary())  # {'added': 3, 'removed': 1, 'modified': 2}

trend = RiskTrend(window=20)
for score in historical_scores:
    trend.record(score.score)
print(trend.trend())       # "increasing"
print(trend.volatility())  # 0.12
```

### Streaming & NDJSON

```python
from returnguard import stream_scores, scores_to_ndjson

for score in stream_scores(results):
    process(score)

for line in scores_to_ndjson(results):
    file.write(line)
```

### Audit Log

```python
from returnguard import AuditLog

log = AuditLog()
log.record("scored", "RET-001", detail="risk=high")
log.record("blocked", "RET-001")
entries = log.export()
```

## Changelog

### v1.2.2 (2026-04-10)
- Added Contributing and Author sections to README

### v1.2.1 (2026-04-10)
- Fixed type error in `SimulationResult.to_dict()` — `max()` key now uses explicit lambda for reliable `SupportsRichComparison` resolution
- Fixed Pylance `reportMissingImports` on optional `opentelemetry` imports in `ReturnSpanEmitter` — guarded with `# type: ignore[import-untyped]` (runtime behaviour unchanged; opentelemetry remains optional)

### v1.2.0 (2026-03-xx)
- Added `RefundAnomalyDetector` — statistical anomaly detection on refund amounts
- Added `BehaviorFingerprinter` — fingerprint customer return behaviour patterns
- Expanded SEO keywords for PyPI discoverability

### v1.0.1
- Advanced features update: pipeline, caching, validation, diff/trend, streaming, audit log

### v1.0.0
- Initial release: core fraud scoring, wardrobing, serial returner, velocity, policy abuse detection

## License

MIT

## Contributing

Contributions are welcome! Here's how to get started:

1. Fork the repository on [GitHub](https://github.com/maheshmakvana/returnguard)
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes and add tests
4. Run the test suite: `pytest tests/ -v`
5. Submit a pull request

Please open an issue first for major changes to discuss the approach.

## Author

**Mahesh Makvana** — [GitHub](https://github.com/maheshmakvana) · [PyPI](https://pypi.org/user/maheshmakvana/)

MIT License
