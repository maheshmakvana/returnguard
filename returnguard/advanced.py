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
