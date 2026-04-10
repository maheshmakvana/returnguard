"""Data models for returnguard — returns fraud detection."""
from __future__ import annotations

import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


class ReturnReason(str, Enum):
    DEFECTIVE = "defective"
    NOT_AS_DESCRIBED = "not_as_described"
    CHANGED_MIND = "changed_mind"
    WRONG_ITEM = "wrong_item"
    DAMAGED_IN_SHIPPING = "damaged_in_shipping"
    OTHER = "other"


class FraudSignal(str, Enum):
    HIGH_RETURN_RATE = "high_return_rate"
    WARDROBING = "wardrobing"
    EMPTY_BOX = "empty_box"
    POLICY_ABUSE = "policy_abuse"
    COUPON_STACKING = "coupon_stacking"
    ACCOUNT_AGE = "account_age"
    VELOCITY = "velocity"
    ADDRESS_MISMATCH = "address_mismatch"
    REFUND_ONLY = "refund_only"
    SERIAL_RETURNER = "serial_returner"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReturnRequest(BaseModel):
    """A single return request submitted by a customer."""

    return_id: str
    order_id: str
    customer_id: str
    sku: str
    quantity: int = Field(ge=1)
    reason: ReturnReason
    order_date: datetime
    return_date: datetime = Field(default_factory=datetime.utcnow)
    order_value: float = Field(ge=0)
    channel: str = "unknown"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("return_id", "order_id", "customer_id")
    @classmethod
    def ids_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("ID fields must not be empty")
        return v.strip()

    @property
    def days_since_purchase(self) -> int:
        delta = self.return_date - self.order_date
        return max(0, delta.days)


class FraudScore(BaseModel):
    """Fraud assessment result for a return request."""

    return_id: str
    customer_id: str
    score: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel
    signals: List[FraudSignal] = Field(default_factory=list)
    explanation: str = ""
    recommended_action: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CustomerProfile(BaseModel):
    """Aggregated return history for a customer."""

    customer_id: str
    total_orders: int = 0
    total_returns: int = 0
    total_return_value: float = 0.0
    flagged_count: int = 0
    last_return_date: Optional[datetime] = None
    return_reasons: Dict[str, int] = Field(default_factory=dict)
    fraud_scores: List[float] = Field(default_factory=list)

    @property
    def return_rate(self) -> float:
        if self.total_orders == 0:
            return 0.0
        return self.total_returns / self.total_orders

    @property
    def avg_fraud_score(self) -> float:
        if not self.fraud_scores:
            return 0.0
        return sum(self.fraud_scores) / len(self.fraud_scores)
