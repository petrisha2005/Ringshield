"""Explainable, rule-based fraud detection for RingShield."""

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from contracts.schemas import validate_transaction


class FraudDetectionEngine:
    """Detect suspicious high-value and rapid repeated transfers."""

    def __init__(
        self,
        high_value_threshold: float = 100_000,
        rapid_window_seconds: int = 60,
        rapid_transfer_limit: int = 5,
    ) -> None:
        self.high_value_threshold = high_value_threshold
        self.rapid_window_seconds = rapid_window_seconds
        self.rapid_transfer_limit = rapid_transfer_limit
        self.sender_history: dict[str, deque[datetime]] = defaultdict(deque)

    def evaluate(self, transaction: dict[str, Any]) -> dict[str, Any]:
        """Return a structured decision for one transaction."""
        validate_transaction(transaction)

        timestamp = datetime.fromisoformat(
            transaction["timestamp"].replace("Z", "+00:00")
        )

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        sender = transaction["sender_id"]
        history = self.sender_history[sender]

        while history and (
            timestamp - history[0]
        ).total_seconds() > self.rapid_window_seconds:
            history.popleft()

        history.append(timestamp)

        reasons = []

        if transaction["amount"] >= self.high_value_threshold:
            reasons.append("HIGH_VALUE_TRANSACTION")

        if len(history) >= self.rapid_transfer_limit:
            reasons.append("RAPID_REPEATED_TRANSFERS")

        return {
            "transaction_id": transaction["transaction_id"],
            "is_suspicious": bool(reasons),
            "risk_reasons": reasons,
            "amount": transaction["amount"],
            "sender_id": sender,
            "receiver_id": transaction["receiver_id"],
            "timestamp": transaction["timestamp"],
        }