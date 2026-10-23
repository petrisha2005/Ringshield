"""Shared data schemas for RingShield transactions."""

from typing import Any


REQUIRED_TRANSACTION_FIELDS = {
    "transaction_id",
    "sender_id",
    "receiver_id",
    "amount",
    "timestamp",
}


def validate_transaction(transaction: dict[str, Any]) -> None:
    """Validate the basic fields of a UPI transaction."""
    if not isinstance(transaction, dict):
        raise ValueError("Transaction must be a dictionary")

    missing = REQUIRED_TRANSACTION_FIELDS - transaction.keys()
    if missing:
        raise ValueError(
            f"Transaction is missing required fields: {sorted(missing)}"
        )

    if not isinstance(transaction["transaction_id"], str):
        raise ValueError("transaction_id must be a string")

    if not isinstance(transaction["sender_id"], str):
        raise ValueError("sender_id must be a string")

    if not isinstance(transaction["receiver_id"], str):
        raise ValueError("receiver_id must be a string")

    if transaction["sender_id"] == transaction["receiver_id"]:
        raise ValueError("Sender and receiver must be different")

    if isinstance(transaction["amount"], bool) or not isinstance(
        transaction["amount"], (int, float)
    ):
        raise ValueError("amount must be a number")

    if transaction["amount"] <= 0:
        raise ValueError("amount must be greater than zero")

    if not isinstance(transaction["timestamp"], str):
        raise ValueError("timestamp must be a string")