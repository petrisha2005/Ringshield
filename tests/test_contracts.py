"""Unit tests for RingShield transaction contracts and schema validation."""

import pytest
from contracts.schemas import validate_transaction


def test_valid_transaction():
    tx = {
        "transaction_id": "tx_valid_001",
        "sender_id": "alice@okhdfcbank",
        "receiver_id": "bob@okaxis",
        "amount": 2500.50,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    # Should not raise any exception
    validate_transaction(tx)


def test_transaction_must_be_dict():
    with pytest.raises(ValueError, match="Transaction must be a dictionary"):
        validate_transaction("not a dict")  # type: ignore

    with pytest.raises(ValueError, match="Transaction must be a dictionary"):
        validate_transaction([1, 2, 3])  # type: ignore


@pytest.mark.parametrize(
    "missing_field",
    ["transaction_id", "sender_id", "receiver_id", "amount", "timestamp"],
)
def test_missing_required_fields(missing_field):
    base_tx = {
        "transaction_id": "tx_001",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": 100.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    del base_tx[missing_field]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_transaction(base_tx)


def test_same_sender_and_receiver():
    tx = {
        "transaction_id": "tx_002",
        "sender_id": "user_a@upi",
        "receiver_id": "user_a@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    with pytest.raises(ValueError, match="Sender and receiver must be different"):
        validate_transaction(tx)


@pytest.mark.parametrize("invalid_amount", [0, -1, -500.25])
def test_non_positive_amount(invalid_amount):
    tx = {
        "transaction_id": "tx_003",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": invalid_amount,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    with pytest.raises(ValueError, match="amount must be greater than zero"):
        validate_transaction(tx)


def test_boolean_amount_rejected():
    tx = {
        "transaction_id": "tx_004",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": True,  # booleans are subclasses of int in Python
        "timestamp": "2026-10-23T10:00:00Z",
    }
    with pytest.raises(ValueError, match="amount must be a number"):
        validate_transaction(tx)


@pytest.mark.parametrize("string_amount", ["1000", "50.5", "ten"])
def test_string_amount_rejected(string_amount):
    tx = {
        "transaction_id": "tx_005",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": string_amount,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    with pytest.raises(ValueError, match="amount must be a number"):
        validate_transaction(tx)


def test_invalid_types_for_string_fields():
    # transaction_id not string
    with pytest.raises(ValueError, match="transaction_id must be a string"):
        validate_transaction({
            "transaction_id": 12345,
            "sender_id": "user_a@upi",
            "receiver_id": "user_b@upi",
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    # sender_id not string
    with pytest.raises(ValueError, match="sender_id must be a string"):
        validate_transaction({
            "transaction_id": "tx_006",
            "sender_id": 999,
            "receiver_id": "user_b@upi",
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    # receiver_id not string
    with pytest.raises(ValueError, match="receiver_id must be a string"):
        validate_transaction({
            "transaction_id": "tx_007",
            "sender_id": "user_a@upi",
            "receiver_id": None,
            "amount": 100.0,
            "timestamp": "2026-10-23T10:00:00Z",
        })

    # timestamp not string
    with pytest.raises(ValueError, match="timestamp must be a string"):
        validate_transaction({
            "transaction_id": "tx_008",
            "sender_id": "user_a@upi",
            "receiver_id": "user_b@upi",
            "amount": 100.0,
            "timestamp": 1729680000,
        })
