"""Unit tests for RingShield FraudDetectionEngine and alert generation."""

from datetime import datetime, timezone
import pytest
from detection.engine import FraudDetectionEngine


def test_normal_transaction_not_suspicious():
    engine = FraudDetectionEngine(high_value_threshold=100_000)
    tx = {
        "transaction_id": "tx_normal_01",
        "sender_id": "user_alice@upi",
        "receiver_id": "merchant_grocery@upi",
        "amount": 450.0,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    alert = engine.evaluate(tx)

    assert alert["transaction_id"] == "tx_normal_01"
    assert alert["is_suspicious"] is False
    assert alert["risk_reasons"] == []
    assert alert["amount"] == 450.0
    assert alert["sender_id"] == "user_alice@upi"
    assert alert["receiver_id"] == "merchant_grocery@upi"
    assert alert["timestamp"] == "2026-10-23T10:00:00Z"


def test_high_value_transaction_detection():
    engine = FraudDetectionEngine(high_value_threshold=100_000)

    # Sub-threshold
    sub_tx = {
        "transaction_id": "tx_sub",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": 99_999.99,
        "timestamp": "2026-10-23T10:00:00Z",
    }
    assert engine.evaluate(sub_tx)["is_suspicious"] is False

    # Exact threshold
    exact_tx = {
        "transaction_id": "tx_exact",
        "sender_id": "user_a@upi",
        "receiver_id": "user_b@upi",
        "amount": 100_000.0,
        "timestamp": "2026-10-23T10:00:05Z",
    }
    res_exact = engine.evaluate(exact_tx)
    assert res_exact["is_suspicious"] is True
    assert "HIGH_VALUE_TRANSACTION" in res_exact["risk_reasons"]

    # Well above threshold
    high_tx = {
        "transaction_id": "tx_high",
        "sender_id": "user_c@upi",
        "receiver_id": "user_d@upi",
        "amount": 500_000.0,
        "timestamp": "2026-10-23T10:00:10Z",
    }
    res_high = engine.evaluate(high_tx)
    assert res_high["is_suspicious"] is True
    assert "HIGH_VALUE_TRANSACTION" in res_high["risk_reasons"]


def test_rapid_repeated_transfers_detection():
    engine = FraudDetectionEngine(
        high_value_threshold=100_000,
        rapid_window_seconds=60,
        rapid_transfer_limit=5,
    )

    sender = "rapid_sender@upi"
    base_time = "2026-10-23T12:00:"

    # 4 transactions in 20 seconds - should not trigger yet
    for i in range(1, 5):
        tx = {
            "transaction_id": f"tx_rapid_{i}",
            "sender_id": sender,
            "receiver_id": f"receiver_{i}@upi",
            "amount": 1000.0,
            "timestamp": f"{base_time}{i*5:02d}Z",
        }
        res = engine.evaluate(tx)
        assert res["is_suspicious"] is False, f"Transaction {i} shouldn't trigger"

    # 5th transaction within 60s - should trigger RAPID_REPEATED_TRANSFERS
    tx_5 = {
        "transaction_id": "tx_rapid_5",
        "sender_id": sender,
        "receiver_id": "receiver_5@upi",
        "amount": 1000.0,
        "timestamp": f"{base_time}25Z",
    }
    res_5 = engine.evaluate(tx_5)
    assert res_5["is_suspicious"] is True
    assert "RAPID_REPEATED_TRANSFERS" in res_5["risk_reasons"]


def test_rapid_transfer_window_pruning():
    engine = FraudDetectionEngine(
        high_value_threshold=100_000,
        rapid_window_seconds=60,
        rapid_transfer_limit=5,
    )
    sender = "slow_sender@upi"

    # Send 4 transactions at minute 10
    for i in range(1, 5):
        tx = {
            "transaction_id": f"tx_slow_{i}",
            "sender_id": sender,
            "receiver_id": f"receiver_{i}@upi",
            "amount": 500.0,
            "timestamp": f"2026-10-23T12:10:{i*5:02d}Z",
        }
        engine.evaluate(tx)

    # 5th transaction happens at minute 15 (5 minutes later > 60 seconds)
    tx_late = {
        "transaction_id": "tx_slow_5",
        "sender_id": sender,
        "receiver_id": "receiver_5@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T12:15:00Z",
    }
    res_late = engine.evaluate(tx_late)
    # The older 4 transactions should have been pruned from the sliding window
    assert res_late["is_suspicious"] is False
    assert "RAPID_REPEATED_TRANSFERS" not in res_late["risk_reasons"]


def test_combined_high_value_and_rapid_transfers():
    engine = FraudDetectionEngine(
        high_value_threshold=100_000,
        rapid_window_seconds=60,
        rapid_transfer_limit=3,
    )
    sender = "multi_threat@upi"

    # First 2 small transactions
    for i in range(1, 3):
        engine.evaluate({
            "transaction_id": f"tx_multi_{i}",
            "sender_id": sender,
            "receiver_id": "receiver@upi",
            "amount": 100.0,
            "timestamp": f"2026-10-23T14:00:{i:02d}Z",
        })

    # 3rd transaction is both >= 100_000 and the 3rd transfer within 60s
    tx_combo = {
        "transaction_id": "tx_multi_combo",
        "sender_id": sender,
        "receiver_id": "receiver@upi",
        "amount": 250_000.0,
        "timestamp": "2026-10-23T14:00:05Z",
    }
    res = engine.evaluate(tx_combo)
    assert res["is_suspicious"] is True
    assert set(res["risk_reasons"]) == {"HIGH_VALUE_TRANSACTION", "RAPID_REPEATED_TRANSFERS"}


def test_senders_tracked_independently():
    engine = FraudDetectionEngine(
        high_value_threshold=100_000,
        rapid_window_seconds=60,
        rapid_transfer_limit=3,
    )

    # Sender 1 sends 2 transactions
    for i in range(2):
        engine.evaluate({
            "transaction_id": f"s1_tx_{i}",
            "sender_id": "sender_1@upi",
            "receiver_id": "merchant@upi",
            "amount": 50.0,
            "timestamp": "2026-10-23T15:00:00Z",
        })

    # Sender 2 sends 1 transaction (should not be affected by Sender 1)
    res_s2 = engine.evaluate({
        "transaction_id": "s2_tx_0",
        "sender_id": "sender_2@upi",
        "receiver_id": "merchant@upi",
        "amount": 50.0,
        "timestamp": "2026-10-23T15:00:01Z",
    })
    assert res_s2["is_suspicious"] is False


def test_alert_schema_structure():
    engine = FraudDetectionEngine(high_value_threshold=50_000)
    tx = {
        "transaction_id": "tx_schema_check",
        "sender_id": "user_x@upi",
        "receiver_id": "user_y@upi",
        "amount": 75_000.0,
        "timestamp": "2026-10-23T16:00:00Z",
    }
    alert = engine.evaluate(tx)

    expected_keys = {
        "transaction_id",
        "is_suspicious",
        "risk_reasons",
        "amount",
        "sender_id",
        "receiver_id",
        "timestamp",
    }
    assert expected_keys.issubset(alert.keys())
    assert isinstance(alert["risk_reasons"], list)
    assert isinstance(alert["is_suspicious"], bool)
