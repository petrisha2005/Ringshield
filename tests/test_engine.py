"""
tests/test_engine.py
Comprehensive test suite for RingShield FraudDetectionEngine (Task 3).

Validates:
1. All five fraud detection topologies: FAN_IN, FAN_OUT, CIRCULAR_FLOW,
   RAPID_PASSTHROUGH, and SHARED_DEVICE.
2. Normal transactions and false-positive-oriented scenarios.
3. Repeated counterparties between the same accounts (no false fan-in/fan-out).
4. Cycle window boundaries, expired hops, and exact transaction-edge evidence.
5. Unknown/missing device identifiers ignored with conservative score cap.
6. Exact time-window boundaries (inclusive at t-W, excluded at t-W-0.01).
7. Duplicate transaction IDs handled idempotently without duplicate alerts.
8. Empty input, single transaction, and reset behavior.
9. Single-use inflow allocation, partial allocation, and insufficient balance.
10. Deterministic alert IDs, stable sorting, and Alert contract compliance.
11. JSON serialization with allow_nan=False.
12. Pre-mutation state integrity: rejected transactions leave all state unchanged.
13. Chronological nondecreasing timestamp policy.
14. Canonical directed cycle deduplication without conflating reversed cycles.
"""

import json
import math
import pytest

from contracts.schemas import Alert, Transaction, VALID_SEVERITIES, validate_alert
from detection.engine import FraudDetectionEngine, _canonical_cycle


# =====================================================================
# 1. Engine Configuration Tests
# =====================================================================

class TestEngineConfiguration:
    """Validates constructor argument parsing and strict validation."""

    def test_default_initialization(self):
        engine = FraudDetectionEngine()
        assert engine.fan_in_threshold == 4
        assert engine.fan_out_threshold == 4
        assert engine.cycle_max_length == 5
        assert engine.passthrough_min_ratio == 0.85
        assert engine.shared_device_threshold == 3

    def test_custom_valid_configuration(self):
        engine = FraudDetectionEngine(
            max_window_seconds=1800.0,
            fan_in_threshold=5,
            fan_in_window_seconds=600.0,
            fan_out_threshold=3,
            fan_out_window_seconds=200.0,
            cycle_max_length=4,
            cycle_window_seconds=900.0,
            passthrough_max_delay_seconds=60.0,
            passthrough_min_ratio=0.90,
            shared_device_threshold=2,
        )
        assert engine.fan_in_threshold == 5
        assert engine.cycle_max_length == 4
        assert engine.passthrough_min_ratio == 0.90

    @pytest.mark.parametrize("param,invalid_val", [
        ("max_window_seconds", 0.0),
        ("max_window_seconds", -10.0),
        ("max_window_seconds", float("nan")),
        ("max_window_seconds", float("inf")),
        ("fan_in_threshold", 1),
        ("fan_in_threshold", True),
        ("fan_in_threshold", "4"),
        ("fan_out_threshold", 0),
        ("fan_out_threshold", False),
        ("cycle_max_length", 2),
        ("cycle_max_length", 0),
        ("passthrough_min_ratio", 0.0),
        ("passthrough_min_ratio", -0.5),
        ("passthrough_min_ratio", 1.05),
        ("passthrough_max_delay_seconds", -1.0),
        ("shared_device_threshold", 1),
    ])
    def test_invalid_configuration_raises_value_error(self, param, invalid_val):
        kwargs = {param: invalid_val}
        with pytest.raises(ValueError):
            FraudDetectionEngine(**kwargs)


# =====================================================================
# 2. Input Validation and Pre-Mutation State Integrity
# =====================================================================

class TestInputValidationAndStateIntegrity:
    """Ensures rejected transactions do not mutate any internal engine state."""

    def test_invalid_transaction_rejected_before_state_mutation(self):
        engine = FraudDetectionEngine()

        # Valid baseline transaction
        valid_txn = Transaction(
            transaction_id="TXN_001",
            timestamp=100.0,
            sender_upi="alice@okaxis",
            receiver_upi="bob@okhdfc",
            amount=500.0,
        )
        engine.process_transaction(valid_txn)

        summary_before = engine.get_graph_summary()
        seen_before = set(engine._seen_transaction_ids)
        watermark_before = engine._watermark

        # Attempt invalid transaction: identical sender and receiver
        with pytest.raises(ValueError, match="identical"):
            engine.process_transaction({
                "transaction_id": "TXN_BAD_01",
                "timestamp": 110.0,
                "sender_upi": "charlie@okaxis",
                "receiver_upi": "charlie@okaxis",
                "amount": 200.0,
            })

        # Attempt invalid transaction: non-finite amount
        with pytest.raises(ValueError, match="finite"):
            engine.process_transaction({
                "transaction_id": "TXN_BAD_02",
                "timestamp": 120.0,
                "sender_upi": "charlie@okaxis",
                "receiver_upi": "david@okhdfc",
                "amount": float("nan"),
            })

        # Attempt invalid transaction: negative amount
        with pytest.raises(ValueError, match="strictly positive"):
            engine.process_transaction({
                "transaction_id": "TXN_BAD_03",
                "timestamp": 130.0,
                "sender_upi": "charlie@okaxis",
                "receiver_upi": "david@okhdfc",
                "amount": -50.0,
            })

        # Attempt invalid type
        with pytest.raises(TypeError):
            engine.process_transaction(["not", "a", "transaction"])

        # Attempt data leakage (ground-truth labels in transaction)
        with pytest.raises(ValueError, match="Data leakage"):
            engine.process_transaction({
                "transaction_id": "TXN_LEAK_01",
                "timestamp": 140.0,
                "sender_upi": "charlie@okaxis",
                "receiver_upi": "david@okhdfc",
                "amount": 100.0,
                "is_fraud": True,
            })

        # Verify state is completely unchanged
        assert engine.get_graph_summary() == summary_before
        assert engine._seen_transaction_ids == seen_before
        assert engine._watermark == watermark_before

    def test_out_of_order_timestamp_rejected_before_state_mutation(self):
        engine = FraudDetectionEngine()
        engine.process_transaction(Transaction(
            transaction_id="TXN_001",
            timestamp=200.0,
            sender_upi="alice@okaxis",
            receiver_upi="bob@okhdfc",
            amount=100.0,
        ))

        summary_before = engine.get_graph_summary()

        # Earlier timestamp than watermark (200.0)
        with pytest.raises(ValueError, match="Out-of-order transaction timestamp"):
            engine.process_transaction(Transaction(
                transaction_id="TXN_002",
                timestamp=199.5,
                sender_upi="bob@okhdfc",
                receiver_upi="charlie@okaxis",
                amount=100.0,
            ))

        # Internal state remains strictly identical
        assert engine.get_graph_summary() == summary_before
        assert "TXN_002" not in engine._seen_transaction_ids


# =====================================================================
# 3. Idempotency, Single Transaction, and Empty State Tests
# =====================================================================

class TestIdempotencyAndBaseline:
    """Validates duplicate handling, empty state, and single-transaction execution."""

    def test_empty_engine_summary(self):
        engine = FraudDetectionEngine()
        summary = engine.get_graph_summary()
        assert summary["node_count"] == 0
        assert summary["edge_count"] == 0
        assert summary["processed_transaction_count"] == 0
        assert summary["alert_count"] == 0
        assert summary["watermark"] == 0.0

    def test_single_normal_transaction(self):
        engine = FraudDetectionEngine()
        txn = Transaction(
            transaction_id="TXN_SINGLE_01",
            timestamp=50.0,
            sender_upi="user_a@okaxis",
            receiver_upi="user_b@okicici",
            amount=1200.0,
        )
        alerts = engine.process_transaction(txn)
        assert alerts == []
        summary = engine.get_graph_summary()
        assert summary["node_count"] == 2
        assert summary["edge_count"] == 1
        assert summary["watermark"] == 50.0

    def test_duplicate_transaction_is_idempotent(self):
        engine = FraudDetectionEngine(fan_in_threshold=2, fan_in_window_seconds=100.0)
        txn1 = Transaction("TXN_01", 10.0, "a@bank", "target@bank", 500.0)
        txn2 = Transaction("TXN_02", 20.0, "b@bank", "target@bank", 500.0)

        alerts1 = engine.process_transaction(txn1)
        assert alerts1 == []

        alerts2 = engine.process_transaction(txn2)
        assert len(alerts2) == 1
        assert alerts2[0].pattern_type == "FAN_IN"

        # Replay txn2 (exact duplicate ID)
        replay_alerts = engine.process_transaction(txn2)
        assert replay_alerts == []

        # Graph node/edge count should NOT have increased
        summary = engine.get_graph_summary()
        assert summary["edge_count"] == 2
        assert summary["processed_transaction_count"] == 2
        assert summary["alert_count"] == 1


# =====================================================================
# 4. FAN_IN Detection & Counterparty Boundary Tests
# =====================================================================

class TestFanInDetection:
    """Validates distinct counterparty aggregation, time window boundary, and deduplication."""

    def test_fan_in_triggers_on_threshold_distinct_counterparties(self):
        engine = FraudDetectionEngine(fan_in_threshold=4, fan_in_window_seconds=300.0)
        target = "aggregator@okaxis"

        senders = ["sender_1@okhdfc", "sender_2@okicici", "sender_3@oksbi", "sender_4@okaxis"]
        alerts = []
        for i, s in enumerate(senders):
            res = engine.process_transaction(Transaction(
                transaction_id=f"TXN_IN_{i+1}",
                timestamp=100.0 + i * 20.0,
                sender_upi=s,
                receiver_upi=target,
                amount=2500.0,
            ))
            alerts.extend(res)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.pattern_type == "FAN_IN"
        assert alert.suspicious_accounts == [target]
        assert alert.evidence["distinct_counterparties"] == 4
        assert alert.evidence["aggregator_account"] == target
        assert alert.recommended_action == "review"
        assert alert.severity in VALID_SEVERITIES
        validate_alert(alert.to_dict())

    def test_repeated_counterparties_do_not_trigger_fan_in(self):
        engine = FraudDetectionEngine(fan_in_threshold=4, fan_in_window_seconds=300.0)
        target = "merchant@okaxis"
        single_sender = "customer@okhdfc"

        # 10 transactions between the exact same pair
        alerts = []
        for i in range(10):
            res = engine.process_transaction(Transaction(
                transaction_id=f"TXN_REP_{i+1}",
                timestamp=100.0 + i * 10.0,
                sender_upi=single_sender,
                receiver_upi=target,
                amount=100.0,
            ))
            alerts.extend(res)

        assert len(alerts) == 0

    def test_fan_in_exact_window_boundary(self):
        # Window = 100.0s, threshold = 2
        engine = FraudDetectionEngine(fan_in_threshold=2, fan_in_window_seconds=100.0)
        target = "mule@okaxis"

        # Transaction 1 at t=100.0
        engine.process_transaction(Transaction("T1", 100.0, "s1@bank", target, 500.0))

        # Transaction 2 exactly at boundary t = 100.0 + 100.0 = 200.0 (included)
        boundary_alerts = engine.process_transaction(Transaction("T2", 200.0, "s2@bank", target, 500.0))
        assert len(boundary_alerts) == 1
        assert boundary_alerts[0].pattern_type == "FAN_IN"

    def test_fan_in_expired_outside_window_boundary(self):
        # Window = 100.0s, threshold = 2
        engine = FraudDetectionEngine(fan_in_threshold=2, fan_in_window_seconds=100.0)
        target = "mule@okaxis"

        # Transaction 1 at t=100.0
        engine.process_transaction(Transaction("T1", 100.0, "s1@bank", target, 500.0))

        # Transaction 2 strictly past boundary t = 200.01 (t-W-0.01 excluded)
        expired_alerts = engine.process_transaction(Transaction("T2", 200.01, "s2@bank", target, 500.0))
        assert len(expired_alerts) == 0


# =====================================================================
# 5. FAN_OUT Detection Tests
# =====================================================================

class TestFanOutDetection:
    """Validates distinct counterparty dispersion, deduplication, and repeated senders."""

    def test_fan_out_triggers_on_threshold_distinct_receivers(self):
        engine = FraudDetectionEngine(fan_out_threshold=3, fan_out_window_seconds=250.0)
        disperser = "disperser_mule@okaxis"

        receivers = ["cashout_1@okicici", "cashout_2@oksbi", "cashout_3@okhdfc"]
        alerts = []
        for i, r in enumerate(receivers):
            res = engine.process_transaction(Transaction(
                transaction_id=f"TXN_OUT_{i+1}",
                timestamp=500.0 + i * 30.0,
                sender_upi=disperser,
                receiver_upi=r,
                amount=10000.0,
            ))
            alerts.extend(res)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.pattern_type == "FAN_OUT"
        assert alert.suspicious_accounts == [disperser]
        assert alert.evidence["distinct_counterparties"] == 3
        validate_alert(alert.to_dict())

    def test_repeated_receivers_do_not_trigger_fan_out(self):
        engine = FraudDetectionEngine(fan_out_threshold=3, fan_out_window_seconds=300.0)
        disperser = "employer@okaxis"
        employee = "worker@okhdfc"

        alerts = []
        for i in range(8):
            res = engine.process_transaction(Transaction(
                transaction_id=f"TXN_SALARY_{i+1}",
                timestamp=1000.0 + i * 15.0,
                sender_upi=disperser,
                receiver_upi=employee,
                amount=5000.0,
            ))
            alerts.extend(res)

        assert len(alerts) == 0

    def test_fan_out_deduplication_requires_new_counterparty(self):
        engine = FraudDetectionEngine(fan_out_threshold=2, fan_out_window_seconds=200.0)
        disperser = "hub@okaxis"

        engine.process_transaction(Transaction("T1", 10.0, disperser, "r1@bank", 100.0))
        alerts_1 = engine.process_transaction(Transaction("T2", 20.0, disperser, "r2@bank", 100.0))
        assert len(alerts_1) == 1

        # Another transaction to existing receiver r1 -> no duplicate alert
        alerts_2 = engine.process_transaction(Transaction("T3", 30.0, disperser, "r1@bank", 100.0))
        assert len(alerts_2) == 0

        # New receiver r3 -> triggers updated alert
        alerts_3 = engine.process_transaction(Transaction("T4", 40.0, disperser, "r3@bank", 100.0))
        assert len(alerts_3) == 1
        assert alerts_3[0].evidence["distinct_counterparties"] == 3


# =====================================================================
# 6. CIRCULAR_FLOW Detection Tests
# =====================================================================

class TestCircularFlowDetection:
    """Validates bounded directed cycle search, transaction IDs in evidence, canonical deduplication, and window expiry."""

    def test_circular_flow_3_hop_detected_with_exact_transaction_ids(self):
        engine = FraudDetectionEngine(cycle_max_length=4, cycle_window_seconds=1800.0)

        # Hop 1: A -> B at t=100
        t1 = Transaction("TXN_C_01", 100.0, "alice@upi", "bob@upi", 10000.0)
        # Hop 2: B -> C at t=300 (delay 200s > passthrough_max_delay of 120s)
        t2 = Transaction("TXN_C_02", 300.0, "bob@upi", "charlie@upi", 9850.0)
        # Hop 3: C -> A at t=500 (closes cycle, delay 200s > passthrough_max_delay)
        t3 = Transaction("TXN_C_03", 500.0, "charlie@upi", "alice@upi", 9700.0)

        engine.process_transaction(t1)
        engine.process_transaction(t2)
        alerts = engine.process_transaction(t3)

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.pattern_type == "CIRCULAR_FLOW"
        assert sorted(alert.suspicious_accounts) == sorted(["alice@upi", "bob@upi", "charlie@upi"])
        assert alert.evidence["cycle_length"] == 3
        assert sorted(alert.evidence["cycle_transaction_ids"]) == sorted(["TXN_C_01", "TXN_C_02", "TXN_C_03"])
        assert alert.evidence["cycle_duration_seconds"] == 400.0
        assert len(alert.subgraph["edges"]) == 3
        validate_alert(alert.to_dict())

    def test_circular_flow_4_hop_detected(self):
        engine = FraudDetectionEngine(cycle_max_length=5, cycle_window_seconds=1800.0)
        nodes = ["node_1@okaxis", "node_2@okhdfc", "node_3@okicici", "node_4@oksbi"]

        # Hop delay 150s to avoid triggering rapid passthrough
        for i in range(3):
            engine.process_transaction(Transaction(
                transaction_id=f"TXN_4HOP_{i+1}",
                timestamp=100.0 + i * 150.0,
                sender_upi=nodes[i],
                receiver_upi=nodes[i+1],
                amount=50000.0,
            ))

        # Closing hop: node_4 -> node_1 at t=550 (150s after node_3 -> node_4 at t=400)
        closing_alerts = engine.process_transaction(Transaction(
            transaction_id="TXN_4HOP_4",
            timestamp=550.0,
            sender_upi=nodes[3],
            receiver_upi=nodes[0],
            amount=49000.0,
        ))

        assert len(closing_alerts) == 1
        alert = closing_alerts[0]
        assert alert.pattern_type == "CIRCULAR_FLOW"
        assert alert.evidence["cycle_length"] == 4
        validate_alert(alert.to_dict())

    def test_cycle_outside_time_window_does_not_alert(self):
        # Window = 500s. Hop 1 at t=100, Closing hop at t=700 (duration 600s > 500s)
        engine = FraudDetectionEngine(cycle_max_length=4, cycle_window_seconds=500.0)

        engine.process_transaction(Transaction("T1", 100.0, "a@upi", "b@upi", 1000.0))
        engine.process_transaction(Transaction("T2", 200.0, "b@upi", "c@upi", 1000.0))
        closing_alerts = engine.process_transaction(Transaction("T3", 700.0, "c@upi", "a@upi", 1000.0))

        assert len(closing_alerts) == 0

    def test_canonical_cycle_deduplication_preserves_directed_orientation(self):
        """A -> B -> C -> A is different from A -> C -> B -> A; both must be distinguishable."""
        engine = FraudDetectionEngine(cycle_max_length=4, cycle_window_seconds=1000.0)

        # Cycle 1: A -> B -> C -> A (hop delay 150s to decouple from rapid passthrough)
        engine.process_transaction(Transaction("C1_1", 10.0, "acc_a@upi", "acc_b@upi", 1000.0))
        engine.process_transaction(Transaction("C1_2", 160.0, "acc_b@upi", "acc_c@upi", 1000.0))
        res1 = engine.process_transaction(Transaction("C1_3", 310.0, "acc_c@upi", "acc_a@upi", 1000.0))
        assert len(res1) == 1
        assert res1[0].pattern_type == "CIRCULAR_FLOW"

        # Re-sending closing edge C1_3 does not re-alert (canonical deduplication)
        # Even with a new transaction ID:
        res1_duplicate = engine.process_transaction(Transaction("C1_4", 320.0, "acc_c@upi", "acc_a@upi", 1000.0))
        assert len(res1_duplicate) == 0

        # Cycle 2 (Reverse direction): A -> C -> B -> A
        engine.process_transaction(Transaction("C2_1", 470.0, "acc_a@upi", "acc_c@upi", 1000.0))
        engine.process_transaction(Transaction("C2_2", 620.0, "acc_c@upi", "acc_b@upi", 1000.0))
        res2 = engine.process_transaction(Transaction("C2_3", 770.0, "acc_b@upi", "acc_a@upi", 1000.0))

        # Because directed orientation is preserved, Cycle 2 IS detected!
        assert len(res2) == 1
        assert res2[0].pattern_type == "CIRCULAR_FLOW"

    def test_canonical_cycle_helper(self):
        c1 = _canonical_cycle(["B", "C", "A"])
        c2 = _canonical_cycle(["A", "B", "C"])
        c3 = _canonical_cycle(["C", "A", "B"])
        c_rev = _canonical_cycle(["A", "C", "B"])

        assert c1 == ("A", "B", "C")
        assert c2 == ("A", "B", "C")
        assert c3 == ("A", "B", "C")
        assert c_rev == ("A", "C", "B")
        assert c1 != c_rev


# =====================================================================
# 7. RAPID_PASSTHROUGH Detection & Inflow Ledger Tests
# =====================================================================

class TestRapidPassthroughDetection:
    """Validates single-use allocation, partial allocation, ratio, and delay bounds."""

    def test_rapid_passthrough_nominal_detection(self):
        engine = FraudDetectionEngine(
            passthrough_max_delay_seconds=120.0,
            passthrough_min_ratio=0.85,
        )
        victim = "victim@okhdfc"
        mule = "transit_mule@okaxis"
        cashout = "cashout@okicici"

        # Step 1: Inflow 50,000 INR
        inflow = Transaction(
            transaction_id="TXN_IN_01",
            timestamp=100.0,
            sender_upi=victim,
            receiver_upi=mule,
            amount=50000.0,
        )
        in_alerts = engine.process_transaction(inflow)
        assert in_alerts == []

        # Step 2: Outflow 47,500 INR (ratio = 0.95, delay = 45s)
        outflow = Transaction(
            transaction_id="TXN_OUT_01",
            timestamp=145.0,
            sender_upi=mule,
            receiver_upi=cashout,
            amount=47500.0,
        )
        out_alerts = engine.process_transaction(outflow)

        assert len(out_alerts) == 1
        alert = out_alerts[0]
        assert alert.pattern_type == "RAPID_PASSTHROUGH"
        assert alert.suspicious_accounts == [mule]
        assert alert.evidence["inflow_transaction_id"] == "TXN_IN_01"
        assert alert.evidence["outflow_transaction_id"] == "TXN_OUT_01"
        assert alert.evidence["forwarding_ratio"] == 0.95
        assert alert.evidence["transit_delay_seconds"] == 45.0
        assert "provenance" in alert.evidence["note"].lower()
        validate_alert(alert.to_dict())

    def test_single_use_inflow_allocation_prevents_double_matching(self):
        """An inflow of 10,000 can only be claimed once for a 9,500 outflow; a second 9,500 outflow must not match."""
        engine = FraudDetectionEngine(passthrough_max_delay_seconds=120.0, passthrough_min_ratio=0.85)

        # Inflow 10,000
        engine.process_transaction(Transaction("IN_1", 100.0, "s@bank", "mule@bank", 10000.0))

        # Outflow 1 (9,500) -> should match and allocate 9,500 (500 remains)
        alerts1 = engine.process_transaction(Transaction("OUT_1", 120.0, "mule@bank", "c1@bank", 9500.0))
        assert len(alerts1) == 1

        # Outflow 2 (9,500) -> insufficient remaining balance (only 500 left) -> no alert
        alerts2 = engine.process_transaction(Transaction("OUT_2", 130.0, "mule@bank", "c2@bank", 9500.0))
        assert len(alerts2) == 0

    def test_partial_allocation_and_insufficient_remaining_balance(self):
        """Allows multi-stage allocation if engine configured with lower threshold."""
        engine = FraudDetectionEngine(passthrough_max_delay_seconds=120.0, passthrough_min_ratio=0.40)

        # Inflow 10,000
        engine.process_transaction(Transaction("IN_10K", 100.0, "s@bank", "mule@bank", 10000.0))

        # Outflow 1: 5,000 (ratio = 0.50 >= 0.40). Remaining unallocated = 5,000.
        alerts1 = engine.process_transaction(Transaction("OUT_5K", 110.0, "mule@bank", "c1@bank", 5000.0))
        assert len(alerts1) == 1

        # Outflow 2: 4,500 (ratio = 0.45 >= 0.40). Remaining unallocated = 500.
        alerts2 = engine.process_transaction(Transaction("OUT_4.5K", 120.0, "mule@bank", "c2@bank", 4500.0))
        assert len(alerts2) == 1

        # Outflow 3: 4,500. Insufficient remaining balance (500 remaining < 4,500) -> no alert.
        alerts3 = engine.process_transaction(Transaction("OUT_4.5K_FAIL", 130.0, "mule@bank", "c3@bank", 4500.0))
        assert len(alerts3) == 0

    def test_passthrough_low_ratio_does_not_trigger(self):
        engine = FraudDetectionEngine(passthrough_min_ratio=0.85)
        # Inflow 10,000; Outflow 2,000 (ratio 0.20 < 0.85)
        engine.process_transaction(Transaction("IN_1", 100.0, "s@bank", "mule@bank", 10000.0))
        alerts = engine.process_transaction(Transaction("OUT_1", 120.0, "mule@bank", "c@bank", 2000.0))
        assert len(alerts) == 0

    def test_passthrough_exact_delay_boundary(self):
        engine = FraudDetectionEngine(passthrough_max_delay_seconds=60.0, passthrough_min_ratio=0.85)
        engine.process_transaction(Transaction("IN_1", 100.0, "s@bank", "mule@bank", 10000.0))

        # Outflow exactly at boundary (100.0 + 60.0 = 160.0) -> ALERT
        alerts_boundary = engine.process_transaction(Transaction("OUT_1", 160.0, "mule@bank", "c@bank", 9500.0))
        assert len(alerts_boundary) == 1

        # Reset and test t-W-0.01 outside boundary
        engine.reset()
        engine.process_transaction(Transaction("IN_2", 100.0, "s@bank", "mule@bank", 10000.0))
        alerts_expired = engine.process_transaction(Transaction("OUT_2", 160.01, "mule@bank", "c@bank", 9500.0))
        assert len(alerts_expired) == 0


# =====================================================================
# 8. SHARED_DEVICE Detection & Unknown ID Tests
# =====================================================================

class TestSharedDeviceDetection:
    """Validates device tracking, weak investigative signal score capping, and unknown device handling."""

    def test_shared_device_detected_with_conservative_score_cap(self):
        engine = FraudDetectionEngine(shared_device_threshold=3)
        device = "DEV_PHYSICAL_MULE_BOX_01"

        engine.process_transaction(Transaction("T1", 10.0, "user_1@bank", "merch@bank", 100.0, device_id=device))
        engine.process_transaction(Transaction("T2", 20.0, "user_2@bank", "merch@bank", 100.0, device_id=device))
        alerts = engine.process_transaction(Transaction("T3", 30.0, "user_3@bank", "merch@bank", 100.0, device_id=device))

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.pattern_type == "SHARED_DEVICE"
        assert alert.risk_score <= 0.35  # Strict conservative cap
        assert alert.severity == "LOW"
        assert alert.evidence["device_id"] == device
        assert alert.evidence["distinct_accounts_count"] == 3
        assert "investigative signal" in alert.evidence["note"].lower()
        validate_alert(alert.to_dict())

    @pytest.mark.parametrize("unknown_id", [
        "DEV_UNKNOWN",
        "UNKNOWN",
        "NONE",
        "NULL",
        "NA",
        "N/A",
        "",
        "   ",
    ])
    def test_unknown_or_missing_devices_never_trigger_alert(self, unknown_id):
        engine = FraudDetectionEngine(shared_device_threshold=2)

        # 5 distinct accounts each sending to a different merchant (avoids fan-in)
        alerts = []
        for i in range(5):
            res = engine.process_transaction(Transaction(
                transaction_id=f"TXN_UNK_{i+1}",
                timestamp=100.0 + i * 10.0,
                sender_upi=f"customer_{i+1}@okaxis",
                receiver_upi=f"store_{i+1}@okhdfc",
                amount=250.0,
                device_id=unknown_id,
            ))
            alerts.extend(res)

        assert len(alerts) == 0
        assert len(engine._device_to_accounts) == 0


# =====================================================================
# 9. Alert Determinism, Output Stability, and JSON Serialization
# =====================================================================

class TestAlertPropertiesAndSerialization:
    """Validates deterministic IDs, valid contracts, and JSON serialization without NaN."""

    def test_deterministic_sequential_alert_ids(self):
        engine = FraudDetectionEngine(fan_in_threshold=2, fan_in_window_seconds=100.0)

        # First alert
        engine.process_transaction(Transaction("T1", 10.0, "a@bank", "target1@bank", 100.0))
        a1 = engine.process_transaction(Transaction("T2", 20.0, "b@bank", "target1@bank", 100.0))[0]

        # Second alert
        engine.process_transaction(Transaction("T3", 30.0, "c@bank", "target2@bank", 100.0))
        a2 = engine.process_transaction(Transaction("T4", 40.0, "d@bank", "target2@bank", 100.0))[0]

        assert a1.alert_id == "ALT_000001"
        assert a2.alert_id == "ALT_000002"

    def test_alert_json_serialization_allow_nan_false(self):
        engine = FraudDetectionEngine(cycle_max_length=3, cycle_window_seconds=1000.0)
        # Delays 150s to isolate circular flow
        engine.process_transaction(Transaction("T1", 10.0, "a@bank", "b@bank", 100.0))
        engine.process_transaction(Transaction("T2", 160.0, "b@bank", "c@bank", 100.0))
        alerts = engine.process_transaction(Transaction("T3", 310.0, "c@bank", "a@bank", 100.0))

        assert len(alerts) == 1
        alert = alerts[0]

        # Convert to dictionary and test strict JSON serialization
        alert_dict = alert.to_dict()
        serialized = json.dumps(alert_dict, allow_nan=False)
        assert isinstance(serialized, str)

        # Deserialize and re-validate
        deserialized = json.loads(serialized)
        validated_alert = validate_alert(deserialized)
        assert validated_alert.alert_id == alert.alert_id
        assert validated_alert.pattern_type == "CIRCULAR_FLOW"

    def test_reset_clears_all_state_and_restores_id_counter(self):
        engine = FraudDetectionEngine(fan_in_threshold=2, fan_in_window_seconds=100.0)
        engine.process_transaction(Transaction("T1", 10.0, "a@bank", "target@bank", 100.0))
        alerts_run1 = engine.process_transaction(Transaction("T2", 20.0, "b@bank", "target@bank", 100.0))
        assert len(alerts_run1) == 1
        assert alerts_run1[0].alert_id == "ALT_000001"

        # Reset
        engine.reset()
        summary = engine.get_graph_summary()
        assert summary["node_count"] == 0
        assert summary["edge_count"] == 0
        assert summary["alert_count"] == 0
        assert summary["watermark"] == 0.0

        # Reprocess exact same transactions -> starts fresh from ALT_000001
        engine.process_transaction(Transaction("T1", 10.0, "a@bank", "target@bank", 100.0))
        alerts_run2 = engine.process_transaction(Transaction("T2", 20.0, "b@bank", "target@bank", 100.0))
        assert len(alerts_run2) == 1
        assert alerts_run2[0].alert_id == "ALT_000001"


# =====================================================================
# 10. Graph Pruning & Subgraph Inspection Tests
# =====================================================================

class TestPruningAndSubgraphExtraction:
    """Validates sliding window pruning and neighborhood subgraph queries."""

    def test_pruning_removes_expired_edges_and_isolated_nodes(self):
        engine = FraudDetectionEngine(max_window_seconds=100.0)

        # t = 10.0
        engine.process_transaction(Transaction("T1", 10.0, "old_u@bank", "old_v@bank", 100.0))
        assert engine.get_graph_summary()["node_count"] == 2
        assert engine.get_graph_summary()["edge_count"] == 1

        # t = 150.0 (cutoff is 150.0 - 100.0 = 50.0 > 10.0)
        engine.process_transaction(Transaction("T2", 150.0, "new_x@bank", "new_y@bank", 200.0))

        summary = engine.get_graph_summary()
        # Old edge (T1) and its isolated nodes (old_u, old_v) pruned
        assert summary["edge_count"] == 1
        assert summary["node_count"] == 2
        assert "old_u@bank" not in engine._graph

    def test_get_subgraph_returns_correct_neighborhood(self):
        engine = FraudDetectionEngine()
        engine.process_transaction(Transaction("T1", 10.0, "a@bank", "b@bank", 50.0))
        engine.process_transaction(Transaction("T2", 20.0, "b@bank", "c@bank", 50.0))
        engine.process_transaction(Transaction("T3", 30.0, "x@bank", "y@bank", 50.0))

        # Query non-existent node
        empty_sub = engine.get_subgraph("nonexistent@bank")
        assert empty_sub == {"nodes": [], "edges": []}

        # Query depth=1 around b@bank
        sub_1 = engine.get_subgraph("b@bank", depth=1)
        assert sorted(sub_1["nodes"]) == ["a@bank", "b@bank", "c@bank"]
        assert len(sub_1["edges"]) == 2


# =====================================================================
# 11. Additional Exact Boundaries and Multi-Pattern Tests
# =====================================================================

class TestAdditionalBoundariesAndComplexFlows:
    """Validates exact window boundaries for FAN_OUT and CIRCULAR_FLOW, normal traffic, and multi-alerts."""

    def test_normal_linear_transactions_no_false_alerts(self):
        engine = FraudDetectionEngine()
        # Normal independent P2P transfers
        normal_txns = [
            Transaction("NORM_1", 10.0, "alice@okaxis", "merchant_grocery@okhdfc", 450.0),
            Transaction("NORM_2", 60.0, "bob@okaxis", "merchant_coffee@okhdfc", 120.0),
            Transaction("NORM_3", 120.0, "charlie@okaxis", "landlord@okhdfc", 15000.0),
            Transaction("NORM_4", 300.0, "david@okaxis", "utilities@okhdfc", 850.0),
        ]
        all_alerts = []
        for t in normal_txns:
            all_alerts.extend(engine.process_transaction(t))

        assert len(all_alerts) == 0

    def test_fan_out_exact_window_boundary(self):
        engine = FraudDetectionEngine(fan_out_threshold=2, fan_out_window_seconds=100.0)
        disperser = "disperser@okaxis"

        # Outflow 1 at t=100.0
        engine.process_transaction(Transaction("T1", 100.0, disperser, "r1@okicici", 1000.0))

        # Outflow 2 at exact boundary t = 100.0 + 100.0 = 200.0 (included)
        alerts_boundary = engine.process_transaction(Transaction("T2", 200.0, disperser, "r2@okicici", 1000.0))
        assert len(alerts_boundary) == 1
        assert alerts_boundary[0].pattern_type == "FAN_OUT"

        # Reset and test t-W-0.01 outside boundary
        engine.reset()
        engine.process_transaction(Transaction("T3", 100.0, disperser, "r1@okicici", 1000.0))
        alerts_expired = engine.process_transaction(Transaction("T4", 200.01, disperser, "r2@okicici", 1000.0))
        assert len(alerts_expired) == 0

    def test_circular_flow_exact_window_boundary(self):
        # Window 500s. Hop 1 at t=100. Closing hop at t=600 (duration 500.0s == window: included)
        engine = FraudDetectionEngine(cycle_max_length=3, cycle_window_seconds=500.0)

        engine.process_transaction(Transaction("T1", 100.0, "a@upi", "b@upi", 1000.0))
        engine.process_transaction(Transaction("T2", 300.0, "b@upi", "c@upi", 1000.0))
        alerts_boundary = engine.process_transaction(Transaction("T3", 600.0, "c@upi", "a@upi", 1000.0))

        # Both CIRCULAR_FLOW and RAPID_PASSTHROUGH could trigger, but CIRCULAR_FLOW must be in alerts
        cf_boundary = [a for a in alerts_boundary if a.pattern_type == "CIRCULAR_FLOW"]
        assert len(cf_boundary) == 1

        # Reset and test at t=600.01 (600.01 - 100.0 = 500.01 > 500.0s: edge T1 expired)
        engine.reset()
        engine.process_transaction(Transaction("T4", 100.0, "a@upi", "b@upi", 1000.0))
        engine.process_transaction(Transaction("T5", 300.0, "b@upi", "c@upi", 1000.0))
        alerts_expired = engine.process_transaction(Transaction("T6", 600.01, "c@upi", "a@upi", 1000.0))

        cf_expired = [a for a in alerts_expired if a.pattern_type == "CIRCULAR_FLOW"]
        assert len(cf_expired) == 0

    def test_simultaneous_multi_pattern_alerts_emitted_with_stable_ids(self):
        """A single transaction closing a rapid pass-through and a cycle emits both alerts deterministically."""
        engine = FraudDetectionEngine(
            cycle_max_length=3,
            cycle_window_seconds=500.0,
            passthrough_max_delay_seconds=120.0,
            passthrough_min_ratio=0.85,
        )

        # Hop 1: A -> B (t=100)
        engine.process_transaction(Transaction("M_1", 100.0, "acc_a@upi", "acc_b@upi", 10000.0))
        # Hop 2: B -> C (t=150)
        engine.process_transaction(Transaction("M_2", 150.0, "acc_b@upi", "acc_c@upi", 9800.0))

        # Hop 3: C -> A (t=180, delay 30s <= 120s, ratio 9600/9800 = 0.979 >= 0.85)
        # C received funds in M_2 and forwards them in M_3, while closing cycle C -> A -> B -> C!
        multi_alerts = engine.process_transaction(Transaction("M_3", 180.0, "acc_c@upi", "acc_a@upi", 9600.0))

        assert len(multi_alerts) == 2
        patterns = [a.pattern_type for a in multi_alerts]
        assert "RAPID_PASSTHROUGH" in patterns
        assert "CIRCULAR_FLOW" in patterns

        # Verify distinct, sequential alert IDs
        assert multi_alerts[0].alert_id != multi_alerts[1].alert_id
        for a in multi_alerts:
            validate_alert(a.to_dict())
