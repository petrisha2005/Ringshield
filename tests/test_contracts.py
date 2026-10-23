"""
tests/test_contracts.py
Comprehensive unit tests for contracts/schemas.py in RingShield.

Tests cover:
- Valid inputs and default optional fields
- Strict type checking (rejecting silent type conversions)
- Numeric edge cases (math.nan, +inf, -inf, zero, negative amounts, out-of-range risk scores)
- Ground-truth data leakage prevention
- Team contract aliases (sender_id, receiver_id, risk_level)
- Severity validation against proposed team tiers
- Subgraph structure and node/edge validation
- JSON serializability of evidence and subgraphs with non-finite value checks
- Alert.from_dict invalid list entries validation
- Validator helper functions
"""

import json
import math
import pytest
from contracts.schemas import (
    Transaction,
    TransactionGroundTruth,
    Alert,
    VALID_SEVERITIES,
    validate_transaction,
    validate_alert,
    validate_ground_truth,
)


# ============================================================================
# Transaction Tests
# ============================================================================

def test_valid_transaction_direct():
    """Test standard valid transaction instantiation."""
    txn = Transaction(
        transaction_id="TXN_001",
        timestamp=1729680000.0,
        sender_upi="alice@okaxis",
        receiver_upi="bob@okhdfc",
        amount=5000.0,
        device_id="DEV_123",
        ip_address="192.168.1.1",
        transaction_type="p2p_transfer",
    )
    assert txn.transaction_id == "TXN_001"
    assert txn.timestamp == 1729680000.0
    assert txn.sender_upi == "alice@okaxis"
    assert txn.receiver_upi == "bob@okhdfc"
    assert txn.amount == 5000.0
    assert txn.device_id == "DEV_123"
    assert txn.ip_address == "192.168.1.1"
    assert txn.transaction_type == "p2p_transfer"
    # Team contract aliases
    assert txn.sender_id == "alice@okaxis"
    assert txn.receiver_id == "bob@okhdfc"


def test_transaction_optional_defaults():
    """Test default values for optional transaction fields."""
    txn = Transaction(
        transaction_id="TXN_002",
        timestamp=1729680010.0,
        sender_upi="carol@okicici",
        receiver_upi="dave@oksbi",
        amount=1200.50,
    )
    assert txn.device_id == "DEV_UNKNOWN"
    assert txn.ip_address is None
    assert txn.transaction_type == "p2p_transfer"


def test_transaction_from_dict_and_aliases():
    """Test from_dict supports sender_id and receiver_id aliases."""
    raw = {
        "transaction_id": "TXN_003",
        "timestamp": 1729680020.0,
        "sender_id": "userA@upi",
        "receiver_id": "userB@upi",
        "amount": 750.0,
    }
    txn = Transaction.from_dict(raw)
    assert txn.sender_upi == "userA@upi"
    assert txn.receiver_upi == "userB@upi"
    assert txn.sender_id == "userA@upi"
    assert txn.receiver_id == "userB@upi"


def test_transaction_to_dict_alias_behavior():
    """Test to_dict emits canonical fields by default and aliases only when requested."""
    txn = Transaction(
        transaction_id="TXN_004",
        timestamp=1729680030.0,
        sender_upi="src@upi",
        receiver_upi="dst@upi",
        amount=999.0,
    )
    default_dict = txn.to_dict()
    assert "sender_upi" in default_dict
    assert "receiver_upi" in default_dict
    assert "sender_id" not in default_dict  # no duplicate alias by default

    aliased_dict = txn.to_dict(include_aliases=True)
    assert aliased_dict["sender_id"] == "src@upi"
    assert aliased_dict["receiver_id"] == "dst@upi"

    # JSON serialization
    serialized = json.dumps(default_dict)
    assert "TXN_004" in serialized


def test_transaction_missing_required_fields():
    """Test validation errors when required fields are missing."""
    with pytest.raises(ValueError, match="Missing required field 'amount'"):
        Transaction.from_dict({
            "transaction_id": "TXN_005",
            "timestamp": 1729680000.0,
            "sender_upi": "a@upi",
            "receiver_upi": "b@upi",
        })

    with pytest.raises(ValueError, match="Missing required sender field"):
        Transaction.from_dict({
            "transaction_id": "TXN_005",
            "timestamp": 1729680000.0,
            "receiver_upi": "b@upi",
            "amount": 100.0,
        })


@pytest.mark.parametrize("invalid_amount", [0, -10.0, -0.01])
def test_transaction_invalid_non_positive_amount(invalid_amount):
    """Test non-positive amount raises ValueError."""
    with pytest.raises(ValueError, match="amount must be strictly positive"):
        Transaction(
            transaction_id="TXN_006",
            timestamp=1729680000.0,
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=invalid_amount,
        )


@pytest.mark.parametrize("non_finite_val", [math.nan, float("inf"), float("-inf")])
def test_transaction_non_finite_numerics(non_finite_val):
    """Test NaN and Infinities are rejected for timestamp and amount."""
    with pytest.raises(ValueError, match="timestamp must be a finite number"):
        Transaction(
            transaction_id="TXN_NAN_1",
            timestamp=non_finite_val,
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=100.0,
        )

    with pytest.raises(ValueError, match="amount must be a finite number"):
        Transaction(
            transaction_id="TXN_NAN_2",
            timestamp=1729680000.0,
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=non_finite_val,
        )


def test_transaction_invalid_types_rejected_without_silent_coercion():
    """Ensure non-string IDs or boolean timestamps/amounts are rejected without silent coercion."""
    # Non-string transaction_id raises TypeError matching regex
    with pytest.raises(TypeError, match="transaction_id must be a string"):
        Transaction.from_dict({
            "transaction_id": 12345,
            "timestamp": 1729680000.0,
            "sender_upi": "a@upi",
            "receiver_upi": "b@upi",
            "amount": 100.0,
        })

    # Empty transaction_id raises ValueError
    with pytest.raises(ValueError, match="transaction_id must be a non-empty string"):
        Transaction(
            transaction_id="   ",
            timestamp=1729680000.0,
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=100.0,
        )

    with pytest.raises(TypeError, match="amount must be a numeric value"):
        Transaction(
            transaction_id="TXN_007",
            timestamp=1729680000.0,
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=True,  # boolean is not a valid amount
        )

    with pytest.raises(TypeError, match="timestamp must be a numeric epoch timestamp"):
        Transaction(
            transaction_id="TXN_008",
            timestamp="not_a_number",
            sender_upi="a@upi",
            receiver_upi="b@upi",
            amount=100.0,
        )


def test_transaction_identical_sender_receiver():
    """Test transaction with identical sender and receiver is rejected."""
    with pytest.raises(ValueError, match="sender_upi and receiver_upi cannot be identical"):
        Transaction(
            transaction_id="TXN_009",
            timestamp=1729680000.0,
            sender_upi="same@upi",
            receiver_upi="same@upi",
            amount=100.0,
        )


def test_transaction_anti_leakage_guard():
    """Test that Transaction.from_dict strictly blocks fraud ground-truth labels."""
    leaked_payload = {
        "transaction_id": "TXN_010",
        "timestamp": 1729680000.0,
        "sender_upi": "a@upi",
        "receiver_upi": "b@upi",
        "amount": 500.0,
        "is_fraud": True,          # LEAK!
        "pattern_type": "FAN_IN",  # LEAK!
    }
    with pytest.raises(ValueError, match="Data leakage detected"):
        Transaction.from_dict(leaked_payload)


# ============================================================================
# TransactionGroundTruth Tests
# ============================================================================

def test_valid_ground_truth():
    """Test TransactionGroundTruth instantiation and serialization."""
    gt = TransactionGroundTruth(
        transaction_id="TXN_001",
        is_fraud=True,
        pattern_type="CIRCULAR_FLOW",
        ring_id="RING_DELTA_01",
    )
    assert gt.is_fraud is True
    assert gt.pattern_type == "CIRCULAR_FLOW"
    assert gt.ring_id == "RING_DELTA_01"

    d = gt.to_dict()
    assert d["is_fraud"] is True
    reconstructed = TransactionGroundTruth.from_dict(d)
    assert reconstructed == gt


def test_ground_truth_strictly_rejects_non_boolean_is_fraud():
    """Test that is_fraud requires an actual boolean, not integer or string."""
    with pytest.raises(TypeError, match="is_fraud must be an actual boolean"):
        TransactionGroundTruth(
            transaction_id="TXN_001",
            is_fraud="True",  # string not allowed
            pattern_type="FAN_IN",
        )

    with pytest.raises(TypeError, match="is_fraud must be an actual boolean"):
        TransactionGroundTruth.from_dict({
            "transaction_id": "TXN_001",
            "is_fraud": 1,  # int 1 instead of True not allowed
            "pattern_type": "FAN_IN",
        })


def test_ground_truth_missing_required():
    """Test missing fields in ground truth dictionary."""
    with pytest.raises(ValueError, match="Missing required field 'pattern_type'"):
        TransactionGroundTruth.from_dict({
            "transaction_id": "TXN_001",
            "is_fraud": False,
        })


# ============================================================================
# Alert Tests
# ============================================================================

def test_valid_alert_creation():
    """Test valid Alert creation with subgraphs and explainability."""
    alert = Alert(
        alert_id="ALT_101",
        timestamp=1729680050.0,
        transaction_id="TXN_999",
        pattern_type="FAN_IN_AGGREGATION",
        risk_score=0.85,
        severity="HIGH",
        suspicious_accounts=["mule1@upi", "mule2@upi"],
        evidence={
            "in_degree": 7,
            "window_seconds": 120,
            "total_inflow": 450000.0,
        },
        subgraph={
            "nodes": ["victim1@upi", "victim2@upi", "mule1@upi"],
            "edges": [
                {"source": "victim1@upi", "target": "mule1@upi", "amount": 25000.0},
                {"source": "victim2@upi", "target": "mule1@upi", "amount": 20000.0},
            ],
        },
        reasons=["High frequency inflows from multiple sources within 2 minutes"],
        recommended_action="review",
    )
    assert alert.risk_score == 0.85
    assert alert.risk_level == "HIGH"
    assert alert.recommended_action == "review"
    assert len(alert.subgraph["nodes"]) == 3
    assert len(alert.subgraph["edges"]) == 2

    # Verify JSON serialization
    default_d = alert.to_dict()
    assert "risk_level" not in default_d  # no duplicate by default
    aliased_d = alert.to_dict(include_aliases=True)
    assert aliased_d["risk_level"] == "HIGH"
    assert "ALT_101" in json.dumps(default_d)


@pytest.mark.parametrize("valid_score", [0.0, 0.5, 0.82, 1.0])
def test_alert_valid_risk_scores(valid_score):
    """Test valid risk score boundaries [0.0, 1.0]."""
    alert = Alert(
        alert_id="ALT_102",
        timestamp=1729680000.0,
        transaction_id="TXN_010",
        pattern_type="NORMAL",
        risk_score=valid_score,
        severity="LOW",
        suspicious_accounts=[],
    )
    assert alert.risk_score == valid_score


@pytest.mark.parametrize("invalid_score", [-0.01, 1.01, 82.0, -1.0, math.nan, float("inf"), float("-inf")])
def test_alert_invalid_risk_scores(invalid_score):
    """Test out-of-bounds, NaN, +Inf, and -Inf risk scores raise ValueError."""
    with pytest.raises(ValueError):
        Alert(
            alert_id="ALT_103",
            timestamp=1729680000.0,
            transaction_id="TXN_011",
            pattern_type="CYCLE",
            risk_score=invalid_score,
            severity="HIGH",
            suspicious_accounts=["mule@upi"],
        )


def test_alert_severity_validation():
    """Test that severity is checked against proposed team tiers."""
    for valid_sev in ("LOW", "HIGH", "CRITICAL", "review", "low"):
        assert valid_sev in VALID_SEVERITIES
        a = Alert(
            alert_id="ALT_SEV",
            timestamp=1729680000.0,
            transaction_id="TXN_011",
            pattern_type="CYCLE",
            risk_score=0.5,
            severity=valid_sev,
            suspicious_accounts=[],
        )
        assert a.severity == valid_sev

    with pytest.raises(ValueError, match="severity must be one of"):
        Alert(
            alert_id="ALT_SEV_INV",
            timestamp=1729680000.0,
            transaction_id="TXN_011",
            pattern_type="CYCLE",
            risk_score=0.5,
            severity="EXTREME_UNSUPPORTED",
            suspicious_accounts=[],
        )


def test_alert_suspicious_accounts_and_reasons_string_validation():
    """Ensure suspicious_accounts and reasons contain non-empty strings."""
    with pytest.raises(TypeError, match="suspicious_accounts.*must be a string"):
        Alert(
            alert_id="ALT_104",
            timestamp=1729680000.0,
            transaction_id="TXN_012",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="HIGH",
            suspicious_accounts=[12345],  # non-string item
        )

    with pytest.raises(ValueError, match="reasons.*must be a non-empty string"):
        Alert(
            alert_id="ALT_105",
            timestamp=1729680000.0,
            transaction_id="TXN_013",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="HIGH",
            suspicious_accounts=["mule@upi"],
            reasons=[""],  # empty string not allowed
        )


def test_alert_from_dict_invalid_list_entries():
    """Ensure Alert.from_dict validates list items correctly."""
    with pytest.raises(TypeError, match="suspicious_accounts.*must be a string"):
        Alert.from_dict({
            "alert_id": "ALT_INV_L1",
            "timestamp": 1729680000.0,
            "transaction_id": "TXN_014",
            "pattern_type": "CYCLE",
            "risk_score": 0.8,
            "severity": "HIGH",
            "suspicious_accounts": ["valid@upi", 999],  # invalid int item
        })

    with pytest.raises(TypeError, match="reasons.*must be a string"):
        Alert.from_dict({
            "alert_id": "ALT_INV_L2",
            "timestamp": 1729680000.0,
            "transaction_id": "TXN_015",
            "pattern_type": "CYCLE",
            "risk_score": 0.8,
            "severity": "HIGH",
            "suspicious_accounts": [],
            "reasons": [None],  # invalid None item
        })


def test_alert_subgraph_validation():
    """Ensure subgraphs have valid nodes and edges with source and target."""
    with pytest.raises(TypeError, match="subgraph must be a dictionary"):
        Alert(
            alert_id="ALT_106",
            timestamp=1729680000.0,
            transaction_id="TXN_014",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="CRITICAL",
            suspicious_accounts=["m@upi"],
            subgraph=["not", "a", "dict"],
        )

    with pytest.raises(ValueError, match="subgraph must contain 'nodes' and 'edges' lists"):
        Alert(
            alert_id="ALT_107",
            timestamp=1729680000.0,
            transaction_id="TXN_015",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="CRITICAL",
            suspicious_accounts=["m@upi"],
            subgraph={"nodes": []},
        )

    with pytest.raises(ValueError, match="must contain 'source' and 'target' keys"):
        Alert(
            alert_id="ALT_108",
            timestamp=1729680000.0,
            transaction_id="TXN_016",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="CRITICAL",
            suspicious_accounts=["m@upi"],
            subgraph={
                "nodes": ["A", "B"],
                "edges": [{"source": "A"}],  # missing target
            },
        )


def test_alert_non_finite_in_evidence_and_subgraph():
    """Ensure NaN and +/-Inf inside evidence and subgraph are rejected."""
    with pytest.raises(ValueError, match="evidence must be valid JSON-serializable without non-finite values"):
        Alert(
            alert_id="ALT_NF_1",
            timestamp=1729680000.0,
            transaction_id="TXN_017",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="HIGH",
            suspicious_accounts=["m@upi"],
            evidence={"metric": math.nan},  # NaN inside evidence
        )

    with pytest.raises(ValueError, match="evidence must be valid JSON-serializable without non-finite values"):
        Alert(
            alert_id="ALT_NF_2",
            timestamp=1729680000.0,
            transaction_id="TXN_018",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="HIGH",
            suspicious_accounts=["m@upi"],
            evidence={"ratio": float("inf")},  # +Inf inside evidence
        )

    with pytest.raises(ValueError, match="subgraph must be valid JSON-serializable without non-finite values"):
        Alert(
            alert_id="ALT_NF_3",
            timestamp=1729680000.0,
            transaction_id="TXN_019",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="HIGH",
            suspicious_accounts=["m@upi"],
            subgraph={
                "nodes": ["A", "B"],
                "edges": [{"source": "A", "target": "B", "amount": float("-inf")}],  # -Inf in subgraph
            },
        )


def test_alert_non_json_serializable_evidence_rejected():
    """Ensure non-JSON-serializable evidence raises ValueError."""
    with pytest.raises(ValueError, match="evidence must be valid JSON-serializable"):
        Alert(
            alert_id="ALT_109",
            timestamp=1729680000.0,
            transaction_id="TXN_020",
            pattern_type="CYCLE",
            risk_score=0.9,
            severity="CRITICAL",
            suspicious_accounts=["m@upi"],
            evidence={"set_data": {1, 2, 3}},  # Python sets are not JSON serializable
        )


def test_alert_from_dict_and_risk_level_alias():
    """Test from_dict supports 'risk_level' alias for 'severity'."""
    raw = {
        "alert_id": "ALT_110",
        "timestamp": 1729680000.0,
        "transaction_id": "TXN_021",
        "pattern_type": "RAPID_PASSTHROUGH",
        "risk_score": 0.77,
        "risk_level": "review",  # alias for severity
        "suspicious_accounts": ["transit_mule@upi"],
    }
    alert = Alert.from_dict(raw)
    assert alert.severity == "review"
    assert alert.risk_level == "review"


# ============================================================================
# Validator Functions Tests
# ============================================================================

def test_validator_helpers():
    """Test helper functions validate_transaction, validate_alert, validate_ground_truth."""
    txn = validate_transaction({
        "transaction_id": "TXN_200",
        "timestamp": 1729680100.0,
        "sender_upi": "u1@upi",
        "receiver_upi": "u2@upi",
        "amount": 200.0,
    })
    assert isinstance(txn, Transaction)

    alert = validate_alert({
        "alert_id": "ALT_200",
        "timestamp": 1729680100.0,
        "transaction_id": "TXN_200",
        "pattern_type": "FAN_OUT",
        "risk_score": 0.65,
        "severity": "MEDIUM",
        "suspicious_accounts": ["u2@upi"],
    })
    assert isinstance(alert, Alert)

    gt = validate_ground_truth({
        "transaction_id": "TXN_200",
        "is_fraud": False,
        "pattern_type": "NORMAL",
    })
    assert isinstance(gt, TransactionGroundTruth)
