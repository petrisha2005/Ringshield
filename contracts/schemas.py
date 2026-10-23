"""
contracts/schemas.py
Shared data contracts for RingShield: Real-Time Mule Account and UPI Fraud Ring Detection.

Defines schemas and validators for:
1. Transaction: Payload entering the streaming pipeline and detection engine.
2. TransactionGroundTruth: Synthetic evaluation labels (isolated from detector).
3. Alert: Explainable detection output emitted to Kafka and Streamlit frontend.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json
import math

# Proposed standard severity levels for team alignment
# Accepts standard security tiers ("LOW", "MEDIUM", "HIGH", "CRITICAL")
# as well as the PDF roadmap tiers ("low", "review", "high").
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "review", "high"}


@dataclass
class Transaction:
    """
    Represents a UPI transaction entering the RingShield system.

    Fields:
        transaction_id: Unique transaction reference string.
        timestamp: Epoch timestamp in seconds (finite numeric float).
        sender_upi: Sender's UPI ID / VPA (e.g. "user1@okhdfcbank").
        receiver_upi: Receiver's UPI ID / VPA (e.g. "mule_a@okaxis").
        amount: Transaction amount in INR (strictly positive finite float).
        device_id: Device identifier for shared-device ring clustering.
        ip_address: Optional client IP address.
        transaction_type: Transaction category (default: "p2p_transfer").
    """
    transaction_id: str
    timestamp: float
    sender_upi: str
    receiver_upi: str
    amount: float
    device_id: str = "DEV_UNKNOWN"
    ip_address: Optional[str] = None
    transaction_type: str = "p2p_transfer"

    def __post_init__(self):
        if not isinstance(self.transaction_id, str):
            raise TypeError("transaction_id must be a string")
        if not self.transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, (int, float)):
            raise TypeError("timestamp must be a numeric epoch timestamp in seconds")
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be a finite number (not NaN or Inf)")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        object.__setattr__(self, "timestamp", float(self.timestamp))

        if not isinstance(self.sender_upi, str):
            raise TypeError("sender_upi must be a string")
        if not self.sender_upi.strip():
            raise ValueError("sender_upi must be a non-empty string")

        if not isinstance(self.receiver_upi, str):
            raise TypeError("receiver_upi must be a string")
        if not self.receiver_upi.strip():
            raise ValueError("receiver_upi must be a non-empty string")

        if self.sender_upi.strip() == self.receiver_upi.strip():
            raise ValueError("sender_upi and receiver_upi cannot be identical")

        if isinstance(self.amount, bool) or not isinstance(self.amount, (int, float)):
            raise TypeError("amount must be a numeric value")
        if not math.isfinite(self.amount):
            raise ValueError("amount must be a finite number (not NaN or Inf)")
        if self.amount <= 0:
            raise ValueError("amount must be strictly positive (> 0)")
        object.__setattr__(self, "amount", float(self.amount))

        if not isinstance(self.device_id, str):
            raise TypeError("device_id must be a string")

        if self.ip_address is not None and not isinstance(self.ip_address, str):
            raise TypeError("ip_address must be a string or None")

        if not isinstance(self.transaction_type, str):
            raise TypeError("transaction_type must be a string")
        if not self.transaction_type.strip():
            raise ValueError("transaction_type must be a non-empty string")

    @property
    def sender_id(self) -> str:
        """Convenience property for sender_upi matching hackathon roadmap PDF."""
        return self.sender_upi

    @property
    def receiver_id(self) -> str:
        """Convenience property for receiver_upi matching hackathon roadmap PDF."""
        return self.receiver_upi

    def to_dict(self, include_aliases: bool = False) -> Dict[str, Any]:
        """
        Convert to a JSON-serializable dictionary.
        Does not emit duplicate alias fields by default unless include_aliases=True.
        """
        d = asdict(self)
        if include_aliases:
            d["sender_id"] = self.sender_upi
            d["receiver_id"] = self.receiver_upi
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        """
        Instantiate Transaction from dictionary, supporting alias fields.
        Strictly guards against data leakage by rejecting ground-truth labels.
        Validates input types without silent coercion.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Transaction data must be a dictionary, got {type(data).__name__}")

        # Anti-leakage guard: ground truth must never enter transaction payload
        forbidden_keys = {"is_fraud", "pattern_type", "ring_id"}
        leaked = forbidden_keys.intersection(data.keys())
        if leaked:
            raise ValueError(
                f"Data leakage detected! Ground-truth labels {sorted(leaked)} "
                "must not be present in Transaction input."
            )

        if "transaction_id" not in data:
            raise ValueError("Missing required field 'transaction_id'")
        if "timestamp" not in data:
            raise ValueError("Missing required field 'timestamp'")
        if "amount" not in data:
            raise ValueError("Missing required field 'amount'")

        sender = data.get("sender_upi")
        if sender is None:
            sender = data.get("sender_id")
        if sender is None:
            raise ValueError("Missing required sender field ('sender_upi' or 'sender_id')")

        receiver = data.get("receiver_upi")
        if receiver is None:
            receiver = data.get("receiver_id")
        if receiver is None:
            raise ValueError("Missing required receiver field ('receiver_upi' or 'receiver_id')")

        txn_id = data["transaction_id"]
        if not isinstance(txn_id, str):
            raise TypeError("transaction_id must be a string")
        if not txn_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if not isinstance(sender, str):
            raise TypeError("sender_upi / sender_id must be a string")
        if not sender.strip():
            raise ValueError("sender_upi / sender_id must be a non-empty string")

        if not isinstance(receiver, str):
            raise TypeError("receiver_upi / receiver_id must be a string")
        if not receiver.strip():
            raise ValueError("receiver_upi / receiver_id must be a non-empty string")

        timestamp = data["timestamp"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise TypeError("timestamp must be a numeric epoch timestamp in seconds")

        amount = data["amount"]
        if isinstance(amount, bool) or not isinstance(amount, (int, float)):
            raise TypeError("amount must be a numeric value")

        device_id = data.get("device_id", "DEV_UNKNOWN")
        if not isinstance(device_id, str):
            raise TypeError("device_id must be a string")

        ip_address = data.get("ip_address")
        if ip_address is not None and not isinstance(ip_address, str):
            raise TypeError("ip_address must be a string or None")

        transaction_type = data.get("transaction_type", "p2p_transfer")
        if not isinstance(transaction_type, str):
            raise TypeError("transaction_type must be a string")
        if not transaction_type.strip():
            raise ValueError("transaction_type must be a non-empty string")

        return cls(
            transaction_id=txn_id,
            timestamp=float(timestamp),
            sender_upi=sender,
            receiver_upi=receiver,
            amount=float(amount),
            device_id=device_id,
            ip_address=ip_address,
            transaction_type=transaction_type,
        )


@dataclass
class TransactionGroundTruth:
    """
    Ground-truth labels generated by the simulator for offline model evaluation.
    Kept strictly isolated from Transaction inputs to avoid data leakage.
    """
    transaction_id: str
    is_fraud: bool
    pattern_type: str
    ring_id: Optional[str] = None

    def __post_init__(self):
        if not isinstance(self.transaction_id, str):
            raise TypeError("transaction_id must be a string")
        if not self.transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if not isinstance(self.is_fraud, bool):
            raise TypeError(f"is_fraud must be an actual boolean (True or False), got {type(self.is_fraud).__name__}")

        if not isinstance(self.pattern_type, str):
            raise TypeError("pattern_type must be a string")
        if not self.pattern_type.strip():
            raise ValueError("pattern_type must be a non-empty string")

        if self.ring_id is not None:
            if not isinstance(self.ring_id, str):
                raise TypeError("ring_id must be a string or None")
            if not self.ring_id.strip():
                raise ValueError("ring_id must be a non-empty string if provided")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TransactionGroundTruth":
        """Instantiate TransactionGroundTruth from dictionary with strict boolean validation."""
        if not isinstance(data, dict):
            raise TypeError(f"Ground truth data must be a dictionary, got {type(data).__name__}")

        for req in ("transaction_id", "is_fraud", "pattern_type"):
            if req not in data:
                raise ValueError(f"Missing required field '{req}' in ground truth data")

        txn_id = data["transaction_id"]
        if not isinstance(txn_id, str):
            raise TypeError("transaction_id must be a string")
        if not txn_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        is_fraud = data["is_fraud"]
        if not isinstance(is_fraud, bool):
            raise TypeError(f"is_fraud must be an actual boolean (True or False), got {type(is_fraud).__name__}")

        pattern_type = data["pattern_type"]
        if not isinstance(pattern_type, str):
            raise TypeError("pattern_type must be a string")
        if not pattern_type.strip():
            raise ValueError("pattern_type must be a non-empty string")

        ring_id = data.get("ring_id")
        if ring_id is not None:
            if not isinstance(ring_id, str):
                raise TypeError("ring_id must be a string or None")
            if not ring_id.strip():
                raise ValueError("ring_id must be a non-empty string if provided")

        return cls(
            transaction_id=txn_id,
            is_fraud=is_fraud,
            pattern_type=pattern_type,
            ring_id=ring_id,
        )


@dataclass
class Alert:
    """
    Represents an explainable fraud alert generated by the detection engine.

    Fields:
        alert_id: Unique alert reference string.
        timestamp: Generation epoch timestamp in seconds (finite numeric float).
        transaction_id: Transaction that triggered the alert.
        pattern_type: Detected fraud typology (e.g. CIRCULAR_FLOW, FAN_IN_AGGREGATION).
        risk_score: Normalized risk score between 0.0 and 1.0 (finite float).
        severity: Severity category ("LOW", "MEDIUM", "HIGH", "CRITICAL" or "low", "review", "high").
        suspicious_accounts: List of non-empty account strings flagged in the ring.
        evidence: JSON-serializable dictionary containing metrics and explanation details.
        subgraph: JSON-serializable dictionary with 'nodes' (list of str) and 'edges' (list of dict).
        reasons: List of human-readable non-empty explanation strings.
        recommended_action: Recommended analyst decision (default: "review").
    """
    alert_id: str
    timestamp: float
    transaction_id: str
    pattern_type: str
    risk_score: float
    severity: str
    suspicious_accounts: List[str]
    evidence: Dict[str, Any] = field(default_factory=dict)
    subgraph: Dict[str, Any] = field(default_factory=lambda: {"nodes": [], "edges": []})
    reasons: List[str] = field(default_factory=list)
    recommended_action: str = "review"

    def __post_init__(self):
        if not isinstance(self.alert_id, str):
            raise TypeError("alert_id must be a string")
        if not self.alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")

        if isinstance(self.timestamp, bool) or not isinstance(self.timestamp, (int, float)):
            raise TypeError("timestamp must be a numeric epoch timestamp in seconds")
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be a finite number (not NaN or Inf)")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        object.__setattr__(self, "timestamp", float(self.timestamp))

        if not isinstance(self.transaction_id, str):
            raise TypeError("transaction_id must be a string")
        if not self.transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        if not isinstance(self.pattern_type, str):
            raise TypeError("pattern_type must be a string")
        if not self.pattern_type.strip():
            raise ValueError("pattern_type must be a non-empty string")

        if isinstance(self.risk_score, bool) or not isinstance(self.risk_score, (int, float)):
            raise TypeError("risk_score must be a numeric value")
        if not math.isfinite(self.risk_score):
            raise ValueError("risk_score must be a finite number (not NaN or Inf)")
        if not (0.0 <= self.risk_score <= 1.0):
            raise ValueError(f"risk_score must be between 0.0 and 1.0, got {self.risk_score}")
        object.__setattr__(self, "risk_score", float(self.risk_score))

        if not isinstance(self.severity, str):
            raise TypeError("severity must be a string")
        if not self.severity.strip():
            raise ValueError("severity must be a non-empty string")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}, got {self.severity!r}")

        if not isinstance(self.suspicious_accounts, list):
            raise TypeError("suspicious_accounts must be a list of account IDs")
        for i, acc in enumerate(self.suspicious_accounts):
            if not isinstance(acc, str):
                raise TypeError(f"suspicious_accounts[{i}] must be a string, got {type(acc).__name__}")
            if not acc.strip():
                raise ValueError(f"suspicious_accounts[{i}] must be a non-empty string")

        if not isinstance(self.evidence, dict):
            raise TypeError("evidence must be a dictionary")
        try:
            json.dumps(self.evidence, allow_nan=False)
        except (TypeError, OverflowError, ValueError) as err:
            raise ValueError(f"evidence must be valid JSON-serializable without non-finite values: {err}")

        if not isinstance(self.subgraph, dict):
            raise TypeError("subgraph must be a dictionary with 'nodes' and 'edges'")
        if "nodes" not in self.subgraph or "edges" not in self.subgraph:
            raise ValueError("subgraph must contain 'nodes' and 'edges' lists")
        if not isinstance(self.subgraph["nodes"], list):
            raise TypeError("subgraph 'nodes' must be a list")
        if not isinstance(self.subgraph["edges"], list):
            raise TypeError("subgraph 'edges' must be a list")

        for i, node in enumerate(self.subgraph["nodes"]):
            if not isinstance(node, str):
                raise TypeError(f"subgraph nodes[{i}] must be a string, got {type(node).__name__}")
            if not node.strip():
                raise ValueError(f"subgraph nodes[{i}] must be a non-empty string")

        for i, edge in enumerate(self.subgraph["edges"]):
            if not isinstance(edge, dict):
                raise TypeError(f"subgraph edges[{i}] must be a dictionary")
            if "source" not in edge or "target" not in edge:
                raise ValueError(f"subgraph edges[{i}] must contain 'source' and 'target' keys")
            if not isinstance(edge["source"], str):
                raise TypeError(f"subgraph edges[{i}] 'source' must be a string")
            if not edge["source"].strip():
                raise ValueError(f"subgraph edges[{i}] 'source' must be a non-empty string")
            if not isinstance(edge["target"], str):
                raise TypeError(f"subgraph edges[{i}] 'target' must be a string")
            if not edge["target"].strip():
                raise ValueError(f"subgraph edges[{i}] 'target' must be a non-empty string")

        try:
            json.dumps(self.subgraph, allow_nan=False)
        except (TypeError, OverflowError, ValueError) as err:
            raise ValueError(f"subgraph must be valid JSON-serializable without non-finite values: {err}")

        if not isinstance(self.reasons, list):
            raise TypeError("reasons must be a list of strings")
        for i, reason in enumerate(self.reasons):
            if not isinstance(reason, str):
                raise TypeError(f"reasons[{i}] must be a string, got {type(reason).__name__}")
            if not reason.strip():
                raise ValueError(f"reasons[{i}] must be a non-empty string")

        if not isinstance(self.recommended_action, str):
            raise TypeError("recommended_action must be a string")
        if not self.recommended_action.strip():
            raise ValueError("recommended_action must be a non-empty string")

    @property
    def risk_level(self) -> str:
        """Convenience property for severity matching hackathon roadmap PDF."""
        return self.severity

    def to_dict(self, include_aliases: bool = False) -> Dict[str, Any]:
        """
        Convert to a JSON-serializable dictionary.
        Does not emit duplicate alias fields by default unless include_aliases=True.
        """
        d = asdict(self)
        if include_aliases:
            d["risk_level"] = self.severity
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Instantiate Alert from dictionary, supporting alias fields without coercion."""
        if not isinstance(data, dict):
            raise TypeError(f"Alert data must be a dictionary, got {type(data).__name__}")

        for req in ("alert_id", "timestamp", "transaction_id", "pattern_type", "risk_score"):
            if req not in data:
                raise ValueError(f"Missing required field '{req}' in Alert data")

        severity = data.get("severity")
        if severity is None:
            severity = data.get("risk_level")
        if severity is None:
            raise ValueError("Missing required field 'severity' (or 'risk_level')")

        alert_id = data["alert_id"]
        if not isinstance(alert_id, str):
            raise TypeError("alert_id must be a string")
        if not alert_id.strip():
            raise ValueError("alert_id must be a non-empty string")

        timestamp = data["timestamp"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise TypeError("timestamp must be a numeric epoch timestamp in seconds")

        transaction_id = data["transaction_id"]
        if not isinstance(transaction_id, str):
            raise TypeError("transaction_id must be a string")
        if not transaction_id.strip():
            raise ValueError("transaction_id must be a non-empty string")

        pattern_type = data["pattern_type"]
        if not isinstance(pattern_type, str):
            raise TypeError("pattern_type must be a string")
        if not pattern_type.strip():
            raise ValueError("pattern_type must be a non-empty string")

        risk_score = data["risk_score"]
        if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
            raise TypeError("risk_score must be a numeric value")

        if not isinstance(severity, str):
            raise TypeError("severity must be a string")
        if not severity.strip():
            raise ValueError("severity must be a non-empty string")

        suspicious_accounts = data.get("suspicious_accounts", [])
        if not isinstance(suspicious_accounts, list):
            raise TypeError("suspicious_accounts must be a list")

        evidence = data.get("evidence", {})
        if not isinstance(evidence, dict):
            raise TypeError("evidence must be a dictionary")

        subgraph = data.get("subgraph", {"nodes": [], "edges": []})
        if not isinstance(subgraph, dict):
            raise TypeError("subgraph must be a dictionary")

        reasons = data.get("reasons", [])
        if not isinstance(reasons, list):
            raise TypeError("reasons must be a list")

        recommended_action = data.get("recommended_action", "review")
        if not isinstance(recommended_action, str):
            raise TypeError("recommended_action must be a string")
        if not recommended_action.strip():
            raise ValueError("recommended_action must be a non-empty string")

        return cls(
            alert_id=alert_id,
            timestamp=float(timestamp),
            transaction_id=transaction_id,
            pattern_type=pattern_type,
            risk_score=float(risk_score),
            severity=severity,
            suspicious_accounts=suspicious_accounts,
            evidence=evidence,
            subgraph=subgraph,
            reasons=reasons,
            recommended_action=recommended_action,
        )


def validate_transaction(data: Dict[str, Any]) -> Transaction:
    """Validate a transaction dictionary and return a Transaction instance."""
    return Transaction.from_dict(data)


def validate_alert(data: Dict[str, Any]) -> Alert:
    """Validate an alert dictionary and return an Alert instance."""
    return Alert.from_dict(data)


def validate_ground_truth(data: Dict[str, Any]) -> TransactionGroundTruth:
    """Validate a ground-truth dictionary and return a TransactionGroundTruth instance."""
    return TransactionGroundTruth.from_dict(data)
