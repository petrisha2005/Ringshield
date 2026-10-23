"""
detection/engine.py
Graph-based fraud detection engine for RingShield.

Detects suspicious UPI transaction networks using NetworkX and temporal flow rules:
1. FAN_IN: Rapid aggregation of funds from multiple distinct counterparties.
2. FAN_OUT: Rapid dispersion of funds to multiple distinct counterparties.
3. CIRCULAR_FLOW: Bounded directed transaction cycles (wash trading / layering).
4. RAPID_PASSTHROUGH: High-velocity pass-through transfers with single-use inflow ledger.
5. SHARED_DEVICE: Weak investigative signal for multi-account device sharing.

Never accepts or inspects fraud ground-truth labels.
Emits explainable, contract-compliant Alert instances.
"""

import json
import math
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Union

import networkx as nx

from contracts.schemas import (
    Alert,
    Transaction,
    VALID_SEVERITIES,
    validate_alert,
    validate_transaction,
)

UNKNOWN_DEVICE_IDS: Set[str] = {
    "DEV_UNKNOWN",
    "UNKNOWN",
    "NONE",
    "NULL",
    "N/A",
    "NA",
    "",
}


def _validate_numeric(val: object, name: str, min_val: Optional[float] = None, allow_zero: bool = True) -> float:
    """Validate that val is a real numeric float/int, not a boolean, not NaN, and not infinite."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"{name} must be a numeric value, got {type(val).__name__}")
    f_val = float(val)
    if not math.isfinite(f_val):
        raise ValueError(f"{name} must be a finite number (not NaN or Inf)")
    if min_val is not None:
        if allow_zero and f_val < min_val:
            raise ValueError(f"{name} must be >= {min_val}")
        elif not allow_zero and f_val <= min_val:
            raise ValueError(f"{name} must be strictly > {min_val}")
    return f_val


def _validate_int(val: object, name: str, min_val: int = 1) -> int:
    """Validate that val is a real integer, not a boolean, and >= min_val."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"{name} must be an integer, got {type(val).__name__}")
    if val < min_val:
        raise ValueError(f"{name} must be an integer >= {min_val}")
    return val


def _canonical_cycle(cycle_nodes: List[str]) -> Tuple[str, ...]:
    """
    Return a canonical tuple representing a directed cycle by shifting it
    to start at the lexicographically smallest node.
    Preserves directed orientation so (A, B, C) != (A, C, B).
    """
    if not cycle_nodes:
        return ()
    min_idx = min(range(len(cycle_nodes)), key=lambda i: cycle_nodes[i])
    return tuple(cycle_nodes[min_idx:] + cycle_nodes[:min_idx])


class FraudDetectionEngine:
    """
    Real-time graph intelligence fraud detection engine for RingShield.
    Processes transactions sequentially, maintains an evolving sliding-window multigraph,
    and returns explainable alerts.
    """

    def __init__(
        self,
        max_window_seconds: float = 3600.0,
        fan_in_threshold: int = 4,
        fan_in_window_seconds: float = 300.0,
        fan_out_threshold: int = 4,
        fan_out_window_seconds: float = 300.0,
        cycle_max_length: int = 5,
        cycle_window_seconds: float = 1800.0,
        passthrough_max_delay_seconds: float = 120.0,
        passthrough_min_ratio: float = 0.85,
        shared_device_threshold: int = 3,
    ):
        """
        Configure engine thresholds and sliding window bounds.
        """
        self.max_window_seconds = _validate_numeric(
            max_window_seconds, "max_window_seconds", min_val=0.0, allow_zero=False
        )
        self.fan_in_threshold = _validate_int(fan_in_threshold, "fan_in_threshold", min_val=2)
        self.fan_in_window_seconds = _validate_numeric(
            fan_in_window_seconds, "fan_in_window_seconds", min_val=0.0, allow_zero=False
        )
        self.fan_out_threshold = _validate_int(fan_out_threshold, "fan_out_threshold", min_val=2)
        self.fan_out_window_seconds = _validate_numeric(
            fan_out_window_seconds, "fan_out_window_seconds", min_val=0.0, allow_zero=False
        )
        self.cycle_max_length = _validate_int(cycle_max_length, "cycle_max_length", min_val=3)
        self.cycle_window_seconds = _validate_numeric(
            cycle_window_seconds, "cycle_window_seconds", min_val=0.0, allow_zero=False
        )
        self.passthrough_max_delay_seconds = _validate_numeric(
            passthrough_max_delay_seconds, "passthrough_max_delay_seconds", min_val=0.0, allow_zero=False
        )
        self.passthrough_min_ratio = _validate_numeric(
            passthrough_min_ratio, "passthrough_min_ratio", min_val=0.0, allow_zero=False
        )
        if self.passthrough_min_ratio > 1.0:
            raise ValueError("passthrough_min_ratio must be in (0, 1]")

        self.shared_device_threshold = _validate_int(
            shared_device_threshold, "shared_device_threshold", min_val=2
        )

        # Internal state
        self.reset()

    def reset(self) -> None:
        """Completely reset all internal graph and ledger state."""
        self._graph: nx.MultiDiGraph = nx.MultiDiGraph()
        # Ledger: account -> list of dicts {transaction_id, timestamp, amount, unallocated_amount, sender}
        self._inflow_ledger: Dict[str, List[Dict[str, Any]]] = {}
        # Device tracking: device_id -> set of distinct sender accounts
        self._device_to_accounts: Dict[str, Set[str]] = {}
        # Seen transaction IDs for idempotent replay
        self._seen_transaction_ids: Set[str] = set()
        # Deduplication caches:
        # Fan-in: receiver -> set of senders already alerted
        self._alerted_fan_in: Dict[str, Set[str]] = {}
        # Fan-out: sender -> set of receivers already alerted
        self._alerted_fan_out: Dict[str, Set[str]] = {}
        # Cycles: set of canonical cycle tuples already alerted
        self._alerted_cycles: Set[Tuple[str, ...]] = set()
        # Shared devices: device_id -> set of accounts already alerted
        self._alerted_devices: Dict[str, Set[str]] = {}
        # Watermark tracking
        self._watermark: float = 0.0
        self._has_processed_any: bool = False
        self._alert_counter: int = 0

    def _next_alert_id(self) -> str:
        """Generate deterministic sequential alert ID."""
        self._alert_counter += 1
        return f"ALT_{self._alert_counter:06d}"

    def process_transaction(
        self, transaction: Union[Transaction, Dict[str, Any]]
    ) -> List[Alert]:
        """
        Process a transaction sequentially:
        1. Validate schema before state change.
        2. Enforce nondecreasing timestamp policy.
        3. Handle duplicate transaction IDs idempotently.
        4. Mutate graph state and inflow ledger.
        5. Prune expired sliding-window entries.
        6. Evaluate all 5 detection heuristics.
        7. Return verified Alert instances.
        """
        # Step 1: Pre-mutation validation
        if isinstance(transaction, dict):
            txn_obj = validate_transaction(transaction)
        elif isinstance(transaction, Transaction):
            txn_obj = transaction
        else:
            raise TypeError(f"Expected Transaction or dict, got {type(transaction).__name__}")

        # Step 2: Idempotent duplicate check
        if txn_obj.transaction_id in self._seen_transaction_ids:
            return []

        # Step 3: Chronological timestamp policy
        if self._has_processed_any and txn_obj.timestamp < self._watermark:
            raise ValueError(
                f"Out-of-order transaction timestamp {txn_obj.timestamp} is earlier "
                f"than current watermark {self._watermark}"
            )

        # Step 4: Mutate state
        self._seen_transaction_ids.add(txn_obj.transaction_id)
        self._watermark = txn_obj.timestamp
        self._has_processed_any = True

        # Insert edge into MultiDiGraph
        self._graph.add_edge(
            txn_obj.sender_upi,
            txn_obj.receiver_upi,
            key=txn_obj.transaction_id,
            transaction_id=txn_obj.transaction_id,
            timestamp=txn_obj.timestamp,
            amount=txn_obj.amount,
            device_id=txn_obj.device_id,
        )

        # Record in unallocated inflow ledger for the receiver
        if txn_obj.receiver_upi not in self._inflow_ledger:
            self._inflow_ledger[txn_obj.receiver_upi] = []
        self._inflow_ledger[txn_obj.receiver_upi].append({
            "transaction_id": txn_obj.transaction_id,
            "timestamp": txn_obj.timestamp,
            "amount": txn_obj.amount,
            "unallocated_amount": txn_obj.amount,
            "sender": txn_obj.sender_upi,
        })

        # Track device reuse if not in UNKNOWN_DEVICE_IDS
        dev_id = txn_obj.device_id.strip() if txn_obj.device_id else ""
        if dev_id and dev_id.upper() not in UNKNOWN_DEVICE_IDS:
            if dev_id not in self._device_to_accounts:
                self._device_to_accounts[dev_id] = set()
            self._device_to_accounts[dev_id].add(txn_obj.sender_upi)

        # Step 5: Prune expired state older than self._watermark - self.max_window_seconds
        self._prune_expired_state()

        # Step 6: Evaluate heuristics
        alerts: List[Alert] = []

        # Heuristic 1: RAPID_PASSTHROUGH (outgoing transfer matching unallocated inflow)
        pt_alert = self._detect_rapid_passthrough(txn_obj)
        if pt_alert:
            alerts.append(pt_alert)

        # Heuristic 2: CIRCULAR_FLOW (closing a directed cycle with recent edges)
        cycle_alert = self._detect_circular_flow(txn_obj)
        if cycle_alert:
            alerts.append(cycle_alert)

        # Heuristic 3: FAN_IN (receiver in-degree counterparty burst)
        fan_in_alert = self._detect_fan_in(txn_obj)
        if fan_in_alert:
            alerts.append(fan_in_alert)

        # Heuristic 4: FAN_OUT (sender out-degree counterparty burst)
        fan_out_alert = self._detect_fan_out(txn_obj)
        if fan_out_alert:
            alerts.append(fan_out_alert)

        # Heuristic 5: SHARED_DEVICE (device footprint across multiple accounts)
        device_alert = self._detect_shared_device(txn_obj)
        if device_alert:
            alerts.append(device_alert)

        # Step 7: Verify all emitted alerts against contract
        for a in alerts:
            validate_alert(a.to_dict())

        return alerts

    def _prune_expired_state(self) -> None:
        """Prune graph edges and ledger entries older than max_window_seconds."""
        cutoff = self._watermark - self.max_window_seconds
        if cutoff <= 0:
            return

        # Prune graph edges
        edges_to_remove = [
            (u, v, k)
            for u, v, k, data in self._graph.edges(keys=True, data=True)
            if data["timestamp"] < cutoff
        ]
        for u, v, k in edges_to_remove:
            self._graph.remove_edge(u, v, key=k)

        # Prune isolated nodes with 0 degree
        isolated = [n for n, deg in self._graph.degree() if deg == 0]
        for n in isolated:
            self._graph.remove_node(n)

        # Prune inflow ledger
        empty_accounts = []
        for acc, entries in self._inflow_ledger.items():
            self._inflow_ledger[acc] = [e for e in entries if e["timestamp"] >= cutoff]
            if not self._inflow_ledger[acc]:
                empty_accounts.append(acc)
        for acc in empty_accounts:
            del self._inflow_ledger[acc]

    def _detect_rapid_passthrough(self, txn: Transaction) -> Optional[Alert]:
        """
        Detect rapid pass-through from the current sender using the unallocated inflow ledger.
        Ensures an inflow is not reused for multiple independent full-value matches.
        """
        sender = txn.sender_upi
        t_now = txn.timestamp
        out_amount = txn.amount

        candidate_inflows = self._inflow_ledger.get(sender, [])
        cutoff = t_now - self.passthrough_max_delay_seconds

        for inflow in candidate_inflows:
            # Check half-open time window [t_now - delay, t_now]
            if inflow["timestamp"] < cutoff or inflow["timestamp"] > t_now:
                continue

            unallocated = inflow["unallocated_amount"]
            if unallocated <= 0.0:
                continue

            # Forwarding ratio relative to original inflow
            ratio = out_amount / inflow["amount"]

            # Ratio must be within configured bound (allow small 5% buffer for slight fluctuations)
            if ratio < self.passthrough_min_ratio or ratio > 1.05:
                continue

            # Inflow must have sufficient remaining unallocated balance
            if out_amount > unallocated * 1.05:
                continue

            # Matched! Allocate from ledger to prevent double counting
            allocated = min(unallocated, out_amount)
            inflow["unallocated_amount"] = max(0.0, round(unallocated - allocated, 2))

            delay = round(t_now - inflow["timestamp"], 2)
            ratio_val = round(ratio, 4)

            # Heuristic score calculation
            if self.passthrough_min_ratio >= 1.0:
                ratio_component = 0.0
            else:
                ratio_component = (
                    (min(1.0, ratio_val) - self.passthrough_min_ratio)
                    / (1.0 - self.passthrough_min_ratio)
                )

            delay_component = max(
                0.0,
                (self.passthrough_max_delay_seconds - delay)
                / self.passthrough_max_delay_seconds,
            )

            score = min(
                0.90,
                max(
                    0.65,
                    0.65
                    + 0.15 * ratio_component
                    + 0.10 * delay_component,
                ),
            )

            severity = "CRITICAL" if score >= 0.80 else "HIGH"

            evidence = {
                "pattern_type": "RAPID_PASSTHROUGH",
                "intermediary_account": sender,
                "inflow_transaction_id": inflow["transaction_id"],
                "inflow_amount": inflow["amount"],
                "outflow_transaction_id": txn.transaction_id,
                "outflow_amount": out_amount,
                "forwarding_ratio": ratio_val,
                "transit_delay_seconds": delay,
                "note": "Heuristic flow matching based on unallocated inflow balance and timestamp sequencing; does not prove legal provenance.",
            }

            subgraph = {
                "nodes": sorted([inflow["sender"], sender, txn.receiver_upi]),
                "edges": [
                    {
                        "source": inflow["sender"],
                        "target": sender,
                        "amount": inflow["amount"],
                        "transaction_id": inflow["transaction_id"],
                    },
                    {
                        "source": sender,
                        "target": txn.receiver_upi,
                        "amount": out_amount,
                        "transaction_id": txn.transaction_id,
                    },
                ],
            }

            reasons = [
                f"Transit mule activity: {ratio_val * 100:.1f}% of incoming funds (Rs. {inflow['amount']:.2f}) forwarded within {delay:.1f}s."
            ]

            return Alert(
                alert_id=self._next_alert_id(),
                timestamp=t_now,
                transaction_id=txn.transaction_id,
                pattern_type="RAPID_PASSTHROUGH",
                risk_score=round(score, 4),
                severity=severity,
                suspicious_accounts=[sender],
                evidence=evidence,
                subgraph=subgraph,
                reasons=reasons,
                recommended_action="review",
            )

        return None

    def _detect_circular_flow(self, txn: Transaction) -> Optional[Alert]:
        """
        Detect bounded directed transaction cycles closed by the current transaction.
        Avoids full-graph cycle enumeration by querying paths from receiver to sender.
        """
        u = txn.sender_upi
        v = txn.receiver_upi
        t_now = txn.timestamp
        cutoff = t_now - self.cycle_window_seconds

        # Build subgraph of eligible recent edges
        eligible_edges = [
            (src, dst, data)
            for src, dst, data in self._graph.edges(data=True)
            if data["timestamp"] >= cutoff
        ]
        if not eligible_edges:
            return None

        # Build temporary simple digraph for path finding
        # Map (src, dst) -> most recent edge data
        recent_hop_map: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for src, dst, data in eligible_edges:
            key = (src, dst)
            if key not in recent_hop_map or data["timestamp"] > recent_hop_map[key]["timestamp"]:
                recent_hop_map[key] = data

        path_graph = nx.DiGraph()
        for (src, dst) in recent_hop_map.keys():
            path_graph.add_edge(src, dst)

        if not path_graph.has_node(v) or not path_graph.has_node(u):
            return None

        # Look for simple directed paths from v back to u with max length cutoff - 1
        max_hops = self.cycle_max_length - 1
        try:
            paths = list(nx.all_simple_paths(path_graph, source=v, target=u, cutoff=max_hops))
        except nx.NetworkXNoPath:
            return None

        if not paths:
            return None

        # Sort paths deterministically: length first, then start timestamp, then node list
        paths.sort(key=lambda p: (len(p), recent_hop_map.get((v, p[1]), {}).get("timestamp", 0.0), p))

        chosen_return_path = None
        cycle_nodes = None
        canonical = None

        for p in paths:
            candidate_nodes = [u] + p[:-1]
            if len(candidate_nodes) < 3:
                continue
            cand_canonical = _canonical_cycle(candidate_nodes)
            if cand_canonical in self._alerted_cycles:
                continue
            chosen_return_path = p
            cycle_nodes = candidate_nodes
            canonical = cand_canonical
            break

        if chosen_return_path is None or cycle_nodes is None or canonical is None:
            return None

        self._alerted_cycles.add(canonical)

        # Assemble full cycle hops and supporting transaction IDs
        full_cycle_path = cycle_nodes + [cycle_nodes[0]]
        cycle_tx_ids: List[str] = []
        subgraph_edges: List[Dict[str, Any]] = []
        hop_timestamps: List[float] = []

        for i in range(len(full_cycle_path) - 1):
            hop_src = full_cycle_path[i]
            hop_dst = full_cycle_path[i + 1]

            if hop_src == u and hop_dst == v:
                hop_data = {
                    "transaction_id": txn.transaction_id,
                    "amount": txn.amount,
                    "timestamp": txn.timestamp,
                }
            else:
                hop_data = recent_hop_map.get((hop_src, hop_dst), {})

            tx_id = hop_data.get("transaction_id", "TXN_UNKNOWN")
            amt = hop_data.get("amount", 0.0)
            ts = hop_data.get("timestamp", t_now)

            cycle_tx_ids.append(tx_id)
            hop_timestamps.append(ts)
            subgraph_edges.append({
                "source": hop_src,
                "target": hop_dst,
                "amount": amt,
                "transaction_id": tx_id,
            })

        duration = round(max(hop_timestamps) - min(hop_timestamps), 2)
        score = 0.75 if len(cycle_nodes) <= 4 else 0.70

        evidence = {
            "pattern_type": "CIRCULAR_FLOW",
            "cycle_length": len(cycle_nodes),
            "cycle_path": full_cycle_path,
            "cycle_transaction_ids": cycle_tx_ids,
            "cycle_duration_seconds": duration,
        }

        subgraph = {
            "nodes": sorted(list(set(cycle_nodes))),
            "edges": subgraph_edges,
        }

        reasons = [
            f"Closed transaction cycle detected: {' -> '.join(full_cycle_path)} over {duration:.1f}s."
        ]

        return Alert(
            alert_id=self._next_alert_id(),
            timestamp=t_now,
            transaction_id=txn.transaction_id,
            pattern_type="CIRCULAR_FLOW",
            risk_score=round(score, 4),
            severity="HIGH",
            suspicious_accounts=sorted(cycle_nodes),
            evidence=evidence,
            subgraph=subgraph,
            reasons=reasons,
            recommended_action="review",
        )

    def _detect_fan_in(self, txn: Transaction) -> Optional[Alert]:
        """
        Detect fan-in aggregation: counts distinct counterparties sending to receiver.
        """
        receiver = txn.receiver_upi
        t_now = txn.timestamp
        cutoff = t_now - self.fan_in_window_seconds

        # Find all distinct senders within the time window
        recent_senders: Set[str] = set()
        total_inflow = 0.0
        subgraph_edges: List[Dict[str, Any]] = []

        for u, v, data in self._graph.in_edges(receiver, data=True):
            if cutoff <= data["timestamp"] <= t_now:
                recent_senders.add(u)
                total_inflow += data["amount"]
                subgraph_edges.append({
                    "source": u,
                    "target": v,
                    "amount": data["amount"],
                    "transaction_id": data["transaction_id"],
                })

        count = len(recent_senders)
        if count < self.fan_in_threshold:
            return None

        # Alert deduplication: only emit if new distinct senders appear
        already_alerted = self._alerted_fan_in.get(receiver, set())
        if recent_senders.issubset(already_alerted):
            return None
        self._alerted_fan_in[receiver] = already_alerted.union(recent_senders)

        score = min(0.85, 0.55 + 0.05 * (count - self.fan_in_threshold))
        severity = "HIGH" if score >= 0.65 else "MEDIUM"

        evidence = {
            "pattern_type": "FAN_IN",
            "aggregator_account": receiver,
            "distinct_counterparties": count,
            "counterparty_sample": sorted(list(recent_senders))[:10],
            "total_inflow_amount": round(total_inflow, 2),
            "window_seconds": self.fan_in_window_seconds,
        }

        subgraph = {
            "nodes": sorted(list(recent_senders.union({receiver}))),
            "edges": subgraph_edges,
        }

        reasons = [
            f"Account {receiver} received rapid inflows from {count} distinct accounts within {self.fan_in_window_seconds:.0f}s."
        ]

        return Alert(
            alert_id=self._next_alert_id(),
            timestamp=t_now,
            transaction_id=txn.transaction_id,
            pattern_type="FAN_IN",
            risk_score=round(score, 4),
            severity=severity,
            suspicious_accounts=[receiver],
            evidence=evidence,
            subgraph=subgraph,
            reasons=reasons,
            recommended_action="review",
        )

    def _detect_fan_out(self, txn: Transaction) -> Optional[Alert]:
        """
        Detect fan-out dispersion: counts distinct counterparties receiving from sender.
        """
        sender = txn.sender_upi
        t_now = txn.timestamp
        cutoff = t_now - self.fan_out_window_seconds

        # Find all distinct receivers within the time window
        recent_receivers: Set[str] = set()
        total_outflow = 0.0
        subgraph_edges: List[Dict[str, Any]] = []

        for u, v, data in self._graph.out_edges(sender, data=True):
            if cutoff <= data["timestamp"] <= t_now:
                recent_receivers.add(v)
                total_outflow += data["amount"]
                subgraph_edges.append({
                    "source": u,
                    "target": v,
                    "amount": data["amount"],
                    "transaction_id": data["transaction_id"],
                })

        count = len(recent_receivers)
        if count < self.fan_out_threshold:
            return None

        # Alert deduplication: only emit if new distinct receivers appear
        already_alerted = self._alerted_fan_out.get(sender, set())
        if recent_receivers.issubset(already_alerted):
            return None
        self._alerted_fan_out[sender] = already_alerted.union(recent_receivers)

        score = min(0.85, 0.55 + 0.05 * (count - self.fan_out_threshold))
        severity = "HIGH" if score >= 0.65 else "MEDIUM"

        evidence = {
            "pattern_type": "FAN_OUT",
            "disperser_account": sender,
            "distinct_counterparties": count,
            "counterparty_sample": sorted(list(recent_receivers))[:10],
            "total_outflow_amount": round(total_outflow, 2),
            "window_seconds": self.fan_out_window_seconds,
        }

        subgraph = {
            "nodes": sorted(list(recent_receivers.union({sender}))),
            "edges": subgraph_edges,
        }

        reasons = [
            f"Account {sender} rapidly dispersed funds across {count} distinct accounts within {self.fan_out_window_seconds:.0f}s."
        ]

        return Alert(
            alert_id=self._next_alert_id(),
            timestamp=t_now,
            transaction_id=txn.transaction_id,
            pattern_type="FAN_OUT",
            risk_score=round(score, 4),
            severity=severity,
            suspicious_accounts=[sender],
            evidence=evidence,
            subgraph=subgraph,
            reasons=reasons,
            recommended_action="review",
        )

    def _detect_shared_device(self, txn: Transaction) -> Optional[Alert]:
        """
        Detect multi-account device footprint.
        Treats device reuse as a weak investigative signal, not proof of fraud.
        """
        dev_id = txn.device_id.strip() if txn.device_id else ""
        if not dev_id or dev_id.upper() in UNKNOWN_DEVICE_IDS:
            return None

        accounts = self._device_to_accounts.get(dev_id, set())
        if len(accounts) < self.shared_device_threshold:
            return None

        already_alerted = self._alerted_devices.get(dev_id, set())
        if accounts.issubset(already_alerted):
            return None
        self._alerted_devices[dev_id] = already_alerted.union(accounts)

        # Conservative weak signal score cap (max 0.35)
        score = 0.35
        severity = "LOW"

        evidence = {
            "pattern_type": "SHARED_DEVICE",
            "device_id": dev_id,
            "distinct_accounts_count": len(accounts),
            "associated_accounts": sorted(list(accounts)),
            "note": "Weak investigative signal: indicates device sharing across accounts; does not prove fraud.",
        }

        subgraph = {
            "nodes": sorted(list(accounts)),
            "edges": [],
        }

        reasons = [
            f"Device footprint '{dev_id}' observed across {len(accounts)} distinct accounts (weak investigative signal for multi-accounting)."
        ]

        return Alert(
            alert_id=self._next_alert_id(),
            timestamp=txn.timestamp,
            transaction_id=txn.transaction_id,
            pattern_type="SHARED_DEVICE",
            risk_score=round(score, 4),
            severity=severity,
            suspicious_accounts=sorted(list(accounts)),
            evidence=evidence,
            subgraph=subgraph,
            reasons=reasons,
            recommended_action="review",
        )

    def get_graph_summary(self) -> Dict[str, Any]:
        """Returns node count, edge count, active devices, and current watermark."""
        return {
            "node_count": self._graph.number_of_nodes(),
            "edge_count": self._graph.number_of_edges(),
            "tracked_devices_count": len(self._device_to_accounts),
            "watermark": self._watermark,
            "processed_transaction_count": len(self._seen_transaction_ids),
            "alert_count": self._alert_counter,
        }

    def get_subgraph(self, account_id: str, depth: int = 1) -> Dict[str, Any]:
        """
        Extract neighborhood subgraph around account_id up to depth for UI visualization.
        """
        if not self._graph.has_node(account_id):
            return {"nodes": [], "edges": []}

        nodes = {account_id}
        for _ in range(depth):
            next_nodes = set(nodes)
            for n in nodes:
                next_nodes.update(self._graph.predecessors(n))
                next_nodes.update(self._graph.successors(n))
            nodes = next_nodes

        edges = []
        for u in nodes:
            for v in nodes:
                if self._graph.has_edge(u, v):
                    for _, data in self._graph.get_edge_data(u, v).items():
                        edges.append({
                            "source": u,
                            "target": v,
                            "amount": data["amount"],
                            "transaction_id": data["transaction_id"],
                        })

        edges.sort(key=lambda e: (e["source"], e["target"], e["transaction_id"]))
        return {
            "nodes": sorted(list(nodes)),
            "edges": edges,
        }
