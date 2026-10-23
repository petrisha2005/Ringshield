"""
simulator/generate.py
Synthetic UPI transaction and fraud scenario generator for RingShield.

Generates realistic background transaction traffic alongside 5 distinct,
explainable graph fraud topologies:
1. FAN_IN: Inflow funneling / smurfing to an aggregator mule.
2. FAN_OUT: Rapid fund dispersion from a mule to multiple cash-out nodes.
3. CIRCULAR_FLOW: Directed cycles (wash trading / layering).
4. RAPID_PASSTHROUGH: High-velocity transit mule forwarding with high ratio and low delay.
5. SHARED_DEVICE: Multi-account mule syndicate sharing a single device_id.

Strictly isolates ground-truth fraud labels (is_fraud, pattern_type, ring_id)
into a separate ground_truth.jsonl file to prevent data leakage.
"""

import argparse
import json
import math
import os
from pathlib import Path
import random
import tempfile
from typing import Dict, List, Optional, Set, Tuple

from contracts.schemas import (
    Transaction,
    TransactionGroundTruth,
    validate_transaction,
    validate_ground_truth,
)

VALID_SCENARIO_NAMES: Set[str] = {
    "fan_in",
    "fan_out",
    "circular_flow",
    "rapid_passthrough",
    "shared_device",
}


def _validate_finite_number(
    val: object,
    name: str,
    min_val: Optional[float] = None,
    allow_zero: bool = True,
    min_rounded_decimals: Optional[int] = None,
) -> float:
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
    if min_rounded_decimals is not None:
        if round(f_val, min_rounded_decimals) <= 0.0:
            raise ValueError(
                f"{name} ({f_val}) must remain strictly positive (> 0) after rounding to {min_rounded_decimals} decimal places"
            )
    return f_val


def _validate_integer(val: object, name: str, min_val: int = 0) -> int:
    """Validate that val is a real integer, not a boolean, and >= min_val."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"{name} must be an integer, got {type(val).__name__}")
    if val < min_val:
        raise ValueError(f"{name} must be an integer >= {min_val}")
    return val


class SyntheticTransactionGenerator:
    """
    Deterministic synthetic transaction generator for RingShield.
    Generates normal UPI transactions and injected graph fraud ring scenarios.
    """

    def __init__(
        self,
        seed: int = 42,
        start_time: float = 1729680000.0,
        user_pool_size: int = 50,
        merchant_pool_size: int = 10,
    ):
        """
        Initialize the generator with reproducible seed and user pools.

        Args:
            seed: Integer random seed for reproducible generation.
            start_time: Baseline epoch timestamp in seconds (finite >= 0).
            user_pool_size: Number of synthetic legitimate peer users (integer >= 2).
            merchant_pool_size: Number of synthetic merchants (integer >= 1).
        """
        self.seed = _validate_integer(seed, "seed", min_val=-(2**31))
        self.start_time = _validate_finite_number(start_time, "start_time", min_val=0.0, allow_zero=True)
        user_pool_count = _validate_integer(user_pool_size, "user_pool_size", min_val=2)
        merchant_pool_count = _validate_integer(merchant_pool_size, "merchant_pool_size", min_val=1)

        self._rng = random.Random(self.seed)
        self._txn_counter = 0

        # Construct synthetic user and merchant pools (fictional UPI IDs)
        self.users = [f"user_{i:03d}@okaxis" for i in range(1, user_pool_count + 1)]
        self.merchants = [f"merchant_{i:02d}@paytm" for i in range(1, merchant_pool_count + 1)]

        # Map each user to a distinct default device and IP
        self.user_devices: Dict[str, str] = {
            u: f"DEV_USR_{i:03d}" for i, u in enumerate(self.users, 1)
        }
        self.user_ips: Dict[str, str] = {
            u: f"192.168.1.{i % 250 + 1}" for i, u in enumerate(self.users, 1)
        }

    def _next_txn_id(self) -> str:
        """Generate monotonically increasing unique transaction ID."""
        self._txn_counter += 1
        return f"TXN_{self._txn_counter:06d}"

    def generate_normal_traffic(
        self, count: int = 100, duration_seconds: float = 3600.0
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        Generate background legitimate transactions.
        """
        valid_count = _validate_integer(count, "count", min_val=0)
        valid_duration = _validate_finite_number(duration_seconds, "duration_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2)

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        receiver_pool = self.users + self.merchants

        for _ in range(valid_count):
            sender = self._rng.choice(self.users)
            # Ensure sender != receiver
            possible_receivers = [r for r in receiver_pool if r != sender]
            receiver = self._rng.choice(possible_receivers)

            is_merchant = receiver in self.merchants
            txn_type = "merchant_payment" if is_merchant else "p2p_transfer"

            # Amounts: normal consumer transfers (INR 50 to 12,000)
            amount = round(self._rng.uniform(50.0, 12000.0), 2)
            timestamp = round(
                self.start_time + self._rng.uniform(0.0, valid_duration), 2
            )

            txn_id = self._next_txn_id()
            txn = Transaction(
                transaction_id=txn_id,
                timestamp=timestamp,
                sender_upi=sender,
                receiver_upi=receiver,
                amount=amount,
                device_id=self.user_devices.get(sender, "DEV_UNKNOWN"),
                ip_address=self.user_ips.get(sender),
                transaction_type=txn_type,
            )
            gt = TransactionGroundTruth(
                transaction_id=txn_id,
                is_fraud=False,
                pattern_type="NORMAL",
                ring_id=None,
            )
            pairs.append((txn, gt))

        return pairs

    def generate_fan_in_scenario(
        self,
        victim_count: int = 5,
        ring_id: str = "RING_FAN_IN_01",
        window_seconds: float = 240.0,
        base_time: Optional[float] = None,
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        FAN_IN Scenario: Multiple victim accounts funnel money into a single aggregator mule.
        """
        valid_victims = _validate_integer(victim_count, "victim_count", min_val=2)
        valid_window = _validate_finite_number(window_seconds, "window_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2)

        if not isinstance(ring_id, str) or not ring_id.strip():
            raise ValueError("ring_id must be a non-empty string")

        if base_time is None:
            valid_base_time = self.start_time + self._rng.uniform(300.0, 1800.0)
        else:
            valid_base_time = _validate_finite_number(base_time, "base_time", min_val=0.0, allow_zero=True)

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        mule = f"mule_agg_{ring_id.lower()}@okaxis"
        victims = [f"victim_{ring_id.lower()}_{i:02d}@okhdfc" for i in range(1, valid_victims + 1)]

        step = valid_window / max(valid_victims, 1)
        for i, victim in enumerate(victims):
            txn_id = self._next_txn_id()
            amount = round(self._rng.uniform(15000.0, 35000.0), 2)
            ts = round(valid_base_time + (i * step) + self._rng.uniform(0.0, step * 0.5), 2)

            txn = Transaction(
                transaction_id=txn_id,
                timestamp=ts,
                sender_upi=victim,
                receiver_upi=mule,
                amount=amount,
                device_id=f"DEV_VIC_{i:02d}",
                ip_address=f"10.1.1.{i + 1}",
                transaction_type="p2p_transfer",
            )
            gt = TransactionGroundTruth(
                transaction_id=txn_id,
                is_fraud=True,
                pattern_type="FAN_IN",
                ring_id=ring_id,
            )
            pairs.append((txn, gt))

        return pairs

    def generate_fan_out_scenario(
        self,
        cashout_count: int = 5,
        ring_id: str = "RING_FAN_OUT_01",
        window_seconds: float = 240.0,
        base_time: Optional[float] = None,
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        FAN_OUT Scenario: A single mule rapidly disperses funds to multiple cash-out accounts.
        """
        valid_cashouts = _validate_integer(cashout_count, "cashout_count", min_val=2)
        valid_window = _validate_finite_number(window_seconds, "window_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2)

        if not isinstance(ring_id, str) or not ring_id.strip():
            raise ValueError("ring_id must be a non-empty string")

        if base_time is None:
            valid_base_time = self.start_time + self._rng.uniform(600.0, 2400.0)
        else:
            valid_base_time = _validate_finite_number(base_time, "base_time", min_val=0.0, allow_zero=True)

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        mule = f"mule_disp_{ring_id.lower()}@okaxis"
        cashouts = [f"cashout_{ring_id.lower()}_{i:02d}@oksbi" for i in range(1, valid_cashouts + 1)]

        step = valid_window / max(valid_cashouts, 1)
        for i, cashout in enumerate(cashouts):
            txn_id = self._next_txn_id()
            amount = round(self._rng.uniform(8000.0, 15000.0), 2)
            ts = round(valid_base_time + (i * step) + self._rng.uniform(0.0, step * 0.5), 2)

            txn = Transaction(
                transaction_id=txn_id,
                timestamp=ts,
                sender_upi=mule,
                receiver_upi=cashout,
                amount=amount,
                device_id=f"DEV_MULE_DISP_{ring_id.lower()}",
                ip_address="10.2.2.1",
                transaction_type="p2p_transfer",
            )
            gt = TransactionGroundTruth(
                transaction_id=txn_id,
                is_fraud=True,
                pattern_type="FAN_OUT",
                ring_id=ring_id,
            )
            pairs.append((txn, gt))

        return pairs

    def generate_circular_flow_scenario(
        self,
        cycle_length: int = 4,
        ring_id: str = "RING_CYCLE_01",
        base_amount: float = 40000.0,
        step_delay_seconds: float = 60.0,
        base_time: Optional[float] = None,
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        CIRCULAR_FLOW Scenario: A directed cycle of transactions (A -> B -> C -> A)
        with strictly sequential timestamps and approximately conserved amounts.
        """
        valid_length = _validate_integer(cycle_length, "cycle_length", min_val=3)
        valid_amount = _validate_finite_number(
            base_amount, "base_amount", min_val=0.0, allow_zero=False, min_rounded_decimals=2
        )
        valid_step = _validate_finite_number(
            step_delay_seconds, "step_delay_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2
        )

        # Ensure that after cycle decay, the minimum hop amount still rounds to > 0.00
        min_decay = 0.985 ** (valid_length - 1)
        if round(valid_amount * min_decay, 2) <= 0.0:
            raise ValueError(
                f"base_amount {valid_amount} with cycle_length {valid_length} produces a rounded hop amount of 0.00"
            )

        if not isinstance(ring_id, str) or not ring_id.strip():
            raise ValueError("ring_id must be a non-empty string")

        if base_time is None:
            valid_base_time = self.start_time + self._rng.uniform(900.0, 2700.0)
        else:
            valid_base_time = _validate_finite_number(base_time, "base_time", min_val=0.0, allow_zero=True)

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        nodes = [f"mule_cycle_{ring_id.lower()}_{i:02d}@okicici" for i in range(1, valid_length + 1)]

        curr_time = valid_base_time
        for i in range(valid_length):
            sender = nodes[i]
            receiver = nodes[(i + 1) % valid_length]
            txn_id = self._next_txn_id()

            decay_factor = 0.985 ** i
            amount = round(valid_amount * decay_factor, 2)
            ts = round(curr_time, 2)

            txn = Transaction(
                transaction_id=txn_id,
                timestamp=ts,
                sender_upi=sender,
                receiver_upi=receiver,
                amount=amount,
                device_id=f"DEV_CYCLE_{i:02d}",
                ip_address=f"10.3.3.{i + 1}",
                transaction_type="p2p_transfer",
            )
            gt = TransactionGroundTruth(
                transaction_id=txn_id,
                is_fraud=True,
                pattern_type="CIRCULAR_FLOW",
                ring_id=ring_id,
            )
            pairs.append((txn, gt))

            # Strictly advance timestamp for the next hop in the cycle
            curr_time += valid_step + self._rng.uniform(1.0, 5.0)

        return pairs

    def generate_rapid_passthrough_scenario(
        self,
        ring_id: str = "RING_PASSTHROUGH_01",
        inflow_amount: float = 50000.0,
        pass_ratio: float = 0.95,
        delay_seconds: float = 45.0,
        base_time: Optional[float] = None,
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        RAPID_PASSTHROUGH Scenario: Inflow immediately followed by matching outflow
        with a measurable time delta and high forwarding ratio (near-zero balance retention).
        """
        valid_inflow = _validate_finite_number(
            inflow_amount, "inflow_amount", min_val=0.0, allow_zero=False, min_rounded_decimals=2
        )
        valid_ratio = _validate_finite_number(pass_ratio, "pass_ratio", min_val=0.0, allow_zero=False)
        if valid_ratio > 1.0:
            raise ValueError("pass_ratio must be a finite number in (0, 1]")

        in_amount = round(valid_inflow, 2)
        out_amount = round(in_amount * valid_ratio, 2)
        if out_amount <= 0.0:
            raise ValueError(
                f"inflow_amount {valid_inflow} with pass_ratio {valid_ratio} produces a rounded outflow of 0.00"
            )

        valid_delay = _validate_finite_number(
            delay_seconds, "delay_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2
        )

        if not isinstance(ring_id, str) or not ring_id.strip():
            raise ValueError("ring_id must be a non-empty string")

        if base_time is None:
            valid_base_time = self.start_time + self._rng.uniform(1200.0, 3000.0)
        else:
            valid_base_time = _validate_finite_number(base_time, "base_time", min_val=0.0, allow_zero=True)

        in_ts = round(valid_base_time, 2)
        out_ts = round(in_ts + valid_delay, 2)
        if out_ts <= in_ts:
            raise ValueError(
                f"delay_seconds {valid_delay} is too small; rounded outflow timestamp equals inflow timestamp ({in_ts})"
            )

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        source_account = f"victim_pt_{ring_id.lower()}@okhdfc"
        transit_mule = f"mule_transit_{ring_id.lower()}@okaxis"
        destination_account = f"cashout_pt_{ring_id.lower()}@okicici"

        # 1. Inflow transaction (Source -> Transit Mule)
        in_txn_id = self._next_txn_id()
        in_txn = Transaction(
            transaction_id=in_txn_id,
            timestamp=in_ts,
            sender_upi=source_account,
            receiver_upi=transit_mule,
            amount=in_amount,
            device_id=f"DEV_VIC_PT_{ring_id.lower()}",
            ip_address="10.4.4.1",
            transaction_type="p2p_transfer",
        )
        in_gt = TransactionGroundTruth(
            transaction_id=in_txn_id,
            is_fraud=True,
            pattern_type="RAPID_PASSTHROUGH",
            ring_id=ring_id,
        )
        pairs.append((in_txn, in_gt))

        # 2. Outflow transaction (Transit Mule -> Destination Account)
        out_txn_id = self._next_txn_id()
        out_txn = Transaction(
            transaction_id=out_txn_id,
            timestamp=out_ts,
            sender_upi=transit_mule,
            receiver_upi=destination_account,
            amount=out_amount,
            device_id=f"DEV_MULE_PT_{ring_id.lower()}",
            ip_address="10.4.4.2",
            transaction_type="p2p_transfer",
        )
        out_gt = TransactionGroundTruth(
            transaction_id=out_txn_id,
            is_fraud=True,
            pattern_type="RAPID_PASSTHROUGH",
            ring_id=ring_id,
        )
        pairs.append((out_txn, out_gt))

        return pairs

    def generate_shared_device_scenario(
        self,
        account_count: int = 4,
        shared_device_id: str = "DEV_SHARED_MULE_RING",
        ring_id: str = "RING_DEVICE_01",
        base_time: Optional[float] = None,
    ) -> List[Tuple[Transaction, TransactionGroundTruth]]:
        """
        SHARED_DEVICE Scenario: Multiple distinct UPI accounts transacting
        from the exact same device_id, exposing a coordinated syndicate.
        """
        valid_accounts = _validate_integer(account_count, "account_count", min_val=2)
        if not isinstance(shared_device_id, str) or not shared_device_id.strip():
            raise ValueError("shared_device_id must be a non-empty string")
        if not isinstance(ring_id, str) or not ring_id.strip():
            raise ValueError("ring_id must be a non-empty string")

        if base_time is None:
            valid_base_time = self.start_time + self._rng.uniform(1500.0, 3200.0)
        else:
            valid_base_time = _validate_finite_number(base_time, "base_time", min_val=0.0, allow_zero=True)

        pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []
        mules = [f"mule_dev_{ring_id.lower()}_{i:02d}@okaxis" for i in range(1, valid_accounts + 1)]
        receivers = [f"target_dev_{ring_id.lower()}_{i:02d}@oksbi" for i in range(1, valid_accounts + 1)]

        for i in range(valid_accounts):
            txn_id = self._next_txn_id()
            amount = round(self._rng.uniform(10000.0, 25000.0), 2)
            ts = round(valid_base_time + (i * 35.0) + self._rng.uniform(2.0, 8.0), 2)

            txn = Transaction(
                transaction_id=txn_id,
                timestamp=ts,
                sender_upi=mules[i],
                receiver_upi=receivers[i],
                amount=amount,
                device_id=shared_device_id,  # identical device_id across distinct accounts
                ip_address="10.5.5.1",
                transaction_type="p2p_transfer",
            )
            gt = TransactionGroundTruth(
                transaction_id=txn_id,
                is_fraud=True,
                pattern_type="SHARED_DEVICE",
                ring_id=ring_id,
            )
            pairs.append((txn, gt))

        return pairs

    def generate_dataset(
        self,
        num_normal: int = 150,
        scenarios: Optional[List[str]] = None,
        duration_seconds: float = 3600.0,
    ) -> Tuple[List[Transaction], List[TransactionGroundTruth]]:
        """
        Orchestrates full dataset generation.
        Sorts transactions chronologically while strictly preserving the 1-to-1
        transaction_id mapping with ground truth.

        Scenario Selection Rules:
        - If scenarios is None or contains "all": all 5 scenarios are selected.
        - Every scenario name must be valid ("fan_in", "fan_out", "circular_flow",
          "rapid_passthrough", "shared_device", or "all"). Any unknown name raises ValueError
          regardless of whether "all" is also present in the list.
        - Duplicate valid scenario names are deduplicated so each runs once.

        Args:
            num_normal: Number of background normal transactions (integer >= 0).
            scenarios: List of scenario names to include, or None/'all' for all.
            duration_seconds: Total time duration window for transactions (> 0).

        Returns:
            Tuple of (transactions, ground_truth) lists.
        """
        valid_normal = _validate_integer(num_normal, "num_normal", min_val=0)
        valid_duration = _validate_finite_number(duration_seconds, "duration_seconds", min_val=0.0, allow_zero=False, min_rounded_decimals=2)

        all_pairs: List[Tuple[Transaction, TransactionGroundTruth]] = []

        # 1. Generate normal traffic
        if valid_normal > 0:
            all_pairs.extend(
                self.generate_normal_traffic(
                    count=valid_normal, duration_seconds=valid_duration
                )
            )

        # 2. Validate and map scenarios
        scenario_map = {
            "fan_in": lambda: self.generate_fan_in_scenario(victim_count=5, ring_id="RING_FAN_IN_01"),
            "fan_out": lambda: self.generate_fan_out_scenario(cashout_count=5, ring_id="RING_FAN_OUT_01"),
            "circular_flow": lambda: self.generate_circular_flow_scenario(cycle_length=4, ring_id="RING_CYCLE_01"),
            "rapid_passthrough": lambda: self.generate_rapid_passthrough_scenario(ring_id="RING_PASSTHROUGH_01"),
            "shared_device": lambda: self.generate_shared_device_scenario(account_count=4, ring_id="RING_DEVICE_01"),
        }

        selected_scenarios: List[str]
        if scenarios is None:
            selected_scenarios = list(scenario_map.keys())
        else:
            if not isinstance(scenarios, list):
                raise ValueError("scenarios must be a list of strings or None")

            cleaned_names: List[str] = []
            has_all = False

            # Strict validation across all items regardless of list ordering
            for s in scenarios:
                if not isinstance(s, str):
                    raise ValueError(f"Scenario item {s!r} must be a string")
                clean = s.lower().strip()
                if clean == "all":
                    has_all = True
                elif clean in VALID_SCENARIO_NAMES:
                    if clean not in cleaned_names:
                        cleaned_names.append(clean)
                else:
                    raise ValueError(
                        f"Unknown scenario '{s}'. Valid scenarios are: {sorted(VALID_SCENARIO_NAMES)} or 'all'"
                    )

            if has_all:
                selected_scenarios = list(scenario_map.keys())
            else:
                selected_scenarios = cleaned_names

        for s_name in selected_scenarios:
            all_pairs.extend(scenario_map[s_name]())

        # 3. Sort chronologically while preserving deterministic tie-breaker
        sorted_pairs = sorted(
            all_pairs, key=lambda p: (p[0].timestamp, p[0].transaction_id)
        )

        transactions: List[Transaction] = []
        ground_truth: List[TransactionGroundTruth] = []

        for txn, gt in sorted_pairs:
            # Validate against shared schemas
            validate_transaction(txn.to_dict())
            validate_ground_truth(gt.to_dict())

            transactions.append(txn)
            ground_truth.append(gt)

        return transactions, ground_truth

    @staticmethod
    def write_dataset(
        transactions: List[Transaction],
        ground_truth: List[TransactionGroundTruth],
        txn_path: Path,
        gt_path: Path,
    ) -> Tuple[int, int]:
        """
        Writes transactions and ground-truth to separate JSONL files.

        Staged Replacement Guarantee:
        - Rejects identical transaction and ground-truth output paths.
        - Validates all records and formats JSON in memory BEFORE touching disk.
        - Writes both datasets to temporary files in the target directories and syncs them.
        - Uses os.replace() to move the temporary files into place.
        - Automatically unlinks temporary files if an error occurs during writing or staging.
        Note: While os.replace() is atomic for each individual file on Windows and POSIX,
        replacing two distinct files sequentially is not a multi-file distributed transaction;
        staging ensures neither destination is modified until all records are validated and staged.

        Returns:
            Tuple of (txn_count, gt_count) written.
        """
        if not isinstance(transactions, list):
            raise ValueError("transactions must be a list of Transaction objects")
        if not isinstance(ground_truth, list):
            raise ValueError("ground_truth must be a list of TransactionGroundTruth objects")
        if len(transactions) != len(ground_truth):
            raise ValueError(
                f"Count mismatch: {len(transactions)} transactions vs {len(ground_truth)} labels"
            )

        txn_path = Path(txn_path)
        gt_path = Path(gt_path)

        if txn_path.resolve() == gt_path.resolve():
            raise ValueError(
                f"Transaction output path and ground-truth output path cannot be identical: '{txn_path}'"
            )

        txn_lines: List[str] = []
        gt_lines: List[str] = []

        # 1. Validate all records and serialize in memory before touching disk
        for i, (txn, gt) in enumerate(zip(transactions, ground_truth)):
            if not isinstance(txn, Transaction):
                raise ValueError(f"transactions[{i}] must be a Transaction instance, got {type(txn).__name__}")
            if not isinstance(gt, TransactionGroundTruth):
                raise ValueError(f"ground_truth[{i}] must be a TransactionGroundTruth instance, got {type(gt).__name__}")

            if txn.transaction_id != gt.transaction_id:
                raise ValueError(
                    f"ID mismatch at index {i}: transaction ID '{txn.transaction_id}' != label ID '{gt.transaction_id}'"
                )

            txn_dict = txn.to_dict()
            for forbidden in ("is_fraud", "pattern_type", "ring_id"):
                if forbidden in txn_dict:
                    raise ValueError(f"Data leakage detected! {forbidden} found in transaction payload at index {i}")

            txn_lines.append(json.dumps(txn_dict, separators=(",", ":")) + "\n")
            gt_lines.append(json.dumps(gt.to_dict(), separators=(",", ":")) + "\n")

        # 2. Stage to temporary files in target directories and sync
        txn_path.parent.mkdir(parents=True, exist_ok=True)
        gt_path.parent.mkdir(parents=True, exist_ok=True)

        tmp_txn = None
        tmp_gt = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=txn_path.parent, delete=False, encoding="utf-8") as f_tmp_txn:
                tmp_txn = Path(f_tmp_txn.name)
                f_tmp_txn.writelines(txn_lines)
                f_tmp_txn.flush()
                os.fsync(f_tmp_txn.fileno())

            with tempfile.NamedTemporaryFile("w", dir=gt_path.parent, delete=False, encoding="utf-8") as f_tmp_gt:
                tmp_gt = Path(f_tmp_gt.name)
                f_tmp_gt.writelines(gt_lines)
                f_tmp_gt.flush()
                os.fsync(f_tmp_gt.fileno())

            # Atomic replace per destination file
            os.replace(tmp_txn, txn_path)
            tmp_txn = None
            os.replace(tmp_gt, gt_path)
            tmp_gt = None
        finally:
            if tmp_txn is not None and tmp_txn.exists():
                try:
                    tmp_txn.unlink()
                except OSError:
                    pass
            if tmp_gt is not None and tmp_gt.exists():
                try:
                    tmp_gt.unlink()
                except OSError:
                    pass

        return len(transactions), len(ground_truth)


def main():
    """CLI entry point for simulator/generate.py."""
    parser = argparse.ArgumentParser(
        description="RingShield Synthetic UPI Transaction and Fraud Ring Generator"
    )
    parser.add_argument(
        "--normal-count",
        type=int,
        default=150,
        help="Number of normal background transactions to generate (default: 150)",
    )
    parser.add_argument(
        "--scenarios",
        type=str,
        default="all",
        help="Comma-separated fraud scenarios or 'all' (fan_in, fan_out, circular_flow, rapid_passthrough, shared_device)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Integer random seed for deterministic generation (default: 42)",
    )
    parser.add_argument(
        "--output-txn",
        type=str,
        default="data/transactions.jsonl",
        help="Path to output transactions JSONL (default: data/transactions.jsonl)",
    )
    parser.add_argument(
        "--output-gt",
        type=str,
        default="data/ground_truth.jsonl",
        help="Path to output ground-truth JSONL (default: data/ground_truth.jsonl)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demonstration mode with small count (30 normal + all scenarios) and print sample records",
    )

    args = parser.parse_args()

    normal_count = 30 if args.demo else args.normal_count
    scenarios = None if args.scenarios == "all" else [s.strip() for s in args.scenarios.split(",")]

    generator = SyntheticTransactionGenerator(seed=args.seed)
    transactions, ground_truth = generator.generate_dataset(
        num_normal=normal_count, scenarios=scenarios
    )

    txn_count, gt_count = generator.write_dataset(
        transactions=transactions,
        ground_truth=ground_truth,
        txn_path=Path(args.output_txn),
        gt_path=Path(args.output_gt),
    )

    fraud_count = sum(1 for gt in ground_truth if gt.is_fraud)
    normal_txns = txn_count - fraud_count

    print(f"[RingShield Simulator] Generated {txn_count} transactions:")
    print(f"  - Legitimate (NORMAL): {normal_txns}")
    print(f"  - Fraudulent injected: {fraud_count}")
    print(f"  - Saved transactions to: {args.output_txn}")
    print(f"  - Saved ground-truth to: {args.output_gt}")

    if args.demo:
        print("\n--- Sample Transaction Record (No Labels) ---")
        print(json.dumps(transactions[0].to_dict(), indent=2))
        print("\n--- Matching Ground-Truth Record (Labels Only) ---")
        print(json.dumps(ground_truth[0].to_dict(), indent=2))

        # Show one fraudulent example too
        fraud_idx = next(i for i, g in enumerate(ground_truth) if g.is_fraud)
        print("\n--- Sample Fraudulent Transaction Record (No Labels) ---")
        print(json.dumps(transactions[fraud_idx].to_dict(), indent=2))
        print("\n--- Matching Fraudulent Ground-Truth Record ---")
        print(json.dumps(ground_truth[fraud_idx].to_dict(), indent=2))


if __name__ == "__main__":
    main()
