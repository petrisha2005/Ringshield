"""
tests/test_generator.py
Focused unit and integration tests for simulator/generate.py in RingShield.

Tests coverage:
- 1-to-1 matching between Transaction and TransactionGroundTruth by transaction_id
- Chronological ordering of generated transactions
- Strict zero-leakage: no fraud labels in transaction records
- Deterministic byte-for-byte reproducibility with fixed random seed
- Topology verification for each of the 5 fraud scenarios:
  1. FAN_IN
  2. FAN_OUT
  3. CIRCULAR_FLOW
  4. RAPID_PASSTHROUGH (verifying inflow, outflow, delta, and forwarding ratio)
  5. SHARED_DEVICE (verifying multi-account device reuse)
- JSONL file writing and parsing compliance with contracts
- CLI execution and demo mode
- Rejection of Boolean values where numeric counts/floats are expected
- Rejection of non-finite numeric inputs (NaN, +inf, -inf)
- Unambiguous scenario selection (including "all" with invalid names and duplicate names)
- Atomic write_dataset: pre-write validation, identical path rejection, and temporary file cleanup on failure
- Post-rounding validation for tiny positive values (amounts and delays)
- Targeted validation of window_seconds and step_delay_seconds
- Preservation of scenario causal event ordering in sorted dataset
"""

import json
import math
from pathlib import Path
import pytest
from contracts.schemas import (
    Transaction,
    TransactionGroundTruth,
    validate_transaction,
    validate_ground_truth,
)
from simulator.generate import SyntheticTransactionGenerator, main


def test_generator_one_to_one_matching_and_counts():
    """Verify that every transaction has exactly one matching ground-truth record."""
    gen = SyntheticTransactionGenerator(seed=101)
    txns, gts = gen.generate_dataset(num_normal=50, scenarios=["fan_in", "rapid_passthrough"])

    assert len(txns) == len(gts)
    assert len(txns) > 50  # 50 normal + 5 fan_in + 2 rapid_passthrough = 57

    # Check 1-to-1 transaction_id matching
    for txn, gt in zip(txns, gts):
        assert txn.transaction_id == gt.transaction_id
        assert isinstance(txn, Transaction)
        assert isinstance(gt, TransactionGroundTruth)


def test_chronological_ordering():
    """Verify generated transactions are chronologically sorted."""
    gen = SyntheticTransactionGenerator(seed=102)
    txns, gts = gen.generate_dataset(num_normal=80, scenarios=["all"])

    for i in range(len(txns) - 1):
        assert txns[i].timestamp <= txns[i + 1].timestamp
        # Ground truth matches the same order
        assert gts[i].transaction_id == txns[i].transaction_id
        assert gts[i + 1].transaction_id == txns[i + 1].transaction_id


def test_strict_zero_leakage():
    """Verify transaction dictionaries contain zero fraud labels or detector-facing leaks."""
    gen = SyntheticTransactionGenerator(seed=103)
    txns, gts = gen.generate_dataset(num_normal=20, scenarios=["all"])

    forbidden_keys = {"is_fraud", "pattern_type", "ring_id"}

    for txn in txns:
        d = txn.to_dict()
        for forbidden in forbidden_keys:
            assert forbidden not in d, f"Forbidden label '{forbidden}' leaked into transaction dict!"

        # Ensure Transaction.from_dict validates without triggering anti-leakage guard
        reconstructed = validate_transaction(d)
        assert reconstructed.transaction_id == txn.transaction_id


def test_deterministic_byte_for_byte_reproducibility(tmp_path):
    """Verify identical seeds produce byte-for-byte identical output files."""
    gen1 = SyntheticTransactionGenerator(seed=42)
    txns1, gt1 = gen1.generate_dataset(num_normal=30, scenarios=["all"])
    t1_path = tmp_path / "t1.jsonl"
    g1_path = tmp_path / "g1.jsonl"
    SyntheticTransactionGenerator.write_dataset(txns1, gt1, t1_path, g1_path)

    gen2 = SyntheticTransactionGenerator(seed=42)
    txns2, gt2 = gen2.generate_dataset(num_normal=30, scenarios=["all"])
    t2_path = tmp_path / "t2.jsonl"
    g2_path = tmp_path / "g2.jsonl"
    SyntheticTransactionGenerator.write_dataset(txns2, gt2, t2_path, g2_path)

    # Byte-for-byte comparison
    assert t1_path.read_bytes() == t2_path.read_bytes()
    assert g1_path.read_bytes() == g2_path.read_bytes()

    # Different seed produces different data
    gen3 = SyntheticTransactionGenerator(seed=999)
    txns3, gt3 = gen3.generate_dataset(num_normal=30, scenarios=["all"])
    t3_path = tmp_path / "t3.jsonl"
    g3_path = tmp_path / "g3.jsonl"
    SyntheticTransactionGenerator.write_dataset(txns3, gt3, t3_path, g3_path)
    assert t1_path.read_bytes() != t3_path.read_bytes()


def test_unique_transaction_ids():
    """Verify all transaction IDs are globally unique in a dataset."""
    gen = SyntheticTransactionGenerator(seed=104)
    txns, _ = gen.generate_dataset(num_normal=100, scenarios=["all"])
    ids = [t.transaction_id for t in txns]
    assert len(ids) == len(set(ids))


# ============================================================================
# Scenario Topology Tests
# ============================================================================

def test_fan_in_topology():
    """Verify FAN_IN generates multiple distinct senders funneling to one receiver."""
    gen = SyntheticTransactionGenerator(seed=201)
    pairs = gen.generate_fan_in_scenario(victim_count=6, ring_id="TEST_FAN_IN")
    assert len(pairs) == 6

    txns = [p[0] for p in pairs]
    gts = [p[1] for p in pairs]

    receivers = {t.receiver_upi for t in txns}
    senders = {t.sender_upi for t in txns}

    # Exactly one aggregator mule
    assert len(receivers) == 1
    # Exactly 6 distinct victims
    assert len(senders) == 6

    for gt in gts:
        assert gt.is_fraud is True
        assert gt.pattern_type == "FAN_IN"
        assert gt.ring_id == "TEST_FAN_IN"


def test_fan_out_topology():
    """Verify FAN_OUT generates one sender dispersing to multiple distinct receivers."""
    gen = SyntheticTransactionGenerator(seed=202)
    pairs = gen.generate_fan_out_scenario(cashout_count=5, ring_id="TEST_FAN_OUT")
    assert len(pairs) == 5

    txns = [p[0] for p in pairs]
    gts = [p[1] for p in pairs]

    senders = {t.sender_upi for t in txns}
    receivers = {t.receiver_upi for t in txns}

    # Exactly one disperser mule
    assert len(senders) == 1
    # Exactly 5 distinct cash-out targets
    assert len(receivers) == 5

    for gt in gts:
        assert gt.is_fraud is True
        assert gt.pattern_type == "FAN_OUT"


def test_circular_flow_topology():
    """Verify CIRCULAR_FLOW forms a closed directed cycle of transactions."""
    gen = SyntheticTransactionGenerator(seed=203)
    pairs = gen.generate_circular_flow_scenario(cycle_length=4, ring_id="TEST_CYCLE")
    assert len(pairs) == 4

    txns = [p[0] for p in pairs]

    # Verify chain: receiver of hop i is sender of hop i+1, and last receiver is first sender
    for i in range(3):
        assert txns[i].receiver_upi == txns[i + 1].sender_upi
        assert txns[i].timestamp < txns[i + 1].timestamp
    assert txns[3].receiver_upi == txns[0].sender_upi


def test_rapid_passthrough_topology():
    """
    Verify RAPID_PASSTHROUGH generates both inflow and outflow with
    measurable time delta and forwarding ratio.
    """
    gen = SyntheticTransactionGenerator(seed=204)
    inflow_amt = 50000.0
    pass_ratio = 0.95
    delay_sec = 30.0

    pairs = gen.generate_rapid_passthrough_scenario(
        ring_id="TEST_PT",
        inflow_amount=inflow_amt,
        pass_ratio=pass_ratio,
        delay_seconds=delay_sec,
    )
    assert len(pairs) == 2

    in_txn, in_gt = pairs[0]
    out_txn, out_gt = pairs[1]

    # The receiver of inflow is the sender of outflow (the transit mule)
    assert in_txn.receiver_upi == out_txn.sender_upi
    # Origin and destination are distinct
    assert in_txn.sender_upi != out_txn.receiver_upi

    # Measurable time delta
    time_delta = round(out_txn.timestamp - in_txn.timestamp, 2)
    assert time_delta == delay_sec

    # Measurable forwarding ratio
    actual_ratio = round(out_txn.amount / in_txn.amount, 2)
    assert actual_ratio == pass_ratio

    assert in_gt.pattern_type == "RAPID_PASSTHROUGH"
    assert out_gt.pattern_type == "RAPID_PASSTHROUGH"


def test_shared_device_topology():
    """Verify SHARED_DEVICE generates distinct accounts transacting from the same device_id."""
    gen = SyntheticTransactionGenerator(seed=205)
    shared_dev = "DEV_MULE_RING_999"
    pairs = gen.generate_shared_device_scenario(
        account_count=4, shared_device_id=shared_dev, ring_id="TEST_DEV"
    )
    assert len(pairs) == 4

    txns = [p[0] for p in pairs]
    senders = {t.sender_upi for t in txns}
    devices = {t.device_id for t in txns}

    # Distinct accounts
    assert len(senders) == 4
    # Single shared device
    assert devices == {shared_dev}


def test_write_dataset_and_jsonl_parsing(tmp_path):
    """Verify generated JSONL files can be cleanly parsed and validated."""
    gen = SyntheticTransactionGenerator(seed=301)
    txns, gts = gen.generate_dataset(num_normal=25, scenarios=["all"])

    txn_file = tmp_path / "transactions.jsonl"
    gt_file = tmp_path / "ground_truth.jsonl"

    n_txns, n_gts = SyntheticTransactionGenerator.write_dataset(
        txns, gts, txn_file, gt_file
    )
    assert n_txns == len(txns)
    assert n_gts == len(gts)

    # Read and validate transactions
    with open(txn_file, "r", encoding="utf-8") as f:
        read_txns = [validate_transaction(json.loads(line)) for line in f]
    assert len(read_txns) == n_txns

    # Read and validate ground-truth
    with open(gt_file, "r", encoding="utf-8") as f:
        read_gts = [validate_ground_truth(json.loads(line)) for line in f]
    assert len(read_gts) == n_gts

    for t, g in zip(read_txns, read_gts):
        assert t.transaction_id == g.transaction_id


def test_cli_demo(tmp_path, monkeypatch, capsys):
    """Test CLI execution in demo mode."""
    t_path = tmp_path / "demo_txns.jsonl"
    g_path = tmp_path / "demo_gt.jsonl"

    test_args = [
        "generate.py",
        "--demo",
        "--seed",
        "42",
        "--output-txn",
        str(t_path),
        "--output-gt",
        str(g_path),
    ]
    monkeypatch.setattr("sys.argv", test_args)

    main()
    captured = capsys.readouterr()

    assert "[RingShield Simulator] Generated" in captured.out
    assert t_path.exists()
    assert g_path.exists()


# ============================================================================
# Validation, Boolean Rejection, Non-Finite, and Error Handling Tests
# ============================================================================

def test_boolean_and_type_rejection():
    """Verify that Boolean values are explicitly rejected where numeric values are expected."""
    # Booleans in generator constructor
    with pytest.raises(ValueError, match="seed must be an integer"):
        SyntheticTransactionGenerator(seed=True)

    with pytest.raises(ValueError, match="start_time must be a numeric value"):
        SyntheticTransactionGenerator(start_time=False)

    with pytest.raises(ValueError, match="user_pool_size must be an integer"):
        SyntheticTransactionGenerator(user_pool_size=True)

    with pytest.raises(ValueError, match="merchant_pool_size must be an integer"):
        SyntheticTransactionGenerator(merchant_pool_size=False)

    gen = SyntheticTransactionGenerator(seed=42)

    # Booleans in method parameters
    with pytest.raises(ValueError, match="count must be an integer"):
        gen.generate_normal_traffic(count=True)

    with pytest.raises(ValueError, match="duration_seconds must be a numeric value"):
        gen.generate_normal_traffic(duration_seconds=False)

    with pytest.raises(ValueError, match="num_normal must be an integer"):
        gen.generate_dataset(num_normal=True)

    with pytest.raises(ValueError, match="victim_count must be an integer"):
        gen.generate_fan_in_scenario(victim_count=True)

    with pytest.raises(ValueError, match="window_seconds must be a numeric value"):
        gen.generate_fan_in_scenario(window_seconds=False)

    with pytest.raises(ValueError, match="inflow_amount must be a numeric value"):
        gen.generate_rapid_passthrough_scenario(inflow_amount=True)

    with pytest.raises(ValueError, match="pass_ratio must be a numeric value"):
        gen.generate_rapid_passthrough_scenario(pass_ratio=True)

    with pytest.raises(ValueError, match="delay_seconds must be a numeric value"):
        gen.generate_rapid_passthrough_scenario(delay_seconds=True)


def test_non_finite_numeric_inputs():
    """Verify NaN, +Inf, -Inf are rejected across all numeric configuration inputs."""
    with pytest.raises(ValueError, match="start_time must be a finite number"):
        SyntheticTransactionGenerator(start_time=math.nan)

    with pytest.raises(ValueError, match="start_time must be a finite number"):
        SyntheticTransactionGenerator(start_time=float("inf"))

    gen = SyntheticTransactionGenerator(seed=42)

    with pytest.raises(ValueError, match="duration_seconds must be a finite number"):
        gen.generate_normal_traffic(duration_seconds=math.nan)

    with pytest.raises(ValueError, match="base_time must be a finite number"):
        gen.generate_fan_in_scenario(base_time=float("-inf"))

    with pytest.raises(ValueError, match="inflow_amount must be a finite number"):
        gen.generate_rapid_passthrough_scenario(inflow_amount=float("inf"))

    with pytest.raises(ValueError, match="pass_ratio must be a finite number"):
        gen.generate_rapid_passthrough_scenario(pass_ratio=math.nan)


def test_scenario_selection_unambiguous():
    """
    Verify scenario selection rules:
    - 'all' expands to all scenarios.
    - 'all' mixed with invalid names raises ValueError regardless of position.
    - Duplicates of valid scenario names are deduplicated cleanly.
    - Non-string or non-list input raises ValueError.
    """
    gen = SyntheticTransactionGenerator(seed=42)

    # 1. 'all' alone
    _, gt_all = gen.generate_dataset(num_normal=0, scenarios=["all"])
    pattern_types = {g.pattern_type for g in gt_all}
    assert pattern_types == {"FAN_IN", "FAN_OUT", "CIRCULAR_FLOW", "RAPID_PASSTHROUGH", "SHARED_DEVICE"}

    # 2. 'all' combined with an invalid name (first or last) must raise ValueError
    with pytest.raises(ValueError, match="Unknown scenario 'invalid_name'"):
        gen.generate_dataset(scenarios=["all", "invalid_name"])

    with pytest.raises(ValueError, match="Unknown scenario 'invalid_name'"):
        gen.generate_dataset(scenarios=["invalid_name", "all"])

    # 3. Duplicate valid scenario names should be deduplicated
    _, gt_dup = gen.generate_dataset(num_normal=0, scenarios=["fan_in", "fan_in", "fan_in"])
    assert len(gt_dup) == 5  # Exactly 1 fan_in scenario (5 victims)

    # 4. Invalid container types
    with pytest.raises(ValueError, match="scenarios must be a list"):
        gen.generate_dataset(scenarios="fan_in")  # string instead of list

    with pytest.raises(ValueError, match="Scenario item 123 must be a string"):
        gen.generate_dataset(scenarios=[123])


def test_post_rounding_validation():
    """Verify that tiny positive numbers rounding to zero or eliminating time deltas are rejected."""
    gen = SyntheticTransactionGenerator(seed=42)

    # Inflow amount rounding to 0.00
    with pytest.raises(ValueError, match="must remain strictly positive.*rounding to 2 decimal places"):
        gen.generate_rapid_passthrough_scenario(inflow_amount=0.001)

    # Outflow amount rounding to 0.00 due to tiny pass ratio
    with pytest.raises(ValueError, match="produces a rounded outflow of 0.00"):
        gen.generate_rapid_passthrough_scenario(inflow_amount=10.0, pass_ratio=0.0001)

    # Delay seconds rounding to 0.00 eliminating the time difference
    with pytest.raises(ValueError, match="must remain strictly positive.*rounding to 2 decimal places"):
        gen.generate_rapid_passthrough_scenario(delay_seconds=0.001)

    # Circular flow base amount rounding to 0.00
    with pytest.raises(ValueError, match="must remain strictly positive.*rounding to 2 decimal places"):
        gen.generate_circular_flow_scenario(base_amount=0.004)

    # Circular flow step delay rounding to 0.00
    with pytest.raises(ValueError, match="must remain strictly positive.*rounding to 2 decimal places"):
        gen.generate_circular_flow_scenario(step_delay_seconds=0.001)


def test_targeted_window_and_step_delay_validation():
    """Verify window_seconds and step_delay_seconds validate <= 0, non-finite, and tiny values."""
    gen = SyntheticTransactionGenerator(seed=42)

    # window_seconds in fan_in
    with pytest.raises(ValueError, match="window_seconds must be strictly > 0.0"):
        gen.generate_fan_in_scenario(window_seconds=0)

    with pytest.raises(ValueError, match="window_seconds must be a finite number"):
        gen.generate_fan_in_scenario(window_seconds=math.nan)

    with pytest.raises(ValueError, match="window_seconds must be strictly > 0.0"):
        gen.generate_fan_in_scenario(window_seconds=-5.0)

    with pytest.raises(ValueError, match="must remain strictly positive.*rounding to 2 decimal places"):
        gen.generate_fan_in_scenario(window_seconds=0.001)

    # window_seconds in fan_out
    with pytest.raises(ValueError, match="window_seconds must be strictly > 0.0"):
        gen.generate_fan_out_scenario(window_seconds=0)

    with pytest.raises(ValueError, match="window_seconds must be a finite number"):
        gen.generate_fan_out_scenario(window_seconds=float("inf"))

    # step_delay_seconds in circular flow
    with pytest.raises(ValueError, match="step_delay_seconds must be strictly > 0.0"):
        gen.generate_circular_flow_scenario(step_delay_seconds=0)

    with pytest.raises(ValueError, match="step_delay_seconds must be a finite number"):
        gen.generate_circular_flow_scenario(step_delay_seconds=math.nan)


def test_identical_output_paths_rejected(tmp_path):
    """Verify that providing identical transaction and ground-truth paths is rejected."""
    gen = SyntheticTransactionGenerator(seed=42)
    txns, gts = gen.generate_dataset(num_normal=5, scenarios=["rapid_passthrough"])

    same_path = tmp_path / "same_file.jsonl"
    with pytest.raises(ValueError, match="Transaction output path and ground-truth output path cannot be identical"):
        SyntheticTransactionGenerator.write_dataset(txns, gts, same_path, same_path)


def test_atomic_write_dataset_and_staging_cleanup_on_failure(tmp_path, monkeypatch):
    """
    Verify that write_dataset validates all records BEFORE writing, and
    if an error occurs during temporary-file staging, no temporary files remain
    and destination files are not created or modified.
    """
    gen = SyntheticTransactionGenerator(seed=42)
    txns, gts = gen.generate_dataset(num_normal=5, scenarios=["rapid_passthrough"])

    # Case 1: Corrupted record detected in pre-write validation
    corrupted_gts = list(gts)
    corrupted_gts[3] = TransactionGroundTruth(
        transaction_id="TXN_CORRUPT_MISMATCH",
        is_fraud=True,
        pattern_type="FAN_IN",
    )

    t_file = tmp_path / "stage_txns.jsonl"
    g_file = tmp_path / "stage_gts.jsonl"

    # Seed destination files with sentinel text
    t_file.write_text("SENTINEL_TXN", encoding="utf-8")
    g_file.write_text("SENTINEL_GT", encoding="utf-8")

    with pytest.raises(ValueError, match="ID mismatch at index 3"):
        SyntheticTransactionGenerator.write_dataset(txns, corrupted_gts, t_file, g_file)

    # Verify sentinel files were NOT overwritten
    assert t_file.read_text(encoding="utf-8") == "SENTINEL_TXN"
    assert g_file.read_text(encoding="utf-8") == "SENTINEL_GT"

    # Case 2: Simulated OS error during temporary staging cleanup
    def mock_fsync_fail(fd):
        raise OSError("Simulated disk flush failure")

    monkeypatch.setattr("os.fsync", mock_fsync_fail)

    with pytest.raises(OSError, match="Simulated disk flush failure"):
        SyntheticTransactionGenerator.write_dataset(txns, gts, t_file, g_file)

    # Verify no temporary files remain in tmp_path
    remaining_files = list(tmp_path.glob("tmp*")) + list(tmp_path.glob("*.tmp"))
    assert len(remaining_files) == 0

    # Destination files still untouched
    assert t_file.read_text(encoding="utf-8") == "SENTINEL_TXN"
    assert g_file.read_text(encoding="utf-8") == "SENTINEL_GT"


def test_sorted_dataset_preserves_causal_order_of_scenarios():
    """
    Verify that in a large dataset with normal transactions interleaved,
    the causal event sequence within each fraud ring remains strictly valid.
    """
    gen = SyntheticTransactionGenerator(seed=403)
    txns, gts = gen.generate_dataset(
        num_normal=200, scenarios=["rapid_passthrough", "circular_flow"]
    )

    # 1. Verify rapid pass-through causal order
    pt_indices = [
        i for i, g in enumerate(gts) if g.pattern_type == "RAPID_PASSTHROUGH"
    ]
    assert len(pt_indices) == 2
    inflow_idx, outflow_idx = pt_indices[0], pt_indices[1]
    assert inflow_idx < outflow_idx
    assert txns[inflow_idx].timestamp < txns[outflow_idx].timestamp
    assert txns[inflow_idx].receiver_upi == txns[outflow_idx].sender_upi

    # 2. Verify circular flow causal order
    cycle_indices = [
        i for i, g in enumerate(gts) if g.pattern_type == "CIRCULAR_FLOW"
    ]
    assert len(cycle_indices) == 4
    for k in range(len(cycle_indices) - 1):
        idx_current = cycle_indices[k]
        idx_next = cycle_indices[k + 1]
        assert idx_current < idx_next
        assert txns[idx_current].timestamp < txns[idx_next].timestamp
        assert txns[idx_current].receiver_upi == txns[idx_next].sender_upi
