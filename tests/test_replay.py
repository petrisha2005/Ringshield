"""Unit and integration tests for local offline transaction replay."""

import json
from pathlib import Path
import subprocess
import sys

import pytest

from streaming.replay import (
    ReplaySummary,
    calculate_percentiles,
    replay_transactions,
)


def test_calculate_percentiles_empty():
    res = calculate_percentiles([])
    assert res["p50"] == 0.0
    assert res["p95"] == 0.0
    assert res["p99"] == 0.0
    assert res["mean"] == 0.0


def test_calculate_percentiles_single_sample():
    res = calculate_percentiles([1.25])
    assert res["p50"] == 1.25
    assert res["p95"] == 1.25
    assert res["p99"] == 1.25
    assert res["mean"] == 1.25


def test_calculate_percentiles_multi_sample():
    data = [float(i) for i in range(1, 101)]  # 1.0 to 100.0
    res = calculate_percentiles(data)
    assert res["p50"] == 50.5
    assert res["p95"] == 95.05
    assert res["p99"] == 99.01
    assert res["mean"] == 50.5


def test_missing_input_file_raises_filenotfound(tmp_path: Path):
    missing_file = tmp_path / "does_not_exist.jsonl"
    out_file = tmp_path / "alerts.jsonl"
    with pytest.raises(FileNotFoundError, match="not found"):
        replay_transactions(input_path=missing_file, output_path=out_file)


def test_normal_transactions_no_alerts(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    txs = [
        {
            "transaction_id": f"norm_{i}",
            "sender_id": f"user_{i}@upi",
            "receiver_id": "merchant@upi",
            "amount": 100.0 * i,
            "timestamp": f"2026-10-23T10:0{i}:00Z",
        }
        for i in range(1, 4)
    ]
    in_file.write_text("\n".join(json.dumps(t) for t in txs) + "\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)

    assert summary.total_records_read == 3
    assert summary.successfully_processed == 3
    assert summary.alerts_generated == 0
    assert summary.invalid_records == 0
    assert summary.total_detector_time_ms > 0
    assert summary.throughput_records_per_sec > 0

    # Output file should exist and be empty
    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8").strip() == ""


def test_high_value_alert_generation(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    txs = [
        {
            "transaction_id": "norm_01",
            "sender_id": "alice@upi",
            "receiver_id": "bob@upi",
            "amount": 500.0,
            "timestamp": "2026-10-23T10:00:00Z",
        },
        {
            "transaction_id": "high_01",
            "sender_id": "whale@upi",
            "receiver_id": "escrow@upi",
            "amount": 150000.0,
            "timestamp": "2026-10-23T10:00:10Z",
        },
    ]
    in_file.write_text("\n".join(json.dumps(t) for t in txs) + "\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)

    assert summary.total_records_read == 2
    assert summary.successfully_processed == 2
    assert summary.alerts_generated == 1
    assert summary.invalid_records == 0

    lines = [line.strip() for line in out_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    alert = json.loads(lines[0])
    assert alert["transaction_id"] == "high_01"
    assert "HIGH_VALUE_TRANSACTION" in alert["risk_reasons"]


def test_rapid_repeated_transfer_alert_generation(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    sender = "burst_user@upi"
    txs = [
        {
            "transaction_id": f"burst_{i}",
            "sender_id": sender,
            "receiver_id": f"merchant_{i}@upi",
            "amount": 1000.0,
            "timestamp": f"2026-10-23T10:00:{i*10:02d}Z",
        }
        for i in range(1, 6)
    ]
    in_file.write_text("\n".join(json.dumps(t) for t in txs) + "\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)

    assert summary.total_records_read == 5
    assert summary.successfully_processed == 5
    # The 5th transaction should trigger RAPID_REPEATED_TRANSFERS
    assert summary.alerts_generated == 1
    assert summary.invalid_records == 0

    lines = [line.strip() for line in out_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 1
    alert = json.loads(lines[0])
    assert alert["transaction_id"] == "burst_5"
    assert "RAPID_REPEATED_TRANSFERS" in alert["risk_reasons"]


def test_malformed_json_skipped_and_counted(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    valid_1 = json.dumps({
        "transaction_id": "v1",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "amount": 200.0,
        "timestamp": "2026-10-23T10:00:00Z",
    })
    malformed = "{ this is definitely not valid json "
    valid_2 = json.dumps({
        "transaction_id": "v2",
        "sender_id": "u3@upi",
        "receiver_id": "u4@upi",
        "amount": 300.0,
        "timestamp": "2026-10-23T10:00:05Z",
    })

    in_file.write_text(f"{valid_1}\n{malformed}\n{valid_2}\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)

    assert summary.total_records_read == 3
    assert summary.successfully_processed == 2
    assert summary.invalid_records == 1
    assert summary.alerts_generated == 0


def test_invalid_schema_skipped_and_counted(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    # 1. Missing amount
    inv_1 = json.dumps({
        "transaction_id": "inv_1",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "timestamp": "2026-10-23T10:00:00Z",
    })
    # 2. Same sender and receiver
    inv_2 = json.dumps({
        "transaction_id": "inv_2",
        "sender_id": "u1@upi",
        "receiver_id": "u1@upi",
        "amount": 500.0,
        "timestamp": "2026-10-23T10:00:05Z",
    })
    # 3. Non-positive amount
    inv_3 = json.dumps({
        "transaction_id": "inv_3",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "amount": -50.0,
        "timestamp": "2026-10-23T10:00:10Z",
    })
    # 4. Valid record
    valid = json.dumps({
        "transaction_id": "valid_1",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "amount": 50.0,
        "timestamp": "2026-10-23T10:00:15Z",
    })

    in_file.write_text(f"{inv_1}\n{inv_2}\n{inv_3}\n{valid}\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)

    assert summary.total_records_read == 4
    assert summary.successfully_processed == 1
    assert summary.invalid_records == 3
    assert summary.alerts_generated == 0


def test_replay_overwrites_existing_output_file(tmp_path: Path):
    in_file = tmp_path / "in.jsonl"
    out_file = tmp_path / "out.jsonl"

    # Pre-populate out_file with stale data
    out_file.write_text('{"stale": "alert"}\n', encoding="utf-8")

    valid = json.dumps({
        "transaction_id": "t1",
        "sender_id": "u1@upi",
        "receiver_id": "u2@upi",
        "amount": 100.0,
        "timestamp": "2026-10-23T10:00:00Z",
    })
    in_file.write_text(f"{valid}\n", encoding="utf-8")

    summary = replay_transactions(input_path=in_file, output_path=out_file)
    assert summary.alerts_generated == 0

    # Old stale alert must be gone
    content = out_file.read_text(encoding="utf-8").strip()
    assert content == ""


def test_demo_dataset_replay_end_to_end():
    # Verify the actual project dataset in data/transactions.jsonl
    in_path = Path("data/transactions.jsonl")
    assert in_path.exists(), "data/transactions.jsonl must exist"

    summary = replay_transactions(
        input_path="data/transactions.jsonl",
        output_path="data/alerts.jsonl",
    )

    assert summary.total_records_read == 25
    assert summary.successfully_processed == 25
    assert summary.alerts_generated == 5
    assert summary.invalid_records == 0
    assert summary.mean_latency_ms > 0
    assert summary.throughput_records_per_sec > 0

    # Validate output alert file
    out_path = Path("data/alerts.jsonl")
    assert out_path.exists()
    alerts = [json.loads(line) for line in out_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(alerts) == 5

    # Check alert reasons
    reasons_found = set()
    for alert in alerts:
        reasons_found.update(alert.get("risk_reasons", []))
    assert "HIGH_VALUE_TRANSACTION" in reasons_found
    assert "RAPID_REPEATED_TRANSFERS" in reasons_found


def test_cli_execution_success(tmp_path: Path):
    in_file = tmp_path / "cli_in.jsonl"
    out_file = tmp_path / "cli_out.jsonl"

    in_file.write_text(
        json.dumps({
            "transaction_id": "cli_tx",
            "sender_id": "a@upi",
            "receiver_id": "b@upi",
            "amount": 250000.0,
            "timestamp": "2026-10-23T10:00:00Z",
        }) + "\n",
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "streaming.replay",
            "-i",
            str(in_file),
            "-o",
            str(out_file),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "RingShield Offline Transaction Replay Summary" in proc.stdout
    assert "Fraud alerts generated:     1" in proc.stdout
    assert out_file.exists()


def test_cli_execution_missing_file():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "streaming.replay",
            "-i",
            "nonexistent_file_xyz_123.jsonl",
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "Error: Input transaction file not found" in proc.stderr
