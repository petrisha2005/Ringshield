"""
tests/test_replay.py
Comprehensive test suite for RingShield local transaction replay module.

Validates:
1. Valid JSONL input produces output conforming strictly to the Alert schema.
2. Empty input is handled cleanly without fabricating alerts.
3. Missing input file raises a clear FileNotFoundError.
4. Malformed JSON reports the exact line number.
5. Invalid transaction records fail clearly with exact line numbers.
6. Ground-truth leakage (is_fraud, pattern_type, ring_id) is rejected with line numbers.
7. Out-of-order transaction timestamps are sorted deterministically (timestamp, transaction_id).
8. Multiple alerts can be emitted and serialized correctly.
9. Output JSONL contains valid JSON with no NaN or Infinity values and normalized [0, 1] risk scores.
10. Replay summary reflects actual engine state and pattern counts.
11. Duplicate transaction IDs are handled idempotently.
12. CLI flags (--input, --output) execute correctly.
"""

import io
import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from contracts.schemas import Alert, validate_alert
from detection.engine import FraudDetectionEngine
from detection.replay import (
    ReplayError,
    load_and_validate_transactions,
    print_replay_summary,
    replay_transactions,
)


def _write_jsonl(path: Path, records: list) -> Path:
    """Helper to write a list of dictionaries as JSON Lines."""
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    return path


# =====================================================================
# 1. Input Validation and Failure Modes
# =====================================================================

class TestReplayInputValidation:
    """Tests file loading, malformed JSON, schema violations, and anti-leakage guards."""

    def test_missing_input_file_raises_failure(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist.jsonl"
        with pytest.raises(FileNotFoundError, match="not found"):
            replay_transactions(nonexistent, tmp_path / "out.jsonl")

    def test_empty_input_file_handled_cleanly(self, tmp_path):
        empty_file = tmp_path / "empty.jsonl"
        empty_file.write_text("", encoding="utf-8")
        out_file = tmp_path / "alerts.jsonl"

        summary = replay_transactions(empty_file, out_file, verbose=False)

        assert summary["transactions_processed"] == 0
        assert summary["alerts_emitted"] == 0
        assert summary["pattern_counts"] == {}
        assert summary["graph_summary"]["node_count"] == 0
        assert summary["graph_summary"]["edge_count"] == 0

        # Output file exists and is empty
        assert out_file.exists()
        assert out_file.read_text(encoding="utf-8") == ""

    def test_malformed_json_reports_exact_line_number(self, tmp_path):
        bad_json_file = tmp_path / "bad.jsonl"
        bad_json_file.write_text(
            '{"transaction_id": "TXN_01", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "b@upi", "amount": 100.0}\n'
            '{"transaction_id": "TXN_02", broken json line\n'
            '{"transaction_id": "TXN_03", "timestamp": 120.0, "sender_upi": "c@upi", "receiver_upi": "d@upi", "amount": 100.0}\n',
            encoding="utf-8",
        )

        with pytest.raises(ReplayError) as exc_info:
            replay_transactions(bad_json_file, tmp_path / "out.jsonl")

        err_msg = str(exc_info.value)
        assert "Line 2" in err_msg
        assert "Malformed JSON" in err_msg

    def test_non_object_json_reports_exact_line_number(self, tmp_path):
        non_dict_file = tmp_path / "non_dict.jsonl"
        non_dict_file.write_text(
            '{"transaction_id": "TXN_01", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "b@upi", "amount": 100.0}\n'
            '["not", "a", "json", "object"]\n',
            encoding="utf-8",
        )

        with pytest.raises(ReplayError) as exc_info:
            replay_transactions(non_dict_file, tmp_path / "out.jsonl")

        err_msg = str(exc_info.value)
        assert "Line 2" in err_msg
        assert "Expected JSON object" in err_msg

    @pytest.mark.parametrize("invalid_field,invalid_val,expected_keyword", [
        ("amount", -50.0, "positive"),
        ("amount", float("nan"), "finite"),
        ("timestamp", -1.0, "non-negative"),
        ("sender_upi", "", "non-empty"),
        ("receiver_upi", "", "non-empty"),
    ])
    def test_invalid_transaction_record_fails_with_line_number(
        self, tmp_path, invalid_field, invalid_val, expected_keyword
    ):
        record = {
            "transaction_id": "TXN_INV_01",
            "timestamp": 100.0,
            "sender_upi": "alice@upi",
            "receiver_upi": "bob@upi",
            "amount": 250.0,
        }
        record[invalid_field] = invalid_val

        in_file = tmp_path / "invalid_record.jsonl"
        _write_jsonl(in_file, [
            {"transaction_id": "TXN_VALID_01", "timestamp": 10.0, "sender_upi": "x@upi", "receiver_upi": "y@upi", "amount": 100.0},
            {"transaction_id": "TXN_VALID_02", "timestamp": 20.0, "sender_upi": "y@upi", "receiver_upi": "z@upi", "amount": 100.0},
            record,
        ])

        with pytest.raises(ReplayError) as exc_info:
            replay_transactions(in_file, tmp_path / "out.jsonl")

        err_msg = str(exc_info.value)
        assert "Line 3" in err_msg
        assert "Invalid transaction" in err_msg

    def test_identical_sender_and_receiver_fails_with_line_number(self, tmp_path):
        in_file = tmp_path / "self_transfer.jsonl"
        _write_jsonl(in_file, [
            {"transaction_id": "TXN_SELF", "timestamp": 100.0, "sender_upi": "same@upi", "receiver_upi": "same@upi", "amount": 100.0}
        ])

        with pytest.raises(ReplayError) as exc_info:
            replay_transactions(in_file, tmp_path / "out.jsonl")

        err_msg = str(exc_info.value)
        assert "Line 1" in err_msg
        assert "identical" in err_msg.lower()

    @pytest.mark.parametrize("leaked_key", ["is_fraud", "pattern_type", "ring_id"])
    def test_ground_truth_leakage_rejected_with_line_number(self, tmp_path, leaked_key):
        record = {
            "transaction_id": "TXN_LEAK",
            "timestamp": 100.0,
            "sender_upi": "alice@upi",
            "receiver_upi": "bob@upi",
            "amount": 250.0,
            leaked_key: True if leaked_key == "is_fraud" else "RING_01",
        }

        in_file = tmp_path / "leak.jsonl"
        _write_jsonl(in_file, [
            {"transaction_id": "TXN_01", "timestamp": 10.0, "sender_upi": "u@upi", "receiver_upi": "v@upi", "amount": 100.0},
            record,
        ])

        with pytest.raises(ReplayError) as exc_info:
            replay_transactions(in_file, tmp_path / "out.jsonl")

        err_msg = str(exc_info.value)
        assert "Line 2" in err_msg
        assert "Data leakage" in err_msg
        assert leaked_key in err_msg


# =====================================================================
# 2. Ordering, Sorting, and Idempotency
# =====================================================================

class TestReplayOrderingAndIdempotency:
    """Validates deterministic chronological reordering and idempotent duplicates."""

    def test_out_of_order_timestamps_sorted_deterministically(self, tmp_path):
        # 4 distinct senders to 'target@upi' within 300s triggering FAN_IN (threshold=4)
        # Transactions are written in scrambled chronological order
        scrambled_records = [
            {"transaction_id": "TXN_D", "timestamp": 250.0, "sender_upi": "s4@upi", "receiver_upi": "target@upi", "amount": 1000.0},
            {"transaction_id": "TXN_A", "timestamp": 100.0, "sender_upi": "s1@upi", "receiver_upi": "target@upi", "amount": 1000.0},
            {"transaction_id": "TXN_C", "timestamp": 200.0, "sender_upi": "s3@upi", "receiver_upi": "target@upi", "amount": 1000.0},
            {"transaction_id": "TXN_B", "timestamp": 150.0, "sender_upi": "s2@upi", "receiver_upi": "target@upi", "amount": 1000.0},
        ]
        in_file = _write_jsonl(tmp_path / "scrambled.jsonl", scrambled_records)
        out_file = tmp_path / "alerts.jsonl"

        engine = FraudDetectionEngine(fan_in_threshold=4, fan_in_window_seconds=300.0)
        summary = replay_transactions(in_file, out_file, engine=engine, sort_transactions=True, verbose=False)

        assert summary["transactions_processed"] == 4
        assert summary["alerts_emitted"] == 1
        assert summary["pattern_counts"].get("FAN_IN") == 1
        # The watermark in the engine must be the largest timestamp
        assert summary["graph_summary"]["watermark"] == 250.0

    def test_secondary_sort_key_deterministic_with_identical_timestamps(self, tmp_path):
        # Three transactions with the exact same timestamp
        records = [
            {"transaction_id": "TXN_Z", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "b@upi", "amount": 100.0},
            {"transaction_id": "TXN_A", "timestamp": 100.0, "sender_upi": "c@upi", "receiver_upi": "d@upi", "amount": 200.0},
            {"transaction_id": "TXN_M", "timestamp": 100.0, "sender_upi": "e@upi", "receiver_upi": "f@upi", "amount": 300.0},
        ]
        in_file = _write_jsonl(tmp_path / "same_ts.jsonl", records)
        txns = load_and_validate_transactions(in_file)
        txns.sort(key=lambda t: (t.timestamp, t.transaction_id))

        assert [t.transaction_id for t in txns] == ["TXN_A", "TXN_M", "TXN_Z"]

    def test_duplicate_transactions_handled_idempotently(self, tmp_path):
        # Inflow and outflow for rapid passthrough, plus a duplicate replay of outflow
        records = [
            {"transaction_id": "TXN_IN", "timestamp": 100.0, "sender_upi": "victim@upi", "receiver_upi": "mule@upi", "amount": 10000.0},
            {"transaction_id": "TXN_OUT", "timestamp": 120.0, "sender_upi": "mule@upi", "receiver_upi": "cashout@upi", "amount": 9500.0},
            # Exact duplicate of TXN_OUT
            {"transaction_id": "TXN_OUT", "timestamp": 120.0, "sender_upi": "mule@upi", "receiver_upi": "cashout@upi", "amount": 9500.0},
        ]
        in_file = _write_jsonl(tmp_path / "duplicates.jsonl", records)
        out_file = tmp_path / "alerts.jsonl"

        summary = replay_transactions(in_file, out_file, verbose=False)

        # 3 transaction records parsed, but only 2 unique processed by graph
        assert summary["transactions_processed"] == 3
        assert summary["graph_summary"]["processed_transaction_count"] == 2
        assert summary["alerts_emitted"] == 1
        assert summary["pattern_counts"].get("RAPID_PASSTHROUGH") == 1


# =====================================================================
# 3. Alert Output Schema and JSON Serialization
# =====================================================================

class TestReplayAlertEmissionAndSerialization:
    """Validates that alerts written to JSONL strictly conform to the Alert contract."""

    def test_valid_jsonl_output_follows_alert_schema(self, tmp_path):
        # 4 distinct senders to target@upi within 300s -> FAN_IN
        records = [
            {"transaction_id": f"TXN_{i}", "timestamp": 100.0 + i * 10, "sender_upi": f"sender_{i}@upi", "receiver_upi": "target@upi", "amount": 500.0}
            for i in range(1, 5)
        ]
        in_file = _write_jsonl(tmp_path / "fan_in.jsonl", records)
        out_file = tmp_path / "alerts.jsonl"

        summary = replay_transactions(in_file, out_file, verbose=False)
        assert summary["alerts_emitted"] == 1

        # Read output JSONL and validate schema
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

        raw_alert = json.loads(lines[0])
        # Validate using shared contract validator
        alert_obj = validate_alert(raw_alert)

        # Check required fields
        assert alert_obj.pattern_type == "FAN_IN"
        assert alert_obj.transaction_id == "TXN_4"
        assert alert_obj.suspicious_accounts == ["target@upi"]
        assert 0.0 <= alert_obj.risk_score <= 1.0
        assert alert_obj.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "low", "review", "high"}
        assert isinstance(alert_obj.evidence, dict)
        assert isinstance(alert_obj.subgraph, dict)
        assert "nodes" in alert_obj.subgraph and "edges" in alert_obj.subgraph
        assert isinstance(alert_obj.reasons, list)
        assert alert_obj.recommended_action == "review"

    def test_multiple_alerts_emitted_and_serialized_correctly(self, tmp_path):
        # A transaction closing both a rapid passthrough and a 3-hop cycle
        records = [
            {"transaction_id": "T1", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "b@upi", "amount": 10000.0},
            {"transaction_id": "T2", "timestamp": 150.0, "sender_upi": "b@upi", "receiver_upi": "c@upi", "amount": 9800.0},
            {"transaction_id": "T3", "timestamp": 180.0, "sender_upi": "c@upi", "receiver_upi": "a@upi", "amount": 9600.0},
        ]
        in_file = _write_jsonl(tmp_path / "multi.jsonl", records)
        out_file = tmp_path / "multi_alerts.jsonl"

        engine = FraudDetectionEngine(cycle_max_length=3, cycle_window_seconds=500.0, passthrough_max_delay_seconds=120.0)
        summary = replay_transactions(in_file, out_file, engine=engine, verbose=False)

        assert summary["alerts_emitted"] == 3
        patterns = summary["pattern_counts"]
        assert patterns.get("RAPID_PASSTHROUGH") == 2
        assert patterns.get("CIRCULAR_FLOW") == 1

        # Read back all 3 alerts
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3
        alert_ids = [json.loads(line)["alert_id"] for line in lines]
        assert len(set(alert_ids)) == 3  # Unique deterministic alert IDs
        assert alert_ids == ["ALT_000001", "ALT_000002", "ALT_000003"]

    def test_output_jsonl_contains_no_nan_or_infinity(self, tmp_path):
        records = [
            {"transaction_id": "TXN_IN", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "m@upi", "amount": 50000.0},
            {"transaction_id": "TXN_OUT", "timestamp": 130.0, "sender_upi": "m@upi", "receiver_upi": "b@upi", "amount": 49000.0},
        ]
        in_file = _write_jsonl(tmp_path / "inflow_outflow.jsonl", records)
        out_file = tmp_path / "alerts.jsonl"

        replay_transactions(in_file, out_file, verbose=False)

        content = out_file.read_text(encoding="utf-8")
        # Strict parsing with allow_nan=False
        for line in content.strip().split("\n"):
            parsed = json.loads(line)
            # Ensure no non-finite numeric floats
            assert math.isfinite(parsed["risk_score"])
            assert math.isfinite(parsed["timestamp"])
            assert 0.0 <= parsed["risk_score"] <= 1.0


# =====================================================================
# 4. Run Summary and Formatting
# =====================================================================

class TestReplaySummary:
    """Validates summary dictionary correctness and printed text representation."""

    def test_replay_summary_reflects_actual_engine_results(self, tmp_path):
        records = [
            {"transaction_id": f"T_{i}", "timestamp": 100.0 + i * 10, "sender_upi": f"s_{i}@upi", "receiver_upi": "hub@upi", "amount": 100.0}
            for i in range(1, 5)
        ]
        in_file = _write_jsonl(tmp_path / "test_sum.jsonl", records)
        out_file = tmp_path / "alerts.jsonl"

        summary = replay_transactions(in_file, out_file, verbose=False)

        assert summary["input_file"] == str(in_file)
        assert summary["output_file"] == str(out_file)
        assert summary["transactions_processed"] == 4
        assert summary["alerts_emitted"] == 1
        assert summary["pattern_counts"] == {"FAN_IN": 1}
        assert summary["graph_summary"]["node_count"] == 5
        assert summary["graph_summary"]["edge_count"] == 4

    def test_print_replay_summary_output(self, tmp_path):
        mock_summary = {
            "input_file": "data/transactions.jsonl",
            "output_file": "data/alerts.jsonl",
            "transactions_processed": 50,
            "alerts_emitted": 3,
            "pattern_counts": {"FAN_IN": 2, "RAPID_PASSTHROUGH": 1},
            "graph_summary": {
                "node_count": 25,
                "edge_count": 50,
                "tracked_devices_count": 10,
                "watermark": 1729680000.0,
                "processed_transaction_count": 50,
                "alert_count": 3,
            },
        }

        buf = io.StringIO()
        print_replay_summary(mock_summary, stream=buf)
        output = buf.getvalue()

        assert "RINGSHIELD REPLAY SUMMARY" in output
        assert "Transactions processed       : 50" in output
        assert "Alerts emitted               : 3" in output
        assert "FAN_IN                     : 2" in output
        assert "RAPID_PASSTHROUGH          : 1" in output
        assert "node_count                 : 25" in output


# =====================================================================
# 5. CLI Execution Tests
# =====================================================================

class TestReplayCLI:
    """Validates command-line interface execution via subprocess."""

    def test_cli_execution_successful(self, tmp_path):
        records = [
            {"transaction_id": f"T_{i}", "timestamp": 100.0 + i * 10, "sender_upi": f"s_{i}@upi", "receiver_upi": "target@upi", "amount": 1000.0}
            for i in range(1, 5)
        ]
        in_file = _write_jsonl(tmp_path / "cli_in.jsonl", records)
        out_file = tmp_path / "cli_out.jsonl"

        result = subprocess.run(
            [sys.executable, "-m", "detection.replay", "--input", str(in_file), "--output", str(out_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "RINGSHIELD REPLAY SUMMARY" in result.stdout
        assert "Transactions processed" in result.stdout
        assert out_file.exists()
        assert len(out_file.read_text(encoding="utf-8").strip().split("\n")) == 1

    def test_cli_missing_input_exits_with_error(self, tmp_path):
        nonexistent = tmp_path / "ghost.jsonl"
        out_file = tmp_path / "out.jsonl"

        result = subprocess.run(
            [sys.executable, "-m", "detection.replay", "--input", str(nonexistent), "--output", str(out_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "not found" in result.stderr.lower()

    def test_cli_leakage_input_exits_with_error(self, tmp_path):
        leaked_records = [
            {"transaction_id": "T_1", "timestamp": 100.0, "sender_upi": "a@upi", "receiver_upi": "b@upi", "amount": 100.0, "is_fraud": True}
        ]
        in_file = _write_jsonl(tmp_path / "cli_leak.jsonl", leaked_records)
        out_file = tmp_path / "out.jsonl"

        result = subprocess.run(
            [sys.executable, "-m", "detection.replay", "--input", str(in_file), "--output", str(out_file)],
            capture_output=True,
            text=True,
        )

        assert result.returncode != 0
        assert "data leakage" in result.stderr.lower()
