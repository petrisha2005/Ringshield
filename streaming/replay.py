"""Local transaction replay and benchmark for RingShield fraud detection.

Reads newline-delimited JSON transactions from disk, evaluates them
sequentially through FraudDetectionEngine, writes suspicious alerts to
an output JSONL file, and measures detector latency and throughput.

Operates purely offline without Kafka credentials or cluster access.
"""

import argparse
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any

import numpy as np

from detection.engine import FraudDetectionEngine

logger = logging.getLogger("ringshield.replay")


@dataclass
class ReplaySummary:
    """Summary metrics of an offline replay run."""

    total_records_read: int
    successfully_processed: int
    alerts_generated: int
    invalid_records: int
    total_detector_time_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    mean_latency_ms: float
    throughput_records_per_sec: float

    def format_report(self) -> str:
        """Format metrics into a human-readable report."""
        divider = "=" * 65
        return (
            f"\n{divider}\n"
            f"          RingShield Offline Transaction Replay Summary\n"
            f"{divider}\n"
            f"Processing Counts:\n"
            f"  - Total records read:         {self.total_records_read}\n"
            f"  - Successfully processed:     {self.successfully_processed}\n"
            f"  - Fraud alerts generated:     {self.alerts_generated}\n"
            f"  - Invalid / malformed records:{self.invalid_records}\n"
            f"\n"
            f"Detector Latency (Isolated engine.evaluate execution):\n"
            f"  - Total detector time:        {self.total_detector_time_ms:.4f} ms "
            f"({self.total_detector_time_ms / 1000.0:.6f} s)\n"
            f"  - Mean latency:               {self.mean_latency_ms:.4f} ms\n"
            f"  - p50 latency:                {self.p50_latency_ms:.4f} ms\n"
            f"  - p95 latency:                {self.p95_latency_ms:.4f} ms\n"
            f"  - p99 latency:                {self.p99_latency_ms:.4f} ms\n"
            f"\n"
            f"Throughput Estimate:\n"
            f"  - Detector-only throughput:   {self.throughput_records_per_sec:,.1f} records/sec\n"
            f"    (Note: Derived strictly from measured detector execution time.\n"
            f"     Excludes Kafka network latency, message queueing, serialization,\n"
            f"     and end-to-end streaming delivery time.)\n"
            f"{divider}\n"
        )


def calculate_percentiles(latencies_ms: list[float]) -> dict[str, float]:
    """Calculate p50, p95, p99, and mean latency in milliseconds.

    Uses numpy.percentile with method='linear' (standard continuous interpolation).
    For n=1 (single sample), p50 = p95 = p99 = sample value.
    For n=0 (empty list), returns 0.0 for all percentiles to avoid division by zero.
    """
    if not latencies_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0}

    arr = np.array(latencies_ms, dtype=float)
    return {
        "p50": float(np.percentile(arr, 50, method="linear")),
        "p95": float(np.percentile(arr, 95, method="linear")),
        "p99": float(np.percentile(arr, 99, method="linear")),
        "mean": float(np.mean(arr)),
    }


def replay_transactions(
    input_path: str | Path = "data/transactions.jsonl",
    output_path: str | Path = "data/alerts.jsonl",
    engine: FraudDetectionEngine | None = None,
) -> ReplaySummary:
    """Replay transactions sequentially from input JSONL and write alerts to output JSONL.

    Parameters:
        input_path: Path to input newline-delimited JSON transactions.
        output_path: Path to write suspicious alert JSON records.
        engine: FraudDetectionEngine instance (or None to create default).

    Returns:
        ReplaySummary with execution metrics and latency statistics.

    Raises:
        FileNotFoundError: If input_path does not exist.
    """
    in_path = Path(input_path)
    out_path = Path(output_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Input transaction file not found: {in_path}")

    # Ensure output parent directory exists and open in 'w' mode to start fresh
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if engine is None:
        engine = FraudDetectionEngine()

    total_records = 0
    successfully_processed = 0
    alerts_generated = 0
    invalid_records = 0
    latencies_ms: list[float] = []

    with open(in_path, "r", encoding="utf-8") as in_file, open(
        out_path, "w", encoding="utf-8"
    ) as out_file:
        for line_num, line in enumerate(in_file, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            total_records += 1

            # 1. Parse JSON record
            try:
                transaction = json.loads(line_str)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                invalid_records += 1
                logger.warning(
                    "Line %d: Malformed JSON skipped: %s", line_num, exc
                )
                continue

            # 2. Measure ONLY the call to engine.evaluate(transaction)
            t_start = time.perf_counter_ns()
            try:
                alert = engine.evaluate(transaction)
            except (ValueError, TypeError) as exc:
                invalid_records += 1
                logger.warning(
                    "Line %d: Invalid transaction schema skipped: %s",
                    line_num,
                    exc,
                )
                continue
            t_end = time.perf_counter_ns()

            # Record detector latency in milliseconds
            elapsed_ms = (t_end - t_start) / 1_000_000.0
            latencies_ms.append(elapsed_ms)
            successfully_processed += 1

            # 3. Write suspicious alerts to output file
            if alert.get("is_suspicious"):
                alerts_generated += 1
                out_file.write(json.dumps(alert) + "\n")

    # Compute aggregate latency metrics
    percentiles = calculate_percentiles(latencies_ms)
    total_detector_time_ms = sum(latencies_ms)

    # Throughput: avoid division by zero
    total_detector_time_sec = total_detector_time_ms / 1000.0
    if total_detector_time_sec > 0:
        throughput = successfully_processed / total_detector_time_sec
    else:
        throughput = 0.0

    return ReplaySummary(
        total_records_read=total_records,
        successfully_processed=successfully_processed,
        alerts_generated=alerts_generated,
        invalid_records=invalid_records,
        total_detector_time_ms=total_detector_time_ms,
        p50_latency_ms=percentiles["p50"],
        p95_latency_ms=percentiles["p95"],
        p99_latency_ms=percentiles["p99"],
        mean_latency_ms=percentiles["mean"],
        throughput_records_per_sec=throughput,
    )


def main() -> None:
    """CLI entrypoint for offline transaction replay."""
    parser = argparse.ArgumentParser(
        description="RingShield Offline Transaction Replay and Benchmark"
    )
    parser.add_argument(
        "-i",
        "--input",
        default="data/transactions.jsonl",
        help="Path to input transactions JSONL (default: data/transactions.jsonl)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="data/alerts.jsonl",
        help="Path to output alerts JSONL (default: data/alerts.jsonl)",
    )
    parser.add_argument(
        "--high-value-threshold",
        type=float,
        default=100_000.0,
        help="Threshold for high-value transactions (default: 100,000)",
    )
    parser.add_argument(
        "--rapid-window",
        type=int,
        default=60,
        help="Sliding window in seconds for rapid transfers (default: 60)",
    )
    parser.add_argument(
        "--rapid-limit",
        type=int,
        default=5,
        help="Transfer limit for rapid transfers (default: 5)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed logging output",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    engine = FraudDetectionEngine(
        high_value_threshold=args.high_value_threshold,
        rapid_window_seconds=args.rapid_window,
        rapid_transfer_limit=args.rapid_limit,
    )

    try:
        summary = replay_transactions(
            input_path=args.input,
            output_path=args.output,
            engine=engine,
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(1)
    except Exception as exc:
        sys.stderr.write(f"Unexpected replay error: {exc}\n")
        sys.exit(2)

    print(summary.format_report())


if __name__ == "__main__":
    main()
