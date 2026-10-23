"""
detection/replay.py
Local transaction replay and alert output module for RingShield.

Sequentially replays generated UPI transactions from a JSONL file through the
FraudDetectionEngine, enforcing schema integrity, strict anti-leakage checks,
and nondecreasing timestamp ordering, and writing explainable Alert instances
to a JSONL output file.
"""

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Union
import argparse
import json
import sys

from contracts.schemas import Alert, Transaction, validate_alert, validate_transaction
from detection.engine import FraudDetectionEngine


class ReplayError(ValueError):
    """Raised when an error occurs during JSONL replay processing."""
    pass


def load_and_validate_transactions(
    input_path: Union[str, Path]
) -> List[Transaction]:
    """
    Read and validate transactions from a JSONL file line by line.

    Reports malformed JSON, schema violations, and ground-truth data leakage
    with the exact line number. Does not silently skip invalid records.
    """
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"Input transactions file not found: {path}")
    if not path.is_file():
        raise ValueError(f"Input path is not a file: {path}")

    transactions: List[Transaction] = []
    forbidden_keys = {"is_fraud", "pattern_type", "ring_id"}

    with path.open("r", encoding="utf-8") as file:
        for line_num, raw_line in enumerate(file, start=1):
            line = raw_line.strip()
            if not line:
                continue

            # Parse JSON
            try:
                record = json.loads(line)
            except json.JSONDecodeError as err:
                raise ReplayError(
                    f"Line {line_num}: Malformed JSON - {err}"
                ) from err

            if not isinstance(record, dict):
                raise ReplayError(
                    f"Line {line_num}: Expected JSON object (dict), got {type(record).__name__}"
                )

            # Check for data leakage explicitly before schema validation
            leaked = forbidden_keys.intersection(record.keys())
            if leaked:
                raise ReplayError(
                    f"Line {line_num}: Data leakage detected! Ground-truth labels "
                    f"{sorted(leaked)} must not be present in Transaction input."
                )

            # Validate against shared contract
            try:
                txn = validate_transaction(record)
            except Exception as err:
                raise ReplayError(
                    f"Line {line_num}: Invalid transaction record - {err}"
                ) from err

            transactions.append(txn)

    return transactions


def replay_transactions(
    input_path: Union[str, Path] = "data/transactions.jsonl",
    output_path: Optional[Union[str, Path]] = "data/alerts.jsonl",
    engine: Optional[FraudDetectionEngine] = None,
    sort_transactions: bool = True,
    verbose: bool = True,
) -> Dict[str, Any]:
    """
    Replay transactions from input_path through FraudDetectionEngine and write alerts to output_path.

    Parameters:
        input_path: Path to input transactions JSONL file.
        output_path: Path to output alerts JSONL file (optional).
        engine: Existing FraudDetectionEngine instance (or None to create a new one).
        sort_transactions: If True, sort transactions by (timestamp, transaction_id) to guarantee
                           nondecreasing chronological ordering.
        verbose: If True, print concise run summary to stdout.

    Returns:
        Summary dictionary with transaction counts, alerts emitted, pattern counts, and graph summary.
    """
    in_path = Path(input_path)
    transactions = load_and_validate_transactions(in_path)

    # Deterministic chronological ordering: secondary key transaction_id
    if sort_transactions:
        transactions.sort(key=lambda t: (t.timestamp, t.transaction_id))

    if engine is None:
        engine = FraudDetectionEngine()

    all_alerts: List[Alert] = []
    for txn in transactions:
        alerts = engine.process_transaction(txn)
        all_alerts.extend(alerts)

    # Write alerts to output JSONL
    out_file_str: Optional[str] = None
    if output_path is not None:
        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as out_f:
            for alert in all_alerts:
                alert_dict = alert.to_dict()
                line = json.dumps(alert_dict, allow_nan=False)
                out_f.write(line + "\n")
        out_file_str = str(out_path)

    # Group alerts by pattern_type
    pattern_counts = Counter(alert.pattern_type for alert in all_alerts)
    graph_summary = engine.get_graph_summary()

    summary: Dict[str, Any] = {
        "input_file": str(in_path),
        "output_file": out_file_str,
        "transactions_processed": len(transactions),
        "alerts_emitted": len(all_alerts),
        "pattern_counts": dict(sorted(pattern_counts.items())),
        "graph_summary": graph_summary,
        "alerts": all_alerts,
    }

    if verbose:
        print_replay_summary(summary)

    return summary


def print_replay_summary(summary: Dict[str, Any], stream: Optional[TextIO] = None) -> None:
    """Print a clean, concise run summary to the specified stream (default sys.stdout)."""
    out = stream if stream is not None else sys.stdout

    print("\n=================== RINGSHIELD REPLAY SUMMARY ===================", file=out)
    print(f"Input file                   : {summary.get('input_file', 'N/A')}", file=out)
    print(f"Output file                  : {summary.get('output_file', 'None')}", file=out)
    print(f"Transactions processed       : {summary.get('transactions_processed', 0)}", file=out)
    print(f"Alerts emitted               : {summary.get('alerts_emitted', 0)}", file=out)

    pattern_counts = summary.get("pattern_counts", {})
    if pattern_counts:
        print("\n--- Alerts Grouped by Pattern Type ---", file=out)
        for pattern, count in pattern_counts.items():
            print(f"  {pattern:<26} : {count}", file=out)
    else:
        print("\n--- Alerts Grouped by Pattern Type ---", file=out)
        print("  (None)", file=out)

    graph_summary = summary.get("graph_summary", {})
    if graph_summary:
        print("\n--- Final Graph Summary ---", file=out)
        for key, val in graph_summary.items():
            print(f"  {key:<26} : {val}", file=out)

    print("=================================================================\n", file=out)


def main() -> None:
    """CLI entrypoint for RingShield transaction replay."""
    parser = argparse.ArgumentParser(
        description="RingShield local JSONL transaction replay and alert emitter."
    )
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default="data/transactions.jsonl",
        help="Path to input transactions JSONL file (default: data/transactions.jsonl)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="data/alerts.jsonl",
        help="Path to output alerts JSONL file (default: data/alerts.jsonl)",
    )
    args = parser.parse_args()

    try:
        replay_transactions(
            input_path=args.input,
            output_path=args.output,
            verbose=True,
        )
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except ReplayError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as err:
        print(f"Unexpected replay error: {err}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
