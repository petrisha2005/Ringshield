
import json
from collections import Counter
from pathlib import Path

from detection.engine import FraudDetectionEngine

BASE_DIR = Path(__file__).resolve().parent
TRANSACTIONS_FILE = BASE_DIR / "data" / "transactions.jsonl"


def load_jsonl(path):
    """Read a JSON Lines file."""
    with path.open("r", encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def main():
    if not TRANSACTIONS_FILE.exists():
        print(f"Dataset not found: {TRANSACTIONS_FILE}")
        print("Run: python -m simulator.generate --demo")
        return

    transactions = load_jsonl(TRANSACTIONS_FILE)

    # Never pass simulator ground-truth labels into the detector.
    forbidden = {"is_fraud", "pattern_type", "ring_id"}
    for txn in transactions:
        txn.pop("is_fraud", None)
        txn.pop("pattern_type", None)
        txn.pop("ring_id", None)

    # The engine requires nondecreasing timestamps.
    transactions.sort(key=lambda txn: txn["timestamp"])

    engine = FraudDetectionEngine()
    all_alerts = []

    print("\n========== RINGSHIELD ENGINE DEMO ==========")
    print(f"Transactions loaded: {len(transactions)}")
    print("Processing transactions through FraudDetectionEngine...\n")

    for txn in transactions:
        alerts = engine.process_transaction(txn)
        for alert in alerts:
            if hasattr(alert, "to_dict"):
                alert = alert.to_dict()
            all_alerts.append(alert)

    summary = engine.get_graph_summary()

    print("--------------- GRAPH SUMMARY --------------")
    for key, value in summary.items():
        print(f"{key}: {value}")

    print("\n---------------- ALERT SUMMARY -------------")
    print(f"Alerts emitted: {len(all_alerts)}")

    pattern_counts = Counter(
        alert.get("pattern_type", alert.get("pattern", "UNKNOWN"))
        for alert in all_alerts
    )

    if pattern_counts:
        for pattern, count in sorted(pattern_counts.items()):
            print(f"{pattern}: {count}")
    else:
        print("No alerts were emitted for this dataset.")

    print("\n---------------- SAMPLE ALERTS -------------")
    for alert in all_alerts[:10]:
        print(json.dumps(alert, indent=2, default=str))

    print("\nDemo completed.")
    print("Note: alerts are suspicious signals, not proof of fraud.")


if __name__ == "__main__":
    main()
