"""Load dashboard alert records from a local JSONL file."""

import json
import math
from pathlib import Path


SAMPLE_ALERTS_PATH = Path(__file__).with_name("sample_alerts.jsonl")


def load_alerts(path: Path = SAMPLE_ALERTS_PATH):
    """Return display rows, per-line errors, and the file's load status.

    The fields below are only for this dashboard's fictional sample display.
    They do not define or replace the team's shared alert contract.
    """
    if not path.exists():
        return [], [], "missing"

    if path.stat().st_size == 0:
        return [], [], "empty"

    alerts = []
    errors = []

    with path.open("r", encoding="utf-8") as alert_file:
        for line_number, line in enumerate(alert_file, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Line {line_number} contains invalid JSON.")
                continue

            if not isinstance(record, dict):
                errors.append(f"Line {line_number} must contain a JSON object.")
                continue

            risk_score = record.get("risk_score")
            if (
                isinstance(risk_score, bool)
                or not isinstance(risk_score, (int, float))
                or not math.isfinite(risk_score)
            ):
                risk_score = "Unknown"

            sender_id = record.get("sender_id")
            if not isinstance(sender_id, str) or not sender_id.strip():
                sender_id = None

            receiver_id = record.get("receiver_id")
            if not isinstance(receiver_id, str) or not receiver_id.strip():
                receiver_id = None

            alerts.append(
                {
                    "Alert ID": str(record.get("alert_id", "Unknown")),
                    "Transaction ID": str(record.get("transaction_id", "Unknown")),
                    "Sender ID": sender_id,
                    "Receiver ID": receiver_id,
                    "Amount": str(record.get("amount", "Unknown")),
                    "Risk Score": risk_score,
                    "Risk Level": str(record.get("risk_level", "Unknown")),
                    "Status": str(record.get("status", "Unknown")),
                    "Timestamp": str(record.get("timestamp", "Unknown")),
                    "Reason": str(record.get("reason", "Not provided")),
                }
            )

    return alerts, errors, "loaded"
