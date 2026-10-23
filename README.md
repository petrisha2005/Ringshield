# RingShield

RingShield is a hackathon project focused on monitoring transactions and highlighting activity that may need review. The proposed direction is a dashboard that helps a person inspect transaction records and their context. The current dashboard is a local demonstration: it reads fictional sample alerts and is **not connected to live transactions or the real fraud detector**.

## Current dashboard architecture

The following flow is verified in the dashboard code:

1. `frontend/sample_alerts.jsonl` contains fictional alert records for demonstration.
2. `frontend/data.py` reads the local JSONL file with Python's built-in JSON support, checks records, and prepares display fields.
3. `frontend/app.py` builds the Streamlit page, calculates the overview counts, and displays the table, alert details, score chart, and transaction network.
4. `frontend/components.py` provides reusable metric-card and alert-table display functions.

The repository also contains `detection/`, `simulator/`, `streaming/`, and `contracts/` directories. Their exact component roles and their integration with the dashboard are not established by the dashboard code, so this README does not describe them as connected or operational.

## Prerequisites

- Python 3.10 or newer.
- Windows PowerShell for the commands below.
- The repository files, including `requirements.txt`.

## Setup and run

Run these commands from the repository root (`C:\Users\LENOVO\Ringshield`). If `.venv` already exists, skip the first command.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run frontend/app.py
```

Streamlit opens the dashboard in a browser. To stop it, press `Ctrl+C` in the PowerShell window running the app.

## Try the fictional sample dashboard

The dashboard reads `frontend/sample_alerts.jsonl`. The records and every value shown from them are fictional demonstration data; the risk scores are not model predictions or detector results.

1. Start the dashboard with the command above.
2. Review the four overview cards. They count records loaded from the local file: total records, records with status `Flagged`, records with risk level `High`, and records with status `Under review`.
3. Browse the sample alert table.
4. In **Investigate a sample alert**, choose an alert to view its fields and the sample-only illustrative analyst action.
5. Review the sample risk-score distribution and directed sender-to-receiver network. The selected transaction and its endpoint nodes are highlighted; other available connections remain visible.

The app shows a helpful message if the sample file is absent or empty and reports malformed JSONL lines that it skips.

## Feature status

### Implemented in the current dashboard

- Streamlit page with four counts calculated from loaded records.
- Fictional sample-alert table and selectable alert details.
- Sample risk-score distribution chart.
- Directed network drawn from sender and receiver IDs present in the loaded records, with the selected transaction highlighted.
- Explicit sample-data notices and handling for missing/empty files and invalid JSON lines.

### Incomplete

- The dashboard does not receive live transactions and is not connected to the real fraud detector.
- Evaluation results are not displayed by the dashboard. No measured precision, recall, false-positive rate, or latency is claimed here.
- The sample alert file is a dashboard demonstration source, not evidence that the end-to-end system is operating.

### Planned direction

The stated project intention is to connect the dashboard to live data later. The exact integration design and completion schedule are not verified here; no live integration is claimed as implemented.

## Limitations and evaluation status

All current rows, statuses, reasons, amounts, and risk scores come from fictional sample records. Dashboard counts and chart bins summarize those records only. They do not measure fraud-detection accuracy or real transaction activity. This README reports no evaluation metrics because verified measured results were not available in the inspected dashboard code.
