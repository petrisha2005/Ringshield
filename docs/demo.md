# RingShield hackathon demo

## Demo sequence

1. **Introduce the goal.** RingShield is a hackathon project focused on monitoring transactions and highlighting activity for review. State that this screen currently uses fictional local sample data; it is not connected to live transactions or the real fraud detector.
2. **Open the dashboard.** From the repository root, run:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   python -m streamlit run frontend/app.py
   ```
   If the virtual environment or dependencies have not been set up, follow the setup steps in the root README first.
3. **Show the overview.** Point out the four cards. Explain that they count the records loaded from the sample JSONL file, not live activity.
4. **Show the sample table.** Explain that the rows are fictional examples and the risk scores are not model predictions or detector results.
5. **Investigate `SAMPLE-001`.** In the alert selector, choose `SAMPLE-001 — TXN-SAMPLE-101`. Expand or review the selected alert details. The sample record shows sender `SENDER-DEMO-01`, receiver `RECEIVER-DEMO-08`, amount `₹2,450.00`, risk score `91`, risk level `High`, status `Under review`, timestamp `2026-10-23T09:15:00+05:30`, and the fictional reason `Fictional example: unusual purchase amount`. The panel also contains a clearly labelled illustrative analyst action; it is not a detector recommendation.
6. **Show the chart and network.** Explain that the chart groups the sample scores and the network draws directions from the sender and receiver fields in the sample records. The selected transaction and its endpoint nodes are highlighted while other sample connections remain visible.
7. **Close honestly.** The local dashboard experience is implemented. Live transaction ingestion, integration with the real fraud detector, and verified evaluation results are not demonstrated by this screen.

## Backup plan

If live streaming or detector integration is unavailable, continue with the local dashboard exactly as described. The sample JSONL file is the dashboard's current source, so the table, cards, chart, selected-alert details, and network can be demonstrated without a live feed. Keep the fictional-data disclaimer visible and describe any live integration as pending unless the team verifies otherwise.
