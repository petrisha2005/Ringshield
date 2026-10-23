"""Main page for the RingShield fraud-monitoring dashboard."""

import streamlit as st

from components import (
    inject_styles,
    render_alert_details,
    render_alert_table,
    render_header,
    render_metric_card,
    render_score_distribution,
    render_section_title,
    render_transaction_network,
)
from data import load_alerts

st.set_page_config(
    page_title="RingShield — Transaction Risk Dashboard",
    page_icon="🛡️",
    layout="wide",
)
inject_styles()
render_header()

alerts, load_errors, file_status = load_alerts()


def count(field: str, value: str) -> int:
    return sum(str(a[field]).strip().casefold() == value for a in alerts)


# ---------- KPIs ----------
render_section_title("Overview", "Key numbers from the loaded sample alerts")
kpis = [
    ("Total Transactions", str(len(alerts)), "Loaded sample records"),
    ("Flagged", str(count("Status", "flagged")), "Flagged status"),
    ("High-risk", str(count("Risk Level", "high")), "High risk level"),
    ("Under Review", str(count("Status", "under review")), "Under review status"),
]
for column, (label, value, note) in zip(st.columns(4, gap="medium"), kpis):
    with column:
        render_metric_card(label, value, note)

# ---------- Filters ----------
render_section_title("Transaction Monitoring", "Filter the sample alerts")
if file_status == "missing":
    st.info("The sample alert file is missing. Add JSONL records to view alerts.")
elif file_status == "empty":
    st.info("The sample alert file is empty. Add JSONL records to view alerts.")
if load_errors:
    st.warning("Some alert records could not be read: " + " ".join(load_errors))

matching_alerts = []
if alerts:
    priority = {"high": 0, "medium": 1, "low": 2}
    risk_options = ["All"] + sorted(
        {a["Risk Level"].strip() for a in alerts if a["Risk Level"].strip()},
        key=lambda v: (priority.get(v.casefold(), 3), v.casefold()),
    )
    status_options = ["All"] + sorted(
        {a["Status"].strip() for a in alerts if a["Status"].strip()},
        key=str.casefold,
    )
    with st.container(key="dashboard_toolbar"):
        f1, f2, f3 = st.columns([1, 1, 1.5], gap="medium")
        risk_choice = f1.selectbox("Risk level", risk_options)
        status_choice = f2.selectbox("Status", status_options)
        search_text = f3.text_input(
            "Search transaction ID", placeholder="e.g. TXN-SAMPLE-101"
        ).strip().casefold()

    for a in alerts:
        if risk_choice != "All" and a["Risk Level"].strip().casefold() != risk_choice.casefold():
            continue
        if status_choice != "All" and a["Status"].strip().casefold() != status_choice.casefold():
            continue
        if search_text and search_text not in a["Transaction ID"].casefold():
            continue
        matching_alerts.append(a)

# ---------- Table + chart ----------
render_section_title("Analytics")
table_col, chart_col = st.columns([1.6, 1], gap="medium")
with table_col:
    with st.container(key="transaction_table_panel"):
        st.markdown(f"##### Transactions ({len(matching_alerts)})")
        if matching_alerts:
            render_alert_table(matching_alerts)
        elif alerts:
            st.info("No alerts match the selected filters.")
        else:
            st.info("No valid sample alert records are available.")

with chart_col:
    with st.container(key="risk_chart_panel"):
        st.markdown("##### Risk Score Distribution")
        st.caption("Sample scores, not model predictions.")
        scores = [
            a["Risk Score"]
            for a in alerts
            if isinstance(a["Risk Score"], (int, float))
            and not isinstance(a["Risk Score"], bool)
        ]
        if scores:
            render_score_distribution(scores)
        else:
            st.info("No numeric risk scores are available to chart.")

# ---------- Investigation ----------
render_section_title("Alert Investigation", "Pick an alert to see its details and connections")
details_col, network_col = st.columns(2, gap="medium")
selected_alert = None
with details_col:
    with st.container(key="selected_alert_panel"):
        st.markdown("##### Selected Alert")
        if matching_alerts:
            index = st.selectbox(
                "Investigate alert",
                options=range(len(matching_alerts)),
                format_func=lambda i: (
                    f"{matching_alerts[i]['Alert ID']} — {matching_alerts[i]['Transaction ID']}"
                ),
            )
            selected_alert = matching_alerts[index]
            render_alert_details(selected_alert)
        elif alerts:
            st.info("No alert is available for the current filters.")
        else:
            st.info("Select an alert after sample records are available.")

with network_col:
    with st.container(key="network_panel"):
        st.markdown("##### Transaction Network")
        render_transaction_network(alerts, selected_alert)

st.markdown(
    "<div class='rs-footer'>RingShield · Fictional sample data only; "
    "not verified fraud results or live monitoring.</div>",
    unsafe_allow_html=True,
)
