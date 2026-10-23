"""Reusable visual components for the RingShield dashboard."""

import math
from html import escape

import streamlit as st

RISK_COLORS = {"high": "#ef4444", "medium": "#f59e0b", "low": "#22c55e"}
STATUS_COLORS = {
    "flagged": "#f97316",
    "under review": "#38bdf8",
    "reviewed": "#22c55e",
}
NEUTRAL = "#94a3b8"

STYLES = """
<style>
:root { color-scheme: dark; }
#MainMenu, footer, header[data-testid="stHeader"] { visibility: hidden; height: 0; }
.stApp {
    background:
        radial-gradient(900px 420px at 8% -8%, rgba(56,189,248,.14), transparent 60%),
        radial-gradient(800px 420px at 100% 0%, rgba(139,92,246,.12), transparent 55%),
        #070f1c;
    color: #e5edf7;
    font-family: Inter, "Segoe UI", system-ui, sans-serif;
}
.block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1280px; }
.stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5 { color: #f1f6fc; letter-spacing: -0.01em; }
.stApp p, .stApp label, .stApp small, .stApp span { color: #c1cfdd; }
.stApp :focus-visible { outline: 2px solid #38bdf8; outline-offset: 2px; }

/* ---------- panels (st.container(key=...)) ---------- */
.st-key-dashboard_toolbar, .st-key-transaction_table_panel, .st-key-risk_chart_panel,
.st-key-selected_alert_panel, .st-key-network_panel {
    background: linear-gradient(180deg, rgba(20,34,52,.92), rgba(14,25,40,.92));
    border: 1px solid #1f3349; border-radius: 16px; padding: 1rem 1.1rem;
    box-shadow: 0 8px 28px rgba(0,0,0,.28);
}

/* ---------- header ---------- */
.rs-brand { display:flex; align-items:center; gap:.9rem; }
.rs-logo {
    display:grid; place-items:center; width:3rem; height:3rem; font-size:1.5rem;
    border-radius:14px; background:linear-gradient(135deg,#0ea5e9,#8b5cf6);
    box-shadow:0 6px 22px rgba(56,189,248,.35);
}
.rs-title { font-size:1.75rem; font-weight:800; color:#fff; line-height:1.1; margin:0; }
.rs-subtitle { color:#8fa5ba; font-size:.85rem; margin-top:.15rem; }
.rs-badge-demo {
    display:inline-block; float:right; padding:.4rem .8rem; border-radius:999px;
    font-size:.72rem; font-weight:700; letter-spacing:.04em; color:#fbbf24;
    background:rgba(251,191,36,.1); border:1px solid rgba(251,191,36,.35);
}

/* ---------- section titles ---------- */
.rs-section { margin:1.3rem 0 .6rem; }
.rs-section h3 { font-size:1.05rem; font-weight:700; margin:0; color:#f1f6fc; }
.rs-section p { margin:.1rem 0 0; font-size:.78rem; color:#7f95ab; }

/* ---------- KPI cards ---------- */
.rs-kpi {
    position:relative; overflow:hidden; padding:.9rem 1rem; border-radius:16px;
    background:linear-gradient(180deg,#142236,#0f1b2c); border:1px solid #1f3349;
    box-shadow:0 8px 24px rgba(0,0,0,.25);
}
.rs-kpi::after {
    content:""; position:absolute; right:-30px; top:-30px; width:110px; height:110px;
    border-radius:50%; background:var(--kpi-accent); opacity:.12; filter:blur(6px);
}
.rs-kpi-label { display:flex; align-items:center; gap:.5rem; color:#9db1c5; font-size:.78rem; font-weight:600; }
.rs-kpi-icon {
    display:grid; place-items:center; width:1.7rem; height:1.7rem; border-radius:8px;
    color:var(--kpi-accent); background:rgba(255,255,255,.05); font-size:.85rem;
}
.rs-kpi-value { color:#fff; font-size:2.1rem; font-weight:800; line-height:1.1; margin:.5rem 0 .1rem; font-variant-numeric:tabular-nums; }
.rs-kpi-note { color:#7f95ab; font-size:.72rem; }

/* ---------- pills ---------- */
.rs-pill {
    display:inline-flex; align-items:center; gap:.35rem; padding:.15rem .6rem; border-radius:999px;
    font-size:.72rem; font-weight:700; white-space:nowrap; color:var(--c);
    background:color-mix(in srgb, var(--c) 14%, transparent);
    border:1px solid color-mix(in srgb, var(--c) 40%, transparent);
}
.rs-pill::before { content:""; width:.42rem; height:.42rem; border-radius:50%; background:var(--c); }

/* ---------- table ---------- */
.rs-table-wrap { max-height:380px; overflow:auto; border:1px solid #1f3349; border-radius:12px; }
.rs-table { width:100%; border-collapse:collapse; font-size:.8rem; }
.rs-table th {
    position:sticky; top:0; z-index:1; text-align:left; padding:.6rem .75rem; white-space:nowrap;
    background:#14263a; color:#9db1c5; font-size:.7rem; font-weight:700;
    text-transform:uppercase; letter-spacing:.05em; border-bottom:1px solid #1f3349;
}
.rs-table td { padding:.55rem .75rem; color:#d9e4ef; border-bottom:1px solid #182a3e; white-space:nowrap; }
.rs-table tr:last-child td { border-bottom:none; }
.rs-table tbody tr:hover td { background:rgba(56,189,248,.06); }
.rs-table td.reason { white-space:normal; min-width:240px; color:#9db1c5; }
.rs-mono { font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:.76rem; }
.rs-score { display:flex; align-items:center; gap:.5rem; font-weight:700; }
.rs-bar { width:56px; height:6px; border-radius:99px; background:#1c3047; overflow:hidden; display:inline-block; }
.rs-bar i { display:block; height:100%; border-radius:99px; }

/* ---------- distribution chart ---------- */
.rs-dist-row { display:grid; grid-template-columns:70px 1fr 28px; align-items:center; gap:.7rem; margin:.55rem 0; font-size:.78rem; }
.rs-dist-label { color:#9db1c5; }
.rs-dist-track { height:14px; border-radius:99px; background:#162a40; overflow:hidden; }
.rs-dist-fill { height:100%; border-radius:99px; }
.rs-dist-count { color:#fff; font-weight:700; text-align:right; font-variant-numeric:tabular-nums; }

/* ---------- alert details ---------- */
.rs-detail-top { display:flex; align-items:center; gap:1rem; margin:.4rem 0 .9rem; }
.rs-ring {
    --pct:0; --c:#38bdf8; flex:0 0 auto; width:84px; height:84px; border-radius:50%;
    display:grid; place-items:center;
    background:conic-gradient(var(--c) calc(var(--pct) * 1%), #1c3047 0);
}
.rs-ring > div {
    width:64px; height:64px; border-radius:50%; background:#0f1b2c; display:grid; place-items:center;
    color:#fff; font-size:1.3rem; font-weight:800;
}
.rs-detail-grid { display:grid; grid-template-columns:1fr 1fr; gap:.55rem; }
.rs-field { padding:.55rem .75rem; border-radius:10px; background:#101e30; border:1px solid #1b2f45; }
.rs-field span { display:block; color:#7f95ab; font-size:.68rem; text-transform:uppercase; letter-spacing:.05em; }
.rs-field b { color:#eaf1f8; font-size:.85rem; font-weight:600; word-break:break-all; }
.rs-reason { margin-top:.65rem; padding:.7rem .85rem; border-radius:10px; background:rgba(56,189,248,.07); border-left:3px solid #38bdf8; color:#d3deea; font-size:.85rem; }

/* ---------- network legend ---------- */
.graph-legend { display:flex; gap:1rem; flex-wrap:wrap; color:#9db1c5; font-size:.74rem; margin:.2rem 0 .5rem; }
.graph-legend span { display:inline-flex; align-items:center; gap:.4rem; }
.graph-legend i { display:inline-block; width:1.2rem; border-top:3px solid; border-radius:2px; }

.rs-footer { text-align:center; color:#5f748a; font-size:.74rem; margin-top:1.6rem; }

@media (max-width:800px) {
    .rs-title { font-size:1.4rem; }
    .rs-badge-demo { float:none; margin-top:.5rem; }
    .rs-detail-grid { grid-template-columns:1fr; }
}
</style>
"""


def inject_styles() -> None:
    """Apply the dashboard theme."""
    st.markdown(STYLES, unsafe_allow_html=True)


def display_detail_value(value: object) -> object:
    """Show a consistent fallback for missing or unknown alert details."""
    if value is None:
        return "Not available"
    if isinstance(value, str) and (
        not value.strip() or value.strip().casefold() in {"unknown", "none"}
    ):
        return "Not available"
    return value


def _pill(text: object, color: str) -> str:
    return f"<span class='rs-pill' style='--c:{color}'>{escape(str(text))}</span>"


def risk_pill(value: object) -> str:
    text = display_detail_value(value)
    color = RISK_COLORS.get(str(text).strip().casefold(), NEUTRAL)
    return _pill(text, color)


def status_pill(value: object) -> str:
    text = display_detail_value(value)
    color = STATUS_COLORS.get(str(text).strip().casefold(), NEUTRAL)
    return _pill(text, color)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _score_color(score: object, risk_level: object = None) -> str:
    level = str(risk_level or "").strip().casefold()
    if level in RISK_COLORS:
        return RISK_COLORS[level]
    if _is_number(score):
        return "#22c55e" if score < 40 else "#f59e0b" if score < 70 else "#ef4444"
    return NEUTRAL


def render_section_title(title: str, subtitle: str = "") -> None:
    sub = f"<p>{escape(subtitle)}</p>" if subtitle else ""
    st.markdown(
        f"<div class='rs-section'><h3>{escape(title)}</h3>{sub}</div>",
        unsafe_allow_html=True,
    )


def render_header() -> None:
    left, right = st.columns([2.7, 1], gap="medium")
    with left:
        st.markdown(
            "<div class='rs-brand'><div class='rs-logo'>🛡</div><div>"
            "<div class='rs-title'>RingShield</div>"
            "<div class='rs-subtitle'>Fraud ring detection &amp; transaction monitoring</div>"
            "</div></div>",
            unsafe_allow_html=True,
        )
    with right:
        st.markdown(
            "<span class='rs-badge-demo'>● FICTIONAL SAMPLE DATA</span>",
            unsafe_allow_html=True,
        )


def render_metric_card(label: str, value: str, note: str) -> None:
    """Display a compact KPI card with its sample-data note."""
    card_styles = {
        "Total Transactions": ("#38bdf8", "▦"),
        "Flagged": ("#f97316", "⚑"),
        "High-risk": ("#ef4444", "▲"),
        "Under Review": ("#8b5cf6", "◷"),
    }
    accent, icon = card_styles.get(label, (NEUTRAL, "•"))
    st.markdown(
        f"<div class='rs-kpi' style='--kpi-accent:{accent}'>"
        f"<div class='rs-kpi-label'><span class='rs-kpi-icon'>{icon}</span>"
        f"<span>{escape(label)}</span></div>"
        f"<div class='rs-kpi-value'>{escape(value)}</div>"
        f"<div class='rs-kpi-note'>{escape(note)}</div>"
        "</div>",
        unsafe_allow_html=True,
    )


def render_alert_table(alerts: list[dict[str, object]]) -> None:
    """Display sample alerts in a clean table with colored badges."""
    headers = [
        "Transaction", "Alert", "Sender", "Receiver", "Amount",
        "Risk Score", "Risk", "Status", "Time", "Reason",
    ]
    rows = []
    for a in alerts:
        score = a.get("Risk Score")
        color = _score_color(score, a.get("Risk Level"))
        if _is_number(score):
            pct = max(0, min(100, score))
            score_html = (
                f"<div class='rs-score'><span>{score:g}</span><span class='rs-bar'>"
                f"<i style='width:{pct}%;background:{color}'></i></span></div>"
            )
        else:
            score_html = "—"
        cells = [
            f"<span class='rs-mono'>{escape(str(display_detail_value(a.get('Transaction ID'))))}</span>",
            escape(str(display_detail_value(a.get("Alert ID")))),
            f"<span class='rs-mono'>{escape(str(display_detail_value(a.get('Sender ID'))))}</span>",
            f"<span class='rs-mono'>{escape(str(display_detail_value(a.get('Receiver ID'))))}</span>",
            f"<b>{escape(str(display_detail_value(a.get('Amount'))))}</b>",
            score_html,
            risk_pill(a.get("Risk Level")),
            status_pill(a.get("Status")),
            escape(str(display_detail_value(a.get("Timestamp")))).replace("T", " ")[:19],
        ]
        tds = "".join(f"<td>{c}</td>" for c in cells)
        tds += f"<td class='reason'>{escape(str(display_detail_value(a.get('Reason'))))}</td>"
        rows.append(f"<tr>{tds}</tr>")
    head = "".join(f"<th>{h}</th>" for h in headers)
    st.markdown(
        f"<div class='rs-table-wrap'><table class='rs-table'><thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>",
        unsafe_allow_html=True,
    )


def render_score_distribution(scores: list[float]) -> None:
    """Horizontal bars showing how many alerts fall in each score range."""
    ranges = [
        ("0–19", 0, 20, "#22c55e"),
        ("20–39", 20, 40, "#84cc16"),
        ("40–59", 40, 60, "#f59e0b"),
        ("60–79", 60, 80, "#f97316"),
        ("80+", 80, math.inf, "#ef4444"),
    ]
    counts = [sum(lo <= s < hi for s in scores) for _, lo, hi, _ in ranges]
    top = max(counts) or 1
    rows = "".join(
        f"<div class='rs-dist-row'><span class='rs-dist-label'>{label}</span>"
        f"<div class='rs-dist-track'><div class='rs-dist-fill' "
        f"style='width:{count / top * 100:.0f}%;background:{color}'></div></div>"
        f"<span class='rs-dist-count'>{count}</span></div>"
        for (label, _, _, color), count in zip(ranges, counts)
    )
    st.markdown(rows, unsafe_allow_html=True)


def render_alert_details(alert: dict[str, object]) -> None:
    """Show one alert as a score ring plus a tidy grid of fields."""
    score = alert.get("Risk Score")
    color = _score_color(score, alert.get("Risk Level"))
    pct = max(0, min(100, score)) if _is_number(score) else 0
    score_text = f"{score:g}" if _is_number(score) else "—"

    def field(label: str, value: object) -> str:
        return (
            f"<div class='rs-field'><span>{label}</span>"
            f"<b>{escape(str(display_detail_value(value)))}</b></div>"
        )

    st.markdown(
        "<div class='rs-detail-top'>"
        f"<div class='rs-ring' style='--pct:{pct};--c:{color}'><div>{score_text}</div></div>"
        f"<div>{risk_pill(alert.get('Risk Level'))} {status_pill(alert.get('Status'))}"
        f"<div style='color:#8fa5ba;font-size:.78rem;margin-top:.4rem'>Risk score out of 100</div></div>"
        "</div>"
        "<div class='rs-detail-grid'>"
        + field("Alert ID", alert.get("Alert ID"))
        + field("Transaction ID", alert.get("Transaction ID"))
        + field("Sender", alert.get("Sender ID"))
        + field("Receiver", alert.get("Receiver ID"))
        + field("Amount", alert.get("Amount"))
        + field("Timestamp", alert.get("Timestamp"))
        + "</div>"
        f"<div class='rs-reason'>{escape(str(display_detail_value(alert.get('Reason'))))}</div>",
        unsafe_allow_html=True,
    )


def render_transaction_network(
    alert_records: list[dict[str, object]],
    selected_alert: dict[str, object] | None = None,
) -> None:
    """Draw a directed SVG network using only loaded sender/receiver values."""
    edges = []
    skipped_records = 0

    for alert in alert_records:
        sender = alert.get("Sender ID")
        receiver = alert.get("Receiver ID")
        if (
            not isinstance(sender, str)
            or not sender.strip()
            or sender.strip().casefold() == "unknown"
            or not isinstance(receiver, str)
            or not receiver.strip()
            or receiver.strip().casefold() == "unknown"
        ):
            skipped_records += 1
            continue

        edges.append((alert, sender.strip(), receiver.strip()))

    st.caption("Arrows go from sender to receiver. The selected link is highlighted.")

    if skipped_records:
        st.info(
            f"Skipped {skipped_records} sample record(s) with missing sender "
            "or receiver IDs."
        )

    if not edges:
        st.info("No sample sender-to-receiver links are available to draw.")
        return

    selected_endpoints = set()
    risk_colors = {
        "high": "#ef4444",
        "medium": "#f59e0b",
        "low": "#22c55e",
    }
    if selected_alert is not None:
        for field in ("Sender ID", "Receiver ID"):
            account_id = selected_alert.get(field)
            if (
                isinstance(account_id, str)
                and account_id.strip()
                and account_id.strip().casefold() != "unknown"
            ):
                selected_endpoints.add(account_id.strip())

    selected_risk_level = (
        selected_alert.get("Risk Level")
        if isinstance(selected_alert, dict)
        else None
    )
    selected_edge_color = (
        risk_colors.get(selected_risk_level.strip().casefold(), "#38bdf8")
        if isinstance(selected_risk_level, str) and selected_risk_level.strip()
        else "#38bdf8"
    )

    sender_ids = {sender for _, sender, _ in edges}
    receiver_ids = {receiver for _, _, receiver in edges}
    sender_only = sorted(sender_ids - receiver_ids)
    receiver_only = sorted(receiver_ids - sender_ids)
    shared_ids = sorted(sender_ids & receiver_ids)

    width = 1100
    box_width = 200
    box_height = 48
    vertical_gap = 24
    top_padding = 90
    bottom_padding = 45
    max_column_size = max(len(sender_only), len(shared_ids), len(receiver_only), 1)
    height = (
        top_padding
        + box_height
        + (max_column_size - 1) * (box_height + vertical_gap)
        + bottom_padding
    )
    column_x = {
        "sender": 190,
        "shared": width / 2,
        "receiver": width - 190,
    }
    positions = {}

    for role, account_ids in (
        ("sender", sender_only),
        ("shared", shared_ids),
        ("receiver", receiver_only),
    ):
        for index, account_id in enumerate(account_ids):
            positions[account_id] = (
                column_x[role],
                top_padding + box_height / 2 + index * (box_height + vertical_gap),
            )

    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        'role="img" aria-label="Fictional sample sender-to-receiver transaction network" '
        'style="width:100%;height:auto">',
        "<defs><marker id='arrowhead' markerWidth='10' markerHeight='8' "
        "refX='9' refY='4' orient='auto' markerUnits='strokeWidth'>"
        "<path d='M0,0 L10,4 L0,8 z' fill='#4b6580'/></marker>"
        "<marker id='selected-arrowhead' markerWidth='10' markerHeight='8' "
        "refX='9' refY='4' orient='auto' markerUnits='strokeWidth'>"
        f"<path d='M0,0 L10,4 L0,8 z' fill='{selected_edge_color}'/></marker></defs>",
    ]

    for edge_index, (alert, sender, receiver) in enumerate(edges):
        is_selected = alert is selected_alert
        edge_color = selected_edge_color if is_selected else "#4b6580"
        edge_width = 4 if is_selected else 2
        arrowhead = "selected-arrowhead" if is_selected else "arrowhead"
        start_x, start_y = positions[sender]
        end_x, end_y = positions[receiver]
        dx = end_x - start_x
        dy = end_y - start_y

        if dx == 0 and dy == 0:
            path = (
                f"M {start_x - 45:.1f} {start_y - box_height / 2 - 12:.1f} "
                f"C {start_x - 45:.1f} {start_y - box_height / 2 - 84:.1f}, "
                f"{start_x + 45:.1f} {start_y - box_height / 2 - 84:.1f}, "
                f"{start_x + 45:.1f} {start_y - box_height / 2 - 12:.1f}"
            )
            svg_parts.append(
                f"<path d='{path}' fill='none' stroke='{edge_color}' "
                f"stroke-width='{edge_width}' marker-end='url(#{arrowhead})'/>"
            )
            label_x = start_x + (180 if start_x <= width / 2 else -180)
            label_y = start_y - box_height / 2 - 48
        else:
            # Leave a small gap between each box and arrowhead so the node fill
            # cannot cover the direction marker.
            clip = 1 / max(
                abs(dx) / (box_width / 2 + 12),
                abs(dy) / (box_height / 2 + 12),
            )
            source_x = start_x + dx * clip
            source_y = start_y + dy * clip
            target_x = end_x - dx * clip
            target_y = end_y - dy * clip
            svg_parts.append(
                f"<line x1='{source_x:.1f}' y1='{source_y:.1f}' "
                f"x2='{target_x:.1f}' y2='{target_y:.1f}' stroke='{edge_color}' "
                f"stroke-width='{edge_width}' marker-end='url(#{arrowhead})'/>"
            )

            edge_length = math.hypot(dx, dy)
            midpoint_x = (source_x + target_x) / 2
            midpoint_y = (source_y + target_y) / 2
            offset = -12 if edge_index % 2 == 0 else 12
            label_x = midpoint_x - (dy / edge_length) * offset
            label_y = midpoint_y + (dx / edge_length) * offset

        label_details = []
        amount = alert.get("Amount")
        risk_score = alert.get("Risk Score")
        if isinstance(amount, str) and amount.strip() and amount.casefold() != "unknown":
            short_amount = amount if len(amount) <= 14 else f"{amount[:11]}…"
            label_details.append(short_amount)
        if isinstance(risk_score, (int, float)) and not isinstance(risk_score, bool):
            label_details.append(f"score {risk_score:g}")

        if label_details:
            label_text = " · ".join(label_details)
            label_width = max(76, min(148, len(label_text) * 6.2 + 16))
            svg_parts.append(
                f"<rect x='{label_x - label_width / 2:.1f}' "
                f"y='{label_y - 13:.1f}' width='{label_width:.1f}' height='26' "
                "rx='7' fill='#13283d' fill-opacity='0.98' stroke='#31506b'/>"
                f"<text x='{label_x:.1f}' y='{label_y + 4:.1f}' "
                "text-anchor='middle' font-size='11' font-family='sans-serif' "
                "fill='#e2eaf4'>"
                f"{escape(label_text)}</text>"
            )

    for account_id, (x, y) in positions.items():
        is_selected_endpoint = account_id in selected_endpoints
        node_fill = "#13263a"
        if is_selected_endpoint:
            node_fill = {
                "high": "#351d25",
                "medium": "#352b1b",
                "low": "#183126",
            }.get(
                selected_risk_level.casefold()
                if isinstance(selected_risk_level, str)
                else "",
                "#153044",
            )
        node_stroke = selected_edge_color if is_selected_endpoint else "#38bdf8"
        node_stroke_width = 4 if is_selected_endpoint else 2
        svg_parts.append(
            f"<rect x='{x - box_width / 2:.1f}' y='{y - box_height / 2:.1f}' "
            f"width='{box_width}' height='{box_height}' "
            f"rx='12' fill='{node_fill}' stroke='{node_stroke}' "
            f"stroke-width='{node_stroke_width}'/>"
            f"<text x='{x:.1f}' y='{y + 5:.1f}' text-anchor='middle' "
            "font-size='14' font-family='sans-serif' font-weight='600' fill='#e5eef8'>"
            f"{escape(account_id)}</text>"
        )

    svg_parts.append("</svg>")
    st.markdown("".join(svg_parts), unsafe_allow_html=True)
    st.markdown(
        "<div class='graph-legend'>"
        f"<span><i style='border-color:{selected_edge_color}'></i>Selected transaction</span>"
        "<span><i style='border-color:#4b6580'></i>Other sample connections</span>"
        "</div>",
        unsafe_allow_html=True,
    )

    edge_details = []
    for alert, sender, receiver in edges:
        edge_details.append(
            {
                "Transaction ID": alert.get("Transaction ID", "Unknown"),
                "Sender ID": sender,
                "Receiver ID": receiver,
                "Amount": alert.get("Amount", "Unknown"),
                "Risk Score": alert.get("Risk Score", "Unknown"),
            }
        )
    with st.expander("View link details"):
        st.dataframe(
            edge_details,
            hide_index=True,
            use_container_width=True,
            height=min(260, max(120, 48 + 32 * len(edge_details))),
        )
