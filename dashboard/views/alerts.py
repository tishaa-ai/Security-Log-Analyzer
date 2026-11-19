"""Security Alerts page: run detection, filter and prioritise alerts."""

from __future__ import annotations

import streamlit as st

from config import ALERT_STATUSES, SEVERITIES
from dashboard import charts
from dashboard.components import (
    alerts_table, empty_state, get_db, indicator_note, open_investigation, page_header, severity_cards,
)
from pipeline import run_analysis


def render() -> None:
    page_header("Security Alerts", "Prioritised by explainable risk score (highest first).")
    db = get_db()

    c1, c2 = st.columns([1, 4])
    if c1.button("Run detection now", type="primary", disabled=db.count_events() == 0):
        with st.spinner("Running detection rules…"):
            summary = run_analysis(db)
        c2.success(f"Analysed {summary.events_analyzed} events → {summary.alerts_generated} alerts "
                   f"({summary.new_alerts} new). Existing alert statuses and notes were preserved.")

    alerts = db.get_alerts_df()
    if alerts.empty:
        empty_state("No alerts yet.")
        return
    indicator_note()

    f1, f2, f3, f4 = st.columns(4)
    sev = f1.multiselect("Severity", SEVERITIES, default=list(SEVERITIES))
    status = f2.multiselect("Status", ALERT_STATUSES, default=list(ALERT_STATUSES))
    rules = f3.multiselect("Rule", sorted(alerts["rule_id"].unique()))
    ip = f4.text_input("Source IP contains")

    df = alerts[alerts["severity"].isin(sev) & alerts["status"].isin(status)]
    if rules:
        df = df[df["rule_id"].isin(rules)]
    if ip:
        df = df[df["source_ip"].fillna("").str.contains(ip, regex=False)]

    severity_cards(df["severity"].value_counts().to_dict())
    st.write("")

    left, right = st.columns(2)
    with left:
        by_rule = (df["rule_id"] + " " + df["rule_name"]).value_counts()
        st.plotly_chart(charts.horizontal_count_bar(by_rule, "Alerts by detection rule", x_title="Alerts"),
                        key="al_by_rule")
    with right:
        st.plotly_chart(charts.alerts_over_time(df), key="al_trend")

    st.subheader(f"{len(df)} alert(s)")
    st.caption("Select a row, then open it in the investigation workspace.")
    event = alerts_table(df, key="alerts_table", selectable=True)
    rows = event.selection.rows if event is not None else []
    if rows:
        alert_id = df.iloc[rows[0]]["alert_id"]
        st.button(f"Investigate {alert_id} →", type="primary", on_click=open_investigation, args=(alert_id,))
