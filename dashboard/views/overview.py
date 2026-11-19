"""Overview page: headline metrics, trends and recent security events."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from config import SEVERITIES
from dashboard import charts
from dashboard.components import (
    alerts_table, empty_state, get_db, indicator_note, page_header, severity_cards,
)
from utils.ip_utils import ip_in_networks, parse_watchlist


def render() -> None:
    page_header("Security Overview", "Live summary of everything stored in the local SQLite database.")
    db = get_db()
    events = db.get_events_df()
    alerts = db.get_alerts_df()
    totals = db.get_ingestion_totals()

    if events.empty:
        empty_state("No log data has been ingested yet.")
        return

    # ---------------- filters (one row above the charts)
    min_day, max_day = events["timestamp"].min().date(), events["timestamp"].max().date()
    f1, f2 = st.columns([2, 3])
    date_range = f1.date_input("Date range (UTC)", value=(min_day, max_day),
                               min_value=min_day, max_value=max_day)
    severities = f2.multiselect("Alert severity", SEVERITIES, default=list(SEVERITIES))
    if isinstance(date_range, tuple) and len(date_range) == 2:
        start, end = pd.Timestamp(date_range[0]), pd.Timestamp(date_range[1]) + pd.Timedelta(days=1)
    else:
        start, end = pd.Timestamp(min_day), pd.Timestamp(max_day) + pd.Timedelta(days=1)

    ev = events[(events["timestamp"] >= start) & (events["timestamp"] < end)]
    al = alerts
    if not alerts.empty:
        al = alerts[(alerts["timestamp"] >= start) & (alerts["timestamp"] < end)
                    & alerts["severity"].isin(severities)]

    # ---------------- headline metrics
    settings = db.load_settings()
    networks, _ = parse_watchlist(settings.watchlist)
    watch_mask = ev["source_ip"].apply(lambda ip: ip_in_networks(ip, networks)) if networks else pd.Series(False, index=ev.index)
    failures = ev[ev["event_type"] == "auth_failure"]

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Log records processed", f"{totals['total']:,}",
              help="All records read from uploaded files (parsed + rejected).")
    c2.metric("Events in range", f"{len(ev):,}", help=f"{totals['rejected']:,} malformed records were rejected overall.")
    c3.metric("Alerts in range", f"{len(al):,}")
    c4.metric("Failed logins", f"{len(failures):,}",
              help=f"From {failures['source_ip'].nunique()} distinct source IP(s).")
    c5.metric("Watchlisted IP events", f"{int(watch_mask.sum()):,}",
              help=f"{ev.loc[watch_mask, 'source_ip'].nunique()} watchlisted IP(s) seen.")

    sev_counts = al["severity"].value_counts().to_dict() if not al.empty else {}
    severity_cards(sev_counts)
    st.write("")
    indicator_note()

    # ---------------- charts
    left, right = st.columns(2)
    with left:
        st.plotly_chart(charts.alerts_over_time(al), key="ov_alert_trend")
    with right:
        st.plotly_chart(charts.events_over_time(ev), key="ov_event_trend")

    left, right = st.columns(2)
    with left:
        st.plotly_chart(charts.failed_logins_over_time(ev), key="ov_failed")
    with right:
        top_ips = al["source_ip"].dropna().value_counts().head(8) if not al.empty else pd.Series(dtype=int)
        st.plotly_chart(charts.horizontal_count_bar(top_ips, "Top source IPs by alert count",
                                                    x_title="Alerts"), key="ov_top_ips")

    # ---------------- top alerts + recent events
    st.subheader("Highest-priority alerts")
    if al.empty:
        st.caption("No alerts in the selected range. Run detection from the Security Alerts page.")
    else:
        alerts_table(al.head(8), key="ov_alerts")

    st.subheader("Recent security events")
    st.caption("Latest failed logins, HTTP 4xx/5xx responses and activity from watchlisted IPs.")
    interesting = ev[
        (ev["event_type"] == "auth_failure")
        | (ev["status_code"].fillna(0) >= 400)
        | watch_mask
    ].sort_values("timestamp", ascending=False).head(15)
    st.dataframe(
        interesting[["timestamp", "event_type", "source_ip", "username", "status_code", "url_path",
                     "message", "file_name"]],
        hide_index=True,
        column_config={"timestamp": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss")},
    )
