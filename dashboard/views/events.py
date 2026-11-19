"""Parsed Events page: searchable table of normalised events and rejected records."""

from __future__ import annotations

import streamlit as st

from dashboard.components import empty_state, get_db, page_header
from parsers.models import EVENT_TYPES


def render() -> None:
    page_header("Parsed Events", "Normalised events from every ingested file, plus rejected records.")
    db = get_db()
    events = db.get_events_df()
    if events.empty:
        empty_state("No events stored yet.")
        return

    tab_events, tab_rejected = st.tabs(["Events", "Rejected records"])
    with tab_events:
        c1, c2, c3 = st.columns(3)
        types = c1.multiselect("Event type", EVENT_TYPES, default=list(EVENT_TYPES))
        files = c2.multiselect("Source file", sorted(events["file_name"].unique()))
        ip_filter = c3.text_input("Source IP contains")
        c4, c5 = st.columns(2)
        user_filter = c4.text_input("Username contains")
        text_filter = c5.text_input("Message / path contains")

        df = events[events["event_type"].isin(types)]
        if files:
            df = df[df["file_name"].isin(files)]
        if ip_filter:
            df = df[df["source_ip"].fillna("").str.contains(ip_filter, regex=False)]
        if user_filter:
            df = df[df["username"].fillna("").str.contains(user_filter, case=False, regex=False)]
        if text_filter:
            haystack = df["message"].fillna("") + " " + df["url_path"].fillna("")
            df = df[haystack.str.contains(text_filter, case=False, regex=False)]

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Matching events", f"{len(df):,}")
        m2.metric("Distinct source IPs", df["source_ip"].nunique())
        m3.metric("Distinct users", df["username"].nunique())
        m4.metric("Auth failures", int((df["event_type"] == "auth_failure").sum()))

        st.dataframe(
            df[["timestamp", "event_type", "outcome", "source_ip", "username", "status_code",
                "http_method", "url_path", "hostname", "service", "message", "file_name", "line_number"]],
            hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
                "line_number": st.column_config.NumberColumn("Line/record #"),
            },
            height=520,
        )
        with st.expander("Show raw log text for the filtered events"):
            st.dataframe(df[["timestamp", "file_name", "line_number", "raw"]].head(500), hide_index=True)

    with tab_rejected:
        rejected = db.get_rejected_df()
        if rejected.empty:
            st.success("No records have been rejected.")
        else:
            st.caption("Records that failed validation are kept for transparency but never analysed.")
            st.metric("Rejected records", len(rejected))
            st.plotly_chart(_reason_chart(rejected), key="rej_reasons")
            st.dataframe(rejected, hide_index=True)


def _reason_chart(rejected):
    from dashboard.charts import horizontal_count_bar

    reasons = rejected["reason"].str.replace(r":.*$", "", regex=True).value_counts()
    return horizontal_count_bar(reasons, "Rejection reasons", color="#8b8b85", x_title="Records")
