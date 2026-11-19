"""Upload Logs page: file upload, sample data and ingestion history."""

from __future__ import annotations

from datetime import datetime

import pandas as pd
import streamlit as st

from config import SUPPORTED_EXTENSIONS
from dashboard.components import get_db, page_header
from parsers.ingest import FORMAT_AUTO, FORMAT_JSON, FORMAT_SYSLOG
from pipeline import IngestSummary, ingest_file, load_sample_data, run_analysis

FORMAT_LABELS = {FORMAT_AUTO: "Auto-detect", FORMAT_JSON: "JSON / JSON Lines", FORMAT_SYSLOG: "Syslog / access log"}


def _show_results(results: list[IngestSummary]) -> None:
    for res in results:
        with st.container(border=True):
            if res.error:
                st.error(f"**{res.file_name}** — {res.error}")
            elif res.duplicate_file:
                st.warning(f"**{res.file_name}** — identical file already ingested; skipped to avoid duplicates.")
            else:
                st.success(f"**{res.file_name}** — parsed as {res.source_format}.")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Total records", res.total_records)
            c2.metric("Parsed", res.parsed_records)
            c3.metric("Rejected", res.rejected_records)
            c4.metric("New events stored", res.inserted_events,
                      help=f"{res.duplicate_events} event(s) were already stored from another file.")
            if res.rejected:
                with st.expander(f"Show {len(res.rejected)} rejected record(s)"):
                    st.dataframe(pd.DataFrame([r.to_dict() for r in res.rejected]), hide_index=True)


def _maybe_analyse(auto: bool) -> None:
    if auto:
        summary = run_analysis(get_db())
        st.session_state["last_analysis"] = summary


def render() -> None:
    page_header("Upload Logs", "Ingest JSON or Syslog files. Data stays local in SQLite.")
    db = get_db()

    left, right = st.columns([3, 2])
    with left:
        with st.form("upload_form", clear_on_submit=True):
            files = st.file_uploader(
                "Log files", accept_multiple_files=True,
                type=[ext.lstrip(".") for ext in sorted(SUPPORTED_EXTENSIONS)],
                help="JSON array/object, JSON Lines, RFC 3164/5424 syslog or Apache/Nginx access logs.",
            )
            c1, c2 = st.columns(2)
            fmt = c1.selectbox("Format", list(FORMAT_LABELS), format_func=FORMAT_LABELS.get)
            year = c2.number_input("Year for syslog lines without a year", min_value=1990, max_value=2100,
                                   value=datetime.now().year, step=1)
            auto = st.checkbox("Run detection automatically after ingestion", value=True)
            submitted = st.form_submit_button("Ingest files", type="primary")
        if submitted:
            if not files:
                st.warning("Choose at least one file first.")
            else:
                with st.spinner("Parsing and storing…"):
                    results = [ingest_file(db, f.name, f.getvalue(), fmt, int(year)) for f in files]
                    _maybe_analyse(auto and any(r.ok and not r.duplicate_file for r in results))
                st.session_state["upload_results"] = results

    with right:
        with st.container(border=True):
            st.markdown("#### Synthetic sample data")
            st.caption("Three clearly-labelled SYNTHETIC datasets (documentation-only IPs) covering normal "
                       "activity, brute force, password spraying, success-after-failure, HTTP 401/403 bursts, "
                       "web scanning and malformed records.")
            if st.button("Load sample datasets", type="primary", key="load_samples"):
                with st.spinner("Loading samples…"):
                    results = load_sample_data(db)
                    _maybe_analyse(any(r.ok and not r.duplicate_file for r in results))
                st.session_state["upload_results"] = results

    if summary := st.session_state.get("last_analysis"):
        st.info(f"Detection run #{summary.run_id}: analysed {summary.events_analyzed} events, "
                f"{summary.alerts_generated} alerts ({summary.new_alerts} new). "
                f"Severity: {summary.severity_counts}")

    if results := st.session_state.get("upload_results"):
        st.subheader("Latest ingestion results")
        _show_results(results)

    st.subheader("Upload history")
    files_df = db.list_files()
    if files_df.empty:
        st.caption("No files ingested yet.")
    else:
        st.dataframe(
            files_df[["id", "file_name", "file_format", "file_size", "uploaded_at", "total_records",
                      "parsed_records", "rejected_records", "inserted_events", "duplicate_events"]],
            hide_index=True,
            column_config={"file_hash": None, "uploaded_at": "Uploaded (UTC)", "file_size": "Bytes"},
        )
