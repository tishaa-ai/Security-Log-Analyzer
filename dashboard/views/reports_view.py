"""Reports page: CSV / JSON / PDF exports and analysis history."""

from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from config import ALERT_STATUSES, SEVERITIES
from dashboard.components import empty_state, get_db, page_header
from reports.exporters import report_from_db, report_to_csv, report_to_json, report_to_pdf


def render() -> None:
    page_header("Reports", "Export findings for hand-off. CSV cells are protected against formula injection.")
    db = get_db()
    alerts = db.get_alerts_df()
    if alerts.empty:
        empty_state("No alerts available to report.")
    else:
        c1, c2 = st.columns(2)
        sev = c1.multiselect("Include severities", SEVERITIES, default=list(SEVERITIES))
        status = c2.multiselect("Include statuses", ALERT_STATUSES, default=list(ALERT_STATUSES))
        scoped = alerts[alerts["severity"].isin(sev) & alerts["status"].isin(status)]
        scope = f"Severities: {', '.join(sev) or 'none'}; statuses: {', '.join(status) or 'none'}"
        st.write(f"**{len(scoped)}** alert(s) in scope.")

        if not scoped.empty:
            report = report_from_db(db, scoped, scope)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            d1, d2, d3 = st.columns(3)
            d1.download_button("⬇ CSV report", report_to_csv(report), f"alerts_{stamp}.csv",
                               mime="text/csv", type="primary")
            d2.download_button("⬇ JSON report", report_to_json(report), f"alerts_{stamp}.json",
                               mime="application/json", type="primary")
            with st.spinner("Building PDF…"):
                pdf_bytes = report_to_pdf(report)
            d3.download_button("⬇ PDF incident report", pdf_bytes, f"incident_report_{stamp}.pdf",
                               mime="application/pdf", type="primary")
            st.caption("Reports contain: analysis summary, severity counts, detection rule details, "
                       "evidence samples, investigation recommendations, MITRE references and analyst notes.")
            with st.expander("Preview report summary (JSON)"):
                st.json(report["summary"])

    st.subheader("Analysis history")
    runs = db.list_runs()
    if runs.empty:
        st.caption("Detection has not been run yet.")
    else:
        st.dataframe(runs, hide_index=True)
