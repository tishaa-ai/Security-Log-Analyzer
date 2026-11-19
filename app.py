"""Streamlit entry point.

Run with:  streamlit run app.py
"""

from __future__ import annotations

import streamlit as st

from config import APP_TITLE
from dashboard.components import get_db
from dashboard.theme import CSS
from dashboard.views import (
    alerts, events, investigation, mitre_view, overview, reports_view, rules, settings_view, upload,
)

st.set_page_config(page_title="Security Log Analyzer", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

PAGES = {
    "Overview": (":material/dashboard:", overview.render),
    "Upload Logs": (":material/upload_file:", upload.render),
    "Parsed Events": (":material/table_rows:", events.render),
    "Security Alerts": (":material/notifications_active:", alerts.render),
    "Detection Rules": (":material/rule:", rules.render),
    "Alert Investigation": (":material/search:", investigation.render),
    "MITRE ATT&CK Mapping": (":material/hub:", mitre_view.render),
    "Reports": (":material/description:", reports_view.render),
    "Settings": (":material/settings:", settings_view.render),
}

st.session_state.setdefault("nav", "Overview")

with st.sidebar:
    st.markdown(f"### 🛡️ {APP_TITLE}")
    st.caption("Defensive SOC triage · local & offline")
    page = st.radio("Navigation", list(PAGES), key="nav", label_visibility="collapsed",
                    format_func=lambda name: f"{PAGES[name][0]} {name}")
    st.divider()
    db = get_db()
    totals = db.get_ingestion_totals()
    alerts_df = db.get_alerts_df()
    open_alerts = int((alerts_df["status"].isin(["New", "Investigating"])).sum()) if not alerts_df.empty else 0
    st.caption(f"Files: {totals['files']} · Events: {db.count_events():,}")
    st.caption(f"Alerts: {len(alerts_df)} · Open: {open_alerts}")
    st.caption("All sample data is synthetic. Detections are indicators, not confirmed attacks.")

PAGES[page][1]()
