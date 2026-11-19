"""Alert Investigation page: evidence, risk explanation, status and notes."""

from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from config import ALERT_STATUSES, DEFAULT_ANALYST
from dashboard import charts
from dashboard.components import (
    empty_state, get_db, indicator_note, page_header, severity_badge, status_badge,
)


def render() -> None:
    page_header("Alert Investigation", "Review evidence, record findings and track the alert lifecycle.")
    db = get_db()
    alerts = db.get_alerts_df()
    if alerts.empty:
        empty_state("There are no alerts to investigate.")
        return

    ids = alerts["alert_id"].tolist()
    labels = {
        row.alert_id: f"{row.alert_id} · {row.severity} · {row.rule_id} {row.rule_name} · {row.source_ip or '-'} · {row.status}"
        for row in alerts.itertuples()
    }
    preselected = st.session_state.get("selected_alert")
    index = ids.index(preselected) if preselected in ids else 0
    alert_id = st.selectbox("Alert (ordered by priority)", ids, index=index, format_func=labels.get)
    st.session_state["selected_alert"] = alert_id
    alert = db.get_alert(alert_id)
    if alert is None:
        st.error("Alert not found.")
        return

    # ---------------- header
    st.markdown(
        f"## {html.escape(alert['rule_name'])} &nbsp; {severity_badge(alert['severity'])} "
        f"{status_badge(alert['status'])}",
        unsafe_allow_html=True,
    )
    indicator_note()
    st.write(alert["description"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{alert['risk_score']}/100")
    c2.metric("Priority", alert["priority"])
    c3.metric("Supporting events", alert["event_count"])
    st.markdown(f"**Source IP:** `{alert['source_ip'] or '—'}` &nbsp;&nbsp; "
                f"**User(s):** `{alert['username'] or '—'}`")
    st.caption(f"Rule {alert['rule_id']} · first seen {alert['first_seen']} · last seen {alert['last_seen']} UTC · "
               f"alert created {alert['created_at']} · updated {alert['updated_at']}")

    tab_ev, tab_risk, tab_mitre, tab_steps = st.tabs(
        ["Evidence", "Risk explanation", "MITRE ATT&CK", "Recommended steps"])
    with tab_ev:
        evidence = pd.DataFrame(alert["evidence"]).dropna(axis=1, how="all")
        if alert["event_count"] > len(evidence):
            st.caption(f"Showing the first {len(evidence)} of {alert['event_count']} supporting events.")
        st.dataframe(evidence, hide_index=True)
    with tab_risk:
        st.plotly_chart(charts.risk_breakdown(alert["risk_factors"]), key="inv_risk")
        st.caption("Score = severity base + volume + context factors, capped at 100. "
                   "No random or hidden inputs are used.")
    with tab_mitre:
        if alert["mitre"]:
            for m in alert["mitre"]:
                st.markdown(f"**[{m['technique_id']} – {m['name']}]({m['url']})**  ·  "
                            f"Tactic(s): {', '.join(m['tactics'])}")
                st.write(f"Why: {m['rationale']}")
            st.caption("A mapping means the evidence is *consistent with* the technique — not that it is confirmed.")
        else:
            st.info("No ATT&CK technique is mapped: the available evidence does not support a specific technique.")
    with tab_steps:
        for i, step in enumerate(alert["recommendations"], start=1):
            st.markdown(f"{i}. {step}")

    st.divider()
    left, right = st.columns(2)

    # ---------------- status update
    with left:
        st.subheader("Update status")
        with st.form("status_form"):
            new_status = st.selectbox("Status", ALERT_STATUSES, index=ALERT_STATUSES.index(alert["status"]))
            analyst = st.text_input("Analyst name", value=st.session_state.get("analyst", DEFAULT_ANALYST))
            if st.form_submit_button("Save status", type="primary"):
                st.session_state["analyst"] = analyst
                if db.update_alert_status(alert_id, new_status, analyst):
                    st.success(f"Status changed to {new_status}.")
                    st.rerun()
                else:
                    st.info("Status unchanged.")
        st.markdown("**Status history**")
        st.dataframe(db.get_status_history(alert_id), hide_index=True)

    # ---------------- notes
    with right:
        st.subheader("Investigation notes")
        with st.form("note_form", clear_on_submit=True):
            note = st.text_area("Add a note", placeholder="e.g. Contacted account owner; login not recognised…")
            analyst = st.text_input("Analyst name ", value=st.session_state.get("analyst", DEFAULT_ANALYST))
            if st.form_submit_button("Add note"):
                if note.strip():
                    db.add_note(alert_id, note, analyst)
                    st.session_state["analyst"] = analyst
                    st.success("Note saved.")
                    st.rerun()
                else:
                    st.warning("The note is empty.")
        notes = db.get_notes(alert_id)
        if notes.empty:
            st.caption("No notes yet.")
        for row in notes.itertuples():
            with st.container(border=True):
                st.caption(f"{row.created_at} UTC · {row.analyst}")
                st.write(row.note)
