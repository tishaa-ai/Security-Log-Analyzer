"""Settings page: thresholds, watchlist, rule switches and data reset."""

from __future__ import annotations

import streamlit as st

from config import ALL_RULE_IDS, DetectionSettings
from dashboard.components import get_db, page_header
from detection.rule_catalog import RULES
from pipeline import run_analysis
from utils.ip_utils import parse_watchlist


def render() -> None:
    page_header("Settings", "Tune detection thresholds. Changes are stored in SQLite.")
    db = get_db()
    s = db.load_settings()

    with st.form("settings_form"):
        st.markdown("#### Authentication rules")
        c1, c2, c3 = st.columns(3)
        bf_t = c1.number_input("AUTH-001 failures threshold", 1, 1000, s.brute_force_threshold)
        bf_w = c2.number_input("AUTH-001 window (minutes)", 1, 1440, s.brute_force_window_minutes)
        bf_h = c3.number_input("AUTH-001 High-severity threshold", 1, 1000, s.brute_force_high_threshold)
        c1, c2 = st.columns(2)
        sf_t = c1.number_input("AUTH-002 prior failures", 1, 1000, s.success_after_failures_threshold)
        sf_w = c2.number_input("AUTH-002 window (minutes)", 1, 1440, s.success_after_failures_window_minutes)
        c1, c2 = st.columns(2)
        ma_t = c1.number_input("AUTH-003 distinct accounts", 1, 1000, s.multi_account_threshold)
        ma_w = c2.number_input("AUTH-003 window (minutes)", 1, 1440, s.multi_account_window_minutes)
        c1, c2, c3 = st.columns(3)
        bh_s = c1.number_input("AUTH-004 business hours start (UTC)", 0, 23, s.business_hours_start)
        bh_e = c2.number_input("AUTH-004 business hours end (UTC)", 1, 24, s.business_hours_end)
        weekend = c3.checkbox("Flag weekend logins", s.flag_weekend_logins)
        privileged = st.text_input("Privileged accounts (comma separated)", ", ".join(s.privileged_accounts))

        st.markdown("#### HTTP rules")
        c1, c2, c3, c4 = st.columns(4)
        he_t = c1.number_input("HTTP-001 401/403 threshold", 1, 10000, s.http_error_threshold)
        he_w = c2.number_input("HTTP-001 window (minutes)", 1, 1440, s.http_error_window_minutes)
        hs_p = c3.number_input("HTTP-002 distinct paths", 1, 10000, s.http_scan_distinct_paths)
        hs_w = c4.number_input("HTTP-002 window (minutes)", 1, 1440, s.http_scan_window_minutes)

        st.markdown("#### Local IP watchlist (NET-001)")
        st.caption("One IP or CIDR per line; text after # is a comment. Used for matching only — "
                   "no lookups, scans or blocking.")
        watchlist_text = st.text_area("Watchlist", "\n".join(s.watchlist), height=150)

        st.markdown("#### Enabled rules")
        cols = st.columns(4)
        enabled = {rid: cols[i % 4].checkbox(f"{rid} {RULES[rid].name}", s.is_enabled(rid), key=f"en_{rid}")
                   for i, rid in enumerate(ALL_RULE_IDS)}
        rerun = st.checkbox("Re-run detection after saving", value=True)
        saved = st.form_submit_button("Save settings", type="primary")

    if saved:
        entries = [line.strip() for line in watchlist_text.splitlines() if line.split("#", 1)[0].strip()]
        _, invalid = parse_watchlist(entries)
        if invalid:
            st.error("Invalid watchlist entr(ies) — fix them before saving: " + ", ".join(invalid))
        else:
            new = DetectionSettings.from_dict({
                "brute_force_threshold": bf_t, "brute_force_window_minutes": bf_w,
                "brute_force_high_threshold": bf_h,
                "success_after_failures_threshold": sf_t, "success_after_failures_window_minutes": sf_w,
                "multi_account_threshold": ma_t, "multi_account_window_minutes": ma_w,
                "business_hours_start": bh_s, "business_hours_end": bh_e, "flag_weekend_logins": weekend,
                "privileged_accounts": [p.strip() for p in privileged.split(",")],
                "http_error_threshold": he_t, "http_error_window_minutes": he_w,
                "http_scan_distinct_paths": hs_p, "http_scan_window_minutes": hs_w,
                "watchlist": [e.split("#", 1)[0].strip() for e in entries],
                "enabled_rules": enabled,
            })
            db.save_settings(new)
            st.success("Settings saved.")
            if rerun and db.count_events():
                summary = run_analysis(db, new)
                st.info(f"Detection re-run: {summary.alerts_generated} alerts ({summary.new_alerts} new).")

    c1, c2 = st.columns(2)
    if c1.button("Restore default settings"):
        db.save_settings(DetectionSettings())
        st.success("Defaults restored.")
        st.rerun()

    st.divider()
    st.markdown("#### Danger zone")
    st.caption("Deletes all uploaded files, events, alerts, notes and history from this app's own SQLite "
               "database. Settings are kept. Nothing outside the app is affected.")
    confirm = st.text_input("Type RESET to confirm")
    if st.button("Reset application data", disabled=confirm != "RESET"):
        db.reset_all()
        for key in ("upload_results", "last_analysis", "selected_alert"):
            st.session_state.pop(key, None)
        st.success("All application data deleted.")
