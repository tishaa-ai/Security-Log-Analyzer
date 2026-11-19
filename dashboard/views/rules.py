"""Detection Rules page: what each rule does and its current configuration."""

from __future__ import annotations

import streamlit as st

from config import (
    RULE_BRUTE_FORCE, RULE_HTTP_AUTH_ERRORS, RULE_HTTP_SUSPICIOUS, RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS, RULE_SUCCESS_AFTER_FAILURES, RULE_WATCHLIST, DetectionSettings,
)
from dashboard.components import get_db, page_header
from detection.mitre import TECHNIQUES
from detection.rule_catalog import RULES


def _thresholds(rule_id: str, s: DetectionSettings) -> str:
    return {
        RULE_BRUTE_FORCE: f"≥ {s.brute_force_threshold} failures in {s.brute_force_window_minutes} min "
                          f"(High at ≥ {s.brute_force_high_threshold})",
        RULE_SUCCESS_AFTER_FAILURES: f"≥ {s.success_after_failures_threshold} failures within "
                                     f"{s.success_after_failures_window_minutes} min before a success",
        RULE_MULTI_ACCOUNT: f"≥ {s.multi_account_threshold} distinct accounts in {s.multi_account_window_minutes} min",
        RULE_OFF_HOURS: f"Business hours {s.business_hours_start:02d}:00–{s.business_hours_end:02d}:00 UTC; "
                        f"weekends flagged: {'yes' if s.flag_weekend_logins else 'no'}; privileged: "
                        f"{', '.join(s.privileged_accounts) or 'none'}",
        RULE_WATCHLIST: f"{len(s.watchlist)} watchlist entr{'y' if len(s.watchlist) == 1 else 'ies'}",
        RULE_HTTP_AUTH_ERRORS: f"≥ {s.http_error_threshold} 401/403 responses in {s.http_error_window_minutes} min",
        RULE_HTTP_SUSPICIOUS: f"≥ {s.http_scan_distinct_paths} distinct paths (≥50% errors) in "
                              f"{s.http_scan_window_minutes} min, ≥ 2 sensitive paths, or exploit patterns",
    }[rule_id]


def render() -> None:
    page_header("Detection Rules", "Transparent, configurable rules. Change thresholds on the Settings page.")
    db = get_db()
    settings = db.load_settings()
    alerts = db.get_alerts_df()
    counts = alerts["rule_id"].value_counts().to_dict() if not alerts.empty else {}

    for rule_id, info in RULES.items():
        enabled = settings.is_enabled(rule_id)
        with st.container(border=True):
            top, badge = st.columns([5, 1])
            top.markdown(f"### {rule_id} · {info.name}")
            badge.badge("Enabled" if enabled else "Disabled", color="green" if enabled else "gray",
                        icon=":material/check_circle:" if enabled else ":material/block:")
            st.write(info.description)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**How it works:** {info.logic}")
                st.markdown(f"**Current thresholds:** {_thresholds(rule_id, settings)}")
                st.markdown(f"**Severity logic:** {info.severity_logic}")
            with c2:
                if info.mitre:
                    techniques = ", ".join(f"[{t} {TECHNIQUES[t].name}]({TECHNIQUES[t].url})" for t in info.mitre)
                    st.markdown(f"**MITRE ATT&CK:** {techniques}")
                else:
                    st.markdown("**MITRE ATT&CK:** none assigned (by design)")
                st.caption(info.mitre_note)
                st.markdown(f"**Alerts currently stored:** {counts.get(rule_id, 0)}")
            with st.expander("Recommended investigation steps"):
                for i, step in enumerate(info.recommendations, start=1):
                    st.markdown(f"{i}. {step}")
