"""MITRE ATT&CK Mapping page."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from dashboard import charts
from dashboard.components import get_db, page_header
from detection.mitre import TECHNIQUES
from detection.rule_catalog import RULES


def render() -> None:
    page_header("MITRE ATT&CK Mapping", "Which techniques the observed indicators are consistent with — and why.")
    st.markdown(
        "**Indicator vs. confirmed attack.** A mapping below means the detection's evidence *matches the "
        "behaviour described by* an ATT&CK technique. It does not prove an adversary used it; only analyst "
        "investigation can confirm that. Rules whose evidence cannot support a technique carry no mapping."
    )
    db = get_db()
    alerts = db.get_alerts_df()

    rows = []
    for alert in alerts.itertuples() if not alerts.empty else []:
        for m in alert.mitre:
            rows.append({"technique_id": m["technique_id"], "alert_id": alert.alert_id,
                         "rule_id": alert.rule_id, "severity": alert.severity,
                         "status": alert.status, "source_ip": alert.source_ip, "rationale": m["rationale"]})
    mapped = pd.DataFrame(rows)

    catalog = []
    for tid, tech in TECHNIQUES.items():
        rules = [r.rule_id for r in RULES.values() if tid in r.mitre]
        n = int((mapped["technique_id"] == tid).sum()) if not mapped.empty else 0
        catalog.append({"Technique": tid, "Name": tech.name, "Tactic(s)": ", ".join(tech.tactics),
                        "Detecting rules": ", ".join(rules), "Alerts": n, "Reference": tech.url})
    catalog_df = pd.DataFrame(catalog)

    st.dataframe(catalog_df, hide_index=True,
                 column_config={"Reference": st.column_config.LinkColumn("Reference", display_text="attack.mitre.org")})
    counts = catalog_df.set_index("Technique")["Alerts"]
    st.plotly_chart(charts.horizontal_count_bar(counts[counts > 0], "Alerts per technique", x_title="Alerts"),
                    key="mitre_counts")

    st.subheader("Why each rule maps (or doesn't)")
    for info in RULES.values():
        label = ", ".join(info.mitre) if info.mitre else "No mapping"
        with st.expander(f"{info.rule_id} {info.name} → {label}"):
            st.write(info.mitre_note)

    st.subheader("Mapped alerts")
    if mapped.empty:
        st.caption("No alerts with ATT&CK mappings yet.")
    else:
        technique = st.selectbox("Technique", sorted(mapped["technique_id"].unique()),
                                 format_func=lambda t: f"{t} {TECHNIQUES[t].name}")
        st.dataframe(mapped[mapped["technique_id"] == technique], hide_index=True)
