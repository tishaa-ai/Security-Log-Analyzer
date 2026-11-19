"""CSV, JSON and PDF report generation.

All reports are built from a single report dictionary created by
:func:`build_report_data`, so the three formats always agree.
"""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import Any

import pandas as pd
from fpdf import FPDF
from fpdf.enums import XPos, YPos

from config import APP_TITLE, SEVERITIES
from detection.rule_catalog import RULES
from utils.security import pdf_safe, sanitize_csv_cell
from utils.time_utils import utc_now_str

DISCLAIMER = (
    "Alerts in this report are DETECTION INDICATORS produced by rule-based analysis of the supplied "
    "logs. They are not confirmed attacks and require analyst validation. MITRE ATT&CK mappings mean "
    "the observed behaviour is consistent with a technique, not that the technique was proven. "
    "No IP addresses were scanned or blocked."
)

CSV_COLUMNS = (
    "alert_id", "priority", "risk_score", "severity", "status", "rule_id", "rule_name",
    "timestamp", "first_seen", "last_seen", "source_ip", "username", "event_count",
    "description", "mitre_techniques", "risk_factors", "recommendations", "evidence_sample",
    "analyst_notes",
)


# ---------------------------------------------------------------------------
# Report data
# ---------------------------------------------------------------------------
def alerts_df_to_records(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Convert the alerts DataFrame from the database into JSON-friendly dicts."""
    if df is None or df.empty:
        return []
    records = []
    for row in df.to_dict("records"):
        clean: dict[str, Any] = {}
        for key, value in row.items():
            if isinstance(value, pd.Timestamp):
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            elif not isinstance(value, (list, dict)) and pd.isna(value):
                value = None
            elif hasattr(value, "item"):  # numpy scalar -> python
                value = value.item()
            clean[key] = value
        records.append(clean)
    return records


def build_report_data(
    alerts: list[dict[str, Any]],
    ingestion: dict[str, int] | None = None,
    events_stored: int = 0,
    notes: dict[str, list[dict[str, Any]]] | None = None,
    filters_description: str = "All alerts",
) -> dict[str, Any]:
    """Assemble everything a report needs into one dictionary."""
    ingestion = ingestion or {"files": 0, "total": 0, "parsed": 0, "rejected": 0}
    notes = notes or {}
    severity_counts = Counter(a["severity"] for a in alerts)
    status_counts = Counter(a.get("status", "New") for a in alerts)
    rule_counts = Counter(a["rule_id"] for a in alerts)
    ip_counts = Counter(a["source_ip"] for a in alerts if a.get("source_ip"))

    mitre_refs: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        for m in alert.get("mitre") or []:
            ref = mitre_refs.setdefault(m["technique_id"], {
                "technique_id": m["technique_id"], "name": m["name"], "tactics": m["tactics"],
                "url": m["url"], "alert_count": 0, "example_rationale": m["rationale"],
            })
            ref["alert_count"] += 1

    enriched = []
    for alert in alerts:
        item = dict(alert)
        item["analyst_notes"] = notes.get(alert["alert_id"], [])
        enriched.append(item)

    return {
        "title": APP_TITLE,
        "generated_at_utc": utc_now_str(),
        "scope": filters_description,
        "disclaimer": DISCLAIMER,
        "summary": {
            "files_ingested": ingestion["files"],
            "total_records": ingestion["total"],
            "parsed_records": ingestion["parsed"],
            "rejected_records": ingestion["rejected"],
            "events_stored": events_stored,
            "alerts_in_report": len(alerts),
            "alerts_by_severity": {sev: severity_counts.get(sev, 0) for sev in SEVERITIES},
            "alerts_by_status": dict(status_counts),
            "alerts_by_rule": dict(sorted(rule_counts.items())),
            "top_source_ips": [{"source_ip": ip, "alerts": n} for ip, n in ip_counts.most_common(10)],
        },
        "detection_rules": [
            {
                "rule_id": info.rule_id, "name": info.name, "category": info.category,
                "description": info.description, "logic": info.logic,
                "severity_logic": info.severity_logic, "mitre_techniques": list(info.mitre),
                "mitre_note": info.mitre_note, "alerts_in_report": rule_counts.get(info.rule_id, 0),
            }
            for info in RULES.values()
        ],
        "mitre_references": sorted(mitre_refs.values(), key=lambda r: r["technique_id"]),
        "alerts": enriched,
    }


def report_from_db(db: Any, alerts_df: pd.DataFrame | None = None, scope: str = "All alerts") -> dict[str, Any]:
    """Convenience wrapper that pulls everything from the :class:`Database`."""
    df = db.get_alerts_df() if alerts_df is None else alerts_df
    alerts = alerts_df_to_records(df)
    notes_df = db.get_all_notes()
    notes: dict[str, list[dict[str, Any]]] = {}
    for row in notes_df.to_dict("records"):
        notes.setdefault(row["alert_id"], []).append(
            {"created_at": row["created_at"], "analyst": row["analyst"], "note": row["note"]}
        )
    return build_report_data(alerts, db.get_ingestion_totals(), db.count_events(), notes, scope)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def report_to_csv(report: dict[str, Any]) -> str:
    """One row per alert. Every cell is protected against formula injection."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for alert in report["alerts"]:
        evidence = alert.get("evidence") or []
        row = {
            **alert,
            "mitre_techniques": "; ".join(f"{m['technique_id']} {m['name']}" for m in alert.get("mitre") or []),
            "risk_factors": "; ".join(f"{f['reason']} (+{f['points']})" for f in alert.get("risk_factors") or []),
            "recommendations": " | ".join(alert.get("recommendations") or []),
            "evidence_sample": " || ".join(
                f"{e.get('timestamp')} {e.get('message') or e.get('url_path') or ''}" for e in evidence[:3]
            ),
            "analyst_notes": " | ".join(
                f"[{n['created_at']} {n['analyst']}] {n['note']}" for n in alert.get("analyst_notes") or []
            ),
        }
        writer.writerow([sanitize_csv_cell(row.get(column)) for column in CSV_COLUMNS])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
SEVERITY_COLORS: dict[str, tuple[int, int, int]] = {
    "Critical": (190, 18, 60), "High": (234, 88, 12), "Medium": (202, 138, 4), "Low": (37, 99, 235),
}


class _ReportPDF(FPDF):
    def header(self) -> None:
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 6, pdf_safe(f"{APP_TITLE} - Incident Report"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.ln(1)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 6, f"Page {self.page_no()} - Detection indicators only; validate before acting.",
                  align="C")


def _heading(pdf: FPDF, text: str, size: int = 13) -> None:
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", size)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(0, 7, pdf_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)


def _para(pdf: FPDF, text: str, size: int = 9, style: str = "") -> None:
    pdf.set_font("Helvetica", style, size)
    pdf.multi_cell(0, 4.8, pdf_safe(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _kv_table(pdf: FPDF, rows: list[tuple[str, str]], widths: tuple[int, int] = (70, 110)) -> None:
    pdf.set_font("Helvetica", "", 9)
    with pdf.table(col_widths=widths, text_align="LEFT", line_height=5.5,
                   first_row_as_headings=False) as table:
        for key, value in rows:
            r = table.row()
            r.cell(pdf_safe(key))
            r.cell(pdf_safe(value))


def report_to_pdf(report: dict[str, Any], max_alerts: int = 50, max_evidence: int = 5) -> bytes:
    """Render the report as a PDF incident report and return the bytes."""
    pdf = _ReportPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.set_margins(15, 12, 15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.multi_cell(0, 9, "Security Incident Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    _para(pdf, f"Generated (UTC): {report['generated_at_utc']}    Scope: {report['scope']}")
    pdf.ln(2)
    pdf.set_fill_color(254, 243, 199)
    pdf.set_font("Helvetica", "B", 9)
    pdf.multi_cell(0, 4.8, pdf_safe("IMPORTANT: " + report["disclaimer"]), fill=True,
                   new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    summary = report["summary"]
    _heading(pdf, "1. Analysis Summary")
    _kv_table(pdf, [
        ("Files ingested", str(summary["files_ingested"])),
        ("Total log records", str(summary["total_records"])),
        ("Successfully parsed", str(summary["parsed_records"])),
        ("Rejected (malformed)", str(summary["rejected_records"])),
        ("Events stored (deduplicated)", str(summary["events_stored"])),
        ("Alerts in this report", str(summary["alerts_in_report"])),
        ("Alerts by status", ", ".join(f"{k}: {v}" for k, v in summary["alerts_by_status"].items()) or "-"),
        ("Top source IPs", ", ".join(f"{i['source_ip']} ({i['alerts']})" for i in summary["top_source_ips"][:5]) or "-"),
    ])

    _heading(pdf, "2. Alert Counts by Severity")
    pdf.set_font("Helvetica", "B", 10)
    for sev in SEVERITIES:
        pdf.set_fill_color(*SEVERITY_COLORS[sev])
        pdf.set_text_color(255, 255, 255)
        pdf.cell(42, 9, f"{sev}: {summary['alerts_by_severity'][sev]}", border=0, align="C", fill=True)
        pdf.cell(3, 9, "")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(12)

    _heading(pdf, "3. Detection Rules")
    pdf.set_font("Helvetica", "", 8)
    with pdf.table(col_widths=(18, 42, 70, 25, 15), text_align="LEFT", line_height=4.5) as table:
        header = table.row()
        for title in ("Rule", "Name", "Logic / severity", "MITRE", "Alerts"):
            header.cell(title)
        for rule in report["detection_rules"]:
            r = table.row()
            r.cell(rule["rule_id"])
            r.cell(pdf_safe(rule["name"]))
            r.cell(pdf_safe(f"{rule['logic']} Severity: {rule['severity_logic']}", 400))
            r.cell(", ".join(rule["mitre_techniques"]) or "None (by design)")
            r.cell(str(rule["alerts_in_report"]))

    _heading(pdf, "4. MITRE ATT&CK References")
    if report["mitre_references"]:
        for ref in report["mitre_references"]:
            _para(pdf, f"{ref['technique_id']} - {ref['name']} [{', '.join(ref['tactics'])}] - "
                       f"{ref['alert_count']} alert(s)", style="B")
            _para(pdf, f"Why: {ref['example_rationale']}  Reference: {ref['url']}")
    else:
        _para(pdf, "No alerts in scope carry an ATT&CK mapping.")
    _para(pdf, "Rules without a mapping (AUTH-004 unusual time, NET-001 watchlist) intentionally carry none: "
               "the evidence does not show a specific technique.", style="I")

    alerts = report["alerts"][:max_alerts]
    _heading(pdf, f"5. Alert Details ({len(alerts)} of {len(report['alerts'])}, highest priority first)")
    for alert in alerts:
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(*SEVERITY_COLORS.get(alert["severity"], (0, 0, 0)))
        pdf.multi_cell(0, 6, pdf_safe(
            f"{alert['alert_id']}  [{alert['severity']} | {alert['priority']} | risk {alert['risk_score']}]  "
            f"{alert['rule_id']} {alert['rule_name']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        _para(pdf, f"Status: {alert.get('status')}   Source IP: {alert.get('source_ip') or '-'}   "
                   f"User(s): {alert.get('username') or '-'}   Window: {alert['first_seen']} -> {alert['last_seen']} UTC")
        _para(pdf, alert["description"])
        factors = "; ".join(f"{f['reason']} (+{f['points']})" for f in alert.get("risk_factors") or [])
        _para(pdf, f"Risk score explanation: {factors}", size=8, style="I")
        if alert.get("mitre"):
            for m in alert["mitre"]:
                _para(pdf, f"MITRE {m['technique_id']} {m['name']}: {m['rationale']}", size=8)
        else:
            _para(pdf, "MITRE: no technique assigned (insufficient evidence for a mapping).", size=8)
        _para(pdf, "Evidence (sample):", size=8, style="B")
        for ev in (alert.get("evidence") or [])[:max_evidence]:
            detail = ev.get("message") or f"{ev.get('http_method') or ''} {ev.get('url_path') or ''} {ev.get('status_code') or ''}"
            _para(pdf, f"  {ev.get('timestamp')}  {ev.get('source_ip') or '-'}  {ev.get('event_type')}  "
                       f"{pdf_safe(detail, 140)}", size=7)
        _para(pdf, "Recommended investigation steps:", size=8, style="B")
        for i, step in enumerate(alert.get("recommendations") or [], start=1):
            _para(pdf, f"  {i}. {step}", size=8)
        for note in alert.get("analyst_notes") or []:
            _para(pdf, f"  Note [{note['created_at']} {note['analyst']}]: {note['note']}", size=8, style="I")
        pdf.set_draw_color(203, 213, 225)
        pdf.line(15, pdf.get_y() + 1, 195, pdf.get_y() + 1)
        pdf.ln(2)

    return bytes(pdf.output())
