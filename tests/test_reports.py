"""CSV, JSON and PDF report tests (including formula-injection protection)."""

from __future__ import annotations

import csv
import io
import json

import pytest

from pipeline import load_sample_data, run_analysis
from reports.exporters import build_report_data, report_from_db, report_to_csv, report_to_json, report_to_pdf
from utils.security import sanitize_csv_cell


@pytest.fixture
def report(db):
    load_sample_data(db)
    run_analysis(db)
    alert_id = db.get_alerts_df().iloc[0]["alert_id"]
    db.add_note(alert_id, "=HYPERLINK(\"http://example.com\") test note", "tier1")
    return report_from_db(db, scope="test")


@pytest.mark.parametrize("value", ["=1+1", "+SUM(A1)", "-2+3", "@cmd", "\tx", "\rx", "|calc", "%0A"])
def test_sanitize_formula_prefixes(value) -> None:
    assert sanitize_csv_cell(value) == "'" + value


def test_sanitize_leaves_safe_values() -> None:
    assert sanitize_csv_cell("192.0.2.1") == "192.0.2.1"
    assert sanitize_csv_cell(-5) == -5
    assert sanitize_csv_cell(None) == ""


def test_csv_report(report) -> None:
    text = report_to_csv(report)
    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(report["alerts"]) > 0
    assert {"alert_id", "severity", "mitre_techniques", "recommendations", "evidence_sample"} <= set(rows[0])
    for row in rows:
        for value in row.values():
            assert not value.startswith(("=", "+", "-", "@")), value
    # The note text is preserved, and the cell itself never starts with a formula character.
    assert any("=HYPERLINK" in r["analyst_notes"] for r in rows)


def test_csv_injection_in_log_derived_fields() -> None:
    alert = {"alert_id": "ALT-1", "priority": "P3", "risk_score": 40, "severity": "Medium", "status": "New",
             "rule_id": "AUTH-001", "rule_name": "x", "timestamp": "t", "first_seen": "t", "last_seen": "t",
             "source_ip": "192.0.2.1", "username": "=cmd|' /C calc'!A0", "event_count": 1,
             "description": "@SUM(1)", "mitre": [], "risk_factors": [], "recommendations": [],
             "evidence": [], "analyst_notes": []}
    text = report_to_csv(build_report_data([alert]))
    row = next(csv.DictReader(io.StringIO(text)))
    assert row["username"].startswith("'=") and row["description"].startswith("'@")


def test_json_report_structure(report) -> None:
    data = json.loads(report_to_json(report))
    assert {"summary", "detection_rules", "mitre_references", "alerts", "disclaimer"} <= set(data)
    summary = data["summary"]
    assert summary["alerts_in_report"] == len(data["alerts"])
    assert sum(summary["alerts_by_severity"].values()) == len(data["alerts"])
    assert "not confirmed attacks" in data["disclaimer"]
    assert any(ref["technique_id"] == "T1110" for ref in data["mitre_references"])
    assert all("recommendations" in a and "evidence" in a for a in data["alerts"])


def test_pdf_report(report) -> None:
    pdf = report_to_pdf(report)
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000


def test_pdf_handles_unicode_and_empty_report() -> None:
    alert = {"alert_id": "ALT-2", "priority": "P4", "risk_score": 15, "severity": "Low", "status": "New",
             "rule_id": "AUTH-004", "rule_name": "Unusual Login Time", "timestamp": "t", "first_seen": "t",
             "last_seen": "t", "source_ip": None, "username": "żółw 用户", "event_count": 1,
             "description": "Unicode — test ✓", "mitre": [], "risk_factors": [], "recommendations": ["step"],
             "evidence": [{"timestamp": "t", "message": "✓ emoji 🚨"}], "analyst_notes": []}
    assert report_to_pdf(build_report_data([alert])).startswith(b"%PDF")
    assert report_to_pdf(build_report_data([])).startswith(b"%PDF")
