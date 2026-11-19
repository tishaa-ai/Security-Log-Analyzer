"""Headless smoke tests for every dashboard section using Streamlit's AppTest."""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import dashboard.components as components
from database import Database
from pipeline import load_sample_data, run_analysis

APP = str(Path(__file__).resolve().parents[1] / "app.py")
PAGES = ["Overview", "Upload Logs", "Parsed Events", "Security Alerts", "Detection Rules",
         "Alert Investigation", "MITRE ATT&CK Mapping", "Reports", "Settings"]


@pytest.fixture
def app_db(tmp_path, monkeypatch):
    path = tmp_path / "dash.db"
    monkeypatch.setattr(components, "DB_PATH", path)
    components.get_db.clear()
    yield Database(path)
    components.get_db.clear()


def _run(page: str) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=60)
    at.session_state["nav"] = page
    at.run()
    return at


@pytest.mark.parametrize("page", PAGES)
def test_pages_render_with_empty_database(app_db, page) -> None:
    at = _run(page)
    assert not at.exception, at.exception


@pytest.mark.parametrize("page", PAGES)
def test_pages_render_with_sample_data(app_db, page) -> None:
    load_sample_data(app_db)
    run_analysis(app_db)
    at = _run(page)
    assert not at.exception, at.exception
    assert at.title[0].value  # each page has a heading


def test_overview_metrics_come_from_database(app_db) -> None:
    load_sample_data(app_db)
    run_analysis(app_db)
    at = _run("Overview")
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Log records processed"] == f"{app_db.get_ingestion_totals()['total']:,}"
    assert metrics["Alerts in range"] == str(len(app_db.get_alerts_df()))


def test_load_samples_button(app_db) -> None:
    at = _run("Upload Logs")
    at.button(key="load_samples").click().run()
    assert not at.exception
    assert app_db.count_events() > 0 and not app_db.get_alerts_df().empty


def test_status_update_from_investigation_page(app_db) -> None:
    load_sample_data(app_db)
    run_analysis(app_db)
    alert_id = app_db.get_alerts_df().iloc[0]["alert_id"]
    at = _run("Alert Investigation")
    at.selectbox[1].set_value("Investigating")  # [0] = alert picker, [1] = status
    at.button[0].click().run()
    assert not at.exception
    assert app_db.get_alert(alert_id)["status"] == "Investigating"
