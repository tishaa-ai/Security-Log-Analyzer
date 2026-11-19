"""Database, duplicate-upload prevention and alert lifecycle tests."""

from __future__ import annotations

import json

import pytest

from config import DetectionSettings
from pipeline import ingest_file, run_analysis

JSON_LOG = json.dumps([
    {"timestamp": f"2026-11-18T02:14:{i:02d}Z", "event_type": "login", "outcome": "failure",
     "username": "admin", "source_ip": "203.0.113.45"} for i in range(0, 60, 5)
] + [{"timestamp": "2026-11-18T02:15:30Z", "event_type": "login", "outcome": "success",
      "username": "admin", "source_ip": "203.0.113.45"}]).encode()


def test_schema_created(db) -> None:
    with db.connect() as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"uploaded_files", "events", "rejected_records", "alerts", "alert_status_history",
            "alert_notes", "analysis_runs", "settings"} <= tables


def test_ingest_stores_file_metadata_and_events(db) -> None:
    summary = ingest_file(db, "auth.json", JSON_LOG)
    assert summary.ok and not summary.duplicate_file
    assert summary.parsed_records == 13 and summary.inserted_events == 13
    files = db.list_files()
    assert len(files) == 1 and files.iloc[0]["file_name"] == "auth.json"
    assert db.count_events() == 13


def test_duplicate_file_upload_is_skipped(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    again = ingest_file(db, "renamed_copy.json", JSON_LOG)
    assert again.duplicate_file
    assert db.count_events() == 13 and len(db.list_files()) == 1


def test_overlapping_files_do_not_duplicate_events(db) -> None:
    lines = [json.dumps({"timestamp": f"2026-11-18T10:00:0{i}Z", "ip": "192.0.2.1", "user": "a",
                         "action": "login", "result": "failed"}) for i in range(4)]
    ingest_file(db, "part1.jsonl", "\n".join(lines[:3]).encode())
    second = ingest_file(db, "part2.jsonl", "\n".join(lines[1:]).encode())
    assert second.inserted_events == 1 and second.duplicate_events == 2
    assert db.count_events() == 4


def test_identical_lines_within_one_file_are_kept(db) -> None:
    line = "Nov 18 10:00:00 h app[1]: login failed for user bob from 192.0.2.5"
    ingest_file(db, "dup.log", f"{line}\n{line}\n".encode(), default_year=2026)
    assert db.count_events() == 2


def test_rejected_records_are_stored(db) -> None:
    ingest_file(db, "bad.log", b"garbage line\nNov 18 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1",
                default_year=2026)
    rejected = db.get_rejected_df()
    assert len(rejected) == 1 and "Unrecognised" in rejected.iloc[0]["reason"]


def test_failed_parse_stores_nothing(db) -> None:
    summary = ingest_file(db, "notes.txt", b"just some text\n")
    assert summary.error and db.count_events() == 0 and db.list_files().empty


def test_analysis_creates_alerts_and_history(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    summary = run_analysis(db, DetectionSettings.from_dict({"watchlist": []}))
    assert summary.alerts_generated >= 2  # AUTH-001 + AUTH-002 (+ AUTH-004 at night)
    alerts = db.get_alerts_df()
    assert set(alerts["status"]) == {"New"}
    assert len(db.list_runs()) == 1


def test_rerun_does_not_duplicate_alerts(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    s = DetectionSettings.from_dict({"watchlist": []})
    first = run_analysis(db, s)
    second = run_analysis(db, s)
    assert second.new_alerts == 0 and len(db.get_alerts_df()) == first.alerts_generated


def test_alert_status_update_and_history(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    run_analysis(db, DetectionSettings.from_dict({"watchlist": []}))
    alert_id = db.get_alerts_df().iloc[0]["alert_id"]

    assert db.update_alert_status(alert_id, "Investigating", "tier1") is True
    assert db.update_alert_status(alert_id, "Investigating", "tier1") is False  # unchanged
    assert db.update_alert_status(alert_id, "Resolved", "tier2") is True
    assert db.get_alert(alert_id)["status"] == "Resolved"

    history = db.get_status_history(alert_id)
    assert list(history["new_status"]) == ["New", "Investigating", "Resolved"]
    assert list(history["analyst"])[-1] == "tier2"


def test_status_survives_reanalysis(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    s = DetectionSettings.from_dict({"watchlist": []})
    run_analysis(db, s)
    alert_id = db.get_alerts_df().iloc[0]["alert_id"]
    db.update_alert_status(alert_id, "False Positive", "tier1")
    run_analysis(db, s)
    assert db.get_alert(alert_id)["status"] == "False Positive"


def test_invalid_status_and_unknown_alert(db) -> None:
    with pytest.raises(ValueError):
        db.update_alert_status("ALT-X", "Closed", "a")
    with pytest.raises(KeyError):
        db.update_alert_status("ALT-DOES-NOT-EXIST", "Resolved", "a")


def test_notes(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    run_analysis(db, DetectionSettings.from_dict({"watchlist": []}))
    alert_id = db.get_alerts_df().iloc[0]["alert_id"]
    db.add_note(alert_id, "Contacted user; login not recognised.", "tier1")
    notes = db.get_notes(alert_id)
    assert len(notes) == 1 and notes.iloc[0]["analyst"] == "tier1"
    with pytest.raises(ValueError):
        db.add_note(alert_id, "   ", "tier1")
    with pytest.raises(KeyError):
        db.add_note("ALT-NOPE", "text", "tier1")


def test_settings_round_trip(db) -> None:
    s = DetectionSettings.from_dict({"brute_force_threshold": 7, "watchlist": ["192.0.2.0/24"]})
    db.save_settings(s)
    loaded = db.load_settings()
    assert loaded.brute_force_threshold == 7 and loaded.watchlist == ["192.0.2.0/24"]


def test_settings_sanitised() -> None:
    s = DetectionSettings.from_dict({"brute_force_threshold": 0, "brute_force_window_minutes": "abc",
                                     "unknown_key": 1, "enabled_rules": {"AUTH-001": False, "BOGUS": True}})
    assert s.brute_force_threshold == 1
    assert s.brute_force_window_minutes == DetectionSettings().brute_force_window_minutes
    assert s.enabled_rules["AUTH-001"] is False and "BOGUS" not in s.enabled_rules


def test_reset_all(db) -> None:
    ingest_file(db, "auth.json", JSON_LOG)
    run_analysis(db, DetectionSettings.from_dict({"watchlist": []}))
    db.reset_all()
    assert db.count_events() == 0 and db.get_alerts_df().empty and db.list_files().empty
