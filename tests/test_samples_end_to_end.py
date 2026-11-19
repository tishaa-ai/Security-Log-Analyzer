"""End-to-end checks against the bundled synthetic datasets."""

from __future__ import annotations

from pipeline import load_sample_data, run_analysis, sample_files
from utils.ip_utils import is_documentation_ip


def test_sample_files_are_labelled_synthetic() -> None:
    files = sample_files()
    assert len(files) == 3
    for path in files:
        assert "SYNTHETIC" in path.read_text(encoding="utf-8")[:400]


def test_sample_ips_are_documentation_ranges(db) -> None:
    load_sample_data(db)
    ips = db.get_events_df()["source_ip"].dropna().unique()
    assert len(ips) > 10
    assert all(is_documentation_ip(ip) for ip in ips)


def test_samples_ingest_with_expected_rejections(db) -> None:
    results = {r.file_name: r for r in load_sample_data(db)}
    assert results["sample_app_auth.json"].rejected_records == 5
    assert results["sample_linux_auth.log"].rejected_records == 4
    assert results["sample_web_access.jsonl"].rejected_records == 3
    assert all(r.ok for r in results.values())
    # Loading again must not duplicate anything.
    again = load_sample_data(db)
    assert all(r.duplicate_file for r in again)


def test_samples_trigger_every_rule(db) -> None:
    load_sample_data(db)
    summary = run_analysis(db)
    alerts = db.get_alerts_df()
    assert set(alerts["rule_id"]) == {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "NET-001",
                                      "HTTP-001", "HTTP-002"}
    assert summary.severity_counts["Critical"] >= 1
    crit = alerts[alerts["severity"] == "Critical"]
    assert set(crit["source_ip"]) == {"203.0.113.45", "203.0.113.12"}
    # Benign traffic (single typo, normal browsing) must not create brute-force alerts.
    assert not ((alerts["rule_id"] == "AUTH-002") & (alerts["username"] == "dave")).any()
