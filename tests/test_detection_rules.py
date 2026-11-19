"""Detection rule tests (one section per rule)."""

from __future__ import annotations

from datetime import datetime

from config import (
    RULE_BRUTE_FORCE, RULE_HTTP_AUTH_ERRORS, RULE_HTTP_SUSPICIOUS, RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS, RULE_SUCCESS_AFTER_FAILURES, RULE_WATCHLIST, DetectionSettings,
)
from detection.engine import run_detection
from tests.conftest import failures, make_events, success, ts


def _by_rule(alerts, rule_id):
    return [a for a in alerts if a["rule_id"] == rule_id]


def _only(settings: DetectionSettings, *rule_ids: str) -> DetectionSettings:
    settings.enabled_rules = {rid: rid in rule_ids for rid in settings.enabled_rules}
    return settings


# ---------------------------------------------------------------- AUTH-001
def test_failed_login_threshold_medium(settings) -> None:
    alerts = run_detection(make_events(failures("192.0.2.77", 5)), _only(settings, RULE_BRUTE_FORCE))
    hits = _by_rule(alerts, RULE_BRUTE_FORCE)
    assert len(hits) == 1
    assert hits[0]["severity"] == "Medium" and hits[0]["source_ip"] == "192.0.2.77"
    assert hits[0]["event_count"] == 5
    assert [m["technique_id"] for m in hits[0]["mitre"]] == ["T1110.001"]


def test_failed_login_below_threshold_no_alert(settings) -> None:
    alerts = run_detection(make_events(failures("192.0.2.77", 4)), _only(settings, RULE_BRUTE_FORCE))
    assert alerts == []


def test_failed_login_high_severity(settings) -> None:
    alerts = run_detection(make_events(failures("192.0.2.77", 12)), _only(settings, RULE_BRUTE_FORCE))
    assert alerts[0]["severity"] == "High"


def test_failures_spread_beyond_window_do_not_alert(settings) -> None:
    # 6 failures, one every 5 minutes: never 5 inside a 10-minute window.
    rows = failures("192.0.2.77", 6, step_s=300)
    alerts = run_detection(make_events(rows), _only(settings, RULE_BRUTE_FORCE))
    assert alerts == []


def test_failures_counted_per_ip(settings) -> None:
    rows = failures("192.0.2.1", 3) + failures("192.0.2.2", 3)
    assert run_detection(make_events(rows), _only(settings, RULE_BRUTE_FORCE)) == []


def test_alert_has_all_required_fields(settings) -> None:
    alert = run_detection(make_events(failures("192.0.2.77", 6)), _only(settings, RULE_BRUTE_FORCE))[0]
    for key in ("alert_id", "timestamp", "rule_id", "rule_name", "source_ip", "username", "severity",
                "description", "evidence", "recommendations", "mitre", "status", "risk_score", "risk_factors"):
        assert key in alert
    assert alert["alert_id"].startswith("ALT-") and alert["status"] == "New"
    assert alert["evidence"][0]["source_ip"] == "192.0.2.77"
    assert len(alert["recommendations"]) >= 3


def test_alert_ids_are_deterministic(settings) -> None:
    events = make_events(failures("192.0.2.77", 6))
    first = run_detection(events, _only(settings, RULE_BRUTE_FORCE))[0]["alert_id"]
    second = run_detection(events, _only(settings, RULE_BRUTE_FORCE))[0]["alert_id"]
    assert first == second


# ---------------------------------------------------------------- AUTH-002
def test_success_after_failures_same_account_is_critical(settings) -> None:
    rows = failures("192.0.2.77", 6, user="admin") + [success("192.0.2.77", "admin", 3)]
    alerts = run_detection(make_events(rows), _only(settings, RULE_SUCCESS_AFTER_FAILURES))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "Critical" and alert["username"] == "admin"
    assert {m["technique_id"] for m in alert["mitre"]} == {"T1110", "T1078"}
    assert alert["evidence"][0]["event_type"] == "auth_success"  # key event first


def test_success_after_few_failures_is_high(settings) -> None:
    rows = failures("192.0.2.77", 3, user="bob") + [success("192.0.2.77", "bob", 2)]
    alerts = run_detection(make_events(rows), _only(settings, RULE_SUCCESS_AFTER_FAILURES))
    assert alerts[0]["severity"] == "High"


def test_single_typo_then_success_is_not_flagged(settings) -> None:
    rows = failures("192.0.2.13", 1, user="dave") + [success("192.0.2.13", "dave", 1)]
    assert run_detection(make_events(rows), _only(settings, RULE_SUCCESS_AFTER_FAILURES)) == []


def test_success_long_after_failures_is_not_flagged(settings) -> None:
    rows = failures("192.0.2.77", 6) + [success("192.0.2.77", "admin", 120)]
    assert run_detection(make_events(rows), _only(settings, RULE_SUCCESS_AFTER_FAILURES)) == []


# ---------------------------------------------------------------- AUTH-003
def test_multiple_accounts_from_one_ip(settings) -> None:
    rows = []
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        rows += failures("198.51.100.77", 1, user=user, start=i)
    alerts = run_detection(make_events(rows), _only(settings, RULE_MULTI_ACCOUNT))
    assert len(alerts) == 1 and alerts[0]["severity"] == "High"
    assert alerts[0]["mitre"][0]["technique_id"] == "T1110.003"


def test_multiple_accounts_with_success_is_critical(settings) -> None:
    rows = []
    for i, user in enumerate(["alice", "bob", "carol"]):
        rows += failures("198.51.100.77", 1, user=user, start=i)
    rows.append(success("198.51.100.77", "carol", 5))
    alerts = run_detection(make_events(rows), _only(settings, RULE_MULTI_ACCOUNT))
    assert alerts[0]["severity"] == "Critical"


def test_same_account_failures_do_not_trigger_multi_account(settings) -> None:
    rows = failures("198.51.100.77", 10, user="alice")
    assert run_detection(make_events(rows), _only(settings, RULE_MULTI_ACCOUNT)) == []


# ---------------------------------------------------------------- AUTH-004
def test_unusual_login_time_night(settings) -> None:
    night = datetime(2026, 11, 18, 2, 30)
    alerts = run_detection(make_events([success("192.0.2.11", "bob", 0, base=night)]),
                           _only(settings, RULE_OFF_HOURS))
    assert len(alerts) == 1 and alerts[0]["severity"] == "Low" and alerts[0]["mitre"] == []


def test_unusual_login_privileged_account_is_medium(settings) -> None:
    night = datetime(2026, 11, 18, 23, 0)
    alerts = run_detection(make_events([success("192.0.2.11", "root", 0, base=night)]),
                           _only(settings, RULE_OFF_HOURS))
    assert alerts[0]["severity"] == "Medium"


def test_weekend_login_flag(settings) -> None:
    saturday = datetime(2026, 11, 21, 11, 0)
    events = make_events([success("192.0.2.12", "carol", 0, base=saturday)])
    assert len(run_detection(events, _only(settings, RULE_OFF_HOURS))) == 1
    settings.flag_weekend_logins = False
    assert run_detection(events, _only(settings, RULE_OFF_HOURS)) == []


def test_business_hours_login_not_flagged(settings) -> None:
    events = make_events([success("192.0.2.11", "bob", 0)])  # Wednesday 10:00
    assert run_detection(events, _only(settings, RULE_OFF_HOURS)) == []


# ---------------------------------------------------------------- NET-001
def test_watchlist_exact_ip_and_cidr(settings) -> None:
    rows = [
        {"timestamp": ts(0), "event_type": "system", "source_ip": "203.0.113.45", "message": "x"},
        {"timestamp": ts(1), "event_type": "auth_failure", "source_ip": "198.51.100.5", "username": "a"},
        {"timestamp": ts(2), "event_type": "auth_success", "source_ip": "198.51.100.6", "username": "b"},
        {"timestamp": ts(3), "event_type": "auth_success", "source_ip": "192.0.2.1", "username": "c"},
    ]
    alerts = run_detection(make_events(rows), _only(settings, RULE_WATCHLIST))
    by_ip = {a["source_ip"]: a for a in alerts}
    assert set(by_ip) == {"203.0.113.45", "198.51.100.5", "198.51.100.6"}
    assert by_ip["203.0.113.45"]["severity"] == "Low"
    assert by_ip["198.51.100.5"]["severity"] == "Medium"
    assert by_ip["198.51.100.6"]["severity"] == "High"
    assert all(a["mitre"] == [] for a in alerts)  # reputation only -> no technique


def test_invalid_watchlist_entries_are_ignored() -> None:
    s = DetectionSettings.from_dict({"watchlist": ["not-an-ip", "300.1.1.1", "203.0.113.45"]})
    rows = [{"timestamp": ts(0), "event_type": "system", "source_ip": "203.0.113.45", "message": "x"}]
    alerts = run_detection(make_events(rows), _only(s, RULE_WATCHLIST))
    assert len(alerts) == 1


def test_empty_watchlist_no_alerts() -> None:
    s = DetectionSettings.from_dict({"watchlist": []})
    rows = [{"timestamp": ts(0), "event_type": "system", "source_ip": "203.0.113.45", "message": "x"}]
    assert run_detection(make_events(rows), _only(s, RULE_WATCHLIST)) == []


# ---------------------------------------------------------------- HTTP-001 / HTTP-002
def _http(ip: str, path: str, status: int, seconds: int) -> dict:
    return {"timestamp": ts(0, seconds), "event_type": "http_request", "source_ip": ip,
            "http_method": "GET", "url_path": path, "status_code": status}


def test_repeated_401_on_login_maps_to_t1110(settings) -> None:
    rows = [_http("203.0.113.99", "/api/login", 401, i * 5) for i in range(12)]
    alerts = run_detection(make_events(rows), _only(settings, RULE_HTTP_AUTH_ERRORS))
    assert len(alerts) == 1 and alerts[0]["severity"] == "Medium"
    assert alerts[0]["mitre"][0]["technique_id"] == "T1110"


def test_repeated_403_without_login_paths_has_no_mapping(settings) -> None:
    rows = [_http("203.0.113.140", "/admin", 403, i * 5) for i in range(25)]
    alerts = run_detection(make_events(rows), _only(settings, RULE_HTTP_AUTH_ERRORS))
    assert alerts[0]["severity"] == "High" and alerts[0]["mitre"] == []


def test_http_scanning_and_exploit_patterns(settings) -> None:
    paths = [f"/dir{i}" for i in range(15)] + ["/.env", "/.git/config", "/../../etc/passwd"]
    rows = [_http("198.51.100.23", p, 404, i * 3) for i, p in enumerate(paths)]
    alerts = run_detection(make_events(rows), _only(settings, RULE_HTTP_SUSPICIOUS))
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert {m["technique_id"] for m in alerts[0]["mitre"]} == {"T1595.003", "T1190"}


def test_normal_browsing_is_not_suspicious(settings) -> None:
    rows = [_http("192.0.2.20", p, 200, i * 30) for i, p in enumerate(["/", "/products", "/cart", "/help"])]
    assert run_detection(make_events(rows), _only(settings, RULE_HTTP_SUSPICIOUS)) == []


# ---------------------------------------------------------------- engine
def test_disabled_rules_do_not_run(settings) -> None:
    settings.enabled_rules = {rid: False for rid in settings.enabled_rules}
    assert run_detection(make_events(failures("192.0.2.77", 20)), settings) == []


def test_empty_events_returns_no_alerts(settings) -> None:
    import pandas as pd
    assert run_detection(pd.DataFrame(), settings) == []


def test_events_without_ip_are_handled(settings) -> None:
    rows = [{"timestamp": ts(i), "event_type": "auth_failure", "username": "x"} for i in range(10)]
    assert _by_rule(run_detection(make_events(rows), settings), RULE_BRUTE_FORCE) == []
