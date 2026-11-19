"""Severity classification and explainable risk scoring tests."""

from __future__ import annotations

import pytest

from config import (
    RULE_BRUTE_FORCE, RULE_HTTP_AUTH_ERRORS, RULE_HTTP_SUSPICIOUS, RULE_MULTI_ACCOUNT, RULE_OFF_HOURS,
    RULE_SUCCESS_AFTER_FAILURES, RULE_WATCHLIST, DetectionSettings,
)
from detection.scoring import compute_risk, prioritize, priority_label
from detection.severity import classify_severity

S = DetectionSettings.from_dict({"watchlist": []})


@pytest.mark.parametrize(
    ("rule_id", "metrics", "expected"),
    [
        (RULE_BRUTE_FORCE, {"peak_count": 5}, "Medium"),
        (RULE_BRUTE_FORCE, {"peak_count": 10}, "High"),
        (RULE_SUCCESS_AFTER_FAILURES, {"failure_count": 3, "same_account": True}, "High"),
        (RULE_SUCCESS_AFTER_FAILURES, {"failure_count": 5, "same_account": True}, "Critical"),
        (RULE_SUCCESS_AFTER_FAILURES, {"failure_count": 9, "same_account": False}, "High"),
        (RULE_MULTI_ACCOUNT, {"success_from_ip": False}, "High"),
        (RULE_MULTI_ACCOUNT, {"success_from_ip": True}, "Critical"),
        (RULE_OFF_HOURS, {"privileged": False}, "Low"),
        (RULE_OFF_HOURS, {"privileged": True}, "Medium"),
        (RULE_WATCHLIST, {}, "Low"),
        (RULE_WATCHLIST, {"has_failures": True}, "Medium"),
        (RULE_WATCHLIST, {"has_success": True, "has_failures": True}, "High"),
        (RULE_HTTP_AUTH_ERRORS, {"peak_count": 10}, "Medium"),
        (RULE_HTTP_AUTH_ERRORS, {"peak_count": 20}, "High"),
        (RULE_HTTP_SUSPICIOUS, {"exploit_patterns": 0}, "Medium"),
        (RULE_HTTP_SUSPICIOUS, {"exploit_patterns": 2}, "High"),
    ],
)
def test_classify_severity(rule_id, metrics, expected) -> None:
    assert classify_severity(rule_id, metrics, S) == expected


def test_unknown_rule_raises() -> None:
    with pytest.raises(ValueError):
        classify_severity("XXX-999", {}, S)


def test_risk_score_is_sum_of_explained_factors() -> None:
    score, factors = compute_risk("High", RULE_BRUTE_FORCE, event_count=12, watchlisted=True,
                                  privileged=True, has_success=False, correlated_rules=1)
    assert score == sum(f["points"] for f in factors) == 65 + 3 + 10 + 5 + 5
    assert all(isinstance(f["reason"], str) and f["reason"] for f in factors)


def test_risk_score_capped_and_deterministic() -> None:
    args = dict(severity="Critical", rule_id=RULE_SUCCESS_AFTER_FAILURES, event_count=100, watchlisted=True,
                privileged=True, has_success=True, correlated_rules=5)
    first = compute_risk(**args)
    assert first[0] == 100 and compute_risk(**args) == first


def test_watchlist_rule_does_not_double_count_watchlist() -> None:
    _, factors = compute_risk("Low", RULE_WATCHLIST, 1, watchlisted=True, privileged=False,
                              has_success=False, correlated_rules=0)
    assert not any("watchlist" in f["reason"] for f in factors)


def test_priority_labels() -> None:
    assert [priority_label(s) for s in (90, 70, 45, 10)] == ["P1", "P2", "P3", "P4"]


def test_prioritize_orders_by_score_then_severity_then_recency() -> None:
    alerts = [
        {"alert_id": "a", "risk_score": 50, "severity": "Medium", "last_seen": "2026-11-18 01:00:00"},
        {"alert_id": "b", "risk_score": 80, "severity": "High", "last_seen": "2026-11-18 01:00:00"},
        {"alert_id": "c", "risk_score": 50, "severity": "Medium", "last_seen": "2026-11-18 05:00:00"},
        {"alert_id": "d", "risk_score": 50, "severity": "High", "last_seen": "2026-11-18 00:00:00"},
    ]
    assert [a["alert_id"] for a in prioritize(alerts)] == ["b", "d", "c", "a"]
