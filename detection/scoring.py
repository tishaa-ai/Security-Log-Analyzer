"""Explainable, deterministic risk scoring (0-100).

score = base points for the severity
      + volume bonus (number of supporting events)
      + context bonuses (watchlisted IP, privileged account, successful login,
        correlation with other rules for the same IP)
capped at 100.

Every contribution is returned as a ``(reason, points)`` factor so the
dashboard can show *why* an alert scored the way it did.
"""

from __future__ import annotations

from config import RULE_WATCHLIST, SEVERITY_RANK

SEVERITY_BASE: dict[str, int] = {"Critical": 85, "High": 65, "Medium": 40, "Low": 15}


def volume_points(event_count: int) -> int:
    if event_count >= 50:
        return 10
    if event_count >= 20:
        return 6
    if event_count >= 10:
        return 3
    return 0


def compute_risk(
    severity: str,
    rule_id: str,
    event_count: int,
    watchlisted: bool,
    privileged: bool,
    has_success: bool,
    correlated_rules: int,
) -> tuple[int, list[dict[str, object]]]:
    """Return ``(score, factors)`` for one alert."""
    factors: list[dict[str, object]] = [
        {"reason": f"Base score for {severity} severity", "points": SEVERITY_BASE[severity]}
    ]
    vol = volume_points(event_count)
    if vol:
        factors.append({"reason": f"Volume: {event_count} supporting events", "points": vol})
    if watchlisted and rule_id != RULE_WATCHLIST:
        factors.append({"reason": "Source IP is on the local watchlist", "points": 10})
    if privileged:
        factors.append({"reason": "Privileged account involved", "points": 5})
    if has_success:
        factors.append({"reason": "A successful authentication is part of the evidence", "points": 5})
    if correlated_rules > 0:
        points = min(10, 5 * correlated_rules)
        factors.append(
            {"reason": f"Correlated with {correlated_rules} other rule(s) for the same IP", "points": points}
        )
    score = min(100, sum(int(f["points"]) for f in factors))
    return score, factors


def priority_label(score: int) -> str:
    """Map a risk score to a triage priority (P1 = handle first)."""
    if score >= 85:
        return "P1"
    if score >= 65:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def prioritize(alerts: list[dict[str, object]]) -> list[dict[str, object]]:
    """Order alerts for triage: highest score, then severity, then most recent.

    Python's sort is stable, so sorting by the least important key first and
    the most important key last gives the combined ordering.
    """
    ordered = sorted(alerts, key=lambda a: str(a["last_seen"]), reverse=True)
    return sorted(
        ordered,
        key=lambda a: (int(a["risk_score"]), SEVERITY_RANK.get(str(a["severity"]), 0)),
        reverse=True,
    )
