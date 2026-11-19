"""Detection engine: runs enabled rules, classifies severity and scores risk."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import pandas as pd

from config import DetectionSettings
from detection.rule_catalog import RULES
from detection.rules import RULE_FUNCTIONS, RuleHit
from detection.scoring import compute_risk, prioritize, priority_label
from detection.severity import classify_severity
from utils.ip_utils import ip_in_networks, parse_watchlist
from utils.security import sha256_hex

REQUIRED_COLUMNS = (
    "timestamp", "source_ip", "username", "event_type", "status_code",
    "http_method", "url_path", "message", "file_name", "line_number",
)


def make_alert_id(rule_id: str, id_key: str) -> str:
    """Deterministic alert ID: the same finding keeps the same ID on re-runs."""
    return "ALT-" + sha256_hex(f"{rule_id}|{id_key}")[:10].upper()


def _prepare(events: pd.DataFrame) -> pd.DataFrame:
    df = events.copy()
    for column in REQUIRED_COLUMNS:
        if column not in df.columns:
            df[column] = None
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").astype("Int64")
    # Use object dtype for text columns so missing values are consistently None/NaN.
    for column in ("source_ip", "username", "event_type", "url_path"):
        df[column] = df[column].astype(object).where(df[column].notna(), None)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)


def _hit_to_alert(
    hit: RuleHit,
    settings: DetectionSettings,
    watchlisted: bool,
    correlated_rules: int,
) -> dict[str, Any]:
    severity = classify_severity(hit.rule_id, hit.metrics, settings)
    users = [u.strip().lower() for u in (hit.username or "").split(",")]
    privileged = any(u in settings.privileged_accounts for u in users if u)
    score, factors = compute_risk(
        severity=severity,
        rule_id=hit.rule_id,
        event_count=hit.event_count,
        watchlisted=watchlisted,
        privileged=privileged,
        has_success=hit.has_success,
        correlated_rules=correlated_rules,
    )
    info = RULES[hit.rule_id]
    fmt = "%Y-%m-%d %H:%M:%S"
    return {
        "alert_id": make_alert_id(hit.rule_id, hit.id_key),
        "rule_id": hit.rule_id,
        "rule_name": info.name,
        "severity": severity,
        "risk_score": score,
        "priority": priority_label(score),
        "risk_factors": factors,
        "timestamp": pd.Timestamp(hit.trigger_time).strftime(fmt),
        "first_seen": pd.Timestamp(hit.first_seen).strftime(fmt),
        "last_seen": pd.Timestamp(hit.last_seen).strftime(fmt),
        "source_ip": hit.source_ip,
        "username": hit.username,
        "description": hit.description,
        "evidence": hit.evidence_records(),
        "event_count": hit.event_count,
        "recommendations": list(info.recommendations),
        "mitre": hit.mitre,
        "status": "New",
    }


def run_detection(events: pd.DataFrame, settings: DetectionSettings) -> list[dict[str, Any]]:
    """Run every enabled rule and return prioritised alert dictionaries."""
    if events is None or events.empty:
        return []
    df = _prepare(events)
    if df.empty:
        return []

    hits: list[RuleHit] = []
    for rule_id, rule_fn in RULE_FUNCTIONS.items():
        if settings.is_enabled(rule_id):
            hits.extend(rule_fn(df, settings))

    # Correlation: how many *different* rules fired for each source IP.
    rules_by_ip: dict[str, set[str]] = defaultdict(set)
    for hit in hits:
        if hit.source_ip:
            rules_by_ip[hit.source_ip].add(hit.rule_id)

    networks, _ = parse_watchlist(settings.watchlist)
    alerts = []
    for hit in hits:
        correlated = len(rules_by_ip.get(hit.source_ip or "", set()) - {hit.rule_id})
        watchlisted = ip_in_networks(hit.source_ip, networks)
        alerts.append(_hit_to_alert(hit, settings, watchlisted, correlated))
    return prioritize(alerts)
