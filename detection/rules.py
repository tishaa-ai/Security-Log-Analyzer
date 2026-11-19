"""Detection rules.

Each rule receives the full events DataFrame (one row per normalised event,
``timestamp`` as pandas datetime) plus the current settings, and returns a list
of :class:`RuleHit` objects. Rules only *measure* facts; severity is decided
in :mod:`detection.severity` and risk in :mod:`detection.scoring`.

Language used in descriptions is deliberately cautious ("consistent with",
"possible"): a rule hit is an indicator for an analyst to validate, not proof
of an attack.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import unquote

import pandas as pd

from config import (
    MAX_EVIDENCE_PER_ALERT,
    RULE_BRUTE_FORCE,
    RULE_HTTP_AUTH_ERRORS,
    RULE_HTTP_SUSPICIOUS,
    RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS,
    RULE_SUCCESS_AFTER_FAILURES,
    RULE_WATCHLIST,
    DetectionSettings,
)
from detection.mitre import mapping
from parsers.models import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS, EVENT_HTTP_REQUEST
from utils.ip_utils import ip_in_networks, parse_watchlist

LOGIN_PATH_RE = re.compile(r"(?:login|logon|signin|sign-in|auth|session|token|account|password)", re.I)
SENSITIVE_PATH_RE = re.compile(
    r"(?:/\.env|/\.git|/\.svn|/\.aws|/\.ssh|/\.htpasswd|/wp-admin|/wp-login\.php|/phpmyadmin|"
    r"/server-status|/actuator|/config\.(?:php|json|ya?ml)|/backup|\.bak$|\.sql$|/admin(?:/|$))",
    re.I,
)
EXPLOIT_RE = re.compile(
    r"(?:\.\./|\.\.\\|/etc/passwd|win\.ini|union\s+select|'\s*or\s+'?1'?\s*=\s*'?1|<script|%00|"
    r"\$\{jndi:|;\s*(?:cat|wget|curl)\s)",
    re.I,
)

EVIDENCE_COLUMNS = (
    "timestamp", "source_ip", "username", "event_type", "status_code", "http_method",
    "url_path", "message", "file_name", "line_number",
)


@dataclass
class RuleHit:
    """Facts produced by one rule match (before severity/risk are applied)."""

    rule_id: str
    id_key: str  # deterministic key -> stable alert ID across re-runs
    source_ip: str | None
    username: str | None
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    trigger_time: pd.Timestamp
    description: str
    evidence: pd.DataFrame
    metrics: dict[str, Any] = field(default_factory=dict)
    mitre: list[dict[str, Any]] = field(default_factory=list)
    has_success: bool = False

    @property
    def event_count(self) -> int:
        return len(self.evidence)

    def evidence_records(self) -> list[dict[str, Any]]:
        df = self.evidence.head(MAX_EVIDENCE_PER_ALERT)
        records: list[dict[str, Any]] = []
        for row in df.to_dict("records"):
            item: dict[str, Any] = {}
            for column in EVIDENCE_COLUMNS:
                value = row.get(column)
                if column == "timestamp" and value is not None:
                    value = pd.Timestamp(value).strftime("%Y-%m-%d %H:%M:%S")
                elif value is None or (not isinstance(value, str) and pd.isna(value)):
                    value = None
                elif column in ("status_code", "line_number"):
                    value = int(value)
                item[column] = value
            records.append(item)
        return records


# ---------------------------------------------------------------------------
# Window helpers
# ---------------------------------------------------------------------------
def _fmt(ts: pd.Timestamp) -> str:
    return pd.Timestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def split_clusters(df: pd.DataFrame, window: pd.Timedelta) -> list[pd.DataFrame]:
    """Split time-sorted events into bursts separated by gaps larger than ``window``."""
    if df.empty:
        return []
    df = df.sort_values("timestamp", kind="stable")
    new_cluster = df["timestamp"].diff().gt(window).cumsum()
    return [group for _, group in df.groupby(new_cluster, sort=True)]


def peak_in_window(times: pd.Series, window: pd.Timedelta) -> int:
    """Largest number of events falling inside any span of length ``window``."""
    values = sorted(times.tolist())
    best = start = 0
    for end, current in enumerate(values):
        while current - values[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def peak_distinct_in_window(df: pd.DataFrame, column: str, window: pd.Timedelta) -> int:
    """Largest number of distinct non-null ``column`` values inside any window."""
    rows = df.dropna(subset=[column]).sort_values("timestamp", kind="stable")
    times = rows["timestamp"].tolist()
    values = rows[column].tolist()
    counts: Counter[str] = Counter()
    best = start = 0
    for end in range(len(times)):
        counts[values[end]] += 1
        while times[end] - times[start] > window:
            counts[values[start]] -= 1
            if counts[values[start]] == 0:
                del counts[values[start]]
            start += 1
        best = max(best, len(counts))
    return best


def _users(df: pd.DataFrame) -> list[str]:
    return sorted({str(u) for u in df["username"].dropna().unique()})


def _user_label(users: list[str]) -> str | None:
    if not users:
        return None
    if len(users) <= 5:
        return ", ".join(users)
    return ", ".join(users[:5]) + f" (+{len(users) - 5} more)"


def _with_ip(events: pd.DataFrame, event_type: str) -> pd.DataFrame:
    return events[(events["event_type"] == event_type) & events["source_ip"].notna()]


# ---------------------------------------------------------------------------
# AUTH-001 Repeated failed logins from one IP
# ---------------------------------------------------------------------------
def detect_brute_force(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    window = pd.Timedelta(minutes=s.brute_force_window_minutes)
    hits: list[RuleHit] = []
    for ip, group in _with_ip(events, EVENT_AUTH_FAILURE).groupby("source_ip"):
        for cluster in split_clusters(group, window):
            peak = peak_in_window(cluster["timestamp"], window)
            if peak < s.brute_force_threshold:
                continue
            users = _users(cluster)
            first, last = cluster["timestamp"].min(), cluster["timestamp"].max()
            minutes = (last - first).total_seconds() / 60
            if len(users) <= 2:
                mitre = [mapping("T1110.001",
                                 f"{len(cluster)} password failures from {ip} against "
                                 f"{len(users) or 'unknown'} account(s) is consistent with password guessing.")]
            else:
                mitre = [mapping("T1110",
                                 f"{len(cluster)} failures from {ip} across {len(users)} accounts is "
                                 "consistent with brute-force activity (see AUTH-003 for spraying).")]
            hits.append(RuleHit(
                rule_id=RULE_BRUTE_FORCE,
                id_key=f"{ip}|{_fmt(first)}",
                source_ip=str(ip),
                username=_user_label(users),
                first_seen=first, last_seen=last, trigger_time=last,
                description=(
                    f"{len(cluster)} failed login attempts from {ip} over {minutes:.1f} minutes "
                    f"(peak {peak} within a {s.brute_force_window_minutes}-minute window; "
                    f"threshold {s.brute_force_threshold}). Targeted account(s): "
                    f"{_user_label(users) or 'unknown'}."
                ),
                evidence=cluster,
                metrics={"peak_count": peak, "total_failures": len(cluster), "distinct_users": len(users)},
                mitre=mitre,
            ))
    return hits


# ---------------------------------------------------------------------------
# AUTH-002 Successful login after repeated failures
# ---------------------------------------------------------------------------
def detect_success_after_failures(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    window = pd.Timedelta(minutes=s.success_after_failures_window_minutes)
    failures = _with_ip(events, EVENT_AUTH_FAILURE)
    successes = _with_ip(events, EVENT_AUTH_SUCCESS)
    hits: list[RuleHit] = []
    for ip, ip_success in successes.groupby("source_ip"):
        ip_failures = failures[failures["source_ip"] == ip]
        if ip_failures.empty:
            continue
        consumed_until: pd.Timestamp | None = None  # failures already used by an earlier alert
        for idx in ip_success.sort_values("timestamp", kind="stable").index:
            success = ip_success.loc[idx]
            ts = success["timestamp"]
            mask = (ip_failures["timestamp"] >= ts - window) & (ip_failures["timestamp"] <= ts)
            if consumed_until is not None:
                mask &= ip_failures["timestamp"] > consumed_until
            prior = ip_failures[mask]
            if len(prior) < s.success_after_failures_threshold:
                continue
            consumed_until = ts
            user = success["username"] if pd.notna(success["username"]) else None
            failed_users = _users(prior)
            same_account = user is not None and user in failed_users
            evidence = pd.concat([ip_success.loc[[idx]], prior])  # key event first
            hits.append(RuleHit(
                rule_id=RULE_SUCCESS_AFTER_FAILURES,
                id_key=f"{ip}|{user}|{_fmt(ts)}",
                source_ip=str(ip),
                username=user,
                first_seen=prior["timestamp"].min(), last_seen=ts, trigger_time=ts,
                description=(
                    f"Successful login for '{user or 'unknown'}' from {ip} at {_fmt(ts)} followed "
                    f"{len(prior)} failed attempt(s) from the same IP within "
                    f"{s.success_after_failures_window_minutes} minutes "
                    f"({'same account' if same_account else 'different account(s): ' + (_user_label(failed_users) or 'unknown')}). "
                    "This may indicate a guessed or compromised credential and must be validated."
                ),
                evidence=evidence,
                metrics={"failure_count": len(prior), "same_account": same_account},
                mitre=[
                    mapping("T1110", f"{len(prior)} failed attempts preceded the successful login."),
                    mapping("T1078", "A successful login after repeated failures is consistent with "
                                     "use of a valid (possibly guessed) account credential."),
                ],
                has_success=True,
            ))
    return hits


# ---------------------------------------------------------------------------
# AUTH-003 Multiple accounts targeted from one IP (password spraying)
# ---------------------------------------------------------------------------
def detect_multi_account(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    window = pd.Timedelta(minutes=s.multi_account_window_minutes)
    successes = _with_ip(events, EVENT_AUTH_SUCCESS)
    hits: list[RuleHit] = []
    for ip, group in _with_ip(events, EVENT_AUTH_FAILURE).groupby("source_ip"):
        for cluster in split_clusters(group, window):
            distinct = peak_distinct_in_window(cluster, "username", window)
            if distinct < s.multi_account_threshold:
                continue
            first, last = cluster["timestamp"].min(), cluster["timestamp"].max()
            users = _users(cluster)
            ip_success = successes[
                (successes["source_ip"] == ip)
                & (successes["timestamp"] >= first)
                & (successes["timestamp"] <= last + window)
            ]
            evidence = pd.concat([cluster, ip_success]).sort_values("timestamp", kind="stable")
            success_note = (
                f" A successful login from the same IP was observed for: {_user_label(_users(ip_success))}."
                if not ip_success.empty else ""
            )
            hits.append(RuleHit(
                rule_id=RULE_MULTI_ACCOUNT,
                id_key=f"{ip}|{_fmt(first)}",
                source_ip=str(ip),
                username=_user_label(users),
                first_seen=first, last_seen=last, trigger_time=last,
                description=(
                    f"{len(cluster)} failed logins from {ip} targeted {len(users)} different accounts "
                    f"(peak {distinct} distinct accounts within {s.multi_account_window_minutes} minutes; "
                    f"threshold {s.multi_account_threshold}).{success_note}"
                ),
                evidence=evidence,
                metrics={"distinct_users": distinct, "success_from_ip": not ip_success.empty},
                mitre=[mapping("T1110.003",
                               f"Failures spread across {len(users)} accounts from one source match the "
                               "password-spraying pattern.")],
                has_success=not ip_success.empty,
            ))
    return hits


# ---------------------------------------------------------------------------
# AUTH-004 Unusual login time
# ---------------------------------------------------------------------------
def _within_business_hours(hour: int, start: int, end: int) -> bool:
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # overnight shift, e.g. 22 -> 6


def detect_off_hours(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    successes = events[events["event_type"] == EVENT_AUTH_SUCCESS].copy()
    if successes.empty:
        return []
    hours = successes["timestamp"].dt.hour
    weekend = successes["timestamp"].dt.day_of_week >= 5
    outside = ~hours.apply(lambda h: _within_business_hours(int(h), s.business_hours_start, s.business_hours_end))
    flagged = successes[outside | (weekend & s.flag_weekend_logins)].copy()
    if flagged.empty:
        return []
    flagged["day"] = flagged["timestamp"].dt.strftime("%Y-%m-%d")
    hits: list[RuleHit] = []
    group_cols = [flagged["username"].fillna("unknown"), flagged["source_ip"].fillna("unknown"), flagged["day"]]
    for (user, ip, day), group in flagged.groupby(group_cols):
        first, last = group["timestamp"].min(), group["timestamp"].max()
        reasons = []
        if (~group["timestamp"].dt.hour.apply(
                lambda h: _within_business_hours(int(h), s.business_hours_start, s.business_hours_end))).any():
            reasons.append(f"outside business hours ({s.business_hours_start:02d}:00-"
                           f"{s.business_hours_end:02d}:00 UTC)")
        if s.flag_weekend_logins and (group["timestamp"].dt.day_of_week >= 5).any():
            reasons.append("on a weekend")
        privileged = str(user).lower() in s.privileged_accounts
        hits.append(RuleHit(
            rule_id=RULE_OFF_HOURS,
            id_key=f"{user}|{ip}|{day}",
            source_ip=None if ip == "unknown" else str(ip),
            username=None if user == "unknown" else str(user),
            first_seen=first, last_seen=last, trigger_time=first,
            description=(
                f"{len(group)} successful login(s) for '{user}' from {ip} on {day} "
                f"{' and '.join(reasons)} (first at {_fmt(first)} UTC)."
                + (" The account is privileged." if privileged else "")
                + " Unusual timing alone is not evidence of compromise."
            ),
            evidence=group.drop(columns=["day"]),
            metrics={"privileged": privileged, "login_count": len(group)},
            mitre=[],
            has_success=True,
        ))
    return hits


# ---------------------------------------------------------------------------
# NET-001 Watchlisted source IP
# ---------------------------------------------------------------------------
def detect_watchlist(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    networks, _invalid = parse_watchlist(s.watchlist)
    if not networks or events.empty:
        return []
    hits: list[RuleHit] = []
    for ip in sorted(events["source_ip"].dropna().unique()):
        matched = [str(n.network_address) if n.num_addresses == 1 else str(n)
                   for n in networks if ip_in_networks(ip, [n])]
        if not matched:
            continue
        group = events[events["source_ip"] == ip].sort_values("timestamp", kind="stable")
        has_success = bool((group["event_type"] == EVENT_AUTH_SUCCESS).any())
        http_errors = (group["event_type"] == EVENT_HTTP_REQUEST) & (group["status_code"].fillna(0) >= 400)
        has_failures = bool(((group["event_type"] == EVENT_AUTH_FAILURE) | http_errors).any())
        type_counts = group["event_type"].value_counts().to_dict()
        summary = ", ".join(f"{count} {etype}" for etype, count in sorted(type_counts.items()))
        first, last = group["timestamp"].min(), group["timestamp"].max()
        users = _users(group)
        hits.append(RuleHit(
            rule_id=RULE_WATCHLIST,
            id_key=str(ip),
            source_ip=str(ip),
            username=_user_label(users),
            first_seen=first, last_seen=last, trigger_time=first,
            description=(
                f"Source IP {ip} matches local watchlist entry {', '.join(matched)}. "
                f"{len(group)} event(s) observed between {_fmt(first)} and {_fmt(last)} ({summary})."
                + (" Includes at least one SUCCESSFUL login." if has_success else "")
                + " No automatic blocking was performed."
            ),
            evidence=group,
            metrics={"has_success": has_success, "has_failures": has_failures, "matched": matched},
            mitre=[],
            has_success=has_success,
        ))
    return hits


# ---------------------------------------------------------------------------
# HTTP-001 Repeated HTTP 401/403 responses
# ---------------------------------------------------------------------------
def detect_http_auth_errors(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    window = pd.Timedelta(minutes=s.http_error_window_minutes)
    http = _with_ip(events, EVENT_HTTP_REQUEST)
    http = http[http["status_code"].isin([401, 403])]
    hits: list[RuleHit] = []
    for ip, group in http.groupby("source_ip"):
        for cluster in split_clusters(group, window):
            peak = peak_in_window(cluster["timestamp"], window)
            if peak < s.http_error_threshold:
                continue
            first, last = cluster["timestamp"].min(), cluster["timestamp"].max()
            n401 = int((cluster["status_code"] == 401).sum())
            n403 = int((cluster["status_code"] == 403).sum())
            paths = cluster["url_path"].dropna().astype(str)
            login_401 = int(((cluster["status_code"] == 401) & cluster["url_path"].fillna("")
                             .astype(str).str.contains(LOGIN_PATH_RE)).sum())
            mitre = []
            if login_401 / len(cluster) >= 0.5:
                mitre.append(mapping("T1110",
                                     f"{login_401} of {len(cluster)} responses were 401s on authentication "
                                     "endpoints, consistent with credential guessing against web login."))
            top_paths = paths.value_counts().head(3)
            hits.append(RuleHit(
                rule_id=RULE_HTTP_AUTH_ERRORS,
                id_key=f"{ip}|{_fmt(first)}",
                source_ip=str(ip),
                username=_user_label(_users(cluster)),
                first_seen=first, last_seen=last, trigger_time=last,
                description=(
                    f"{len(cluster)} HTTP error responses for {ip} ({n401}x 401, {n403}x 403) between "
                    f"{_fmt(first)} and {_fmt(last)} (peak {peak} within {s.http_error_window_minutes} "
                    f"minutes; threshold {s.http_error_threshold}). Top paths: "
                    + ", ".join(f"{p} ({c})" for p, c in top_paths.items()) + "."
                ),
                evidence=cluster,
                metrics={"peak_count": peak, "count_401": n401, "count_403": n403},
                mitre=mitre,
            ))
    return hits


# ---------------------------------------------------------------------------
# HTTP-002 Suspicious HTTP request patterns
# ---------------------------------------------------------------------------
def detect_http_suspicious(events: pd.DataFrame, s: DetectionSettings) -> list[RuleHit]:
    window = pd.Timedelta(minutes=s.http_scan_window_minutes)
    http = _with_ip(events, EVENT_HTTP_REQUEST)
    hits: list[RuleHit] = []
    for ip, group in http.groupby("source_ip"):
        for cluster in split_clusters(group, window):
            paths = cluster["url_path"].fillna("").astype(str)
            decoded = paths.apply(unquote)
            distinct_paths = peak_distinct_in_window(cluster, "url_path", window)
            error_ratio = float((cluster["status_code"].fillna(0) >= 400).mean())
            enumeration = distinct_paths >= s.http_scan_distinct_paths and error_ratio >= 0.5
            sensitive_mask = decoded.str.contains(SENSITIVE_PATH_RE)
            sensitive_paths = sorted(set(paths[sensitive_mask]))
            exploit_mask = decoded.str.contains(EXPLOIT_RE)
            exploit_paths = sorted(set(paths[exploit_mask]))
            sensitive = len(sensitive_paths) >= 2

            if not (enumeration or sensitive or exploit_paths):
                continue

            reasons, mitre = [], []
            if enumeration:
                reasons.append(f"{distinct_paths} distinct paths requested within "
                               f"{s.http_scan_window_minutes} minutes with {error_ratio:.0%} error responses")
            if sensitive:
                reasons.append(f"probing of {len(sensitive_paths)} sensitive path(s) such as "
                               + ", ".join(sensitive_paths[:3]))
            if enumeration or sensitive:
                mitre.append(mapping("T1595.003",
                                     "Requests for many or well-known sensitive paths are consistent "
                                     "with wordlist-based content discovery."))
            if exploit_paths:
                reasons.append(f"{len(exploit_paths)} request(s) containing traversal/injection "
                               "patterns, e.g. " + exploit_paths[0][:80])
                mitre.append(mapping("T1190",
                                     "Exploit-like request strings indicate an ATTEMPT to exploit a "
                                     "public-facing application; success is not implied."))

            # Show the most relevant requests first in the evidence.
            relevance = (exploit_mask.astype(int) * 2 + sensitive_mask.astype(int))
            evidence = cluster.assign(_rel=relevance.values).sort_values(
                ["_rel", "timestamp"], ascending=[False, True], kind="stable").drop(columns="_rel")
            first, last = cluster["timestamp"].min(), cluster["timestamp"].max()
            hits.append(RuleHit(
                rule_id=RULE_HTTP_SUSPICIOUS,
                id_key=f"{ip}|{_fmt(first)}",
                source_ip=str(ip),
                username=_user_label(_users(cluster)),
                first_seen=first, last_seen=last, trigger_time=last,
                description=f"Unusual HTTP activity from {ip}: " + "; ".join(reasons) + ".",
                evidence=evidence,
                metrics={
                    "distinct_paths": distinct_paths,
                    "error_ratio": round(error_ratio, 2),
                    "sensitive_paths": len(sensitive_paths),
                    "exploit_patterns": len(exploit_paths),
                },
                mitre=mitre,
            ))
    return hits


RULE_FUNCTIONS: dict[str, Callable[[pd.DataFrame, DetectionSettings], list[RuleHit]]] = {
    RULE_BRUTE_FORCE: detect_brute_force,
    RULE_SUCCESS_AFTER_FAILURES: detect_success_after_failures,
    RULE_MULTI_ACCOUNT: detect_multi_account,
    RULE_OFF_HOURS: detect_off_hours,
    RULE_WATCHLIST: detect_watchlist,
    RULE_HTTP_AUTH_ERRORS: detect_http_auth_errors,
    RULE_HTTP_SUSPICIOUS: detect_http_suspicious,
}
