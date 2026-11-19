"""Human-readable metadata for every detection rule.

Used by the *Detection Rules* and *MITRE ATT&CK* dashboard pages, by reports,
and to attach recommended investigation steps to each alert.
"""

from __future__ import annotations

from dataclasses import dataclass

from config import (
    RULE_BRUTE_FORCE,
    RULE_HTTP_AUTH_ERRORS,
    RULE_HTTP_SUSPICIOUS,
    RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS,
    RULE_SUCCESS_AFTER_FAILURES,
    RULE_WATCHLIST,
)


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    name: str
    category: str
    description: str
    logic: str
    severity_logic: str
    mitre: tuple[str, ...]
    mitre_note: str
    recommendations: tuple[str, ...]


RULES: dict[str, RuleInfo] = {
    RULE_BRUTE_FORCE: RuleInfo(
        RULE_BRUTE_FORCE,
        "Repeated Failed Login Attempts",
        "Authentication",
        "Many failed logins from the same source IP in a short time window.",
        "Groups auth_failure events by source IP and slides a time window over them. "
        "Alerts when the peak count inside the window reaches the threshold.",
        "Medium when peak >= threshold; High when peak >= high threshold.",
        ("T1110", "T1110.001"),
        "Repeated password failures from one source are the defining behaviour of password guessing.",
        (
            "Confirm whether the source IP belongs to a known user, VPN, or internal scanner.",
            "Check whether any login from this IP later succeeded (see AUTH-002).",
            "Review the targeted account(s) for lockouts and recent password resets.",
            "If unexplained, escalate per your incident process; consider rate-limiting or MFA (manual decision).",
        ),
    ),
    RULE_SUCCESS_AFTER_FAILURES: RuleInfo(
        RULE_SUCCESS_AFTER_FAILURES,
        "Successful Login After Repeated Failures",
        "Authentication",
        "A successful login from an IP that just produced several failed logins.",
        "For each auth_success, counts auth_failure events from the same IP in the preceding window.",
        "High by default; Critical when failures >= brute-force threshold and target the same account.",
        ("T1110", "T1078"),
        "Failures followed by success can indicate a guessed password now being used as a valid account.",
        (
            "Contact the account owner out-of-band to confirm whether they logged in.",
            "Review session activity after the successful login (commands, data access, privilege changes).",
            "If not confirmed by the user, treat the credential as potentially compromised: reset and enforce MFA.",
            "Search for the same source IP across other systems and accounts.",
        ),
    ),
    RULE_MULTI_ACCOUNT: RuleInfo(
        RULE_MULTI_ACCOUNT,
        "Multiple Accounts Targeted From One IP",
        "Authentication",
        "Failed logins against many different usernames from a single source IP.",
        "Counts distinct usernames among auth_failure events per IP in a sliding window.",
        "High when distinct accounts >= threshold; Critical if any login from that IP succeeded in/after the window.",
        ("T1110.003",),
        "Few attempts across many accounts from one source matches password spraying. "
        "(Credential stuffing, T1110.004, cannot be distinguished from logs alone.)",
        (
            "List every targeted account and check for any successful authentication from this IP.",
            "Check whether the usernames are valid accounts (indicates prior reconnaissance).",
            "Review lockout events and help-desk tickets for the targeted users.",
            "Consider (manually) adding the IP to perimeter controls after validation.",
        ),
    ),
    RULE_OFF_HOURS: RuleInfo(
        RULE_OFF_HOURS,
        "Unusual Login Time",
        "Authentication",
        "Successful login outside configured business hours (UTC) or on a weekend.",
        "Compares the hour/weekday of each auth_success event timestamp with the configured business hours.",
        "Low by default; Medium for privileged accounts (e.g. root, admin).",
        (),
        "No ATT&CK technique is assigned: login time alone does not show how access was obtained.",
        (
            "Verify with the user or their manager whether off-hours work was expected.",
            "Check the source IP against the user's usual locations and devices.",
            "Correlate with other alerts for the same user or IP.",
        ),
    ),
    RULE_WATCHLIST: RuleInfo(
        RULE_WATCHLIST,
        "Watchlisted Source IP Activity",
        "Network",
        "Activity from an IP or CIDR range present in the local watchlist.",
        "Matches every event's validated source IP against the configured local watchlist. "
        "No external lookups, scans, or blocking are performed.",
        "Low for any activity; Medium if failures/4xx errors; High if a login succeeded.",
        (),
        "No technique is assigned: a watchlist match is reputation context, not evidence of a technique.",
        (
            "Review why the IP is on the watchlist and when the entry was added.",
            "Inspect every event from this IP and identify the accounts or URLs involved.",
            "If a login succeeded, validate it with the account owner immediately.",
            "Do not block automatically - document findings and follow your change process.",
        ),
    ),
    RULE_HTTP_AUTH_ERRORS: RuleInfo(
        RULE_HTTP_AUTH_ERRORS,
        "Repeated HTTP 401/403 Responses",
        "Web",
        "Many HTTP 401 (Unauthorized) or 403 (Forbidden) responses for one client IP.",
        "Slides a time window over 401/403 responses per IP and alerts when the peak reaches the threshold.",
        "Medium when peak >= threshold; High when peak >= 2x threshold.",
        ("T1110",),
        "T1110 is assigned only when most failures are 401s on login/auth endpoints; "
        "403s on other paths are access-control denials and receive no technique.",
        (
            "Identify the targeted endpoints and whether they require authentication.",
            "Check the web/application logs for any 2xx response to the same IP afterwards.",
            "Review WAF or reverse-proxy logs for the same client.",
            "Consider (manually) rate-limiting the endpoint if abuse is confirmed.",
        ),
    ),
    RULE_HTTP_SUSPICIOUS: RuleInfo(
        RULE_HTTP_SUSPICIOUS,
        "Suspicious HTTP Request Pattern",
        "Web",
        "Path enumeration, probing of sensitive files, or exploit-like request strings.",
        "Per IP and time window: many distinct paths with mostly 4xx responses (enumeration), "
        "requests for >= 2 sensitive paths (e.g. /.env, /.git/config), or traversal/injection patterns.",
        "Medium for enumeration or sensitive-path probing; High when traversal/injection patterns are present.",
        ("T1595.003", "T1190"),
        "Enumeration and sensitive-path probing map to Wordlist Scanning; exploit-like strings map to "
        "an *attempt* at Exploit Public-Facing Application. Neither confirms success.",
        (
            "Check whether any probed resource returned 200 (possible exposure).",
            "Verify that sensitive files (.env, .git, backups) are not publicly reachable.",
            "Review application logs for errors triggered by the malicious requests.",
            "Report confirmed exposures to the application owner for remediation.",
        ),
    ),
}
