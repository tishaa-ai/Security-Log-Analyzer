"""Central configuration for the Security Log Analyzer.

All tunable detection thresholds live in :class:`DetectionSettings`. The
defaults below are used the first time the application starts; after that,
analysts can change them on the *Settings* page and they are persisted in
SQLite (table ``settings``).
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR: Path = Path(__file__).resolve().parent
DATA_DIR: Path = BASE_DIR / "data"
SAMPLES_DIR: Path = DATA_DIR / "samples"
OUTPUT_DIR: Path = BASE_DIR / "output"
WATCHLIST_FILE: Path = DATA_DIR / "watchlist.txt"

# The database location can be overridden with an environment variable,
# which is handy for tests or for keeping several investigations apart.
DB_PATH: Path = Path(os.environ.get("SLA_DB_PATH", DATA_DIR / "security_analyzer.db"))

# ---------------------------------------------------------------------------
# Ingestion limits
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES: int = 50 * 1024 * 1024  # 50 MB
JSON_EXTENSIONS: frozenset[str] = frozenset({".json", ".jsonl", ".ndjson"})
SYSLOG_EXTENSIONS: frozenset[str] = frozenset({".log", ".txt", ".syslog"})
SUPPORTED_EXTENSIONS: frozenset[str] = JSON_EXTENSIONS | SYSLOG_EXTENSIONS

# Classic RFC 3164 syslog lines do not contain a year. The sample datasets
# were generated for this year so they line up with the JSON samples.
SAMPLE_DATA_YEAR: int = 2026

# Maximum evidence rows stored with a single alert (keeps the DB small).
MAX_EVIDENCE_PER_ALERT: int = 25

APP_TITLE: str = "Security Log Analyzer & Alert Triage Dashboard"
DEFAULT_ANALYST: str = "analyst"

# ---------------------------------------------------------------------------
# Detection rule identifiers
# ---------------------------------------------------------------------------
RULE_BRUTE_FORCE = "AUTH-001"
RULE_SUCCESS_AFTER_FAILURES = "AUTH-002"
RULE_MULTI_ACCOUNT = "AUTH-003"
RULE_OFF_HOURS = "AUTH-004"
RULE_WATCHLIST = "NET-001"
RULE_HTTP_AUTH_ERRORS = "HTTP-001"
RULE_HTTP_SUSPICIOUS = "HTTP-002"

ALL_RULE_IDS: tuple[str, ...] = (
    RULE_BRUTE_FORCE,
    RULE_SUCCESS_AFTER_FAILURES,
    RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS,
    RULE_WATCHLIST,
    RULE_HTTP_AUTH_ERRORS,
    RULE_HTTP_SUSPICIOUS,
)

SEVERITIES: tuple[str, ...] = ("Critical", "High", "Medium", "Low")
SEVERITY_RANK: dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
ALERT_STATUSES: tuple[str, ...] = ("New", "Investigating", "Resolved", "False Positive")


def _default_watchlist() -> list[str]:
    """Read the default watchlist file (one IP or CIDR per line, '#' comments)."""
    if not WATCHLIST_FILE.exists():
        return []
    entries: list[str] = []
    for line in WATCHLIST_FILE.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return entries


@dataclass
class DetectionSettings:
    """Every configurable threshold used by the detection engine."""

    # AUTH-001 Repeated failed logins from one IP
    brute_force_threshold: int = 5
    brute_force_window_minutes: int = 10
    brute_force_high_threshold: int = 10

    # AUTH-002 Successful login after repeated failures
    success_after_failures_threshold: int = 3
    success_after_failures_window_minutes: int = 30

    # AUTH-003 Failed logins against many accounts from one IP
    multi_account_threshold: int = 3
    multi_account_window_minutes: int = 30

    # AUTH-004 Unusual login time (UTC hours, end is exclusive)
    business_hours_start: int = 7
    business_hours_end: int = 20
    flag_weekend_logins: bool = True
    privileged_accounts: list[str] = field(
        default_factory=lambda: ["root", "admin", "administrator", "sysadmin"]
    )

    # HTTP-001 Repeated HTTP 401/403 responses
    http_error_threshold: int = 10
    http_error_window_minutes: int = 5

    # HTTP-002 Unusual HTTP request patterns
    http_scan_distinct_paths: int = 15
    http_scan_window_minutes: int = 10

    # NET-001 Local watchlist of IPs / CIDR ranges
    watchlist: list[str] = field(default_factory=_default_watchlist)

    # Rule on/off switches
    enabled_rules: dict[str, bool] = field(
        default_factory=lambda: {rule_id: True for rule_id in ALL_RULE_IDS}
    )

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "DetectionSettings":
        """Build settings from a (possibly partial or stale) dictionary.

        Unknown keys are ignored, missing keys fall back to defaults and
        numeric values are clamped to sensible minimums so a typo in the UI
        can never produce a zero/negative window.
        """
        defaults = cls()
        if not data:
            return defaults
        values = defaults.to_dict()
        for key, value in data.items():
            if key in values:
                values[key] = value
        settings = cls(**values)
        settings._sanitize()
        return settings

    def _sanitize(self) -> None:
        int_fields = [
            "brute_force_threshold",
            "brute_force_window_minutes",
            "brute_force_high_threshold",
            "success_after_failures_threshold",
            "success_after_failures_window_minutes",
            "multi_account_threshold",
            "multi_account_window_minutes",
            "http_error_threshold",
            "http_error_window_minutes",
            "http_scan_distinct_paths",
            "http_scan_window_minutes",
        ]
        for name in int_fields:
            try:
                setattr(self, name, max(1, int(getattr(self, name))))
            except (TypeError, ValueError):
                setattr(self, name, getattr(DetectionSettings(), name))
        self.brute_force_high_threshold = max(
            self.brute_force_high_threshold, self.brute_force_threshold
        )
        self.business_hours_start = min(23, max(0, int(self.business_hours_start)))
        self.business_hours_end = min(24, max(1, int(self.business_hours_end)))
        self.flag_weekend_logins = bool(self.flag_weekend_logins)
        self.privileged_accounts = [
            str(a).strip().lower() for a in (self.privileged_accounts or []) if str(a).strip()
        ]
        self.watchlist = [str(w).strip() for w in (self.watchlist or []) if str(w).strip()]
        merged = {rule_id: True for rule_id in ALL_RULE_IDS}
        if isinstance(self.enabled_rules, dict):
            for rule_id, enabled in self.enabled_rules.items():
                if rule_id in merged:
                    merged[rule_id] = bool(enabled)
        self.enabled_rules = merged

    def is_enabled(self, rule_id: str) -> bool:
        return self.enabled_rules.get(rule_id, True)
