"""Rule-based severity classification.

Each detection rule measures some facts (counts, flags) and passes them here.
Keeping the decision logic in one module makes it easy to read, test and
explain: severity is never random and never invented.
"""

from __future__ import annotations

from config import (
    RULE_BRUTE_FORCE,
    RULE_HTTP_AUTH_ERRORS,
    RULE_HTTP_SUSPICIOUS,
    RULE_MULTI_ACCOUNT,
    RULE_OFF_HOURS,
    RULE_SUCCESS_AFTER_FAILURES,
    RULE_WATCHLIST,
    DetectionSettings,
)


def classify_severity(rule_id: str, metrics: dict[str, object], settings: DetectionSettings) -> str:
    """Return ``Critical``, ``High``, ``Medium`` or ``Low`` for a rule hit."""
    if rule_id == RULE_BRUTE_FORCE:
        peak = int(metrics.get("peak_count", 0))
        return "High" if peak >= settings.brute_force_high_threshold else "Medium"

    if rule_id == RULE_SUCCESS_AFTER_FAILURES:
        failures = int(metrics.get("failure_count", 0))
        same_account = bool(metrics.get("same_account", False))
        if same_account and failures >= settings.brute_force_threshold:
            return "Critical"
        return "High"

    if rule_id == RULE_MULTI_ACCOUNT:
        return "Critical" if metrics.get("success_from_ip") else "High"

    if rule_id == RULE_OFF_HOURS:
        return "Medium" if metrics.get("privileged") else "Low"

    if rule_id == RULE_WATCHLIST:
        if metrics.get("has_success"):
            return "High"
        if metrics.get("has_failures"):
            return "Medium"
        return "Low"

    if rule_id == RULE_HTTP_AUTH_ERRORS:
        peak = int(metrics.get("peak_count", 0))
        return "High" if peak >= 2 * settings.http_error_threshold else "Medium"

    if rule_id == RULE_HTTP_SUSPICIOUS:
        return "High" if metrics.get("exploit_patterns") else "Medium"

    raise ValueError(f"Unknown rule id: {rule_id}")
