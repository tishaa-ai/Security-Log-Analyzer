"""Syslog and text access-log parser (regex based).

Supported line layouts:

* RFC 3164 (BSD syslog): ``<34>Nov 18 08:15:02 host sshd[123]: message``
  (the ``<PRI>`` prefix is optional; the year is supplied by the caller)
* RFC 5424: ``<34>1 2026-11-18T08:15:02Z host app 123 ID47 - message``
* ISO-timestamped rsyslog format: ``2026-11-18T08:15:02+00:00 host app[1]: message``
* Apache / Nginx common or combined access-log lines (stand-alone or
  embedded in a syslog message)

Recognised message contents: OpenSSH failed/accepted logins and invalid
users, PAM authentication failures, generic "login failed/succeeded for user
X from IP" application messages, and HTTP access-log entries.
"""

from __future__ import annotations

import re
from datetime import datetime

from parsers.common import classify_event, clean_username, parse_status_code, truncate
from parsers.models import (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    EVENT_HTTP_REQUEST,
    EVENT_SYSTEM,
    LogEvent,
    ParseResult,
    RejectedRecord,
)
from utils.ip_utils import looks_like_ip, normalize_ip
from utils.time_utils import format_timestamp, parse_rfc3164_timestamp, parse_timestamp

# ---------------------------------------------------------------------------
# Line header formats
# ---------------------------------------------------------------------------
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>\d{1,2}\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>-|(?:\[[^\]]*\])+)\s?(?P<msg>.*)$"
)
RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
ISO_SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
ACCESS_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]{3,10})\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

# ---------------------------------------------------------------------------
# Message content patterns
# ---------------------------------------------------------------------------
SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive(?:/pam)?|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive(?:/pam)?) for (?P<user>\S+) from (?P<ip>\S+)"
)
SSH_INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
PAM_FAILURE_RE = re.compile(
    r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?"
)
GENERIC_AUTH_RE = re.compile(
    r"(?i)\b(?:login|logon|authentication|sign-?in)\s+(?P<result>fail\w*|succe\w*)\s+"
    r"for\s+(?:user\s+)?['\"]?(?P<user>[^\s'\"]+)['\"]?\s+from\s+(?:ip\s+)?(?P<ip>[^\s,;]+)"
)


class _InvalidIP(ValueError):
    """Raised when a message contains a malformed IP address."""


def _resolve_ip(value: str | None) -> str | None:
    """Validate an IP from a message. Hostnames are ignored, bad IPs rejected."""
    if not value:
        return None
    value = value.rstrip(",;.")
    canonical = normalize_ip(value)
    if canonical is None and looks_like_ip(value):
        raise _InvalidIP(value)
    return canonical


def _parse_message(msg: str, tag: str | None) -> dict[str, object]:
    """Extract security fields from a syslog message body."""
    fields: dict[str, object] = {}
    service = (tag or "").lower()

    if match := SSH_FAILED_RE.search(msg):
        fields.update(event_type=EVENT_AUTH_FAILURE, outcome="failure",
                      username=match["user"], source_ip=_resolve_ip(match["ip"]))
    elif match := SSH_ACCEPTED_RE.search(msg):
        fields.update(event_type=EVENT_AUTH_SUCCESS, outcome="success",
                      username=match["user"], source_ip=_resolve_ip(match["ip"]))
    elif match := SSH_INVALID_USER_RE.search(msg):
        # sshd logs "Invalid user X" *and* "Failed password for invalid user X"
        # for the same attempt; we keep this line as informational only to
        # avoid double-counting failures.
        fields.update(event_type=EVENT_SYSTEM, outcome=None,
                      username=match["user"], source_ip=_resolve_ip(match["ip"]))
    elif match := PAM_FAILURE_RE.search(msg):
        # For sshd the matching "Failed password" line is counted instead.
        event_type = EVENT_SYSTEM if service == "sshd" else EVENT_AUTH_FAILURE
        fields.update(event_type=event_type, outcome="failure" if event_type != EVENT_SYSTEM else None,
                      username=match["user"], source_ip=_resolve_ip(match["ip"]))
    elif match := GENERIC_AUTH_RE.search(msg):
        is_fail = match["result"].lower().startswith("fail")
        fields.update(event_type=EVENT_AUTH_FAILURE if is_fail else EVENT_AUTH_SUCCESS,
                      outcome="failure" if is_fail else "success",
                      username=match["user"], source_ip=_resolve_ip(match["ip"]))
    elif match := ACCESS_LOG_RE.search(msg):
        fields.update(_access_fields(match))
    else:
        event_type, outcome = classify_event(msg)
        fields.update(event_type=event_type, outcome=outcome)
    return fields


def _access_fields(match: re.Match[str]) -> dict[str, object]:
    status_code, _ = parse_status_code(match["status"])
    return {
        "event_type": EVENT_HTTP_REQUEST,
        "outcome": "failure" if (status_code or 0) >= 400 else "success",
        "source_ip": _resolve_ip(match["ip"]),
        "username": match["user"],
        "http_method": match["method"],
        "url_path": match["path"][:500],
        "status_code": status_code,
        "access_ts": match["ts"],
    }


def parse_syslog_line(line: str, line_number: int, default_year: int) -> LogEvent | RejectedRecord:
    """Parse one non-empty line into an event or a rejected record."""
    raw = truncate(line)
    ts: datetime | None = None
    host = tag = None
    msg: str

    try:
        if match := RFC5424_RE.match(line):
            ts = parse_timestamp(match["ts"])
            host, tag, msg = match["host"], match["app"], match["msg"]
        elif match := RFC3164_RE.match(line):
            ts = parse_rfc3164_timestamp(match["ts"], default_year)
            host, tag, msg = match["host"], match["tag"], match["msg"]
        elif match := ISO_SYSLOG_RE.match(line):
            ts = parse_timestamp(match["ts"])
            host, tag, msg = match["host"], match["tag"], match["msg"]
        elif (match := ACCESS_LOG_RE.match(line)):
            fields = _access_fields(match)
            ts = parse_timestamp(fields.pop("access_ts"))
            if ts is None:
                return RejectedRecord(line_number, "Invalid access-log timestamp", raw)
            return _build_event(ts, fields, None, "web", line, line_number)
        else:
            return RejectedRecord(
                line_number,
                "Unrecognised line format (expected RFC 3164/5424 syslog or access log)",
                raw,
            )

        if ts is None:
            return RejectedRecord(line_number, "Invalid or unparseable syslog timestamp", raw)

        fields = _parse_message(msg, tag)
        if "access_ts" in fields:
            embedded_ts = parse_timestamp(fields.pop("access_ts"))
            ts = embedded_ts or ts
    except _InvalidIP as exc:
        return RejectedRecord(line_number, f"Invalid IP address in message: {str(exc)[:60]!r}", raw)

    if not msg.strip():
        return RejectedRecord(line_number, "Syslog line has an empty message", raw)
    return _build_event(ts, fields, host, tag, msg, line_number, raw)


def _build_event(
    ts: datetime,
    fields: dict[str, object],
    host: str | None,
    tag: str | None,
    msg: str,
    line_number: int,
    raw: str | None = None,
) -> LogEvent:
    return LogEvent(
        timestamp=format_timestamp(ts),
        event_type=str(fields.get("event_type", EVENT_SYSTEM)),
        source_format="syslog",
        line_number=line_number,
        raw=raw if raw is not None else truncate(msg),
        source_ip=fields.get("source_ip"),  # type: ignore[arg-type]
        username=clean_username(fields.get("username")),
        outcome=fields.get("outcome"),  # type: ignore[arg-type]
        status_code=fields.get("status_code"),  # type: ignore[arg-type]
        http_method=fields.get("http_method"),  # type: ignore[arg-type]
        url_path=fields.get("url_path"),  # type: ignore[arg-type]
        hostname=host if host and host != "-" else None,
        service=tag if tag and tag != "-" else None,
        message=truncate(msg, 1000),
    )


def parse_syslog_content(text: str, default_year: int | None = None) -> ParseResult:
    """Parse syslog / access-log text. Lines starting with ``#`` are comments."""
    year = default_year or datetime.now().year
    result = ParseResult(source_format="syslog")
    text = text.lstrip("﻿")
    if not text.strip():
        result.error = "The file is empty."
        return result

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.rstrip("\r\n")
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        item = parse_syslog_line(stripped.strip(), line_number, year)
        if isinstance(item, LogEvent):
            result.events.append(item)
        else:
            result.rejected.append(item)

    if not result.events and result.rejected:
        result.error = (
            "Unsupported format: no lines matched the supported syslog formats "
            "(RFC 3164, RFC 5424, ISO-timestamped syslog, Apache/Nginx access log)."
        )
    return result
