"""JSON / JSON Lines log parser.

Accepted layouts:

* a JSON array of objects: ``[{...}, {...}]``
* a wrapper object holding a list: ``{"events": [...]}`` (also ``records``,
  ``logs``, ``data``, ``Records``)
* a single JSON object
* JSON Lines / NDJSON: one object per line (lines starting with ``#`` are
  treated as comments)

Field names vary between products, so each normalised field is looked up
through a list of common aliases (including nested keys such as
``source.ip`` used by Elastic Common Schema).
"""

from __future__ import annotations

import json
from typing import Any

from parsers.common import classify_event, clean_username, parse_status_code, truncate
from parsers.models import LogEvent, ParseResult, RejectedRecord
from utils.ip_utils import normalize_ip
from utils.time_utils import format_timestamp, parse_timestamp

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "time", "ts", "datetime", "date",
                  "event_time", "eventtime", "created_at", "event.created"),
    "source_ip": ("source_ip", "src_ip", "sourceip", "client_ip", "clientip",
                  "remote_addr", "remote_ip", "ip", "ip_address", "source.ip",
                  "client.ip", "sourceipaddress", "src"),
    "username": ("username", "user", "user_name", "user.name", "account",
                 "account_name", "login", "target_user", "useridentity.username"),
    "event": ("event_type", "event", "action", "event.action", "eventname",
              "activity", "type", "category", "event.category"),
    "outcome": ("outcome", "event.outcome", "result", "auth_result", "status"),
    "success": ("success", "successful", "authenticated"),
    "status_code": ("status_code", "http_status", "response_code", "statuscode",
                    "http.response.status_code", "response.status", "status"),
    "http_method": ("http_method", "method", "request_method", "http.request.method"),
    "url_path": ("url_path", "path", "uri", "url", "request_path", "url.path",
                 "url.original", "request"),
    "hostname": ("hostname", "host", "host.name", "server"),
    "service": ("service", "app", "application", "program", "process",
                "service.name", "process.name"),
    "message": ("message", "msg", "description", "log", "details"),
}

WRAPPER_KEYS = ("events", "records", "Records", "logs", "data", "entries")


def _flatten(record: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dictionaries into lower-case dotted keys."""
    flat: dict[str, Any] = {}
    for key, value in record.items():
        full_key = f"{prefix}{key}".lower()
        if isinstance(value, dict):
            flat.update(_flatten(value, f"{full_key}."))
        else:
            flat[full_key] = value
    return flat


def _lookup(flat: dict[str, Any], field_name: str) -> Any:
    for alias in FIELD_ALIASES[field_name]:
        value = flat.get(alias)
        if value is not None and value != "":
            return value
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    return None


def record_to_event(record: Any, line_number: int, raw: str) -> LogEvent | RejectedRecord:
    """Validate one JSON record and convert it to a :class:`LogEvent`."""
    raw = truncate(raw)
    if not isinstance(record, dict):
        return RejectedRecord(line_number, "Record is not a JSON object", raw)
    if not record:
        return RejectedRecord(line_number, "Empty JSON object", raw)

    flat = _flatten(record)

    ts_value = _lookup(flat, "timestamp")
    if ts_value is None:
        return RejectedRecord(line_number, "Missing timestamp field", raw)
    parsed_ts = parse_timestamp(ts_value)
    if parsed_ts is None:
        return RejectedRecord(line_number, f"Invalid timestamp: {str(ts_value)[:60]!r}", raw)

    ip_value = _lookup(flat, "source_ip")
    source_ip = normalize_ip(ip_value)
    if ip_value is not None and source_ip is None:
        return RejectedRecord(line_number, f"Invalid source IP address: {str(ip_value)[:60]!r}", raw)

    # 'status' is ambiguous: numeric -> HTTP status code, text -> outcome.
    status_raw = _lookup(flat, "status_code")
    outcome_raw = _lookup(flat, "outcome")
    if isinstance(status_raw, str) and not status_raw.strip().isdigit():
        status_raw = flat.get("status_code") or flat.get("http_status") or flat.get("response_code")
    if outcome_raw is not None and str(outcome_raw).strip().isdigit():
        outcome_raw = None
    status_code, status_ok = parse_status_code(status_raw)
    if not status_ok:
        return RejectedRecord(line_number, f"Invalid HTTP status code: {str(status_raw)[:20]!r}", raw)

    method = _lookup(flat, "http_method")
    url_path = _lookup(flat, "url_path")
    if isinstance(url_path, str) and " " in url_path.strip():
        # e.g. "GET /login HTTP/1.1"
        parts = url_path.split()
        if len(parts) >= 2 and parts[0].isalpha():
            method = method or parts[0]
            url_path = parts[1]

    username = clean_username(_lookup(flat, "username"))
    event_text = _lookup(flat, "event")
    message = _lookup(flat, "message")
    is_http = status_code is not None and (method is not None or url_path is not None)

    event_type, outcome = classify_event(
        str(event_text) if event_text is not None else None,
        str(outcome_raw) if outcome_raw is not None else None,
        str(message) if message is not None else None,
        success_flag=_as_bool(_lookup(flat, "success")),
        status_code=status_code,
        is_http=is_http,
    )

    if source_ip is None and username is None and status_code is None and message is None:
        return RejectedRecord(
            line_number,
            "Record has no usable fields (need source IP, user, HTTP status or message)",
            raw,
        )

    if message is None:
        message = " ".join(
            str(part) for part in (event_text, outcome_raw, method, url_path, status_code) if part
        ) or None

    return LogEvent(
        timestamp=format_timestamp(parsed_ts),
        event_type=event_type,
        source_format="json",
        line_number=line_number,
        raw=raw,
        source_ip=source_ip,
        username=username,
        outcome=outcome,
        status_code=status_code,
        http_method=str(method).upper()[:10] if method else None,
        url_path=str(url_path)[:500] if url_path else None,
        hostname=str(_lookup(flat, "hostname"))[:255] if _lookup(flat, "hostname") else None,
        service=str(_lookup(flat, "service"))[:100] if _lookup(flat, "service") else None,
        message=truncate(str(message), 1000) if message else None,
    )


def _add(result: ParseResult, item: LogEvent | RejectedRecord) -> None:
    if isinstance(item, LogEvent):
        result.events.append(item)
    else:
        result.rejected.append(item)


def parse_json_content(text: str) -> ParseResult:
    """Parse JSON or JSON Lines text into a :class:`ParseResult`."""
    result = ParseResult(source_format="json")
    text = text.lstrip("﻿")
    if not text.strip():
        result.error = "The file is empty."
        return result

    # 1) Try the whole document as a single JSON value.
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        document = None
    else:
        if isinstance(document, dict):
            wrapped = next(
                (document[k] for k in WRAPPER_KEYS if isinstance(document.get(k), list)), None
            )
            records = wrapped if wrapped is not None else [document]
        elif isinstance(document, list):
            records = document
        else:
            result.error = "Unsupported JSON structure: expected an object or an array of objects."
            return result
        for index, record in enumerate(records, start=1):
            raw = json.dumps(record, ensure_ascii=False, default=str)
            _add(result, record_to_event(record, index, raw))
        return result

    # 2) Fall back to JSON Lines (one JSON object per line).
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            result.rejected.append(
                RejectedRecord(line_number, f"Invalid JSON: {exc.msg} (column {exc.colno})", truncate(stripped))
            )
            continue
        _add(result, record_to_event(record, line_number, stripped))

    if not result.events and result.rejected and not text.lstrip().startswith(("{", "[")):
        result.error = (
            "Unsupported format: the file is neither valid JSON nor JSON Lines. "
            "If this is a syslog/text log, choose the Syslog format."
        )
    return result
