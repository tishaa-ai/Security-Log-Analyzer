"""Malformed, incomplete and unsupported input handling."""

from __future__ import annotations

import json

from parsers.ingest import parse_file
from parsers.json_parser import parse_json_content
from parsers.syslog_parser import parse_syslog_content


def _reasons(result) -> list[str]:
    return [r.reason for r in result.rejected]


def test_json_records_with_missing_or_bad_fields_are_rejected() -> None:
    records = [
        {"event_type": "login", "username": "eve", "source_ip": "192.0.2.50"},          # no timestamp
        {"timestamp": "2026-11-18T11:00:00Z", "username": "m", "source_ip": "999.10.1.5"},  # bad IP
        {"timestamp": "yesterday afternoon", "username": "t", "source_ip": "192.0.2.51"},  # bad time
        "not-an-object",
        {},
        {"timestamp": "2026-11-18T11:00:00Z", "client_ip": "192.0.2.1", "path": "/", "status": 999},
        {"timestamp": "2026-11-18T11:00:00Z"},  # no usable fields
        {"timestamp": "2026-11-18T11:00:00Z", "username": "ok", "source_ip": "192.0.2.9", "outcome": "success",
         "event_type": "login"},
    ]
    result = parse_json_content(json.dumps(records))
    assert result.parsed_count == 1 and result.rejected_count == 7
    reasons = " | ".join(_reasons(result))
    for expected in ("Missing timestamp", "Invalid source IP", "Invalid timestamp", "not a JSON object",
                     "Empty JSON object", "Invalid HTTP status code", "no usable fields"):
        assert expected in reasons


def test_broken_json_line_is_rejected_but_others_parse() -> None:
    text = '{"time": "2026-11-18T10:00:00Z", "ip": "192.0.2.1", "user": "a", "action": "login failed"}\n{"time": "2026'
    result = parse_json_content(text)
    assert result.parsed_count == 1 and result.rejected_count == 1
    assert result.rejected[0].reason.startswith("Invalid JSON")
    assert result.rejected[0].line_number == 2


def test_syslog_malformed_lines() -> None:
    text = "\n".join([
        "this is not a syslog line at all",
        "<38>Nov 18 25:61:00 h sshd[1]: Failed password for bob from 192.0.2.11 port 22 ssh2",
        "<38>Nov 18 10:00:00 h sshd[2]: Failed password for bob from 300.1.2.3 port 22 ssh2",
        "<13>Nov 18",
        "<38>Nov 18 10:00:00 h sshd[3]: Accepted password for bob from 192.0.2.11 port 22 ssh2",
    ])
    result = parse_syslog_content(text, default_year=2026)
    assert result.parsed_count == 1 and result.rejected_count == 4
    reasons = " | ".join(_reasons(result))
    assert "Unrecognised line format" in reasons
    assert "Invalid or unparseable syslog timestamp" in reasons
    assert "Invalid IP address in message" in reasons


def test_empty_files_report_errors() -> None:
    assert parse_json_content("   ").error == "The file is empty."
    assert parse_syslog_content("\n\n").error == "The file is empty."


def test_unsupported_extension() -> None:
    result = parse_file("evil.exe", b"MZ....")
    assert result.error and "Unsupported file type" in result.error


def test_binary_content_rejected() -> None:
    result = parse_file("data.log", b"\x00\x01\x02binary")
    assert result.error and "Binary" in result.error


def test_text_file_that_is_not_syslog() -> None:
    result = parse_file("notes.txt", b"hello world\nthis is plain text\n")
    assert result.error and "Unsupported format" in result.error
    assert result.rejected_count == 2


def test_wrong_format_hint_gives_useful_error() -> None:
    result = parse_file("auth.json", b"Nov 18 10:00:00 h sshd[1]: Accepted password for a from 192.0.2.1 port 1",
                        format_hint="json")
    assert result.error and "neither valid JSON" in result.error


def test_jsonl_inside_txt_is_autodetected() -> None:
    content = b'{"timestamp": "2026-11-18T10:00:00Z", "ip": "192.0.2.1", "user": "a", "result": "failed login"}\n'
    result = parse_file("export.txt", content)
    assert result.source_format == "json" and result.parsed_count == 1
