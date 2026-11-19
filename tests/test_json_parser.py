"""JSON / JSON Lines parsing tests."""

from __future__ import annotations

import json

from parsers.json_parser import parse_json_content
from parsers.models import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS, EVENT_HTTP_REQUEST, EVENT_SYSTEM


def test_json_array_auth_events_are_normalised() -> None:
    text = json.dumps([
        {"timestamp": "2026-11-18T08:00:00Z", "event_type": "user_login", "outcome": "failure",
         "username": "alice", "source_ip": "192.0.2.10"},
        {"timestamp": "2026-11-18T08:01:00+02:00", "event_type": "user_login", "outcome": "success",
         "username": "alice", "source_ip": "192.0.2.10"},
    ])
    result = parse_json_content(text)
    assert result.ok and result.parsed_count == 2 and result.rejected_count == 0
    first, second = result.events
    assert first.event_type == EVENT_AUTH_FAILURE and first.outcome == "failure"
    assert first.timestamp == "2026-11-18 08:00:00"
    assert second.event_type == EVENT_AUTH_SUCCESS
    assert second.timestamp == "2026-11-18 06:01:00"  # converted to UTC


def test_wrapper_object_with_events_key() -> None:
    doc = {"_synthetic_notice": "x", "events": [
        {"time": 1794988800, "user": "bob", "ip": "198.51.100.5", "action": "login", "result": "denied"}]}
    result = parse_json_content(json.dumps(doc))
    assert result.parsed_count == 1
    assert result.events[0].event_type == EVENT_AUTH_FAILURE
    assert result.events[0].username == "bob"


def test_nested_ecs_fields_are_supported() -> None:
    record = {"@timestamp": "2026-11-18T10:15:00Z", "event": {"action": "authentication", "outcome": "success"},
              "user": {"name": "erin"}, "source": {"ip": "192.0.2.14"}}
    result = parse_json_content(json.dumps(record))
    event = result.events[0]
    assert event.username == "erin" and event.source_ip == "192.0.2.14"
    assert event.event_type == EVENT_AUTH_SUCCESS


def test_json_lines_http_records() -> None:
    lines = "\n".join([
        "# comment line is ignored",
        json.dumps({"time": "2026-11-18T09:30:00Z", "client_ip": "203.0.113.99", "method": "POST",
                    "path": "/api/login", "status": 401}),
        json.dumps({"time": "2026-11-18T09:31:00Z", "client_ip": "192.0.2.20",
                    "request": "GET /index.html HTTP/1.1", "status_code": "200"}),
    ])
    result = parse_json_content(lines)
    assert result.parsed_count == 2
    a, b = result.events
    assert a.event_type == EVENT_HTTP_REQUEST and a.status_code == 401 and a.http_method == "POST"
    assert a.outcome == "failure"
    assert b.http_method == "GET" and b.url_path == "/index.html" and b.status_code == 200


def test_logout_is_not_a_login_success() -> None:
    record = {"timestamp": "2026-11-18T10:00:00Z", "event_type": "user_logout", "username": "bob",
              "source_ip": "192.0.2.11", "outcome": "success"}
    assert parse_json_content(json.dumps(record)).events[0].event_type == EVENT_SYSTEM


def test_boolean_success_flag() -> None:
    record = {"timestamp": "2026-11-18T10:00:00Z", "username": "x", "source_ip": "192.0.2.1", "success": False}
    assert parse_json_content(json.dumps(record)).events[0].event_type == EVENT_AUTH_FAILURE
