"""Syslog / access-log parsing tests."""

from __future__ import annotations

from parsers.models import EVENT_AUTH_FAILURE, EVENT_AUTH_SUCCESS, EVENT_HTTP_REQUEST, EVENT_SYSTEM
from parsers.syslog_parser import parse_syslog_content


def _one(line: str, year: int = 2026):
    result = parse_syslog_content(line, default_year=year)
    assert result.parsed_count == 1, result.rejected
    return result.events[0]


def test_rfc3164_failed_password() -> None:
    e = _one("<38>Nov 18 03:02:00 bastion01 sshd[4106]: Failed password for root from 203.0.113.12 port 50000 ssh2")
    assert e.event_type == EVENT_AUTH_FAILURE
    assert e.username == "root" and e.source_ip == "203.0.113.12"
    assert e.timestamp == "2026-11-18 03:02:00"
    assert e.hostname == "bastion01" and e.service == "sshd"


def test_rfc3164_without_priority_and_single_digit_day() -> None:
    e = _one("Nov  8 09:00:01 host1 sshd[1]: Accepted publickey for alice from 192.0.2.10 port 5000 ssh2")
    assert e.event_type == EVENT_AUTH_SUCCESS and e.timestamp == "2026-11-08 09:00:01"


def test_failed_password_for_invalid_user() -> None:
    e = _one("Nov 18 21:30:02 h sshd[9]: Failed password for invalid user oracle from 198.51.100.200 port 4 ssh2")
    assert e.event_type == EVENT_AUTH_FAILURE and e.username == "oracle"


def test_invalid_user_line_is_informational_to_avoid_double_counting() -> None:
    e = _one("Nov 18 21:30:00 h sshd[9]: Invalid user oracle from 198.51.100.200 port 41001")
    assert e.event_type == EVENT_SYSTEM and e.source_ip == "198.51.100.200"


def test_rfc5424_generic_application_message() -> None:
    e = _one("<38>1 2026-11-18T11:00:00Z app02.example.com webportal 2211 AUTH - "
             "login failed for user 'carol' from 192.0.2.12")
    assert e.event_type == EVENT_AUTH_FAILURE and e.username == "carol" and e.source_ip == "192.0.2.12"
    assert e.service == "webportal"


def test_iso_timestamped_syslog() -> None:
    e = _one("2026-11-18T12:05:33+01:00 bastion01 sshd[1]: Accepted publickey for erin from 192.0.2.14 port 1 ssh2")
    assert e.event_type == EVENT_AUTH_SUCCESS and e.timestamp == "2026-11-18 11:05:33"


def test_pam_failure_outside_sshd_counts_as_failure() -> None:
    e = _one("<85>Nov 18 14:22:10 h su[1]: pam_unix(su:auth): authentication failure; logname=dave "
             "uid=1001 euid=0 tty=pts/0 ruser=dave rhost=  user=root")
    assert e.event_type == EVENT_AUTH_FAILURE and e.username == "root" and e.source_ip is None


def test_embedded_nginx_access_log() -> None:
    e = _one('<190>Nov 18 16:20:01 web02 nginx: 203.0.113.140 - - [18/Nov/2026:16:20:01 +0000] '
             '"GET /admin HTTP/1.1" 403 153 "-" "Mozilla/5.0"')
    assert e.event_type == EVENT_HTTP_REQUEST and e.status_code == 403
    assert e.url_path == "/admin" and e.source_ip == "203.0.113.140"


def test_standalone_apache_access_log() -> None:
    e = _one('192.0.2.20 - - [18/Nov/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 12')
    assert e.event_type == EVENT_HTTP_REQUEST and e.status_code == 401 and e.http_method == "POST"


def test_cron_line_is_system_event() -> None:
    e = _one("<78>Nov 18 00:17:00 bastion01 CRON[4127]: (root) CMD (run-parts /etc/cron.hourly)")
    assert e.event_type == EVENT_SYSTEM
