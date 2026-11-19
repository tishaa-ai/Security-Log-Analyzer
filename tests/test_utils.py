"""Utility function tests (IP validation, timestamps)."""

from __future__ import annotations

from datetime import datetime

from utils.ip_utils import ip_in_networks, is_valid_ip, looks_like_ip, normalize_ip, parse_watchlist
from utils.security import pdf_safe
from utils.time_utils import parse_rfc3164_timestamp, parse_timestamp


def test_ip_validation() -> None:
    assert is_valid_ip("192.0.2.1") and is_valid_ip("2001:db8::1")
    assert not is_valid_ip("999.1.1.1") and not is_valid_ip("abc") and not is_valid_ip(None)
    assert normalize_ip(" 2001:DB8:0:0::1 ") == "2001:db8::1"
    assert looks_like_ip("300.1.2.3") and not looks_like_ip("host.example.com")


def test_watchlist_parsing_and_matching() -> None:
    nets, invalid = parse_watchlist(["203.0.113.0/28", "198.51.100.7  # note", "bogus", "", "# only comment"])
    assert len(nets) == 2 and invalid == ["bogus"]
    assert ip_in_networks("203.0.113.12", nets)
    assert not ip_in_networks("203.0.113.16", nets)
    assert not ip_in_networks("not-ip", nets)


def test_timestamp_formats() -> None:
    expected = datetime(2026, 11, 18, 8, 0, 0)
    assert parse_timestamp("2026-11-18T08:00:00Z") == expected
    assert parse_timestamp("2026-11-18 10:00:00+02:00") == expected
    assert parse_timestamp("18/Nov/2026:08:00:00 +0000") == expected
    assert parse_timestamp(1794988800) == expected
    assert parse_timestamp(1794988800000) == expected
    assert parse_timestamp("garbage") is None and parse_timestamp(True) is None
    assert parse_timestamp("1800-01-01T00:00:00") is None  # out of sane range


def test_rfc3164_timestamp() -> None:
    assert parse_rfc3164_timestamp("Nov  8 09:00:01", 2026) == datetime(2026, 11, 8, 9, 0, 1)
    assert parse_rfc3164_timestamp("Feb 30 09:00:01", 2026) is None


def test_pdf_safe() -> None:
    assert pdf_safe("a — b ✓") == "a - b ?"
    assert pdf_safe("x" * 50, max_len=10) == "xxxxxxx..."
