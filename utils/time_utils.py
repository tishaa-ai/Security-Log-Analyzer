"""Timestamp parsing and normalisation.

Every event timestamp is normalised to a *naive UTC* ``datetime`` and stored
as the string ``YYYY-MM-DD HH:MM:SS``. Timezone-aware inputs are converted to
UTC; inputs without a timezone are assumed to already be UTC.
"""

from __future__ import annotations

from datetime import datetime, timezone

STORAGE_FORMAT = "%Y-%m-%d %H:%M:%S"
MIN_YEAR = 1990
MAX_YEAR = 2100

_EXTRA_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",  # Apache / Nginx access logs
    "%d/%b/%Y:%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%b %d %Y %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
)


def _to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0)


def _in_range(dt: datetime | None) -> datetime | None:
    if dt is None or not (MIN_YEAR <= dt.year <= MAX_YEAR):
        return None
    return dt


def parse_timestamp(value: object) -> datetime | None:
    """Parse many common timestamp representations; return ``None`` if invalid.

    Supported: ISO 8601 (with or without ``Z``/offset), ``YYYY-MM-DD HH:MM:SS``,
    Apache access-log format, and Unix epoch seconds/milliseconds.
    """
    if value is None or isinstance(value, bool):
        return None

    # Unix epoch (seconds or milliseconds)
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:  # milliseconds
            seconds /= 1000.0
        try:
            dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return _in_range(_to_naive_utc(dt))

    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return parse_timestamp(int(text))

    try:
        return _in_range(_to_naive_utc(datetime.fromisoformat(text.replace("Z", "+00:00"))))
    except ValueError:
        pass

    for fmt in _EXTRA_FORMATS:
        try:
            return _in_range(_to_naive_utc(datetime.strptime(text, fmt)))
        except ValueError:
            continue
    return None


def parse_rfc3164_timestamp(text: str, year: int) -> datetime | None:
    """Parse ``'Nov 18 08:15:02'`` style timestamps using the supplied year."""
    cleaned = " ".join(text.split())  # collapse the double space in 'Nov  8'
    try:
        return _in_range(datetime.strptime(f"{cleaned} {year}", "%b %d %H:%M:%S %Y"))
    except ValueError:
        return None


def format_timestamp(dt: datetime) -> str:
    return dt.strftime(STORAGE_FORMAT)


def utc_now_str() -> str:
    return format_timestamp(_to_naive_utc(datetime.now(timezone.utc)))
