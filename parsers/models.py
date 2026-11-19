"""Data classes shared by all log parsers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Normalised event types produced by the parsers.
EVENT_AUTH_FAILURE = "auth_failure"
EVENT_AUTH_SUCCESS = "auth_success"
EVENT_HTTP_REQUEST = "http_request"
EVENT_SYSTEM = "system"

EVENT_TYPES: tuple[str, ...] = (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    EVENT_HTTP_REQUEST,
    EVENT_SYSTEM,
)


@dataclass
class LogEvent:
    """One successfully parsed and normalised log record."""

    timestamp: str  # 'YYYY-MM-DD HH:MM:SS' (UTC)
    event_type: str
    source_format: str  # 'json' or 'syslog'
    line_number: int
    raw: str
    source_ip: str | None = None
    username: str | None = None
    outcome: str | None = None
    status_code: int | None = None
    http_method: str | None = None
    url_path: str | None = None
    hostname: str | None = None
    service: str | None = None
    message: str | None = None
    event_hash: str = ""  # filled in by the ingestion pipeline (dedup key)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RejectedRecord:
    """A record that could not be parsed, with a human-readable reason."""

    line_number: int
    reason: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ParseResult:
    """Outcome of parsing one file."""

    source_format: str
    events: list[LogEvent] = field(default_factory=list)
    rejected: list[RejectedRecord] = field(default_factory=list)
    error: str | None = None  # set when the whole file is unusable

    @property
    def parsed_count(self) -> int:
        return len(self.events)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    @property
    def total_records(self) -> int:
        return self.parsed_count + self.rejected_count

    @property
    def ok(self) -> bool:
        return self.error is None
