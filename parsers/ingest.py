"""File-level entry point: decode bytes, detect the format, dispatch to a parser."""

from __future__ import annotations

from pathlib import PurePath

from config import JSON_EXTENSIONS, MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS, SYSLOG_EXTENSIONS
from parsers.json_parser import parse_json_content
from parsers.models import ParseResult
from parsers.syslog_parser import parse_syslog_content

FORMAT_AUTO = "auto"
FORMAT_JSON = "json"
FORMAT_SYSLOG = "syslog"


def decode_bytes(content: bytes) -> tuple[str | None, str | None]:
    """Decode uploaded bytes as text. Returns ``(text, error)``."""
    if b"\x00" in content[:4096]:
        return None, "Binary file detected. Only UTF-8 text log files are supported."
    try:
        return content.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        try:
            # Latin-1 never fails; acceptable for legacy syslog files.
            return content.decode("latin-1"), None
        except UnicodeDecodeError:  # pragma: no cover - defensive
            return None, "Could not decode the file as text."


def detect_format(file_name: str, text: str) -> str | None:
    """Guess the log format from the extension, falling back to content sniffing."""
    suffix = PurePath(file_name).suffix.lower()
    if suffix in JSON_EXTENSIONS:
        return FORMAT_JSON
    if suffix in SYSLOG_EXTENSIONS:
        # A .txt/.log file may still hold JSON Lines.
        first = next((l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")), "")
        return FORMAT_JSON if first.startswith(("{", "[")) else FORMAT_SYSLOG
    return None


def parse_file(
    file_name: str,
    content: bytes,
    format_hint: str = FORMAT_AUTO,
    default_year: int | None = None,
) -> ParseResult:
    """Parse an uploaded file and return a :class:`ParseResult`.

    ``format_hint`` may be ``'auto'``, ``'json'`` or ``'syslog'``.
    ``default_year`` is used for RFC 3164 syslog lines that carry no year.
    """
    suffix = PurePath(file_name).suffix.lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        return ParseResult(
            source_format="unknown",
            error=f"Unsupported file type '{suffix or '(none)'}'. Supported extensions: {allowed}.",
        )
    if len(content) > MAX_UPLOAD_BYTES:
        return ParseResult(
            source_format="unknown",
            error=f"File is too large ({len(content):,} bytes). Limit is {MAX_UPLOAD_BYTES:,} bytes.",
        )

    text, error = decode_bytes(content)
    if error or text is None:
        return ParseResult(source_format="unknown", error=error)

    chosen = format_hint if format_hint in (FORMAT_JSON, FORMAT_SYSLOG) else detect_format(file_name, text)
    if chosen == FORMAT_JSON:
        return parse_json_content(text)
    if chosen == FORMAT_SYSLOG:
        return parse_syslog_content(text, default_year=default_year)
    return ParseResult(source_format="unknown", error="Could not determine the log format.")
