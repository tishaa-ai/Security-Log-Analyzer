"""Output-safety helpers (CSV formula-injection protection, PDF text safety)."""

from __future__ import annotations

import hashlib

# Characters that make spreadsheet applications (Excel, LibreOffice, Google
# Sheets) interpret a cell as a formula. See OWASP "CSV Injection".
FORMULA_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r", "\n", "|", "%")


def sanitize_csv_cell(value: object) -> object:
    """Neutralise values that a spreadsheet could execute as a formula.

    Numbers are returned unchanged (a negative *number* is harmless). Text
    starting with a dangerous character is prefixed with a single quote so the
    spreadsheet treats it as plain text.
    """
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def pdf_safe(text: object, max_len: int | None = None) -> str:
    """Make text safe for the built-in PDF fonts (Latin-1 only).

    Unsupported characters are replaced instead of crashing the export, and
    very long values can be truncated for readability.
    """
    value = "" if text is None else str(text)
    replacements = {"—": "-", "–": "-", "’": "'", "‘": "'",
                    "“": '"', "”": '"', "…": "...", "→": "->",
                    "≥": ">=", "≤": "<="}
    for old, new in replacements.items():
        value = value.replace(old, new)
    value = value.encode("latin-1", errors="replace").decode("latin-1")
    # Control characters (except newline) can break PDF layout.
    value = "".join(ch if ch == "\n" or ord(ch) >= 32 else " " for ch in value)
    if max_len is not None and len(value) > max_len:
        value = value[: max_len - 3] + "..."
    return value


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
