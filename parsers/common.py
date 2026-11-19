"""Helpers shared by the JSON and Syslog parsers (classification, validation)."""

from __future__ import annotations

import re

from parsers.models import (
    EVENT_AUTH_FAILURE,
    EVENT_AUTH_SUCCESS,
    EVENT_HTTP_REQUEST,
    EVENT_SYSTEM,
)

_AUTH_KEYWORDS = (
    "login", "logon", "log_in", "log-in", "signin", "sign_in", "sign-in",
    "auth", "password", "credential", "ssh", "session_start",
)
_LOGOUT_KEYWORDS = ("logout", "logoff", "log_out", "sign_out", "signout")
_FAILURE_PATTERN = re.compile(
    r"\b(fail\w*|denied|invalid|rejected|unsuccessful|unauthori[sz]ed|bad[_ ]password|locked)\b"
)
_SUCCESS_PATTERN = re.compile(
    r"\b(success\w*|succeeded|accepted|granted|allowed|ok|authenticated|logged[_ ]in)\b"
)
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@\\$-]{1,128}$")


def classify_event(
    *texts: str | None,
    success_flag: bool | None = None,
    status_code: int | None = None,
    is_http: bool = False,
) -> tuple[str, str | None]:
    """Decide the normalised event type and outcome for a record.

    Returns ``(event_type, outcome)`` where outcome is ``'failure'``,
    ``'success'`` or ``None``.
    """
    if is_http and status_code is not None:
        outcome = "failure" if status_code >= 400 else "success"
        return EVENT_HTTP_REQUEST, outcome

    combined = " ".join(t for t in texts if t).lower()
    if any(k in combined for k in _LOGOUT_KEYWORDS):
        return EVENT_SYSTEM, None

    is_auth = any(k in combined for k in _AUTH_KEYWORDS) or success_flag is not None
    if not is_auth:
        return EVENT_SYSTEM, None

    if success_flag is True:
        return EVENT_AUTH_SUCCESS, "success"
    if success_flag is False:
        return EVENT_AUTH_FAILURE, "failure"
    if _FAILURE_PATTERN.search(combined):
        return EVENT_AUTH_FAILURE, "failure"
    if _SUCCESS_PATTERN.search(combined):
        return EVENT_AUTH_SUCCESS, "success"
    return EVENT_SYSTEM, None


def clean_username(value: object) -> str | None:
    """Normalise a username; drop empty or obviously invalid values."""
    if value is None:
        return None
    text = str(value).strip().strip("'\"")
    if not text or text in {"-", "unknown", "null", "none"}:
        return None
    if not _USERNAME_PATTERN.match(text):
        return None
    return text


def parse_status_code(value: object) -> tuple[int | None, bool]:
    """Return ``(status_code, is_valid)``. Missing values are valid (None)."""
    if value is None or value == "":
        return None, True
    try:
        code = int(str(value).strip())
    except ValueError:
        return None, False
    if 100 <= code <= 599:
        return code, True
    return None, False


def truncate(text: str, limit: int = 2000) -> str:
    return text if len(text) <= limit else text[:limit] + "...[truncated]"
