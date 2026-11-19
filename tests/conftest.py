"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import DetectionSettings  # noqa: E402
from database import Database  # noqa: E402

BASE_TIME = datetime(2026, 11, 18, 10, 0, 0)  # Wednesday, inside business hours


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """A fresh, empty SQLite database for each test."""
    return Database(tmp_path / "test.db")


@pytest.fixture
def settings() -> DetectionSettings:
    """Default settings with an explicit, test-controlled watchlist."""
    return DetectionSettings.from_dict({"watchlist": ["203.0.113.45", "198.51.100.0/28"]})


def make_events(rows: list[dict[str, Any]]) -> pd.DataFrame:
    """Build an events DataFrame shaped like ``Database.get_events_df()``."""
    defaults = {
        "source_ip": None, "username": None, "outcome": None, "status_code": None,
        "http_method": None, "url_path": None, "message": None, "file_name": "test.log",
        "line_number": 1, "hostname": None, "service": None,
    }
    df = pd.DataFrame([{**defaults, **row} for row in rows])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").astype("Int64")
    return df


def ts(minutes: float = 0, seconds: float = 0, base: datetime = BASE_TIME) -> str:
    return (base + timedelta(minutes=minutes, seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S")


def failures(ip: str, count: int, user: str = "admin", start: float = 0, step_s: int = 20,
             base: datetime = BASE_TIME) -> list[dict[str, Any]]:
    return [
        {"timestamp": ts(start, i * step_s, base), "event_type": "auth_failure", "source_ip": ip,
         "username": user, "outcome": "failure"}
        for i in range(count)
    ]


def success(ip: str, user: str, minutes: float, base: datetime = BASE_TIME) -> dict[str, Any]:
    return {"timestamp": ts(minutes, 0, base), "event_type": "auth_success", "source_ip": ip,
            "username": user, "outcome": "success"}
