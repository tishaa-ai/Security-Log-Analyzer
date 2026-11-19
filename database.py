"""SQLite persistence layer.

Tables
------
uploaded_files        metadata for every ingested file (unique by SHA-256)
events                normalised log events (unique by ``event_hash``)
rejected_records      lines/records the parsers could not accept
alerts                detection results (status and notes are analyst-owned)
alert_status_history  audit trail of every status change
alert_notes           analyst investigation notes
analysis_runs         history of detection-engine runs
settings              persisted :class:`config.DetectionSettings`

A new connection is opened for each operation, which keeps the class safe to
use from Streamlit's script reruns and threads.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

import pandas as pd

from config import ALERT_STATUSES, DB_PATH, DetectionSettings
from parsers.models import LogEvent, RejectedRecord
from utils.time_utils import utc_now_str

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploaded_files (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name        TEXT NOT NULL,
    file_hash        TEXT NOT NULL UNIQUE,
    file_format      TEXT NOT NULL,
    file_size        INTEGER NOT NULL,
    uploaded_at      TEXT NOT NULL,
    total_records    INTEGER NOT NULL DEFAULT 0,
    parsed_records   INTEGER NOT NULL DEFAULT 0,
    rejected_records INTEGER NOT NULL DEFAULT 0,
    inserted_events  INTEGER NOT NULL DEFAULT 0,
    duplicate_events INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash    TEXT NOT NULL UNIQUE,
    file_id       INTEGER NOT NULL REFERENCES uploaded_files(id) ON DELETE CASCADE,
    line_number   INTEGER,
    timestamp     TEXT NOT NULL,
    source_ip     TEXT,
    username      TEXT,
    event_type    TEXT NOT NULL,
    outcome       TEXT,
    status_code   INTEGER,
    http_method   TEXT,
    url_path      TEXT,
    hostname      TEXT,
    service       TEXT,
    message       TEXT,
    raw           TEXT,
    source_format TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);

CREATE TABLE IF NOT EXISTS rejected_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER NOT NULL REFERENCES uploaded_files(id) ON DELETE CASCADE,
    line_number INTEGER,
    reason      TEXT NOT NULL,
    raw         TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    rule_id         TEXT NOT NULL,
    rule_name       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    priority        TEXT NOT NULL,
    risk_factors    TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    source_ip       TEXT,
    username        TEXT,
    description     TEXT NOT NULL,
    evidence        TEXT NOT NULL,
    event_count     INTEGER NOT NULL,
    recommendations TEXT NOT NULL,
    mitre           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'New',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    run_id          INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

CREATE TABLE IF NOT EXISTS alert_status_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    old_status TEXT,
    new_status TEXT NOT NULL,
    analyst    TEXT NOT NULL,
    changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    analyst    TEXT NOT NULL,
    note       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analysis_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    events_analyzed  INTEGER NOT NULL DEFAULT 0,
    alerts_generated INTEGER NOT NULL DEFAULT 0,
    new_alerts       INTEGER NOT NULL DEFAULT 0,
    settings         TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

EVENT_COLUMNS = (
    "event_hash", "file_id", "line_number", "timestamp", "source_ip", "username",
    "event_type", "outcome", "status_code", "http_method", "url_path", "hostname",
    "service", "message", "raw", "source_format",
)
JSON_ALERT_FIELDS = ("risk_factors", "evidence", "recommendations", "mitre")


class Database:
    """Thin wrapper around an SQLite file."""

    def __init__(self, path: str | Path = DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    # ------------------------------------------------------------------ core
    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    # ----------------------------------------------------------------- files
    def get_file_by_hash(self, file_hash: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM uploaded_files WHERE file_hash = ?", (file_hash,)).fetchone()
        return dict(row) if row else None

    def store_parsed_file(
        self,
        file_name: str,
        file_hash: str,
        file_format: str,
        file_size: int,
        events: Iterable[LogEvent],
        rejected: Iterable[RejectedRecord],
    ) -> dict[str, Any]:
        """Insert file metadata, events and rejected records in one transaction.

        Events whose ``event_hash`` already exists (e.g. overlapping files)
        are skipped. Returns the stored file row.
        """
        events = list(events)
        rejected = list(rejected)
        with self.connect() as conn:
            cur = conn.execute(
                """INSERT INTO uploaded_files
                   (file_name, file_hash, file_format, file_size, uploaded_at,
                    total_records, parsed_records, rejected_records)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (file_name, file_hash, file_format, file_size, utc_now_str(),
                 len(events) + len(rejected), len(events), len(rejected)),
            )
            file_id = int(cur.lastrowid)
            before = conn.total_changes
            conn.executemany(
                f"INSERT OR IGNORE INTO events ({', '.join(EVENT_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in EVENT_COLUMNS)})",
                [
                    (e.event_hash, file_id, e.line_number, e.timestamp, e.source_ip, e.username,
                     e.event_type, e.outcome, e.status_code, e.http_method, e.url_path,
                     e.hostname, e.service, e.message, e.raw, e.source_format)
                    for e in events
                ],
            )
            inserted = conn.total_changes - before
            conn.executemany(
                "INSERT INTO rejected_records (file_id, line_number, reason, raw) VALUES (?, ?, ?, ?)",
                [(file_id, r.line_number, r.reason, r.raw) for r in rejected],
            )
            conn.execute(
                "UPDATE uploaded_files SET inserted_events = ?, duplicate_events = ? WHERE id = ?",
                (inserted, len(events) - inserted, file_id),
            )
            row = conn.execute("SELECT * FROM uploaded_files WHERE id = ?", (file_id,)).fetchone()
        return dict(row)

    def list_files(self) -> pd.DataFrame:
        return self._query_df("SELECT * FROM uploaded_files ORDER BY id DESC")

    # ---------------------------------------------------------------- events
    def get_events_df(self) -> pd.DataFrame:
        df = self._query_df(
            """SELECT e.*, f.file_name FROM events e
               JOIN uploaded_files f ON f.id = e.file_id
               ORDER BY e.timestamp, e.id"""
        )
        if not df.empty:
            df["timestamp"] = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S")
            df["status_code"] = pd.to_numeric(df["status_code"], errors="coerce").astype("Int64")
        return df

    def get_rejected_df(self) -> pd.DataFrame:
        return self._query_df(
            """SELECT r.line_number, r.reason, r.raw, f.file_name FROM rejected_records r
               JOIN uploaded_files f ON f.id = r.file_id ORDER BY r.id"""
        )

    def count_events(self) -> int:
        return self._scalar("SELECT COUNT(*) FROM events")

    def get_ingestion_totals(self) -> dict[str, int]:
        with self.connect() as conn:
            row = conn.execute(
                """SELECT COUNT(*) AS files,
                          COALESCE(SUM(total_records), 0) AS total,
                          COALESCE(SUM(parsed_records), 0) AS parsed,
                          COALESCE(SUM(rejected_records), 0) AS rejected
                   FROM uploaded_files"""
            ).fetchone()
        return {k: int(row[k]) for k in ("files", "total", "parsed", "rejected")}

    # ---------------------------------------------------------------- alerts
    def upsert_alerts(self, alerts: Iterable[dict[str, Any]], run_id: int | None) -> int:
        """Insert new alerts or refresh detection fields of existing ones.

        The analyst-owned ``status`` and notes are never overwritten.
        Returns the number of *new* alerts.
        """
        now = utc_now_str()
        new_count = 0
        with self.connect() as conn:
            for alert in alerts:
                exists = conn.execute(
                    "SELECT 1 FROM alerts WHERE alert_id = ?", (alert["alert_id"],)
                ).fetchone()
                payload = {k: (json.dumps(alert[k], default=str) if k in JSON_ALERT_FIELDS else alert[k])
                           for k in alert if k not in ("status",)}
                if exists:
                    conn.execute(
                        """UPDATE alerts SET rule_name=:rule_name, severity=:severity,
                           risk_score=:risk_score, priority=:priority, risk_factors=:risk_factors,
                           timestamp=:timestamp, first_seen=:first_seen, last_seen=:last_seen,
                           source_ip=:source_ip, username=:username, description=:description,
                           evidence=:evidence, event_count=:event_count,
                           recommendations=:recommendations, mitre=:mitre, updated_at=:updated_at
                           WHERE alert_id=:alert_id""",
                        {**payload, "updated_at": now},
                    )
                else:
                    new_count += 1
                    conn.execute(
                        """INSERT INTO alerts (alert_id, rule_id, rule_name, severity, risk_score,
                           priority, risk_factors, timestamp, first_seen, last_seen, source_ip,
                           username, description, evidence, event_count, recommendations, mitre,
                           status, created_at, updated_at, run_id)
                           VALUES (:alert_id, :rule_id, :rule_name, :severity, :risk_score,
                           :priority, :risk_factors, :timestamp, :first_seen, :last_seen,
                           :source_ip, :username, :description, :evidence, :event_count,
                           :recommendations, :mitre, 'New', :now, :now, :run_id)""",
                        {**payload, "now": now, "run_id": run_id},
                    )
                    conn.execute(
                        """INSERT INTO alert_status_history (alert_id, old_status, new_status, analyst, changed_at)
                           VALUES (?, NULL, 'New', 'detection-engine', ?)""",
                        (alert["alert_id"], now),
                    )
        return new_count

    def get_alerts_df(self) -> pd.DataFrame:
        df = self._query_df(
            "SELECT * FROM alerts ORDER BY risk_score DESC, last_seen DESC, alert_id"
        )
        if not df.empty:
            for column in JSON_ALERT_FIELDS:
                df[column] = df[column].apply(json.loads)
            for column in ("timestamp", "first_seen", "last_seen"):
                df[column] = pd.to_datetime(df[column], format="%Y-%m-%d %H:%M:%S")
        return df

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        alert = dict(row)
        for column in JSON_ALERT_FIELDS:
            alert[column] = json.loads(alert[column])
        return alert

    def update_alert_status(self, alert_id: str, new_status: str, analyst: str) -> bool:
        """Change an alert's status and record the change. Returns False if unchanged."""
        if new_status not in ALERT_STATUSES:
            raise ValueError(f"Invalid status {new_status!r}. Allowed: {', '.join(ALERT_STATUSES)}")
        analyst = (analyst or "").strip() or "analyst"
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if row is None:
                raise KeyError(f"Alert {alert_id} not found")
            if row["status"] == new_status:
                return False
            now = utc_now_str()
            conn.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE alert_id = ?",
                (new_status, now, alert_id),
            )
            conn.execute(
                """INSERT INTO alert_status_history (alert_id, old_status, new_status, analyst, changed_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (alert_id, row["status"], new_status, analyst[:100], now),
            )
        return True

    def add_note(self, alert_id: str, note: str, analyst: str) -> int:
        note = (note or "").strip()
        if not note:
            raise ValueError("Note text cannot be empty")
        analyst = (analyst or "").strip() or "analyst"
        with self.connect() as conn:
            if conn.execute("SELECT 1 FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone() is None:
                raise KeyError(f"Alert {alert_id} not found")
            cur = conn.execute(
                "INSERT INTO alert_notes (alert_id, analyst, note, created_at) VALUES (?, ?, ?, ?)",
                (alert_id, analyst[:100], note[:5000], utc_now_str()),
            )
            return int(cur.lastrowid)

    def get_notes(self, alert_id: str) -> pd.DataFrame:
        return self._query_df(
            "SELECT created_at, analyst, note FROM alert_notes WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        )

    def get_all_notes(self) -> pd.DataFrame:
        return self._query_df("SELECT alert_id, created_at, analyst, note FROM alert_notes ORDER BY id")

    def get_status_history(self, alert_id: str) -> pd.DataFrame:
        return self._query_df(
            """SELECT changed_at, old_status, new_status, analyst FROM alert_status_history
               WHERE alert_id = ? ORDER BY id""",
            (alert_id,),
        )

    # ------------------------------------------------------------ analysis runs
    def start_run(self, settings: DetectionSettings) -> int:
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO analysis_runs (started_at, settings) VALUES (?, ?)",
                (utc_now_str(), json.dumps(settings.to_dict())),
            )
            return int(cur.lastrowid)

    def finish_run(self, run_id: int, events_analyzed: int, alerts_generated: int, new_alerts: int) -> None:
        with self.connect() as conn:
            conn.execute(
                """UPDATE analysis_runs SET finished_at = ?, events_analyzed = ?,
                   alerts_generated = ?, new_alerts = ? WHERE id = ?""",
                (utc_now_str(), events_analyzed, alerts_generated, new_alerts, run_id),
            )

    def list_runs(self) -> pd.DataFrame:
        return self._query_df(
            """SELECT id, started_at, finished_at, events_analyzed, alerts_generated, new_alerts
               FROM analysis_runs ORDER BY id DESC"""
        )

    # --------------------------------------------------------------- settings
    def load_settings(self) -> DetectionSettings:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = 'detection'").fetchone()
        return DetectionSettings.from_dict(json.loads(row["value"]) if row else None)

    def save_settings(self, settings: DetectionSettings) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('detection', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (json.dumps(settings.to_dict()),),
            )

    # ------------------------------------------------------------ maintenance
    def reset_all(self) -> None:
        """Delete all data stored by this application (its own SQLite tables only)."""
        with self.connect() as conn:
            for table in ("alert_notes", "alert_status_history", "alerts", "rejected_records",
                          "events", "uploaded_files", "analysis_runs"):
                conn.execute(f"DELETE FROM {table}")

    # ---------------------------------------------------------------- helpers
    def _query_df(self, sql: str, params: tuple[Any, ...] = ()) -> pd.DataFrame:
        with self.connect() as conn:
            return pd.read_sql_query(sql, conn, params=params)

    def _scalar(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self.connect() as conn:
            return int(conn.execute(sql, params).fetchone()[0])
