"""High-level workflows used by the dashboard, scripts and tests.

* :func:`ingest_file`   - parse an uploaded file and store it (with dedup)
* :func:`run_analysis`  - run the detection engine over all stored events
* :func:`load_sample_data` - ingest the bundled synthetic datasets
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from config import SAMPLE_DATA_YEAR, SAMPLES_DIR, DetectionSettings
from database import Database
from detection.engine import run_detection
from parsers.ingest import FORMAT_AUTO, parse_file
from parsers.models import ParseResult, RejectedRecord
from utils.security import sha256_hex


@dataclass
class IngestSummary:
    file_name: str
    duplicate_file: bool
    error: str | None
    total_records: int = 0
    parsed_records: int = 0
    rejected_records: int = 0
    inserted_events: int = 0
    duplicate_events: int = 0
    source_format: str = "unknown"
    rejected: list[RejectedRecord] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class AnalysisSummary:
    run_id: int
    events_analyzed: int
    alerts_generated: int
    new_alerts: int
    severity_counts: dict[str, int]


def assign_event_hashes(result: ParseResult) -> None:
    """Give every event a content-based hash used to avoid duplicate rows.

    The hash covers the raw record text plus its occurrence number inside the
    file, so two genuinely repeated identical lines in one file are both kept,
    while the same record arriving again in another (overlapping) file is not.
    """
    seen: Counter[str] = Counter()
    for event in result.events:
        seen[event.raw] += 1
        event.event_hash = sha256_hex(f"{event.source_format}|{event.raw}|{seen[event.raw]}")


def ingest_file(
    db: Database,
    file_name: str,
    content: bytes,
    format_hint: str = FORMAT_AUTO,
    default_year: int | None = None,
) -> IngestSummary:
    """Parse and store a file. Re-uploading identical content is a no-op."""
    file_hash = sha256_hex(content)
    existing = db.get_file_by_hash(file_hash)
    if existing:
        return IngestSummary(
            file_name=file_name,
            duplicate_file=True,
            error=None,
            total_records=existing["total_records"],
            parsed_records=existing["parsed_records"],
            rejected_records=existing["rejected_records"],
            source_format=existing["file_format"],
        )

    result = parse_file(file_name, content, format_hint=format_hint, default_year=default_year)
    if result.error and not result.events:
        return IngestSummary(
            file_name=file_name,
            duplicate_file=False,
            error=result.error,
            total_records=result.total_records,
            rejected_records=result.rejected_count,
            source_format=result.source_format,
            rejected=result.rejected,
        )

    assign_event_hashes(result)
    row = db.store_parsed_file(
        file_name=Path(file_name).name[:255],
        file_hash=file_hash,
        file_format=result.source_format,
        file_size=len(content),
        events=result.events,
        rejected=result.rejected,
    )
    return IngestSummary(
        file_name=file_name,
        duplicate_file=False,
        error=None,
        total_records=row["total_records"],
        parsed_records=row["parsed_records"],
        rejected_records=row["rejected_records"],
        inserted_events=row["inserted_events"],
        duplicate_events=row["duplicate_events"],
        source_format=result.source_format,
        rejected=result.rejected,
    )


def run_analysis(db: Database, settings: DetectionSettings | None = None) -> AnalysisSummary:
    """Run detection over every stored event and persist the alerts."""
    settings = settings or db.load_settings()
    run_id = db.start_run(settings)
    events = db.get_events_df()
    alerts = run_detection(events, settings)
    new_alerts = db.upsert_alerts(alerts, run_id)
    db.finish_run(run_id, len(events), len(alerts), new_alerts)
    counts = Counter(a["severity"] for a in alerts)
    return AnalysisSummary(
        run_id=run_id,
        events_analyzed=len(events),
        alerts_generated=len(alerts),
        new_alerts=new_alerts,
        severity_counts={sev: counts.get(sev, 0) for sev in ("Critical", "High", "Medium", "Low")},
    )


def sample_files() -> list[Path]:
    return sorted(p for p in SAMPLES_DIR.iterdir() if p.is_file() and p.suffix in {".json", ".jsonl", ".log"})


def load_sample_data(db: Database) -> list[IngestSummary]:
    """Ingest every bundled synthetic dataset (safe to call repeatedly)."""
    return [
        ingest_file(db, path.name, path.read_bytes(), default_year=SAMPLE_DATA_YEAR)
        for path in sample_files()
    ]
