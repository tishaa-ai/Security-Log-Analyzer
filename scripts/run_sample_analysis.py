"""Ingest the synthetic samples, run detection and write CSV/JSON/PDF reports.

Uses a separate database (``output/sample_analysis.db``) so it never touches
the dashboard's own data. Run from the project root:

    .venv\\Scripts\\python.exe scripts\\run_sample_analysis.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from config import OUTPUT_DIR  # noqa: E402
from database import Database  # noqa: E402
from pipeline import load_sample_data, run_analysis  # noqa: E402
from reports.exporters import report_from_db, report_to_csv, report_to_json, report_to_pdf  # noqa: E402


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    db_path = OUTPUT_DIR / "sample_analysis.db"
    db_path.unlink(missing_ok=True)
    db = Database(db_path)

    print("== Ingestion ==")
    for summary in load_sample_data(db):
        print(f"  {summary.file_name:<28} format={summary.source_format:<7} total={summary.total_records:<4} "
              f"parsed={summary.parsed_records:<4} rejected={summary.rejected_records}")

    result = run_analysis(db)
    print("\n== Detection ==")
    print(f"  events analysed: {result.events_analyzed}")
    print(f"  alerts generated: {result.alerts_generated}  by severity: {result.severity_counts}")

    report = report_from_db(db, scope="Synthetic sample datasets")
    (OUTPUT_DIR / "sample_alerts_report.csv").write_text(report_to_csv(report), encoding="utf-8")
    (OUTPUT_DIR / "sample_alerts_report.json").write_text(report_to_json(report), encoding="utf-8")
    (OUTPUT_DIR / "sample_incident_report.pdf").write_bytes(report_to_pdf(report))
    print("\n== Reports written ==")
    for name in ("sample_alerts_report.csv", "sample_alerts_report.json", "sample_incident_report.pdf"):
        path = OUTPUT_DIR / name
        print(f"  {path}  ({path.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
