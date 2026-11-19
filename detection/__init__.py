"""Detection engine: rules, severity classification, risk scoring, MITRE mapping."""

from detection.engine import make_alert_id, run_detection
from detection.rule_catalog import RULES
from detection.severity import classify_severity

__all__ = ["RULES", "classify_severity", "make_alert_id", "run_detection"]
