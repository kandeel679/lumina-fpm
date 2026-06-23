"""Benchmark runner (Volume 7 §10) — DB-backed.

Builds expected cases from the ground-truth matrix resolved to the *deployed*
rules, loads the engine's findings for an analysis run, scores them, and
persists `benchmark_case` + `benchmark_result`. Returns the scorecard.

Read-only against firewalls (operates entirely on the normalized DB).
"""
from __future__ import annotations

from collections import Counter
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.logging import get_logger
from models import models

from . import ground_truth as GT
from .scorer import ExpectedCase, score

logger = get_logger(__name__)


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()


def _deployed_rules(db: Session) -> Dict[str, models.PolicyRule]:
    rows = db.query(models.PolicyRule).filter(models.PolicyRule.is_active.is_(True)).all()
    return {r.rule_name: r for r in rows}


def _actual_findings(db: Session, run_id: int) -> Dict[str, Dict[str, dict]]:
    rows = (
        db.query(
            models.RuleAnomaly.anomaly_id,
            models.RuleAnomaly.anomaly_type,
            models.RuleAnomaly.severity_level,
            models.PolicyRule.rule_name,
        )
        .join(models.PolicyRule, models.RuleAnomaly.rule_id == models.PolicyRule.rule_id)
        .filter(models.RuleAnomaly.analysis_run_id == run_id)
        .all()
    )
    actual: Dict[str, Dict[str, dict]] = {}
    for anomaly_id, atype, severity, rule_name in rows:
        bucket = actual.setdefault(rule_name, {})
        # presence-based: keep the first finding per (rule, type)
        bucket.setdefault(atype, {"severity": severity, "anomaly_id": anomaly_id})
    return actual


def _build_expected(deployed: Dict[str, models.PolicyRule]) -> List[ExpectedCase]:
    cases: List[ExpectedCase] = []
    for vendor, rules in GT.INTRA.items():
        for rule_name, anomalies in rules.items():
            if rule_name not in deployed:
                continue
            ctype = "compound" if len(anomalies) > 1 else "atomic"
            for atype in anomalies:
                cases.append(ExpectedCase(
                    anomaly_type=atype, rules=[rule_name],
                    expected_severity=GT.EXPECTED_SEVERITY.get(atype),
                    case_type=ctype, kind="intra",
                ))
    for pair in GT.CROSS_DEVICE:
        if pair["a"] in deployed and pair["b"] in deployed:
            cases.append(ExpectedCase(
                anomaly_type=pair["anomaly_type"], rules=[pair["a"], pair["b"]],
                expected_severity=GT.EXPECTED_SEVERITY.get(pair["anomaly_type"]),
                case_type="compound", kind="cross_device", reason=pair.get("reason", ""),
            ))
    return cases


def _persist(db: Session, run_id: int, result_score, deployed) -> None:
    """Materialize benchmark_case + benchmark_result for this run (fresh)."""
    db.query(models.BenchmarkResult).delete()
    db.query(models.BenchmarkCase).delete()
    db.flush()
    for cr in result_score.results:
        c = cr.case
        rule_a = deployed.get(c.rules[0])
        rule_b = deployed.get(c.rules[1]) if len(c.rules) > 1 else None
        case = models.BenchmarkCase(
            case_type=c.case_type, anomaly_type=c.anomaly_type,
            device_a_id=rule_a.device_id if rule_a else None,
            rule_a_id=rule_a.rule_id if rule_a else None,
            device_b_id=rule_b.device_id if rule_b else None,
            rule_b_id=rule_b.rule_id if rule_b else None,
            expected_severity=c.expected_severity, expected_reason=c.reason or None,
            detection_mode="config_only",
        )
        db.add(case)
        db.flush()
        db.add(models.BenchmarkResult(
            case_id=case.case_id, analysis_run_id=run_id,
            detected=cr.detected, detected_anomaly_id=cr.detected_anomaly_id,
            match_quality=cr.match_quality,
            false_positive=False, false_negative=not cr.detected,
            notes=None if cr.detected else "expected anomaly not detected",
        ))
    db.commit()


def run_benchmark(db: Session, run_id: Optional[int] = None) -> dict:
    if run_id is None:
        run_id = _latest_run_id(db)
    if run_id is None:
        return {"error": "no analysis run found"}

    deployed = _deployed_rules(db)
    expected = _build_expected(deployed)
    actual = _actual_findings(db, run_id)
    s = score(expected, actual)
    _persist(db, run_id, s, deployed)

    by_type = Counter()
    detected_by_type = Counter()
    for cr in s.results:
        by_type[cr.case.anomaly_type] += 1
        if cr.detected:
            detected_by_type[cr.case.anomaly_type] += 1

    logger.info(
        "Benchmark run %s: TP=%d FP=%d FN=%d precision=%.3f recall=%.3f f1=%.3f",
        run_id, s.tp, s.fp, s.fn, s.precision, s.recall, s.f1,
    )
    return {
        "analysis_run_id": run_id,
        "metrics": {
            "tp": s.tp, "fp": s.fp, "fn": s.fn,
            "precision": s.precision, "recall": s.recall, "f1": s.f1,
            "severity_match_rate": s.severity_match_rate,
            "expected_cases": len(expected),
        },
        "by_type": {
            t: {"expected": by_type[t], "detected": detected_by_type[t]}
            for t in sorted(by_type)
        },
        "missed": [
            {"anomaly_type": cr.case.anomaly_type, "rules": cr.case.rules}
            for cr in s.results if not cr.detected
        ],
        "false_positives": [
            {"rule_name": r, "anomaly_type": t} for r, t in s.false_positives
        ],
    }
