"""Risk runner (Volume 8 §7-8, §12) — DB-backed.

Scores every deployed rule from its findings for an analysis run, aggregates a
device-level score, and persists risk_assessment rows (rule + device scopes).
Idempotent per run (replaces that run's rows) but keeps history across runs.
Read-only against firewalls.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.logging import get_logger
from models import models

from .scorer import RISK_VERSION, score_device, score_rule

logger = get_logger(__name__)


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()


def _findings_by_rule(db: Session, run_id: int) -> Dict[int, List[dict]]:
    rows = (
        db.query(models.RuleAnomaly.rule_id,
                 models.RuleAnomaly.anomaly_type,
                 models.RuleAnomaly.severity_level)
        .filter(models.RuleAnomaly.analysis_run_id == run_id,
                models.RuleAnomaly.rule_id.isnot(None))
        .all()
    )
    out: Dict[int, List[dict]] = defaultdict(list)
    for rule_id, atype, severity in rows:
        out[rule_id].append({"anomaly_type": atype, "severity": severity})
    return out


def run_risk(db: Session, run_id: Optional[int] = None) -> dict:
    if run_id is None:
        run_id = _latest_run_id(db)
    if run_id is None:
        return {"error": "no analysis run found"}

    findings = _findings_by_rule(db, run_id)
    rules = db.query(models.PolicyRule).filter(models.PolicyRule.is_active.is_(True)).all()

    # idempotent per run: clear this run's prior assessments, keep other runs (history).
    db.query(models.RiskAssessment).filter(
        models.RiskAssessment.analysis_run_id == run_id
    ).delete()
    db.flush()

    tier_counts: Counter = Counter()
    by_device: Dict[int, List[int]] = defaultdict(list)
    top_rules: List[dict] = []

    for rule in rules:
        res = score_rule(findings.get(rule.rule_id, []))
        db.add(models.RiskAssessment(
            scope_type="rule", scope_id=rule.rule_id,
            risk_score=res["risk_score"], risk_tier=res["risk_tier"],
            factor_breakdown=res["factor_breakdown"],
            calculation_version=RISK_VERSION, analysis_run_id=run_id,
        ))
        tier_counts[res["risk_tier"]] += 1
        by_device[rule.device_id].append(res["risk_score"])
        top_rules.append({
            "rule_id": rule.rule_id, "rule_name": rule.rule_name,
            "device_id": rule.device_id, "vendor_type": rule.vendor_type,
            "risk_score": res["risk_score"], "risk_tier": res["risk_tier"],
            "factor_breakdown": res["factor_breakdown"],
        })

    device_scores = []
    for device_id, scores in by_device.items():
        res = score_device(scores)
        db.add(models.RiskAssessment(
            scope_type="device", scope_id=device_id,
            risk_score=res["risk_score"], risk_tier=res["risk_tier"],
            factor_breakdown=res["factor_breakdown"],
            calculation_version=RISK_VERSION, analysis_run_id=run_id,
        ))
        device_scores.append({"device_id": device_id, "risk_score": res["risk_score"],
                              "risk_tier": res["risk_tier"]})

    db.commit()
    top_rules.sort(key=lambda r: r["risk_score"], reverse=True)
    logger.info("Risk run %s: %d rules scored, tiers=%s", run_id, len(rules), dict(tier_counts))
    return {
        "analysis_run_id": run_id,
        "calculation_version": RISK_VERSION,
        "rules_scored": len(rules),
        "tier_counts": dict(tier_counts),
        "devices": sorted(device_scores, key=lambda d: d["risk_score"], reverse=True),
        "top_rules": top_rules[:10],
    }
