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

from .scorer import RISK_VERSION, _VULN_POINTS, score_device, score_rule

logger = get_logger(__name__)


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()


def _device_firmware_factors(db: Session) -> Dict[int, Dict[str, int]]:
    """device_id -> {'firmware_modifier': pts} from firmware-CVE CTI evidence.

    Derived from cti_indicator(type='firmware_version') + cti_observation
    (threat_type='vulnerability'); the worst observed severity sets the modifier.
    Best-effort: any failure degrades to {} so the proven device-risk path never
    breaks when no firmware CVEs are present.
    """
    out: Dict[int, Dict[str, int]] = {}
    try:
        rows = (
            db.query(models.CtiIndicator.source_device_id,
                     models.CtiObservation.severity)
            .join(models.CtiObservation,
                  models.CtiObservation.indicator_id == models.CtiIndicator.indicator_id)
            .filter(models.CtiIndicator.type == "firmware_version",
                    models.CtiObservation.threat_type == "vulnerability",
                    models.CtiIndicator.source_device_id.isnot(None))
            .all()
        )
    except Exception as exc:  # noqa: BLE001 — never break the proven risk path
        logger.warning("device firmware-CVE risk lookup failed: %s", exc)
        return out
    worst: Dict[int, int] = {}
    for dev_id, severity in rows:
        pts = _VULN_POINTS.get((severity or "").lower(), 0)
        if pts > worst.get(dev_id, 0):
            worst[dev_id] = pts
    return {dev_id: {"firmware_modifier": pts} for dev_id, pts in worst.items() if pts}


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

    # Device firmware-CVE modifiers (Vol8 §8): a device with vulnerable firmware but
    # only clean rules still earns a device score, so iterate the UNION of rule-scored
    # devices and firmware-vulnerable devices.
    device_vuln = _device_firmware_factors(db)
    device_scores = []
    for device_id in set(by_device) | set(device_vuln):
        scores = by_device.get(device_id, [])
        res = score_device(scores, device_factors=device_vuln.get(device_id))
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
