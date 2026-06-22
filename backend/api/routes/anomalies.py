"""Anomaly API (Volume 6).

Triggers deterministic anomaly analysis and exposes the findings the engine wrote.
Analysis itself runs in the Celery ``analysis`` worker (never in the request
cycle). An all-scope run (device_id omitted) is required for the cross-device
detectors. Read-only with respect to firewalls; the suppression workflow only
updates finding status in LuminaFPM's own DB (V6 §12).
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from api.deps import get_db_session
from models import models
from models.models import utcnow

router = APIRouter(prefix="/api/v1/anomalies", tags=["Anomalies"])


class AnalyzeRequest(BaseModel):
    device_id: Optional[int] = None  # omit / null = all devices (enables cross-device detection)


class SuppressRequest(BaseModel):
    status: str                       # open|resolved|suppressed|accepted_risk|false_positive
    reason: Optional[str] = None
    admin_id: Optional[int] = None


_VALID_STATUS = {"open", "resolved", "suppressed", "accepted_risk", "false_positive"}


def _finding_dict(a: models.RuleAnomaly, rule: Optional[models.PolicyRule] = None) -> dict:
    out = {
        "anomaly_id": a.anomaly_id,
        "rule_id": a.rule_id,
        "related_rule_id": a.related_rule_id,
        "anomaly_type": a.anomaly_type,
        "severity_level": a.severity_level,
        "confidence": a.confidence,
        "description": a.description,
        "evidence": a.evidence,
        "recommendation": a.recommendation,
        "detection_mode": a.detection_mode,
        "analysis_run_id": a.analysis_run_id,
        "status": a.status,
        "detected_at": a.detected_at,
    }
    if rule is not None:
        out["device_id"] = rule.device_id
        out["rule_name"] = rule.rule_name
        out["vendor_type"] = rule.vendor_type
    return out


@router.post("/run", status_code=202)
def run_analysis(body: AnalyzeRequest | None = None, db: Session = Depends(get_db_session)):
    """Trigger a deterministic anomaly run. Omit device_id for an all-scope (cross-device) run."""
    device_id = body.device_id if body else None
    if device_id is not None:
        if not db.query(models.FirewallDevice.device_id).filter(
            models.FirewallDevice.device_id == device_id
        ).first():
            raise HTTPException(status_code=404, detail="Device not found")
    from tasks.anomaly import run_anomaly_analysis_task
    task = run_anomaly_analysis_task.delay(device_id=device_id)
    return {
        "status": "accepted",
        "task_id": task.id,
        "scope": "device" if device_id is not None else "all",
        "device_id": device_id,
    }


@router.get("")
@router.get("/")
def list_anomalies(
    severity: Optional[str] = None,
    anomaly_type: Optional[str] = None,
    status: Optional[str] = None,
    device_id: Optional[int] = None,
    analysis_run_id: Optional[int] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db_session),
):
    """List findings with filters (joins policy_rule for device context)."""
    q = db.query(models.RuleAnomaly, models.PolicyRule).join(
        models.PolicyRule, models.RuleAnomaly.rule_id == models.PolicyRule.rule_id
    )
    if severity:
        q = q.filter(models.RuleAnomaly.severity_level == severity)
    if anomaly_type:
        q = q.filter(models.RuleAnomaly.anomaly_type == anomaly_type)
    if status:
        q = q.filter(models.RuleAnomaly.status == status)
    if device_id is not None:
        q = q.filter(models.PolicyRule.device_id == device_id)
    if analysis_run_id is not None:
        q = q.filter(models.RuleAnomaly.analysis_run_id == analysis_run_id)

    total = q.count()
    rows = (
        q.order_by(models.RuleAnomaly.detected_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    items = [_finding_dict(a, rule) for a, rule in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/runs")
def list_runs(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db_session)):
    """List anomaly execution runs (observability)."""
    runs = (
        db.query(models.AnomalyExecutionLog)
        .order_by(models.AnomalyExecutionLog.run_id.desc())
        .limit(limit)
        .all()
    )
    return {"items": [{
        "run_id": r.run_id, "scope_type": r.scope_type, "scope_id": r.scope_id,
        "status": r.status, "findings_count": r.findings_count,
        "started_at": r.started_at, "completed_at": r.completed_at,
        "engine_version": r.engine_version,
    } for r in runs]}


@router.get("/{anomaly_id}")
def get_anomaly(anomaly_id: int, db: Session = Depends(get_db_session)):
    a = db.query(models.RuleAnomaly).filter(models.RuleAnomaly.anomaly_id == anomaly_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    rule = db.query(models.PolicyRule).filter(models.PolicyRule.rule_id == a.rule_id).first()
    return _finding_dict(a, rule)


@router.patch("/{anomaly_id}")
def update_anomaly_status(anomaly_id: int, body: SuppressRequest, db: Session = Depends(get_db_session)):
    """Analyst lifecycle: resolve / suppress / accept-risk / false-positive (V6 §12).

    Suppression keeps the finding in history (never deletes) and requires a reason.
    """
    if body.status not in _VALID_STATUS:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(_VALID_STATUS)}")
    a = db.query(models.RuleAnomaly).filter(models.RuleAnomaly.anomaly_id == anomaly_id).first()
    if not a:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    if body.status in ("suppressed", "accepted_risk", "false_positive") and not body.reason:
        raise HTTPException(status_code=422, detail="A reason is required to suppress/accept/dismiss a finding")
    a.status = body.status
    if body.reason is not None:
        a.suppression_reason = body.reason
    if body.admin_id is not None:
        a.suppressed_by = body.admin_id
    if body.status != "open":
        a.suppression_expires_at = a.suppression_expires_at  # left to caller policy
    db.commit()
    return _finding_dict(a)
