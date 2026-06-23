"""Risk API (Volume 8 §13).

Recomputes and exposes deterministic 0-100 risk scores with factor breakdowns —
top risky rules first, plus device-level risk. Pure DB analysis; never touches a
firewall.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from services.risk.runner import run_risk

router = APIRouter(prefix="/api/v1/risk", tags=["Risk"])


class RunRequest(BaseModel):
    analysis_run_id: Optional[int] = None  # omit = score the latest analysis run


@router.post("/run")
def run(req: RunRequest, db: Session = Depends(get_db_session)):
    """Recalculate risk for an analysis run; persists risk_assessment (rule + device)."""
    return run_risk(db, req.analysis_run_id)


@router.get("")
def list_risk(
    scope_type: str = Query("rule", pattern="^(rule|device)$"),
    limit: int = Query(20, ge=1, le=200),
    db: Session = Depends(get_db_session),
):
    """Latest risk assessments for the most recently scored run, highest risk first."""
    latest_run = db.query(func.max(models.RiskAssessment.analysis_run_id)).scalar()
    if latest_run is None:
        return {"analysis_run_id": None, "items": []}
    q = (
        db.query(models.RiskAssessment)
        .filter(models.RiskAssessment.analysis_run_id == latest_run,
                models.RiskAssessment.scope_type == scope_type)
        .order_by(models.RiskAssessment.risk_score.desc())
        .limit(limit)
    )
    rows = q.all()
    # resolve rule names for rule-scope rows
    names = {}
    if scope_type == "rule":
        ids = [r.scope_id for r in rows]
        for pr in db.query(models.PolicyRule).filter(models.PolicyRule.rule_id.in_(ids)).all():
            names[pr.rule_id] = (pr.rule_name, pr.vendor_type, pr.device_id)
    items = []
    for r in rows:
        item = {
            "scope_type": r.scope_type, "scope_id": r.scope_id,
            "risk_score": r.risk_score, "risk_tier": r.risk_tier,
            "factor_breakdown": r.factor_breakdown,
            "calculation_version": r.calculation_version,
        }
        if r.scope_type == "rule" and r.scope_id in names:
            nm, vt, dev = names[r.scope_id]
            item.update({"rule_name": nm, "vendor_type": vt, "device_id": dev})
        items.append(item)
    return {"analysis_run_id": latest_run, "scope_type": scope_type, "items": items}
