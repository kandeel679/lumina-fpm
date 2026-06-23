"""AI SOC report API (Volume 10).

Generates evidence-grounded SOC reports via the LLM provider abstraction and
exposes the stored reports. The LLM explains deterministic findings; it never
detects. Read-only against firewalls.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from services.llm.reporter import generate_report

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


class GenerateRequest(BaseModel):
    scope_type: str                    # rule | executive
    scope_id: Optional[int] = None     # rule_id for scope_type=rule


@router.post("/generate")
def generate(req: GenerateRequest, db: Session = Depends(get_db_session)):
    """Generate an evidence-grounded SOC report for a rule or an executive summary."""
    result = generate_report(db, req.scope_type, req.scope_id)
    # only input errors (no report produced) are 400; an LLM failure still returns the
    # stored report with status='failed' so deterministic data stays available (V10 §11).
    if "report_id" not in result:
        raise HTTPException(status_code=400, detail=result.get("error", "bad request"))
    return result


@router.get("")
def list_reports(db: Session = Depends(get_db_session), limit: int = 20):
    rows = (db.query(models.LlmReport)
            .order_by(models.LlmReport.report_id.desc()).limit(limit).all())
    return {"reports": [
        {"report_id": r.report_id, "scope_type": r.scope_type, "scope_id": r.scope_id,
         "provider": r.provider, "model": r.model, "status": r.status,
         "prompt_version": r.prompt_version, "evidence_refs": r.evidence_refs,
         "confidence_note": r.confidence_note, "created_at": r.created_at}
        for r in rows]}


@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db_session)):
    r = db.query(models.LlmReport).filter(models.LlmReport.report_id == report_id).first()
    if r is None:
        raise HTTPException(status_code=404, detail="report not found")
    return {
        "report_id": r.report_id, "scope_type": r.scope_type, "scope_id": r.scope_id,
        "provider": r.provider, "model": r.model, "prompt_version": r.prompt_version,
        "evidence_refs": r.evidence_refs, "confidence_note": r.confidence_note,
        "status": r.status, "output": r.output, "created_at": r.created_at,
    }
