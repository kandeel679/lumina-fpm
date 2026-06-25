"""CTI API (Volume 9 §13).

Runs API-based threat-intel enrichment and exposes the Threat Center view:
indicators, providers, confidence, and the rules they affect. Provider evidence
is kept separate from any AI explanation (V9 §13). Read-only against firewalls.
"""
from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from services.cti.runner import run_cti
from services.cti.vuln_runner import run_vuln

router = APIRouter(prefix="/api/v1/cti", tags=["CTI"])


class RunRequest(BaseModel):
    analysis_run_id: Optional[int] = None  # omit = enrich against the latest analysis run


@router.post("/run")
def run(req: RunRequest, db: Session = Depends(get_db_session)):
    """Two-axis threat enrichment for an analysis run, then recalc risk:

    - CTI (rule axis): malicious-indicator exposure -> threat_exposure findings.
    - VULN (device axis): firmware CVEs -> device-scoped firmware_version evidence.

    Both persist to the CTI tables and trigger a risk recalculation (idempotent).
    """
    cti_res = run_cti(db, req.analysis_run_id)
    vuln_res = run_vuln(db, req.analysis_run_id)
    return {"cti": cti_res, "vuln": vuln_res}


@router.get("")
def list_cti(db: Session = Depends(get_db_session)):
    """Threat Center: enriched indicators with their provider observations."""
    indicators = db.query(models.CtiIndicator).all()
    out = []
    for ind in indicators:
        obs = [
            {
                "provider": o.provider, "severity": o.severity, "confidence": o.confidence,
                "threat_type": o.threat_type, "summary": o.summary,
                "reference": o.provider_reference, "observed_at": o.observed_at,
            }
            for o in ind.observations
        ]
        malicious = any((o["confidence"] or 0) >= 0.25 for o in obs)
        out.append({
            "indicator_id": ind.indicator_id, "type": ind.type, "value": ind.value,
            "is_public": ind.is_public, "source_device_id": ind.source_device_id,
            "malicious": malicious, "observations": obs,
        })
    return {"indicators": out, "count": len(out)}
