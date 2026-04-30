from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from fastapi.responses import JSONResponse
from fastapi import BackgroundTasks

from services.lumina_threat_intel.orchestrator import run_scan
from services.lumina_threat_intel.db_models import ThreatIntelReport
from api.deps import get_db_session, SessionLocal
from models import models, crud
from schemas.pydantic_schemas import (
    ThreatIntelligenceCreate, ThreatIntelligenceUpdate, ThreatIntelligenceResponse,
    ThreatCorrelationCreate, ThreatCorrelationResponse,
)

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])


# =====================================================================
# THREAT INTELLIGENCE ENDPOINTS
# =====================================================================

@router.post("/scan", status_code=202)
def trigger_threat_intel_scan(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db_session)
):
    # 1. First, create the initial report synchronously so we can return its ID
    report = ThreatIntelReport(
        trigger_type="manual",
        status="running"
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    report_id = report.id

    # 2. Define a wrapper function that creates its OWN database session
    def run_scan_in_background(r_id: int):
        # Create a new session specifically for the background thread
        bg_session = SessionLocal() 
        try:
            # Re-fetch the report in this new session
            bg_report = bg_session.query(ThreatIntelReport).get(r_id)
            if bg_report:
                # Execute the long-running Tor scrape and LLM analysis
                run_scan(bg_session, trigger_type="manual", report=bg_report)
        finally:
            # Always close the background session to prevent connection leaks
            bg_session.close()

    # 3. Queue the task to run without blocking the event loop
    background_tasks.add_task(run_scan_in_background, report_id)

    # 4. Return immediately to the client
    return JSONResponse(
        status_code=202,
        content={
            "message": "Scan started in background", 
            "report_id": report_id,
            "status": "running"
        }
    )


@router.get("/", response_model=List[ThreatIntelligenceResponse])
def list_threat_intel(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.ThreatIntelligence, skip=skip, limit=limit)


@router.get("/{threat_id}", response_model=ThreatIntelligenceResponse)
def get_threat_intel(threat_id: int, db: Session = Depends(get_db_session)):
    threat = crud.get_by_id(db, models.ThreatIntelligence, "threat_id", threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat intelligence entry not found")
    return threat


@router.post("/", response_model=ThreatIntelligenceResponse, status_code=201)
def create_threat_intel(threat: ThreatIntelligenceCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.ThreatIntelligence, threat.model_dump())


@router.patch("/{threat_id}", response_model=ThreatIntelligenceResponse)
def update_threat_intel(threat_id: int, threat: ThreatIntelligenceUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.ThreatIntelligence, "threat_id", threat_id, threat.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Threat intelligence entry not found")
    return updated


@router.delete("/{threat_id}", status_code=204)
def delete_threat_intel(threat_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.ThreatIntelligence, "threat_id", threat_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Threat intelligence entry not found")
    return None


# =====================================================================
# THREAT-RULE CORRELATIONS (Nested under /threat-intel/{threat_id}/correlations)
# =====================================================================

@router.get("/{threat_id}/correlations", response_model=List[ThreatCorrelationResponse], tags=["Threat Correlations"])
def list_threat_correlations(threat_id: int, db: Session = Depends(get_db_session)):
    threat = crud.get_by_id(db, models.ThreatIntelligence, "threat_id", threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat intelligence entry not found")
    return db.query(models.ThreatCorrelation).filter(
        models.ThreatCorrelation.threat_id == threat_id
    ).all()


@router.post("/{threat_id}/correlations", response_model=ThreatCorrelationResponse, status_code=201, tags=["Threat Correlations"])
def create_threat_correlation(threat_id: int, correlation: ThreatCorrelationCreate, db: Session = Depends(get_db_session)):
    threat = crud.get_by_id(db, models.ThreatIntelligence, "threat_id", threat_id)
    if not threat:
        raise HTTPException(status_code=404, detail="Threat intelligence entry not found")
    data = correlation.model_dump()
    data["threat_id"] = threat_id
    return crud.insert_data(db, models.ThreatCorrelation, data)


@router.delete("/{threat_id}/correlations/{rule_id}", status_code=204, tags=["Threat Correlations"])
def delete_threat_correlation(threat_id: int, rule_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data_composite(db, models.ThreatCorrelation, {
        "rule_id": rule_id, "threat_id": threat_id
    })
    if not deleted:
        raise HTTPException(status_code=404, detail="Correlation not found")
    return None
