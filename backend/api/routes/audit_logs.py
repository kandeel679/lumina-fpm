from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import AuditLogCreate, AuditLogResponse

router = APIRouter(prefix="/api/v1/audit-logs", tags=["Audit Logs"])

@router.get("/", response_model=List[AuditLogResponse])
def list_audit_logs(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.AuditLog, skip=skip, limit=limit)

@router.get("/{log_id}", response_model=AuditLogResponse)
def get_audit_log(log_id: int, db: Session = Depends(get_db_session)):
    log = crud.get_by_id(db, models.AuditLog, "log_id", log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log

@router.post("/", response_model=AuditLogResponse, status_code=201)
def create_audit_log(log: AuditLogCreate, db: Session = Depends(get_db_session)):
    return crud.create_audit_log(db, log.model_dump())

@router.delete("/{log_id}", status_code=204)
def delete_audit_log(log_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_audit_log(db, log_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Log not found")
    return None
