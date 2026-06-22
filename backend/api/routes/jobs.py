"""Acquisition job status endpoints (V3 §16, Table 27).

Read-only views over the acquisition_job lifecycle the frontend polls. Never
exposes secrets; raw-artifact listing returns metadata (type/path/sha256) only.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from api.deps import get_db_session
from models import models

router = APIRouter(prefix="/api/v1/jobs", tags=["Acquisition Jobs"])


def _job_dict(job: models.AcquisitionJob) -> dict:
    return {
        "job_id": job.job_id,
        "device_id": job.device_id,
        "vendor_type": job.vendor_type,
        "requested_by": job.requested_by,
        "status": job.status,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
        "duration_ms": job.duration_ms,
        "connector_version": job.connector_version,
        "error_code": job.error_code,
        "error_message": job.error_message,
        "created_at": job.created_at,
    }


@router.get("")
@router.get("/")
def list_jobs(
    device_id: Optional[int] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db_session),
):
    q = db.query(models.AcquisitionJob)
    if device_id is not None:
        q = q.filter(models.AcquisitionJob.device_id == device_id)
    jobs = q.order_by(models.AcquisitionJob.job_id.desc()).limit(limit).all()
    return {"items": [_job_dict(j) for j in jobs], "count": len(jobs)}


@router.get("/{job_id}")
def get_job(job_id: int, db: Session = Depends(get_db_session)):
    job = db.query(models.AcquisitionJob).filter(models.AcquisitionJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _job_dict(job)


@router.get("/{job_id}/artifacts")
def list_job_artifacts(job_id: int, db: Session = Depends(get_db_session)):
    job = db.query(models.AcquisitionJob).filter(models.AcquisitionJob.job_id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    arts = db.query(models.RawArtifact).filter(models.RawArtifact.job_id == job_id).all()
    return {
        "job_id": job_id,
        "artifacts": [
            {"artifact_id": a.artifact_id, "type": a.type, "path": a.path, "sha256": a.sha256}
            for a in arts
        ],
    }
