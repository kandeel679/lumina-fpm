"""Scheduling API (Settings → Scheduling).

Exposes the three global schedules — acquisition / detection / threat_intel — that
the Celery Beat tick consumes. Editing a schedule recomputes its next run; "run now"
dispatches the same read-only pipeline immediately. Read-only toward firewalls.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from models.models import utcnow
from services import scheduling

router = APIRouter(prefix="/api/v1/schedules", tags=["Schedules"])


class ScheduleUpdate(BaseModel):
    enabled: Optional[bool] = None
    mode: Optional[str] = None                  # interval | cron
    interval_minutes: Optional[int] = None
    cron_expression: Optional[str] = None


def _serialize(row: models.ScheduleConfig) -> dict:
    return {
        "operation": row.operation,
        "enabled": bool(row.enabled),
        "mode": row.mode,
        "interval_minutes": row.interval_minutes,
        "cron_expression": row.cron_expression,
        "summary": scheduling.describe(row),
        "last_run_at": row.last_run_at,
        "next_run_at": row.next_run_at if row.enabled else None,
        "updated_at": row.updated_at,
    }


def _get_or_create(db: Session, operation: str) -> models.ScheduleConfig:
    row = (
        db.query(models.ScheduleConfig)
        .filter(models.ScheduleConfig.operation == operation)
        .first()
    )
    if row is None:
        row = models.ScheduleConfig(
            operation=operation, enabled=False, mode="interval", interval_minutes=360,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


@router.get("")
@router.get("/")
def list_schedules(db: Session = Depends(get_db_session)):
    """Return all three schedules, creating any missing defaults on first read."""
    rows = [_get_or_create(db, op) for op in scheduling.OPERATIONS]
    return {"items": [_serialize(r) for r in rows]}


@router.patch("/{operation}")
def update_schedule(operation: str, body: ScheduleUpdate, db: Session = Depends(get_db_session)):
    if operation not in scheduling.OPERATIONS:
        raise HTTPException(status_code=404, detail=f"Unknown operation '{operation}'")
    row = _get_or_create(db, operation)

    if body.mode is not None:
        if body.mode not in scheduling.VALID_MODES:
            raise HTTPException(status_code=422, detail=f"mode must be one of {scheduling.VALID_MODES}")
        row.mode = body.mode
    if body.interval_minutes is not None:
        if body.interval_minutes < 1:
            raise HTTPException(status_code=422, detail="interval_minutes must be >= 1")
        row.interval_minutes = body.interval_minutes
    if body.cron_expression is not None:
        cron = body.cron_expression.strip()
        if cron:
            try:
                scheduling.parse_cron(cron)
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=f"Invalid cron: {exc}")
        row.cron_expression = cron or None
    if body.enabled is not None:
        row.enabled = body.enabled

    # Validate the chosen mode actually has its parameter before enabling.
    if row.enabled:
        if row.mode == "interval" and not row.interval_minutes:
            raise HTTPException(status_code=422, detail="interval mode requires interval_minutes")
        if row.mode == "cron" and not row.cron_expression:
            raise HTTPException(status_code=422, detail="cron mode requires cron_expression")

    # Recompute next run from now whenever config changes; clear it when disabled.
    now = utcnow()
    if row.enabled:
        row.next_run_at = scheduling.compute_next_run(
            row.mode, row.interval_minutes, row.cron_expression, now
        )
    else:
        row.next_run_at = None
    db.commit()
    db.refresh(row)
    return _serialize(row)


@router.post("/{operation}/run-now")
def run_now(operation: str, db: Session = Depends(get_db_session)):
    """Dispatch the operation immediately (the same read-only pipeline the tick uses)."""
    if operation not in scheduling.OPERATIONS:
        raise HTTPException(status_code=404, detail=f"Unknown operation '{operation}'")
    try:
        result = scheduling.dispatch_operation(db, operation, requested_by="manual")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Dispatch failed: {exc}")
    return {"status": "dispatched", **result}
