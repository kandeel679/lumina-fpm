"""Notifications API (topbar bell + Settings → Notifications).

Read + mark-read for the in-app notifications written by the background pipeline.
Informational only; no firewall side effects.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db_session
from models import models
from models.models import utcnow

router = APIRouter(prefix="/api/v1/notifications", tags=["Notifications"])


def _serialize(n: models.Notification) -> dict:
    return {
        "id": n.id,
        "level": n.level,
        "category": n.category,
        "title": n.title,
        "body": n.body,
        "link": n.link,
        "created_at": n.created_at,
        "read": n.read_at is not None,
        "read_at": n.read_at,
    }


@router.get("")
@router.get("/")
def list_notifications(
    unread_only: bool = False,
    limit: int = Query(30, ge=1, le=200),
    db: Session = Depends(get_db_session),
):
    """Latest notifications (newest first) plus the current unread count."""
    q = db.query(models.Notification)
    if unread_only:
        q = q.filter(models.Notification.read_at.is_(None))
    rows = q.order_by(models.Notification.created_at.desc()).limit(limit).all()
    unread_count = (
        db.query(models.Notification)
        .filter(models.Notification.read_at.is_(None))
        .count()
    )
    return {
        "items": [_serialize(n) for n in rows],
        "unread_count": unread_count,
        "count": len(rows),
    }


@router.post("/{notification_id}/read")
def mark_read(notification_id: int, db: Session = Depends(get_db_session)):
    n = db.query(models.Notification).filter(models.Notification.id == notification_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    if n.read_at is None:
        n.read_at = utcnow()
        db.commit()
        db.refresh(n)
    return _serialize(n)


@router.post("/read-all")
def mark_all_read(db: Session = Depends(get_db_session)):
    now = utcnow()
    updated = (
        db.query(models.Notification)
        .filter(models.Notification.read_at.is_(None))
        .update({models.Notification.read_at: now}, synchronize_session=False)
    )
    db.commit()
    return {"updated": int(updated)}
