"""In-app notification service.

A tiny helper the background pipeline calls when an operation completes/fails or a
scan surfaces high/critical findings. Notifications are informational only — they
never touch a firewall. ``emit_safe`` is best-effort: a notification failure must
never break the acquisition / analysis / CTI pipeline that produced it.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from core.logging import get_logger
from models import models

logger = get_logger(__name__)

VALID_LEVELS = {"info", "success", "warning", "critical"}
VALID_CATEGORIES = {"acquisition", "detection", "threat_intel", "finding", "system"}


def emit(
    db: Session,
    level: str,
    category: str,
    title: str,
    body: Optional[str] = None,
    link: Optional[str] = None,
) -> models.Notification:
    """Persist a notification and return it. Raises on DB error (use emit_safe in tasks)."""
    if level not in VALID_LEVELS:
        level = "info"
    if category not in VALID_CATEGORIES:
        category = "system"
    note = models.Notification(
        level=level,
        category=category,
        title=title[:200],
        body=body,
        link=link,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


def emit_safe(
    db: Session,
    level: str,
    category: str,
    title: str,
    body: Optional[str] = None,
    link: Optional[str] = None,
) -> Optional[models.Notification]:
    """Best-effort emit — swallows and logs any error so the caller never fails."""
    try:
        return emit(db, level, category, title, body=body, link=link)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to emit notification '%s': %s", title, exc)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
