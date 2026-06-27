"""Celery Beat scheduler tick.

A single periodic task (every 60s, see celery_app.beat_schedule) reads the
``schedule_config`` rows and dispatches any operation whose ``next_run_at`` is due,
then recomputes the next run. All it does is trigger the existing read-only
pipelines — it never modifies a firewall.

Keeping ONE tick that reads a DB table (instead of N static beat entries) is what
makes the schedules editable from the Settings page without restarting Beat.
"""
from __future__ import annotations

from celery_app import celery
from core.logging import get_logger
from models import models
from models.models import get_db, utcnow
from services import scheduling

logger = get_logger(__name__)
SessionLocal = get_db()


@celery.task(name="scheduler.tick")
def tick() -> dict:
    """Fire every enabled schedule that is due; recompute its next run."""
    db = SessionLocal()
    fired = []
    try:
        now = utcnow()
        rows = (
            db.query(models.ScheduleConfig)
            .filter(models.ScheduleConfig.enabled.is_(True))
            .all()
        )
        for row in rows:
            # Freshly enabled with no next_run yet — arm it, don't fire immediately.
            if row.next_run_at is None:
                row.next_run_at = scheduling.compute_next_run(
                    row.mode, row.interval_minutes, row.cron_expression, now
                )
                continue
            if row.next_run_at <= now:
                try:
                    result = scheduling.dispatch_operation(db, row.operation, requested_by="scheduler")
                    fired.append({"operation": row.operation, "result": result})
                except Exception as exc:  # noqa: BLE001 - one bad schedule must not stop others
                    logger.exception("Schedule dispatch failed for '%s': %s", row.operation, exc)
                row.last_run_at = now
                row.next_run_at = scheduling.compute_next_run(
                    row.mode, row.interval_minutes, row.cron_expression, now
                )
        db.commit()
        if fired:
            logger.info("scheduler.tick fired %d operation(s): %s",
                        len(fired), [f["operation"] for f in fired])
        return {"checked": len(rows), "fired": fired}
    except Exception as exc:  # noqa: BLE001
        logger.exception("scheduler.tick failed: %s", exc)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {"checked": 0, "fired": [], "error": str(exc)}
    finally:
        db.close()
