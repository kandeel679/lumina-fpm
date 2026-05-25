"""Celery tasks for threat-intel scan pipeline.

The ``run_scan_task`` replaces the old ``BackgroundTasks.add_task()`` pattern.
It runs inside a dedicated Celery worker container, communicating progress to
the FastAPI API via Redis keys that the SSE endpoint polls.

Progress key format:  ``scan_progress:{report_id}``
Progress value (JSON):
    {
        "phase": "Phase 3: Searching Dark Web",
        "detail": "optional extra info",
        "percent": 30,
        "status": "running"   // or "SUCCESS" / "FAILED"
    }
"""
from __future__ import annotations

import json
import logging
import time
import os
from datetime import datetime
from typing import Any, Optional

import redis

from celery_app import celery
from models.models import get_db
from services.lumina_threat_intel.db_models import ThreatIntelReport
from services.lumina_threat_intel.orchestrator import run_scan

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
PROGRESS_TTL = 3600  # 1 hour auto-cleanup


def _redis_client() -> redis.Redis:
    """Create a short-lived Redis client for progress updates."""
    return redis.Redis.from_url(REDIS_URL, decode_responses=True)


def _set_progress(
    report_id: int,
    phase: str,
    percent: int = 0,
    status: str = "running",
    detail: str = "",
) -> None:
    """Write scan progress to a Redis key."""
    key = f"scan_progress:{report_id}"
    payload = json.dumps({
        "phase": phase,
        "percent": percent,
        "status": status,
        "detail": detail,
        "updated_at": datetime.utcnow().isoformat(),
    })
    try:
        r = _redis_client()
        r.set(key, payload, ex=PROGRESS_TTL)
        r.close()
    except Exception as e:
        logger.warning("Failed to update Redis progress for report %d: %s", report_id, str(e)[:100])


@celery.task(
    bind=True,
    name="tasks.run_scan_pipeline",
    max_retries=0,
    acks_late=True,
    time_limit=1800,       # Hard kill after 30 min
    soft_time_limit=1500,  # Raise SoftTimeLimitExceeded after 25 min
)
def run_scan_task(
    self,
    report_id: int,
    trigger_type: str = "manual",
    categories: Optional[list[str]] = None,
    device_ids: Optional[list[int]] = None,
) -> dict[str, Any]:
    """Celery task that executes the full threat-intel scan pipeline.

    This task:
      1. Opens its own DB session (worker is a separate process/container)
      2. Publishes progress to Redis for the SSE endpoint to poll
      3. Delegates to ``orchestrator.run_scan()`` for the actual work
      4. Cleans up and returns a summary dict

    Args:
        report_id:    Pre-created ThreatIntelReport ID.
        trigger_type: "manual" | "scheduled" | "on_import".
        categories:   List of threat category strings to scan.
        device_ids:   Device IDs to scope (None = all devices).
    """
    logger.info(
        "Celery task started: run_scan_pipeline report_id=%d task_id=%s",
        report_id,
        self.request.id,
    )

    _set_progress(report_id, "Phase 1: Initializing", percent=0, status="running")

    SessionLocal = get_db()
    session = SessionLocal()

    try:
        # Retrieve the pre-created report row
        report = session.query(ThreatIntelReport).get(report_id)
        if not report:
            error_msg = f"Report {report_id} not found in database"
            logger.error(error_msg)
            _set_progress(report_id, error_msg, percent=0, status="FAILED")
            return {"error": error_msg}

        _set_progress(report_id, "Phase 2: Extracting Keywords", percent=10)

        # ----- Run the orchestrator (blocking, synchronous) -----
        # The orchestrator already handles all phases internally.
        # We wrap it so the task lifecycle (pre/post) gets progress updates.
        result_report = run_scan(
            db=session,
            trigger_type=trigger_type,
            requested_categories=categories,
            device_ids=device_ids,
            report=report,
        )

        # Build summary
        summary = {
            "report_id": result_report.id,
            "status": result_report.status,
            "scan_duration_seconds": result_report.scan_duration_seconds,
            "findings_count": (
                result_report.stats.get("total_findings", 0)
                if result_report.stats else 0
            ),
        }

        final_status = "SUCCESS" if result_report.status in ("completed", "partial") else "FAILED"
        _set_progress(
            report_id,
            f"Phase 12: Complete — {result_report.status}",
            percent=100,
            status=final_status,
            detail=json.dumps(summary),
        )

        logger.info(
            "Celery task complete: report_id=%d status=%s",
            report_id,
            result_report.status,
        )
        return summary

    except Exception as exc:
        error_msg = str(exc)[:500]
        logger.exception("Celery task failed: report_id=%d error=%s", report_id, error_msg)

        _set_progress(
            report_id,
            f"Error: {error_msg[:200]}",
            percent=0,
            status="FAILED",
            detail=error_msg,
        )

        # Mark report as failed in DB
        try:
            report = session.query(ThreatIntelReport).get(report_id)
            if report:
                report.status = "failed"
                report.scan_completed_at = datetime.utcnow()
                session.commit()
        except Exception:
            logger.exception("Failed to mark report %d as failed", report_id)

        return {"error": error_msg, "report_id": report_id}

    finally:
        session.close()
