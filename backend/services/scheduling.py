"""Scheduling service.

Two concerns, kept deliberately simple:

  1. A small, dependency-free 5-field cron evaluator + a next-run calculator. These
     are PURE functions (no DB, no Celery) so they are trivially unit-testable.
  2. ``dispatch_operation`` — fans a due/again-now schedule out to the EXISTING
     read-only pipelines (acquisition poll / anomaly analysis / CTI enrichment).
     It adds no new firewall capability; it only triggers what the manual buttons
     already trigger.

Schedules are global per operation: 'acquisition' polls every credentialed device,
'detection' runs an all-scope anomaly analysis, 'threat_intel' refreshes CTI/vuln.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Set

from sqlalchemy.orm import Session

from core.logging import get_logger
from models import models

logger = get_logger(__name__)

OPERATIONS = ("acquisition", "detection", "threat_intel")
VALID_MODES = ("interval", "cron")

# Friendly interval presets surfaced in the UI (minutes). 'cron' covers daily-at-time
# and anything bespoke, so we keep the interval list short and obvious.
INTERVAL_PRESETS = (15, 30, 60, 360, 720, 1440)

# Bound the forward cron search so a never-matching expression can't loop forever.
_CRON_SEARCH_LIMIT_MIN = 366 * 24 * 60  # one year of minutes


# ---------------------------------------------------------------------------
# Cron: a minimal but correct 5-field evaluator (minute hour dom month dow).
# Supports '*', '*/n', 'a', 'a-b', 'a-b/n', and comma lists of those.
# dow: 0-6 (Sun=0); 7 is accepted as Sunday. Standard Vixie semantics — when BOTH
# day-of-month and day-of-week are restricted, a match on EITHER fires.
# ---------------------------------------------------------------------------

def _parse_field(field: str, lo: int, hi: int) -> Set[int]:
    field = field.strip()
    if not field:
        raise ValueError("empty cron field")
    values: Set[int] = set()
    for part in field.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty cron list element")
        step = 1
        base = part
        if "/" in part:
            base, step_s = part.split("/", 1)
            step = int(step_s)
            if step < 1:
                raise ValueError("cron step must be >= 1")
        if base == "*":
            start, end = lo, hi
        elif "-" in base:
            a, b = base.split("-", 1)
            start, end = int(a), int(b)
        else:
            start = end = int(base)
        if start < lo or end > hi or start > end:
            raise ValueError(f"cron field value out of range: '{part}' (allowed {lo}-{hi})")
        values.update(range(start, end + 1, step))
    return values


def parse_cron(expr: str) -> Dict[str, object]:
    """Validate + parse a 5-field cron expression. Raises ValueError if malformed."""
    fields = expr.split()
    if len(fields) != 5:
        raise ValueError("cron expression must have exactly 5 fields: 'minute hour dom month dow'")
    minute = _parse_field(fields[0], 0, 59)
    hour = _parse_field(fields[1], 0, 23)
    dom = _parse_field(fields[2], 1, 31)
    month = _parse_field(fields[3], 1, 12)
    dow = _parse_field(fields[4], 0, 7)
    if 7 in dow:
        dow.add(0)
    return {
        "minute": minute, "hour": hour, "dom": dom, "month": month, "dow": dow,
        "dom_restricted": fields[2].strip() != "*",
        "dow_restricted": fields[4].strip() != "*",
    }


def cron_matches(expr: str, dt: datetime) -> bool:
    """True if ``dt`` (minute granularity) satisfies the cron expression."""
    p = parse_cron(expr)
    if dt.minute not in p["minute"]:
        return False
    if dt.hour not in p["hour"]:
        return False
    if dt.month not in p["month"]:
        return False
    # Python weekday(): Mon=0..Sun=6. Cron dow: Sun=0..Sat=6.
    cron_dow = (dt.weekday() + 1) % 7
    dom_ok = dt.day in p["dom"]
    dow_ok = cron_dow in p["dow"]
    if p["dom_restricted"] and p["dow_restricted"]:
        return dom_ok or dow_ok
    if p["dom_restricted"]:
        return dom_ok
    if p["dow_restricted"]:
        return dow_ok
    return True


def next_cron_after(expr: str, after: datetime) -> Optional[datetime]:
    """First minute strictly after ``after`` that matches the cron expression."""
    parse_cron(expr)  # validate once up front
    cursor = after.replace(second=0, microsecond=0) + timedelta(minutes=1)
    for _ in range(_CRON_SEARCH_LIMIT_MIN):
        if cron_matches(expr, cursor):
            return cursor
        cursor += timedelta(minutes=1)
    return None


def compute_next_run(
    mode: str,
    interval_minutes: Optional[int],
    cron_expression: Optional[str],
    after: datetime,
) -> Optional[datetime]:
    """Next fire time strictly after ``after`` for the given schedule config."""
    if mode == "interval":
        if not interval_minutes or interval_minutes < 1:
            return None
        return after + timedelta(minutes=interval_minutes)
    if mode == "cron":
        if not cron_expression:
            return None
        return next_cron_after(cron_expression, after)
    return None


def describe(row: "models.ScheduleConfig") -> str:
    """Human label for a schedule, e.g. 'every 6h' or 'cron 0 2 * * *'."""
    if row.mode == "interval" and row.interval_minutes:
        m = row.interval_minutes
        if m % 1440 == 0:
            return f"every {m // 1440}d"
        if m % 60 == 0:
            return f"every {m // 60}h"
        return f"every {m}m"
    if row.mode == "cron" and row.cron_expression:
        return f"cron {row.cron_expression}"
    return "unconfigured"


# ---------------------------------------------------------------------------
# Dispatch — trigger the existing read-only pipelines. Imports of task modules are
# lazy (mirrors the rest of the codebase) to avoid import cycles at module load.
# ---------------------------------------------------------------------------

def dispatch_operation(db: Session, operation: str, requested_by: str = "scheduler") -> Dict:
    if operation == "acquisition":
        return _dispatch_acquisition(db, requested_by)
    if operation == "detection":
        return _dispatch_detection(db, requested_by)
    if operation == "threat_intel":
        return _dispatch_threat_intel(db, requested_by)
    raise ValueError(f"unknown operation '{operation}'")


def _dispatch_acquisition(db: Session, requested_by: str) -> Dict:
    from services import credentials
    from services.acquisition import resolve_device_vendor_type
    from tasks.acquisition import poll_device as poll_task

    devices = db.query(models.FirewallDevice).all()
    dispatched, skipped = 0, 0
    for d in devices:
        if not credentials.has_credential(db, d.device_id):
            skipped += 1
            continue
        job = models.AcquisitionJob(
            device_id=d.device_id,
            vendor_type=resolve_device_vendor_type(d),
            requested_by=requested_by,
            status="queued",
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        poll_task.delay(job_id=job.job_id)
        dispatched += 1
    logger.info("Dispatched acquisition for %d device(s) (%d without credentials skipped)",
                dispatched, skipped)
    return {"operation": "acquisition", "devices_dispatched": dispatched, "skipped_no_credential": skipped}


def _dispatch_detection(db: Session, requested_by: str) -> Dict:
    from tasks.anomaly import run_anomaly_analysis_task

    task = run_anomaly_analysis_task.delay(device_id=None)
    logger.info("Dispatched all-scope anomaly analysis (task=%s)", task.id)
    return {"operation": "detection", "task_id": task.id, "scope": "all"}


def _dispatch_threat_intel(db: Session, requested_by: str) -> Dict:
    from tasks.cti_scan import run_scheduled_cti

    task = run_scheduled_cti.delay()
    logger.info("Dispatched scheduled CTI/vuln enrichment (task=%s)", task.id)
    return {"operation": "threat_intel", "task_id": task.id}
