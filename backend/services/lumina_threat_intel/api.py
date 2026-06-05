"""FastAPI router for Lumina Threat Intel endpoints.

All endpoints are mounted under /api/threat-intel by main.py.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import os
from datetime import datetime, timedelta
from typing import Optional

import redis
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from models.models import get_db, FirewallDevice, Vendor

from .db_models import (
    ThreatIntelFinding,
    ThreatIntelIOC,
    ThreatIntelRawScrape,
    ThreatIntelReport,
)
from .schemas import (
    DashboardStatsResponse,
    FindingResponse,
    IOCResponse,
    PaginatedResponse,
    ReportDetailResponse,
    ReportStatsResponse,
    ReportSummaryResponse,
    ScanCreatedResponse,
    ScanRequest,
    ScanStatus,
)
from .stream import format_sse_message

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intel"])

# DB session dependency
SessionLocal = get_db()


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Rate limit tracking (in-memory, simple) ──
_scan_timestamps: dict[str, list[float]] = {}

RATE_LIMIT_PER_USER_HOUR = 10
RATE_LIMIT_PER_TENANT_DAY = 50


def _check_rate_limit(admin_id: Optional[int]) -> None:
    """Simple in-memory rate limiter."""
    now = datetime.utcnow().timestamp()
    key = f"user:{admin_id or 'anon'}"
    history = _scan_timestamps.setdefault(key, [])

    one_hour_ago = now - 3600
    history[:] = [t for t in history if t > one_hour_ago]

    if len(history) >= RATE_LIMIT_PER_USER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT_PER_USER_HOUR} scans per hour",
        )

    history.append(now)


# ── Endpoints ──

@router.post("/scans", response_model=ScanCreatedResponse)
def trigger_scan(
    request: ScanRequest,
    db: Session = Depends(get_session),
):
    """Trigger a manual threat-intel scan.

    The scan is dispatched to a Celery worker via ``.delay()``.
    Progress is tracked through a Redis key polled by the SSE endpoint.
    """
    _check_rate_limit(None)

    running = (
        db.query(ThreatIntelReport)
        .filter(ThreatIntelReport.status == "running")
        .first()
    )
    if running:
        raise HTTPException(
            status_code=409,
            detail="A scan is already running. Wait for it to complete.",
        )

    # Normalize and validate device_ids
    device_ids = request.device_ids
    if device_ids is not None and len(device_ids) == 0:
        device_ids = None

    if device_ids:
        # Verify all requested device IDs exist
        existing_ids = {
            row[0]
            for row in db.query(FirewallDevice.device_id)
            .filter(FirewallDevice.device_id.in_(device_ids))
            .all()
        }
        missing = set(device_ids) - existing_ids
        if missing:
            raise HTTPException(
                status_code=404,
                detail=f"Device(s) not found: {sorted(missing)}",
            )

    # Create report synchronously so we can return its ID immediately
    report = ThreatIntelReport(
        trigger_type=request.trigger_type.value,
        triggered_by_admin_id=None,
        status="running",
        scan_started_at=datetime.utcnow(),
        scanned_device_ids=device_ids,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    categories = [c.value for c in request.categories]

    # Dispatch to Celery worker
    from tasks.threat_intel import run_scan_task

    run_scan_task.delay(
        report_id=report.id,
        trigger_type=request.trigger_type.value,
        categories=categories,
        device_ids=device_ids,
    )

    # Count devices in scope
    if device_ids:
        device_count = len(device_ids)
    else:
        device_count = db.query(func.count(FirewallDevice.device_id)).scalar() or 0

    return ScanCreatedResponse(
        report_id=report.id,
        status=ScanStatus.RUNNING,
        device_ids=device_ids,
        device_count=device_count,
    )


@router.get("/scans", response_model=PaginatedResponse)
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    archived: Optional[bool] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_session),
):
    """List threat-intel reports with pagination."""
    query = db.query(ThreatIntelReport)
    if archived is not None:
        query = query.filter(ThreatIntelReport.archived == archived)
    else:
        query = query.filter(ThreatIntelReport.archived == False)
    if status:
        query = query.filter(ThreatIntelReport.status == status)

    total = query.count()
    reports = (
        query
        .order_by(ThreatIntelReport.scan_started_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = []
    for r in reports:
        items.append(ReportSummaryResponse(
            id=r.id,
            trigger_type=r.trigger_type,
            triggered_by_admin_id=r.triggered_by_admin_id,
            status=r.status,
            scan_started_at=r.scan_started_at,
            scan_completed_at=r.scan_completed_at,
            scan_duration_seconds=r.scan_duration_seconds,
            queries_generated_count=r.queries_generated_count,
            onion_pages_scraped_count=r.onion_pages_scraped_count,
            narrative_summary=r.narrative_summary,
            clean=r.clean,
            coverage_note=r.coverage_note,
            stats=r.stats,
            llm_model_name=r.llm_model_name,
            scanned_device_ids=r.scanned_device_ids,
            archived=r.archived,
            created_at=r.created_at,
        ))

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/scans/{report_id}", response_model=ReportDetailResponse)
def get_report_detail(report_id: int, db: Session = Depends(get_session)):
    """Get full report with all findings and IOCs."""
    report = db.query(ThreatIntelReport).filter(ThreatIntelReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    findings = (
        db.query(ThreatIntelFinding)
        .filter(ThreatIntelFinding.report_id == report_id)
        .order_by(
            ThreatIntelFinding.severity,
            ThreatIntelFinding.confidence.desc(),
        )
        .all()
    )

    finding_responses = []
    for f in findings:
        iocs = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.finding_id == f.id).all()
        finding_responses.append(FindingResponse(
            id=f.id,
            report_id=f.report_id,
            category=f.category,
            severity=f.severity,
            criticality=f.criticality,
            relevance_score=f.relevance_score,
            relevance_band=f.relevance_band,
            relevance_reason=f.relevance_reason,
            confidence=f.confidence,
            title=f.title,
            description=f.description or "",
            recommended_actions=f.recommended_actions or [],
            tags=f.tags or [],
            source_onion_url=f.source_onion_url,
            source_search_engine=f.source_search_engine,
            source_scraped_at=f.source_scraped_at,
            source_raw_excerpt=f.source_raw_excerpt,
            source_page_title=f.source_page_title,
            source_marketplace_or_forum=f.source_marketplace_or_forum,
            matched_rule_ids=f.matched_rule_ids or [],
            matched_device_ids=f.matched_device_ids or [],
            correlation_match_reason=f.correlation_match_reason,
            is_new_since_last_scan=f.is_new_since_last_scan or False,
            first_seen_in_scan_id=f.first_seen_in_scan_id,
            parse_error=f.parse_error or False,
            iocs=[IOCResponse(id=i.id, ioc_type=i.ioc_type, ioc_value=i.ioc_value) for i in iocs],
            created_at=f.created_at,
        ))

    return ReportDetailResponse(
        id=report.id,
        trigger_type=report.trigger_type,
        triggered_by_admin_id=report.triggered_by_admin_id,
        status=report.status,
        scan_started_at=report.scan_started_at,
        scan_completed_at=report.scan_completed_at,
        scan_duration_seconds=report.scan_duration_seconds,
        queries_generated_count=report.queries_generated_count,
        onion_pages_scraped_count=report.onion_pages_scraped_count,
        narrative_summary=report.narrative_summary,
        clean=report.clean,
        coverage_note=report.coverage_note,
        stats=report.stats,
        llm_model_name=report.llm_model_name,
        scanned_device_ids=report.scanned_device_ids,
        archived=report.archived,
        created_at=report.created_at,
        findings=finding_responses,
        error_log=report.error_log,
    )


@router.delete("/scans/{report_id}")
def archive_report(report_id: int, db: Session = Depends(get_session)):
    """Soft-archive a report (set archived=true)."""
    report = db.query(ThreatIntelReport).filter(ThreatIntelReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report.archived = True
    db.commit()
    return {"message": "Report archived", "report_id": report_id}


@router.get("/scans/{report_id}/stream")
async def stream_scan_progress(report_id: int, db: Session = Depends(get_session)):
    """SSE stream of pipeline events for a running scan.

    Reads progress from a Redis key written by the Celery worker.
    This works cross-container since both API and worker share the
    same Redis instance.
    """
    report = db.query(ThreatIntelReport).filter(ThreatIntelReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    async def event_generator():
        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        key = f"scan_progress:{report_id}"
        last_phase = None
        try:
            while True:
                raw = r.get(key)
                if raw:
                    progress = json.loads(raw)
                    current_phase = progress.get("phase", "")

                    # Only emit if phase changed (avoid duplicate events)
                    if current_phase != last_phase:
                        last_phase = current_phase
                        event = {
                            "event": progress.get("status", "progress"),
                            "data": progress,
                        }
                        yield format_sse_message(event)

                    # Terminal states
                    status = progress.get("status", "")
                    if status in ("SUCCESS", "FAILED"):
                        break
                else:
                    # No progress yet — check if report already finished
                    db_session = SessionLocal()
                    try:
                        rpt = db_session.query(ThreatIntelReport).filter(
                            ThreatIntelReport.id == report_id
                        ).first()
                        if rpt and rpt.status in ("completed", "failed", "partial"):
                            yield format_sse_message({
                                "event": "done",
                                "data": {"status": rpt.status, "report_id": report_id},
                            })
                            break
                    finally:
                        db_session.close()

                # Poll interval
                await asyncio.sleep(1)

                # Keepalive
                yield ": keepalive\n\n"
        finally:
            r.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/devices")
def list_scannable_devices(db: Session = Depends(get_session)):
    """List all firewall devices available for scanning.

    Returns a lightweight list for the frontend multi-select UI.
    """
    devices = (
        db.query(FirewallDevice)
        .order_by(FirewallDevice.hostname)
        .all()
    )

    items = []
    for d in devices:
        vendor_name = None
        if d.vendor:
            vendor_name = d.vendor.name
        else:
            vendor = db.query(Vendor).filter(Vendor.vendor_id == d.vendor_id).first()
            vendor_name = vendor.name if vendor else None

        items.append({
            "device_id": d.device_id,
            "hostname": d.hostname,
            "vendor_name": vendor_name,
            "management_ip": d.management_ip,
            "firmware_version": d.firmware_version,
            "status": d.status,
        })

    return {"devices": items, "total": len(items)}


@router.get("/findings")
def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    category: Optional[str] = None,
    correlated_only: bool = False,
    new_only: bool = False,
    search: Optional[str] = None,
    db: Session = Depends(get_session),
):
    """Cross-report findings query with filters."""
    query = db.query(ThreatIntelFinding)

    if severity:
        query = query.filter(ThreatIntelFinding.severity == severity)
    if category:
        query = query.filter(ThreatIntelFinding.category == category)
    if correlated_only:
        query = query.filter(ThreatIntelFinding.matched_rule_ids != None)
    if new_only:
        query = query.filter(ThreatIntelFinding.is_new_since_last_scan == True)
    if search:
        query = query.filter(
            ThreatIntelFinding.title.ilike(f"%{search}%")
            | ThreatIntelFinding.description.ilike(f"%{search}%")
        )

    total = query.count()
    findings = (
        query.order_by(ThreatIntelFinding.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = []
    for f in findings:
        iocs = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.finding_id == f.id).all()
        items.append(FindingResponse(
            id=f.id, report_id=f.report_id, category=f.category,
            criticality=f.criticality,
            relevance_score=f.relevance_score, relevance_band=f.relevance_band,
            relevance_reason=f.relevance_reason,
            severity=f.severity, confidence=f.confidence, title=f.title,
            description=f.description or "", recommended_actions=f.recommended_actions or [],
            tags=f.tags or [], source_onion_url=f.source_onion_url,
            source_search_engine=f.source_search_engine, source_scraped_at=f.source_scraped_at,
            source_raw_excerpt=f.source_raw_excerpt, source_page_title=f.source_page_title,
            source_marketplace_or_forum=f.source_marketplace_or_forum,
            matched_rule_ids=f.matched_rule_ids or [],
            matched_device_ids=f.matched_device_ids or [],
            correlation_match_reason=f.correlation_match_reason,
            is_new_since_last_scan=f.is_new_since_last_scan or False,
            first_seen_in_scan_id=f.first_seen_in_scan_id,
            parse_error=f.parse_error or False,
            iocs=[IOCResponse(id=i.id, ioc_type=i.ioc_type, ioc_value=i.ioc_value) for i in iocs],
            created_at=f.created_at,
        ))

    return PaginatedResponse(
        items=items, total=total, page=page, page_size=page_size,
        total_pages=math.ceil(total / page_size) if total else 0,
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding_detail(finding_id: int, db: Session = Depends(get_session)):
    """Get a single finding with IOCs and correlation detail."""
    f = db.query(ThreatIntelFinding).filter(ThreatIntelFinding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")

    iocs = db.query(ThreatIntelIOC).filter(ThreatIntelIOC.finding_id == f.id).all()
    return FindingResponse(
        id=f.id, report_id=f.report_id, category=f.category,
        criticality=f.criticality,
        relevance_score=f.relevance_score, relevance_band=f.relevance_band,
        relevance_reason=f.relevance_reason,
        severity=f.severity, confidence=f.confidence, title=f.title,
        description=f.description or "", recommended_actions=f.recommended_actions or [],
        tags=f.tags or [], source_onion_url=f.source_onion_url,
        source_search_engine=f.source_search_engine, source_scraped_at=f.source_scraped_at,
        source_raw_excerpt=f.source_raw_excerpt, source_page_title=f.source_page_title,
        source_marketplace_or_forum=f.source_marketplace_or_forum,
        matched_rule_ids=f.matched_rule_ids or [],
        matched_device_ids=f.matched_device_ids or [],
        correlation_match_reason=f.correlation_match_reason,
        is_new_since_last_scan=f.is_new_since_last_scan or False,
        first_seen_in_scan_id=f.first_seen_in_scan_id,
        parse_error=f.parse_error or False,
        iocs=[IOCResponse(id=i.id, ioc_type=i.ioc_type, ioc_value=i.ioc_value) for i in iocs],
        created_at=f.created_at,
    )


@router.get("/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_session)):
    """Stats for the threat-intel dashboard overview."""
    seven_days_ago = datetime.utcnow() - timedelta(days=7)

    total_scans = db.query(func.count(ThreatIntelReport.id)).scalar() or 0

    last_report = (
        db.query(ThreatIntelReport)
        .order_by(ThreatIntelReport.scan_started_at.desc())
        .first()
    )

    recent_findings = (
        db.query(ThreatIntelFinding)
        .filter(ThreatIntelFinding.created_at >= seven_days_ago)
        .all()
    )

    critical_7d = sum(1 for f in recent_findings if f.severity == "critical")
    high_7d = sum(1 for f in recent_findings if f.severity == "high")

    new_last = 0
    if last_report:
        new_last = (
            db.query(func.count(ThreatIntelFinding.id))
            .filter(
                ThreatIntelFinding.report_id == last_report.id,
                ThreatIntelFinding.is_new_since_last_scan == True,
            )
            .scalar() or 0
        )

    top_cats: dict[str, int] = {}
    for f in recent_findings:
        cat = f.category or "exploit"
        top_cats[cat] = top_cats.get(cat, 0) + 1

    corr_count = sum(
        1 for f in recent_findings
        if f.matched_rule_ids and len(f.matched_rule_ids) > 0
    )

    return DashboardStatsResponse(
        total_scans=total_scans,
        last_scan_at=last_report.scan_started_at if last_report else None,
        last_scan_status=last_report.status if last_report else None,
        total_findings_last_7d=len(recent_findings),
        critical_findings_last_7d=critical_7d,
        high_findings_last_7d=high_7d,
        new_findings_last_scan=new_last,
        top_categories=top_cats,
        correlated_rules_count=corr_count,
    )


@router.get("/rules/{rule_id}/findings")
def get_findings_for_rule(rule_id: int, db: Session = Depends(get_session)):
    """Get all findings correlated to a specific firewall rule."""
    findings = (
        db.query(ThreatIntelFinding)
        .filter(
            ThreatIntelFinding.matched_rule_ids.isnot(None),
            func.cast(ThreatIntelFinding.matched_rule_ids, func.text()).contains(str(rule_id)),
        )
        .order_by(ThreatIntelFinding.severity, ThreatIntelFinding.created_at.desc())
        .limit(50)
        .all()
    )

    items = []
    for f in findings:
        if rule_id in (f.matched_rule_ids or []):
            items.append({
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "confidence": f.confidence,
                "report_id": f.report_id,
            })

    return {"rule_id": rule_id, "count": len(items), "findings": items}
