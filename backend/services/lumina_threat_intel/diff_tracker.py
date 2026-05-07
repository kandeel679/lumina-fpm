"""Diff tracker — determines which findings are new since the last scan.

Uses a hash of (category, title, sorted IOC values) to detect previously-
seen findings. If a finding's hash was seen in the last 7 days, it is
marked as not new.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from .db_models import ThreatIntelFinding, ThreatIntelReport

logger = logging.getLogger(__name__)


def compute_finding_hash(finding: dict[str, Any]) -> str:
    """Compute a deterministic hash for deduplication / diff tracking.

    Hash = SHA256(category | title | sorted IOC values)
    """
    category = finding.get("category", "")
    title = finding.get("title", "")
    iocs = finding.get("iocs", [])
    sorted_ioc_values = sorted(
        (ioc.get("value", "") for ioc in iocs),
        key=str.lower,
    )
    payload = f"{category}|{title}|{json.dumps(sorted_ioc_values)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def mark_new_findings(
    db: Session,
    current_report_id: int,
    findings: list[dict[str, Any]],
    lookback_days: int = 7,
) -> list[dict[str, Any]]:
    """Mark each finding as new or previously-seen.

    Checks the last `lookback_days` of findings for hash collisions.
    Populates `is_new_since_last_scan`, `first_seen_in_scan_id`, and
    `finding_hash` on each finding dict.
    """
    cutoff = datetime.utcnow() - timedelta(days=lookback_days)

    # Load recent finding hashes from DB
    try:
        recent_findings = (
            db.query(
                ThreatIntelFinding.finding_hash,
                ThreatIntelFinding.report_id,
            )
            .join(
                ThreatIntelReport,
                ThreatIntelFinding.report_id == ThreatIntelReport.id,
            )
            .filter(
                ThreatIntelReport.scan_started_at >= cutoff,
                ThreatIntelFinding.finding_hash.isnot(None),
                ThreatIntelReport.id != current_report_id,
            )
            .all()
        )
        # hash -> earliest report_id
        existing_hashes: dict[str, int] = {}
        for row in recent_findings:
            h, rid = row
            if h not in existing_hashes:
                existing_hashes[h] = rid
    except Exception as e:
        logger.error("Failed to load recent finding hashes: %s", str(e))
        existing_hashes = {}

    new_count = 0
    for finding in findings:
        h = compute_finding_hash(finding)
        finding["finding_hash"] = h

        if h in existing_hashes:
            finding["is_new_since_last_scan"] = False
            finding["first_seen_in_scan_id"] = existing_hashes[h]
        else:
            finding["is_new_since_last_scan"] = True
            finding["first_seen_in_scan_id"] = current_report_id
            new_count += 1

    logger.info(
        "Diff tracking: %d new, %d previously-seen out of %d findings",
        new_count, len(findings) - new_count, len(findings),
    )
    return findings
