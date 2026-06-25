"""Firmware-CVE runner (Volume 9 §6, device axis) — DB-backed.

Mirrors :mod:`services.cti.runner`, but for the DEVICE axis. For each device with a
known firmware version it correlates the active CVE feed (offline lab dataset in v1)
against the installed firmware and, on a confirmed version match, persists DEVICE-scoped
CTI evidence:

  * one ``cti_indicator(type='firmware_version', source_device_id=<dev>)`` per
    vulnerable device, and
  * one ``cti_observation(threat_type='vulnerability', provider='nvd'|'vendor_advisory')``
    per matched CVE.

It then triggers a risk recalculation so the device *firmware modifier* lands
(:mod:`services.risk.runner`). It writes **zero** ``rule_anomaly`` rows — the
config-anomaly benchmark is therefore untouched by construction.

Read-only against firewalls. No LLM, no Tor, no API key (offline mode).
"""
from __future__ import annotations

import hashlib
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from core.config import settings
from core.logging import get_logger
from models import models

from . import vuln_intel

logger = get_logger(__name__)


def _latest_run_id(db: Session) -> Optional[int]:
    return db.query(func.max(models.RuleAnomaly.analysis_run_id)).scalar()

# CtiObservation.confidence per source (>= 0.25 so the /cti `malicious` flag lights up).
_CONFIDENCE = {"cisa-kev": 0.95, "lab-offline": 0.92, "nvd": 0.9}


def _provider_mode() -> str:
    return (getattr(settings, "vuln_provider", "offline") or "offline").lower()


def _firmware_indicator(db: Session, device: models.FirewallDevice) -> models.CtiIndicator:
    """Upsert the device's firmware_version indicator.

    Dedupe key is (value, source_device_id, type) — deliberately NOT the CTI
    runner's (value, source_object_id) key, which would NULL-collide for a
    device-scoped CVE (source_object_id is always NULL here).
    """
    row = (
        db.query(models.CtiIndicator)
        .filter(
            models.CtiIndicator.type == "firmware_version",
            models.CtiIndicator.source_device_id == device.device_id,
            models.CtiIndicator.value == device.firmware_version,
            models.CtiIndicator.source_object_id.is_(None),
        )
        .first()
    )
    if row is None:
        row = models.CtiIndicator(
            type="firmware_version",
            value=device.firmware_version,
            source_object_id=None,
            source_device_id=device.device_id,
            is_public=True,
        )
        db.add(row)
        db.flush()
    else:
        row.last_seen = models.utcnow()
    return row


def run_vuln(db: Session, run_id: Optional[int] = None) -> dict:
    """Correlate firmware CVEs to devices, persist device-scoped CTI evidence, recalc risk."""
    mode = _provider_mode()
    if run_id is None:
        run_id = _latest_run_id(db)

    devices = (
        db.query(models.FirewallDevice)
        .filter(models.FirewallDevice.firmware_version.isnot(None))
        .all()
    )
    in_scope_ids = [d.device_id for d in devices]
    if not in_scope_ids:
        return {"provider": mode, "devices_scanned": 0, "devices_vulnerable": 0,
                "cve_observations": 0, "vendors": []}

    # Idempotent clear — STRICTLY scoped to firmware_version indicators for the
    # in-scope devices. Never touches the CTI runner's ip/cidr/fqdn indicators
    # (which also carry source_device_id). Observations cascade via the ORM
    # relationship (cascade='all, delete-orphan').
    stale = (
        db.query(models.CtiIndicator)
        .filter(
            models.CtiIndicator.type == "firmware_version",
            models.CtiIndicator.source_device_id.in_(in_scope_ids),
        )
        .all()
    )
    for ind in stale:
        db.delete(ind)
    db.flush()

    findings: List[vuln_intel.CveFinding] = vuln_intel.build_cve_findings(
        db, mode=mode, device_ids=in_scope_ids
    )

    vulnerable_devices: set[int] = set()
    observations = 0
    vendors_used: set[str] = set()
    device_by_id = {d.device_id: d for d in devices}

    for finding in findings:
        matched = vuln_intel.decide_vulnerable_devices(db, finding, device_ids=in_scope_ids)
        for dev_id in matched:
            device = device_by_id.get(dev_id)
            if device is None:
                continue
            indicator = _firmware_indicator(db, device)
            db.add(models.CtiObservation(
                indicator_id=indicator.indicator_id,
                provider=finding.provider,
                provider_reference=finding.reference or finding.cve,
                severity=finding.severity,
                confidence=_CONFIDENCE.get(finding.source, 0.9),
                threat_type="vulnerability",
                summary=(
                    f"{finding.cve}: {finding.title}"
                    + (f" (CVSS {finding.cvss})" if finding.cvss is not None else "")
                    + (" — CISA KEV, actively exploited" if finding.kev else "")
                    + (" — known ransomware use" if finding.ransomware else "")
                    + f". Installed firmware {device.firmware_version} is within an "
                      f"affected version range."
                ),
                raw_response_hash=hashlib.sha256(
                    f"{finding.source}:{finding.cve}:{dev_id}".encode()
                ).hexdigest(),
            ))
            observations += 1
            vulnerable_devices.add(dev_id)
            if device.vendor_type:
                vendors_used.add(device.vendor_type)

    db.commit()

    # Firmware CVEs feed risk (Vol8 §8 device modifier): recalc so the device
    # firmware_modifier lands. Best-effort — a risk failure only warns.
    try:
        from services.risk.runner import run_risk
        run_risk(db, run_id)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Risk recalculation after VULN failed for run %s: %s", run_id, exc)

    logger.info(
        "VULN run (%s): %d devices scanned, %d vulnerable, %d CVE observations (%s)",
        mode, len(in_scope_ids), len(vulnerable_devices), observations, sorted(vendors_used),
    )
    return {
        "provider": mode,
        "analysis_run_id": run_id,
        "devices_scanned": len(in_scope_ids),
        "devices_vulnerable": len(vulnerable_devices),
        "cve_observations": observations,
        "vendors": sorted(vendors_used),
    }
