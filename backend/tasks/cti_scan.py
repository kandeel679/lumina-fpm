"""Scheduled / on-demand CTI enrichment task.

Wraps the synchronous two-axis enrichment (run_cti rule-axis + run_vuln device-axis)
in a Celery task so it can run off the request cycle for scheduled and "run now"
triggers. The manual ``POST /api/v1/cti/run`` still runs inline; this task is the
background equivalent used by the scheduler and the Settings "run now" button.

Read-only: enrichment reads firewall-derived indicators and queries threat-intel
providers; it never modifies a device.
"""
from __future__ import annotations

from celery_app import celery
from core.logging import get_logger
from models.models import get_db
from services.cti.runner import run_cti
from services.cti.vuln_runner import run_vuln
from services.notifications import emit_safe

logger = get_logger(__name__)
SessionLocal = get_db()


@celery.task(name="cti.run_scheduled", queue="cti")
def run_scheduled_cti(analysis_run_id: int | None = None) -> dict:
    """Run CTI + VULN enrichment against an analysis run (latest if omitted)."""
    db = SessionLocal()
    try:
        cti_res = run_cti(db, analysis_run_id)
        vuln_res = run_vuln(db, analysis_run_id)

        if isinstance(cti_res, dict) and cti_res.get("error"):
            emit_safe(db, "warning", "threat_intel", "Threat-intel refresh skipped",
                      body=str(cti_res.get("error")), link="#/threats")
            return {"cti": cti_res, "vuln": vuln_res}

        malicious = (cti_res or {}).get("malicious_indicators", 0)
        exposures = (cti_res or {}).get("threat_exposure_findings", 0)
        cves = (vuln_res or {}).get("cve_observations", 0)
        vuln_devices = (vuln_res or {}).get("devices_vulnerable", 0)
        level = "warning" if (malicious or cves) else "success"
        emit_safe(
            db, level, "threat_intel", "Threat-intel refresh complete",
            body=(f"{malicious} malicious indicator(s), {exposures} exposure finding(s); "
                  f"{cves} firmware CVE observation(s) across {vuln_devices} device(s)."),
            link="#/threats",
        )
        logger.info("Scheduled CTI complete: cti=%s vuln=%s", cti_res, vuln_res)
        return {"cti": cti_res, "vuln": vuln_res}
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scheduled CTI failed: %s", exc)
        emit_safe(db, "critical", "threat_intel", "Threat-intel refresh failed",
                  body="See server logs for details.", link="#/threats")
        return {"status": "failed", "error": str(exc)}
    finally:
        db.close()
