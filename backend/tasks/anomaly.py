"""Deterministic anomaly analysis task (Volume 5).

Reads the NORMALIZED REPOSITORY (Schema v4) via ``load_normalized_result``, runs
the deterministic config-only anomaly engine, and persists each Finding as a
RuleAnomaly row tied to an AnomalyExecutionLog run. There is NO randomness, NO
mock data, NO LLM, and the engine never touches raw vendor data or the network.

The callable is named ``run_anomaly_analysis_task`` (imported by
api/routes/rules.py). Celery task name is ``analysis.run_anomaly_analysis`` and it
runs on the ``analysis`` queue. Signature: ``run_anomaly_analysis_task(device_id=None)``
— ``device_id=None`` analyzes ALL devices (required for cross-device detectors).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from celery_app import celery
from core.logging import get_logger
from models import models
from models.models import get_db, utcnow
from services.anomaly import analyze
from services.normalization.loader import load_normalized_result

logger = get_logger(__name__)
SessionLocal = get_db()

ENGINE_VERSION = "anomaly-engine/1.0.0"


def _rule_index(db, device_ids: Optional[List[int]]) -> Dict[tuple, int]:
    """Map (device_id, vendor_uuid) -> PolicyRule.rule_id for finding resolution."""
    q = db.query(
        models.PolicyRule.rule_id,
        models.PolicyRule.device_id,
        models.PolicyRule.vendor_uuid,
    ).filter(models.PolicyRule.deleted_at.is_(None))
    if device_ids is not None:
        q = q.filter(models.PolicyRule.device_id.in_(device_ids))
    index: Dict[tuple, int] = {}
    for rule_id, dev_id, vendor_uuid in q.all():
        if vendor_uuid is None:
            continue
        index[(dev_id, vendor_uuid)] = rule_id
    return index


@celery.task(
    bind=True,
    name="analysis.run_anomaly_analysis",
    queue="analysis",
    max_retries=0,
    acks_late=True,
    time_limit=300,
)
def run_anomaly_analysis_task(self, device_id: Optional[int] = None) -> Dict[str, Any]:
    """Run the deterministic anomaly engine and persist RuleAnomaly findings.

    Steps:
      1. Create an AnomalyExecutionLog row (status=running).
      2. Reconstruct the NormalizationResult from the persisted repository.
      3. analyze(result) -> deterministic list[Finding].
      4. Map each Finding (device_id + rule_uuid) -> PolicyRule.rule_id and write
         a RuleAnomaly row with the full output contract.
      5. Finalize the log (status=completed, findings_count).
    """
    device_ids = [device_id] if device_id is not None else None
    scope_type = "device" if device_id is not None else "all"

    db = SessionLocal()
    run: Optional[models.AnomalyExecutionLog] = None
    try:
        run = models.AnomalyExecutionLog(
            scope_type=scope_type,
            scope_id=device_id,
            status="running",
            findings_count=0,
            engine_version=ENGINE_VERSION,
        )
        db.add(run)
        db.flush()  # assign run_id without committing the whole transaction yet

        result = load_normalized_result(db, device_ids=device_ids)
        findings = analyze(result)

        index = _rule_index(db, device_ids)

        inserted = 0
        skipped = 0
        for f in findings:
            rule_id = index.get((f.device_id, f.rule_uuid))
            if rule_id is None:
                # Finding references a rule not present in the persisted repository
                # (e.g. cross-device scope mismatch). Skip rather than guess.
                skipped += 1
                logger.warning(
                    "Anomaly %s references unknown rule device=%s uuid=%s; skipped.",
                    f.anomaly_type, f.device_id, f.rule_uuid,
                )
                continue

            related_rule_id = None
            if f.related_rule_uuid is not None:
                rel_dev = f.related_device_id if f.related_device_id is not None else f.device_id
                related_rule_id = index.get((rel_dev, f.related_rule_uuid))

            db.add(models.RuleAnomaly(
                rule_id=rule_id,
                related_rule_id=related_rule_id,
                anomaly_type=f.anomaly_type,
                severity_level=f.severity,
                confidence=f.confidence,
                description=f.description,
                evidence=f.evidence,
                recommendation=f.recommendation,
                detection_mode=f.detection_mode,
                analysis_run_id=run.run_id,
                status="open",
            ))
            inserted += 1

        run.status = "completed"
        run.findings_count = inserted
        run.completed_at = utcnow()
        db.commit()

        logger.info(
            "Anomaly analysis run %s (scope=%s id=%s) completed: %d findings inserted, %d skipped.",
            run.run_id, scope_type, device_id, inserted, skipped,
        )

        # Lifecycle step 8 (V6 §11): trigger risk recalculation for this run.
        # Best-effort — a risk failure must never fail the anomaly analysis.
        try:
            from services.risk.runner import run_risk
            risk_summary = run_risk(db, run.run_id)
            logger.info("Risk recalculated for run %s: tiers=%s",
                        run.run_id, risk_summary.get("tier_counts"))
        except Exception as risk_exc:  # noqa: BLE001
            logger.warning("Risk recalculation failed for run %s: %s", run.run_id, risk_exc)

        return {
            "status": "completed",
            "run_id": run.run_id,
            "findings_count": inserted,
            "skipped": skipped,
        }

    except Exception as exc:  # noqa: BLE001 - record failure on the run log
        logger.exception("Anomaly analysis failed (scope=%s id=%s): %s", scope_type, device_id, exc)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        # Best-effort: mark the run failed in a fresh transaction.
        if run is not None and run.run_id is not None:
            try:
                failed = (
                    db.query(models.AnomalyExecutionLog)
                    .filter(models.AnomalyExecutionLog.run_id == run.run_id)
                    .first()
                )
                if failed is not None:
                    failed.status = "failed"
                    failed.completed_at = utcnow()
                    failed.error_log = {"error": str(exc)}
                    db.commit()
            except Exception:  # noqa: BLE001
                db.rollback()
        return {"status": "failed", "error": "internal_error"}
    finally:
        db.close()
