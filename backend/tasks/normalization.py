"""Celery normalization task (Volume 4).

Runs on the dedicated ``normalization`` queue. Replays the raw artifacts stored
by the acquisition job, parses them into vendor-tagged parser models, normalizes
those into the canonical model, persists the canonical repository (Schema v4),
and finally chains the deterministic anomaly analysis for the device.

This task NEVER touches the live firewall and NEVER stores secrets — it operates
purely on previously stored raw artifacts on disk.
"""
from __future__ import annotations

from celery_app import celery
from core.logging import get_logger
from models import models
from models.models import get_db
from services.acquisition import storage
from services.acquisition.models import ARTIFACT_MANIFEST
from services.parsing import parse_artifacts
from services.normalization import normalize_payloads
from services.normalization.persist import persist_result

logger = get_logger(__name__)
SessionLocal = get_db()


@celery.task(name="normalization.normalize_device", queue="normalization", bind=True)
def normalize_device(self, job_id: int) -> dict:
    """Parse + normalize + persist the artifacts of acquisition ``job_id``.

    Steps:
      1. Load the acquisition job and its device + raw artifact rows.
      2. Read each raw artifact file from disk (storage.load_artifact).
      3. parse_artifacts(vendor_type, device_id, {type: text}) -> ParsedDevicePayload.
      4. normalize_payloads([payload]) -> NormalizationResult (pure).
      5. persist_result(db, result, [payload]) -> canonical repository (idempotent).
      6. enqueue analysis: run_anomaly_analysis_task.delay(device_id=...).
    """
    db = SessionLocal()
    try:
        job = (
            db.query(models.AcquisitionJob)
            .filter(models.AcquisitionJob.job_id == job_id)
            .first()
        )
        if not job:
            logger.error("Normalization: acquisition job %s not found", job_id)
            return {"job_id": job_id, "status": "failed", "error": "job_not_found"}

        device = (
            db.query(models.FirewallDevice)
            .filter(models.FirewallDevice.device_id == job.device_id)
            .first()
        )
        if not device:
            logger.error("Normalization: device %s not found for job %s", job.device_id, job_id)
            return {"job_id": job_id, "status": "failed", "error": "device_not_found"}

        device_id = device.device_id
        vendor_type = (job.vendor_type or getattr(device, "vendor_type", None) or "").lower()

        artifacts_rows = (
            db.query(models.RawArtifact)
            .filter(models.RawArtifact.job_id == job_id)
            .all()
        )
        if not artifacts_rows:
            logger.error("Normalization: no raw artifacts for job %s", job_id)
            return {"job_id": job_id, "status": "failed", "error": "no_artifacts"}

        # Build {artifact_type: file_text}, skipping the acquisition manifest.
        artifacts: dict[str, str] = {}
        for art in artifacts_rows:
            if art.type == ARTIFACT_MANIFEST:
                continue
            if not art.path:
                continue
            try:
                artifacts[art.type] = storage.load_artifact(art.path)
            except OSError as exc:
                logger.error(
                    "Normalization: failed to read artifact %s (%s) for job %s: %s",
                    art.type, art.path, job_id, exc,
                )

        if not artifacts:
            logger.error("Normalization: no readable artifacts for job %s", job_id)
            return {"job_id": job_id, "status": "failed", "error": "no_readable_artifacts"}

        # Parse -> normalize (pure) -> persist (idempotent).
        payload = parse_artifacts(vendor_type, device_id, artifacts)
        result = normalize_payloads([payload])
        counts = persist_result(db, result, [payload])

        logger.info(
            "Normalization for job %s device %s completed: %s",
            job_id, device_id, counts,
        )

        # Chain deterministic anomaly analysis for this device.
        # Imported lazily to avoid import-time coupling across task modules.
        from tasks.anomaly import run_anomaly_analysis_task
        run_anomaly_analysis_task.delay(device_id=device_id)

        return {
            "job_id": job_id,
            "device_id": device_id,
            "status": "completed",
            "counts": counts,
        }

    except Exception:  # noqa: BLE001 - record + surface safely, never leak internals
        logger.exception("Unexpected normalization failure for job %s", job_id)
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {"job_id": job_id, "status": "failed", "error": "internal_error"}
    finally:
        db.close()
