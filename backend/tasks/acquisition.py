"""Celery acquisition tasks (V3 §17).

Runs read-only firewall extraction on the dedicated ``acquisition`` queue, never
inside the FastAPI request cycle. Persists raw artifacts, updates the
acquisition_job lifecycle, records firmware/last_poll on the device, and (next
phase) enqueues the parser.
"""
from __future__ import annotations

import time

from celery_app import celery
from core.config import settings
from core.logging import get_logger
from models import models
from models.models import get_db
from services import credentials
from services.acquisition import get_connector, resolve_device_vendor_type
from services.acquisition.base import ConnectorConfig
from services.acquisition.errors import AcquisitionError
from services.acquisition.models import AcquisitionStatus
from services.acquisition import storage

logger = get_logger(__name__)
SessionLocal = get_db()

# Map normalized connector error codes → acquisition_job status (V3 Table 9/23).
_ERROR_TO_STATUS = {
    "AUTH_FAILED": "authentication_failed",
    "AUTHZ_FAILED": "authorization_failed",
    "CONNECTION_FAILED": "connection_failed",
    "TIMEOUT": "timeout",
    "TLS_FAILED": "failed",
    "RATE_LIMITED": "rate_limited",
    "UNSUPPORTED_ENDPOINT": "failed",
    "MALFORMED_RESPONSE": "failed",
    "PARTIAL_DATA": "partial_success",
    "UNSUPPORTED_VENDOR": "failed",
}


@celery.task(name="acquisition.poll_device", queue="acquisition", bind=True)
def poll_device(self, job_id: int) -> dict:
    """Execute the acquisition job identified by ``job_id``."""
    db = SessionLocal()
    started = time.time()
    try:
        job = db.query(models.AcquisitionJob).filter(models.AcquisitionJob.job_id == job_id).first()
        if not job:
            logger.error("Acquisition job %s not found", job_id)
            return {"job_id": job_id, "status": "failed", "error": "job_not_found"}

        device = (
            db.query(models.FirewallDevice)
            .filter(models.FirewallDevice.device_id == job.device_id)
            .first()
        )
        if not device:
            _fail_job(db, job, "failed", "CONNECTION_FAILED", "Device not found")
            return {"job_id": job_id, "status": "failed"}

        cred = credentials.get_decrypted_secret(db, device.device_id)
        if not cred:
            _fail_job(db, job, "authentication_failed", "AUTH_FAILED",
                      "No credential configured for device")
            return {"job_id": job_id, "status": "authentication_failed"}
        auth_type, secret = cred

        vendor_type = resolve_device_vendor_type(device)
        if not vendor_type:
            _fail_job(db, job, "failed", "UNSUPPORTED_VENDOR",
                      "Device vendor_type could not be determined")
            return {"job_id": job_id, "status": "failed"}
        job.status = "running"
        job.started_at = models.utcnow()
        job.vendor_type = vendor_type
        db.commit()

        scheme = (
            "http"
            if (getattr(device, "use_http", False)
                or device.management_ip in settings.firewall_insecure_http_hosts)
            else "https"
        )
        config = ConnectorConfig(
            device_id=device.device_id,
            vendor_type=vendor_type,
            management_ip=device.management_ip,
            secret=secret,
            auth_type=auth_type,
            verify_tls=settings.firewall_tls_verify,
            timeout_seconds=settings.acquisition_timeout_seconds,
            scheme=scheme,
        )
        connector = get_connector(config)
        bundle = connector.collect()

        # Persist raw artifacts + manifest (replayable).
        artifacts = storage.store_bundle(job_id, bundle)
        for meta in artifacts:
            db.add(models.RawArtifact(
                job_id=job_id, device_id=device.device_id,
                type=meta["type"], path=meta["path"], sha256=meta["sha256"],
            ))

        # Update device freshness + firmware.
        device.last_poll_time = models.utcnow()
        device.status = "online"
        if bundle.firmware_version:
            device.firmware_version = bundle.firmware_version

        job.status = (
            "partial_success" if bundle.status == AcquisitionStatus.PARTIAL_SUCCESS else "success"
        )
        job.connector_version = bundle.connector_version
        job.completed_at = models.utcnow()
        job.duration_ms = int((time.time() - started) * 1000)
        db.commit()

        logger.info(
            "Acquisition job %s for device %s completed: %s (%d artifacts)",
            job_id, device.device_id, job.status, len(artifacts),
        )
        # Notify (best-effort): acquisition completed.
        from services.notifications import emit_safe
        _fw = bundle.firmware_version
        emit_safe(
            db,
            "success" if job.status == "success" else "warning",
            "acquisition",
            f"Acquisition {job.status}: {device.hostname}",
            body=(f"{len(artifacts)} artifact(s) collected"
                  + (f"; firmware {_fw}" if _fw else "") + "."),
            link="#/",
        )
        # Chain the normalization pipeline (parse -> normalize -> persist -> analyze).
        # Enqueued on success and partial_success so usable data is still processed.
        if job.status in ("success", "partial_success"):
            from tasks.normalization import normalize_device
            normalize_device.delay(job_id)
        return {"job_id": job_id, "status": job.status, "artifacts": len(artifacts)}

    except AcquisitionError as exc:
        status = _ERROR_TO_STATUS.get(exc.code, "failed")
        _fail_job(db, _get_job(db, job_id), status, exc.code, str(exc))
        return {"job_id": job_id, "status": status, "error_code": exc.code}
    except Exception as exc:  # noqa: BLE001 - record + surface safely
        logger.exception("Unexpected acquisition failure for job %s", job_id)
        _fail_job(db, _get_job(db, job_id), "failed", "INTERNAL", "Internal acquisition error")
        return {"job_id": job_id, "status": "failed"}
    finally:
        db.close()


def _get_job(db, job_id):
    return db.query(models.AcquisitionJob).filter(models.AcquisitionJob.job_id == job_id).first()


def _fail_job(db, job, status: str, error_code: str, message: str) -> None:
    if not job:
        return
    job.status = status
    job.error_code = error_code
    job.error_message = message  # already secret-safe (no secrets in connector messages)
    job.completed_at = models.utcnow()
    db.commit()
    # Notify (best-effort): acquisition failed.
    from services.notifications import emit_safe
    emit_safe(
        db, "critical", "acquisition",
        f"Acquisition failed (device {job.device_id})",
        body=f"{error_code}: {message}",
        link="#/",
    )
