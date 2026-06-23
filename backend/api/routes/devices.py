from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from typing import List, Optional

from api.deps import get_db_session
from core.config import settings
from core.logging import get_logger
from models import models, crud
from services import credentials
from services.acquisition import get_connector, resolve_device_vendor_type
from services.acquisition.base import ConnectorConfig
from services.acquisition.errors import AcquisitionError, UnsupportedVendorError
from schemas.pydantic_schemas import (
    DeviceCreate, DeviceUpdate, DeviceResponse,
    AdminDeviceAssignmentCreate, AdminDeviceAssignmentResponse,
    AdministratorCreate, AdministratorUpdate, AdministratorResponse,
)

logger = get_logger(__name__)
router = APIRouter(prefix="/api/v1/devices", tags=["Firewall Devices"])


class CredentialIn(BaseModel):
    """Write-only credential payload (V3 §6.2). The secret is encrypted at rest
    and never returned. auth_type: fortigate_api_token | panos_api_key | panos_userpass."""
    auth_type: str = Field(..., description="fortigate_api_token | panos_api_key | panos_userpass")
    secret: str = Field(..., description="API token / API key / 'user:password' — stored encrypted")


# =====================================================================
# FIREWALL DEVICE ENDPOINTS
# =====================================================================

@router.get("/", response_model=List[DeviceResponse])
def list_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.FirewallDevice, skip=skip, limit=limit)

# =====================================================================
# ADMINISTRATOR ENDPOINTS (Co-located since admins manage devices)
# =====================================================================

@router.get("/admins/all", response_model=List[AdministratorResponse], tags=["Administrators"])
def list_administrators(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.Administrator, skip=skip, limit=limit)

@router.get("/admins/{admin_id}", response_model=AdministratorResponse, tags=["Administrators"])
def get_administrator(admin_id: int, db: Session = Depends(get_db_session)):
    admin = crud.get_by_id(db, models.Administrator, "admin_id", admin_id)
    if not admin:
        raise HTTPException(status_code=404, detail="Administrator not found")
    return admin

@router.post("/admins/", response_model=AdministratorResponse, status_code=201, tags=["Administrators"])
def create_administrator(admin: AdministratorCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.Administrator, admin.model_dump())

@router.patch("/admins/{admin_id}", response_model=AdministratorResponse, tags=["Administrators"])
def update_administrator(admin_id: int, admin: AdministratorUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.Administrator, "admin_id", admin_id, admin.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Administrator not found")
    return updated

@router.delete("/admins/{admin_id}", status_code=204, tags=["Administrators"])
def delete_administrator(admin_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.Administrator, "admin_id", admin_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Administrator not found")
    return None


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device(device_id: int, db: Session = Depends(get_db_session)):
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


@router.post("/", response_model=DeviceResponse, status_code=201)
def create_device(device: DeviceCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.FirewallDevice, device.model_dump())


@router.patch("/{device_id}", response_model=DeviceResponse)
def update_device(device_id: int, device: DeviceUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.FirewallDevice, "device_id", device_id, device.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found")
    return updated


@router.delete("/{device_id}", status_code=204)
def delete_device(device_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.FirewallDevice, "device_id", device_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Device not found")
    return None


# =====================================================================
# ACQUISITION (V3) — encrypted credentials, connection test, async poll
# The old synchronous mock /sync endpoint was removed (it bypassed the async
# acquisition pipeline, raw-artifact capture, parsing, and normalization).
# =====================================================================

@router.post("/{device_id}/credentials", status_code=204, tags=["Acquisition"])
def set_device_credential(device_id: int, body: CredentialIn, db: Session = Depends(get_db_session)):
    """Create/rotate the encrypted firewall credential. Returns no secret."""
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    try:
        credentials.set_credential(db, device_id, body.auth_type, body.secret)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return None


def _connector_config(db: Session, device) -> ConnectorConfig:
    cred = credentials.get_decrypted_secret(db, device.device_id)
    if not cred:
        raise HTTPException(status_code=409, detail="No credential configured for device")
    auth_type, secret = cred
    vendor_type = resolve_device_vendor_type(device)
    if not vendor_type:
        raise HTTPException(status_code=422, detail="Device vendor_type could not be determined")
    scheme = "http" if device.management_ip in settings.firewall_insecure_http_hosts else "https"
    return ConnectorConfig(
        device_id=device.device_id,
        vendor_type=vendor_type,
        management_ip=device.management_ip,
        secret=secret,
        auth_type=auth_type,
        verify_tls=settings.firewall_tls_verify,
        timeout_seconds=min(15, settings.acquisition_timeout_seconds),
        scheme=scheme,
    )


@router.post("/{device_id}/test-connection", tags=["Acquisition"])
def test_device_connection(device_id: int, db: Session = Depends(get_db_session)):
    """Validate API connectivity (read-only). Returns status only — never the secret."""
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    config = _connector_config(db, device)
    try:
        connector = get_connector(config)
        connector.authenticate()
        ok = connector.validate_connection()
        return {"device_id": device_id, "ok": bool(ok), "detail": "connection successful"}
    except UnsupportedVendorError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except AcquisitionError as exc:
        # Safe message (connectors never include secrets in messages).
        return {"device_id": device_id, "ok": False, "error_code": exc.code, "detail": str(exc)}


@router.post("/{device_id}/poll", status_code=202, tags=["Acquisition"])
def poll_device(device_id: int, db: Session = Depends(get_db_session)):
    """Trigger an asynchronous read-only acquisition job (V3 §7). Returns a job id to poll."""
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    if not credentials.has_credential(db, device_id):
        raise HTTPException(status_code=409, detail="No credential configured for device")

    job = models.AcquisitionJob(
        device_id=device_id,
        vendor_type=resolve_device_vendor_type(device),
        requested_by="api",
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Dispatch to the acquisition queue (never run polling in the request cycle).
    from tasks.acquisition import poll_device as poll_task
    poll_task.delay(job_id=job.job_id)

    return {"job_id": job.job_id, "status": "queued", "device_id": device_id}


# =====================================================================
# ADMIN-DEVICE ASSIGNMENT (Nested under /devices/{device_id}/admins)
# =====================================================================

@router.get("/{device_id}/admins", response_model=List[AdminDeviceAssignmentResponse])
def list_device_admins(device_id: int, db: Session = Depends(get_db_session)):
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return db.query(models.AdminDeviceAssignment).filter(
        models.AdminDeviceAssignment.device_id == device_id
    ).all()


@router.post("/{device_id}/admins", response_model=AdminDeviceAssignmentResponse, status_code=201)
def assign_admin_to_device(device_id: int, assignment: AdminDeviceAssignmentCreate, db: Session = Depends(get_db_session)):
    device = crud.get_by_id(db, models.FirewallDevice, "device_id", device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    data = assignment.model_dump()
    data["device_id"] = device_id  # ensure consistency with URL
    return crud.insert_data(db, models.AdminDeviceAssignment, data)


@router.delete("/{device_id}/admins/{admin_id}", status_code=204)
def remove_admin_from_device(device_id: int, admin_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data_composite(db, models.AdminDeviceAssignment, {
        "admin_id": admin_id, "device_id": device_id
    })
    if not deleted:
        raise HTTPException(status_code=404, detail="Assignment not found")
    return None


