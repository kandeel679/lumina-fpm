from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import (
    DeviceCreate, DeviceUpdate, DeviceResponse,
    AdminDeviceAssignmentCreate, AdminDeviceAssignmentResponse,
    AdministratorCreate, AdministratorUpdate, AdministratorResponse,
)

router = APIRouter(prefix="/api/v1/devices", tags=["Firewall Devices"])


# =====================================================================
# FIREWALL DEVICE ENDPOINTS
# =====================================================================

@router.get("/", response_model=List[DeviceResponse])
def list_devices(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.FirewallDevice, skip=skip, limit=limit)


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
