from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import (
    VendorCreate, VendorUpdate, VendorResponse,
)

router = APIRouter(prefix="/api/v1/vendors", tags=["Vendors"])


@router.get("/", response_model=List[VendorResponse])
def list_vendors(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.Vendor, skip=skip, limit=limit)


@router.get("/{vendor_id}", response_model=VendorResponse)
def get_vendor(vendor_id: int, db: Session = Depends(get_db_session)):
    vendor = crud.get_by_id(db, models.Vendor, "vendor_id", vendor_id)
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return vendor


@router.post("/", response_model=VendorResponse, status_code=201)
def create_vendor(vendor: VendorCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.Vendor, vendor.model_dump())


@router.patch("/{vendor_id}", response_model=VendorResponse)
def update_vendor(vendor_id: int, vendor: VendorUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.Vendor, "vendor_id", vendor_id, vendor.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return updated


@router.delete("/{vendor_id}", status_code=204)
def delete_vendor(vendor_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.Vendor, "vendor_id", vendor_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return None
