from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import (
    NetworkObjectCreate, NetworkObjectUpdate, NetworkObjectResponse,
)

router = APIRouter(prefix="/api/v1/network-objects", tags=["Network Objects"])


@router.get("/", response_model=List[NetworkObjectResponse])
def list_network_objects(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.NetworkObject, skip=skip, limit=limit)


@router.get("/{object_id}", response_model=NetworkObjectResponse)
def get_network_object(object_id: int, db: Session = Depends(get_db_session)):
    obj = crud.get_by_id(db, models.NetworkObject, "object_id", object_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Network object not found")
    return obj


@router.post("/", response_model=NetworkObjectResponse, status_code=201)
def create_network_object(network_object: NetworkObjectCreate, db: Session = Depends(get_db_session)):
    return crud.insert_data(db, models.NetworkObject, network_object.model_dump())


@router.patch("/{object_id}", response_model=NetworkObjectResponse)
def update_network_object(object_id: int, network_object: NetworkObjectUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.NetworkObject, "object_id", object_id, network_object.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Network object not found")
    return updated


@router.delete("/{object_id}", status_code=204)
def delete_network_object(object_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_data(db, models.NetworkObject, "object_id", object_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Network object not found")
    return None
