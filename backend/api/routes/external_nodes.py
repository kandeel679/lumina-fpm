from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import ExternalNodeCreate, ExternalNodeUpdate, ExternalNodeResponse

router = APIRouter(prefix="/api/v1/external-nodes", tags=["External Nodes"])

@router.get("/", response_model=List[ExternalNodeResponse])
def list_external_nodes(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.ExternalNode, skip=skip, limit=limit)

@router.get("/{node_id}", response_model=ExternalNodeResponse)
def get_external_node(node_id: int, db: Session = Depends(get_db_session)):
    node = crud.get_by_id(db, models.ExternalNode, "node_id", node_id)
    if not node:
        raise HTTPException(status_code=404, detail="Node not found")
    return node

@router.post("/", response_model=ExternalNodeResponse, status_code=201)
def create_external_node(node: ExternalNodeCreate, db: Session = Depends(get_db_session)):
    return crud.create_external_node(db, node.model_dump())

@router.patch("/{node_id}", response_model=ExternalNodeResponse)
def update_external_node(node_id: int, node: ExternalNodeUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.ExternalNode, "node_id", node_id, node.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Node not found")
    return updated

@router.delete("/{node_id}", status_code=204)
def delete_external_node(node_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_external_node(db, node_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Node not found")
    return None
