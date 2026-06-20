from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import SavedSearchCreate, SavedSearchUpdate, SavedSearchResponse

router = APIRouter(prefix="/api/v1/saved-searches", tags=["Saved Searches"])

@router.get("/", response_model=List[SavedSearchResponse])
def list_saved_searches(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.SavedSearch, skip=skip, limit=limit)

@router.get("/{search_id}", response_model=SavedSearchResponse)
def get_saved_search(search_id: int, db: Session = Depends(get_db_session)):
    search = crud.get_by_id(db, models.SavedSearch, "search_id", search_id)
    if not search:
        raise HTTPException(status_code=404, detail="Search not found")
    return search

@router.post("/", response_model=SavedSearchResponse, status_code=201)
def create_saved_search(search: SavedSearchCreate, db: Session = Depends(get_db_session)):
    return crud.create_saved_search(db, search.model_dump())

@router.patch("/{search_id}", response_model=SavedSearchResponse)
def update_saved_search(search_id: int, search: SavedSearchUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.SavedSearch, "search_id", search_id, search.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Search not found")
    return updated

@router.delete("/{search_id}", status_code=204)
def delete_saved_search(search_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_saved_search(db, search_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Search not found")
    return None
