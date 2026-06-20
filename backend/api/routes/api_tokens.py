from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import APITokenCreate, APITokenUpdate, APITokenResponse

router = APIRouter(prefix="/api/v1/api-tokens", tags=["API Tokens"])

@router.get("/", response_model=List[APITokenResponse])
def list_api_tokens(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.APIToken, skip=skip, limit=limit)

@router.get("/{token_id}", response_model=APITokenResponse)
def get_api_token(token_id: int, db: Session = Depends(get_db_session)):
    token = crud.get_by_id(db, models.APIToken, "token_id", token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return token

@router.post("/", response_model=APITokenResponse, status_code=201)
def create_api_token(token: APITokenCreate, db: Session = Depends(get_db_session)):
    return crud.create_api_token(db, token.model_dump())

@router.patch("/{token_id}", response_model=APITokenResponse)
def update_api_token(token_id: int, token: APITokenUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.APIToken, "token_id", token_id, token.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Token not found")
    return updated

@router.delete("/{token_id}", status_code=204)
def delete_api_token(token_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_api_token(db, token_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Token not found")
    return None
