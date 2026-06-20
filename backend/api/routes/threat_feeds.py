from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from api.deps import get_db_session
from models import models, crud
from schemas.pydantic_schemas import ThreatFeedCreate, ThreatFeedUpdate, ThreatFeedResponse

router = APIRouter(prefix="/api/v1/threat-feeds", tags=["Threat Feeds"])

@router.get("/", response_model=List[ThreatFeedResponse])
def list_threat_feeds(skip: int = 0, limit: int = 100, db: Session = Depends(get_db_session)):
    return crud.get_all(db, models.ThreatFeed, skip=skip, limit=limit)

@router.get("/{feed_id}", response_model=ThreatFeedResponse)
def get_threat_feed(feed_id: int, db: Session = Depends(get_db_session)):
    feed = crud.get_by_id(db, models.ThreatFeed, "feed_id", feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed

@router.post("/", response_model=ThreatFeedResponse, status_code=201)
def create_threat_feed(feed: ThreatFeedCreate, db: Session = Depends(get_db_session)):
    return crud.create_threat_feed(db, feed.model_dump())

@router.patch("/{feed_id}", response_model=ThreatFeedResponse)
def update_threat_feed(feed_id: int, feed: ThreatFeedUpdate, db: Session = Depends(get_db_session)):
    updated = crud.update_data(db, models.ThreatFeed, "feed_id", feed_id, feed.model_dump(exclude_unset=True))
    if not updated:
        raise HTTPException(status_code=404, detail="Feed not found")
    return updated

@router.delete("/{feed_id}", status_code=204)
def delete_threat_feed(feed_id: int, db: Session = Depends(get_db_session)):
    deleted = crud.delete_threat_feed(db, feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Feed not found")
    return None
