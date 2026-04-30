from sqlalchemy.orm import Session
from models.models import get_db

# Create the session factory once at module level
SessionLocal = get_db()


def get_db_session():
    """
    FastAPI dependency that provides a database session.
    Yields a SQLAlchemy Session and ensures it is closed after the request.
    Usage: db: Session = Depends(get_db_session)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
