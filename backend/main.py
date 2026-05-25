from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import crud
from models.models import get_db, Base
from sqlalchemy import text

# Import threat-intel DB models so they register with Base.metadata
from services.lumina_threat_intel import db_models as ti_models  # noqa: F401
from services.lumina_threat_intel.api import router as threat_intel_router

# Ensure Celery app is initialized (needed for .delay() calls from API)
import celery_app as _celery_app  # noqa: F401

from models.models import get_db
from models import crud, models
from api.routes import vendors, devices, rules, network_objects

app = FastAPI(
    title="LuminaFPM Backend API",
    description="API for the LuminaFPM Firewall Policy Management application",
    version="0.1.0"
)

# Configure CORS to allow communication with the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database session factory
SessionLocal = get_db()

# Mount the Threat Intel router
app.include_router(threat_intel_router)

# Create threat-intel tables on startup (matches existing pattern in crud.py)
@app.on_event("startup")
def create_threat_intel_tables():
    """Auto-create threat-intel tables if they don't exist."""
    from models.models import get_db as _get_db
    from sqlalchemy import create_engine
    from os import getenv
    engine = create_engine(getenv("DATABASE_URL", ""), echo=False)
    Base.metadata.create_all(bind=engine)


# =====================================================================
# STARTUP EVENT — Auto-create tables if they don't exist
# =====================================================================
@app.on_event("startup")
def on_startup():
    db = SessionLocal()
    try:
        engine = db.get_bind()
        crud.create_database(engine)
    finally:
        db.close()


# =====================================================================
# CORE ENDPOINTS
# =====================================================================
@app.get("/")
def read_root():
    return {"message": "Welcome to the LuminaFPM API!"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/checkdbconnection")
def checkdbconnection():
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"message": "Database connection successful"}
    except Exception as e:
        return {"message": f"Database connection failed: {e}"}
    finally:
        db.close()


# =====================================================================
# REGISTER API ROUTERS
# =====================================================================
app.include_router(vendors.router)
app.include_router(devices.router)
app.include_router(rules.router)
app.include_router(network_objects.router)
