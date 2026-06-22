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
from api.routes import external_nodes, threat_feeds, api_tokens, audit_logs, saved_searches
from api.routes import jobs
from api.routes import anomalies

from contextlib import asynccontextmanager

from core.config import settings
from core.logging import configure_logging

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Schema is owned by Alembic migrations (run `alembic upgrade head` at deploy;
    # the container entrypoint does this). create_all is intentionally retired here
    # per ADR LFPM-IMPL-002 / Volume 5 §14 (no destructive auto-sync).
    configure_logging()
    yield
    # Shutdown logic can go here

app = FastAPI(
    title="LuminaFPM Backend API",
    description="API for the LuminaFPM Firewall Policy Management application",
    version="0.1.0",
    lifespan=lifespan
)

# Configure CORS — restricted origin allowlist (V12 Table 5). A wildcard origin
# with credentials is invalid/unsafe; origins come from CORS_ALLOWED_ORIGINS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins or ["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database session factory
SessionLocal = get_db()

# Mount the Threat Intel router
app.include_router(threat_intel_router)


# =====================================================================
# CORE ENDPOINTS
# =====================================================================
@app.get("/")
def read_root():
    return {"message": "Welcome to the LuminaFPM API!"}


app.include_router(vendors.router)
app.include_router(devices.router)
app.include_router(network_objects.router)
app.include_router(rules.router)
app.include_router(external_nodes.router)
app.include_router(threat_feeds.router)
app.include_router(api_tokens.router)
app.include_router(audit_logs.router)
app.include_router(saved_searches.router)
app.include_router(jobs.router)
app.include_router(anomalies.router)

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

# NOTE: routers are registered once above (lines ~60-68). The previous duplicate
# include_router block here was removed (it double-registered vendors/devices/
# rules/network_objects). See docs/CODEBASE_GAP_ANALYSIS.md.
