from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from models.models import get_db
from models import crud, models
from api.routes import vendors, devices, rules, network_objects, threat_intel

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
app.include_router(threat_intel.router)
