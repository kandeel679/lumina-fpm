from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from models import crud
from models.models import get_db
from sqlalchemy import text

app = FastAPI(
    title="LuminaFPM Backend API",
    description="API for the LuminaFPM application",
    version="0.0.1"
)

# Configure CORS to allow communication with the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
SessionLocal = get_db()


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
    
# if __name__ == "__main__":
#     import uvicorn
#     # This allows you to run the file directly during development
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
