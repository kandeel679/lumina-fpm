from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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



@app.get("/")
def read_root():
    return {"message": "Welcome to the LuminaFPM API!"}

@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/allpolicies")
def allpolicies():
    
    return {"message": "Welcome to the LuminaFPM API!"}
    
# if __name__ == "__main__":
#     import uvicorn
#     # This allows you to run the file directly during development
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
