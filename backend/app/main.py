from dotenv import load_dotenv
from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")
from fastapi import FastAPI
from app.database.db import engine
from app.database import models
from app.routers import logs, network_events
from app.routers import incidents
from fastapi.middleware.cors import CORSMiddleware
models.Base.metadata.create_all(bind=engine)
from app.routers import live_capture 
from app.routers import evaluation
from app.routers import threat_intel, reports

app = FastAPI(title="AI Threat Disruption System")

app.include_router(live_capture.router)
app.include_router(logs.router)
app.include_router(network_events.router)
app.include_router(incidents.router)
app.include_router(evaluation.router)
app.include_router(threat_intel.router)
app.include_router(reports.router)
@app.get("/")
def root():
    return {"status": "Backend running"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # safe for dev
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)