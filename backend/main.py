from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from datetime import datetime
from models.database import engine, get_db
from models.threat import ThreatIndicator
from models.user_alert import UserAlert
from scheduler.jobs import start_scheduler, run_all_ingestors

ThreatIndicator.metadata.create_all(bind=engine)
UserAlert.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatView API", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup_event():
    start_scheduler()
    print("ThreatView API started successfully.")
