from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from models.database import engine, get_db
from models.threat import ThreatIndicator
from scheduler.jobs import start_scheduler, run_all_ingestors

ThreatIndicator.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatView API", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])
@app.on_event("startup")
def startup_event():
    print("ThreatView starting up...")
    run_all_ingestors()
    start_scheduler()

@app.get("/")
def root():
    return {"message": "ThreatView API is running", "status": "ok"}

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(ThreatIndicator).count()
    by_type = db.query(ThreatIndicator.threat_type, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.threat_type).all()
    by_country = db.query(ThreatIndicator.country, func.count(ThreatIndicator.id)).filter(ThreatIndicator.country != None).group_by(ThreatIndicator.country).order_by(func.count(ThreatIndicator.id).desc()).limit(10).all()
    by_source = db.query(ThreatIndicator.source, func.count(ThreatIndicator.id)).group_by(ThreatIndicator.source).all()
    return {
        "total_indicators": total,
        "by_threat_type": [{"type": t, "count": c} for t, c in by_type],
        "top_countries": [{"country": c or "Unknown", "count": cnt} for c, cnt in by_country],
        "by_source": [{"source": s, "count": c} for s, c in by_source],
    }

@app.get("/api/indicators")
def get_indicators(skip: int = 0, limit: int = 50, threat_type: str = None, db: Session = Depends(get_db)):
    query = db.query(ThreatIndicator)
    if threat_type:
        query = query.filter(ThreatIndicator.threat_type == threat_type)
    total = query.count()
    items = query.order_by(ThreatIndicator.created_at.desc()).offset(skip).limit(limit).all()
    return {
        "total": total,
        "items": [{"id": i.id, "type": i.indicator_type, "value": i.indicator_value, "threat_type": i.threat_type, "confidence": i.confidence_score, "source": i.source, "country": i.country, "tags": i.tags, "created_at": str(i.created_at)} for i in items]
    }

@app.get("/api/search")
def search_indicator(q: str, db: Session = Depends(get_db)):
    results = db.query(ThreatIndicator).filter(ThreatIndicator.indicator_value.ilike(f"%{q}%")).limit(20).all()
    return {
        "query": q, "found": len(results),
        "results": [{"value": r.indicator_value, "type": r.indicator_type, "threat_type": r.threat_type, "confidence": r.confidence_score, "source": r.source, "country": r.country, "description": r.description} for r in results]
    }
