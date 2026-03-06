import requests, os
from datetime import datetime
from dotenv import load_dotenv
from models.database import SessionLocal
from models.threat import ThreatIndicator

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

def fetch_abuseipdb_blacklist():
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        print("[AbuseIPDB] Fetching blacklist...")
        response = requests.get(f"{ABUSEIPDB_BASE_URL}/blacklist", headers=headers, params={"confidenceMinimum": 90, "limit": 100}, timeout=30)
        response.raise_for_status()
        ips = response.json().get("data", [])
        print(f"[AbuseIPDB] Got {len(ips)} IPs")
        return ips
    except Exception as e:
        print(f"[AbuseIPDB] Error: {e}")
        return []

def run_abuseipdb_ingestion():
    ip_list = fetch_abuseipdb_blacklist()
    if not ip_list: return
    db = SessionLocal()
    saved = skipped = 0
    try:
        for ip_data in ip_list:
            value = ip_data.get("ipAddress", "")
            if not value: continue
            existing = db.query(ThreatIndicator).filter(
                ThreatIndicator.indicator_value == value,
                ThreatIndicator.source == "abuseipdb"
            ).first()
            if not existing:
                db.add(ThreatIndicator(
                    indicator_type="ip", indicator_value=value,
                    threat_type="abuse",
                    confidence_score=float(ip_data.get("abuseConfidenceScore", 0)),
                    source="abuseipdb",
                    country=ip_data.get("countryCode", None),
                    description=f"Total reports: {ip_data.get('totalReports', 0)}",
                    tags="blacklisted,high-confidence",
                    first_seen=datetime.utcnow(), last_seen=datetime.utcnow(),
                ))
                saved += 1
            else:
                existing.confidence_score = float(ip_data.get("abuseConfidenceScore", 0))
                existing.last_seen = datetime.utcnow()
                skipped += 1
        db.commit()
        print(f"[AbuseIPDB] Done — saved {saved} new, updated {skipped} existing")
    except Exception as e:
        db.rollback()
        print(f"[AbuseIPDB] DB error: {e}")
    finally:
        db.close()
