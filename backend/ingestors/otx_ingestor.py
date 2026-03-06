import requests, os
from datetime import datetime
from dotenv import load_dotenv
from models.database import SessionLocal
from models.threat import ThreatIndicator

load_dotenv()
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

def fetch_otx_pulses():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        print("[OTX] Fetching latest pulses...")
        response = requests.get(f"{OTX_BASE_URL}/pulses/subscribed", headers=headers, params={"limit": 20}, timeout=30)
        response.raise_for_status()
        pulses = response.json().get("results", [])
        print(f"[OTX] Got {len(pulses)} pulses")
        return pulses
    except Exception as e:
        print(f"[OTX] Error: {e}")
        return []

def normalize_otx_indicator(indicator, pulse):
    type_map = {"IPv4": "ip", "IPv6": "ip", "domain": "domain", "hostname": "domain", "URL": "url", "FileHash-MD5": "hash", "FileHash-SHA256": "hash"}
    indicator_type = type_map.get(indicator.get("type"), "unknown")
    if indicator_type == "unknown":
        return None
    tags = pulse.get("tags", [])
    threat_type = "malware"
    if any(t.lower() in ["phishing", "phish"] for t in tags): threat_type = "phishing"
    elif any(t.lower() in ["ransomware"] for t in tags): threat_type = "ransomware"
    elif any(t.lower() in ["botnet", "c2"] for t in tags): threat_type = "botnet"
    return {
        "indicator_type": indicator_type,
        "indicator_value": indicator.get("indicator", ""),
        "threat_type": threat_type,
        "confidence_score": min(pulse.get("TLP", 0) * 25, 100),
        "source": "otx",
        "country": indicator.get("country", None),
        "description": (pulse.get("description", "") or "")[:500],
        "tags": ",".join(tags[:10]),
        "first_seen": datetime.utcnow(),
        "last_seen": datetime.utcnow(),
    }

def run_otx_ingestion():
    pulses = fetch_otx_pulses()
    if not pulses: return
    db = SessionLocal()
    saved = skipped = 0
    try:
        for pulse in pulses:
            for ind in pulse.get("indicators", [])[:50]:
                normalized = normalize_otx_indicator(ind, pulse)
                if not normalized or not normalized["indicator_value"]:
                    skipped += 1
                    continue
                existing = db.query(ThreatIndicator).filter(
                    ThreatIndicator.indicator_value == normalized["indicator_value"],
                    ThreatIndicator.source == "otx"
                ).first()
                if not existing:
                    db.add(ThreatIndicator(**normalized))
                    saved += 1
                else:
                    existing.last_seen = datetime.utcnow()
                    skipped += 1
        db.commit()
        print(f"[OTX] Done — saved {saved} new, skipped {skipped} duplicates")
    except Exception as e:
        db.rollback()
        print(f"[OTX] DB error: {e}")
    finally:
        db.close()
