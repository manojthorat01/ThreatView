from apscheduler.schedulers.background import BackgroundScheduler
from ingestors.otx_ingestor import run_otx_ingestion
from ingestors.abuseipdb_ingestor import run_abuseipdb_ingestion

def run_all_ingestors():
    print("\n⚡ Running all ingestors...")
    run_otx_ingestion()
    run_abuseipdb_ingestion()
    print("✅ All ingestors complete\n")

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_all_ingestors, "interval", hours=1, id="threat_ingestion")
    scheduler.start()
    print("⏰ Scheduler started — runs every hour")
    return scheduler
