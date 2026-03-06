# 🛡️ ThreatView - Tiered Threat Intelligence Dashboard

A full-stack threat intelligence platform that aggregates, normalizes, and visualizes cybersecurity threat data from multiple public APIs — built for small to medium-sized businesses that can't afford enterprise Threat Intelligence Platforms.

## 🚀 Live Features
- **Real-time threat ingestion** from AlienVault OTX and AbuseIPDB
- **Automated scheduler** pulls fresh threat data every hour
- **Normalized ThreatModel** — maps different API schemas into one unified database
- **Interactive dashboard** with threat type charts and attack origin map
- **IoC Search** — paste any IP, domain, or hash to check against threat feeds

## 🏗️ Architecture
```
ThreatView/
├── backend/
│   ├── ingestors/        # ETL scripts per data source
│   ├── models/           # Unified ThreatIndicator database model
│   ├── scheduler/        # APScheduler hourly jobs
│   ├── api/              # FastAPI route handlers
│   └── main.py           # App entry point
├── frontend/
│   └── src/App.jsx       # React dashboard
└── docker-compose.yml    # PostgreSQL database
```

## 🔌 Threat Feeds Integrated
| Source | Type | Data |
|--------|------|------|
| AlienVault OTX | Pulses | IPs, Domains, URLs, File Hashes |
| AbuseIPDB | Blacklist | Malicious IPs with confidence scores |

## 🛠️ Tech Stack
- **Backend:** Python, FastAPI, SQLAlchemy, APScheduler
- **Database:** PostgreSQL (Docker)
- **Frontend:** React, Recharts, Axios
- **APIs:** AlienVault OTX, AbuseIPDB

## ⚙️ Setup & Run

### Prerequisites
- Python 3.10+
- Node.js 18+
- Docker Desktop

### 1. Start the database
```bash
docker compose up -d
```

### 2. Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 3. Frontend
```bash
cd frontend
npm install
npm run dev
```

### 4. Environment Variables
Create `backend/.env`:
```
DATABASE_URL=postgresql://threatview:threatview123@localhost:5432/threatview_db
OTX_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

## 📡 API Endpoints
| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Dashboard summary stats |
| `GET /api/indicators` | Paginated IoC list |
| `GET /api/search?q=` | Search threat database |

## 🗓️ Project Timeline
- ✅ Week 1 — ETL Pipeline & Data Ingestion
- ✅ Week 2 — React Dashboard & Visualizations
- 🔄 Week 3 — Alerting & Search
- 🔄 Week 4 — PDF Reports & Deployment
